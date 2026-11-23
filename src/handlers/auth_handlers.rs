use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;
use uuid::Uuid;

use super::two_factor::{self, Used};
use crate::{
    auth::{
        challenge_cookie, clear_challenge_cookie, clear_session_cookie, extract_challenge_cookie,
        extract_session_cookie, session_cookie, via_https,
    },
    db, ldap, AppState,
};

#[derive(Deserialize)]
pub struct LoginForm {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginQuery {
    expired: Option<String>,
}

pub async fn get_login(
    State(state): State<AppState>,
    Query(q): Query<LoginQuery>,
) -> impl IntoResponse {
    if !db::has_users(&state.db).await.unwrap_or(true) {
        return Redirect::to("/setup").into_response();
    }
    let mut ctx = Context::new();
    if q.expired.is_some() {
        ctx.insert("notice", "Your session expired. Sign in again.");
    }
    ctx.insert("domain_accounts", &db::has_domain_accounts(&state.db).await);
    Html(state.tera.render("login.html", &ctx).unwrap_or_default()).into_response()
}

/// The sign-in page again, with why it did not work.
async fn refused(state: &AppState, message: &str) -> axum::response::Response {
    let mut ctx = Context::new();
    ctx.insert("error", message);
    ctx.insert("domain_accounts", &db::has_domain_accounts(&state.db).await);
    Html(state.tera.render("login.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn post_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    let typed = form.username.trim();
    let username = match db::sign_in_account(&state.db, typed).await {
        Some(db::SignIn::Local { username, hash }) => {
            if !bcrypt::verify(&form.password, &hash).unwrap_or(false) {
                return refused(&state, "Invalid username or password").await;
            }
            // If the database cannot say whether a code is needed, no sign-in.
            match db::two_factor(&state.db, &username).await {
                Ok(Some(t)) if t.enabled => return ask_for_code(&state, &headers, &username).await,
                Ok(_) => {}
                Err(_) => return refused(&state, "Sign-in is not available right now. Try again.").await,
            }
            username
        }
        Some(db::SignIn::Domain { username, domain_user, server_id }) => {
            let Some(server) = db::server(&state.db, server_id.unwrap_or(-1)).await else {
                let e = "The server for this domain account has been removed from EasyDC. An EasyDC admin can add the account again.";
                db::log_action(&state.db, &username, "auth.sign_in", &username, None, &Err(e.to_string())).await;
                return refused(&state, e).await;
            };
            let result = ldap::check_domain_password(&server, &domain_user, &form.password).await;
            let logged = result.as_ref().map(|_| ()).map_err(|e| e.message());
            db::log_action(&state.db, &username, "auth.sign_in", &username, Some(server.id), &logged).await;
            if let Err(e) = result {
                return refused(&state, &e.message()).await;
            }
            username
        }
        None => {
            // As long as a wrong password takes, so the answer does not say
            // which names exist.
            let _ = bcrypt::verify(&form.password, dummy_hash());
            return refused(&state, "Invalid username or password").await;
        }
    };

    start_session(&state, &headers, &username, "/").await
}

/// The password was right and the account has two-factor: open the code step.
async fn ask_for_code(state: &AppState, headers: &HeaderMap, username: &str) -> Response {
    let token = Uuid::new_v4().to_string();
    if db::create_challenge(&state.db, &token, username, db::unix_now()).await.is_err() {
        return refused(state, "Sign-in is not available right now. Try again.").await;
    }
    let mut response = Redirect::to("/login/code").into_response();
    if let Ok(v) = HeaderValue::from_str(&challenge_cookie(&token, via_https(headers))) {
        response.headers_mut().insert(header::SET_COOKIE, v);
    }
    response
}

/// Back to the password, with the code step closed.
fn start_over(headers: &HeaderMap) -> Response {
    let mut response = Redirect::to("/login?expired=1").into_response();
    response.headers_mut().insert(header::SET_COOKIE, clear_challenge_cookie(via_https(headers)));
    response
}

fn code_page(state: &AppState, error: Option<&str>) -> Response {
    let mut ctx = Context::new();
    if let Some(e) = error {
        ctx.insert("error", e);
    }
    let mut response = Html(state.tera.render("login_code.html", &ctx).unwrap_or_default()).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

pub async fn get_login_code(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let open = match extract_challenge_cookie(&headers) {
        Some(token) => db::challenge_user(&state.db, &token, db::unix_now()).await.is_some(),
        None => false,
    };
    if open { code_page(&state, None) } else { start_over(&headers) }
}

#[derive(Deserialize)]
pub struct LoginCodeForm {
    pub code: String,
}

pub async fn post_login_code(State(state): State<AppState>, headers: HeaderMap, Form(form): Form<LoginCodeForm>) -> Response {
    let Some(token) = extract_challenge_cookie(&headers) else {
        return start_over(&headers);
    };
    let Some(username) = db::challenge_user(&state.db, &token, db::unix_now()).await else {
        return start_over(&headers);
    };
    // Turned off, or reset by an admin, since the password was typed.
    let secret = match db::two_factor(&state.db, &username).await {
        Ok(Some(t)) if t.enabled => t.secret,
        _ => {
            db::close_challenge(&state.db, &token).await;
            return start_over(&headers);
        }
    };
    let used = match two_factor::check_code(&state, &username, &secret, &form.code).await {
        Ok(used) => used,
        Err(e) => {
            db::log_action(&state.db, &username, "auth.two_factor", &username, None, &Err(e.clone())).await;
            return code_page(&state, Some(&e));
        }
    };
    if !db::close_challenge(&state.db, &token).await {
        return start_over(&headers);
    }
    let action = if used == Used::Recovery { "auth.two_factor_recovery" } else { "auth.two_factor" };
    db::log_action(&state.db, &username, action, &username, None, &Ok(())).await;
    let to = if used == Used::Recovery { "/settings/two-factor?done=recovery" } else { "/" };
    let mut response = start_session(&state, &headers, &username, to).await;
    response.headers_mut().append(header::SET_COOKIE, clear_challenge_cookie(via_https(&headers)));
    response
}

/// Everything needed is proven: create the session and send the browser on.
async fn start_session(state: &AppState, headers: &HeaderMap, username: &str, to: &str) -> Response {
    db::purge_expired_sessions(&state.db).await;

    let token = Uuid::new_v4().to_string();
    let now = db::unix_now();

    sqlx::query("INSERT INTO sessions (token, created_at, last_seen, username) VALUES (?, ?, ?, ?)")
        .bind(&token)
        .bind(now)
        .bind(now)
        .bind(username)
        .execute(&state.db)
        .await
        .unwrap();

    let cookie = session_cookie(&token, via_https(headers));
    let mut response = Redirect::to(to).into_response();
    response
        .headers_mut()
        .insert(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    response
}

/// bcrypt of a random password nobody knows, at the cost real ones use.
fn dummy_hash() -> &'static str {
    static HASH: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HASH.get_or_init(|| bcrypt::hash(Uuid::new_v4().to_string(), bcrypt::DEFAULT_COST).unwrap_or_default())
}

pub async fn logout(State(state): State<AppState>, req: axum::extract::Request) -> impl IntoResponse {
    if let Some(token) = extract_session_cookie(req.headers()) {
        let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(&token)
            .execute(&state.db)
            .await;
    }
    let mut response = Redirect::to("/login").into_response();
    let secure = via_https(req.headers());
    response
        .headers_mut()
        .insert(header::SET_COOKIE, clear_session_cookie(secure));
    response
}
