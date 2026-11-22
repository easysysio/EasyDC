use axum::{
    extract::{Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;
use tera::Context;
use uuid::Uuid;

use crate::{
    auth::{clear_session_cookie, extract_session_cookie, session_cookie, via_https},
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

    db::purge_expired_sessions(&state.db).await;

    let token = Uuid::new_v4().to_string();
    let now = db::unix_now();

    sqlx::query("INSERT INTO sessions (token, created_at, last_seen, username) VALUES (?, ?, ?, ?)")
        .bind(&token)
        .bind(now)
        .bind(now)
        .bind(&username)
        .execute(&state.db)
        .await
        .unwrap();

    let cookie = session_cookie(&token, via_https(&headers));
    let mut response = Redirect::to("/").into_response();
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
