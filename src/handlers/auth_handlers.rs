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
    db, AppState,
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
    Html(state.tera.render("login.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn post_login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> impl IntoResponse {
    use sqlx::Row;

    let row = sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(&form.username)
        .fetch_optional(&state.db)
        .await
        .unwrap();

    let authenticated = if let Some(row) = row {
        let hash: String = row.get("password_hash");
        bcrypt::verify(&form.password, &hash).unwrap_or(false)
    } else {
        false
    };

    if !authenticated {
        let mut ctx = Context::new();
        ctx.insert("error", "Invalid username or password");
        return Html(state.tera.render("login.html", &ctx).unwrap_or_default()).into_response();
    }

    db::purge_expired_sessions(&state.db).await;

    let token = Uuid::new_v4().to_string();
    let now = db::unix_now();

    sqlx::query("INSERT INTO sessions (token, created_at, last_seen, username) VALUES (?, ?, ?, ?)")
        .bind(&token)
        .bind(now)
        .bind(now)
        .bind(&form.username)
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
