use axum::{
    extract::State,
    response::{Html, IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{db, AppState};

#[derive(Deserialize)]
pub struct SetupForm {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

pub async fn get_setup(State(state): State<AppState>) -> impl IntoResponse {
    if db::has_users(&state.db).await.unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }
    let ctx = Context::new();
    Html(state.tera.render("setup.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn post_setup(
    State(state): State<AppState>,
    Form(form): Form<SetupForm>,
) -> impl IntoResponse {
    if db::has_users(&state.db).await.unwrap_or(false) {
        return Redirect::to("/login").into_response();
    }

    // The same rules as an account added in Settings: sign-in trims the
    // name, so a name with spaces around it could never sign in.
    let username = form.username.trim();
    let error = if username.is_empty() {
        Some("Username is required.".to_string())
    } else if username.len() > 64 {
        Some("Username must be 64 characters or fewer.".to_string())
    } else if !super::settings::valid_username(username) {
        Some("Usernames may contain letters, digits, and . _ - @ only.".to_string())
    } else if form.password != form.confirm_password {
        Some("Passwords do not match.".to_string())
    } else if form.password.len() < super::settings::MIN_PASSWORD_LEN {
        Some(format!("Password must be at least {} characters.", super::settings::MIN_PASSWORD_LEN))
    } else {
        None
    };
    if let Some(e) = error {
        return page(&state, &e);
    }

    let hash = match crate::auth::hash_password(&form.password).await {
        Ok(h) => h,
        Err(e) => return page(&state, &format!("Could not hash the password: {e}")),
    };
    // The first account is an admin: someone has to be able to add the rest.
    if let Err(e) = db::create_account(&state.db, username, &hash, true, &Default::default()).await {
        return page(&state, &format!("Could not create the account: {e}"));
    }

    Redirect::to("/login").into_response()
}

fn page(state: &AppState, error: &str) -> axum::response::Response {
    let mut ctx = Context::new();
    ctx.insert("error", error);
    Html(state.tera.render("setup.html", &ctx).unwrap_or_default()).into_response()
}
