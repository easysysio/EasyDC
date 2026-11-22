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

    let mut ctx = Context::new();

    if form.password != form.confirm_password {
        ctx.insert("error", "Passwords do not match");
        return Html(state.tera.render("setup.html", &ctx).unwrap_or_default()).into_response();
    }

    if form.password.len() < 8 {
        ctx.insert("error", "Password must be at least 8 characters");
        return Html(state.tera.render("setup.html", &ctx).unwrap_or_default()).into_response();
    }

    let hash = bcrypt::hash(&form.password, bcrypt::DEFAULT_COST).unwrap();
    // The first account is an admin: someone has to be able to add the rest.
    db::create_account(&state.db, &form.username, &hash, true, &Default::default())
        .await
        .unwrap();

    Redirect::to("/login").into_response()
}
