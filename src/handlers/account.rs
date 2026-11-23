//! The signed-in person's own account: their password. Their two-factor
//! sign-in is in `two_factor`, under the same menu.

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use super::settings::MIN_PASSWORD_LEN;
use crate::{
    access,
    auth::{extract_session_cookie, CurrentUser},
    db, AppState,
};

#[derive(Deserialize)]
pub struct AccountQuery {
    done: Option<String>,
}

async fn render(state: &AppState, actor: &str, error: Option<String>, done: Option<&str>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("actor", actor);
    ctx.insert("local", &db::is_local_account(&state.db, actor).await);
    ctx.insert("min_password_len", &MIN_PASSWORD_LEN);
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    if let Some(d) = done {
        ctx.insert("done", d);
    }
    Html(access::render(&state.tera, "account.html", &ctx)).into_response()
}

pub async fn page(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Query(q): Query<AccountQuery>) -> Response {
    let done = (q.done.as_deref() == Some("password")).then_some("Password changed. Your other sessions have been signed out.");
    render(&state, &actor, None, done).await
}

#[derive(Deserialize)]
pub struct ChangePasswordForm {
    pub current_password: String,
    pub new_password: String,
    pub confirm_password: String,
}

pub async fn change_password(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<ChangePasswordForm>,
) -> Response {
    let fail = |msg: &str| msg.to_string();

    if db::list_accounts(&state.db).await.unwrap_or_default().iter().any(|a| a.username == actor && a.domain) {
        return render(
            &state,
            &actor,
            Some(fail("You sign in with your domain password. Change it on a computer in the domain.")),
            None,
        )
        .await;
    }

    // A session created before usernames were recorded cannot be attributed to
    // a row in `users`, so there is no account to change.
    let Some(hash) = db::password_hash_for(&state.db, &actor).await else {
        return render(
            &state,
            &actor,
            Some(fail("Your session predates account tracking. Sign out and back in, then try again.")),
            None,
        )
        .await;
    };

    let error = if !bcrypt::verify(&form.current_password, &hash).unwrap_or(false) {
        Some(fail("Current password is incorrect."))
    } else if form.new_password.len() < MIN_PASSWORD_LEN {
        Some(format!(
            "New password must be at least {} characters.",
            MIN_PASSWORD_LEN
        ))
    } else if form.new_password != form.confirm_password {
        Some(fail("New passwords do not match."))
    } else if form.new_password == form.current_password {
        Some(fail("New password must be different from the current one."))
    } else {
        None
    };

    if let Some(e) = error {
        // A rejected attempt is worth recording: it is the shape of someone
        // guessing at an unattended session.
        db::log_action(
            &state.db,
            &actor,
            "settings.password_change",
            &actor,
            None,
            &Err(e.clone()),
        )
        .await;
        return render(&state, &actor, Some(e), None).await;
    }

    let new_hash = match bcrypt::hash(&form.new_password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("Could not hash the new password: {}", e);
            db::log_action(&state.db, &actor, "settings.password_change", &actor, None, &Err(msg.clone())).await;
            return render(&state, &actor, Some(msg), None).await;
        }
    };

    let result = db::set_password_hash(&state.db, &actor, &new_hash)
        .await
        .map_err(|e| e.to_string());
    db::log_action(&state.db, &actor, "settings.password_change", &actor, None, &result).await;

    if let Err(e) = result {
        return render(&state, &actor, Some(e), None).await;
    }

    // Keep this browser signed in; drop every other session for the account so
    // a changed password actually ends anyone else's access.
    let current = extract_session_cookie(&headers);
    db::delete_sessions_for(&state.db, &actor, current.as_deref()).await;

    Redirect::to("/account?done=password").into_response()
}

#[cfg(test)]
mod tests {
    use tera::{Context, Tera};

    fn render(local: bool) -> String {
        let mut t = Tera::new("templates/**/*.html").unwrap();
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        let me = crate::access::Access { username: "alice".into(), ..Default::default() };
        let mut c = Context::new();
        c.insert("access", &me.view());
        c.insert("actor", "alice");
        c.insert("local", &local);
        c.insert("min_password_len", &8);
        t.render("account.html", &c).unwrap()
    }

    #[test]
    fn a_local_account_gets_the_form_and_a_domain_account_is_told_why_not() {
        let html = render(true);
        assert!(html.contains(r#"action="/account/password""#) && html.contains(r#"href="/account/two-factor""#));
        let html = render(false);
        assert!(!html.contains(r#"action="/account/password""#));
        assert!(html.contains("domain account"));
    }
}
