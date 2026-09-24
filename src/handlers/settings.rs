//! EasyDC's own settings: the administrator accounts that sign in to EasyDC.
//!
//! Nothing here touches a domain controller — these are the local accounts in
//! EasyDC's SQLite database, not directory users. Every change is written to
//! the audit log, so the `actor` column can be traced back to a real person.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{
    auth::{extract_session_cookie, CurrentUser},
    db, AppState,
};

const MIN_PASSWORD_LEN: usize = 8;

/// Letters, digits, and `. _ - @`. Names appear in URL paths and in the page,
/// so anything outside this set would need escaping somewhere it could be
/// forgotten.
fn valid_username(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

#[derive(Deserialize)]
pub struct SettingsQuery {
    /// Set by the post-redirect-get after a successful change.
    pub done: Option<String>,
}

fn done_message(code: &str) -> Option<&'static str> {
    match code {
        "password" => Some("Password changed. Your other sessions have been signed out."),
        "created" => Some("Administrator added."),
        "deleted" => Some("Administrator removed and signed out."),
        _ => None,
    }
}

/// Render the settings page. `error` is shown when a submission is rejected;
/// the form values are not echoed back, since both forms are passwords.
async fn render(
    state: &AppState,
    actor: &str,
    error: Option<String>,
    done: Option<&str>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("actor", actor);
    ctx.insert("admins", &db::list_admins(&state.db).await.unwrap_or_default());
    ctx.insert("min_password_len", &MIN_PASSWORD_LEN);
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    if let Some(d) = done {
        ctx.insert("done", d);
    }
    Html(state.tera.render("settings.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn settings(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Query(q): Query<SettingsQuery>,
) -> Response {
    let done = q.done.as_deref().and_then(done_message);
    render(&state, &actor, None, done).await
}

// ── change your own password ──────────────────────────────────────────────────

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

    Redirect::to("/settings?done=password").into_response()
}

// ── administrator accounts ────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct NewAdminForm {
    pub username: String,
    pub password: String,
    pub confirm_password: String,
}

pub async fn create_admin(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Form(form): Form<NewAdminForm>,
) -> Response {
    let username = form.username.trim().to_string();

    let error = if username.is_empty() {
        Some("Username is required.".to_string())
    } else if username.len() > 64 {
        Some("Username must be 64 characters or fewer.".to_string())
    } else if !valid_username(&username) {
        Some("Usernames may contain letters, digits, and . _ - @ only.".to_string())
    } else if form.password.len() < MIN_PASSWORD_LEN {
        Some(format!("Password must be at least {} characters.", MIN_PASSWORD_LEN))
    } else if form.password != form.confirm_password {
        Some("Passwords do not match.".to_string())
    } else if db::admin_name_taken(&state.db, &username).await {
        Some(format!("An administrator named '{}' already exists.", username))
    } else {
        None
    };

    if let Some(e) = error {
        db::log_action(&state.db, &actor, "settings.admin_create", &username, None, &Err(e.clone())).await;
        return render(&state, &actor, Some(e), None).await;
    }

    let hash = match bcrypt::hash(&form.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("Could not hash the password: {}", e);
            db::log_action(&state.db, &actor, "settings.admin_create", &username, None, &Err(msg.clone())).await;
            return render(&state, &actor, Some(msg), None).await;
        }
    };

    let result = db::create_admin(&state.db, &username, &hash)
        .await
        .map_err(|e| e.to_string());
    db::log_action(&state.db, &actor, "settings.admin_create", &username, None, &result).await;

    match result {
        Err(e) => render(&state, &actor, Some(e), None).await,
        Ok(()) => Redirect::to("/settings?done=created").into_response(),
    }
}

pub async fn delete_admin(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(username): Path<String>,
) -> Response {
    // Two guards, both of which would otherwise lock everyone out: deleting the
    // account you are using, and deleting the last one that exists.
    // The last-administrator rule is enforced inside db::delete_admin, in the
    // same statement as the delete; these checks only pick the message.
    let error = if username == actor {
        Some("You cannot delete the account you are signed in as.".to_string())
    } else if !db::admin_exists(&state.db, &username).await {
        Some(format!("No administrator named '{}'.", username))
    } else {
        None
    };

    if let Some(e) = error {
        db::log_action(&state.db, &actor, "settings.admin_delete", &username, None, &Err(e.clone())).await;
        return render(&state, &actor, Some(e), None).await;
    }

    let result = match db::delete_admin(&state.db, &username).await {
        Ok(true) => Ok(()),
        // The account existed a moment ago, so nothing deleted means it was the
        // last one — or it vanished in between; either way, report it.
        Ok(false) => Err("At least one administrator must remain.".to_string()),
        Err(e) => Err(e.to_string()),
    };
    db::log_action(&state.db, &actor, "settings.admin_delete", &username, None, &result).await;

    match result {
        Err(e) => render(&state, &actor, Some(e), None).await,
        Ok(()) => {
            // Their sessions outlive the row otherwise.
            db::delete_sessions_for(&state.db, &username, None).await;
            Redirect::to("/settings?done=deleted").into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use tera::{Context, Tera};

    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn ctx(actor: &str, admins: &[&str]) -> Context {
        let mut c = Context::new();
        c.insert("actor", actor);
        c.insert("admins", admins);
        c.insert("min_password_len", &super::MIN_PASSWORD_LEN);
        c
    }

    #[test]
    fn lists_administrators_and_marks_the_current_one() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice", "bob"]))
            .expect("renders");
        assert!(html.contains("alice"));
        assert!(html.contains("bob"));
        assert!(html.contains(">you<"));
    }

    /// The two lock-yourself-out cases the handler refuses must not be offered
    /// in the UI either.
    #[test]
    fn offers_no_delete_for_your_own_account() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice", "bob"]))
            .expect("renders");
        assert!(html.contains("/settings/admins/bob/delete"));
        assert!(!html.contains("/settings/admins/alice/delete"));
    }

    #[test]
    fn offers_no_delete_for_the_last_administrator() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice"]))
            .expect("renders");
        assert!(!html.contains("/delete"));
    }

    #[test]
    fn shows_error_and_success_banners() {
        let mut c = ctx("alice", &["alice"]);
        c.insert("error", "Current password is incorrect.");
        let html = tera().render("settings.html", &c).expect("renders");
        assert!(html.contains("Current password is incorrect."));
        assert!(html.contains("alert-danger"));

        let mut c = ctx("alice", &["alice"]);
        c.insert("done", "Password changed. Your other sessions have been signed out.");
        let html = tera().render("settings.html", &c).expect("renders");
        assert!(html.contains("alert-success"));
    }

    #[test]
    fn every_page_links_to_settings() {
        let mut c = Context::new();
        c.insert("entries", &Vec::<tera::Value>::new());
        let html = tera().render("audit.html", &c).expect("renders");
        assert!(html.contains("href=\"/settings\""));
    }

    /// Names that predate the character rules may still exist. A quote must
    /// not reach a JavaScript context, and a slash must not break the URL.
    #[test]
    fn awkward_names_render_safely() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice", "o'brien", "a/b"]))
            .expect("renders");
        assert!(!html.contains("onsubmit="), "no inline handlers");
        assert!(html.contains("/settings/admins/o%27brien/delete"));
        assert!(html.contains("/settings/admins/a%2Fb/delete"));
        assert!(html.contains(r#"data-admin="o&#x27;brien""#));
    }

    #[test]
    fn usernames_are_limited_to_safe_characters() {
        assert!(super::valid_username("alice"));
        assert!(super::valid_username("a.smith-2@corp"));
        assert!(!super::valid_username("o'brien"));
        assert!(!super::valid_username("a/b"));
        assert!(!super::valid_username("x');alert(1);//"));
        assert!(!super::valid_username("two words"));
    }

    #[test]
    fn done_codes_map_to_messages() {
        assert!(super::done_message("password").is_some());
        assert!(super::done_message("created").is_some());
        assert!(super::done_message("deleted").is_some());
        // An unknown or hand-typed code shows no banner rather than echoing it.
        assert!(super::done_message("<script>").is_none());
    }
}
