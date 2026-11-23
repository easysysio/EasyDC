//! Two-factor sign-in for local EasyDC accounts: setting it up, recovery
//! codes, turning it off, and what an admin can do about someone else's.
//!
//! Domain accounts are not covered: they sign in with their domain password.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap, HeaderValue},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{
    access,
    auth::{extract_session_cookie, CurrentUser},
    db, totp, AppState,
};

/// How a code was accepted.
#[derive(Debug, PartialEq)]
pub enum Used {
    App,
    Recovery,
}

/// Check a typed code for an account with two-factor on. The attempt is
/// counted before it is checked, so requests sent at the same moment cannot
/// get past the limit. A right code clears the count.
pub async fn check_code(state: &AppState, username: &str, secret: &str, typed: &str) -> Result<Used, String> {
    let kind = totp::read_code(typed);
    if kind == totp::Typed::Neither {
        return Err("Enter the 6-digit code from your app, or a recovery code.".to_string());
    }
    let now = db::unix_now();
    let unavailable = |_| "The code could not be checked. Try again.".to_string();
    if !db::count_code_attempt(&state.db, username, now).await.map_err(unavailable)? {
        let until = db::two_factor(&state.db, username).await.ok().flatten().map_or(now, |t| t.locked_until);
        let minutes = ((until - now).max(1) + 59) / 60;
        return Err(format!("Too many wrong codes. Try again in {minutes} minute{}.", if minutes == 1 { "" } else { "s" }));
    }
    let used = match kind {
        totp::Typed::App(code) => match totp::matching_step(secret, &code, now) {
            None => return Err("That code is not right. Check the time on your phone.".to_string()),
            Some(step) => {
                if !db::claim_code_step(&state.db, username, step).await.map_err(unavailable)? {
                    return Err("That code was already used. Wait for the next one.".to_string());
                }
                Used::App
            }
        },
        totp::Typed::Recovery(code) => {
            let hash = totp::hash_recovery(username, &code).map_err(|_| "The code could not be checked. Try again.".to_string())?;
            if !db::use_recovery_code(&state.db, username, &hash).await.map_err(unavailable)? {
                return Err("That recovery code is not right, or was already used.".to_string());
            }
            Used::Recovery
        }
        totp::Typed::Neither => unreachable!("returned above"),
    };
    db::clear_code_failures(&state.db, username).await.map_err(unavailable)?;
    Ok(used)
}

/// A page holding a secret: the browser must not keep a copy.
fn private(html: String) -> Response {
    let mut response = Html(html).into_response();
    response.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

enum View<'a> {
    Status,
    Setup(&'a str),
    Codes(&'a [String]),
}

async fn page(state: &AppState, actor: &str, view: View<'_>, error: Option<String>, done: Option<&str>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("actor", actor);
    ctx.insert("local", &db::is_local_account(&state.db, actor).await);
    let row = db::two_factor(&state.db, actor).await.ok().flatten();
    ctx.insert("enabled", &row.as_ref().is_some_and(|t| t.enabled));
    ctx.insert("recovery_left", &db::recovery_codes_left(&state.db, actor).await);
    ctx.insert("must_set_up", &db::must_set_up_two_factor(&state.db, actor).await);
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    if let Some(d) = done {
        ctx.insert("done", d);
    }
    match view {
        View::Status => ctx.insert("view", "status"),
        View::Setup(secret) => {
            ctx.insert("view", "setup");
            ctx.insert("secret", &totp::grouped(secret));
            match totp::qr_svg(&totp::otpauth_url(actor, secret)) {
                Ok(svg) => ctx.insert("qr", &svg),
                Err(e) => tracing::warn!("QR code: {e}"),
            }
        }
        View::Codes(codes) => {
            ctx.insert("view", "codes");
            ctx.insert("codes", codes);
        }
    }
    private(access::render(&state.tera, "two_factor.html", &ctx))
}

#[derive(Deserialize)]
pub struct PageQuery {
    done: Option<String>,
}

fn done_message(code: &str) -> Option<&'static str> {
    match code {
        "off" => Some("Two-factor sign-in is off."),
        "recovery" => Some("You signed in with a recovery code, and it cannot be used again."),
        _ => None,
    }
}

pub async fn get_page(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Query(q): Query<PageQuery>) -> Response {
    page(&state, &actor, View::Status, None, q.done.as_deref().and_then(done_message)).await
}

async fn password_ok(state: &AppState, actor: &str, password: &str) -> bool {
    match db::password_hash_for(&state.db, actor).await {
        Some(hash) => bcrypt::verify(password, &hash).unwrap_or(false),
        None => false,
    }
}

#[derive(Deserialize)]
pub struct StartForm {
    password: String,
}

/// Asks for the password again, so an unattended browser cannot tie the
/// account to someone else's phone.
pub async fn start(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Form(form): Form<StartForm>) -> Response {
    let result: Result<String, String> = async {
        if !db::is_local_account(&state.db, &actor).await {
            return Err("You sign in with your domain password, so two-factor here does not apply.".to_string());
        }
        if !password_ok(&state, &actor, &form.password).await {
            return Err("Password is incorrect.".to_string());
        }
        let secret = totp::new_secret().map_err(|e| e.to_string())?;
        match db::begin_two_factor(&state.db, &actor, &secret, db::unix_now()).await {
            Ok(true) => Ok(secret),
            Ok(false) => Err("Two-factor sign-in is already on.".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    .await;
    match result {
        Ok(secret) => page(&state, &actor, View::Setup(&secret), None, None).await,
        Err(e) => {
            db::log_action(&state.db, &actor, "settings.two_factor_on", &actor, None, &Err(e.clone())).await;
            page(&state, &actor, View::Status, Some(e), None).await
        }
    }
}

#[derive(Deserialize)]
pub struct CodeForm {
    code: String,
}

/// Turned on only once the app has produced a right code.
pub async fn confirm(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    headers: HeaderMap,
    Form(form): Form<CodeForm>,
) -> Response {
    let now = db::unix_now();
    let row = match db::two_factor(&state.db, &actor).await {
        Ok(Some(t)) if !t.enabled && now - t.created_at < totp::SETUP_SECONDS => t,
        _ => {
            let e = "The setup timed out. Start again.".to_string();
            return page(&state, &actor, View::Status, Some(e), None).await;
        }
    };
    let totp::Typed::App(code) = totp::read_code(&form.code) else {
        let e = "Enter the 6-digit code from your app.".to_string();
        return page(&state, &actor, View::Setup(&row.secret), Some(e), None).await;
    };
    let Some(step) = totp::matching_step(&row.secret, &code, now) else {
        let e = "That code is not right. Check the time on your phone, and try the next code.".to_string();
        return page(&state, &actor, View::Setup(&row.secret), Some(e), None).await;
    };
    let result: Result<Vec<String>, String> = async {
        let codes = totp::new_recovery_codes().map_err(|e| e.to_string())?;
        let hashes = hashes_of(&actor, &codes)?;
        match db::enable_two_factor(&state.db, &actor, &row.secret, step, &hashes).await {
            Ok(true) => Ok(codes),
            Ok(false) => Err("The setup changed in another window. Start again.".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }
    .await;
    db::log_action(&state.db, &actor, "settings.two_factor_on", &actor, None, &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok(codes) => {
            // Anyone signed in with the password alone has to come back through the code.
            let current = extract_session_cookie(&headers);
            db::delete_sessions_for(&state.db, &actor, current.as_deref()).await;
            page(&state, &actor, View::Codes(&codes), None, Some("Two-factor sign-in is on. Your other sessions have been signed out.")).await
        }
        Err(e) => page(&state, &actor, View::Status, Some(e), None).await,
    }
}

fn hashes_of(username: &str, codes: &[String]) -> Result<Vec<String>, String> {
    codes.iter().map(|c| totp::hash_recovery(username, c).map_err(|e| e.to_string())).collect()
}

#[derive(Deserialize)]
pub struct ProveForm {
    password: String,
    code: String,
}

/// The password and a current code, before a change to an account's two-factor.
async fn prove(state: &AppState, actor: &str, form: &ProveForm) -> Result<(), String> {
    if !password_ok(state, actor, &form.password).await {
        return Err("Password is incorrect.".to_string());
    }
    let row = db::two_factor(&state.db, actor).await.map_err(|e| e.to_string())?;
    let Some(row) = row.filter(|t| t.enabled) else {
        return Err("Two-factor sign-in is not on.".to_string());
    };
    check_code(state, actor, &row.secret, &form.code).await.map(|_| ())
}

pub async fn new_recovery_codes(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Form(form): Form<ProveForm>) -> Response {
    let result: Result<Vec<String>, String> = async {
        prove(&state, &actor, &form).await?;
        let codes = totp::new_recovery_codes().map_err(|e| e.to_string())?;
        db::replace_recovery_codes(&state.db, &actor, &hashes_of(&actor, &codes)?).await.map_err(|e| e.to_string())?;
        Ok(codes)
    }
    .await;
    db::log_action(&state.db, &actor, "settings.two_factor_codes", &actor, None, &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok(codes) => page(&state, &actor, View::Codes(&codes), None, Some("New recovery codes. The old ones no longer work.")).await,
        Err(e) => page(&state, &actor, View::Status, Some(e), None).await,
    }
}

pub async fn disable(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Form(form): Form<ProveForm>) -> Response {
    let result: Result<(), String> = async {
        prove(&state, &actor, &form).await?;
        db::remove_two_factor(&state.db, &actor).await.map(|_| ()).map_err(|e| e.to_string())
    }
    .await;
    db::log_action(&state.db, &actor, "settings.two_factor_off", &actor, None, &result).await;
    match result {
        Ok(()) => Redirect::to("/settings/two-factor?done=off").into_response(),
        Err(e) => page(&state, &actor, View::Status, Some(e), None).await,
    }
}

// ── what an admin can do ──────────────────────────────────────────────────────

/// For someone who lost their phone and their recovery codes. Their sessions
/// end too, in case the phone was stolen.
pub async fn reset(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(username): Path<String>) -> Response {
    let result: Result<(), String> = async {
        if username == actor {
            return Err("Change your own two-factor on its page.".to_string());
        }
        match db::remove_two_factor(&state.db, &username).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!("{username} does not have two-factor sign-in on.")),
            Err(e) => Err(e.to_string()),
        }
    }
    .await;
    db::log_action(&state.db, &actor, "settings.two_factor_reset", &username, None, &result).await;
    match result {
        Ok(()) => {
            db::delete_sessions_for(&state.db, &username, None).await;
            Redirect::to("/settings?done=two_factor_reset").into_response()
        }
        Err(e) => super::settings::show_error(&state, &actor, e).await,
    }
}

#[derive(Deserialize)]
pub struct RequireForm {
    required: Option<String>,
}

/// Whether every local admin must use two-factor. The admin turning it on
/// goes first, so nobody is sent to a setup they have not seen.
pub async fn set_required(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Form(form): Form<RequireForm>) -> Response {
    let required = form.required.as_deref() == Some("on");
    let result: Result<(), String> = async {
        if required && db::is_local_account(&state.db, &actor).await {
            let on = db::two_factor(&state.db, &actor).await.map_err(|e| e.to_string())?.is_some_and(|t| t.enabled);
            if !on {
                return Err("Turn on two-factor sign-in for your own account first.".to_string());
            }
        }
        db::set_two_factor_required(&state.db, required).await.map_err(|e| e.to_string())
    }
    .await;
    let target = if required { "required for local admins" } else { "optional" };
    db::log_action(&state.db, &actor, "settings.two_factor_require", target, None, &result).await;
    match result {
        Ok(()) => Redirect::to(if required { "/settings?done=two_factor_required" } else { "/settings?done=two_factor_optional" }).into_response(),
        Err(e) => super::settings::show_error(&state, &actor, e).await,
    }
}

#[cfg(test)]
mod tests {
    use tera::{Context, Tera};

    fn render(view: &str, enabled: bool, local: bool, must: bool) -> String {
        let mut t = Tera::new("templates/**/*.html").unwrap();
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        let mut c = Context::new();
        let me = crate::access::Access { username: "alice".into(), admin: true, ..Default::default() };
        c.insert("access", &me.view());
        c.insert("actor", "alice");
        c.insert("view", view);
        c.insert("enabled", &enabled);
        c.insert("local", &local);
        c.insert("must_set_up", &must);
        c.insert("recovery_left", &3);
        c.insert("secret", "ABCD EFGH");
        c.insert("qr", "<svg id=\"qr\"></svg>");
        c.insert("codes", &["7KQ2M-XH9TC"]);
        t.render("two_factor.html", &c).unwrap()
    }

    #[test]
    fn each_step_shows_what_it_should() {
        let off = render("status", false, true, false);
        assert!(off.contains(r#"action="/settings/two-factor/start""#));
        assert!(!off.contains("/settings/two-factor/disable"));

        let setup = render("setup", false, true, false);
        assert!(setup.contains(r#"<svg id="qr">"#), "the QR code is not escaped");
        assert!(setup.contains("ABCD EFGH") && setup.contains(r#"action="/settings/two-factor/confirm""#));

        let codes = render("codes", true, true, false);
        assert!(codes.contains("7KQ2M-XH9TC"));

        let on = render("status", true, true, false);
        assert!(on.contains("3 recovery codes left"));
        assert!(on.contains("/settings/two-factor/disable") && on.contains("/settings/two-factor/recovery"));
        assert!(!on.contains(r#"action="/settings/two-factor/start""#));
    }

    #[test]
    fn it_says_when_setup_is_required_and_when_it_does_not_apply() {
        assert!(render("status", false, true, true).contains("must set up"));
        let domain = render("status", false, false, false);
        assert!(domain.contains("is a domain account") && !domain.contains("/settings/two-factor/start"));
    }

    #[test]
    fn unknown_done_codes_show_nothing() {
        assert!(super::done_message("off").is_some());
        assert!(super::done_message("<script>").is_none());
    }
}
