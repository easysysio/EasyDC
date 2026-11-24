//! EasyDC's own settings: the accounts that sign in to EasyDC, and what each
//! may change.
//!
//! Nothing here touches a domain controller — these are the local accounts in
//! EasyDC's SQLite database, not directory users. Every change is written to
//! the audit log, so the `actor` column can be traced back to a real person.

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use tera::Context;

use crate::{
    access::{self, Area, AREAS},
    audit,
    auth::CurrentUser,
    db, ldap, tls, AppState,
};

pub(super) const MIN_PASSWORD_LEN: usize = 8;

/// Letters, digits, and `. _ - @`. Names appear in URL paths and in the page,
/// so anything outside this set would need escaping somewhere it could be
/// forgotten.
pub(super) fn valid_username(name: &str) -> bool {
    name.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '@'))
}

#[derive(Deserialize)]
pub struct SettingsQuery {
    /// Set by the post-redirect-get after a successful change.
    pub done: Option<String>,
    /// The tab to open.
    pub tab: Option<String>,
    /// What saving the audit log setting rotated out right away.
    #[serde(default)]
    pub entries: u64,
    #[serde(default)]
    pub files: u64,
    #[serde(default)]
    pub to_files: bool,
}

/// The tab a page opens on: the one asked for, or the one a change was made on.
fn tab_for(q: &SettingsQuery) -> &'static str {
    let name = q.tab.as_deref().or(match q.done.as_deref() {
        Some("certificate" | "generated") => Some("https"),
        Some("two_factor_required" | "two_factor_optional") => Some("two-factor"),
        Some("audit_saved") => Some("audit-log"),
        _ => None,
    });
    match name {
        Some("https") => "https",
        Some("audit-log") => "audit-log",
        Some("two-factor") if access::current().admin => "two-factor",
        _ => "accounts",
    }
}

fn done_message(code: &str) -> Option<&'static str> {
    match code {
        "created" => Some("Account added."),
        "deleted" => Some("Account removed and signed out."),
        "permissions" => Some("Permissions saved. They apply from that account's next click."),
        "certificate" => Some("Certificate saved. New connections use it now, with no restart."),
        "generated" => Some("A new self-signed certificate is in use. Your browser will warn about it once."),
        "two_factor_reset" => Some("Two-factor sign-in removed and the account signed out. They can set it up again."),
        "two_factor_required" => Some("Local admins must now use two-factor sign-in. Those without it set it up at their next click."),
        "two_factor_optional" => Some("Two-factor sign-in is now optional for admins."),
        _ => None,
    }
}

/// Render the settings page. `error` is shown when a submission is rejected;
/// the form values are not echoed back, since both forms are passwords.
async fn render(state: &AppState, actor: &str, error: Option<String>, done: Option<&str>) -> Response {
    render_tab(state, actor, "accounts", error, done).await
}

async fn render_tab(state: &AppState, actor: &str, tab: &str, error: Option<String>, done: Option<&str>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("active_tab", tab);
    ctx.insert("actor", actor);
    let accounts = db::list_accounts(&state.db).await.unwrap_or_default();
    ctx.insert("me_domain", &accounts.iter().any(|a| a.username == actor && a.domain));
    ctx.insert("me_two_factor", &accounts.iter().any(|a| a.username == actor && a.two_factor));
    ctx.insert("two_factor_required", &db::two_factor_required(&state.db).await);
    ctx.insert("accounts", &accounts);
    let servers: Vec<_> = db::server_names(&state.db)
        .await
        .into_iter()
        .map(|(id, name)| serde_json::json!({ "id": id, "name": name }))
        .collect();
    ctx.insert("servers", &servers);
    ctx.insert("areas", &area_rows());
    ctx.insert("min_password_len", &MIN_PASSWORD_LEN);
    insert_audit_log(state, &mut ctx).await;
    if let Some(live) = &state.tls {
        ctx.insert("tls", &live.info());
    }
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    if let Some(d) = done {
        ctx.insert("done", d);
    }
    Html(access::render(&state.tera, "settings.html", &ctx)).into_response()
}

/// The settings page with why something was refused.
pub async fn show_error(state: &AppState, actor: &str, tab: &str, error: String) -> Response {
    render_tab(state, actor, tab, Some(error), None).await
}

pub async fn settings(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Query(q): Query<SettingsQuery>,
) -> Response {
    let audit_done = (q.done.as_deref() == Some("audit_saved")).then(|| {
        let summary = audit::Rotated { entries: q.entries, files_deleted: q.files, to_files: q.to_files, error: None }.summary();
        if summary.is_empty() { "Saved.".to_string() } else { format!("Saved: {summary}.") }
    });
    let done = audit_done.as_deref().or(q.done.as_deref().and_then(done_message));
    render_tab(&state, &actor, tab_for(&q), None, done).await
}

// ── how long the audit log is kept ────────────────────────────────────────────

async fn insert_audit_log(state: &AppState, ctx: &mut Context) {
    let dir = std::path::Path::new(audit::ARCHIVE_DIR);
    let (retention, read_error) = match audit::load(&state.db).await {
        Ok(r) => (r, None),
        Err(e) => (audit::Retention::default(), Some(e)),
    };
    let (files, files_error) = match audit::list_files(dir) {
        Ok(f) => (f, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    let (keep_choices, file_choices) = audit::preview(&state.db, &files, db::unix_now()).await;
    let entries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_log").fetch_one(&state.db).await.unwrap_or(0);
    ctx.insert(
        "audit_log",
        &serde_json::json!({
            "keep_days": retention.keep_days,
            "file_days": retention.file_days,
            "describe": retention.describe(),
            "keep_choices": keep_choices,
            "file_choices": file_choices,
            "files": files,
            "entries": entries,
            "folder": audit::ARCHIVE_DIR,
            "error": read_error.or(files_error),
        }),
    );
}

#[derive(Deserialize)]
pub struct AuditLogForm {
    keep_days: i64,
    #[serde(default)]
    file_days: i64,
}

/// Save, and rotate right away, so the page shows what the choice did.
pub async fn save_audit_log(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Form(f): Form<AuditLogForm>) -> Response {
    let wanted = audit::Retention { keep_days: f.keep_days, file_days: f.file_days };
    let saved = audit::save(&state.db, wanted).await;
    db::log_action(&state.db, &actor, "settings.audit_log", &wanted.describe(), None, &saved).await;
    if let Err(e) = saved {
        return show_error(&state, &actor, "audit-log", e).await;
    }
    let done = audit::rotate(&state.db, std::path::Path::new(audit::ARCHIVE_DIR), db::unix_now()).await;
    audit::record(&state.db, &actor, &done).await;
    if let Some(e) = done.error {
        return show_error(&state, &actor, "audit-log", format!("The setting was saved, but rotation stopped: {e}")).await;
    }
    Redirect::to(&format!(
        "/settings?done=audit_saved&entries={}&files={}&to_files={}",
        done.entries, done.files_deleted, done.to_files
    ))
    .into_response()
}

/// One rotated file. Everyone can read the Audit Log page, and this is the
/// same information. The name must be one of ours, so it cannot leave the folder.
pub async fn audit_file(Path(name): Path<String>) -> Response {
    use axum::http::{header, StatusCode};
    if audit::file_day(&name).is_none() {
        return StatusCode::NOT_FOUND.into_response();
    }
    match tokio::fs::read(std::path::Path::new(audit::ARCHIVE_DIR).join(&name)).await {
        Ok(bytes) => (
            [
                (header::CONTENT_TYPE, "application/gzip".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{name}\"")),
                (header::CACHE_CONTROL, "no-store".to_string()),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

// ── the HTTPS certificate ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CertificateForm {
    pub cert: String,
    pub key: String,
}

/// Stores a certificate, then starts serving it. The key is never echoed back.
async fn use_certificate(state: &AppState, pair: Result<tls::Pair, String>) -> Result<String, String> {
    let live = state.tls.as_ref().ok_or("HTTPS is turned off (EASYDC_TLS=off).")?;
    let pair = pair?;
    db::save_tls_pair(&state.db, &pair).await.map_err(|e| format!("Could not save the certificate: {e}"))?;
    live.set(&pair)?;
    Ok(live.info().fingerprint)
}

pub async fn upload_certificate(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Form(form): Form<CertificateForm>,
) -> Response {
    let result = use_certificate(&state, tls::check_upload(&form.cert, &form.key)).await;
    certificate_changed(&state, &actor, "tls.upload", result, "certificate").await
}

pub async fn generate_certificate(State(state): State<AppState>, CurrentUser(actor): CurrentUser) -> Response {
    let result = use_certificate(&state, tls::self_signed()).await;
    certificate_changed(&state, &actor, "tls.generate", result, "generated").await
}

async fn certificate_changed(state: &AppState, actor: &str, action: &str, result: Result<String, String>, done: &str) -> Response {
    let target = result.as_deref().unwrap_or("HTTPS certificate").to_string();
    db::log_action(&state.db, actor, action, &target, None, &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok(_) => Redirect::to(&format!("/settings?done={done}")).into_response(),
        Err(e) => render_tab(state, actor, "https", Some(e), None).await,
    }
}

// ── EasyDC accounts ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct AreaRow {
    key: &'static str,
    label: &'static str,
    covers: &'static str,
}

fn area_rows() -> Vec<AreaRow> {
    AREAS.iter().map(|a| AreaRow { key: a.key(), label: a.label(), covers: a.covers() }).collect()
}

/// The permission fields of a form: `admin=on`, and `area_<key>=edit` for
/// each area to edit. An area left out, or set to anything else, is View.
fn read_permissions(fields: &HashMap<String, String>) -> (bool, BTreeSet<Area>) {
    let admin = fields.get("admin").is_some_and(|v| v == "on");
    let edit = AREAS
        .into_iter()
        .filter(|a| fields.get(&format!("area_{}", a.key())).is_some_and(|v| v == "edit"))
        .collect();
    (admin, edit)
}

/// What an account may change, for the audit log.
fn described(admin: bool, edit: &BTreeSet<Area>) -> String {
    access::Access { admin, edit: edit.clone(), ..Default::default() }.summary()
}

#[derive(Deserialize)]
pub struct NewAccountForm {
    /// "local" (the default) or "domain".
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub confirm_password: String,
    /// For a domain account: the server whose domain it is in, and the
    /// person's username there.
    #[serde(default)]
    pub server_id: String,
    #[serde(default)]
    pub domain_user: String,
    #[serde(flatten)]
    pub permissions: HashMap<String, String>,
}

pub async fn create_account(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Form(form): Form<NewAccountForm>,
) -> Response {
    let (admin, edit) = read_permissions(&form.permissions);
    if form.kind == "domain" {
        return create_domain_account(&state, &actor, &form, admin, edit).await;
    }
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
    } else if db::account_name_taken(&state.db, &username).await {
        Some(format!("An account named '{}' already exists.", username))
    } else {
        None
    };

    if let Some(e) = error {
        db::log_action(&state.db, &actor, "settings.account_create", &username, None, &Err(e.clone())).await;
        return render(&state, &actor, Some(e), None).await;
    }

    let hash = match crate::auth::hash_password(&form.password).await {
        Ok(h) => h,
        Err(e) => {
            let msg = format!("Could not hash the password: {}", e);
            db::log_action(&state.db, &actor, "settings.account_create", &username, None, &Err(msg.clone())).await;
            return render(&state, &actor, Some(msg), None).await;
        }
    };

    let result = db::create_account(&state.db, &username, &hash, admin, &edit)
        .await
        .map_err(|e| e.to_string());
    let target = format!("{username} ({})", described(admin, &edit));
    db::log_action(&state.db, &actor, "settings.account_create", &target, None, &result).await;

    match result {
        Err(e) => render(&state, &actor, Some(e), None).await,
        Ok(()) => Redirect::to("/settings?done=created").into_response(),
    }
}

/// A domain account: the person must exist in the server's domain. Its
/// EasyDC name is their username with the domain, such as `ann@lab.test`.
async fn create_domain_account(
    state: &AppState,
    actor: &str,
    form: &NewAccountForm,
    admin: bool,
    edit: BTreeSet<Area>,
) -> Response {
    let typed = form.domain_user.trim();
    let typed = typed.rsplit('\\').next().unwrap_or(typed);
    let typed = typed.split('@').next().unwrap_or(typed).trim();
    let server = match form.server_id.parse::<i64>() {
        Ok(id) => db::server(&state.db, id).await,
        Err(_) => None,
    };
    let found: Result<(String, String), String> = async {
        let server = server.as_ref().ok_or("Choose the server whose domain the person is in.")?;
        if typed.is_empty() {
            return Err("Enter the person's domain username.".to_string());
        }
        let (mut conn, base_dn) = ldap::open(server).await?;
        let user = ldap::find_domain_user(&mut conn, &base_dn, typed).await?;
        let _ = conn.unbind().await;
        let user = user.ok_or_else(|| format!("{} has no user named {typed}.", server.name))?;
        let name = format!("{}@{}", user.username, ldap::base_dn_to_domain(&base_dn).to_lowercase());
        if db::account_name_taken(&state.db, &name).await {
            return Err(format!("An account named '{name}' already exists."));
        }
        Ok((name, user.username))
    }
    .await;
    let server_id = server.as_ref().map(|s| s.id);
    let (name, domain_user) = match found {
        Ok(f) => f,
        Err(e) => {
            db::log_action(&state.db, actor, "settings.account_create", typed, server_id, &Err(e.clone())).await;
            return render(state, actor, Some(e), None).await;
        }
    };
    let result = db::create_domain_account(&state.db, &name, &domain_user, server_id.unwrap_or_default(), admin, &edit)
        .await
        .map_err(|e| e.to_string());
    let target = format!("{name} ({})", described(admin, &edit));
    db::log_action(&state.db, actor, "settings.account_create", &target, server_id, &result).await;
    match result {
        Err(e) => render(state, actor, Some(e), None).await,
        Ok(()) => Redirect::to("/settings?done=created").into_response(),
    }
}

pub async fn update_permissions(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(username): Path<String>,
    Form(fields): Form<HashMap<String, String>>,
) -> Response {
    let (admin, edit) = read_permissions(&fields);
    let target = format!("{username} ({})", described(admin, &edit));
    // Changing your own would let a slip of the mouse lock you out of
    // Settings; another admin can do it.
    let error = if username == actor {
        Some("You cannot change your own permissions. Another admin can.".to_string())
    } else if !db::account_exists(&state.db, &username).await {
        Some(format!("No account named '{}'.", username))
    } else {
        None
    };
    let result = match error {
        Some(e) => Err(e),
        None => match db::set_permissions(&state.db, &username, admin, &edit).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(format!(
                "{username} is the last local admin, so stays one: someone must be able to sign in while the DC is down. \
                 Make another local account an admin first."
            )),
            Err(e) => Err(e.to_string()),
        },
    };
    db::log_action(&state.db, &actor, "settings.account_permissions", &target, None, &result).await;
    match result {
        Err(e) => render(&state, &actor, Some(e), None).await,
        Ok(()) => Redirect::to("/settings?done=permissions").into_response(),
    }
}

pub async fn delete_account(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(username): Path<String>,
) -> Response {
    // Two guards, both of which would otherwise lock everyone out: deleting the
    // account you are using, and deleting the last admin.
    // The last-admin rule is enforced inside db::delete_account, in the same
    // statement as the delete; these checks only pick the message.
    let error = if username == actor {
        Some("You cannot delete the account you are signed in as.".to_string())
    } else if !db::account_exists(&state.db, &username).await {
        Some(format!("No account named '{}'.", username))
    } else {
        None
    };

    if let Some(e) = error {
        db::log_action(&state.db, &actor, "settings.account_delete", &username, None, &Err(e.clone())).await;
        return render(&state, &actor, Some(e), None).await;
    }

    let result = match db::delete_account(&state.db, &username).await {
        Ok(true) => Ok(()),
        // The account existed a moment ago, so nothing deleted means it was the
        // last local admin — or it vanished in between; either way, report it.
        Ok(false) => Err(format!(
            "{username} is the last local admin, so it stays: someone must be able to sign in while the DC is down."
        )),
        Err(e) => Err(e.to_string()),
    };
    db::log_action(&state.db, &actor, "settings.account_delete", &username, None, &result).await;

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

    use crate::access::{Access, Area};
    use crate::db::Account;

    fn account(name: &str, admin: bool, edit: &[Area]) -> Account {
        let a = Access { username: name.to_string(), admin, edit: edit.iter().copied().collect() };
        Account {
            username: name.to_string(),
            domain: false,
            server_name: None,
            domain_user: String::new(),
            admin,
            two_factor: false,
            edit: a.edit.iter().map(|x| x.key()).collect(),
            summary: a.summary(),
        }
    }

    fn ctx_for(actor: &str, me: Access, accounts: &[Account]) -> Context {
        let mut c = Context::new();
        c.insert("actor", actor);
        c.insert("accounts", accounts);
        c.insert("areas", &super::area_rows());
        c.insert("min_password_len", &super::MIN_PASSWORD_LEN);
        c.insert("access", &me.view());
        c.insert("me_domain", &accounts.iter().any(|a| a.username == actor && a.domain));
        c.insert("servers", &[serde_json::json!({ "id": 2, "name": "LAB" })]);
        c
    }

    fn domain(name: &str, admin: bool, server: Option<&str>) -> Account {
        Account {
            domain: true,
            server_name: server.map(str::to_string),
            domain_user: name.split('@').next().unwrap().to_string(),
            ..account(name, admin, &[])
        }
    }

    #[test]
    fn domain_accounts_are_marked_and_sign_in_with_their_domain_password() {
        let accounts = [account("alice", true, &[]), domain("ann@lab.test", true, Some("LAB")), domain("old@x.test", false, None)];
        let me = Access { username: "alice".into(), admin: true, ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("alice", me, &accounts)).unwrap();
        assert!(html.contains("Domain · LAB"));
        assert!(html.contains("Server removed"));
        assert!(html.contains(r#"name="kind" value="domain""#));
        assert!(html.contains(r#"<option value="2">LAB</option>"#));
        // alice is the only local admin: a domain admin does not count.
        assert!(!html.contains("/settings/accounts/alice/delete"));
        assert!(html.contains("/settings/accounts/ann%40lab%2Etest/delete"), "{html}");

        let me = Access { username: "ann@lab.test".into(), admin: true, ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("ann@lab.test", me, &accounts)).unwrap();
        assert!(!html.contains(r#"name="current_password""#), "the password is not changed here");
        assert!(!html.contains("/settings/accounts/alice/delete"), "alice is still the last local admin");
    }

    /// Signed in as alice, an admin.
    fn ctx(actor: &str, names: &[&str]) -> Context {
        let accounts: Vec<Account> = names.iter().map(|n| account(n, true, &[])).collect();
        ctx_for(actor, Access { username: actor.into(), admin: true, ..Default::default() }, &accounts)
    }

    #[test]
    fn lists_accounts_and_marks_the_current_one() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice", "bob"]))
            .expect("renders");
        assert!(html.contains("alice"));
        assert!(html.contains("bob"));
        assert!(html.contains(">you<"));
        assert!(html.contains("Admin: changes everything"));
    }

    /// The lock-yourself-out cases the handler refuses must not be offered
    /// in the UI either.
    #[test]
    fn offers_nothing_for_your_own_account() {
        let html = tera()
            .render("settings.html", &ctx("alice", &["alice", "bob"]))
            .expect("renders");
        assert!(html.contains("/settings/accounts/bob/delete"));
        assert!(html.contains("/settings/accounts/bob/permissions"));
        assert!(!html.contains("/settings/accounts/alice/"));
    }

    #[test]
    fn offers_no_delete_for_the_last_admin() {
        let accounts = [account("alice", true, &[]), account("bob", true, &[]), account("helpdesk", false, &[])];
        let me = Access { username: "alice".into(), admin: true, ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("alice", me.clone(), &accounts)).unwrap();
        assert!(html.contains("/settings/accounts/bob/delete"), "two admins: either may go");

        let accounts = [account("alice", true, &[]), account("helpdesk", false, &[Area::Users])];
        let html = tera().render("settings.html", &ctx_for("alice", me, &accounts)).unwrap();
        assert!(html.contains("/settings/accounts/helpdesk/delete"), "not an admin, so it can go");
        assert!(html.contains("Edit: Users"));
    }

    #[test]
    fn the_permission_grid_shows_what_an_account_may_change() {
        let accounts = [account("alice", true, &[]), account("helpdesk", false, &[Area::Users, Area::DnsRecords])];
        let me = Access { username: "alice".into(), admin: true, ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("alice", me, &accounts)).unwrap();
        // The new-account form, and helpdesk's dialog with its two Edit areas.
        assert!(html.contains(r#"name="area_users" value="edit"
                            id="acct2-users-edit" checked"#), "{html}");
        assert!(html.contains(r#"id="acct2-dns_records-edit" checked"#));
        assert!(html.contains(r#"id="acct2-groups-view" checked"#));
        assert!(html.contains(r#"id="new-users-view" checked"#), "a new account starts on View");
        assert!(html.contains("Add account"));
        assert!(html.contains("DNS zones") && html.contains("create and delete zones"));
    }

    #[test]
    fn someone_who_is_not_an_admin_only_sees_the_list() {
        let accounts = [account("alice", true, &[]), account("helpdesk", false, &[Area::Users])];
        let me = Access { username: "helpdesk".into(), edit: [Area::Users].into(), ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("helpdesk", me, &accounts)).unwrap();
        assert!(!html.contains("/settings/accounts/"), "no add, change or remove");
        assert!(html.contains("Your permissions: Edit: Users."));
        assert!(html.contains(r#"href="/account""#), "they change their own password from the top bar");
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
        let c = super::super::servers::tests_support::empty_audit_context();
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
        assert!(html.contains("/settings/accounts/o%27brien/delete"));
        assert!(html.contains("/settings/accounts/a%2Fb/delete"));
        assert!(html.contains(r#"data-account="o&#x27;brien""#));
    }

    #[test]
    fn permission_fields_are_read_from_the_form() {
        let f = |pairs: &[(&str, &str)]| {
            super::read_permissions(&pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
        };
        assert_eq!(f(&[]), (false, Default::default()));
        let (admin, edit) = f(&[("area_users", "edit"), ("area_gpos", "view"), ("area_bogus", "edit"), ("admin", "on")]);
        assert!(admin);
        assert_eq!(edit, [Area::Users].into());
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

    fn tls_info(uploaded: bool, days_left: i32) -> crate::tls::Info {
        crate::tls::Info {
            name: "easydc-01".into(),
            issuer: if uploaded { "Example CA".into() } else { "easydc-01".into() },
            names: vec!["easydc-01".into(), "localhost".into()],
            not_after: "Feb 25 10:00:00 2029 GMT".into(),
            days_left,
            expired: days_left < 0,
            fingerprint: "AA:BB:CC".into(),
            uploaded,
        }
    }

    #[test]
    fn the_certificate_card_shows_what_is_served() {
        let render = |tls: Option<crate::tls::Info>, admin: bool| {
            let me = Access { username: "root".into(), admin, ..Default::default() };
            let mut c = ctx_for("root", me, &[account("root", admin, &[])]);
            if let Some(t) = tls {
                c.insert("tls", &t);
            }
            tera().render("settings.html", &c).unwrap()
        };
        let html = render(Some(tls_info(false, 800)), true);
        assert!(html.contains("HTTPS certificate") && html.contains("Self-signed"));
        assert!(html.contains("AA:BB:CC") && html.contains("easydc-01, localhost"));
        assert!(html.contains(r#"action="/settings/certificate""#));
        assert!(html.contains(r#"action="/settings/certificate/generate""#));

        let html = render(Some(tls_info(true, 12)), true);
        assert!(html.contains("Example CA") && html.contains("Expires in 12 days"));

        let html = render(Some(tls_info(true, -1)), true);
        assert!(html.contains("Expired"));

        let html = render(Some(tls_info(false, 800)), false);
        assert!(html.contains("AA:BB:CC"), "anyone can see which certificate is served");
        assert!(!html.contains(r#"action="/settings/certificate""#), "only an admin can change it");

        let html = render(None, true);
        assert!(html.contains("EASYDC_TLS=off") && !html.contains(r#"action="/settings/certificate""#));
    }

    #[test]
    fn the_two_factor_card_and_its_admin_controls() {
        let mut bob = account("bob", false, &[]);
        bob.two_factor = true;
        let accounts = [account("alice", true, &[]), bob, account("carol", false, &[])];
        let me = Access { username: "alice".into(), admin: true, ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("alice", me, &accounts)).unwrap();
        assert!(html.contains(r#"href="/account/two-factor""#));
        assert!(html.contains(r#"action="/settings/two-factor/require""#));
        assert!(html.contains("/settings/accounts/bob/two-factor/reset"));
        assert!(!html.contains("/settings/accounts/carol/two-factor/reset"), "carol has none to reset");

        let me = Access { username: "carol".into(), ..Default::default() };
        let html = tera().render("settings.html", &ctx_for("carol", me, &accounts)).unwrap();
        assert!(html.contains(r#"href="/account/two-factor""#), "anyone can set up their own");
        assert!(!html.contains("/settings/two-factor/require") && !html.contains("two-factor/reset"));
    }

    #[tokio::test]
    async fn a_page_opens_on_the_tab_of_its_change() {
        use crate::access::{scope, Access};
        let q = |tab: Option<&str>, done: Option<&str>| super::SettingsQuery { tab: tab.map(String::from), done: done.map(String::from), entries: 0, files: 0, to_files: false };
        let admin = Access { username: "a".into(), admin: true, ..Default::default() };
        scope(admin, async {
            assert_eq!(super::tab_for(&q(None, None)), "accounts");
            assert_eq!(super::tab_for(&q(Some("https"), None)), "https");
            assert_eq!(super::tab_for(&q(Some("audit-log"), None)), "audit-log");
            assert_eq!(super::tab_for(&q(None, Some("audit_saved"))), "audit-log");
            assert_eq!(super::tab_for(&q(None, Some("certificate"))), "https");
            assert_eq!(super::tab_for(&q(None, Some("two_factor_required"))), "two-factor");
            assert_eq!(super::tab_for(&q(None, Some("two_factor_reset"))), "accounts");
            assert_eq!(super::tab_for(&q(Some("<x>"), None)), "accounts");
        })
        .await;
        let viewer = Access { username: "v".into(), ..Default::default() };
        scope(viewer, async {
            assert_eq!(super::tab_for(&q(Some("two-factor"), None)), "accounts", "that tab is for admins");
            assert_eq!(super::tab_for(&q(Some("https"), None)), "https");
        })
        .await;
    }

    #[test]
    fn done_codes_map_to_messages() {
        assert!(super::done_message("created").is_some());
        assert!(super::done_message("deleted").is_some());
        assert!(super::done_message("permissions").is_some());
        // An unknown or hand-typed code shows no banner rather than echoing it.
        assert!(super::done_message("<script>").is_none());
    }
}
