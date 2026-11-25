use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tera::Context;

use crate::{auth::CurrentUser, db, health, ldap, models::Server, remediate, AppState};

/// The last report for each server, as it came from the directory. Hiding or
/// showing a finding shows it again instead of waiting for a fresh check.
type Kept = HashMap<(i64, String), (Instant, health::HealthReport)>;
static LAST: Mutex<Option<Kept>> = Mutex::new(None);
const LAST_KEPT: Duration = Duration::from_secs(600);

#[derive(Deserialize, Default)]
pub struct HealthQuery {
    #[serde(default)]
    kept: String,
    #[serde(default)]
    done: String,
}

pub async fn health_check(State(state): State<AppState>, Path(id): Path<i64>, Query(query): Query<HealthQuery>) -> Response {
    let server = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);

    let Some(server) = server else {
        return Redirect::to("/").into_response();
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    if matches!(query.done.as_str(), "hidden" | "shown" | "failed") {
        ctx.insert("done", &query.done);
    }

    // Diagnostics are read-only, so nothing here is written to the audit log.
    let key = (id, server.ldap_url.clone());
    let kept = (query.kept == "1")
        .then(|| LAST.lock().ok()?.as_ref()?.get(&key).filter(|(at, _)| at.elapsed() < LAST_KEPT).map(|(_, r)| r.clone()))
        .flatten();
    let report = match kept {
        Some(r) => Ok(r),
        None => health::run(&server).await,
    };
    match report {
        Ok(report) => {
            if let Ok(mut last) = LAST.lock() {
                last.get_or_insert_with(Default::default).insert(key, (Instant::now(), report.clone()));
            }
            let hidden = db::hidden_findings(&state.db, id).await;
            ctx.insert("report", &report.with_hidden(&hidden));
        }
        Err(e) => ctx.insert("error", &e),
    }

    Html(crate::access::render(&state.tera, "health.html", &ctx)).into_response()
}

// ── hiding findings ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct HideForm {
    check: String,
    #[serde(default)]
    fingerprint: String,
    /// "changed": until the finding changes; "always": whatever it finds.
    #[serde(default)]
    mode: String,
    #[serde(default)]
    reason: String,
}

/// What a hide form asks for, checked: the check, and the fingerprint to keep
/// (empty for "always").
fn hide_request(form: &HideForm) -> Result<(&'static str, String, String), String> {
    let check = health::CHECK_IDS.iter().find(|c| **c == form.check).ok_or_else(|| format!("Unknown check '{}'", form.check))?;
    let fingerprint = match form.mode.as_str() {
        "always" => String::new(),
        "changed" if form.fingerprint.len() == 32 && form.fingerprint.bytes().all(|b| b.is_ascii_hexdigit()) => form.fingerprint.clone(),
        "changed" => return Err("The finding to hide was not given.".into()),
        _ => return Err("Choose how long to hide it.".into()),
    };
    let reason: String = form.reason.trim().chars().take(200).collect();
    Ok((check, fingerprint, reason))
}

pub async fn health_hide(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<HideForm>,
) -> Response {
    let result = match hide_request(&form) {
        Ok((check, fingerprint, reason)) => {
            let result = db::hide_finding(&state.db, id, check, &fingerprint, &reason, &actor).await;
            let how = if fingerprint.is_empty() { "always" } else { "until it changes" };
            let target = if reason.is_empty() { format!("{check} ({how})") } else { format!("{check} ({how}): {reason}") };
            db::log_action(&state.db, &actor, "health.hide", &target, Some(id), &result).await;
            result
        }
        Err(e) => Err(e),
    };
    finish(id, result, "hidden")
}

#[derive(Deserialize)]
pub struct ShowForm {
    check: String,
}

pub async fn health_show(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<ShowForm>,
) -> Response {
    let result = match health::CHECK_IDS.iter().find(|c| **c == form.check) {
        Some(check) => {
            let result = db::show_finding(&state.db, id, Some(check)).await;
            db::log_action(&state.db, &actor, "health.show", check, Some(id), &result).await;
            result
        }
        None => Err(format!("Unknown check '{}'", form.check)),
    };
    finish(id, result, "shown")
}

/// Back to the report just seen, with a word on how it went. The audit log
/// has the reason when it failed.
fn finish(id: i64, result: Result<(), String>, done: &str) -> Response {
    let done = if result.is_ok() { done } else { "failed" };
    Redirect::to(&format!("/servers/{id}/health?kept=1&done={done}")).into_response()
}

// ── guided fixes ──────────────────────────────────────────────────────────────

/// The keys a fix form submitted. Checkboxes are named t0, t1, … so the form
/// deserialises as a plain map — urlencoded forms have no list type.
fn submitted_keys(form: &HashMap<String, String>) -> Vec<String> {
    let mut keys: Vec<String> = form
        .iter()
        .filter(|(k, _)| k.len() > 1 && k.starts_with('t') && k[1..].bytes().all(|b| b.is_ascii_digit()))
        .map(|(_, v)| v.clone())
        .collect();
    keys.sort();
    keys.dedup();
    keys
}

/// Two steps on one route. `stage=preview` lists exactly what would change;
/// `stage=apply` re-plans from a fresh scan — never from the preview — and
/// applies what still qualifies, one audit entry per change.
pub async fn health_fix(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let server = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    let Some(server) = server else {
        return Redirect::to("/").into_response();
    };

    let kind = form.get("kind").cloned().unwrap_or_default();
    let applying = form.get("stage").map(String::as_str) == Some("apply");
    let keys = submitted_keys(&form);

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    ctx.insert("kind", &kind);
    ctx.insert("keys", &keys);

    let render = |ctx: &Context| {
        Html(crate::access::render(&state.tera, "health_fix.html", ctx)).into_response()
    };

    if !remediate::known_kind(&kind) {
        ctx.insert("error", &format!("Unknown fix '{}'", kind));
        return render(&ctx);
    }
    if keys.is_empty() {
        ctx.insert("error", "Nothing was selected.");
        return render(&ctx);
    }

    let (mut conn, base_dn) = match ldap::open(&server).await {
        Ok(c) => c,
        Err(e) => {
            ctx.insert("error", &e);
            return render(&ctx);
        }
    };

    let plan = match remediate::plan(&mut conn, &base_dn, &kind, &keys).await {
        Ok(p) => p,
        Err(e) => {
            ctx.insert("error", &e);
            return render(&ctx);
        }
    };
    ctx.insert("skipped", &plan.skipped);

    if !applying {
        let preview: Vec<String> = plan.changes.iter().map(|c| c.describe()).collect();
        ctx.insert("stage", "preview");
        ctx.insert("preview", &preview);
        return render(&ctx);
    }

    let mut outcomes: Vec<(String, Option<String>)> = Vec::new();
    for change in &plan.changes {
        let result = remediate::apply(&mut conn, change).await;
        let (action, target) = change.audit();
        db::log_action(&state.db, &actor, action, &target, Some(id), &result).await;
        outcomes.push((change.describe(), result.err()));
    }
    let failed = outcomes.iter().filter(|(_, e)| e.is_some()).count();

    ctx.insert("stage", "done");
    ctx.insert("outcomes", &outcomes);
    ctx.insert("failed", &failed);
    render(&ctx)
}

#[cfg(test)]
mod tests {
    use crate::health::{CheckResult, HealthReport, FAIL, PASS, SKIP, WARN};
    use crate::models::Server;
    use tera::{Context, Tera};

    /// The handler renders with `unwrap_or_default()`, so a broken template
    /// would surface as a blank page rather than an error. Render it here
    /// against a synthetic report so template breakage fails the build.
    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn check(status: &'static str, remediation: Option<&str>) -> CheckResult {
        CheckResult {
            id: "sample",
            category: "DNS",
            title: "Sample check",
            status,
            summary: "A one-line verdict".to_string(),
            detail: vec!["detail line one".to_string(), "detail line two".to_string()],
            remediation: remediation.map(String::from),
            fixes: Vec::new(),
            link: None,
            fingerprint: String::new(),
            hidden: None,
        }
    }

    fn server() -> Server {
        Server {
            id: 1,
            name: "Test DC".to_string(),
            ldap_url: "ldaps://dc.example.com".to_string(),
            bind_dn: "CN=Administrator,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    #[test]
    fn renders_a_full_report() {
        let report = HealthReport {
            domain: "example.com".to_string(),
            base_dn: "DC=example,DC=com".to_string(),
            checks: vec![
                check(PASS, None),
                check(WARN, Some("do the thing")),
                check(FAIL, Some("do the other thing")),
                check(SKIP, None),
            ],
            pass_count: 1,
            warn_count: 1,
            fail_count: 1,
            skip_count: 1,
            hidden_count: 0,
            elapsed_ms: 1234,
        };

        let mut ctx = Context::new();
        ctx.insert("server", &server());
        ctx.insert("report", &report);

        let html = tera().render("health.html", &ctx).expect("health.html renders");
        assert!(html.contains("Health check"));
        assert!(html.contains("A one-line verdict"));
        assert!(html.contains("do the other thing"));
        assert!(html.contains("example.com"));
        // The bind password must never reach the page.
        assert!(!html.contains("secret"));
    }

    #[test]
    fn a_warning_offers_hide_and_a_hidden_one_offers_show() {
        let mut warn = check(WARN, None);
        warn.id = "delegation";
        warn.fingerprint = "ab".repeat(16);
        let mut gone = check(FAIL, None);
        gone.id = "anonymous_bind";
        gone.summary = "the accepted one".into();
        gone.hidden = Some(crate::health::HiddenNote { until_changed: false, reason: "lab only".into(), by: "admin".into(), on: "2026-11-25".into() });
        let report = HealthReport {
            domain: "example.com".into(),
            base_dn: "DC=example,DC=com".into(),
            checks: vec![check(PASS, None), warn, gone],
            pass_count: 1,
            warn_count: 1,
            fail_count: 0,
            skip_count: 0,
            hidden_count: 1,
            elapsed_ms: 1,
        };
        let mut ctx = Context::new();
        ctx.insert("server", &server());
        ctx.insert("report", &report);
        ctx.insert("done", "hidden");
        let html = tera().render("health.html", &ctx).expect("renders");
        let flat = html.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(&format!(r#"data-check="delegation" data-fingerprint="{}""#, "ab".repeat(16))));
        assert_eq!(flat.matches("data-bs-target=\"#hideModal\"").count(), 1, "only the shown warning can be hidden");
        assert!(flat.contains(r#"data-status="hidden" style="display:none""#));
        assert!(flat.contains(r#"action="/servers/1/health/show""#));
        assert!(flat.contains(r#"name="check" value="anonymous_bind""#));
        assert!(flat.contains("Hidden 1"));
        assert!(flat.contains("whatever this check finds"));
        assert!(html.contains("lab only"));
        assert!(html.contains("no longer counts"));
    }

    #[test]
    fn a_hide_form_is_checked() {
        use super::{hide_request, HideForm};
        let form = |check: &str, fingerprint: &str, mode: &str| HideForm { check: check.into(), fingerprint: fingerprint.into(), mode: mode.into(), reason: "  why  ".into() };
        let fp = "0123456789abcdef".repeat(2);
        assert_eq!(hide_request(&form("delegation", &fp, "changed")), Ok(("delegation", fp.clone(), "why".into())));
        assert_eq!(hide_request(&form("delegation", &fp, "always")), Ok(("delegation", String::new(), "why".into())));
        assert!(hide_request(&form("no_such_check", &fp, "always")).is_err());
        assert!(hide_request(&form("delegation", "", "changed")).is_err(), "until it changes needs the finding");
        assert!(hide_request(&form("delegation", "not hex", "changed")).is_err());
        assert!(hide_request(&form("delegation", &fp, "")).is_err());
    }

    #[test]
    fn renders_the_unreachable_case() {
        let mut ctx = Context::new();
        ctx.insert("server", &server());
        ctx.insert("error", "Bind failed: invalid credentials");

        let html = tera().render("health.html", &ctx).expect("health.html renders");
        assert!(html.contains("Could not reach the directory"));
        assert!(html.contains("invalid credentials"));
    }

    #[test]
    fn server_detail_links_to_the_health_page() {
        let mut ctx = Context::new();
        ctx.insert("server", &server());
        let html = tera().render("server_detail.html", &ctx).expect("renders");
        assert!(html.contains("/servers/1/health"));
        assert!(!html.contains("data-without-two-factor="), "said only when someone is without it");

        ctx.insert("without_two_factor", &vec!["admin", "o'neil"]);
        let html = tera().render("server_detail.html", &ctx).expect("renders");
        assert!(html.contains(r#"data-without-two-factor="[&quot;admin&quot;,&quot;o&#x27;neil&quot;]""#), "{}", &html[html.find("id=\"attention\"").unwrap()..][..120]);
    }
}

#[cfg(test)]
mod fix_tests {
    use super::submitted_keys;
    use crate::health::{CheckResult, HealthReport, WARN};
    use crate::models::Server;
    use crate::remediate::{Fix, FixTarget};
    use std::collections::HashMap;
    use tera::{Context, Tera};

    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn server() -> Server {
        Server {
            id: 1,
            name: "DC1".into(),
            ldap_url: "ldaps://dc1".into(),
            bind_dn: "CN=Administrator".into(),
            bind_password: "secret".into(),
            skip_tls: true,
        }
    }

    #[test]
    fn only_target_fields_are_collected() {
        let form: HashMap<String, String> = [
            ("kind", "disable_stale_computers"),
            ("stage", "preview"),
            ("t0", "aaaa"),
            ("t1", "bbbb"),
            ("t1x", "not-a-target"),
            ("t", "not-a-target"),
            ("token", "not-a-target"),
            ("t2", "aaaa"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
        assert_eq!(submitted_keys(&form), vec!["aaaa", "bbbb"]);
    }

    fn report_with_fix() -> HealthReport {
        let mut check = CheckResult {
            id: "stale_computers",
            category: "Hygiene",
            title: "Stale computer accounts",
            status: WARN,
            summary: "2 computers inactive for over 90 days".into(),
            detail: vec![],
            remediation: Some("Disable rather than delete first.".into()),
            fixes: vec![],
            link: None,
            fingerprint: String::new(),
            hidden: None,
        };
        check.fixes.push(Fix {
            kind: "disable_stale_computers",
            label: "Disable selected computers".into(),
            explain: "Re-enable on the Computers page.".into(),
            targets: vec![
                FixTarget { key: "k1".into(), label: "GAMES$ — last logon 620 days ago".into() },
                FixTarget { key: "k2".into(), label: "ROUGE$ — last logon 530 days ago".into() },
            ],
        });
        HealthReport {
            domain: "hakim.family".into(),
            base_dn: "DC=hakim,DC=family".into(),
            checks: vec![check],
            pass_count: 0,
            warn_count: 1,
            fail_count: 0,
            skip_count: 0,
            hidden_count: 0,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn a_fix_renders_as_a_preview_form_with_its_targets() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("report", &report_with_fix());
        let html = tera().render("health.html", &c).expect("renders");
        assert!(html.contains(r#"action="/servers/1/health/fix""#));
        assert!(html.contains(r#"name="stage" value="preview""#), "the first step is always a preview");
        // Attributes wrap across lines in the template, so compare with the
        // whitespace collapsed.
        let flat = html.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(flat.contains(r#"name="t0" value="k1""#));
        assert!(flat.contains(r#"name="t1" value="k2""#));
        assert!(html.contains("GAMES$ — last logon 620 days ago"));
    }

    #[test]
    fn the_preview_page_lists_changes_and_carries_the_keys_forward() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("kind", "disable_stale_computers");
        c.insert("keys", &vec!["k1", "k2"]);
        c.insert("stage", "preview");
        c.insert("preview", &vec!["Disable computer GAMES$ (last logon 620 days ago)"]);
        c.insert("skipped", &1usize);
        let html = tera().render("health_fix.html", &c).expect("renders");
        assert!(html.contains("Disable computer GAMES$"));
        assert!(html.contains(r#"name="stage" value="apply""#));
        assert!(html.contains(r#"name="t1" value="k2""#));
        assert!(html.contains("Apply 1 change"));
        assert!(html.contains("no longer need fixing"));
    }

    #[test]
    fn the_result_page_shows_each_outcome() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("kind", "disable_stale_computers");
        c.insert("keys", &Vec::<String>::new());
        c.insert("stage", "done");
        c.insert(
            "outcomes",
            &vec![
                ("Disable computer GAMES$".to_string(), None::<String>),
                ("Disable computer ROUGE$".to_string(), Some("insufficient access".to_string())),
            ],
        );
        c.insert("failed", &1usize);
        c.insert("skipped", &0usize);
        let html = tera().render("health_fix.html", &c).expect("renders");
        assert!(html.contains("Done, with 1 failure"));
        assert!(html.contains("insufficient access"));
        assert!(!html.contains("secret"));
    }
}
