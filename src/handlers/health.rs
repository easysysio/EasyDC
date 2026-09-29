use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use std::collections::HashMap;
use tera::Context;

use crate::{auth::CurrentUser, db, health, ldap, models::Server, remediate, AppState};

pub async fn health_check(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
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

    // Diagnostics are read-only, so nothing here is written to the audit log.
    match health::run(&server).await {
        Ok(report) => ctx.insert("report", &report),
        Err(e) => ctx.insert("error", &e),
    }

    Html(state.tera.render("health.html", &ctx).unwrap_or_default()).into_response()
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
        Html(state.tera.render("health_fix.html", ctx).unwrap_or_default()).into_response()
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
            elapsed_ms: 1234,
        };

        let mut ctx = Context::new();
        ctx.insert("server", &server());
        ctx.insert("report", &report);

        let html = tera().render("health.html", &ctx).expect("health.html renders");
        assert!(html.contains("Domain Health Check"));
        assert!(html.contains("A one-line verdict"));
        assert!(html.contains("do the other thing"));
        assert!(html.contains("example.com"));
        // The bind password must never reach the page.
        assert!(!html.contains("secret"));
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
