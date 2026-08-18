use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use tera::Context;

use crate::{health, models::Server, AppState};

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
