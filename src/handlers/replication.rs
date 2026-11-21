//! The Replication page: every DC's inbound partners and their state.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
};
use tera::Context;

use crate::{models::Server, replication, AppState};

pub async fn replication(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
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
    match replication::report(&server).await {
        Ok(r) => ctx.insert("report", &r),
        Err(e) => ctx.insert("error", &e),
    }
    Html(state.tera.render("replication.html", &ctx).unwrap_or_default()).into_response()
}

#[cfg(test)]
mod tests {
    use crate::models::Server;
    use crate::replication::{DcStatus, Link, Report};
    use tera::{Context, Tera};

    fn render(dcs: Vec<DcStatus>) -> String {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        let report = Report { dcs, ..Default::default() }.tally();
        let mut c = Context::new();
        c.insert("server", &Server {
            id: 1,
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        });
        c.insert("report", &report);
        t.render("replication.html", &c).unwrap()
    }

    fn link(partition: &str, source: &str, status: &'static str, note: &str) -> Link {
        Link {
            partition: partition.to_string(),
            source: source.to_string(),
            last_success: "2026-11-16 08:56 UTC".to_string(),
            ago: "2 min ago".to_string(),
            status,
            note: note.to_string(),
        }
    }

    fn dc(name: &str, links: Vec<Link>, error: Option<&str>) -> DcStatus {
        DcStatus {
            name: name.to_string(),
            host: format!("{}.example.com", name.to_lowercase()),
            site: "Default-First-Site-Name".to_string(),
            configured: name == "DC1",
            error: error.map(str::to_string),
            links,
        }
    }

    #[test]
    fn all_healthy() {
        let html = render(vec![
            dc("DC1", vec![link("Domain", "DC2", "ok", ""), link("Schema", "DC2", "ok", "")], None),
            dc("DC2", vec![link("Domain", "DC1", "ok", "")], None),
        ]);
        assert!(html.contains("All 3 links healthy"));
        assert!(html.contains("2 min ago"));
        assert!(html.contains(">connected<"));
        assert!(!html.contains("bi-x-circle"));
    }

    #[test]
    fn failures_and_unreachable_dcs_stand_out() {
        let html = render(vec![
            dc("DC1", vec![link("Domain", "DC2", "fail", "3 failed attempts in a row: the RPC server is unavailable")], None),
            dc("DC2", vec![], Some("ldaps://dc2.example.com: Connection failed: timed out")),
            dc("DC3", vec![], None),
        ]);
        assert!(html.contains("1 failing"));
        assert!(html.contains("1 DC not reachable"));
        assert!(html.contains("the RPC server is unavailable"));
        assert!(html.contains("Could not read this DC: ldaps:"), "Tera escapes the slashes");
        assert!(html.contains("No inbound replication partners"));
        assert!(html.contains("1 DC receives from no one"));
        assert!(!html.contains("links healthy"));
    }

    #[test]
    fn a_dc_with_no_partners_is_not_called_healthy() {
        let html = render(vec![
            dc("DC1", vec![], None),
            dc("DC2", vec![link("Domain", "DC1", "ok", ""), link("Schema", "DC1", "ok", "")], None),
        ]);
        assert!(!html.contains("links healthy"), "{html}");
        assert!(html.contains("1 DC receives from no one"));
        assert!(html.contains("2 healthy"));
        assert!(html.contains("about 10 minutes"), "a DC that has just joined is explained");
    }

    #[test]
    fn a_single_dc_has_nothing_to_replicate() {
        let html = render(vec![dc("DC1", vec![], None)]);
        assert!(html.contains("single domain controller"));
    }

    #[test]
    fn hostile_values_are_escaped() {
        let html = render(vec![
            dc("DC1", vec![link("<img src=a>", "<img src=b>", "warn", "<img src=c>")], None),
            dc("<img src=d>", vec![], Some("<img src=e>")),
        ]);
        assert!(!html.contains("<img"));
    }
}
