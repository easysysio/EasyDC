//! The Reports page, and each report as a CSV file. Nothing here changes the
//! directory, so every account may see them, as with every other page.

use axum::{
    extract::{Path, Query, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use tera::Context;

use super::{ldap_mgmt::get_server, users_csv::file_name_part};
use crate::{
    access, db, ldap,
    reports::{self, Directory, Kind, KINDS},
    AppState,
};

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ReportQuery {
    report: String,
    /// Text, so that a mistyped number falls back instead of failing the page.
    days: Option<String>,
}

impl ReportQuery {
    fn kind(&self) -> Kind {
        Kind::from_key(&self.report).unwrap_or(Kind::Inactive)
    }
}

#[derive(Serialize)]
struct Tab {
    key: &'static str,
    title: &'static str,
    icon: &'static str,
    count: usize,
    active: bool,
}

async fn read(server: &crate::models::Server, kind: Kind, days: Option<i64>, now: i64) -> Result<Directory, String> {
    let expiring = if kind == Kind::Expiring { days } else { None };
    let expiring = expiring.or(Kind::Expiring.days().map(|d| d.0)).unwrap_or(14);
    let (mut conn, base_dn) = ldap::open(server).await?;
    let result = reports::read(&mut conn, &base_dn, expiring, now).await;
    drop(conn);
    result
}

pub async fn page(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<ReportQuery>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let kind = q.kind();
    let days = kind.days_from(q.days.as_deref());
    let now = db::unix_now();

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    ctx.insert("report_key", kind.key());
    ctx.insert("title", kind.title());
    ctx.insert("about", kind.about());
    ctx.insert("icon", kind.icon());
    if let (Some(d), Some((_, low, high))) = (days, kind.days()) {
        ctx.insert("days", &d);
        ctx.insert("days_min", &low);
        ctx.insert("days_max", &high);
    }
    match read(&server, kind, days, now).await {
        Ok(dir) => {
            let tabs: Vec<Tab> = KINDS
                .into_iter()
                .map(|k| Tab {
                    key: k.key(),
                    title: k.title(),
                    icon: k.icon(),
                    count: reports::build(k, &dir, if k == kind { days } else { None }, now).rows.len(),
                    active: k == kind,
                })
                .collect();
            ctx.insert("tabs", &tabs);
            ctx.insert("table", &reports::build(kind, &dir, days, now));
        }
        Err(e) => {
            let tabs: Vec<serde_json::Value> = KINDS
                .into_iter()
                .map(|k| serde_json::json!({ "key": k.key(), "title": k.title(), "icon": k.icon(), "active": k == kind }))
                .collect();
            ctx.insert("tabs", &tabs);
            ctx.insert("error", &e);
        }
    }
    Html(access::render(&state.tera, "reports.html", &ctx)).into_response()
}

pub async fn export(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<ReportQuery>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let kind = q.kind();
    let days = kind.days_from(q.days.as_deref());
    let now = db::unix_now();
    let dir = match read(&server, kind, days, now).await {
        Ok(d) => d,
        Err(e) => return (StatusCode::BAD_GATEWAY, format!("The report could not be read: {e}")).into_response(),
    };
    let body = reports::to_csv(&reports::build(kind, &dir, days, now));
    let file = format!("{}-{}.csv", kind.key(), file_name_part(&server.name));
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reports::{Account, Group};
    use tera::Tera;

    const NOW: i64 = 1_800_000_000;

    fn render(kind: Kind, error: Option<&str>) -> String {
        let mut t = Tera::new("templates/**/*.html").unwrap();
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        let dir = Directory {
            accounts: vec![Account {
                dn: "CN=<b>x</b>,DC=x".into(),
                name: "<b>x</b>".into(),
                enabled: false,
                locked: true,
                ..Default::default()
            }],
            groups: vec![Group {
                dn: "CN=Sales/EMEA,DC=x".into(),
                name: "Sales/EMEA".into(),
                sid: "S-1-5-21-1-2-3-1500".into(),
                ..Default::default()
            }],
            passwords_expire: true,
        };
        let days = kind.days_from(None);
        let mut c = Context::new();
        let me = crate::access::Access { username: "viewer".into(), ..Default::default() };
        c.insert("access", &me.view());
        c.insert("server", &serde_json::json!({ "id": 7, "name": "LAB" }));
        c.insert("report_key", kind.key());
        c.insert("title", kind.title());
        c.insert("about", kind.about());
        c.insert("icon", kind.icon());
        if let (Some(d), Some((_, low, high))) = (days, kind.days()) {
            c.insert("days", &d);
            c.insert("days_min", &low);
            c.insert("days_max", &high);
        }
        let tabs: Vec<Tab> = KINDS
            .into_iter()
            .map(|k| Tab { key: k.key(), title: k.title(), icon: k.icon(), count: 3, active: k == kind })
            .collect();
        c.insert("tabs", &tabs);
        match error {
            Some(e) => c.insert("error", e),
            None => c.insert("table", &reports::build(kind, &dir, days, NOW)),
        }
        t.render("reports.html", &c).unwrap()
    }

    #[test]
    fn every_report_renders_with_its_export() {
        for k in KINDS {
            let html = render(k, None);
            assert!(html.contains(k.title()), "{}", k.key());
            assert!(html.contains(&format!("/servers/7/reports/export?report={}", k.key())), "{}", k.key());
        }
    }

    #[test]
    fn values_from_the_directory_are_escaped_and_statuses_are_badges() {
        let html = render(Kind::Problems, None);
        assert!(!html.contains("<b>x</b>") && html.contains("&lt;b&gt;x"));
        assert!(html.contains(">Locked</span>") && html.contains(">Disabled</span>"));
    }

    #[test]
    fn a_group_links_to_its_members() {
        assert!(render(Kind::Empty, None).contains("/servers/7/groups/Sales%2FEMEA/members"));
    }

    #[test]
    fn the_days_box_is_only_on_reports_that_use_it() {
        assert!(render(Kind::Inactive, None).contains(r#"name="days""#));
        assert!(render(Kind::Expiring, None).contains(r#"name="days""#));
        assert!(!render(Kind::Privileged, None).contains(r#"name="days""#));
    }

    #[test]
    fn a_dc_that_cannot_be_reached_is_explained() {
        let html = render(Kind::Inactive, Some("Could not connect"));
        assert!(html.contains("Could not connect") && !html.contains("Download CSV"));
    }
}
