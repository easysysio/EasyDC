use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{auth::CurrentUser, db, models::Server, AppState};

// ── audit log view ─────────────────────────────────────────────────────────────

/// The Audit Log page: a search, "failures only", and a page number.
#[derive(Deserialize, Default)]
pub struct AuditView {
    #[serde(default)]
    pub q: String,
    /// "1" for failures only.
    #[serde(default)]
    pub failures: String,
    /// Text, so that a mistyped page number is page 1 rather than an error.
    #[serde(default)]
    pub page: String,
}

const AUDIT_PAGE_SIZE: i64 = 100;

pub async fn audit(State(state): State<AppState>, Query(view): Query<AuditView>) -> impl IntoResponse {
    let failures = view.failures == "1";
    let wanted = view.page.trim().parse::<i64>().unwrap_or(1).max(1);
    let (mut entries, mut total) = (Vec::new(), 0);
    let mut error = None;
    match db::search_audit(&state.db, &view.q, failures, AUDIT_PAGE_SIZE, (wanted - 1) * AUDIT_PAGE_SIZE).await {
        Ok(found) => (entries, total) = found,
        Err(e) => error = Some(format!("The audit log could not be read: {e}")),
    }
    let ctx = audit_context(&view, failures, wanted, entries, total, error);
    Html(state.tera.render("audit.html", &ctx).unwrap_or_default())
}

fn audit_context(
    view: &AuditView,
    failures: bool,
    page: i64,
    entries: Vec<crate::models::AuditEntry>,
    total: i64,
    error: Option<String>,
) -> Context {
    let pages = ((total + AUDIT_PAGE_SIZE - 1) / AUDIT_PAGE_SIZE).max(1);
    let first = (page - 1) * AUDIT_PAGE_SIZE + 1;
    // Links keep the search and the filter.
    let mut keep = Vec::new();
    if !view.q.trim().is_empty() {
        keep.push(("q", view.q.trim()));
    }
    if failures {
        keep.push(("failures", "1"));
    }
    let qs = keep.iter().map(|(k, v)| format!("{k}={}", super::path_segment(v))).collect::<Vec<_>>().join("&");
    let mut ctx = Context::new();
    ctx.insert("q", view.q.trim());
    ctx.insert("failures", &failures);
    ctx.insert("filtered", &!keep.is_empty());
    ctx.insert("entries", &entries);
    ctx.insert("total", &total);
    ctx.insert("first", &first);
    ctx.insert("last", &(first + entries.len() as i64 - 1));
    ctx.insert("page", &page);
    ctx.insert("pages", &pages);
    ctx.insert("page_links", &page_links(page, pages));
    ctx.insert("link", &if qs.is_empty() { "/audit?".to_string() } else { format!("/audit?{qs}&") });
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    ctx
}

/// The page numbers to offer: the first and last, and two either side of
/// this one; 0 marks a gap.
fn page_links(page: i64, pages: i64) -> Vec<i64> {
    let mut want: Vec<i64> = [1, pages, page - 2, page - 1, page, page + 1, page + 2]
        .into_iter()
        .filter(|n| (1..=pages).contains(n))
        .collect();
    want.sort_unstable();
    want.dedup();
    let mut out = Vec::new();
    for n in want {
        if out.last().is_some_and(|last| n - last > 1) {
            out.push(0);
        }
        out.push(n);
    }
    out
}

pub async fn dashboard(State(state): State<AppState>) -> impl IntoResponse {
    let servers = sqlx::query_as::<_, Server>("SELECT * FROM servers ORDER BY name")
        .fetch_all(&state.db)
        .await
        .unwrap_or_default();

    let mut ctx = Context::new();
    ctx.insert("servers", &servers);
    Html(state.tera.render("dashboard.html", &ctx).unwrap_or_default())
}

pub async fn server_detail(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let server = sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap();

    match server {
        None => Redirect::to("/").into_response(),
        Some(server) => {
            let mut ctx = Context::new();
            ctx.insert("server", &server);
            Html(state.tera.render("server_detail.html", &ctx).unwrap_or_default()).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct ServerForm {
    pub name: String,
    pub ldap_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub skip_tls: Option<String>,
}

pub async fn create_server(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Form(form): Form<ServerForm>,
) -> impl IntoResponse {
    let skip_tls = form.skip_tls.is_some();
    let res = sqlx::query(
        "INSERT INTO servers (name, ldap_url, bind_dn, bind_password, skip_tls) VALUES (?, ?, ?, ?, ?)",
    )
    .bind(&form.name)
    .bind(&form.ldap_url)
    .bind(&form.bind_dn)
    .bind(&form.bind_password)
    .bind(skip_tls)
    .execute(&state.db)
    .await;

    let result = res.map(|_| ()).map_err(|e| e.to_string());
    db::log_action(&state.db, &actor, "server.create", &form.name, None, &result).await;

    Redirect::to("/")
}

#[derive(Deserialize)]
pub struct UpdateServerForm {
    pub name: String,
    pub ldap_url: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub skip_tls: Option<String>,
}

pub async fn update_server(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<UpdateServerForm>,
) -> impl IntoResponse {
    let skip_tls = form.skip_tls.is_some();

    let res = if form.bind_password.is_empty() {
        sqlx::query(
            "UPDATE servers SET name=?, ldap_url=?, bind_dn=?, skip_tls=? WHERE id=?",
        )
        .bind(&form.name)
        .bind(&form.ldap_url)
        .bind(&form.bind_dn)
        .bind(skip_tls)
        .bind(id)
        .execute(&state.db)
        .await
    } else {
        sqlx::query(
            "UPDATE servers SET name=?, ldap_url=?, bind_dn=?, bind_password=?, skip_tls=? WHERE id=?",
        )
        .bind(&form.name)
        .bind(&form.ldap_url)
        .bind(&form.bind_dn)
        .bind(&form.bind_password)
        .bind(skip_tls)
        .bind(id)
        .execute(&state.db)
        .await
    };

    let result = res.map(|_| ()).map_err(|e| e.to_string());
    db::log_action(&state.db, &actor, "server.update", &form.name, Some(id), &result).await;

    Redirect::to("/")
}

pub async fn delete_server(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let res = sqlx::query("DELETE FROM servers WHERE id = ?")
        .bind(id)
        .execute(&state.db)
        .await;

    let result = res.map(|_| ()).map_err(|e| e.to_string());
    db::log_action(&state.db, &actor, "server.delete", &id.to_string(), Some(id), &result).await;

    Redirect::to("/")
}

#[cfg(test)]
mod audit_page_tests {
    use super::{audit_context, page_links, AuditView};
    use crate::models::AuditEntry;
    use tera::Tera;

    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn entry(id: i64, target: &str) -> AuditEntry {
        AuditEntry {
            id,
            ts: 1_795_000_000,
            actor: "alice".into(),
            action: "user.disable".into(),
            target: target.into(),
            server_id: Some(2),
            server_name: Some("LAB".into()),
            result: "success".into(),
            detail: None,
        }
    }

    fn render(view: &AuditView, page: i64, entries: Vec<AuditEntry>, total: i64) -> String {
        let c = audit_context(view, view.failures == "1", page, entries, total, None);
        tera().render("audit.html", &c).map_err(|e| format!("{e:?}")).unwrap()
    }

    #[test]
    fn page_links_show_the_ends_and_the_neighbours() {
        assert_eq!(page_links(1, 1), vec![1]);
        assert_eq!(page_links(1, 4), vec![1, 2, 3, 4]);
        assert_eq!(page_links(10, 114), vec![1, 0, 8, 9, 10, 11, 12, 0, 114]);
    }

    #[test]
    fn page_links_keep_the_search_and_the_filter() {
        let view = AuditView { q: "group & co".into(), failures: "1".into(), page: "2".into() };
        let html = render(&view, 2, (0..100).map(|i| entry(i, "x")).collect(), 250);
        let at = html.find(r#"aria-label="Next page""#).map(|i| &html[i.saturating_sub(120)..i]).unwrap_or("");
        assert!(html.contains(r#"href="&#x2F;audit?q=group%20%26%20co&amp;failures=1&amp;page=3""#), "next page link: {at}");
        assert!(html.contains(r#"value="group &amp; co""#), "the search box keeps the search");
        assert!(html.contains("101–200 of 250"));
        assert!(!html.contains("onchange="), "no inline handlers");
    }

    #[test]
    fn short_logs_have_no_pager_and_empty_searches_say_so() {
        let html = render(&AuditView::default(), 1, vec![entry(1, "bob")], 1);
        assert!(!html.contains(r#"aria-label="Next page""#), "no pager");
        assert!(html.contains("Every action, newest first"));
        let html = render(&AuditView { q: "nothing".into(), ..Default::default() }, 1, vec![], 0);
        assert!(html.contains("No action matches"));
        let html = render(&AuditView::default(), 1, vec![], 0);
        assert!(html.contains("No actions recorded yet"));
    }
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// The Audit Log page's context with nothing in the log, for other pages' tests.
    pub fn empty_audit_context() -> tera::Context {
        super::audit_context(&super::AuditView::default(), false, 1, Vec::new(), 0, None)
    }
}
