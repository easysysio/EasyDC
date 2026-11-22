//! The Delegation page: who may do what in an OU beyond the built-in
//! defaults, and giving a group a common task there (admins only).

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use super::{ldap_mgmt::get_server, path_segment};
use crate::{auth::CurrentUser, db, delegation, ldap, models::Server, AppState};

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct PageQuery {
    dn: String,
    /// After a change: the task's key (or "other"), and who.
    granted: String,
    removed: String,
    who: String,
}

fn task_label(key: &str) -> &'static str {
    delegation::TASKS.iter().find(|t| t.key == key).map(|t| t.label).unwrap_or("Other rights")
}

fn done_message(q: &PageQuery, ou: &str) -> Option<String> {
    if q.who.is_empty() {
        return None;
    }
    if !q.granted.is_empty() {
        Some(format!("{} can now do \"{}\" in {ou} and the OUs in it.", q.who, task_label(&q.granted)))
    } else if !q.removed.is_empty() {
        Some(format!("\"{}\" was taken from {} on {ou}.", task_label(&q.removed), q.who))
    } else {
        None
    }
}

pub async fn page(State(state): State<AppState>, Path(id): Path<i64>, Query(q): Query<PageQuery>) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render(&state, &server, &q, None).await,
    }
}

async fn render(state: &AppState, server: &Server, q: &PageQuery, flash_error: Option<String>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    ctx.insert("tasks", &delegation::TASKS);
    let loaded: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let ous = ldap::list_ous_tree(&mut conn, &base_dn).await?;
        let dn = if q.dn.is_empty() { ous.first().map(|o| o.dn.clone()).unwrap_or_default() } else { q.dn.clone() };
        ctx.insert("ous", &ous);
        ctx.insert("dn", &dn);
        let mut groups: Vec<String> = ldap::list_groups(&mut conn, &base_dn)
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|g| g.security)
            .map(|g| g.name)
            .collect();
        groups.sort_by_key(|g| g.to_lowercase());
        ctx.insert("groups", &groups);
        if dn.is_empty() {
            return Ok(());
        }
        let v = delegation::view(&mut conn, &base_dn, &dn).await?;
        if let Some(done) = done_message(q, &v.name) {
            ctx.insert("done", &done);
        }
        ctx.insert("v", &v);
        Ok(())
    }
    .await;
    if let Some(e) = flash_error.or(loaded.err()) {
        ctx.insert("error", &e);
    }
    Html(crate::access::render(&state.tera, "delegation.html", &ctx)).into_response()
}

fn back(id: i64, pairs: &[(&str, &str)]) -> Response {
    let query: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={}", path_segment(v))).collect();
    let query = query.join("&");
    Redirect::to(&format!("/servers/{id}/delegation?{query}")).into_response()
}

#[derive(Deserialize)]
pub struct GrantForm {
    dn: String,
    #[serde(default)]
    group: String,
    #[serde(default)]
    task: String,
}

pub async fn grant(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<GrantForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let result = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        delegation::grant_task(&mut conn, &base_dn, &f.dn, &f.group, &f.task).await
    }
    .await;
    let target = format!("{} on {}: {}", f.group.trim(), f.dn, task_label(&f.task));
    db::log_action(&state.db, &actor, "ou.delegate", &target, Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok((group, _)) => back(id, &[("dn", &f.dn), ("granted", &f.task), ("who", &group)]),
        Err(e) => render(&state, &server, &PageQuery { dn: f.dn, ..Default::default() }, Some(e)).await,
    }
}

#[derive(Deserialize)]
pub struct RevokeForm {
    dn: String,
    sid: String,
    #[serde(default)]
    task: String,
}

pub async fn revoke(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<RevokeForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let result = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        delegation::revoke(&mut conn, &base_dn, &f.dn, &f.sid, &f.task).await
    }
    .await;
    let who = result.as_ref().map(|(w, _)| w.clone()).unwrap_or_else(|_| f.sid.clone());
    let target = format!("{who} on {}: {}", f.dn, task_label(&f.task));
    db::log_action(&state.db, &actor, "ou.undelegate", &target, Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok((who, _)) => {
            let key = if f.task.is_empty() { "other" } else { f.task.as_str() };
            back(id, &[("dn", &f.dn), ("removed", key), ("who", &who)])
        }
        Err(e) => render(&state, &server, &PageQuery { dn: f.dn, ..Default::default() }, Some(e)).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delegation::{Row, View};

    fn tera() -> tera::Tera {
        let mut t = tera::Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn server() -> Server {
        Server {
            id: 1,
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    fn row(who: &str, task: &str, label: &str, inherited: bool) -> Row {
        Row {
            who: who.into(),
            sid: "S-1-5-21-1-2-3-1105".into(),
            kind: "group".into(),
            task: task.into(),
            label: label.into(),
            lines: if task.is_empty() { vec!["Read and write gPLink (this OU only)".into()] } else { Vec::new() },
            inherited,
        }
    }

    fn render(v: &View) -> String {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("tasks", &delegation::TASKS);
        c.insert("ous", &vec![ldap::LdapOuNode { dn: v.dn.clone(), name: v.name.clone(), description: String::new(), depth: 0 }]);
        c.insert("dn", &v.dn);
        c.insert("groups", &vec!["Helpdesk".to_string()]);
        c.insert("v", v);
        tera().render("delegation.html", &c).unwrap()
    }

    #[test]
    fn the_page_lists_tasks_and_offers_removal_only_where_set() {
        let v = View {
            dn: "OU=Sales,DC=example,DC=com".into(),
            name: "Sales".into(),
            delegated: vec![
                row("Helpdesk", "passwords", "Reset passwords and unlock accounts", false),
                row("Helpdesk", "", "Other rights", false),
                row("IT", "users", "Create, delete and manage user accounts", true),
            ],
            builtin: vec![Row { lines: vec!["Full control (this OU only)".into()], ..row("Domain Admins", "", "Other rights", false) }],
        };
        let html = render(&v);
        assert!(html.contains("Reset passwords and unlock accounts"));
        assert!(html.contains("Read and write gPLink (this OU only)"));
        assert_eq!(html.matches(r##"data-bs-target="#revokeModal""##).count(), 2, "an inherited one is removed where it was set");
        assert!(html.contains("From a parent OU"));
        assert!(html.contains("Domain Admins"));
        assert!(html.contains(r#"action="/servers/1/delegation/grant""#));
        assert!(html.contains(r#"data-needs="admin""#));
        assert!(html.contains(r#"value="gplinks""#));
    }

    #[test]
    fn an_ou_with_nothing_delegated_says_so() {
        let html = render(&View { dn: "OU=Sales,DC=example,DC=com".into(), name: "Sales".into(), ..Default::default() });
        assert!(html.contains("Nothing is delegated on Sales"));
    }

    #[test]
    fn the_message_after_a_change_names_the_task() {
        let q = PageQuery { granted: "passwords".into(), who: "Helpdesk".into(), ..Default::default() };
        assert_eq!(
            done_message(&q, "Sales").unwrap(),
            "Helpdesk can now do \"Reset passwords and unlock accounts\" in Sales and the OUs in it."
        );
        let q = PageQuery { removed: "other".into(), who: "Helpdesk".into(), ..Default::default() };
        assert_eq!(done_message(&q, "Sales").unwrap(), "\"Other rights\" was taken from Helpdesk on Sales.");
        assert_eq!(done_message(&PageQuery::default(), "Sales"), None);
        let need = |r| crate::access::need(&axum::http::Method::POST, r);
        assert_eq!(need("/servers/:id/delegation/grant"), crate::access::Need::Admin);
        assert_eq!(need("/servers/:id/delegation/revoke"), crate::access::Need::Admin);
    }
}
