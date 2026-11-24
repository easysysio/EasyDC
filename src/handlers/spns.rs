//! The SPNs page: every service principal name in the domain, and adding or
//! removing one. Which permission that takes depends on the account, a user
//! or a computer, so the handlers check it once they have found the account.

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use super::{ldap_mgmt::get_server, path_segment};
use crate::{
    access::{self, Area},
    auth::CurrentUser,
    db, ldap,
    models::Server,
    spn::{self, Account, Kind, Row},
    AppState,
};

#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Done {
    done: String,
    spn: String,
    account: String,
}

/// Said only if it is true when the page loads.
fn done_message(rows: &[Row], d: &Done) -> Option<String> {
    let there = rows.iter().any(|r| r.spn.eq_ignore_ascii_case(&d.spn) && r.account.eq_ignore_ascii_case(&d.account));
    match d.done.as_str() {
        "added" if there => Some(format!("{} now has {}.", d.account, d.spn)),
        "removed" if !there && !d.spn.is_empty() => Some(format!("{} was removed from {}.", d.spn, d.account)),
        _ => None,
    }
}

pub async fn page(State(state): State<AppState>, Path(id): Path<i64>, Query(d): Query<Done>) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render(&state, &server, None, &d).await,
    }
}

async fn render(state: &AppState, server: &Server, flash_error: Option<String>, d: &Done) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    let loaded = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let rows = spn::list(&mut conn, &base_dn).await;
        let _ = conn.unbind().await;
        rows
    }
    .await;
    let mut error = flash_error;
    match loaded {
        Ok(rows) => {
            if let Some(done) = done_message(&rows, d) {
                ctx.insert("done", &done);
            }
            let duplicates = rows.iter().filter(|r| r.duplicate).count();
            ctx.insert("duplicates", &duplicates);
            ctx.insert("rows", &rows);
        }
        Err(e) => error = error.or(Some(e)),
    }
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    Html(access::render(&state.tera, "spns.html", &ctx)).into_response()
}

#[derive(Deserialize)]
pub struct SpnForm {
    account: String,
    spn: String,
}

/// Editing an SPN takes Edit on what it is on.
async fn allowed(state: &AppState, actor: &str, id: i64, account: &Account, target: &str) -> Result<(), String> {
    let area = match account.kind {
        Kind::User => Area::Users,
        Kind::Computer => Area::Computers,
        Kind::Other => return Err(format!("{}: EasyDC changes SPNs on users and computers only.", account.sam)),
    };
    if access::current().can_edit(area) {
        return Ok(());
    }
    let reason = access::refusal(access::Need::Edit(area));
    db::log_action(&state.db, actor, "access.refused", target, Some(id), &Err(reason.clone())).await;
    Err(reason)
}

fn back(id: i64, done: &str, spn: &str, account: &str) -> Response {
    Redirect::to(&format!(
        "/servers/{id}/spns?done={done}&spn={}&account={}",
        path_segment(spn),
        path_segment(account)
    ))
    .into_response()
}

pub async fn add(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<SpnForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let target = format!("{} on {}", f.spn.trim(), f.account.trim());
    let result: Result<(String, String), String> = async {
        let value = spn::check(&f.spn)?;
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let account = spn::find_account(&mut conn, &base_dn, &f.account).await?;
        allowed(&state, &actor, id, &account, &target).await?;
        crate::handlers::ldap_mgmt::Guard::new(&mut conn, &base_dn).await?.check(&mut conn, &account.dn).await?;
        spn::add(&mut conn, &base_dn, &account, &value).await?;
        let _ = conn.unbind().await;
        Ok((value, account.sam))
    }
    .await;
    db::log_action(&state.db, &actor, "spn.add", &target, Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok((value, sam)) => back(id, "added", &value, &sam),
        Err(e) => render(&state, &server, Some(e), &Done::default()).await,
    }
}

pub async fn remove(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<SpnForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let target = format!("{} on {}", f.spn.trim(), f.account.trim());
    let result: Result<String, String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let account = spn::find_account(&mut conn, &base_dn, &f.account).await?;
        allowed(&state, &actor, id, &account, &target).await?;
        crate::handlers::ldap_mgmt::Guard::new(&mut conn, &base_dn).await?.check(&mut conn, &account.dn).await?;
        spn::remove(&mut conn, &account, f.spn.trim()).await?;
        let _ = conn.unbind().await;
        Ok(account.sam)
    }
    .await;
    db::log_action(&state.db, &actor, "spn.remove", &target, Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok(sam) => back(id, "removed", f.spn.trim(), &sam),
        Err(e) => render(&state, &server, Some(e), &Done::default()).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(spn: &str, account: &str, kind: Kind, locked: Option<&'static str>, duplicate: bool) -> Row {
        Row {
            spn: spn.into(),
            account: account.into(),
            kind,
            needs: if kind == Kind::Computer { "computers" } else { "users" },
            locked,
            duplicate,
            warning: "",
        }
    }

    fn render_rows(rows: &[Row]) -> String {
        let mut t = tera::Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| Ok(tera::Value::String("test".into())));
        let mut c = Context::new();
        c.insert("server", &serde_json::json!({ "id": 7, "name": "LAB" }));
        c.insert("rows", rows);
        c.insert("duplicates", &rows.iter().filter(|r| r.duplicate).count());
        t.render("spns.html", &c).unwrap()
    }

    #[test]
    fn the_page_offers_removal_only_where_allowed() {
        let html = render_rows(&[
            row("HTTP/web", "svc-web", Kind::User, None, false),
            row("HOST/dc1", "DC1$", Kind::Computer, Some("A domain controller's SPNs are managed by Samba."), false),
            row("HTTP/dup", "svc-dup", Kind::User, None, true),
        ]);
        assert!(html.contains(r#"action="/servers/7/spns/add""#));
        assert!(html.contains(r#"action="/servers/7/spns/remove""#));
        assert!(html.contains(r#"data-spn="HTTP&#x2F;web""#), "the page's escaping, which the browser undoes");
        assert!(!html.contains(r#"data-spn="HOST&#x2F;dc1""#), "a locked SPN has no remove button");
        assert!(html.contains("managed by Samba"));
        assert!(html.contains("Duplicate"));
    }

    #[test]
    fn what_a_page_says_is_true_when_it_loads() {
        let rows = [row("HTTP/web", "svc", Kind::User, None, false)];
        let d = |done: &str, spn: &str| Done { done: done.into(), spn: spn.into(), account: "svc".into() };
        assert_eq!(done_message(&rows, &d("added", "HTTP/web")).unwrap(), "svc now has HTTP/web.");
        assert_eq!(done_message(&rows, &d("added", "HTTP/other")), None);
        assert_eq!(done_message(&rows, &d("removed", "HTTP/other")).unwrap(), "HTTP/other was removed from svc.");
        assert_eq!(done_message(&rows, &d("removed", "HTTP/web")), None, "it is still there");
        assert_eq!(done_message(&rows, &d("nonsense", "HTTP/web")), None);
    }

    #[test]
    fn changing_an_spn_is_checked_by_its_handler() {
        use axum::http::Method;
        for route in ["/servers/:id/spns/add", "/servers/:id/spns/remove"] {
            assert_eq!(access::need(&Method::POST, route), access::Need::Handler);
        }
    }
}
