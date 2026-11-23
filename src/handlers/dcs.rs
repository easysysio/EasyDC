//! The Domain Controllers page: each DC, its site and its FSMO roles, and
//! moving roles between DCs (admins only).

use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use super::{ldap_mgmt::get_server, path_segment};
use crate::{
    auth::CurrentUser,
    dc_removal, db,
    fsmo::{self, Role},
    ldap,
    level,
    models::Server,
    AppState,
};

/// After a move, the page says so, but only if it is true when it loads.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Moved {
    moved: String,
    to: String,
    /// A DC just removed, and how many objects and DNS records went with it.
    removed: String,
    objects: usize,
    records: usize,
    /// When a move this DC had not seen yet was made (unix seconds).
    at: i64,
}

/// How long after a move the page explains that it is still on its way.
const CATCHING_UP: i64 = 600;

pub async fn page(State(state): State<AppState>, Path(id): Path<i64>, Query(moved): Query<Moved>) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render(&state, &server, None, &moved).await,
    }
}

async fn render(state: &AppState, server: &Server, flash_error: Option<String>, moved: &Moved) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    let loaded = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let (o, _, p) = fsmo::overview(&mut conn, &base_dn).await?;
        // The rest of the page is still useful if the levels cannot be read.
        let levels = level::read(&mut conn, &p, &o.roles).await.map(|s| s.view());
        let _ = conn.unbind().await;
        Ok::<_, String>((o, levels))
    }
    .await;
    let mut error = flash_error;
    match loaded {
        Ok((o, levels)) => {
            if let Some(done) = removed_message(&o, moved).or_else(|| done_message(&o, moved)) {
                ctx.insert("done", &done);
            } else if let Some(note) = pending_message(&o, moved, crate::health::now_unix()) {
                ctx.insert("pending", &note);
            }
            ctx.insert("o", &o);
            match levels {
                Ok(v) => ctx.insert("levels", &v),
                Err(e) => ctx.insert("levels_error", &e),
            }
        }
        Err(e) => error = error.or(Some(e)),
    }
    if let Some(e) = error {
        ctx.insert("error", &e);
    }
    Html(crate::access::render(&state.tera, "dcs.html", &ctx)).into_response()
}

/// "The PDC emulator is now on DC2." when it is.
fn done_message(o: &fsmo::Overview, m: &Moved) -> Option<String> {
    if m.to.is_empty() {
        return None;
    }
    let holds = |h: &fsmo::Holder| h.dc.eq_ignore_ascii_case(&m.to);
    if m.moved == "all" {
        let movable: Vec<&fsmo::Holder> = o.roles.iter().filter(|h| !h.missing).collect();
        let name = movable.first().map(|h| h.dc.clone())?;
        return movable.iter().all(|h| holds(h)).then(|| format!("{name} now holds all {} FSMO roles.", movable.len()));
    }
    let role = Role::from_key(&m.moved)?;
    o.roles.iter().find(|h| h.role == role && holds(h)).map(|h| format!("The {} is now on {}.", h.label, h.dc))
}

/// "OLDDC was removed: …" when it is no longer listed.
fn removed_message(o: &fsmo::Overview, m: &Moved) -> Option<String> {
    if m.removed.is_empty() || o.dcs.iter().any(|d| d.name.eq_ignore_ascii_case(&m.removed)) {
        return None;
    }
    let records = match m.records {
        0 => String::new(),
        1 => " and 1 DNS record".to_string(),
        n => format!(" and {n} DNS records"),
    };
    Some(format!("{} was removed from the domain: {} objects{records}.", m.removed, m.objects))
}

/// Right after a move this DC has not seen yet: what to expect.
fn pending_message(o: &fsmo::Overview, m: &Moved, now: i64) -> Option<String> {
    if m.to.is_empty() || m.at == 0 || now - m.at > CATCHING_UP || now < m.at {
        return None;
    }
    let what = if m.moved == "all" { "The roles were".to_string() } else { format!("The {} was", Role::from_key(&m.moved)?.label()) };
    let here = o.dcs.iter().find(|d| d.configured).map_or("The DC EasyDC reads from".to_string(), |d| d.name.clone());
    Some(format!(
        "{what} moved to {}. This page shows what {here} knows, and {here} lists the new holder once it replicates, within a few minutes.",
        m.to
    ))
}

/// GET (JSON): what removing a DC would delete, and why it may not be removed.
pub async fn removal_plan(State(state): State<AppState>, Path((id, name)): Path<(i64, String)>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return axum::Json(serde_json::json!({ "error": "There is no such server." })).into_response();
    };
    let plan = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        dc_removal::plan(&mut conn, &base_dn, &name).await
    }
    .await;
    match plan {
        Ok(p) => axum::Json(p).into_response(),
        Err(e) => axum::Json(serde_json::json!({ "error": e })).into_response(),
    }
}

#[derive(Deserialize)]
pub struct RemoveForm {
    /// The DC's name typed again.
    #[serde(default)]
    confirm: String,
}

pub async fn remove(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(f): Form<RemoveForm>,
) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let result = async {
        if !f.confirm.trim().eq_ignore_ascii_case(&name) {
            return Err(format!("Type the DC's name, {name}, to confirm."));
        }
        let (mut conn, base_dn) = ldap::open(&server).await?;
        dc_removal::remove(&mut conn, &base_dn, &name).await
    }
    .await;
    db::log_action(&state.db, &actor, "dc.remove", &name, Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
    match result {
        Ok(done) => Redirect::to(&format!(
            "/servers/{id}/dcs?removed={}&objects={}&records={}",
            path_segment(&name),
            done.objects,
            done.records
        ))
        .into_response(),
        Err(e) => render(&state, &server, Some(e), &Moved::default()).await,
    }
}

#[derive(Deserialize)]
pub struct TransferForm {
    /// A role's key, or `all`.
    role: String,
    to: String,
}

pub async fn transfer(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<TransferForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Redirect::to("/").into_response();
    };
    let to = f.to.trim().to_string();
    let roles: Vec<Role> = if f.role == "all" {
        fsmo::ROLES.to_vec()
    } else {
        match Role::from_key(&f.role) {
            Some(r) => vec![r],
            None => return render(&state, &server, Some(format!("There is no FSMO role '{}'.", f.role)), &Moved::default()).await,
        }
    };

    let mut failed = Vec::new();
    let mut seen = true;
    match ldap::open(&server).await {
        Err(e) => failed.push(e),
        Ok((mut conn, base_dn)) => {
            // For "all", the roles it already holds, or that this domain lacks, are skipped.
            let current = fsmo::overview(&mut conn, &base_dn).await.map(|(o, _, _)| o.roles).unwrap_or_default();
            for role in roles {
                let skip = f.role == "all"
                    && current.iter().any(|h| h.role == role && (h.missing || h.dc.eq_ignore_ascii_case(&to)));
                if skip {
                    continue;
                }
                let result = fsmo::transfer(&server, &mut conn, &base_dn, role, &to).await;
                db::log_action(&state.db, &actor, "fsmo.transfer", &format!("{} → {to}", role.label()), Some(id), &result.as_ref().map(|_| ()).map_err(Clone::clone)).await;
                match result {
                    Ok(here) => seen &= here,
                    Err(e) => failed.push(e),
                }
            }
        }
    }
    if failed.is_empty() {
        let at = if seen { String::new() } else { format!("&at={}", crate::health::now_unix()) };
        Redirect::to(&format!("/servers/{id}/dcs?moved={}&to={}{at}", f.role, path_segment(&to))).into_response()
    } else {
        render(&state, &server, Some(failed.join(" ")), &Moved::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fsmo::{Dc, Holder, Overview, ROLES};

    fn overview(holder: &str) -> Overview {
        Overview {
            dcs: vec![
                Dc { name: "DC1".into(), host: "dc1.x.com".into(), site: "HQ".into(), roles: vec![], configured: true, holds_all: false },
                Dc { name: "DC2".into(), host: "dc2.x.com".into(), site: "HQ".into(), roles: vec![], configured: false, holds_all: true },
            ],
            roles: ROLES
                .iter()
                .map(|&r| Holder {
                    role: r,
                    key: r.key(),
                    label: r.label(),
                    does: r.does(),
                    dc: if r == Role::ForestDns { "OLDDC".into() } else { holder.into() },
                    owner: String::new(),
                    gone: r == Role::ForestDns,
                    missing: false,
                })
                .collect(),
        }
    }

    fn render(o: &Overview) -> String {
        let mut t = tera::Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| Ok(tera::Value::String("test".into())));
        let mut c = Context::new();
        c.insert("server", &Server {
            id: 1,
            name: "DC1".into(),
            ldap_url: "ldaps://dc1.x.com".into(),
            bind_dn: "CN=Administrator".into(),
            bind_password: "secret".into(),
            skip_tls: true,
        });
        c.insert("o", o);
        t.render("dcs.html", &c).unwrap()
    }

    #[test]
    fn the_page_shows_each_role_and_how_to_move_it() {
        let html = render(&overview("DC1"));
        assert!(html.contains("PDC emulator") && html.contains("Hands each DC blocks of IDs"));
        assert!(html.contains(r#"data-role="pdc" data-holder="DC1""#));
        assert!(html.contains(r#"action="/servers/1/dcs/fsmo""#));
        assert!(html.contains(r#"data-needs="admin""#), "moving roles is for admins");
        assert!(html.contains("samba-tool fsmo seize --role=forestdns"), "a role whose holder is gone says how to take it");
        assert!(html.contains(r#"data-to="DC1""#), "all roles can be moved to a DC");
        assert!(!html.contains(r#"data-to="DC2""#), "but not to one that holds them all");
        assert_eq!(crate::access::need(&axum::http::Method::POST, "/servers/:id/dcs/fsmo"), crate::access::Need::Admin);
    }

    #[test]
    fn a_move_is_reported_only_when_true() {
        let o = overview("DC2");
        let m = |moved: &str, to: &str| Moved { moved: moved.into(), to: to.into(), ..Default::default() };
        assert_eq!(done_message(&o, &m("pdc", "DC2")).unwrap(), "The PDC emulator is now on DC2.");
        assert_eq!(done_message(&o, &m("pdc", "DC1")), None, "a stale link says nothing");
        assert_eq!(done_message(&o, &m("nonsense", "DC2")), None);
        assert_eq!(done_message(&o, &m("all", "DC2")), None, "the forest DNS role is elsewhere");
        let mut o = overview("DC2");
        o.roles.iter_mut().for_each(|h| h.dc = "DC2".into());
        assert_eq!(done_message(&o, &m("all", "dc2")).unwrap(), "DC2 now holds all 7 FSMO roles.");
    }

    #[test]
    fn a_removal_is_reported_once_the_dc_is_gone() {
        let o = overview("DC1");
        let m = |name: &str, records: usize| Moved { removed: name.into(), objects: 4, records, ..Default::default() };
        assert_eq!(removed_message(&o, &m("OLDDC", 23)).unwrap(), "OLDDC was removed from the domain: 4 objects and 23 DNS records.");
        assert_eq!(removed_message(&o, &m("OLDDC", 0)).unwrap(), "OLDDC was removed from the domain: 4 objects.");
        assert_eq!(removed_message(&o, &m("DC2", 3)), None, "a DC still listed was not removed");
        assert_eq!(crate::access::need(&axum::http::Method::POST, "/servers/:id/dcs/:name/remove"), crate::access::Need::Admin);
    }

    #[test]
    fn the_page_offers_removal_except_for_its_own_dc() {
        let html = render(&overview("DC1"));
        assert!(html.contains(r#"data-remove="DC2""#));
        assert!(!html.contains(r#"data-remove="DC1""#), "the DC EasyDC is connected to is running");
        assert!(html.contains("/dcs/' + segment(name) + '/removal"));
    }

    fn levels(domain: i64) -> level::View {
        level::Snapshot {
            forest: 3,
            domain,
            domain_name: "x.com".into(),
            forest_name: "x.com".into(),
            dcs: vec![("DC1".into(), 7), ("DC2".into(), 5)],
            other_domains: vec![],
            pdc: Ok("DC1".into()),
            naming: Ok("DC2".into()),
            schema_master: Ok("DC1".into()),
            infrastructure: Ok("DC1".into()),
            prep: level::Prep { schema: 88, forest: 16, domain: 16 },
        }
        .view()
    }

    #[test]
    fn the_level_card_offers_only_what_is_allowed() {
        let mut t = tera::Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| Ok(tera::Value::String("test".into())));
        let mut c = Context::new();
        c.insert("server", &serde_json::json!({ "id": 1, "name": "DC1" }));
        c.insert("o", &overview("DC1"));
        c.insert("levels", &levels(4));
        let html = t.render("dcs.html", &c).unwrap();
        assert!(!html.contains("/dcs/level"), "EasyDC does not make the change itself");
        assert!(html.contains(r##"data-bs-target="#raiseGuide""##));
        assert!(html.contains(r#"<option value="5">Windows Server 2012</option>"#));
        assert!(html.contains(r#"<option value="7">Windows Server 2016</option>"#), "a guide can start from a DC still to change");
        assert!(html.contains("samba-tool domain level raise --domain-level=2016"));
        assert!(html.contains("ad dc functional level = 2016"));
        assert!(html.contains("cannot be undone"));
    }

    #[test]
    fn a_move_still_on_its_way_says_so_for_a_while() {
        let o = overview("DC1");
        let m = Moved { moved: "domaindns".into(), to: "DC2".into(), at: 1_000, ..Default::default() };
        let note = pending_message(&o, &m, 1_030).unwrap();
        assert_eq!(note, "The Domain DNS zones master was moved to DC2. This page shows what DC1 knows, and DC1 lists the new holder once it replicates, within a few minutes.");
        assert_eq!(pending_message(&o, &m, 1_000 + CATCHING_UP + 1), None, "an old link says nothing");
        assert_eq!(pending_message(&o, &Moved { at: 0, ..m }, 1_030), None);
        let all = Moved { moved: "all".into(), to: "DC2".into(), at: 1_000, ..Default::default() };
        assert!(pending_message(&o, &all, 1_010).unwrap().starts_with("The roles were moved to DC2."));
    }
}
