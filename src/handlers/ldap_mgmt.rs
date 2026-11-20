use axum::{
    extract::{Path, Query, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::{Deserialize, Serialize};
use tera::Context;

use super::path_segment;
use crate::{auth::CurrentUser, db, ldap, models::Server, AppState};

// ── shared helpers ────────────────────────────────────────────────────────────

async fn get_server(state: &AppState, id: i64) -> Option<Server> {
    sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None)
}

fn redirect_home() -> Response {
    Redirect::to("/").into_response()
}


fn group_page(id: i64, name: &str) -> String {
    format!("/servers/{}/groups/{}/members", id, path_segment(name))
}

// ── group list ────────────────────────────────────────────────────────────────

/// The groups page, with `flash_error` when an action on it just failed: the
/// reason belongs on the page, not only in the audit log.
async fn render_groups(
    state: &AppState,
    server: &Server,
    view: &ListView,
    flash_error: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);

    let loaded: Result<_, String> = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let groups = ldap::list_groups(&mut conn, &base_dn).await?;
        let objects_in: Vec<&str> = groups.iter().map(|g| g.container.as_str()).collect();
        let tree = ldap::list_containers(&mut conn, &base_dn, &objects_in).await?;
        Ok((base_dn, groups, tree))
    }
    .await;
    let load_error = match loaded {
        Ok((base_dn, groups, tree)) => groups_context(&mut ctx, server, &base_dn, &groups, &tree, view),
        Err(e) => {
            ctx.insert("groups", &Vec::<ldap::LdapGroup>::new());
            Some(e)
        }
    };
    if let Some(e) = flash_error.or(load_error) {
        ctx.insert("error", &e);
    }

    Html(state.tera.render("groups.html", &ctx).unwrap_or_default()).into_response()
}

/// Back to the same view of the groups on success; with the reason on failure.
async fn after_group_action(
    state: &AppState,
    server: &Server,
    view: &ListView,
    result: Result<(), String>,
) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/groups{}", server.id, view.query())).into_response(),
        Err(e) => render_groups(state, server, view, Some(e)).await,
    }
}

pub async fn groups(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(view): Query<ListView>,
) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_groups(&state, &server, &view, None).await,
    }
}

// ── create group ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGroupForm {
    pub name: String,
    pub description: String,
    pub group_type: i64,
}

pub async fn create_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Query(view): Query<ListView>,
    Form(form): Form<CreateGroupForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::create_group(
            &mut conn,
            &base_dn,
            &ldap::NewGroup {
                name: form.name.trim(),
                description: form.description.trim(),
                group_type: form.group_type,
                parent: &view.ou,
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "group.create", &form.name, Some(id), &result).await;

    after_group_action(&state, &server, &view, result).await
}

// ── update group ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGroupForm {
    pub description: String,
    /// global, domain_local or universal. Absent on a built-in group's form,
    /// and on a page from before scopes were editable: the scope stays.
    #[serde(default)]
    pub scope: Option<String>,
    /// security or distribution.
    #[serde(default)]
    pub kind: Option<String>,
}

pub async fn update_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Query(view): Query<ListView>,
    Form(form): Form<UpdateGroupForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let scope = match form.scope.as_deref() {
            None | Some("") => None,
            Some(s) => Some(ldap::GroupScope::parse(s).ok_or_else(|| format!("Unknown group scope '{s}'"))?),
        };
        let security = match form.kind.as_deref() {
            None | Some("") => None,
            Some("security") => Some(true),
            Some("distribution") => Some(false),
            Some(k) => return Err(format!("Unknown group type '{k}'")),
        };
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::update_group(
            &mut conn,
            &base_dn,
            &name,
            &ldap::GroupUpdate { description: form.description.trim(), scope, security },
        )
        .await
    }
    .await;
    let target = match (&form.scope, &form.kind) {
        (Some(s), Some(k)) if !s.is_empty() => format!("{name} ({s} {k})"),
        _ => name.clone(),
    };
    db::log_action(&state.db, &actor, "group.update", &target, Some(id), &result).await;

    after_group_action(&state, &server, &view, result).await
}

// ── delete group ──────────────────────────────────────────────────────────────

pub async fn delete_group(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Query(view): Query<ListView>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::delete_group(&mut conn, &base_dn, &name).await
    }
    .await;
    db::log_action(&state.db, &actor, "group.delete", &name, Some(id), &result).await;

    after_group_action(&state, &server, &view, result).await
}

// ── group members page ────────────────────────────────────────────────────────

async fn render_group(
    state: &AppState,
    server: &Server,
    name: &str,
    flash_error: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    ctx.insert("group_name", name);

    let loaded = match ldap::open_after(server, flash_error.as_deref()).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => match ldap::group_detail(&mut conn, &base_dn, name).await {
            Err(e) => Err(e),
            // Suggestions only: the page works without them.
            Ok(d) => Ok((d, ldap::member_candidates(&mut conn, &base_dn).await.unwrap_or_default())),
        },
    };
    let load_error = match loaded {
        Ok((detail, candidates)) => {
            ctx.insert("group", &detail.group);
            ctx.insert("members", &detail.members);
            ctx.insert("member_of", &detail.member_of);
            ctx.insert("candidates", &candidates);
            None
        }
        Err(e) => {
            ctx.insert("members", &Vec::<ldap::GroupMember>::new());
            ctx.insert("member_of", &Vec::<ldap::LdapGroup>::new());
            ctx.insert("candidates", &Vec::<String>::new());
            Some(e)
        }
    };
    if let Some(e) = flash_error.or(load_error) {
        ctx.insert("error", &e);
    }

    Html(state.tera.render("group_members.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn group_members(
    State(state): State<AppState>,
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_group(&state, &server, &name, None).await,
    }
}

// ── add / remove member ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddMemberForm {
    /// A username, computer name or group name.
    #[serde(alias = "username")]
    pub member: String,
}

pub async fn add_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, group_name)): Path<(i64, String)>,
    Form(form): Form<AddMemberForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };
    let member = form.member.trim();

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::add_group_member(&mut conn, &base_dn, &group_name, member).await
    }
    .await;
    let target = format!("{} → {}", member, group_name);
    db::log_action(&state.db, &actor, "group.add_member", &target, Some(id), &result).await;

    match result {
        Ok(()) => Redirect::to(&group_page(id, &group_name)).into_response(),
        Err(e) => render_group(&state, &server, &group_name, Some(e)).await,
    }
}

#[derive(Deserialize)]
pub struct RemoveMemberForm {
    pub member_dn: String,
}

pub async fn remove_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, group_name)): Path<(i64, String)>,
    Form(form): Form<RemoveMemberForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::remove_group_member(&mut conn, &base_dn, &group_name, &form.member_dn).await
    }
    .await;
    let target = format!("{} ✕ {}", form.member_dn, group_name);
    db::log_action(&state.db, &actor, "group.remove_member", &target, Some(id), &result).await;

    match result {
        Ok(()) => Redirect::to(&group_page(id, &group_name)).into_response(),
        Err(e) => render_group(&state, &server, &group_name, Some(e)).await,
    }
}

pub async fn computers(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_computers(&state, &server, None).await,
    }
}

/// The computers page, with `flash_error` when an action on it just failed.
async fn render_computers(state: &AppState, server: &Server, flash_error: Option<String>) -> Response {
    let list = match ldap::open_after(server, flash_error.as_deref()).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::list_computers(&mut conn, &base_dn).await,
    };
    let ctx = computers_context(server, list, flash_error);
    Html(state.tera.render("computers.html", &ctx).unwrap_or_default()).into_response()
}

fn computers_context(
    server: &Server,
    list: Result<Vec<ldap::LdapComputer>, String>,
    flash_error: Option<String>,
) -> Context {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    match list {
        Ok(list) => ctx.insert("computers", &list),
        Err(e) => {
            ctx.insert("computers", &Vec::<ldap::LdapComputer>::new());
            ctx.insert("error", &e);
        }
    }
    // The action's own failure says more than a list that did not load after it.
    if let Some(e) = flash_error {
        ctx.insert("error", &e);
    }
    ctx
}

/// Back to the computers list on success; the list with the reason on failure.
async fn after_computer_action(state: &AppState, server: &Server, result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/computers", server.id)).into_response(),
        Err(e) => render_computers(state, server, Some(e)).await,
    }
}

pub async fn delete_computer(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::delete_computer(&mut conn, &base_dn, &name).await
    }
    .await;
    db::log_action(&state.db, &actor, "computer.delete", &name, Some(id), &result).await;
    after_computer_action(&state, &server, result).await
}

pub async fn toggle_computer(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::set_computer_enabled(&mut conn, &base_dn, &name, enable).await
    }
    .await;
    let action = if enable { "computer.enable" } else { "computer.disable" };
    db::log_action(&state.db, &actor, action, &name, Some(id), &result).await;
    after_computer_action(&state, &server, result).await
}

// ── OU list ───────────────────────────────────────────────────────────────────

pub async fn ous(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_ous(&state, &server, None).await,
    }
}

/// Back to the OU list on success; the list with the reason on failure.
async fn after_ou_action(state: &AppState, server: &Server, result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/ous", server.id)).into_response(),
        Err(e) => render_ous(state, server, Some(e)).await,
    }
}

async fn render_ous(state: &AppState, server: &Server, flash_error: Option<String>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);

    match ldap::open_after(server, flash_error.as_deref()).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("ou_nodes", &Vec::<ldap::LdapOuNode>::new());
            ctx.insert("ous_flat", &Vec::<ldap::LdapOu>::new());
        }
        Ok((mut conn, base_dn)) => {
            ctx.insert("base_dn", &base_dn);
            match ldap::list_ous_tree(&mut conn, &base_dn).await {
                Err(e) => {
                    ctx.insert("error", &e);
                    ctx.insert("ou_nodes", &Vec::<ldap::LdapOuNode>::new());
                    ctx.insert("ous_flat", &Vec::<ldap::LdapOu>::new());
                }
                Ok(nodes) => {
                    // Also build a flat list for the parent dropdown
                    let mut flat: Vec<ldap::LdapOu> = nodes
                        .iter()
                        .map(|n| ldap::LdapOu { dn: n.dn.clone(), name: n.name.clone() })
                        .collect();
                    flat.insert(0, ldap::LdapOu {
                        dn: base_dn.clone(),
                        name: format!("Domain Root ({})", base_dn),
                    });
                    ctx.insert("ous_flat", &flat);
                    ctx.insert("ou_nodes", &nodes);
                }
            }
        }
    }

    if let Some(e) = flash_error {
        ctx.insert("error", &e);
    }
    Html(state.tera.render("ous.html", &ctx).unwrap_or_default()).into_response()
}

// ── create OU ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateOuForm {
    pub name: String,
    pub description: String,
    pub parent_dn: String,
}

pub async fn ou_create(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CreateOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, _) = ldap::open(&server).await?;
        ldap::create_ou(&mut conn, &form.parent_dn, &form.name, &form.description).await
    }
    .await;
    let target = format!("OU={},{}", ldap::dn_escape(form.name.trim()), form.parent_dn);
    db::log_action(&state.db, &actor, "ou.create", &target, Some(id), &result).await;

    after_ou_action(&state, &server, result).await
}

// ── rename OU ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RenameOuForm {
    pub ou_dn: String,
    pub new_name: String,
}

pub async fn ou_rename(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<RenameOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, _) = ldap::open(&server).await?;
        ldap::rename_ou(&mut conn, &form.ou_dn, &form.new_name).await
    }
    .await;
    let target = format!("{} → {}", form.ou_dn, form.new_name);
    db::log_action(&state.db, &actor, "ou.rename", &target, Some(id), &result).await;

    after_ou_action(&state, &server, result).await
}

// ── delete OU ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteOuForm {
    pub ou_dn: String,
}

pub async fn ou_delete(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<DeleteOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, _) = ldap::open(&server).await?;
        ldap::delete_ou(&mut conn, &form.ou_dn).await
    }
    .await;
    db::log_action(&state.db, &actor, "ou.delete", &form.ou_dn, Some(id), &result).await;

    after_ou_action(&state, &server, result).await
}

// ── move object to OU ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct MoveObjectForm {
    pub sam_account: String,
    pub target_ou_dn: String,
}

pub async fn ou_move_object(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<MoveObjectForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::move_object_to_ou(&mut conn, &base_dn, &form.sam_account, &form.target_ou_dn).await
    }
    .await;
    let target = format!("{} → {}", form.sam_account, form.target_ou_dn);
    db::log_action(&state.db, &actor, "ou.move_object", &target, Some(id), &result).await;

    after_ou_action(&state, &server, result).await
}

// ── DNS zone list ─────────────────────────────────────────────────────────────

async fn render_dns(
    state: &AppState,
    server: &Server,
    error: Option<String>,
    notice: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    if let Some(n) = notice {
        ctx.insert("notice", &n);
    }

    match ldap::open_after(server, error.as_deref()).await {
        Err(e) => {
            ctx.insert("error", &error.unwrap_or(e));
            ctx.insert("zones", &Vec::<ldap::LdapDnsZone>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_dns_zones(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &error.unwrap_or(e));
                ctx.insert("zones", &Vec::<ldap::LdapDnsZone>::new());
            }
            Ok(zones) => {
                if let Some(e) = error {
                    ctx.insert("error", &e);
                }
                ctx.insert("domain", &ldap::base_dn_to_domain(&base_dn));
                ctx.insert("zones", &zones);
            }
        },
    }

    Html(state.tera.render("dns.html", &ctx).unwrap_or_default()).into_response()
}

// ── create a zone ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateZoneForm {
    pub zone: String,
    /// Present when the "reverse zone" box is ticked, in which case the input
    /// is a network such as 192.168.10 rather than a zone name.
    pub reverse: Option<String>,
}

pub async fn dns_zone_create(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CreateZoneForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let input = form.zone.trim().to_string();
    let zone = if form.reverse.is_some() {
        match ldap::reverse_zone_name(&input) {
            Some(z) => z,
            None => {
                let e = format!(
                    "'{}' is not an IPv4 network. Use 192.168.10, or 192.168.10.0/24.",
                    input
                );
                db::log_action(&state.db, &actor, "dns.zone_create", &input, Some(id), &Err(e.clone())).await;
                return render_dns(&state, &server, Some(e), None).await;
            }
        }
    } else {
        input.to_lowercase()
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::create_dns_zone(&mut conn, &base_dn, &zone).await,
    };
    db::log_action(&state.db, &actor, "dns.zone_create", &zone, Some(id), &result).await;

    match result {
        Ok(()) => render_dns(
            &state,
            &server,
            None,
            Some(format!(
                "Zone {} created. This DC serves it immediately and the others follow \
                 within seconds, as replication catches up — no restart needed.",
                zone
            )),
        )
        .await,
        Err(e) => render_dns(&state, &server, Some(e), None).await,
    }
}

// ── delete a zone ─────────────────────────────────────────────────────────────

pub async fn dns_zone_delete(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, zone)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::delete_dns_zone(&mut conn, &base_dn, &zone).await,
    };

    let logged = result.as_ref().map(|_| ()).map_err(|e| e.clone());
    db::log_action(&state.db, &actor, "dns.zone_delete", &zone, Some(id), &logged).await;

    match result {
        Ok(nodes) => render_dns(
            &state,
            &server,
            None,
            Some(format!(
                "Zone {} and its {} node(s) removed from the directory.                  The DNS server keeps answering for {} until samba is restarted on each DC.",
                zone, nodes, zone
            )),
        )
        .await,
        Err(e) => render_dns(&state, &server, Some(e), None).await,
    }
}

pub async fn dns(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };
    render_dns(&state, &server, None, None).await
}

// ── DNS zone shared renderer ──────────────────────────────────────────────────

async fn render_dns_zone(
    state: &AppState,
    server: &crate::models::Server,
    zone_name: &str,
    flash_error: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    ctx.insert("zone_name", zone_name);

    let load_error = match ldap::open_after(server, flash_error.as_deref()).await {
        Err(e) => Some(e),
        Ok((mut conn, base_dn)) => match ldap::find_zone_dn(&mut conn, &base_dn, zone_name).await {
            Err(e) => Some(e),
            Ok(zone_dn) => match ldap::list_dns_records(&mut conn, &zone_dn).await {
                Err(e) => Some(e),
                Ok(nodes) => {
                    ctx.insert("nodes", &nodes);
                    None
                }
            },
        },
    };

    let error = flash_error.or(load_error);
    if let Some(e) = error {
        ctx.insert("error", &e);
        ctx.insert("nodes", &Vec::<ldap::DnsNode>::new());
    }

    Html(state.tera.render("dns_zone.html", &ctx).unwrap_or_default()).into_response()
}

// ── DNS records in zone ───────────────────────────────────────────────────────

pub async fn dns_zone(
    State(state): State<AppState>,
    Path((id, zone_name)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };
    render_dns_zone(&state, &server, &zone_name, None).await
}

// ── add DNS record ────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddDnsRecordForm {
    pub node_name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

pub async fn dns_add_record(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, zone_name)): Path<(i64, String)>,
    Form(form): Form<AddDnsRecordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => match ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
            Err(e) => Err(e),
            Ok(zone_dn) => ldap::add_dns_record(
                &mut conn,
                &zone_dn,
                &form.node_name,
                &form.record_type,
                &form.value,
                form.ttl,
            )
            .await,
        },
    };

    let target = format!("{} {} {} ({})", zone_name, form.node_name, form.record_type, form.value);
    db::log_action(&state.db, &actor, "dns.add_record", &target, Some(id), &result).await;

    match result {
        Ok(_) => Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response(),
        Err(e) => render_dns_zone(&state, &server, &zone_name, Some(e)).await,
    }
}

// ── delete DNS record ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteDnsRecordForm {
    pub node_name: String,
    pub raw_hex: String,
}

pub async fn dns_delete_record(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, zone_name)): Path<(i64, String)>,
    Form(form): Form<DeleteDnsRecordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => match ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
            Err(e) => Err(e),
            Ok(zone_dn) => {
                ldap::delete_dns_record(&mut conn, &zone_dn, &form.node_name, &form.raw_hex).await
            }
        },
    };

    let target = format!("{} {}", zone_name, form.node_name);
    db::log_action(&state.db, &actor, "dns.delete_record", &target, Some(id), &result).await;

    match result {
        Ok(_) => Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response(),
        Err(e) => render_dns_zone(&state, &server, &zone_name, Some(e)).await,
    }
}

// ── edit DNS record ───────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct EditDnsRecordForm {
    pub node_name: String,
    pub raw_hex: String,
    pub value: String,
    pub ttl: u32,
}

/// Changes one record's value and TTL in place. The type comes from the stored
/// record, not the form.
pub async fn dns_edit_record(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, zone_name)): Path<(i64, String)>,
    Form(form): Form<EditDnsRecordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => match ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
            Err(e) => Err(e),
            Ok(zone_dn) => {
                ldap::edit_dns_record(&mut conn, &zone_dn, &form.node_name, &form.raw_hex, &form.value, form.ttl)
                    .await
            }
        },
    };

    // Nothing changed: nothing to record.
    if let Ok(false) = result {
        return Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response();
    }
    let target = format!(
        "{} {} {} -> {} (TTL {})",
        zone_name,
        form.node_name,
        ldap::describe_record(&form.raw_hex),
        form.value.trim(),
        form.ttl
    );
    let logged = result.as_ref().map(|_| ()).map_err(|e| e.clone());
    db::log_action(&state.db, &actor, "dns.edit_record", &target, Some(id), &logged).await;

    match result {
        Ok(_) => Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response(),
        Err(e) => render_dns_zone(&state, &server, &zone_name, Some(e)).await,
    }
}

// ── GPO list ──────────────────────────────────────────────────────────────────

pub async fn gpo(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_gpo(&state, &server, None).await,
    }
}

/// The GPO page, with `flash_error` when an action on it just failed.
async fn render_gpo(state: &AppState, server: &Server, flash_error: Option<String>) -> Response {
    let list = match ldap::open_after(server, flash_error.as_deref()).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::list_gpos(&mut conn, &base_dn).await,
    };
    let ctx = gpo_context(server, list, flash_error);
    Html(state.tera.render("gpo.html", &ctx).unwrap_or_default()).into_response()
}

fn gpo_context(server: &Server, list: Result<Vec<ldap::LdapGpo>, String>, flash_error: Option<String>) -> Context {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    match list {
        Ok(list) => ctx.insert("gpos", &list),
        Err(e) => {
            ctx.insert("gpos", &Vec::<ldap::LdapGpo>::new());
            ctx.insert("error", &e);
        }
    }
    if let Some(e) = flash_error {
        ctx.insert("error", &e);
    }
    ctx
}

/// Back to the GPO list on success; the list with the reason on failure.
async fn after_gpo_action(state: &AppState, server: &Server, result: Result<(), String>) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/gpo", server.id)).into_response(),
        Err(e) => render_gpo(state, server, Some(e)).await,
    }
}

// ── create GPO ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateGpoForm {
    pub display_name: String,
}

pub async fn gpo_create(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<CreateGpoForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::create_gpo(&mut conn, &base_dn, &form.display_name).await
    }
    .await;
    db::log_action(&state.db, &actor, "gpo.create", &form.display_name, Some(id), &result).await;
    after_gpo_action(&state, &server, result).await
}

// ── update GPO ────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGpoForm {
    pub display_name: String,
    pub flags: i32,
}

pub async fn gpo_update(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<UpdateGpoForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        ldap::update_gpo(&mut conn, &gpo_dn, &form.display_name, form.flags).await
    }
    .await;
    db::log_action(&state.db, &actor, "gpo.update", &form.display_name, Some(id), &result).await;
    after_gpo_action(&state, &server, result).await
}

// ── delete GPO ────────────────────────────────────────────────────────────────

pub async fn gpo_delete(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, guid)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        ldap::delete_gpo(&mut conn, &gpo_dn).await
    }
    .await;
    db::log_action(&state.db, &actor, "gpo.delete", &guid, Some(id), &result).await;
    after_gpo_action(&state, &server, result).await
}

// ── GPO links page ────────────────────────────────────────────────────────────

pub async fn gpo_links(
    State(state): State<AppState>,
    Path((id, guid)): Path<(i64, String)>,
) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_gpo_links(&state, &server, &guid, None).await,
    }
}

/// What the links page shows: the GPO's name, its links, and the OUs it can be linked to.
struct GpoLinks {
    name: String,
    links: Vec<ldap::GpoLink>,
    ous: Vec<ldap::LdapOu>,
}

/// The links page of one GPO, with `flash_error` when an action on it just failed.
async fn render_gpo_links(state: &AppState, server: &Server, guid: &str, flash_error: Option<String>) -> Response {
    let loaded: Result<GpoLinks, String> = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        // The name is only for show: the GUID stands in if it cannot be read.
        let name = ldap::list_gpos(&mut conn, &base_dn)
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|g| g.guid_url.eq_ignore_ascii_case(guid))
            .map(|g| g.display_name)
            .unwrap_or_else(|| guid.to_string());
        let links = ldap::list_gpo_links(&mut conn, &base_dn, &gpo_dn).await?;
        let ous = ldap::list_ous(&mut conn, &base_dn).await?;
        Ok(GpoLinks { name, links, ous })
    }
    .await;
    let ctx = gpo_links_context(server, guid, loaded, flash_error);
    Html(state.tera.render("gpo_links.html", &ctx).unwrap_or_default()).into_response()
}

fn gpo_links_context(
    server: &Server,
    guid: &str,
    loaded: Result<GpoLinks, String>,
    flash_error: Option<String>,
) -> Context {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    ctx.insert("guid", guid);
    match loaded {
        Ok(page) => {
            ctx.insert("gpo_name", &page.name);
            ctx.insert("links", &page.links);
            ctx.insert("ous", &page.ous);
        }
        Err(e) => {
            ctx.insert("gpo_name", guid);
            ctx.insert("links", &Vec::<ldap::GpoLink>::new());
            ctx.insert("ous", &Vec::<ldap::LdapOu>::new());
            ctx.insert("error", &e);
        }
    }
    if let Some(e) = flash_error {
        ctx.insert("error", &e);
    }
    ctx
}

/// Back to the GPO's links on success; its links with the reason on failure.
async fn after_gpo_link_action(
    state: &AppState,
    server: &Server,
    guid: &str,
    result: Result<(), String>,
) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/gpo/{}/links", server.id, path_segment(guid))).into_response(),
        Err(e) => render_gpo_links(state, server, guid, Some(e)).await,
    }
}

// ── add GPO link ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct GpoLinkForm {
    pub ou_dn: String,
}

pub async fn gpo_link_add(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<GpoLinkForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        ldap::link_gpo_to_ou(&mut conn, &form.ou_dn, &gpo_dn).await
    }
    .await;
    let target = format!("{} → {}", guid, form.ou_dn);
    db::log_action(&state.db, &actor, "gpo.link", &target, Some(id), &result).await;
    after_gpo_link_action(&state, &server, &guid, result).await
}

// ── remove GPO link ───────────────────────────────────────────────────────────

pub async fn gpo_link_remove(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<GpoLinkForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        ldap::unlink_gpo_from_ou(&mut conn, &form.ou_dn, &gpo_dn).await
    }
    .await;
    let target = format!("{} ✕ {}", guid, form.ou_dn);
    db::log_action(&state.db, &actor, "gpo.unlink", &target, Some(id), &result).await;
    after_gpo_link_action(&state, &server, &guid, result).await
}

// ── user management ───────────────────────────────────────────────────────────

/// What the Users or Groups page shows: one OU or container (or the whole
/// domain), optionally with everything below it, and (users only) which accounts. It rides along in
/// the query string of every action on the page, so an action comes back to
/// the same view.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct ListView {
    /// DN of the OU or container; empty for the whole domain.
    pub ou: String,
    /// Non-empty: include users in nested OUs and containers.
    pub sub: String,
    /// `enabled`, `disabled`, `locked`, `expired` or `password`; anything else is all.
    pub status: String,
}

const STATUSES: [(&str, &str); 6] = [
    ("all", "All"),
    ("enabled", "Enabled"),
    ("disabled", "Disabled"),
    ("locked", "Locked"),
    ("expired", "Expired"),
    ("password", "Password to change"),
];

impl ListView {
    fn nested(&self) -> bool {
        !self.sub.is_empty()
    }

    fn status(&self) -> &'static str {
        STATUSES
            .iter()
            .find(|(k, _)| *k == self.status)
            .map_or("all", |(k, _)| k)
    }

    fn with(&self, ou: &str, nested: bool, status: &str) -> ListView {
        ListView { ou: ou.to_string(), sub: if nested { "1".into() } else { String::new() }, status: status.to_string() }
    }

    /// `""` for the default view, otherwise `?ou=…&sub=1&status=…`.
    fn query(&self) -> String {
        let mut parts = Vec::new();
        if !self.ou.is_empty() {
            parts.push(format!("ou={}", path_segment(&self.ou)));
            if self.nested() {
                parts.push("sub=1".to_string());
            }
        }
        if self.status() != "all" {
            parts.push(format!("status={}", self.status()));
        }
        if parts.is_empty() { String::new() } else { format!("?{}", parts.join("&")) }
    }

    /// Whether something in `container` is in this view's OU.
    fn holds(&self, container: &str) -> bool {
        self.ou.is_empty()
            || if self.nested() {
                ldap::is_within(container, &self.ou)
            } else {
                container.eq_ignore_ascii_case(&self.ou)
            }
    }

    fn shows(&self, u: &ldap::LdapUser) -> bool {
        self.holds(&u.container) && status_matches(u, self.status())
    }
}

fn status_matches(u: &ldap::LdapUser, status: &str) -> bool {
    match status {
        "enabled" => u.enabled,
        "disabled" => !u.enabled,
        "locked" => u.locked,
        "expired" => u.expired,
        "password" => !u.password.is_empty(),
        _ => true,
    }
}

#[derive(Serialize)]
struct TreeLink {
    /// Empty for the domain itself.
    dn: String,
    name: String,
    depth: usize,
    is_ou: bool,
    count: usize,
    href: String,
    active: bool,
}

#[derive(Serialize)]
struct StatusLink {
    key: &'static str,
    label: &'static str,
    count: usize,
    href: String,
    active: bool,
}

/// The view checked against the tree: the OU it shows (if any), and a message
/// when it asked for one that is not there and fell back to the whole domain.
fn resolve_view<'t>(
    requested: &ListView,
    base_dn: &str,
    tree: &'t [ldap::UserContainer],
    what: &str,
) -> (ListView, Option<&'t ldap::UserContainer>, Option<String>) {
    let mut view = requested.clone();
    if view.ou.eq_ignore_ascii_case(base_dn) {
        view.ou.clear();
    }
    let selected = tree.iter().find(|c| c.dn.eq_ignore_ascii_case(&view.ou));
    let mut error = None;
    match selected {
        Some(c) => view.ou = c.dn.clone(),
        None if !view.ou.is_empty() => {
            error = Some(format!("{} is not an OU or container with {what}; showing the whole domain.", view.ou));
            view.ou.clear();
        }
        None => {}
    }
    (view, selected, error)
}

/// The tree on the left and what goes with it, the same on the Users and
/// Groups pages. `page` turns a view into its URL; `total` counts everything.
fn insert_tree(
    ctx: &mut Context,
    page: &dyn Fn(&ListView) -> String,
    base_dn: &str,
    total: usize,
    tree: &[ldap::UserContainer],
    view: &ListView,
    selected: Option<&ldap::UserContainer>,
) {
    let mut links = vec![TreeLink {
        dn: String::new(),
        name: ldap::base_dn_to_domain(base_dn),
        depth: 0,
        is_ou: false,
        count: total,
        href: page(&view.with("", view.nested(), view.status())),
        active: view.ou.is_empty(),
    }];
    links.extend(tree.iter().map(|c| TreeLink {
        dn: c.dn.clone(),
        name: c.name.clone(),
        depth: c.depth,
        is_ou: c.is_ou,
        count: if view.nested() { c.total } else { c.direct },
        href: page(&view.with(&c.dn, view.nested(), view.status())),
        active: c.dn == view.ou,
    }));
    ctx.insert("tree", &links);
    ctx.insert("view_qs", &view.query());
    ctx.insert("nested", &view.nested());
    ctx.insert("nested_href", &page(&view.with(&view.ou, !view.nested(), view.status())));
    // The OU's own name; a list that spans several shows where each entry is.
    ctx.insert("selected", &selected.map(|c| c.name.clone()));
    // Where Add creates: the OU shown, except Builtin, which holds only
    // Windows' own groups; then the default container, Users.
    let create_in = selected.filter(|c| !ldap::is_builtin_container(&c.dn, base_dn));
    ctx.insert("create_in", &create_in.map(|c| c.name.clone()));
    ctx.insert("show_location", &(view.ou.is_empty() || view.nested()));
    ctx.insert("below", &selected.map_or(0, |c| c.total - c.direct));
}

/// Everything the users page needs, from the full user list and the tree.
/// A view of an OU that is not in the tree falls back to the whole domain.
fn users_context(
    ctx: &mut Context,
    server: &Server,
    base_dn: &str,
    all: &[ldap::LdapUser],
    tree: &[ldap::UserContainer],
    requested: &ListView,
) -> Option<String> {
    let (view, selected, error) = resolve_view(requested, base_dn, tree, "users");
    let page = |v: &ListView| format!("/servers/{}/users{}", server.id, v.query());
    insert_tree(ctx, &page, base_dn, all.len(), tree, &view, selected);

    let here = view.with(&view.ou, view.nested(), "all");
    let in_scope: Vec<&ldap::LdapUser> = all.iter().filter(|u| here.shows(u)).collect();
    let statuses: Vec<StatusLink> = STATUSES
        .iter()
        .map(|&(key, label)| StatusLink {
            key,
            label,
            count: in_scope.iter().filter(|u| status_matches(u, key)).count(),
            href: page(&view.with(&view.ou, view.nested(), key)),
            active: view.status() == key,
        })
        .collect();
    let users: Vec<&ldap::LdapUser> = in_scope.into_iter().filter(|u| view.shows(u)).collect();

    ctx.insert("users", &users);
    ctx.insert("directory", all);
    ctx.insert("statuses", &statuses);
    ctx.insert("status", view.status());
    error
}

/// The groups page's list and tree; like [`users_context`], without statuses.
fn groups_context(
    ctx: &mut Context,
    server: &Server,
    base_dn: &str,
    all: &[ldap::LdapGroup],
    tree: &[ldap::UserContainer],
    requested: &ListView,
) -> Option<String> {
    let (mut view, selected, error) = resolve_view(requested, base_dn, tree, "groups");
    view.status.clear();
    let page = |v: &ListView| format!("/servers/{}/groups{}", server.id, v.query());
    insert_tree(ctx, &page, base_dn, all.len(), tree, &view, selected);
    let groups: Vec<&ldap::LdapGroup> = all.iter().filter(|g| view.holds(&g.container)).collect();
    ctx.insert("groups", &groups);
    ctx.insert("any_groups", &!all.is_empty());
    error
}

/// The users page, with `flash_error` when an action on it just failed.
/// What the Users page needs when the DC could not be read: an empty list,
/// and the view its forms carry. Without the view the page fails to render
/// and comes out blank instead of showing why.
fn users_failed_context(ctx: &mut Context, view: &ListView) {
    ctx.insert("users", &Vec::<ldap::LdapUser>::new());
    ctx.insert("view_qs", &view.query());
}

async fn render_users(
    state: &AppState,
    server: &Server,
    view: &ListView,
    flash_error: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);

    let loaded: Result<_, String> = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let users = ldap::list_users(&mut conn, &base_dn).await?;
        let objects_in: Vec<&str> = users.iter().map(|u| u.container.as_str()).collect();
        let tree = ldap::list_containers(&mut conn, &base_dn, &objects_in).await?;
        let groups = ldap::group_names(&mut conn, &base_dn).await?;
        Ok((base_dn, users, tree, groups))
    }
    .await;
    let load_error = match loaded {
        Ok((base_dn, users, tree, groups)) => {
            ctx.insert("group_names", &groups);
            users_context(&mut ctx, server, &base_dn, &users, &tree, view)
        }
        Err(e) => {
            users_failed_context(&mut ctx, view);
            Some(e)
        }
    };
    if let Some(e) = flash_error.or(load_error) {
        ctx.insert("error", &e);
    }

    Html(state.tera.render("users.html", &ctx).unwrap_or_default()).into_response()
}

/// Back to the same view on success; the view with the reason on failure.
async fn after_user_action(
    state: &AppState,
    server: &Server,
    view: &ListView,
    result: Result<(), String>,
) -> Response {
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/users{}", server.id, view.query())).into_response(),
        Err(e) => render_users(state, server, view, Some(e)).await,
    }
}

pub async fn users(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(view): Query<ListView>,
) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_users(&state, &server, &view, None).await,
    }
}

// ── user profile fields ───────────────────────────────────────────────────────

/// The optional fields the Add and Edit user forms share. Missing fields are
/// empty, so a form posted by an older page still works.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ProfileForm {
    pub description: String,
    pub title: String,
    pub department: String,
    pub office: String,
    pub phone: String,
    pub mobile: String,
    pub manager: String,
    pub expires: String,
}

impl ProfileForm {
    fn as_profile(&self) -> ldap::UserProfile<'_> {
        ldap::UserProfile {
            description: self.description.trim(),
            title: self.title.trim(),
            department: self.department.trim(),
            office: self.office.trim(),
            phone: self.phone.trim(),
            mobile: self.mobile.trim(),
            manager: self.manager.trim(),
            expires: self.expires.trim(),
        }
    }
}

// ── create user ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
    #[serde(flatten)]
    pub profile: ProfileForm,
}

pub async fn create_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Query(view): Query<ListView>,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::create_user(
            &mut conn,
            &base_dn,
            &ldap::NewUser {
                username: form.username.trim(),
                first_name: form.first_name.trim(),
                last_name: form.last_name.trim(),
                email: form.email.trim(),
                password: &form.password,
                profile: form.profile.as_profile(),
                parent: &view.ou,
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "user.create", form.username.trim(), Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

// ── update user ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateUserForm {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
    #[serde(flatten)]
    pub profile: ProfileForm,
}

pub async fn update_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<ListView>,
    Form(form): Form<UpdateUserForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::update_user(
            &mut conn,
            &base_dn,
            &username,
            &ldap::UserUpdate {
                first_name: &form.first_name,
                last_name: &form.last_name,
                email: &form.email,
                password: &form.password,
                profile: form.profile.as_profile(),
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "user.update", &username, Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

// ── delete user ───────────────────────────────────────────────────────────────

pub async fn delete_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<ListView>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let user = ldap::find_user_for_change(&mut conn, &base_dn, &username, &server.bind_dn).await?;
        refuse_bind_account(user.is_bind, &username, "deleting")?;
        ldap::delete_user(&mut conn, &base_dn, &username).await
    }
    .await;
    db::log_action(&state.db, &actor, "user.delete", &username, Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

// ── enable / disable user ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ToggleForm {
    pub enable: String, // "true" or "false"
}

pub async fn toggle_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<ListView>,
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let user = ldap::find_user_for_change(&mut conn, &base_dn, &username, &server.bind_dn).await?;
        if !enable {
            refuse_bind_account(user.is_bind, &username, "disabling")?;
        }
        ldap::set_user_enabled(&mut conn, &user, enable).await
    }
    .await;
    let action = if enable { "user.enable" } else { "user.disable" };
    db::log_action(&state.db, &actor, action, &username, Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

// ── reset password ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    pub password: String,
    #[serde(default)]
    pub force_change: Option<String>, // checkbox sends "on" when ticked
}

pub async fn reset_password(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<ListView>,
    Form(form): Form<ResetPasswordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let force_change = form.force_change.is_some();
    let result: Result<(), String> = async {
        if form.password.is_empty() {
            return Err("Password cannot be empty".to_string());
        }
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::reset_password(&mut conn, &base_dn, &username, &form.password, force_change).await
    }
    .await;
    db::log_action(&state.db, &actor, "user.reset_password", &username, Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

/// EasyDC signs in to the DC with one account. Disabling, deleting or moving
/// it would lock EasyDC out, so those are refused with a way forward.
fn refuse_bind_account(is_bind: bool, username: &str, doing: &str) -> Result<(), String> {
    if is_bind {
        Err(format!(
            "EasyDC signs in to the DC as {username}, so {doing} it would lock EasyDC out. \
             To do it, first change the server's bind account (Edit on the dashboard)."
        ))
    } else {
        Ok(())
    }
}

// ── several users at once ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct BulkUsersForm {
    /// `enable`, `disable`, `move` or `add_to_group`.
    pub action: String,
    /// The selected usernames, one per line.
    pub users: String,
    /// The OU or container DN to move to, or the group to add to.
    #[serde(default)]
    pub target: String,
    /// "1" when the browser sends a big selection in parts.
    #[serde(default)]
    pub part: String,
}

/// Each selected name once, in the order given.
fn selected_names(users: &str) -> Vec<&str> {
    let mut seen = std::collections::HashSet::new();
    users
        .lines()
        .map(str::trim)
        .filter(|n| !n.is_empty() && seen.insert(n.to_lowercase()))
        .collect()
}

/// One sentence for a bulk action that did not fully work.
/// The page lists this many; the Audit Log has them all. (The Users page
/// script lists the same number when it sends a selection in parts.)
const FAILURES_LISTED: usize = 20;

fn bulk_summary(verb: &str, place: &str, total: usize, failed: &[String]) -> String {
    let done = total - failed.len();
    let users = if total == 1 { "user" } else { "users" };
    let mut listed = failed.iter().take(FAILURES_LISTED).cloned().collect::<Vec<_>>().join("; ");
    if failed.len() > FAILURES_LISTED {
        listed += &format!("; and {} more, listed in the Audit Log", failed.len() - FAILURES_LISTED);
    }
    format!("{verb} {done} of {total} {users}{place}. Not done: {listed}")
}

/// What a bulk action did: one sentence's worth, for the page or the browser.
#[derive(Serialize)]
struct BulkOutcome {
    /// "Disabled", "Moved", …
    verb: &'static str,
    /// " to Sales" for a move or a group; empty otherwise.
    place: String,
    total: usize,
    /// "name (reason)" for each user it was not done for.
    failed: Vec<String>,
}

/// A big selection comes from the browser in parts, so that no one request
/// runs long enough for a proxy in front of EasyDC to give up on it: the DC
/// writes about 30 changes a second, however they are sent. A part (`part=1`)
/// is answered with the outcome as JSON instead of a page.
pub async fn bulk_users(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Query(view): Query<ListView>,
    Form(form): Form<BulkUsersForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };
    let outcome = run_bulk(&state, &actor, &server, &form).await;
    if form.part == "1" {
        return match outcome {
            Ok(o) => axum::Json(o).into_response(),
            Err(e) => axum::Json(serde_json::json!({ "error": e })).into_response(),
        };
    }
    let result = outcome.and_then(|o| {
        if o.failed.is_empty() { Ok(()) } else { Err(bulk_summary(o.verb, &o.place, o.total, &o.failed)) }
    });
    after_user_action(&state, &server, &view, result).await
}

async fn run_bulk(state: &AppState, actor: &str, server: &Server, form: &BulkUsersForm) -> Result<BulkOutcome, String> {
    let names = selected_names(&form.users);
    let target = form.target.trim();
    let action = form.action.as_str();
    let (verb, audit) = match action {
        "enable" => ("Enabled", "user.enable"),
        "disable" => ("Disabled", "user.disable"),
        "move" => ("Moved", "user.move"),
        "add_to_group" => ("Added", "group.add_member"),
        other => return Err(format!("Unknown action '{other}'")),
    };
    if names.is_empty() {
        return Err("No users were selected".to_string());
    }
    let (mut conn, base_dn) = ldap::open(server).await?;
    // Checked once, not once per user: the group is looked up here and
    // reused for every user.
    let mut group = None;
    let place = match action {
        "move" => {
            if target.is_empty() {
                return Err("Pick an OU or container to move to".to_string());
            }
            let container = ldap::container_name(&mut conn, &base_dn, target).await?;
            format!(" to {container}")
        }
        "add_to_group" => {
            if target.is_empty() {
                return Err("Enter the group to add to".to_string());
            }
            let found = ldap::find_group(&mut conn, &base_dn, target).await?;
            let place = format!(" to {}", found.name);
            group = Some(found);
            place
        }
        _ => String::new(),
    };

    let results = match &group {
        Some(group) => add_users_to_group(&mut conn, &base_dn, group, &names).await?,
        None => {
            let mut results = Vec::with_capacity(names.len());
            for name in &names {
                results.push(bulk_one(&mut conn, &base_dn, &server.bind_dn, action, name, target).await);
            }
            results
        }
    };

    let mut failed = Vec::new();
    for (name, r) in names.iter().zip(results) {
        let logged = if target.is_empty() { name.to_string() } else { format!("{name} → {target}") };
        db::log_action(&state.db, actor, audit, &logged, Some(server.id), &r).await;
        if let Err(e) = r {
            failed.push(format!("{name} ({e})"));
        }
    }
    Ok(BulkOutcome { verb, place, total: names.len(), failed })
}

async fn bulk_one(
    conn: &mut ldap3::Ldap,
    base_dn: &str,
    bind: &str,
    action: &str,
    name: &str,
    target: &str,
) -> Result<(), String> {
    let user = ldap::find_user_for_change(conn, base_dn, name, bind).await?;
    match action {
        "enable" => ldap::set_user_enabled(conn, &user, true).await,
        "disable" => {
            refuse_bind_account(user.is_bind, name, "disabling")?;
            ldap::set_user_enabled(conn, &user, false).await
        }
        "move" => {
            // A bind account given as a DN stops working when the DN changes.
            refuse_bind_account(bind.trim().eq_ignore_ascii_case(&user.dn), name, "moving")?;
            ldap::move_entry(conn, base_dn, &user.dn, target).await
        }
        other => Err(format!("Unknown action '{other}'")),
    }
}

/// Bulk "Add to group": look every user up, leave out those already in the
/// group, and add the rest a few hundred per change. One result per name.
async fn add_users_to_group(
    conn: &mut ldap3::Ldap,
    base_dn: &str,
    group: &ldap::LdapGroup,
    names: &[&str],
) -> Result<Vec<Result<(), String>>, String> {
    let present: std::collections::HashSet<String> =
        ldap::group_member_dns(conn, &group.dn).await?.iter().map(|dn| dn.to_lowercase()).collect();
    let mut results: Vec<Result<(), String>> = vec![Ok(()); names.len()];
    let mut todo: Vec<(usize, String)> = Vec::new();
    for (i, name) in names.iter().enumerate() {
        match ldap::find_user_for_change(conn, base_dn, name, "").await {
            Err(e) => results[i] = Err(e),
            Ok(user) if present.contains(&user.dn.to_lowercase()) => {}
            Ok(user) => todo.push((i, user.dn)),
        }
    }
    let dns: Vec<String> = todo.iter().map(|(_, dn)| dn.clone()).collect();
    let added = ldap::add_member_dns(conn, group, &dns).await;
    for ((i, _), r) in todo.iter().zip(added) {
        results[*i] = match r {
            Err(e) if ldap::is_already_member(&e) => Ok(()),
            other => other,
        };
    }
    Ok(results)
}

// ── unlock account ─────────────────────────────────────────────────────────────

pub async fn unlock_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<ListView>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::unlock_user(&mut conn, &base_dn, &username).await
    }
    .await;
    db::log_action(&state.db, &actor, "user.unlock", &username, Some(id), &result).await;

    after_user_action(&state, &server, &view, result).await
}

#[cfg(test)]
mod dns_zone_tests {
    use crate::models::Server;
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
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    fn ctx(zones: &[&str], domain: &str) -> Context {
        let zone_objs: Vec<tera::Value> = zones
            .iter()
            .map(|z| {
                let mut m = tera::Map::new();
                m.insert("name".to_string(), tera::Value::String(z.to_string()));
                m.insert("dn".to_string(), tera::Value::String(format!("DC={}", z)));
                tera::Value::Object(m)
            })
            .collect();
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("zones", &zone_objs);
        c.insert("domain", domain);
        c
    }

    #[test]
    fn offers_zone_creation() {
        let html = tera().render("dns.html", &ctx(&["example.com"], "example.com")).expect("renders");
        assert!(html.contains("/servers/1/dns-zones/new"));
        assert!(html.contains("Reverse zone"));
        assert!(!html.contains("secret"), "bind password must not reach the page");
    }

    /// Deleting the realm's own zone would take the SRV records every member
    /// uses to find a DC. The handler refuses it; the button must not be there
    /// either.
    #[test]
    fn the_domain_zone_has_no_delete_button() {
        let html = tera()
            .render("dns.html", &ctx(&["example.com", "10.168.192.in-addr.arpa"], "example.com"))
            .expect("renders");
        assert!(html.contains("/servers/1/dns-zones/10.168.192.in-addr.arpa/delete"));
        assert!(!html.contains("/servers/1/dns-zones/example.com/delete"));
    }

    /// Regression: `domain` was set on one render path and not the other, so
    /// the comparison failed and unwrap_or_default() served a blank page.
    #[test]
    fn renders_even_without_the_domain_in_context() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("zones", &vec![tera::Value::Object({
            let mut m = tera::Map::new();
            m.insert("name".to_string(), tera::Value::String("example.com".to_string()));
            m
        })]);
        let html = tera().render("dns.html", &c).expect("renders without domain");
        assert!(html.contains("example.com"), "zones must still be listed");
        assert!(!html.contains("/delete"), "without a domain, no delete buttons");
    }

    #[test]
    fn shows_the_notice_after_a_change() {
        let mut c = ctx(&["example.com"], "example.com");
        c.insert("notice", "Zone test.example created and served immediately — no restart needed.");
        let html = tera().render("dns.html", &c).expect("renders");
        assert!(html.contains("alert-info"));
        assert!(html.contains("served immediately"));
    }

    /// The confirmation must name the restart caveat, since that is the part
    /// that surprises people.
    #[test]
    fn delete_confirmation_warns_about_the_restart() {
        let html = tera()
            .render("dns.html", &ctx(&["example.com", "other.test"], "example.com"))
            .expect("renders");
        assert!(html.contains("Type the zone name to confirm"));
        assert!(html.contains("until samba is"));
    }

    fn zone_ctx(node: &str, rtype: &str, value: &str) -> Context {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("zone_name", "example.com");
        c.insert(
            "nodes",
            &vec![crate::ldap::DnsNode {
                name: node.to_string(),
                records: vec![crate::ldap::DnsRecord {
                    node_name: node.to_string(),
                    record_type: rtype.to_string(),
                    value: value.to_string(),
                    ttl: 900,
                    raw_hex: "abcd".to_string(),
                }],
            }],
        );
        c
    }

    #[test]
    fn records_have_edit_buttons_and_srv_can_be_added() {
        let html = tera()
            .render("dns_zone.html", &zone_ctx("_ldap._tcp", "SRV", "0 100 389 dc1.example.com"))
            .unwrap();
        assert!(html.contains(r#"action="/servers/1/dns/example.com/edit""#));
        assert!(html.contains(r#"data-value="0 100 389 dc1.example.com""#));
        assert!(html.contains(r#"data-raw="abcd""#));
        assert!(html.contains(r#"<option value="SRV">"#));
    }

    #[test]
    fn soa_has_no_edit_or_delete() {
        let html = tera().render("dns_zone.html", &zone_ctx("@", "SOA", "(zone authority)")).unwrap();
        assert!(!html.contains("data-raw="));
        assert!(!html.contains("data-confirm="));
    }

    /// A record name comes from the directory, where a client's dynamic update
    /// may have put it. It must stay text: no script, no attribute break-out.
    #[test]
    fn hostile_names_are_escaped() {
        let evil = r#"x');alert(1);//"><img src=x>"#;
        let html = tera().render("dns_zone.html", &zone_ctx(evil, "A", "10.0.0.1")).unwrap();
        assert!(!html.contains("<img src=x>"));
        assert!(!html.contains(r#""><img"#));
        assert!(!html.contains("onsubmit"));
    }
}

#[cfg(test)]
mod users_page_tests {
    use super::{users_context, CreateUserForm, UpdateUserForm, ListView};
    use crate::ldap::{self, LdapUser};
    use crate::models::Server;
    use tera::{Context, Tera};

    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    const BASE: &str = "DC=example,DC=com";

    fn server() -> Server {
        Server {
            id: 1,
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    /// The page as the handler builds it: the users, the tree they give, a view.
    fn page(users: &[LdapUser], view: &ListView, error: Option<&str>) -> (String, Option<String>) {
        let found = vec![
            (format!("CN=Users,{BASE}"), false),
            (format!("OU=Sales,{BASE}"), true),
            (format!("OU=Europe,OU=Sales,{BASE}"), true),
        ];
        let tree = tree_of(found, users);
        let mut c = Context::new();
        c.insert("server", &server());
        let fallback = users_context(&mut c, &server(), BASE, users, &tree, view);
        if let Some(e) = error.map(str::to_string).or(fallback.clone()) {
            c.insert("error", &e);
        }
        (tera().render("users.html", &c).unwrap(), fallback)
    }

    fn render(users: &[LdapUser]) -> String {
        page(users, &ListView::default(), None).0
    }

    fn tree_of(found: Vec<(String, bool)>, users: &[LdapUser]) -> Vec<ldap::UserContainer> {
        let objects_in: Vec<&str> = users.iter().map(|u| u.container.as_str()).collect();
        ldap::container_tree(BASE, found, &objects_in)
    }

    fn user_in(name: &str, container: &str) -> LdapUser {
        let container = format!("{container},{BASE}");
        LdapUser {
            dn: format!("CN={name},{container}"),
            username: name.to_string(),
            display_name: name.to_string(),
            enabled: true,
            container,
            ..Default::default()
        }
    }

    fn user(name: &str) -> LdapUser {
        user_in(name, "CN=Users")
    }

    fn view(ou: &str, nested: bool, status: &str) -> ListView {
        ListView {
            ou: if ou.is_empty() { String::new() } else { format!("{ou},{BASE}") },
            sub: if nested { "1".into() } else { String::new() },
            status: status.into(),
        }
    }

    /// Usernames in the table, in order.
    fn listed(html: &str) -> Vec<String> {
        html.split(r#"<i class="bi bi-person-circle me-1 text-secondary"></i>"#)
            .skip(1)
            .map(|s| s.split_whitespace().next().unwrap_or_default().to_string())
            .collect()
    }

    fn people() -> Vec<LdapUser> {
        let mut off = user_in("carol", "OU=Europe,OU=Sales");
        off.enabled = false;
        vec![user("alice"), user_in("bob", "OU=Sales"), off]
    }

    #[test]
    fn an_ou_shows_its_own_users_or_everything_below_it() {
        let users = people();
        assert_eq!(listed(&render(&users)), ["alice", "bob", "carol"], "the whole domain by default");
        assert_eq!(listed(&page(&users, &view("OU=Sales", false, ""), None).0), ["bob"]);
        assert_eq!(listed(&page(&users, &view("OU=Sales", true, ""), None).0), ["bob", "carol"]);
        assert_eq!(listed(&page(&users, &view("CN=Users", false, ""), None).0), ["alice"]);
    }

    #[test]
    fn status_buttons_filter_and_count_within_the_ou() {
        let users = people();
        let (html, _) = page(&users, &view("", false, "disabled"), None);
        assert_eq!(listed(&html), ["carol"]);
        let (html, _) = page(&users, &view("OU=Sales", true, "enabled"), None);
        assert_eq!(listed(&html), ["bob"]);
        // Counts are for the OU being shown: Sales and below has 2, 1 disabled.
        assert!(html.contains("All <span class=\"ms-1 opacity-75\">2</span>"), "{html}");
        assert!(html.contains("Disabled <span class=\"ms-1 opacity-75\">1</span>"));
        let (html, _) = page(&users, &view("", false, "locked"), None);
        assert!(listed(&html).is_empty());
        assert!(html.contains("No locked accounts in this view."));
        let (html, _) = page(&users, &view("", false, "password"), None);
        assert!(html.contains("No user in this view has a password to change."), "{html}");
    }

    #[test]
    fn a_password_to_change_is_shown_and_filtered() {
        let mut users = people();
        users[0].password = "must_change";
        users[1].password = "expired";
        let (html, _) = page(&users, &view("", false, ""), None);
        assert_eq!(html.matches("Must change password</span>").count(), 1);
        assert_eq!(html.matches("Password expired</span>").count(), 1);
        let (html, _) = page(&users, &view("", false, "password"), None);
        assert_eq!(listed(&html).len(), 2);
        assert!(html.contains("Password to change <span class=\"ms-1 opacity-75\">2</span>"), "{html}");
    }

    #[test]
    fn users_can_be_selected_and_moved() {
        let (html, _) = page(&people(), &view("OU=Sales", true, ""), None);
        assert!(html.contains(r#"class="form-check-input js-select" value="bob""#));
        // The bulk form comes back to the same view.
        assert!(html.contains("/users/bulk?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom&amp;sub=1"));
        // Move targets: every OU and container, not the domain itself.
        assert!(html.contains(r#"<option value="OU=Sales,DC=example,DC=com">Sales</option>"#), "{html}");
        assert!(html.contains(
            r#"<option value="OU=Europe,OU=Sales,DC=example,DC=com">&nbsp;&nbsp;&nbsp;Europe</option>"#
        ));
        assert!(!html.contains(r#"<option value="">"#));
        assert!(html.contains(r#"data-user="carol""#), "{html}");
        assert!(html.contains(r#"class="dropdown-item js-move-one""#));
    }

    #[test]
    fn one_set_of_dialogs_for_any_number_of_users() {
        let html = render(&people());
        // The list is paged and searched in the browser.
        assert!(html.contains(r#"<tbody data-paged="users" data-search-input="userSearch">"#));
        // Edit, Reset password and Delete exist once, not once per user.
        for id in ["editUserModal", "resetUserModal", "deleteUserModal"] {
            assert_eq!(html.matches(&format!(r#"id="{id}""#)).count(), 1, "{id}");
        }
        assert!(!html.contains("editModal1"));
    }

    #[test]
    fn group_names_are_suggested() {
        let users = people();
        let tree = tree_of(vec![], &users);
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("group_names", &vec!["Domain Admins", "<Sales>"]);
        users_context(&mut c, &server(), BASE, &users, &tree, &ListView::default());
        let html = tera().render("users.html", &c).unwrap();
        assert!(html.contains(r#"<option value="Domain Admins">"#));
        assert!(html.contains(r#"<option value="&lt;Sales&gt;">"#), "escaped");
    }

    #[test]
    fn selected_names_are_trimmed_and_unique() {
        assert_eq!(super::selected_names("bob\r\n alice \n\nBOB\ncarol"), ["bob", "alice", "carol"]);
        assert!(super::selected_names("\n \n").is_empty());
    }

    #[test]
    fn a_partial_bulk_action_says_what_failed() {
        let failed = vec!["bob (Sales already holds an object named Bob)".to_string()];
        assert_eq!(
            super::bulk_summary("Moved", " to Sales", 3, &failed),
            "Moved 2 of 3 users to Sales. Not done: bob (Sales already holds an object named Bob)"
        );
        assert_eq!(
            super::bulk_summary("Disabled", "", 1, &["admin (no)".into()]),
            "Disabled 0 of 1 user. Not done: admin (no)"
        );
    }

    #[test]
    fn a_long_list_of_failures_is_cut_short() {
        let failed: Vec<String> = (1..=25).map(|i| format!("u{i} (no)")).collect();
        let e = super::bulk_summary("Disabled", "", 100, &failed);
        assert!(e.starts_with("Disabled 75 of 100 users. Not done: u1 (no); "), "{e}");
        assert!(e.contains("u20 (no)") && !e.contains("u21 (no)"), "{e}");
        assert!(e.ends_with("; and 5 more, listed in the Audit Log"), "{e}");
    }

    /// The Users page script reads these names when it sends a selection in parts.
    #[test]
    fn a_part_is_answered_with_what_the_page_reads() {
        let o = super::BulkOutcome { verb: "Moved", place: " to Sales".into(), total: 100, failed: vec!["bob (x)".into()] };
        let v = serde_json::to_value(&o).unwrap();
        assert_eq!(v, serde_json::json!({ "verb": "Moved", "place": " to Sales", "total": 100, "failed": ["bob (x)"] }));
        let page = std::fs::read_to_string("templates/users.html").unwrap();
        for read in ["answer.error", "answer.failed", "outcome.verb", "outcome.place", "part: '1'"] {
            assert!(page.contains(read), "users.html no longer reads {read}");
        }
    }

    #[test]
    fn the_bind_account_is_protected() {
        assert!(super::refuse_bind_account(false, "bob", "disabling").is_ok());
        let e = super::refuse_bind_account(true, "Administrator", "disabling").unwrap_err();
        assert!(e.contains("EasyDC signs in to the DC as Administrator"));
        assert!(e.contains("disabling it would lock EasyDC out"));
        assert!(e.contains("Edit on the dashboard"));
    }

    #[test]
    fn an_empty_ou_points_to_nested_users_only_when_there_are_some() {
        let users = [user_in("carol", "OU=Europe,OU=Sales")];
        let (html, _) = page(&users, &view("OU=Sales", false, ""), None);
        assert!(html.contains("users below it"), "Europe holds carol");
        let (html, _) = page(&users, &view("OU=Europe,OU=Sales", false, "disabled"), None);
        assert!(!html.contains("users below it"));
        let (html, _) = page(&[user("alice")], &view("OU=Sales", false, ""), None);
        assert!(html.contains("This OU or container holds no users."));
        assert!(!html.contains("users below it"));
    }

    #[test]
    fn the_tree_counts_users_and_links_keep_the_view() {
        let users = people();
        let (html, _) = page(&users, &view("OU=Sales", true, "disabled"), None);
        assert!(html.contains("example.com"), "the domain is the top of the tree");
        assert!(html.contains(r#"<span class="text-muted fw-normal">in Sales</span>"#));
        // Links to other OUs keep "nested" and the status filter.
        assert!(html.contains("ou=OU%3DEurope%2COU%3DSales%2CDC%3Dexample%2CDC%3Dcom&amp;sub=1&amp;status=disabled"), "{html}");
        // An action comes back to the same view.
        assert!(html.contains(r#"data-qs="?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom&amp;sub=1&amp;status=disabled""#), "{html}");
        assert!(html.contains("/toggle?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom&amp;sub=1&amp;status=disabled"));
        // And a new user is created in the OU being shown.
        assert!(html.contains("/users/new?ou=OU%3DSales"));
        assert!(html.contains("Created in\n                        <strong>Sales</strong>"));
    }

    #[test]
    fn an_unknown_ou_falls_back_to_the_whole_domain() {
        let (html, err) = page(&people(), &view("OU=Gone", false, ""), None);
        assert!(err.unwrap().contains("is not an OU or container"));
        assert_eq!(listed(&html).len(), 3);
    }

    #[test]
    fn the_view_survives_the_query_string() {
        let v = ListView { ou: format!("OU=Doe\\, J & Co+,{BASE}"), sub: "1".into(), status: "expired".into() };
        let back: ListView = serde_urlencoded::from_str(&v.query()[1..]).unwrap();
        assert_eq!(back.ou, v.ou);
        assert!(back.nested());
        assert_eq!(back.status(), "expired");
        assert_eq!(ListView::default().query(), "");
        let odd = ListView { status: "<script>".into(), ..Default::default() };
        assert_eq!(odd.query(), "", "an unknown status is just 'all'");
    }

    #[test]
    fn description_is_a_column_and_editable() {
        let mut u = user("ivan");
        u.description = "Иван Петров".into();
        let html = render(&[u]);
        assert!(html.contains(r#"<td class="small text-break">Иван Петров</td>"#));
        assert!(html.contains(r#"data-description="Иван Петров""#));
        let f: UpdateUserForm =
            serde_urlencoded::from_str("first_name=&last_name=&email=&password=&description=+Ivan+").unwrap();
        assert_eq!(f.profile.as_profile().description, "Ivan");
    }

    #[test]
    fn location_shows_when_the_list_spans_several_ous() {
        let mut u = user_in("bob", "OU=Sales");
        u.location = "Sales".into();
        let html = render(&[u.clone()]);
        assert!(html.contains("bi-folder2 me-1\"></i>Sales</div>"));
        let (html, _) = page(&[u], &view("OU=Sales", false, ""), None);
        assert!(!html.contains("bi-folder2 me-1\"></i>Sales</div>"), "one OU: no need");
    }

    #[test]
    fn profile_and_expiry_are_shown_and_editable() {
        let mut u = user("contractor");
        u.title = "Consultant".into();
        u.department = "IT".into();
        u.manager = "boss".into();
        u.expires = "2026-12-31".into();
        let mut gone = user("former");
        gone.expires = "2025-01-31".into();
        gone.expired = true;
        let html = render(&[u, gone, user("boss")]);

        assert!(html.contains("Consultant · IT"));
        assert!(html.contains("Until 2026-12-31"));
        assert!(html.contains("Expired"));
        assert!(html.contains(r#"data-expires="2026-12-31""#));
        assert!(html.contains(r#"data-manager="boss""#), "manager prefilled");
        // One shared list of usernames for the manager field, not one per user.
        assert_eq!(html.matches(r#"<datalist id="userDirectory">"#).count(), 1);
        assert!(html.contains(r#"<option value="boss">boss</option>"#));
    }

    #[test]
    fn a_failure_is_shown_above_the_list() {
        let (html, _) = page(
            &[user("someone")],
            &ListView::default(),
            Some("The password was not changed: the password does not meet the password policy"),
        );
        assert!(html.contains("alert-danger"));
        assert!(html.contains("does not meet the password policy"));
        assert!(html.contains("someone"), "the list is still there");
    }

    #[test]
    fn a_dc_that_cannot_be_reached_still_gets_a_page() {
        let mut c = Context::new();
        c.insert("server", &server());
        super::users_failed_context(&mut c, &view("OU=Sales", true, "disabled"));
        c.insert("error", "Connection failed: the domain controller did not answer within 10 seconds");
        let html = tera().render("users.html", &c).map_err(|e| format!("{e:?}")).unwrap();
        assert!(html.contains("did not answer within 10 seconds"));
    }

    #[test]
    fn no_expiry_no_badge() {
        let html = render(&[user("plain")]);
        assert!(!html.contains("Until "));
        assert!(!html.contains("bi-calendar-x"));
    }

    #[test]
    fn hostile_profile_values_are_escaped() {
        let mut u = user("victim");
        let evil = r#""><img src=x onerror=alert(1)>"#;
        u.title = evil.into();
        u.manager = evil.into();
        u.office = evil.into();
        u.description = evil.into();
        u.location = evil.into();
        let html = render(&[u]);
        assert!(!html.contains("<img src=x"));
    }

    /// A form posted by a page from before these fields existed still parses.
    #[test]
    fn old_forms_still_parse() {
        let f: UpdateUserForm =
            serde_urlencoded::from_str("first_name=A&last_name=B&email=&password=").unwrap();
        assert_eq!(f.profile.expires, "");
        let f: CreateUserForm = serde_urlencoded::from_str(
            "username=u&first_name=&last_name=&email=&password=p&title=CTO&expires=2026-12-31",
        )
        .unwrap();
        assert_eq!(f.profile.title, "CTO");
        assert_eq!(f.profile.as_profile().expires, "2026-12-31");
    }
}

#[cfg(test)]
mod groups_page_tests {
    use super::{groups_context, path_segment, AddMemberForm, ListView, UpdateGroupForm};
    use crate::ldap::{self, GroupMember, LdapGroup};
    use crate::models::Server;
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
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    fn group(name: &str, gt: i64, system: bool) -> LdapGroup {
        LdapGroup {
            dn: format!("CN={name},CN=Users,DC=example,DC=com"),
            name: name.to_string(),
            description: String::new(),
            group_type: gt,
            group_type_label: String::new(),
            scope: crate::ldap::GroupScope::of(gt),
            security: gt < 0,
            system,
            member_count: 0,
            container: "CN=Users,DC=example,DC=com".to_string(),
            location: "Users".to_string(),
        }
    }

    const BASE: &str = "DC=example,DC=com";

    /// The groups page as the handler builds it, for a view.
    fn groups_page(groups: &[LdapGroup], view: &ListView) -> (String, Option<String>) {
        let found = vec![
            (format!("CN=Users,{BASE}"), false),
            (format!("CN=Builtin,{BASE}"), false),
            (format!("OU=Sales,{BASE}"), true),
            (format!("OU=Europe,OU=Sales,{BASE}"), true),
        ];
        let objects_in: Vec<&str> = groups.iter().map(|g| g.container.as_str()).collect();
        let tree = ldap::container_tree(BASE, found, &objects_in);
        let mut c = Context::new();
        c.insert("server", &server());
        let err = groups_context(&mut c, &server(), BASE, groups, &tree, view);
        (tera().render("groups.html", &c).unwrap(), err)
    }

    fn group_in(name: &str, container: &str, location: &str) -> LdapGroup {
        LdapGroup {
            dn: format!("CN={name},{container},{BASE}"),
            container: format!("{container},{BASE}"),
            location: location.to_string(),
            ..group(name, -2147483646, false)
        }
    }

    fn listed(html: &str) -> Vec<String> {
        html.split(r#"<i class="bi bi-people-fill me-1 text-secondary"></i>"#)
            .skip(1)
            .map(|s| s.split_whitespace().next().unwrap_or_default().to_string())
            .collect()
    }

    fn ou(ou: &str, nested: bool) -> ListView {
        ListView { ou: format!("{ou},{BASE}"), sub: if nested { "1".into() } else { String::new() }, status: String::new() }
    }

    #[test]
    fn groups_can_be_browsed_by_ou() {
        let groups = vec![
            group_in("Admins", "CN=Builtin", "Builtin"),
            group_in("Sales", "OU=Sales", "Sales"),
            group_in("EU", "OU=Europe,OU=Sales", "Sales › Europe"),
        ];
        let (html, _) = groups_page(&groups, &ListView::default());
        assert_eq!(listed(&html), ["Admins", "Sales", "EU"]);
        assert!(html.contains("Builtin"), "CN=Builtin is in the tree");
        assert!(html.contains("bi-folder2 me-1\"></i>Sales › Europe</div>"), "location shown");

        let (html, _) = groups_page(&groups, &ou("OU=Sales", false));
        assert_eq!(listed(&html), ["Sales"]);
        assert!(html.contains(r#"<span class="text-muted fw-normal">in Sales</span>"#));
        // Actions come back here, and a new group is created here.
        assert!(html.contains("/groups/Sales/edit?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom"));
        assert!(html.contains("/groups/new?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom"));
        assert!(html.contains("Created in\n                        <strong>Sales</strong>"));

        // Builtin holds only Windows' own groups: new ones go to Users.
        let (html, _) = groups_page(&groups, &ou("CN=Builtin", false));
        assert_eq!(listed(&html), ["Admins"]);
        assert!(html.contains("Created in\n                        <strong>Users</strong>"), "{html}");
        assert!(crate::ldap::is_builtin_container("CN=Builtin,DC=example,DC=com", BASE));
        assert!(!crate::ldap::is_builtin_container("CN=Builtin,OU=x,DC=example,DC=com", BASE));

        let (html, _) = groups_page(&groups, &ou("OU=Sales", true));
        assert_eq!(listed(&html), ["Sales", "EU"]);
    }

    #[test]
    fn an_empty_ou_and_an_unknown_one() {
        let groups = vec![group_in("EU", "OU=Europe,OU=Sales", "Sales › Europe")];
        let (html, _) = groups_page(&groups, &ou("OU=Sales", false));
        assert!(html.contains("No groups here"));
        assert!(html.contains("to see the groups below it"));
        let (html, err) = groups_page(&groups, &ou("OU=Gone", false));
        assert!(err.unwrap().contains("not an OU or container with groups"));
        assert_eq!(listed(&html), ["EU"]);
    }

    #[test]
    fn names_stay_one_path_segment() {
        assert_eq!(path_segment("Domain Admins"), "Domain%20Admins");
        assert_eq!(path_segment("Sales/EMEA?x#y"), "Sales%2FEMEA%3Fx%23y");
        assert_eq!(path_segment("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(path_segment("ש"), "%D7%A9");
    }

    #[test]
    fn edit_dialog_offers_scope_only_for_ordinary_groups() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("groups", &vec![group("Team", -2147483646, false), group("Domain Admins", -2147483646, true)]);
        let html = tera().render("groups.html", &c).unwrap();
        // One Edit dialog for every group, filled from the row's button.
        assert_eq!(html.matches(r#"id="editGroupModal""#).count(), 1);
        assert_eq!(html.matches(r#"<select name="scope""#).count(), 1);
        // An ordinary group carries its scope; a built-in one none, so the
        // dialog shows scope and type as fixed and does not send them.
        assert!(html.contains(r#"data-scope="global""#), "{html}");
        assert_eq!(html.matches(r#"data-scope="""#).count(), 1);
        assert_eq!(html.matches(r#"data-system="1""#).count(), 1);
        assert!(html.contains("a built-in group"));
        assert!(html.contains("/groups/Domain%20Admins/edit"));
    }

    fn member(name: &str, kind: &'static str, enabled: Option<bool>) -> GroupMember {
        GroupMember {
            dn: format!("CN={name},CN=Users,DC=example,DC=com"),
            name: name.to_string(),
            display_name: String::new(),
            kind,
            detail: String::new(),
            group: (kind == "group").then(|| name.to_string()),
            enabled,
        }
    }

    fn members_page(members: Vec<GroupMember>, member_of: Vec<LdapGroup>, error: Option<&str>) -> String {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("group_name", "Administrators");
        c.insert("group", &group("Administrators", -2147483643, true));
        c.insert("members", &members);
        c.insert("member_of", &member_of);
        c.insert("candidates", &vec!["yariv".to_string(), "Domain Admins".to_string()]);
        if let Some(e) = error {
            c.insert("error", e);
        }
        tera().render("group_members.html", &c).unwrap()
    }

    #[test]
    fn member_rows_stay_small() {
        // A group can have thousands of members: the page grows by one row
        // each, so the row must stay lean (it was 1.4 KB; now about 0.7 KB).
        let one = |i: usize| {
            let mut m = member(&format!("test{i:04}"), "user", Some(true));
            m.display_name = format!("Test User {i:04}");
            m
        };
        let empty = members_page(vec![one(0)], vec![], None).len();
        let html = members_page((0..1001).map(one).collect(), vec![], None);
        let per_row = (html.len() - empty) / 1000;
        assert!(per_row < 800, "{per_row} bytes per member row");
    }

    #[test]
    fn members_of_every_kind_are_listed_and_removable_by_dn() {
        let html = members_page(
            vec![member("Domain Admins", "group", None), member("yariv", "user", Some(true)),
                 member("PC1$", "computer", Some(false)), member("Authenticated Users", "foreign", None)],
            vec![group("Parent Group", -2147483640, false)],
            None,
        );
        assert!(html.contains("/groups/Domain%20Admins/members\">Domain Admins</a>"), "nested group links");
        assert!(html.contains("bi-pc-display"));
        assert!(html.contains("Built-in identity"));
        // Each row's remove button carries the member's DN to one shared dialog.
        assert_eq!(html.matches(r##"data-bs-target="#removeMemberModal""##).count(), 4);
        assert_eq!(html.matches(r#"id="removeMemberModal""#).count(), 1);
        assert!(html.contains(r#"data-dn="CN=yariv,CN=Users,DC=example,DC=com""#));
        assert!(html.contains(r#"<input type="hidden" name="member_dn" data-fill="dn">"#));
        assert!(html.contains("/groups/Parent%20Group/members"), "member of");
        assert!(html.contains(r#"<option value="Domain Admins">"#));
        assert!(!html.contains("no other group"));
    }

    #[test]
    fn a_refusal_is_shown_on_the_page() {
        let html = members_page(vec![], vec![], Some("Team is a global group and cannot contain All, a universal group"));
        assert!(html.contains("cannot contain All"));
        assert!(html.contains("no other group"));
        assert!(!html.contains("No members in this group"), "an error, not an empty group");
    }

    #[test]
    fn hostile_member_names_are_escaped() {
        let mut m = member("x", "user", Some(true));
        m.name = r#""><img src=x onerror=alert(1)>"#.into();
        m.dn = r#"CN=\"><img src=x>,DC=x"#.into();
        let html = members_page(vec![m], vec![], None);
        assert!(!html.contains("<img src=x"));
    }

    #[test]
    fn forms_parse_old_and_new() {
        let f: UpdateGroupForm = serde_urlencoded::from_str("description=x").unwrap();
        assert!(f.scope.is_none() && f.kind.is_none());
        let f: UpdateGroupForm = serde_urlencoded::from_str("description=&scope=universal&kind=security").unwrap();
        assert_eq!(f.scope.as_deref(), Some("universal"));
        let f: AddMemberForm = serde_urlencoded::from_str("username=yariv").unwrap();
        assert_eq!(f.member, "yariv");
    }
}

#[cfg(test)]
mod computer_gpo_page_tests {
    use super::{computers_context, gpo_context, gpo_links_context, GpoLinks};
    use crate::ldap::{GpoLink, LdapComputer, LdapGpo, LdapOu};
    use crate::models::Server;
    use tera::{Context, Tera};

    fn tera() -> Tera {
        let mut t = Tera::new("templates/**/*.html").expect("templates parse");
        t.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
            Ok(tera::Value::String("test".to_string()))
        });
        t
    }

    fn render(page: &str, c: &Context) -> String {
        tera().render(page, c).map_err(|e| format!("{e:?}")).unwrap()
    }

    fn server() -> Server {
        Server {
            id: 1,
            name: "DC1".to_string(),
            ldap_url: "ldaps://dc1.example.com".to_string(),
            bind_dn: "CN=Administrator,CN=Users,DC=example,DC=com".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    fn computer(name: &str) -> LdapComputer {
        LdapComputer {
            dn: format!("CN={name},CN=Computers,DC=example,DC=com"),
            name: name.to_string(),
            sam_account: format!("{name}$"),
            dns_hostname: format!("{}.example.com", name.to_lowercase()),
            os: "Windows 11 Pro".to_string(),
            os_version: "10.0".to_string(),
            enabled: true,
        }
    }

    const GUID: &str = "31B2F340-016D-11D2-945F-00C04FB984F9";

    fn gpo(name: &str) -> LdapGpo {
        LdapGpo {
            dn: format!("CN={{{GUID}}},CN=Policies,CN=System,DC=example,DC=com"),
            guid: format!("{{{GUID}}}"),
            guid_url: GUID.to_string(),
            display_name: name.to_string(),
            flags: 0,
            version: 1,
            file_sys_path: String::new(),
            status_label: "Enabled".to_string(),
        }
    }

    const REFUSED: &str = "Insufficient access rights";
    const SILENT: &str = "Connection failed: the domain controller did not answer within 10 seconds";

    #[test]
    fn a_failed_computer_action_is_shown_above_the_list() {
        let c = computers_context(&server(), Ok(vec![computer("PC-01")]), Some(REFUSED.into()));
        let html = render("computers.html", &c);
        assert!(html.contains(REFUSED));
        assert!(html.contains("PC-01"));
    }

    #[test]
    fn the_computers_page_renders_when_the_list_did_not_load() {
        let html = render("computers.html", &computers_context(&server(), Err(SILENT.into()), None));
        assert!(html.contains(SILENT));
        // And the action's reason wins over the list's.
        let c = computers_context(&server(), Err(SILENT.into()), Some(REFUSED.into()));
        assert!(render("computers.html", &c).contains(REFUSED));
    }

    #[test]
    fn a_failed_gpo_action_is_shown_above_the_list() {
        let c = gpo_context(&server(), Ok(vec![gpo("Desktop Policy")]), Some(REFUSED.into()));
        let html = render("gpo.html", &c);
        assert!(html.contains(REFUSED));
        assert!(html.contains("Desktop Policy"));
    }

    #[test]
    fn the_gpo_page_renders_when_the_list_did_not_load() {
        let html = render("gpo.html", &gpo_context(&server(), Err(SILENT.into()), None));
        assert!(html.contains(SILENT));
    }

    #[test]
    fn a_failed_link_change_is_shown_above_the_links() {
        let page = GpoLinks {
            name: "Desktop Policy".to_string(),
            links: vec![GpoLink {
                ou_dn: "OU=Sales,DC=example,DC=com".to_string(),
                ou_name: "Sales".to_string(),
                link_flags: 0,
                link_status: "Enabled".to_string(),
            }],
            ous: vec![LdapOu { dn: "OU=Sales,DC=example,DC=com".to_string(), name: "Sales".to_string() }],
        };
        let html = render("gpo_links.html", &gpo_links_context(&server(), GUID, Ok(page), Some(REFUSED.into())));
        assert!(html.contains(REFUSED));
        assert!(html.contains("OU=Sales,DC=example,DC=com"));
    }

    #[test]
    fn the_links_page_renders_when_the_links_did_not_load() {
        let html = render("gpo_links.html", &gpo_links_context(&server(), GUID, Err(SILENT.into()), None));
        assert!(html.contains(SILENT));
        assert!(html.contains(GUID));
    }
}
