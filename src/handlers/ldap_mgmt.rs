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
async fn render_groups(state: &AppState, server: &Server, flash_error: Option<String>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);

    let loaded = match ldap::open(server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::list_groups(&mut conn, &base_dn).await,
    };
    let (groups, load_error) = match loaded {
        Ok(g) => (g, None),
        Err(e) => (Vec::new(), Some(e)),
    };
    ctx.insert("groups", &groups);
    if let Some(e) = flash_error.or(load_error) {
        ctx.insert("error", &e);
    }

    Html(state.tera.render("groups.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn groups(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => redirect_home(),
        Some(server) => render_groups(&state, &server, None).await,
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
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "group.create", &form.name, Some(id), &result).await;

    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/groups", id)).into_response(),
        Err(e) => render_groups(&state, &server, Some(e)).await,
    }
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

    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/groups", id)).into_response(),
        Err(e) => render_groups(&state, &server, Some(e)).await,
    }
}

// ── delete group ──────────────────────────────────────────────────────────────

pub async fn delete_group(
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
        ldap::delete_group(&mut conn, &base_dn, &name).await
    }
    .await;
    db::log_action(&state.db, &actor, "group.delete", &name, Some(id), &result).await;

    match result {
        Ok(()) => Redirect::to(&format!("/servers/{}/groups", id)).into_response(),
        Err(e) => render_groups(&state, &server, Some(e)).await,
    }
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

    let loaded = match ldap::open(server).await {
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
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("computers", &Vec::<ldap::LdapComputer>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_computers(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("computers", &Vec::<ldap::LdapComputer>::new());
            }
            Ok(list) => {
                ctx.insert("computers", &list);
            }
        },
    }

    Html(state.tera.render("computers.html", &ctx).unwrap_or_default()).into_response()
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

    Redirect::to(&format!("/servers/{}/computers", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/computers", id)).into_response()
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

    match ldap::open(server).await {
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
    let target = format!("OU={},{}", ldap::dn_escape(&form.name), form.parent_dn);
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

    match ldap::open(server).await {
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

    let load_error = match ldap::open(server).await {
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
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("gpos", &Vec::<ldap::LdapGpo>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_gpos(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("gpos", &Vec::<ldap::LdapGpo>::new());
            }
            Ok(list) => {
                ctx.insert("gpos", &list);
            }
        },
    }

    Html(state.tera.render("gpo.html", &ctx).unwrap_or_default()).into_response()
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

    Redirect::to(&format!("/servers/{}/gpo", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/gpo", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/gpo", id)).into_response()
}

// ── GPO links page ────────────────────────────────────────────────────────────

pub async fn gpo_links(
    State(state): State<AppState>,
    Path((id, guid)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    ctx.insert("guid", &guid);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("gpo_name", &guid);
            ctx.insert("links", &Vec::<ldap::GpoLink>::new());
            ctx.insert("ous", &Vec::<ldap::LdapOu>::new());
        }
        Ok((mut conn, base_dn)) => {
            let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);

            // Load GPO name for display
            let gpo_name = ldap::list_gpos(&mut conn, &base_dn)
                .await
                .unwrap_or_default()
                .into_iter()
                .find(|g| g.guid_url.to_uppercase() == guid.to_uppercase())
                .map(|g| g.display_name)
                .unwrap_or_else(|| guid.clone());
            ctx.insert("gpo_name", &gpo_name);

            let links = ldap::list_gpo_links(&mut conn, &base_dn, &gpo_dn)
                .await
                .unwrap_or_default();
            ctx.insert("links", &links);

            let ous = ldap::list_ous(&mut conn, &base_dn).await.unwrap_or_default();
            ctx.insert("ous", &ous);
        }
    }

    Html(state.tera.render("gpo_links.html", &ctx).unwrap_or_default()).into_response()
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

    Redirect::to(&format!("/servers/{}/gpo/{}/links", id, guid)).into_response()
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

    Redirect::to(&format!("/servers/{}/gpo/{}/links", id, guid)).into_response()
}

// ── user management ───────────────────────────────────────────────────────────

/// What the users page shows: one OU or container (or the whole domain),
/// optionally with everything below it, and which accounts. It rides along in
/// the query string of every action on the page, so an action comes back to
/// the same view.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct UsersView {
    /// DN of the OU or container; empty for the whole domain.
    pub ou: String,
    /// Non-empty: include users in nested OUs and containers.
    pub sub: String,
    /// `enabled`, `disabled`, `locked` or `expired`; anything else is all.
    pub status: String,
}

const STATUSES: [(&str, &str); 5] = [
    ("all", "All"),
    ("enabled", "Enabled"),
    ("disabled", "Disabled"),
    ("locked", "Locked"),
    ("expired", "Expired"),
];

impl UsersView {
    fn nested(&self) -> bool {
        !self.sub.is_empty()
    }

    fn status(&self) -> &'static str {
        STATUSES
            .iter()
            .find(|(k, _)| *k == self.status)
            .map_or("all", |(k, _)| k)
    }

    fn with(&self, ou: &str, nested: bool, status: &str) -> UsersView {
        UsersView { ou: ou.to_string(), sub: if nested { "1".into() } else { String::new() }, status: status.to_string() }
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

    fn shows(&self, u: &ldap::LdapUser) -> bool {
        let here = self.ou.is_empty()
            || if self.nested() {
                ldap::is_within(&u.container, &self.ou)
            } else {
                u.container.eq_ignore_ascii_case(&self.ou)
            };
        here && status_matches(u, self.status())
    }
}

fn status_matches(u: &ldap::LdapUser, status: &str) -> bool {
    match status {
        "enabled" => u.enabled,
        "disabled" => !u.enabled,
        "locked" => u.locked,
        "expired" => u.expired,
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

/// Everything the users page needs, from the full user list and the tree.
/// A view of an OU that is not in the tree falls back to the whole domain.
fn users_context(
    ctx: &mut Context,
    server: &Server,
    base_dn: &str,
    all: &[ldap::LdapUser],
    tree: &[ldap::UserContainer],
    requested: &UsersView,
) -> Option<String> {
    let mut view = requested.clone();
    let mut error = None;
    if view.ou.eq_ignore_ascii_case(base_dn) {
        view.ou.clear();
    }
    let selected = tree.iter().find(|c| c.dn.eq_ignore_ascii_case(&view.ou));
    if !view.ou.is_empty() && selected.is_none() {
        error = Some(format!("{} is not an OU or container with users; showing the whole domain.", view.ou));
        view.ou.clear();
    }
    if let Some(c) = selected {
        view.ou = c.dn.clone();
    }
    let page = |v: &UsersView| format!("/servers/{}/users{}", server.id, v.query());

    let mut links = vec![TreeLink {
        dn: String::new(),
        name: ldap::base_dn_to_domain(base_dn),
        depth: 0,
        is_ou: false,
        count: all.len(),
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
    ctx.insert("tree", &links);
    ctx.insert("statuses", &statuses);
    ctx.insert("status", view.status());
    ctx.insert("view_qs", &view.query());
    ctx.insert("nested", &view.nested());
    ctx.insert("nested_href", &page(&view.with(&view.ou, !view.nested(), view.status())));
    // The OU's own name; a user list that spans several shows where each user is.
    ctx.insert("selected", &selected.map(|c| c.name.clone()));
    ctx.insert("show_location", &(view.ou.is_empty() || view.nested()));
    ctx.insert("below", &selected.map_or(0, |c| c.total - c.direct));
    error
}

/// The users page, with `flash_error` when an action on it just failed.
async fn render_users(
    state: &AppState,
    server: &Server,
    view: &UsersView,
    flash_error: Option<String>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);

    let loaded: Result<_, String> = async {
        let (mut conn, base_dn) = ldap::open(server).await?;
        let users = ldap::list_users(&mut conn, &base_dn).await?;
        let tree = ldap::list_user_containers(&mut conn, &base_dn, &users).await?;
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
            ctx.insert("users", &Vec::<ldap::LdapUser>::new());
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
    view: &UsersView,
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
    Query(view): Query<UsersView>,
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
    Query(view): Query<UsersView>,
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
                username: &form.username,
                first_name: &form.first_name,
                last_name: &form.last_name,
                email: &form.email,
                password: &form.password,
                profile: form.profile.as_profile(),
                parent: &view.ou,
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "user.create", &form.username, Some(id), &result).await;

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
    Query(view): Query<UsersView>,
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
    Query(view): Query<UsersView>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let (_, is_bind) = ldap::find_user_for_change(&mut conn, &base_dn, &username, &server.bind_dn).await?;
        refuse_bind_account(is_bind, &username, "deleting")?;
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
    Query(view): Query<UsersView>,
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        if !enable {
            let (_, is_bind) = ldap::find_user_for_change(&mut conn, &base_dn, &username, &server.bind_dn).await?;
            refuse_bind_account(is_bind, &username, "disabling")?;
        }
        ldap::set_user_enabled(&mut conn, &base_dn, &username, enable).await
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
    Query(view): Query<UsersView>,
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
fn bulk_summary(verb: &str, place: &str, total: usize, failed: &[String]) -> String {
    let done = total - failed.len();
    let users = if total == 1 { "user" } else { "users" };
    format!("{verb} {done} of {total} {users}{place}. Not done: {}", failed.join("; "))
}

pub async fn bulk_users(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Query(view): Query<UsersView>,
    Form(form): Form<BulkUsersForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };
    let names = selected_names(&form.users);
    let target = form.target.trim();
    let action = form.action.as_str();

    let result: Result<(), String> = async {
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
        let (mut conn, base_dn) = ldap::open(&server).await?;
        // Checked once, not once per user.
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
                format!(" to {}", ldap::find_group(&mut conn, &base_dn, target).await?.name)
            }
            _ => String::new(),
        };

        let mut failed = Vec::new();
        for name in &names {
            let r = bulk_one(&mut conn, &base_dn, &server.bind_dn, action, name, target).await;
            let logged = if target.is_empty() { name.to_string() } else { format!("{name} → {target}") };
            db::log_action(&state.db, &actor, audit, &logged, Some(id), &r).await;
            if let Err(e) = r {
                failed.push(format!("{name} ({e})"));
            }
        }
        if failed.is_empty() { Ok(()) } else { Err(bulk_summary(verb, &place, names.len(), &failed)) }
    }
    .await;

    after_user_action(&state, &server, &view, result).await
}

async fn bulk_one(
    conn: &mut ldap3::Ldap,
    base_dn: &str,
    bind: &str,
    action: &str,
    name: &str,
    target: &str,
) -> Result<(), String> {
    let (dn, is_bind) = ldap::find_user_for_change(conn, base_dn, name, bind).await?;
    match action {
        "enable" => ldap::set_user_enabled(conn, base_dn, name, true).await,
        "disable" => {
            refuse_bind_account(is_bind, name, "disabling")?;
            ldap::set_user_enabled(conn, base_dn, name, false).await
        }
        "move" => {
            // A bind account given as a DN stops working when the DN changes.
            refuse_bind_account(bind.trim().eq_ignore_ascii_case(&dn), name, "moving")?;
            ldap::move_entry(conn, base_dn, &dn, target).await
        }
        _ => match ldap::add_group_member(conn, base_dn, target, name).await {
            Err(e) if ldap::is_already_member(&e) => Ok(()),
            other => other,
        },
    }
}

// ── unlock account ─────────────────────────────────────────────────────────────

pub async fn unlock_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
    Query(view): Query<UsersView>,
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
    use super::{users_context, CreateUserForm, UpdateUserForm, UsersView};
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
    fn page(users: &[LdapUser], view: &UsersView, error: Option<&str>) -> (String, Option<String>) {
        let found = vec![
            (format!("CN=Users,{BASE}"), false),
            (format!("OU=Sales,{BASE}"), true),
            (format!("OU=Europe,OU=Sales,{BASE}"), true),
        ];
        let tree = ldap::user_tree(BASE, found, users);
        let mut c = Context::new();
        c.insert("server", &server());
        let fallback = users_context(&mut c, &server(), BASE, users, &tree, view);
        if let Some(e) = error.map(str::to_string).or(fallback.clone()) {
            c.insert("error", &e);
        }
        (tera().render("users.html", &c).unwrap(), fallback)
    }

    fn render(users: &[LdapUser]) -> String {
        page(users, &UsersView::default(), None).0
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

    fn view(ou: &str, nested: bool, status: &str) -> UsersView {
        UsersView {
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
        assert!(html.contains(r#"data-user="carol" title="Move to another OU""#));
    }

    #[test]
    fn group_names_are_suggested() {
        let users = people();
        let tree = ldap::user_tree(BASE, vec![], &users);
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("group_names", &vec!["Domain Admins", "<Sales>"]);
        users_context(&mut c, &server(), BASE, &users, &tree, &UsersView::default());
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
        assert!(html.contains("/users/carol/edit?ou=OU%3DSales%2CDC%3Dexample%2CDC%3Dcom&amp;sub=1&amp;status=disabled"));
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
        let v = UsersView { ou: format!("OU=Doe\\, J & Co+,{BASE}"), sub: "1".into(), status: "expired".into() };
        let back: UsersView = serde_urlencoded::from_str(&v.query()[1..]).unwrap();
        assert_eq!(back.ou, v.ou);
        assert!(back.nested());
        assert_eq!(back.status(), "expired");
        assert_eq!(UsersView::default().query(), "");
        let odd = UsersView { status: "<script>".into(), ..Default::default() };
        assert_eq!(odd.query(), "", "an unknown status is just 'all'");
    }

    #[test]
    fn description_is_a_column_and_editable() {
        let mut u = user("ivan");
        u.description = "Иван Петров".into();
        let html = render(&[u]);
        assert!(html.contains(r#"<td class="small text-break">Иван Петров</td>"#));
        assert!(html.contains(r#"maxlength="1024"
                            value="Иван Петров""#));
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
        assert!(html.contains(r#"name="expires" class="form-control w-auto"
                            value="2026-12-31""#));
        assert!(html.contains(r#"value="boss">"#), "manager prefilled");
        // One shared list of usernames for the manager field, not one per user.
        assert_eq!(html.matches(r#"<datalist id="userDirectory">"#).count(), 1);
        assert!(html.contains(r#"<option value="boss">boss</option>"#));
    }

    #[test]
    fn a_failure_is_shown_above_the_list() {
        let (html, _) = page(
            &[user("someone")],
            &UsersView::default(),
            Some("The password was not changed: the password does not meet the password policy"),
        );
        assert!(html.contains("alert-danger"));
        assert!(html.contains("does not meet the password policy"));
        assert!(html.contains("someone"), "the list is still there");
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
    use super::{path_segment, AddMemberForm, UpdateGroupForm};
    use crate::ldap::{GroupMember, LdapGroup};
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
        }
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
        assert_eq!(html.matches(r#"<select name="scope""#).count(), 1);
        assert!(html.contains(r#"<option value="global" selected>"#));
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
        assert_eq!(html.matches(r#"name="member_dn""#).count(), 4);
        assert!(html.contains(r#"value="CN=yariv,CN=Users,DC=example,DC=com""#));
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
