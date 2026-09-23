use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

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

fn redirect_users(id: i64) -> Response {
    Redirect::to(&format!("/servers/{}/users", id)).into_response()
}

// ── group list ────────────────────────────────────────────────────────────────

pub async fn groups(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("groups", &Vec::<ldap::LdapGroup>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_groups(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("groups", &Vec::<ldap::LdapGroup>::new());
            }
            Ok(group_list) => {
                ctx.insert("groups", &group_list);
            }
        },
    }

    Html(state.tera.render("groups.html", &ctx).unwrap_or_default()).into_response()
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
                name: &form.name,
                description: &form.description,
                group_type: form.group_type,
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "group.create", &form.name, Some(id), &result).await;

    Redirect::to(&format!("/servers/{}/groups", id)).into_response()
}

// ── update group ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGroupForm {
    pub description: String,
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
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::update_group(
            &mut conn,
            &base_dn,
            &name,
            &ldap::GroupUpdate {
                description: &form.description,
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "group.update", &name, Some(id), &result).await;

    Redirect::to(&format!("/servers/{}/groups", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/groups", id)).into_response()
}

// ── group members page ────────────────────────────────────────────────────────

pub async fn group_members(
    State(state): State<AppState>,
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    ctx.insert("group_name", &name);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("members", &Vec::<ldap::LdapUser>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_group_members(&mut conn, &base_dn, &name).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("members", &Vec::<ldap::LdapUser>::new());
            }
            Ok(members) => {
                ctx.insert("members", &members);
            }
        },
    }

    Html(state.tera.render("group_members.html", &ctx).unwrap_or_default()).into_response()
}

// ── add / remove member ───────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct AddMemberForm {
    pub username: String,
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

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::add_group_member(&mut conn, &base_dn, &group_name, &form.username).await
    }
    .await;
    let target = format!("{} → {}", form.username, group_name);
    db::log_action(&state.db, &actor, "group.add_member", &target, Some(id), &result).await;

    Redirect::to(&format!("/servers/{}/groups/{}/members", id, group_name)).into_response()
}

pub async fn remove_member(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, group_name, username)): Path<(i64, String, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::remove_group_member(&mut conn, &base_dn, &group_name, &username).await
    }
    .await;
    let target = format!("{} ✕ {}", username, group_name);
    db::log_action(&state.db, &actor, "group.remove_member", &target, Some(id), &result).await;

    Redirect::to(&format!("/servers/{}/groups/{}/members", id, group_name)).into_response()
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
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
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
    let target = format!("OU={},{}", form.name, form.parent_dn);
    db::log_action(&state.db, &actor, "ou.create", &target, Some(id), &result).await;

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
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

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
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

pub async fn users(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("users", &Vec::<ldap::LdapUser>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_users(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("users", &Vec::<ldap::LdapUser>::new());
            }
            Ok(user_list) => {
                ctx.insert("users", &user_list);
            }
        },
    }

    Html(state.tera.render("users.html", &ctx).unwrap_or_default()).into_response()
}

// ── create user ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct CreateUserForm {
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

pub async fn create_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
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
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "user.create", &form.username, Some(id), &result).await;

    redirect_users(id)
}

// ── update user ───────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateUserForm {
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    pub password: String,
}

pub async fn update_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
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
            },
        )
        .await
    }
    .await;
    db::log_action(&state.db, &actor, "user.update", &username, Some(id), &result).await;

    redirect_users(id)
}

// ── delete user ───────────────────────────────────────────────────────────────

pub async fn delete_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::delete_user(&mut conn, &base_dn, &username).await
    }
    .await;
    db::log_action(&state.db, &actor, "user.delete", &username, Some(id), &result).await;

    redirect_users(id)
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
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::set_user_enabled(&mut conn, &base_dn, &username, enable).await
    }
    .await;
    let action = if enable { "user.enable" } else { "user.disable" };
    db::log_action(&state.db, &actor, action, &username, Some(id), &result).await;

    redirect_users(id)
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

    redirect_users(id)
}

// ── unlock account ─────────────────────────────────────────────────────────────

pub async fn unlock_user(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, username)): Path<(i64, String)>,
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

    redirect_users(id)
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
}
