use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{ldap, models::Server, AppState};

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
    Path(id): Path<i64>,
    Form(form): Form<CreateGroupForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::create_group(
            &mut conn,
            &base_dn,
            &ldap::NewGroup {
                name: &form.name,
                description: &form.description,
                group_type: form.group_type,
            },
        )
        .await;
    }

    Redirect::to(&format!("/servers/{}/groups", id)).into_response()
}

// ── update group ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct UpdateGroupForm {
    pub description: String,
}

pub async fn update_group(
    State(state): State<AppState>,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<UpdateGroupForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::update_group(
            &mut conn,
            &base_dn,
            &name,
            &ldap::GroupUpdate {
                description: &form.description,
            },
        )
        .await;
    }

    Redirect::to(&format!("/servers/{}/groups", id)).into_response()
}

// ── delete group ──────────────────────────────────────────────────────────────

pub async fn delete_group(
    State(state): State<AppState>,
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::delete_group(&mut conn, &base_dn, &name).await;
    }

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
    Path((id, group_name)): Path<(i64, String)>,
    Form(form): Form<AddMemberForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::add_group_member(&mut conn, &base_dn, &group_name, &form.username).await;
    }

    Redirect::to(&format!("/servers/{}/groups/{}/members", id, group_name)).into_response()
}

pub async fn remove_member(
    State(state): State<AppState>,
    Path((id, group_name, username)): Path<(i64, String, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ =
            ldap::remove_group_member(&mut conn, &base_dn, &group_name, &username).await;
    }

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
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::delete_computer(&mut conn, &base_dn, &name).await;
    }

    Redirect::to(&format!("/servers/{}/computers", id)).into_response()
}

pub async fn toggle_computer(
    State(state): State<AppState>,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::set_computer_enabled(&mut conn, &base_dn, &name, enable).await;
    }

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
    Path(id): Path<i64>,
    Form(form): Form<CreateOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, _)) = ldap::open(&server).await {
        let _ = ldap::create_ou(&mut conn, &form.parent_dn, &form.name, &form.description).await;
    }

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
    Path(id): Path<i64>,
    Form(form): Form<RenameOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, _)) = ldap::open(&server).await {
        let _ = ldap::rename_ou(&mut conn, &form.ou_dn, &form.new_name).await;
    }

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
}

// ── delete OU ─────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteOuForm {
    pub ou_dn: String,
}

pub async fn ou_delete(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Form(form): Form<DeleteOuForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, _)) = ldap::open(&server).await {
        let _ = ldap::delete_ou(&mut conn, &form.ou_dn).await;
    }

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
    Path(id): Path<i64>,
    Form(form): Form<MoveObjectForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::move_object_to_ou(&mut conn, &base_dn, &form.sam_account, &form.target_ou_dn).await;
    }

    Redirect::to(&format!("/servers/{}/ous", id)).into_response()
}

// ── DNS zone list ─────────────────────────────────────────────────────────────

pub async fn dns(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let mut ctx = Context::new();
    ctx.insert("server", &server);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("zones", &Vec::<ldap::LdapDnsZone>::new());
        }
        Ok((mut conn, base_dn)) => match ldap::list_dns_zones(&mut conn, &base_dn).await {
            Err(e) => {
                ctx.insert("error", &e);
                ctx.insert("zones", &Vec::<ldap::LdapDnsZone>::new());
            }
            Ok(zones) => {
                ctx.insert("zones", &zones);
            }
        },
    }

    Html(state.tera.render("dns.html", &ctx).unwrap_or_default()).into_response()
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

    let mut ctx = Context::new();
    ctx.insert("server", &server);
    ctx.insert("zone_name", &zone_name);

    match ldap::open(&server).await {
        Err(e) => {
            ctx.insert("error", &e);
            ctx.insert("nodes", &Vec::<ldap::DnsNode>::new());
        }
        Ok((mut conn, base_dn)) => {
            match ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
                Err(e) => {
                    ctx.insert("error", &e);
                    ctx.insert("nodes", &Vec::<ldap::DnsNode>::new());
                }
                Ok(zone_dn) => {
                    match ldap::list_dns_records(&mut conn, &zone_dn).await {
                        Err(e) => {
                            ctx.insert("error", &e);
                            ctx.insert("nodes", &Vec::<ldap::DnsNode>::new());
                        }
                        Ok(nodes) => {
                            ctx.insert("nodes", &nodes);
                        }
                    }
                }
            }
        }
    }

    Html(state.tera.render("dns_zone.html", &ctx).unwrap_or_default()).into_response()
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
    Path((id, zone_name)): Path<(i64, String)>,
    Form(form): Form<AddDnsRecordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        if let Ok(zone_dn) = ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
            let _ = ldap::add_dns_record(
                &mut conn,
                &zone_dn,
                &form.node_name,
                &form.record_type,
                &form.value,
                form.ttl,
            )
            .await;
        }
    }

    Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response()
}

// ── delete DNS record ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct DeleteDnsRecordForm {
    pub node_name: String,
    pub raw_hex: String,
}

pub async fn dns_delete_record(
    State(state): State<AppState>,
    Path((id, zone_name)): Path<(i64, String)>,
    Form(form): Form<DeleteDnsRecordForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        if let Ok(zone_dn) = ldap::find_zone_dn(&mut conn, &base_dn, &zone_name).await {
            let _ =
                ldap::delete_dns_record(&mut conn, &zone_dn, &form.node_name, &form.raw_hex)
                    .await;
        }
    }

    Redirect::to(&format!("/servers/{}/dns/{}", id, zone_name)).into_response()
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
    Path(id): Path<i64>,
    Form(form): Form<CreateGpoForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::create_gpo(&mut conn, &base_dn, &form.display_name).await;
    }

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
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<UpdateGpoForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        let _ = ldap::update_gpo(&mut conn, &gpo_dn, &form.display_name, form.flags).await;
    }

    Redirect::to(&format!("/servers/{}/gpo", id)).into_response()
}

// ── delete GPO ────────────────────────────────────────────────────────────────

pub async fn gpo_delete(
    State(state): State<AppState>,
    Path((id, guid)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        let _ = ldap::delete_gpo(&mut conn, &gpo_dn).await;
    }

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
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<GpoLinkForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        let _ = ldap::link_gpo_to_ou(&mut conn, &form.ou_dn, &gpo_dn).await;
    }

    Redirect::to(&format!("/servers/{}/gpo/{}/links", id, guid)).into_response()
}

// ── remove GPO link ───────────────────────────────────────────────────────────

pub async fn gpo_link_remove(
    State(state): State<AppState>,
    Path((id, guid)): Path<(i64, String)>,
    Form(form): Form<GpoLinkForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let gpo_dn = format!("CN={{{}}},CN=Policies,CN=System,{}", guid.to_uppercase(), base_dn);
        let _ = ldap::unlink_gpo_from_ou(&mut conn, &form.ou_dn, &gpo_dn).await;
    }

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
    Path(id): Path<i64>,
    Form(form): Form<CreateUserForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::create_user(
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
        .await;
    }

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
    Path((id, username)): Path<(i64, String)>,
    Form(form): Form<UpdateUserForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::update_user(
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
        .await;
    }

    redirect_users(id)
}

// ── delete user ───────────────────────────────────────────────────────────────

pub async fn delete_user(
    State(state): State<AppState>,
    Path((id, username)): Path<(i64, String)>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::delete_user(&mut conn, &base_dn, &username).await;
    }

    redirect_users(id)
}

// ── enable / disable user ─────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ToggleForm {
    pub enable: String, // "true" or "false"
}

pub async fn toggle_user(
    State(state): State<AppState>,
    Path((id, username)): Path<(i64, String)>,
    Form(form): Form<ToggleForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return redirect_home(),
        Some(s) => s,
    };

    let enable = form.enable == "true";
    if let Ok((mut conn, base_dn)) = ldap::open(&server).await {
        let _ = ldap::set_user_enabled(&mut conn, &base_dn, &username, enable).await;
    }

    redirect_users(id)
}
