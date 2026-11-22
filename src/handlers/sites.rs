//! The Sites and subnets page: sites with their DCs, subnets, and site links.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use super::ldap_mgmt::get_server;
use crate::{auth::CurrentUser, db, ldap, models::Server, sites, AppState};

pub async fn page(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render(&state, &server, None).await,
    }
}

async fn render(state: &AppState, server: &Server, flash_error: Option<String>) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    let loaded: Result<sites::Topology, String> = async {
        let (mut conn, base_dn) = ldap::open_after(server, flash_error.as_deref()).await?;
        let config = sites::config_dn(&mut conn, &base_dn).await;
        sites::load(&mut conn, &config).await
    }
    .await;
    let load_error = match loaded {
        Ok(t) => {
            ctx.insert("t", &t);
            None
        }
        Err(e) => Some(e),
    };
    if let Some(e) = flash_error.or(load_error) {
        ctx.insert("error", &e);
    }
    Html(crate::access::render(&state.tera, "sites.html", &ctx)).into_response()
}

/// Run a change against the server's configuration partition, log it, and
/// come back to the page (with the reason when it failed).
async fn change<F>(state: &AppState, actor: &str, id: i64, action: &str, target: &str, run: F) -> Response
where
    F: for<'c> FnOnce(&'c mut ldap3::Ldap, &'c str) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'c>>,
{
    let Some(server) = get_server(state, id).await else {
        return Redirect::to("/").into_response();
    };
    let result: Result<(), String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let config = sites::config_dn(&mut conn, &base_dn).await;
        run(&mut conn, &config).await
    }
    .await;
    db::log_action(&state.db, actor, action, target, Some(id), &result).await;
    match result {
        Ok(()) => Redirect::to(&format!("/servers/{id}/sites")).into_response(),
        Err(e) => render(state, &server, Some(e)).await,
    }
}

// ── sites ────────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct NewSiteForm {
    name: String,
    #[serde(default)]
    description: String,
    link: String,
}

pub async fn create_site(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(f): Form<NewSiteForm>,
) -> Response {
    let name = f.name.trim().to_string();
    change(&state, &actor, id, "site.create", &name.clone(), move |conn, config| {
        Box::pin(async move { sites::create_site(conn, config, &name, f.description.trim(), f.link.trim()).await })
    })
    .await
}

#[derive(Deserialize)]
pub struct SiteForm {
    #[serde(default)]
    description: String,
}

pub async fn update_site(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(f): Form<SiteForm>,
) -> Response {
    change(&state, &actor, id, "site.update", &name.clone(), move |conn, config| {
        Box::pin(async move { sites::update_site(conn, config, &name, f.description.trim()).await })
    })
    .await
}

pub async fn delete_site(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path((id, name)): Path<(i64, String)>) -> Response {
    change(&state, &actor, id, "site.delete", &name.clone(), move |conn, config| {
        Box::pin(async move { sites::delete_site(conn, config, &name).await })
    })
    .await
}

#[derive(Deserialize)]
pub struct MoveDcForm {
    dc: String,
    to: String,
}

pub async fn move_dc(State(state): State<AppState>, CurrentUser(actor): CurrentUser, Path(id): Path<i64>, Form(f): Form<MoveDcForm>) -> Response {
    let target = format!("{} → {}", f.dc, f.to);
    change(&state, &actor, id, "site.move_dc", &target, move |conn, config| {
        Box::pin(async move { sites::move_dc(conn, config, f.dc.trim(), f.to.trim()).await })
    })
    .await
}

// ── subnets ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct SubnetForm {
    #[serde(default)]
    subnet: String,
    #[serde(default)]
    site: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    location: String,
}

impl SubnetForm {
    fn change(&self) -> sites::SubnetChange<'_> {
        sites::SubnetChange { site: self.site.trim(), description: self.description.trim(), location: self.location.trim() }
    }
}

pub async fn create_subnet(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(f): Form<SubnetForm>,
) -> Response {
    let target = f.subnet.trim().to_string();
    change(&state, &actor, id, "subnet.create", &target, move |conn, config| {
        Box::pin(async move { sites::create_subnet(conn, config, &f.subnet, &f.change()).await.map(|_| ()) })
    })
    .await
}

pub async fn update_subnet(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, subnet)): Path<(i64, String)>,
    Form(f): Form<SubnetForm>,
) -> Response {
    change(&state, &actor, id, "subnet.update", &subnet.clone(), move |conn, config| {
        Box::pin(async move { sites::update_subnet(conn, config, &subnet, &f.change()).await })
    })
    .await
}

pub async fn delete_subnet(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, subnet)): Path<(i64, String)>,
) -> Response {
    change(&state, &actor, id, "subnet.delete", &subnet.clone(), move |conn, config| {
        Box::pin(async move { sites::delete_subnet(conn, config, &subnet).await })
    })
    .await
}

// ── site links ───────────────────────────────────────────────────────────────

/// The form, read as pairs: each ticked site is its own `site` field.
struct LinkForm {
    cost: String,
    interval: String,
    description: String,
    sites: Vec<String>,
}

impl LinkForm {
    fn from_pairs(pairs: Vec<(String, String)>) -> LinkForm {
        let mut f = LinkForm { cost: String::new(), interval: String::new(), description: String::new(), sites: Vec::new() };
        for (k, v) in pairs {
            match k.as_str() {
                "cost" => f.cost = v,
                "interval" => f.interval = v,
                "description" => f.description = v,
                "site" if !f.sites.contains(&v) => f.sites.push(v),
                _ => {}
            }
        }
        f
    }
}

pub async fn update_site_link(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let f = LinkForm::from_pairs(pairs);
    change(&state, &actor, id, "sitelink.update", &name.clone(), move |conn, config| {
        Box::pin(async move {
            let number = |label: &str, v: &str| v.trim().parse::<i64>().map_err(|_| format!("{label} is not a number."));
            let cost = number("The cost", &f.cost)?;
            let interval = number("The interval", &f.interval)?;
            let c = sites::LinkChange { cost, interval, description: f.description.trim(), sites: &f.sites };
            sites::update_site_link(conn, config, &name, &c).await
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sites::{Site, SiteDc, SiteLink, Subnet, Topology};

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

    fn topology() -> Topology {
        Topology {
            sites: vec![
                Site {
                    name: "Default-First-Site-Name".into(),
                    description: String::new(),
                    dcs: vec![SiteDc { name: "DC1".into(), host: "dc1.example.com".into() }],
                    subnets: vec!["10.0.0.0/16".into()],
                    links: vec!["DEFAULTIPSITELINK".into()],
                },
                Site {
                    name: "Branch".into(),
                    description: "Haifa office".into(),
                    subnets: vec!["10.1.0.0/16".into()],
                    links: vec!["DEFAULTIPSITELINK".into()],
                    ..Default::default()
                },
            ],
            subnets: vec![
                Subnet { name: "10.0.0.0/16".into(), site: "Default-First-Site-Name".into(), ..Default::default() },
                Subnet { name: "2001:db8::/48".into(), site: String::new(), description: "old".into(), ..Default::default() },
            ],
            links: vec![SiteLink {
                name: "DEFAULTIPSITELINK".into(),
                transport: "IP".into(),
                sites: vec!["Branch".into(), "Default-First-Site-Name".into()],
                cost: 100,
                interval: 180,
                every: "every 3 hours".into(),
                description: String::new(),
            }],
        }
    }

    fn render(t: &Topology) -> String {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("t", t);
        tera().render("sites.html", &c).unwrap()
    }

    #[test]
    fn the_page_shows_sites_subnets_and_links() {
        let html = render(&topology());
        assert!(html.contains("Default-First-Site-Name") && html.contains("Haifa office"));
        assert!(html.contains("dc1.example.com"));
        assert!(html.contains(r#"data-url="/servers/1/subnets/10%2E0%2E0%2E0%2F16/edit""#), "a subnet's / stays in one path segment");
        assert!(html.contains(r#"data-url="/servers/1/subnets/2001%3Adb8%3A%3A%2F48/delete""#));
        assert!(html.contains("No site"), "a subnet without a site is pointed out");
        assert!(html.contains(r#"data-url="/servers/1/site-links/DEFAULTIPSITELINK/edit""#));
        assert!(html.contains("every 3 hours"));
        assert!(html.contains(r#"data-needs="sites""#));
    }

    #[test]
    fn a_site_with_a_dc_offers_no_delete() {
        let html = render(&topology());
        assert!(html.contains(r#"data-url="/servers/1/sites/Branch/delete""#));
        assert!(!html.contains(r#"data-url="/servers/1/sites/Default%2DFirst%2DSite%2DName/delete""#));
        assert!(html.contains(r#"data-dc="DC1""#), "a DC can be moved");
        assert!(html.contains("Its subnets (10.1.0.0&#x2F;16) stay, with no site"), "deleting says what happens to its subnets");
    }

    #[test]
    fn an_empty_domain_says_what_to_do() {
        let html = render(&Topology::default());
        assert!(html.contains("No subnets yet"));
    }

    #[test]
    fn a_site_link_form_reads_every_ticked_site() {
        let pairs: Vec<(String, String)> = serde_urlencoded::from_str("cost=50&interval=60&site=HQ&site=Lab&site=HQ&description=x").unwrap();
        let f = LinkForm::from_pairs(pairs);
        assert_eq!((f.cost.as_str(), f.interval.as_str(), f.description.as_str()), ("50", "60", "x"));
        assert_eq!(f.sites, ["HQ", "Lab"]);
    }
}
