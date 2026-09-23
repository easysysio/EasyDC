mod auth;
mod db;
mod handlers;
mod health;
mod ldap;
mod models;

use std::sync::Arc;

use axum::{middleware, routing::{get, post}, Router};
use rust_embed::RustEmbed;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePool};
use std::str::FromStr;
use tera::Tera;

#[derive(RustEmbed)]
#[folder = "templates/"]
struct Templates;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub tera: Arc<Tera>,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{}", USAGE);
        return;
    }
    let port = match parse_port(&args, std::env::var("EASYDC_PORT").ok()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("EasyDC: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };

    tracing_subscriber::fmt::init();

    let opts = SqliteConnectOptions::from_str("sqlite://easydc.db")
        .unwrap()
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(opts)
        .await
        .expect("Failed to connect to database");

    db::init_tables(&pool).await.expect("Failed to initialize database");

    let mut tera = Tera::default();
    // Collect all templates first, then register them together so template
    // inheritance (e.g. {% extends "base.html" %}) resolves regardless of the
    // order rust-embed iterates files in.
    let raw: Vec<(String, String)> = Templates::iter()
        .map(|path| {
            let content = Templates::get(&path).unwrap();
            let source = std::str::from_utf8(content.data.as_ref())
                .expect("Template is not valid UTF-8")
                .to_string();
            (path.to_string(), source)
        })
        .collect();
    tera.add_raw_templates(raw.iter().map(|(n, s)| (n.as_str(), s.as_str())))
        .expect("Failed to load templates");
    tera.register_function("app_version", |_: &std::collections::HashMap<String, tera::Value>| {
        Ok(tera::Value::String(env!("CARGO_PKG_VERSION").to_string()))
    });

    let state = AppState {
        db: pool,
        tera: Arc::new(tera),
    };

    let public = Router::new()
        .route("/setup", get(handlers::setup::get_setup).post(handlers::setup::post_setup))
        .route("/login", get(handlers::auth_handlers::get_login).post(handlers::auth_handlers::post_login));

    let protected = Router::new()
        .route("/", get(handlers::servers::dashboard))
        .route("/audit", get(handlers::servers::audit))
        .route("/settings", get(handlers::settings::settings))
        .route("/settings/password", post(handlers::settings::change_password))
        .route("/settings/admins/new", post(handlers::settings::create_admin))
        .route("/settings/admins/:username/delete", post(handlers::settings::delete_admin))
        .route("/logout", post(handlers::auth_handlers::logout))
        .route("/servers/new", post(handlers::servers::create_server))
        .route("/servers/:id", get(handlers::servers::server_detail))
        .route("/servers/:id/edit", post(handlers::servers::update_server))
        .route("/servers/:id/delete", post(handlers::servers::delete_server))
        .route("/servers/:id/health", get(handlers::health::health_check))
        .route("/servers/:id/users", get(handlers::ldap_mgmt::users))
        .route("/servers/:id/users/new", post(handlers::ldap_mgmt::create_user))
        .route("/servers/:id/users/:username/edit", post(handlers::ldap_mgmt::update_user))
        .route("/servers/:id/users/:username/delete", post(handlers::ldap_mgmt::delete_user))
        .route("/servers/:id/users/:username/toggle", post(handlers::ldap_mgmt::toggle_user))
        .route("/servers/:id/users/:username/reset-password", post(handlers::ldap_mgmt::reset_password))
        .route("/servers/:id/users/:username/unlock", post(handlers::ldap_mgmt::unlock_user))
        .route("/servers/:id/groups", get(handlers::ldap_mgmt::groups))
        .route("/servers/:id/groups/new", post(handlers::ldap_mgmt::create_group))
        .route("/servers/:id/groups/:name/edit", post(handlers::ldap_mgmt::update_group))
        .route("/servers/:id/groups/:name/delete", post(handlers::ldap_mgmt::delete_group))
        .route("/servers/:id/groups/:name/members", get(handlers::ldap_mgmt::group_members))
        .route("/servers/:id/groups/:name/members/add", post(handlers::ldap_mgmt::add_member))
        .route("/servers/:id/groups/:name/members/:username/remove", post(handlers::ldap_mgmt::remove_member))
        .route("/servers/:id/ous", get(handlers::ldap_mgmt::ous))
        .route("/servers/:id/ous/new", post(handlers::ldap_mgmt::ou_create))
        .route("/servers/:id/ous/rename", post(handlers::ldap_mgmt::ou_rename))
        .route("/servers/:id/ous/delete", post(handlers::ldap_mgmt::ou_delete))
        .route("/servers/:id/ous/move", post(handlers::ldap_mgmt::ou_move_object))
        .route("/servers/:id/computers", get(handlers::ldap_mgmt::computers))
        .route("/servers/:id/computers/:name/delete", post(handlers::ldap_mgmt::delete_computer))
        .route("/servers/:id/computers/:name/toggle", post(handlers::ldap_mgmt::toggle_computer))
        .route("/servers/:id/dns", get(handlers::ldap_mgmt::dns))
        .route("/servers/:id/dns/:zone", get(handlers::ldap_mgmt::dns_zone))
        .route("/servers/:id/dns/:zone/add", post(handlers::ldap_mgmt::dns_add_record))
        .route("/servers/:id/dns/:zone/delete", post(handlers::ldap_mgmt::dns_delete_record))
        .route("/servers/:id/dns-zones/new", post(handlers::ldap_mgmt::dns_zone_create))
        .route("/servers/:id/dns-zones/:zone/delete", post(handlers::ldap_mgmt::dns_zone_delete))
        .route("/servers/:id/gpo", get(handlers::ldap_mgmt::gpo))
        .route("/servers/:id/gpo/new", post(handlers::ldap_mgmt::gpo_create))
        .route("/servers/:id/gpo/:guid/edit", post(handlers::ldap_mgmt::gpo_update))
        .route("/servers/:id/gpo/:guid/delete", post(handlers::ldap_mgmt::gpo_delete))
        .route("/servers/:id/gpo/:guid/links", get(handlers::ldap_mgmt::gpo_links))
        .route("/servers/:id/gpo/:guid/links/add", post(handlers::ldap_mgmt::gpo_link_add))
        .route("/servers/:id/gpo/:guid/links/remove", post(handlers::ldap_mgmt::gpo_link_remove))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::require_auth,
        ));

    let app = Router::new()
        .merge(public)
        .merge(protected)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            // A port clash is the common case and used to surface as a panic
            // with a backtrace hint, which says nothing about what to do.
            match e.kind() {
                std::io::ErrorKind::AddrInUse => {
                    eprintln!("EasyDC cannot start: port {} is already in use.", port);
                    eprintln!("Another copy of EasyDC may already be running.");
                    eprintln!("Run on a different port with --port <PORT>, or set EASYDC_PORT.");
                }
                std::io::ErrorKind::PermissionDenied => {
                    eprintln!("EasyDC cannot start: not allowed to listen on port {}.", port);
                    eprintln!("Ports below 1024 need extra privileges; pick a higher port with --port <PORT>.");
                }
                _ => eprintln!("EasyDC cannot start: could not listen on {}: {}", addr, e),
            }
            std::process::exit(1);
        }
    };

    println!("EasyDC running on http://{}", addr);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("EasyDC stopped: {}", e);
        std::process::exit(1);
    }
}

const USAGE: &str = "\
EasyDC — a web GUI for Samba Active Directory domain controllers

Usage: easydc [OPTIONS]

Options:
  -p, --port <PORT>    Port to listen on [default: 3000, or $EASYDC_PORT]
  -h, --help           Print this help

The SQLite database (easydc.db) is created in the working directory.";

/// Port precedence: the flag, then EASYDC_PORT, then 3000. Kept separate from
/// main so the parsing is testable without binding a socket.
fn parse_port<I: AsRef<str>>(args: &[I], env_port: Option<String>) -> Result<u16, String> {
    let mut args = args.iter().map(|a| a.as_ref());
    while let Some(arg) = args.next() {
        let value = match arg {
            "-p" | "--port" => args
                .next()
                .ok_or_else(|| "--port needs a port number".to_string())?
                .to_string(),
            a if a.starts_with("--port=") => a.trim_start_matches("--port=").to_string(),
            a => return Err(format!("unknown argument '{}'", a)),
        };
        return parse_port_value(&value, "--port");
    }

    match env_port {
        Some(v) if !v.trim().is_empty() => parse_port_value(v.trim(), "EASYDC_PORT"),
        _ => Ok(3000),
    }
}

fn parse_port_value(value: &str, source: &str) -> Result<u16, String> {
    match value.parse::<u16>() {
        Ok(0) => Err(format!("{}: 0 is not a usable port", source)),
        Ok(p) => Ok(p),
        Err(_) => Err(format!("{}: '{}' is not a port number", source, value)),
    }
}

#[cfg(test)]
mod port_tests {
    use super::parse_port;

    fn port(args: &[&str], env: Option<&str>) -> Result<u16, String> {
        parse_port(args, env.map(String::from))
    }

    #[test]
    fn defaults_to_3000() {
        assert_eq!(port(&[], None), Ok(3000));
        assert_eq!(port(&[], Some("")), Ok(3000));
    }

    #[test]
    fn reads_the_environment() {
        assert_eq!(port(&[], Some("8080")), Ok(8080));
        assert_eq!(port(&[], Some(" 8080 ")), Ok(8080));
    }

    #[test]
    fn the_flag_wins_over_the_environment() {
        assert_eq!(port(&["--port", "9000"], Some("8080")), Ok(9000));
        assert_eq!(port(&["--port=9000"], Some("8080")), Ok(9000));
        assert_eq!(port(&["-p", "9000"], Some("8080")), Ok(9000));
    }

    #[test]
    fn rejects_what_cannot_be_a_port() {
        assert!(port(&["--port", "0"], None).is_err());
        assert!(port(&["--port", "70000"], None).is_err());
        assert!(port(&["--port", "http"], None).is_err());
        assert!(port(&["--port"], None).is_err());
        assert!(port(&["--wat"], None).is_err());
        // A bad environment value is reported, not silently ignored.
        assert!(port(&[], Some("nope")).is_err());
    }
}
