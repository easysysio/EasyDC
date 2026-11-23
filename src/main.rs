mod access;
mod assets;
mod audit;
mod auth;
mod db;
mod dc_removal;
mod delegation;
mod fsmo;
mod handlers;
mod health;
mod ldap;
mod level;
mod models;
mod remediate;
mod replication;
mod reports;
mod csv;
mod sd;
mod sites;
mod spn;
mod sysvol;
mod tls;
mod totp;

use std::sync::Arc;

use axum::{extract::DefaultBodyLimit, middleware, routing::{get, post}, Router};
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
    /// The certificate being served; None with EASYDC_TLS=off.
    pub tls: Option<Arc<tls::Live>>,
}

/// A CSV file of users, checked or imported: about 50,000 users. Other
/// requests keep axum's 2 MB.
const IMPORT_LIMIT: usize = 16 * 1024 * 1024;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let port = match parse_command(&args, std::env::var("EASYDC_PORT").ok()) {
        Ok(Command::Help) => {
            println!("{}", USAGE);
            return;
        }
        Ok(Command::Version) => {
            println!("{}", version_line());
            return;
        }
        Ok(Command::ResetTwoFactor(name)) => std::process::exit(reset_two_factor(&name).await),
        Ok(Command::Serve(p)) => p,
        Err(e) => {
            eprintln!("EasyDC: {}\n\n{}", e, USAGE);
            std::process::exit(2);
        }
    };

    let https = match tls::enabled(std::env::var("EASYDC_TLS").ok().as_deref()) {
        Ok(on) => on,
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

    let live = if https {
        match tls::load(&pool).await {
            Ok(live) => Some(live),
            Err(e) => {
                eprintln!("EasyDC cannot start: {e}");
                eprintln!("Set EASYDC_TLS=off to run without HTTPS.");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

    let state = AppState {
        db: pool,
        tera: Arc::new(tera),
        tls: live.clone(),
    };

    let public = Router::new()
        .route("/setup", get(handlers::setup::get_setup).post(handlers::setup::post_setup))
        .route("/login", get(handlers::auth_handlers::get_login).post(handlers::auth_handlers::post_login))
        .route("/login/code", get(handlers::auth_handlers::get_login_code).post(handlers::auth_handlers::post_login_code))
        .route("/healthz", get(|| async { "ok" }))
        .route("/static/*path", get(assets::serve));

    let protected = Router::new()
        .route("/", get(handlers::servers::dashboard))
        .route("/audit", get(handlers::servers::audit))
        .route("/settings", get(handlers::settings::settings))
        .route("/account", get(handlers::account::page))
        .route("/account/password", post(handlers::account::change_password))
        .route("/settings/audit-log", post(handlers::settings::save_audit_log))
        .route("/settings/audit-log/files/:name", get(handlers::settings::audit_file))
        .route("/settings/certificate", post(handlers::settings::upload_certificate))
        .route("/settings/certificate/generate", post(handlers::settings::generate_certificate))
        .route("/account/two-factor", get(handlers::two_factor::get_page))
        .route("/account/two-factor/start", post(handlers::two_factor::start))
        .route("/account/two-factor/confirm", post(handlers::two_factor::confirm))
        .route("/account/two-factor/recovery", post(handlers::two_factor::new_recovery_codes))
        .route("/account/two-factor/disable", post(handlers::two_factor::disable))
        .route("/settings/two-factor/require", post(handlers::two_factor::set_required))
        .route("/settings/accounts/:username/two-factor/reset", post(handlers::two_factor::reset))
        .route("/settings/accounts/new", post(handlers::settings::create_account))
        .route("/settings/accounts/:username/permissions", post(handlers::settings::update_permissions))
        .route("/settings/accounts/:username/delete", post(handlers::settings::delete_account))
        .route("/logout", post(handlers::auth_handlers::logout))
        .route("/servers/new", post(handlers::servers::create_server))
        .route("/servers/:id", get(handlers::servers::server_detail))
        .route("/servers/:id/edit", post(handlers::servers::update_server))
        .route("/servers/:id/delete", post(handlers::servers::delete_server))
        .route("/servers/:id/health", get(handlers::health::health_check))
        .route("/servers/:id/health/fix", post(handlers::health::health_fix))
        .route("/servers/:id/replication", get(handlers::replication::replication))
        .route("/servers/:id/reports", get(handlers::reports::page))
        .route("/servers/:id/reports/export", get(handlers::reports::export))
        .route("/servers/:id/dcs", get(handlers::dcs::page))
        .route("/servers/:id/dcs/fsmo", post(handlers::dcs::transfer))
        .route("/servers/:id/dcs/level", post(handlers::dcs::raise_level))
        .route("/servers/:id/dcs/:name/removal", get(handlers::dcs::removal_plan))
        .route("/servers/:id/dcs/:name/remove", post(handlers::dcs::remove))
        .route("/servers/:id/sites", get(handlers::sites::page))
        .route("/servers/:id/sites/new", post(handlers::sites::create_site))
        .route("/servers/:id/sites/move-dc", post(handlers::sites::move_dc))
        .route("/servers/:id/sites/:name/edit", post(handlers::sites::update_site))
        .route("/servers/:id/sites/:name/delete", post(handlers::sites::delete_site))
        .route("/servers/:id/subnets/new", post(handlers::sites::create_subnet))
        .route("/servers/:id/subnets/:subnet/edit", post(handlers::sites::update_subnet))
        .route("/servers/:id/subnets/:subnet/delete", post(handlers::sites::delete_subnet))
        .route("/servers/:id/site-links/:name/edit", post(handlers::sites::update_site_link))
        .route("/servers/:id/policy", get(handlers::policy::policy).post(handlers::policy::update_policy))
        .route("/servers/:id/policy/pso", post(handlers::policy::pso_create))
        .route("/servers/:id/policy/pso/:name/edit", post(handlers::policy::pso_update))
        .route("/servers/:id/policy/pso/:name/delete", post(handlers::policy::pso_delete))
        .route("/servers/:id/policy/pso/:name/apply", post(handlers::policy::pso_apply))
        .route("/servers/:id/policy/pso/:name/unapply", post(handlers::policy::pso_unapply))
        .route("/servers/:id/users", get(handlers::ldap_mgmt::users))
        .route("/servers/:id/users/new", post(handlers::ldap_mgmt::create_user))
        .route("/servers/:id/users/bulk", post(handlers::ldap_mgmt::bulk_users))
        .route("/servers/:id/users/export", get(handlers::users_csv::export))
        .route("/servers/:id/users/import/check", post(handlers::users_csv::import_check).layer(DefaultBodyLimit::max(IMPORT_LIMIT)))
        .route("/servers/:id/users/import", post(handlers::users_csv::import).layer(DefaultBodyLimit::max(IMPORT_LIMIT)))
        .route("/servers/:id/users/:username/edit", post(handlers::ldap_mgmt::update_user))
        .route("/servers/:id/users/:username/groups", get(handlers::ldap_mgmt::user_groups))
        .route("/servers/:id/users/:username/password-settings", get(handlers::ldap_mgmt::password_settings).post(handlers::ldap_mgmt::update_password_settings))
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
        .route("/servers/:id/groups/:name/members/remove", post(handlers::ldap_mgmt::remove_member))
        .route("/servers/:id/ous", get(handlers::ldap_mgmt::ous))
        .route("/servers/:id/ous/new", post(handlers::ldap_mgmt::ou_create))
        .route("/servers/:id/ous/rename", post(handlers::ldap_mgmt::ou_rename))
        .route("/servers/:id/ous/delete", post(handlers::ldap_mgmt::ou_delete))
        .route("/servers/:id/ous/move", post(handlers::ldap_mgmt::ou_move_object))
        .route("/servers/:id/spns", get(handlers::spns::page))
        .route("/servers/:id/spns/add", post(handlers::spns::add))
        .route("/servers/:id/spns/remove", post(handlers::spns::remove))
        .route("/servers/:id/delegation", get(handlers::delegation::page))
        .route("/servers/:id/delegation/grant", post(handlers::delegation::grant))
        .route("/servers/:id/delegation/revoke", post(handlers::delegation::revoke))
        .route("/servers/:id/computers", get(handlers::ldap_mgmt::computers))
        .route("/servers/:id/computers/bulk", post(handlers::ldap_mgmt::bulk_computers))
        .route("/servers/:id/computers/:name/delete", post(handlers::ldap_mgmt::delete_computer))
        .route("/servers/:id/computers/:name/toggle", post(handlers::ldap_mgmt::toggle_computer))
        .route("/servers/:id/dns", get(handlers::ldap_mgmt::dns))
        .route("/servers/:id/dns/:zone", get(handlers::ldap_mgmt::dns_zone))
        .route("/servers/:id/dns/:zone/add", post(handlers::ldap_mgmt::dns_add_record))
        .route("/servers/:id/dns/:zone/delete", post(handlers::ldap_mgmt::dns_delete_record))
        .route("/servers/:id/dns/:zone/edit", post(handlers::ldap_mgmt::dns_edit_record))
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

    // Lists of thousands of users are large HTML pages that shrink about
    // twenty-fold with gzip.
    let app = Router::new()
        .merge(public)
        .merge(protected)
        .layer(tower_http::compression::CompressionLayer::new())
        .with_state(state.clone());

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

    tokio::spawn(audit::keep_rotating(state.db.clone()));

    if let Some(live) = live {
        let info = live.info();
        println!("EasyDC running on https://{addr} (plain HTTP is redirected)");
        println!("Certificate SHA-256: {}", info.fingerprint);
        tokio::spawn(tls::renew_generated(state.db.clone(), live.clone()));
        tls::serve(listener, app, live).await;
        return;
    }
    println!("EasyDC running on http://{addr} (EASYDC_TLS=off)");
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("EasyDC stopped: {}", e);
        std::process::exit(1);
    }
}

const USAGE: &str = "\
EasyDC — a web GUI for Samba Active Directory domain controllers

Usage: easydc [OPTIONS]

Options:
  -p, --port <PORT>        Port to listen on [default: 3000, or $EASYDC_PORT]
      --reset-2fa <USER>   Remove an account's two-factor sign-in and exit.
                           Run it in the folder that holds easydc.db
  -V, --version            Print the version
  -h, --help               Print this help

EasyDC serves HTTPS on its port and redirects plain HTTP to it. Set
EASYDC_TLS=off to serve plain HTTP, behind a reverse proxy.

The SQLite database (easydc.db) is created in the working directory.";

/// What the command line asks for. Decided before anything is started — no
/// database, no socket — so `--version` and `--help` work on a host where
/// EasyDC could not otherwise run.
#[derive(Debug, PartialEq)]
enum Command {
    Help,
    Version,
    ResetTwoFactor(String),
    Serve(u16),
}

/// Help and version win wherever they appear, as with most tools, so
/// `easydc --port 8080 --version` prints the version instead of starting.
fn parse_command<I: AsRef<str>>(args: &[I], env_port: Option<String>) -> Result<Command, String> {
    if args.iter().any(|a| matches!(a.as_ref(), "-h" | "--help")) {
        return Ok(Command::Help);
    }
    if args.iter().any(|a| matches!(a.as_ref(), "-V" | "--version")) {
        return Ok(Command::Version);
    }
    if let Some(at) = args.iter().position(|a| a.as_ref() == "--reset-2fa" || a.as_ref().starts_with("--reset-2fa=")) {
        if args.len() > 2 || (args.len() == 2 && args[at].as_ref() != "--reset-2fa") {
            return Err("--reset-2fa takes one username and no other options".to_string());
        }
        let name = match args[at].as_ref().strip_prefix("--reset-2fa=") {
            Some(v) => v,
            None => args.get(at + 1).map_or("", |a| a.as_ref()),
        };
        if name.is_empty() || name.starts_with('-') {
            return Err("--reset-2fa needs a username".to_string());
        }
        return Ok(Command::ResetTwoFactor(name.to_string()));
    }
    parse_port(args, env_port).map(Command::Serve)
}

/// For an admin locked out with no phone, no recovery codes and no other
/// admin. Whoever can run this can already read the database. Never creates a
/// database: in the wrong folder it says so.
async fn reset_two_factor(username: &str) -> i32 {
    let opts = SqliteConnectOptions::from_str("sqlite://easydc.db").unwrap();
    let Ok(pool) = SqlitePool::connect_with(opts).await else {
        eprintln!("EasyDC: no easydc.db here. Run this in EasyDC's data folder, as its user.");
        return 1;
    };
    if let Err(e) = db::init_tables(&pool).await {
        eprintln!("EasyDC: cannot use easydc.db: {e}");
        return 1;
    }
    if !db::account_exists(&pool, username).await {
        eprintln!("EasyDC: no account named '{username}'.");
        return 1;
    }
    match db::remove_two_factor(&pool, username).await {
        Ok(true) => {
            db::delete_sessions_for(&pool, username, None).await;
            db::log_action(&pool, "command line", "settings.two_factor_reset", username, None, &Ok(())).await;
            println!("Two-factor sign-in removed from {username}, and its sessions ended.");
            0
        }
        Ok(false) => {
            println!("{username} does not have two-factor sign-in on.");
            0
        }
        Err(e) => {
            eprintln!("EasyDC: could not change easydc.db: {e}");
            1
        }
    }
}

fn version_line() -> String {
    format!("EasyDC {}", env!("CARGO_PKG_VERSION"))
}

/// Port precedence: the flag, then EASYDC_PORT, then 3000. Kept separate from
/// main so the parsing is testable without binding a socket.
fn parse_port<I: AsRef<str>>(args: &[I], env_port: Option<String>) -> Result<u16, String> {
    // Every argument is checked: anything unrecognised is an error wherever it
    // appears, and a repeated --port takes the last value, as most tools do.
    let mut port = None;
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
        port = Some(parse_port_value(&value, "--port")?);
    }
    if let Some(p) = port {
        return Ok(p);
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
mod command_tests {
    use super::{parse_command, version_line, Command};

    fn cmd(args: &[&str]) -> Result<Command, String> {
        parse_command(args, None)
    }

    #[test]
    fn version_flags() {
        assert_eq!(cmd(&["--version"]), Ok(Command::Version));
        assert_eq!(cmd(&["-V"]), Ok(Command::Version));
    }

    /// Asking for the version must not start the server, even alongside
    /// options that would otherwise be used to start it.
    #[test]
    fn version_wins_over_serving() {
        assert_eq!(cmd(&["--port", "8080", "--version"]), Ok(Command::Version));
    }

    #[test]
    fn help_wins_over_version() {
        assert_eq!(cmd(&["--version", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn no_flags_serves_on_the_default_port() {
        assert_eq!(cmd(&[]), Ok(Command::Serve(3000)));
        assert_eq!(cmd(&["--port", "8080"]), Ok(Command::Serve(8080)));
    }

    #[test]
    fn the_two_factor_reset_takes_one_name() {
        assert_eq!(cmd(&["--reset-2fa", "alice"]), Ok(Command::ResetTwoFactor("alice".into())));
        assert_eq!(cmd(&["--reset-2fa=alice"]), Ok(Command::ResetTwoFactor("alice".into())));
        assert!(cmd(&["--reset-2fa"]).is_err());
        assert!(cmd(&["--reset-2fa="]).is_err());
        assert!(cmd(&["--reset-2fa", "--port"]).is_err());
        assert!(cmd(&["--reset-2fa", "alice", "--port", "80"]).is_err());
        assert!(cmd(&["--port", "80", "--reset-2fa=alice"]).is_err());
        assert_eq!(cmd(&["--reset-2fa", "alice", "--help"]), Ok(Command::Help));
    }

    #[test]
    fn version_line_is_name_and_cargo_version() {
        assert_eq!(version_line(), format!("EasyDC {}", env!("CARGO_PKG_VERSION")));
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

    /// The loop used to return on its first argument, so anything after
    /// --port was silently ignored.
    #[test]
    fn arguments_after_the_port_are_still_checked() {
        assert!(port(&["--port", "8080", "--verbose"], None).is_err());
        assert!(port(&["--port", "8080", "junk"], None).is_err());
        assert!(port(&["--port", "8080", "--port", "nope"], None).is_err());
    }

    #[test]
    fn a_repeated_port_takes_the_last_value() {
        assert_eq!(port(&["--port", "8080", "--port", "9090"], None), Ok(9090));
        assert_eq!(port(&["-p", "8080", "--port=9090"], Some("7070")), Ok(9090));
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
