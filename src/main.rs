mod auth;
mod db;
mod handlers;
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
    tracing_subscriber::fmt::init();

    let opts = SqliteConnectOptions::from_str("sqlite://easydc.db")
        .unwrap()
        .create_if_missing(true);

    let pool = SqlitePool::connect_with(opts)
        .await
        .expect("Failed to connect to database");

    db::init_tables(&pool).await.expect("Failed to initialize database");

    let mut tera = Tera::default();
    for path in Templates::iter() {
        let content = Templates::get(&path).unwrap();
        let source = std::str::from_utf8(content.data.as_ref()).expect("Template is not valid UTF-8");
        tera.add_raw_template(&path, source).expect("Failed to load template");
    }
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
        .route("/logout", post(handlers::auth_handlers::logout))
        .route("/servers/new", post(handlers::servers::create_server))
        .route("/servers/:id", get(handlers::servers::server_detail))
        .route("/servers/:id/edit", post(handlers::servers::update_server))
        .route("/servers/:id/delete", post(handlers::servers::delete_server))
        .route("/servers/:id/users", get(handlers::ldap_mgmt::users))
        .route("/servers/:id/users/new", post(handlers::ldap_mgmt::create_user))
        .route("/servers/:id/users/:username/edit", post(handlers::ldap_mgmt::update_user))
        .route("/servers/:id/users/:username/delete", post(handlers::ldap_mgmt::delete_user))
        .route("/servers/:id/users/:username/toggle", post(handlers::ldap_mgmt::toggle_user))
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

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("EasyDC running on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}
