//! The domain's password and lockout policy — the settings
//! `samba-tool domain passwordsettings` reads and writes.
//!
//! Unlike Settings, which manages EasyDC's own logins, everything here is
//! written to the directory and applies to every account in the domain.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    Form,
};
use serde::Deserialize;
use tera::Context;

use crate::{auth::CurrentUser, db, ldap, models::Server, AppState};

async fn get_server(state: &AppState, id: i64) -> Option<Server> {
    sqlx::query_as::<_, Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None)
}

async fn render(
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
        Err(e) => ctx.insert("error", &error.unwrap_or(e)),
        Ok((mut conn, base_dn)) => match ldap::get_password_policy(&mut conn, &base_dn).await {
            Err(e) => ctx.insert("error", &error.unwrap_or(e)),
            Ok(policy) => {
                if let Some(e) = error {
                    ctx.insert("error", &e);
                }
                ctx.insert("policy", &policy);
                ctx.insert("domain", &ldap::base_dn_to_domain(&base_dn));
            }
        },
    }

    Html(state.tera.render("policy.html", &ctx).unwrap_or_default()).into_response()
}

pub async fn policy(State(state): State<AppState>, Path(id): Path<i64>) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render(&state, &server, None, None).await,
    }
}

#[derive(Deserialize)]
pub struct PolicyForm {
    pub min_length: i64,
    /// Absent when the box is unticked.
    pub complexity: Option<String>,
    pub history: i64,
    pub max_age_days: i64,
    pub min_age_days: i64,
    pub lockout_threshold: i64,
    pub lockout_minutes: i64,
    pub observation_minutes: i64,
    pub machine_account_quota: i64,
}

pub async fn update_policy(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<PolicyForm>,
) -> Response {
    let server = match get_server(&state, id).await {
        None => return Redirect::to("/").into_response(),
        Some(s) => s,
    };

    let wanted = ldap::PasswordPolicy {
        min_length: form.min_length,
        complexity: form.complexity.is_some(),
        history: form.history,
        max_age_days: form.max_age_days,
        min_age_days: form.min_age_days,
        lockout_threshold: form.lockout_threshold,
        lockout_minutes: form.lockout_minutes,
        observation_minutes: form.observation_minutes,
        machine_account_quota: form.machine_account_quota,
    };

    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => ldap::set_password_policy(&mut conn, &base_dn, &wanted).await,
    };

    // The whole policy in one audit line, so a later "who loosened this?" has
    // an answer.
    let target = format!(
        "min_length={} complexity={} history={} max_age={}d min_age={}d lockout={}/{}m window={}m quota={}",
        wanted.min_length,
        wanted.complexity,
        wanted.history,
        wanted.max_age_days,
        wanted.min_age_days,
        wanted.lockout_threshold,
        wanted.lockout_minutes,
        wanted.observation_minutes,
        wanted.machine_account_quota
    );
    db::log_action(&state.db, &actor, "policy.update", &target, Some(id), &result).await;

    match result {
        Ok(()) => render(&state, &server, None, Some("Password policy updated.".to_string())).await,
        Err(e) => render(&state, &server, Some(e), None).await,
    }
}

#[cfg(test)]
mod tests {
    use crate::ldap::PasswordPolicy;
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
            bind_dn: "CN=Administrator".to_string(),
            bind_password: "secret".to_string(),
            skip_tls: true,
        }
    }

    fn ctx(policy: PasswordPolicy) -> Context {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("policy", &policy);
        c.insert("domain", "example.com");
        c
    }

    #[test]
    fn shows_the_current_values() {
        let p = PasswordPolicy {
            min_length: 7,
            complexity: true,
            history: 24,
            max_age_days: 42,
            min_age_days: 1,
            lockout_threshold: 5,
            lockout_minutes: 30,
            observation_minutes: 30,
            machine_account_quota: 10,
        };
        let html = tera().render("policy.html", &ctx(p)).expect("renders");
        assert!(html.contains(r#"name="min_length" class="form-control" required
                            min="0" max="255" value="7""#) || html.contains(r#"value="7""#));
        assert!(html.contains("checked"), "complexity box reflects the policy");
        assert!(html.contains("ms-DS-MachineAccountQuota"));
        assert!(!html.contains("secret"), "bind password must not reach the page");
    }

    #[test]
    fn an_unset_complexity_flag_leaves_the_box_clear() {
        let p = PasswordPolicy { complexity: false, ..Default::default() };
        let html = tera().render("policy.html", &ctx(p)).expect("renders");
        let box_line = html
            .lines()
            .find(|l| l.contains(r#"name="complexity""#))
            .unwrap_or("");
        assert!(!box_line.contains("checked"));
    }

    /// The page must still render when the directory could not be read, so the
    /// error is visible rather than a blank page.
    #[test]
    fn renders_the_unreachable_case() {
        let mut c = Context::new();
        c.insert("server", &server());
        c.insert("error", "Bind failed: invalid credentials");
        let html = tera().render("policy.html", &c).expect("renders");
        assert!(html.contains("invalid credentials"));
        assert!(!html.contains("Save policy"), "no form without a policy to edit");
    }
}
