//! The domain's password and lockout policy — the settings
//! `samba-tool domain passwordsettings` reads and writes.
//!
//! Unlike Settings, which manages EasyDC's own logins, everything here is
//! written to the directory and applies to every account in the domain —
//! except the per-group policies (PSOs), which apply to the users and groups
//! each one names.

use axum::{
    extract::{Path, Query, State},
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
    render_checked(state, server, error, notice, None).await
}

/// The page, optionally answering "which policy applies to this user?".
async fn render_checked(
    state: &AppState,
    server: &Server,
    error: Option<String>,
    notice: Option<String>,
    check: Option<&str>,
) -> Response {
    let mut ctx = Context::new();
    ctx.insert("server", server);
    if let Some(n) = notice {
        ctx.insert("notice", &n);
    }

    match ldap::open_after(server, error.as_deref()).await {
        Err(e) => ctx.insert("error", &error.unwrap_or(e)),
        Ok((mut conn, base_dn)) => match ldap::get_password_policy(&mut conn, &base_dn).await {
            Err(e) => ctx.insert("error", &error.unwrap_or(e)),
            Ok(policy) => {
                let mut error = error;
                ctx.insert("policy", &policy);
                ctx.insert("domain", &ldap::base_dn_to_domain(&base_dn));

                // Per-group policies: only where the domain level allows them.
                let level = ldap::domain_level(&mut conn).await.unwrap_or(0);
                ctx.insert("domain_level", &level);
                ctx.insert("pso_supported", &(level >= ldap::PSO_MIN_DOMAIN_LEVEL));
                if level >= ldap::PSO_MIN_DOMAIN_LEVEL {
                    match ldap::list_psos(&mut conn, &base_dn).await {
                        Ok(psos) => ctx.insert("psos", &psos),
                        Err(e) => {
                            error.get_or_insert(e);
                            ctx.insert("psos", &Vec::<ldap::Pso>::new());
                        }
                    }
                    let candidates = ldap::pso_candidates(&mut conn, &base_dn).await.unwrap_or_default();
                    ctx.insert("candidates", &candidates);
                    if let Some(user) = check.map(str::trim).filter(|u| !u.is_empty()) {
                        ctx.insert("check_user", user);
                        match ldap::resultant_pso(&mut conn, &base_dn, user).await {
                            Ok(pso) => ctx.insert("check_result", &pso.unwrap_or_default()),
                            Err(e) => ctx.insert("check_error", &e),
                        }
                    }
                }
                if let Some(e) = error {
                    ctx.insert("error", &e);
                }
            }
        },
    }

    Html(crate::access::render(&state.tera, "policy.html", &ctx)).into_response()
}

#[derive(Deserialize)]
pub struct PolicyQuery {
    /// A username: show which policy governs it.
    pub check: Option<String>,
}

pub async fn policy(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<PolicyQuery>,
) -> Response {
    match get_server(&state, id).await {
        None => Redirect::to("/").into_response(),
        Some(server) => render_checked(&state, &server, None, None, q.check.as_deref()).await,
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

// ── per-group policies (PSOs) ────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct PsoForm {
    /// Only read when creating: a policy keeps its name.
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub precedence: i64,
    pub min_length: i64,
    /// Absent when the box is unticked.
    pub complexity: Option<String>,
    pub history: i64,
    pub max_age_days: i64,
    pub min_age_days: i64,
    pub lockout_threshold: i64,
    pub lockout_minutes: i64,
    pub observation_minutes: i64,
}

impl PsoForm {
    fn policy(&self) -> ldap::PasswordPolicy {
        ldap::PasswordPolicy {
            min_length: self.min_length,
            complexity: self.complexity.is_some(),
            history: self.history,
            max_age_days: self.max_age_days,
            min_age_days: self.min_age_days,
            lockout_threshold: self.lockout_threshold,
            lockout_minutes: self.lockout_minutes,
            observation_minutes: self.observation_minutes,
            machine_account_quota: 0,
        }
    }

    /// The whole policy in one audit line, as for the domain policy.
    fn summary(&self, name: &str) -> String {
        format!(
            "{name}: precedence={} min_length={} complexity={} history={} max_age={}d min_age={}d lockout={}/{}m window={}m",
            self.precedence,
            self.min_length,
            self.complexity.is_some(),
            self.history,
            self.max_age_days,
            self.min_age_days,
            self.lockout_threshold,
            self.lockout_minutes,
            self.observation_minutes
        )
    }
}

/// Run one PSO action, audit it, and show the page with its outcome.
async fn pso_action<F>(
    state: &AppState,
    actor: &str,
    id: i64,
    action: &str,
    target: String,
    done: &str,
    f: F,
) -> Response
where
    F: for<'a> FnOnce(
        &'a mut ldap3::Ldap,
        &'a str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + 'a>>,
{
    let server = match get_server(state, id).await {
        None => return Redirect::to("/").into_response(),
        Some(s) => s,
    };
    let result = match ldap::open(&server).await {
        Err(e) => Err(e),
        Ok((mut conn, base_dn)) => f(&mut conn, &base_dn).await,
    };
    db::log_action(&state.db, actor, action, &target, Some(id), &result).await;
    match result {
        Ok(()) => render(state, &server, None, Some(done.to_string())).await,
        Err(e) => render(state, &server, Some(e), None).await,
    }
}

pub async fn pso_create(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Form(form): Form<PsoForm>,
) -> Response {
    let name = form.name.trim().to_string();
    let done = format!("Password policy {name} created. Apply it to users or groups below.");
    pso_action(&state, &actor, id, "pso.create", form.summary(&name), &done, move |conn, base_dn| {
        Box::pin(async move {
            let settings = ldap::PsoSettings {
                name: &name,
                description: form.description.trim(),
                precedence: form.precedence,
                policy: form.policy(),
            };
            ldap::create_pso(conn, base_dn, &settings).await
        })
    })
    .await
}

pub async fn pso_update(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<PsoForm>,
) -> Response {
    let done = format!("Password policy {name} updated.");
    pso_action(&state, &actor, id, "pso.update", form.summary(&name), &done, move |conn, base_dn| {
        Box::pin(async move {
            let settings = ldap::PsoSettings {
                name: &name,
                description: form.description.trim(),
                precedence: form.precedence,
                policy: form.policy(),
            };
            ldap::update_pso(conn, base_dn, &name, &settings).await
        })
    })
    .await
}

pub async fn pso_delete(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
) -> Response {
    let done = format!("Password policy {name} deleted. Its users follow the domain policy, or another policy that applies to them.");
    let target = name.clone();
    pso_action(&state, &actor, id, "pso.delete", target, &done, move |conn, base_dn| {
        Box::pin(async move { ldap::delete_pso(conn, base_dn, &name).await })
    })
    .await
}

#[derive(Deserialize)]
pub struct PsoApplyForm {
    pub target: String,
}

pub async fn pso_apply(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<PsoApplyForm>,
) -> Response {
    let target = form.target.trim().to_string();
    let done = format!("{name} now applies to {target}.");
    pso_action(&state, &actor, id, "pso.apply", format!("{name} → {target}"), &done, move |conn, base_dn| {
        Box::pin(async move { ldap::apply_pso(conn, base_dn, &name, &target).await })
    })
    .await
}

#[derive(Deserialize)]
pub struct PsoUnapplyForm {
    pub target_dn: String,
}

pub async fn pso_unapply(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path((id, name)): Path<(i64, String)>,
    Form(form): Form<PsoUnapplyForm>,
) -> Response {
    let done = format!("{name} no longer applies to {}.", form.target_dn);
    let audit = format!("{name} ✕ {}", form.target_dn);
    pso_action(&state, &actor, id, "pso.unapply", audit, &done, move |conn, base_dn| {
        Box::pin(async move { ldap::unapply_pso(conn, base_dn, &name, &form.target_dn).await })
    })
    .await
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

    fn pso(name: &str, applies_to: &[(&str, &'static str)]) -> crate::ldap::Pso {
        crate::ldap::Pso {
            dn: format!("CN={name},CN=Password Settings Container,CN=System,DC=example,DC=com"),
            name: name.to_string(),
            description: "for admins".to_string(),
            precedence: 5,
            policy: PasswordPolicy { min_length: 14, complexity: true, history: 24, max_age_days: 90,
                lockout_threshold: 5, lockout_minutes: 30, observation_minutes: 15, ..Default::default() },
            applies_to: applies_to
                .iter()
                .map(|(n, k)| crate::ldap::PsoTarget { dn: format!("CN={n},CN=Users,DC=example,DC=com"),
                    name: n.to_string(), kind: k })
                .collect(),
        }
    }

    fn pso_ctx(psos: Vec<crate::ldap::Pso>) -> Context {
        let mut c = ctx(PasswordPolicy { min_length: 7, history: 24, ..Default::default() });
        c.insert("pso_supported", &true);
        c.insert("domain_level", &4);
        c.insert("psos", &psos);
        c.insert("candidates", &vec!["yariv".to_string(), "Domain Admins".to_string()]);
        c
    }

    #[test]
    fn policies_for_groups_are_listed_with_their_targets() {
        let html = tera()
            .render("policy.html", &pso_ctx(vec![pso("Admin Policy", &[("Domain Admins", "group"), ("yariv", "user")])]))
            .expect("renders");
        assert!(html.contains("precedence 5"));
        assert!(html.contains("At least <strong>14</strong> characters, complex"));
        assert!(html.contains("for 30 min"));
        assert!(html.contains("/policy/pso/Admin%20Policy/unapply"));
        assert!(html.contains(r#"value="CN=Domain Admins,CN=Users,DC=example,DC=com""#));
        assert!(html.contains(r#"<option value="Domain Admins">"#));
        // The shared fields carry this policy's values in its Edit dialog,
        // and the domain policy's in the Add dialog.
        assert!(html.contains(r#"id="pso1-min" name="min_length" class="form-control" required
            min="0" max="255" value="14""#));
        assert!(html.contains(r#"id="new-min" name="min_length" class="form-control" required
            min="0" max="255" value="7""#));
        assert!(html.contains(r#"id="pso1-win" name="observation_minutes" class="form-control" required
            min="0" value="15""#));
    }

    #[test]
    fn no_policies_yet() {
        let html = tera().render("policy.html", &pso_ctx(vec![])).expect("renders");
        assert!(html.contains("No policies for groups yet"));
        assert!(html.contains("addPsoModal"));
        let html = tera().render("policy.html", &pso_ctx(vec![pso("Unused", &[])])).expect("renders");
        assert!(html.contains("nobody yet"));
    }

    #[test]
    fn an_old_domain_explains_instead_of_offering() {
        let mut c = ctx(PasswordPolicy::default());
        c.insert("pso_supported", &false);
        c.insert("domain_level", &2);
        let html = tera().render("policy.html", &c).expect("renders");
        assert!(html.contains("level 2"));
        assert!(html.contains("Domain Controllers"), "it says where to raise the level");
        assert!(!html.contains("addPsoModal"));
    }

    #[test]
    fn the_check_answers() {
        let mut c = pso_ctx(vec![]);
        c.insert("check_user", "yariv");
        c.insert("check_result", "Admin Policy");
        let html = tera().render("policy.html", &c).expect("renders");
        assert!(html.contains("<strong>Admin Policy</strong>."));
        assert!(!html.contains("follows the domain policy."));
        c.insert("check_result", "");
        let html = tera().render("policy.html", &c).expect("renders");
        assert!(html.contains("follows the domain policy"));
    }

    #[test]
    fn hostile_policy_names_are_escaped() {
        let html = tera()
            .render("policy.html", &pso_ctx(vec![pso(r#""><img src=x onerror=alert(1)>"#, &[(r#"<img src=y>"#, "user")])]))
            .expect("renders");
        assert!(!html.contains("<img src=x"));
        assert!(!html.contains("<img src=y>"));
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
