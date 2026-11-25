//! What each EasyDC account may change.
//!
//! An admin sets every area to View or Edit for each account; an account
//! marked Admin may change everything, including what only admins do (EasyDC
//! accounts, server connections, the health check's fixes). Everyone may view
//! every page.
//!
//! The check is made once, in the sign-in middleware, from the route a request
//! matched: every POST route needs the area it changes, and a route this file
//! does not name needs an admin. Two routes change more than one area,
//! depending on what they are given, and their handlers check further with
//! [`current`].

use std::collections::BTreeSet;

use axum::http::Method;
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Area {
    Users,
    Groups,
    Computers,
    DnsRecords,
    DnsZones,
    Gpos,
    Ous,
    PasswordPolicies,
    Sites,
}

/// In the order the Settings page lists them.
pub const AREAS: [Area; 9] = [
    Area::Users,
    Area::Groups,
    Area::Computers,
    Area::DnsRecords,
    Area::DnsZones,
    Area::Gpos,
    Area::Ous,
    Area::PasswordPolicies,
    Area::Sites,
];

impl Area {
    /// As stored in the database and used in forms and pages.
    pub fn key(self) -> &'static str {
        match self {
            Area::Users => "users",
            Area::Groups => "groups",
            Area::Computers => "computers",
            Area::DnsRecords => "dns_records",
            Area::DnsZones => "dns_zones",
            Area::Gpos => "gpos",
            Area::Ous => "ous",
            Area::PasswordPolicies => "password_policies",
            Area::Sites => "sites",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Area::Users => "Users",
            Area::Groups => "Groups",
            Area::Computers => "Computers",
            Area::DnsRecords => "DNS records",
            Area::DnsZones => "DNS zones",
            Area::Gpos => "GPOs",
            Area::Ous => "OUs",
            Area::PasswordPolicies => "Password policies",
            Area::Sites => "Sites and subnets",
        }
    }

    /// What Edit lets someone do, for the Settings page.
    pub fn covers(self) -> &'static str {
        match self {
            Area::Users => "add, edit, delete, enable or disable, reset passwords, unlock, move",
            Area::Groups => "add, edit, delete, members",
            Area::Computers => "enable or disable, delete, move",
            Area::DnsRecords => "add, edit, delete records",
            Area::DnsZones => "create and delete zones",
            Area::Gpos => "create, edit, delete, link to OUs",
            Area::Ous => "create, rename, delete",
            Area::PasswordPolicies => "the domain policy and per-group policies",
            Area::Sites => "sites, subnets and site links, and which site a DC is in",
        }
    }

    pub fn from_key(key: &str) -> Option<Area> {
        AREAS.into_iter().find(|a| a.key() == key)
    }
}

/// What a request needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Need {
    Anyone,
    Edit(Area),
    Admin,
    /// The handler decides from what it is given, with [`current`].
    Handler,
}

/// The need of a request, from its method and the route it matched (the
/// pattern, such as `/servers/:id/users/:username/edit`). Viewing is open to
/// everyone; a change on a route not named here needs an admin.
pub fn need(method: &Method, route: &str) -> Need {
    if method == Method::GET || method == Method::HEAD {
        return Need::Anyone;
    }
    let Some(rest) = route.strip_prefix("/servers/:id/") else {
        return match route {
            "/logout"
            | "/account/password"
            | "/account/two-factor/start"
            | "/account/two-factor/confirm"
            | "/account/two-factor/recovery"
            | "/account/two-factor/disable" => Need::Anyone,
            _ => Need::Admin,
        };
    };
    let first = rest.split('/').next().unwrap_or("");
    match first {
        "users" => Need::Edit(Area::Users),
        "groups" => Need::Edit(Area::Groups),
        "computers" => Need::Edit(Area::Computers),
        "dns" => Need::Edit(Area::DnsRecords),
        "dns-zones" => Need::Edit(Area::DnsZones),
        "gpo" => Need::Edit(Area::Gpos),
        "policy" => Need::Edit(Area::PasswordPolicies),
        "sites" | "subnets" | "site-links" => Need::Edit(Area::Sites),
        // Moving a user, group or computer needs the area of what is moved.
        "ous" if rest == "ous/move" => Need::Handler,
        "ous" => Need::Edit(Area::Ous),
        // A user's SPN needs Users, a computer's needs Computers.
        "spns" => Need::Handler,
        _ => Need::Admin,
    }
}

/// One signed-in account's permissions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Access {
    pub username: String,
    pub admin: bool,
    pub edit: BTreeSet<Area>,
}

impl Access {
    pub fn can_edit(&self, area: Area) -> bool {
        self.admin || self.edit.contains(&area)
    }

    pub fn allows(&self, need: Need) -> bool {
        match need {
            Need::Anyone | Need::Handler => true,
            Need::Edit(area) => self.can_edit(area),
            Need::Admin => self.admin,
        }
    }

    /// For the pages: `access.admin`, and `access.edit.<area key>` for every area.
    pub fn view(&self) -> AccessView {
        AccessView {
            username: self.username.clone(),
            admin: self.admin,
            edit: AREAS.iter().map(|a| (a.key(), self.can_edit(*a))).collect(),
            labels: AREAS.iter().map(|a| (a.key(), a.label())).collect(),
        }
    }

    /// "Admin", or what the account may change.
    pub fn summary(&self) -> String {
        if self.admin {
            return "Admin: changes everything".to_string();
        }
        let edit: Vec<&str> = AREAS.iter().filter(|a| self.edit.contains(a)).map(|a| a.label()).collect();
        match edit.len() {
            0 => "View only".to_string(),
            n if n == AREAS.len() => "Edit: every area".to_string(),
            _ => format!("Edit: {}", edit.join(", ")),
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct AccessView {
    pub username: String,
    pub admin: bool,
    pub edit: std::collections::BTreeMap<&'static str, bool>,
    pub labels: std::collections::BTreeMap<&'static str, &'static str>,
}

/// What a refused request is told.
pub fn refusal(need: Need) -> String {
    match need {
        Need::Edit(area) => format!(
            "You can view {0} but not change them. An EasyDC admin can give you Edit on {0} in Settings.",
            area.label()
        ),
        _ => "Only an EasyDC admin can do this.".to_string(),
    }
}

tokio::task_local! {
    static CURRENT: Access;
}

/// Run `f` with `access` as the request's account, for [`current`] and the
/// pages rendered on the way.
pub async fn scope<F: std::future::Future>(access: Access, f: F) -> F::Output {
    CURRENT.scope(access, f).await
}

/// The account behind the request being handled. Outside a request (in
/// tests), an account that may change nothing.
pub fn current() -> Access {
    CURRENT.try_with(Clone::clone).unwrap_or_default()
}

/// Render a page with `access` in its context, so it can grey out what the
/// account may not change.
pub fn render(tera: &tera::Tera, name: &str, ctx: &tera::Context) -> String {
    let mut ctx = ctx.clone();
    ctx.insert("access", &current().view());
    tera.render(name, &ctx).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every route in main.rs, as written there.
    fn routes() -> Vec<(String, Vec<Method>)> {
        let src = include_str!("main.rs");
        let mut out = Vec::new();
        for line in src.lines() {
            let line = line.trim();
            let Some(rest) = line.strip_prefix(".route(\"") else { continue };
            let Some((path, handlers)) = rest.split_once('"') else { continue };
            let mut methods = Vec::new();
            if handlers.contains("get(") {
                methods.push(Method::GET);
            }
            if handlers.contains("post(") {
                methods.push(Method::POST);
            }
            out.push((path.to_string(), methods));
        }
        assert!(out.len() > 40, "main.rs routes were found");
        out
    }

    #[test]
    fn every_change_needs_a_permission() {
        let public = ["/setup", "/login", "/login/code", "/static/*path"];
        let mut handler_checked = Vec::new();
        for (path, methods) in routes() {
            if public.contains(&path.as_str()) {
                continue;
            }
            for m in methods {
                let n = need(&m, &path);
                if m == Method::GET {
                    assert_eq!(n, Need::Anyone, "{path}: every page can be viewed");
                    continue;
                }
                match n {
                    Need::Anyone => assert!(
                        [
                            "/logout",
                            "/account/password",
                            "/account/two-factor/start",
                            "/account/two-factor/confirm",
                            "/account/two-factor/recovery",
                            "/account/two-factor/disable",
                        ]
                        .contains(&path.as_str()),
                        "{path} may be posted by anyone"
                    ),
                    Need::Handler => handler_checked.push(path.clone()),
                    _ => {}
                }
            }
        }
        assert_eq!(
            handler_checked,
            vec!["/servers/:id/ous/move", "/servers/:id/spns/add", "/servers/:id/spns/remove"],
            "only these handlers check for themselves"
        );
    }

    #[test]
    fn routes_need_their_area() {
        let post = |r| need(&Method::POST, r);
        assert_eq!(post("/settings/two-factor/require"), Need::Admin);
        assert_eq!(post("/settings/accounts/:username/two-factor/reset"), Need::Admin);
        assert_eq!(post("/servers/:id/users/:username/reset-password"), Need::Edit(Area::Users));
        assert_eq!(post("/servers/:id/users/bulk"), Need::Edit(Area::Users));
        assert_eq!(post("/servers/:id/users/:username/password-settings"), Need::Edit(Area::Users));
        assert_eq!(post("/servers/:id/users/import/check"), Need::Edit(Area::Users));
        assert_eq!(post("/servers/:id/users/import"), Need::Edit(Area::Users));
        assert_eq!(need(&Method::GET, "/servers/:id/users/export"), Need::Anyone);
        assert_eq!(post("/servers/:id/groups/:name/members/add"), Need::Edit(Area::Groups));
        assert_eq!(post("/servers/:id/computers/:name/toggle"), Need::Edit(Area::Computers));
        assert_eq!(post("/servers/:id/computers/bulk"), Need::Edit(Area::Computers));
        assert_eq!(post("/servers/:id/dns/:zone/add"), Need::Edit(Area::DnsRecords));
        assert_eq!(post("/servers/:id/dns-zones/:zone/delete"), Need::Edit(Area::DnsZones));
        assert_eq!(post("/servers/:id/gpo/:guid/links/add"), Need::Edit(Area::Gpos));
        assert_eq!(post("/servers/:id/ous/rename"), Need::Edit(Area::Ous));
        assert_eq!(post("/servers/:id/policy/pso/:name/apply"), Need::Edit(Area::PasswordPolicies));
        assert_eq!(post("/servers/:id/policy"), Need::Edit(Area::PasswordPolicies));
        assert_eq!(post("/servers/:id/sites/new"), Need::Edit(Area::Sites));
        assert_eq!(post("/servers/:id/sites/move-dc"), Need::Edit(Area::Sites));
        assert_eq!(post("/servers/:id/subnets/:subnet/delete"), Need::Edit(Area::Sites));
        assert_eq!(post("/servers/:id/site-links/:name/edit"), Need::Edit(Area::Sites));
        for admin_only in [
            "/servers/new",
            "/servers/:id/edit",
            "/servers/:id/delete",
            "/servers/:id/health/fix",
            "/servers/:id/health/hide",
            "/servers/:id/health/show",
            "/settings/accounts/new",
            "/settings/accounts/:username/delete",
            "/settings/accounts/:username/permissions",
            "/something/new",
            "/servers/:id/something-new",
        ] {
            assert_eq!(post(admin_only), Need::Admin, "{admin_only}");
        }
        assert_eq!(need(&Method::GET, "/servers/:id/health"), Need::Anyone);
    }

    #[test]
    fn admin_may_change_everything() {
        let admin = Access { admin: true, ..Default::default() };
        let helpdesk = Access { edit: [Area::Users].into(), ..Default::default() };
        assert!(admin.allows(Need::Admin) && admin.allows(Need::Edit(Area::Gpos)));
        assert!(helpdesk.allows(Need::Edit(Area::Users)));
        assert!(!helpdesk.allows(Need::Edit(Area::Groups)));
        assert!(!helpdesk.allows(Need::Admin));
        assert!(Access::default().allows(Need::Anyone));
    }

    #[test]
    fn summaries_read_plainly() {
        assert_eq!(Access { admin: true, ..Default::default() }.summary(), "Admin: changes everything");
        assert_eq!(Access::default().summary(), "View only");
        let a = Access { edit: [Area::Groups, Area::Users].into(), ..Default::default() };
        assert_eq!(a.summary(), "Edit: Users, Groups");
        let all = Access { edit: AREAS.into_iter().collect(), ..Default::default() };
        assert_eq!(all.summary(), "Edit: every area");
        assert!(!all.allows(Need::Admin), "every area on Edit is still not an admin");
    }

    #[test]
    fn refusals_say_who_can_help() {
        assert_eq!(
            refusal(Need::Edit(Area::DnsZones)),
            "You can view DNS zones but not change them. An EasyDC admin can give you Edit on DNS zones in Settings."
        );
        assert_eq!(refusal(Need::Admin), "Only an EasyDC admin can do this.");
    }

    #[test]
    fn area_keys_round_trip() {
        for a in AREAS {
            assert_eq!(Area::from_key(a.key()), Some(a));
        }
        assert_eq!(Area::from_key("admin"), None);
    }

    #[tokio::test]
    async fn the_current_account_is_known_inside_a_request() {
        assert!(!current().admin, "outside a request, nothing may be changed");
        let a = Access { username: "ann".into(), admin: true, ..Default::default() };
        let seen = scope(a.clone(), async { current() }).await;
        assert_eq!(seen, a);
    }
}
