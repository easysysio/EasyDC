//! Service principal names: which account Kerberos issues a ticket for when a
//! client asks for a service, such as `HTTP/web.example.com`.
//!
//! An SPN must be on one account only, or Kerberos cannot tell which key to
//! use. The SPNs that keep the domain itself working are shown but not
//! changed here: those of domain controllers, of `krbtgt` and other critical
//! system objects, and the `DNS/` SPN of Samba's `dns-<host>` account.

use std::collections::{HashMap, HashSet};

use ldap3::{Mod, Scope, SearchEntry};
use serde::Serialize;

use crate::{
    health::{attr_ci, attrs_ci, search},
    ldap::{self, ldap_err, ldap_escape, LdapResult, OP_TIMEOUT},
};

const UAC_SERVER_TRUST: i64 = 0x2000;
const UAC_READ_ONLY_DC: i64 = 0x0400_0000;
const MAX_LENGTH: usize = 2048;
const ATTRS: [&str; 6] = ["servicePrincipalName", "sAMAccountName", "objectClass", "userAccountControl", "isCriticalSystemObject", "cn"];

/// Check an SPN's form: `service/host`, `service/host:port` or
/// `service/host:port/name`. Returns it without surrounding spaces.
pub fn check(spn: &str) -> Result<String, String> {
    let spn = spn.trim();
    if spn.is_empty() {
        return Err("Enter an SPN, such as HTTP/web.example.com.".to_string());
    }
    if spn.len() > MAX_LENGTH {
        return Err(format!("An SPN can be at most {MAX_LENGTH} characters."));
    }
    if spn.chars().any(|c| c.is_whitespace() || c.is_control() || c == '\\' || c == '@') {
        return Err("An SPN cannot contain spaces, a backslash or @.".to_string());
    }
    let parts: Vec<&str> = spn.split('/').collect();
    if !(2..=3).contains(&parts.len()) || parts.iter().any(|p| p.is_empty()) {
        return Err("Write an SPN as service/host, service/host:port or service/host:port/name.".to_string());
    }
    let service = parts[0];
    if service.contains(':') {
        return Err("The service, before the first /, cannot contain a colon.".to_string());
    }
    if let Some((host, port)) = parts[1].split_once(':') {
        if host.is_empty() || port.is_empty() || port.contains(':') {
            return Err("Write the host as name or name:port.".to_string());
        }
        if port.bytes().all(|b| b.is_ascii_digit()) {
            if !port.parse::<u32>().is_ok_and(|p| (1..=65_535).contains(&p)) {
                return Err("The port must be between 1 and 65535.".to_string());
            }
        } else if !service.eq_ignore_ascii_case("MSSQLSvc") {
            // SQL Server alone puts an instance name where the port goes.
            return Err("The part after the colon must be a port number.".to_string());
        }
    }
    Ok(spn.to_string())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Kind {
    User,
    Computer,
    Other,
}

#[derive(Debug, Clone)]
pub struct Account {
    pub dn: String,
    pub sam: String,
    pub kind: Kind,
    uac: i64,
    critical: bool,
    pub spns: Vec<String>,
}

impl Account {
    fn from_entry(e: &SearchEntry) -> Self {
        let classes = attrs_ci(e, "objectClass");
        let is = |c: &str| classes.iter().any(|x| x.eq_ignore_ascii_case(c));
        let kind = if is("computer") {
            Kind::Computer
        } else if is("user") {
            Kind::User
        } else {
            Kind::Other
        };
        let sam = attr_ci(e, "sAMAccountName");
        Self {
            dn: e.dn.clone(),
            sam: if sam.is_empty() { attr_ci(e, "cn") } else { sam },
            kind,
            uac: attr_ci(e, "userAccountControl").parse().unwrap_or(0),
            critical: attr_ci(e, "isCriticalSystemObject").eq_ignore_ascii_case("TRUE"),
            spns: attrs_ci(e, "servicePrincipalName"),
        }
    }

    /// Why this SPN may not be changed here, if so.
    pub fn locked(&self, spn: &str) -> Option<&'static str> {
        if self.uac & (UAC_SERVER_TRUST | UAC_READ_ONLY_DC) != 0 {
            return Some("A domain controller's SPNs are managed by Samba.");
        }
        if self.critical {
            return Some("This is a critical system account.");
        }
        if self.kind == Kind::Other {
            return Some("EasyDC changes SPNs on users and computers only.");
        }
        let dns_account = self.sam.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("dns-"));
        let dns_spn = spn.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("dns/"));
        (dns_account && dns_spn).then_some("Samba's DNS server signs in with this SPN.")
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub spn: String,
    pub account: String,
    pub kind: Kind,
    /// The permission that changes it: `users` or `computers`.
    pub needs: &'static str,
    pub locked: Option<&'static str>,
    /// The same SPN is on another account too.
    pub duplicate: bool,
    /// Said before removing it.
    pub warning: &'static str,
}

fn rows(accounts: &[Account]) -> Vec<Row> {
    let mut holders: HashMap<String, HashSet<&str>> = HashMap::new();
    for a in accounts {
        for s in &a.spns {
            holders.entry(s.to_lowercase()).or_default().insert(&a.dn);
        }
    }
    let mut out = Vec::new();
    for a in accounts {
        for s in &a.spns {
            let host = s.get(..5).is_some_and(|p| p.eq_ignore_ascii_case("host/"));
            out.push(Row {
                spn: s.clone(),
                account: a.sam.clone(),
                kind: a.kind,
                needs: if a.kind == Kind::Computer { "computers" } else { "users" },
                locked: a.locked(s),
                duplicate: holders.get(&s.to_lowercase()).is_some_and(|h| h.len() > 1),
                warning: if host && a.kind == Kind::Computer {
                    "This computer uses its HOST SPN for sign-ins and file sharing. Removing it can break them."
                } else {
                    ""
                },
            });
        }
    }
    out.sort_by_cached_key(|r| (r.spn.to_lowercase(), r.account.to_lowercase()));
    out
}

pub async fn list(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<Row>> {
    let entries = search(conn, base_dn, Scope::Subtree, "(servicePrincipalName=*)", ATTRS.to_vec()).await?;
    let accounts: Vec<Account> = entries.iter().map(Account::from_entry).collect();
    Ok(rows(&accounts))
}

/// The user or computer with this account name. A computer's name ends in
/// `$`, which may be left out.
pub async fn find_account(conn: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<Account> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Enter the account the SPN goes on.".to_string());
    }
    for candidate in [name.to_string(), format!("{name}$")] {
        let filter = format!("(&(objectClass=user)(sAMAccountName={}))", ldap_escape(&candidate));
        if let Some(e) = search(conn, base_dn, Scope::Subtree, &filter, ATTRS.to_vec()).await?.first() {
            return Ok(Account::from_entry(e));
        }
    }
    Err(format!("There is no user or computer named {name}."))
}

pub async fn add(conn: &mut ldap3::Ldap, base_dn: &str, account: &Account, spn: &str) -> LdapResult<()> {
    if let Some(why) = account.locked(spn) {
        return Err(format!("{spn} cannot be added to {}: {why}", account.sam));
    }
    let filter = format!("(servicePrincipalName={})", ldap_escape(spn));
    let holders = search(conn, base_dn, Scope::Subtree, &filter, ATTRS.to_vec()).await?;
    if let Some(e) = holders.first() {
        let holder = Account::from_entry(e);
        return Err(if holder.dn.eq_ignore_ascii_case(&account.dn) {
            format!("{} already has {spn}.", account.sam)
        } else {
            format!("{} already has {spn}. An SPN must be on one account only, or Kerberos sign-ins to the service fail.", holder.sam)
        });
    }
    let value = HashSet::from([spn.as_bytes().to_vec()]);
    let mods = vec![Mod::Add(b"servicePrincipalName".to_vec(), value)];
    let res = conn.with_timeout(OP_TIMEOUT).modify(&account.dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        20 => Err(format!("{} already has {spn}.", account.sam)),
        _ => Err(ldap::refused("Could not add the SPN", &account.sam, &res)),
    }
}

pub async fn remove(conn: &mut ldap3::Ldap, account: &Account, spn: &str) -> LdapResult<()> {
    // As the directory stores it, whatever the case it was asked for in.
    let Some(stored) = account.spns.iter().find(|s| s.eq_ignore_ascii_case(spn)) else {
        return Err(format!("{} does not have {spn}. Reload the page to see the current list.", account.sam));
    };
    if let Some(why) = account.locked(stored) {
        return Err(format!("{stored} cannot be removed from {}: {why}", account.sam));
    }
    let value = HashSet::from([stored.as_bytes().to_vec()]);
    let mods = vec![Mod::Delete(b"servicePrincipalName".to_vec(), value)];
    let res = conn.with_timeout(OP_TIMEOUT).modify(&account.dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        _ => Err(ldap::refused("Could not remove the SPN", &account.sam, &res)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account(sam: &str, kind: Kind, uac: i64, critical: bool, spns: &[&str]) -> Account {
        Account {
            dn: format!("CN={sam},DC=x"),
            sam: sam.into(),
            kind,
            uac,
            critical,
            spns: spns.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn good_spns_are_accepted() {
        for spn in [
            "HTTP/web.example.com",
            "HTTP/web",
            "MSSQLSvc/db.example.com:1433",
            "MSSQLSvc/db.example.com:SALES",
            "ldap/dc1.example.com/example.com",
            "E3514235-4B06-11D1-AB04-00C04FC2DCD2/guid/example.com",
            "svc/host:65535/name",
        ] {
            assert_eq!(check(spn).as_deref(), Ok(spn));
        }
        assert_eq!(check("  HTTP/web  ").unwrap(), "HTTP/web", "spaces around it are dropped");
    }

    #[test]
    fn bad_spns_are_refused() {
        for spn in [
            "",
            "   ",
            "HTTP",
            "/web",
            "HTTP/",
            "HTTP//web",
            "a/b/c/d",
            "HTTP/web/",
            "HTTP/we b",
            "HTTP/we\nb",
            "HTTP/web\tx",
            "HTTP\\web",
            "HTTP/web@EXAMPLE.COM",
            "HT:TP/web",
            "HTTP/:80",
            "HTTP/web:",
            "HTTP/web:0",
            "HTTP/web:65536",
            "HTTP/web:80:81",
            "HTTP/web:SALES",
        ] {
            assert!(check(spn).is_err(), "{spn:?}");
        }
        assert!(check(&format!("HTTP/{}", "a".repeat(MAX_LENGTH))).is_err());
    }

    #[test]
    fn what_keeps_the_domain_running_is_locked() {
        let dc = account("DC1$", Kind::Computer, 0x82000, false, &[]);
        assert!(dc.locked("HOST/dc1").is_some());
        let rodc = account("RO$", Kind::Computer, 0x0400_1000, false, &[]);
        assert!(rodc.locked("HOST/ro").is_some());
        let krbtgt = account("krbtgt", Kind::User, 0x202, true, &[]);
        assert!(krbtgt.locked("kadmin/changepw").is_some());
        let dns = account("dns-dc1", Kind::User, 0x200, false, &[]);
        assert!(dns.locked("DNS/dc1.example.com").is_some());
        assert!(dns.locked("dns/dc1.example.com").is_some());
        assert!(dns.locked("HTTP/other").is_none(), "only its DNS SPN");
        assert!(account("other", Kind::Other, 0, false, &[]).locked("x/y").is_some());
        assert!(account("svc-web", Kind::User, 0x200, false, &[]).locked("DNS/x").is_none(), "only Samba's own account");
        assert!(account("PC1$", Kind::Computer, 0x1000, false, &[]).locked("HOST/pc1").is_none());
    }

    #[test]
    fn rows_flag_duplicates_and_warn_about_host() {
        let accounts = [
            account("svc-a", Kind::User, 0x200, false, &["HTTP/web", "HOST/not-a-computer"]),
            account("svc-b", Kind::User, 0x200, false, &["http/WEB"]),
            account("PC1$", Kind::Computer, 0x1000, false, &["HOST/pc1"]),
        ];
        let r = rows(&accounts);
        assert_eq!(r.len(), 4);
        let get = |spn: &str| r.iter().find(|x| x.spn == spn).unwrap();
        assert!(get("HTTP/web").duplicate && get("http/WEB").duplicate, "whatever the case");
        assert!(!get("HOST/pc1").duplicate);
        assert!(!get("HOST/pc1").warning.is_empty());
        assert!(get("HOST/not-a-computer").warning.is_empty());
        assert_eq!(get("HOST/pc1").needs, "computers");
        assert_eq!(get("HTTP/web").needs, "users");
        assert_eq!(r[0].spn, "HOST/not-a-computer", "sorted by SPN");
    }

    #[test]
    fn one_account_with_the_same_spn_twice_is_not_a_duplicate() {
        let a = [account("svc", Kind::User, 0x200, false, &["HTTP/web", "http/web"])];
        assert!(rows(&a).iter().all(|r| !r.duplicate));
    }
}
