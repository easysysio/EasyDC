//! Sites, subnets and site links: where the DCs are, which client addresses
//! belong to which site, and how sites replicate with each other. They live
//! in the configuration partition, under `CN=Sites`:
//!
//! - a site is `CN=<name>,CN=Sites,…` with two objects inside it, `CN=NTDS
//!   Site Settings` and `CN=Servers` (which holds a server object per DC);
//! - a subnet is `CN=10.1.0.0/16,CN=Subnets,CN=Sites,…`, its site in `siteObject`;
//! - a site link is `CN=<name>,CN=IP,CN=Inter-Site Transports,CN=Sites,…`,
//!   its sites in `siteList`, with a `cost` and `replInterval` (minutes).
//!
//! The formats are Microsoft's published ones ([MS-ADTS]); written here, not
//! taken from Samba's tools.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ldap3::{Mod, Scope, SearchEntry};
use serde::Serialize;

use crate::health::{attr_ci, attrs_ci, read_one, search};
use crate::ldap::{self, dn_escape, first_rdn_value, ldap_escape, parent_dn, refused, LdapResult, OP_TIMEOUT};

#[derive(Debug, Serialize, Clone, Default, PartialEq)]
pub struct SiteDc {
    pub name: String,
    pub host: String,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Site {
    pub name: String,
    pub description: String,
    pub dcs: Vec<SiteDc>,
    /// Its subnets, by name.
    pub subnets: Vec<String>,
    /// The site links it is in, by name.
    pub links: Vec<String>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Subnet {
    pub name: String,
    /// The site's name; empty when it has none (or its site was deleted).
    pub site: String,
    pub description: String,
    pub location: String,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct SiteLink {
    pub name: String,
    /// `IP`, or `SMTP` for the rare link that replicates by mail.
    pub transport: String,
    /// Its sites, by name.
    pub sites: Vec<String>,
    pub cost: i64,
    /// Minutes between replications.
    pub interval: i64,
    /// The interval in words: "every 3 hours".
    pub every: String,
    pub description: String,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Topology {
    pub sites: Vec<Site>,
    pub subnets: Vec<Subnet>,
    pub links: Vec<SiteLink>,
}

/// The configuration partition's DN, from the DC's root entry: in a child
/// domain it is under the forest root, not under the domain.
pub async fn config_dn(conn: &mut ldap3::Ldap, base_dn: &str) -> String {
    read_one(conn, "", vec!["configurationNamingContext"])
        .await
        .map(|e| attr_ci(&e, "configurationNamingContext"))
        .ok()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("CN=Configuration,{base_dn}"))
}

fn sites_dn(config: &str) -> String {
    format!("CN=Sites,{config}")
}

fn site_dn(config: &str, name: &str) -> String {
    format!("CN={},CN=Sites,{config}", dn_escape(name))
}

fn subnet_dn(config: &str, name: &str) -> String {
    format!("CN={},CN=Subnets,CN=Sites,{config}", dn_escape(name))
}

fn same_dn(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// The name of the site a DN under `CN=Sites` names, if it is one of `sites`.
fn site_name_of(dn: &str, sites: &[(String, String)]) -> String {
    sites.iter().find(|(d, _)| same_dn(d, dn)).map(|(_, n)| n.clone()).unwrap_or_default()
}

/// Everything under `CN=Sites`, read in four searches.
pub async fn load(conn: &mut ldap3::Ldap, config: &str) -> LdapResult<Topology> {
    let base = sites_dn(config);
    let site_entries = search(conn, &base, Scope::OneLevel, "(objectClass=site)", vec!["cn", "description"]).await?;
    let mut sites: Vec<Site> = Vec::new();
    let mut site_dns: Vec<(String, String)> = Vec::new();
    for e in &site_entries {
        let name = first_rdn_value(&e.dn);
        site_dns.push((e.dn.clone(), name.clone()));
        sites.push(Site { name, description: attr_ci(e, "description"), ..Default::default() });
    }

    // A DC's server object is CN=<dc>,CN=Servers,CN=<site>,CN=Sites,…
    for e in search(conn, &base, Scope::Subtree, "(objectClass=server)", vec!["cn", "dNSHostName"]).await? {
        let site = site_name_of(parent_dn(parent_dn(&e.dn)), &site_dns);
        if let Some(s) = sites.iter_mut().find(|s| s.name == site) {
            s.dcs.push(SiteDc { name: first_rdn_value(&e.dn), host: attr_ci(&e, "dNSHostName") });
        }
    }

    let mut subnets: Vec<Subnet> = search(
        conn,
        &format!("CN=Subnets,{base}"),
        Scope::OneLevel,
        "(objectClass=subnet)",
        vec!["cn", "siteObject", "description", "location"],
    )
    .await?
    .iter()
    .map(|e| Subnet {
        name: first_rdn_value(&e.dn),
        site: site_name_of(&attr_ci(e, "siteObject"), &site_dns),
        description: attr_ci(e, "description"),
        location: attr_ci(e, "location"),
    })
    .collect();
    subnets.sort_by_key(|a| subnet_sort_key(&a.name));

    let mut links: Vec<SiteLink> = search(
        conn,
        &format!("CN=Inter-Site Transports,{base}"),
        Scope::Subtree,
        "(objectClass=siteLink)",
        vec!["cn", "siteList", "cost", "replInterval", "description"],
    )
    .await?
    .iter()
    .map(|e| SiteLink {
        name: first_rdn_value(&e.dn),
        transport: first_rdn_value(parent_dn(&e.dn)),
        sites: attrs_ci(e, "siteList").iter().map(|d| site_name_of(d, &site_dns)).filter(|n| !n.is_empty()).collect(),
        cost: attr_ci(e, "cost").parse().unwrap_or(100),
        interval: attr_ci(e, "replInterval").parse().unwrap_or(180),
        every: String::new(),
        description: attr_ci(e, "description"),
    })
    .collect();
    links.sort_by_key(|a| (a.transport != "IP", a.name.to_lowercase()));

    for s in &mut sites {
        s.subnets = subnets.iter().filter(|n| n.site == s.name).map(|n| n.name.clone()).collect();
        s.links = links.iter().filter(|l| l.sites.contains(&s.name)).map(|l| l.name.clone()).collect();
        s.dcs.sort_by_key(|d| d.name.to_lowercase());
    }
    sites.sort_by_key(|s| s.name.to_lowercase());
    for l in &mut links {
        l.sites.sort_by_key(|n| n.to_lowercase());
        l.every = every(l.interval);
    }
    Ok(Topology { sites, subnets, links })
}

/// Minutes as the page says them: "every 15 minutes", "every 3 hours",
/// "every 1 hour 30 minutes", "every day".
pub fn every(minutes: i64) -> String {
    let plural = |n: i64, unit: &str| if n == 1 { format!("1 {unit}") } else { format!("{n} {unit}s") };
    match minutes {
        m if m % 1440 == 0 => if m == 1440 { "every day".to_string() } else { format!("every {}", plural(m / 1440, "day")) },
        m if m % 60 == 0 => format!("every {}", plural(m / 60, "hour")),
        m if m > 60 => format!("every {} {}", plural(m / 60, "hour"), plural(m % 60, "minute")),
        m => format!("every {}", plural(m, "minute")),
    }
}

/// IPv4 before IPv6, then by address and prefix, as numbers.
fn subnet_sort_key(name: &str) -> (u8, u128, u8) {
    let (addr, len) = name.split_once('/').unwrap_or((name, ""));
    let len = len.parse().unwrap_or(0);
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => (0, u32::from(a) as u128, len),
        Ok(IpAddr::V6(a)) => (1, u128::from(a), len),
        Err(_) => (2, 0, len),
    }
}

// ── checks ───────────────────────────────────────────────────────────────────

/// A site name. Each DC advertises its site in DNS (`_ldap._tcp.<site>._sites…`),
/// so the name must work as a DNS label: letters, digits and hyphens, up to 63.
pub fn check_site_name(name: &str) -> LdapResult<()> {
    if name.is_empty() {
        return Err("Give the site a name.".to_string());
    }
    if name.len() > 63 {
        return Err("A site name is at most 63 characters.".to_string());
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(format!(
            "The site name {name} can hold only letters (a-z), digits and hyphens: \
             DCs publish their site in DNS, where other characters do not work."
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("A site name cannot start or end with a hyphen.".to_string());
    }
    Ok(())
}

/// A subnet as AD stores it: `network/prefix`, with the address the network
/// itself (no host bits) and IPv6 in its short form. Returns that form.
pub fn normalise_subnet(text: &str) -> LdapResult<String> {
    let text = text.trim();
    let bad = || format!("{text} is not a subnet. Write it as an address and a prefix length, such as 10.1.0.0/16 or 2001:db8::/48.");
    let (addr, len) = text.split_once('/').ok_or_else(bad)?;
    let len: u8 = len.parse().map_err(|_| bad())?;
    match addr.parse::<IpAddr>().map_err(|_| bad())? {
        IpAddr::V4(a) => {
            if !(1..=32).contains(&len) {
                return Err(format!("An IPv4 prefix length is 1 to 32, not {len}."));
            }
            let mask = u32::MAX << (32 - len);
            let network = Ipv4Addr::from(u32::from(a) & mask);
            if network != a {
                return Err(format!("{text} has host bits set: the subnet is {network}/{len}."));
            }
            Ok(format!("{network}/{len}"))
        }
        IpAddr::V6(a) => {
            if !(1..=128).contains(&len) {
                return Err(format!("An IPv6 prefix length is 1 to 128, not {len}."));
            }
            let mask = u128::MAX << (128 - len as u32);
            let network = Ipv6Addr::from(u128::from(a) & mask);
            if network != a {
                return Err(format!("{text} has host bits set: the subnet is {network}/{len}."));
            }
            Ok(format!("{network}/{len}"))
        }
    }
}

/// The values a site link's form gives, checked against the domain: a cost
/// of 1 to 99,999, an interval of 15 minutes to a week in steps of 15 (what
/// the DC acts on), at least one site, and no site left in no link at all,
/// which would cut its DCs off from the others.
pub fn check_link_change(t: &Topology, link: &str, cost: i64, interval: i64, sites: &[String]) -> LdapResult<()> {
    if !(1..=99_999).contains(&cost) {
        return Err("The cost is a number from 1 to 99,999.".to_string());
    }
    if !(15..=10_080).contains(&interval) || interval % 15 != 0 {
        return Err("Replication runs every 15 minutes to every week (10,080 minutes), in steps of 15.".to_string());
    }
    if sites.is_empty() {
        return Err("A site link needs at least one site.".to_string());
    }
    for s in sites {
        if !t.sites.iter().any(|x| &x.name == s) {
            return Err(format!("There is no site {s}."));
        }
    }
    if t.sites.len() > 1 {
        for s in &t.sites {
            let elsewhere = t.links.iter().any(|l| l.name != link && l.sites.contains(&s.name));
            if !elsewhere && !sites.contains(&s.name) && t.links.iter().any(|l| l.name == link && l.sites.contains(&s.name)) {
                return Err(format!(
                    "{} would be in no site link, so its DCs would not replicate with the other sites. \
                     Add it to another site link first.",
                    s.name
                ));
            }
        }
    }
    Ok(())
}

/// Whether a site can be deleted: not while a DC is in it.
pub fn check_site_delete(t: &Topology, name: &str) -> LdapResult<()> {
    let site = t.sites.iter().find(|s| s.name.eq_ignore_ascii_case(name)).ok_or_else(|| format!("There is no site {name}."))?;
    if !site.dcs.is_empty() {
        let names: Vec<&str> = site.dcs.iter().map(|d| d.name.as_str()).collect();
        return Err(format!(
            "{} still holds {} ({}). Move {} to another site first.",
            site.name,
            if names.len() == 1 { "a domain controller" } else { "domain controllers" },
            names.join(", "),
            if names.len() == 1 { "it" } else { "them" }
        ));
    }
    Ok(())
}

// ── changes ──────────────────────────────────────────────────────────────────

fn sv(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn one(s: &str) -> HashSet<Vec<u8>> {
    HashSet::from([sv(s)])
}

/// Replace an attribute, or remove it when the value is empty.
fn set_or_clear(attr: &str, value: &str) -> Mod<Vec<u8>> {
    Mod::Replace(sv(attr), if value.is_empty() { HashSet::new() } else { one(value) })
}

fn check_text(label: &str, value: &str, max: usize) -> LdapResult<()> {
    if value.chars().count() > max {
        return Err(format!("{label} is longer than {max} characters."));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("{label} contains a control character."));
    }
    Ok(())
}

async fn add(conn: &mut ldap3::Ldap, what: &str, dn: &str, attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)>) -> LdapResult<()> {
    let res = conn.with_timeout(OP_TIMEOUT).add(dn, attrs).await.map_err(ldap::ldap_err)?;
    match res.rc {
        0 => Ok(()),
        68 => Err(format!("{what}: {} already exists.", first_rdn_value(dn))),
        _ => Err(refused(what, &first_rdn_value(parent_dn(dn)), &res)),
    }
}

async fn modify(conn: &mut ldap3::Ldap, what: &str, dn: &str, mods: Vec<Mod<Vec<u8>>>) -> LdapResult<()> {
    let res = conn.with_timeout(OP_TIMEOUT).modify(dn, mods).await.map_err(ldap::ldap_err)?;
    match res.rc {
        0 => Ok(()),
        _ => Err(refused(what, &first_rdn_value(dn), &res)),
    }
}

/// The DN of a site link by name, the IP one when a name is used twice.
async fn link_dn(conn: &mut ldap3::Ldap, config: &str, name: &str) -> LdapResult<String> {
    let found = search(
        conn,
        &format!("CN=Inter-Site Transports,{}", sites_dn(config)),
        Scope::Subtree,
        &format!("(&(objectClass=siteLink)(cn={}))", ldap_escape(name)),
        vec!["cn"],
    )
    .await?;
    let ip = found.iter().find(|e| first_rdn_value(parent_dn(&e.dn)).eq_ignore_ascii_case("IP"));
    ip.or(found.first()).map(|e| e.dn.clone()).ok_or_else(|| format!("There is no site link {name}."))
}

/// A new site, with the two objects every site holds, added to a site link
/// so it replicates (as the Windows tool insists).
pub async fn create_site(conn: &mut ldap3::Ldap, config: &str, name: &str, description: &str, link: &str) -> LdapResult<()> {
    check_site_name(name)?;
    check_text("The description", description, 1024)?;
    let what = "The site was not created";
    // Looked up first, so a wrong link does not leave a site behind.
    let link_dn = link_dn(conn, config, link).await.map_err(|_| format!("{what}: there is no site link {link}."))?;
    let dn = site_dn(config, name);
    let mut attrs = vec![(sv("objectClass"), one("site"))];
    if !description.is_empty() {
        attrs.push((sv("description"), one(description)));
    }
    add(conn, what, &dn, attrs).await?;
    let made: LdapResult<()> = async {
        add(conn, what, &format!("CN=NTDS Site Settings,{dn}"), vec![(sv("objectClass"), one("nTDSSiteSettings"))]).await?;
        add(conn, what, &format!("CN=Servers,{dn}"), vec![(sv("objectClass"), one("serversContainer"))]).await?;
        modify(conn, what, &link_dn, vec![Mod::Add(sv("siteList"), one(&dn))]).await
    }
    .await;
    if let Err(e) = made {
        // Half a site is worse than none: take it away again.
        let gone = delete_tree(conn, &dn).await.is_ok();
        return Err(if gone { e } else { format!("{e} The site {name} was left half made; delete it before trying again.") });
    }
    Ok(())
}

pub async fn update_site(conn: &mut ldap3::Ldap, config: &str, name: &str, description: &str) -> LdapResult<()> {
    check_text("The description", description, 1024)?;
    modify(conn, "The site was not changed", &site_dn(config, name), vec![set_or_clear("description", description)]).await
}

/// Delete a site that holds no DC: its subnets are left without a site, and
/// it is taken out of its site links first.
pub async fn delete_site(conn: &mut ldap3::Ldap, config: &str, name: &str) -> LdapResult<()> {
    let t = load(conn, config).await?;
    check_site_delete(&t, name)?;
    let what = "The site was not deleted";
    let dn = site_dn(config, name);
    for subnet in t.subnets.iter().filter(|s| s.site.eq_ignore_ascii_case(name)) {
        modify(conn, what, &subnet_dn(config, &subnet.name), vec![Mod::Replace(sv("siteObject"), HashSet::new())]).await?;
    }
    for link in t.links.iter().filter(|l| l.sites.iter().any(|s| s.eq_ignore_ascii_case(name))) {
        let ldn = link_dn(conn, config, &link.name).await?;
        modify(conn, what, &ldn, vec![Mod::Delete(sv("siteList"), one(&dn))]).await?;
    }
    delete_tree(conn, &dn).await.map_err(|e| format!("{what}: {e}"))
}

/// Delete an object and everything below it, deepest first.
async fn delete_tree(conn: &mut ldap3::Ldap, dn: &str) -> LdapResult<()> {
    let mut all: Vec<SearchEntry> = search(conn, dn, Scope::Subtree, "(objectClass=*)", vec!["1.1"]).await?;
    all.sort_by_key(|e| std::cmp::Reverse(ldap::dn_parts(&e.dn).len()));
    for e in all {
        let res = conn.with_timeout(OP_TIMEOUT).delete(&e.dn).await.map_err(ldap::ldap_err)?;
        if res.rc != 0 && res.rc != 32 {
            return Err(refused("It was not deleted", &first_rdn_value(&e.dn), &res));
        }
    }
    Ok(())
}

/// Move a DC's server object to another site's `CN=Servers`. The DC then
/// replicates and serves clients as part of that site; Samba updates its DNS
/// records for the site at its next DNS update (within about 10 minutes).
pub async fn move_dc(conn: &mut ldap3::Ldap, config: &str, dc: &str, to: &str) -> LdapResult<()> {
    let what = "The DC was not moved";
    let found = search(
        conn,
        &sites_dn(config),
        Scope::Subtree,
        &format!("(&(objectClass=server)(cn={}))", ldap_escape(dc)),
        vec!["cn"],
    )
    .await?;
    let from = found.first().ok_or_else(|| format!("{what}: there is no DC {dc} in any site."))?;
    let target = format!("CN=Servers,{}", site_dn(config, to));
    if same_dn(parent_dn(&from.dn), &target) {
        return Ok(());
    }
    let rdn = format!("CN={}", dn_escape(&first_rdn_value(&from.dn)));
    let res = conn.with_timeout(OP_TIMEOUT).modifydn(&from.dn, &rdn, true, Some(&target)).await.map_err(ldap::ldap_err)?;
    match res.rc {
        0 => Ok(()),
        32 => Err(format!("{what}: there is no site {to}.")),
        _ => Err(refused(what, dc, &res)),
    }
}

pub struct SubnetChange<'a> {
    pub site: &'a str,
    pub description: &'a str,
    pub location: &'a str,
}

fn check_subnet_change(c: &SubnetChange) -> LdapResult<()> {
    if c.site.is_empty() {
        return Err("Pick the site the subnet belongs to.".to_string());
    }
    check_text("The description", c.description, 1024)?;
    check_text("The location", c.location, 1024)
}

/// The site a subnet is given must exist; the DC's own refusal is cryptic.
async fn check_site_exists(conn: &mut ldap3::Ldap, config: &str, what: &str, site: &str) -> LdapResult<()> {
    let found = search(conn, &sites_dn(config), Scope::OneLevel, &format!("(&(objectClass=site)(cn={}))", ldap_escape(site)), vec!["1.1"]).await?;
    if found.is_empty() {
        return Err(format!("{what}: there is no site {site}."));
    }
    Ok(())
}

pub async fn create_subnet(conn: &mut ldap3::Ldap, config: &str, subnet: &str, c: &SubnetChange<'_>) -> LdapResult<String> {
    let name = normalise_subnet(subnet)?;
    check_subnet_change(c)?;
    check_site_exists(conn, config, "The subnet was not added", c.site).await?;
    let mut attrs = vec![(sv("objectClass"), one("subnet")), (sv("siteObject"), one(&site_dn(config, c.site)))];
    if !c.description.is_empty() {
        attrs.push((sv("description"), one(c.description)));
    }
    if !c.location.is_empty() {
        attrs.push((sv("location"), one(c.location)));
    }
    add(conn, "The subnet was not added", &subnet_dn(config, &name), attrs).await?;
    Ok(name)
}

pub async fn update_subnet(conn: &mut ldap3::Ldap, config: &str, subnet: &str, c: &SubnetChange<'_>) -> LdapResult<()> {
    check_subnet_change(c)?;
    check_site_exists(conn, config, "The subnet was not changed", c.site).await?;
    let mods = vec![
        Mod::Replace(sv("siteObject"), one(&site_dn(config, c.site))),
        set_or_clear("description", c.description),
        set_or_clear("location", c.location),
    ];
    modify(conn, "The subnet was not changed", &subnet_dn(config, subnet), mods).await
}

pub async fn delete_subnet(conn: &mut ldap3::Ldap, config: &str, subnet: &str) -> LdapResult<()> {
    let dn = subnet_dn(config, subnet);
    let res = conn.with_timeout(OP_TIMEOUT).delete(&dn).await.map_err(ldap::ldap_err)?;
    match res.rc {
        0 => Ok(()),
        _ => Err(refused("The subnet was not deleted", subnet, &res)),
    }
}

pub struct LinkChange<'a> {
    pub cost: i64,
    pub interval: i64,
    pub description: &'a str,
    pub sites: &'a [String],
}

pub async fn update_site_link(conn: &mut ldap3::Ldap, config: &str, name: &str, c: &LinkChange<'_>) -> LdapResult<()> {
    let t = load(conn, config).await?;
    check_link_change(&t, name, c.cost, c.interval, c.sites)?;
    check_text("The description", c.description, 1024)?;
    let dn = link_dn(conn, config, name).await?;
    let site_list: HashSet<Vec<u8>> = c.sites.iter().map(|s| sv(&site_dn(config, s))).collect();
    let mods = vec![
        Mod::Replace(sv("cost"), one(&c.cost.to_string())),
        Mod::Replace(sv("replInterval"), one(&c.interval.to_string())),
        set_or_clear("description", c.description),
        Mod::Replace(sv("siteList"), site_list),
    ];
    modify(conn, "The site link was not changed", &dn, mods).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnets_are_written_as_ad_stores_them() {
        assert_eq!(normalise_subnet(" 10.1.0.0/16 ").unwrap(), "10.1.0.0/16");
        assert_eq!(normalise_subnet("192.168.1.0/24").unwrap(), "192.168.1.0/24");
        assert_eq!(normalise_subnet("10.0.0.5/32").unwrap(), "10.0.0.5/32");
        assert_eq!(normalise_subnet("2001:DB8:0:0::/48").unwrap(), "2001:db8::/48");
        assert!(normalise_subnet("10.1.2.3/16").unwrap_err().contains("the subnet is 10.1.0.0/16"));
        assert!(normalise_subnet("2001:db8::1/64").unwrap_err().contains("2001:db8::/64"));
        assert!(normalise_subnet("10.0.0.0/33").unwrap_err().contains("1 to 32"));
        assert!(normalise_subnet("10.0.0.0/0").unwrap_err().contains("1 to 32"));
        assert!(normalise_subnet("::/0").unwrap_err().contains("1 to 128"));
        for bad in ["10.0.0.0", "10.0.0/8", "010.0.0.0/8", "x/8", "10.0.0.0/a", ""] {
            assert!(normalise_subnet(bad).unwrap_err().contains("is not a subnet"), "{bad}");
        }
    }

    #[test]
    fn intervals_read_plainly() {
        assert_eq!(every(15), "every 15 minutes");
        assert_eq!(every(60), "every 1 hour");
        assert_eq!(every(180), "every 3 hours");
        assert_eq!(every(90), "every 1 hour 30 minutes");
        assert_eq!(every(1440), "every day");
        assert_eq!(every(10_080), "every 7 days");
    }

    #[test]
    fn subnets_sort_as_numbers() {
        let mut names = vec!["10.10.0.0/16", "2001:db8::/32", "10.2.0.0/16", "10.2.0.0/24", "192.168.0.0/16"];
        names.sort_by_key(|n| subnet_sort_key(n));
        assert_eq!(names, ["10.2.0.0/16", "10.2.0.0/24", "10.10.0.0/16", "192.168.0.0/16", "2001:db8::/32"]);
    }

    #[test]
    fn site_names_work_in_dns() {
        assert!(check_site_name("Default-First-Site-Name").is_ok());
        assert!(check_site_name("TLV2").is_ok());
        assert!(check_site_name("").is_err());
        assert!(check_site_name("Tel Aviv").unwrap_err().contains("letters (a-z), digits and hyphens"));
        assert!(check_site_name("Zürich").is_err());
        assert!(check_site_name("-edge").unwrap_err().contains("hyphen"));
        assert!(check_site_name(&"a".repeat(64)).unwrap_err().contains("63"));
    }

    fn topology() -> Topology {
        let site = |name: &str, dcs: &[&str]| Site {
            name: name.into(),
            dcs: dcs.iter().map(|d| SiteDc { name: d.to_string(), host: String::new() }).collect(),
            ..Default::default()
        };
        let link = |name: &str, sites: &[&str]| SiteLink {
            name: name.into(),
            transport: "IP".into(),
            sites: sites.iter().map(|s| s.to_string()).collect(),
            cost: 100,
            interval: 180,
            ..Default::default()
        };
        Topology {
            sites: vec![site("HQ", &["DC1", "DC2"]), site("Branch", &[]), site("Lab", &["DC3"])],
            subnets: vec![],
            links: vec![link("DEFAULTIPSITELINK", &["HQ", "Branch"]), link("HQ-Lab", &["HQ", "Lab"])],
        }
    }

    fn names(n: &[&str]) -> Vec<String> {
        n.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_site_link_change_is_checked() {
        let t = topology();
        assert!(check_link_change(&t, "HQ-Lab", 50, 15, &names(&["HQ", "Lab"])).is_ok());
        assert!(check_link_change(&t, "HQ-Lab", 0, 180, &names(&["HQ"])).unwrap_err().contains("cost"));
        assert!(check_link_change(&t, "HQ-Lab", 100, 20, &names(&["HQ"])).unwrap_err().contains("steps of 15"));
        assert!(check_link_change(&t, "HQ-Lab", 100, 10_095, &names(&["HQ"])).unwrap_err().contains("10,080"));
        assert!(check_link_change(&t, "HQ-Lab", 100, 180, &[]).unwrap_err().contains("at least one"));
        assert!(check_link_change(&t, "HQ-Lab", 100, 180, &names(&["Nowhere"])).unwrap_err().contains("no site Nowhere"));
        // Lab is only in HQ-Lab: taking it out cuts it off.
        let e = check_link_change(&t, "HQ-Lab", 100, 180, &names(&["HQ"])).unwrap_err();
        assert!(e.starts_with("Lab would be in no site link"), "{e}");
        // HQ is in DEFAULTIPSITELINK too, so it may leave this one.
        assert!(check_link_change(&t, "HQ-Lab", 100, 180, &names(&["Lab", "Branch"])).is_ok());
    }

    #[test]
    fn a_site_with_a_dc_stays() {
        let t = topology();
        assert!(check_site_delete(&t, "branch").is_ok());
        assert_eq!(check_site_delete(&t, "HQ").unwrap_err(), "HQ still holds domain controllers (DC1, DC2). Move them to another site first.");
        assert_eq!(check_site_delete(&t, "Lab").unwrap_err(), "Lab still holds a domain controller (DC3). Move it to another site first.");
        assert!(check_site_delete(&t, "Mars").unwrap_err().contains("no site Mars"));
    }
}
