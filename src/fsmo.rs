//! FSMO roles: which DC holds each, and moving one to another live DC.
//!
//! Each role is the `fSMORoleOwner` of one object, naming the holder's NTDS
//! Settings object ([MS-ADTS] 3.1.1.1.11). The five classic roles move when
//! the DC that is to hold the role is asked to take it: a write of
//! `become<Role>` to that DC's root entry ([MS-ADTS] 3.1.1.3.3), after which
//! it fetches the role from the holder. The two DNS partition roles have no
//! such operation: their holder is told the new owner by changing
//! `fSMORoleOwner` on the partition's `CN=Infrastructure` object.
//!
//! Seizing a role from a DC that is gone is not done here: it is a last
//! resort, done on a DC with `samba-tool fsmo seize`.

use std::collections::HashSet;
use std::time::Duration;

use ldap3::{Mod, Scope};
use serde::Serialize;

use crate::health::{self, attr_ci, read_one, DcInfo};
use crate::ldap::{self, dn_parts, ldap_err, LdapResult, OP_TIMEOUT};
use crate::models::Server;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Schema,
    Naming,
    Pdc,
    Rid,
    Infrastructure,
    DomainDns,
    ForestDns,
}

pub const ROLES: [Role; 7] = [Role::Pdc, Role::Rid, Role::Infrastructure, Role::Schema, Role::Naming, Role::DomainDns, Role::ForestDns];

impl Role {
    pub fn key(self) -> &'static str {
        match self {
            Role::Schema => "schema",
            Role::Naming => "naming",
            Role::Pdc => "pdc",
            Role::Rid => "rid",
            Role::Infrastructure => "infrastructure",
            Role::DomainDns => "domaindns",
            Role::ForestDns => "forestdns",
        }
    }

    pub fn from_key(key: &str) -> Option<Role> {
        ROLES.into_iter().find(|r| r.key() == key)
    }

    pub fn label(self) -> &'static str {
        match self {
            Role::Schema => "Schema master",
            Role::Naming => "Domain naming master",
            Role::Pdc => "PDC emulator",
            Role::Rid => "RID master",
            Role::Infrastructure => "Infrastructure master",
            Role::DomainDns => "Domain DNS zones master",
            Role::ForestDns => "Forest DNS zones master",
        }
    }

    /// What the role does, in a sentence.
    pub fn does(self) -> &'static str {
        match self {
            Role::Schema => "The one DC that can change the schema, as a Samba upgrade or Exchange does now and then.",
            Role::Naming => "Adds and removes domains and partitions in the forest.",
            Role::Pdc => "The domain's time source and the last word on a password just changed. The busiest role: keep it on a well-connected DC.",
            Role::Rid => "Hands each DC blocks of IDs for new users, groups and computers. Without it, DCs run out after a few hundred new objects each.",
            Role::Infrastructure => "Keeps references to objects in other domains up to date.",
            Role::DomainDns => "Owns the DomainDnsZones partition, where the domain's DNS zones are kept.",
            Role::ForestDns => "Owns the ForestDnsZones partition, where _msdcs and other forest-wide DNS zones are kept.",
        }
    }

    /// The root entry attribute that asks a DC to take the role, for the
    /// classic five.
    fn become_attr(self) -> Option<&'static str> {
        match self {
            Role::Schema => Some("becomeSchemaMaster"),
            Role::Naming => Some("becomeDomainMaster"),
            Role::Pdc => Some("becomePdc"),
            Role::Rid => Some("becomeRidMaster"),
            Role::Infrastructure => Some("becomeInfrastructureMaster"),
            Role::DomainDns | Role::ForestDns => None,
        }
    }
}

/// Where the role's `fSMORoleOwner` is.
pub struct Partitions {
    pub domain: String,
    pub config: String,
    pub schema: String,
    pub forest: String,
}

impl Partitions {
    pub async fn read(conn: &mut ldap3::Ldap, base_dn: &str) -> Partitions {
        let root = read_one(conn, "", vec!["configurationNamingContext", "schemaNamingContext", "rootDomainNamingContext"]).await.ok();
        let get = |k: &str, default: String| root.as_ref().map(|e| attr_ci(e, k)).filter(|v| !v.is_empty()).unwrap_or(default);
        let config = get("configurationNamingContext", format!("CN=Configuration,{base_dn}"));
        Partitions {
            domain: base_dn.to_string(),
            schema: get("schemaNamingContext", format!("CN=Schema,{config}")),
            forest: get("rootDomainNamingContext", base_dn.to_string()),
            config,
        }
    }

    pub fn role_dn(&self, role: Role) -> String {
        match role {
            Role::Schema => self.schema.clone(),
            Role::Naming => format!("CN=Partitions,{}", self.config),
            Role::Pdc => self.domain.clone(),
            Role::Rid => format!("CN=RID Manager$,CN=System,{}", self.domain),
            Role::Infrastructure => format!("CN=Infrastructure,{}", self.domain),
            Role::DomainDns => format!("CN=Infrastructure,DC=DomainDnsZones,{}", self.domain),
            Role::ForestDns => format!("CN=Infrastructure,DC=ForestDnsZones,{}", self.forest),
        }
    }
}

/// One role and who holds it.
#[derive(Debug, Serialize, Clone)]
pub struct Holder {
    pub role: Role,
    pub key: &'static str,
    pub label: &'static str,
    pub does: &'static str,
    /// The holding DC's name; empty when no one holds it.
    pub dc: String,
    /// The holder's NTDS Settings DN (internal).
    #[serde(skip)]
    pub owner: String,
    /// The holder named is not a DC that exists: only seizing can fix it.
    pub gone: bool,
    /// The partition is not there (a domain without DNS partitions).
    pub missing: bool,
}

/// A DC as the page lists it.
#[derive(Debug, Serialize, Clone)]
pub struct Dc {
    pub name: String,
    pub host: String,
    pub site: String,
    /// The roles it holds, by label.
    pub roles: Vec<&'static str>,
    /// The DC EasyDC is configured to connect to.
    pub configured: bool,
    /// It holds every role there is: "Move all roles here" has nothing to do.
    pub holds_all: bool,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Overview {
    pub dcs: Vec<Dc>,
    pub roles: Vec<Holder>,
}

/// The NTDS Settings DN of a DC as `fSMORoleOwner` gives it.
fn ntds_dn_of(owner: &str) -> String {
    dn_parts(owner).get(1).and_then(|p| p.split_once('=')).map(|(_, v)| v.to_string()).unwrap_or_default()
}

pub async fn holders(conn: &mut ldap3::Ldap, p: &Partitions, dc_names: &HashSet<String>) -> Vec<Holder> {
    let mut out = Vec::new();
    for role in ROLES {
        let (owner, missing) = match read_one(conn, &p.role_dn(role), vec!["fSMORoleOwner"]).await {
            Ok(e) => (attr_ci(&e, "fSMORoleOwner"), false),
            Err(_) => (String::new(), true),
        };
        let dc = ntds_dn_of(&owner);
        // A deleted DC's NTDS Settings is renamed "…\0ADEL:<guid>" and moved
        // to Deleted Objects; either way it is not one of the DCs listed.
        let gone = !owner.is_empty() && (owner.contains("\\0ADEL:") || !dc_names.contains(&dc.to_lowercase()));
        out.push(Holder { role, key: role.key(), label: role.label(), does: role.does(), dc, owner, gone, missing });
    }
    out
}

/// The DCs, the roles, and which DC EasyDC is connected to.
pub async fn overview(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<(Overview, Vec<DcInfo>, Partitions)> {
    let p = Partitions::read(conn, base_dn).await;
    let infos = health::load_dcs(conn, &p.config).await?;
    let names: HashSet<String> = infos.iter().map(|d| d.name.to_lowercase()).collect();
    let roles = holders(conn, &p, &names).await;
    let here = read_one(conn, "", vec!["dsServiceName"]).await.map(|e| ntds_dn_of(&attr_ci(&e, "dsServiceName"))).unwrap_or_default();
    let there = roles.iter().filter(|h| !h.missing).count();
    let dcs = infos
        .iter()
        .map(|d| {
            let held: Vec<&'static str> = roles.iter().filter(|h| !h.gone && h.dc.eq_ignore_ascii_case(&d.name)).map(|h| h.label).collect();
            Dc {
                name: d.name.clone(),
                host: d.dns_host_name.clone(),
                site: d.site.clone(),
                holds_all: held.len() == there,
                roles: held,
                configured: here.eq_ignore_ascii_case(&d.name),
            }
        })
        .collect();
    Ok((Overview { dcs, roles }, infos, p))
}

/// Whether a role can move to `to`, from what the page knows.
pub fn check_transfer(h: &Holder, to: &str, dcs: &[DcInfo]) -> LdapResult<()> {
    if h.missing {
        return Err(format!("This domain has no {} partition, so there is no {} to move.", partition_name(h.role), h.label));
    }
    if !dcs.iter().any(|d| d.name.eq_ignore_ascii_case(to)) {
        return Err(format!("There is no DC {to}."));
    }
    if h.owner.is_empty() || h.gone {
        let who = if h.owner.is_empty() { "No DC holds it".to_string() } else { format!("Its holder, {}, no longer exists", h.dc) };
        return Err(format!(
            "The {} cannot be moved: {who}, and moving needs the holder to hand it over. \
             Take it on a DC with `samba-tool fsmo seize --role={}`.",
            h.label,
            h.role.key()
        ));
    }
    if h.dc.eq_ignore_ascii_case(to) {
        return Err(format!("{} already holds the {}.", h.dc, h.label));
    }
    Ok(())
}

fn partition_name(role: Role) -> &'static str {
    match role {
        Role::DomainDns => "DomainDnsZones",
        Role::ForestDns => "ForestDnsZones",
        _ => "",
    }
}

/// Connect to a DC by its DNS name, as the configured server does: the same
/// account, TLS setting and port.
async fn connect_to(server: &Server, dc: &DcInfo) -> LdapResult<ldap3::Ldap> {
    if dc.dns_host_name.is_empty() {
        return Err(format!("{} has no DNS name in the directory, so EasyDC cannot reach it.", dc.name));
    }
    let url = crate::replication::url_for_host(&server.ldap_url, &dc.dns_host_name)
        .ok_or_else(|| format!("EasyDC cannot build an address for {} from {}.", dc.name, server.ldap_url))?;
    ldap::connect_url(server, &url, Some(Duration::from_secs(10)))
        .await
        .map_err(|e| format!("EasyDC could not reach {} at {url}: {e}", dc.name))
}

/// Move one role to `to`. Returns once the DC asked has taken it (classic
/// roles) or once the holder has written the new owner (DNS roles), with
/// whether the DC `conn` is on already sees the new holder: a DNS role is
/// changed on its holder, and the others learn of it as they replicate.
pub async fn transfer(server: &Server, conn: &mut ldap3::Ldap, base_dn: &str, role: Role, to: &str) -> LdapResult<bool> {
    let (_, dcs, p) = overview(conn, base_dn).await?;
    let names: HashSet<String> = dcs.iter().map(|d| d.name.to_lowercase()).collect();
    let h = holders(conn, &p, &names).await.into_iter().find(|h| h.role == role).ok_or("Unknown role")?;
    check_transfer(&h, to, &dcs)?;
    let target = dcs.iter().find(|d| d.name.eq_ignore_ascii_case(to)).ok_or("Unknown DC")?;
    let what = format!("The {} was not moved to {}", h.label, target.name);

    match role.become_attr() {
        Some(attr) => {
            let value = if role == Role::Pdc {
                // Asking to become PDC names the domain, by its SID.
                let e = read_one(conn, base_dn, vec!["objectSid"]).await?;
                e.bin_attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case("objectSid")).and_then(|(_, v)| v.first().cloned()).ok_or("The domain's SID could not be read")?
            } else {
                b"1".to_vec()
            };
            let mut at = connect_to(server, target).await.map_err(|e| format!("{what}: {e}"))?;
            let res = at
                .with_timeout(Duration::from_secs(120))
                .modify("", vec![Mod::Replace(attr.as_bytes().to_vec(), HashSet::from([value]))])
                .await
                .map_err(|e| format!("{what}: {}", ldap_err(e)));
            let res = match res {
                Ok(r) => r,
                Err(e) => {
                    let _ = at.unbind().await;
                    return Err(e);
                }
            };
            // What counts is who holds the role afterwards, read from the DC
            // that asked for it. Samba can answer the PDC emulator's move with
            // "Failed FSMO transfer: WERR_GEN_FAILURE" after about 10 seconds
            // although the role has moved, so an error is checked the same way,
            // a few times while the role settles.
            let tries = if res.rc == 0 { 1 } else { 4 };
            let mut now = Err(String::new());
            for i in 0..tries {
                if i > 0 {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                now = read_one(&mut at, &p.role_dn(role), vec!["fSMORoleOwner"]).await.map(|e| ntds_dn_of(&attr_ci(&e, "fSMORoleOwner")));
                if matches!(&now, Ok(dc) if dc.eq_ignore_ascii_case(&target.name)) {
                    break;
                }
            }
            let _ = at.unbind().await;
            match now {
                // Both DCs write the new holder during the move, so this DC
                // sees it at once when it is one of them; another catches up.
                Ok(dc) if dc.eq_ignore_ascii_case(&target.name) => Ok(sees(conn, &p, role, &target.name).await),
                _ if res.rc != 0 => Err(refused_transfer(&what, &h.dc, &target.name, &res)),
                Ok(dc) => Err(format!("{what}: {} accepted the request, but still names {dc} as the holder.", target.name)),
                Err(e) => Err(format!("{what}: {} accepted the request, but the holder could not be read back: {e}", target.name)),
            }
        }
        None => {
            // The DNS roles: the holder writes the new owner itself.
            let target_ntds = ntds_settings_dn(conn, &p, target).await?;
            let holder = dcs.iter().find(|d| d.name.eq_ignore_ascii_case(&h.dc)).ok_or("Unknown holder")?;
            let mut at = connect_to(server, holder).await.map_err(|e| format!("{what}: {e}"))?;
            let mods = vec![
                Mod::Delete(b"fSMORoleOwner".to_vec(), HashSet::from([h.owner.as_bytes().to_vec()])),
                Mod::Add(b"fSMORoleOwner".to_vec(), HashSet::from([target_ntds.as_bytes().to_vec()])),
            ];
            let res = at.with_timeout(OP_TIMEOUT).modify(&p.role_dn(role), mods).await.map_err(|e| format!("{what}: {}", ldap_err(e)));
            let _ = at.unbind().await;
            let res = res?;
            if res.rc != 0 {
                return Err(refused_transfer(&what, &h.dc, &target.name, &res));
            }
            // DCs in a site pass a change on within about 15 seconds of it.
            for _ in 0..7 {
                if sees(conn, &p, role, &target.name).await {
                    return Ok(true);
                }
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Ok(false)
        }
    }
}

/// Whether the DC `conn` is on names `dc` as the role's holder.
async fn sees(conn: &mut ldap3::Ldap, p: &Partitions, role: Role, dc: &str) -> bool {
    read_one(conn, &p.role_dn(role), vec!["fSMORoleOwner"]).await.is_ok_and(|e| ntds_dn_of(&attr_ci(&e, "fSMORoleOwner")).eq_ignore_ascii_case(dc))
}

/// A DC's NTDS Settings DN, as `fSMORoleOwner` names it.
async fn ntds_settings_dn(conn: &mut ldap3::Ldap, p: &Partitions, dc: &DcInfo) -> LdapResult<String> {
    let found = health::search(
        conn,
        &format!("CN=Sites,{}", p.config),
        Scope::Subtree,
        &format!("(&(objectClass=nTDSDSA)(objectGUID={}))", guid_filter(&dc.guid)),
        vec!["1.1"],
    )
    .await?;
    found.first().map(|e| e.dn.clone()).ok_or_else(|| format!("The NTDS Settings of {} could not be found.", dc.name))
}

/// A GUID as text (`b4d2…-…`) as an LDAP filter value: its 16 bytes in the
/// order the directory stores them, each `\xx`.
fn guid_filter(guid: &str) -> String {
    let hex: String = guid.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if hex.len() != 32 {
        return String::new();
    }
    let b: Vec<u8> = (0..16).map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap_or(0)).collect();
    // The first three groups are little-endian in storage.
    let order = [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15];
    order.iter().map(|&i| format!("\\{:02x}", b[i])).collect()
}

/// What a refused move means, in words.
fn refused_transfer(what: &str, from: &str, to: &str, res: &ldap3::LdapResult) -> String {
    match res.rc {
        50 => format!("{what}: the account EasyDC signs in with may not move FSMO roles. It needs to be a Domain Admin (an Enterprise Admin for the schema and domain naming roles)."),
        51 | 52 | 80 => format!(
            "{what}: {to} could not get it from {from}, which must be running and reachable from {to}. \
             The DC said \"{}\" (LDAP code {}).",
            res.text.trim(),
            res.rc
        ),
        _ => ldap::dc_refused(what, res),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dcs() -> Vec<DcInfo> {
        ["DC1", "DC2"]
            .iter()
            .map(|n| DcInfo { name: n.to_string(), site: "S".into(), dns_host_name: format!("{}.x.com", n.to_lowercase()), guid: String::new() })
            .collect()
    }

    fn holder(role: Role, dc: &str, gone: bool) -> Holder {
        Holder {
            role,
            key: role.key(),
            label: role.label(),
            does: role.does(),
            dc: dc.to_string(),
            owner: if dc.is_empty() { String::new() } else { format!("CN=NTDS Settings,CN={dc},CN=Servers,CN=S,CN=Sites,CN=Configuration,DC=x,DC=com") },
            gone,
            missing: false,
        }
    }

    #[test]
    fn every_role_has_its_object() {
        let p = Partitions {
            domain: "DC=x,DC=com".into(),
            config: "CN=Configuration,DC=root,DC=com".into(),
            schema: "CN=Schema,CN=Configuration,DC=root,DC=com".into(),
            forest: "DC=root,DC=com".into(),
        };
        assert_eq!(p.role_dn(Role::Pdc), "DC=x,DC=com");
        assert_eq!(p.role_dn(Role::Rid), "CN=RID Manager$,CN=System,DC=x,DC=com");
        assert_eq!(p.role_dn(Role::Naming), "CN=Partitions,CN=Configuration,DC=root,DC=com");
        assert_eq!(p.role_dn(Role::Schema), "CN=Schema,CN=Configuration,DC=root,DC=com");
        assert_eq!(p.role_dn(Role::DomainDns), "CN=Infrastructure,DC=DomainDnsZones,DC=x,DC=com");
        assert_eq!(p.role_dn(Role::ForestDns), "CN=Infrastructure,DC=ForestDnsZones,DC=root,DC=com", "the forest's, in a child domain");
        for r in ROLES {
            assert_eq!(Role::from_key(r.key()), Some(r));
            assert_eq!(r.become_attr().is_none(), matches!(r, Role::DomainDns | Role::ForestDns));
        }
    }

    #[test]
    fn the_holder_is_the_dc_its_ntds_settings_is_in() {
        assert_eq!(ntds_dn_of("CN=NTDS Settings,CN=TESTDC2,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=lab,DC=test"), "TESTDC2");
        assert_eq!(ntds_dn_of(""), "");
    }

    #[test]
    fn a_move_is_checked_first() {
        let d = dcs();
        assert!(check_transfer(&holder(Role::Pdc, "DC1", false), "DC2", &d).is_ok());
        assert_eq!(check_transfer(&holder(Role::Pdc, "DC1", false), "dc1", &d).unwrap_err(), "DC1 already holds the PDC emulator.");
        assert_eq!(check_transfer(&holder(Role::Pdc, "DC1", false), "DC9", &d).unwrap_err(), "There is no DC DC9.");
        let e = check_transfer(&holder(Role::Rid, "OLDDC", true), "DC2", &d).unwrap_err();
        assert!(e.contains("Its holder, OLDDC, no longer exists") && e.contains("samba-tool fsmo seize --role=rid"), "{e}");
        assert!(check_transfer(&holder(Role::Rid, "", false), "DC2", &d).unwrap_err().contains("No DC holds it"));
        let mut h = holder(Role::DomainDns, "", false);
        h.missing = true;
        assert!(check_transfer(&h, "DC2", &d).unwrap_err().contains("no DomainDnsZones partition"));
    }

    #[test]
    fn a_guid_becomes_a_filter_in_stored_order() {
        // As format_guid writes it, and as the directory stores it.
        let bytes: Vec<u8> = (0u8..16).collect();
        let text = health::format_guid(&bytes);
        let f = guid_filter(&text);
        let back: String = bytes.iter().map(|b| format!("\\{b:02x}")).collect();
        assert_eq!(f, back);
        assert_eq!(guid_filter("nope"), "");
    }
}
