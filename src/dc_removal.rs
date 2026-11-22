//! Removing a DC that is gone for good (a dead server, a failed disk) from
//! the directory, as `samba-tool domain demote --remove-other-dead-server`
//! does. A running DC is demoted on itself instead; EasyDC refuses one that
//! still answers.
//!
//! What a DC leaves behind ([MS-ADTS] 6.1.1.2, and what a demotion removes):
//! - in the configuration partition, its server object under its site, with
//!   its NTDS Settings (which makes it a DC) and their replication
//!   connections inside, and connections on other DCs that name it;
//! - in the domain, its computer account, with its RID Set inside, the
//!   `krbtgt_<n>` account of a read-only DC, Samba's `dns-<name>` account,
//!   and its SYSVOL replication entries;
//! - in DNS, its own A/AAAA records, its address on the names every DC
//!   registers (the zone itself, `gc._msdcs`, `DomainDnsZones`,
//!   `ForestDnsZones`), and the SRV, NS, CNAME and PTR records naming it.
//!
//! Everything is found first and shown; the removal deletes what was found,
//! the server object last: while it stays, the DC is still listed and the
//! removal can be run again to finish.

use std::collections::{BTreeMap, HashSet};
use std::time::Duration;

use ldap3::{Mod, Scope, SearchEntry};
use serde::Serialize;

use crate::fsmo::{self, Partitions};
use crate::health::{attr_ci, attrs_ci, read_one, search};
use crate::ldap::{self, dn_escape, first_rdn_value, ldap_escape, parent_dn, LdapResult, OP_TIMEOUT};

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Object {
    /// What it is, in words: "Computer account".
    pub what: String,
    pub dn: String,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct Record {
    /// The full name: `_ldap._tcp.lab.test`.
    pub name: String,
    pub rtype: String,
    pub value: String,
    #[serde(skip)]
    pub node_dn: String,
    #[serde(skip)]
    pub raw: Vec<u8>,
}

#[derive(Debug, Serialize, Clone, Default)]
pub struct Plan {
    pub dc: String,
    pub host: String,
    /// Why it cannot be removed; empty when it can.
    pub refusals: Vec<String>,
    /// In the order they are deleted, the server object last.
    pub objects: Vec<Object>,
    pub records: Vec<Record>,
}

/// The DC's server object, as the search found it.
struct Server {
    dn: String,
    host: String,
    computer: String,
}

async fn find_server(conn: &mut ldap3::Ldap, p: &Partitions, name: &str) -> LdapResult<Server> {
    let found = search(
        conn,
        &format!("CN=Sites,{}", p.config),
        Scope::Subtree,
        &format!("(&(objectClass=server)(cn={}))", ldap_escape(name)),
        vec!["dNSHostName", "serverReference"],
    )
    .await?;
    let e = found.first().ok_or_else(|| format!("There is no DC {name}."))?;
    // A server object without NTDS Settings inside is not a DC (any more).
    let ntds = search(conn, &e.dn, Scope::OneLevel, "(objectClass=nTDSDSA)", vec!["1.1"]).await.unwrap_or_default();
    if ntds.is_empty() {
        return Err(format!("{name} is not a domain controller."));
    }
    Ok(Server { dn: e.dn.clone(), host: attr_ci(e, "dNSHostName"), computer: attr_ci(e, "serverReference") })
}

/// Whether anything accepts a connection on the DC's LDAP ports. A name that
/// no longer resolves counts as not answering.
/// Whether something answers on the LDAP ports at the DC's name, or at an
/// address its name has in the directory's DNS: EasyDC's own host may not
/// use the domain's DNS. Returns where, and the port.
async fn answers(host: &str, addresses: &[String]) -> Option<(String, u16)> {
    let mut tries = tokio::task::JoinSet::new();
    let targets = std::iter::once(host.to_string()).filter(|h| !h.is_empty()).chain(addresses.iter().cloned());
    for target in targets {
        for port in [389u16, 636] {
            let target = target.clone();
            tries.spawn(async move {
                let wait = Duration::from_secs(3);
                let reached = match target.parse::<std::net::IpAddr>() {
                    Ok(ip) => tokio::time::timeout(wait, tokio::net::TcpStream::connect((ip, port))).await,
                    Err(_) => tokio::time::timeout(wait, tokio::net::TcpStream::connect((target.as_str(), port))).await,
                };
                matches!(reached, Ok(Ok(_))).then_some((target, port))
            });
        }
    }
    while let Some(done) = tries.join_next().await {
        if let Ok(Some(found)) = done {
            return Some(found);
        }
    }
    None
}

async fn exists(conn: &mut ldap3::Ldap, dn: &str) -> bool {
    read_one(conn, dn, vec!["1.1"]).await.is_ok()
}

/// Find everything a DC left behind, and whether it may be removed.
pub async fn plan(conn: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<Plan> {
    let (overview, _, p) = fsmo::overview(conn, base_dn).await?;
    let server = find_server(conn, &p, name).await?;
    let dc = first_rdn_value(&server.dn);
    let mut plan = Plan { dc: dc.clone(), host: server.host.clone(), ..Default::default() };

    if overview.dcs.iter().any(|d| d.configured && d.name.eq_ignore_ascii_case(&dc)) {
        plan.refusals.push(format!(
            "EasyDC is connected to {dc}, so it is running. A running DC is removed by demoting it, on itself: \
             samba-tool domain demote."
        ));
    }
    let held: Vec<&fsmo::Holder> = overview.roles.iter().filter(|h| !h.gone && h.dc.eq_ignore_ascii_case(&dc)).collect();
    if !held.is_empty() {
        let names: Vec<&str> = held.iter().map(|h| h.label).collect();
        let keys: Vec<&str> = held.iter().map(|h| h.key).collect();
        plan.refusals.push(format!(
            "{dc} still holds the {}. A DC that is gone cannot hand them over, so take them on a live DC first: \
             samba-tool fsmo seize --role=<role> (for {}).",
            join_words(&names),
            keys.join(", ")
        ));
    }
    let mut dns = Dns::default();
    if !server.host.is_empty() {
        let others: Vec<String> = overview.dcs.iter().filter(|d| !d.name.eq_ignore_ascii_case(&dc)).map(|d| d.host.clone()).collect();
        dns = dns_records(conn, &p, &server.host, &others).await;
    }
    let addresses: Vec<String> = dns.addresses.iter().map(|(a, _)| a.clone()).collect();
    if plan.refusals.is_empty()
        && let Some((at, port)) = answers(&server.host, &addresses).await
    {
        let host = &server.host;
        let other = dns.addresses.iter().find(|(a, _)| *a == at).and_then(|(_, o)| o.as_ref());
        plan.refusals.push(match other {
            Some(other) => format!(
                "In DNS, {host} points at {at}, which is also the address of {other}, and something answers there. \
                 Change or remove the A record of {host} on the DNS page first, so it no longer points at a live machine."
            ),
            None => format!(
                "{dc} still answers at {at} (port {port}), so it is not gone. Demote a running DC on itself: \
                 samba-tool domain demote. If it is shut down for good and the address now belongs to another machine, \
                 change or remove the A record of {host} first."
            ),
        });
    }
    plan.records = dns.records;

    // Connections on other DCs that replicate from it.
    let ntds_dn = format!("CN=NTDS Settings,{}", server.dn);
    for e in search(
        conn,
        &format!("CN=Sites,{}", p.config),
        Scope::Subtree,
        &format!("(&(objectClass=nTDSConnection)(fromServer={}))", ldap_escape(&ntds_dn)),
        vec!["1.1"],
    )
    .await
    .unwrap_or_default()
    {
        if !ldap::is_within(&e.dn, &server.dn) {
            plan.objects.push(Object { what: format!("Replication connection from {dc}"), dn: e.dn });
        }
    }

    // SYSVOL replication entries, under the configuration partition and the domain.
    let realm = ldap::base_dn_to_domain(base_dn);
    for parent in [
        format!("CN=Enterprise,CN=Microsoft System Volumes,CN=System,{}", p.config),
        format!("CN={},CN=Microsoft System Volumes,CN=System,{}", dn_escape(&realm), p.config),
        format!("CN=Domain System Volumes (SYSVOL share),CN=File Replication Service,CN=System,{base_dn}"),
        format!("CN=Topology,CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,{base_dn}"),
    ] {
        let dn = format!("CN={},{parent}", dn_escape(&dc));
        if exists(conn, &dn).await {
            plan.objects.push(Object { what: "SYSVOL replication entry".into(), dn });
        }
    }

    // Samba's DNS service account for the DC.
    if !server.host.is_empty() {
        let filter = format!(
            "(&(objectClass=user)(cn=dns-{})(servicePrincipalName=DNS/{}))",
            ldap_escape(&dc),
            ldap_escape(&server.host)
        );
        for e in search(conn, base_dn, Scope::Subtree, &filter, vec!["1.1"]).await.unwrap_or_default() {
            plan.objects.push(Object { what: "Samba DNS service account".into(), dn: e.dn });
        }
    }

    // The computer account, and a read-only DC's own krbtgt account.
    if !server.computer.is_empty()
        && let Ok(e) = read_one(conn, &server.computer, vec!["msDS-KrbTgtLink"]).await
    {
        for link in attrs_ci(&e, "msDS-KrbTgtLink") {
            plan.objects.push(Object { what: "Read-only DC's krbtgt account".into(), dn: link });
        }
        plan.objects.push(Object { what: "Computer account, with its RID Set".into(), dn: server.computer.clone() });
    }

    plan.objects.push(Object { what: "Server object, with its NTDS Settings".into(), dn: server.dn.clone() });
    Ok(plan)
}

fn join_words(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [one] => one.to_string(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// A DNS name as compared: lowercase, without the final dot.
fn plain(name: &str) -> String {
    name.trim_end_matches('.').to_lowercase()
}

/// Names every DC registers its address on, besides its own.
const SHARED_NAMES: [&str; 4] = ["@", "gc", "domaindnszones", "forestdnszones"];

/// Which of a node's records point at `host`: SRV, NS, CNAME and PTR records
/// naming it, all A/AAAA records of its own name, and on the names every DC
/// shares, the A/AAAA records with one of its addresses.
fn pointing_at(node: &str, zone: &str, records: &[(String, String)], host: &str, addresses: &HashSet<String>) -> Vec<usize> {
    let host = plain(host);
    let full = if node == "@" { plain(zone) } else { plain(&format!("{node}.{zone}")) };
    let shared = SHARED_NAMES.contains(&node.to_lowercase().as_str());
    records
        .iter()
        .enumerate()
        .filter(|(_, (rtype, value))| match rtype.as_str() {
            "NS" | "CNAME" | "PTR" => plain(value) == host,
            // "priority weight port target"
            "SRV" => value.split_whitespace().nth(3).is_some_and(|t| plain(t) == host),
            "A" | "AAAA" => full == host || (shared && addresses.contains(value)),
            _ => false,
        })
        .map(|(i, _)| i)
        .collect()
}

/// The DC's addresses, from the A/AAAA records of its own name, less any
/// address another DC's name also has: a dead DC's name may point at an
/// address a live DC now uses (or was registered from it), and the live DC's
/// records on the shared names must stay.
fn own_addresses(names: &[(String, Vec<(String, String)>)], host: &str, others: &[String]) -> HashSet<String> {
    name_addresses(names, host, others).into_iter().filter(|(_, other)| other.is_none()).map(|(a, _)| a).collect()
}

/// The A/AAAA addresses of `host`'s own name, each with the other DC whose
/// name has it too, if one does.
fn name_addresses(names: &[(String, Vec<(String, String)>)], host: &str, others: &[String]) -> Vec<(String, Option<String>)> {
    let of = |h: &str| -> Vec<String> {
        let h = plain(h);
        let mut v: Vec<String> = names
            .iter()
            .filter(|(full, _)| *full == h)
            .flat_map(|(_, recs)| recs.iter().filter(|(t, _)| t == "A" || t == "AAAA").map(|(_, v)| v.clone()))
            .collect();
        v.dedup();
        v
    };
    of(host)
        .into_iter()
        .map(|a| {
            let other = others.iter().filter(|o| !o.is_empty()).find(|o| of(o).contains(&a)).cloned();
            (a, other)
        })
        .collect()
}

/// What DNS says about the DC.
#[derive(Default)]
struct Dns {
    /// The records to delete.
    records: Vec<Record>,
    /// Its own name's addresses, with another DC sharing each.
    addresses: Vec<(String, Option<String>)>,
}

/// Every DNS record pointing at `host`, in all the zones kept in the
/// directory: the domain's and the forest's DNS partitions, and the old place
/// under the domain's System container. `others` are the other DCs' names.
async fn dns_records(conn: &mut ldap3::Ldap, p: &Partitions, host: &str, others: &[String]) -> Dns {
    let mut nodes: Vec<(String, String, String, Vec<Vec<u8>>)> = Vec::new(); // dn, node, zone, records
    for base in [
        format!("DC=DomainDnsZones,{}", p.domain),
        format!("DC=ForestDnsZones,{}", p.forest),
        format!("CN=MicrosoftDNS,CN=System,{}", p.domain),
    ] {
        let Ok(found) = search(conn, &base, Scope::Subtree, "(&(objectClass=dnsNode)(dnsRecord=*))", vec!["dc", "dnsRecord"]).await else {
            continue;
        };
        for e in found {
            let raw = bin_values(&e, "dnsRecord");
            let zone = first_rdn_value(parent_dn(&e.dn));
            nodes.push((e.dn.clone(), attr_ci(&e, "dc"), zone, raw));
        }
    }
    let parse = |raw: &[Vec<u8>]| -> Vec<(String, String)> {
        raw.iter().map(|r| ldap::parse_dns_record_binary(r).map(|(t, v, _)| (t, v)).unwrap_or_default()).collect()
    };
    let names: Vec<(String, Vec<(String, String)>)> = nodes
        .iter()
        .map(|(_, node, zone, raw)| (if node == "@" { plain(zone) } else { plain(&format!("{node}.{zone}")) }, parse(raw)))
        .collect();
    let addresses = own_addresses(&names, host, others);
    let named = name_addresses(&names, host, others);
    let mut out = Vec::new();
    for (dn, node, zone, raw) in nodes {
        let parsed = parse(&raw);
        for i in pointing_at(&node, &zone, &parsed, host, &addresses) {
            let name = if node == "@" { zone.clone() } else { format!("{node}.{zone}") };
            out.push(Record { name, rtype: parsed[i].0.clone(), value: parsed[i].1.clone(), node_dn: dn.clone(), raw: raw[i].clone() });
        }
    }
    out.sort_by(|a, b| (a.name.to_lowercase(), &a.rtype).cmp(&(b.name.to_lowercase(), &b.rtype)));
    Dns { records: out, addresses: named }
}

fn bin_values(e: &SearchEntry, key: &str) -> Vec<Vec<u8>> {
    e.bin_attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).map(|(_, v)| v.clone()).unwrap_or_default()
}

/// What a removal did, for the page.
pub struct Done {
    pub objects: usize,
    pub records: usize,
}

/// Remove the DC: the plan is made again here, and nothing happens while it
/// has a reason to refuse.
pub async fn remove(conn: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<Done> {
    let plan = plan(conn, base_dn, name).await?;
    if !plan.refusals.is_empty() {
        return Err(plan.refusals.join(" "));
    }
    let what = format!("{} was not fully removed", plan.dc);
    let mut by_node: BTreeMap<String, Vec<Vec<u8>>> = BTreeMap::new();
    for r in &plan.records {
        by_node.entry(r.node_dn.clone()).or_default().push(r.raw.clone());
    }
    for (node, values) in by_node {
        let res = conn
            .with_timeout(OP_TIMEOUT)
            .modify(&node, vec![Mod::Delete(b"dnsRecord".to_vec(), values.into_iter().collect::<HashSet<_>>())])
            .await
            .map_err(ldap::ldap_err)?;
        if res.rc != 0 && res.rc != 16 && res.rc != 32 {
            return Err(ldap::refused(&format!("{what}: a DNS record was not deleted"), &first_rdn_value(&node), &res));
        }
        // A name left with no records goes too, as when a record is deleted on the DNS page.
        let empty = search(conn, &node, Scope::Base, "(&(objectClass=dnsNode)(!(dnsRecord=*)))", vec!["1.1"]).await.is_ok_and(|e| !e.is_empty());
        if empty {
            let _ = conn.with_timeout(OP_TIMEOUT).delete(&node).await;
        }
    }
    for o in &plan.objects {
        if exists(conn, &o.dn).await {
            crate::sites::delete_tree(conn, &o.dn).await.map_err(|e| format!("{what}: its {} was not deleted: {e}", o.what.to_lowercase()))?;
        }
    }
    Ok(Done { objects: plan.objects.len(), records: plan.records.len() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recs(r: &[(&str, &str)]) -> Vec<(String, String)> {
        r.iter().map(|(t, v)| (t.to_string(), v.to_string())).collect()
    }

    fn ips() -> HashSet<String> {
        ["192.168.7.12".to_string()].into_iter().collect()
    }

    const HOST: &str = "testdc2.lab.test";

    #[test]
    fn its_own_name_goes() {
        let r = recs(&[("A", "192.168.7.12"), ("AAAA", "fd00::12"), ("TXT", "keep me")]);
        assert_eq!(pointing_at("testdc2", "lab.test", &r, HOST, &ips()), [0, 1]);
        assert_eq!(pointing_at("TESTDC2", "LAB.TEST", &r, "TESTDC2.lab.test.", &ips()), [0, 1], "names compare without case or final dot");
    }

    #[test]
    fn shared_names_lose_only_its_address() {
        let r = recs(&[("A", "192.168.7.11"), ("A", "192.168.7.12"), ("NS", "testdc.lab.test"), ("NS", "testdc2.lab.test."), ("SOA", "x")]);
        assert_eq!(pointing_at("@", "lab.test", &r, HOST, &ips()), [1, 3]);
        assert_eq!(pointing_at("gc", "_msdcs.lab.test", &r, HOST, &ips()), [1, 3]);
        assert_eq!(pointing_at("DomainDnsZones", "lab.test", &r, HOST, &ips()), [1, 3]);
        // Another name sharing the address is not the DC's.
        assert_eq!(pointing_at("printer", "lab.test", &recs(&[("A", "192.168.7.12")]), HOST, &ips()), Vec::<usize>::new());
    }

    #[test]
    fn an_address_a_live_dc_uses_is_not_its() {
        let r = |v: &[(&str, &str)]| v.iter().map(|(t, x)| (t.to_string(), x.to_string())).collect::<Vec<_>>();
        let names = vec![
            ("deaddc.lab.test".to_string(), r(&[("A", "192.168.7.11"), ("A", "192.168.7.99")])),
            ("testdc.lab.test".to_string(), r(&[("A", "192.168.7.11")])),
            ("lab.test".to_string(), r(&[("A", "192.168.7.11"), ("A", "192.168.7.99")])),
        ];
        let others = ["testdc.lab.test".to_string(), String::new()];
        let mine = own_addresses(&names, "DEADDC.lab.test.", &others);
        assert_eq!(
            name_addresses(&names, "deaddc.lab.test", &others),
            [("192.168.7.11".to_string(), Some("testdc.lab.test".to_string())), ("192.168.7.99".to_string(), None)]
        );
        assert_eq!(mine, HashSet::from(["192.168.7.99".to_string()]));
        // So on the shared names only its own address goes; its own name loses both.
        let shared = r(&[("A", "192.168.7.11"), ("A", "192.168.7.99")]);
        assert_eq!(pointing_at("@", "lab.test", &shared, "deaddc.lab.test", &mine), [1]);
        assert_eq!(pointing_at("deaddc", "lab.test", &shared, "deaddc.lab.test", &mine), [0, 1]);
    }

    #[test]
    fn records_naming_it_go() {
        let srv = recs(&[("SRV", "0 100 389 testdc.lab.test"), ("SRV", "0 100 389 testdc2.lab.test")]);
        assert_eq!(pointing_at("_ldap._tcp", "lab.test", &srv, HOST, &ips()), [1]);
        let cname = recs(&[("CNAME", "testdc2.lab.test")]);
        assert_eq!(pointing_at("1d1a3b2c-0000-4c3e-9e10-5a5b7c9d0e1f", "_msdcs.lab.test", &cname, HOST, &ips()), [0]);
        let ptr = recs(&[("PTR", "testdc2.lab.test"), ("PTR", "testdc2.lab.test.evil")]);
        assert_eq!(pointing_at("12", "7.168.192.in-addr.arpa", &ptr, HOST, &ips()), [0]);
    }

    #[test]
    fn roles_read_as_a_list() {
        assert_eq!(join_words(&["PDC emulator"]), "PDC emulator");
        assert_eq!(join_words(&["PDC emulator", "RID master", "Schema master"]), "PDC emulator, RID master and Schema master");
    }
}
