//! Read-only domain health diagnostics ("test domain").
//!
//! Every check here runs over the same LDAP connection the rest of EasyDC
//! uses — no host access, no root, no process spawning. Checks that genuinely
//! require running commands on the DC (`samba-tool dbcheck`, SYSVOL ACL
//! consistency, `net ads testjoin`, service status) are deliberately absent.
//!
//! A check never aborts the report: anything that fails to run reports itself
//! as `SKIP` with the reason, so one broken partition cannot hide the rest of
//! the diagnosis.

use ldap3::{Scope, SearchEntry};
use serde::Serialize;
use std::collections::HashMap;

use crate::ldap::{self, base_dn_to_domain, LdapResult};
use crate::models::Server;

pub const PASS: &str = "pass";
pub const WARN: &str = "warn";
pub const FAIL: &str = "fail";
pub const SKIP: &str = "skip";

// ── result types ──────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct CheckResult {
    pub id: &'static str,
    pub category: &'static str,
    pub title: &'static str,
    pub status: &'static str,
    /// One-line verdict, always populated.
    pub summary: String,
    /// Supporting lines shown under the summary.
    pub detail: Vec<String>,
    /// What to do about it. Task #3 turns these into guided fixes.
    pub remediation: Option<String>,
}

impl CheckResult {
    fn new(id: &'static str, category: &'static str, title: &'static str) -> Self {
        CheckResult {
            id,
            category,
            title,
            status: SKIP,
            summary: String::new(),
            detail: Vec::new(),
            remediation: None,
        }
    }

    fn set(mut self, status: &'static str, summary: impl Into<String>) -> Self {
        self.status = status;
        self.summary = summary.into();
        self
    }

    fn line(mut self, line: impl Into<String>) -> Self {
        self.detail.push(line.into());
        self
    }

    fn fix(mut self, hint: impl Into<String>) -> Self {
        self.remediation = Some(hint.into());
        self
    }

    fn skipped(self, why: impl Into<String>) -> Self {
        self.set(SKIP, why)
    }
}

#[derive(Debug, Serialize)]
pub struct HealthReport {
    pub domain: String,
    pub base_dn: String,
    pub checks: Vec<CheckResult>,
    pub pass_count: usize,
    pub warn_count: usize,
    pub fail_count: usize,
    pub skip_count: usize,
    /// Wall-clock time the whole battery took, milliseconds.
    pub elapsed_ms: u128,
}

impl HealthReport {
    fn tally(mut self) -> Self {
        self.pass_count = self.checks.iter().filter(|c| c.status == PASS).count();
        self.warn_count = self.checks.iter().filter(|c| c.status == WARN).count();
        self.fail_count = self.checks.iter().filter(|c| c.status == FAIL).count();
        self.skip_count = self.checks.iter().filter(|c| c.status == SKIP).count();
        self
    }
}

// ── shared context ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct DcInfo {
    pub name: String,
    pub site: String,
    pub dns_host_name: String,
    pub guid: String,
}

struct Ctx {
    base_dn: String,
    domain: String,
    config_dn: String,
    dcs: Vec<DcInfo>,
    /// Every DNS name found in the AD-integrated zones, lowercased, mapped to
    /// the record types present at that name.
    dns: HashMap<String, Vec<String>>,
    dns_error: Option<String>,
}

// ── low-level helpers ─────────────────────────────────────────────────────────

async fn search(
    conn: &mut ldap3::Ldap,
    base: &str,
    scope: Scope,
    filter: &str,
    attrs: Vec<&str>,
) -> LdapResult<Vec<SearchEntry>> {
    let (entries, _) = conn
        .search(base, scope, filter, attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    Ok(entries.into_iter().map(SearchEntry::construct).collect())
}

/// Base-scope read of a single object.
async fn read_one(
    conn: &mut ldap3::Ldap,
    dn: &str,
    attrs: Vec<&str>,
) -> LdapResult<SearchEntry> {
    search(conn, dn, Scope::Base, "(objectClass=*)", attrs)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| format!("{} not found", dn))
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Days since the civil epoch (1970-01-01). Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse an LDAP GeneralizedTime (`20260818103000.0Z`) into a unix timestamp.
fn parse_generalized_time(s: &str) -> Option<i64> {
    let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.len() < 14 {
        return None;
    }
    let num = |a: usize, b: usize| digits[a..b].parse::<i64>().ok();
    let (y, mo, d) = (num(0, 4)?, num(4, 6)?, num(6, 8)?);
    let (h, mi, sec) = (num(8, 10)?, num(10, 12)?, num(12, 14)?);
    Some(days_from_civil(y, mo, d) * 86_400 + h * 3_600 + mi * 60 + sec)
}

/// Windows FILETIME (100ns ticks since 1601-01-01) to unix seconds.
fn filetime_to_unix(ft: i64) -> i64 {
    ft / 10_000_000 - 11_644_473_600
}

/// objectGUID is stored little-endian in its first three fields.
fn format_guid(b: &[u8]) -> String {
    if b.len() != 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{}",
        b[3], b[2], b[1], b[0],
        b[5], b[4],
        b[7], b[6],
        b[8], b[9],
        b[10..16].iter().map(|x| format!("{:02x}", x)).collect::<String>()
    )
}

/// First RDN value of a DN — `CN=DC1,CN=Servers,…` becomes `DC1`.
fn rdn_value(dn: &str) -> String {
    dn.split(',')
        .next()
        .and_then(|p| p.split_once('='))
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
}

/// Split a DN into its RDN values, so positional lookups into the Sites tree
/// stay readable.
fn dn_parts(dn: &str) -> Vec<String> {
    dn.split(',').map(rdn_value).collect()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let hostport = rest.split('/').next()?;
    let host = if let Some(stripped) = hostport.strip_prefix('[') {
        stripped.split(']').next()?.to_string()
    } else {
        hostport.split(':').next()?.to_string()
    };
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 {
        format!("{} {}", n, one)
    } else {
        format!("{} {}", n, many)
    }
}

// ── context building ──────────────────────────────────────────────────────────

/// Enumerate the domain controllers from the Sites container. Each nTDSDSA
/// object sits at `CN=NTDS Settings,CN=<server>,CN=Servers,CN=<site>,CN=Sites,…`,
/// so the server and site names come straight out of the DN, and the matching
/// server object carries the DNS host name.
async fn load_dcs(conn: &mut ldap3::Ldap, config_dn: &str) -> LdapResult<Vec<DcInfo>> {
    let sites_dn = format!("CN=Sites,{}", config_dn);
    let ntds = search(
        conn,
        &sites_dn,
        Scope::Subtree,
        "(objectClass=nTDSDSA)",
        vec!["objectGUID"],
    )
    .await?;

    let mut dcs = Vec::new();
    for e in ntds {
        let parts = dn_parts(&e.dn);
        // parts[0] = "NTDS Settings", [1] = server, [2] = "Servers", [3] = site
        let name = parts.get(1).cloned().unwrap_or_default();
        let site = parts.get(3).cloned().unwrap_or_default();
        let guid = e
            .bin_attrs
            .get("objectGUID")
            .or_else(|| e.bin_attrs.get("objectguid"))
            .and_then(|v| v.first())
            .map(|b| format_guid(b))
            .unwrap_or_default();

        // The parent of the NTDS Settings object is the server object.
        let server_dn = e.dn.splitn(2, ',').nth(1).unwrap_or("").to_string();
        let dns_host_name = read_one(conn, &server_dn, vec!["dNSHostName"])
            .await
            .map(|s| attr_ci(&s, "dNSHostName"))
            .unwrap_or_default();

        dcs.push(DcInfo { name, site, dns_host_name, guid });
    }

    dcs.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(dcs)
}

/// Build a map of every name held in the AD-integrated DNS zones to the record
/// types present at that name. Zones can live in any of three partitions and
/// `_msdcs` is frequently split into its own forest-wide zone, so records are
/// keyed by fully-qualified name rather than by (zone, node) — that way a
/// lookup does not need to know which layout this domain uses.
async fn load_dns(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<HashMap<String, Vec<String>>> {
    let partitions = [
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,DC=ForestDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
    ];

    let mut zones: Vec<(String, String)> = Vec::new();
    for p in &partitions {
        if let Ok(entries) = search(conn, p, Scope::OneLevel, "(objectClass=dnsZone)", vec!["dc"]).await {
            for e in entries {
                let name = attr_ci(&e, "dc");
                // Unlike the DNS management page, nothing is filtered here:
                // `_msdcs.<domain>` is exactly the zone these checks care about.
                if !name.is_empty() && name != "RootDNSServers" && !name.starts_with('.') {
                    zones.push((name.to_lowercase(), e.dn.clone()));
                }
            }
        }
    }

    if zones.is_empty() {
        return Err("No AD-integrated DNS zones found".to_string());
    }

    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for (zone_name, zone_dn) in zones {
        let nodes = match search(
            conn,
            &zone_dn,
            Scope::OneLevel,
            "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))",
            vec!["dc", "dnsRecord"],
        )
        .await
        {
            Ok(n) => n,
            Err(_) => continue,
        };

        for e in nodes {
            let node = attr_ci(&e, "dc");
            if node.is_empty() {
                continue;
            }
            let fqdn = if node == "@" {
                zone_name.clone()
            } else {
                format!("{}.{}", node.to_lowercase(), zone_name)
            };

            let raw: Vec<Vec<u8>> = e
                .bin_attrs
                .get("dnsRecord")
                .or_else(|| e.bin_attrs.get("dnsrecord"))
                .cloned()
                .unwrap_or_default();

            let types = map.entry(fqdn).or_default();
            for r in raw {
                if let Some((rtype, _, _)) = ldap::parse_dns_record_binary(&r) {
                    if !types.contains(&rtype) {
                        types.push(rtype);
                    }
                }
            }
        }
    }

    Ok(map)
}

// ── case-insensitive attribute access ─────────────────────────────────────────
//
// Servers vary in the casing they echo back for requested attributes, so every
// read in this module goes through these rather than indexing `attrs` directly.

fn attr_ci(e: &SearchEntry, key: &str) -> String {
    let k = key.to_lowercase();
    e.attrs
        .iter()
        .find(|(name, _)| name.to_lowercase() == k)
        .and_then(|(_, v)| v.first())
        .cloned()
        .unwrap_or_default()
}

fn attrs_ci(e: &SearchEntry, key: &str) -> Vec<String> {
    let k = key.to_lowercase();
    e.attrs
        .iter()
        .find(|(name, _)| name.to_lowercase() == k)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn bin_ci(e: &SearchEntry, key: &str) -> Vec<Vec<u8>> {
    let k = key.to_lowercase();
    e.bin_attrs
        .iter()
        .find(|(name, _)| name.to_lowercase() == k)
        .map(|(_, v)| v.clone())
        .unwrap_or_default()
}

fn int_ci(e: &SearchEntry, key: &str) -> i64 {
    attr_ci(e, key).parse().unwrap_or(0)
}

// ── time ──────────────────────────────────────────────────────────────────────

/// Clock skew is the most common single cause of sudden Kerberos failure:
/// MIT/AD default `clockskew` is 300s, past which every ticket request fails.
async fn check_clock_skew(conn: &mut ldap3::Ldap) -> CheckResult {
    let c = CheckResult::new("clock_skew", "Time", "Clock skew");
    let entry = match read_one(conn, "", vec!["currentTime"]).await {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Could not read rootDSE: {}", e)),
    };
    let raw = attr_ci(&entry, "currentTime");
    let dc_time = match parse_generalized_time(&raw) {
        Some(t) => t,
        None => return c.skipped(format!("Unparseable currentTime: '{}'", raw)),
    };

    let skew = (dc_time - now_unix()).abs();
    let c = c.line(format!("DC clock is {}s from this host's clock", skew));
    if skew >= 300 {
        c.set(FAIL, format!("{}s skew — past the 300s Kerberos limit", skew))
            .fix("Sync both hosts to the same NTP source. Above 300s all Kerberos authentication fails.")
    } else if skew >= 60 {
        c.set(WARN, format!("{}s skew — drifting toward the 300s Kerberos limit", skew))
            .fix("Check NTP on the DC (Samba DCs should serve time to domain members).")
    } else {
        c.set(PASS, format!("{}s skew", skew))
    }
}

// ── functional levels ─────────────────────────────────────────────────────────

fn functional_level_name(level: i64) -> &'static str {
    match level {
        0 => "2000",
        1 => "2003 interim",
        2 => "2003",
        3 => "2008",
        4 => "2008 R2",
        5 => "2012",
        6 => "2012 R2",
        7 => "2016",
        _ => "unknown",
    }
}

async fn check_functional_levels(conn: &mut ldap3::Ldap) -> CheckResult {
    let c = CheckResult::new("functional_levels", "Domain", "Functional levels");
    let entry = match read_one(
        conn,
        "",
        vec![
            "domainFunctionality",
            "forestFunctionality",
            "domainControllerFunctionality",
        ],
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Could not read rootDSE: {}", e)),
    };

    let domain = int_ci(&entry, "domainFunctionality");
    let forest = int_ci(&entry, "forestFunctionality");
    let dc = int_ci(&entry, "domainControllerFunctionality");

    let c = c
        .line(format!("Domain: {} ({})", functional_level_name(domain), domain))
        .line(format!("Forest: {} ({})", functional_level_name(forest), forest))
        .line(format!("DC: {} ({})", functional_level_name(dc), dc));

    if domain < 4 || forest < 4 {
        c.set(
            WARN,
            format!(
                "Domain at {}, forest at {} — below 2008 R2",
                functional_level_name(domain),
                functional_level_name(forest)
            ),
        )
        .fix("Raising to 2008 R2 enables AES Kerberos and the Managed Service Account features Samba supports. Requires all DCs to support the target level.")
    } else {
        c.set(PASS, format!("Domain and forest at {} or better", functional_level_name(4)))
    }
}

// ── FSMO ──────────────────────────────────────────────────────────────────────

/// An FSMO role pointing at a DC that no longer exists is silent until the day
/// something needs that role — then RID allocation, schema changes or password
/// changes start failing with no obvious cause.
async fn check_fsmo(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("fsmo_roles", "Domain", "FSMO role holders");

    let roles = [
        ("Schema", format!("CN=Schema,{}", ctx.config_dn)),
        ("Domain Naming", format!("CN=Partitions,{}", ctx.config_dn)),
        ("PDC Emulator", ctx.base_dn.clone()),
        ("RID Master", format!("CN=RID Manager$,CN=System,{}", ctx.base_dn)),
        ("Infrastructure", format!("CN=Infrastructure,{}", ctx.base_dn)),
    ];

    let mut c = c;
    let mut broken = Vec::new();

    for (role, dn) in &roles {
        let owner = match read_one(conn, dn, vec!["fSMORoleOwner"]).await {
            Ok(e) => attr_ci(&e, "fSMORoleOwner"),
            Err(e) => {
                broken.push(role.to_string());
                c = c.line(format!("{}: could not read owner ({})", role, e));
                continue;
            }
        };

        if owner.is_empty() {
            broken.push(role.to_string());
            c = c.line(format!("{}: no owner set", role));
            continue;
        }

        // The owner is an NTDS Settings DN; the DC name is its parent RDN.
        let holder = dn_parts(&owner).get(1).cloned().unwrap_or_default();
        // Confirm the holder still exists rather than trusting the pointer.
        match read_one(conn, &owner, vec!["objectClass"]).await {
            Ok(_) => c = c.line(format!("{}: {}", role, holder)),
            Err(_) => {
                broken.push(role.to_string());
                c = c.line(format!("{}: {} — owner object does not exist", role, holder));
            }
        }
    }

    if broken.is_empty() {
        c.set(PASS, "All five roles held by live DCs")
    } else {
        c.set(
            FAIL,
            format!("{} unresolvable: {}", plural(broken.len(), "role", "roles"), broken.join(", ")),
        )
        .fix("Seizing an FSMO role is done with `samba-tool fsmo seize --role=<role>`, and only after confirming the old holder is permanently gone — seizing a role a live DC still holds splits the domain. EasyDC will not automate this.")
    }
}

// ── DC inventory ──────────────────────────────────────────────────────────────

async fn check_dc_inventory(ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("dc_inventory", "Domain", "Domain controllers");
    if ctx.dcs.is_empty() {
        return c
            .set(FAIL, "No domain controllers found in the Sites container")
            .fix("The configuration partition may be unreachable with the current bind account.");
    }

    let mut c = c;
    for dc in &ctx.dcs {
        let host = if dc.dns_host_name.is_empty() {
            "no dNSHostName".to_string()
        } else {
            dc.dns_host_name.clone()
        };
        c = c.line(format!("{} — site {}, {}", dc.name, dc.site, host));
    }

    let missing_host: Vec<&DcInfo> = ctx.dcs.iter().filter(|d| d.dns_host_name.is_empty()).collect();
    let count = ctx.dcs.len();

    if !missing_host.is_empty() {
        c.set(
            WARN,
            format!(
                "{} found, {} without a dNSHostName",
                plural(count, "DC", "DCs"),
                missing_host.len()
            ),
        )
        .fix("A DC with no dNSHostName cannot be located by clients through DNS.")
    } else if count == 1 {
        c.set(WARN, "Single domain controller — no redundancy")
            .fix("A second DC removes the single point of failure. `samba-tool domain join` handles the provisioning.")
    } else {
        let mut sites: Vec<&str> = ctx.dcs.iter().map(|d| d.site.as_str()).collect();
        sites.sort_unstable();
        sites.dedup();
        c.set(
            PASS,
            format!(
                "{} across {}",
                plural(count, "DC", "DCs"),
                plural(sites.len(), "site", "sites")
            ),
        )
    }
}

// ── DNS ───────────────────────────────────────────────────────────────────────

/// The SRV set below is what a domain member actually queries to find a DC. A
/// missing entry here presents as "cannot join the domain" or "no logon
/// servers available" long before anyone suspects DNS.
async fn check_dns_records(ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("dns_srv", "DNS", "Service location records");

    if let Some(err) = &ctx.dns_error {
        return c.skipped(format!("DNS zones unreadable: {}", err));
    }

    let d = &ctx.domain;
    // (name, record type, critical)
    let mut required: Vec<(String, &str, bool)> = vec![
        (format!("_ldap._tcp.{}", d), "SRV", true),
        (format!("_ldap._tcp.dc._msdcs.{}", d), "SRV", true),
        (format!("_kerberos._tcp.{}", d), "SRV", true),
        (format!("_kerberos._udp.{}", d), "SRV", true),
        (format!("_kerberos._tcp.dc._msdcs.{}", d), "SRV", false),
        (format!("_kpasswd._tcp.{}", d), "SRV", true),
        (format!("_kpasswd._udp.{}", d), "SRV", false),
        (format!("_gc._tcp.{}", d), "SRV", false),
        (format!("_ldap._tcp.gc._msdcs.{}", d), "SRV", false),
    ];
    for dc in &ctx.dcs {
        if !dc.dns_host_name.is_empty() {
            required.push((dc.dns_host_name.to_lowercase(), "A", true));
        }
        if !dc.guid.is_empty() {
            required.push((format!("{}._msdcs.{}", dc.guid, d), "CNAME", false));
        }
    }

    let mut missing_critical = Vec::new();
    let mut missing_optional = Vec::new();

    for (name, rtype, critical) in &required {
        let key = name.to_lowercase();
        let present = match ctx.dns.get(&key) {
            None => false,
            Some(types) => {
                if *rtype == "A" {
                    // A host answer of either family satisfies the lookup.
                    types.iter().any(|t| t == "A" || t == "AAAA")
                } else {
                    types.iter().any(|t| t == rtype)
                }
            }
        };
        if !present {
            if *critical {
                missing_critical.push(format!("{} ({})", name, rtype));
            } else {
                missing_optional.push(format!("{} ({})", name, rtype));
            }
        }
    }

    let mut c = c.line(format!(
        "Checked {} names against {} names present in AD-integrated DNS",
        required.len(),
        ctx.dns.len()
    ));
    for m in &missing_critical {
        c = c.line(format!("MISSING (critical): {}", m));
    }
    for m in &missing_optional {
        c = c.line(format!("missing: {}", m));
    }

    if !missing_critical.is_empty() {
        c.set(
            FAIL,
            format!("{} missing", plural(missing_critical.len(), "critical record", "critical records")),
        )
        .fix("Restart the `samba` service to have the DC re-register its records, or add them by hand under DNS Management. `samba_dnsupdate --verbose` on the DC shows exactly which updates fail.")
    } else if !missing_optional.is_empty() {
        c.set(
            WARN,
            format!("{} missing", plural(missing_optional.len(), "optional record", "optional records")),
        )
        .fix("Global-catalog and kpasswd records are only needed if you use those services, but their absence usually means dynamic registration is partly broken.")
    } else {
        c.set(PASS, "All expected SRV, host and GUID records present")
    }
}

// ── replication ───────────────────────────────────────────────────────────────

/// Presence-only for now. `repsFrom` is an NDR-encoded blob whose full decode
/// is a separate piece of work (the same class of problem as the `dnsRecord`
/// parsing in `ldap.rs`); until that lands, this reports whether replication is
/// configured at all, which still catches the common "second DC joined but
/// never replicated" case.
async fn check_replication(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("replication", "Replication", "Replication partners");

    if ctx.dcs.len() < 2 {
        return c.skipped("Single domain controller — nothing to replicate with");
    }

    let partitions = [
        ("Domain", ctx.base_dn.clone()),
        ("Configuration", ctx.config_dn.clone()),
        ("Schema", format!("CN=Schema,{}", ctx.config_dn)),
    ];

    let mut c = c;
    let mut unconfigured = Vec::new();

    for (label, dn) in &partitions {
        match read_one(conn, dn, vec!["repsFrom"]).await {
            Ok(e) => {
                let n = bin_ci(&e, "repsFrom").len().max(attrs_ci(&e, "repsFrom").len());
                if n == 0 {
                    unconfigured.push(label.to_string());
                    c = c.line(format!("{}: no inbound replication partners", label));
                } else {
                    c = c.line(format!("{}: {}", label, plural(n, "inbound partner", "inbound partners")));
                }
            }
            Err(e) => {
                c = c.line(format!("{}: could not read repsFrom ({})", label, e));
            }
        }
    }

    c = c.line("Note: partner health and last-success times are not yet decoded — run `samba-tool drs showrepl` for those.");

    if unconfigured.is_empty() {
        c.set(PASS, "All three partitions have inbound replication partners")
    } else {
        c.set(
            FAIL,
            format!("No inbound replication for: {}", unconfigured.join(", ")),
        )
        .fix("Check `samba-tool drs showrepl` on each DC. A partition with no partners will silently diverge.")
    }
}

// ── LDAPS ─────────────────────────────────────────────────────────────────────

/// Blocking TLS probe, run off the async runtime. Certificate *trust* is
/// deliberately not verified — self-signed is normal for Samba and the point
/// of this check is reachability and expiry, not chain validation.
fn probe_ldaps(host: String) -> Result<(String, i32), String> {
    use openssl::asn1::Asn1Time;
    use openssl::ssl::{SslConnector, SslMethod, SslVerifyMode};
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Duration;

    let addr = format!("{}:636", host)
        .to_socket_addrs()
        .map_err(|e| format!("could not resolve {}: {}", host, e))?
        .next()
        .ok_or_else(|| format!("no address for {}", host))?;

    let stream = TcpStream::connect_timeout(&addr, Duration::from_secs(5))
        .map_err(|e| format!("port 636 unreachable: {}", e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

    let mut builder = SslConnector::builder(SslMethod::tls()).map_err(|e| e.to_string())?;
    builder.set_verify(SslVerifyMode::NONE);
    let connector = builder.build();
    let cfg = connector.configure().map_err(|e| e.to_string())?;

    let ssl = cfg
        .connect(&host, stream)
        .map_err(|e| format!("TLS handshake failed: {}", e))?;
    let cert = ssl
        .ssl()
        .peer_certificate()
        .ok_or_else(|| "server presented no certificate".to_string())?;

    let not_after = cert.not_after();
    let now = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    let days = now.diff(not_after).map_err(|e| e.to_string())?.days;

    Ok((not_after.to_string(), days))
}

async fn check_ldaps(server: &Server) -> CheckResult {
    let c = CheckResult::new("ldaps", "Security", "LDAPS availability and certificate");

    let host = match host_of(&server.ldap_url) {
        Some(h) => h,
        None => return c.skipped(format!("Could not parse a host from '{}'", server.ldap_url)),
    };

    let probe = tokio::task::spawn_blocking({
        let host = host.clone();
        move || probe_ldaps(host)
    })
    .await;

    let (not_after, days) = match probe {
        Err(e) => return c.skipped(format!("Probe did not run: {}", e)),
        Ok(Err(e)) => {
            return c
                .set(FAIL, format!("LDAPS not available on {}: {}", host, e))
                .line("Password resets and any other unicodePwd write require LDAPS.")
                .fix("Samba serves LDAPS on 636 using the certificate in `/var/lib/samba/private/tls/`. Check the service is listening and the firewall allows 636.")
        }
        Ok(Ok(v)) => v,
    };

    let c = c
        .line(format!("Certificate expires {}", not_after))
        .line(format!("{} days remaining", days));

    if days <= 0 {
        c.set(FAIL, "Certificate has expired")
            .fix("Replace the certificate in `/var/lib/samba/private/tls/` and restart samba. Clients will refuse LDAPS until then.")
    } else if days <= 30 {
        c.set(WARN, format!("Certificate expires in {} days", days))
            .fix("Renew before expiry — password resets stop working the moment LDAPS fails.")
    } else {
        c.set(PASS, format!("LDAPS reachable, certificate valid for {} days", days))
    }
}

// ── security posture ──────────────────────────────────────────────────────────

/// The default of 10 lets any authenticated user join ten machines to the
/// domain, which is a well-worn path in privilege-escalation write-ups.
async fn check_machine_account_quota(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("machine_account_quota", "Security", "Machine account quota");

    let entry = match read_one(conn, &ctx.base_dn, vec!["ms-DS-MachineAccountQuota"]).await {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Could not read domain object: {}", e)),
    };

    let raw = attr_ci(&entry, "ms-DS-MachineAccountQuota");
    if raw.is_empty() {
        return c.skipped("Attribute not set on this domain");
    }
    let quota: i64 = raw.parse().unwrap_or(-1);
    let c = c.line(format!("ms-DS-MachineAccountQuota = {}", quota));

    if quota > 0 {
        c.set(WARN, format!("Any authenticated user can join {} machines", quota))
            .fix("Set ms-DS-MachineAccountQuota to 0 and delegate machine joins to a specific group instead.")
    } else {
        c.set(PASS, "Unprivileged users cannot join machines")
    }
}

/// The seventh character of dSHeuristics controls anonymous LDAP operations.
async fn check_anonymous_bind(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("anonymous_bind", "Security", "Anonymous LDAP access");

    let dn = format!(
        "CN=Directory Service,CN=Windows NT,CN=Services,{}",
        ctx.config_dn
    );
    let entry = match read_one(conn, &dn, vec!["dSHeuristics"]).await {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Could not read Directory Service object: {}", e)),
    };

    let h = attr_ci(&entry, "dSHeuristics");
    if h.is_empty() {
        return c
            .set(PASS, "Anonymous LDAP operations disabled (dSHeuristics unset)")
            .line("An unset dSHeuristics means the default, which denies anonymous operations.");
    }

    let c = c.line(format!("dSHeuristics = {}", h));
    if h.chars().nth(6) == Some('2') {
        c.set(WARN, "Anonymous LDAP operations are enabled")
            .fix("Clear the 7th character of dSHeuristics unless an application genuinely requires anonymous binds.")
    } else {
        c.set(PASS, "Anonymous LDAP operations disabled")
    }
}

/// Accounts trusted for unconstrained delegation can impersonate any user who
/// authenticates to them. Domain controllers hold this legitimately; nothing
/// else should without a deliberate reason.
async fn check_delegation(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("delegation", "Security", "Unconstrained delegation");

    let entries = match search(
        conn,
        &ctx.base_dn,
        Scope::Subtree,
        "(userAccountControl:1.2.840.113556.1.4.803:=524288)",
        vec!["sAMAccountName", "primaryGroupID"],
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Search failed: {}", e)),
    };

    // primaryGroupID 516 is Domain Controllers — expected to hold this flag.
    let flagged: Vec<String> = entries
        .iter()
        .filter(|e| int_ci(e, "primaryGroupID") != 516)
        .map(|e| attr_ci(e, "sAMAccountName"))
        .filter(|n| !n.is_empty())
        .collect();

    let dc_count = entries.iter().filter(|e| int_ci(e, "primaryGroupID") == 516).count();
    let mut c = c.line(format!(
        "{} hold the flag legitimately",
        plural(dc_count, "domain controller", "domain controllers")
    ));
    for f in &flagged {
        c = c.line(format!("Unconstrained: {}", f));
    }

    if flagged.is_empty() {
        c.set(PASS, "Only domain controllers are trusted for delegation")
    } else {
        c.set(
            WARN,
            format!("{} outside the DCs", plural(flagged.len(), "account", "accounts")),
        )
        .fix("Replace unconstrained delegation with constrained delegation (msDS-AllowedToDelegateTo), or clear the flag if it is not needed.")
    }
}

async fn check_privileged_groups(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("privileged_groups", "Security", "Privileged group membership");

    let groups = ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"];
    let mut c = c;
    let mut total = 0usize;
    let mut disabled_members = Vec::new();

    for g in &groups {
        let filter = format!("(&(objectClass=group)(sAMAccountName={}))", g);
        let found = match search(conn, &ctx.base_dn, Scope::Subtree, &filter, vec!["member"]).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        let Some(entry) = found.into_iter().next() else {
            continue;
        };

        let members = attrs_ci(&entry, "member");
        total += members.len();
        c = c.line(format!("{}: {}", g, plural(members.len(), "member", "members")));

        // These groups are small by nature, so a per-member read is cheap and
        // catches the disabled-but-still-privileged case.
        for m in &members {
            if let Ok(me) = read_one(conn, m, vec!["userAccountControl", "sAMAccountName"]).await {
                let uac = int_ci(&me, "userAccountControl");
                if (uac & 2) != 0 {
                    let name = attr_ci(&me, "sAMAccountName");
                    let label = format!("{} (in {})", if name.is_empty() { rdn_value(m) } else { name }, g);
                    if !disabled_members.contains(&label) {
                        disabled_members.push(label);
                    }
                }
            }
        }
    }

    for d in &disabled_members {
        c = c.line(format!("Disabled but still privileged: {}", d));
    }

    if !disabled_members.is_empty() {
        c.set(
            WARN,
            format!(
                "{} disabled but still in a privileged group",
                plural(disabled_members.len(), "account", "accounts")
            ),
        )
        .fix("A disabled account in Domain Admins is a re-enable away from full control. Remove the membership rather than relying on the disabled flag.")
    } else if total == 0 {
        c.skipped("No privileged groups readable with this bind account")
    } else {
        c.set(PASS, format!("{} across the four privileged groups, all enabled", plural(total, "member", "members")))
    }
}

// ── hygiene ───────────────────────────────────────────────────────────────────

const STALE_DAYS: i64 = 90;

async fn check_stale_computers(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("stale_computers", "Hygiene", "Stale computer accounts");

    let entries = match search(
        conn,
        &ctx.base_dn,
        Scope::Subtree,
        "(objectClass=computer)",
        vec!["sAMAccountName", "lastLogonTimestamp", "userAccountControl"],
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Search failed: {}", e)),
    };

    let cutoff = now_unix() - STALE_DAYS * 86_400;
    let mut stale: Vec<(String, i64)> = Vec::new();
    let mut total = 0usize;

    for e in &entries {
        let uac = int_ci(e, "userAccountControl");
        if (uac & 2) != 0 {
            continue; // already disabled
        }
        total += 1;
        let ts = int_ci(e, "lastLogonTimestamp");
        if ts == 0 {
            continue; // never replicated a logon time; not evidence of staleness
        }
        let last = filetime_to_unix(ts);
        if last < cutoff {
            let days = (now_unix() - last) / 86_400;
            stale.push((attr_ci(e, "sAMAccountName"), days));
        }
    }

    stale.sort_by(|a, b| b.1.cmp(&a.1));
    let mut c = c.line(format!("{} enabled computer accounts", total));
    for (name, days) in stale.iter().take(15) {
        c = c.line(format!("{} — last logon {} days ago", name, days));
    }
    if stale.len() > 15 {
        c = c.line(format!("… and {} more", stale.len() - 15));
    }

    if stale.is_empty() {
        c.set(PASS, format!("No computer inactive for over {} days", STALE_DAYS))
    } else {
        c.set(
            WARN,
            format!(
                "{} inactive for over {} days",
                plural(stale.len(), "computer", "computers"),
                STALE_DAYS
            ),
        )
        .fix("Disable rather than delete first — a deleted computer account cannot be un-joined cleanly if the machine comes back.")
    }
}

async fn check_password_hygiene(conn: &mut ldap3::Ldap, ctx: &Ctx) -> CheckResult {
    let c = CheckResult::new("password_hygiene", "Hygiene", "Account password flags");

    let entries = match search(
        conn,
        &ctx.base_dn,
        Scope::Subtree,
        "(&(objectClass=user)(!(objectClass=computer)))",
        vec!["sAMAccountName", "userAccountControl", "pwdLastSet"],
    )
    .await
    {
        Ok(e) => e,
        Err(e) => return c.skipped(format!("Search failed: {}", e)),
    };

    const DONT_EXPIRE_PASSWORD: i64 = 0x10000;
    const PASSWD_NOTREQD: i64 = 0x0020;

    let mut never_expires = Vec::new();
    let mut not_required = Vec::new();
    let mut must_change = 0usize;
    let mut enabled = 0usize;

    for e in &entries {
        let uac = int_ci(e, "userAccountControl");
        if (uac & 2) != 0 {
            continue;
        }
        enabled += 1;
        let name = attr_ci(e, "sAMAccountName");
        if (uac & DONT_EXPIRE_PASSWORD) != 0 {
            never_expires.push(name.clone());
        }
        if (uac & PASSWD_NOTREQD) != 0 {
            not_required.push(name.clone());
        }
        if int_ci(e, "pwdLastSet") == 0 {
            must_change += 1;
        }
    }

    let mut c = c.line(format!("{} enabled user accounts", enabled));
    if !never_expires.is_empty() {
        c = c.line(format!("Password never expires: {}", never_expires.join(", ")));
    }
    if !not_required.is_empty() {
        c = c.line(format!("Password not required: {}", not_required.join(", ")));
    }
    if must_change > 0 {
        c = c.line(format!("{} must change password at next logon", must_change));
    }

    if !not_required.is_empty() {
        c.set(
            FAIL,
            format!("{} can have an empty password", plural(not_required.len(), "account", "accounts")),
        )
        .fix("Clear the PASSWD_NOTREQD flag (0x0020) on these accounts and set a real password.")
    } else if !never_expires.is_empty() {
        c.set(
            WARN,
            format!("{} with non-expiring passwords", plural(never_expires.len(), "account", "accounts")),
        )
        .fix("Service accounts are the usual reason. Confirm each is intentional and rotate them on a schedule.")
    } else {
        c.set(PASS, "No accounts with weak password flags")
    }
}

// ── driver ────────────────────────────────────────────────────────────────────

/// Run the full battery against one server. Errors reaching the directory at
/// all are returned as `Err`; anything narrower shows up as a skipped check.
pub async fn run(server: &Server) -> LdapResult<HealthReport> {
    let started = std::time::Instant::now();
    let (mut conn, base_dn) = ldap::open(server).await?;

    let config_dn = match read_one(&mut conn, "", vec!["configurationNamingContext"]).await {
        Ok(e) => {
            let v = attr_ci(&e, "configurationNamingContext");
            if v.is_empty() {
                format!("CN=Configuration,{}", base_dn)
            } else {
                v
            }
        }
        Err(_) => format!("CN=Configuration,{}", base_dn),
    };

    let dcs = load_dcs(&mut conn, &config_dn).await.unwrap_or_default();
    let (dns, dns_error) = match load_dns(&mut conn, &base_dn).await {
        Ok(m) => (m, None),
        Err(e) => (HashMap::new(), Some(e)),
    };

    let ctx = Ctx {
        domain: base_dn_to_domain(&base_dn),
        base_dn: base_dn.clone(),
        config_dn,
        dcs,
        dns,
        dns_error,
    };

    let checks = vec![
        check_clock_skew(&mut conn).await,
        check_dc_inventory(&ctx).await,
        check_fsmo(&mut conn, &ctx).await,
        check_replication(&mut conn, &ctx).await,
        check_dns_records(&ctx).await,
        check_functional_levels(&mut conn).await,
        check_ldaps(server).await,
        check_machine_account_quota(&mut conn, &ctx).await,
        check_anonymous_bind(&mut conn, &ctx).await,
        check_delegation(&mut conn, &ctx).await,
        check_privileged_groups(&mut conn, &ctx).await,
        check_stale_computers(&mut conn, &ctx).await,
        check_password_hygiene(&mut conn, &ctx).await,
    ];

    Ok(HealthReport {
        domain: ctx.domain,
        base_dn,
        checks,
        pass_count: 0,
        warn_count: 0,
        fail_count: 0,
        skip_count: 0,
        elapsed_ms: started.elapsed().as_millis(),
    }
    .tally())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generalized_time_parses_to_unix() {
        // 2026-08-18T10:30:00Z
        assert_eq!(parse_generalized_time("20260818103000.0Z"), Some(1_787_049_000));
        // Trailing fraction and zone are optional.
        assert_eq!(
            parse_generalized_time("20260818103000"),
            parse_generalized_time("20260818103000.0Z")
        );
    }

    #[test]
    fn generalized_time_rejects_short_input() {
        assert_eq!(parse_generalized_time("2026"), None);
        assert_eq!(parse_generalized_time(""), None);
    }

    #[test]
    fn epoch_round_numbers() {
        assert_eq!(days_from_civil(1970, 1, 1), 0);
        assert_eq!(days_from_civil(2000, 3, 1), 11017);
    }

    #[test]
    fn filetime_epoch_matches_unix_epoch() {
        // 1970-01-01 in FILETIME ticks.
        assert_eq!(filetime_to_unix(116_444_736_000_000_000), 0);
    }

    #[test]
    fn guid_first_three_fields_are_little_endian() {
        let bytes: Vec<u8> = vec![
            0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0x78, 0x56, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22,
            0x33, 0x44,
        ];
        assert_eq!(
            format_guid(&bytes),
            "12345678-1234-5678-9abc-def011223344"
        );
    }

    #[test]
    fn guid_rejects_wrong_length() {
        assert_eq!(format_guid(&[0u8; 8]), "");
    }

    #[test]
    fn dn_parts_yields_rdn_values() {
        let dn = "CN=NTDS Settings,CN=DC1,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com";
        let parts = dn_parts(dn);
        assert_eq!(parts[1], "DC1");
        assert_eq!(parts[3], "Default-First-Site-Name");
    }

    #[test]
    fn host_parsing_handles_schemes_and_ports() {
        assert_eq!(host_of("ldap://192.168.1.10").as_deref(), Some("192.168.1.10"));
        assert_eq!(host_of("ldaps://dc.example.com:636").as_deref(), Some("dc.example.com"));
        assert_eq!(host_of("ldap://[2001:db8::1]:389").as_deref(), Some("2001:db8::1"));
        assert_eq!(host_of("dc.example.com").as_deref(), Some("dc.example.com"));
        assert_eq!(host_of("ldap://"), None);
    }
}
