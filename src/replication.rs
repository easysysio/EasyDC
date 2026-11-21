//! Replication status: for each DC, the partners it pulls each partition from,
//! when that last worked, and why it failed if it did — what
//! `samba-tool drs showrepl` prints, read over LDAP instead of RPC.
//!
//! The source is `repsFrom` on each naming context's head object: one
//! NDR-encoded `repsFromToBlob` per inbound partner (MS-DRSR 5.177, Samba's
//! drsblobs.idl). Each DC keeps its own, so EasyDC connects to every DC with
//! the configured account.

use std::time::Duration;

use ldap3::{Scope, SearchEntry};
use serde::Serialize;

use crate::health::{self, DcInfo};
use crate::ldap::{self, LdapResult};
use crate::models::Server;

/// Samba replicates every 5 minutes by default (`dreplsrv:periodic_interval`),
/// even when nothing changed, so an hour without success is already unusual.
const WARN_AFTER_SECS: i64 = 3_600;
const FAIL_AFTER_SECS: i64 = 86_400;
/// Seconds between 1601-01-01 and 1970-01-01.
const EPOCH_1601: i64 = 11_644_473_600;

const DRS_DISABLE_AUTO_SYNC: u32 = 0x2000_0000;
const DRS_DISABLE_PERIODIC_SYNC: u32 = 0x4000_0000;

/// One inbound partner, as stored.
#[derive(Debug, Clone, PartialEq)]
pub struct RepsFrom {
    pub failures: u32,
    /// Unix seconds; None when it never happened.
    pub last_success: Option<i64>,
    pub last_attempt: Option<i64>,
    /// The Windows error of the last attempt; 0 is success.
    pub result: u32,
    pub flags: u32,
    /// objectGUID of the partner's NTDS Settings object.
    pub source_guid: String,
    /// `<guid>._msdcs.<forest>`, the partner's replication DNS name.
    pub source_dns: String,
}

/// Decode a repsFromToBlob, version 1 (what Samba writes). The layout:
/// version and a reserved word, then repsFromTo1 — blob size, consecutive
/// failures, last success and last attempt (seconds since 1601), the last
/// result, a pointer to the partner's DNS name (from the start of the blob),
/// its length, the replica flags, an 84-byte schedule, a reserved word, the
/// high-water mark (3 × 8 bytes), and three GUIDs: the partner's NTDS
/// Settings object, its invocation ID, and the transport.
pub fn decode_reps_from(b: &[u8]) -> Result<RepsFrom, String> {
    let u32_at = |o: usize| b.get(o..o + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]));
    let u64_at = |o: usize| {
        b.get(o..o + 8).map(|s| {
            let mut a = [0u8; 8];
            a.copy_from_slice(s);
            u64::from_le_bytes(a)
        })
    };
    let short = || format!("record too short ({} bytes)", b.len());

    let version = u32_at(0).ok_or_else(short)?;
    if version != 1 {
        return Err(format!("record format version {version} is not decoded"));
    }
    const BASE: usize = 8;
    if b.len() < BASE + 200 {
        return Err(short());
    }
    let time = |o: usize| -> Option<i64> {
        let secs = u64_at(o)? as i64;
        (secs > 0).then_some(secs - EPOCH_1601)
    };
    let ptr = u32_at(BASE + 28).ok_or_else(short)? as usize;
    let source_dns = match u32_at(ptr) {
        Some(n) if ptr >= BASE + 200 => b
            .get(ptr + 4..ptr + 4 + n as usize)
            .map(|s| String::from_utf8_lossy(s).trim_end_matches('\0').to_string())
            .unwrap_or_default(),
        _ => String::new(),
    };

    Ok(RepsFrom {
        failures: u32_at(BASE + 4).ok_or_else(short)?,
        last_success: time(BASE + 8),
        last_attempt: time(BASE + 16),
        result: u32_at(BASE + 24).ok_or_else(short)?,
        flags: u32_at(BASE + 36).ok_or_else(short)?,
        source_guid: health::format_guid(&b[BASE + 152..BASE + 168]),
        source_dns,
    })
}

/// The Windows errors replication reports most, in words. The code is shown
/// alongside, for searching.
pub fn error_text(code: u32) -> &'static str {
    match code {
        0 => "success",
        5 => "access denied",
        1256 => "the remote system is not available",
        1396 => "the target account name is incorrect (a Kerberos/SPN problem)",
        1722 => "the RPC server is unavailable: the partner is down, or a firewall blocks it",
        1753 => "no endpoint is listening on the partner",
        1908 => "the domain controller could not be found",
        8333 => "a directory object was not found",
        8418 => "the schemas do not match",
        8451 => "the partner reported a database error",
        8453 => "replication access was denied",
        8456 => "the partner is refusing replication requests",
        8457 => "this DC is refusing replication requests",
        8524 => "the partner's name could not be found in DNS",
        8606 => "an object could not be created: lingering objects",
        8614 => "the partner has not replicated for longer than the tombstone lifetime",
        _ => "",
    }
}

fn describe_error(code: u32) -> String {
    match error_text(code) {
        "" => format!("Windows error {code} (0x{code:X})"),
        t => format!("{t} (error {code})"),
    }
}

/// ok, warn or fail, and why.
pub fn assess(r: &RepsFrom, now: i64) -> (&'static str, String) {
    if r.failures > 0 {
        let since = r
            .last_success
            .map(|t| format!("; last success {}", ago(now - t)))
            .unwrap_or_else(|| "; it has never succeeded".to_string());
        return (
            "fail",
            format!(
                "{} failed {} in a row: {}{}",
                r.failures,
                if r.failures == 1 { "attempt" } else { "attempts" },
                describe_error(r.result),
                since
            ),
        );
    }
    let Some(last) = r.last_success else {
        // No failure, no error and no success: a new link that has not run yet.
        if r.result == 0 {
            return ("warn", "Not run yet. Samba runs a new link within a few minutes".to_string());
        }
        return ("fail", "Never replicated successfully".to_string());
    };
    let age = now - last;
    if age > FAIL_AFTER_SECS {
        return ("fail", format!("No successful replication for {}", span(age)));
    }
    if r.flags & (DRS_DISABLE_AUTO_SYNC | DRS_DISABLE_PERIODIC_SYNC) != 0 {
        return ("warn", "Automatic replication is disabled for this link".to_string());
    }
    if age > WARN_AFTER_SECS {
        return ("warn", format!("No successful replication for {}; Samba normally replicates every 5 minutes", span(age)));
    }
    if r.result != 0 {
        return ("warn", format!("The last attempt reported {}", describe_error(r.result)));
    }
    ("ok", String::new())
}

fn span(secs: i64) -> String {
    let secs = secs.max(0);
    match secs {
        0..=89 => format!("{secs} s"),
        90..=5_399 => format!("{} min", (secs + 30) / 60),
        5_400..=172_799 => format!("{} h", (secs + 1_800) / 3_600),
        _ => format!("{} days", secs / 86_400),
    }
}

fn ago(secs: i64) -> String {
    if secs < 10 { "just now".to_string() } else { format!("{} ago", span(secs)) }
}

fn utc(unix: i64) -> String {
    let (y, m, d) = health::civil_from_days(unix.div_euclid(86_400));
    let s = unix.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", s / 3600, s % 3600 / 60)
}

// ── the report ────────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct Link {
    pub partition: String,
    /// The partner's name, or its GUID when it is not a known DC (a demoted
    /// DC whose links were never cleaned up).
    pub source: String,
    pub last_success: String,
    pub ago: String,
    pub status: &'static str,
    pub note: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct DcStatus {
    pub name: String,
    pub host: String,
    pub site: String,
    /// The DC EasyDC's server entry points at.
    pub configured: bool,
    /// Why this DC could not be read; its links are then unknown.
    pub error: Option<String>,
    pub links: Vec<Link>,
}

#[derive(Debug, Serialize, Default)]
pub struct Report {
    pub dcs: Vec<DcStatus>,
    pub ok: usize,
    pub warn: usize,
    pub fail: usize,
    /// DCs that could not be read.
    pub unreachable: usize,
    /// DCs that were read but receive from no one.
    pub isolated: usize,
}

impl Report {
    pub(crate) fn tally(mut self) -> Self {
        let links = || self.dcs.iter().flat_map(|d| d.links.iter());
        self.ok = links().filter(|l| l.status == "ok").count();
        self.warn = links().filter(|l| l.status == "warn").count();
        self.fail = links().filter(|l| l.status == "fail").count();
        self.unreachable = self.dcs.iter().filter(|d| d.error.is_some()).count();
        self.isolated = self.dcs.iter().filter(|d| d.error.is_none() && d.links.is_empty()).count();
        self
    }
}

/// `ldaps://dc1.example.com:636` with another host: `ldaps://dc2.example.com:636`.
pub fn url_for_host(url: &str, host: &str) -> Option<String> {
    let (scheme, rest) = url.split_once("://")?;
    let authority = rest.split('/').next()?;
    let port = if let Some(i) = authority.rfind("]:") {
        Some(&authority[i + 2..])
    } else if authority.starts_with('[') {
        None
    } else {
        authority.rsplit_once(':').map(|(_, p)| p)
    };
    Some(match port.filter(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_digit())) {
        Some(p) => format!("{scheme}://{host}:{p}"),
        None => format!("{scheme}://{host}"),
    })
}

fn partition_label(nc: &str, base_dn: &str, config_dn: &str) -> String {
    let lc = nc.to_lowercase();
    if lc == base_dn.to_lowercase() {
        "Domain".to_string()
    } else if lc == config_dn.to_lowercase() {
        "Configuration".to_string()
    } else if lc == format!("cn=schema,{config_dn}").to_lowercase() {
        "Schema".to_string()
    } else if lc.starts_with("dc=domaindnszones,") {
        "DomainDnsZones".to_string()
    } else if lc.starts_with("dc=forestdnszones,") {
        "ForestDnsZones".to_string()
    } else {
        nc.to_string()
    }
}

/// Every value of an attribute, as bytes. A binary value only lands in
/// `bin_attrs` when it is not valid UTF-8, so both maps are read.
fn values(e: &SearchEntry, key: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    for (k, v) in &e.bin_attrs {
        if k.eq_ignore_ascii_case(key) {
            out.extend(v.iter().cloned());
        }
    }
    for (k, v) in &e.attrs {
        if k.eq_ignore_ascii_case(key) {
            out.extend(v.iter().map(|s| s.as_bytes().to_vec()));
        }
    }
    out
}

/// The inbound links of the DC behind `conn`, one per partition and partner.
async fn read_links(
    conn: &mut ldap3::Ldap,
    base_dn: &str,
    config_dn: &str,
    dcs: &[DcInfo],
    now: i64,
) -> LdapResult<Vec<Link>> {
    let root = health::read_one(conn, "", vec!["namingContexts"]).await?;
    let mut ncs = health::attrs_ci(&root, "namingContexts");
    let order = |nc: &String| match partition_label(nc, base_dn, config_dn).as_str() {
        "Domain" => 0,
        "Configuration" => 1,
        "Schema" => 2,
        "DomainDnsZones" => 3,
        "ForestDnsZones" => 4,
        _ => 5,
    };
    ncs.sort_by_key(order);

    let mut links = Vec::new();
    for nc in ncs {
        let entry = health::search(conn, &nc, Scope::Base, "(objectClass=*)", vec!["repsFrom"]).await?;
        let Some(e) = entry.into_iter().next() else { continue };
        for blob in values(&e, "repsFrom") {
            let partition = partition_label(&nc, base_dn, config_dn);
            match decode_reps_from(&blob) {
                Ok(r) => {
                    let source = dcs
                        .iter()
                        .find(|d| d.guid.eq_ignore_ascii_case(&r.source_guid))
                        .map(|d| d.name.clone())
                        .unwrap_or_else(|| format!("unknown DC {}", r.source_guid));
                    let (status, note) = assess(&r, now);
                    links.push(Link {
                        partition,
                        source,
                        last_success: r.last_success.map(utc).unwrap_or_else(|| "never".to_string()),
                        ago: r.last_success.map(|t| ago(now - t)).unwrap_or_default(),
                        status,
                        note,
                    });
                }
                Err(err) => links.push(Link {
                    partition,
                    source: "?".to_string(),
                    last_success: String::new(),
                    ago: String::new(),
                    status: "warn",
                    note: format!("Could not decode this link: {err}"),
                }),
            }
        }
    }
    Ok(links)
}

/// The whole domain: every DC's inbound links. `conn` is the configured
/// server's connection, reused for that DC; the others are reached by their
/// dNSHostName with the same account.
pub async fn collect(
    server: &Server,
    conn: &mut ldap3::Ldap,
    base_dn: &str,
    config_dn: &str,
    dcs: &[DcInfo],
) -> Report {
    let now = health::now_unix();
    // Which DC the configured connection is on: its rootDSE names its own
    // NTDS Settings object.
    let here = health::read_one(conn, "", vec!["dsServiceName"])
        .await
        .map(|e| health::attr_ci(&e, "dsServiceName").to_lowercase())
        .unwrap_or_default();

    let mut out = Vec::new();
    for dc in dcs {
        let configured = !here.is_empty()
            && here.starts_with(&format!("cn=ntds settings,cn={},", dc.name.to_lowercase()));
        let links = if configured {
            read_links(conn, base_dn, config_dn, dcs, now).await
        } else if dc.dns_host_name.is_empty() {
            Err("it has no dNSHostName, so EasyDC cannot reach it".to_string())
        } else {
            match url_for_host(&server.ldap_url, &dc.dns_host_name) {
                None => Err(format!("cannot build a URL for it from {}", server.ldap_url)),
                Some(url) => match ldap::connect_url(server, &url, Some(Duration::from_secs(5))).await {
                    Err(e) => Err(format!("{url}: {e}")),
                    Ok(mut other) => {
                        let r = read_links(&mut other, base_dn, config_dn, dcs, now).await;
                        let _ = other.unbind().await;
                        r
                    }
                },
            }
        };
        let (links, error) = match links {
            Ok(l) => (l, None),
            Err(e) => (Vec::new(), Some(e)),
        };
        out.push(DcStatus {
            name: dc.name.clone(),
            host: dc.dns_host_name.clone(),
            site: dc.site.clone(),
            configured,
            error,
            links,
        });
    }
    Report { dcs: out, ..Default::default() }.tally()
}

/// The report for a server: connect, find the DCs, collect.
pub async fn report(server: &Server) -> LdapResult<Report> {
    let (mut conn, base_dn) = ldap::open(server).await?;
    let config_dn = health::read_one(&mut conn, "", vec!["configurationNamingContext"])
        .await
        .map(|e| health::attr_ci(&e, "configurationNamingContext"))
        .ok()
        .filter(|c| !c.is_empty())
        .unwrap_or_else(|| format!("CN=Configuration,{base_dn}"));
    let dcs = health::load_dcs(&mut conn, &config_dn).await?;
    Ok(collect(server, &mut conn, &base_dn, &config_dn, &dcs).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// DC1's inbound link for the domain partition, exactly as a live Samba DC
    /// returned it: partner DC2 (NTDS objectGUID 710661ee-…), last success
    /// 2026-11-16 08:56:20 UTC, no failures, schedule all 0x11.
    const DC1_DOMAIN_LINK: &str = "01000000000000000d0100000000000034560b210300000034560b210300000000000000d00000003d000000740000001111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111110000000047fe000000000000000000000000000047fe000000000000ee6106717eda194ebac27a4e4a411826d822db8f88341b4093f793af88a11532000000000000000000000000000000003900000037313036363165652d646137652d346531392d626163322d3761346534613431313832362e5f6d736463732e68616b696d2e66616d696c7900";

    fn dc1_domain_link() -> Vec<u8> {
        crate::ldap::from_hex(DC1_DOMAIN_LINK).unwrap()
    }

    #[test]
    fn decodes_a_live_record() {
        let r = decode_reps_from(&dc1_domain_link()).unwrap();
        assert_eq!(r.failures, 0);
        assert_eq!(r.result, 0);
        assert_eq!(r.source_guid, "710661ee-da7e-4e19-bac2-7a4e4a411826");
        assert_eq!(r.source_dns, "710661ee-da7e-4e19-bac2-7a4e4a411826._msdcs.hakim.family");
        assert_eq!(r.last_success, Some(1_794_819_380)); // 2026-11-16 08:56:20 UTC
        assert_eq!(r.last_success.map(utc).as_deref(), Some("2026-11-16 08:56 UTC"));
        assert_eq!(r.flags, 0x74);
    }

    #[test]
    fn short_or_unknown_records_are_refused() {
        assert!(decode_reps_from(&[]).is_err());
        assert!(decode_reps_from(&[1, 0, 0, 0, 0, 0, 0, 0, 1, 2]).is_err());
        let mut v2 = dc1_domain_link();
        v2[0] = 2;
        assert!(decode_reps_from(&v2).unwrap_err().contains("version 2"));
        // A pointer into the fixed part or past the end gives no name, not a panic.
        let mut bad = dc1_domain_link();
        bad[36..40].copy_from_slice(&5000u32.to_le_bytes());
        assert_eq!(decode_reps_from(&bad).unwrap().source_dns, "");
        bad[36..40].copy_from_slice(&12u32.to_le_bytes());
        assert_eq!(decode_reps_from(&bad).unwrap().source_dns, "");
    }

    fn link(failures: u32, result: u32, age: Option<i64>, flags: u32) -> (RepsFrom, i64) {
        let now = 1_800_000_000;
        (
            RepsFrom {
                failures,
                last_success: age.map(|a| now - a),
                last_attempt: Some(now - 10),
                result,
                flags,
                source_guid: String::new(),
                source_dns: String::new(),
            },
            now,
        )
    }

    #[test]
    fn assessment() {
        let (r, now) = link(0, 0, Some(120), 0x74);
        assert_eq!(assess(&r, now), ("ok", String::new()));

        let (r, now) = link(3, 1722, Some(7_200), 0);
        let (status, note) = assess(&r, now);
        assert_eq!(status, "fail");
        assert!(note.starts_with("3 failed attempts in a row: the RPC server is unavailable"), "{note}");
        assert!(note.contains("last success 2 h ago"), "{note}");

        // A link the KCC has just added, as testdc showed it after testdc2 joined.
        let (r, now) = link(0, 0, None, 0);
        assert_eq!(assess(&r, now), ("warn", "Not run yet. Samba runs a new link within a few minutes".to_string()));
        let (r, now) = link(0, 8524, None, 0);
        assert_eq!(assess(&r, now).0, "fail");
        let (r, now) = link(0, 0, Some(2 * 86_400), 0);
        assert!(assess(&r, now).1.contains("2 days"));
        let (r, now) = link(0, 0, Some(2 * 3_600), 0);
        assert_eq!(assess(&r, now).0, "warn");
        let (r, now) = link(0, 0, Some(60), DRS_DISABLE_PERIODIC_SYNC);
        assert!(assess(&r, now).1.contains("disabled"));
        let (r, now) = link(1, 99_999, Some(60), 0);
        assert!(assess(&r, now).1.contains("Windows error 99999 (0x1869F)"));
    }

    #[test]
    fn urls_for_other_dcs() {
        assert_eq!(url_for_host("ldaps://dc1.example.com", "dc2.example.com").as_deref(), Some("ldaps://dc2.example.com"));
        assert_eq!(url_for_host("ldaps://dc1.example.com:3269/", "dc2").as_deref(), Some("ldaps://dc2:3269"));
        assert_eq!(url_for_host("ldap://10.0.0.5:389", "dc2.example.com").as_deref(), Some("ldap://dc2.example.com:389"));
        assert_eq!(url_for_host("ldaps://[2001:db8::1]:636", "dc2").as_deref(), Some("ldaps://dc2:636"));
        assert_eq!(url_for_host("ldaps://[2001:db8::1]", "dc2").as_deref(), Some("ldaps://dc2"));
        assert_eq!(url_for_host("dc1.example.com", "dc2"), None);
    }

    #[test]
    fn partitions_are_named() {
        let (b, c) = ("DC=example,DC=com", "CN=Configuration,DC=example,DC=com");
        assert_eq!(partition_label("DC=example,DC=com", b, c), "Domain");
        assert_eq!(partition_label("CN=Schema,CN=Configuration,DC=example,DC=com", b, c), "Schema");
        assert_eq!(partition_label("DC=ForestDnsZones,DC=example,DC=com", b, c), "ForestDnsZones");
    }

    #[test]
    fn spans_read_naturally() {
        assert_eq!(ago(3), "just now");
        assert_eq!(ago(45), "45 s ago");
        assert_eq!(ago(150), "3 min ago");
        assert_eq!(ago(7_200), "2 h ago");
        assert_eq!(ago(3 * 86_400 + 5), "3 days ago");
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
    }
}
