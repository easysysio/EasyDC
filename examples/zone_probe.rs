//! Does a Samba AD DC serve a DNS zone created purely over LDAP?
//!
//! `samba-tool dns zonecreate` does not write LDAP directly — it calls the DNS
//! server's RPC pipe, and the Samba wiki's promise that a new zone is "directly
//! live without restarting Samba" belongs to that path. Samba's internal DNS
//! reads its zones from the directory at startup, so a zone written straight
//! into LDAP may sit there looking correct while the server never answers for
//! it. EasyDC speaks only LDAP, so the answer decides whether zone create and
//! delete can be a real feature or should only generate a samba-tool command.
//!
//! This probe is deliberately not a unit test: it needs a live domain
//! controller and it writes to it. It creates one throwaway zone, and deletes
//! it again.
//!
//!   export EASYDC_LDAP_URL=ldaps://dc1.example.com
//!   export EASYDC_BIND_DN='CN=Administrator,CN=Users,DC=example,DC=com'
//!   export EASYDC_BIND_PW="$(sqlite3 easydc.db 'select bind_password from servers where id=1')"
//!   export EASYDC_SKIP_TLS=1          # self-signed DC certificate
//!
//!   cargo run --example zone_probe -- inspect
//!   cargo run --example zone_probe -- create easydc-probe-1.test
//!   cargo run --example zone_probe -- delete easydc-probe-1.test
//!
//! Between create and delete, ask the DC itself whether it serves the zone,
//! WITHOUT restarting samba:
//!
//!   dig @dc1.example.com SOA easydc-probe-1.test +short
//!
//! An answer means a zone can be created over LDAP alone. SERVFAIL or an empty
//! answer means it cannot, and the generator approach is the honest one. Then
//! restart samba on the DC and dig again: if it answers only after the restart,
//! that confirms the startup-load theory rather than a malformed zone object.

use std::collections::HashSet;
use std::env;

use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};

type R<T> = Result<T, String>;

// ── connection ────────────────────────────────────────────────────────────────

struct Conn {
    ldap: ldap3::Ldap,
    base_dn: String,
    dns_root: String,
}

async fn connect() -> R<Conn> {
    let url = env::var("EASYDC_LDAP_URL").map_err(|_| "EASYDC_LDAP_URL is not set".to_string())?;
    let bind_dn = env::var("EASYDC_BIND_DN").map_err(|_| "EASYDC_BIND_DN is not set".to_string())?;
    let bind_pw = env::var("EASYDC_BIND_PW").map_err(|_| "EASYDC_BIND_PW is not set".to_string())?;
    let skip_tls = env::var("EASYDC_SKIP_TLS").map(|v| v != "0").unwrap_or(false);

    let settings = LdapConnSettings::new().set_no_tls_verify(skip_tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &url)
        .await
        .map_err(|e| format!("connection failed: {}", e))?;
    ldap3::drive!(conn);
    ldap.simple_bind(&bind_dn, &bind_pw)
        .await
        .map_err(|e| format!("bind failed: {}", e))?
        .success()
        .map_err(|e| format!("authentication failed: {}", e))?;

    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    let base_dn = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("defaultNamingContext")?.first().cloned())
        .ok_or("could not read defaultNamingContext")?;

    let dns_root = format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn);
    println!("connected to {}", url);
    println!("  base DN   {}", base_dn);
    println!("  DNS root  {}", dns_root);
    Ok(Conn { ldap, base_dn, dns_root })
}

fn domain_of(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|p| {
            let p = p.trim();
            p.strip_prefix("dc=").or_else(|| p.strip_prefix("DC="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

// ── record helpers ────────────────────────────────────────────────────────────

fn sv(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn record_type(raw: &[u8]) -> u16 {
    if raw.len() < 4 { 0 } else { u16::from_le_bytes([raw[2], raw[3]]) }
}

fn type_name(t: u16) -> &'static str {
    match t {
        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA", 12 => "PTR",
        15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV",
        _ => "?",
    }
}

fn hexdump(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
}

async fn records_at(conn: &mut Conn, dn: &str) -> R<Vec<Vec<u8>>> {
    let (entries, _) = conn
        .ldap
        .search(dn, Scope::Base, "(objectClass=*)", vec!["dnsRecord"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    let Some(e) = entries.into_iter().next().map(SearchEntry::construct) else {
        return Ok(Vec::new());
    };
    Ok(e.bin_attrs
        .get("dnsRecord")
        .or_else(|| e.bin_attrs.get("dnsrecord"))
        .cloned()
        .unwrap_or_default())
}

/// The SOA serial is the first field of the record's data section. Bumping it is
/// the one edit the probe makes to the cloned bytes, so the new zone does not
/// claim the domain zone's serial. The DNS_RPC_RECORD header is 24 bytes
/// (wDataLength, wType, version, rank, flags, dwSerial, dwTtlSeconds,
/// dwReserved, dwTimeStamp — see build_dns_record_binary in src/ldap.rs), and
/// MS-DNSP stores the SOA counters big-endian.
fn bump_soa_serial(raw: &mut [u8]) -> Option<u32> {
    if raw.len() < 28 {
        return None;
    }
    let serial = u32::from_be_bytes([raw[24], raw[25], raw[26], raw[27]]);
    let next = serial.wrapping_add(1).max(1);
    raw[24..28].copy_from_slice(&next.to_be_bytes());
    Some(next)
}

/// The dNSProperty values of an existing zone, to clone onto a new one.
async fn zone_properties(conn: &mut Conn, zone_dn: &str) -> R<Vec<Vec<u8>>> {
    let (entries, _) = conn
        .ldap
        .search(zone_dn, Scope::Base, "(objectClass=*)", vec!["dNSProperty"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    let Some(e) = entries.into_iter().next().map(SearchEntry::construct) else {
        return Ok(Vec::new());
    };
    Ok(e.bin_attrs
        .get("dNSProperty")
        .or_else(|| e.bin_attrs.get("dnsproperty"))
        .cloned()
        .unwrap_or_default())
}

/// Decode a dNSProperty value (MS-DNSP DNS_PROPERTY): dwDataLength,
/// dwNameLength, dwFlag, dwVersion, dwId, then the data. The Id says which
/// setting it is, and for the two that matter the data is a single u32.
fn decode_property(raw: &[u8]) -> String {
    if raw.len() < 20 {
        return format!("<short: {} bytes>", raw.len());
    }
    let u32le = |o: usize| u32::from_le_bytes([raw[o], raw[o + 1], raw[o + 2], raw[o + 3]]);
    let data_len = u32le(0) as usize;
    let id = u32le(16);
    let value = if raw.len() >= 24 { u32le(20) } else { 0 };

    let name = match id {
        0x01 => "ZONE_TYPE",
        0x02 => "ZONE_ALLOW_UPDATE",
        0x08 => "ZONE_SECURE_TIME",
        0x10 => "ZONE_NOREFRESH_INTERVAL",
        0x11 => "ZONE_SCAVENGING_SERVERS",
        0x12 => "ZONE_AGING_ENABLED_TIME",
        0x20 => "ZONE_REFRESH_INTERVAL",
        0x40 => "ZONE_AGING_STATE",
        0x80 => "ZONE_DELETED_FROM_HOSTNAME",
        _ => "?",
    };
    let meaning = match (id, value) {
        (0x01, 1) => " = DNS_ZONE_TYPE_PRIMARY".to_string(),
        (0x01, 2) => " = SECONDARY".to_string(),
        (0x01, 3) => " = STUB".to_string(),
        (0x01, 4) => " = FORWARDER".to_string(),
        (0x02, 0) => " = update OFF".to_string(),
        (0x02, 1) => " = update UNSECURE".to_string(),
        (0x02, 2) => " = update SECURE".to_string(),
        (0x40, 0) => " = aging off".to_string(),
        (0x40, 1) => " = aging on".to_string(),
        (0x10, v) | (0x20, v) => format!(" = {} hours", v),
        _ => String::new(),
    };
    format!("id 0x{:02x} {:<26} data_len {} value {}{}", id, name, data_len, value, meaning)
}

/// Print the decoded zone properties, so "is this really a primary zone?" is
/// answered by the bytes rather than by assumption.
async fn props(conn: &mut Conn, zone: &str) -> R<()> {
    let dn = format!("DC={},{}", zone, conn.dns_root);
    println!("\n{}", zone);
    for v in zone_properties(conn, &dn).await? {
        println!("  {}", decode_property(&v));
    }
    Ok(())
}

// ── inspect ───────────────────────────────────────────────────────────────────

/// Read-only. Lists the zones and dumps the domain zone's apex records, which
/// are the template `create` clones.
async fn inspect(conn: &mut Conn, zone: Option<&str>) -> R<()> {
    let (entries, _) = conn
        .ldap
        .search(&conn.dns_root.clone(), Scope::OneLevel, "(objectClass=dnsZone)", vec!["dc"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    println!("\nzones under the domain DNS partition:");
    for e in entries {
        let e = SearchEntry::construct(e);
        println!("  {}", e.attrs.get("dc").and_then(|v| v.first()).cloned().unwrap_or_default());
    }

    let target = zone.map(String::from).unwrap_or_else(|| domain_of(&conn.base_dn));
    let apex = format!("DC=@,DC={},{}", target, conn.dns_root);
    println!("\napex records of {} ({}):", target, apex);
    for raw in records_at(conn, &apex).await? {
        let t = record_type(&raw);
        println!("  {:<5} {:>3} bytes  {}", type_name(t), raw.len(), hexdump(&raw));
    }
    Ok(())
}

/// Dump every attribute of a zone object. Used to compare a zone this probe
/// created against one Samba created — in particular dNSProperty, which holds
/// the zone type, allow-update and aging settings and which the probe does not
/// write.
async fn attrs(conn: &mut Conn, zone: &str) -> R<()> {
    let dn = format!("DC={},{}", zone, conn.dns_root);
    let (entries, _) = conn
        .ldap
        .search(&dn, Scope::Base, "(objectClass=*)", vec!["*"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("{} not found", dn))?;

    println!("\n{}", dn);
    let mut names: Vec<&String> = e.attrs.keys().collect();
    names.sort();
    for n in names {
        println!("  {:<22} {:?}", n, e.attrs[n]);
    }
    let mut bnames: Vec<&String> = e.bin_attrs.keys().collect();
    bnames.sort();
    for n in bnames {
        for v in &e.bin_attrs[n] {
            println!("  {:<22} <{} bytes> {}", n, v.len(), hexdump(v));
        }
    }
    Ok(())
}

// ── create ────────────────────────────────────────────────────────────────────

async fn create(conn: &mut Conn, zone: &str, template: Option<&str>) -> R<()> {
    // Cloning from an existing zone of the same kind is the strictest form of
    // the experiment: the new object then differs from one Samba built only in
    // its name and serial.
    let template = template.map(String::from).unwrap_or_else(|| domain_of(&conn.base_dn));
    let apex = format!("DC=@,DC={},{}", template, conn.dns_root);

    // Clone the SOA and NS bytes rather than encoding them from scratch: the
    // point of the probe is whether a zone written over LDAP is served, not
    // whether this program can build an SOA record. Cloning also keeps the
    // primary-server and responsible-party names pointing at this DC, which is
    // what they should be for a zone it hosts.
    let mut soa: Option<Vec<u8>> = None;
    let mut ns: Vec<Vec<u8>> = Vec::new();
    for raw in records_at(conn, &apex).await? {
        match record_type(&raw) {
            6 if soa.is_none() => soa = Some(raw),
            // Every NS, not just the first: a zone served by two DCs lists both.
            2 => ns.push(raw),
            _ => {}
        }
    }
    let mut soa = soa.ok_or_else(|| format!("no SOA on {} to use as a template", apex))?;
    let serial = bump_soa_serial(&mut soa);
    println!("cloned SOA from {} ({} bytes, serial now {:?})", apex, soa.len(), serial);
    if ns.is_empty() {
        println!("no NS record on the template apex; creating the zone without one");
    } else {
        println!("cloned {} NS record(s)", ns.len());
    }

    // dNSProperty carries the zone type, the allow-update mode and the aging
    // and refresh settings. A zone without them still answers queries, but it
    // is not the object Samba would have built — and secure dynamic update,
    // which is how hosts register their own PTRs, is one of these properties.
    let template_dn = format!("DC={},{}", template, conn.dns_root);
    let props = zone_properties(conn, &template_dn).await?;
    println!("cloned {} dNSProperty value(s) from {}", props.len(), template);

    let zone_dn = format!("DC={},{}", zone, conn.dns_root);
    let node_dn = format!("DC=@,{}", zone_dn);

    println!("\ncreating {}", zone_dn);
    // ldap3 wants the attribute name and its values as the same type, so
    // everything goes in as bytes — matching create_group in src/ldap.rs.
    let mut zone_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsZone")])),
        (sv("dc"), HashSet::from([sv(zone)])),
    ];
    if !props.is_empty() {
        zone_attrs.push((sv("dNSProperty"), props.iter().cloned().collect()));
    }
    conn.ldap
        .add(&zone_dn, zone_attrs)
        .await
        .map_err(|e| format!("zone add failed: {}", e))?
        .success()
        .map_err(|e| format!("zone add rejected: {}", e))?;
    println!("  zone object created");

    println!("creating {}", node_dn);
    let mut recs: HashSet<Vec<u8>> = HashSet::from([soa.clone()]);
    for n in &ns {
        recs.insert(n.clone());
    }
    let node_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsNode")])),
        (sv("dc"), HashSet::from([sv("@")])),
        (sv("dnsRecord"), recs),
    ];
    conn.ldap
        .add(&node_dn, node_attrs)
        .await
        .map_err(|e| format!("apex node add failed: {}", e))?
        .success()
        .map_err(|e| format!("apex node rejected: {}", e))?;
    println!("  apex node created with {} record(s)", 1 + ns.len());

    println!("\nthe directory now has the zone. Ask the DC itself, WITHOUT restarting samba:");
    println!("  dig @<dc> SOA {} +short", zone);
    println!("  samba-tool dns zonelist <dc> -U Administrator");
    println!("\nan answer means LDAP alone is enough; SERVFAIL or an empty answer means it is not.");
    println!("then restart samba on the DC and dig again — if it answers only after the restart,");
    println!("the zone object is fine and the internal DNS simply loads zones at startup.");
    println!("\nclean up with:  cargo run --example zone_probe -- delete {}", zone);
    Ok(())
}

// ── delete ────────────────────────────────────────────────────────────────────

/// Leaf-first: LDAP will not delete a node that still has children, and this
/// deliberately does not reach for the tree-delete control, so nothing can
/// remove more than the probe put there.
async fn delete(conn: &mut Conn, zone: &str) -> R<()> {
    let zone_dn = format!("DC={},{}", zone, conn.dns_root);

    let (entries, _) = conn
        .ldap
        .search(&zone_dn, Scope::OneLevel, "(objectClass=*)", vec!["dc"])
        .await
        .map_err(|e| format!("could not list zone children: {}", e))?
        .success()
        .map_err(|e| format!("could not list zone children: {}", e))?;

    let children: Vec<String> = entries.into_iter().map(|e| SearchEntry::construct(e).dn).collect();
    println!("{} has {} child object(s)", zone_dn, children.len());
    for dn in children {
        conn.ldap
            .delete(&dn)
            .await
            .map_err(|e| format!("delete {} failed: {}", dn, e))?
            .success()
            .map_err(|e| format!("delete {} rejected: {}", dn, e))?;
        println!("  deleted {}", dn);
    }

    conn.ldap
        .delete(&zone_dn)
        .await
        .map_err(|e| format!("delete {} failed: {}", zone_dn, e))?
        .success()
        .map_err(|e| format!("delete {} rejected: {}", zone_dn, e))?;
    println!("  deleted {}", zone_dn);
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let usage = "usage: zone_probe <inspect [zone] | attrs <zone> | props <zone> | create <zone> [template-zone] | delete <zone>>";

    let result = async {
        let mut conn = connect().await?;
        match args.first().map(|s| s.as_str()) {
            Some("inspect") => inspect(&mut conn, args.get(1).map(|s| s.as_str())).await,
            Some("acl") => {
                let a = args.get(1).ok_or_else(|| usage.to_string())?;
                let b = args.get(2).ok_or("need two zones to compare")?;
                acl(&mut conn, a, b).await
            }
            Some("verify") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                let primary = args.get(2).ok_or("need <primary-server>")?;
                let hostmaster = args.get(3).ok_or("need <hostmaster>")?;
                verify(&mut conn, zone, primary, hostmaster).await
            }
            Some("create-synth") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                let primary = args.get(2).ok_or("need <primary-server>")?;
                let hostmaster = args.get(3).ok_or("need <hostmaster>")?;
                let ns: Vec<String> = args[4..].to_vec();
                create_synth(&mut conn, zone, primary, hostmaster, &ns).await
            }
            Some("props") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                props(&mut conn, zone).await
            }
            Some("attrs") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                attrs(&mut conn, zone).await
            }
            Some("create") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                create(&mut conn, zone, args.get(2).map(|s| s.as_str())).await
            }
            Some("delete") => {
                let zone = args.get(1).ok_or_else(|| usage.to_string())?;
                delete(&mut conn, zone).await
            }
            _ => Err(usage.to_string()),
        }
    }
    .await;

    if let Err(e) = result {
        eprintln!("\nerror: {}", e);
        std::process::exit(1);
    }
}

/// Compare the security descriptors of two zone objects. A zone created over
/// LDAP inherits its ACL from the DNS partition; one created through the DNS
/// RPC server could in principle be given its own. Whether they match decides
/// if an LDAP-created zone is administratively the same thing.
async fn acl(conn: &mut Conn, a: &str, b: &str) -> R<()> {
    let mut sds = Vec::new();
    for zone in [a, b] {
        let dn = format!("DC={},{}", zone, conn.dns_root);
        let (entries, _) = conn
            .ldap
            .search(&dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"])
            .await
            .map_err(|e| e.to_string())?
            .success()
            .map_err(|e| e.to_string())?;
        let e = entries.into_iter().next().map(SearchEntry::construct).ok_or("zone not found")?;
        let sd = e
            .bin_attrs
            .get("nTSecurityDescriptor")
            .or_else(|| e.bin_attrs.get("ntsecuritydescriptor"))
            .and_then(|v| v.first().cloned())
            .unwrap_or_default();
        println!("  {:<28} nTSecurityDescriptor {} bytes", zone, sd.len());
        sds.push(sd);
    }
    if sds[0].is_empty() || sds[1].is_empty() {
        println!("  (could not read one of them — the bind account may lack the right)");
    } else if sds[0] == sds[1] {
        println!("  IDENTICAL security descriptors");
    } else {
        println!("  DIFFERENT security descriptors");
        println!("    {}\n    {}", hexdump(&sds[0]), hexdump(&sds[1]));
    }
    Ok(())
}

// ── synthesis ─────────────────────────────────────────────────────────────────
//
// Cloning a neighbouring zone is fine for a probe but wrong for a feature: it
// inherits whatever that zone happens to have, so one zone with aging switched
// on would quietly infect every zone created afterwards. These build the
// objects from scratch instead. Every layout below was read off the zones
// Samba itself created on this DC, and `verify` checks the synthesis against
// them byte for byte.

/// dnsp_name / DNS_COUNT_NAME: [total_len][label_count][len]label…[0x00].
/// Same encoding as encode_dns_rpc_name in src/ldap.rs.
fn encode_name(name: &str) -> Vec<u8> {
    let labels: Vec<&str> = name.trim_end_matches('.').split('.').filter(|l| !l.is_empty()).collect();
    let body_len: usize = labels.iter().map(|l| 1 + l.len()).sum::<usize>() + 1;
    let mut out = vec![body_len as u8, labels.len() as u8];
    for l in &labels {
        out.push(l.len() as u8);
        out.extend_from_slice(l.as_bytes());
    }
    out.push(0);
    out
}

/// The 24-byte DNS_RPC_RECORD header. version 5 and rank 0xF0 are what make
/// Samba treat the value as a live zone record.
fn record(rtype: u16, serial: u32, ttl: u32, data: Vec<u8>) -> Vec<u8> {
    let mut rec = Vec::new();
    rec.extend_from_slice(&(data.len() as u16).to_le_bytes());
    rec.extend_from_slice(&rtype.to_le_bytes());
    rec.push(5);
    rec.push(0xF0);
    rec.extend_from_slice(&0u16.to_le_bytes());
    rec.extend_from_slice(&serial.to_le_bytes());
    rec.extend_from_slice(&ttl.to_be_bytes()); // big-endian, unlike the rest
    rec.extend_from_slice(&0u32.to_le_bytes()); // dwReserved
    rec.extend_from_slice(&0u32.to_le_bytes()); // dwTimeStamp (0 = static)
    rec.extend(data);
    rec
}

/// SOA data: five big-endian counters, then the primary server and the
/// responsible party as dnsp_names.
fn soa_record(primary: &str, hostmaster: &str, serial: u32, ttl: u32) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [serial, 900u32, 600, 86_400, 3_600] {
        d.extend_from_slice(&v.to_be_bytes());
    }
    d.extend(encode_name(primary));
    d.extend(encode_name(hostmaster));
    record(6, serial, ttl, d)
}

fn ns_record(host: &str, serial: u32, ttl: u32) -> Vec<u8> {
    record(2, serial, ttl, encode_name(host))
}

/// DNS_PROPERTY: dwDataLength, dwNameLength, dwFlag, dwVersion, dwId, the data,
/// then four trailing zero bytes (the empty name).
fn property(id: u32, data: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(data.len() as u32).to_le_bytes());
    p.extend_from_slice(&0u32.to_le_bytes()); // dwNameLength
    p.extend_from_slice(&0u32.to_le_bytes()); // dwFlag
    p.extend_from_slice(&1u32.to_le_bytes()); // dwVersion
    p.extend_from_slice(&id.to_le_bytes());
    p.extend_from_slice(data);
    p.extend_from_slice(&0u32.to_le_bytes());
    p
}

/// The property set Samba gives a new primary zone: primary type, secure
/// dynamic update, default refresh intervals, aging off.
fn primary_zone_properties() -> Vec<Vec<u8>> {
    let u32d = |v: u32| v.to_le_bytes().to_vec();
    vec![
        property(0x01, &u32d(1)),            // ZONE_TYPE = primary
        property(0x02, &[2u8]),              // ALLOW_UPDATE = secure
        property(0x08, &[0u8; 8]),           // SECURE_TIME
        property(0x10, &u32d(168)),          // NOREFRESH_INTERVAL, hours
        property(0x20, &u32d(168)),          // REFRESH_INTERVAL, hours
        property(0x40, &u32d(0)),            // AGING_STATE = off
        property(0x12, &u32d(0)),            // AGING_ENABLED_TIME
    ]
}

/// Prove the synthesis by rebuilding an existing zone's bytes and comparing.
/// Only the serial may differ, so a layout mistake cannot slip through.
async fn verify(conn: &mut Conn, zone: &str, primary: &str, hostmaster: &str) -> R<()> {
    let zone_dn = format!("DC={},{}", zone, conn.dns_root);
    let apex = format!("DC=@,{}", zone_dn);
    println!("\nrebuilding {} from scratch and comparing with what Samba stored", zone);

    let mut real_soa = None;
    for raw in records_at(conn, &apex).await? {
        if record_type(&raw) == 6 {
            real_soa = Some(raw);
            break;
        }
    }
    let real_soa = real_soa.ok_or("no SOA on that zone")?;
    let serial = u32::from_be_bytes([real_soa[24], real_soa[25], real_soa[26], real_soa[27]]);
    let rec_serial = u32::from_le_bytes([real_soa[8], real_soa[9], real_soa[10], real_soa[11]]);
    let ttl = u32::from_be_bytes([real_soa[12], real_soa[13], real_soa[14], real_soa[15]]);
    let mine = soa_record(primary, hostmaster, serial, ttl);
    let mut mine_fixed = mine.clone();
    mine_fixed[8..12].copy_from_slice(&rec_serial.to_le_bytes()); // header serial is the DC's own counter
    println!("  SOA  samba {} bytes / mine {} bytes", real_soa.len(), mine_fixed.len());
    if mine_fixed == real_soa {
        println!("  SOA  IDENTICAL");
    } else {
        println!("  SOA  DIFFERS\n    samba {}\n    mine  {}", hexdump(&real_soa), hexdump(&mine_fixed));
    }

    let real_props = zone_properties(conn, &zone_dn).await?;
    let mine_props = primary_zone_properties();
    let mut matched = 0;
    for p in &mine_props {
        if real_props.contains(p) {
            matched += 1;
        } else {
            println!("  prop NOT FOUND in samba's set: {}", decode_property(p));
        }
    }
    println!("  props {}/{} synthesised values match samba's (samba has {})", matched, mine_props.len(), real_props.len());
    Ok(())
}

/// Create a primary zone with nothing copied from another zone.
async fn create_synth(conn: &mut Conn, zone: &str, primary: &str, hostmaster: &str, nameservers: &[String]) -> R<()> {
    let zone_dn = format!("DC={},{}", zone, conn.dns_root);
    let node_dn = format!("DC=@,{}", zone_dn);

    let props: HashSet<Vec<u8>> = primary_zone_properties().into_iter().collect();
    println!("\ncreating {} (synthesised, nothing cloned)", zone_dn);
    let zone_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsZone")])),
        (sv("dc"), HashSet::from([sv(zone)])),
        (sv("dNSProperty"), props),
    ];
    conn.ldap
        .add(&zone_dn, zone_attrs)
        .await
        .map_err(|e| format!("zone add failed: {}", e))?
        .success()
        .map_err(|e| format!("zone add rejected: {}", e))?;
    println!("  zone object created with 7 properties");

    let mut recs: HashSet<Vec<u8>> = HashSet::from([soa_record(primary, hostmaster, 1, 3600)]);
    for ns in nameservers {
        recs.insert(ns_record(ns, 1, 3600));
    }
    let node_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsNode")])),
        (sv("dc"), HashSet::from([sv("@")])),
        (sv("dnsRecord"), recs),
    ];
    conn.ldap
        .add(&node_dn, node_attrs)
        .await
        .map_err(|e| format!("apex node add failed: {}", e))?
        .success()
        .map_err(|e| format!("apex node rejected: {}", e))?;
    println!("  apex node created: SOA + {} NS", nameservers.len());
    Ok(())
}
