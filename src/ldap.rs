use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use serde::Serialize;
use std::collections::HashSet;
use uuid::Uuid;

use crate::models::Server;

pub type LdapResult<T> = Result<T, String>;

#[derive(Debug, Serialize, Clone)]
pub struct LdapUser {
    pub dn: String,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub display_name: String,
    pub email: String,
    pub enabled: bool,
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn sv(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

fn encode_password(password: &str) -> Vec<u8> {
    format!("\"{}\"", password)
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect()
}

fn base_dn_to_domain(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| {
            let p = part.trim();
            p.strip_prefix("dc=").or_else(|| p.strip_prefix("DC="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

fn attr(e: &SearchEntry, key: &str) -> String {
    e.attrs
        .get(key)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

// ── connection ────────────────────────────────────────────────────────────────

pub async fn connect_and_bind(server: &Server) -> LdapResult<ldap3::Ldap> {
    let settings = LdapConnSettings::new().set_no_tls_verify(server.skip_tls);
    let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &server.ldap_url)
        .await
        .map_err(|e| format!("Connection failed: {}", e))?;
    ldap3::drive!(conn);
    ldap.simple_bind(&server.bind_dn, &server.bind_password)
        .await
        .map_err(|e| format!("Bind failed: {}", e))?
        .success()
        .map_err(|e| format!("Authentication failed: {}", e))?;
    Ok(ldap)
}

pub async fn get_base_dn(ldap: &mut ldap3::Ldap) -> LdapResult<String> {
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("defaultNamingContext")?.first().cloned())
        .ok_or_else(|| "Could not determine domain base DN from server".to_string())
}

pub async fn open(server: &Server) -> LdapResult<(ldap3::Ldap, String)> {
    let mut ldap = connect_and_bind(server).await?;
    let base_dn = get_base_dn(&mut ldap).await?;
    Ok((ldap, base_dn))
}

// ── user lookup ───────────────────────────────────────────────────────────────

async fn find_user_dn(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
) -> LdapResult<String> {
    let filter = format!("(&(objectClass=user)(sAMAccountName={}))", username);
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    entries
        .into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| format!("User '{}' not found", username))
}

// ── list users ────────────────────────────────────────────────────────────────

pub async fn list_users(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapUser>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=user)(!(objectClass=computer)))",
            vec![
                "sAMAccountName",
                "givenName",
                "sn",
                "displayName",
                "mail",
                "userAccountControl",
            ],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut users: Vec<LdapUser> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let uac: i64 = attr(&e, "userAccountControl").parse().unwrap_or(514);
            LdapUser {
                dn: e.dn.clone(),
                username: attr(&e, "sAMAccountName"),
                first_name: attr(&e, "givenName"),
                last_name: attr(&e, "sn"),
                display_name: attr(&e, "displayName"),
                email: attr(&e, "mail"),
                enabled: (uac & 2) == 0,
            }
        })
        .filter(|u| !u.username.is_empty())
        .collect();

    users.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    Ok(users)
}

// ── create user ───────────────────────────────────────────────────────────────

pub struct NewUser<'a> {
    pub username: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub password: &'a str,
}

pub async fn create_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    u: &NewUser<'_>,
) -> LdapResult<()> {
    let display = format!("{} {}", u.first_name, u.last_name)
        .trim()
        .to_string();
    let cn = if display.is_empty() {
        u.username.to_string()
    } else {
        display.clone()
    };
    let domain = base_dn_to_domain(base_dn);
    let upn = format!("{}@{}", u.username, domain);
    let user_dn = format!("CN={},CN=Users,{}", cn, base_dn);

    let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (
            sv("objectClass"),
            HashSet::from([
                sv("top"),
                sv("person"),
                sv("organizationalPerson"),
                sv("user"),
            ]),
        ),
        (sv("cn"), HashSet::from([sv(&cn)])),
        (sv("sAMAccountName"), HashSet::from([sv(u.username)])),
        (sv("userPrincipalName"), HashSet::from([sv(&upn)])),
        (sv("userAccountControl"), HashSet::from([sv("514")])),
    ];
    if !u.first_name.is_empty() {
        attrs.push((sv("givenName"), HashSet::from([sv(u.first_name)])));
    }
    if !u.last_name.is_empty() {
        attrs.push((sv("sn"), HashSet::from([sv(u.last_name)])));
    }
    if !display.is_empty() {
        attrs.push((sv("displayName"), HashSet::from([sv(&display)])));
    }
    if !u.email.is_empty() {
        attrs.push((sv("mail"), HashSet::from([sv(u.email)])));
    }

    ldap.add(&user_dn, attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to create user: {}", e))?;

    // Set password then enable
    let pwd_mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("unicodePwd"),
        HashSet::from([encode_password(u.password)]),
    )];
    ldap.modify(&user_dn, pwd_mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to set password (requires LDAPS): {}", e))?;

    let enable_mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv("512")]),
    )];
    ldap.modify(&user_dn, enable_mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to enable account: {}", e))?;

    Ok(())
}

// ── update user ───────────────────────────────────────────────────────────────

pub struct UserUpdate<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub password: &'a str,
}

pub async fn update_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    u: &UserUpdate<'_>,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    let display = format!("{} {}", u.first_name, u.last_name)
        .trim()
        .to_string();

    let mut mods: Vec<Mod<Vec<u8>>> = vec![
        Mod::Replace(sv("givenName"), HashSet::from([sv(u.first_name)])),
        Mod::Replace(sv("sn"), HashSet::from([sv(u.last_name)])),
        Mod::Replace(sv("displayName"), HashSet::from([sv(&display)])),
        Mod::Replace(sv("mail"), HashSet::from([sv(u.email)])),
    ];

    if !u.password.is_empty() {
        mods.push(Mod::Replace(
            sv("unicodePwd"),
            HashSet::from([encode_password(u.password)]),
        ));
    }

    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to update user: {}", e))?;

    Ok(())
}

// ── delete user ───────────────────────────────────────────────────────────────

pub async fn delete_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    ldap.delete(&dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete user: {}", e))?;
    Ok(())
}

// ── enable / disable user ────────────────────────────────────────────────────

pub async fn set_user_enabled(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    enable: bool,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    let uac = if enable { "512" } else { "514" };
    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv(uac)]),
    )];
    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to change account state: {}", e))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Groups
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct LdapGroup {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub group_type: i64,
    pub group_type_label: String,
    pub member_count: usize,
}

fn group_type_label(t: i64) -> &'static str {
    match t {
        -2147483646 => "Global Security",
        -2147483644 => "Domain Local Security",
        -2147483640 => "Universal Security",
        2 => "Global Distribution",
        4 => "Domain Local Distribution",
        8 => "Universal Distribution",
        _ => "Other",
    }
}

async fn find_group_dn(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
) -> LdapResult<String> {
    let filter = format!("(&(objectClass=group)(sAMAccountName={}))", name);
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    entries
        .into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| format!("Group '{}' not found", name))
}

// ── list groups ───────────────────────────────────────────────────────────────

pub async fn list_groups(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapGroup>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=group)",
            vec!["sAMAccountName", "description", "groupType", "member"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut groups: Vec<LdapGroup> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let name = attr(&e, "sAMAccountName");
            let gt: i64 = attr(&e, "groupType").parse().unwrap_or(0);
            let member_count = e.attrs.get("member").map(|v| v.len()).unwrap_or(0);
            LdapGroup {
                dn: e.dn.clone(),
                name,
                description: attr(&e, "description"),
                group_type: gt,
                group_type_label: group_type_label(gt).to_string(),
                member_count,
            }
        })
        .filter(|g| !g.name.is_empty())
        .collect();

    groups.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(groups)
}

// ── create group ──────────────────────────────────────────────────────────────

pub struct NewGroup<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub group_type: i64,
}

pub async fn create_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    g: &NewGroup<'_>,
) -> LdapResult<()> {
    let group_dn = format!("CN={},CN=Users,{}", g.name, base_dn);
    let gt = g.group_type.to_string();

    let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("group")])),
        (sv("cn"), HashSet::from([sv(g.name)])),
        (sv("sAMAccountName"), HashSet::from([sv(g.name)])),
        (sv("groupType"), HashSet::from([sv(&gt)])),
    ];
    if !g.description.is_empty() {
        attrs.push((sv("description"), HashSet::from([sv(g.description)])));
    }

    ldap.add(&group_dn, attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to create group: {}", e))?;

    Ok(())
}

// ── update group ──────────────────────────────────────────────────────────────

pub struct GroupUpdate<'a> {
    pub description: &'a str,
}

pub async fn update_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
    g: &GroupUpdate<'_>,
) -> LdapResult<()> {
    let dn = find_group_dn(ldap, base_dn, name).await?;

    let mods: Vec<Mod<Vec<u8>>> = if g.description.is_empty() {
        vec![Mod::Delete(sv("description"), HashSet::new())]
    } else {
        vec![Mod::Replace(
            sv("description"),
            HashSet::from([sv(g.description)]),
        )]
    };

    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to update group: {}", e))?;

    Ok(())
}

// ── delete group ──────────────────────────────────────────────────────────────

pub async fn delete_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
) -> LdapResult<()> {
    let dn = find_group_dn(ldap, base_dn, name).await?;
    ldap.delete(&dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete group: {}", e))?;
    Ok(())
}

// ── group members ─────────────────────────────────────────────────────────────

pub async fn list_group_members(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    group_name: &str,
) -> LdapResult<Vec<LdapUser>> {
    let group_dn = find_group_dn(ldap, base_dn, group_name).await?;

    let (entries, _) = ldap
        .search(&group_dn, Scope::Base, "(objectClass=group)", vec!["member"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let member_dns: Vec<String> = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("member").cloned())
        .unwrap_or_default();

    if member_dns.is_empty() {
        return Ok(vec![]);
    }

    let mut members = Vec::new();
    for dn in &member_dns {
        let (mes, _) = ldap
            .search(
                dn,
                Scope::Base,
                "(objectClass=*)",
                vec![
                    "sAMAccountName",
                    "givenName",
                    "sn",
                    "displayName",
                    "mail",
                    "userAccountControl",
                ],
            )
            .await
            .map_err(|e| e.to_string())?
            .success()
            .map_err(|e| e.to_string())?;

        if let Some(entry) = mes.into_iter().next() {
            let e = SearchEntry::construct(entry);
            let username = attr(&e, "sAMAccountName");
            if !username.is_empty() {
                let uac: i64 = attr(&e, "userAccountControl").parse().unwrap_or(514);
                members.push(LdapUser {
                    dn: e.dn.clone(),
                    username,
                    first_name: attr(&e, "givenName"),
                    last_name: attr(&e, "sn"),
                    display_name: attr(&e, "displayName"),
                    email: attr(&e, "mail"),
                    enabled: (uac & 2) == 0,
                });
            }
        }
    }

    members.sort_by(|a, b| a.username.to_lowercase().cmp(&b.username.to_lowercase()));
    Ok(members)
}

pub async fn add_group_member(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    group_name: &str,
    username: &str,
) -> LdapResult<()> {
    let group_dn = find_group_dn(ldap, base_dn, group_name).await?;
    let user_dn = find_user_dn(ldap, base_dn, username).await?;

    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Add(
        sv("member"),
        HashSet::from([sv(&user_dn)]),
    )];
    ldap.modify(&group_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to add member: {}", e))?;

    Ok(())
}

pub async fn remove_group_member(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    group_name: &str,
    username: &str,
) -> LdapResult<()> {
    let group_dn = find_group_dn(ldap, base_dn, group_name).await?;
    let user_dn = find_user_dn(ldap, base_dn, username).await?;

    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Delete(
        sv("member"),
        HashSet::from([sv(&user_dn)]),
    )];
    ldap.modify(&group_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to remove member: {}", e))?;

    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Computers
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct LdapComputer {
    pub dn: String,
    pub name: String,
    pub sam_account: String,
    pub dns_hostname: String,
    pub os: String,
    pub os_version: String,
    pub enabled: bool,
}

async fn find_computer_dn(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
) -> LdapResult<String> {
    let filter = format!("(&(objectClass=computer)(cn={}))", name);
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    entries
        .into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| format!("Computer '{}' not found", name))
}

pub async fn list_computers(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<Vec<LdapComputer>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=computer)",
            vec![
                "cn",
                "sAMAccountName",
                "dNSHostName",
                "operatingSystem",
                "operatingSystemVersion",
                "userAccountControl",
            ],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut computers: Vec<LdapComputer> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let uac: i64 = attr(&e, "userAccountControl").parse().unwrap_or(4096);
            LdapComputer {
                dn: e.dn.clone(),
                name: attr(&e, "cn"),
                sam_account: attr(&e, "sAMAccountName"),
                dns_hostname: attr(&e, "dNSHostName"),
                os: attr(&e, "operatingSystem"),
                os_version: attr(&e, "operatingSystemVersion"),
                enabled: (uac & 2) == 0,
            }
        })
        .filter(|c| !c.name.is_empty())
        .collect();

    computers.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(computers)
}

pub async fn delete_computer(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
) -> LdapResult<()> {
    let dn = find_computer_dn(ldap, base_dn, name).await?;
    ldap.delete(&dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete computer: {}", e))?;
    Ok(())
}

pub async fn set_computer_enabled(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
    enable: bool,
) -> LdapResult<()> {
    let dn = find_computer_dn(ldap, base_dn, name).await?;
    // Standard computer UAC: 4096 (enabled) or 4098 (disabled)
    let uac = if enable { "4096" } else { "4098" };
    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv(uac)]),
    )];
    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to change computer state: {}", e))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS
// ═══════════════════════════════════════════════════════════════════════════

// ── binary helpers ────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let name = name.trim_end_matches('.');
    if name.is_empty() {
        out.push(0);
        return out;
    }
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn parse_dns_name_bytes(data: &[u8]) -> String {
    let mut labels = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        if len == 0 {
            break;
        }
        if len >= 64 {
            break; // compression pointer or invalid
        }
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        labels.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    }
}

fn parse_txt_bytes(data: &[u8]) -> String {
    let mut strings = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        let len = data[pos] as usize;
        pos += 1;
        if pos + len > data.len() {
            break;
        }
        strings.push(String::from_utf8_lossy(&data[pos..pos + len]).to_string());
        pos += len;
    }
    strings.join(" ")
}

// Returns (type_str, value, ttl) or None for tombstone / unrecognised
fn parse_dns_record_binary(data: &[u8]) -> Option<(String, String, u32)> {
    if data.len() < 24 {
        return None;
    }
    let data_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let record_type = u16::from_le_bytes([data[2], data[3]]);
    if record_type == 0 {
        return None; // tombstone record
    }
    let ttl = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);
    let end = std::cmp::min(24 + data_len, data.len());
    let payload = &data[24..end];

    let (type_str, value) = match record_type {
        1 if payload.len() >= 4 => (
            "A".to_string(),
            format!("{}.{}.{}.{}", payload[0], payload[1], payload[2], payload[3]),
        ),
        28 if payload.len() >= 16 => {
            let bytes: [u8; 16] = payload[..16].try_into().ok()?;
            ("AAAA".to_string(), std::net::Ipv6Addr::from(bytes).to_string())
        }
        2 => ("NS".to_string(), parse_dns_name_bytes(payload)),
        5 => ("CNAME".to_string(), parse_dns_name_bytes(payload)),
        6 => ("SOA".to_string(), "(zone authority)".to_string()),
        12 => ("PTR".to_string(), parse_dns_name_bytes(payload)),
        15 if payload.len() >= 2 => {
            let priority = u16::from_be_bytes([payload[0], payload[1]]);
            let name = parse_dns_name_bytes(&payload[2..]);
            ("MX".to_string(), format!("{} {}", priority, name))
        }
        16 => ("TXT".to_string(), parse_txt_bytes(payload)),
        33 if payload.len() >= 6 => {
            let priority = u16::from_be_bytes([payload[0], payload[1]]);
            let weight = u16::from_be_bytes([payload[2], payload[3]]);
            let port = u16::from_be_bytes([payload[4], payload[5]]);
            let target = parse_dns_name_bytes(&payload[6..]);
            ("SRV".to_string(), format!("{} {} {} {}", priority, weight, port, target))
        }
        _ => (format!("TYPE{}", record_type), to_hex(payload)),
    };

    Some((type_str, value, ttl))
}

fn build_dns_record_binary(record_type: &str, value: &str, ttl: u32) -> LdapResult<Vec<u8>> {
    let (rtype, data): (u16, Vec<u8>) = match record_type {
        "A" => {
            let addr: std::net::Ipv4Addr = value
                .parse()
                .map_err(|_| format!("Invalid IPv4: {}", value))?;
            (1, addr.octets().to_vec())
        }
        "AAAA" => {
            let addr: std::net::Ipv6Addr = value
                .parse()
                .map_err(|_| format!("Invalid IPv6: {}", value))?;
            (28, addr.octets().to_vec())
        }
        "NS" => (2, encode_dns_name(value)),
        "CNAME" => (5, encode_dns_name(value)),
        "PTR" => (12, encode_dns_name(value)),
        "TXT" => {
            let bytes = value.as_bytes();
            let mut d = vec![bytes.len() as u8];
            d.extend_from_slice(bytes);
            (16, d)
        }
        "MX" => {
            let parts: Vec<&str> = value.splitn(2, ' ').collect();
            let priority: u16 = parts
                .first()
                .and_then(|p| p.parse().ok())
                .ok_or_else(|| "MX format: <priority> <hostname>".to_string())?;
            let name = parts
                .get(1)
                .ok_or_else(|| "MX format: <priority> <hostname>".to_string())?;
            let mut d = priority.to_be_bytes().to_vec();
            d.extend(encode_dns_name(name));
            (15, d)
        }
        _ => return Err(format!("Unsupported type: {}", record_type)),
    };

    let mut rec = Vec::new();
    rec.extend_from_slice(&(data.len() as u16).to_le_bytes()); // wDataLength
    rec.extend_from_slice(&rtype.to_le_bytes());               // wType
    rec.extend_from_slice(&0x60000000u32.to_le_bytes());       // dwFlags
    rec.extend_from_slice(&0u32.to_le_bytes());                // dwSerial
    rec.extend_from_slice(&ttl.to_le_bytes());                 // dwTtlSeconds
    rec.extend_from_slice(&0u32.to_le_bytes());                // dwTimeStamp
    rec.extend_from_slice(&0u32.to_le_bytes());                // dwReserved
    rec.extend(data);
    Ok(rec)
}

// ── DNS structs ───────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct LdapDnsZone {
    pub dn: String,
    pub name: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct DnsRecord {
    pub node_name: String,
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
    pub raw_hex: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct DnsNode {
    pub name: String,
    pub records: Vec<DnsRecord>,
}

// ── zone discovery ────────────────────────────────────────────────────────────

pub async fn list_dns_zones(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<Vec<LdapDnsZone>> {
    let candidates = [
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
        format!("DC=DomainDnsZones,{}", base_dn),
    ];

    let mut entries = Vec::new();
    for base in &candidates {
        if let Ok(Ok((e, _))) = ldap
            .search(base, Scope::OneLevel, "(objectClass=dnsZone)", vec!["dc"])
            .await
            .map(|r| r.success())
        {
            if !e.is_empty() {
                entries = e;
                break;
            }
        }
    }

    let mut zones: Vec<LdapDnsZone> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            LdapDnsZone {
                dn: e.dn.clone(),
                name: attr(&e, "dc"),
            }
        })
        .filter(|z| {
            !z.name.is_empty()
                && !z.name.starts_with('_')
                && z.name != "RootDNSServers"
                && !z.name.starts_with('.')
        })
        .collect();

    zones.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(zones)
}

pub async fn find_zone_dn(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    zone_name: &str,
) -> LdapResult<String> {
    let filter = format!("(&(objectClass=dnsZone)(dc={}))", zone_name);
    let candidates = [
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
        format!("DC=DomainDnsZones,{}", base_dn),
    ];

    for base in &candidates {
        if let Ok(Ok((entries, _))) = ldap
            .search(base, Scope::OneLevel, &filter, vec!["dc"])
            .await
            .map(|r| r.success())
        {
            if let Some(e) = entries.into_iter().next() {
                return Ok(SearchEntry::construct(e).dn);
            }
        }
    }
    Err(format!("Zone '{}' not found", zone_name))
}

// ── record listing ────────────────────────────────────────────────────────────

pub async fn list_dns_records(
    ldap: &mut ldap3::Ldap,
    zone_dn: &str,
) -> LdapResult<Vec<DnsNode>> {
    let (entries, _) = ldap
        .search(
            zone_dn,
            Scope::OneLevel,
            "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))",
            vec!["dc", "dnsRecord"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut nodes: Vec<DnsNode> = entries
        .into_iter()
        .filter_map(|e| {
            let e = SearchEntry::construct(e);
            let name = attr(&e, "dc");
            if name.is_empty() {
                return None;
            }
            let records: Vec<DnsRecord> = e
                .bin_attrs
                .get("dnsRecord")
                .map(|recs| {
                    recs.iter()
                        .filter_map(|raw| {
                            let (record_type, value, ttl) = parse_dns_record_binary(raw)?;
                            Some(DnsRecord {
                                node_name: name.clone(),
                                record_type,
                                value,
                                ttl,
                                raw_hex: to_hex(raw),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();

            if records.is_empty() {
                None
            } else {
                Some(DnsNode { name, records })
            }
        })
        .collect();

    // Sort: @ first, then alphabetically
    nodes.sort_by(|a, b| {
        if a.name == "@" {
            return std::cmp::Ordering::Less;
        }
        if b.name == "@" {
            return std::cmp::Ordering::Greater;
        }
        a.name.to_lowercase().cmp(&b.name.to_lowercase())
    });
    Ok(nodes)
}

// ── add record ────────────────────────────────────────────────────────────────

pub async fn add_dns_record(
    ldap: &mut ldap3::Ldap,
    zone_dn: &str,
    node_name: &str,
    record_type: &str,
    value: &str,
    ttl: u32,
) -> LdapResult<()> {
    let record_bytes = build_dns_record_binary(record_type, value, ttl)?;
    let node_dn = format!("DC={},{}", node_name, zone_dn);

    // Check if the node already exists
    let exists = ldap
        .search(&node_dn, Scope::Base, "(objectClass=dnsNode)", vec!["dc"])
        .await
        .ok()
        .and_then(|r| r.success().ok())
        .map(|(e, _)| !e.is_empty())
        .unwrap_or(false);

    if exists {
        let mods: Vec<Mod<Vec<u8>>> =
            vec![Mod::Add(sv("dnsRecord"), HashSet::from([record_bytes]))];
        ldap.modify(&node_dn, mods)
            .await
            .map_err(|e| e.to_string())?
            .success()
            .map_err(|e| format!("Failed to add record: {}", e))?;
    } else {
        let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (sv("objectClass"), HashSet::from([sv("top"), sv("dnsNode")])),
            (sv("dc"), HashSet::from([sv(node_name)])),
            (sv("dnsRecord"), HashSet::from([record_bytes])),
        ];
        ldap.add(&node_dn, attrs)
            .await
            .map_err(|e| e.to_string())?
            .success()
            .map_err(|e| format!("Failed to create DNS node: {}", e))?;
    }
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// GPO
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct LdapGpo {
    pub dn: String,
    pub guid: String,
    pub guid_url: String,
    pub display_name: String,
    pub flags: i32,
    pub version: i32,
    pub file_sys_path: String,
    pub status_label: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct LdapOu {
    pub dn: String,
    pub name: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct GpoLink {
    pub ou_dn: String,
    pub ou_name: String,
    pub link_flags: u8,
    pub link_status: String,
}

fn gpo_status_label(flags: i32) -> &'static str {
    match flags {
        1 => "User Config Disabled",
        2 => "Computer Config Disabled",
        3 => "All Settings Disabled",
        _ => "Enabled",
    }
}

// ── GPO list ──────────────────────────────────────────────────────────────────

pub async fn list_gpos(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapGpo>> {
    let policies_dn = format!("CN=Policies,CN=System,{}", base_dn);
    let (entries, _) = ldap
        .search(
            &policies_dn,
            Scope::OneLevel,
            "(objectClass=groupPolicyContainer)",
            vec!["cn", "displayName", "flags", "versionNumber", "gPCFileSysPath"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut gpos: Vec<LdapGpo> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let guid = attr(&e, "cn");
            let guid_url = guid.trim_matches(|c| c == '{' || c == '}').to_string();
            let flags: i32 = attr(&e, "flags").parse().unwrap_or(0);
            let version: i32 = attr(&e, "versionNumber").parse().unwrap_or(0);
            LdapGpo {
                dn: e.dn.clone(),
                display_name: attr(&e, "displayName"),
                file_sys_path: attr(&e, "gPCFileSysPath"),
                status_label: gpo_status_label(flags).to_string(),
                guid_url,
                guid,
                flags,
                version,
            }
        })
        .filter(|g| !g.guid.is_empty())
        .collect();

    gpos.sort_by(|a, b| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()));
    Ok(gpos)
}

// ── create GPO ────────────────────────────────────────────────────────────────

pub async fn create_gpo(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    display_name: &str,
) -> LdapResult<()> {
    let guid = format!("{{{}}}", Uuid::new_v4().to_string().to_uppercase());
    let domain = base_dn_to_domain(base_dn);
    let gpo_dn = format!("CN={},CN=Policies,CN=System,{}", guid, base_dn);
    let file_sys_path = format!("\\\\{}\\SysVol\\{}\\Policies\\{}", domain, domain, guid);

    let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (
            sv("objectClass"),
            HashSet::from([sv("top"), sv("container"), sv("groupPolicyContainer")]),
        ),
        (sv("cn"), HashSet::from([sv(&guid)])),
        (sv("displayName"), HashSet::from([sv(display_name)])),
        (sv("gPCFileSysPath"), HashSet::from([sv(&file_sys_path)])),
        (sv("gPCFunctionalityVersion"), HashSet::from([sv("2")])),
        (sv("flags"), HashSet::from([sv("0")])),
        (sv("versionNumber"), HashSet::from([sv("0")])),
    ];

    ldap.add(&gpo_dn, attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to create GPO: {}", e))?;

    Ok(())
}

// ── update GPO ────────────────────────────────────────────────────────────────

pub async fn update_gpo(
    ldap: &mut ldap3::Ldap,
    gpo_dn: &str,
    display_name: &str,
    flags: i32,
) -> LdapResult<()> {
    let flags_str = flags.to_string();
    let mods: Vec<Mod<Vec<u8>>> = vec![
        Mod::Replace(sv("displayName"), HashSet::from([sv(display_name)])),
        Mod::Replace(sv("flags"), HashSet::from([sv(&flags_str)])),
    ];
    ldap.modify(gpo_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to update GPO: {}", e))?;
    Ok(())
}

// ── delete GPO ────────────────────────────────────────────────────────────────

pub async fn delete_gpo(ldap: &mut ldap3::Ldap, gpo_dn: &str) -> LdapResult<()> {
    ldap.delete(gpo_dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete GPO: {}", e))?;
    Ok(())
}

// ── OU list ───────────────────────────────────────────────────────────────────

pub async fn list_ous(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapOu>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["ou", "name"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let domain = base_dn_to_domain(base_dn);
    let mut ous: Vec<LdapOu> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let name = {
                let n = attr(&e, "ou");
                if n.is_empty() { attr(&e, "name") } else { n }
            };
            LdapOu { dn: e.dn.clone(), name }
        })
        .filter(|o| !o.name.is_empty())
        .collect();

    ous.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));

    // Domain root goes first
    ous.insert(0, LdapOu {
        dn: base_dn.to_string(),
        name: format!("Domain Root ({})", domain),
    });

    Ok(ous)
}

// ── gPLink helpers ────────────────────────────────────────────────────────────

fn parse_gp_link(gp_link: &str) -> Vec<(String, u8)> {
    let mut links = Vec::new();
    let mut s = gp_link;
    while let Some(start) = s.find('[') {
        let rest = &s[start + 1..];
        if let Some(end) = rest.find(']') {
            let entry = &rest[..end];
            let entry = entry.trim_start_matches("LDAP://").trim_start_matches("ldap://");
            if let Some(semi) = entry.rfind(';') {
                let dn = entry[..semi].to_string();
                let flags: u8 = entry[semi + 1..].parse().unwrap_or(0);
                links.push((dn, flags));
            }
            s = &rest[end + 1..];
        } else {
            break;
        }
    }
    links
}

fn build_gp_link(links: &[(String, u8)]) -> String {
    links
        .iter()
        .map(|(dn, flags)| format!("[LDAP://{};{}]", dn, flags))
        .collect::<Vec<_>>()
        .join("")
}

// ── GPO link list ─────────────────────────────────────────────────────────────

pub async fn list_gpo_links(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    gpo_dn: &str,
) -> LdapResult<Vec<GpoLink>> {
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, "(gPLink=*)", vec!["name", "ou", "gPLink"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let gpo_dn_lower = gpo_dn.to_lowercase();
    let mut result = Vec::new();

    for e in entries {
        let e = SearchEntry::construct(e);
        let gp_link = attr(&e, "gPLink");
        for (dn, flags) in parse_gp_link(&gp_link) {
            if dn.to_lowercase() == gpo_dn_lower {
                let ou_name = {
                    let n = attr(&e, "ou");
                    if n.is_empty() { attr(&e, "name") } else { n }
                };
                let link_status = match flags {
                    1 => "Disabled",
                    2 => "Enforced",
                    3 => "Disabled + Enforced",
                    _ => "Enabled",
                }.to_string();
                result.push(GpoLink {
                    ou_dn: e.dn.clone(),
                    ou_name,
                    link_flags: flags,
                    link_status,
                });
                break;
            }
        }
    }

    Ok(result)
}

// ── link / unlink GPO ─────────────────────────────────────────────────────────

pub async fn link_gpo_to_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    gpo_dn: &str,
) -> LdapResult<()> {
    let (entries, _) = ldap
        .search(ou_dn, Scope::Base, "(objectClass=*)", vec!["gPLink"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let current = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "gPLink"))
        .unwrap_or_default();

    let gpo_dn_lower = gpo_dn.to_lowercase();
    let mut links = parse_gp_link(&current);

    if links.iter().any(|(dn, _)| dn.to_lowercase() == gpo_dn_lower) {
        return Ok(());
    }
    links.push((gpo_dn.to_string(), 0));
    let new_link = build_gp_link(&links);

    let mods: Vec<Mod<Vec<u8>>> =
        vec![Mod::Replace(sv("gPLink"), HashSet::from([sv(&new_link)]))];
    ldap.modify(ou_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to link GPO: {}", e))?;

    Ok(())
}

pub async fn unlink_gpo_from_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    gpo_dn: &str,
) -> LdapResult<()> {
    let (entries, _) = ldap
        .search(ou_dn, Scope::Base, "(objectClass=*)", vec!["gPLink"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let current = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "gPLink"))
        .unwrap_or_default();

    let gpo_dn_lower = gpo_dn.to_lowercase();
    let links: Vec<(String, u8)> = parse_gp_link(&current)
        .into_iter()
        .filter(|(dn, _)| dn.to_lowercase() != gpo_dn_lower)
        .collect();

    let mods: Vec<Mod<Vec<u8>>> = if links.is_empty() {
        vec![Mod::Delete(sv("gPLink"), HashSet::new())]
    } else {
        let new_link = build_gp_link(&links);
        vec![Mod::Replace(sv("gPLink"), HashSet::from([sv(&new_link)]))]
    };

    ldap.modify(ou_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to unlink GPO: {}", e))?;

    Ok(())
}

// ── delete record ─────────────────────────────────────────────────────────────

pub async fn delete_dns_record(
    ldap: &mut ldap3::Ldap,
    zone_dn: &str,
    node_name: &str,
    raw_hex: &str,
) -> LdapResult<()> {
    let raw_bytes =
        from_hex(raw_hex).ok_or_else(|| "Invalid record data".to_string())?;
    let node_dn = format!("DC={},{}", node_name, zone_dn);

    let mods: Vec<Mod<Vec<u8>>> =
        vec![Mod::Delete(sv("dnsRecord"), HashSet::from([raw_bytes]))];
    ldap.modify(&node_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete record: {}", e))?;
    Ok(())
}
