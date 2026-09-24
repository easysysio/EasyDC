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
    pub locked: bool,
    pub bad_pwd_count: i64,
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

pub(crate) fn base_dn_to_domain(base_dn: &str) -> String {
    base_dn
        .split(',')
        .filter_map(|part| {
            let p = part.trim();
            p.strip_prefix("dc=").or_else(|| p.strip_prefix("DC="))
        })
        .collect::<Vec<_>>()
        .join(".")
}

pub(crate) fn attr(e: &SearchEntry, key: &str) -> String {
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
                "lockoutTime",
                "badPwdCount",
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
            // lockoutTime is a FILETIME; any non-zero value means the account
            // is currently locked out.
            let lockout: i64 = attr(&e, "lockoutTime").parse().unwrap_or(0);
            LdapUser {
                dn: e.dn.clone(),
                username: attr(&e, "sAMAccountName"),
                first_name: attr(&e, "givenName"),
                last_name: attr(&e, "sn"),
                display_name: attr(&e, "displayName"),
                email: attr(&e, "mail"),
                enabled: (uac & 2) == 0,
                locked: lockout != 0,
                bad_pwd_count: attr(&e, "badPwdCount").parse().unwrap_or(0),
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

// ── reset password ─────────────────────────────────────────────────────────────

/// Set a new password for a user. Requires an LDAPS (or sign/seal) connection,
/// same as initial password set. When `force_change` is true the user must
/// change the password at next logon (pwdLastSet=0); otherwise it is marked as
/// freshly set (pwdLastSet=-1).
pub async fn reset_password(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    new_password: &str,
    force_change: bool,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    let pwd_last_set = if force_change { "0" } else { "-1" };
    let mods: Vec<Mod<Vec<u8>>> = vec![
        Mod::Replace(sv("unicodePwd"), HashSet::from([encode_password(new_password)])),
        Mod::Replace(sv("pwdLastSet"), HashSet::from([sv(pwd_last_set)])),
    ];
    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to reset password (requires LDAPS): {}", e))?;
    Ok(())
}

// ── unlock account ─────────────────────────────────────────────────────────────

/// Clear an account lockout by resetting lockoutTime to 0.
pub async fn unlock_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    let mods: Vec<Mod<Vec<u8>>> =
        vec![Mod::Replace(sv("lockoutTime"), HashSet::from([sv("0")]))];
    ldap.modify(&dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to unlock account: {}", e))?;
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
                    locked: false, // lock status not shown in member lists
                    bad_pwd_count: 0,
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

// Samba stores name-based DNS records (PTR, NS, CNAME, MX, SRV targets) using
// the DNS_COUNT_NAME / dnsp_name format (MS-DNSP):
//   [total_len: u8][label_count: u8] then for each label [len: u8][bytes] and
//   a trailing 0x00 root byte. total_len is the byte length of the label
//   section including the length bytes and the trailing null (i.e. everything
//   after the count byte). e.g. "example.com" -> [13][2][7]example[3]com[0]
fn encode_dns_rpc_name(name: &str) -> Vec<u8> {
    let name = name.trim_end_matches('.');
    if name.is_empty() || name == "@" {
        // root / apex: zero labels, just the trailing null
        return vec![1, 0, 0];
    }
    let mut raw = Vec::new();
    let mut count: u8 = 0;
    for label in name.split('.') {
        raw.push(label.len() as u8);
        raw.extend_from_slice(label.as_bytes());
        count += 1;
    }
    raw.push(0); // trailing root label
    let mut out = Vec::with_capacity(raw.len() + 2);
    out.push(raw.len() as u8); // total_len
    out.push(count); // label count
    out.extend_from_slice(&raw);
    out
}

fn parse_dns_rpc_name(data: &[u8]) -> String {
    if data.len() < 2 {
        return ".".to_string();
    }
    let count = data[1] as usize;
    let mut pos = 2;
    let mut labels = Vec::with_capacity(count);
    for _ in 0..count {
        if pos >= data.len() {
            break;
        }
        let len = data[pos] as usize;
        pos += 1;
        if len == 0 || pos + len > data.len() {
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
pub(crate) fn parse_dns_record_binary(data: &[u8]) -> Option<(String, String, u32)> {
    if data.len() < 24 {
        return None;
    }
    let data_len = u16::from_le_bytes([data[0], data[1]]) as usize;
    let record_type = u16::from_le_bytes([data[2], data[3]]);
    if record_type == 0 {
        return None; // tombstone record
    }
    // dwTtlSeconds is stored big-endian in dnsRecord (MS-DNSP / Samba quirk)
    let ttl = u32::from_be_bytes([data[12], data[13], data[14], data[15]]);
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
        2 => ("NS".to_string(), parse_dns_rpc_name(payload)),
        5 => ("CNAME".to_string(), parse_dns_rpc_name(payload)),
        6 => ("SOA".to_string(), "(zone authority)".to_string()),
        12 => ("PTR".to_string(), parse_dns_rpc_name(payload)),
        15 if payload.len() >= 2 => {
            let priority = u16::from_le_bytes([payload[0], payload[1]]);
            let name = parse_dns_rpc_name(&payload[2..]);
            ("MX".to_string(), format!("{} {}", priority, name))
        }
        16 => ("TXT".to_string(), parse_txt_bytes(payload)),
        33 if payload.len() >= 6 => {
            let priority = u16::from_le_bytes([payload[0], payload[1]]);
            let weight = u16::from_le_bytes([payload[2], payload[3]]);
            let port = u16::from_le_bytes([payload[4], payload[5]]);
            let target = parse_dns_rpc_name(&payload[6..]);
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
        "NS" => (2, encode_dns_rpc_name(value)),
        "CNAME" => (5, encode_dns_rpc_name(value)),
        "PTR" => (12, encode_dns_rpc_name(value)),
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
            let mut d = priority.to_le_bytes().to_vec();
            d.extend(encode_dns_rpc_name(name));
            (15, d)
        }
        _ => return Err(format!("Unsupported type: {}", record_type)),
    };

    Ok(wrap_dns_record(rtype, 0, ttl, data))
}

/// dnsp_DnssrvRpcRecord header (MS-DNSP, as Samba stores it in dnsRecord):
///   u16 wDataLength | u16 wType | u8 version | u8 rank | u16 flags |
///   u32 dwSerial | u32 dwTtlSeconds (BIG ENDIAN) | u32 dwReserved |
///   u32 dwTimeStamp | data…
/// version must be 5 and rank must be 0xF0 (DNS_RANK_ZONE) or Samba will not
/// treat the value as a live zone record (shows up as Records=0).
fn wrap_dns_record(rtype: u16, serial: u32, ttl: u32, data: Vec<u8>) -> Vec<u8> {
    let mut rec = Vec::new();
    rec.extend_from_slice(&(data.len() as u16).to_le_bytes()); // wDataLength
    rec.extend_from_slice(&rtype.to_le_bytes());               // wType
    rec.push(5); // version
    rec.push(0xF0); // rank = DNS_RANK_ZONE
    rec.extend_from_slice(&0u16.to_le_bytes()); // flags
    rec.extend_from_slice(&serial.to_le_bytes()); // dwSerial
    rec.extend_from_slice(&ttl.to_be_bytes()); // dwTtlSeconds (big-endian)
    rec.extend_from_slice(&0u32.to_le_bytes()); // dwReserved
    rec.extend_from_slice(&0u32.to_le_bytes()); // dwTimeStamp (0 = static)
    rec.extend(data);
    rec
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
            // ldap3 may lowercase attribute names; check both casings
            let raw_records: Vec<Vec<u8>> = e
                .bin_attrs
                .get("dnsRecord")
                .or_else(|| e.bin_attrs.get("dnsrecord"))
                .cloned()
                .unwrap_or_default();

            let records: Vec<DnsRecord> = raw_records
                .iter()
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
                .collect();

            if records.is_empty() && raw_records.is_empty() {
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

// ═══════════════════════════════════════════════════════════════════════════
// Organizational Units
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct LdapOuNode {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub depth: usize,
}

fn ou_depth(dn: &str, base_dn: &str) -> usize {
    let dn_parts = dn.split(',').count();
    let base_parts = base_dn.split(',').count();
    dn_parts.saturating_sub(base_parts + 1)
}

fn dn_tree_sort_key(dn: &str) -> String {
    dn.split(',')
        .rev()
        .map(|s| s.trim().to_lowercase())
        .collect::<Vec<_>>()
        .join(",")
}

// ── list OUs (tree order) ─────────────────────────────────────────────────────

pub async fn list_ous_tree(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<Vec<LdapOuNode>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["ou", "description"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut nodes: Vec<LdapOuNode> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            LdapOuNode {
                depth: ou_depth(&e.dn, base_dn),
                name: attr(&e, "ou"),
                description: attr(&e, "description"),
                dn: e.dn.clone(),
            }
        })
        .filter(|o| !o.name.is_empty())
        .collect();

    nodes.sort_by(|a, b| dn_tree_sort_key(&a.dn).cmp(&dn_tree_sort_key(&b.dn)));
    Ok(nodes)
}

// ── create OU ─────────────────────────────────────────────────────────────────

pub async fn create_ou(
    ldap: &mut ldap3::Ldap,
    parent_dn: &str,
    name: &str,
    description: &str,
) -> LdapResult<()> {
    let ou_dn = format!("OU={},{}", name, parent_dn);
    let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (
            sv("objectClass"),
            HashSet::from([sv("top"), sv("organizationalUnit")]),
        ),
        (sv("ou"), HashSet::from([sv(name)])),
    ];
    if !description.is_empty() {
        attrs.push((sv("description"), HashSet::from([sv(description)])));
    }

    ldap.add(&ou_dn, attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to create OU: {}", e))?;
    Ok(())
}

// ── rename OU ─────────────────────────────────────────────────────────────────

pub async fn rename_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    new_name: &str,
) -> LdapResult<()> {
    let new_rdn = format!("OU={}", new_name);
    ldap.modifydn(ou_dn, &new_rdn, true, None)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to rename OU: {}", e))?;
    Ok(())
}

// ── delete OU ─────────────────────────────────────────────────────────────────

pub async fn delete_ou(ldap: &mut ldap3::Ldap, ou_dn: &str) -> LdapResult<()> {
    ldap.delete(ou_dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete OU (must be empty): {}", e))?;
    Ok(())
}

// ── move object to OU ─────────────────────────────────────────────────────────

pub async fn move_object_to_ou(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    sam_account: &str,
    target_ou_dn: &str,
) -> LdapResult<()> {
    // Find the object by sAMAccountName
    let filter = format!("(sAMAccountName={})", sam_account);
    let (entries, _) = ldap
        .search(base_dn, Scope::Subtree, &filter, vec!["cn"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let entry = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("Object '{}' not found", sam_account))?;

    // Extract the RDN (first component of DN, e.g. "CN=JohnDoe")
    let rdn = entry
        .dn
        .split(',')
        .next()
        .ok_or_else(|| "Invalid DN".to_string())?
        .to_string();

    ldap.modifydn(&entry.dn, &rdn, true, Some(target_ou_dn))
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to move object: {}", e))?;

    Ok(())
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

// ── domain password policy ────────────────────────────────────────────────────
//
// What `samba-tool domain passwordsettings` reads and writes: plain attributes
// on the domain head. Durations are stored as negative 100-nanosecond
// intervals, and i64::MIN means "never" (for a lockout duration, "until an
// administrator unlocks").

pub const PWD_COMPLEX: i64 = 0x1;

#[derive(Debug, Serialize, Clone, Default)]
pub struct PasswordPolicy {
    pub min_length: i64,
    pub complexity: bool,
    pub history: i64,
    /// 0 means passwords never expire.
    pub max_age_days: i64,
    pub min_age_days: i64,
    /// 0 disables lockout entirely.
    pub lockout_threshold: i64,
    /// 0 means locked until an administrator unlocks the account.
    pub lockout_minutes: i64,
    pub observation_minutes: i64,
    pub machine_account_quota: i64,
}

/// A stored interval to whole units; "never" and unset both read as 0.
fn interval_to_units(raw: i64, seconds_per_unit: i64) -> i64 {
    if raw == i64::MIN || raw == 0 {
        return 0;
    }
    raw.saturating_neg() / 10_000_000 / seconds_per_unit
}

/// Whole units back to a stored interval; 0 becomes "never".
fn units_to_interval(units: i64, seconds_per_unit: i64) -> i64 {
    if units <= 0 {
        return i64::MIN;
    }
    -(units * seconds_per_unit * 10_000_000)
}

pub async fn get_password_policy(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<PasswordPolicy> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Base,
            "(objectClass=*)",
            vec![
                "minPwdLength",
                "pwdProperties",
                "pwdHistoryLength",
                "maxPwdAge",
                "minPwdAge",
                "lockoutThreshold",
                "lockoutDuration",
                "lockOutObservationWindow",
                "ms-DS-MachineAccountQuota",
            ],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| "Could not read the domain object".to_string())?;
    let num = |k: &str| attr(&e, k).parse::<i64>().unwrap_or(0);

    Ok(PasswordPolicy {
        min_length: num("minPwdLength"),
        complexity: (num("pwdProperties") & PWD_COMPLEX) != 0,
        history: num("pwdHistoryLength"),
        max_age_days: interval_to_units(num("maxPwdAge"), 86_400),
        min_age_days: interval_to_units(num("minPwdAge"), 86_400),
        lockout_threshold: num("lockoutThreshold"),
        lockout_minutes: interval_to_units(num("lockoutDuration"), 60),
        observation_minutes: interval_to_units(num("lockOutObservationWindow"), 60),
        machine_account_quota: num("ms-DS-MachineAccountQuota"),
    })
}

/// Reject what the directory would reject anyway, plus the combinations that
/// are accepted but nonsensical, before anything is written.
pub fn validate_password_policy(p: &PasswordPolicy) -> LdapResult<()> {
    if !(0..=255).contains(&p.min_length) {
        return Err("Minimum length must be between 0 and 255".to_string());
    }
    if !(0..=1024).contains(&p.history) {
        return Err("Password history must be between 0 and 1024".to_string());
    }
    if p.max_age_days < 0 || p.min_age_days < 0 {
        return Err("Password ages cannot be negative".to_string());
    }
    if p.max_age_days > 0 && p.min_age_days >= p.max_age_days {
        return Err("Minimum age must be shorter than maximum age".to_string());
    }
    if !(0..=999).contains(&p.lockout_threshold) {
        return Err("Lockout threshold must be between 0 and 999".to_string());
    }
    if p.lockout_minutes < 0 || p.observation_minutes < 0 {
        return Err("Lockout times cannot be negative".to_string());
    }
    // The directory enforces this one; catching it here gives a better message.
    if p.lockout_minutes > 0 && p.observation_minutes > p.lockout_minutes {
        return Err(
            "The observation window must not be longer than the lockout duration".to_string(),
        );
    }
    if p.machine_account_quota < 0 {
        return Err("Machine account quota cannot be negative".to_string());
    }
    Ok(())
}

pub async fn set_password_policy(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    p: &PasswordPolicy,
) -> LdapResult<()> {
    validate_password_policy(p)?;

    // pwdProperties carries other flags too, so flip only the complexity bit.
    let (entries, _) = ldap
        .search(base_dn, Scope::Base, "(objectClass=*)", vec!["pwdProperties"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    let raw_props = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "pwdProperties").parse::<i64>().unwrap_or(0))
        .unwrap_or(0);
    let props = if p.complexity {
        raw_props | PWD_COMPLEX
    } else {
        raw_props & !PWD_COMPLEX
    };
    let set = |v: String| HashSet::from([sv(&v)]);
    let mods = vec![
        Mod::Replace(sv("minPwdLength"), set(p.min_length.to_string())),
        Mod::Replace(sv("pwdProperties"), set(props.to_string())),
        Mod::Replace(sv("pwdHistoryLength"), set(p.history.to_string())),
        Mod::Replace(
            sv("maxPwdAge"),
            set(units_to_interval(p.max_age_days, 86_400).to_string()),
        ),
        Mod::Replace(
            sv("minPwdAge"),
            set(if p.min_age_days == 0 {
                "0".to_string()
            } else {
                units_to_interval(p.min_age_days, 86_400).to_string()
            }),
        ),
        Mod::Replace(sv("lockoutThreshold"), set(p.lockout_threshold.to_string())),
        Mod::Replace(
            sv("lockoutDuration"),
            set(units_to_interval(p.lockout_minutes, 60).to_string()),
        ),
        Mod::Replace(
            sv("lockOutObservationWindow"),
            set(units_to_interval(p.observation_minutes, 60).to_string()),
        ),
        Mod::Replace(
            sv("ms-DS-MachineAccountQuota"),
            set(p.machine_account_quota.to_string()),
        ),
    ];

    ldap.modify(base_dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to update the password policy: {}", e))?;
    Ok(())
}

// ── zone create / delete ──────────────────────────────────────────────────────
//
// A zone is a dnsZone object holding dNSProperty settings, plus an "@" dnsNode
// carrying the SOA and NS records. Samba's own tooling writes these through the
// DNS server's RPC pipe; EasyDC speaks only LDAP, and writing the objects
// directly works — a zone created this way is served immediately, by every DC
// in the domain, with no restart. Deleting one is NOT picked up by the running
// DNS server, which keeps answering authoritatively for the removed zone until
// samba restarts; the UI says so before it deletes anything.
//
// Every byte layout below was verified against zones Samba created (see tests).

/// SOA data: five big-endian counters, then the primary server and the
/// responsible party as DNS_COUNT_NAMEs.
fn build_soa_record(primary: &str, hostmaster: &str, serial: u32, ttl: u32) -> Vec<u8> {
    let mut d = Vec::new();
    for v in [serial, 900u32, 600, 86_400, 3_600] {
        d.extend_from_slice(&v.to_be_bytes());
    }
    d.extend(encode_dns_rpc_name(primary));
    d.extend(encode_dns_rpc_name(hostmaster));
    wrap_dns_record(6, serial, ttl, d)
}

/// DNS_PROPERTY: dwDataLength, dwNameLength, dwFlag, dwVersion, dwId, the data,
/// then four zero bytes for the empty name.
fn build_dns_property(id: u32, data: &[u8]) -> Vec<u8> {
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
/// dynamic update, default refresh intervals, aging off. Synthesised rather
/// than copied from a neighbouring zone, so one zone with aging switched on
/// cannot silently pass that on to every zone created afterwards.
fn primary_zone_properties() -> Vec<Vec<u8>> {
    let u32d = |v: u32| v.to_le_bytes().to_vec();
    vec![
        build_dns_property(0x01, &u32d(1)),   // ZONE_TYPE = primary
        build_dns_property(0x02, &[2u8]),     // ALLOW_UPDATE = secure
        build_dns_property(0x08, &[0u8; 8]),  // SECURE_TIME
        build_dns_property(0x10, &u32d(168)), // NOREFRESH_INTERVAL, hours
        build_dns_property(0x20, &u32d(168)), // REFRESH_INTERVAL, hours
        build_dns_property(0x40, &u32d(0)),   // AGING_STATE = off
        build_dns_property(0x12, &u32d(0)),   // AGING_ENABLED_TIME
    ]
}

/// Turn a network into its in-addr.arpa zone name: "192.168.10" or
/// "192.168.10.0/24" both give "10.168.192.in-addr.arpa". Returns None for
/// anything that is not an IPv4 network, so a name typed in full passes
/// through untouched.
pub fn reverse_zone_name(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_end_matches('.');
    let (addr, prefix) = match trimmed.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (trimmed, None),
    };

    let octets: Vec<&str> = addr.split('.').filter(|o| !o.is_empty()).collect();
    if octets.is_empty() || octets.len() > 4 {
        return None;
    }
    for o in &octets {
        if o.parse::<u8>().is_err() {
            return None;
        }
    }

    // With a prefix, keep the octets it covers; without one, keep what was
    // typed (a trailing .0 being the network is the common shorthand).
    let keep = match prefix {
        Some(8) => 1,
        Some(16) => 2,
        Some(24) => 3,
        Some(_) => return None,
        None => {
            if octets.len() == 4 && octets[3] == "0" {
                3
            } else {
                octets.len()
            }
        }
    };
    if keep > octets.len() {
        return None;
    }

    let mut parts: Vec<&str> = octets[..keep].to_vec();
    parts.reverse();
    Some(format!("{}.in-addr.arpa", parts.join(".")))
}

/// Reject anything that is not a plausible DNS zone name before it reaches the
/// directory, where a bad name becomes a malformed object.
pub fn validate_zone_name(zone: &str) -> LdapResult<()> {
    if zone.is_empty() {
        return Err("Zone name is required".to_string());
    }
    if zone.len() > 255 {
        return Err("Zone name is too long".to_string());
    }
    if zone.starts_with('.') || zone.ends_with('.') {
        return Err("Zone name must not start or end with a dot".to_string());
    }
    if zone.contains("..") {
        return Err("Zone name must not contain an empty label".to_string());
    }
    if !zone.contains('.') {
        return Err("Zone name must be fully qualified, for example example.com".to_string());
    }
    for label in zone.split('.') {
        if label.len() > 63 {
            return Err(format!("Label '{}' is longer than 63 characters", label));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!("Label '{}' has characters that are not allowed", label));
        }
    }
    Ok(())
}

/// The DNS partition holding this domain's zones. Zones can live in any of
/// three places, so a new zone goes wherever the existing ones are.
pub async fn dns_partition_dn(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<String> {
    let candidates = [
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
        format!("DC=DomainDnsZones,{}", base_dn),
    ];
    for base in &candidates {
        if let Ok(Ok((entries, _))) = ldap
            .search(base, Scope::Base, "(objectClass=*)", vec!["dn"])
            .await
            .map(|r| r.success())
        {
            if !entries.is_empty() {
                return Ok(base.clone());
            }
        }
    }
    Err("Could not find the DNS partition on this server".to_string())
}

/// Every domain controller's FQDN. A DC's computer account carries
/// SERVER_TRUST_ACCOUNT (0x2000) in userAccountControl, which identifies them
/// in one search without walking the configuration partition.
///
/// A new zone gets an NS record for each: zones live in a partition replicated
/// to all of them, so they all answer for it, and every zone Samba creates
/// lists them all. Registering only the DC that happened to create the zone
/// would leave it inconsistent with the rest of the domain.
pub async fn list_dc_hostnames(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<String>> {
    let (entries, _) = ldap
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            vec!["dNSHostName"],
        )
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut hosts: Vec<String> = entries
        .into_iter()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "dNSHostName"))
        .filter(|h| !h.is_empty())
        .collect();
    hosts.sort_by_key(|h| h.to_lowercase());
    hosts.dedup_by_key(|h| h.to_lowercase());
    Ok(hosts)
}

/// This DC's own fully-qualified name, from the rootDSE. It becomes the SOA
/// primary server.
pub async fn dc_hostname(ldap: &mut ldap3::Ldap) -> LdapResult<String> {
    let (entries, _) = ldap
        .search("", Scope::Base, "(objectClass=*)", vec!["dnsHostName"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;
    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "dnsHostName"))
        .filter(|h| !h.is_empty())
        .ok_or_else(|| "Could not read the DC's dnsHostName".to_string())
}

/// Create a primary, AD-integrated zone: the dnsZone object with its
/// properties, and an apex node holding SOA and NS.
pub async fn create_dns_zone(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    zone: &str,
) -> LdapResult<()> {
    validate_zone_name(zone)?;

    if find_zone_dn(ldap, base_dn, zone).await.is_ok() {
        return Err(format!("Zone '{}' already exists", zone));
    }

    let partition = dns_partition_dn(ldap, base_dn).await?;
    let primary = dc_hostname(ldap).await?;
    let hostmaster = format!("hostmaster.{}", base_dn_to_domain(base_dn));

    let zone_dn = format!("DC={},{}", zone, partition);
    let props: HashSet<Vec<u8>> = primary_zone_properties().into_iter().collect();
    let zone_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsZone")])),
        (sv("dc"), HashSet::from([sv(zone)])),
        (sv("dNSProperty"), props),
    ];
    ldap.add(&zone_dn, zone_attrs)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to create zone: {}", e))?;

    // The apex. If this fails the zone object is already there, so it is
    // removed again rather than left as a zone with no SOA.
    let node_dn = format!("DC=@,{}", zone_dn);

    // Every DC serves this zone, so every DC belongs in the NS set. If the
    // lookup finds nothing, fall back to the one we are talking to rather than
    // creating a zone with no NS at all.
    let mut nameservers = list_dc_hostnames(ldap, base_dn).await.unwrap_or_default();
    if nameservers.is_empty() {
        nameservers.push(primary.clone());
    }

    let mut recs: HashSet<Vec<u8>> = HashSet::from([build_soa_record(&primary, &hostmaster, 1, 3600)]);
    for ns in &nameservers {
        recs.insert(wrap_dns_record(2, 1, 3600, encode_dns_rpc_name(ns)));
    }
    let node_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsNode")])),
        (sv("dc"), HashSet::from([sv("@")])),
        (sv("dnsRecord"), recs),
    ];
    if let Err(e) = ldap
        .add(&node_dn, node_attrs)
        .await
        .map_err(|e| e.to_string())
        .and_then(|r| r.success().map_err(|e| e.to_string()))
    {
        let _ = ldap.delete(&zone_dn).await;
        return Err(format!("Failed to create the zone's apex records: {}", e));
    }

    Ok(())
}

/// Delete a zone and everything in it. LDAP will not remove an object that
/// still has children, so the nodes go first; the tree-delete control is
/// deliberately not used, so nothing can be removed beyond this zone.
pub async fn delete_dns_zone(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    zone: &str,
) -> LdapResult<usize> {
    // Deleting the realm's own zone takes the SRV records every domain member
    // uses to find a DC with it, so it is refused outright rather than left to
    // a confirmation dialog.
    let domain = base_dn_to_domain(base_dn);
    let lower = zone.to_lowercase();
    if lower == domain.to_lowercase() {
        return Err(format!(
            "'{}' is the domain's own zone and cannot be deleted from EasyDC",
            zone
        ));
    }
    if lower.starts_with("_msdcs.") || lower == "rootdnsservers" {
        return Err(format!("'{}' is an internal zone and cannot be deleted", zone));
    }

    let zone_dn = find_zone_dn(ldap, base_dn, zone).await?;

    let (entries, _) = ldap
        .search(&zone_dn, Scope::OneLevel, "(objectClass=*)", vec!["dc"])
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| e.to_string())?;

    let mut removed = 0usize;
    for e in entries {
        let dn = SearchEntry::construct(e).dn;
        ldap.delete(&dn)
            .await
            .map_err(|e| e.to_string())?
            .success()
            .map_err(|err| format!("Failed to delete {}: {}", dn, err))?;
        removed += 1;
    }

    ldap.delete(&zone_dn)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map_err(|e| format!("Failed to delete zone: {}", e))?;

    Ok(removed)
}

#[cfg(test)]
mod dns_name_tests {
    use super::*;

    #[test]
    fn encode_dnsp_name_matches_ms_dnsp_layout() {
        // "example.com" -> [13][2][7]example[3]com[0]
        let got = encode_dns_rpc_name("example.com");
        let mut want = vec![13u8, 2, 7];
        want.extend_from_slice(b"example");
        want.push(3);
        want.extend_from_slice(b"com");
        want.push(0);
        assert_eq!(got, want);
    }

    #[test]
    fn encode_strips_trailing_dot() {
        assert_eq!(encode_dns_rpc_name("host.lan."), encode_dns_rpc_name("host.lan"));
    }

    #[test]
    fn roundtrip_ptr_target() {
        let name = "win10.hakim.family";
        assert_eq!(parse_dns_rpc_name(&encode_dns_rpc_name(name)), name);
    }

    #[test]
    fn ptr_record_header_is_valid_zone_record() {
        let rec = build_dns_record_binary("PTR", "easylog.hakim.family", 3600).unwrap();
        // wType = 12 (PTR), little-endian
        assert_eq!(u16::from_le_bytes([rec[2], rec[3]]), 12);
        // version = 5, rank = DNS_RANK_ZONE (0xF0) — required or Samba shows Records=0
        assert_eq!(rec[4], 5);
        assert_eq!(rec[5], 0xF0);
        // dwTtlSeconds is big-endian
        assert_eq!(u32::from_be_bytes([rec[12], rec[13], rec[14], rec[15]]), 3600);
    }

    #[test]
    fn ptr_record_roundtrips_through_parse() {
        let rec = build_dns_record_binary("PTR", "easylog.hakim.family", 3600).unwrap();
        let (rtype, value, ttl) = parse_dns_record_binary(&rec).unwrap();
        assert_eq!(rtype, "PTR");
        assert_eq!(value, "easylog.hakim.family");
        assert_eq!(ttl, 3600);
    }
}

#[cfg(test)]
mod zone_tests {
    use super::*;

    /// The SOA Samba itself stores for 9.168.192.in-addr.arpa on a live DC:
    /// serial 2, TTL 3600, refresh 900, retry 600, expire 86400, minimum 3600,
    /// primary dc1.hakim.family, responsible party hostmaster.hakim.family.
    /// Building the same record from scratch must reproduce it byte for byte.
    const REAL_SOA: &str = "4300060005f000000200000000000e1000000000000000000000000200000384000002580001518000000e101203036463310568616b696d0666616d696c790019030a686f73746d61737465720568616b696d0666616d696c7900";

    #[test]
    fn soa_matches_what_samba_stores() {
        let built = build_soa_record("dc1.hakim.family", "hostmaster.hakim.family", 2, 3600);
        assert_eq!(to_hex(&built), REAL_SOA);
    }

    #[test]
    fn soa_counters_are_big_endian_and_type_is_6() {
        let rec = build_soa_record("dc1.example.com", "hostmaster.example.com", 7, 3600);
        assert_eq!(u16::from_le_bytes([rec[2], rec[3]]), 6); // wType = SOA
        assert_eq!(rec[4], 5); // version
        assert_eq!(rec[5], 0xF0); // DNS_RANK_ZONE
        assert_eq!(u32::from_be_bytes([rec[12], rec[13], rec[14], rec[15]]), 3600); // TTL
        assert_eq!(u32::from_be_bytes([rec[24], rec[25], rec[26], rec[27]]), 7); // serial
        assert_eq!(u32::from_be_bytes([rec[28], rec[29], rec[30], rec[31]]), 900); // refresh
    }

    /// Likewise the ZONE_TYPE property, as stored by Samba.
    #[test]
    fn zone_type_property_matches_samba() {
        let p = build_dns_property(0x01, &1u32.to_le_bytes());
        assert_eq!(to_hex(&p), "04000000000000000000000001000000010000000100000000000000");
    }

    #[test]
    fn a_new_zone_is_primary_with_secure_update() {
        let props = primary_zone_properties();
        assert_eq!(props.len(), 7);
        let id_of = |p: &Vec<u8>| u32::from_le_bytes([p[16], p[17], p[18], p[19]]);
        let by_id = |id: u32| props.iter().find(|p| id_of(p) == id).cloned().unwrap();

        let zone_type = by_id(0x01);
        assert_eq!(zone_type[20], 1, "DNS_ZONE_TYPE_PRIMARY");
        let allow_update = by_id(0x02);
        assert_eq!(allow_update[20], 2, "secure dynamic update");
        let aging = by_id(0x40);
        assert_eq!(aging[20], 0, "aging off");
    }

    #[test]
    fn reverse_zone_names_from_networks() {
        let r = |s: &str| reverse_zone_name(s).unwrap();
        assert_eq!(r("192.168.10"), "10.168.192.in-addr.arpa");
        assert_eq!(r("192.168.10.0/24"), "10.168.192.in-addr.arpa");
        assert_eq!(r("192.168.10.0"), "10.168.192.in-addr.arpa");
        assert_eq!(r("192.168.0.0/16"), "168.192.in-addr.arpa");
        assert_eq!(r("10.0.0.0/8"), "10.in-addr.arpa");
        assert_eq!(r("192.168"), "168.192.in-addr.arpa");
    }

    #[test]
    fn reverse_zone_rejects_things_that_are_not_networks() {
        assert!(reverse_zone_name("example.com").is_none());
        assert!(reverse_zone_name("192.168.300").is_none());
        assert!(reverse_zone_name("192.168.1.2.3").is_none());
        assert!(reverse_zone_name("").is_none());
        // A prefix length that does not fall on an octet boundary has no
        // in-addr.arpa name.
        assert!(reverse_zone_name("192.168.10.0/25").is_none());
    }

    #[test]
    fn zone_names_are_validated() {
        assert!(validate_zone_name("example.com").is_ok());
        assert!(validate_zone_name("10.168.192.in-addr.arpa").is_ok());
        assert!(validate_zone_name("_msdcs.example.com").is_ok());

        assert!(validate_zone_name("").is_err());
        assert!(validate_zone_name("singlelabel").is_err());
        assert!(validate_zone_name(".example.com").is_err());
        assert!(validate_zone_name("example.com.").is_err());
        assert!(validate_zone_name("exa mple.com").is_err());
        assert!(validate_zone_name("example..com").is_err());
        assert!(validate_zone_name(&format!("{}.com", "a".repeat(64))).is_err());
    }
}

#[cfg(test)]
mod password_policy_tests {
    use super::*;

    #[test]
    fn stored_intervals_round_trip() {
        // Samba's default maximum age.
        assert_eq!(interval_to_units(-36_288_000_000_000, 86_400), 42);
        assert_eq!(units_to_interval(42, 86_400), -36_288_000_000_000);
        // 30 minutes of lockout.
        assert_eq!(interval_to_units(-18_000_000_000, 60), 30);
        assert_eq!(units_to_interval(30, 60), -18_000_000_000);
    }

    #[test]
    fn never_reads_as_zero_and_writes_back_as_never() {
        assert_eq!(interval_to_units(i64::MIN, 86_400), 0);
        assert_eq!(interval_to_units(0, 86_400), 0);
        assert_eq!(units_to_interval(0, 86_400), i64::MIN);
    }

    fn sane() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 8,
            complexity: true,
            history: 24,
            max_age_days: 42,
            min_age_days: 1,
            lockout_threshold: 5,
            lockout_minutes: 30,
            observation_minutes: 30,
            machine_account_quota: 0,
        }
    }

    #[test]
    fn a_sane_policy_validates() {
        assert!(validate_password_policy(&sane()).is_ok());
    }

    #[test]
    fn rejects_policies_the_directory_would_refuse() {
        let mut p = sane();
        p.min_age_days = 60; // longer than the maximum age
        assert!(validate_password_policy(&p).is_err());

        let mut p = sane();
        p.observation_minutes = 60; // longer than the lockout duration
        assert!(validate_password_policy(&p).is_err());

        let mut p = sane();
        p.min_length = -1;
        assert!(validate_password_policy(&p).is_err());

        let mut p = sane();
        p.lockout_threshold = 1000;
        assert!(validate_password_policy(&p).is_err());
    }

    /// Passwords that never expire are a legitimate choice, so a zero maximum
    /// age must not be rejected — and a minimum age is then unconstrained.
    #[test]
    fn never_expiring_is_allowed() {
        let mut p = sane();
        p.max_age_days = 0;
        p.min_age_days = 7;
        assert!(validate_password_policy(&p).is_ok());
    }
}
