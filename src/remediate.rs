//! Guided fixes for health-check findings.
//!
//! Every fixable finding is computed here, by the same scans the health check
//! reports from, so there is one definition of "what needs fixing". A fix is
//! always re-planned from a fresh scan at the moment it is applied: the form
//! only carries opaque keys, and a key that is not in the fresh scan is skipped.
//! A stale page, a finding someone else has already fixed, or a hand-crafted
//! request can therefore never act on an object that no longer qualifies.
//!
//! Only reversible changes get a button: disabling a computer, removing a
//! group membership, clearing a flag, lowering a quota. Anything whose wrong
//! use is hard to undo — seizing an FSMO role, rewriting DNS, changing
//! dSHeuristics — stays as guidance in the report.

use ldap3::{Mod, Scope};
use serde::Serialize;
use std::collections::HashSet;

use crate::health::{attr_ci, attrs_ci, filetime_to_unix, int_ci, now_unix, rdn_value, read_one, search};
use crate::ldap::{self, LdapResult};

pub const STALE_DAYS: i64 = 90;

const UAC_DISABLED: i64 = 0x0002;
const UAC_PASSWD_NOTREQD: i64 = 0x0020;
const UAC_DONT_EXPIRE_PASSWORD: i64 = 0x1_0000;
const UAC_SERVER_TRUST_ACCOUNT: i64 = 0x2000;

pub const PRIVILEGED_GROUPS: [&str; 4] =
    ["Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators"];

// ── what the page offers ──────────────────────────────────────────────────────

/// A fix offered under a health-check finding.
#[derive(Debug, Serialize, Clone)]
pub struct Fix {
    pub kind: &'static str,
    /// The button, e.g. "Disable selected computers".
    pub label: String,
    /// What the fix does and how to undo it.
    pub explain: String,
    /// The objects it would change; empty for a fix with a single target.
    pub targets: Vec<FixTarget>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FixTarget {
    pub key: String,
    pub label: String,
}

/// A stable, opaque identifier for a target. Hashed so the form never carries
/// a DN the server would be tempted to parse; it is only ever compared with
/// the keys of a fresh scan. FNV-1a, 64 bits, with a separator between parts.
fn key_of(parts: &[&str]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            h ^= 0xff;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        for b in p.to_lowercase().bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
    }
    format!("{:016x}", h)
}

// ── scans ─────────────────────────────────────────────────────────────────────

pub struct StaleComputer {
    pub dn: String,
    pub name: String,
    pub days: i64,
    uac: i64,
    /// Domain controller accounts are reported but never offered for disabling.
    pub is_dc: bool,
}

impl StaleComputer {
    pub fn key(&self) -> String {
        key_of(&["stale", &self.dn])
    }
}

pub struct StaleScan {
    pub enabled: usize,
    /// Longest-idle first.
    pub stale: Vec<StaleComputer>,
}

/// Enabled computer accounts whose last logon is older than STALE_DAYS. An
/// account that has never recorded a logon is not evidence of staleness.
pub async fn stale_computers(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<StaleScan> {
    let entries = search(
        conn,
        base_dn,
        Scope::Subtree,
        "(objectClass=computer)",
        vec!["sAMAccountName", "lastLogonTimestamp", "userAccountControl"],
    )
    .await?;

    let now = now_unix();
    let cutoff = now - STALE_DAYS * 86_400;
    let mut enabled = 0usize;
    let mut stale = Vec::new();

    for e in &entries {
        let uac = int_ci(e, "userAccountControl");
        if (uac & UAC_DISABLED) != 0 {
            continue;
        }
        enabled += 1;
        let ts = int_ci(e, "lastLogonTimestamp");
        if ts == 0 {
            continue;
        }
        let last = filetime_to_unix(ts);
        if last < cutoff {
            stale.push(StaleComputer {
                dn: e.dn.clone(),
                name: attr_ci(e, "sAMAccountName"),
                days: (now - last) / 86_400,
                uac,
                is_dc: (uac & UAC_SERVER_TRUST_ACCOUNT) != 0,
            });
        }
    }
    stale.sort_by(|a, b| b.days.cmp(&a.days));
    Ok(StaleScan { enabled, stale })
}

/// A disabled account holding a privileged group's rights.
pub struct DisabledMember {
    pub user_dn: String,
    pub user_name: String,
    /// The privileged groups it holds, directly or through nesting.
    pub grants: Vec<String>,
    /// The groups it is directly a member of that confer those rights — where
    /// a removal has to happen. Empty when the rights come through the primary
    /// group, which is not a `member` value and cannot be removed that way.
    pub via: Vec<(String, String)>,
}

impl DisabledMember {
    pub fn removal_key(&self, group_dn: &str) -> String {
        key_of(&["unprivilege", &self.user_dn, group_dn])
    }
}

pub struct PrivilegedScan {
    pub lines: Vec<String>,
    pub total: usize,
    pub fell_back: bool,
    pub disabled: Vec<DisabledMember>,
}

/// Every account in the four privileged groups, nested groups expanded, and
/// among them the disabled ones with the direct memberships that grant them.
pub async fn privileged_members(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<PrivilegedScan> {
    let mut scan = PrivilegedScan { lines: Vec::new(), total: 0, fell_back: false, disabled: Vec::new() };

    for g in PRIVILEGED_GROUPS {
        let filter = format!("(&(objectClass=group)(sAMAccountName={}))", ldap::ldap_escape(g));
        let found = match search(conn, base_dn, Scope::Subtree, &filter, vec!["member"]).await {
            Ok(e) => e,
            Err(_) => continue,
        };
        let Some(group) = found.into_iter().next() else {
            continue;
        };

        // LDAP_MATCHING_RULE_IN_CHAIN has the server follow nesting, so a
        // disabled user inside a group that is itself in Domain Admins is found.
        let chain = format!(
            "(&(objectCategory=person)(memberOf:1.2.840.113556.1.4.1941:={}))",
            ldap::ldap_escape(&group.dn)
        );
        let (members, direct_only) = match search(
            conn,
            base_dn,
            Scope::Subtree,
            &chain,
            vec!["sAMAccountName", "userAccountControl", "memberOf"],
        )
        .await
        {
            Ok(m) => (m, false),
            Err(_) => {
                // A server without the matching rule: direct members only.
                scan.fell_back = true;
                let mut direct = Vec::new();
                for m in attrs_ci(&group, "member") {
                    if let Ok(me) = read_one(conn, &m, vec!["userAccountControl", "sAMAccountName"]).await {
                        direct.push(me);
                    }
                }
                (direct, true)
            }
        };

        scan.total += members.len();
        scan.lines.push(if direct_only {
            format!("{}: {} (direct only)", g, plural(attrs_ci(&group, "member").len(), "member", "members"))
        } else {
            format!("{}: {}", g, plural(members.len(), "account", "accounts"))
        });

        for me in &members {
            if (int_ci(me, "userAccountControl") & UAC_DISABLED) == 0 {
                continue;
            }

            // Which of the user's own memberships put them in this group: the
            // group itself, or a group nested inside it.
            let mut via: Vec<(String, String)> = Vec::new();
            if direct_only {
                via.push((group.dn.clone(), g.to_string()));
            } else {
                for m in attrs_ci(me, "memberOf") {
                    if m.eq_ignore_ascii_case(&group.dn) {
                        via.push((group.dn.clone(), g.to_string()));
                        continue;
                    }
                    let inside = format!(
                        "(memberOf:1.2.840.113556.1.4.1941:={})",
                        ldap::ldap_escape(&group.dn)
                    );
                    if let Ok(hit) = search(conn, &m, Scope::Base, &inside, vec!["cn"]).await {
                        if !hit.is_empty() {
                            via.push((m.clone(), rdn_value(&m)));
                        }
                    }
                }
            }

            let name = attr_ci(me, "sAMAccountName");
            let name = if name.is_empty() { rdn_value(&me.dn) } else { name };
            // The same user is found again under Administrators when they are
            // in Domain Admins; merge rather than list them twice.
            match scan.disabled.iter_mut().find(|d| d.user_dn.eq_ignore_ascii_case(&me.dn)) {
                Some(existing) => {
                    existing.grants.push(g.to_string());
                    for v in via {
                        if !existing.via.iter().any(|(dn, _)| dn.eq_ignore_ascii_case(&v.0)) {
                            existing.via.push(v);
                        }
                    }
                }
                None => scan.disabled.push(DisabledMember {
                    user_dn: me.dn.clone(),
                    user_name: name,
                    grants: vec![g.to_string()],
                    via,
                }),
            }
        }
    }
    Ok(scan)
}

pub struct FlaggedAccount {
    pub dn: String,
    pub name: String,
    uac: i64,
}

impl FlaggedAccount {
    pub fn key(&self) -> String {
        key_of(&["passwd_notreqd", &self.dn])
    }
}

pub struct PasswordFlagScan {
    pub enabled: usize,
    pub never_expires: Vec<String>,
    pub not_required: Vec<FlaggedAccount>,
    pub must_change: usize,
}

pub async fn password_flags(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<PasswordFlagScan> {
    let entries = search(
        conn,
        base_dn,
        Scope::Subtree,
        "(&(objectClass=user)(!(objectClass=computer)))",
        vec!["sAMAccountName", "userAccountControl", "pwdLastSet"],
    )
    .await?;

    let mut scan = PasswordFlagScan { enabled: 0, never_expires: Vec::new(), not_required: Vec::new(), must_change: 0 };
    for e in &entries {
        let uac = int_ci(e, "userAccountControl");
        if (uac & UAC_DISABLED) != 0 {
            continue;
        }
        scan.enabled += 1;
        let name = attr_ci(e, "sAMAccountName");
        if (uac & UAC_DONT_EXPIRE_PASSWORD) != 0 {
            scan.never_expires.push(name.clone());
        }
        if (uac & UAC_PASSWD_NOTREQD) != 0 {
            scan.not_required.push(FlaggedAccount { dn: e.dn.clone(), name, uac });
        }
        if int_ci(e, "pwdLastSet") == 0 {
            scan.must_change += 1;
        }
    }
    Ok(scan)
}

/// ms-DS-MachineAccountQuota, or None when the attribute is not set.
pub async fn machine_account_quota(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Option<i64>> {
    let e = read_one(conn, base_dn, vec!["ms-DS-MachineAccountQuota"]).await?;
    let raw = attr_ci(&e, "ms-DS-MachineAccountQuota");
    Ok(if raw.is_empty() { None } else { raw.parse().ok() })
}

pub const QUOTA_KEY: &str = "quota";

fn plural(n: usize, one: &str, many: &str) -> String {
    if n == 1 { format!("{} {}", n, one) } else { format!("{} {}", n, many) }
}

// ── offers, built from a scan ─────────────────────────────────────────────────

pub fn stale_computer_fix(scan: &StaleScan) -> Option<Fix> {
    let targets: Vec<FixTarget> = scan
        .stale
        .iter()
        .filter(|c| !c.is_dc)
        .map(|c| FixTarget { key: c.key(), label: format!("{} — last logon {} days ago", c.name, c.days) })
        .collect();
    (!targets.is_empty()).then(|| Fix {
        kind: "disable_stale_computers",
        label: "Disable selected computers".to_string(),
        explain: "Disabled accounts stop authenticating but keep their group memberships and settings. \
                  Re-enable one on the Computers page if the machine comes back."
            .to_string(),
        targets,
    })
}

pub fn privileged_fix(scan: &PrivilegedScan) -> Option<Fix> {
    let mut targets = Vec::new();
    for d in &scan.disabled {
        for (group_dn, group_name) in &d.via {
            let grants: Vec<&str> = d.grants.iter().map(String::as_str).collect();
            let label = if grants.len() == 1 && grants[0] == group_name {
                format!("Remove {} from {}", d.user_name, group_name)
            } else {
                format!("Remove {} from {} (grants {})", d.user_name, group_name, grants.join(", "))
            };
            targets.push(FixTarget { key: d.removal_key(group_dn), label });
        }
    }
    (!targets.is_empty()).then(|| Fix {
        kind: "remove_disabled_privileged",
        label: "Remove selected memberships".to_string(),
        explain: "Removes the membership that grants the rights. When it comes through a nested group, \
                  that is the group the account leaves — which also ends whatever else that group grants. \
                  Add the membership back on the Groups page to undo."
            .to_string(),
        targets,
    })
}

pub fn password_flag_fix(scan: &PasswordFlagScan) -> Option<Fix> {
    let targets: Vec<FixTarget> = scan
        .not_required
        .iter()
        .map(|a| FixTarget { key: a.key(), label: format!("{} — password not required", a.name) })
        .collect();
    (!targets.is_empty()).then(|| Fix {
        kind: "clear_passwd_notreqd",
        label: "Require a password on selected accounts".to_string(),
        explain: "Clears the PASSWD_NOTREQD flag. An account that currently has an empty password keeps it \
                  until it is next set, so reset its password afterwards."
            .to_string(),
        targets,
    })
}

pub fn quota_fix(quota: Option<i64>) -> Option<Fix> {
    match quota {
        Some(q) if q > 0 => Some(Fix {
            kind: "zero_machine_quota",
            label: format!("Set the machine account quota from {} to 0", q),
            explain: "Only administrators, or accounts they delegate, can then join machines to the domain. \
                      Change it back on the Password Policy page."
                .to_string(),
            targets: Vec::new(),
        }),
        _ => None,
    }
}

// ── planning and applying ─────────────────────────────────────────────────────

/// One concrete change, fully described by fresh data.
pub enum Change {
    DisableComputer { dn: String, name: String, days: i64, uac: i64 },
    RemoveMember { user_dn: String, user_name: String, group_dn: String, group_name: String },
    ClearNotRequired { dn: String, name: String, uac: i64 },
    ZeroQuota { base_dn: String, from: i64 },
}

impl Change {
    pub fn describe(&self) -> String {
        match self {
            Change::DisableComputer { name, days, .. } => {
                format!("Disable computer {} (last logon {} days ago)", name, days)
            }
            Change::RemoveMember { user_name, group_name, .. } => {
                format!("Remove {} from {}", user_name, group_name)
            }
            Change::ClearNotRequired { name, .. } => format!("Require a password for {}", name),
            Change::ZeroQuota { from, .. } => format!("Set ms-DS-MachineAccountQuota from {} to 0", from),
        }
    }

    /// The audit-log action and target for this change.
    pub fn audit(&self) -> (&'static str, String) {
        match self {
            Change::DisableComputer { name, .. } => ("health.fix.disable_computer", name.clone()),
            Change::RemoveMember { user_name, group_name, .. } => {
                ("health.fix.remove_member", format!("{} from {}", user_name, group_name))
            }
            Change::ClearNotRequired { name, .. } => ("health.fix.clear_passwd_notreqd", name.clone()),
            Change::ZeroQuota { from, .. } => ("health.fix.machine_quota", format!("{} -> 0", from)),
        }
    }
}

pub struct Plan {
    pub changes: Vec<Change>,
    /// Keys that were asked for but no longer qualify in the fresh scan.
    pub skipped: usize,
}

pub fn known_kind(kind: &str) -> bool {
    matches!(
        kind,
        "disable_stale_computers" | "remove_disabled_privileged" | "clear_passwd_notreqd" | "zero_machine_quota"
    )
}

/// Work out, from a fresh scan, which of the requested targets still qualify.
pub async fn plan(conn: &mut ldap3::Ldap, base_dn: &str, kind: &str, keys: &[String]) -> LdapResult<Plan> {
    let wanted: HashSet<&str> = keys.iter().map(String::as_str).collect();
    let mut changes = Vec::new();

    match kind {
        "disable_stale_computers" => {
            for c in stale_computers(conn, base_dn).await?.stale {
                if !c.is_dc && wanted.contains(c.key().as_str()) {
                    changes.push(Change::DisableComputer { dn: c.dn, name: c.name, days: c.days, uac: c.uac });
                }
            }
        }
        "remove_disabled_privileged" => {
            for d in privileged_members(conn, base_dn).await?.disabled {
                for (group_dn, group_name) in &d.via {
                    if wanted.contains(d.removal_key(group_dn).as_str()) {
                        changes.push(Change::RemoveMember {
                            user_dn: d.user_dn.clone(),
                            user_name: d.user_name.clone(),
                            group_dn: group_dn.clone(),
                            group_name: group_name.clone(),
                        });
                    }
                }
            }
        }
        "clear_passwd_notreqd" => {
            for a in password_flags(conn, base_dn).await?.not_required {
                if wanted.contains(a.key().as_str()) {
                    changes.push(Change::ClearNotRequired { dn: a.dn, name: a.name, uac: a.uac });
                }
            }
        }
        "zero_machine_quota" => {
            if let Some(q) = machine_account_quota(conn, base_dn).await? {
                if q > 0 && wanted.contains(QUOTA_KEY) {
                    changes.push(Change::ZeroQuota { base_dn: base_dn.to_string(), from: q });
                }
            }
        }
        other => return Err(format!("Unknown fix '{}'", other)),
    }

    let skipped = wanted.len().saturating_sub(changes.len());
    Ok(Plan { changes, skipped })
}

async fn modify(conn: &mut ldap3::Ldap, dn: &str, mods: Vec<Mod<Vec<u8>>>) -> LdapResult<()> {
    conn.modify(dn, mods)
        .await
        .map_err(|e| e.to_string())?
        .success()
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn one(v: String) -> HashSet<Vec<u8>> {
    HashSet::from([v.into_bytes()])
}

/// Apply one change. Each is independent, so one failure does not stop the rest.
pub async fn apply(conn: &mut ldap3::Ldap, change: &Change) -> LdapResult<()> {
    match change {
        Change::DisableComputer { dn, uac, .. } => {
            modify(conn, dn, vec![Mod::Replace(b"userAccountControl".to_vec(), one((uac | UAC_DISABLED).to_string()))]).await
        }
        Change::RemoveMember { user_dn, group_dn, .. } => {
            modify(conn, group_dn, vec![Mod::Delete(b"member".to_vec(), HashSet::from([user_dn.clone().into_bytes()]))]).await
        }
        Change::ClearNotRequired { dn, uac, .. } => {
            modify(conn, dn, vec![Mod::Replace(b"userAccountControl".to_vec(), one((uac & !UAC_PASSWD_NOTREQD).to_string()))]).await
        }
        Change::ZeroQuota { base_dn, .. } => {
            modify(conn, base_dn, vec![Mod::Replace(b"ms-DS-MachineAccountQuota".to_vec(), one("0".to_string()))]).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_stable_and_distinct() {
        let a = key_of(&["stale", "CN=GAMES,CN=Computers,DC=hakim,DC=family"]);
        assert_eq!(a, key_of(&["stale", "CN=GAMES,CN=Computers,DC=hakim,DC=family"]));
        // DNs compare case-insensitively in the directory, and so do keys.
        assert_eq!(a, key_of(&["stale", "cn=games,cn=computers,dc=hakim,dc=family"]));
        assert_ne!(a, key_of(&["stale", "CN=ROUGE,CN=Computers,DC=hakim,DC=family"]));
        // The kind is part of the key, so a key from one fix cannot drive another.
        assert_ne!(a, key_of(&["passwd_notreqd", "CN=GAMES,CN=Computers,DC=hakim,DC=family"]));
        // Parts are separated, so shifting text between them changes the key.
        assert_ne!(key_of(&["ab", "c"]), key_of(&["a", "bc"]));
        assert_eq!(a.len(), 16);
    }

    fn computer(name: &str, days: i64, is_dc: bool) -> StaleComputer {
        StaleComputer { dn: format!("CN={},CN=Computers,DC=x", name), name: format!("{}$", name), days, uac: 4096, is_dc }
    }

    #[test]
    fn domain_controllers_are_never_offered_for_disabling() {
        let scan = StaleScan { enabled: 3, stale: vec![computer("OLDPC", 400, false), computer("DC3", 200, true)] };
        let fix = stale_computer_fix(&scan).unwrap();
        assert_eq!(fix.targets.len(), 1);
        assert!(fix.targets[0].label.starts_with("OLDPC$"));
        let only_dc = StaleScan { enabled: 1, stale: vec![computer("DC3", 200, true)] };
        assert!(stale_computer_fix(&only_dc).is_none());
    }

    #[test]
    fn removal_targets_name_the_group_that_grants_the_rights() {
        let scan = PrivilegedScan {
            lines: vec![],
            total: 2,
            fell_back: false,
            disabled: vec![
                DisabledMember {
                    user_dn: "CN=olduser,DC=x".into(),
                    user_name: "olduser".into(),
                    grants: vec!["Domain Admins".into(), "Administrators".into()],
                    via: vec![("CN=IT-Admins,DC=x".into(), "IT-Admins".into())],
                },
                DisabledMember {
                    user_dn: "CN=direct,DC=x".into(),
                    user_name: "direct".into(),
                    grants: vec!["Domain Admins".into()],
                    via: vec![("CN=Domain Admins,DC=x".into(), "Domain Admins".into())],
                },
                // Rights through the primary group: reported, but no removal to offer.
                DisabledMember {
                    user_dn: "CN=primary,DC=x".into(),
                    user_name: "primary".into(),
                    grants: vec!["Domain Admins".into()],
                    via: vec![],
                },
            ],
        };
        let fix = privileged_fix(&scan).unwrap();
        let labels: Vec<&str> = fix.targets.iter().map(|t| t.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Remove olduser from IT-Admins (grants Domain Admins, Administrators)",
                "Remove direct from Domain Admins",
            ]
        );
    }

    #[test]
    fn quota_is_offered_only_above_zero() {
        assert!(quota_fix(Some(10)).is_some());
        assert!(quota_fix(Some(0)).is_none());
        assert!(quota_fix(None).is_none());
    }

    #[test]
    fn unknown_kinds_are_rejected() {
        assert!(known_kind("disable_stale_computers"));
        assert!(!known_kind("seize_fsmo"));
        assert!(!known_kind(""));
    }
}
