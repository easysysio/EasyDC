//! Read-only reports: the questions an admin asks every week.
//!
//! One read of the directory serves every report, so the counts beside them
//! agree. Everything after [`read`] works on that copy and changes nothing.
//!
//! Two things in Active Directory make the obvious answers wrong:
//! - A user's *primary group* is not in that group's `member` list. A group
//!   can look empty and hold every computer in the domain, and someone can be
//!   a Domain Admin through it alone.
//! - `lastLogonTimestamp` is only replicated about every 14 days, so it can be
//!   that far behind. The shortest inactive period offered is 14 days.

use std::collections::{HashMap, HashSet, VecDeque};

use ldap3::{Scope, SearchEntry};
use serde::Serialize;

use crate::health::{attr_ci, civil_from_days, days_from_civil};
use crate::ldap::{self, LdapGroup, LdapResult, OP_TIMEOUT};

const DAY: i64 = 86_400;
const UF_ACCOUNTDISABLE: i64 = 0x2;
const UF_DONT_EXPIRE_PASSWD: i64 = 0x1_0000;

// ── the reports ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Inactive,
    Expiring,
    NeverExpire,
    Problems,
    Privileged,
    Empty,
}

pub const KINDS: [Kind; 6] = [Kind::Inactive, Kind::Expiring, Kind::NeverExpire, Kind::Problems, Kind::Privileged, Kind::Empty];

impl Kind {
    pub fn key(self) -> &'static str {
        match self {
            Kind::Inactive => "inactive",
            Kind::Expiring => "expiring",
            Kind::NeverExpire => "never-expire",
            Kind::Problems => "problems",
            Kind::Privileged => "privileged",
            Kind::Empty => "empty-groups",
        }
    }

    pub fn from_key(key: &str) -> Option<Kind> {
        KINDS.into_iter().find(|k| k.key() == key)
    }

    pub fn title(self) -> &'static str {
        match self {
            Kind::Inactive => "Inactive accounts",
            Kind::Expiring => "Passwords expiring",
            Kind::NeverExpire => "Passwords that never expire",
            Kind::Problems => "Locked, disabled or expired",
            Kind::Privileged => "Privileged group members",
            Kind::Empty => "Empty groups",
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Kind::Inactive => "bi-hourglass-split",
            Kind::Expiring => "bi-calendar-x",
            Kind::NeverExpire => "bi-infinity",
            Kind::Problems => "bi-person-lock",
            Kind::Privileged => "bi-shield-exclamation",
            Kind::Empty => "bi-people",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Kind::Inactive => "Enabled users and computers with no sign-in for this long. The last sign-in can be up to 14 days behind.",
            Kind::Expiring => "Enabled users whose password expires within this time, or already has. Password policies for groups are included.",
            Kind::NeverExpire => "Enabled users whose password is set never to expire.",
            Kind::Problems => "Users who cannot sign in because they are locked out, disabled or expired. Built-in accounts that are always disabled are left out.",
            Kind::Privileged => "Everyone in the domain's most powerful groups, including through nested groups and primary groups.",
            Kind::Empty => "Groups with no members, counting primary group members. Built-in groups are left out.",
        }
    }

    /// The days this report asks about: (default, smallest, largest).
    pub fn days(self) -> Option<(i64, i64, i64)> {
        match self {
            Kind::Inactive => Some((90, 14, 3650)),
            Kind::Expiring => Some((14, 1, 365)),
            _ => None,
        }
    }

    /// The days to use from what was typed: out of range is brought into it,
    /// and anything that is not a number is the default.
    pub fn days_from(self, typed: Option<&str>) -> Option<i64> {
        let (default, low, high) = self.days()?;
        Some(typed.and_then(|t| t.trim().parse::<i64>().ok()).map_or(default, |d| d.clamp(low, high)))
    }
}

/// A report as rows of text, so the page and the CSV file cannot disagree.
#[derive(Debug, Serialize)]
pub struct Table {
    pub columns: &'static [&'static str],
    pub rows: Vec<Row>,
    /// The column holding statuses, shown as badges.
    pub status_column: Option<usize>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct Row {
    /// When the first column is a group: its name, to link to its members.
    pub group: Option<String>,
    pub cells: Vec<String>,
}

// ── what is read from the directory ──────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct Account {
    pub dn: String,
    pub name: String,
    pub display_name: String,
    pub email: String,
    pub computer: bool,
    pub enabled: bool,
    pub locked: bool,
    pub expired: bool,
    /// Last day the account can be used, `YYYY-MM-DD`; empty for never.
    pub expires: String,
    pub location: String,
    pub last_sign_in: Option<i64>,
    pub created: Option<i64>,
    pub password_set: Option<i64>,
    pub password_expires: Option<i64>,
    pub never_expires: bool,
    /// Built in and always there, such as krbtgt and Guest.
    pub critical: bool,
    /// The SID of its primary group.
    pub primary_group: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Group {
    pub dn: String,
    pub name: String,
    pub sid: String,
    pub type_label: String,
    pub description: String,
    pub location: String,
    pub system: bool,
    pub members: Vec<String>,
}

#[derive(Debug, Default)]
pub struct Directory {
    pub accounts: Vec<Account>,
    pub groups: Vec<Group>,
    /// Whether any password policy sets a maximum age.
    pub passwords_expire: bool,
}

/// `20260115093000.0Z` as Unix time.
fn generalized_time(text: &str) -> Option<i64> {
    let digits = text.get(..14)?;
    if !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n = |r: std::ops::Range<usize>| digits[r].parse::<i64>().ok();
    let day = days_from_civil(n(0..4)?, n(4..6)?, n(6..8)?);
    Some(day * DAY + n(8..10)? * 3600 + n(10..12)? * 60 + n(12..14)?)
}

/// The primary group's SID: the account's SID with its last part replaced.
fn primary_group_sid(account_sid: &str, rid: &str) -> Option<String> {
    let (domain, _) = account_sid.rsplit_once('-')?;
    rid.parse::<u32>().ok().map(|r| format!("{domain}-{r}"))
}

fn sid_of(e: &SearchEntry) -> String {
    ldap::object_sid(e).unwrap_or_default()
}

/// Read what every report needs. `expiring_days` limits which users the DC is
/// asked about for an exact password expiry, since that answer is slow.
pub async fn read(conn: &mut ldap3::Ldap, base_dn: &str, expiring_days: i64, now: i64) -> LdapResult<Directory> {
    // The Users page's own reading, so both say the same about who is locked.
    let users = ldap::list_users(conn, base_dn).await?;
    let users: HashMap<String, ldap::LdapUser> = users.into_iter().map(|u| (u.dn.to_lowercase(), u)).collect();

    let (entries, _) = conn
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=user)",
            vec![
                "sAMAccountName",
                "objectClass",
                "objectSid",
                "displayName",
                "userAccountControl",
                "accountExpires",
                "lastLogonTimestamp",
                "lastLogon",
                "pwdLastSet",
                "whenCreated",
                "primaryGroupID",
                "isCriticalSystemObject",
            ],
        )
        .await
        .map_err(ldap::ldap_err)?
        .success()
        .map_err(ldap::ldap_err)?;

    let mut accounts = Vec::with_capacity(entries.len());
    for e in entries.into_iter().map(SearchEntry::construct) {
        let name = attr_ci(&e, "sAMAccountName");
        if name.is_empty() {
            continue;
        }
        let computer = e.attrs.iter().any(|(k, v)| k.eq_ignore_ascii_case("objectClass") && v.iter().any(|c| c.eq_ignore_ascii_case("computer")));
        let uac: i64 = attr_ci(&e, "userAccountControl").parse().unwrap_or(UF_ACCOUNTDISABLE);
        let time = |key: &str| attr_ci(&e, key).parse::<i64>().ok().and_then(ldap::filetime_to_unix);
        let expires_at = attr_ci(&e, "accountExpires").parse::<i64>().unwrap_or(0);
        let user = users.get(&e.dn.to_lowercase());
        accounts.push(Account {
            name: if computer { name.trim_end_matches('$').to_string() } else { name },
            display_name: attr_ci(&e, "displayName"),
            email: user.map(|u| u.email.clone()).unwrap_or_default(),
            computer,
            enabled: uac & UF_ACCOUNTDISABLE == 0,
            locked: user.is_some_and(|u| u.locked),
            expired: ldap::filetime_to_unix(expires_at).is_some_and(|t| t <= now),
            expires: ldap::expiry_date(expires_at).unwrap_or_default(),
            location: ldap::location(ldap::parent_dn(&e.dn), base_dn),
            // The DC we asked may have seen a newer sign-in than has replicated.
            last_sign_in: time("lastLogonTimestamp").max(time("lastLogon")),
            created: generalized_time(&attr_ci(&e, "whenCreated")),
            password_set: time("pwdLastSet"),
            password_expires: None,
            never_expires: uac & UF_DONT_EXPIRE_PASSWD != 0,
            critical: attr_ci(&e, "isCriticalSystemObject").eq_ignore_ascii_case("TRUE"),
            primary_group: primary_group_sid(&sid_of(&e), &attr_ci(&e, "primaryGroupID")),
            dn: e.dn,
        });
    }

    let shortest_age = ldap::shortest_max_password_age(conn, base_dn).await.map(|ticks| ticks / 10_000_000);
    if let Some(age) = shortest_age {
        read_password_expiry(conn, base_dn, &mut accounts, age, now + expiring_days * DAY).await?;
    }
    let groups = read_groups(conn, base_dn).await?;
    Ok(Directory { accounts, groups, passwords_expire: shortest_age.is_some() })
}

/// Ask the DC when passwords expire, since a policy for a group can change it
/// per user. Only for users whose password could be due by `until` under the
/// shortest maximum age in force.
async fn read_password_expiry(conn: &mut ldap3::Ldap, base_dn: &str, accounts: &mut [Account], shortest_age: i64, until: i64) -> LdapResult<()> {
    let due: Vec<usize> = (0..accounts.len())
        .filter(|&i| {
            let a = &accounts[i];
            !a.computer && a.enabled && !a.never_expires && a.password_set.is_some_and(|set| set + shortest_age <= until)
        })
        .collect();
    for part in due.chunks(100) {
        let names: String = part.iter().map(|&i| format!("(sAMAccountName={})", ldap::ldap_escape(&accounts[i].name))).collect();
        let (entries, _) = conn
            .with_timeout(OP_TIMEOUT)
            .search(base_dn, Scope::Subtree, &format!("(&(objectClass=user)(|{names}))"), vec!["msDS-UserPasswordExpiryTimeComputed"])
            .await
            .map_err(ldap::ldap_err)?
            .success()
            .map_err(ldap::ldap_err)?;
        let found: HashMap<String, String> = entries
            .into_iter()
            .map(SearchEntry::construct)
            .map(|e| (e.dn.to_lowercase(), attr_ci(&e, "msDS-UserPasswordExpiryTimeComputed")))
            .collect();
        for &i in part {
            let a = &mut accounts[i];
            a.password_expires = match found.get(&a.dn.to_lowercase()).map(|v| v.parse::<i64>()) {
                Some(Ok(t)) => ldap::filetime_to_unix(t),
                // A DC that does not work it out: the earliest it can be.
                _ => a.password_set.map(|set| set + shortest_age),
            };
        }
    }
    Ok(())
}

async fn read_groups(conn: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<Group>> {
    let mut attrs = ldap::GROUP_ATTRS.to_vec();
    attrs.extend(["member", "objectSid"]);
    let (entries, _) = conn
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, "(objectClass=group)", attrs)
        .await
        .map_err(ldap::ldap_err)?
        .success()
        .map_err(ldap::ldap_err)?;
    Ok(entries
        .into_iter()
        .map(SearchEntry::construct)
        .map(|e| {
            let g = LdapGroup::from_entry(&e);
            Group {
                location: ldap::location(&g.container, base_dn),
                sid: sid_of(&e),
                members: e.attrs.get("member").cloned().unwrap_or_default(),
                dn: g.dn,
                name: g.name,
                type_label: g.group_type_label,
                description: g.description,
                system: g.system,
            }
        })
        .filter(|g| !g.name.is_empty())
        .collect())
}

// ── building the reports ─────────────────────────────────────────────────────

fn date(unix: i64) -> String {
    let (y, m, d) = civil_from_days(unix.div_euclid(DAY));
    format!("{y:04}-{m:02}-{d:02}")
}

fn date_or(unix: Option<i64>, none: &str) -> String {
    unix.map_or_else(|| none.to_string(), date)
}

fn account_kind(a: &Account) -> &'static str {
    if a.computer { "Computer" } else { "User" }
}

/// What is wrong with an account, or `Enabled`.
fn status(a: &Account) -> String {
    let mut parts = Vec::new();
    if a.locked {
        parts.push("Locked");
    }
    if a.expired {
        parts.push("Expired");
    }
    if !a.enabled {
        parts.push("Disabled");
    }
    if parts.is_empty() { "Enabled".to_string() } else { parts.join(", ") }
}

fn row(cells: Vec<String>) -> Row {
    Row { group: None, cells }
}

fn by_name(a: &Account, b: &Account) -> std::cmp::Ordering {
    a.name.to_lowercase().cmp(&b.name.to_lowercase())
}

pub fn build(kind: Kind, dir: &Directory, days: Option<i64>, now: i64) -> Table {
    let days = days.or(kind.days().map(|d| d.0)).unwrap_or(0);
    match kind {
        Kind::Inactive => inactive(dir, days, now),
        Kind::Expiring => expiring(dir, days, now),
        Kind::NeverExpire => never_expire(dir),
        Kind::Problems => problems(dir),
        Kind::Privileged => privileged(dir),
        Kind::Empty => empty_groups(dir),
    }
}

fn inactive(dir: &Directory, days: i64, now: i64) -> Table {
    let cutoff = now - days * DAY;
    let mut found: Vec<&Account> = dir
        .accounts
        .iter()
        .filter(|a| a.enabled)
        .filter(|a| match a.last_sign_in {
            Some(t) => t <= cutoff,
            // Never signed in: only once it has existed for that long.
            None => a.created.is_none_or(|c| c <= cutoff),
        })
        .collect();
    found.sort_by(|a, b| a.last_sign_in.unwrap_or(0).cmp(&b.last_sign_in.unwrap_or(0)).then_with(|| by_name(a, b)));
    Table {
        columns: &["Account", "Display name", "Type", "Last sign-in", "Created", "Location"],
        rows: found
            .into_iter()
            .map(|a| {
                row(vec![
                    a.name.clone(),
                    a.display_name.clone(),
                    account_kind(a).to_string(),
                    date_or(a.last_sign_in, "Never"),
                    date_or(a.created, ""),
                    a.location.clone(),
                ])
            })
            .collect(),
        status_column: None,
        note: None,
    }
}

fn no_expiry_note(dir: &Directory) -> Option<String> {
    (!dir.passwords_expire).then(|| "No password policy in this domain sets a maximum age, so no password expires.".to_string())
}

fn expiring(dir: &Directory, days: i64, now: i64) -> Table {
    let until = now + days * DAY;
    let mut found: Vec<(&Account, i64)> = dir
        .accounts
        .iter()
        .filter(|a| !a.computer && a.enabled && !a.never_expires)
        .filter_map(|a| a.password_expires.filter(|&t| t <= until).map(|t| (a, t)))
        .collect();
    found.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| by_name(a.0, b.0)));
    Table {
        columns: &["Account", "Display name", "Email", "Password set", "Expires", "Status", "Location"],
        rows: found
            .into_iter()
            .map(|(a, t)| {
                let left = (t - now + DAY - 1).div_euclid(DAY);
                let state = match left {
                    _ if t <= now => "Expired".to_string(),
                    1 => "In 1 day".to_string(),
                    n => format!("In {n} days"),
                };
                row(vec![
                    a.name.clone(),
                    a.display_name.clone(),
                    a.email.clone(),
                    date_or(a.password_set, ""),
                    date(t),
                    state,
                    a.location.clone(),
                ])
            })
            .collect(),
        status_column: Some(5),
        note: no_expiry_note(dir),
    }
}

fn never_expire(dir: &Directory) -> Table {
    let mut found: Vec<&Account> = dir.accounts.iter().filter(|a| !a.computer && a.enabled && a.never_expires).collect();
    found.sort_by(|a, b| by_name(a, b));
    Table {
        columns: &["Account", "Display name", "Password set", "Last sign-in", "Location"],
        rows: found
            .into_iter()
            .map(|a| {
                row(vec![
                    a.name.clone(),
                    a.display_name.clone(),
                    date_or(a.password_set, "Never"),
                    date_or(a.last_sign_in, "Never"),
                    a.location.clone(),
                ])
            })
            .collect(),
        status_column: None,
        note: no_expiry_note(dir),
    }
}

fn problems(dir: &Directory) -> Table {
    let mut found: Vec<&Account> = dir
        .accounts
        .iter()
        .filter(|a| !a.computer && (a.locked || a.expired || !a.enabled))
        // krbtgt and Guest are disabled on every domain.
        .filter(|a| a.locked || a.expired || !a.critical)
        .collect();
    found.sort_by(|a, b| (!a.locked, !a.expired).cmp(&(!b.locked, !b.expired)).then_with(|| by_name(a, b)));
    Table {
        columns: &["Account", "Display name", "Status", "Account expires", "Last sign-in", "Location"],
        rows: found
            .into_iter()
            .map(|a| {
                row(vec![
                    a.name.clone(),
                    a.display_name.clone(),
                    status(a),
                    a.expires.clone(),
                    date_or(a.last_sign_in, "Never"),
                    a.location.clone(),
                ])
            })
            .collect(),
        status_column: Some(2),
        note: None,
    }
}

/// The place of a powerful group in the report, by SID: its name can be
/// changed or translated, its SID cannot.
fn privileged_rank(sid: &str) -> Option<u8> {
    if let Some(rid) = sid.strip_prefix("S-1-5-32-") {
        return match rid {
            "544" => Some(3), // Administrators
            "548" => Some(4), // Account Operators
            "549" => Some(5), // Server Operators
            "551" => Some(6), // Backup Operators
            "550" => Some(7), // Print Operators
            _ => None,
        };
    }
    if !sid.starts_with("S-1-5-21-") {
        return None;
    }
    match sid.rsplit('-').next()? {
        "512" => Some(0), // Domain Admins
        "519" => Some(1), // Enterprise Admins
        "518" => Some(2), // Schema Admins
        "520" => Some(8), // Group Policy Creator Owners
        _ => None,
    }
}

/// One member found under a group, and how it got there.
struct Found<'a> {
    account: Option<&'a Account>,
    dn: &'a str,
    how: String,
}

/// Everyone in a group, through nested groups (each once, so a loop of groups
/// ends) and primary groups. Breadth first, so `how` is the shortest way in.
fn members_of<'a>(
    root: &'a Group,
    groups: &HashMap<String, &'a Group>,
    accounts: &HashMap<String, &'a Account>,
    primary: &HashMap<&'a str, Vec<&'a Account>>,
) -> Vec<Found<'a>> {
    let mut out = Vec::new();
    let mut seen_groups = HashSet::from([root.dn.to_lowercase()]);
    let mut seen = HashSet::new();
    let mut queue: VecDeque<(&Group, Vec<&str>)> = VecDeque::from([(root, Vec::new())]);
    while let Some((group, path)) = queue.pop_front() {
        let through = path.join(" › ");
        for dn in &group.members {
            let key = dn.to_lowercase();
            if let Some(child) = groups.get(&key) {
                if seen_groups.insert(key) {
                    let mut next = path.clone();
                    next.push(child.name.as_str());
                    queue.push_back((child, next));
                }
            } else if seen.insert(key.clone()) {
                let how = if path.is_empty() { "Direct".to_string() } else { format!("Through {through}") };
                out.push(Found { account: accounts.get(&key).copied(), dn, how });
            }
        }
        for a in primary.get(group.sid.as_str()).into_iter().flatten() {
            if seen.insert(a.dn.to_lowercase()) {
                let how = if path.is_empty() { "Primary group".to_string() } else { format!("Through {through} (primary group)") };
                out.push(Found { account: Some(a), dn: &a.dn, how });
            }
        }
    }
    out
}

fn primary_members(dir: &Directory) -> HashMap<&str, Vec<&Account>> {
    let mut primary: HashMap<&str, Vec<&Account>> = HashMap::new();
    for a in &dir.accounts {
        if let Some(sid) = &a.primary_group {
            primary.entry(sid.as_str()).or_default().push(a);
        }
    }
    primary
}

fn privileged(dir: &Directory) -> Table {
    let groups: HashMap<String, &Group> = dir.groups.iter().map(|g| (g.dn.to_lowercase(), g)).collect();
    let accounts: HashMap<String, &Account> = dir.accounts.iter().map(|a| (a.dn.to_lowercase(), a)).collect();
    let primary = primary_members(dir);
    let mut powerful: Vec<(u8, &Group)> = dir.groups.iter().filter_map(|g| privileged_rank(&g.sid).map(|r| (r, g))).collect();
    powerful.sort_by_key(|(rank, _)| *rank);

    let mut rows = Vec::new();
    let mut people = HashSet::new();
    for (_, group) in powerful {
        let mut found = members_of(group, &groups, &accounts, &primary);
        found.sort_by_key(|f| f.account.map_or_else(|| ldap::first_rdn_value(f.dn), |a| a.name.clone()).to_lowercase());
        for f in found {
            people.insert(f.dn.to_lowercase());
            let cells = match f.account {
                Some(a) => vec![
                    group.name.clone(),
                    a.name.clone(),
                    a.display_name.clone(),
                    account_kind(a).to_string(),
                    f.how,
                    status(a),
                    date_or(a.last_sign_in, "Never"),
                ],
                None => {
                    let rdn = ldap::first_rdn_value(f.dn);
                    let foreign = f.dn.to_lowercase().contains(",cn=foreignsecurityprincipals,");
                    let name = ldap::well_known_sid(&rdn).map_or(rdn.clone(), str::to_string);
                    let kind = if foreign { "Foreign" } else { "Other" };
                    vec![group.name.clone(), name, String::new(), kind.to_string(), f.how, String::new(), String::new()]
                }
            };
            rows.push(Row { group: Some(group.name.clone()), cells });
        }
    }
    let note = Some(match people.len() {
        1 => "1 account holds these rights.".to_string(),
        n => format!("{n} different accounts hold these rights."),
    });
    Table {
        columns: &["Group", "Member", "Display name", "Type", "How", "Status", "Last sign-in"],
        rows,
        status_column: Some(5),
        note,
    }
}

fn empty_groups(dir: &Directory) -> Table {
    let primary = primary_members(dir);
    let (system, mut found): (Vec<&Group>, Vec<&Group>) = dir
        .groups
        .iter()
        .filter(|g| g.members.is_empty() && !primary.contains_key(g.sid.as_str()))
        .partition(|g| g.system);
    found.sort_by_key(|g| g.name.to_lowercase());
    let note = match system.len() {
        0 => None,
        1 => Some("1 built-in group is also empty and is not listed.".to_string()),
        n => Some(format!("{n} built-in groups are also empty and are not listed.")),
    };
    Table {
        columns: &["Group", "Type", "Description", "Location"],
        rows: found
            .into_iter()
            .map(|g| Row {
                group: Some(g.name.clone()),
                cells: vec![g.name.clone(), g.type_label.clone(), g.description.clone(), g.location.clone()],
            })
            .collect(),
        status_column: None,
        note,
    }
}

/// A report as a CSV file. Values that a spreadsheet would run as a formula
/// are neutralized by `csv::write_row`.
pub fn to_csv(table: &Table) -> String {
    let mut out = String::from(crate::csv::BOM);
    crate::csv::write_row(&mut out, table.columns);
    for r in &table.rows {
        crate::csv::write_row(&mut out, &r.cells);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const D: &str = "S-1-5-21-1-2-3";

    fn user(name: &str) -> Account {
        Account {
            dn: format!("CN={name},CN=Users,DC=x"),
            name: name.to_string(),
            enabled: true,
            created: Some(NOW - 1000 * DAY),
            last_sign_in: Some(NOW - DAY),
            primary_group: Some(format!("{D}-513")),
            ..Default::default()
        }
    }

    fn group(name: &str, sid: &str, members: &[&str]) -> Group {
        Group {
            dn: format!("CN={name},CN=Users,DC=x"),
            name: name.to_string(),
            sid: sid.to_string(),
            members: members.iter().map(|m| format!("CN={m},CN=Users,DC=x")).collect(),
            ..Default::default()
        }
    }

    fn names(t: &Table, col: usize) -> Vec<&str> {
        t.rows.iter().map(|r| r.cells[col].as_str()).collect()
    }

    fn dir(accounts: Vec<Account>, groups: Vec<Group>) -> Directory {
        Directory { accounts, groups, passwords_expire: true }
    }

    #[test]
    fn days_are_kept_in_range() {
        assert_eq!(Kind::Inactive.days_from(None), Some(90));
        assert_eq!(Kind::Inactive.days_from(Some("abc")), Some(90));
        assert_eq!(Kind::Inactive.days_from(Some("3")), Some(14), "the sign-in time is only this exact");
        assert_eq!(Kind::Inactive.days_from(Some("99999")), Some(3650));
        assert_eq!(Kind::Expiring.days_from(Some("30")), Some(30));
        assert_eq!(Kind::Empty.days_from(Some("30")), None);
        assert!(KINDS.iter().all(|k| Kind::from_key(k.key()) == Some(*k)));
        assert_eq!(Kind::from_key("nope"), None);
    }

    #[test]
    fn times_from_the_directory() {
        assert_eq!(generalized_time("20260115093000.0Z"), Some(days_from_civil(2026, 1, 15) * DAY + 9 * 3600 + 30 * 60));
        assert_eq!(generalized_time("bad"), None);
        assert_eq!(primary_group_sid("S-1-5-21-1-2-3-1105", "513").as_deref(), Some("S-1-5-21-1-2-3-513"));
        assert_eq!(primary_group_sid("S-1-5-21-1-2-3-1105", ""), None);
    }

    /// S-1-5-32-544 is valid UTF-8, so the library does not call it binary.
    #[test]
    fn a_built_in_groups_sid_is_read_wherever_the_library_put_it() {
        let bytes = [1u8, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0];
        let as_text = SearchEntry {
            dn: "CN=Administrators,CN=Builtin,DC=x".into(),
            attrs: HashMap::from([("objectSid".to_string(), vec![String::from_utf8(bytes.to_vec()).unwrap()])]),
            bin_attrs: HashMap::new(),
        };
        let as_binary = SearchEntry {
            dn: as_text.dn.clone(),
            attrs: HashMap::new(),
            bin_attrs: HashMap::from([("objectSid".to_string(), vec![bytes.to_vec()])]),
        };
        assert_eq!(sid_of(&as_text), "S-1-5-32-544");
        assert_eq!(sid_of(&as_binary), "S-1-5-32-544");
    }

    #[test]
    fn inactive_lists_who_has_been_away_and_not_who_is_new() {
        let old = Account { last_sign_in: Some(NOW - 100 * DAY), ..user("old") };
        let recent = Account { last_sign_in: Some(NOW - 89 * DAY), ..user("recent") };
        let never = Account { last_sign_in: None, ..user("never") };
        let new_hire = Account { last_sign_in: None, created: Some(NOW - 5 * DAY), ..user("newhire") };
        let disabled = Account { enabled: false, last_sign_in: Some(NOW - 500 * DAY), ..user("gone") };
        let pc = Account { computer: true, last_sign_in: Some(NOW - 200 * DAY), ..user("PC1") };
        let t = build(Kind::Inactive, &dir(vec![old, recent, never, new_hire, disabled, pc], vec![]), Some(90), NOW);
        assert_eq!(names(&t, 0), ["never", "PC1", "old"], "never first, then the longest away");
        assert_eq!(t.rows[0].cells[3], "Never");
        assert_eq!(t.rows[1].cells[2], "Computer");
    }

    #[test]
    fn expiring_shows_what_is_due_soonest_first() {
        let soon = Account { password_expires: Some(NOW + 3 * DAY), ..user("soon") };
        let tomorrow = Account { password_expires: Some(NOW + 3600), ..user("tomorrow") };
        let past = Account { password_expires: Some(NOW - DAY), ..user("past") };
        let later = Account { password_expires: Some(NOW + 15 * DAY), ..user("later") };
        let off = Account { enabled: false, password_expires: Some(NOW + DAY), ..user("off") };
        let t = build(Kind::Expiring, &dir(vec![soon, tomorrow, past, later, off], vec![]), Some(14), NOW);
        assert_eq!(names(&t, 0), ["past", "tomorrow", "soon"]);
        assert_eq!(names(&t, 5), ["Expired", "In 1 day", "In 3 days"]);
        assert!(t.note.is_none());
        let none = Directory { passwords_expire: false, ..Default::default() };
        assert!(build(Kind::Expiring, &none, None, NOW).note.unwrap().contains("maximum age"));
    }

    #[test]
    fn never_expiring_passwords_of_enabled_users() {
        let flagged = Account { never_expires: true, ..user("svc") };
        let off = Account { never_expires: true, enabled: false, ..user("off") };
        let pc = Account { never_expires: true, computer: true, ..user("pc") };
        let t = build(Kind::NeverExpire, &dir(vec![flagged, off, pc, user("plain")], vec![]), None, NOW);
        assert_eq!(names(&t, 0), ["svc"]);
    }

    #[test]
    fn problems_lead_with_what_can_be_fixed_and_skip_the_built_in_accounts() {
        let locked = Account { locked: true, ..user("zed") };
        let expired = Account { expired: true, expires: "2026-01-01".into(), ..user("yan") };
        let disabled = Account { enabled: false, ..user("abe") };
        let both = Account { enabled: false, locked: true, ..user("bea") };
        let krbtgt = Account { enabled: false, critical: true, ..user("krbtgt") };
        let pc = Account { computer: true, enabled: false, ..user("pc") };
        let t = build(Kind::Problems, &dir(vec![locked, expired, disabled, both, krbtgt, pc, user("fine")], vec![]), None, NOW);
        assert_eq!(names(&t, 0), ["bea", "zed", "yan", "abe"]);
        assert_eq!(t.rows[0].cells[2], "Locked, Disabled");
        assert_eq!(t.rows[2].cells[3], "2026-01-01");
    }

    #[test]
    fn privileged_finds_nested_and_primary_members_and_survives_a_loop() {
        let direct = user("direct");
        let deep = user("deep");
        let by_primary = Account { primary_group: Some(format!("{D}-512")), ..user("primary") };
        let nested_primary = Account { primary_group: Some(format!("{D}-1200")), ..user("nestedprimary") };
        let disabled = Account { enabled: false, ..user("off") };
        let groups = vec![
            group("Domain Admins", &format!("{D}-512"), &["direct", "Tier1", "off"]),
            group("Tier1", &format!("{D}-1200"), &["Tier2"]),
            // Tier2 holds Domain Admins, closing a loop.
            group("Tier2", &format!("{D}-1201"), &["deep", "Domain Admins", "direct"]),
            group("Staff", &format!("{D}-1300"), &["bystander"]),
        ];
        let t = build(Kind::Privileged, &dir(vec![direct, deep, by_primary, nested_primary, disabled, user("bystander")], groups), None, NOW);
        let how = |n: &str| t.rows.iter().find(|r| r.cells[1] == n).map(|r| r.cells[4].as_str());
        assert_eq!(t.rows.len(), 5);
        assert_eq!(how("direct"), Some("Direct"), "the shortest way in");
        assert_eq!(how("primary"), Some("Primary group"));
        assert_eq!(how("nestedprimary"), Some("Through Tier1 (primary group)"));
        assert_eq!(how("deep"), Some("Through Tier1 › Tier2"));
        assert_eq!(how("bystander"), None);
        assert_eq!(t.rows.iter().find(|r| r.cells[1] == "off").unwrap().cells[5], "Disabled");
        assert_eq!(t.note.as_deref(), Some("5 different accounts hold these rights."));
    }

    #[test]
    fn powerful_groups_are_known_by_sid_not_name() {
        assert_eq!(privileged_rank("S-1-5-32-544"), Some(3));
        assert_eq!(privileged_rank(&format!("{D}-512")), Some(0));
        assert_eq!(privileged_rank(&format!("{D}-513")), None, "Domain Users");
        assert_eq!(privileged_rank("S-1-5-32-545"), None, "Users");
        let renamed = group("Domänen-Admins", &format!("{D}-512"), &["a"]);
        let fake = group("Domain Admins", &format!("{D}-1500"), &["b"]);
        let t = build(Kind::Privileged, &dir(vec![user("a"), user("b")], vec![renamed, fake]), None, NOW);
        assert_eq!(names(&t, 1), ["a"]);
        assert_eq!(names(&t, 0), ["Domänen-Admins"]);
    }

    #[test]
    fn well_known_and_unknown_members_are_still_listed() {
        let mut admins = group("Administrators", "S-1-5-32-544", &[]);
        admins.members = vec!["CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=x".into(), "CN=Far Away,DC=other".into()];
        let t = build(Kind::Privileged, &dir(vec![], vec![admins]), None, NOW);
        let cell = |n: &str, col: usize| t.rows.iter().find(|r| r.cells[1] == n).unwrap().cells[col].clone();
        assert_eq!(cell("Authenticated Users", 3), "Foreign");
        assert_eq!(cell("Far Away", 3), "Other");
    }

    #[test]
    fn a_group_with_only_primary_members_is_not_empty() {
        let pc = Account { computer: true, primary_group: Some(format!("{D}-515")), ..user("pc") };
        let mut builtin = group("Print Operators", "S-1-5-32-550", &[]);
        builtin.system = true;
        let groups = vec![
            group("Domain Computers", &format!("{D}-515"), &[]),
            group("Unused", &format!("{D}-1400"), &[]),
            group("Used", &format!("{D}-1401"), &["pc"]),
            builtin,
        ];
        let t = build(Kind::Empty, &dir(vec![pc], groups), None, NOW);
        assert_eq!(names(&t, 0), ["Unused"]);
        assert_eq!(t.rows[0].group.as_deref(), Some("Unused"));
        assert_eq!(t.note.as_deref(), Some("1 built-in group is also empty and is not listed."));
    }

    #[test]
    fn the_csv_has_the_rows_and_cannot_run_as_a_formula() {
        let evil = Account { display_name: "=HYPERLINK(\"x\")".into(), never_expires: true, ..user("svc") };
        let text = to_csv(&build(Kind::NeverExpire, &dir(vec![evil], vec![]), None, NOW));
        let records = crate::csv::parse(&text).unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].fields[0], "Account");
        assert_eq!(records[1].fields[1], "=HYPERLINK(\"x\")");
        assert!(text.contains("'=HYPERLINK"));
    }
}
