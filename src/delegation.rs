//! Delegate control of an OU, as `samba-tool dsacl` and Windows' Delegation
//! of Control wizard do: show who has rights on an OU beyond the built-in
//! defaults, give a group one of a few common tasks there, and take one away.
//!
//! A task is a handful of allow entries in the OU's access list
//! (`nTSecurityDescriptor`, DACL only), most of them inherited by the objects
//! below. The rights and GUIDs are Microsoft's published ones ([MS-ADTS]
//! 5.1.3.2 access rights, the schema's schemaIDGUID values, and the extended
//! rights' rightsGuid); before anything is written they are checked against
//! the DC's own schema, so a wrong one is refused rather than written.

use std::collections::{HashMap, HashSet};

use ldap3::{Mod, Scope, SearchEntry};
use serde::Serialize;

use crate::fsmo::Partitions;
use crate::health::{attr_ci, search};
use crate::ldap::{self, ldap_escape, LdapResult, OP_TIMEOUT};
use crate::sd::{Descriptor, Entry, CONTAINER_INHERIT, INHERIT_ONLY};

// Directory access rights ([MS-ADTS] 5.1.3.2).
const CREATE_CHILD: u32 = 0x1;
const DELETE_CHILD: u32 = 0x2;
const LIST_CHILDREN: u32 = 0x4;
const SELF_WRITE: u32 = 0x8;
const READ_PROP: u32 = 0x10;
const WRITE_PROP: u32 = 0x20;
const DELETE_TREE: u32 = 0x40;
const LIST_OBJECT: u32 = 0x80;
const CONTROL_ACCESS: u32 = 0x100;
const DELETE: u32 = 0x1_0000;
const READ_CONTROL: u32 = 0x2_0000;
const WRITE_DAC: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
/// Every right above: what Full control is stored as.
const FULL_CONTROL: u32 = 0xF_01FF;
const GENERIC_ALL: u32 = 0x1000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_READ: u32 = 0x8000_0000;
/// What Read is stored as on a directory object.
const READ: u32 = READ_CONTROL | LIST_CHILDREN | READ_PROP | LIST_OBJECT;

/// Inherited by the objects below only, not this OU itself.
const BELOW: u8 = CONTAINER_INHERIT | INHERIT_ONLY;
/// This OU and the objects below.
const HERE_AND_BELOW: u8 = CONTAINER_INHERIT;

/// A class, attribute or extended right a task names: its GUID, and the
/// name the DC's schema must give it (an extended right's cn).
#[derive(Clone, Copy, Debug)]
struct Named {
    guid: &'static str,
    name: &'static str,
}

const USER: Named = Named { guid: "bf967aba-0de6-11d0-a285-00aa003049e2", name: "user" };
const GROUP: Named = Named { guid: "bf967a9c-0de6-11d0-a285-00aa003049e2", name: "group" };
const COMPUTER: Named = Named { guid: "bf967a86-0de6-11d0-a285-00aa003049e2", name: "computer" };
const PWD_LAST_SET: Named = Named { guid: "bf967a0a-0de6-11d0-a285-00aa003049e2", name: "pwdLastSet" };
const LOCKOUT_TIME: Named = Named { guid: "28630ebf-41d5-11d1-a9c1-0000f80367c1", name: "lockoutTime" };
const MEMBER: Named = Named { guid: "bf9679c0-0de6-11d0-a285-00aa003049e2", name: "member" };
const GP_LINK: Named = Named { guid: "f30e3bbe-9ff0-11d1-b603-0000f80367c1", name: "gPLink" };
const GP_OPTIONS: Named = Named { guid: "f30e3bbf-9ff0-11d1-b603-0000f80367c1", name: "gPOptions" };
/// The Reset Password extended right.
const RESET_PASSWORD: Named = Named { guid: "00299570-246d-11d0-a768-00aa006e0529", name: "User-Force-Change-Password" };

/// One entry a task adds.
struct Grant {
    mask: u32,
    flags: u8,
    object: Option<Named>,
    applies_to: Option<Named>,
}

const fn grant(mask: u32, flags: u8, object: Option<Named>, applies_to: Option<Named>) -> Grant {
    Grant { mask, flags, object, applies_to }
}

#[derive(Serialize)]
pub struct Task {
    pub key: &'static str,
    pub label: &'static str,
    pub does: &'static str,
    #[serde(skip)]
    grants: &'static [Grant],
}

pub const TASKS: [Task; 6] = [
    Task {
        key: "users",
        label: "Create, delete and manage user accounts",
        does: "Create users here, delete them, and change anything about them, passwords included.",
        grants: &[
            grant(CREATE_CHILD | DELETE_CHILD, HERE_AND_BELOW, Some(USER), None),
            grant(FULL_CONTROL, BELOW, None, Some(USER)),
        ],
    },
    Task {
        key: "passwords",
        label: "Reset passwords and unlock accounts",
        does: "Reset users' passwords, make them change it at the next sign-in, and unlock them. For a help desk.",
        grants: &[
            grant(CONTROL_ACCESS, BELOW, Some(RESET_PASSWORD), Some(USER)),
            grant(READ_PROP | WRITE_PROP, BELOW, Some(PWD_LAST_SET), Some(USER)),
            grant(READ_PROP | WRITE_PROP, BELOW, Some(LOCKOUT_TIME), Some(USER)),
        ],
    },
    Task {
        key: "groups",
        label: "Create, delete and manage groups",
        does: "Create groups here, delete them, and change anything about them.",
        grants: &[
            grant(CREATE_CHILD | DELETE_CHILD, HERE_AND_BELOW, Some(GROUP), None),
            grant(FULL_CONTROL, BELOW, None, Some(GROUP)),
        ],
    },
    Task {
        key: "members",
        label: "Change group membership",
        does: "Add and remove members of the groups here.",
        grants: &[grant(READ_PROP | WRITE_PROP, BELOW, Some(MEMBER), Some(GROUP))],
    },
    Task {
        key: "computers",
        label: "Create, delete and manage computers",
        does: "Join computers to the domain into this OU, delete them, and change anything about them.",
        grants: &[
            grant(CREATE_CHILD | DELETE_CHILD, HERE_AND_BELOW, Some(COMPUTER), None),
            grant(FULL_CONTROL, BELOW, None, Some(COMPUTER)),
        ],
    },
    Task {
        key: "gplinks",
        label: "Link GPOs",
        does: "Link GPOs to this OU and the OUs in it, and change the order and enforcement of those links.",
        grants: &[
            grant(READ_PROP | WRITE_PROP, HERE_AND_BELOW, Some(GP_LINK), None),
            grant(READ_PROP | WRITE_PROP, HERE_AND_BELOW, Some(GP_OPTIONS), None),
        ],
    },
];

fn task(key: &str) -> LdapResult<&'static Task> {
    TASKS.iter().find(|t| t.key == key).ok_or_else(|| "Choose a task to delegate.".to_string())
}

/// A GUID's text form as stored: the first three fields little-endian.
fn guid_bytes(text: &str) -> [u8; 16] {
    let hex: Vec<u8> = text
        .split('-')
        .flat_map(|part| (0..part.len()).step_by(2).map(move |i| u8::from_str_radix(&part[i..i + 2], 16).unwrap_or(0)))
        .collect();
    let mut b = [0u8; 16];
    b.copy_from_slice(&hex[..16]);
    b[0..4].reverse();
    b[4..6].reverse();
    b[6..8].reverse();
    b
}

fn guid_text(b: &[u8; 16]) -> String {
    let h = |r: &[u8]| r.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let rev = |r: &[u8]| h(&r.iter().rev().copied().collect::<Vec<u8>>());
    format!("{}-{}-{}-{}-{}", rev(&b[0..4]), rev(&b[4..6]), rev(&b[6..8]), h(&b[8..10]), h(&b[10..16]))
}

impl Task {
    fn entries(&self, sid: &[u8]) -> Vec<Entry> {
        self.grants
            .iter()
            .map(|g| {
                let id = |n: Option<Named>| n.map(|n| guid_bytes(n.guid));
                Entry::allow(g.mask, g.flags, id(g.object), id(g.applies_to), sid)
            })
            .collect()
    }

    fn named(&self) -> impl Iterator<Item = Named> + '_ {
        self.grants.iter().flat_map(|g| [g.object, g.applies_to]).flatten()
    }
}

// ── reading ──────────────────────────────────────────────────────────────────

/// A value that may be binary: ldap3 keeps it as text when the bytes happen
/// to be valid UTF-8.
fn bytes_of(e: &SearchEntry, key: &str) -> Option<Vec<u8>> {
    e.bin_attrs
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(key))
        .and_then(|(_, v)| v.first().cloned())
        .or_else(|| e.attrs.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).and_then(|(_, v)| v.first()).map(|s| s.as_bytes().to_vec()))
}

fn binary_filter(b: &[u8]) -> String {
    b.iter().map(|x| format!("\\{x:02x}")).collect()
}

/// Names for GUIDs: classes and attributes by lDAPDisplayName, extended
/// rights, property sets and validated writes by their display name (and cn).
#[derive(Default)]
struct Names {
    schema: HashMap<[u8; 16], String>,
    rights: HashMap<[u8; 16], (String, String)>,
}

impl Names {
    fn of(&self, g: &[u8; 16]) -> String {
        let text = guid_text(g);
        self.rights
            .get(g)
            .map(|(_, display)| display.clone())
            .or_else(|| self.schema.get(g).cloned())
            .or_else(|| MORE_RIGHTS.iter().find(|(id, _)| *id == text).map(|(_, n)| n.to_string()))
            .unwrap_or(text)
    }

    /// Whether the schema calls `n` what EasyDC thinks it is.
    fn confirms(&self, n: Named) -> bool {
        let g = guid_bytes(n.guid);
        self.schema.get(&g).is_some_and(|s| s.eq_ignore_ascii_case(n.name))
            || self.rights.get(&g).is_some_and(|(cn, _)| cn.eq_ignore_ascii_case(n.name))
    }
}

async fn names(conn: &mut ldap3::Ldap, p: &Partitions, guids: &HashSet<[u8; 16]>) -> Names {
    let mut out = Names::default();
    let list: Vec<&[u8; 16]> = guids.iter().collect();
    for chunk in list.chunks(40) {
        let terms: String = chunk.iter().map(|g| format!("(schemaIDGUID={})", binary_filter(*g))).collect();
        for e in search(conn, &p.schema, Scope::OneLevel, &format!("(|{terms})"), vec!["lDAPDisplayName", "schemaIDGUID"])
            .await
            .unwrap_or_default()
        {
            if let Some(g) = bytes_of(&e, "schemaIDGUID").and_then(|b| <[u8; 16]>::try_from(b).ok()) {
                out.schema.insert(g, attr_ci(&e, "lDAPDisplayName"));
            }
        }
        let terms: String = chunk.iter().map(|g| format!("(rightsGuid={})", guid_text(g))).collect();
        let base = format!("CN=Extended-Rights,{}", p.config);
        for e in search(conn, &base, Scope::OneLevel, &format!("(|{terms})"), vec!["cn", "displayName", "rightsGuid"])
            .await
            .unwrap_or_default()
        {
            let g = guid_bytes(&attr_ci(&e, "rightsGuid"));
            let cn = attr_ci(&e, "cn");
            let display = Some(attr_ci(&e, "displayName")).filter(|d| !d.is_empty()).unwrap_or_else(|| cn.clone());
            out.rights.insert(g, (cn, display));
        }
    }
    out
}

/// Who a SID is.
#[derive(Clone, Debug)]
struct Who {
    name: String,
    kind: &'static str,
    /// Not made by an admin: a well-known or built-in account, or one of the
    /// domain's own (RID below 1000, such as Domain Admins).
    builtin: bool,
}

const MORE_WELL_KNOWN: [(&str, &str); 7] = [
    ("S-1-3-0", "Creator Owner"),
    ("S-1-5-7", "Anonymous Logon"),
    ("S-1-5-10", "Self"),
    ("S-1-5-18", "SYSTEM"),
    ("S-1-5-32-544", "Administrators"),
    ("S-1-5-32-548", "Account Operators"),
    ("S-1-5-32-550", "Print Operators"),
];

/// The domain's own accounts by RID, for those a domain may not have (a
/// domain provisioned before Key Admins existed still has entries for them).
const DOMAIN_RIDS: [(u32, &str); 8] = [
    (498, "Enterprise Read-only Domain Controllers"),
    (512, "Domain Admins"),
    (516, "Domain Controllers"),
    (518, "Schema Admins"),
    (519, "Enterprise Admins"),
    (521, "Read-only Domain Controllers"),
    (526, "Key Admins"),
    (527, "Enterprise Key Admins"),
];

fn known_name(sid: &str) -> Option<&'static str> {
    ldap::well_known_sid(sid).or_else(|| MORE_WELL_KNOWN.iter().find(|(s, _)| *s == sid).map(|(_, n)| *n)).or_else(|| {
        let rid: u32 = sid.strip_prefix("S-1-5-21-")?.rsplit('-').next()?.parse().ok()?;
        DOMAIN_RIDS.iter().find(|(r, _)| *r == rid).map(|(_, n)| *n)
    })
}

/// Rights a schema may lack a name for, though entries name them.
const MORE_RIGHTS: [(&str, &str); 1] = [("9b026da6-0d3c-465c-8bee-5199d7165cba", "Validated write to computer attributes")];

fn builtin_sid(sid: &str) -> bool {
    if !sid.starts_with("S-1-5-21-") {
        return true;
    }
    sid.rsplit('-').next().and_then(|rid| rid.parse::<u32>().ok()).is_none_or(|rid| rid < 1000)
}

async fn trustees(conn: &mut ldap3::Ldap, base_dn: &str, sids: &HashSet<String>) -> HashMap<String, Who> {
    let mut out = HashMap::new();
    let list: Vec<&String> = sids.iter().collect();
    for chunk in list.chunks(40) {
        let terms: String = chunk.iter().map(|s| format!("(objectSid={})", ldap_escape(s))).collect();
        for e in search(conn, base_dn, Scope::Subtree, &format!("(|{terms})"), vec!["sAMAccountName", "cn", "objectClass", "objectSid"])
            .await
            .unwrap_or_default()
        {
            let Some(sid) = bytes_of(&e, "objectSid").and_then(|b| ldap::sid_string(&b)) else { continue };
            let classes: Vec<String> = crate::health::attrs_ci(&e, "objectClass").iter().map(|c| c.to_ascii_lowercase()).collect();
            let kind = if classes.iter().any(|c| c == "computer") {
                "computer"
            } else if classes.iter().any(|c| c == "group") {
                "group"
            } else if classes.iter().any(|c| c == "user") {
                "user"
            } else {
                ""
            };
            // A foreign security principal is named by its SID: say who that is.
            let name = Some(attr_ci(&e, "sAMAccountName"))
                .filter(|n| !n.is_empty())
                .or_else(|| known_name(&sid).map(str::to_string))
                .unwrap_or_else(|| attr_ci(&e, "cn"));
            let builtin = builtin_sid(&sid);
            out.insert(sid, Who { name, kind, builtin });
        }
    }
    for sid in sids {
        out.entry(sid.clone()).or_insert_with(|| {
            Who { name: known_name(sid).map(str::to_string).unwrap_or_else(|| sid.clone()), kind: "", builtin: builtin_sid(sid) }
        });
    }
    out
}

/// The OU's name and access list.
async fn read_ou(conn: &mut ldap3::Ldap, dn: &str) -> LdapResult<(String, Descriptor)> {
    let (entries, _) = conn
        .with_controls(ldap::sd_flags_dacl())
        .with_timeout(OP_TIMEOUT)
        .search(dn, Scope::Base, "(objectClass=organizationalUnit)", vec!["ou", "nTSecurityDescriptor"])
        .await
        .map_err(ldap::ldap_err)?
        .success()
        .map_err(|_| format!("There is no OU {dn}. It may have just been deleted or renamed."))?;
    let e = entries.into_iter().next().map(SearchEntry::construct).ok_or_else(|| format!("{dn} is not an OU."))?;
    let raw = bytes_of(&e, "nTSecurityDescriptor")
        .ok_or("The DC did not give the OU's access list; the account EasyDC signs in with may not be allowed to read it.")?;
    let d = Descriptor::parse(&raw).map_err(|why| format!("Could not read the access list of {dn}: {why}"))?;
    Ok((attr_ci(&e, "ou"), d))
}

async fn write_ou(conn: &mut ldap3::Ldap, dn: &str, d: &Descriptor, what: &str) -> LdapResult<()> {
    let res = conn
        .with_controls(ldap::sd_flags_dacl())
        .with_timeout(OP_TIMEOUT)
        .modify(dn, vec![Mod::Replace(b"nTSecurityDescriptor".to_vec(), HashSet::from([d.to_bytes()]))])
        .await
        .map_err(ldap::ldap_err)?;
    if res.rc != 0 {
        return Err(ldap::refused(what, "the OU", &res));
    }
    Ok(())
}

// ── sorting entries into what the page shows ─────────────────────────────────

/// One trustee's entries, set here or inherited: the tasks they add up to,
/// and what is left.
struct Sorted {
    sid: Vec<u8>,
    inherited: bool,
    tasks: Vec<&'static Task>,
    rest: Vec<Entry>,
}

fn sort_out(entries: &[Entry]) -> Vec<Sorted> {
    let mut out: Vec<Sorted> = Vec::new();
    for e in entries {
        match out.iter_mut().find(|s| s.sid == e.sid && s.inherited == e.inherited) {
            Some(s) => s.rest.push(e.clone()),
            None => out.push(Sorted { sid: e.sid.clone(), inherited: e.inherited, tasks: Vec::new(), rest: vec![e.clone()] }),
        }
    }
    for s in &mut out {
        for t in &TASKS {
            let wanted = t.entries(&s.sid);
            let mut at = Vec::new();
            for w in &wanted {
                match s.rest.iter().enumerate().position(|(i, e)| !at.contains(&i) && e.same_grant(w)) {
                    Some(i) => at.push(i),
                    None => break,
                }
            }
            if at.len() == wanted.len() {
                s.tasks.push(t);
                at.sort_unstable();
                for i in at.into_iter().rev() {
                    s.rest.remove(i);
                }
            }
        }
    }
    out
}

/// The rights in an entry, in words.
fn rights_words(mask: u32, object: Option<&str>) -> String {
    let mut m = if mask & GENERIC_ALL != 0 { FULL_CONTROL } else { mask };
    if m & FULL_CONTROL == FULL_CONTROL && object.is_none() {
        return "Full control".to_string();
    }
    let mut parts: Vec<String> = Vec::new();
    if m & GENERIC_READ != 0 || (object.is_none() && m & READ == READ) {
        parts.push("Read".into());
        m &= !(READ | GENERIC_READ);
    }
    if m & GENERIC_WRITE != 0 {
        parts.push("Write".into());
    }
    let children = object.map(|o| format!("{o} objects")).unwrap_or_else(|| "all child objects".into());
    match (m & CREATE_CHILD != 0, m & DELETE_CHILD != 0) {
        (true, true) => parts.push(format!("Create and delete {children}")),
        (true, false) => parts.push(format!("Create {children}")),
        (false, true) => parts.push(format!("Delete {children}")),
        _ => {}
    }
    let props = object.unwrap_or("all properties");
    match (m & READ_PROP != 0, m & WRITE_PROP != 0) {
        (true, true) => parts.push(format!("Read and write {props}")),
        (true, false) => parts.push(format!("Read {props}")),
        (false, true) => parts.push(format!("Write {props}")),
        _ => {}
    }
    if m & CONTROL_ACCESS != 0 {
        parts.push(match object {
            // A property set read and written, and its confidential properties too.
            Some(o) if m & (READ_PROP | WRITE_PROP) != 0 => format!("Control access to {o}"),
            Some(o) => o.to_string(),
            None => "All extended rights".into(),
        });
    }
    if m & SELF_WRITE != 0 {
        parts.push(object.map(str::to_string).unwrap_or_else(|| "All validated writes".into()));
    }
    for (bit, words) in [
        (LIST_CHILDREN | GENERIC_EXECUTE, "List contents"),
        (LIST_OBJECT, "List object"),
        (DELETE_TREE, "Delete subtree"),
        (DELETE, "Delete"),
        (READ_CONTROL, "Read permissions"),
        (WRITE_DAC, "Change permissions"),
        (WRITE_OWNER, "Take ownership"),
    ] {
        if m & bit != 0 {
            parts.push(words.into());
        }
    }
    if parts.is_empty() {
        format!("Rights 0x{mask:x}")
    } else {
        parts.join(", ")
    }
}

/// Where an entry applies, in words.
fn scope_words(e: &Entry, names: &Names) -> String {
    let class = e.applies_to.map(|g| format!("{} objects", names.of(&g)));
    match (e.flags & CONTAINER_INHERIT != 0, e.flags & INHERIT_ONLY != 0, class) {
        (false, _, _) => "this OU only".into(),
        (true, false, None) => "this OU and everything in it".into(),
        (true, true, None) => "everything in it".into(),
        (true, true, Some(c)) => format!("{c} in it"),
        (true, false, Some(c)) => format!("this OU and {c} in it"),
    }
}

fn entry_words(e: &Entry, names: &Names) -> String {
    let object = e.object.map(|g| names.of(&g));
    format!("{}{} ({})", if e.deny { "Deny: " } else { "" }, rights_words(e.mask, object.as_deref()), scope_words(e, names))
}

// ── the page ─────────────────────────────────────────────────────────────────

#[derive(Serialize, Debug)]
pub struct Row {
    pub who: String,
    pub sid: String,
    pub kind: String,
    /// The task's key, or empty for other rights.
    pub task: String,
    pub label: String,
    /// Other rights, each in words.
    pub lines: Vec<String>,
    /// Set on a parent OU (or the domain) and inherited here.
    pub inherited: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct View {
    pub dn: String,
    pub name: String,
    /// Rights given to groups and users an admin made.
    pub delegated: Vec<Row>,
    /// Rights of the built-in and well-known accounts.
    pub builtin: Vec<Row>,
}

fn rows(sorted: &[Sorted], who: &HashMap<String, Who>, names: &Names) -> (Vec<Row>, Vec<Row>) {
    let (mut delegated, mut builtin) = (Vec::new(), Vec::new());
    for s in sorted {
        let sid = ldap::sid_string(&s.sid).unwrap_or_default();
        let w = who.get(&sid).cloned().unwrap_or_else(|| Who { name: sid.clone(), kind: "", builtin: builtin_sid(&sid) });
        let row = |task: &str, label: &str, lines: Vec<String>| Row {
            who: w.name.clone(),
            sid: sid.clone(),
            kind: w.kind.to_string(),
            task: task.to_string(),
            label: label.to_string(),
            lines,
            inherited: s.inherited,
        };
        let list = if w.builtin { &mut builtin } else { &mut delegated };
        for t in &s.tasks {
            list.push(row(t.key, t.label, Vec::new()));
        }
        if !s.rest.is_empty() {
            list.push(row("", "Other rights", s.rest.iter().map(|e| entry_words(e, names)).collect()));
        }
    }
    let order = |a: &Row, b: &Row| {
        (a.inherited, a.who.to_lowercase(), a.task.is_empty(), &a.label).cmp(&(b.inherited, b.who.to_lowercase(), b.task.is_empty(), &b.label))
    };
    delegated.sort_by(order);
    builtin.sort_by(order);
    (delegated, builtin)
}

/// Who may do what on the OU `dn`.
pub async fn view(conn: &mut ldap3::Ldap, base_dn: &str, dn: &str) -> LdapResult<View> {
    let (name, d) = read_ou(conn, dn).await?;
    let entries = d.entries();
    let p = Partitions::read(conn, base_dn).await;
    let guids: HashSet<[u8; 16]> = entries.iter().flat_map(|e| [e.object, e.applies_to]).flatten().collect();
    let names = names(conn, &p, &guids).await;
    let sids: HashSet<String> = entries.iter().filter_map(|e| ldap::sid_string(&e.sid)).collect();
    let who = trustees(conn, base_dn, &sids).await;
    let (delegated, builtin) = rows(&sort_out(&entries), &who, &names);
    Ok(View { dn: dn.to_string(), name, delegated, builtin })
}

/// Give the group `group` (its sAMAccountName) the task on the OU `dn`.
/// Returns the group's name and the task's label.
pub async fn grant_task(conn: &mut ldap3::Ldap, base_dn: &str, dn: &str, group: &str, key: &str) -> LdapResult<(String, &'static str)> {
    let t = task(key)?;
    let group = group.trim();
    if group.is_empty() {
        return Err("Choose the group to delegate to.".into());
    }
    let filter = format!("(&(objectClass=group)(sAMAccountName={}))", ldap_escape(group));
    let found = search(conn, base_dn, Scope::Subtree, &filter, vec!["sAMAccountName", "objectSid", "groupType"]).await?;
    let g = found.first().ok_or_else(|| format!("There is no group {group}."))?;
    let sid = bytes_of(g, "objectSid").ok_or_else(|| format!("Could not read the SID of {group}."))?;
    let name = attr_ci(g, "sAMAccountName");
    let group_type: i64 = attr_ci(g, "groupType").parse().unwrap_or(0);
    if group_type & 0x8000_0000 == 0 {
        return Err(format!("{name} is a distribution group, which cannot be given rights. Use a security group."));
    }

    let p = Partitions::read(conn, base_dn).await;
    let wanted: HashSet<[u8; 16]> = t.named().map(|n| guid_bytes(n.guid)).collect();
    let names = names(conn, &p, &wanted).await;
    if let Some(n) = t.named().find(|n| !names.confirms(*n)) {
        return Err(format!(
            "This DC's schema does not have {} where EasyDC expects it, so nothing was written.",
            n.name
        ));
    }

    let (ou, mut d) = read_ou(conn, dn).await?;
    let added = t.entries(&sid).iter().filter(|e| d.add(e)).count();
    if added == 0 {
        return Err(format!("{name} can already do this in {ou}."));
    }
    write_ou(conn, dn, &d, &format!("{name} was not given \"{}\"", t.label)).await?;
    Ok((name, t.label))
}

/// Take a task (or, for an empty key, the other rights) away from the
/// account with `sid` on the OU `dn`: only what was set on this OU. Returns
/// who it was and what was taken.
pub async fn revoke(conn: &mut ldap3::Ldap, base_dn: &str, dn: &str, sid: &str, key: &str) -> LdapResult<(String, String)> {
    if builtin_sid(sid) {
        return Err("The rights of built-in accounts stay as they are.".into());
    }
    let (ou, mut d) = read_ou(conn, dn).await?;
    let entries = d.entries();
    let Some(mine) = sort_out(&entries).into_iter().find(|s| !s.inherited && ldap::sid_string(&s.sid).as_deref() == Some(sid)) else {
        return Err(format!("Nothing set on {ou} for that account. It may have just been changed; reload the page."));
    };
    let (gone, label) = if key.is_empty() {
        (mine.rest.clone(), "Other rights".to_string())
    } else {
        let t = task(key)?;
        if !mine.tasks.iter().any(|x| x.key == t.key) {
            return Err(format!("That account does not have \"{}\" on {ou}. It may have just been changed; reload the page.", t.label));
        }
        (t.entries(&mine.sid), t.label.to_string())
    };
    if gone.is_empty() || d.remove(|e| gone.iter().any(|g| g.same_grant(e))) == 0 {
        return Err(format!("Nothing to remove on {ou}. It may have just been changed; reload the page."));
    }
    let sids = HashSet::from([sid.to_string()]);
    let who = trustees(conn, base_dn, &sids).await.remove(sid).map(|w| w.name).unwrap_or_else(|| sid.to_string());
    write_ou(conn, dn, &d, &format!("\"{label}\" was not taken from {who}")).await?;
    Ok((who, label))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(rid: u32) -> Vec<u8> {
        let mut s = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1, 2, 3, rid] {
            s.extend(sub.to_le_bytes());
        }
        s
    }

    #[test]
    fn guids_are_stored_as_microsoft_documents_them() {
        let user = guid_bytes(USER.guid);
        assert_eq!(&user[..4], &0xbf967abau32.to_le_bytes());
        assert_eq!(&user[4..6], &0x0de6u16.to_le_bytes());
        assert_eq!(&user[6..8], &0x11d0u16.to_le_bytes());
        assert_eq!(user[8..], [0xa2, 0x85, 0x00, 0xaa, 0x00, 0x30, 0x49, 0xe2]);
        for t in &TASKS {
            for n in t.named() {
                assert_eq!(guid_text(&guid_bytes(n.guid)), n.guid);
            }
        }
    }

    #[test]
    fn tasks_are_recognised_and_the_rest_is_kept() {
        let helpdesk = sid(1105);
        let mut entries = TASKS[1].entries(&helpdesk);
        entries.push(Entry::allow(READ, 0, None, None, &helpdesk));
        entries.extend(TASKS[3].entries(&helpdesk));
        let mut inherited = TASKS[1].entries(&helpdesk);
        inherited.iter_mut().for_each(|e| e.inherited = true);
        entries.extend(inherited);
        let sorted = sort_out(&entries);
        assert_eq!(sorted.len(), 2);
        let keys: Vec<&str> = sorted[0].tasks.iter().map(|t| t.key).collect();
        assert_eq!(keys, ["passwords", "members"]);
        assert_eq!(sorted[0].rest.len(), 1);
        assert!(sorted[1].inherited && sorted[1].tasks.len() == 1 && sorted[1].rest.is_empty());
    }

    #[test]
    fn half_a_task_is_shown_as_other_rights() {
        let s = sid(1105);
        let entries = vec![TASKS[0].entries(&s).remove(0)];
        let sorted = sort_out(&entries);
        assert!(sorted[0].tasks.is_empty());
        assert_eq!(sorted[0].rest.len(), 1);
    }

    #[test]
    fn rights_read_as_words() {
        let mut names = Names::default();
        names.schema.insert(guid_bytes(USER.guid), "user".into());
        names.schema.insert(guid_bytes(GP_LINK.guid), "gPLink".into());
        names.rights.insert(guid_bytes(RESET_PASSWORD.guid), ("User-Force-Change-Password".into(), "Reset Password".into()));
        let w = |e: &Entry| entry_words(e, &names);
        let s = sid(1105);
        let e = TASKS[1].entries(&s);
        assert_eq!(w(&e[0]), "Reset Password (user objects in it)");
        let e = TASKS[0].entries(&s);
        assert_eq!(w(&e[0]), "Create and delete user objects (this OU and everything in it)");
        assert_eq!(w(&e[1]), "Full control (user objects in it)");
        assert_eq!(w(&TASKS[5].entries(&s)[0]), "Read and write gPLink (this OU and everything in it)");
        assert_eq!(w(&Entry::allow(READ, 0, None, None, &s)), "Read (this OU only)");
        let mut deny = Entry::allow(DELETE | DELETE_TREE, BELOW, None, None, &s);
        deny.deny = true;
        assert_eq!(w(&deny), "Deny: Delete subtree, Delete (everything in it)");
        assert_eq!(rights_words(GENERIC_ALL, None), "Full control");
        assert_eq!(rights_words(CONTROL_ACCESS, None), "All extended rights");
        assert_eq!(
            rights_words(READ_PROP | WRITE_PROP | CONTROL_ACCESS, Some("Private Information")),
            "Read and write Private Information, Control access to Private Information"
        );
        assert_eq!(names.of(&guid_bytes("9b026da6-0d3c-465c-8bee-5199d7165cba")), "Validated write to computer attributes");
        let unknown = [1u8; 16];
        assert_eq!(names.of(&unknown), "01010101-0101-0101-0101-010101010101");
    }

    #[test]
    fn builtin_accounts_are_told_apart() {
        assert!(builtin_sid("S-1-5-32-544"));
        assert!(builtin_sid("S-1-1-0"));
        assert!(builtin_sid("S-1-5-21-1-2-3-512"), "Domain Admins");
        assert!(!builtin_sid("S-1-5-21-1-2-3-1105"));
        assert_eq!(known_name("S-1-5-11"), Some("Authenticated Users"));
        assert_eq!(known_name("S-1-5-21-1-2-3-526"), Some("Key Admins"));
        assert_eq!(known_name("S-1-5-21-1-2-3-1105"), None);
    }

    #[test]
    fn rows_split_delegated_from_builtin() {
        let helpdesk = sid(1105);
        let admins = sid(512);
        let mut entries = TASKS[1].entries(&helpdesk);
        entries.push(Entry::allow(FULL_CONTROL, 0, None, None, &admins));
        let mut who = HashMap::new();
        who.insert(ldap::sid_string(&helpdesk).unwrap(), Who { name: "Helpdesk".into(), kind: "group", builtin: false });
        who.insert(ldap::sid_string(&admins).unwrap(), Who { name: "Domain Admins".into(), kind: "group", builtin: true });
        let (delegated, builtin) = rows(&sort_out(&entries), &who, &Names::default());
        assert_eq!(delegated.len(), 1);
        assert_eq!((delegated[0].who.as_str(), delegated[0].task.as_str()), ("Helpdesk", "passwords"));
        assert_eq!(builtin.len(), 1);
        assert_eq!(builtin[0].lines, ["Full control (this OU only)"]);
    }
}
