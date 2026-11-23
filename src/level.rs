//! The domain and forest functional levels, and raising them.
//!
//! A level says which features every DC can be relied on to have. Raising one
//! cannot be undone from here, and a DC below it can no longer join, so every
//! limit is checked again on the DC that makes the change: the PDC emulator
//! for the domain, the domain naming master for the forest ([MS-ADTS] 6.1.4).

use std::collections::HashSet;

use ldap3::{Mod, Scope as LdapScope};
use serde::Serialize;

use crate::{
    fsmo::{self, Holder, Partitions, Role},
    health::{attr_ci, functional_level_name, read_one, search},
    ldap::{self, base_dn_to_domain, ldap_err, LdapResult, OP_TIMEOUT},
    models::Server,
};

const ATTR: &str = "msDS-Behavior-Version";
/// Windows Server 2003, the lowest level EasyDC raises to.
const LOWEST_TARGET: i64 = 2;
/// Windows Server 2016, the highest level Samba can run at.
const HIGHEST_TARGET: i64 = 7;
/// systemFlags of a crossRef that describes a domain.
const CR_NTDS_DOMAIN: i64 = 2;
const UNWILLING_TO_PERFORM: u32 = 53;

pub fn label(level: i64) -> String {
    match functional_level_name(level) {
        "unknown" => format!("Level {level}"),
        "2000" => "Windows 2000".to_string(),
        name => format!("Windows Server {name}"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Domain,
    Forest,
}

impl Scope {
    pub fn from_key(key: &str) -> Option<Self> {
        match key {
            "domain" => Some(Self::Domain),
            "forest" => Some(Self::Forest),
            _ => None,
        }
    }

    pub fn key(self) -> &'static str {
        match self {
            Self::Domain => "domain",
            Self::Forest => "forest",
        }
    }
}

/// What the directory says, as read from one DC.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub forest: i64,
    pub domain: i64,
    pub mixed: bool,
    pub domain_name: String,
    pub forest_name: String,
    /// This domain's crossRef, which carries its level for the whole forest.
    pub cross_ref: Option<String>,
    pub dcs: Vec<(String, i64)>,
    /// The other domains in the forest, and their levels.
    pub other_domains: Vec<(String, i64)>,
    /// The role's holder if it can be used, or why it cannot.
    pub pdc: Result<String, String>,
    pub naming: Result<String, String>,
    pub prep: Prep,
}

/// How far the schema and the forest and domain updates have gone.
#[derive(Debug, Clone, Copy)]
pub struct Prep {
    pub schema: i64,
    pub forest: i64,
    pub domain: i64,
}

/// What a level needs first: the schema version, the forest and domain update
/// revisions, and the names `samba-tool` uses for the schema and the level.
fn prep_for(level: i64) -> Option<(Prep, &'static str, &'static str)> {
    let prep = |schema, forest, domain| Prep { schema, forest, domain };
    match level {
        5 => Some((prep(56, 11, 9), "2012", "2012")),
        6 => Some((prep(69, 15, 10), "2012_R2", "2012_R2")),
        7 => Some((prep(87, 16, 16), "2019", "2016")),
        _ => None,
    }
}

fn prep_advice(level: i64) -> String {
    let (schema, function) = prep_for(level).map_or(("", ""), |p| (p.1, p.2));
    format!(
        "{} needs the directory prepared first. On the DC holding the schema and infrastructure master roles, run samba-tool domain schemaupgrade --schema={schema}, then samba-tool domain functionalprep --function-level={function}.",
        label(level)
    )
}

#[derive(Debug, Clone, Serialize)]
pub struct Target {
    pub level: i64,
    pub label: String,
}

/// One of the two levels, as the page shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeView {
    pub key: &'static str,
    pub title: &'static str,
    pub name: String,
    pub level: i64,
    pub current: String,
    pub holder: String,
    pub role: &'static str,
    pub targets: Vec<Target>,
    /// Why it cannot be raised now, when it cannot.
    pub why_not: Option<String>,
    /// What a higher level still needs, when a lower one can be raised to.
    pub prep_note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DcLevel {
    pub name: String,
    pub level: String,
    pub lowest: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct View {
    pub scopes: Vec<ScopeView>,
    pub dcs: Vec<DcLevel>,
}

impl Snapshot {
    fn lowest_dc(&self) -> Option<&(String, i64)> {
        self.dcs.iter().min_by_key(|d| d.1)
    }

    fn holder(&self, scope: Scope) -> &Result<String, String> {
        match scope {
            Scope::Domain => &self.pdc,
            Scope::Forest => &self.naming,
        }
    }

    pub fn name(&self, scope: Scope) -> &str {
        match scope {
            Scope::Domain => &self.domain_name,
            Scope::Forest => &self.forest_name,
        }
    }

    fn current(&self, scope: Scope) -> i64 {
        match scope {
            Scope::Domain => self.domain,
            Scope::Forest => self.forest,
        }
    }

    /// The most this level may be raised to.
    fn ceiling(&self, scope: Scope) -> i64 {
        match scope {
            Scope::Domain => self.lowest_dc().map_or(0, |d| d.1),
            Scope::Forest => self.other_domains.iter().map(|d| d.1).fold(self.domain, i64::min),
        }
    }

    pub fn targets(&self, scope: Scope) -> Vec<i64> {
        let (current, ceiling) = (self.current(scope), self.ceiling(scope).min(HIGHEST_TARGET));
        (LOWEST_TARGET..=ceiling).filter(|l| *l > current && self.prepared(*l)).collect()
    }

    fn prepared(&self, level: i64) -> bool {
        prep_for(level).is_none_or(|(need, ..)| {
            self.prep.schema >= need.schema && self.prep.forest >= need.forest && self.prep.domain >= need.domain
        })
    }

    /// The highest level the DCs allow that is not prepared yet.
    fn unprepared(&self, scope: Scope) -> Option<i64> {
        let (current, ceiling) = (self.current(scope), self.ceiling(scope).min(HIGHEST_TARGET));
        (LOWEST_TARGET..=ceiling).rev().find(|l| *l > current && !self.prepared(*l))
    }

    /// Why this level cannot be raised at all right now.
    pub fn why_not(&self, scope: Scope) -> Option<String> {
        if self.current(scope) >= HIGHEST_TARGET {
            return Some(format!("{} is the highest level Samba can run at.", label(HIGHEST_TARGET)));
        }
        match scope {
            Scope::Domain => {
                if self.mixed {
                    return Some("This domain is in mixed mode. Raise it on a DC with samba-tool domain level raise.".to_string());
                }
                if self.cross_ref.is_none() {
                    return Some("EasyDC could not find this domain's entry in the forest's list of partitions.".to_string());
                }
                let Some((dc, level)) = self.lowest_dc() else {
                    return Some("EasyDC could not read the level of any DC.".to_string());
                };
                if *level <= self.domain {
                    return Some(format!(
                        "{dc} can run at {} at most, and the domain cannot be higher than its lowest DC.",
                        label(*level)
                    ));
                }
            }
            Scope::Forest => {
                if let Some((name, level)) = self.other_domains.iter().min_by_key(|d| d.1)
                    && *level <= self.forest
                {
                    return Some(format!("Domain {name} is at {}. Raise it first.", label(*level)));
                }
                if self.domain <= self.forest {
                    return Some("The forest cannot be higher than its domains. Raise the domain first.".to_string());
                }
            }
        }
        if self.targets(scope).is_empty()
            && let Some(level) = self.unprepared(scope)
        {
            return Some(prep_advice(level));
        }
        self.holder(scope).as_ref().err().cloned()
    }

    /// May this level be raised to `target`, as far as this DC knows?
    pub fn check(&self, scope: Scope, target: i64) -> Result<(), String> {
        if let Some(why) = self.why_not(scope) {
            return Err(why);
        }
        if target <= self.current(scope) {
            return Err(format!("It is already at {}, and a level can only be raised.", label(self.current(scope))));
        }
        if target <= self.ceiling(scope).min(HIGHEST_TARGET) && !self.prepared(target) {
            return Err(prep_advice(target));
        }
        if !self.targets(scope).contains(&target) {
            return Err(format!("{} is above what this {} can run at.", label(target), scope.key()));
        }
        Ok(())
    }

    pub fn view(&self) -> View {
        let lowest = self.lowest_dc().map(|d| d.1);
        let scope_view = |scope: Scope, title, role| ScopeView {
            key: scope.key(),
            title,
            name: self.name(scope).to_string(),
            level: self.current(scope),
            current: label(self.current(scope)),
            holder: self.holder(scope).clone().unwrap_or_default(),
            role,
            why_not: self.why_not(scope),
            prep_note: if self.why_not(scope).is_none() { self.unprepared(scope).map(prep_advice) } else { None },
            targets: match self.why_not(scope) {
                Some(_) => Vec::new(),
                None => self.targets(scope).into_iter().map(|level| Target { level, label: label(level) }).collect(),
            },
        };
        View {
            scopes: vec![
                scope_view(Scope::Domain, "Domain", "PDC emulator"),
                scope_view(Scope::Forest, "Forest", "domain naming master"),
            ],
            dcs: self
                .dcs
                .iter()
                .map(|(name, level)| DcLevel { name: name.clone(), level: label(*level), lowest: Some(*level) == lowest })
                .collect(),
        }
    }
}

fn usable(roles: &[Holder], role: Role) -> Result<String, String> {
    let Some(h) = roles.iter().find(|h| h.role == role) else {
        return Err(format!("EasyDC could not find the {}.", role.label()));
    };
    if h.missing || h.dc.is_empty() {
        return Err(format!("No DC holds the {}. Take the role on a DC first.", h.label));
    }
    if h.gone {
        return Err(format!("The {} is on {}, which no longer exists. Take the role on a DC first.", h.label, h.dc));
    }
    Ok(h.dc.clone())
}

fn number(value: String, what: &str) -> LdapResult<i64> {
    if value.is_empty() {
        return Ok(0);
    }
    value.parse().map_err(|_| format!("The {what} level in the directory is not a number: {value}"))
}

/// A number from one object. Missing or unreadable counts as not prepared.
async fn prep_number(conn: &mut ldap3::Ldap, dn: &str, attr: &str) -> i64 {
    read_one(conn, dn, vec![attr]).await.ok().and_then(|e| attr_ci(&e, attr).parse().ok()).unwrap_or(0)
}

pub async fn read(conn: &mut ldap3::Ldap, p: &Partitions, roles: &[Holder]) -> LdapResult<Snapshot> {
    let partitions = format!("CN=Partitions,{}", p.config);
    let forest = number(attr_ci(&read_one(conn, &partitions, vec![ATTR]).await?, ATTR), "forest")?;
    let domain_entry = read_one(conn, &p.domain, vec![ATTR, "nTMixedDomain"]).await?;
    let domain = number(attr_ci(&domain_entry, ATTR), "domain")?;
    let mixed = number(attr_ci(&domain_entry, "nTMixedDomain"), "mixed mode")? != 0;

    let refs = search(conn, &partitions, LdapScope::Subtree, "(objectClass=crossRef)", vec!["nCName", "systemFlags", "dnsRoot", ATTR]).await?;
    let (mut cross_ref, mut other_domains) = (None, Vec::new());
    for e in refs.iter().filter(|e| attr_ci(e, "systemFlags").parse::<i64>().is_ok_and(|f| f & CR_NTDS_DOMAIN != 0)) {
        let nc = attr_ci(e, "nCName");
        if nc.eq_ignore_ascii_case(&p.domain) {
            cross_ref = Some(e.dn.clone());
        } else {
            let name = attr_ci(e, "dnsRoot");
            let name = if name.is_empty() { base_dn_to_domain(&nc) } else { name };
            other_domains.push((name, number(attr_ci(e, ATTR), "domain")?));
        }
    }

    let sites = format!("CN=Sites,{}", p.config);
    let ntds = search(conn, &sites, LdapScope::Subtree, "(objectClass=nTDSDSA)", vec![ATTR]).await?;
    let mut dcs = Vec::new();
    for e in &ntds {
        dcs.push((fsmo::ntds_dn_of(&e.dn), number(attr_ci(e, ATTR), "DC")?));
    }
    dcs.sort_by_key(|d| d.0.to_lowercase());

    let prep = Prep {
        schema: prep_number(conn, &p.schema, "objectVersion").await,
        forest: prep_number(conn, &format!("CN=ActiveDirectoryUpdate,CN=ForestUpdates,{}", p.config), "revision").await,
        domain: prep_number(conn, &format!("CN=ActiveDirectoryUpdate,CN=DomainUpdates,CN=System,{}", p.domain), "revision").await,
    };

    Ok(Snapshot {
        forest,
        domain,
        mixed,
        domain_name: base_dn_to_domain(&p.domain),
        forest_name: base_dn_to_domain(&p.forest),
        cross_ref,
        dcs,
        other_domains,
        pdc: usable(roles, Role::Pdc),
        naming: usable(roles, Role::Naming),
        prep,
    })
}

/// A raise that was made and read back.
#[derive(Debug, PartialEq)]
pub struct Raised {
    pub name: String,
    pub from: i64,
    pub to: i64,
}

async fn replace(conn: &mut ldap3::Ldap, dn: &str, value: i64) -> LdapResult<ldap3::LdapResult> {
    let values = HashSet::from([value.to_string().into_bytes()]);
    let mods = vec![Mod::Replace(ATTR.as_bytes().to_vec(), values)];
    conn.with_timeout(OP_TIMEOUT).modify(dn, mods).await.map_err(ldap_err)
}

async fn write(conn: &mut ldap3::Ldap, p: &Partitions, s: &Snapshot, scope: Scope, target: i64) -> LdapResult<()> {
    let what = format!("Could not raise the {} level", scope.key());
    let dn = match scope {
        Scope::Domain => p.domain.clone(),
        Scope::Forest => format!("CN=Partitions,{}", p.config),
    };
    let res = replace(conn, &dn, target).await?;
    if res.rc != 0 {
        return Err(ldap::refused(&what, s.name(scope), &res));
    }
    if scope == Scope::Domain {
        let cross_ref = s.cross_ref.as_deref().ok_or("This domain has no entry in the forest's partitions.")?;
        let res = replace(conn, cross_ref, target).await?;
        // A DC that is not the naming master may decline this copy, which
        // then arrives by replication.
        if res.rc != 0 && res.rc != UNWILLING_TO_PERFORM {
            return Err(format!(
                "The domain is now at {}, but its entry in the forest's partitions was not updated: {}",
                label(target),
                ldap::refused(&what, cross_ref, &res)
            ));
        }
    }
    let now = number(attr_ci(&read_one(conn, &dn, vec![ATTR]).await?, ATTR), scope.key())?;
    if now != target {
        return Err(format!("The DC accepted the change, but the {} still reads {}.", scope.key(), label(now)));
    }
    Ok(())
}

/// Raise one level. `confirm` is its name, typed again.
pub async fn raise(server: &Server, conn: &mut ldap3::Ldap, base_dn: &str, scope: Scope, target: i64, confirm: &str) -> LdapResult<Raised> {
    let (o, infos, p) = fsmo::overview(conn, base_dn).await?;
    let here = read(conn, &p, &o.roles).await?;
    if !confirm.trim().eq_ignore_ascii_case(here.name(scope)) {
        return Err(format!("Type the {}'s name, {}, to confirm.", scope.key(), here.name(scope)));
    }
    here.check(scope, target)?;
    let holder = here.holder(scope).clone()?;
    let dc = infos
        .iter()
        .find(|d| d.name.eq_ignore_ascii_case(&holder))
        .ok_or_else(|| format!("{holder} is not in the list of DCs."))?;

    // The DC that makes the change has the last word on every limit.
    let mut on_holder = fsmo::connect_to(server, dc).await?;
    let result = async {
        let names: HashSet<String> = infos.iter().map(|d| d.name.to_lowercase()).collect();
        let roles = fsmo::holders(&mut on_holder, &p, &names).await;
        let there = read(&mut on_holder, &p, &roles).await?;
        if !there.holder(scope).as_ref().is_ok_and(|h| h.eq_ignore_ascii_case(&holder)) {
            return Err(format!("{holder} no longer holds the role this change needs. Reload the page and try again."));
        }
        there.check(scope, target)?;
        write(&mut on_holder, &p, &there, scope, target).await?;
        Ok(Raised { name: there.name(scope).to_string(), from: there.current(scope), to: target })
    }
    .await;
    let _ = on_holder.unbind().await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(forest: i64, domain: i64, dcs: &[i64]) -> Snapshot {
        Snapshot {
            forest,
            domain,
            mixed: false,
            domain_name: "lab.test".into(),
            forest_name: "lab.test".into(),
            cross_ref: Some("CN=LAB,CN=Partitions".into()),
            dcs: dcs.iter().enumerate().map(|(i, l)| (format!("DC{}", i + 1), *l)).collect(),
            other_domains: vec![],
            pdc: Ok("DC1".into()),
            naming: Ok("DC1".into()),
            prep: Prep { schema: 88, forest: 16, domain: 16 },
        }
    }

    #[test]
    fn a_level_waits_for_its_prep() {
        let mut s = snapshot(4, 4, &[7, 7]);
        s.prep = Prep { schema: 47, forest: 5, domain: 5 };
        assert!(s.targets(Scope::Domain).is_empty());
        assert!(s.why_not(Scope::Domain).unwrap().contains("schemaupgrade --schema=2019"));
        assert!(s.check(Scope::Domain, 7).unwrap_err().contains("functionalprep --function-level=2016"));

        // The schema alone is not enough.
        s.prep = Prep { schema: 88, forest: 5, domain: 5 };
        assert!(s.targets(Scope::Domain).is_empty());

        s.prep = Prep { schema: 56, forest: 11, domain: 9 };
        assert_eq!(s.targets(Scope::Domain), [5]);
        assert!(s.check(Scope::Domain, 5).is_ok());
        assert!(s.check(Scope::Domain, 6).unwrap_err().contains("--function-level=2012_R2"));
        assert!(s.view().scopes[0].prep_note.as_deref().unwrap().contains("--function-level=2016"));

        s.prep = Prep { schema: 88, forest: 16, domain: 16 };
        assert_eq!(s.targets(Scope::Domain), [5, 6, 7]);
        assert!(s.view().scopes[0].prep_note.is_none());
    }

    #[test]
    fn levels_up_to_2008_r2_need_no_prep() {
        let mut s = snapshot(2, 2, &[4, 4]);
        s.prep = Prep { schema: 47, forest: 5, domain: 5 };
        assert_eq!(s.targets(Scope::Domain), [3, 4]);
    }

    #[test]
    fn the_domain_stops_at_its_lowest_dc() {
        let s = snapshot(3, 3, &[7, 5]);
        assert_eq!(s.targets(Scope::Domain), [4, 5]);
        assert!(s.check(Scope::Domain, 5).is_ok());
        assert!(s.check(Scope::Domain, 6).unwrap_err().contains("above what"));
        assert!(s.check(Scope::Domain, 3).unwrap_err().contains("only be raised"));
        assert!(s.check(Scope::Domain, 2).is_err());
    }

    #[test]
    fn a_dc_with_no_level_holds_the_domain_back() {
        let s = snapshot(2, 2, &[7, 0]);
        assert!(s.targets(Scope::Domain).is_empty());
        assert!(s.why_not(Scope::Domain).unwrap().contains("DC2"));
        assert!(s.check(Scope::Domain, 3).is_err());
    }

    #[test]
    fn with_no_dcs_read_nothing_is_raised() {
        let s = snapshot(2, 2, &[]);
        assert!(s.check(Scope::Domain, 3).is_err());
    }

    #[test]
    fn the_forest_stops_at_its_lowest_domain() {
        let mut s = snapshot(3, 5, &[7]);
        assert_eq!(s.targets(Scope::Forest), [4, 5]);
        s.other_domains.push(("child.lab.test".into(), 4));
        assert_eq!(s.targets(Scope::Forest), [4]);
        assert!(s.check(Scope::Forest, 5).is_err());
        assert!(s.check(Scope::Forest, 4).is_ok());
        s.other_domains[0].1 = 3;
        assert!(s.why_not(Scope::Forest).unwrap().contains("child.lab.test"));
    }

    #[test]
    fn the_forest_waits_for_the_domain() {
        let s = snapshot(4, 4, &[7]);
        assert!(s.why_not(Scope::Forest).unwrap().contains("Raise the domain first"));
        assert!(s.check(Scope::Forest, 5).is_err());
    }

    #[test]
    fn nothing_goes_past_2016_or_below_2003() {
        let s = snapshot(0, 0, &[10]);
        assert_eq!(s.targets(Scope::Domain), [2, 3, 4, 5, 6, 7]);
        assert!(s.check(Scope::Domain, 10).is_err());
        assert!(s.check(Scope::Domain, 1).is_err());
        let top = snapshot(7, 7, &[7]);
        assert!(top.why_not(Scope::Domain).unwrap().contains("highest"));
        assert!(top.why_not(Scope::Forest).unwrap().contains("highest"));
    }

    #[test]
    fn mixed_mode_and_a_missing_entry_are_refused() {
        let mut s = snapshot(2, 2, &[7]);
        s.mixed = true;
        assert!(s.check(Scope::Domain, 3).unwrap_err().contains("mixed mode"));
        let mut s = snapshot(2, 2, &[7]);
        s.cross_ref = None;
        assert!(s.check(Scope::Domain, 3).is_err());
    }

    #[test]
    fn a_role_with_no_live_holder_stops_the_raise() {
        let mut s = snapshot(2, 3, &[7]);
        s.pdc = Err("The PDC emulator is on OLD, which no longer exists.".into());
        s.naming = Err("No DC holds the domain naming master.".into());
        assert!(s.check(Scope::Domain, 4).unwrap_err().contains("OLD"));
        assert!(s.check(Scope::Forest, 3).unwrap_err().contains("naming"));
    }

    #[test]
    fn the_view_offers_only_what_is_allowed() {
        let v = snapshot(3, 4, &[5, 4]).view();
        assert_eq!(v.scopes[0].key, "domain");
        assert!(v.scopes[0].targets.is_empty(), "the lowest DC is at the domain's level");
        assert!(v.scopes[0].why_not.as_deref().unwrap().contains("DC2"));
        assert_eq!(v.scopes[1].targets.iter().map(|t| t.level).collect::<Vec<_>>(), [4]);
        assert_eq!(v.scopes[1].targets[0].label, "Windows Server 2008 R2");
        assert!(v.dcs[1].lowest && !v.dcs[0].lowest);
    }

    #[test]
    fn levels_have_names() {
        assert_eq!(label(0), "Windows 2000");
        assert_eq!(label(4), "Windows Server 2008 R2");
        assert_eq!(label(7), "Windows Server 2016");
        assert_eq!(label(10), "Level 10");
    }
}
