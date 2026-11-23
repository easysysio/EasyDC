//! The domain and forest functional levels, and how to raise them.
//!
//! Samba lets only a system process on a DC change a level, so EasyDC cannot
//! make the change over LDAP. It reads where the domain stands and writes out
//! the commands a chosen level still needs, for the DC that must run them.

use ldap3::Scope as LdapScope;
use serde::Serialize;

use crate::{
    fsmo::{self, Holder, Partitions, Role},
    health::{attr_ci, functional_level_name, read_one, search},
    ldap::{base_dn_to_domain, LdapResult},
};

const ATTR: &str = "msDS-Behavior-Version";
/// Windows Server 2003, the lowest level EasyDC guides a raise to.
const LOWEST_TARGET: i64 = 2;
/// Windows Server 2008 R2, the lowest value `ad dc functional level` takes.
const LOWEST_DC_SETTING: i64 = 4;
/// Windows Server 2016, the highest level Samba can run at.
const HIGHEST_TARGET: i64 = 7;
/// systemFlags of a crossRef that describes a domain.
const CR_NTDS_DOMAIN: i64 = 2;

pub fn label(level: i64) -> String {
    match functional_level_name(level) {
        "unknown" => format!("Level {level}"),
        "2000" => "Windows 2000".to_string(),
        name => format!("Windows Server {name}"),
    }
}

/// The short label shown beside a server, and the detail behind it.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Badge {
    pub text: String,
    pub title: String,
}

pub fn badge(domain: i64, forest: i64, dc: i64) -> Badge {
    let short = |level: i64| match functional_level_name(level) {
        "unknown" => level.to_string(),
        name => name.to_string(),
    };
    let text = if domain == forest {
        format!("Level {}", short(domain))
    } else {
        format!("Domain {} · Forest {}", short(domain), short(forest))
    };
    let title = format!("Domain: {}. Forest: {}. This DC can run at: {}.", label(domain), label(forest), label(dc));
    Badge { text, title }
}

/// `samba-tool`'s and `smb.conf`'s name for a level.
fn tool_name(level: i64) -> &'static str {
    match level {
        2 => "2003",
        3 => "2008",
        4 => "2008_R2",
        5 => "2012",
        6 => "2012_R2",
        _ => "2016",
    }
}

/// What the directory says, as read from one DC.
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub forest: i64,
    pub domain: i64,
    pub domain_name: String,
    pub forest_name: String,
    pub dcs: Vec<(String, i64)>,
    /// The other domains in the forest, and their levels.
    pub other_domains: Vec<(String, i64)>,
    /// Each role's holder if it can be used, or why it cannot.
    pub pdc: Result<String, String>,
    pub naming: Result<String, String>,
    pub schema_master: Result<String, String>,
    pub infrastructure: Result<String, String>,
    pub prep: Prep,
}

/// How far the schema and the forest and domain updates have gone.
#[derive(Debug, Clone, Copy)]
pub struct Prep {
    pub schema: i64,
    pub forest: i64,
    pub domain: i64,
}

/// What a level needs first, and `samba-tool`'s name for that schema.
fn prep_for(level: i64) -> Option<(Prep, &'static str)> {
    let prep = |schema, forest, domain| Prep { schema, forest, domain };
    match level {
        5 => Some((prep(56, 11, 9), "2012")),
        6 => Some((prep(69, 15, 10), "2012_R2")),
        7 => Some((prep(87, 16, 16), "2019")),
        _ => None,
    }
}

/// One thing to do, on the DCs named.
#[derive(Debug, Clone, Serialize)]
pub struct Step {
    pub title: String,
    pub on: String,
    pub detail: String,
    pub commands: Vec<String>,
}

fn step(title: &str, on: &str, detail: &str, commands: Vec<String>) -> Step {
    Step { title: title.to_string(), on: on.to_string(), detail: detail.to_string(), commands }
}

/// Everything a chosen level still needs.
#[derive(Debug, Clone, Serialize)]
pub struct Guide {
    pub level: i64,
    pub label: String,
    pub note: Option<String>,
    /// Why this level cannot be reached until something is fixed.
    pub blocked: Option<String>,
    pub steps: Vec<Step>,
}

/// One of the two levels, as the page shows it.
#[derive(Debug, Clone, Serialize)]
pub struct ScopeView {
    pub title: &'static str,
    pub name: String,
    pub current: String,
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
    pub guides: Vec<Guide>,
    /// Why there is nothing to raise to, when there is not.
    pub why_not: Option<String>,
}

fn same(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

impl Snapshot {
    fn lowest_dc(&self) -> Option<&(String, i64)> {
        self.dcs.iter().min_by_key(|d| d.1)
    }

    /// The forest can reach a level once every other domain has.
    fn forest_can_reach(&self, level: i64) -> bool {
        self.other_domains.iter().all(|d| d.1 >= level)
    }

    fn prepare_steps(&self, level: i64) -> Result<Vec<Step>, String> {
        let Some((need, schema)) = prep_for(level) else {
            return Ok(Vec::new());
        };
        let mut steps = Vec::new();
        let wait = if self.dcs.len() > 1 { "Let it reach the other DCs before the next step." } else { "" };
        if self.prep.schema < need.schema {
            let dc = self.schema_master.clone()?;
            steps.push(step("Upgrade the schema", &dc, wait, vec![format!("samba-tool domain schemaupgrade --schema={schema}")]));
        }
        let command = format!("samba-tool domain functionalprep --function-level={}", tool_name(level));
        let forest_dc = if self.prep.forest < need.forest { Some(self.schema_master.clone()?) } else { None };
        let domain_dc = if self.prep.domain < need.domain { Some(self.infrastructure.clone()?) } else { None };
        match (forest_dc, domain_dc) {
            (Some(f), Some(d)) if same(&f, &d) => steps.push(step("Prepare the forest and domain", &f, wait, vec![command])),
            (f, d) => {
                if let Some(f) = f {
                    steps.push(step("Prepare the forest", &f, wait, vec![format!("{command} --forest-prep")]));
                }
                if let Some(d) = d {
                    steps.push(step("Prepare the domain", &d, wait, vec![format!("{command} --domain-prep")]));
                }
            }
        }
        Ok(steps)
    }

    fn raise_steps(&self, level: i64, domain: bool, forest: bool) -> Result<Vec<Step>, String> {
        let name = tool_name(level);
        let raise = |flags: String| vec![format!("samba-tool domain level raise {flags}")];
        let domain_flag = format!("--domain-level={name}");
        let forest_flag = format!("--forest-level={name}");
        Ok(match (domain, forest) {
            (true, true) => {
                let (pdc, naming) = (self.pdc.clone()?, self.naming.clone()?);
                if same(&pdc, &naming) {
                    vec![step("Raise the domain and forest", &pdc, "This is the step that cannot be undone. Run it on this DC only.", raise(format!("{domain_flag} {forest_flag}")))]
                } else {
                    vec![
                        step("Raise the domain", &pdc, "This cannot be undone. Let it reach the other DCs before the next step.", raise(domain_flag)),
                        step("Raise the forest", &naming, "This cannot be undone.", raise(forest_flag)),
                    ]
                }
            }
            (true, false) => vec![step("Raise the domain", &self.pdc.clone()?, "This is the step that cannot be undone. Run it on this DC only.", raise(domain_flag))],
            _ => vec![step("Raise the forest", &self.naming.clone()?, "This is the step that cannot be undone. Run it on this DC only.", raise(forest_flag))],
        })
    }

    fn steps(&self, level: i64, domain: bool, forest: bool) -> Result<Vec<Step>, String> {
        if self.dcs.is_empty() {
            return Err("EasyDC could not read the level of any DC.".to_string());
        }
        let names = |dcs: Vec<&(String, i64)>| dcs.iter().map(|d| d.0.as_str()).collect::<Vec<_>>().join(", ");
        let everyone = names(self.dcs.iter().collect());
        let mut steps = vec![step("Back up", &everyone, "Take a snapshot or backup of every DC. Going back means restoring all of them together.", Vec::new())];
        let below: Vec<_> = self.dcs.iter().filter(|d| d.1 < level).collect();
        if !below.is_empty() {
            steps.push(step(
                "Allow this level on each DC",
                &names(below),
                "Add this line under [global] in smb.conf, then restart Samba on that DC.",
                vec![format!("ad dc functional level = {}", tool_name(level.max(LOWEST_DC_SETTING)))],
            ));
        }
        steps.extend(self.prepare_steps(level)?);
        steps.extend(self.raise_steps(level, domain, forest)?);
        steps.push(step("Restart Samba", &everyone, "One DC at a time, so that one stays up.", Vec::new()));
        Ok(steps)
    }

    fn guide(&self, level: i64) -> Option<Guide> {
        let domain = self.domain < level;
        let forest = self.forest < level && self.forest_can_reach(level);
        if !domain && !forest {
            return None;
        }
        let mut notes = Vec::new();
        if level > LOWEST_DC_SETTING {
            notes.push("Needs Samba 4.19 or newer, the same version on every DC. Samba 4.19 calls its support for levels above 2008 R2 partial.".to_string());
        }
        if self.forest < level
            && let Some((name, _)) = self.other_domains.iter().filter(|d| d.1 < level).min_by_key(|d| d.1)
        {
            notes.push(format!("The forest stays where it is until domain {name} reaches this level."));
        }
        let (steps, blocked) = match self.steps(level, domain, forest) {
            Ok(steps) => (steps, None),
            Err(why) => (Vec::new(), Some(why)),
        };
        Some(Guide { level, label: label(level), note: (!notes.is_empty()).then(|| notes.join(" ")), blocked, steps })
    }

    fn guides(&self) -> Vec<Guide> {
        let from = (self.domain.min(self.forest) + 1).max(LOWEST_TARGET);
        (from..=HIGHEST_TARGET).filter_map(|l| self.guide(l)).collect()
    }

    pub fn view(&self) -> View {
        let lowest = self.lowest_dc().map(|d| d.1);
        let guides = self.guides();
        let why_not = guides.is_empty().then(|| {
            if self.domain >= HIGHEST_TARGET && self.forest >= HIGHEST_TARGET {
                format!("{} is the highest level Samba can run at.", label(HIGHEST_TARGET))
            } else {
                "The forest cannot go higher until its other domains do.".to_string()
            }
        });
        View {
            scopes: vec![
                ScopeView { title: "Domain", name: self.domain_name.clone(), current: label(self.domain) },
                ScopeView { title: "Forest", name: self.forest_name.clone(), current: label(self.forest) },
            ],
            dcs: self
                .dcs
                .iter()
                .map(|(name, level)| DcLevel { name: name.clone(), level: label(*level), lowest: Some(*level) == lowest })
                .collect(),
            guides,
            why_not,
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
    let domain = number(attr_ci(&read_one(conn, &p.domain, vec![ATTR]).await?, ATTR), "domain")?;

    let refs = search(conn, &partitions, LdapScope::Subtree, "(objectClass=crossRef)", vec!["nCName", "systemFlags", "dnsRoot", ATTR]).await?;
    let mut other_domains = Vec::new();
    for e in refs.iter().filter(|e| attr_ci(e, "systemFlags").parse::<i64>().is_ok_and(|f| f & CR_NTDS_DOMAIN != 0)) {
        let nc = attr_ci(e, "nCName");
        if !nc.eq_ignore_ascii_case(&p.domain) {
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
        domain_name: base_dn_to_domain(&p.domain),
        forest_name: base_dn_to_domain(&p.forest),
        dcs,
        other_domains,
        pdc: usable(roles, Role::Pdc),
        naming: usable(roles, Role::Naming),
        schema_master: usable(roles, Role::Schema),
        infrastructure: usable(roles, Role::Infrastructure),
        prep,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const READY: Prep = Prep { schema: 88, forest: 16, domain: 16 };

    fn snapshot(forest: i64, domain: i64, dcs: &[i64]) -> Snapshot {
        Snapshot {
            forest,
            domain,
            domain_name: "lab.test".into(),
            forest_name: "lab.test".into(),
            dcs: dcs.iter().enumerate().map(|(i, l)| (format!("DC{}", i + 1), *l)).collect(),
            other_domains: vec![],
            pdc: Ok("DC1".into()),
            naming: Ok("DC1".into()),
            schema_master: Ok("DC1".into()),
            infrastructure: Ok("DC1".into()),
            prep: READY,
        }
    }

    fn titles(g: &Guide) -> Vec<&str> {
        g.steps.iter().map(|s| s.title.as_str()).collect()
    }

    fn commands(g: &Guide) -> Vec<&str> {
        g.steps.iter().flat_map(|s| s.commands.iter().map(String::as_str)).collect()
    }

    #[test]
    fn every_level_above_the_domain_gets_a_guide() {
        let levels: Vec<i64> = snapshot(4, 4, &[7, 7]).view().guides.iter().map(|g| g.level).collect();
        assert_eq!(levels, [5, 6, 7]);
        let levels: Vec<i64> = snapshot(0, 0, &[7]).view().guides.iter().map(|g| g.level).collect();
        assert_eq!(levels, [2, 3, 4, 5, 6, 7], "nothing below 2003");
    }

    #[test]
    fn at_the_top_there_is_nothing_to_do() {
        let v = snapshot(7, 7, &[7, 7]).view();
        assert!(v.guides.is_empty());
        assert!(v.why_not.unwrap().contains("highest level"));
    }

    #[test]
    fn a_ready_domain_needs_only_the_raise() {
        let g = snapshot(4, 4, &[7, 7]).guide(7).unwrap();
        assert_eq!(titles(&g), ["Back up", "Raise the domain and forest", "Restart Samba"]);
        assert_eq!(commands(&g), ["samba-tool domain level raise --domain-level=2016 --forest-level=2016"]);
        assert_eq!(g.steps[1].on, "DC1");
        assert_eq!(g.steps[2].on, "DC1, DC2");
        assert!(g.note.unwrap().contains("4.19"));
    }

    #[test]
    fn only_the_dcs_below_the_level_are_changed() {
        let g = snapshot(4, 4, &[7, 4, 5]).guide(6).unwrap();
        let s = g.steps.iter().find(|s| s.title.starts_with("Allow")).unwrap();
        assert_eq!(s.on, "DC2, DC3");
        assert_eq!(s.commands, ["ad dc functional level = 2012_R2"]);
    }

    #[test]
    fn an_unprepared_directory_gets_the_commands_for_that_level() {
        let mut s = snapshot(4, 4, &[7, 7]);
        s.prep = Prep { schema: 47, forest: 5, domain: 5 };
        assert_eq!(
            commands(&s.guide(7).unwrap())[..2],
            ["samba-tool domain schemaupgrade --schema=2019", "samba-tool domain functionalprep --function-level=2016"]
        );
        assert_eq!(
            commands(&s.guide(6).unwrap())[..2],
            ["samba-tool domain schemaupgrade --schema=2012_R2", "samba-tool domain functionalprep --function-level=2012_R2"]
        );
        // A step already done is not asked for again.
        s.prep = Prep { schema: 88, forest: 16, domain: 5 };
        let g = s.guide(7).unwrap();
        assert_eq!(commands(&g)[0], "samba-tool domain functionalprep --function-level=2016 --domain-prep");
        assert!(!commands(&g).iter().any(|c| c.contains("schemaupgrade")));
    }

    #[test]
    fn levels_up_to_2008_r2_need_no_prep() {
        let mut s = snapshot(3, 3, &[4, 4]);
        s.prep = Prep { schema: 47, forest: 5, domain: 5 };
        let g = s.guide(4).unwrap();
        assert_eq!(commands(&g), ["samba-tool domain level raise --domain-level=2008_R2 --forest-level=2008_R2"]);
        assert!(g.note.is_none());
    }

    #[test]
    fn each_command_names_the_dc_with_the_role() {
        let mut s = snapshot(4, 4, &[7, 7]);
        s.prep = Prep { schema: 47, forest: 5, domain: 5 };
        s.schema_master = Ok("DC2".into());
        s.infrastructure = Ok("DC3".into());
        s.naming = Ok("DC4".into());
        let g = s.guide(7).unwrap();
        let on = |t: &str| g.steps.iter().find(|s| s.title == t).unwrap().on.clone();
        assert_eq!(on("Upgrade the schema"), "DC2");
        assert_eq!(on("Prepare the forest"), "DC2");
        assert_eq!(on("Prepare the domain"), "DC3");
        assert_eq!(on("Raise the domain"), "DC1");
        assert_eq!(on("Raise the forest"), "DC4");
        assert!(commands(&g).contains(&"samba-tool domain functionalprep --function-level=2016 --forest-prep"));
        assert!(commands(&g).contains(&"samba-tool domain level raise --domain-level=2016"));
        assert!(commands(&g).contains(&"samba-tool domain level raise --forest-level=2016"));
    }

    #[test]
    fn the_forest_waits_for_its_other_domains() {
        let mut s = snapshot(4, 4, &[7]);
        s.other_domains.push(("child.lab.test".into(), 5));
        let g = s.guide(7).unwrap();
        assert_eq!(commands(&g), ["samba-tool domain level raise --domain-level=2016"]);
        assert!(g.note.unwrap().contains("child.lab.test"));
        assert!(commands(&s.guide(5).unwrap())[0].contains("--forest-level=2012"));

        let mut s = snapshot(4, 7, &[7]);
        s.other_domains.push(("child.lab.test".into(), 4));
        let v = s.view();
        assert!(v.guides.is_empty());
        assert!(v.why_not.unwrap().contains("other domains"));
    }

    #[test]
    fn a_domain_already_higher_raises_only_the_forest() {
        let g = snapshot(4, 7, &[7]).guide(7).unwrap();
        assert_eq!(commands(&g), ["samba-tool domain level raise --forest-level=2016"]);
    }

    #[test]
    fn a_role_with_no_live_holder_blocks_the_guide() {
        let mut s = snapshot(4, 4, &[7]);
        s.pdc = Err("The PDC emulator is on OLD, which no longer exists.".into());
        let g = s.guide(7).unwrap();
        assert!(g.steps.is_empty());
        assert!(g.blocked.unwrap().contains("OLD"));
    }

    #[test]
    fn with_no_dcs_read_there_are_no_steps() {
        let g = snapshot(4, 4, &[]).guide(5).unwrap();
        assert!(g.steps.is_empty() && g.blocked.is_some());
    }

    #[test]
    fn the_badge_is_short_and_shows_a_difference() {
        assert_eq!(badge(7, 7, 7).text, "Level 2016");
        assert_eq!(badge(4, 4, 7).text, "Level 2008 R2");
        assert_eq!(badge(5, 4, 7).text, "Domain 2012 · Forest 2008 R2");
        assert_eq!(badge(9, 9, 9).text, "Level 9");
        assert_eq!(badge(4, 4, 7).title, "Domain: Windows Server 2008 R2. Forest: Windows Server 2008 R2. This DC can run at: Windows Server 2016.");
    }

    #[test]
    fn levels_have_names() {
        assert_eq!(label(4), "Windows Server 2008 R2");
        assert_eq!(label(7), "Windows Server 2016");
        assert_eq!(label(99), "Level 99");
    }
}
