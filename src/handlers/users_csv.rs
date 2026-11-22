//! Users as a CSV file: the Users page's view exported, and new users
//! created from a file. An import is checked first (nothing is changed),
//! then the browser sends the rows that passed in parts, like a bulk action.

use std::collections::{HashMap, HashSet};

use axum::{
    extract::{Path, Query, State},
    http::header,
    response::{IntoResponse, Response},
    Form, Json,
};
use serde::{Deserialize, Serialize};

use super::ldap_mgmt::{get_server, ListView};
use crate::{auth::CurrentUser, csv, db, ldap, AppState};

/// The columns an export has, in order. An import reads the same names.
const EXPORT_HEADER: [&str; 15] = [
    "Username",
    "First name",
    "Last name",
    "Display name",
    "Email",
    "Description",
    "Job title",
    "Department",
    "Office",
    "Phone",
    "Mobile",
    "Manager",
    "Account expires",
    "OU",
    "Enabled",
];

// ── export ───────────────────────────────────────────────────────────────────

/// GET: the users the page shows (its OU, nested or not, and status), as a
/// CSV file. The search box is not part of the view: it filters in the browser.
pub async fn export(State(state): State<AppState>, Path(id): Path<i64>, Query(view): Query<ListView>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    };
    let users = match async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        ldap::list_users(&mut conn, &base_dn).await
    }
    .await
    {
        Ok(u) => u,
        Err(e) => return (axum::http::StatusCode::BAD_GATEWAY, format!("The users could not be read: {e}")).into_response(),
    };
    let shown: Vec<&ldap::LdapUser> = users.iter().filter(|u| view.shows(u)).collect();
    let body = export_csv(&shown);
    let file = format!("users-{}.csv", file_name_part(&server.name));
    (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{file}\"")),
            (header::CACHE_CONTROL, "no-store".to_string()),
        ],
        body,
    )
        .into_response()
}

fn export_csv(users: &[&ldap::LdapUser]) -> String {
    let mut out = String::from(csv::BOM);
    csv::write_row(&mut out, &EXPORT_HEADER);
    for u in users {
        csv::write_row(
            &mut out,
            &[
                u.username.as_str(),
                &u.first_name,
                &u.last_name,
                &u.display_name,
                &u.email,
                &u.description,
                &u.title,
                &u.department,
                &u.office,
                &u.phone,
                &u.mobile,
                &u.manager,
                &u.expires,
                &u.container,
                if u.enabled { "Yes" } else { "No" },
            ],
        );
    }
    out
}

/// A server's name as part of a file name: letters, digits, `-` and `_`.
fn file_name_part(name: &str) -> String {
    let s: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).collect();
    let s = s.trim_matches('-').to_string();
    if s.is_empty() { "domain".to_string() } else { s }
}

// ── import: the columns ──────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
enum Column {
    Username,
    FirstName,
    LastName,
    Email,
    Password,
    Description,
    Title,
    Department,
    Office,
    Phone,
    Mobile,
    Manager,
    Expires,
    Ou,
}

/// What a column heading means. Case, spaces, `_` and `-` do not matter, and
/// the LDAP names (`sAMAccountName`, `givenName`, …) work too.
fn column(heading: &str) -> Option<Column> {
    let h: String = heading.chars().filter(|c| c.is_alphanumeric()).collect::<String>().to_lowercase();
    Some(match h.as_str() {
        "username" | "samaccountname" | "user" | "logonname" | "login" | "account" => Column::Username,
        "firstname" | "givenname" | "first" => Column::FirstName,
        "lastname" | "sn" | "surname" | "last" | "familyname" => Column::LastName,
        "email" | "mail" | "emailaddress" => Column::Email,
        "password" => Column::Password,
        "description" => Column::Description,
        "jobtitle" | "title" => Column::Title,
        "department" => Column::Department,
        "office" | "physicaldeliveryofficename" => Column::Office,
        "phone" | "telephone" | "telephonenumber" => Column::Phone,
        "mobile" | "mobilephone" => Column::Mobile,
        "manager" => Column::Manager,
        "accountexpires" | "expires" | "expiry" => Column::Expires,
        "ou" | "container" | "location" | "path" => Column::Ou,
        _ => return None,
    })
}

// ── import: checking the file ────────────────────────────────────────────────

/// One user to create, as the check found it and the browser sends it back.
#[derive(Serialize, Deserialize, Debug, Default, Clone, PartialEq)]
#[serde(default)]
pub struct ImportRow {
    pub line: usize,
    pub username: String,
    pub first_name: String,
    pub last_name: String,
    pub email: String,
    /// Empty: the one given for rows without one.
    pub password: String,
    pub description: String,
    pub title: String,
    pub department: String,
    pub office: String,
    pub phone: String,
    pub mobile: String,
    pub manager: String,
    pub expires: String,
    /// The OU's DN; empty for the one picked in the dialog.
    pub ou: String,
}

impl ImportRow {
    fn profile(&self) -> ldap::UserProfile<'_> {
        ldap::UserProfile {
            description: &self.description,
            title: &self.title,
            department: &self.department,
            office: &self.office,
            phone: &self.phone,
            mobile: &self.mobile,
            manager: &self.manager,
            expires: &self.expires,
        }
    }
}

/// A row that is not created, and why.
#[derive(Serialize, Debug, PartialEq)]
pub struct RowNote {
    pub line: usize,
    pub username: String,
    pub reason: String,
}

/// What an import would do.
#[derive(Serialize, Debug, Default)]
pub struct Plan {
    /// In the order to create them: a manager before the users they manage.
    pub rows: Vec<ImportRow>,
    /// Users already in the domain: left as they are.
    pub skipped: Vec<RowNote>,
    /// Rows that cannot be created as they are.
    pub problems: Vec<RowNote>,
    /// Headings EasyDC does not read.
    pub ignored: Vec<String>,
}

/// Where a user can go: an OU or container's DN and its path of names.
pub struct Place {
    pub dn: String,
    pub path: String,
}

/// Check a file against the domain without changing anything. `existing`
/// holds the lowercase usernames already in the domain.
pub fn plan(text: &str, existing: &HashSet<String>, places: &[Place], has_default_password: bool) -> Result<Plan, String> {
    let records = csv::parse(text)?;
    let Some((head, body)) = records.split_first() else {
        return Err("The file is empty.".to_string());
    };
    let mut columns: Vec<Option<Column>> = Vec::new();
    let mut seen = HashSet::new();
    let mut plan = Plan::default();
    for h in &head.fields {
        let c = column(h);
        match c {
            Some(c) if !seen.insert(c) => return Err(format!("The first line names the column '{h}' twice.")),
            None if !h.is_empty() => plan.ignored.push(h.clone()),
            _ => {}
        }
        columns.push(c);
    }
    if !seen.contains(&Column::Username) {
        return Err("The first line must name the columns, one of them Username (or sAMAccountName). \
                    Export the users to see a file EasyDC reads."
            .to_string());
    }

    let mut in_file: HashMap<String, usize> = HashMap::new();
    for r in body {
        let mut row = ImportRow { line: r.line, ..Default::default() };
        let mut extra = false;
        for (i, value) in r.fields.iter().enumerate() {
            let Some(c) = columns.get(i) else {
                extra |= !value.is_empty();
                continue;
            };
            let value = value.trim().to_string();
            match c {
                Some(Column::Username) => row.username = value,
                Some(Column::FirstName) => row.first_name = value,
                Some(Column::LastName) => row.last_name = value,
                Some(Column::Email) => row.email = value,
                // Spaces count in a password.
                Some(Column::Password) => row.password = r.fields[i].clone(),
                Some(Column::Description) => row.description = value,
                Some(Column::Title) => row.title = value,
                Some(Column::Department) => row.department = value,
                Some(Column::Office) => row.office = value,
                Some(Column::Phone) => row.phone = value,
                Some(Column::Mobile) => row.mobile = value,
                Some(Column::Manager) => row.manager = value,
                Some(Column::Expires) => row.expires = value,
                Some(Column::Ou) => row.ou = value,
                None => {}
            }
        }
        let mut problem = |reason: String| plan.problems.push(RowNote { line: r.line, username: row.username.clone(), reason });
        if extra {
            problem("it has more fields than the first line names; a value with a comma needs quotes around it".to_string());
            continue;
        }
        if row.username.is_empty() {
            problem("it has no username".to_string());
            continue;
        }
        if let Err(e) = ldap::check_account_name("The username", &row.username) {
            problem(e);
            continue;
        }
        let key = row.username.to_lowercase();
        if let Some(first) = in_file.get(&key) {
            problem(format!("the username is on line {first} already"));
            continue;
        }
        in_file.insert(key.clone(), r.line);
        if existing.contains(&key) {
            plan.skipped.push(RowNote { line: r.line, username: row.username.clone(), reason: "already in the domain".to_string() });
            continue;
        }
        if row.password.is_empty() && !has_default_password {
            problem("it has no password, and none is given for rows without one".to_string());
            continue;
        }
        if let Err(e) = row.profile().check() {
            problem(e);
            continue;
        }
        if !row.ou.is_empty() {
            match find_place(&row.ou, places) {
                Some(dn) => row.ou = dn,
                None => {
                    let reason = format!("there is no OU or container {}", row.ou);
                    problem(reason);
                    continue;
                }
            }
        }
        plan.rows.push(row);
    }
    order_by_manager(&mut plan, existing);
    Ok(plan)
}

/// An OU by DN, or by its path of names: `Sales/Europe`, `Sales › Europe` or
/// `Sales\Europe`, as the Users page shows it. Builtin holds no users.
fn find_place(ou: &str, places: &[Place]) -> Option<String> {
    if ou.contains('=') {
        return places.iter().find(|p| p.dn.eq_ignore_ascii_case(ou)).map(|p| p.dn.clone());
    }
    let path: Vec<String> = ou.split(['/', '\\', '›']).map(|p| p.trim().to_lowercase()).filter(|p| !p.is_empty()).collect();
    places
        .iter()
        .find(|p| {
            let names: Vec<String> = p.path.split('›').map(|n| n.trim().to_lowercase()).collect();
            names == path
        })
        .map(|p| p.dn.clone())
}

/// A manager named by username must be in the domain or made by this file,
/// earlier than the users they manage. Rows whose manager is neither (or is
/// a row that cannot be created) become problems; a loop of managers too.
fn order_by_manager(plan: &mut Plan, existing: &HashSet<String>) {
    let in_file = |m: &str| !m.is_empty() && !m.contains('=') && !existing.contains(&m.to_lowercase());
    // Rows dropped can leave others without their manager, so until nothing changes.
    loop {
        let here: HashSet<String> = plan.rows.iter().map(|r| r.username.to_lowercase()).collect();
        let (keep, missing): (Vec<ImportRow>, Vec<ImportRow>) =
            std::mem::take(&mut plan.rows).into_iter().partition(|r| !in_file(&r.manager) || here.contains(&r.manager.to_lowercase()));
        plan.rows = keep;
        if missing.is_empty() {
            break;
        }
        for r in missing {
            plan.problems.push(RowNote {
                line: r.line,
                reason: format!("its manager {} is not in the domain, nor a user this file creates", r.manager),
                username: r.username,
            });
        }
    }
    let mut pending = std::mem::take(&mut plan.rows);
    let mut made: HashSet<String> = HashSet::new();
    loop {
        let waiting: HashSet<String> = pending.iter().map(|r| r.username.to_lowercase()).collect();
        let (ready, rest): (Vec<ImportRow>, Vec<ImportRow>) = pending.into_iter().partition(|r| {
            let m = r.manager.to_lowercase();
            !in_file(&r.manager) || made.contains(&m) || !waiting.contains(&m)
        });
        if ready.is_empty() {
            for r in rest {
                plan.problems.push(RowNote {
                    line: r.line,
                    reason: "its manager is managed by it, directly or through others in the file".to_string(),
                    username: r.username,
                });
            }
            break;
        }
        made.extend(ready.iter().map(|r| r.username.to_lowercase()));
        plan.rows.extend(ready);
        if rest.is_empty() {
            break;
        }
        pending = rest;
    }
    plan.problems.sort_by_key(|p| p.line);
}

#[derive(Deserialize)]
pub struct CheckForm {
    csv: String,
    /// Non-empty: the dialog gives a password for rows without one.
    #[serde(default)]
    default_password: String,
}

/// POST: what importing a file would do, as JSON. Changes nothing.
pub async fn import_check(State(state): State<AppState>, Path(id): Path<i64>, Form(form): Form<CheckForm>) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Json(serde_json::json!({ "error": "There is no such server." })).into_response();
    };
    let checked: Result<Plan, String> = async {
        let (mut conn, base_dn) = ldap::open(&server).await?;
        let users = ldap::list_users(&mut conn, &base_dn).await?;
        let tree = ldap::list_containers(&mut conn, &base_dn, &[], &format!("CN=Users,{base_dn}")).await?;
        let existing: HashSet<String> = users.iter().map(|u| u.username.to_lowercase()).collect();
        let places: Vec<Place> = tree
            .iter()
            .filter(|c| !ldap::is_builtin_container(&c.dn, &base_dn))
            .map(|c| Place { dn: c.dn.clone(), path: ldap::location(&c.dn, &base_dn) })
            .collect();
        plan(&form.csv, &existing, &places, !form.default_password.is_empty())
    }
    .await;
    let body = match checked {
        Ok(p) => serde_json::to_value(p).unwrap_or_default(),
        Err(e) => serde_json::json!({ "error": e }),
    };
    // The rows carry the file's passwords back to the page.
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}

// ── import: creating ─────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct ImportPart {
    rows: Vec<ImportRow>,
    /// Where rows without an OU go; empty for CN=Users.
    #[serde(default)]
    ou: String,
    /// For rows without a password.
    #[serde(default)]
    default_password: String,
    #[serde(default)]
    must_change: bool,
}

/// The rows a part may hold: the browser sends 25 at a time, a few seconds'
/// work for the DC.
const MOST_IN_A_PART: usize = 200;

/// POST (JSON): create one part of an import. Answers like a bulk action,
/// so the page reports it the same way.
pub async fn import(
    State(state): State<AppState>,
    CurrentUser(actor): CurrentUser,
    Path(id): Path<i64>,
    Json(part): Json<ImportPart>,
) -> Response {
    let Some(server) = get_server(&state, id).await else {
        return Json(serde_json::json!({ "error": "There is no such server." })).into_response();
    };
    if part.rows.len() > MOST_IN_A_PART {
        return Json(serde_json::json!({ "error": format!("A part holds at most {MOST_IN_A_PART} users.") })).into_response();
    }
    let (mut conn, base_dn) = match ldap::open(&server).await {
        Ok(c) => c,
        Err(e) => return Json(serde_json::json!({ "error": e })).into_response(),
    };
    let mut failed = Vec::new();
    for row in &part.rows {
        let password = if row.password.is_empty() { part.default_password.as_str() } else { row.password.as_str() };
        let result = if password.is_empty() {
            Err("no password".to_string())
        } else {
            ldap::create_user(
                &mut conn,
                &base_dn,
                &ldap::NewUser {
                    username: &row.username,
                    first_name: &row.first_name,
                    last_name: &row.last_name,
                    email: &row.email,
                    password,
                    profile: row.profile(),
                    parent: if row.ou.is_empty() { &part.ou } else { &row.ou },
                    must_change: part.must_change,
                },
            )
            .await
        };
        db::log_action(&state.db, &actor, "user.create", &row.username, Some(id), &result).await;
        if let Err(e) = result {
            failed.push(format!("{} (line {}: {e})", row.username, row.line));
        }
    }
    Json(serde_json::json!({ "verb": "Created", "place": "", "total": part.rows.len(), "failed": failed })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn places() -> Vec<Place> {
        vec![
            Place { dn: "CN=Users,DC=x,DC=com".into(), path: "Users".into() },
            Place { dn: "OU=Sales,DC=x,DC=com".into(), path: "Sales".into() },
            Place { dn: "OU=Europe,OU=Sales,DC=x,DC=com".into(), path: "Sales › Europe".into() },
        ]
    }

    fn existing() -> HashSet<String> {
        ["administrator", "bob"].iter().map(|s| s.to_string()).collect()
    }

    fn check(text: &str) -> Plan {
        plan(text, &existing(), &places(), false).unwrap()
    }

    fn user(name: &str) -> ldap::LdapUser {
        ldap::LdapUser {
            dn: format!("CN={name},CN=Users,DC=x,DC=com"),
            username: name.to_string(),
            first_name: "Ann".into(),
            last_name: "Lee, Jr.".into(),
            display_name: "Ann Lee".into(),
            email: "ann@x.com".into(),
            enabled: true,
            locked: false,
            bad_pwd_count: 0,
            title: String::new(),
            department: "Sales".into(),
            office: String::new(),
            phone: "+972 3 555 0101".into(),
            mobile: String::new(),
            manager: "bob".into(),
            expires: "2027-01-31".into(),
            expired: false,
            password: "",
            check: false,
            description: "says \"hi\"".into(),
            container: "OU=Europe,OU=Sales,DC=x,DC=com".into(),
            location: "Sales › Europe".into(),
        }
    }

    #[test]
    fn an_export_reads_back_as_an_import() {
        let ann = user("ann");
        let text = export_csv(&[&ann]);
        assert!(text.starts_with(csv::BOM));
        assert!(text.contains("\"Lee, Jr.\""));
        assert!(text.contains("'+972 3 555 0101"), "a value that looks like a formula is not one");
        let p = plan(&text, &existing(), &places(), true).unwrap();
        assert!(p.problems.is_empty(), "{:?}", p.problems);
        assert_eq!(p.ignored, ["Display name", "Enabled"]);
        let r = &p.rows[0];
        assert_eq!((r.username.as_str(), r.last_name.as_str(), r.phone.as_str()), ("ann", "Lee, Jr.", "+972 3 555 0101"));
        assert_eq!((r.manager.as_str(), r.expires.as_str(), r.description.as_str()), ("bob", "2027-01-31", "says \"hi\""));
        assert_eq!(r.ou, "OU=Europe,OU=Sales,DC=x,DC=com");
    }

    #[test]
    fn headings_are_read_loosely() {
        let p = check("SAMAccountName;given_name;SN;E-mail;Password;Shoe size\ncarol;Carol;Ng;c@x.com;Pw-1 2;44\n");
        assert_eq!(p.ignored, ["Shoe size"]);
        let r = &p.rows[0];
        assert_eq!((r.username.as_str(), r.first_name.as_str(), r.last_name.as_str()), ("carol", "Carol", "Ng"));
        assert_eq!((r.email.as_str(), r.password.as_str()), ("c@x.com", "Pw-1 2"));
    }

    #[test]
    fn a_file_without_a_username_column_is_refused() {
        assert!(plan("Name,Email\nx,y\n", &existing(), &places(), true).unwrap_err().contains("Username"));
        assert!(plan("", &existing(), &places(), true).unwrap_err().contains("empty"));
        assert!(plan("user,login\n", &existing(), &places(), true).unwrap_err().contains("twice"));
    }

    #[test]
    fn rows_that_cannot_be_created_say_why() {
        let p = check(
            "Username,Password,OU,Account expires\n\
             ,pw,,\n\
             bad/name,pw,,\n\
             BOB,pw,,\n\
             dave,,,\n\
             erin,pw,Nowhere,\n\
             fay,pw,,2027-02-30\n\
             gus,pw,sales/europe,\n\
             GUS,pw,,\n\
             hal,pw,,,extra\n",
        );
        let reasons: Vec<(usize, &str)> = p.problems.iter().map(|n| (n.line, n.reason.as_str())).collect();
        assert_eq!(reasons.len(), 7, "{reasons:?}");
        assert!(reasons[0].1.contains("no username"));
        assert!(reasons[1].1.contains("cannot contain \"/\""), "{}", reasons[1].1);
        assert!(reasons[2].1.contains("no password"));
        assert!(reasons[3].1.contains("no OU or container Nowhere"));
        assert!(reasons[4].1.contains("2027-02-30"));
        assert_eq!(reasons[5], (9, "the username is on line 8 already"));
        assert!(reasons[6].1.contains("more fields"));
        assert_eq!(p.skipped, [RowNote { line: 4, username: "BOB".into(), reason: "already in the domain".into() }]);
        assert_eq!(p.rows.len(), 1);
        assert_eq!(p.rows[0].ou, "OU=Europe,OU=Sales,DC=x,DC=com");
    }

    #[test]
    fn a_default_password_fills_rows_without_one() {
        let p = plan("Username\nzed\n", &existing(), &places(), true).unwrap();
        assert_eq!(p.rows.len(), 1);
        assert!(p.rows[0].password.is_empty(), "the default is added when created");
    }

    #[test]
    fn managers_are_created_before_the_users_they_manage() {
        let p = check(
            "Username,Password,Manager\n\
             ann,pw,cat\n\
             cat,pw,dan\n\
             dan,pw,bob\n\
             eve,pw,\"CN=Someone,DC=x,DC=com\"\n\
             fox,pw,nobody\n\
             gil,pw,fox\n\
             hoy,pw,ivy\n\
             ivy,pw,hoy\n",
        );
        let order: Vec<&str> = p.rows.iter().map(|r| r.username.as_str()).collect();
        assert_eq!(order, ["dan", "eve", "cat", "ann"]);
        let why: Vec<(&str, &str)> = p.problems.iter().map(|n| (n.username.as_str(), n.reason.as_str())).collect();
        assert_eq!(why.len(), 4, "{why:?}");
        assert!(why[0].0 == "fox" && why[0].1.contains("nobody is not in the domain"));
        assert!(why[1].0 == "gil" && why[1].1.contains("fox is not in the domain"), "a manager that is not created");
        assert!(why[2].1.contains("managed by it") && why[3].1.contains("managed by it"));
    }

    #[test]
    fn file_names_are_safe() {
        assert_eq!(file_name_part("DC1"), "DC1");
        assert_eq!(file_name_part("Lab \"test\"/x"), "Lab--test--x");
        assert_eq!(file_name_part("שרת"), "domain");
    }
}
