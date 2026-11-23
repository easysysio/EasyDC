use ldap3::{LdapConnAsync, LdapConnSettings, Mod, Scope, SearchEntry};
use serde::Serialize;
use std::collections::HashSet;
use uuid::Uuid;

use crate::models::Server;

pub type LdapResult<T> = Result<T, String>;

#[derive(Debug, Serialize, Clone, Default)]
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
    pub title: String,
    pub department: String,
    pub office: String,
    pub phone: String,
    pub mobile: String,
    /// The manager's username, or their DN when it is not a user EasyDC lists
    /// (a contact, say). Empty when none is set.
    pub manager: String,
    /// Last day the account can be used, `YYYY-MM-DD`; empty for never.
    pub expires: String,
    pub expired: bool,
    /// `must_change` (set a new password at next sign-in), `expired` (older
    /// than the maximum password age), or empty. Either way the user cannot
    /// sign in with their current password.
    pub password: &'static str,
    /// Whether the DC is asked about `locked` and `password` (internal).
    #[serde(skip)]
    pub check: bool,
    pub description: String,
    /// The DN of the OU or container the user is in.
    pub container: String,
    /// That OU or container as a path of names below the domain, such as
    /// `Sales › Europe`; empty for a user at the top of the domain.
    pub location: String,
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

/// Escape a value for use inside an LDAP search filter (RFC 4515). Every
/// filter built from input goes through this: an unescaped `*` is a wildcard,
/// so a name taken from a URL could otherwise match — and a delete handler then
/// act on — whichever object the directory happened to return first.
pub(crate) fn ldap_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\5c"),
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\0' => out.push_str("\\00"),
            c => out.push(c),
        }
    }
    out
}

/// Escape a value for use as one part of a DN, as in `CN=<value>,CN=Users,…`
/// (RFC 4514). Every DN built from a name goes through this: an unescaped
/// comma ends the part, so `Doe, John` would otherwise be read as `CN=Doe`
/// under a parent called ` John` — rejected, or worse, the wrong object.
///
/// Uses the `\,` form rather than `\2c`, because that is how Samba writes DNs
/// back, and EasyDC compares DNs it built with DNs it read.
pub(crate) fn dn_escape(value: &str) -> String {
    let last = value.chars().count().saturating_sub(1);
    let mut out = String::with_capacity(value.len() + 4);
    for (i, c) in value.chars().enumerate() {
        match c {
            ',' | '+' | '"' | '\\' | '<' | '>' | ';' | '=' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            '#' if i == 0 => out.push_str("\\#"),
            ' ' if i == 0 || i == last => out.push_str("\\ "),
            c => out.push(c),
        }
    }
    out
}

/// The parts of a DN (`CN=Doe\\, John`, `OU=Sales`, …), split at the commas
/// between them and not at an escaped `\\,` inside a name.
pub(crate) fn dn_parts(dn: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut start, mut escaped) = (0, false);
    for (i, c) in dn.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' {
            parts.push(dn[start..i].trim_start());
            start = i + 1;
        }
    }
    let last = dn[start..].trim_start();
    if !last.is_empty() {
        parts.push(last);
    }
    parts
}

/// The DN of the object that holds `dn`; empty at the top.
pub(crate) fn parent_dn(dn: &str) -> &str {
    let mut escaped = false;
    for (i, c) in dn.char_indices() {
        if escaped {
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ',' {
            return dn[i + 1..].trim_start();
        }
    }
    ""
}

/// Whether `dn` is `top` or somewhere below it. Compares whole parts, so
/// `OU=a\\,OU=Sales,DC=x` (an OU named `a,OU=Sales`) is not inside `OU=Sales,DC=x`.
pub(crate) fn is_within(dn: &str, top: &str) -> bool {
    let top = top.to_lowercase();
    let mut d = dn.to_lowercase();
    loop {
        if d == top {
            return true;
        }
        let p = parent_dn(&d).to_string();
        if p.is_empty() {
            return false;
        }
        d = p;
    }
}

pub(crate) fn attr(e: &SearchEntry, key: &str) -> String {
    e.attrs
        .get(key)
        .and_then(|v| v.first())
        .cloned()
        .unwrap_or_default()
}

// ── connection ────────────────────────────────────────────────────────────────

/// How long EasyDC waits for the DC to answer one request. A DC busy with a
/// long change, such as deleting an OU with thousands of users, holds every
/// other change until it is done; without a limit the page would load
/// forever.
pub(crate) const OP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// How long EasyDC waits to connect to a DC.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// An LDAP error in words. A timeout says what it means for the person
/// waiting: the change may still be made once the DC gets to it.
pub(crate) fn ldap_err(e: ldap3::LdapError) -> String {
    match e {
        ldap3::LdapError::Timeout { .. } => timed_out(),
        other => other.to_string(),
    }
}

pub(crate) fn timed_out() -> String {
    format!(
        "The domain controller did not answer within {} seconds, so EasyDC stopped waiting. \
         It may be busy with a large change, such as deleting or importing many objects. \
         If you were making a change, it may still be made once the DC is free: check again in a few minutes.",
        OP_TIMEOUT.as_secs()
    )
}

/// A change the domain controller refused, in words. `what` says what did not
/// happen, and `object` names the thing it was made on, for when the DC says it
/// does not exist. Callers handle the codes that need their own advice first.
pub(crate) fn refused(what: &str, object: &str, res: &ldap3::LdapResult) -> String {
    match res.rc {
        32 => format!("{what}: {object} does not exist. It may have just been deleted or renamed; reload the page to see the current list."),
        50 => format!("{what}: the account EasyDC signs in with is not allowed to make this change."),
        rc => format!("{what}: the domain controller refused it, saying \"{}\" (LDAP code {rc}).", dc_text(&res.text)),
    }
}

/// A change the DC refused, in words, for the places that have nothing more
/// particular to say. `what` says what did not happen.
pub(crate) fn dc_refused(what: &str, res: &ldap3::LdapResult) -> String {
    match res.rc {
        50 => format!("{what}: the account EasyDC signs in with is not allowed to make this change."),
        32 => format!("{what}: it no longer exists. It may have just been deleted or renamed; reload the page to see the current list."),
        rc => format!("{what}: the domain controller refused it, saying \"{}\" (LDAP code {rc}).", dc_text(&res.text)),
    }
}

/// `dc_refused`, for the error from `.success()`; any other error (a
/// timeout, say) keeps its own words.
pub(crate) fn dc_failed(what: &str) -> impl FnOnce(ldap3::LdapError) -> String + '_ {
    move |e| match e {
        ldap3::LdapError::LdapResult { result } => dc_refused(what, &result),
        other => format!("{what}: {}", ldap_err(other)),
    }
}

/// The DC's own words, without Samba's leading error number ("00002030: ").
fn dc_text(text: &str) -> &str {
    let text = text.trim_matches(|c: char| c.is_whitespace() || c == '\0');
    match text.split_once(": ") {
        Some((code, rest)) if code.len() == 8 && code.chars().all(|c| c.is_ascii_hexdigit()) => rest,
        _ => text,
    }
}

/// The host and port an LDAP URL points at, for messages.
fn url_place(url: &str) -> (String, u16) {
    let (scheme, rest) = url.split_once("://").unwrap_or(("ldap", url));
    let hostport = rest.split(['/', '?']).next().unwrap_or("");
    let default = if scheme.eq_ignore_ascii_case("ldaps") { 636 } else { 389 };
    // An IPv6 address is written in brackets: [::1]:636.
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) if !p.contains(']') => (h, p.parse().unwrap_or(default)),
        _ => (hostport, default),
    };
    (host.trim_matches(['[', ']']).to_string(), port)
}

/// Why EasyDC could not connect to a DC, in words, with what to check.
fn connect_failed(url: &str, wait: std::time::Duration, e: ldap3::LdapError) -> String {
    use std::io::ErrorKind;
    let (host, port) = url_place(url);
    let io = match &e {
        ldap3::LdapError::Timeout { .. } => {
            return format!("Connection failed: the domain controller did not answer within {} seconds", wait.as_secs())
        }
        ldap3::LdapError::Io { source } => source,
        ldap3::LdapError::NativeTLS { source } => {
            let detail = source.to_string();
            return if detail.contains("certificate") || detail.contains("verify") {
                format!(
                    "Connection failed: this machine does not trust the certificate of {host}, \
                     or it does not match that name. Samba makes its own certificate, which nothing trusts \
                     until you install the domain's CA certificate here. Until then, you can turn on \
                     Skip TLS verification with the Edit button on this server's card on the Dashboard: \
                     the connection stays encrypted, but the DC's identity is not checked."
                )
            } else if port == 389 {
                format!(
                    "Connection failed: {host} did not start a secure connection on port 389. \
                     Port 389 is for ldap://; ldaps:// uses port 636. Fix the address with the Edit button \
                     on this server's card on the Dashboard."
                )
            } else {
                format!(
                    "Connection failed: a secure connection to {host} on port {port} could not be set up ({detail}). \
                     Check that the address uses the DC's LDAPS port, normally 636."
                )
            };
        }
        _ => return format!("Connection failed: {e}"),
    };
    match io.kind() {
        ErrorKind::ConnectionRefused => format!(
            "Connection failed: {host} turned the connection away on port {port}. \
             Samba may be stopped there (on the DC, check with: systemctl status samba-ad-dc), \
             or the port in the address is wrong."
        ),
        ErrorKind::HostUnreachable | ErrorKind::NetworkUnreachable => format!(
            "Connection failed: there is no network path to {host}. \
             The machine may be off, or a network or firewall is in the way."
        ),
        _ if io.to_string().contains("lookup address") => format!(
            "Connection failed: the name {host} was not found in DNS. \
             Check the spelling of this server's LDAP URL, and that this machine uses DNS that knows the domain."
        ),
        _ => format!("Connection failed: {e}"),
    }
}

pub async fn connect_and_bind(server: &Server) -> LdapResult<ldap3::Ldap> {
    connect_url(server, &server.ldap_url, None).await
}

/// Bind to `url` with the server's account and TLS setting: how EasyDC reaches
/// the domain's other DCs. A timeout keeps an unreachable DC from stalling a
/// page.
/// A connection to `url` with this server's TLS settings, before any sign-in.
async fn connect_only(
    server: &Server,
    url: &str,
    timeout: Option<std::time::Duration>,
) -> LdapResult<ldap3::Ldap> {
    let wait = timeout.unwrap_or(CONNECT_TIMEOUT);
    let settings = LdapConnSettings::new().set_no_tls_verify(server.skip_tls).set_conn_timeout(wait);
    let (conn, ldap) = LdapConnAsync::with_settings(settings, url)
        .await
        .map_err(|e| connect_failed(url, wait, e))?;
    ldap3::drive!(conn);
    Ok(ldap)
}

pub async fn connect_url(
    server: &Server,
    url: &str,
    timeout: Option<std::time::Duration>,
) -> LdapResult<ldap3::Ldap> {
    let mut ldap = connect_only(server, url, timeout).await?;
    ldap.with_timeout(OP_TIMEOUT).simple_bind(&server.bind_dn, &server.bind_password)
        .await
        .map_err(|e| bind_failed(url, e))?
        .success()
        .map_err(|e| match e {
            ldap3::LdapError::LdapResult { result } => sign_in_refused(url, &result),
            other => format!("Sign-in to the DC failed: {other}"),
        })?;
    Ok(ldap)
}

// ── signing in to EasyDC with a domain account ───────────────────────────────

/// A domain user who may sign in to EasyDC, as found by the bind account.
#[derive(Debug, Clone, PartialEq)]
pub struct DomainUser {
    pub dn: String,
    /// sAMAccountName, as the directory spells it.
    pub username: String,
    pub display_name: String,
}

/// The user (not computer) with this sAMAccountName, if any.
pub async fn find_domain_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
) -> LdapResult<Option<DomainUser>> {
    let filter = format!(
        "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName={}))",
        ldap_escape(username)
    );
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["sAMAccountName", "displayName"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    Ok(entries.into_iter().next().map(SearchEntry::construct).map(|e| DomainUser {
        username: attr(&e, "sAMAccountName"),
        display_name: attr(&e, "displayName"),
        dn: e.dn,
    }))
}

/// Why a domain sign-in did not work.
#[derive(Debug, Clone, PartialEq)]
pub enum DomainSignIn {
    /// A wrong password, or no such user: the same answer for both.
    Refused,
    Disabled,
    LockedOut,
    AccountExpired,
    /// Expired, or must be changed at the next sign-in.
    PasswordChange,
    /// EasyDC could not ask the DC.
    Unavailable(String),
}

impl DomainSignIn {
    pub fn message(&self) -> String {
        match self {
            DomainSignIn::Refused => "Invalid username or password".to_string(),
            DomainSignIn::Disabled => "This domain account is disabled.".to_string(),
            DomainSignIn::LockedOut => {
                "This domain account is locked out after too many wrong passwords. It unlocks by itself \
                 after the lockout time, or someone who manages users can unlock it."
                    .to_string()
            }
            DomainSignIn::AccountExpired => "This domain account has expired.".to_string(),
            DomainSignIn::PasswordChange => {
                "Your domain password must be changed before you can sign in. Change it on a computer in \
                 the domain, then sign in here with the new one."
                    .to_string()
            }
            DomainSignIn::Unavailable(e) => format!(
                "EasyDC could not check domain passwords just now: {e} Local EasyDC accounts can still sign in."
            ),
        }
    }
}

/// What a refused bind means, from the "data" code in Samba's text.
fn domain_refusal(res: &ldap3::LdapResult) -> DomainSignIn {
    let reason = res.text.split("data ").nth(1).and_then(|s| s.split(',').next()).unwrap_or("").trim();
    match (res.rc, reason) {
        (49, "533") => DomainSignIn::Disabled,
        (49, "775") => DomainSignIn::LockedOut,
        (49, "701") => DomainSignIn::AccountExpired,
        (49, "532") | (49, "773") => DomainSignIn::PasswordChange,
        _ => DomainSignIn::Refused,
    }
}

/// Check a domain user's password by signing in as them. The bind account
/// finds them first, so the sign-in uses their DN, whatever form their name
/// takes; Samba then says whether the account may sign in at all.
pub async fn check_domain_password(server: &Server, username: &str, password: &str) -> Result<DomainUser, DomainSignIn> {
    // An empty password is an anonymous bind, which "succeeds" without
    // proving anything.
    if password.is_empty() {
        return Err(DomainSignIn::Refused);
    }
    let (mut ldap, base_dn) = open(server).await.map_err(DomainSignIn::Unavailable)?;
    let found = find_domain_user(&mut ldap, &base_dn, username).await;
    let _ = ldap.unbind().await;
    let user = match found {
        Ok(Some(u)) => u,
        Ok(None) => return Err(DomainSignIn::Refused),
        Err(e) => return Err(DomainSignIn::Unavailable(e)),
    };
    let mut as_user = connect_only(server, &server.ldap_url, None).await.map_err(DomainSignIn::Unavailable)?;
    let result = as_user
        .with_timeout(OP_TIMEOUT)
        .simple_bind(&user.dn, password)
        .await
        .map_err(|e| DomainSignIn::Unavailable(bind_failed(&server.ldap_url, e)))?;
    let _ = as_user.unbind().await;
    match result.rc {
        0 => Ok(user),
        _ => Err(domain_refusal(&result)),
    }
}

const EDIT_SERVER: &str = "with the Edit button on this server's card on the Dashboard";

/// The bind request got no answer: the DC timed out, or closed the connection.
fn bind_failed(url: &str, e: ldap3::LdapError) -> String {
    let (host, port) = url_place(url);
    match e {
        ldap3::LdapError::ResultRecv { .. } | ldap3::LdapError::OpSend { .. } => {
            let mut text = format!("Connection failed: {host} closed the connection before answering.");
            if port == 636 && !url.to_ascii_lowercase().starts_with("ldaps") {
                text.push_str(&format!(" Port 636 is for ldaps://: change the address to ldaps://{host} {EDIT_SERVER}."));
            }
            text
        }
        other => format!("Bind failed: {}", ldap_err(other)),
    }
}

/// The DC refused the bind account's sign-in. For a refused password,
/// Samba (like Windows) says why in the "data" part of its text.
fn sign_in_refused(url: &str, res: &ldap3::LdapResult) -> String {
    let start = "Sign-in to the DC failed:";
    let reason = res.text.split("data ").nth(1).and_then(|s| s.split(',').next()).unwrap_or("").trim();
    match (res.rc, reason) {
        (8, _) => format!(
            "{start} the DC only accepts passwords over an encrypted connection, and this address starts with ldap://. \
             Change it to ldaps://{} {EDIT_SERVER}.",
            url_place(url).0
        ),
        (49, "533") => format!("{start} the bind account is disabled. Enable it on the DC, or use another account."),
        (49, "775") => format!(
            "{start} the bind account is locked out after too many wrong passwords. \
             It unlocks by itself after the lockout time, or unlock it on the DC."
        ),
        (49, "532") => format!("{start} the bind account's password has expired. Set a new one on the DC, then {EDIT_SERVER}."),
        (49, "773") => format!(
            "{start} the bind account must change its password before it can sign in. \
             Set a new one on the DC, then enter it {EDIT_SERVER}."
        ),
        (49, "701") => format!("{start} the bind account has expired. Extend it on the DC, or use another account."),
        (49, _) => format!("{start} the bind DN or its password is wrong. Check both {EDIT_SERVER}."),
        (rc, _) => format!("{start} the DC refused it, saying \"{}\" (LDAP code {rc}).", dc_text(&res.text)),
    }
}

pub async fn get_base_dn(ldap: &mut ldap3::Ldap) -> LdapResult<String> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search("", Scope::Base, "(objectClass=*)", vec!["defaultNamingContext"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("defaultNamingContext")?.first().cloned())
        .ok_or_else(|| "Could not determine domain base DN from server".to_string())
}

/// True for an error saying the DC did not answer in time, when connecting
/// or during a request.
pub(crate) fn is_timeout(error: &str) -> bool {
    error.contains("did not answer within")
}

/// `open`, for showing a page after an action. If the action just failed
/// because the DC did not answer, reading the page from the same DC would
/// only wait as long again: the action's error is returned instead.
pub async fn open_after(server: &Server, earlier: Option<&str>) -> LdapResult<(ldap3::Ldap, String)> {
    match earlier {
        Some(e) if is_timeout(e) => Err(e.to_string()),
        _ => open(server).await,
    }
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
    let filter = format!("(&(objectClass=user)(sAMAccountName={}))", ldap_escape(username));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["dn"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    entries
        .into_iter()
        .next()
        .map(|e| SearchEntry::construct(e).dn)
        .ok_or_else(|| format!("User '{}' not found", username))
}

/// A user's DN, and whether it is the account EasyDC signs in to the DC with
/// (`bind`, as the server entry gives it: a DN, `user@domain` or `DOMAIN\\user`).
/// A user about to be changed: everything a change needs, read in one request.
pub struct UserForChange {
    pub dn: String,
    /// Whether it is the account EasyDC signs in with.
    pub is_bind: bool,
    pub uac: i64,
}

pub async fn find_user_for_change(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    bind: &str,
) -> LdapResult<UserForChange> {
    let filter = format!("(&(objectClass=user)(sAMAccountName={}))", ldap_escape(username));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["sAMAccountName", "userPrincipalName", "userAccountControl"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("User '{}' not found", username))?;
    let is_bind = is_bind_account(bind, &e.dn, &attr(&e, "userPrincipalName"), &attr(&e, "sAMAccountName"));
    let uac = attr(&e, "userAccountControl")
        .parse::<i64>()
        .map_err(|_| format!("Could not read userAccountControl of {}", e.dn))?;
    Ok(UserForChange { dn: e.dn, is_bind, uac })
}

pub(crate) fn is_bind_account(bind: &str, dn: &str, upn: &str, sam: &str) -> bool {
    let bind = bind.trim();
    !bind.is_empty()
        && (bind.eq_ignore_ascii_case(dn)
            || (!upn.is_empty() && bind.eq_ignore_ascii_case(upn))
            || bind.rsplit_once('\\').is_some_and(|(_, user)| user.eq_ignore_ascii_case(sam)))
}

/// Every group's name, sorted: the suggestions for "Add to group".
pub async fn group_names(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<String>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, "(objectClass=group)", vec!["sAMAccountName"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut names: Vec<String> = entries
        .into_iter()
        .map(|e| attr(&SearchEntry::construct(e), "sAMAccountName"))
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    Ok(names)
}

// ── list users ────────────────────────────────────────────────────────────────

/// Whether an account is locked out now. lockoutTime keeps the time of the
/// lockout after the lockout duration has run out, until the user next signs
/// in, so it alone would show an account as locked that can sign in. The DC
/// works out the real state in msDS-User-Account-Control-Computed (bit 0x10);
/// lockoutTime is the fallback for a DC that does not give it.
fn is_locked(e: &SearchEntry) -> bool {
    const UF_LOCKOUT: i64 = 0x10;
    match crate::health::attr_ci(e, "msDS-User-Account-Control-Computed").parse::<i64>() {
        Ok(computed) => computed & UF_LOCKOUT != 0,
        Err(_) => attr(e, "lockoutTime").parse::<i64>().unwrap_or(0) != 0,
    }
}

/// Whether the user must set a new password before signing in, from the
/// DC's computed state (bit 0x800000): pwdLastSet 0 means an administrator
/// asked for a change; otherwise the password has outlived the maximum age.
fn password_state(e: &SearchEntry) -> &'static str {
    const UF_PASSWORD_EXPIRED: i64 = 0x80_0000;
    let computed = crate::health::attr_ci(e, "msDS-User-Account-Control-Computed").parse::<i64>().unwrap_or(0);
    if computed & UF_PASSWORD_EXPIRED == 0 {
        ""
    } else if attr(e, "pwdLastSet") == "0" {
        "must_change"
    } else {
        "expired"
    }
}

pub async fn list_users(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapUser>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
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
                "pwdLastSet",
                "badPwdCount",
                "title",
                "department",
                "physicalDeliveryOfficeName",
                "telephoneNumber",
                "mobile",
                "manager",
                "accountExpires",
                "description",
            ],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    let entries: Vec<SearchEntry> = entries.into_iter().map(SearchEntry::construct).collect();
    // manager holds a DN; show the username when the manager is a listed user.
    let usernames: std::collections::HashMap<String, String> = entries
        .iter()
        .map(|e| (e.dn.to_lowercase(), attr(e, "sAMAccountName")))
        .collect();
    let now = unix_to_filetime(crate::health::now_unix());
    let max_age = shortest_max_password_age(ldap, base_dn).await;

    let mut users: Vec<LdapUser> = entries
        .iter()
        .map(|e| {
            let uac: i64 = attr(e, "userAccountControl").parse().unwrap_or(514);
            let lockout: i64 = attr(e, "lockoutTime").parse().unwrap_or(0);
            let expires_at: i64 = attr(e, "accountExpires").parse().unwrap_or(0);
            let manager_dn = attr(e, "manager");
            let manager = usernames
                .get(&manager_dn.to_lowercase())
                .filter(|u| !u.is_empty())
                .cloned()
                .unwrap_or(manager_dn);
            LdapUser {
                dn: e.dn.clone(),
                username: attr(e, "sAMAccountName"),
                first_name: attr(e, "givenName"),
                last_name: attr(e, "sn"),
                display_name: attr(e, "displayName"),
                email: attr(e, "mail"),
                enabled: (uac & 2) == 0,
                // Until the DC confirms (below): lockoutTime may have run out,
                // and a password's age is not known to be past its limit.
                locked: lockout != 0,
                password: "",
                check: lockout != 0 || password_may_have_expired(e, uac, max_age, now),
                bad_pwd_count: attr(e, "badPwdCount").parse().unwrap_or(0),
                title: attr(e, "title"),
                department: attr(e, "department"),
                office: attr(e, "physicalDeliveryOfficeName"),
                phone: attr(e, "telephoneNumber"),
                mobile: attr(e, "mobile"),
                manager,
                expires: expiry_date(expires_at).unwrap_or_default(),
                expired: expiry_date(expires_at).is_some() && expires_at <= now,
                description: attr(e, "description"),
                container: parent_dn(&e.dn).to_string(),
                location: location(parent_dn(&e.dn), base_dn),
            }
        })
        .filter(|u| !u.username.is_empty())
        .collect();

    confirm_sign_in_state(ldap, base_dn, &mut users).await;
    users.sort_by_key(|a| a.username.to_lowercase());
    Ok(users)
}

/// The shortest maximum password age in force, from the domain policy and
/// any PSO, in FILETIME ticks; `None` when passwords never expire. A PSO that
/// cannot be read is left out.
pub(crate) async fn shortest_max_password_age(ldap: &mut ldap3::Ldap, base_dn: &str) -> Option<i64> {
    let places = [
        (base_dn.to_string(), Scope::Base, "(objectClass=*)", "maxPwdAge"),
        (format!("{PSO_CONTAINER},{base_dn}"), Scope::OneLevel, "(objectClass=msDS-PasswordSettings)", "msDS-MaximumPasswordAge"),
    ];
    let mut ages = Vec::new();
    for (base, scope, filter, key) in places {
        let found = ldap.with_timeout(OP_TIMEOUT).search(&base, scope, filter, vec![key]).await;
        let entries = found.ok().and_then(|r| r.success().ok()).map(|(es, _)| es).unwrap_or_default();
        ages.extend(entries.into_iter().filter_map(|e| crate::health::attr_ci(&SearchEntry::construct(e), key).parse::<i64>().ok()));
    }
    // Stored as a negative interval; 0 and the most negative value mean never.
    ages.into_iter().filter(|&a| a < 0 && a != i64::MIN).map(|a| -a).min()
}

/// Whether a user's password could be past its limit: a change was asked
/// for, or it is older than the shortest maximum age in force. Only these
/// users are asked about, since the DC's own answer is slow to work out for
/// every user.
fn password_may_have_expired(e: &SearchEntry, uac: i64, max_age: Option<i64>, now: i64) -> bool {
    const DONT_EXPIRE_PASSWORD: i64 = 0x1_0000;
    if uac & DONT_EXPIRE_PASSWORD != 0 {
        return false;
    }
    match attr(e, "pwdLastSet").parse::<i64>() {
        Ok(0) => true,
        Ok(set) => max_age.is_some_and(|age| set <= now - age),
        Err(_) => false,
    }
}

/// Ask the DC whether the users that may be locked out, or may have to change
/// their password, really are: it works this out with the lockout duration
/// and maximum password age that apply to each, PSOs included. They are
/// looked up by name, a few at a time. If the DC cannot be asked, a user with
/// a lockout time stays shown as locked.
async fn confirm_sign_in_state(ldap: &mut ldap3::Ldap, base_dn: &str, users: &mut [LdapUser]) {
    let wanted: Vec<usize> = (0..users.len()).filter(|&i| users[i].check).collect();
    for part in wanted.chunks(100) {
        let names: String = part.iter().map(|&i| format!("(sAMAccountName={})", ldap_escape(&users[i].username))).collect();
        let filter = format!("(&(objectClass=user)(|{names}))");
        let attrs = vec!["sAMAccountName", "lockoutTime", "pwdLastSet", "msDS-User-Account-Control-Computed"];
        let Ok(Ok((entries, _))) =
            ldap.with_timeout(OP_TIMEOUT).search(base_dn, Scope::Subtree, &filter, attrs).await.map(|r| r.success())
        else {
            return;
        };
        let found: std::collections::HashMap<String, SearchEntry> = entries
            .into_iter()
            .map(SearchEntry::construct)
            .map(|e| (attr(&e, "sAMAccountName").to_lowercase(), e))
            .collect();
        for &i in part {
            if let Some(e) = found.get(&users[i].username.to_lowercase()) {
                users[i].locked = is_locked(e);
                users[i].password = password_state(e);
            }
        }
    }
}

/// `OU=Europe,OU=Sales,DC=x` below `DC=x` as `Sales › Europe`.
pub(crate) fn location(dn: &str, base_dn: &str) -> String {
    let parts = dn_parts(dn);
    let below = parts.len().saturating_sub(dn_parts(base_dn).len());
    parts[..below]
        .iter()
        .rev()
        .map(|p| first_rdn_value(p))
        .collect::<Vec<_>>()
        .join(" › ")
}

// ── OUs and containers, as a tree to browse by ───────────────────────────────

/// One entry of the directory tree on the Users and Groups pages.
#[derive(Debug, Serialize, Clone)]
pub struct UserContainer {
    pub dn: String,
    pub name: String,
    /// 1 for an OU or container at the top of the domain.
    pub depth: usize,
    pub is_ou: bool,
    /// Objects (users, or groups) directly in it.
    pub direct: usize,
    /// Objects in it and everything below it.
    pub total: usize,
}

/// The OUs and containers to browse by, in tree order: every OU, and the
/// containers (such as `CN=Users` or `CN=Builtin`) that hold one of the
/// objects listed, given by the DN of the container each is in. Like Active
/// Directory Users and Computers, "advanced" ones such as `CN=System` are left out.
/// `keep` names a container shown even when empty — the page's default one
/// (`CN=Users`, `CN=Computers`), so there is always somewhere to move back to.
pub async fn list_containers(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    objects_in: &[&str],
    keep: &str,
) -> LdapResult<Vec<UserContainer>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Subtree,
            "(&(|(objectClass=organizationalUnit)(objectClass=container)(objectClass=builtinDomain))\
             (!(showInAdvancedViewOnly=TRUE)))",
            vec!["objectClass"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let found = entries
        .into_iter()
        .map(SearchEntry::construct)
        .map(|e| {
            let is_ou = e.attrs.get("objectClass").is_some_and(|v| {
                v.iter().any(|c| c.eq_ignore_ascii_case("organizationalUnit"))
            });
            (e.dn, is_ou)
        })
        .collect();
    Ok(container_tree(base_dn, found, objects_in, keep))
}

pub(crate) fn container_tree(
    base_dn: &str,
    mut found: Vec<(String, bool)>,
    objects_in: &[&str],
    keep: &str,
) -> Vec<UserContainer> {
    found.sort_by_cached_key(|(dn, _)| dn_tree_sort_key(dn));

    let mut direct: std::collections::HashMap<String, usize> = Default::default();
    let mut total: std::collections::HashMap<String, usize> = Default::default();
    for container in objects_in {
        let c = container.to_lowercase();
        *direct.entry(c.clone()).or_default() += 1;
        let mut d = c.as_str();
        while !d.is_empty() {
            *total.entry(d.to_string()).or_default() += 1;
            d = parent_dn(d);
        }
    }

    // Parents sort before their children, so one pass drops everything under
    // something left out (such as a container inside CN=System).
    let mut kept: HashSet<String> = HashSet::from([base_dn.to_lowercase()]);
    let mut tree = Vec::new();
    for (dn, is_ou) in found {
        let key = dn.to_lowercase();
        let in_tree = kept.contains(parent_dn(&key));
        let count = total.get(&key).copied().unwrap_or(0);
        // A container with none of the objects (Computers on the Users page,
        // ForeignSecurityPrincipals…) is noise here. An OU stays: it is the domain's own structure.
        if !in_tree || (!is_ou && count == 0 && !key.eq_ignore_ascii_case(keep)) {
            continue;
        }
        kept.insert(key.clone());
        tree.push(UserContainer {
            name: first_rdn_value(&dn),
            depth: ou_depth(&dn, base_dn) + 1,
            is_ou,
            direct: direct.get(&key).copied().unwrap_or(0),
            total: count,
            dn,
        });
    }
    tree
}

// ── profile fields and account expiry ────────────────────────────────────────

/// The optional fields the Add and Edit forms share. An empty value means
/// "not set": nothing is written on create, and the attribute is cleared on edit.
#[derive(Default)]
pub struct UserProfile<'a> {
    pub description: &'a str,
    pub title: &'a str,
    pub department: &'a str,
    pub office: &'a str,
    pub phone: &'a str,
    pub mobile: &'a str,
    /// A username, or a DN (kept as-is, for a manager that is not a user).
    pub manager: &'a str,
    /// Last day the account can be used, `YYYY-MM-DD`; empty for never.
    pub expires: &'a str,
}

impl UserProfile<'_> {
    /// (label, attribute, value, maximum length). The limits are Windows AD's
    /// schema limits: Samba does not enforce them, but a Windows DC joined
    /// later, or a Windows tool, would trip over longer values.
    fn text_fields(&self) -> [(&'static str, &'static str, &str, usize); 6] {
        [
            ("Description", "description", self.description, 1024),
            ("Job title", "title", self.title, 128),
            ("Department", "department", self.department, 64),
            ("Office", "physicalDeliveryOfficeName", self.office, 128),
            ("Phone", "telephoneNumber", self.phone, 64),
            ("Mobile", "mobile", self.mobile, 64),
        ]
    }

    pub(crate) fn check(&self) -> LdapResult<()> {
        for (label, _, value, max) in self.text_fields() {
            if value.chars().count() > max {
                return Err(format!("{label} is longer than {max} characters"));
            }
            if value.chars().any(char::is_control) {
                return Err(format!("{label} contains a control character"));
            }
        }
        expiry_filetime(self.expires)?;
        Ok(())
    }
}

/// accountExpires value meaning "never" — what Windows writes. Samba also
/// treats 0 as never.
const NEVER_EXPIRES: i64 = i64::MAX;
const TICKS_PER_SECOND: i64 = 10_000_000;
const FILETIME_UNIX_EPOCH: i64 = 11_644_473_600 * TICKS_PER_SECOND;

fn unix_to_filetime(secs: i64) -> i64 {
    secs * TICKS_PER_SECOND + FILETIME_UNIX_EPOCH
}

/// A FILETIME as Unix time; `None` for 0 and "never", which are not moments.
pub(crate) fn filetime_to_unix(ft: i64) -> Option<i64> {
    (ft > 0 && ft != NEVER_EXPIRES).then(|| (ft - FILETIME_UNIX_EPOCH).div_euclid(TICKS_PER_SECOND))
}

/// accountExpires for "the account works through this day": midnight UTC at
/// the start of the next day. `Ok(None)` for an empty date (never expires).
pub(crate) fn expiry_filetime(date: &str) -> LdapResult<Option<i64>> {
    if date.is_empty() {
        return Ok(None);
    }
    let bad = || format!("Account expiry '{date}' is not a date (YYYY-MM-DD)");
    let b = date.as_bytes();
    if b.len() != 10 || b[4] != b'-' || b[7] != b'-' {
        return Err(bad());
    }
    let num = |r: std::ops::Range<usize>| date[r].parse::<i64>().map_err(|_| bad());
    let (y, m, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    if !(1970..=9999).contains(&y) {
        return Err(bad());
    }
    let day = crate::health::days_from_civil(y, m, d);
    // Rejects 2026-02-30 and the like, which days_from_civil would roll over.
    if crate::health::civil_from_days(day) != (y, m, d) {
        return Err(bad());
    }
    Ok(Some(unix_to_filetime((day + 1) * 86_400)))
}

/// The last day an account can be used, from its accountExpires; `None` when
/// it never expires. The inverse of expiry_filetime, and for a value another
/// tool wrote at some time of day, the day that moment falls on (UTC).
pub(crate) fn expiry_date(filetime: i64) -> Option<String> {
    if filetime <= 0 || filetime == NEVER_EXPIRES {
        return None;
    }
    let last_moment = (filetime - 1 - FILETIME_UNIX_EPOCH).div_euclid(TICKS_PER_SECOND);
    let (y, m, d) = crate::health::civil_from_days(last_moment.div_euclid(86_400));
    Some(format!("{y:04}-{m:02}-{d:02}"))
}

/// Replace an attribute, or remove it when the value is empty: an empty value
/// is not a valid LDAP string, and "remove" is what a blanked field means.
fn set_or_clear(attr: &str, value: &str) -> Mod<Vec<u8>> {
    let values = if value.is_empty() { HashSet::new() } else { HashSet::from([sv(value)]) };
    Mod::Replace(sv(attr), values)
}

/// The manager's DN. A username is looked up; a DN (what the form shows for a
/// manager that is not a user) is kept as it is — the DC checks that it exists.
async fn manager_dn(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    manager: &str,
) -> LdapResult<Option<String>> {
    if manager.is_empty() {
        return Ok(None);
    }
    if manager.contains('=') {
        return Ok(Some(manager.to_string()));
    }
    find_user_dn(ldap, base_dn, manager)
        .await
        .map(Some)
        .map_err(|_| format!("Manager '{manager}' not found"))
}

// ── create user ───────────────────────────────────────────────────────────────

pub struct NewUser<'a> {
    pub username: &'a str,
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub password: &'a str,
    pub profile: UserProfile<'a>,
    /// The OU or container to create the user in; empty for `CN=Users`.
    pub parent: &'a str,
    /// Must set a new password at the first sign-in.
    pub must_change: bool,
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
    check_account_name("A username", u.username)?;
    let domain = base_dn_to_domain(base_dn);
    let upn = format!("{}@{}", u.username, domain);
    let parent = new_object_parent(u.parent, base_dn)?;
    let mut user_dn = format!("CN={},{}", dn_escape(&cn), parent);

    // Checked before anything is created, so a typo does not leave a
    // half-made account behind.
    u.profile.check()?;
    let manager = manager_dn(ldap, base_dn, u.profile.manager).await?;
    let expires = expiry_filetime(u.profile.expires)?;

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
    for (_, name, value, _) in u.profile.text_fields() {
        if !value.is_empty() {
            attrs.push((sv(name), HashSet::from([sv(value)])));
        }
    }
    if let Some(dn) = &manager {
        attrs.push((sv("manager"), HashSet::from([sv(dn)])));
    }
    if let Some(ft) = expires {
        attrs.push((sv("accountExpires"), HashSet::from([sv(&ft.to_string())])));
    }

    let mut res = ldap.with_timeout(OP_TIMEOUT).add(&user_dn, attrs.clone()).await.map_err(ldap_err)?;
    if res.rc == 68 && !account_name_taken(&res) && cn != u.username {
        // Something here already has this name, such as a second John
        // Smith: this one's object is named after its username as well. Its
        // display name stays as typed.
        let cn = format!("{cn} ({})", u.username);
        user_dn = format!("CN={},{}", dn_escape(&cn), parent);
        for (name, values) in attrs.iter_mut() {
            if name.as_slice() == b"cn" {
                *values = HashSet::from([sv(&cn)]);
            }
        }
        res = ldap.with_timeout(OP_TIMEOUT).add(&user_dn, attrs).await.map_err(ldap_err)?;
    }
    let what = "The user was not created";
    match res.rc {
        0 => {}
        68 if account_name_taken(&res) => {
            return Err(format!("{what}: the username {} is already used by another user, group or computer.", u.username))
        }
        68 => return Err(format!("{what}: {} already holds an object named {cn}.", link_place(&parent))),
        _ => return Err(refused(what, &link_place(&parent), &res)),
    }

    // Set password then enable
    let pwd_mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("unicodePwd"),
        HashSet::from([encode_password(u.password)]),
    )];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&user_dn, pwd_mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        // The account exists now, disabled and without a password. Remove
        // it, so a corrected retry does not hit "already exists".
        let removed = ldap.with_timeout(OP_TIMEOUT).delete(&user_dn).await.ok().and_then(|r| r.success().ok()).is_some();
        let msg = password_error("The user was not created", res.rc, &res.text);
        return Err(if removed {
            msg
        } else {
            format!("{msg} A disabled account {} was left behind; delete it before trying again.", u.username)
        });
    }

    let mut enable_mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv("512")]),
    )];
    if u.must_change {
        enable_mods.push(Mod::Replace(sv("pwdLastSet"), HashSet::from([sv("0")])));
    }
    ldap.with_timeout(OP_TIMEOUT).modify(&user_dn, enable_mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to enable account"))?;

    Ok(())
}

// ── update user ───────────────────────────────────────────────────────────────

pub struct UserUpdate<'a> {
    pub first_name: &'a str,
    pub last_name: &'a str,
    pub email: &'a str,
    pub password: &'a str,
    pub profile: UserProfile<'a>,
}

pub async fn update_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    u: &UserUpdate<'_>,
) -> LdapResult<()> {
    u.profile.check()?;
    let filter = format!("(&(objectClass=user)(sAMAccountName={}))", ldap_escape(username));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["accountExpires"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let entry = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("User '{}' not found", username))?;
    let dn = entry.dn.clone();
    let current_expiry: i64 = attr(&entry, "accountExpires").parse().unwrap_or(0);
    let manager = manager_dn(ldap, base_dn, u.profile.manager).await?;

    let display = format!("{} {}", u.first_name, u.last_name)
        .trim()
        .to_string();

    let mut mods: Vec<Mod<Vec<u8>>> = vec![
        set_or_clear("givenName", u.first_name),
        set_or_clear("sn", u.last_name),
        set_or_clear("displayName", &display),
        set_or_clear("mail", u.email),
        set_or_clear("manager", manager.as_deref().unwrap_or_default()),
    ];
    for (_, name, value, _) in u.profile.text_fields() {
        mods.push(set_or_clear(name, value));
    }
    // Only when the date changed: the form shows a date, and a time of day
    // another tool set (samba-tool setexpiry --days) would otherwise be moved
    // to midnight by saving an unrelated field.
    if expiry_date(current_expiry).unwrap_or_default() != u.profile.expires {
        let ft = expiry_filetime(u.profile.expires)?.unwrap_or(NEVER_EXPIRES);
        mods.push(Mod::Replace(sv("accountExpires"), HashSet::from([sv(&ft.to_string())])));
    }

    if !u.password.is_empty() {
        mods.push(Mod::Replace(
            sv("unicodePwd"),
            HashSet::from([encode_password(u.password)]),
        ));
    }

    let res = ldap.with_timeout(OP_TIMEOUT).modify(&dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        rc if !u.password.is_empty() && is_password_refusal(rc, &res.text) => {
            Err(password_error("Nothing was saved", rc, &res.text))
        }
        _ => Err(dc_refused("Failed to update user", &res)),
    }
}

// ── delete user ───────────────────────────────────────────────────────────────

pub async fn delete_user(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
) -> LdapResult<()> {
    let dn = find_user_dn(ldap, base_dn, username).await?;
    ldap.with_timeout(OP_TIMEOUT).delete(&dn)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to delete user"))?;
    Ok(())
}

// ── enable / disable user ────────────────────────────────────────────────────

/// userAccountControl with only the ACCOUNTDISABLE bit changed.
///
/// Enabling and disabling used to write fixed values — 512/514 for users,
/// 4096/4098 for computers — which silently cleared every other flag: "password
/// never expires", delegation, and for a domain controller SERVER_TRUST_ACCOUNT,
/// turning its account into a workstation's.
fn with_account_disabled(uac: i64, disabled: bool) -> i64 {
    if disabled { uac | 0x2 } else { uac & !0x2 }
}

/// Enable or disable a user found with [`find_user_for_change`]. A user
/// already that way is left alone: the DC is not asked to write anything.
pub async fn set_user_enabled(ldap: &mut ldap3::Ldap, user: &UserForChange, enable: bool) -> LdapResult<()> {
    let uac = with_account_disabled(user.uac, !enable);
    if uac == user.uac {
        return Ok(());
    }
    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv(&uac.to_string())]),
    )];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&user.dn, mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        let what = format!("{} was not {}", first_rdn_value(&user.dn), if enable { "enabled" } else { "disabled" });
        return Err(refused(&what, "the user", &res));
    }
    Ok(())
}

// ── reset password ─────────────────────────────────────────────────────────────

/// Set a new password for the user at `dn`. Requires an LDAPS (or sign/seal) connection,
/// same as initial password set. When `force_change` is true the user must
/// change the password at next logon (pwdLastSet=0); otherwise it is marked as
/// freshly set (pwdLastSet=-1).
pub async fn reset_password(ldap: &mut ldap3::Ldap, dn: &str, new_password: &str, force_change: bool) -> LdapResult<()> {
    let pwd_last_set = if force_change { "0" } else { "-1" };
    let mods: Vec<Mod<Vec<u8>>> = vec![
        Mod::Replace(sv("unicodePwd"), HashSet::from([encode_password(new_password)])),
        Mod::Replace(sv("pwdLastSet"), HashSet::from([sv(pwd_last_set)])),
    ];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        rc => Err(password_error("The password was not changed", rc, &res.text)),
    }
}

// ── password settings ─────────────────────────────────────────────────────────

/// A user's password settings, for the Edit dialog's Password tab.
#[derive(Debug, Serialize, Clone, PartialEq, Default)]
pub struct PasswordSettings {
    /// Must set a new password at the next sign-in (pwdLastSet 0).
    pub must_change: bool,
    /// Denied the Change Password right (see [`crate::sd`]).
    pub cannot_change: bool,
    /// DONT_EXPIRE_PASSWORD in userAccountControl.
    pub never_expires: bool,
    /// When the password was last set, "2026-11-22 10:15 UTC"; empty when never.
    pub last_set: String,
    /// When it expires: a time, "Never", or empty when the DC does not say.
    pub expires: String,
}

const DONT_EXPIRE_PASSWORD: i64 = 0x1_0000;

/// What the settings are changed to.
pub struct PasswordSettingsChange {
    pub must_change: bool,
    pub cannot_change: bool,
    pub never_expires: bool,
}

/// A user's entry with what its password settings are read from.
struct PasswordEntry {
    dn: String,
    name: String,
    is_bind: bool,
    uac: i64,
    pwd_last_set: i64,
    descriptor: crate::sd::Descriptor,
    expiry: Option<i64>,
}

pub(crate) fn sd_flags_dacl() -> ldap3::controls::RawControl {
    ldap3::controls::RawControl {
        ctype: crate::sd::SD_FLAGS_OID.to_string(),
        crit: true,
        val: Some(crate::sd::SD_FLAGS_DACL.to_vec()),
    }
}

async fn password_entry(ldap: &mut ldap3::Ldap, base_dn: &str, username: &str, bind: &str) -> LdapResult<PasswordEntry> {
    let filter = format!(
        "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName={}))",
        ldap_escape(username.trim())
    );
    let attrs = vec![
        "sAMAccountName",
        "userPrincipalName",
        "userAccountControl",
        "pwdLastSet",
        "msDS-UserPasswordExpiryTimeComputed",
        "nTSecurityDescriptor",
    ];
    let (entries, _) = ldap
        .with_controls(sd_flags_dacl())
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, attrs)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("User '{}' not found", username.trim()))?;
    let raw = e
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first())
        .ok_or("The DC did not give the user's security descriptor; the bind account may lack the right to read it")?;
    let uac = attr(&e, "userAccountControl")
        .parse()
        .map_err(|_| format!("Could not read userAccountControl of {}", e.dn))?;
    Ok(PasswordEntry {
        name: attr(&e, "sAMAccountName"),
        is_bind: is_bind_account(bind, &e.dn, &attr(&e, "userPrincipalName"), &attr(&e, "sAMAccountName")),
        uac,
        pwd_last_set: attr(&e, "pwdLastSet").parse().unwrap_or(0),
        descriptor: crate::sd::Descriptor::parse(raw).map_err(|why| format!("Could not read {}'s access list: {why}", e.dn))?,
        expiry: crate::health::attr_ci(&e, "msDS-UserPasswordExpiryTimeComputed").parse().ok(),
        dn: e.dn,
    })
}

/// A FILETIME as "2026-11-22 10:15 UTC".
fn filetime_text(ft: i64) -> String {
    let secs = (ft - FILETIME_UNIX_EPOCH).div_euclid(TICKS_PER_SECOND);
    let (y, m, d) = crate::health::civil_from_days(secs.div_euclid(86_400));
    let rest = secs.rem_euclid(86_400);
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02} UTC", rest / 3600, rest % 3600 / 60)
}

impl PasswordEntry {
    fn settings(&self) -> PasswordSettings {
        let never_expires = self.uac & DONT_EXPIRE_PASSWORD != 0;
        PasswordSettings {
            must_change: self.pwd_last_set == 0,
            cannot_change: self.descriptor.cannot_change_password(),
            never_expires,
            last_set: if self.pwd_last_set > 0 { filetime_text(self.pwd_last_set) } else { String::new() },
            expires: match self.expiry {
                // A change was asked for: it has to be changed now, whatever the age.
                _ if self.pwd_last_set == 0 => String::new(),
                _ if never_expires => "Never".to_string(),
                Some(t) if t == i64::MAX || t == 0 => "Never".to_string(),
                Some(t) if t > 0 => filetime_text(t),
                _ => String::new(),
            },
        }
    }
}

pub async fn password_settings(ldap: &mut ldap3::Ldap, base_dn: &str, username: &str) -> LdapResult<PasswordSettings> {
    Ok(password_entry(ldap, base_dn, username, "").await?.settings())
}

/// Settings that cannot go together, as Windows warns about them: a user who
/// may not change the password, or whose password never expires, cannot be
/// made to change it at the next sign-in.
fn conflicting(want: &PasswordSettingsChange) -> Option<&'static str> {
    if want.must_change && want.cannot_change {
        Some("A user who cannot change their password cannot be made to change it at the next sign-in. Choose one.")
    } else if want.must_change && want.never_expires {
        Some("A password that never expires is not asked to be changed at the next sign-in either. Choose one.")
    } else {
        None
    }
}

/// Change a user's password settings. Returns what changed, in words, for
/// the audit log; nothing when they were already so.
pub async fn set_password_settings(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    username: &str,
    bind: &str,
    want: &PasswordSettingsChange,
) -> LdapResult<Vec<String>> {
    if let Some(why) = conflicting(want) {
        return Err(why.to_string());
    }
    let mut entry = password_entry(ldap, base_dn, username, bind).await?;
    let now = entry.settings();
    if want.must_change && !now.must_change && entry.is_bind {
        return Err(format!(
            "EasyDC signs in to the DC as {}, so making it change its password at the next sign-in would lock \
             EasyDC out. To do it, first change the server's bind account (Edit on the dashboard).",
            entry.name
        ));
    }
    let on_off = |b: bool| if b { "on" } else { "off" };
    let mut changed = Vec::new();
    let mut mods: Vec<Mod<Vec<u8>>> = Vec::new();
    if want.never_expires != now.never_expires {
        let uac = if want.never_expires { entry.uac | DONT_EXPIRE_PASSWORD } else { entry.uac & !DONT_EXPIRE_PASSWORD };
        mods.push(Mod::Replace(sv("userAccountControl"), HashSet::from([sv(&uac.to_string())])));
        changed.push(format!("password never expires: {}", on_off(want.never_expires)));
    }
    if want.must_change != now.must_change {
        // -1 marks the password as set now, so it does not count as expired.
        let value = if want.must_change { "0" } else { "-1" };
        mods.push(Mod::Replace(sv("pwdLastSet"), HashSet::from([sv(value)])));
        changed.push(format!("must change at next sign-in: {}", on_off(want.must_change)));
    }
    if !mods.is_empty() {
        let res = ldap.with_timeout(OP_TIMEOUT).modify(&entry.dn, mods).await.map_err(ldap_err)?;
        if res.rc != 0 {
            return Err(refused("The password settings were not changed", "the user", &res));
        }
    }
    if want.cannot_change != now.cannot_change {
        entry.descriptor.set_cannot_change_password(want.cannot_change);
        let value = HashSet::from([entry.descriptor.to_bytes()]);
        let res = ldap
            .with_controls(sd_flags_dacl())
            .with_timeout(OP_TIMEOUT)
            .modify(&entry.dn, vec![Mod::Replace(b"nTSecurityDescriptor".to_vec(), value)])
            .await
            .map_err(ldap_err)?;
        if res.rc != 0 {
            let what = if changed.is_empty() {
                "\"Cannot change password\" was not changed".to_string()
            } else {
                format!("Saved {}, but \"cannot change password\" was not changed", changed.join(", "))
            };
            return Err(refused(&what, "the user's access list", &res));
        }
        changed.push(format!("cannot change password: {}", on_off(want.cannot_change)));
    }
    Ok(changed)
}

/// Samba's replies to a password write that it refuses: 0000052D (Windows'
/// ERROR_PASSWORD_RESTRICTION) when the password breaks the policy that
/// governs the account, and confidentialityRequired (13) when the connection
/// is not encrypted.
fn is_password_refusal(rc: u32, text: &str) -> bool {
    (rc == 19 && text.contains("0000052D")) || rc == 13
}

/// A password write's failure in words: which rule it broke, not just the
/// LDAP code. `what` says what did not happen.
pub(crate) fn password_error(what: &str, rc: u32, text: &str) -> String {
    if rc == 19 && text.contains("0000052D") {
        format!(
            "{what}: the password does not meet the password policy for this account — too short, \
             not complex enough, or used before. The Password Policy page shows which policy applies."
        )
    } else if rc == 13 {
        format!("{what}: passwords can only be set over an encrypted connection. Add the server with an ldaps:// URL.")
    } else if rc == 50 {
        format!("{what}: the account EasyDC signs in with is not allowed to set passwords here.")
    } else {
        format!("{what}: {} (rc={rc})", text.trim())
    }
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
    ldap.with_timeout(OP_TIMEOUT).modify(&dn, mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to unlock account"))?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Groups
// ═══════════════════════════════════════════════════════════════════════════

// groupType bits (MS-ADTS 2.2.12). Stored as a signed 32-bit integer, so a
// security group's value is negative.
const GT_BUILTIN: u32 = 0x1;
const GT_GLOBAL: u32 = 0x2;
const GT_DOMAIN_LOCAL: u32 = 0x4;
const GT_UNIVERSAL: u32 = 0x8;
const GT_SECURITY: u32 = 0x8000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupScope {
    Global,
    DomainLocal,
    Universal,
    /// The groups under CN=Builtin (Administrators, Users…): domain local in
    /// behaviour, fixed in type.
    Builtin,
}

impl GroupScope {
    pub fn of(group_type: i64) -> Option<Self> {
        let b = group_type as u32;
        if b & GT_BUILTIN != 0 {
            Some(Self::Builtin)
        } else if b & GT_GLOBAL != 0 {
            Some(Self::Global)
        } else if b & GT_DOMAIN_LOCAL != 0 {
            Some(Self::DomainLocal)
        } else if b & GT_UNIVERSAL != 0 {
            Some(Self::Universal)
        } else {
            None
        }
    }

    /// The scopes a form may ask for. Builtin is not one: no group becomes one.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "global" => Some(Self::Global),
            "domain_local" => Some(Self::DomainLocal),
            "universal" => Some(Self::Universal),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::DomainLocal => "domain local",
            Self::Universal => "universal",
            Self::Builtin => "builtin local",
        }
    }

    fn bit(self) -> u32 {
        match self {
            Self::Global => GT_GLOBAL,
            Self::DomainLocal => GT_DOMAIN_LOCAL,
            Self::Universal => GT_UNIVERSAL,
            Self::Builtin => GT_BUILTIN | GT_DOMAIN_LOCAL,
        }
    }

    /// AD's nesting rules, within one domain: a global group holds only global
    /// groups, a universal one global and universal groups, and a domain local
    /// one any of them. Samba does not enforce these, but Windows clients and
    /// tools assume them, so EasyDC does.
    fn may_contain(self, child: GroupScope) -> bool {
        match self {
            Self::Global => child == Self::Global,
            Self::Universal => matches!(child, Self::Global | Self::Universal),
            Self::DomainLocal | Self::Builtin => true,
        }
    }
}

pub fn group_type_value(scope: GroupScope, security: bool) -> i64 {
    let sec = if security { GT_SECURITY } else { 0 };
    ((scope.bit() | sec) as i32) as i64
}

fn is_security(group_type: i64) -> bool {
    group_type as u32 & GT_SECURITY != 0
}

fn group_type_label(t: i64) -> String {
    match GroupScope::of(t) {
        None => "Other".to_string(),
        Some(s) => {
            let mut label = s.label().to_string();
            label[..1].make_ascii_uppercase();
            let label = label.replace("local", "Local");
            format!("{label} {}", if is_security(t) { "Security" } else { "Distribution" })
        }
    }
}

#[derive(Debug, Serialize, Clone)]
pub struct LdapGroup {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub group_type: i64,
    pub group_type_label: String,
    pub scope: Option<GroupScope>,
    pub security: bool,
    /// A built-in or critical system group: its scope and type stay as they are.
    pub system: bool,
    pub member_count: usize,
    /// The DN of the OU or container the group is in.
    pub container: String,
    /// That OU or container as `Sales › Europe`; filled in by [`list_groups`].
    pub location: String,
}

impl LdapGroup {
    pub(crate) fn from_entry(e: &SearchEntry) -> Self {
        let gt: i64 = attr(e, "groupType").parse().unwrap_or(0);
        let scope = GroupScope::of(gt);
        LdapGroup {
            dn: e.dn.clone(),
            name: attr(e, "sAMAccountName"),
            description: attr(e, "description"),
            group_type: gt,
            group_type_label: group_type_label(gt),
            scope,
            security: is_security(gt),
            system: scope == Some(GroupScope::Builtin)
                || attr(e, "isCriticalSystemObject").eq_ignore_ascii_case("TRUE"),
            member_count: e.attrs.get("member").map(|v| v.len()).unwrap_or(0),
            container: parent_dn(&e.dn).to_string(),
            location: String::new(),
        }
    }
}

pub(crate) const GROUP_ATTRS: [&str; 4] = ["sAMAccountName", "description", "groupType", "isCriticalSystemObject"];

/// Whether a group search also reads each group's member list. Only the
/// groups list needs it, for the member count: a large group's list is
/// thousands of DNs, so every other lookup leaves it out.
#[derive(Clone, Copy, PartialEq)]
enum Members {
    Count,
    Skip,
}

async fn search_groups(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    filter: &str,
    members: Members,
) -> LdapResult<Vec<LdapGroup>> {
    let mut attrs = GROUP_ATTRS.to_vec();
    if members == Members::Count {
        attrs.push("member");
    }
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &format!("(&(objectClass=group){filter})"), attrs)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut groups: Vec<LdapGroup> = entries
        .into_iter()
        .map(|e| LdapGroup::from_entry(&SearchEntry::construct(e)))
        .filter(|g| !g.name.is_empty())
        .collect();
    groups.sort_by_key(|a| a.name.to_lowercase());
    Ok(groups)
}

pub(crate) async fn find_group(ldap: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<LdapGroup> {
    let filter = format!("(sAMAccountName={})", ldap_escape(name));
    search_groups(ldap, base_dn, &filter, Members::Skip)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| format!("Group '{}' not found", name))
}

async fn find_group_dn(ldap: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<String> {
    Ok(find_group(ldap, base_dn, name).await?.dn)
}

/// Groups that have `dn` as a direct member.
async fn parent_groups(ldap: &mut ldap3::Ldap, base_dn: &str, dn: &str) -> LdapResult<Vec<LdapGroup>> {
    search_groups(ldap, base_dn, &format!("(member={})", ldap_escape(dn)), Members::Skip).await
}

/// One group a user is in, for the Edit dialog.
#[derive(Debug, Serialize, Clone, PartialEq)]
pub struct UserGroup {
    pub name: String,
    pub dn: String,
    pub description: String,
    /// Where the group is: `Sales › Europe`.
    pub location: String,
    /// The user's primary group (usually Domain Users). AD keeps it as a
    /// number on the user, not in the group's members, so it cannot be removed.
    pub primary: bool,
}

/// The groups a user is directly in, the primary group first, and the user's DN.
pub async fn user_groups(ldap: &mut ldap3::Ldap, base_dn: &str, username: &str) -> LdapResult<(String, Vec<UserGroup>)> {
    let filter = format!(
        "(&(objectClass=user)(!(objectClass=computer))(sAMAccountName={}))",
        ldap_escape(username.trim())
    );
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["primaryGroupID", "objectSid"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let user = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("User '{}' not found", username.trim()))?;

    let as_row = |g: LdapGroup, primary: bool| UserGroup {
        location: location(&g.container, base_dn),
        name: g.name,
        dn: g.dn,
        description: g.description,
        primary,
    };
    let mut groups: Vec<UserGroup> =
        parent_groups(ldap, base_dn, &user.dn).await?.into_iter().map(|g| as_row(g, false)).collect();

    // The primary group's SID is the domain's SID and primaryGroupID.
    let sid = object_sid(&user);
    let rid = attr(&user, "primaryGroupID").parse::<u32>().ok();
    if let (Some(sid), Some(rid)) = (sid, rid)
        && let Some((domain, _)) = sid.rsplit_once('-')
    {
        let filter = format!("(objectSid={domain}-{rid})");
        if let Some(g) = search_groups(ldap, base_dn, &filter, Members::Skip).await?.into_iter().next() {
            groups.retain(|x| !x.dn.eq_ignore_ascii_case(&g.dn));
            groups.insert(0, as_row(g, true));
        }
    }
    Ok((user.dn, groups))
}

/// An entry's objectSid as text. The LDAP library files a value under `attrs`
/// when its bytes happen to be valid UTF-8, and every built-in group's SID is
/// (`S-1-5-32-544` is all bytes below 0x80), so both places are looked in.
pub(crate) fn object_sid(e: &SearchEntry) -> Option<String> {
    let binary = e.bin_attrs.get("objectSid").and_then(|v| v.first()).map(Vec::as_slice);
    let text = e.attrs.get("objectSid").and_then(|v| v.first()).map(String::as_bytes);
    binary.or(text).and_then(sid_string)
}

/// A binary SID as text: `S-1-5-21-…-1105` (revision, 48-bit authority,
/// then the sub-authorities, little-endian).
pub(crate) fn sid_string(b: &[u8]) -> Option<String> {
    let count = usize::from(*b.get(1)?);
    if b.len() != 8 + 4 * count {
        return None;
    }
    let authority = b[2..8].iter().fold(0u64, |a, &x| (a << 8) | u64::from(x));
    let mut sid = format!("S-{}-{}", b[0], authority);
    for sub in b[8..].as_chunks::<4>().0 {
        sid += &format!("-{}", u32::from_le_bytes(*sub));
    }
    Some(sid)
}

/// Groups that are direct members of the group `dn`.
async fn child_groups(ldap: &mut ldap3::Ldap, base_dn: &str, dn: &str) -> LdapResult<Vec<LdapGroup>> {
    search_groups(ldap, base_dn, &format!("(memberOf={})", ldap_escape(dn)), Members::Skip).await
}

// ── list groups ───────────────────────────────────────────────────────────────

pub async fn list_groups(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapGroup>> {
    let mut groups = search_groups(ldap, base_dn, "", Members::Count).await?;
    for g in &mut groups {
        g.location = location(&g.container, base_dn);
    }
    Ok(groups)
}

// ── create group ──────────────────────────────────────────────────────────────

pub struct NewGroup<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub group_type: i64,
    /// The OU or container to create the group in; empty for `CN=Users`.
    pub parent: &'a str,
}

/// `CN=Builtin`, the container for Windows' own groups.
pub(crate) fn is_builtin_container(dn: &str, base_dn: &str) -> bool {
    parent_dn(dn).eq_ignore_ascii_case(base_dn)
        && dn_parts(dn).first().is_some_and(|p| p.eq_ignore_ascii_case("CN=Builtin"))
}

/// Where a new user or group goes: `parent`, checked to be in the domain, or
/// `CN=Users` when none is given, or when it is `CN=Builtin`, which holds only
/// Windows' own groups.
/// The characters Samba and Windows refuse in an account name
/// (sAMAccountName): a username, or a group's name.
const ACCOUNT_NAME_FORBIDDEN: &str = "\"/\\[]:;|=,+*?<>@";

/// Refuse an account name the DC would refuse, saying which character is
/// the problem; `what` is "A username" or "A group name".
pub(crate) fn check_account_name(what: &str, name: &str) -> LdapResult<()> {
    if name.trim().is_empty() {
        return Err(format!("{what} is needed."));
    }
    if name != name.trim() {
        return Err(format!("{what} cannot start or end with a space."));
    }
    if let Some(c) = name.chars().find(|&c| ACCOUNT_NAME_FORBIDDEN.contains(c) || c.is_control()) {
        let shown = if c.is_control() { "a control character".to_string() } else { format!("\"{c}\"") };
        return Err(format!("{what} cannot contain {shown}. These are not allowed: \" / \\ [ ] : ; | = , + * ? < > @"));
    }
    if name.ends_with('.') {
        return Err(format!("{what} cannot end with a full stop."));
    }
    Ok(())
}

/// The DC refused an add because the account name is in use somewhere in
/// the domain, rather than because the same place holds the same name.
fn account_name_taken(res: &ldap3::LdapResult) -> bool {
    res.text.to_ascii_lowercase().contains("samaccountname")
}

/// `text` with a capital first letter, to start a message.
fn sentence(text: &str) -> String {
    let mut chars = text.chars();
    chars.next().map(|c| c.to_uppercase().chain(chars).collect()).unwrap_or_default()
}

/// `link_place`, or "the top of the domain" for the domain itself.
fn place_or_domain(dn: &str) -> String {
    if dn.get(..3).is_some_and(|t| t.eq_ignore_ascii_case("DC=")) { "the top of the domain".into() } else { link_place(dn) }
}

fn new_object_parent(parent: &str, base_dn: &str) -> LdapResult<String> {
    if parent.is_empty() || is_builtin_container(parent, base_dn) {
        Ok(format!("CN=Users,{base_dn}"))
    } else if is_within(parent, base_dn) {
        Ok(parent.to_string())
    } else {
        Err(format!("{parent} is not in this domain"))
    }
}

/// One of the six types the Add form offers, and nothing else: a made-up
/// value (a builtin bit, two scopes at once) would make a group no tool
/// expects.
fn check_new_group_type(t: i64) -> LdapResult<()> {
    match GroupScope::of(t) {
        Some(s) if s != GroupScope::Builtin && group_type_value(s, is_security(t)) == t => Ok(()),
        _ => Err(format!("Group type {t} is not one EasyDC creates")),
    }
}

pub async fn create_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    g: &NewGroup<'_>,
) -> LdapResult<()> {
    check_new_group_type(g.group_type)?;
    check_account_name("A group name", g.name)?;
    let parent = new_object_parent(g.parent, base_dn)?;
    let group_dn = format!("CN={},{}", dn_escape(g.name), parent);
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

    let res = ldap.with_timeout(OP_TIMEOUT).add(&group_dn, attrs).await.map_err(ldap_err)?;
    let what = "The group was not created";
    match res.rc {
        0 => Ok(()),
        68 if account_name_taken(&res) => {
            Err(format!("{what}: the name {} is already used by another user, group or computer.", g.name))
        }
        68 => Err(format!("{what}: {} already holds an object named {}.", link_place(&parent), g.name)),
        _ => Err(refused(what, &link_place(&parent), &res)),
    }
}

// ── update group ──────────────────────────────────────────────────────────────

pub struct GroupUpdate<'a> {
    pub description: &'a str,
    /// None leaves the scope as it is (a form from before scopes were editable).
    pub scope: Option<GroupScope>,
    pub security: Option<bool>,
}

/// Whether `group` may change to `scope`, given the groups it is in and the
/// groups in it. These are AD's rules: global and domain local only change
/// through universal, and no membership may break the nesting rules after
/// the change.
pub(crate) fn check_scope_change(
    group: &LdapGroup,
    scope: GroupScope,
    security: bool,
    parents: &[LdapGroup],
    children: &[LdapGroup],
) -> LdapResult<()> {
    let Some(old) = group.scope else {
        return Err(format!("{} has a group type EasyDC does not know, so it is left as it is", group.name));
    };
    if old == scope && group.security == security {
        return Ok(());
    }
    if group.system {
        return Err(format!("{} is a built-in group: its scope and type cannot be changed", group.name));
    }
    if old == scope {
        return Ok(()); // security ↔ distribution only
    }
    if matches!(
        (old, scope),
        (GroupScope::Global, GroupScope::DomainLocal) | (GroupScope::DomainLocal, GroupScope::Global)
    ) {
        return Err(format!(
            "A {} group cannot become {} directly. Change {} to universal first, then to {}.",
            old.label(), scope.label(), group.name, scope.label()
        ));
    }
    for p in parents {
        if let Some(ps) = p.scope
            && !ps.may_contain(scope)
        {
            return Err(format!(
                "{} is a member of {}, a {} group, which cannot contain a {} group. Remove it from {} first.",
                group.name, p.name, ps.label(), scope.label(), p.name
            ));
        }
    }
    for c in children {
        if let Some(cs) = c.scope
            && !scope.may_contain(cs)
        {
            return Err(format!(
                "{} has {} as a member, a {} group, which a {} group cannot contain. Remove {} first.",
                group.name, c.name, cs.label(), scope.label(), c.name
            ));
        }
    }
    Ok(())
}

pub async fn update_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
    g: &GroupUpdate<'_>,
) -> LdapResult<()> {
    let group = find_group(ldap, base_dn, name).await?;

    // Replace with no value, not Delete: Delete fails when the group has no
    // description to begin with.
    let mut mods: Vec<Mod<Vec<u8>>> = vec![set_or_clear("description", g.description)];

    let scope = g.scope.or(group.scope);
    let security = g.security.unwrap_or(group.security);
    if let Some(scope) = scope
        && (Some(scope) != group.scope || security != group.security)
    {
        let parents = parent_groups(ldap, base_dn, &group.dn).await?;
        let children = child_groups(ldap, base_dn, &group.dn).await?;
        check_scope_change(&group, scope, security, &parents, &children)?;
        let gt = group_type_value(scope, security).to_string();
        mods.push(Mod::Replace(sv("groupType"), HashSet::from([sv(&gt)])));
    }

    ldap.with_timeout(OP_TIMEOUT).modify(&group.dn, mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to update group"))?;

    Ok(())
}

// ── delete group ──────────────────────────────────────────────────────────────

pub async fn delete_group(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
) -> LdapResult<()> {
    let dn = find_group_dn(ldap, base_dn, name).await?;
    ldap.with_timeout(OP_TIMEOUT).delete(&dn)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to delete group"))?;
    Ok(())
}

// ── group members ─────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Clone)]
pub struct GroupMember {
    pub dn: String,
    pub name: String,
    pub display_name: String,
    /// user, computer, group, contact, foreign or other.
    pub kind: &'static str,
    /// Email for a user, type for a group.
    pub detail: String,
    /// For a group member: its name, to link to its own members page.
    pub group: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct GroupDetail {
    pub group: LdapGroup,
    pub members: Vec<GroupMember>,
    pub member_of: Vec<LdapGroup>,
}

/// The value of a DN's first part, unescaped enough to read: `CN=Doe\, John,…`
/// gives `Doe, John`.
pub(crate) fn first_rdn_value(dn: &str) -> String {
    // Bytes, since an escape may be hex: `\3B` for `;`, `\C3\A9` for `é`.
    let mut out = Vec::new();
    let mut chars = dn.chars().peekable();
    let mut in_value = false;
    let hex = |c: Option<&char>| c.and_then(|c| c.to_digit(16));
    while let Some(c) = chars.next() {
        if c == '\\' {
            let high = hex(chars.peek());
            let mut ahead = chars.clone();
            ahead.next();
            match (high, hex(ahead.peek())) {
                (Some(h), Some(l)) => {
                    chars.next();
                    chars.next();
                    if in_value {
                        out.push((h * 16 + l) as u8);
                    }
                }
                _ => {
                    if let Some(e) = chars.next().filter(|_| in_value) {
                        out.extend_from_slice(e.encode_utf8(&mut [0; 4]).as_bytes());
                    }
                }
            }
        } else if !in_value {
            in_value = c == '=';
        } else if c == ',' {
            break;
        } else {
            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Names for the well-known SIDs Samba puts into builtin groups, which show
/// up as foreign security principals named by SID.
pub(crate) fn well_known_sid(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-1-0" => "Everyone",
        "S-1-5-4" => "Interactive",
        "S-1-5-9" => "Enterprise Domain Controllers",
        "S-1-5-11" => "Authenticated Users",
        "S-1-5-17" => "IUSR",
        "S-1-5-20" => "Network Service",
        _ => return None,
    })
}

fn member_from_entry(e: &SearchEntry) -> GroupMember {
    let classes: Vec<String> = e
        .attrs
        .get("objectClass")
        .map(|v| v.iter().map(|c| c.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    let has = |c: &str| classes.iter().any(|x| x == c);
    let sam = attr(e, "sAMAccountName");
    let cn = attr(e, "cn");
    let uac: Option<i64> = attr(e, "userAccountControl").parse().ok();
    let (kind, detail, group) = if has("computer") {
        ("computer", String::new(), None)
    } else if has("group") {
        let gt: i64 = attr(e, "groupType").parse().unwrap_or(0);
        ("group", group_type_label(gt), Some(sam.clone()))
    } else if has("user") {
        ("user", attr(e, "mail"), None)
    } else if has("contact") {
        ("contact", attr(e, "mail"), None)
    } else if has("foreignsecurityprincipal") {
        ("foreign", cn.clone(), None)
    } else {
        ("other", String::new(), None)
    };
    let name = match kind {
        "foreign" => well_known_sid(&cn).map(str::to_string).unwrap_or_else(|| cn.clone()),
        _ if !sam.is_empty() => sam,
        _ => cn,
    };
    GroupMember {
        dn: e.dn.clone(),
        name,
        display_name: attr(e, "displayName"),
        kind,
        detail,
        group,
        enabled: if matches!(kind, "user" | "computer") { uac.map(|u| u & 2 == 0) } else { None },
    }
}

/// A group with its members — every kind, not only users — and the groups it
/// is a member of.
pub async fn group_detail(ldap: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<GroupDetail> {
    let group = find_group(ldap, base_dn, name).await?;
    let member_dns = group_member_dns(ldap, &group.dn).await?;

    // One search for all members, instead of one per member.
    let mut found: std::collections::HashMap<String, GroupMember> = std::collections::HashMap::new();
    if !member_dns.is_empty() {
        let (entries, _) = ldap
            .with_timeout(OP_TIMEOUT)
            .search(
                base_dn,
                Scope::Subtree,
                &format!("(memberOf={})", ldap_escape(&group.dn)),
                vec!["objectClass", "sAMAccountName", "cn", "displayName", "mail", "userAccountControl", "groupType"],
            )
            .await
            .map_err(ldap_err)?
            .success()
            .map_err(ldap_err)?;
        for e in entries {
            let m = member_from_entry(&SearchEntry::construct(e));
            found.insert(m.dn.to_lowercase(), m);
        }
    }
    // A member the search did not return (outside this partition) still shows.
    let mut members: Vec<GroupMember> = member_dns
        .iter()
        .map(|dn| {
            found.remove(&dn.to_lowercase()).unwrap_or_else(|| GroupMember {
                dn: dn.clone(),
                name: first_rdn_value(dn),
                display_name: String::new(),
                kind: "other",
                detail: String::new(),
                group: None,
                enabled: None,
            })
        })
        .collect();
    members.sort_by_key(|m| (m.kind != "group", m.name.to_lowercase()));

    let member_of = parent_groups(ldap, base_dn, &group.dn).await?;
    Ok(GroupDetail { group, members, member_of })
}

/// Everything that can be added to a group, for the Add box's suggestions.
pub async fn member_candidates(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<String>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, "(|(objectClass=user)(objectClass=group))", vec!["sAMAccountName"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut names: Vec<String> = entries
        .into_iter()
        .map(|e| attr(&SearchEntry::construct(e), "sAMAccountName"))
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    Ok(names)
}

/// Whether `child` may be added to `parent`, by the nesting rules. A group of
/// unknown type is left to the DC.
pub(crate) fn check_nesting(parent: &LdapGroup, child: &LdapGroup) -> LdapResult<()> {
    if parent.dn.eq_ignore_ascii_case(&child.dn) {
        return Err(format!("{} cannot be a member of itself", parent.name));
    }
    if let (Some(ps), Some(cs)) = (parent.scope, child.scope)
        && !ps.may_contain(cs)
    {
        return Err(format!(
            "{} is a {} group and cannot contain {}, a {} group",
            parent.name, ps.label(), child.name, cs.label()
        ));
    }
    Ok(())
}

const ALREADY_MEMBER: &str = "is already a member of";

/// Whether an error from [`add_group_member`] only says the member was there.
pub(crate) fn is_already_member(error: &str) -> bool {
    error.contains(ALREADY_MEMBER)
}

/// The DNs of a group's direct members.
pub async fn group_member_dns(ldap: &mut ldap3::Ldap, group_dn: &str) -> LdapResult<Vec<String>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(group_dn, Scope::Base, "(objectClass=group)", vec!["member"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    Ok(entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| e.attrs.get("member").cloned())
        .unwrap_or_default())
}

/// How many members one change adds. Samba rewrites a group's whole member
/// list on every change, so one change per member slows down as the group
/// grows: 2,000 one at a time took two minutes.
const MEMBERS_PER_CHANGE: usize = 250;

/// Add users, by DN, to a group, a few hundred per change. Every DN gets its
/// own result. If a change is refused, its users are added one at a time, so
/// the one that caused it gets the error and the others are still added.
/// The caller leaves out users already in the group.
pub async fn add_member_dns(ldap: &mut ldap3::Ldap, group: &LdapGroup, dns: &[String]) -> Vec<LdapResult<()>> {
    let mut results = Vec::with_capacity(dns.len());
    for chunk in dns.chunks(MEMBERS_PER_CHANGE) {
        let all: HashSet<Vec<u8>> = chunk.iter().map(|dn| sv(dn)).collect();
        let together = ldap.with_timeout(OP_TIMEOUT).modify(&group.dn, vec![Mod::Add(sv("member"), all)]).await;
        if matches!(&together, Ok(res) if res.rc == 0) {
            results.extend(chunk.iter().map(|_| Ok(())));
            continue;
        }
        for dn in chunk {
            let one = ldap.with_timeout(OP_TIMEOUT).modify(&group.dn, vec![Mod::Add(sv("member"), HashSet::from([sv(dn)]))]).await;
            results.push(match one {
                Ok(res) if res.rc == 0 => Ok(()),
                Ok(res) if res.rc == 20 || res.rc == 68 => {
                    Err(format!("{} {ALREADY_MEMBER} {}", first_rdn_value(dn), group.name))
                }
                Ok(res) => Err(dc_refused("Failed to add member", &res)),
                Err(e) => Err(e.to_string()),
            });
        }
    }
    results
}

/// Add a user, computer or group to a group, by its sAMAccountName. A
/// computer can be given without its trailing `$`.
pub async fn add_group_member(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    group_name: &str,
    member: &str,
) -> LdapResult<()> {
    let target = find_group(ldap, base_dn, group_name).await?;

    let filter = format!(
        "(&(|(objectClass=user)(objectClass=group))(|(sAMAccountName={0})(sAMAccountName={0}$)))",
        ldap_escape(member)
    );
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["objectClass", "sAMAccountName", "groupType", "isCriticalSystemObject"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut entries: Vec<SearchEntry> = entries.into_iter().map(SearchEntry::construct).collect();
    // "name" itself before "name$".
    entries.sort_by_key(|e| !attr(e, "sAMAccountName").eq_ignore_ascii_case(member));
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| format!("No user, computer or group is named '{}'", member))?;

    let is_group = entry
        .attrs
        .get("objectClass")
        .is_some_and(|v| v.iter().any(|c| c.eq_ignore_ascii_case("group")));
    if is_group {
        let child = LdapGroup::from_entry(&entry);
        check_nesting(&target, &child)?;
        // AD allows loops (A in B in A), but they make membership confusing
        // and some tools walk them forever. In-chain matching finds a target
        // that is already inside the child at any depth.
        let loop_filter = format!("(member:1.2.840.113556.1.4.1941:={})", ldap_escape(&target.dn));
        let (inside, _) = ldap
            .with_timeout(OP_TIMEOUT)
            .search(&child.dn, Scope::Base, &loop_filter, vec!["dn"])
            .await
            .map_err(ldap_err)?
            .success()
            .map_err(ldap_err)?;
        if !inside.is_empty() {
            return Err(format!(
                "{} is already inside {}, directly or through other groups; adding {} to it would make a loop",
                target.name, child.name, child.name
            ));
        }
    }

    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Add(sv("member"), HashSet::from([sv(&entry.dn)]))];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&target.dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        20 | 68 => Err(format!("{} {ALREADY_MEMBER} {}", attr(&entry, "sAMAccountName"), target.name)),
        _ => Err(dc_refused("Failed to add member", &res)),
    }
}

/// Remove a member by DN: members without a username (contacts, foreign
/// principals) can be removed too.
pub async fn remove_group_member(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    group_name: &str,
    member_dn: &str,
) -> LdapResult<()> {
    let group_dn = find_group_dn(ldap, base_dn, group_name).await?;
    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Delete(sv("member"), HashSet::from([sv(member_dn)]))];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&group_dn, mods).await.map_err(ldap_err)?;
    if res.rc == 0 {
        return Ok(());
    }
    Err(if not_a_member(res.rc, &res.text) {
        format!("{} is not a member of {}", first_rdn_value(member_dn), group_name)
    } else {
        dc_refused("Failed to remove member", &res)
    })
}

/// Removing a value that is not there: LDAP says noSuchAttribute (16), but
/// Samba answers unwillingToPerform (53) with "Attribute member already
/// deleted" (seen on a 4.x DC).
fn not_a_member(rc: u32, text: &str) -> bool {
    rc == 16 || (rc == 53 && text.contains("already deleted"))
}

// ═══════════════════════════════════════════════════════════════════════════
// Computers
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Serialize, Clone)]
pub struct LdapComputer {
    pub dn: String,
    pub name: String,
    pub sam_account: String,
    /// The account name without its `$`: unique in the domain, unlike the
    /// name, so the page acts on computers by it.
    pub account: String,
    pub dns_hostname: String,
    pub os: String,
    pub os_version: String,
    pub enabled: bool,
    /// A domain controller's own account, which EasyDC leaves alone.
    pub is_dc: bool,
    /// DN of the OU or container it is in.
    pub container: String,
    /// Where that is, read top down: `Sales › Laptops`.
    pub location: String,
}

/// userAccountControl's SERVER_TRUST_ACCOUNT: the account of a domain controller.
const SERVER_TRUST_ACCOUNT: i64 = 0x2000;

/// A computer about to be changed: its entry, and whether it is a DC.
struct ComputerEntry {
    dn: String,
    name: String,
    uac: i64,
}

impl ComputerEntry {
    fn is_dc(&self) -> bool {
        self.uac & SERVER_TRUST_ACCOUNT != 0
    }

    /// Refuse a change that would take a domain controller out of the domain.
    fn refuse_dc(&self, doing: &str) -> LdapResult<()> {
        if !self.is_dc() {
            return Ok(());
        }
        if doing == "delete" {
            return Err(format!(
                "{} is a domain controller, so EasyDC does not delete it. To remove a DC, demote it first \
                 (samba-tool domain demote on that DC).",
                self.name
            ));
        }
        Err(format!(
            "{} is a domain controller, so EasyDC does not {doing} it: that would stop it working as one.",
            self.name
        ))
    }
}

/// The computer whose account name is `account` (with or without its `$`).
async fn find_computer(ldap: &mut ldap3::Ldap, base_dn: &str, account: &str) -> LdapResult<ComputerEntry> {
    let account = account.trim().trim_end_matches('$');
    let filter = format!("(&(objectClass=computer)(sAMAccountName={}$))", ldap_escape(account));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["cn", "userAccountControl"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("Computer '{}' not found", account))?;
    // Read, not assumed: it is written back with one bit changed.
    let uac = attr(&e, "userAccountControl")
        .parse()
        .map_err(|_| format!("Could not read userAccountControl of {}", e.dn))?;
    Ok(ComputerEntry {
        name: Some(attr(&e, "cn")).filter(|n| !n.is_empty()).unwrap_or_else(|| account.to_string()),
        uac,
        dn: e.dn,
    })
}

pub async fn list_computers(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<Vec<LdapComputer>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
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
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    let mut computers: Vec<LdapComputer> = entries
        .into_iter()
        .map(|e| {
            let e = SearchEntry::construct(e);
            let uac: i64 = attr(&e, "userAccountControl").parse().unwrap_or(4096);
            let sam_account = attr(&e, "sAMAccountName");
            let container = parent_dn(&e.dn).to_string();
            LdapComputer {
                name: attr(&e, "cn"),
                account: sam_account.trim_end_matches('$').to_string(),
                sam_account,
                dns_hostname: attr(&e, "dNSHostName"),
                os: attr(&e, "operatingSystem"),
                os_version: attr(&e, "operatingSystemVersion"),
                enabled: (uac & 2) == 0,
                is_dc: uac & SERVER_TRUST_ACCOUNT != 0,
                location: location(&container, base_dn),
                container,
                dn: e.dn,
            }
        })
        .filter(|c| !c.name.is_empty() && !c.account.is_empty())
        .collect();

    computers.sort_by_key(|a| a.name.to_lowercase());
    Ok(computers)
}

pub async fn delete_computer(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    account: &str,
) -> LdapResult<()> {
    let computer = find_computer(ldap, base_dn, account).await?;
    computer.refuse_dc("delete")?;
    let name = computer.name.as_str();
    let res = ldap.with_timeout(OP_TIMEOUT).delete(&computer.dn).await.map_err(ldap_err)?;
    let what = format!("{name} was not deleted");
    match res.rc {
        0 => Ok(()),
        66 => Err(format!(
            "{what}: it holds other objects, such as BitLocker recovery keys or a domain controller's own records, \
             and the domain controller deletes only computers that hold nothing."
        )),
        _ => Err(refused(&what, &format!("computer {name}"), &res)),
    }
}

pub async fn set_computer_enabled(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    account: &str,
    enable: bool,
) -> LdapResult<()> {
    let computer = find_computer(ldap, base_dn, account).await?;
    if !enable {
        computer.refuse_dc("disable")?;
    }
    let name = computer.name.as_str();
    let uac = with_account_disabled(computer.uac, !enable);
    if uac == computer.uac {
        return Ok(());
    }
    let mods: Vec<Mod<Vec<u8>>> = vec![Mod::Replace(
        sv("userAccountControl"),
        HashSet::from([sv(&uac.to_string())]),
    )];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&computer.dn, mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        let what = format!("{name} was not {}", if enable { "enabled" } else { "disabled" });
        return Err(refused(&what, &format!("computer {name}"), &res));
    }
    Ok(())
}

/// Move a computer into the OU or container `target`. A domain controller
/// stays in Domain Controllers, where the policies DCs need apply.
pub async fn move_computer(ldap: &mut ldap3::Ldap, base_dn: &str, account: &str, target: &str) -> LdapResult<()> {
    let computer = find_computer(ldap, base_dn, account).await?;
    computer.refuse_dc("move")?;
    move_entry(ldap, base_dn, &computer.dn, target).await
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS
// ═══════════════════════════════════════════════════════════════════════════

// ── binary helpers ────────────────────────────────────────────────────────────

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub(crate) fn from_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
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

/// A hostname the record formats can hold: labels of 1 to 63 bytes, 253 in
/// all. "@" and "." (the zone apex / no target) are allowed.
fn check_dns_name(name: &str) -> LdapResult<()> {
    let bare = name.trim_end_matches('.');
    if bare.is_empty() || bare == "@" {
        return Ok(());
    }
    if bare.len() > 253 {
        return Err(format!("'{}' is longer than 253 characters", name));
    }
    if bare.split('.').any(|l| l.is_empty() || l.len() > 63) {
        return Err(format!("'{}' is not a valid hostname: each part must be 1 to 63 characters", name));
    }
    if bare.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(format!("'{}' is not a valid hostname", name));
    }
    Ok(())
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
        // MX and SRV numbers are big-endian (Samba's dnsp.idl).
        15 if payload.len() >= 2 => {
            let priority = u16::from_be_bytes([payload[0], payload[1]]);
            let name = parse_dns_rpc_name(&payload[2..]);
            ("MX".to_string(), format!("{} {}", priority, name))
        }
        16 => ("TXT".to_string(), parse_txt_bytes(payload)),
        33 if payload.len() >= 6 => {
            let priority = u16::from_be_bytes([payload[0], payload[1]]);
            let weight = u16::from_be_bytes([payload[2], payload[3]]);
            let port = u16::from_be_bytes([payload[4], payload[5]]);
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
        "NS" | "CNAME" | "PTR" => {
            check_dns_name(value)?;
            let code = match record_type { "NS" => 2, "CNAME" => 5, _ => 12 };
            (code, encode_dns_rpc_name(value))
        }
        "TXT" => {
            // A DNS character-string holds at most 255 bytes; longer text (DKIM
            // keys, long SPF) is split across several, which resolvers join.
            let bytes = value.as_bytes();
            if bytes.len() > 4000 {
                return Err("TXT value is too long (4000 bytes at most)".to_string());
            }
            let mut d = Vec::with_capacity(bytes.len() + bytes.len() / 255 + 1);
            for chunk in bytes.chunks(255) {
                d.push(chunk.len() as u8);
                d.extend_from_slice(chunk);
            }
            if bytes.is_empty() {
                d.push(0);
            }
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
                .map(|n| n.trim())
                .ok_or_else(|| "MX format: <priority> <hostname>".to_string())?;
            check_dns_name(name)?;
            let mut d = priority.to_be_bytes().to_vec();
            d.extend(encode_dns_rpc_name(name));
            (15, d)
        }
        "SRV" => {
            // priority weight port target, e.g. "0 100 389 dc1.example.com".
            // The numbers are big-endian, as Samba stores them.
            const FORMAT: &str = "SRV format: <priority> <weight> <port> <target>";
            let parts: Vec<&str> = value.split_whitespace().collect();
            let [priority, weight, port, target] = parts[..] else {
                return Err(FORMAT.to_string());
            };
            let mut d = Vec::new();
            for n in [priority, weight, port] {
                let n: u16 = n.parse().map_err(|_| FORMAT.to_string())?;
                d.extend_from_slice(&n.to_be_bytes());
            }
            check_dns_name(target)?;
            d.extend(encode_dns_rpc_name(target));
            (33, d)
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
            .with_timeout(OP_TIMEOUT)
            .search(base, Scope::OneLevel, "(objectClass=dnsZone)", vec!["dc"])
            .await
            .map(|r| r.success())
            && !e.is_empty()
        {
            entries = e;
            break;
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
    let filter = format!("(&(objectClass=dnsZone)(dc={}))", ldap_escape(zone_name));
    let candidates = [
        format!("CN=MicrosoftDNS,DC=DomainDnsZones,{}", base_dn),
        format!("CN=MicrosoftDNS,CN=System,{}", base_dn),
        format!("DC=DomainDnsZones,{}", base_dn),
    ];

    for base in &candidates {
        if let Ok(Ok((entries, _))) = ldap
            .with_timeout(OP_TIMEOUT)
            .search(base, Scope::OneLevel, &filter, vec!["dc"])
            .await
            .map(|r| r.success())
            && let Some(e) = entries.into_iter().next()
        {
            return Ok(SearchEntry::construct(e).dn);
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
        .with_timeout(OP_TIMEOUT)
        .search(
            zone_dn,
            Scope::OneLevel,
            "(&(objectClass=dnsNode)(!(dNSTombstoned=TRUE)))",
            vec!["dc", "dnsRecord"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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
    let node_dn = format!("DC={},{}", dn_escape(node_name), zone_dn);

    // Check if the node already exists
    let exists = ldap
        .with_timeout(OP_TIMEOUT)
        .search(&node_dn, Scope::Base, "(objectClass=dnsNode)", vec!["dc"])
        .await
        .ok()
        .and_then(|r| r.success().ok())
        .map(|(e, _)| !e.is_empty())
        .unwrap_or(false);

    if exists {
        let mods: Vec<Mod<Vec<u8>>> =
            vec![Mod::Add(sv("dnsRecord"), HashSet::from([record_bytes]))];
        ldap.with_timeout(OP_TIMEOUT).modify(&node_dn, mods)
            .await
            .map_err(ldap_err)?
            .success()
            .map_err(dc_failed("Failed to add record"))?;
    } else {
        let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (sv("objectClass"), HashSet::from([sv("top"), sv("dnsNode")])),
            (sv("dc"), HashSet::from([sv(node_name)])),
            (sv("dnsRecord"), HashSet::from([record_bytes])),
        ];
        ldap.with_timeout(OP_TIMEOUT).add(&node_dn, attrs)
            .await
            .map_err(ldap_err)?
            .success()
            .map_err(dc_failed("Failed to create DNS node"))?;
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
    dn_parts(dn).len().saturating_sub(dn_parts(base_dn).len() + 1)
}

/// Sorts a DN after its parent and before its parent's next sibling, siblings
/// by name.
fn dn_tree_sort_key(dn: &str) -> Vec<(String, String)> {
    dn_parts(dn)
        .into_iter()
        .rev()
        .map(|p| (first_rdn_value(p).to_lowercase(), p.to_lowercase()))
        .collect()
}

// ── list OUs (tree order) ─────────────────────────────────────────────────────

pub async fn list_ous_tree(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<Vec<LdapOuNode>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["ou", "description"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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

    nodes.sort_by_cached_key(|a| dn_tree_sort_key(&a.dn));
    Ok(nodes)
}

// ── create OU ─────────────────────────────────────────────────────────────────

pub async fn create_ou(
    ldap: &mut ldap3::Ldap,
    parent_dn: &str,
    name: &str,
    description: &str,
) -> LdapResult<()> {
    let name = name.trim();
    if name.is_empty() {
        return Err("The OU was not created: its name is empty.".into());
    }
    let ou_dn = format!("OU={},{}", dn_escape(name), parent_dn);
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

    let res = ldap.with_timeout(OP_TIMEOUT).add(&ou_dn, attrs).await.map_err(ldap_err)?;
    let what = "The OU was not created";
    match res.rc {
        0 => Ok(()),
        68 => Err(format!("{what}: {} already holds an OU or container named {name}.", place_or_domain(parent_dn))),
        _ => Err(refused(what, &place_or_domain(parent_dn), &res)),
    }
}

// ── rename OU ─────────────────────────────────────────────────────────────────

pub async fn rename_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    new_name: &str,
) -> LdapResult<()> {
    let new_name = new_name.trim();
    let what = sentence(&format!("{} was not renamed", link_place(ou_dn)));
    if new_name.is_empty() {
        return Err(format!("{what}: the new name is empty."));
    }
    let new_rdn = format!("OU={}", dn_escape(new_name));
    let res = ldap.with_timeout(OP_TIMEOUT).modifydn(ou_dn, &new_rdn, true, None).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        68 => Err(format!("{what}: an OU or container named {new_name} is already there.")),
        _ => Err(refused(&what, &link_place(ou_dn), &res)),
    }
}

// ── delete OU ─────────────────────────────────────────────────────────────────

pub async fn delete_ou(ldap: &mut ldap3::Ldap, ou_dn: &str) -> LdapResult<()> {
    let res = ldap.with_timeout(OP_TIMEOUT).delete(ou_dn).await.map_err(ldap_err)?;
    let what = sentence(&format!("{} was not deleted", link_place(ou_dn)));
    match res.rc {
        0 => Ok(()),
        66 => Err(format!(
            "{what}: it is not empty. Move or delete what is in it first: users, groups, computers and the OUs below it."
        )),
        _ => Err(refused(&what, &link_place(ou_dn), &res)),
    }
}

// ── move object to OU ─────────────────────────────────────────────────────────

/// What kind of object an account name is, for the permission moving it needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    User,
    Group,
    Computer,
}

/// The entry behind an account name (a computer's without its `$`), and its kind.
pub async fn find_movable(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    sam_account: &str,
) -> LdapResult<(String, ObjectKind)> {
    // A computer's account name ends in `$`; the form says to leave it off.
    let filter = format!(
        "(|(sAMAccountName={0})(sAMAccountName={0}$))",
        ldap_escape(sam_account)
    );
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["sAMAccountName", "objectClass"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut entries: Vec<SearchEntry> = entries.into_iter().map(SearchEntry::construct).collect();
    entries.sort_by_key(|e| !attr(e, "sAMAccountName").eq_ignore_ascii_case(sam_account));
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| format!("Object '{}' not found", sam_account))?;
    Ok((entry.dn.clone(), object_kind(&entry)))
}

/// A computer is also a user in AD, so it is checked first.
fn object_kind(e: &SearchEntry) -> ObjectKind {
    let classes = e.attrs.get("objectClass").cloned().unwrap_or_default();
    let is = |c: &str| classes.iter().any(|x| x.eq_ignore_ascii_case(c));
    if is("computer") {
        ObjectKind::Computer
    } else if is("group") {
        ObjectKind::Group
    } else {
        ObjectKind::User
    }
}

pub async fn move_object_to_ou(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    dn: &str,
    target_ou_dn: &str,
) -> LdapResult<()> {
    move_entry(ldap, base_dn, dn, target_ou_dn).await
}

/// The name of the OU or container at `dn`, after checking it is one and is
/// in this domain: somewhere users and computers can be moved to.
pub async fn container_name(ldap: &mut ldap3::Ldap, base_dn: &str, dn: &str) -> LdapResult<String> {
    if !is_within(dn, base_dn) {
        return Err(format!("{dn} is not in this domain"));
    }
    let res = ldap
        .with_timeout(OP_TIMEOUT)
        .search(dn, Scope::Base, "(|(objectClass=organizationalUnit)(objectClass=container))", vec!["dn"])
        .await
        .map_err(ldap_err)?;
    match res.1.rc {
        0 if !res.0.is_empty() => Ok(first_rdn_value(dn)),
        0 => Err(format!("{} is not an OU or container", first_rdn_value(dn))),
        32 => Err(format!("{dn} does not exist")),
        _ => Err(format!("Could not read {dn}: {}", res.1)),
    }
}

/// Move the object at `dn` into the OU or container `target`, keeping its
/// name. Nothing happens when it is already there.
pub async fn move_entry(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    dn: &str,
    target: &str,
) -> LdapResult<()> {
    if !is_within(target, base_dn) {
        return Err(format!("{target} is not in this domain"));
    }
    if parent_dn(dn).eq_ignore_ascii_case(target) {
        return Ok(());
    }
    let rdn = dn_parts(dn).first().copied().ok_or_else(|| format!("Invalid DN: {dn}"))?;
    let res = ldap
        .with_timeout(OP_TIMEOUT)
        .modifydn(dn, rdn, true, Some(target))
        .await
        .map_err(ldap_err)?;
    let (name, place) = (first_rdn_value(rdn), first_rdn_value(target));
    match res.rc {
        0 => Ok(()),
        68 => Err(format!("{place} already holds an object named {name}")),
        32 => Err(format!("{target} does not exist")),
        _ => Err(dc_refused(&format!("Failed to move {name}"), &res)),
    }
}

// ── GPO list ──────────────────────────────────────────────────────────────────

pub async fn list_gpos(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapGpo>> {
    let policies_dn = format!("CN=Policies,CN=System,{}", base_dn);
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(
            &policies_dn,
            Scope::OneLevel,
            "(objectClass=groupPolicyContainer)",
            vec!["cn", "displayName", "flags", "versionNumber", "gPCFileSysPath"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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

    gpos.sort_by_key(|a| a.display_name.to_lowercase());
    Ok(gpos)
}

// ── create GPO ────────────────────────────────────────────────────────────────

/// The directory's half of a GPO, with the `User` and `Machine` containers
/// clients and GPMC expect. Returns its GUID, in capitals, without braces.
pub(crate) async fn add_gpo_object(ldap: &mut ldap3::Ldap, base_dn: &str, display_name: &str) -> LdapResult<String> {
    let id = Uuid::new_v4().to_string().to_uppercase();
    let guid = format!("{{{id}}}");
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

    let res = ldap.with_timeout(OP_TIMEOUT).add(&gpo_dn, attrs).await.map_err(ldap_err)?;
    if res.rc != 0 {
        return Err(refused(&format!("{display_name} was not created"), "the Policies container", &res));
    }
    for child in ["User", "Machine"] {
        let attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
            (sv("objectClass"), HashSet::from([sv("top"), sv("container")])),
            (sv("cn"), HashSet::from([sv(child)])),
        ];
        let added = ldap.with_timeout(OP_TIMEOUT).add(&format!("CN={child},{gpo_dn}"), attrs).await.map_err(ldap_err);
        let failed = match added {
            Ok(r) if r.rc == 0 => None,
            Ok(r) => Some(refused(&format!("{display_name} was not created"), &gpo_dn, &r)),
            Err(e) => Some(e),
        };
        if let Some(e) = failed {
            let _ = delete_gpo_tree(ldap, &gpo_dn).await;
            return Err(e);
        }
    }
    Ok(id)
}

/// The GPO object's owner, group and permissions.
pub(crate) async fn gpo_descriptor(ldap: &mut ldap3::Ldap, gpo_dn: &str) -> LdapResult<crate::sd::Descriptor> {
    let control = ldap3::controls::RawControl {
        ctype: crate::sd::SD_FLAGS_OID.to_string(),
        crit: true,
        val: Some(crate::sd::SD_FLAGS_OWNER_GROUP_DACL.to_vec()),
    };
    let (entries, _) = ldap
        .with_controls(control)
        .with_timeout(OP_TIMEOUT)
        .search(gpo_dn, Scope::Base, "(objectClass=*)", vec!["nTSecurityDescriptor"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let e = entries.into_iter().next().map(SearchEntry::construct).ok_or("The DC did not return the GPO.")?;
    let raw = e
        .bin_attrs
        .get("nTSecurityDescriptor")
        .and_then(|v| v.first())
        .ok_or("The DC did not give the GPO's permissions; the bind account may lack the right to read them.")?;
    crate::sd::Descriptor::parse(raw)
}

pub(crate) async fn gpo_has_children(ldap: &mut ldap3::Ldap, gpo_dn: &str) -> LdapResult<bool> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(gpo_dn, Scope::OneLevel, "(objectClass=*)", vec!["1.1"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    Ok(!entries.is_empty())
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
    let res = ldap.with_timeout(OP_TIMEOUT).modify(gpo_dn, mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        return Err(refused("The GPO was not saved", "this GPO", &res));
    }
    Ok(())
}

// ── delete GPO ────────────────────────────────────────────────────────────────

/// The GPO object and what it holds, with the tree delete control.
pub(crate) async fn delete_gpo_tree(ldap: &mut ldap3::Ldap, gpo_dn: &str) -> LdapResult<()> {
    let tree_delete = ldap3::controls::RawControl { ctype: "1.2.840.113556.1.4.805".to_string(), crit: true, val: None };
    let res = ldap.with_controls(tree_delete).with_timeout(OP_TIMEOUT).delete(gpo_dn).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        _ => Err(refused("The GPO was not deleted", "this GPO", &res)),
    }
}

// ── OU list ───────────────────────────────────────────────────────────────────

pub async fn list_ous(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<LdapOu>> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Subtree,
            "(objectClass=organizationalUnit)",
            vec!["ou", "name"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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

    ous.sort_by_key(|a| a.name.to_lowercase());

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
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, "(gPLink=*)", vec!["name", "ou", "gPLink"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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

/// The OU or container a link is changed on, by name, for messages.
fn link_place(ou_dn: &str) -> String {
    let name = first_rdn_value(ou_dn);
    if ou_dn.get(..3).is_some_and(|t| t.eq_ignore_ascii_case("OU=")) { format!("the OU {name}") } else { name }
}

/// The gPLink of the OU at `ou_dn`; `what` says what did not happen if it cannot be read.
async fn read_gp_link(ldap: &mut ldap3::Ldap, ou_dn: &str, what: &str) -> LdapResult<String> {
    let ldap3::SearchResult(entries, res) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(ou_dn, Scope::Base, "(objectClass=*)", vec!["gPLink"])
        .await
        .map_err(ldap_err)?;
    if res.rc != 0 {
        return Err(refused(what, &link_place(ou_dn), &res));
    }
    Ok(entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .map(|e| attr(&e, "gPLink"))
        .unwrap_or_default())
}

pub async fn link_gpo_to_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    gpo_dn: &str,
) -> LdapResult<()> {
    let what = "The GPO was not linked";
    // A link to a GPO that is gone would point at nothing.
    let ldap3::SearchResult(_, found) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(gpo_dn, Scope::Base, "(objectClass=groupPolicyContainer)", vec!["cn"])
        .await
        .map_err(ldap_err)?;
    if found.rc != 0 {
        return Err(refused(what, "this GPO", &found));
    }
    let current = read_gp_link(ldap, ou_dn, what).await?;

    let gpo_dn_lower = gpo_dn.to_lowercase();
    let mut links = parse_gp_link(&current);

    if links.iter().any(|(dn, _)| dn.to_lowercase() == gpo_dn_lower) {
        return Ok(());
    }
    links.push((gpo_dn.to_string(), 0));
    let new_link = build_gp_link(&links);

    let mods: Vec<Mod<Vec<u8>>> =
        vec![Mod::Replace(sv("gPLink"), HashSet::from([sv(&new_link)]))];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(ou_dn, mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        return Err(refused(what, &link_place(ou_dn), &res));
    }

    Ok(())
}

pub async fn unlink_gpo_from_ou(
    ldap: &mut ldap3::Ldap,
    ou_dn: &str,
    gpo_dn: &str,
) -> LdapResult<()> {
    let what = "The link was not removed";
    let current = read_gp_link(ldap, ou_dn, what).await?;

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

    let res = ldap.with_timeout(OP_TIMEOUT).modify(ou_dn, mods).await.map_err(ldap_err)?;
    if res.rc != 0 {
        return Err(refused(what, &link_place(ou_dn), &res));
    }

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
    let node_dn = format!("DC={},{}", dn_escape(node_name), zone_dn);

    let mods: Vec<Mod<Vec<u8>>> =
        vec![Mod::Delete(sv("dnsRecord"), HashSet::from([raw_bytes]))];
    ldap.with_timeout(OP_TIMEOUT).modify(&node_dn, mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to delete record"))?;

    // That was the name's last record: remove the name too, or an empty
    // dnsNode stays in the directory. Best effort — the record is gone
    // either way.
    let now_empty = ldap
        .with_timeout(OP_TIMEOUT)
        .search(&node_dn, Scope::Base, "(&(objectClass=dnsNode)(!(dnsRecord=*)))", vec!["dc"])
        .await
        .ok()
        .and_then(|r| r.success().ok())
        .is_some_and(|(e, _)| !e.is_empty());
    if now_empty {
        let _ = ldap.with_timeout(OP_TIMEOUT).delete(&node_dn).await;
    }
    Ok(())
}

// ── edit record ───────────────────────────────────────────────────────────────

/// "TYPE value" for a record as the page submitted it, for the audit log.
pub fn describe_record(raw_hex: &str) -> String {
    from_hex(raw_hex)
        .and_then(|raw| parse_dns_record_binary(&raw))
        .map(|(t, v, _)| format!("{} {}", t, v))
        .unwrap_or_else(|| "(unreadable record)".to_string())
}

/// The stored record after changing its value and TTL. Name and type stay.
///
/// Everything else in the header is kept as it was — rank, flags, serial and
/// the timestamp that marks a record as dynamically registered — so an edit
/// changes only what the form shows. A value submitted unchanged keeps its
/// stored bytes exactly: a TXT record made of several strings is displayed
/// joined, and rebuilding it from that text would alter it.
pub(crate) fn edited_record(old: &[u8], value: &str, ttl: u32) -> LdapResult<Vec<u8>> {
    let (rtype, old_value, _) =
        parse_dns_record_binary(old).ok_or_else(|| "This record cannot be read".to_string())?;
    if rtype == "SOA" {
        return Err("The SOA record cannot be edited here".to_string());
    }
    let old_len = u16::from_le_bytes([old[0], old[1]]) as usize;
    let payload = if value.trim() == old_value {
        old[24..std::cmp::min(24 + old_len, old.len())].to_vec()
    } else {
        build_dns_record_binary(&rtype, value.trim(), ttl)?.split_off(24)
    };

    let mut rec = old[..24].to_vec();
    rec[0..2].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    rec[12..16].copy_from_slice(&ttl.to_be_bytes());
    rec.extend(payload);
    Ok(rec)
}

/// Replace one record of a node in a single LDAP modify: the old value is
/// removed and the new one added together, or neither happens.
/// Returns false when the edit changed nothing.
pub async fn edit_dns_record(
    ldap: &mut ldap3::Ldap,
    zone_dn: &str,
    node_name: &str,
    raw_hex: &str,
    value: &str,
    ttl: u32,
) -> LdapResult<bool> {
    let old = from_hex(raw_hex).ok_or_else(|| "Invalid record data".to_string())?;
    let new = edited_record(&old, value, ttl)?;
    if new == old {
        return Ok(false);
    }
    let node_dn = format!("DC={},{}", dn_escape(node_name), zone_dn);
    let mods: Vec<Mod<Vec<u8>>> = vec![
        Mod::Delete(sv("dnsRecord"), HashSet::from([old])),
        Mod::Add(sv("dnsRecord"), HashSet::from([new])),
    ];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&node_dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(true),
        // noSuchAttribute / noSuchObject: the old value is gone.
        16 | 32 => Err("This record was changed or removed since the page loaded. \
                       Nothing was saved; check the current records and try again."
            .to_string()),
        // attributeOrValueExists: the new value is already a record here.
        20 => Err("An identical record already exists on this name. Nothing was saved."
            .to_string()),
        _ => Err(dc_refused("Failed to edit record", &res)),
    }
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

/// The value to store for an interval the form submitted in whole units.
///
/// The page shows each interval in whole days or minutes, so a value set
/// elsewhere with finer precision — a 12-hour minimum age, a 90-second lockout
/// — is displayed rounded down. Writing the displayed number back would quietly
/// change a setting nobody touched, so a field whose submitted value still
/// matches what was displayed keeps its stored value exactly. `zero_means` is
/// what 0 stores when the field was changed to it: "never" for most intervals,
/// but a literal 0 for the minimum password age.
fn resolve_interval(submitted: i64, current_raw: i64, seconds_per_unit: i64, zero_means: i64) -> i64 {
    if submitted == interval_to_units(current_raw, seconds_per_unit) {
        return current_raw;
    }
    if submitted <= 0 {
        return zero_means;
    }
    units_to_interval(submitted, seconds_per_unit)
}

pub async fn get_password_policy(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
) -> LdapResult<PasswordPolicy> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
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
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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
    // 0 minutes stores "never" for the attempt window too, which would mean a
    // failed attempt is never forgotten: with lockout on, an account would lock
    // after its threshold of typos spread over any length of time.
    if p.lockout_threshold > 0 && p.observation_minutes == 0 {
        return Err(
            "With lockout enabled, the attempt window must be at least 1 minute".to_string(),
        );
    }
    // The directory requires the window to be no longer than the lockout
    // duration, and a "never" window is longer than any finite duration.
    if p.lockout_minutes > 0 && p.observation_minutes == 0 {
        return Err(
            "Set an attempt window no longer than the lockout duration".to_string(),
        );
    }
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

    // The current raw values: pwdProperties carries other flags, so only the
    // complexity bit is flipped, and each interval is kept exactly as stored
    // unless its field was changed (see resolve_interval).
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Base,
            "(objectClass=*)",
            vec![
                "pwdProperties",
                "maxPwdAge",
                "minPwdAge",
                "lockoutDuration",
                "lockOutObservationWindow",
            ],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let current = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| "Could not read the domain object".to_string())?;
    let raw = |k: &str| attr(&current, k).parse::<i64>().unwrap_or(0);
    let raw_props = raw("pwdProperties");
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
            set(resolve_interval(p.max_age_days, raw("maxPwdAge"), 86_400, i64::MIN).to_string()),
        ),
        Mod::Replace(
            sv("minPwdAge"),
            set(resolve_interval(p.min_age_days, raw("minPwdAge"), 86_400, 0).to_string()),
        ),
        Mod::Replace(sv("lockoutThreshold"), set(p.lockout_threshold.to_string())),
        Mod::Replace(
            sv("lockoutDuration"),
            set(resolve_interval(p.lockout_minutes, raw("lockoutDuration"), 60, i64::MIN).to_string()),
        ),
        Mod::Replace(
            sv("lockOutObservationWindow"),
            set(
                resolve_interval(p.observation_minutes, raw("lockOutObservationWindow"), 60, i64::MIN)
                    .to_string(),
            ),
        ),
        Mod::Replace(
            sv("ms-DS-MachineAccountQuota"),
            set(p.machine_account_quota.to_string()),
        ),
    ];

    ldap.with_timeout(OP_TIMEOUT).modify(base_dn, mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to update the password policy"))?;
    Ok(())
}

// ── fine-grained password policies (PSOs) ─────────────────────────────────────
//
// What `samba-tool domain passwordsettings pso` manages: msDS-PasswordSettings
// objects in the Password Settings Container, each with the same settings as
// the domain policy, a precedence, and the users and groups it applies to.
// When several apply to a user, the lowest precedence number wins; a policy
// on the user directly beats one through a group.

const PSO_CONTAINER: &str = "CN=Password Settings Container,CN=System";

/// PSOs need domain functional level 2008 (3) or higher.
pub const PSO_MIN_DOMAIN_LEVEL: i64 = 3;

#[derive(Debug, Serialize, Clone)]
pub struct PsoTarget {
    pub dn: String,
    pub name: String,
    /// user, group, or other (an object EasyDC could not read).
    pub kind: &'static str,
}

#[derive(Debug, Serialize, Clone)]
pub struct Pso {
    pub dn: String,
    pub name: String,
    pub description: String,
    pub precedence: i64,
    pub policy: PasswordPolicy,
    pub applies_to: Vec<PsoTarget>,
}

pub struct PsoSettings<'a> {
    pub name: &'a str,
    pub description: &'a str,
    pub precedence: i64,
    pub policy: PasswordPolicy,
}

const PSO_ATTRS: [&str; 13] = [
    "cn",
    "description",
    "msDS-PasswordSettingsPrecedence",
    "msDS-PasswordReversibleEncryptionEnabled",
    "msDS-PasswordHistoryLength",
    "msDS-PasswordComplexityEnabled",
    "msDS-MinimumPasswordLength",
    "msDS-MinimumPasswordAge",
    "msDS-MaximumPasswordAge",
    "msDS-LockoutThreshold",
    "msDS-LockoutObservationWindow",
    "msDS-LockoutDuration",
    "msDS-PSOAppliesTo",
];

/// The domain functional level from the rootDSE: 2 = 2003, 3 = 2008,
/// 4 = 2008 R2, and so on.
pub async fn domain_level(ldap: &mut ldap3::Ldap) -> LdapResult<i64> {
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search("", Scope::Base, "(objectClass=*)", vec!["domainFunctionality"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .and_then(|e| attr(&e, "domainFunctionality").parse().ok())
        .ok_or_else(|| "Could not read the domain functional level".to_string())
}

fn pso_from_entry(e: &SearchEntry) -> Pso {
    let num = |k: &str| attr(e, k).parse::<i64>().unwrap_or(0);
    Pso {
        dn: e.dn.clone(),
        name: attr(e, "cn"),
        description: attr(e, "description"),
        precedence: num("msDS-PasswordSettingsPrecedence"),
        policy: PasswordPolicy {
            min_length: num("msDS-MinimumPasswordLength"),
            complexity: attr(e, "msDS-PasswordComplexityEnabled").eq_ignore_ascii_case("TRUE"),
            history: num("msDS-PasswordHistoryLength"),
            max_age_days: interval_to_units(num("msDS-MaximumPasswordAge"), 86_400),
            min_age_days: interval_to_units(num("msDS-MinimumPasswordAge"), 86_400),
            lockout_threshold: num("msDS-LockoutThreshold"),
            lockout_minutes: interval_to_units(num("msDS-LockoutDuration"), 60),
            observation_minutes: interval_to_units(num("msDS-LockoutObservationWindow"), 60),
            machine_account_quota: 0,
        },
        applies_to: e
            .attrs
            .get("msDS-PSOAppliesTo")
            .map(|v| {
                v.iter()
                    .map(|dn| PsoTarget { dn: dn.clone(), name: first_rdn_value(dn), kind: "other" })
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// Every PSO, lowest precedence (the strongest) first, with the users and
/// groups each applies to named.
pub async fn list_psos(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<Pso>> {
    let container = format!("{PSO_CONTAINER},{base_dn}");
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(&container, Scope::OneLevel, "(objectClass=msDS-PasswordSettings)", PSO_ATTRS.to_vec())
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut psos: Vec<Pso> = entries.into_iter().map(|e| pso_from_entry(&SearchEntry::construct(e))).collect();

    for pso in &mut psos {
        for t in &mut pso.applies_to {
            let found = ldap
                .with_timeout(OP_TIMEOUT)
                .search(&t.dn, Scope::Base, "(objectClass=*)", vec!["sAMAccountName", "objectClass"])
                .await
                .ok()
                .and_then(|r| r.success().ok())
                .and_then(|(es, _)| es.into_iter().next())
                .map(SearchEntry::construct);
            if let Some(e) = found {
                let is_group = e
                    .attrs
                    .get("objectClass")
                    .is_some_and(|v| v.iter().any(|c| c.eq_ignore_ascii_case("group")));
                t.kind = if is_group { "group" } else { "user" };
                let sam = attr(&e, "sAMAccountName");
                if !sam.is_empty() {
                    t.name = sam;
                }
            }
        }
        pso.applies_to.sort_by_key(|t| (t.kind != "group", t.name.to_lowercase()));
    }
    psos.sort_by_key(|p| (p.precedence, p.name.to_lowercase()));
    Ok(psos)
}

pub(crate) fn validate_pso(s: &PsoSettings<'_>) -> LdapResult<()> {
    if s.name.is_empty() {
        return Err("A policy needs a name".to_string());
    }
    if s.name.chars().count() > 64 {
        return Err("A policy name can be at most 64 characters".to_string());
    }
    if s.name.chars().any(char::is_control) {
        return Err("The policy name contains a control character".to_string());
    }
    if s.precedence < 1 || s.precedence > i32::MAX as i64 {
        return Err("Precedence must be 1 or higher (1 wins over every other policy)".to_string());
    }
    validate_password_policy(&s.policy)
}

/// The settings as attribute values. `current` is the stored object when
/// editing, so an interval the form could not show exactly (12 hours, say)
/// is kept as stored unless its field was changed — the same rule as the
/// domain policy.
fn pso_values(s: &PsoSettings<'_>, current: Option<&SearchEntry>) -> Vec<(&'static str, String)> {
    let raw = |k: &str| current.map(|e| attr(e, k).parse::<i64>().unwrap_or(0));
    let interval = |field: i64, attr: &str, unit: i64, zero_means: i64| match raw(attr) {
        Some(stored) => resolve_interval(field, stored, unit, zero_means),
        None if field <= 0 => zero_means,
        None => units_to_interval(field, unit),
    };
    let p = &s.policy;
    let tf = |b: bool| if b { "TRUE" } else { "FALSE" }.to_string();
    vec![
        ("msDS-PasswordSettingsPrecedence", s.precedence.to_string()),
        ("msDS-PasswordHistoryLength", p.history.to_string()),
        ("msDS-PasswordComplexityEnabled", tf(p.complexity)),
        ("msDS-MinimumPasswordLength", p.min_length.to_string()),
        ("msDS-MinimumPasswordAge", interval(p.min_age_days, "msDS-MinimumPasswordAge", 86_400, 0).to_string()),
        ("msDS-MaximumPasswordAge", interval(p.max_age_days, "msDS-MaximumPasswordAge", 86_400, i64::MIN).to_string()),
        ("msDS-LockoutThreshold", p.lockout_threshold.to_string()),
        ("msDS-LockoutDuration", interval(p.lockout_minutes, "msDS-LockoutDuration", 60, i64::MIN).to_string()),
        (
            "msDS-LockoutObservationWindow",
            interval(p.observation_minutes, "msDS-LockoutObservationWindow", 60, i64::MIN).to_string(),
        ),
    ]
}

async fn find_pso(ldap: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<SearchEntry> {
    let container = format!("{PSO_CONTAINER},{base_dn}");
    let filter = format!("(&(objectClass=msDS-PasswordSettings)(cn={}))", ldap_escape(name));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(&container, Scope::OneLevel, &filter, PSO_ATTRS.to_vec())
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("Password policy '{}' not found", name))
}

pub async fn create_pso(ldap: &mut ldap3::Ldap, base_dn: &str, s: &PsoSettings<'_>) -> LdapResult<()> {
    validate_pso(s)?;
    let dn = format!("CN={},{PSO_CONTAINER},{base_dn}", dn_escape(s.name));
    let mut attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("msDS-PasswordSettings")])),
        (sv("cn"), HashSet::from([sv(s.name)])),
        // Required by the schema; storing passwords reversibly is never wanted.
        (sv("msDS-PasswordReversibleEncryptionEnabled"), HashSet::from([sv("FALSE")])),
    ];
    for (name, value) in pso_values(s, None) {
        attrs.push((sv(name), HashSet::from([sv(&value)])));
    }
    if !s.description.is_empty() {
        attrs.push((sv("description"), HashSet::from([sv(s.description)])));
    }
    let res = ldap.with_timeout(OP_TIMEOUT).add(&dn, attrs).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        68 => Err(format!("A password policy named '{}' already exists", s.name)),
        _ => Err(dc_refused("Failed to create password policy", &res)),
    }
}

pub async fn update_pso(
    ldap: &mut ldap3::Ldap,
    base_dn: &str,
    name: &str,
    s: &PsoSettings<'_>,
) -> LdapResult<()> {
    validate_pso(s)?;
    let current = find_pso(ldap, base_dn, name).await?;
    let mut mods: Vec<Mod<Vec<u8>>> = pso_values(s, Some(&current))
        .into_iter()
        .map(|(attr, value)| Mod::Replace(sv(attr), HashSet::from([sv(&value)])))
        .collect();
    mods.push(set_or_clear("description", s.description));
    ldap.with_timeout(OP_TIMEOUT).modify(&current.dn, mods)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to update password policy"))?;
    Ok(())
}

pub async fn delete_pso(ldap: &mut ldap3::Ldap, base_dn: &str, name: &str) -> LdapResult<()> {
    let current = find_pso(ldap, base_dn, name).await?;
    ldap.with_timeout(OP_TIMEOUT).delete(&current.dn)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to delete password policy"))?;
    Ok(())
}

/// Whether a policy may be applied to this object. Windows applies PSOs to
/// users and to global security groups only; applied to anything else it is
/// silently ignored, which is worse than a refusal.
pub(crate) fn check_pso_target(name: &str, classes: &[String], group_type: i64) -> LdapResult<()> {
    let has = |c: &str| classes.iter().any(|x| x.eq_ignore_ascii_case(c));
    if has("computer") {
        return Err(format!("{name} is a computer; password policies apply to users and groups"));
    }
    if has("group") {
        if GroupScope::of(group_type) != Some(GroupScope::Global) || !is_security(group_type) {
            return Err(format!(
                "{name} is a {} group. Windows applies password policies only through global security groups.",
                group_type_label(group_type).to_lowercase()
            ));
        }
        return Ok(());
    }
    if has("user") {
        return Ok(());
    }
    Err(format!("{name} is not a user or a group"))
}

pub async fn apply_pso(ldap: &mut ldap3::Ldap, base_dn: &str, pso_name: &str, target: &str) -> LdapResult<()> {
    let pso = find_pso(ldap, base_dn, pso_name).await?;
    let filter = format!("(&(|(objectClass=user)(objectClass=group))(sAMAccountName={}))", ldap_escape(target));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["objectClass", "groupType"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("No user or group is named '{}'", target))?;
    let classes = e.attrs.get("objectClass").cloned().unwrap_or_default();
    check_pso_target(target, &classes, attr(&e, "groupType").parse().unwrap_or(0))?;

    let mods = vec![Mod::Add(sv("msDS-PSOAppliesTo"), HashSet::from([sv(&e.dn)]))];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&pso.dn, mods).await.map_err(ldap_err)?;
    match res.rc {
        0 => Ok(()),
        20 => Err(format!("{} already applies to {}", pso_name, target)),
        _ => Err(dc_refused("Failed to apply password policy", &res)),
    }
}

pub async fn unapply_pso(ldap: &mut ldap3::Ldap, base_dn: &str, pso_name: &str, target_dn: &str) -> LdapResult<()> {
    let pso = find_pso(ldap, base_dn, pso_name).await?;
    let mods = vec![Mod::Delete(sv("msDS-PSOAppliesTo"), HashSet::from([sv(target_dn)]))];
    let res = ldap.with_timeout(OP_TIMEOUT).modify(&pso.dn, mods).await.map_err(ldap_err)?;
    if res.rc == 0 {
        return Ok(());
    }
    Err(if not_a_member(res.rc, &res.text) {
        format!("{} does not apply to {}", pso_name, first_rdn_value(target_dn))
    } else {
        dc_refused("Failed to remove", &res)
    })
}

/// Users and global security groups, for the "Apply to" box's suggestions.
pub async fn pso_candidates(ldap: &mut ldap3::Ldap, base_dn: &str) -> LdapResult<Vec<String>> {
    let filter = format!(
        "(|(&(objectCategory=person)(objectClass=user))(&(objectClass=group)(groupType={})))",
        group_type_value(GroupScope::Global, true)
    );
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["sAMAccountName"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let mut names: Vec<String> = entries
        .into_iter()
        .map(|e| attr(&SearchEntry::construct(e), "sAMAccountName"))
        .filter(|n| !n.is_empty())
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    Ok(names)
}

/// Which policy governs a user: the name of the PSO the DC computes for it
/// (msDS-ResultantPSO), or None when the domain policy does.
pub async fn resultant_pso(ldap: &mut ldap3::Ldap, base_dn: &str, username: &str) -> LdapResult<Option<String>> {
    let filter = format!("(&(objectCategory=person)(objectClass=user)(sAMAccountName={}))", ldap_escape(username));
    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(base_dn, Scope::Subtree, &filter, vec!["msDS-ResultantPSO"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
    let e = entries
        .into_iter()
        .next()
        .map(SearchEntry::construct)
        .ok_or_else(|| format!("User '{}' not found", username))?;
    let dn = attr(&e, "msDS-ResultantPSO");
    Ok((!dn.is_empty()).then(|| first_rdn_value(&dn)))
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
            .with_timeout(OP_TIMEOUT)
            .search(base, Scope::Base, "(objectClass=*)", vec!["dn"])
            .await
            .map(|r| r.success())
            && !entries.is_empty()
        {
            return Ok(base.clone());
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
        .with_timeout(OP_TIMEOUT)
        .search(
            base_dn,
            Scope::Subtree,
            "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))",
            vec!["dNSHostName"],
        )
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

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
        .with_timeout(OP_TIMEOUT)
        .search("", Scope::Base, "(objectClass=*)", vec!["dnsHostName"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;
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

    let zone_dn = format!("DC={},{}", dn_escape(zone), partition);
    let props: HashSet<Vec<u8>> = primary_zone_properties().into_iter().collect();
    let zone_attrs: Vec<(Vec<u8>, HashSet<Vec<u8>>)> = vec![
        (sv("objectClass"), HashSet::from([sv("top"), sv("dnsZone")])),
        (sv("dc"), HashSet::from([sv(zone)])),
        (sv("dNSProperty"), props),
    ];
    ldap.with_timeout(OP_TIMEOUT).add(&zone_dn, zone_attrs)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to create zone"))?;

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
        .with_timeout(OP_TIMEOUT)
        .add(&node_dn, node_attrs)
        .await
        .map_err(ldap_err)
        .and_then(|r| r.success().map_err(ldap_err))
    {
        let _ = ldap.with_timeout(OP_TIMEOUT).delete(&zone_dn).await;
        return Err(format!("Failed to create the zone's apex records: {}", e));
    }

    Ok(())
}

/// Zones that must never be deleted from EasyDC. The realm's own zone holds
/// the SRV records every domain member uses to find a DC; the others are
/// Samba's internal zones.
pub fn refuse_protected_zone(zone: &str, base_dn: &str) -> LdapResult<()> {
    let lower = zone.to_lowercase();
    if lower == base_dn_to_domain(base_dn).to_lowercase() {
        return Err(format!(
            "'{}' is the domain's own zone and cannot be deleted from EasyDC",
            zone
        ));
    }
    if lower.starts_with("_msdcs.") || lower == "rootdnsservers" {
        return Err(format!("'{}' is an internal zone and cannot be deleted", zone));
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
    // Only a well-formed name can reach the lookup, so nothing here depends on
    // the filter escaping alone.
    validate_zone_name(zone)?;
    refuse_protected_zone(zone, base_dn)?;

    let zone_dn = find_zone_dn(ldap, base_dn, zone).await?;

    // Check the zone that was actually found, not just the name that was
    // asked for: this is the object about to be deleted.
    let resolved = zone_dn
        .split(',')
        .next()
        .and_then(|rdn| rdn.split_once('='))
        .map(|(_, v)| v.to_string())
        .unwrap_or_default();
    refuse_protected_zone(&resolved, base_dn)?;
    if !resolved.eq_ignore_ascii_case(zone) {
        return Err(format!(
            "Asked to delete '{}' but the directory returned '{}'; nothing was deleted",
            zone, resolved
        ));
    }

    let (entries, _) = ldap
        .with_timeout(OP_TIMEOUT)
        .search(&zone_dn, Scope::OneLevel, "(objectClass=*)", vec!["dc"])
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(ldap_err)?;

    let mut removed = 0usize;
    for e in entries {
        let dn = SearchEntry::construct(e).dn;
        ldap.with_timeout(OP_TIMEOUT).delete(&dn)
            .await
            .map_err(ldap_err)?
            .success()
            .map_err(dc_failed(&format!("Failed to delete {}", first_rdn_value(&dn))))?;
        removed += 1;
    }

    ldap.with_timeout(OP_TIMEOUT).delete(&zone_dn)
        .await
        .map_err(ldap_err)?
        .success()
        .map_err(dc_failed("Failed to delete zone"))?;

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

#[cfg(test)]
mod review_fix_tests {
    use super::*;

    #[test]
    fn filter_metacharacters_are_escaped() {
        assert_eq!(ldap_escape("*"), "\\2a");
        assert_eq!(ldap_escape("h*"), "h\\2a");
        assert_eq!(ldap_escape("a(b)c"), "a\\28b\\29c");
        assert_eq!(ldap_escape("back\\slash"), "back\\5cslash");
        assert_eq!(ldap_escape("plain.name-01"), "plain.name-01");
    }

    #[test]
    fn dn_special_characters_are_escaped() {
        assert_eq!(dn_escape("Doe, John"), "Doe\\, John");
        assert_eq!(dn_escape("Sales + Marketing"), "Sales \\+ Marketing");
        assert_eq!(dn_escape(r#"a"b\c<d>e;f=g"#), r#"a\"b\\c\<d\>e\;f\=g"#);
        assert_eq!(dn_escape("#1"), "\\#1");
        assert_eq!(dn_escape("a#1"), "a#1");
        assert_eq!(dn_escape(" pad "), "\\ pad\\ ");
        assert_eq!(dn_escape("in side"), "in side");
        assert_eq!(dn_escape("nul\0"), "nul\\00");
        assert_eq!(dn_escape("Müller é"), "Müller é");
        assert_eq!(dn_escape("_ldap._tcp"), "_ldap._tcp");
        assert_eq!(dn_escape("@"), "@");
        assert_eq!(dn_escape(""), "");
    }

    /// A name that looks like a DN must stay one part of the DN, not graft
    /// itself onto another place in the tree.
    #[test]
    fn a_name_cannot_change_where_the_object_goes() {
        let name = "x,CN=Users,DC=evil";
        let dn = format!("CN={},CN=Users,DC=example,DC=com", dn_escape(name));
        assert_eq!(dn, "CN=x\\,CN\\=Users\\,DC\\=evil,CN=Users,DC=example,DC=com");
        // Exactly one unescaped comma per parent level: four parts in all.
        let bytes = dn.as_bytes();
        let parts = (0..bytes.len())
            .filter(|&i| bytes[i] == b',' && (i == 0 || bytes[i - 1] != b'\\'))
            .count()
            + 1;
        assert_eq!(parts, 4);
    }

    /// The bypass the review found: "*" passed a guard that compared strings,
    /// then matched the realm zone as a wildcard. It must now fail validation
    /// before any lookup.
    #[test]
    fn wildcard_zone_names_are_rejected_before_lookup() {
        assert!(validate_zone_name("*").is_err());
        assert!(validate_zone_name("h*").is_err());
        assert!(validate_zone_name("hakim.*").is_err());
    }

    #[test]
    fn the_realm_and_internal_zones_are_protected() {
        let base = "DC=hakim,DC=family";
        assert!(refuse_protected_zone("hakim.family", base).is_err());
        assert!(refuse_protected_zone("HAKIM.FAMILY", base).is_err());
        assert!(refuse_protected_zone("_msdcs.hakim.family", base).is_err());
        assert!(refuse_protected_zone("RootDNSServers", base).is_err());
        assert!(refuse_protected_zone("10.168.192.in-addr.arpa", base).is_ok());
    }

    #[test]
    fn an_untouched_interval_keeps_its_stored_value() {
        // 12 hours, shown as 0 days. Submitting the 0 that was displayed must
        // not rewrite it.
        let twelve_hours = -(12 * 3600 * 10_000_000i64);
        assert_eq!(resolve_interval(0, twelve_hours, 86_400, 0), twelve_hours);
        // 90 seconds, shown as 1 minute.
        let ninety_seconds = -(90 * 10_000_000i64);
        assert_eq!(resolve_interval(1, ninety_seconds, 60, i64::MIN), ninety_seconds);
        // "Never", shown as 0, stays "never".
        assert_eq!(resolve_interval(0, i64::MIN, 86_400, i64::MIN), i64::MIN);
    }

    #[test]
    fn a_changed_interval_is_written() {
        assert_eq!(resolve_interval(42, i64::MIN, 86_400, i64::MIN), -36_288_000_000_000);
        // Changed to 0: "never" for most fields, a literal 0 for minimum age.
        assert_eq!(resolve_interval(0, -36_288_000_000_000, 86_400, i64::MIN), i64::MIN);
        assert_eq!(resolve_interval(0, -864_000_000_000, 86_400, 0), 0);
    }

    fn policy(threshold: i64, duration: i64, window: i64) -> PasswordPolicy {
        PasswordPolicy {
            min_length: 8,
            complexity: true,
            history: 24,
            max_age_days: 42,
            min_age_days: 1,
            lockout_threshold: threshold,
            lockout_minutes: duration,
            observation_minutes: window,
            machine_account_quota: 0,
        }
    }

    /// The case the review found: lockout on, window 0. That used to store an
    /// infinite window, so failed attempts were never forgotten.
    #[test]
    fn a_zero_attempt_window_is_refused_when_lockout_is_on() {
        assert!(validate_password_policy(&policy(5, 30, 0)).is_err());
        assert!(validate_password_policy(&policy(5, 0, 0)).is_err());
    }

    #[test]
    fn a_zero_window_beside_a_finite_duration_is_refused() {
        // Lockout off, but the directory still requires window <= duration.
        assert!(validate_password_policy(&policy(0, 30, 0)).is_err());
    }

    #[test]
    fn valid_window_combinations_pass() {
        assert!(validate_password_policy(&policy(5, 30, 30)).is_ok());
        assert!(validate_password_policy(&policy(5, 0, 30)).is_ok()); // until an admin unlocks
        assert!(validate_password_policy(&policy(0, 0, 0)).is_ok()); // lockout off entirely
    }
}

#[cfg(test)]
mod account_toggle_tests {
    use super::with_account_disabled;

    #[test]
    fn plain_accounts_toggle_as_before() {
        assert_eq!(with_account_disabled(512, true), 514);
        assert_eq!(with_account_disabled(514, false), 512);
        assert_eq!(with_account_disabled(4096, true), 4098);
        assert_eq!(with_account_disabled(4098, false), 4096);
    }

    /// Administrator on the test domain: NORMAL_ACCOUNT + DONT_EXPIRE_PASSWORD.
    /// The old code would have written 514, dropping "password never expires".
    #[test]
    fn other_user_flags_survive() {
        assert_eq!(with_account_disabled(66048, true), 66050);
        assert_eq!(with_account_disabled(66050, false), 66048);
    }

    /// A domain controller: SERVER_TRUST_ACCOUNT + TRUSTED_FOR_DELEGATION. The
    /// old code wrote 4098 — a disabled workstation account.
    #[test]
    fn a_domain_controller_stays_a_domain_controller() {
        let dc = 0x2000 | 0x80000;
        assert_eq!(with_account_disabled(dc, true), dc | 0x2);
        assert_eq!(with_account_disabled(dc | 0x2, false), dc);
    }

    #[test]
    fn toggling_is_idempotent() {
        assert_eq!(with_account_disabled(514, true), 514);
        assert_eq!(with_account_disabled(512, false), 512);
    }

    #[test]
    fn password_settings_that_cannot_go_together() {
        let want = |must_change, cannot_change, never_expires| super::PasswordSettingsChange { must_change, cannot_change, never_expires };
        assert!(super::conflicting(&want(true, true, false)).unwrap().contains("cannot change their password"));
        assert!(super::conflicting(&want(true, false, true)).unwrap().contains("never expires"));
        assert_eq!(super::conflicting(&want(true, false, false)), None);
        assert_eq!(super::conflicting(&want(false, true, true)), None);
    }

    #[test]
    fn a_password_time_reads_plainly() {
        // 2026-11-22 10:15:30 UTC
        let ft = super::unix_to_filetime(1_795_342_530);
        assert_eq!(super::filetime_text(ft), "2026-11-22 10:15 UTC");
    }

    #[test]
    fn a_binary_sid_reads_as_text() {
        // S-1-5-21-1004336348-1177238915-682003330-513 (Domain Users).
        let mut b = vec![1u8, 5, 0, 0, 0, 0, 0, 5];
        for sub in [21u32, 1004336348, 1177238915, 682003330, 513] {
            b.extend(sub.to_le_bytes());
        }
        assert_eq!(super::sid_string(&b).as_deref(), Some("S-1-5-21-1004336348-1177238915-682003330-513"));
        assert_eq!(super::sid_string(&b[..10]), None, "cut short");
        assert_eq!(super::sid_string(&[]), None);
    }

    /// EasyDC does not disable, move or delete a DC's own account.
    #[test]
    fn a_domain_controller_is_refused_changes() {
        let entry = |uac| super::ComputerEntry { dn: "CN=DC1,OU=Domain Controllers,DC=x".into(), name: "DC1".into(), uac };
        let e = entry(0x2000 | 0x80000).refuse_dc("disable").unwrap_err();
        assert_eq!(e, "DC1 is a domain controller, so EasyDC does not disable it: that would stop it working as one.");
        assert!(entry(4096).refuse_dc("move").is_ok(), "a workstation may be moved");
        assert!(entry(0x2000).refuse_dc("delete").unwrap_err().contains("demote it first"));
    }
}

#[cfg(test)]
mod dns_record_tests {
    use super::*;

    /// `_ldap._tcp` -> dc1 as Samba stored it on a live DC (serial 110, TTL 900).
    const DC1_LDAP_SRV: &str = "1a00210005f000006e0000000000038400000000000000000000006401851203036463310568616b696d0666616d696c7900";

    fn hex(s: &str) -> Vec<u8> {
        from_hex(s).unwrap()
    }

    #[test]
    fn srv_is_encoded_exactly_as_samba_stores_it() {
        let samba = hex(DC1_LDAP_SRV);
        let ours = build_dns_record_binary("SRV", "0 100 389 dc1.hakim.family", 900).unwrap();
        // Same length, type, TTL and data; ours has serial 0, like every add.
        assert_eq!(ours[0..4], samba[0..4]);
        assert_eq!(ours[12..16], samba[12..16]);
        assert_eq!(ours[24..], samba[24..]);
        assert_eq!(
            parse_dns_record_binary(&ours).unwrap(),
            ("SRV".to_string(), "0 100 389 dc1.hakim.family".to_string(), 900)
        );
    }

    #[test]
    fn samba_srv_records_display_correctly() {
        let (_, value, ttl) = parse_dns_record_binary(&hex(DC1_LDAP_SRV)).unwrap();
        assert_eq!((value.as_str(), ttl), ("0 100 389 dc1.hakim.family", 900));
    }

    /// dnsp.idl marks MX like SRV: priority 10 is stored 00 0a, or Samba
    /// serves it as 2560.
    #[test]
    fn mx_priority_is_big_endian() {
        let rec = build_dns_record_binary("MX", "10 mail.example.com", 3600).unwrap();
        assert_eq!(rec[24..26], [0x00, 0x0a]);
        assert_eq!(parse_dns_record_binary(&rec).unwrap().1, "10 mail.example.com");
    }

    #[test]
    fn srv_input_is_checked() {
        for bad in ["", "0 100 389", "0 100 70000 dc1", "a b c d", "0 100 389 dc1 extra"] {
            assert!(build_dns_record_binary("SRV", bad, 900).is_err(), "{bad:?}");
        }
        // Extra spaces are fine.
        assert!(build_dns_record_binary("SRV", " 10  5 5060   sip.example.com ", 900).is_ok());
    }

    #[test]
    fn hostnames_are_checked_for_every_name_type() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        for (t, v) in [
            ("CNAME", "a..example.com"),
            ("NS", long_label.as_str()),
            ("PTR", "host name.example.com"),
            ("MX", "10 a..b"),
            ("SRV", "0 0 80 a..b"),
        ] {
            assert!(build_dns_record_binary(t, v, 300).is_err(), "{t} {v}");
        }
        let longest_label = format!("{}.example.com.", "a".repeat(63));
        assert!(build_dns_record_binary("CNAME", &longest_label, 300).is_ok());
        assert!(build_dns_record_binary("SRV", "0 0 0 .", 300).is_ok()); // "no service"
    }

    #[test]
    fn long_txt_is_split_into_255_byte_strings() {
        let long = "k".repeat(600);
        let rec = build_dns_record_binary("TXT", &long, 300).unwrap();
        let data = &rec[24..];
        assert_eq!(data.len(), 600 + 3);
        assert_eq!((data[0], data[256], data[512]), (255, 255, 90));
        assert_eq!(u16::from_le_bytes([rec[0], rec[1]]) as usize, data.len());
        assert!(build_dns_record_binary("TXT", &"k".repeat(4001), 300).is_err());
    }

    #[test]
    fn an_edit_keeps_the_header_and_changes_value_and_ttl() {
        let old = hex(DC1_LDAP_SRV);
        let new = edited_record(&old, "5 50 636 dc1.hakim.family", 3600).unwrap();
        // version, rank, flags, serial and timestamp are untouched.
        assert_eq!(new[2..12], old[2..12]);
        assert_eq!(new[16..24], old[16..24]);
        assert_eq!(
            parse_dns_record_binary(&new).unwrap(),
            ("SRV".to_string(), "5 50 636 dc1.hakim.family".to_string(), 3600)
        );
    }

    #[test]
    fn a_dynamic_record_stays_dynamic() {
        let mut old = build_dns_record_binary("A", "10.0.0.5", 1200).unwrap();
        old[20..24].copy_from_slice(&3_700_000u32.to_le_bytes()); // dwTimeStamp
        let new = edited_record(&old, "10.0.0.6", 1200).unwrap();
        assert_eq!(new[20..24], old[20..24]);
        assert_eq!(parse_dns_record_binary(&new).unwrap().1, "10.0.0.6");
    }

    #[test]
    fn an_unchanged_value_keeps_its_bytes() {
        // Three strings, displayed as "v=spf1 a ~all": a TTL-only edit must not
        // rebuild them as one string.
        let mut old = build_dns_record_binary("TXT", "x", 300).unwrap();
        old.truncate(24);
        let data = b"\x06v=spf1\x01a\x04~all";
        old.extend_from_slice(data);
        old[0..2].copy_from_slice(&(data.len() as u16).to_le_bytes());
        let shown = parse_dns_record_binary(&old).unwrap().1;
        assert_eq!(shown, "v=spf1 a ~all");

        let same = edited_record(&old, &shown, 300).unwrap();
        assert_eq!(same, old);
        let ttl_only = edited_record(&old, &shown, 60).unwrap();
        assert_eq!(ttl_only[24..], old[24..]);
        assert_eq!(parse_dns_record_binary(&ttl_only).unwrap().2, 60);
    }

    #[test]
    fn soa_and_bad_values_are_refused() {
        let soa = build_soa_record("dc1.example.com", "hostmaster.example.com", 1, 3600);
        assert!(edited_record(&soa, "anything", 3600).is_err());
        let a = build_dns_record_binary("A", "10.0.0.5", 1200).unwrap();
        assert!(edited_record(&a, "not-an-ip", 1200).is_err());
        assert!(edited_record(&a[..10], "10.0.0.6", 1200).is_err());
    }

    #[test]
    fn unknown_types_can_still_change_ttl() {
        let rec = wrap_dns_record(99, 0, 300, vec![1, 2, 3]);
        let shown = parse_dns_record_binary(&rec).unwrap().1;
        let new = edited_record(&rec, &shown, 900).unwrap();
        assert_eq!(new[24..], [1, 2, 3]);
        assert!(edited_record(&rec, "010204", 900).is_err());
    }
}

#[cfg(test)]
mod user_profile_tests {
    use super::*;

    #[test]
    fn expiry_is_the_end_of_the_chosen_day() {
        // 2027-01-01T00:00:00Z: the account works through all of 2026-12-31.
        let ft = expiry_filetime("2026-12-31").unwrap().unwrap();
        assert_eq!(ft, unix_to_filetime(1_798_761_600));
        assert_eq!(expiry_date(ft).as_deref(), Some("2026-12-31"));
    }

    #[test]
    fn expiry_round_trips_across_awkward_days() {
        for d in ["1970-01-01", "2024-02-29", "2026-03-01", "2026-12-31", "9999-12-30"] {
            let ft = expiry_filetime(d).unwrap().unwrap();
            assert_eq!(expiry_date(ft).as_deref(), Some(d), "{d}");
        }
    }

    #[test]
    fn never_expires_in_both_spellings() {
        assert_eq!(expiry_filetime("").unwrap(), None);
        assert_eq!(expiry_date(0), None);
        assert_eq!(expiry_date(NEVER_EXPIRES), None);
    }

    /// samba-tool user setexpiry --days writes a time of day, not midnight:
    /// it shows as the day that moment falls on.
    #[test]
    fn a_time_of_day_shows_as_its_day() {
        // 2026-11-20T14:30:00Z
        let ft = unix_to_filetime(1_795_185_000);
        assert_eq!(expiry_date(ft).as_deref(), Some("2026-11-20"));
    }

    #[test]
    fn bad_dates_are_refused() {
        for d in ["2026-02-30", "2026-13-01", "2026-00-10", "26-01-01", "2026/01/01",
                  "2026-1-1", "1969-12-31", "abcd-ef-gh", "2026-01-01T00:00", "+026-01-01"] {
            assert!(expiry_filetime(d).is_err(), "{d} should be refused");
        }
    }

    #[test]
    fn profile_limits_are_windows_schema_limits() {
        let ok = UserProfile { title: &"t".repeat(128), department: &"d".repeat(64), ..Default::default() };
        assert!(ok.check().is_ok());
        let long = "d".repeat(65);
        let err = UserProfile { department: &long, ..Default::default() }.check().unwrap_err();
        assert!(err.contains("Department"), "{err}");
        // Characters, not bytes: 64 Hebrew letters fit.
        let hebrew = "ש".repeat(64);
        assert!(UserProfile { department: &hebrew, ..Default::default() }.check().is_ok());
        assert!(UserProfile { phone: "555\n1234", ..Default::default() }.check().is_err());
        assert!(UserProfile { expires: "2026-02-30", ..Default::default() }.check().is_err());
    }

    /// How Samba's reply began when a PSO refused a short password in the
    /// live test on a DC: rc=19 and "0000052D: Constraint violation".
    #[test]
    fn a_policy_refusal_is_explained() {
        let samba = "0000052D: Constraint violation";
        assert!(is_password_refusal(19, samba));
        let msg = password_error("The password was not changed", 19, samba);
        assert!(msg.starts_with("The password was not changed: the password does not meet"), "{msg}");
        assert!(msg.contains("Password Policy page"));
        assert!(!msg.contains("LDAPS"));

        let msg = password_error("x", 13, "confidentiality required");
        assert!(msg.contains("ldaps://"));
        // No access is said in words; anything else is passed on with its code.
        assert!(!is_password_refusal(19, "some other constraint"));
        assert_eq!(password_error("x", 50, " no rights "), "x: the account EasyDC signs in with is not allowed to set passwords here.");
        assert_eq!(password_error("x", 53, " unwilling "), "x: unwilling (rc=53)");
    }

    #[test]
    fn a_refused_change_is_said_in_words() {
        let res = |rc, text: &str| ldap3::LdapResult { rc, matched: String::new(), text: text.into(), refs: vec![], ctrls: vec![] };
        let no_access = res(50, "00002098: Object CN=x,DC=lab,DC=test has no write property access ");
        assert_eq!(
            dc_refused("Failed to update group", &no_access),
            "Failed to update group: the account EasyDC signs in with is not allowed to make this change."
        );
        assert!(dc_refused("Failed to delete group", &res(32, "")).contains("no longer exists"));
        assert_eq!(
            dc_refused("Failed to delete zone", &res(53, "00000000: busy")),
            "Failed to delete zone: the domain controller refused it, saying \"busy\" (LDAP code 53)."
        );
        let e = dc_failed("Failed to unlock account")(ldap3::LdapError::LdapResult { result: no_access });
        assert!(e.ends_with("is not allowed to make this change."), "{e}");
        assert_eq!(dc_failed("x")(ldap3::LdapError::FilterParsing), "x: filter parse error");
    }

    #[test]
    fn a_blank_field_clears_the_attribute() {
        match set_or_clear("mobile", "") {
            Mod::Replace(a, v) => assert!(a == b"mobile" && v.is_empty()),
            _ => panic!("expected Replace"),
        }
        match set_or_clear("mobile", "555") {
            Mod::Replace(_, v) => assert_eq!(v, HashSet::from([sv("555")])),
            _ => panic!("expected Replace"),
        }
    }
}

#[cfg(test)]
mod group_tests {
    use super::*;
    use std::collections::HashMap;

    fn entry(dn: &str, attrs: &[(&str, &[&str])]) -> SearchEntry {
        SearchEntry {
            dn: dn.to_string(),
            attrs: attrs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect::<HashMap<_, _>>(),
            bin_attrs: HashMap::new(),
        }
    }

    fn group(name: &str, scope: GroupScope, system: bool) -> LdapGroup {
        let gt = group_type_value(scope, true);
        let critical = if system { "TRUE" } else { "FALSE" };
        LdapGroup::from_entry(&entry(
            &format!("CN={name},CN=Users,DC=example,DC=com"),
            &[("sAMAccountName", &[name]), ("groupType", &[&gt.to_string()]), ("isCriticalSystemObject", &[critical])],
        ))
    }
    use GroupScope::*;

    /// The values found on a real Samba DC, and the six the Add form sends.
    #[test]
    fn group_types_decode() {
        assert_eq!(group_type_label(-2147483643), "Builtin Local Security");
        assert_eq!(group_type_label(-2147483646), "Global Security");
        assert_eq!(group_type_label(-2147483644), "Domain Local Security");
        assert_eq!(group_type_label(-2147483640), "Universal Security");
        assert_eq!(group_type_label(2), "Global Distribution");
        assert_eq!(group_type_label(4), "Domain Local Distribution");
        assert_eq!(group_type_label(8), "Universal Distribution");
        assert_eq!(group_type_label(0), "Other");
        for (scope, sec, value) in [
            (Global, true, -2147483646), (DomainLocal, true, -2147483644), (Universal, true, -2147483640),
            (Global, false, 2), (DomainLocal, false, 4), (Universal, false, 8),
        ] {
            assert_eq!(group_type_value(scope, sec), value);
            assert_eq!(GroupScope::of(value), Some(scope));
            assert!(check_new_group_type(value).is_ok());
        }
        assert_eq!(GroupScope::of(-2147483643), Some(Builtin));
    }

    #[test]
    fn made_up_group_types_are_refused() {
        for t in [-2147483643, 0, 6, 1, 16, -2147483648, 0x7fff_ffff] {
            assert!(check_new_group_type(t).is_err(), "{t}");
        }
    }

    #[test]
    fn builtin_groups_are_system_groups() {
        let e = entry("CN=Administrators,CN=Builtin,DC=example,DC=com",
            &[("sAMAccountName", &["Administrators"]), ("groupType", &["-2147483643"])]);
        let g = LdapGroup::from_entry(&e);
        assert!(g.system);
        assert_eq!(g.scope, Some(Builtin));
    }

    #[test]
    fn scope_changes_follow_ad_rules() {
        let none: [LdapGroup; 0] = [];
        let g = group("Team", Global, false);
        assert!(check_scope_change(&g, Universal, true, &none, &none).is_ok());
        assert!(check_scope_change(&g, Global, false, &none, &none).is_ok(), "security → distribution");
        let err = check_scope_change(&g, DomainLocal, true, &none, &none).unwrap_err();
        assert!(err.contains("universal first"), "{err}");

        let dl = group("Printers", DomainLocal, false);
        assert!(check_scope_change(&dl, Global, true, &none, &none).is_err());
        assert!(check_scope_change(&dl, Universal, true, &none, &none).is_ok());

        let u = group("All", Universal, false);
        assert!(check_scope_change(&u, Global, true, &none, &none).is_ok());
        assert!(check_scope_change(&u, DomainLocal, true, &none, &none).is_ok());
    }

    #[test]
    fn scope_changes_that_break_memberships_are_refused() {
        let none: [LdapGroup; 0] = [];
        // Global → universal while inside a global group.
        let g = group("Team", Global, false);
        let err = check_scope_change(&g, Universal, true, &[group("Dept", Global, false)], &none).unwrap_err();
        assert!(err.contains("member of Dept"), "{err}");
        // …fine when the parent is universal or domain local.
        assert!(check_scope_change(&g, Universal, true, &[group("U", Universal, false)], &none).is_ok());

        // Domain local → universal while holding a domain local group.
        let dl = group("Printers", DomainLocal, false);
        let err = check_scope_change(&dl, Universal, true, &none, &[group("Scanners", DomainLocal, false)]).unwrap_err();
        assert!(err.contains("Scanners"), "{err}");

        // Universal → global while holding a universal group.
        let u = group("All", Universal, false);
        assert!(check_scope_change(&u, Global, true, &none, &[group("U2", Universal, false)]).is_err());
        assert!(check_scope_change(&u, Global, true, &none, &[group("G", Global, false)]).is_ok());
        // Universal → domain local while inside a universal group.
        assert!(check_scope_change(&u, DomainLocal, true, &[group("U3", Universal, false)], &none).is_err());
    }

    #[test]
    fn system_groups_keep_their_type() {
        let none: [LdapGroup; 0] = [];
        let da = group("Domain Admins", Global, true);
        assert!(check_scope_change(&da, Universal, true, &none, &none).is_err());
        assert!(check_scope_change(&da, Global, false, &none, &none).is_err());
        assert!(check_scope_change(&da, Global, true, &none, &none).is_ok(), "no change is fine");
    }

    #[test]
    fn nesting_rules() {
        let g = group("G", Global, false);
        let u = group("U", Universal, false);
        let dl = group("DL", DomainLocal, false);
        assert!(check_nesting(&g, &group("G2", Global, false)).is_ok());
        assert!(check_nesting(&g, &u).is_err());
        assert!(check_nesting(&g, &dl).is_err());
        assert!(check_nesting(&u, &g).is_ok());
        assert!(check_nesting(&u, &u.clone()).is_err(), "itself");
        assert!(check_nesting(&u, &dl).is_err());
        assert!(check_nesting(&dl, &g).is_ok());
        assert!(check_nesting(&dl, &u).is_ok());
        assert!(check_nesting(&dl, &group("DL2", DomainLocal, false)).is_ok());
        assert!(check_nesting(&group("Administrators", Builtin, true), &group("Domain Admins", Global, true)).is_ok());
    }

    #[test]
    fn removing_a_non_member_is_recognised() {
        assert!(not_a_member(16, ""));
        assert!(not_a_member(53, "Attribute member already deleted for target GUID fc44a04b-…"));
        assert!(!not_a_member(53, "something else"));
        assert!(!not_a_member(50, "already deleted"));
    }

    #[test]
    fn account_names_are_checked_before_the_dc_sees_them() {
        assert!(check_account_name("A username", "zz-josé").is_ok());
        assert!(check_account_name("A username", "דני").is_ok());
        assert!(check_account_name("A group name", "R&D Team (EU) #1 100%").is_ok());
        assert!(check_account_name("A username", "o'brien").is_ok());
        let e = check_account_name("A username", "a/b").unwrap_err();
        assert!(e.starts_with("A username cannot contain \"/\"."), "{e}");
        assert!(e.contains("\" / \\ [ ] : ; | = , + * ? < > @"), "{e}");
        assert!(check_account_name("A group name", "q\"x").unwrap_err().contains("cannot contain \"\"\""));
        assert!(check_account_name("A username", "a@b").is_err());
        assert!(check_account_name("A username", "x.").unwrap_err().contains("full stop"));
        assert!(check_account_name("A username", " x").unwrap_err().contains("space"));
        assert!(check_account_name("A username", "").unwrap_err().contains("needed"));
        assert_eq!(sentence("the OU Sales was not deleted"), "The OU Sales was not deleted");
        assert_eq!(sentence("éclair"), "Éclair");
    }

    #[test]
    fn rdn_values_are_unescaped_for_display() {
        assert_eq!(first_rdn_value("CN=Doe\\, John,CN=Users,DC=x"), "Doe, John");
        assert_eq!(first_rdn_value("CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=x"), "S-1-5-11");
        assert_eq!(first_rdn_value("OU=a\\+b"), "a+b");
        // Samba writes some characters as hex: `;` and `=` here.
        assert_eq!(first_rdn_value("OU=zz semi\\3Beq\\3D,DC=lab,DC=test"), "zz semi;eq=");
        assert_eq!(first_rdn_value("OU=Caf\\C3\\A9,DC=x"), "Café");
        assert_eq!(first_rdn_value("OU=zz Q\\#1 \\<b\\>,DC=x"), "zz Q#1 <b>");
        assert_eq!(first_rdn_value("OU=zz a/b\\\\c,DC=x"), "zz a/b\\c");
        assert_eq!(first_rdn_value("OU=zz trailing\\ ,DC=x"), "zz trailing ");
        assert_eq!(first_rdn_value("OU=מכירות,DC=x"), "מכירות");
    }

    #[test]
    fn members_of_every_kind() {
        let user = member_from_entry(&entry("CN=yariv,CN=Users,DC=x", &[
            ("objectClass", &["top", "person", "organizationalPerson", "user"]),
            ("sAMAccountName", &["yariv"]), ("mail", &["y@x"]), ("userAccountControl", &["512"])]));
        assert_eq!((user.kind, user.detail.as_str(), user.enabled), ("user", "y@x", Some(true)));

        let pc = member_from_entry(&entry("CN=PC1,CN=Computers,DC=x", &[
            ("objectClass", &["top", "person", "organizationalPerson", "user", "computer"]),
            ("sAMAccountName", &["PC1$"]), ("userAccountControl", &["4098"])]));
        assert_eq!((pc.kind, pc.enabled), ("computer", Some(false)));

        let grp = member_from_entry(&entry("CN=Domain Admins,CN=Users,DC=x", &[
            ("objectClass", &["top", "group"]), ("sAMAccountName", &["Domain Admins"]), ("groupType", &["-2147483646"])]));
        assert_eq!((grp.kind, grp.detail.as_str(), grp.group.as_deref(), grp.enabled),
            ("group", "Global Security", Some("Domain Admins"), None));

        let fsp = member_from_entry(&entry("CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=x", &[
            ("objectClass", &["top", "foreignSecurityPrincipal"]), ("cn", &["S-1-5-11"])]));
        assert_eq!((fsp.kind, fsp.name.as_str(), fsp.detail.as_str()), ("foreign", "Authenticated Users", "S-1-5-11"));
    }
}

#[cfg(test)]
mod pso_tests {
    use super::*;
    use std::collections::HashMap;

    fn settings(policy: PasswordPolicy) -> PsoSettings<'static> {
        PsoSettings { name: "Admins", description: "", precedence: 10, policy }
    }

    fn strict() -> PasswordPolicy {
        PasswordPolicy {
            min_length: 14,
            complexity: true,
            history: 24,
            max_age_days: 90,
            min_age_days: 1,
            lockout_threshold: 5,
            lockout_minutes: 30,
            observation_minutes: 30,
            machine_account_quota: 0,
        }
    }

    fn values(v: &[(&'static str, String)]) -> HashMap<&'static str, String> {
        v.iter().cloned().collect()
    }

    #[test]
    fn new_policy_values() {
        let v = values(&pso_values(&settings(strict()), None));
        assert_eq!(v["msDS-PasswordSettingsPrecedence"], "10");
        assert_eq!(v["msDS-PasswordComplexityEnabled"], "TRUE");
        assert_eq!(v["msDS-MinimumPasswordLength"], "14");
        assert_eq!(v["msDS-MaximumPasswordAge"], (-90i64 * 86_400 * 10_000_000).to_string());
        assert_eq!(v["msDS-MinimumPasswordAge"], (-86_400i64 * 10_000_000).to_string());
        assert_eq!(v["msDS-LockoutDuration"], (-30i64 * 60 * 10_000_000).to_string());
        assert_eq!(v["msDS-LockoutObservationWindow"], (-30i64 * 60 * 10_000_000).to_string());
    }

    #[test]
    fn zero_means_never_except_for_minimum_age() {
        let p = PasswordPolicy { max_age_days: 0, min_age_days: 0, lockout_threshold: 0, lockout_minutes: 0,
            observation_minutes: 0, ..strict() };
        let v = values(&pso_values(&settings(p), None));
        assert_eq!(v["msDS-MaximumPasswordAge"], i64::MIN.to_string());
        assert_eq!(v["msDS-MinimumPasswordAge"], "0");
        assert_eq!(v["msDS-LockoutDuration"], i64::MIN.to_string());
    }

    /// A 12-hour minimum age set elsewhere shows as 0 days; saving the form
    /// unchanged must keep the 12 hours.
    #[test]
    fn edit_keeps_what_the_form_cannot_show() {
        let twelve_hours = (-12i64 * 3600 * 10_000_000).to_string();
        let current = SearchEntry {
            dn: "CN=Admins".into(),
            attrs: HashMap::from([("msDS-MinimumPasswordAge".to_string(), vec![twelve_hours.clone()])]),
            bin_attrs: HashMap::new(),
        };
        let p = PasswordPolicy { min_age_days: 0, ..strict() };
        let v = values(&pso_values(&settings(p), Some(&current)));
        assert_eq!(v["msDS-MinimumPasswordAge"], twelve_hours);
        // Changed on purpose: written.
        let p = PasswordPolicy { min_age_days: 2, ..strict() };
        let v = values(&pso_values(&settings(p), Some(&current)));
        assert_eq!(v["msDS-MinimumPasswordAge"], (-2i64 * 86_400 * 10_000_000).to_string());
    }

    #[test]
    fn stored_policy_reads_back() {
        let mut attrs = HashMap::new();
        for (k, v) in values(&pso_values(&settings(strict()), None)) {
            attrs.insert(k.to_string(), vec![v]);
        }
        attrs.insert("cn".into(), vec!["Admins".into()]);
        attrs.insert("msDS-PSOAppliesTo".into(), vec!["CN=Domain Admins,CN=Users,DC=x".into()]);
        let pso = pso_from_entry(&SearchEntry { dn: "CN=Admins,…".into(), attrs, bin_attrs: HashMap::new() });
        assert_eq!(pso.name, "Admins");
        assert_eq!(pso.precedence, 10);
        assert_eq!(pso.policy.min_length, strict().min_length);
        assert_eq!(pso.policy.max_age_days, 90);
        assert_eq!(pso.policy.lockout_minutes, 30);
        assert!(pso.policy.complexity);
        assert_eq!(pso.applies_to[0].name, "Domain Admins");
    }

    #[test]
    fn bad_policies_are_refused() {
        assert!(validate_pso(&settings(strict())).is_ok());
        assert!(validate_pso(&PsoSettings { name: "", ..settings(strict()) }).is_err());
        assert!(validate_pso(&PsoSettings { precedence: 0, ..settings(strict()) }).is_err());
        assert!(validate_pso(&PsoSettings { name: &"x".repeat(65), ..settings(strict()) }).is_err());
        // The domain policy's own rules apply too.
        let p = PasswordPolicy { observation_minutes: 60, lockout_minutes: 30, ..strict() };
        assert!(validate_pso(&settings(p)).is_err());
    }

    #[test]
    fn only_users_and_global_security_groups() {
        let c = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let user = c(&["top", "person", "organizationalPerson", "user"]);
        let computer = c(&["top", "person", "organizationalPerson", "user", "computer"]);
        let group = c(&["top", "group"]);
        assert!(check_pso_target("yariv", &user, 0).is_ok());
        assert!(check_pso_target("PC1$", &computer, 0).is_err());
        assert!(check_pso_target("Team", &group, -2147483646).is_ok());
        let err = check_pso_target("All", &group, -2147483640).unwrap_err();
        assert!(err.contains("universal security") && err.contains("global security"), "{err}");
        assert!(check_pso_target("List", &group, 2).is_err(), "global distribution");
        assert!(check_pso_target("Administrators", &group, -2147483643).is_err(), "builtin");
    }
}

#[cfg(test)]
mod user_tree_tests {
    use super::*;

    const BASE: &str = "DC=example,DC=com";

    #[test]
    fn dn_parts_respect_escaped_commas() {
        assert_eq!(
            dn_parts(r"CN=Doe\, John,OU=Sales,DC=x"),
            [r"CN=Doe\, John", "OU=Sales", "DC=x"]
        );
        assert_eq!(dn_parts(r"CN=a\\,DC=x"), [r"CN=a\\", "DC=x"], "an escaped backslash ends");
        assert_eq!(parent_dn(r"CN=Doe\, John,OU=Sales,DC=x"), "OU=Sales,DC=x");
        assert_eq!(parent_dn("DC=x"), "");
        assert!(dn_parts("").is_empty());
        assert_eq!(ou_depth(r"OU=a\,b,OU=Sales,DC=example,DC=com", BASE), 1);
    }

    #[test]
    fn is_within_compares_whole_parts() {
        assert!(is_within("OU=Europe,OU=Sales,DC=example,DC=com", "ou=sales,dc=example,dc=com"));
        assert!(is_within(BASE, BASE));
        assert!(!is_within(r"OU=a\,OU=Sales,DC=example,DC=com", "OU=Sales,DC=example,DC=com"));
        assert!(!is_within("OU=Sales,DC=other,DC=com", BASE));
    }

    #[test]
    fn the_bind_account_is_recognised_in_every_form() {
        let (dn, upn, sam) = ("CN=Administrator,CN=Users,DC=x,DC=com", "administrator@x.com", "Administrator");
        assert!(is_bind_account("cn=administrator,cn=users,dc=x,dc=com", dn, upn, sam));
        assert!(is_bind_account("Administrator@X.com", dn, upn, sam));
        assert!(is_bind_account(r"X\administrator", dn, upn, sam));
        assert!(!is_bind_account("CN=bob,CN=Users,DC=x,DC=com", dn, upn, sam));
        assert!(!is_bind_account("", dn, "", sam));
        assert!(!is_bind_account("bob@x.com", dn, "", sam), "no UPN on the account");
    }

    #[test]
    fn location_reads_top_down() {
        assert_eq!(location("OU=Europe,OU=Sales,DC=example,DC=com", BASE), "Sales › Europe");
        assert_eq!(location("CN=Users,DC=example,DC=com", BASE), "Users");
        assert_eq!(location(r"OU=Doe\, J,DC=example,DC=com", BASE), "Doe, J");
        assert_eq!(location(BASE, BASE), "");
    }

    fn u(container: &str) -> LdapUser {
        LdapUser { container: format!("{container},{BASE}"), ..Default::default() }
    }

    #[test]
    fn the_tree_keeps_ous_and_containers_with_users() {
        let found = vec![
            (format!("OU=Sales,{BASE}"), true),
            (format!("CN=Users,{BASE}"), false),
            (format!("CN=Computers,{BASE}"), false),
            (format!("OU=Empty,{BASE}"), true),
            (format!("OU=Europe,OU=Sales,{BASE}"), true),
            // A sibling whose name starts like "Sales" must not land inside it.
            (format!("OU=Sales Ops,{BASE}"), true),
            // Under an advanced-view container that the search left out.
            (format!("CN=Hidden,CN=System,{BASE}"), false),
        ];
        let users = [u("CN=Users"), u("OU=Sales"), u("OU=Europe,OU=Sales"), u("OU=Europe,OU=Sales")];
        let objects_in: Vec<&str> = users.iter().map(|u| u.container.as_str()).collect();
        let tree = container_tree(BASE, found, &objects_in, "");
        let shown: Vec<(&str, usize, usize, usize)> =
            tree.iter().map(|c| (c.name.as_str(), c.depth, c.direct, c.total)).collect();
        assert_eq!(
            shown,
            [
                ("Empty", 1, 0, 0),
                ("Sales", 1, 1, 3),
                ("Europe", 2, 2, 2),
                ("Sales Ops", 1, 0, 0),
                ("Users", 1, 1, 1),
            ]
        );
    }
}

#[cfg(test)]
mod timeout_tests {
    use super::{check_domain_password, domain_refusal, DomainSignIn, Server};
    use std::time::Duration;

    #[tokio::test]
    async fn a_timeout_says_what_it_means() {
        let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
            .await
            .unwrap_err();
        let text = super::ldap_err(ldap3::LdapError::Timeout { elapsed });
        assert!(text.contains("did not answer within 30 seconds"), "{text}");
        assert!(text.contains("may still be made"), "{text}");
        // Other errors keep ldap3's own words.
        assert_eq!(super::ldap_err(ldap3::LdapError::FilterParsing), "filter parse error");
    }

    #[test]
    fn a_failed_connection_says_what_to_check() {
        use std::io::{Error, ErrorKind};
        let wait = std::time::Duration::from_secs(10);
        let io = |kind, text: &str| ldap3::LdapError::Io { source: Error::new(kind, text.to_string()) };

        let text = super::connect_failed("ldaps://dc.lab.test", wait, io(ErrorKind::ConnectionRefused, "refused"));
        assert!(text.contains("dc.lab.test turned the connection away on port 636"), "{text}");
        assert!(text.contains("systemctl status samba-ad-dc"), "{text}");
        let text = super::connect_failed("ldap://dc.lab.test:3890/", wait, io(ErrorKind::ConnectionRefused, "refused"));
        assert!(text.contains("on port 3890"), "{text}");

        let text = super::connect_failed(
            "ldaps://nosuch.lab.test",
            wait,
            io(ErrorKind::Other, "failed to lookup address information: nodename nor servname provided, or not known"),
        );
        assert!(text.contains("the name nosuch.lab.test was not found in DNS"), "{text}");
        assert!(!text.contains("nodename"), "{text}");

        let text = super::connect_failed("ldaps://[fd00::5]:636", wait, io(ErrorKind::HostUnreachable, "no route"));
        assert!(text.contains("no network path to fd00::5"), "{text}");

        // A plain timeout keeps the words a page shown after it looks for.
        let elapsed = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap().block_on(async {
            tokio::time::timeout(std::time::Duration::from_millis(1), std::future::pending::<()>()).await.unwrap_err()
        });
        let text = super::connect_failed("ldaps://dc", wait, ldap3::LdapError::Timeout { elapsed });
        assert!(super::is_timeout(&text), "{text}");

        // Anything else keeps ldap3's words.
        let text = super::connect_failed("ldaps://dc", wait, io(ErrorKind::ConnectionReset, "reset by peer"));
        assert_eq!(text, "Connection failed: I/O error: reset by peer");
    }

    #[test]
    fn a_lockout_that_has_run_out_is_not_shown_as_locked() {
        let entry = |pairs: &[(&str, &str)]| ldap3::SearchEntry {
            dn: "CN=x".into(),
            attrs: pairs.iter().map(|(k, v)| (k.to_string(), vec![v.to_string()])).collect(),
            bin_attrs: Default::default(),
        };
        // Locked: the DC sets bit 0x10.
        assert!(super::is_locked(&entry(&[("lockoutTime", "134080000000000000"), ("msDS-User-Account-Control-Computed", "16")])));
        // The lockout ran out: lockoutTime is still set until the next sign-in.
        assert!(!super::is_locked(&entry(&[("lockoutTime", "134080000000000000"), ("msDS-User-Account-Control-Computed", "0")])));
        assert!(!super::is_locked(&entry(&[("msds-user-account-control-computed", "8388608")])));
        // A DC that does not give the computed value: lockoutTime decides.
        assert!(super::is_locked(&entry(&[("lockoutTime", "134080000000000000")])));
        assert!(!super::is_locked(&entry(&[("lockoutTime", "0")])));

        assert_eq!(super::password_state(&entry(&[("msDS-User-Account-Control-Computed", "8388608"), ("pwdLastSet", "0")])), "must_change");
        assert_eq!(
            super::password_state(&entry(&[("msDS-User-Account-Control-Computed", "8388608"), ("pwdLastSet", "134080000000000000")])),
            "expired"
        );
        assert_eq!(super::password_state(&entry(&[("msDS-User-Account-Control-Computed", "16"), ("pwdLastSet", "0")])), "");
        assert_eq!(super::password_state(&entry(&[("pwdLastSet", "0")])), "");

        // Only users whose password may be past its limit are asked about.
        let day = 86_400 * 10_000_000_i64;
        let now = 1_000 * day;
        let set = |days_ago: i64| entry(&[("pwdLastSet", &(now - days_ago * day).to_string())]);
        let may = super::password_may_have_expired;
        assert!(may(&entry(&[("pwdLastSet", "0")]), 512, None, now));
        assert!(may(&set(43), 512, Some(42 * day), now));
        assert!(!may(&set(41), 512, Some(42 * day), now));
        assert!(!may(&set(400), 512, None, now), "passwords never expire");
        assert!(!may(&set(43), 512 | 0x1_0000, Some(42 * day), now), "password never expires");
    }

    #[test]
    fn a_refused_domain_sign_in_says_why() {
        let res = |rc: u32, text: &str| ldap3::LdapResult {
            rc,
            matched: String::new(),
            text: text.to_string(),
            refs: vec![],
            ctrls: vec![],
        };
        let samba = |code: &str| format!("80090308: LdapErr: DSID-0C09030B, comment: AcceptSecurityContext error, data {code}, v893");
        assert_eq!(domain_refusal(&res(49, &samba("52e"))), DomainSignIn::Refused);
        assert_eq!(domain_refusal(&res(49, &samba("525"))), DomainSignIn::Refused, "no such user: the same answer");
        assert_eq!(domain_refusal(&res(49, &samba("533"))), DomainSignIn::Disabled);
        assert_eq!(domain_refusal(&res(49, &samba("775"))), DomainSignIn::LockedOut);
        assert_eq!(domain_refusal(&res(49, &samba("701"))), DomainSignIn::AccountExpired);
        assert_eq!(domain_refusal(&res(49, &samba("532"))), DomainSignIn::PasswordChange);
        assert_eq!(domain_refusal(&res(49, &samba("773"))), DomainSignIn::PasswordChange);
        assert_eq!(domain_refusal(&res(53, "")), DomainSignIn::Refused);
        assert_eq!(DomainSignIn::Refused.message(), "Invalid username or password");
        assert!(DomainSignIn::Unavailable("Connection failed: x.".into()).message().contains("Local EasyDC accounts can still sign in"));
    }

    #[tokio::test]
    async fn an_empty_domain_password_is_refused_before_asking_the_dc() {
        let server = Server {
            id: 1,
            name: "x".into(),
            ldap_url: "ldaps://192.0.2.1".into(),
            bind_dn: String::new(),
            bind_password: String::new(),
            skip_tls: true,
        };
        // 192.0.2.1 is unreachable: an answer at once means nothing was asked.
        let t = std::time::Instant::now();
        assert_eq!(check_domain_password(&server, "ann", "").await, Err(DomainSignIn::Refused));
        assert!(t.elapsed() < std::time::Duration::from_secs(1));
    }

    #[test]
    fn a_refused_sign_in_says_why() {
        let res = |rc, text: &str| ldap3::LdapResult { rc, matched: String::new(), text: text.into(), refs: vec![], ctrls: vec![] };
        let samba = |data| format!("80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data {data}, v1db1");
        let url = "ldaps://dc.lab.test";
        for (data, says) in [
            ("52e", "the bind DN or its password is wrong"),
            ("533", "the bind account is disabled"),
            ("775", "the bind account is locked out"),
            ("532", "password has expired"),
            ("773", "must change its password"),
            ("701", "the bind account has expired"),
        ] {
            let text = super::sign_in_refused(url, &res(49, &samba(data)));
            assert!(text.starts_with("Sign-in to the DC failed: "), "{text}");
            assert!(text.contains(says), "{data}: {text}");
            assert!(!text.contains("DSID"), "{text}");
        }
        let text = super::sign_in_refused("ldap://dc.lab.test", &res(8, "BindSimple: Transport encryption required."));
        assert!(text.contains("Change it to ldaps://dc.lab.test"), "{text}");
        let text = super::sign_in_refused(url, &res(53, "00000000: unwilling"));
        assert_eq!(text, "Sign-in to the DC failed: the DC refused it, saying \"unwilling\" (LDAP code 53).");
    }

    #[test]
    fn a_closed_connection_points_to_the_port() {
        // What ldap3 gives when the DC drops the connection mid-request.
        let closed = || {
            let (tx, rx) = tokio::sync::oneshot::channel::<()>();
            drop(tx);
            let source = tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(rx).unwrap_err();
            ldap3::LdapError::ResultRecv { source }
        };
        let text = super::bind_failed("ldap://dc.lab.test:636", closed());
        assert!(text.contains("dc.lab.test closed the connection"), "{text}");
        assert!(text.contains("change the address to ldaps://dc.lab.test"), "{text}");
        let text = super::bind_failed("ldaps://dc.lab.test", closed());
        assert!(!text.contains("change the address"), "{text}");
    }

    #[test]
    fn both_kinds_of_timeout_are_recognised() {
        // A page shown after a timed-out action does not wait for the DC again.
        assert!(super::is_timeout(&super::timed_out()));
        assert!(super::is_timeout(&format!("Bind failed: {}", super::timed_out())));
        assert!(super::is_timeout("Connection failed: the domain controller did not answer within 10 seconds"));
        assert!(!super::is_timeout("Connection failed: connection refused"));
        assert!(!super::is_timeout("Group 'x' not found"));
    }

    /// Every request to the DC carries a time limit: a DC busy with a long
    /// change would otherwise leave the page loading forever.
    #[test]
    fn every_request_has_a_time_limit() {
        let ops = ["search", "modify", "add", "delete", "modifydn", "extended", "simple_bind"];
        for (file, src) in [
            ("ldap.rs", include_str!("ldap.rs")),
            ("health.rs", include_str!("health.rs")),
            ("remediate.rs", include_str!("remediate.rs")),
        ] {
            let lines: Vec<&str> = src.lines().collect();
            for (i, line) in lines.iter().enumerate() {
                let t = line.trim_start();
                for op in ops {
                    // Connection and operation on one line, with no limit between.
                    for recv in ["ldap", "conn"] {
                        assert!(
                            !line.contains(&format!("{recv}.{op}(")),
                            "{file}:{}: {op} without a time limit",
                            i + 1
                        );
                    }
                    // The operation on its own line, under the connection.
                    if t.starts_with(&format!(".{op}(")) {
                        assert!(
                            lines[i - 1].contains("with_timeout("),
                            "{file}:{}: {op} without a time limit",
                            i + 1
                        );
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod refusal_tests {
    use super::{dc_text, link_place, refused};

    fn res(rc: u32, text: &str) -> ldap3::LdapResult {
        ldap3::LdapResult { rc, matched: String::new(), text: text.to_string(), refs: vec![], ctrls: vec![] }
    }

    #[test]
    fn a_missing_object_is_named() {
        let e = refused("The GPO was not linked", "the OU Sales", &res(32, "0000208D: acl_read: Error retrieving instanceType for base."));
        assert!(e.starts_with("The GPO was not linked: the OU Sales does not exist."), "{e}");
        assert!(!e.contains("rc=") && !e.contains("acl_read"), "{e}");
    }

    #[test]
    fn no_access_says_whose() {
        let e = refused("The GPO was not deleted", "this GPO", &res(50, "00002098: Insufficient access rights"));
        assert!(e.contains("the account EasyDC signs in with is not allowed"), "{e}");
    }

    #[test]
    fn anything_else_keeps_the_dcs_words_without_its_number() {
        let e = refused("The GPO was not saved", "this GPO", &res(19, "0000202F: Constraint violation\n\0"));
        assert_eq!(e, "The GPO was not saved: the domain controller refused it, saying \"Constraint violation\" (LDAP code 19).");
        assert_eq!(dc_text("objectclass: no such class"), "objectclass: no such class");
    }

    #[test]
    fn link_places_read_naturally() {
        assert_eq!(link_place("OU=Europe,OU=Sales,DC=lab,DC=test"), "the OU Europe");
        assert_eq!(link_place("CN=Users,DC=lab,DC=test"), "Users");
    }
}
