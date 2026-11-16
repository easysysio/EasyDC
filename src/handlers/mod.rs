pub mod auth_handlers;
pub mod health;
pub mod ldap_mgmt;
pub mod policy;
pub mod servers;
pub mod settings;
pub mod setup;

/// A name as one URL path segment: `Sales/EMEA` must not become two segments,
/// nor `a?b` a query.
pub(crate) fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
