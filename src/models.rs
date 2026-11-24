use serde::Serialize;

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct Server {
    pub id: i64,
    pub name: String,
    pub ldap_url: String,
    pub bind_dn: String,
    /// Never sent to a page: the record is in every server page's context.
    #[serde(skip_serializing)]
    pub bind_password: String,
    pub skip_tls: bool,
}

#[derive(Debug, sqlx::FromRow, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub ts: i64,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub server_id: Option<i64>,
    pub server_name: Option<String>,
    pub result: String,
    pub detail: Option<String>,
}
