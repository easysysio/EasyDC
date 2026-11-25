use sqlx::{sqlite::SqlitePool, AssertSqlSafe};

pub async fn init_tables(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Migration: an admin flag. The accounts that exist when it is added were
    // all full administrators, so they stay admins; accounts added later get
    // what the admin who adds them chooses.
    if sqlx::query("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await
        .is_ok()
    {
        sqlx::query("UPDATE users SET is_admin = 1").execute(pool).await?;
    }

    // Migration: domain accounts. A local account has a password hash; a
    // domain account has none, and signs in with its password in the domain
    // of `server_id`, as `domain_user` (its sAMAccountName).
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN kind TEXT NOT NULL DEFAULT 'local'")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN server_id INTEGER").execute(pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN domain_user TEXT").execute(pool).await;

    // What each account may change: a row per area it may edit. An area
    // without a row is View.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS permissions (
            username TEXT NOT NULL,
            area TEXT NOT NULL,
            level TEXT NOT NULL,
            PRIMARY KEY (username, area)
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS servers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            ldap_url TEXT NOT NULL,
            bind_dn TEXT NOT NULL,
            bind_password TEXT NOT NULL,
            skip_tls BOOLEAN NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;

    // Migration: associate each session with the user who created it so actions
    // can be attributed in the audit log. Ignore the error if it already exists.
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN username TEXT")
        .execute(pool)
        .await;

    // Sessions from before that column cannot be tied to an account, so a
    // password change or an administrator's removal cannot end them — and
    // sessions do not expire. Drop them: their owners sign in once more.
    sqlx::query("DELETE FROM sessions WHERE username IS NULL")
        .execute(pool)
        .await?;

    // Migration: the time of each session's latest request, for the idle
    // timeout. Older sessions count from their sign-in.
    let _ = sqlx::query("ALTER TABLE sessions ADD COLUMN last_seen INTEGER")
        .execute(pool)
        .await;
    sqlx::query("UPDATE sessions SET last_seen = created_at WHERE last_seen IS NULL")
        .execute(pool)
        .await?;
    purge_expired_sessions(pool).await;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts INTEGER NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            server_id INTEGER,
            result TEXT NOT NULL,
            detail TEXT
        )",
    )
    .execute(pool)
    .await?;
    // Rotation finds old entries by time.
    sqlx::query("CREATE INDEX IF NOT EXISTS audit_log_ts ON audit_log (ts)").execute(pool).await?;

    // One row: the certificate EasyDC serves, and its private key.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS tls_certificate (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cert_pem TEXT NOT NULL,
            key_pem TEXT NOT NULL,
            uploaded INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;

    // Two-factor sign-in. `enabled` is 0 during setup. `last_step` stops a
    // code being used twice; `failures` and `locked_until` limit guessing.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_totp (
            username TEXT PRIMARY KEY,
            secret TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 0,
            created_at INTEGER NOT NULL,
            last_step INTEGER NOT NULL DEFAULT 0,
            failures INTEGER NOT NULL DEFAULT 0,
            locked_until INTEGER NOT NULL DEFAULT 0
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS user_recovery_codes (
            username TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            PRIMARY KEY (username, code_hash)
        )",
    )
    .execute(pool)
    .await?;
    // A sign-in whose password was right and whose code is still to come. Not
    // a session: nothing but the code page reads this table.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS sign_in_challenges (
            token TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )",
    )
    .execute(pool)
    .await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS app_settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(pool)
        .await?;

    // Health check findings someone chose not to see. An empty fingerprint
    // hides the check whatever it finds.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS health_hidden (
            server_id   INTEGER NOT NULL,
            check_id    TEXT NOT NULL,
            fingerprint TEXT NOT NULL DEFAULT '',
            reason      TEXT NOT NULL DEFAULT '',
            hidden_by   TEXT NOT NULL,
            hidden_at   INTEGER NOT NULL,
            PRIMARY KEY (server_id, check_id)
        )",
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ── hidden health findings ───────────────────────────────────────────────────

/// What is hidden on this server. A read error shows everything.
pub async fn hidden_findings(pool: &SqlitePool, server_id: i64) -> Vec<crate::health::HiddenRow> {
    sqlx::query_as("SELECT check_id, fingerprint, reason, hidden_by, hidden_at FROM health_hidden WHERE server_id = ?")
        .bind(server_id)
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}

/// Hide one check's finding, replacing an earlier hide of the same check.
pub async fn hide_finding(pool: &SqlitePool, server_id: i64, check_id: &str, fingerprint: &str, reason: &str, by: &str) -> Result<(), String> {
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    sqlx::query("INSERT OR REPLACE INTO health_hidden (server_id, check_id, fingerprint, reason, hidden_by, hidden_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(server_id)
        .bind(check_id)
        .bind(fingerprint)
        .bind(reason)
        .bind(by)
        .bind(now)
        .execute(pool)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Show one check's finding again. `None` removes every hide on the server.
pub async fn show_finding(pool: &SqlitePool, server_id: i64, check_id: Option<&str>) -> Result<(), String> {
    let q = match check_id {
        Some(c) => sqlx::query("DELETE FROM health_hidden WHERE server_id = ? AND check_id = ?").bind(server_id).bind(c.to_string()),
        None => sqlx::query("DELETE FROM health_hidden WHERE server_id = ?").bind(server_id),
    };
    q.execute(pool).await.map(|_| ()).map_err(|e| e.to_string())
}

// ── two-factor sign-in ───────────────────────────────────────────────────────

const REQUIRE_TWO_FACTOR: &str = "require_two_factor_admins";

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct TwoFactor {
    pub secret: String,
    pub enabled: bool,
    pub created_at: i64,
    pub locked_until: i64,
}

/// An error is returned, not hidden: sign-in must not skip the code because
/// the database could not say whether the account has one.
pub async fn two_factor(pool: &SqlitePool, username: &str) -> Result<Option<TwoFactor>, sqlx::Error> {
    sqlx::query_as("SELECT secret, enabled, created_at, locked_until FROM user_totp WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
}

pub async fn is_local_account(pool: &SqlitePool, username: &str) -> bool {
    sqlx::query("SELECT 1 FROM users WHERE username = ? AND kind = 'local'")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Start or restart setup. False, changing nothing, when it is already on.
pub async fn begin_two_factor(pool: &SqlitePool, username: &str, secret: &str, now: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "INSERT INTO user_totp (username, secret, enabled, created_at) VALUES (?, ?, 0, ?)
         ON CONFLICT (username) DO UPDATE SET secret = excluded.secret, created_at = excluded.created_at
         WHERE user_totp.enabled = 0",
    )
    .bind(username)
    .bind(secret)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

/// Turn it on, with the code that proved the app works already spent.
pub async fn enable_two_factor(
    pool: &SqlitePool,
    username: &str,
    secret: &str,
    step: i64,
    code_hashes: &[String],
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE user_totp SET enabled = 1, last_step = ?, failures = 0, locked_until = 0
         WHERE username = ? AND secret = ? AND enabled = 0",
    )
    .bind(step)
    .bind(username)
    .bind(secret)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if !changed {
        return Ok(false);
    }
    write_recovery_codes(&mut tx, username, code_hashes).await?;
    tx.commit().await?;
    Ok(true)
}

async fn write_recovery_codes(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    username: &str,
    code_hashes: &[String],
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM user_recovery_codes WHERE username = ?")
        .bind(username)
        .execute(&mut **tx)
        .await?;
    for hash in code_hashes {
        sqlx::query("INSERT INTO user_recovery_codes (username, code_hash) VALUES (?, ?)")
            .bind(username)
            .bind(hash)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub async fn replace_recovery_codes(pool: &SqlitePool, username: &str, code_hashes: &[String]) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    write_recovery_codes(&mut tx, username, code_hashes).await?;
    tx.commit().await
}

pub async fn recovery_codes_left(pool: &SqlitePool, username: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM user_recovery_codes WHERE username = ?")
        .bind(username)
        .fetch_one(pool)
        .await
        .unwrap_or(0)
}

/// Remove an account's two-factor, codes and open sign-ins. True when it was on.
pub async fn remove_two_factor(pool: &SqlitePool, username: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let was_on = sqlx::query("SELECT 1 FROM user_totp WHERE username = ? AND enabled = 1")
        .bind(username)
        .fetch_optional(&mut *tx)
        .await?
        .is_some();
    clear_two_factor(&mut tx, username).await?;
    tx.commit().await?;
    Ok(was_on)
}

async fn clear_two_factor(tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>, username: &str) -> Result<(), sqlx::Error> {
    for table in ["user_totp", "user_recovery_codes", "sign_in_challenges"] {
        // The table names are the fixed list above; the username is bound.
        sqlx::query(AssertSqlSafe(format!("DELETE FROM {table} WHERE username = ?")))
            .bind(username)
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

/// Count one attempt at a code, in one statement so that requests sent at the
/// same moment each count. False when the account is not taking codes now.
pub async fn count_code_attempt(pool: &SqlitePool, username: &str, now: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(
        "UPDATE user_totp SET
            failures = CASE WHEN locked_until > 0 THEN 1 ELSE failures + 1 END,
            locked_until = CASE WHEN locked_until = 0 AND failures + 1 >= ? THEN ? ELSE 0 END
         WHERE username = ? AND enabled = 1 AND locked_until <= ?",
    )
    .bind(crate::totp::MAX_WRONG_CODES)
    .bind(now + crate::totp::LOCK_SECONDS)
    .bind(username)
    .bind(now)
    .execute(pool)
    .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn clear_code_failures(pool: &SqlitePool, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE user_totp SET failures = 0, locked_until = 0 WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Spend a code's time step. False when it, or a later one, was already used.
pub async fn claim_code_step(pool: &SqlitePool, username: &str, step: i64) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("UPDATE user_totp SET last_step = ? WHERE username = ? AND enabled = 1 AND last_step < ?")
        .bind(step)
        .bind(username)
        .bind(step)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

/// Spend a recovery code. False when there is no such unused code.
pub async fn use_recovery_code(pool: &SqlitePool, username: &str, code_hash: &str) -> Result<bool, sqlx::Error> {
    let done = sqlx::query("DELETE FROM user_recovery_codes WHERE username = ? AND code_hash = ?")
        .bind(username)
        .bind(code_hash)
        .execute(pool)
        .await?;
    Ok(done.rows_affected() > 0)
}

pub async fn create_challenge(pool: &SqlitePool, token: &str, username: &str, now: i64) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM sign_in_challenges WHERE created_at <= ?")
        .bind(now - crate::totp::CHALLENGE_SECONDS)
        .execute(pool)
        .await?;
    sqlx::query("INSERT INTO sign_in_challenges (token, username, created_at) VALUES (?, ?, ?)")
        .bind(token)
        .bind(username)
        .bind(now)
        .execute(pool)
        .await
        .map(|_| ())
}

/// The account of an open sign-in, if it has not timed out.
pub async fn challenge_user(pool: &SqlitePool, token: &str, now: i64) -> Option<String> {
    sqlx::query_scalar("SELECT username FROM sign_in_challenges WHERE token = ? AND created_at > ?")
        .bind(token)
        .bind(now - crate::totp::CHALLENGE_SECONDS)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

/// True for the one request that closes this sign-in.
pub async fn close_challenge(pool: &SqlitePool, token: &str) -> bool {
    sqlx::query("DELETE FROM sign_in_challenges WHERE token = ?")
        .bind(token)
        .execute(pool)
        .await
        .is_ok_and(|d| d.rows_affected() > 0)
}

pub async fn two_factor_required(pool: &SqlitePool) -> bool {
    sqlx::query("SELECT 1 FROM app_settings WHERE key = ? AND value = '1'")
        .bind(REQUIRE_TWO_FACTOR)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

pub async fn set_two_factor_required(pool: &SqlitePool, required: bool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO app_settings (key, value) VALUES (?, ?)
         ON CONFLICT (key) DO UPDATE SET value = excluded.value",
    )
    .bind(REQUIRE_TWO_FACTOR)
    .bind(if required { "1" } else { "0" })
    .execute(pool)
    .await
    .map(|_| ())
}

/// Whether this account is a local admin who has to set up two-factor before
/// doing anything else. If the database cannot say, the answer is yes.
pub async fn must_set_up_two_factor(pool: &SqlitePool, username: &str) -> bool {
    sqlx::query(
        "SELECT 1 FROM users u JOIN app_settings s ON s.key = ? AND s.value = '1'
         WHERE u.username = ? AND u.kind = 'local' AND u.is_admin = 1
           AND NOT EXISTS (SELECT 1 FROM user_totp t WHERE t.username = u.username AND t.enabled = 1)",
    )
    .bind(REQUIRE_TWO_FACTOR)
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_or(true, |row| row.is_some())
}

/// Local admins who sign in with a password alone, while two-factor is not
/// required. Domain accounts sign in at the DC, so EasyDC cannot add a code
/// to theirs. A read error lists no one.
pub async fn admins_without_two_factor(pool: &SqlitePool) -> Vec<String> {
    if two_factor_required(pool).await {
        return Vec::new();
    }
    sqlx::query_scalar(
        "SELECT u.username FROM users u
         WHERE u.kind = 'local' AND u.is_admin = 1
           AND NOT EXISTS (SELECT 1 FROM user_totp t WHERE t.username = u.username AND t.enabled = 1)
         ORDER BY u.username",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

pub async fn tls_pair(pool: &SqlitePool) -> Option<crate::tls::Pair> {
    let row: (String, String, bool) =
        sqlx::query_as("SELECT cert_pem, key_pem, uploaded FROM tls_certificate WHERE id = 1")
            .fetch_optional(pool)
            .await
            .ok()??;
    Some(crate::tls::Pair { cert: row.0, key: row.1, uploaded: row.2 })
}

pub async fn save_tls_pair(pool: &SqlitePool, pair: &crate::tls::Pair) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO tls_certificate (id, cert_pem, key_pem, uploaded) VALUES (1, ?, ?, ?)
         ON CONFLICT (id) DO UPDATE SET cert_pem = excluded.cert_pem, key_pem = excluded.key_pem, uploaded = excluded.uploaded",
    )
    .bind(&pair.cert)
    .bind(&pair.key)
    .bind(pair.uploaded)
    .execute(pool)
    .await?;
    Ok(())
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Delete every session past its idle or absolute limit. A request on an
/// expired session is refused either way; this only keeps the table small.
pub async fn purge_expired_sessions(pool: &SqlitePool) {
    let now = unix_now();
    let _ = sqlx::query(
        "DELETE FROM sessions WHERE created_at <= ? OR COALESCE(last_seen, created_at) <= ?",
    )
    .bind(now - crate::auth::MAX_SESSION_AGE)
    .bind(now - crate::auth::IDLE_TIMEOUT)
    .execute(pool)
    .await;
}

// ── audit log ────────────────────────────────────────────────────────────────

/// Record one action in the audit log. Best-effort: logging failures are
/// swallowed so they can never block the operation being audited.
pub async fn log_action(
    pool: &SqlitePool,
    actor: &str,
    action: &str,
    target: &str,
    server_id: Option<i64>,
    result: &Result<(), String>,
) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (result_str, detail): (&str, Option<String>) = match result {
        Ok(()) => ("success", None),
        Err(e) => ("failure", Some(e.clone())),
    };
    let _ = sqlx::query(
        "INSERT INTO audit_log (ts, actor, action, target, server_id, result, detail)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(now)
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(server_id)
    .bind(result_str)
    .bind(detail)
    .execute(pool)
    .await;
}

/// One page of the audit log, newest first, and how many entries match in
/// all. Every word of `search` must appear somewhere in the entry: its actor,
/// action, target, reason or server. The whole log is searched, not just a
/// recent part of it, so one big bulk action does not hide everything older.
pub async fn search_audit(
    pool: &SqlitePool,
    search: &str,
    failures_only: bool,
    limit: i64,
    offset: i64,
) -> Result<(Vec<crate::models::AuditEntry>, i64), sqlx::Error> {
    let words: Vec<String> = search.split_whitespace().map(str::to_lowercase).collect();
    let mut filter = String::from(" WHERE 1 = 1");
    if failures_only {
        filter.push_str(" AND a.result = 'failure'");
    }
    for _ in &words {
        filter.push_str(
            " AND instr(lower(a.actor || ' ' || a.action || ' ' || a.target || ' ' || \
             coalesce(a.detail, '') || ' ' || coalesce(s.name, '')), ?) > 0",
        );
    }
    let from = " FROM audit_log a LEFT JOIN servers s ON s.id = a.server_id";
    // The SQL below is fixed text and one placeholder per word: the words
    // themselves are bound, never put into it.

    let count_sql = format!("SELECT COUNT(*){from}{filter}");
    let mut count = sqlx::query_scalar::<_, i64>(AssertSqlSafe(count_sql));
    for w in &words {
        count = count.bind(w);
    }
    let total = count.fetch_one(pool).await?;

    let page_sql = format!(
        "SELECT a.id, a.ts, a.actor, a.action, a.target, a.server_id,
                s.name AS server_name, a.result, a.detail{from}{filter}
         ORDER BY a.id DESC LIMIT ? OFFSET ?"
    );
    let mut page = sqlx::query_as::<_, crate::models::AuditEntry>(AssertSqlSafe(page_sql));
    for w in &words {
        page = page.bind(w);
    }
    let entries = page.bind(limit).bind(offset).fetch_all(pool).await?;
    Ok((entries, total))
}

// ── session ↔ user lookup ──────────────────────────────────────────────────────

/// Resolve the username that owns a given session token, if any.
#[cfg(test)]
pub async fn username_for_token(pool: &SqlitePool, token: &str) -> Option<String> {
    use sqlx::Row;
    sqlx::query("SELECT username FROM sessions WHERE token = ?")
        .bind(token)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .and_then(|row| row.get::<Option<String>, _>("username"))
}

pub async fn has_users(pool: &SqlitePool) -> Result<bool, sqlx::Error> {
    use sqlx::Row;
    let row = sqlx::query("SELECT COUNT(*) as count FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("count") > 0)
}

// ── EasyDC accounts ──────────────────────────────────────────────────────────

/// One account as the Settings page lists it.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Account {
    pub username: String,
    /// Signs in with a domain password, not one kept by EasyDC.
    pub domain: bool,
    /// For a domain account: the server whose domain it is in, if it still exists.
    pub server_name: Option<String>,
    pub domain_user: String,
    pub admin: bool,
    /// Signs in with a code from an authenticator app as well.
    pub two_factor: bool,
    /// The keys of the areas it may edit.
    pub edit: Vec<&'static str>,
    pub summary: String,
}

/// Every account, alphabetically, with its permissions.
pub async fn list_accounts(pool: &SqlitePool) -> Result<Vec<Account>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query(
        "SELECT u.username, u.kind, u.domain_user, s.name AS server_name, \
         EXISTS (SELECT 1 FROM user_totp t WHERE t.username = u.username AND t.enabled = 1) AS two_factor \
         FROM users u LEFT JOIN servers s ON s.id = u.server_id ORDER BY u.username COLLATE NOCASE",
    )
    .fetch_all(pool)
    .await?;
    let mut out = Vec::new();
    for r in rows {
        let username: String = r.get("username");
        let a = access_for(pool, &username).await?.unwrap_or_default();
        out.push(Account {
            domain: r.get::<String, _>("kind") == "domain",
            server_name: r.get("server_name"),
            domain_user: r.get::<Option<String>, _>("domain_user").unwrap_or_default(),
            admin: a.admin,
            two_factor: r.get::<i64, _>("two_factor") != 0,
            edit: a.edit.iter().map(|x| x.key()).collect(),
            summary: a.summary(),
            username,
        });
    }
    Ok(out)
}

/// An account's permissions, or None when there is no such account.
pub async fn access_for(
    pool: &SqlitePool,
    username: &str,
) -> Result<Option<crate::access::Access>, sqlx::Error> {
    use sqlx::Row;
    let Some(row) = sqlx::query("SELECT is_admin FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await?
    else {
        return Ok(None);
    };
    let rows = sqlx::query("SELECT area FROM permissions WHERE username = ? AND level = 'edit'")
        .bind(username)
        .fetch_all(pool)
        .await?;
    Ok(Some(crate::access::Access {
        username: username.to_string(),
        admin: row.get::<i64, _>("is_admin") != 0,
        edit: rows
            .iter()
            .filter_map(|r| crate::access::Area::from_key(&r.get::<String, _>("area")))
            .collect(),
    }))
}

/// Exact match, the same comparison login and delete use.
pub async fn account_exists(pool: &SqlitePool, username: &str) -> bool {
    sqlx::query("SELECT 1 FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Case-insensitive, used only to refuse a new name that differs from an
/// existing one by case alone — "Alice" beside "alice" is a trap for whoever
/// types the name next.
pub async fn account_name_taken(pool: &SqlitePool, username: &str) -> bool {
    sqlx::query("SELECT 1 FROM users WHERE username = ? COLLATE NOCASE")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

pub async fn password_hash_for(pool: &SqlitePool, username: &str) -> Option<String> {
    use sqlx::Row;
    sqlx::query("SELECT password_hash FROM users WHERE username = ?")
        .bind(username)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .map(|row| row.get::<String, _>("password_hash"))
}

pub async fn set_password_hash(
    pool: &SqlitePool,
    username: &str,
    hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE users SET password_hash = ? WHERE username = ?")
        .bind(hash)
        .bind(username)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Write the areas an account may edit, replacing what it had.
async fn write_areas(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    username: &str,
    edit: &std::collections::BTreeSet<crate::access::Area>,
) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM permissions WHERE username = ?")
        .bind(username)
        .execute(&mut **tx)
        .await?;
    for area in edit {
        sqlx::query("INSERT INTO permissions (username, area, level) VALUES (?, ?, 'edit')")
            .bind(username)
            .bind(area.key())
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

pub async fn create_account(
    pool: &SqlitePool,
    username: &str,
    hash: &str,
    admin: bool,
    edit: &std::collections::BTreeSet<crate::access::Area>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("INSERT INTO users (username, password_hash, is_admin) VALUES (?, ?, ?)")
        .bind(username)
        .bind(hash)
        .bind(admin as i64)
        .execute(&mut *tx)
        .await?;
    write_areas(&mut tx, username, edit).await?;
    tx.commit().await
}

pub async fn create_domain_account(
    pool: &SqlitePool,
    username: &str,
    domain_user: &str,
    server_id: i64,
    admin: bool,
    edit: &std::collections::BTreeSet<crate::access::Area>,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query(
        "INSERT INTO users (username, password_hash, is_admin, kind, server_id, domain_user) \
         VALUES (?, '', ?, 'domain', ?, ?)",
    )
    .bind(username)
    .bind(admin as i64)
    .bind(server_id)
    .bind(domain_user)
    .execute(&mut *tx)
    .await?;
    write_areas(&mut tx, username, edit).await?;
    tx.commit().await
}

pub async fn server(pool: &SqlitePool, id: i64) -> Option<crate::models::Server> {
    sqlx::query_as::<_, crate::models::Server>("SELECT * FROM servers WHERE id = ?")
        .bind(id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
}

/// Every server's id and name, for choosing a domain.
pub async fn server_names(pool: &SqlitePool) -> Vec<(i64, String)> {
    sqlx::query_as::<_, (i64, String)>("SELECT id, name FROM servers ORDER BY name COLLATE NOCASE")
        .fetch_all(pool)
        .await
        .unwrap_or_default()
}

pub async fn has_domain_accounts(pool: &SqlitePool) -> bool {
    sqlx::query("SELECT 1 FROM users WHERE kind = 'domain' LIMIT 1")
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// How an account signs in.
#[derive(Debug, Clone, PartialEq)]
pub enum SignIn {
    Local { username: String, hash: String },
    Domain { username: String, domain_user: String, server_id: Option<i64> },
}

/// The account behind what someone typed at sign-in: its EasyDC name
/// exactly, a domain account's name in any case (`ann@lab.test`), or a
/// domain username alone (`ann`, or `LAB\ann`) when only one domain account
/// has it and no local account is called that.
pub async fn sign_in_account(pool: &SqlitePool, typed: &str) -> Option<SignIn> {
    use sqlx::Row;
    let row_to = |r: sqlx::sqlite::SqliteRow| {
        let username: String = r.get("username");
        if r.get::<String, _>("kind") == "domain" {
            SignIn::Domain {
                username,
                domain_user: r.get::<Option<String>, _>("domain_user").unwrap_or_default(),
                server_id: r.get("server_id"),
            }
        } else {
            SignIn::Local { username, hash: r.get("password_hash") }
        }
    };
    // Fixed text; the names are bound.
    const COLS: &str = "SELECT username, kind, password_hash, domain_user, server_id FROM users";
    if let Ok(Some(r)) = sqlx::query(AssertSqlSafe(format!("{COLS} WHERE username = ?"))).bind(typed).fetch_optional(pool).await {
        return Some(row_to(r));
    }
    if let Ok(Some(r)) = sqlx::query(AssertSqlSafe(format!("{COLS} WHERE kind = 'domain' AND username = ? COLLATE NOCASE")))
        .bind(typed)
        .fetch_optional(pool)
        .await
    {
        return Some(row_to(r));
    }
    let short = typed.rsplit('\\').next().unwrap_or(typed);
    if short.is_empty() || short.contains('@') {
        return None;
    }
    let local_named = sqlx::query("SELECT 1 FROM users WHERE kind = 'local' AND username = ? COLLATE NOCASE")
        .bind(short)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some();
    if local_named {
        return None;
    }
    let rows = sqlx::query(AssertSqlSafe(format!("{COLS} WHERE kind = 'domain' AND domain_user = ? COLLATE NOCASE")))
        .bind(short)
        .fetch_all(pool)
        .await
        .ok()?;
    match rows.len() {
        1 => rows.into_iter().next().map(row_to),
        _ => None,
    }
}

/// Change an account's permissions. Returns false, changing nothing, when
/// that would leave no local admin — one who can sign in while the DC is down. The count is part of the same statement, so
/// two admins removing each other's admin at the same moment cannot both
/// succeed.
pub async fn set_permissions(
    pool: &SqlitePool,
    username: &str,
    admin: bool,
    edit: &std::collections::BTreeSet<crate::access::Area>,
) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let changed = sqlx::query(
        "UPDATE users SET is_admin = ? WHERE username = ? AND \
         (? = 1 OR is_admin = 0 OR kind != 'local' OR \
          (SELECT COUNT(*) FROM users WHERE is_admin = 1 AND kind = 'local' AND username != ?) > 0)",
    )
    .bind(admin as i64)
    .bind(username)
    .bind(admin as i64)
    .bind(username)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if !changed {
        return Ok(false);
    }
    write_areas(&mut tx, username, edit).await?;
    tx.commit().await?;
    Ok(true)
}

/// Delete an account unless it is the last local admin, in a single statement.
/// Returns whether a row was removed.
///
/// The count is part of the DELETE rather than a check before it: two
/// admins deleting each other at the same moment would otherwise both see a
/// count of two, both succeed, and leave no admin.
pub async fn delete_account(pool: &SqlitePool, username: &str) -> Result<bool, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let removed = sqlx::query(
        "DELETE FROM users WHERE username = ? AND \
         (is_admin = 0 OR kind != 'local' OR \
          (SELECT COUNT(*) FROM users WHERE is_admin = 1 AND kind = 'local' AND username != ?) > 0)",
    )
    .bind(username)
    .bind(username)
    .execute(&mut *tx)
    .await?
    .rows_affected()
        > 0;
    if removed {
        sqlx::query("DELETE FROM permissions WHERE username = ?")
            .bind(username)
            .execute(&mut *tx)
            .await?;
        // A later account with this name must not inherit it.
        clear_two_factor(&mut tx, username).await?;
    }
    tx.commit().await?;
    Ok(removed)
}

/// Drop an account's sessions, optionally sparing one token. Used to sign a
/// deleted administrator out everywhere, and to leave only the current browser
/// signed in after a password change.
pub async fn delete_sessions_for(pool: &SqlitePool, username: &str, except: Option<&str>) {
    // A sign-in waiting for its code ends with them.
    let _ = sqlx::query("DELETE FROM sign_in_challenges WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await;
    let _ = match except {
        Some(token) => {
            sqlx::query("DELETE FROM sessions WHERE username = ? AND token != ?")
                .bind(username)
                .bind(token)
                .execute(pool)
                .await
        }
        None => {
            sqlx::query("DELETE FROM sessions WHERE username = ?")
                .bind(username)
                .execute(pool)
                .await
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    /// A real file, not an in-memory database: each pooled connection to
    /// :memory: gets its own empty database, which would make the concurrency
    /// test below meaningless.
    async fn pool() -> SqlitePool {
        let path = std::env::temp_dir().join(format!("easydc-test-{}.db", uuid::Uuid::new_v4()));
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .unwrap()
            .create_if_missing(true);
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(4)
            .connect_with(opts)
            .await
            .unwrap();
        init_tables(&pool).await.unwrap();
        pool
    }

    async fn with_two_factor(pool: &SqlitePool, name: &str, admin: bool) {
        create_account(pool, name, "hash", admin, &Default::default()).await.unwrap();
        assert!(begin_two_factor(pool, name, "SECRET", 1000).await.unwrap());
        assert!(enable_two_factor(pool, name, "SECRET", 50, &["h1".into(), "h2".into()]).await.unwrap());
    }

    #[tokio::test]
    async fn setup_only_counts_once_confirmed_and_cannot_replace_a_live_secret() {
        let pool = pool().await;
        create_account(&pool, "alice", "hash", true, &Default::default()).await.unwrap();
        assert!(begin_two_factor(&pool, "alice", "FIRST", 1000).await.unwrap());
        assert!(!two_factor(&pool, "alice").await.unwrap().unwrap().enabled);
        assert!(begin_two_factor(&pool, "alice", "SECOND", 1001).await.unwrap(), "setup can restart");
        assert!(!enable_two_factor(&pool, "alice", "FIRST", 50, &[]).await.unwrap(), "the old QR code is dead");
        assert!(enable_two_factor(&pool, "alice", "SECOND", 50, &["h".into()]).await.unwrap());
        assert!(!begin_two_factor(&pool, "alice", "THIRD", 1002).await.unwrap());
        assert_eq!(two_factor(&pool, "alice").await.unwrap().unwrap().secret, "SECOND");
    }

    #[tokio::test]
    async fn a_code_and_a_recovery_code_each_work_once() {
        let pool = pool().await;
        with_two_factor(&pool, "alice", true).await;
        assert!(!claim_code_step(&pool, "alice", 50).await.unwrap(), "spent when setup confirmed it");
        assert!(claim_code_step(&pool, "alice", 51).await.unwrap());
        assert!(!claim_code_step(&pool, "alice", 51).await.unwrap());
        assert!(!claim_code_step(&pool, "alice", 50).await.unwrap(), "no going back");

        assert!(use_recovery_code(&pool, "alice", "h1").await.unwrap());
        assert!(!use_recovery_code(&pool, "alice", "h1").await.unwrap());
        assert_eq!(recovery_codes_left(&pool, "alice").await, 1);
    }

    #[tokio::test]
    async fn guesses_are_limited_even_when_sent_together() {
        let pool = pool().await;
        with_two_factor(&pool, "alice", true).await;
        let now = 10_000;
        let tries: Vec<_> = (0..40)
            .map(|_| {
                let pool = pool.clone();
                tokio::spawn(async move { count_code_attempt(&pool, "alice", now).await.unwrap() })
            })
            .collect();
        let mut allowed = 0;
        for t in tries {
            allowed += t.await.unwrap() as i64;
        }
        assert_eq!(allowed, crate::totp::MAX_WRONG_CODES);

        let until = now + crate::totp::LOCK_SECONDS;
        assert!(!count_code_attempt(&pool, "alice", until - 1).await.unwrap(), "still locked");
        assert!(count_code_attempt(&pool, "alice", until).await.unwrap(), "open again");
        for _ in 1..crate::totp::MAX_WRONG_CODES {
            assert!(count_code_attempt(&pool, "alice", until).await.unwrap(), "the count restarted");
        }
        assert!(!count_code_attempt(&pool, "alice", until).await.unwrap());

        clear_code_failures(&pool, "alice").await.unwrap();
        assert!(count_code_attempt(&pool, "alice", until).await.unwrap(), "a right code clears it");
    }

    #[tokio::test]
    async fn a_removed_account_leaves_nothing_for_the_next_one_with_its_name() {
        let pool = pool().await;
        create_account(&pool, "root", "hash", true, &Default::default()).await.unwrap();
        with_two_factor(&pool, "bob", false).await;
        create_challenge(&pool, "tok", "bob", unix_now()).await.unwrap();
        assert!(delete_account(&pool, "bob").await.unwrap());
        create_account(&pool, "bob", "hash2", false, &Default::default()).await.unwrap();
        assert!(two_factor(&pool, "bob").await.unwrap().is_none());
        assert_eq!(recovery_codes_left(&pool, "bob").await, 0);
        assert!(challenge_user(&pool, "tok", unix_now()).await.is_none());
    }

    #[tokio::test]
    async fn an_open_sign_in_ends_with_a_password_change_and_after_five_minutes() {
        let pool = pool().await;
        with_two_factor(&pool, "alice", true).await;
        let now = unix_now();
        create_challenge(&pool, "a", "alice", now).await.unwrap();
        assert_eq!(challenge_user(&pool, "a", now).await.as_deref(), Some("alice"));
        assert!(challenge_user(&pool, "a", now + crate::totp::CHALLENGE_SECONDS).await.is_none());
        delete_sessions_for(&pool, "alice", Some("current")).await;
        assert!(challenge_user(&pool, "a", now).await.is_none());

        create_challenge(&pool, "b", "alice", now).await.unwrap();
        assert!(close_challenge(&pool, "b").await);
        assert!(!close_challenge(&pool, "b").await, "one session per sign-in");
    }

    #[tokio::test]
    async fn only_local_admins_without_it_must_set_it_up() {
        let pool = pool().await;
        create_account(&pool, "plain", "hash", true, &Default::default()).await.unwrap();
        create_account(&pool, "viewer", "hash", false, &Default::default()).await.unwrap();
        with_two_factor(&pool, "secured", true).await;
        create_domain_account(&pool, "ann@lab.test", "ann", 1, true, &Default::default()).await.unwrap();

        assert!(!must_set_up_two_factor(&pool, "plain").await, "off until required");
        set_two_factor_required(&pool, true).await.unwrap();
        assert!(two_factor_required(&pool).await);
        assert!(must_set_up_two_factor(&pool, "plain").await);
        assert!(!must_set_up_two_factor(&pool, "viewer").await);
        assert!(!must_set_up_two_factor(&pool, "secured").await);
        assert!(!must_set_up_two_factor(&pool, "ann@lab.test").await);

        assert!(remove_two_factor(&pool, "secured").await.unwrap());
        assert!(must_set_up_two_factor(&pool, "secured").await);
        assert!(!remove_two_factor(&pool, "secured").await.unwrap(), "nothing left to remove");

        set_two_factor_required(&pool, false).await.unwrap();
        assert!(!must_set_up_two_factor(&pool, "plain").await);
    }

    #[tokio::test]
    async fn the_overview_names_local_admins_without_it() {
        let pool = pool().await;
        create_account(&pool, "plain", "hash", true, &Default::default()).await.unwrap();
        create_account(&pool, "bob", "hash", true, &Default::default()).await.unwrap();
        create_account(&pool, "viewer", "hash", false, &Default::default()).await.unwrap();
        with_two_factor(&pool, "secured", true).await;
        create_domain_account(&pool, "ann@lab.test", "ann", 1, true, &Default::default()).await.unwrap();

        assert_eq!(admins_without_two_factor(&pool).await, vec!["bob", "plain"]);
        set_two_factor_required(&pool, true).await.unwrap();
        assert!(admins_without_two_factor(&pool).await.is_empty(), "required: they set it up at sign-in");
    }

    #[tokio::test]
    async fn the_account_list_says_who_has_it() {
        let pool = pool().await;
        create_account(&pool, "plain", "hash", true, &Default::default()).await.unwrap();
        with_two_factor(&pool, "secured", false).await;
        let accounts = list_accounts(&pool).await.unwrap();
        let has = |n: &str| accounts.iter().find(|a| a.username == n).unwrap().two_factor;
        assert!(!has("plain") && has("secured"));
    }

    #[tokio::test]
    async fn the_audit_log_is_searched_whole_and_paged() {
        let pool = pool().await;
        log_action(&pool, "alice", "group.create", "Finance", None, &Ok(())).await;
        for i in 0..250 {
            log_action(&pool, "bob", "user.disable", &format!("test{i:04}"), None, &Ok(())).await;
        }
        log_action(&pool, "bob", "user.disable", "Administrator", None, &Err("It is EasyDC's own account".into())).await;

        let (page, total) = search_audit(&pool, "", false, 100, 0).await.unwrap();
        assert_eq!((page.len(), total), (100, 252));
        assert_eq!(page[0].target, "Administrator", "newest first");

        // Behind 251 newer entries, and still found.
        let (found, total) = search_audit(&pool, "GROUP.create fin", false, 100, 0).await.unwrap();
        assert_eq!((found.len(), total), (1, 1));
        assert_eq!(found[0].actor, "alice");

        let (failed, total) = search_audit(&pool, "", true, 100, 0).await.unwrap();
        assert_eq!((failed[0].target.as_str(), total), ("Administrator", 1));
        assert_eq!(search_audit(&pool, "own account", false, 100, 0).await.unwrap().1, 1, "the reason is searched");

        let (last, _) = search_audit(&pool, "", false, 100, 200).await.unwrap();
        assert_eq!(last.len(), 52);
        assert_eq!(last.last().unwrap().target, "Finance");
        // A % or _ is an ordinary character, not a wildcard.
        assert_eq!(search_audit(&pool, "%", false, 100, 0).await.unwrap().1, 0);
    }

    async fn add(pool: &SqlitePool, name: &str) {
        create_account(pool, name, "hash", true, &Default::default()).await.unwrap();
    }

    fn areas(list: &[crate::access::Area]) -> std::collections::BTreeSet<crate::access::Area> {
        list.iter().copied().collect()
    }

    #[tokio::test]
    async fn the_last_admin_cannot_be_deleted() {
        let pool = pool().await;
        add(&pool, "alice").await;
        create_account(&pool, "viewer", "hash", false, &Default::default()).await.unwrap();
        assert!(!delete_account(&pool, "alice").await.unwrap());
        assert!(account_exists(&pool, "alice").await);
        // An account that is not an admin can go, even with a single admin.
        assert!(delete_account(&pool, "viewer").await.unwrap());
    }

    #[tokio::test]
    async fn the_last_admin_cannot_lose_admin() {
        use crate::access::Area;
        let pool = pool().await;
        add(&pool, "alice").await;
        assert!(!set_permissions(&pool, "alice", false, &areas(&[Area::Users])).await.unwrap());
        let a = access_for(&pool, "alice").await.unwrap().unwrap();
        assert!(a.admin && a.edit.is_empty(), "nothing changed: {a:?}");

        add(&pool, "bob").await;
        assert!(set_permissions(&pool, "alice", false, &areas(&[Area::Users, Area::Gpos])).await.unwrap());
        let a = access_for(&pool, "alice").await.unwrap().unwrap();
        assert!(!a.admin);
        assert_eq!(a.edit, areas(&[Area::Users, Area::Gpos]));
        assert!(!set_permissions(&pool, "bob", false, &Default::default()).await.unwrap(), "bob is the last admin now");
    }

    #[tokio::test]
    async fn permissions_are_kept_and_go_with_the_account() {
        use crate::access::Area;
        let pool = pool().await;
        add(&pool, "alice").await;
        create_account(&pool, "helpdesk", "hash", false, &areas(&[Area::Users, Area::Groups])).await.unwrap();
        let listed = list_accounts(&pool).await.unwrap();
        let h = listed.iter().find(|a| a.username == "helpdesk").unwrap();
        assert_eq!((h.admin, h.edit.clone(), h.summary.as_str()), (false, vec!["users", "groups"], "Edit: Users, Groups"));
        assert_eq!(access_for(&pool, "nobody").await.unwrap(), None);

        assert!(delete_account(&pool, "helpdesk").await.unwrap());
        // A new account with the same name starts from nothing.
        create_account(&pool, "helpdesk", "hash", false, &Default::default()).await.unwrap();
        assert!(access_for(&pool, "helpdesk").await.unwrap().unwrap().edit.is_empty());
    }

    #[tokio::test]
    async fn a_local_admin_always_remains() {
        let pool = pool().await;
        add(&pool, "alice").await;
        create_domain_account(&pool, "ann@lab.test", "ann", 2, true, &Default::default()).await.unwrap();
        // Two admins, but only alice can sign in while the DC is down.
        assert!(!delete_account(&pool, "alice").await.unwrap());
        assert!(!set_permissions(&pool, "alice", false, &Default::default()).await.unwrap());
        // The domain admin can go, or lose admin.
        assert!(set_permissions(&pool, "ann@lab.test", false, &Default::default()).await.unwrap());
        assert!(delete_account(&pool, "ann@lab.test").await.unwrap());
    }

    #[tokio::test]
    async fn sign_in_finds_the_account_behind_what_was_typed() {
        let pool = pool().await;
        add(&pool, "alice").await;
        create_domain_account(&pool, "Ann@lab.test", "Ann", 2, false, &Default::default()).await.unwrap();
        create_domain_account(&pool, "bob@lab.test", "bob", 2, false, &Default::default()).await.unwrap();
        create_domain_account(&pool, "bob@other.test", "bob", 3, false, &Default::default()).await.unwrap();
        create_domain_account(&pool, "alice@lab.test", "alice", 2, false, &Default::default()).await.unwrap();
        let domain = |name: &str| match name {
            "" => None,
            n => Some(n.to_string()),
        };
        let who = |s: Option<SignIn>| match s {
            Some(SignIn::Local { username, .. }) => domain(&format!("local {username}")),
            Some(SignIn::Domain { username, domain_user, server_id }) => {
                domain(&format!("{username} as {domain_user} on {}", server_id.unwrap()))
            }
            None => None,
        };
        assert_eq!(who(sign_in_account(&pool, "alice").await).as_deref(), Some("local alice"));
        assert_eq!(who(sign_in_account(&pool, "ann@LAB.TEST").await).as_deref(), Some("Ann@lab.test as Ann on 2"));
        assert_eq!(who(sign_in_account(&pool, "ann").await).as_deref(), Some("Ann@lab.test as Ann on 2"));
        assert_eq!(who(sign_in_account(&pool, "LAB\\ann").await).as_deref(), Some("Ann@lab.test as Ann on 2"));
        assert_eq!(who(sign_in_account(&pool, "bob").await), None, "two domains have a bob: say which");
        assert_eq!(who(sign_in_account(&pool, "bob@other.test").await).as_deref(), Some("bob@other.test as bob on 3"));
        assert_eq!(who(sign_in_account(&pool, "Alice").await), None, "a local alice exists: no guessing");
        assert_eq!(who(sign_in_account(&pool, "nobody").await), None);
        // A local name is exact, as before.
        assert_eq!(who(sign_in_account(&pool, "ALICE@lab.test").await).as_deref(), Some("alice@lab.test as alice on 2"));
    }

    /// Before permissions, every account was a full administrator; upgrading
    /// must not take that away from anyone, nor hand it to later accounts.
    #[tokio::test]
    async fn existing_accounts_stay_admins_on_upgrade() {
        let path = std::env::temp_dir().join(format!("easydc-test-{}.db", uuid::Uuid::new_v4()));
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", path.display()))
            .unwrap()
            .create_if_missing(true);
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        sqlx::query("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO users (username, password_hash) VALUES ('alice', 'h'), ('bob', 'h')")
            .execute(&pool)
            .await
            .unwrap();
        init_tables(&pool).await.unwrap();
        for name in ["alice", "bob"] {
            assert!(access_for(&pool, name).await.unwrap().unwrap().admin, "{name}");
        }
        // Starting again does not make a later account an admin.
        create_account(&pool, "carol", "h", false, &Default::default()).await.unwrap();
        init_tables(&pool).await.unwrap();
        assert!(!access_for(&pool, "carol").await.unwrap().unwrap().admin);
    }

    /// The race the review found: two administrators deleting each other at
    /// once both passed a separate count check and left no accounts, which
    /// reopens /setup. Run it many times with real concurrent connections.
    #[tokio::test]
    async fn concurrent_deletions_never_remove_every_administrator() {
        let pool = pool().await;
        for round in 0..25 {
            add(&pool, "alice").await;
            add(&pool, "bob").await;
            let (a, b) = tokio::join!(delete_account(&pool, "bob"), delete_account(&pool, "alice"));
            let removed = [a.unwrap(), b.unwrap()].iter().filter(|r| **r).count();
            let left = list_accounts(&pool).await.unwrap();
            assert_eq!(removed, 1, "round {}: exactly one deletion may succeed", round);
            assert_eq!(left.len(), 1, "round {}: one administrator must remain, got {:?}", round, left);
            sqlx::query("DELETE FROM users").execute(&pool).await.unwrap();
        }
    }

    /// Existence for delete is exact, matching login and the DELETE itself;
    /// look-alike names are only refused at creation.
    #[tokio::test]
    async fn existence_is_exact_but_look_alikes_are_caught() {
        let pool = pool().await;
        add(&pool, "alice").await;
        add(&pool, "bob").await;
        assert!(!account_exists(&pool, "Alice").await);
        assert!(account_name_taken(&pool, "Alice").await);
        // A differently-cased delete removes nothing, and says so.
        assert!(!delete_account(&pool, "Alice").await.unwrap());
        assert!(account_exists(&pool, "alice").await);
    }

    /// Sessions from before usernames were recorded cannot be ended by a
    /// password change, so startup removes them.
    #[tokio::test]
    async fn unattributable_sessions_are_dropped_at_startup() {
        let pool = pool().await;
        sqlx::query("INSERT INTO sessions (token, created_at, username) VALUES ('legacy', 0, NULL)")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO sessions (token, created_at, username) VALUES ('current', ?, 'alice')")
            .bind(unix_now())
            .execute(&pool)
            .await
            .unwrap();
        init_tables(&pool).await.unwrap();
        assert_eq!(username_for_token(&pool, "legacy").await, None);
        assert_eq!(username_for_token(&pool, "current").await.as_deref(), Some("alice"));
        let legacy_left: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sessions WHERE token = 'legacy'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(legacy_left, 0);
    }

    /// Startup clears sessions past either limit and keeps live ones; sessions
    /// from before last_seen existed count from their sign-in.
    #[tokio::test]
    async fn expired_sessions_are_purged_at_startup() {
        let pool = pool().await;
        let now = unix_now();
        for (token, created, seen) in [
            ("live", now - 3600, Some(now - 60)),
            ("idle", now - 10 * 3600, Some(now - 9 * 3600)),
            ("old", now - 25 * 3600, Some(now - 60)),
            ("legacy_recent", now - 3600, None),
            ("legacy_stale", now - 9 * 3600, None),
        ] {
            sqlx::query("INSERT INTO sessions (token, created_at, username, last_seen) VALUES (?, ?, 'alice', ?)")
                .bind(token)
                .bind(created)
                .bind(seen)
                .execute(&pool)
                .await
                .unwrap();
        }
        init_tables(&pool).await.unwrap();
        let mut left: Vec<String> = sqlx::query_scalar("SELECT token FROM sessions")
            .fetch_all(&pool)
            .await
            .unwrap();
        left.sort();
        assert_eq!(left, ["legacy_recent", "live"]);
        let seen: i64 = sqlx::query_scalar("SELECT last_seen FROM sessions WHERE token = 'legacy_recent'")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(seen, now - 3600);
    }
}
