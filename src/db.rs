use sqlx::sqlite::SqlitePool;

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

    Ok(())
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

/// Fetch the most recent audit entries (newest first), capped at `limit`.
pub async fn recent_audit(
    pool: &SqlitePool,
    limit: i64,
) -> Result<Vec<crate::models::AuditEntry>, sqlx::Error> {
    sqlx::query_as::<_, crate::models::AuditEntry>(
        "SELECT a.id, a.ts, a.actor, a.action, a.target, a.server_id,
                s.name AS server_name, a.result, a.detail
         FROM audit_log a
         LEFT JOIN servers s ON s.id = a.server_id
         ORDER BY a.id DESC
         LIMIT ?",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
}

// ── session ↔ user lookup ──────────────────────────────────────────────────────

/// Resolve the username that owns a given session token, if any.
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

// ── EasyDC administrator accounts ─────────────────────────────────────────────

/// Every administrator username, alphabetically.
pub async fn list_admins(pool: &SqlitePool) -> Result<Vec<String>, sqlx::Error> {
    use sqlx::Row;
    let rows = sqlx::query("SELECT username FROM users ORDER BY username COLLATE NOCASE")
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(|r| r.get::<String, _>("username")).collect())
}

pub async fn admin_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    use sqlx::Row;
    let row = sqlx::query("SELECT COUNT(*) AS count FROM users")
        .fetch_one(pool)
        .await?;
    Ok(row.get::<i64, _>("count"))
}

pub async fn admin_exists(pool: &SqlitePool, username: &str) -> bool {
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

pub async fn create_admin(
    pool: &SqlitePool,
    username: &str,
    hash: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO users (username, password_hash) VALUES (?, ?)")
        .bind(username)
        .bind(hash)
        .execute(pool)
        .await
        .map(|_| ())
}

pub async fn delete_admin(pool: &SqlitePool, username: &str) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM users WHERE username = ?")
        .bind(username)
        .execute(pool)
        .await
        .map(|_| ())
}

/// Drop an account's sessions, optionally sparing one token. Used to sign a
/// deleted administrator out everywhere, and to leave only the current browser
/// signed in after a password change.
pub async fn delete_sessions_for(pool: &SqlitePool, username: &str, except: Option<&str>) {
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
