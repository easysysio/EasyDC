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

    let count_sql = format!("SELECT COUNT(*){from}{filter}");
    let mut count = sqlx::query_scalar::<_, i64>(&count_sql);
    for w in &words {
        count = count.bind(w);
    }
    let total = count.fetch_one(pool).await?;

    let page_sql = format!(
        "SELECT a.id, a.ts, a.actor, a.action, a.target, a.server_id,
                s.name AS server_name, a.result, a.detail{from}{filter}
         ORDER BY a.id DESC LIMIT ? OFFSET ?"
    );
    let mut page = sqlx::query_as::<_, crate::models::AuditEntry>(&page_sql);
    for w in &words {
        page = page.bind(w);
    }
    let entries = page.bind(limit).bind(offset).fetch_all(pool).await?;
    Ok((entries, total))
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

/// Exact match, the same comparison login and delete use.
pub async fn admin_exists(pool: &SqlitePool, username: &str) -> bool {
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
pub async fn admin_name_taken(pool: &SqlitePool, username: &str) -> bool {
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

/// Delete an administrator unless they are the last one, in a single
/// statement. Returns whether a row was removed.
///
/// The count is part of the DELETE rather than a check before it: two
/// administrators deleting each other at the same moment would otherwise both
/// see a count of two, both succeed, and leave no accounts — at which point
/// /setup is open to anyone.
pub async fn delete_admin(pool: &SqlitePool, username: &str) -> Result<bool, sqlx::Error> {
    sqlx::query(
        "DELETE FROM users WHERE username = ? AND (SELECT COUNT(*) FROM users) > 1",
    )
    .bind(username)
    .execute(pool)
    .await
    .map(|r| r.rows_affected() > 0)
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
        create_admin(pool, name, "hash").await.unwrap();
    }

    #[tokio::test]
    async fn the_last_administrator_cannot_be_deleted() {
        let pool = pool().await;
        add(&pool, "alice").await;
        assert!(!delete_admin(&pool, "alice").await.unwrap());
        assert!(admin_exists(&pool, "alice").await);
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
            let (a, b) = tokio::join!(delete_admin(&pool, "bob"), delete_admin(&pool, "alice"));
            let removed = [a.unwrap(), b.unwrap()].iter().filter(|r| **r).count();
            let left = list_admins(&pool).await.unwrap();
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
        assert!(!admin_exists(&pool, "Alice").await);
        assert!(admin_name_taken(&pool, "Alice").await);
        // A differently-cased delete removes nothing, and says so.
        assert!(!delete_admin(&pool, "Alice").await.unwrap());
        assert!(admin_exists(&pool, "alice").await);
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
