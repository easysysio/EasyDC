//! How long the audit log is kept, and rotating out what is older.
//!
//! By default nothing is ever removed. Once an admin sets a time, entries
//! older than that leave the database, one whole UTC day at a time, into a
//! compressed CSV file per day in `audit-archive/` next to `easydc.db`. A day
//! is deleted from the database only after its file is safely on disk, so a
//! full disk stops the rotation instead of losing entries.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};

use flate2::{write::GzEncoder, Compression};
use serde::Serialize;
use sqlx::SqlitePool;

use crate::{
    csv, db,
    health::{civil_from_days, days_from_civil},
    models::AuditEntry,
};

/// In EasyDC's data folder, its working directory.
pub const ARCHIVE_DIR: &str = "audit-archive";

const DAY: i64 = 86_400;
const CHECK_EVERY: Duration = Duration::from_secs(3_600);
const KEEP_KEY: &str = "audit_keep_days";
const FILES_KEY: &str = "audit_file_days";

/// `file_days` for "delete old entries, with no file".
pub const NO_FILES: i64 = -1;

/// Days an entry stays in the log. 0 is forever.
pub const KEEP_CHOICES: [(i64, &str); 6] =
    [(0, "Forever"), (30, "30 days"), (90, "90 days"), (180, "6 months"), (365, "1 year"), (730, "2 years")];

/// Days, from the entries' date, before a rotated file is deleted. 0 is never.
pub const FILE_CHOICES: [(i64, &str); 7] = [
    (0, "Keep them forever"),
    (365, "Delete after 1 year"),
    (730, "Delete after 2 years"),
    (1095, "Delete after 3 years"),
    (1825, "Delete after 5 years"),
    (2555, "Delete after 7 years"),
    (NO_FILES, "Don't make files: delete old entries"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize)]
pub struct Retention {
    pub keep_days: i64,
    pub file_days: i64,
}

impl Retention {
    fn check(self) -> Result<Self, String> {
        if !KEEP_CHOICES.iter().any(|c| c.0 == self.keep_days) || !FILE_CHOICES.iter().any(|c| c.0 == self.file_days) {
            return Err("Choose how long to keep the log from the list.".to_string());
        }
        if self.keep_days > 0 && self.file_days > 0 && self.file_days <= self.keep_days {
            return Err("Rotated files must be kept longer than entries stay in the log.".to_string());
        }
        Ok(self)
    }

    /// For the audit log itself, and the Audit Log page.
    pub fn describe(self) -> String {
        let label = |choices: &[(i64, &'static str)], days| choices.iter().find(|c| c.0 == days).map_or("?", |c| c.1);
        if self.keep_days == 0 {
            return "keep forever".to_string();
        }
        let files = match self.file_days {
            NO_FILES => "no files".to_string(),
            0 => "files kept forever".to_string(),
            d => format!("files: {}", label(&FILE_CHOICES, d).to_lowercase()),
        };
        format!("keep {}, {files}", label(&KEEP_CHOICES, self.keep_days))
    }
}

/// An unreadable or unknown setting is an error, so nothing gets removed
/// because of it.
pub async fn load(pool: &SqlitePool) -> Result<Retention, String> {
    let read = |key: &'static str| async move {
        let value: Option<String> = sqlx::query_scalar("SELECT value FROM app_settings WHERE key = ?")
            .bind(key)
            .fetch_optional(pool)
            .await
            .map_err(|e| format!("Could not read the audit log setting: {e}"))?;
        value.map_or(Ok(0), |v| v.parse::<i64>().map_err(|_| format!("The saved audit log setting is not valid: {v}")))
    };
    Retention { keep_days: read(KEEP_KEY).await?, file_days: read(FILES_KEY).await? }.check()
}

pub async fn save(pool: &SqlitePool, r: Retention) -> Result<(), String> {
    let r = r.check()?;
    let failed = |e: sqlx::Error| format!("Could not save the setting: {e}");
    let mut tx = pool.begin().await.map_err(failed)?;
    for (key, value) in [(KEEP_KEY, r.keep_days), (FILES_KEY, r.file_days)] {
        sqlx::query(
            "INSERT INTO app_settings (key, value) VALUES (?, ?)
             ON CONFLICT (key) DO UPDATE SET value = excluded.value",
        )
        .bind(key)
        .bind(value.to_string())
        .execute(&mut *tx)
        .await
        .map_err(failed)?;
    }
    tx.commit().await.map_err(failed)
}

fn start_of_day(ts: i64) -> i64 {
    ts.div_euclid(DAY) * DAY
}

fn date(ts: i64) -> String {
    let (y, m, d) = civil_from_days(ts.div_euclid(DAY));
    format!("{y:04}-{m:02}-{d:02}")
}

/// The start of the day a rotated file holds, if the name is one of ours:
/// `audit-2026-11-23.csv.gz`, or `audit-2026-11-23-2.csv.gz`. It is also what
/// keeps a download inside the archive folder.
pub fn file_day(name: &str) -> Option<i64> {
    let middle = name.strip_prefix("audit-")?.strip_suffix(".csv.gz")?;
    let day = middle.get(..10)?;
    match middle.get(10..)? {
        "" => {}
        rest => {
            let n = rest.strip_prefix('-')?;
            if n.is_empty() || n.starts_with('0') || n.len() > 6 || !n.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
        }
    }
    let b = day.as_bytes();
    let digits = [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&i| b[i].is_ascii_digit());
    if !digits || b[4] != b'-' || b[7] != b'-' {
        return None;
    }
    let (y, m, d) = (day[..4].parse().ok()?, day[5..7].parse().ok()?, day[8..].parse().ok()?);
    let days = days_from_civil(y, m, d);
    // 2026-02-31 does not come back as itself.
    (civil_from_days(days) == (y, m, d)).then_some(days * DAY)
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchiveFile {
    pub name: String,
    pub date: String,
    pub size: String,
    #[serde(skip)]
    pub day: i64,
}

fn size_text(bytes: u64) -> String {
    match bytes {
        b if b < 1024 => format!("{b} B"),
        b if b < 1024 * 1024 => format!("{:.1} KB", b as f64 / 1024.0),
        b => format!("{:.1} MB", b as f64 / (1024.0 * 1024.0)),
    }
}

/// The rotated files, newest first. No folder yet is no files.
pub fn list_files(dir: &Path) -> Result<Vec<ArchiveFile>, String> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("Could not read {}: {e}", dir.display())),
    };
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(day) = file_day(&name) else { continue };
        let Ok(meta) = entry.metadata() else { continue };
        if meta.is_file() {
            files.push(ArchiveFile { date: date(day), size: size_text(meta.len()), name, day });
        }
    }
    files.sort_by(|a, b| b.day.cmp(&a.day).then_with(|| b.name.cmp(&a.name)));
    Ok(files)
}

/// One day's entries as CSV. The server's name is written out because the
/// server may be removed from EasyDC later.
fn to_csv(rows: &[AuditEntry]) -> String {
    let mut out = String::from(csv::BOM);
    csv::write_row(&mut out, &["id", "time_utc", "actor", "action", "target", "server", "result", "detail"]);
    for e in rows {
        let (y, m, d) = civil_from_days(e.ts.div_euclid(DAY));
        let s = e.ts.rem_euclid(DAY);
        let time = format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}", s / 3600, s % 3600 / 60, s % 60);
        let server = e.server_name.clone().or(e.server_id.map(|id| format!("#{id}"))).unwrap_or_default();
        csv::write_row(
            &mut out,
            &[&e.id.to_string(), &time, &e.actor, &e.action, &e.target, &server, &e.result, e.detail.as_deref().unwrap_or("")],
        );
    }
    out
}

fn private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

fn private_file(path: &Path) -> std::io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    options.open(path)
}

/// Write the day's file, whole and flushed to disk, under a name not in use.
/// A second file for a day happens if EasyDC stopped between writing a file
/// and deleting its entries, or the clock was moved back.
fn write_day(dir: &Path, day: i64, text: &str) -> std::io::Result<PathBuf> {
    private_dir(dir)?;
    let temp = dir.join(format!(".tmp-{}", uuid::Uuid::new_v4()));
    let written = (|| {
        let mut gz = GzEncoder::new(private_file(&temp)?, Compression::default());
        gz.write_all(text.as_bytes())?;
        gz.finish()?.sync_all()?;
        let stem = format!("audit-{}", date(day));
        let mut path = dir.join(format!("{stem}.csv.gz"));
        let mut n = 2;
        // Only one rotation runs at a time, so a free name stays free.
        while path.exists() {
            path = dir.join(format!("{stem}-{n}.csv.gz"));
            n += 1;
        }
        fs::rename(&temp, &path)?;
        if let Ok(folder) = fs::File::open(dir) {
            let _ = folder.sync_all();
        }
        Ok(path)
    })();
    let _ = fs::remove_file(&temp);
    written
}

/// What one rotation did, and why it stopped if it did not finish.
#[derive(Debug, Default, PartialEq)]
pub struct Rotated {
    pub entries: u64,
    pub files_deleted: u64,
    /// Entries went into files, rather than being deleted.
    pub to_files: bool,
    pub error: Option<String>,
}

impl Rotated {
    pub fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.entries > 0 {
            let what = if self.entries == 1 { "entry" } else { "entries" };
            let how = if self.to_files { format!("moved to {ARCHIVE_DIR}") } else { "deleted".to_string() };
            parts.push(format!("{} {what} {how}", self.entries));
        }
        if self.files_deleted > 0 {
            let what = if self.files_deleted == 1 { "file" } else { "files" };
            parts.push(format!("{} old {what} deleted", self.files_deleted));
        }
        parts.join(", ")
    }
}

// One at a time: saving the setting and the hourly check may coincide.
static ROTATING: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn rotate_days(pool: &SqlitePool, dir: &Path, r: Retention, cutoff: i64, done: &mut Rotated) -> Result<(), String> {
    let failed = |e: sqlx::Error| format!("Could not rotate the audit log: {e}");
    loop {
        let oldest: Option<i64> = sqlx::query_scalar("SELECT MIN(ts) FROM audit_log WHERE ts < ?")
            .bind(cutoff)
            .fetch_one(pool)
            .await
            .map_err(failed)?;
        let Some(oldest) = oldest else { return Ok(()) };
        let day = start_of_day(oldest);
        let rows = sqlx::query_as::<_, AuditEntry>(
            "SELECT a.id, a.ts, a.actor, a.action, a.target, a.server_id,
                    s.name AS server_name, a.result, a.detail
             FROM audit_log a LEFT JOIN servers s ON s.id = a.server_id
             WHERE a.ts >= ? AND a.ts < ? ORDER BY a.id",
        )
        .bind(day)
        .bind(day + DAY)
        .fetch_all(pool)
        .await
        .map_err(failed)?;
        let Some(last_id) = rows.last().map(|e| e.id) else {
            return Err("Could not rotate the audit log: the oldest day has no entries.".to_string());
        };
        if r.file_days != NO_FILES {
            let (folder, text) = (dir.to_path_buf(), to_csv(&rows));
            tokio::task::spawn_blocking(move || write_day(&folder, day, &text))
                .await
                .map_err(|e| format!("Could not write the rotated file: {e}"))?
                .map_err(|e| format!("Could not write the rotated file in {}: {e}. Nothing was removed from the log.", dir.display()))?;
        }
        // Only what went into the file: an entry written since then stays.
        let gone = sqlx::query("DELETE FROM audit_log WHERE ts >= ? AND ts < ? AND id <= ?")
            .bind(day)
            .bind(day + DAY)
            .bind(last_id)
            .execute(pool)
            .await
            .map_err(failed)?
            .rows_affected();
        if gone == 0 {
            return Err("Could not rotate the audit log: its entries could not be removed.".to_string());
        }
        done.entries += gone;
    }
}

/// Move entries past their time out of the log, and delete files past theirs.
/// With the log kept forever, this touches nothing.
pub async fn rotate(pool: &SqlitePool, dir: &Path, now: i64) -> Rotated {
    let _one_at_a_time = ROTATING.lock().await;
    let mut done = Rotated::default();
    let r = match load(pool).await {
        Ok(r) => r,
        Err(e) => {
            done.error = Some(e);
            return done;
        }
    };
    if r.keep_days == 0 {
        return done;
    }
    done.to_files = r.file_days != NO_FILES;
    let today = start_of_day(now);
    if let Err(e) = rotate_days(pool, dir, r, today - r.keep_days * DAY, &mut done).await {
        done.error = Some(e);
    }
    if r.file_days > 0 {
        let cutoff = today - r.file_days * DAY;
        match list_files(dir) {
            Ok(files) => {
                for f in files.iter().filter(|f| f.day < cutoff) {
                    match fs::remove_file(dir.join(&f.name)) {
                        Ok(()) => done.files_deleted += 1,
                        Err(e) => done.error = done.error.take().or(Some(format!("Could not delete {}: {e}", f.name))),
                    }
                }
            }
            Err(e) => done.error = done.error.take().or(Some(e)),
        }
    }
    done
}

/// Write what a rotation did to the audit log.
pub async fn record(pool: &SqlitePool, actor: &str, done: &Rotated) {
    let summary = done.summary();
    if !summary.is_empty() {
        db::log_action(pool, actor, "audit.rotate", &summary, None, &Ok(())).await;
    }
    if let Some(e) = &done.error {
        db::log_action(pool, actor, "audit.rotate", ARCHIVE_DIR, None, &Err(e.clone())).await;
    }
}

/// Runs for as long as EasyDC does. A failure that keeps repeating is
/// recorded once, not every hour.
pub async fn keep_rotating(pool: SqlitePool) {
    let dir = Path::new(ARCHIVE_DIR);
    let mut last_error = None;
    loop {
        let mut done = rotate(&pool, dir, db::unix_now()).await;
        if done.error.is_some() && done.error == last_error {
            done.error = None;
        } else {
            last_error = done.error.clone();
        }
        if let Some(e) = &done.error {
            eprintln!("EasyDC: {e}");
        }
        record(&pool, "EasyDC", &done).await;
        tokio::time::sleep(CHECK_EVERY).await;
    }
}

/// For the Settings page: how much each choice would remove right now.
pub async fn preview(pool: &SqlitePool, files: &[ArchiveFile], now: i64) -> (Vec<serde_json::Value>, Vec<serde_json::Value>) {
    let today = start_of_day(now);
    let mut keep = Vec::new();
    for (days, label) in KEEP_CHOICES {
        let older: i64 = if days == 0 {
            0
        } else {
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_log WHERE ts < ?")
                .bind(today - days * DAY)
                .fetch_one(pool)
                .await
                .unwrap_or(0)
        };
        keep.push(serde_json::json!({ "days": days, "label": label, "older": older }));
    }
    let file_choices = FILE_CHOICES
        .iter()
        .map(|&(days, label)| {
            let expired = if days > 0 { files.iter().filter(|f| f.day < today - days * DAY).count() } else { 0 };
            serde_json::json!({ "days": days, "label": label, "expired": expired })
        })
        .collect();
    (keep, file_choices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::read::MultiGzDecoder;
    use std::io::Read;

    // 2026-11-23 12:00 UTC.
    const NOW: i64 = 1_795_435_200;

    struct Scratch {
        pool: SqlitePool,
        root: PathBuf,
    }

    impl Scratch {
        async fn new() -> Self {
            let root = std::env::temp_dir().join(format!("easydc-audit-{}", uuid::Uuid::new_v4()));
            fs::create_dir_all(&root).unwrap();
            let url = format!("sqlite://{}?mode=rwc", root.join("t.db").display());
            let pool = SqlitePool::connect(&url).await.unwrap();
            db::init_tables(&pool).await.unwrap();
            Self { pool, root }
        }
        fn dir(&self) -> PathBuf {
            self.root.join(ARCHIVE_DIR)
        }
        async fn entry(&self, ts: i64, target: &str) {
            sqlx::query("INSERT INTO audit_log (ts, actor, action, target, result) VALUES (?, 'ann', 'user.create', ?, 'success')")
                .bind(ts)
                .bind(target)
                .execute(&self.pool)
                .await
                .unwrap();
        }
        async fn left(&self) -> Vec<String> {
            sqlx::query_scalar("SELECT target FROM audit_log ORDER BY id").fetch_all(&self.pool).await.unwrap()
        }
        fn read(&self, name: &str) -> String {
            let mut text = String::new();
            MultiGzDecoder::new(fs::File::open(self.dir().join(name)).unwrap()).read_to_string(&mut text).unwrap();
            text
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_test_clock_is_what_it_says() {
        assert_eq!(date(NOW), "2026-11-23");
    }

    #[tokio::test]
    async fn by_default_nothing_is_ever_removed() {
        let s = Scratch::new().await;
        s.entry(1_000, "very old").await;
        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!(done, Rotated::default());
        assert_eq!(s.left().await, ["very old"]);
        assert!(!s.dir().exists());
    }

    #[tokio::test]
    async fn old_days_move_to_files_and_new_entries_stay() {
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: 0 }).await.unwrap();
        let cutoff = start_of_day(NOW) - 30 * DAY;
        s.entry(cutoff - DAY - 5, "=two days out").await;
        s.entry(cutoff - 1, "last second out").await;
        s.entry(cutoff - 2, "same day").await;
        s.entry(cutoff, "first second kept").await;
        s.entry(NOW, "today").await;

        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!((done.entries, done.error.clone()), (3, None));
        assert_eq!(s.left().await, ["first second kept", "today"]);

        let files = list_files(&s.dir()).unwrap();
        assert_eq!(files.iter().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["audit-2026-10-23.csv.gz", "audit-2026-10-22.csv.gz"]);
        let day = s.read("audit-2026-10-22.csv.gz");
        assert!(day.starts_with(csv::BOM) && day.contains("id,time_utc,actor"));
        assert!(day.contains("'=two days out"), "a spreadsheet does not run it");
        assert!(s.read("audit-2026-10-23.csv.gz").contains("2026-10-23 23:59:59"));

        assert_eq!(rotate(&s.pool, &s.dir(), NOW).await.entries, 0, "a second run has nothing to do");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn rotated_files_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: 0 }).await.unwrap();
        s.entry(1_000, "old").await;
        rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!(fs::metadata(s.dir()).unwrap().permissions().mode() & 0o777, 0o700);
        let file = s.dir().join("audit-1970-01-01.csv.gz");
        assert_eq!(fs::metadata(file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn a_failed_write_loses_nothing() {
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: 0 }).await.unwrap();
        s.entry(1_000, "old").await;
        fs::write(s.dir(), "a file where the folder should be").unwrap();
        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!(done.entries, 0);
        assert!(done.error.unwrap().contains("Nothing was removed"));
        assert_eq!(s.left().await, ["old"]);
    }

    #[tokio::test]
    async fn a_day_already_on_disk_is_never_overwritten() {
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: 0 }).await.unwrap();
        s.entry(1_000, "first").await;
        rotate(&s.pool, &s.dir(), NOW).await;
        s.entry(2_000, "second").await;
        rotate(&s.pool, &s.dir(), NOW).await;
        assert!(s.read("audit-1970-01-01.csv.gz").contains("first"));
        assert!(s.read("audit-1970-01-01-2.csv.gz").contains("second"));
    }

    #[tokio::test]
    async fn with_no_files_old_entries_are_deleted() {
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: NO_FILES }).await.unwrap();
        s.entry(1_000, "old").await;
        s.entry(NOW, "today").await;
        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!((done.entries, done.to_files), (1, false));
        assert_eq!(done.summary(), "1 entry deleted");
        assert_eq!(s.left().await, ["today"]);
        assert!(!s.dir().exists());
    }

    #[tokio::test]
    async fn only_our_own_files_past_their_time_are_deleted() {
        let s = Scratch::new().await;
        save(&s.pool, Retention { keep_days: 30, file_days: 365 }).await.unwrap();
        fs::create_dir_all(s.dir()).unwrap();
        for name in ["audit-2025-01-01.csv.gz", "audit-2025-01-01-2.csv.gz", "audit-2026-11-01.csv.gz", "notes.txt", "audit-backup.csv.gz"] {
            fs::write(s.dir().join(name), "x").unwrap();
        }
        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert_eq!((done.files_deleted, done.error), (2, None));
        assert!(!s.dir().join("audit-2025-01-01.csv.gz").exists());
        for name in ["audit-2026-11-01.csv.gz", "notes.txt", "audit-backup.csv.gz"] {
            assert!(s.dir().join(name).exists(), "{name}");
        }
    }

    #[tokio::test]
    async fn settings_are_checked_and_a_broken_one_removes_nothing() {
        let s = Scratch::new().await;
        assert_eq!(load(&s.pool).await.unwrap(), Retention::default());
        assert!(save(&s.pool, Retention { keep_days: 7, file_days: 0 }).await.is_err());
        assert!(save(&s.pool, Retention { keep_days: 30, file_days: 100 }).await.is_err());
        assert!(save(&s.pool, Retention { keep_days: 730, file_days: 365 }).await.is_err(), "files outlive the log");
        assert!(save(&s.pool, Retention { keep_days: 730, file_days: 730 }).await.is_err());
        save(&s.pool, Retention { keep_days: 730, file_days: 1095 }).await.unwrap();
        assert_eq!(load(&s.pool).await.unwrap().file_days, 1095);

        sqlx::query("UPDATE app_settings SET value = 'soon' WHERE key = ?").bind(KEEP_KEY).execute(&s.pool).await.unwrap();
        s.entry(1_000, "old").await;
        let done = rotate(&s.pool, &s.dir(), NOW).await;
        assert!(done.error.is_some());
        assert_eq!(s.left().await, ["old"]);
    }

    #[test]
    fn only_real_file_names_are_accepted() {
        assert_eq!(file_day("audit-1970-01-02.csv.gz"), Some(DAY));
        assert_eq!(file_day("audit-1970-01-02-12.csv.gz"), Some(DAY));
        for bad in [
            "../easydc.db",
            "audit-../../etc.csv.gz",
            "audit-2026-02-31.csv.gz",
            "audit-2026-13-01.csv.gz",
            "audit-2026-11-23-0.csv.gz",
            "audit-2026-11-23-.csv.gz",
            "audit-2026-11-23-2/x.csv.gz",
            "audit-2026-11-23.csv",
            "audit-20261123aa.csv.gz",
            "audit-é026-11-2.csv.gz",
        ] {
            assert_eq!(file_day(bad), None, "{bad}");
        }
    }

    #[test]
    fn what_it_did_reads_well() {
        let d = |entries, files_deleted, to_files| Rotated { entries, files_deleted, to_files, error: None }.summary();
        assert_eq!(d(12, 0, true), "12 entries moved to audit-archive");
        assert_eq!(d(1, 1, true), "1 entry moved to audit-archive, 1 old file deleted");
        assert_eq!(d(0, 3, true), "3 old files deleted");
        assert_eq!(d(0, 0, true), "");
    }
}
