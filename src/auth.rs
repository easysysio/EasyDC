use axum::{
    extract::{FromRequestParts, MatchedPath, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
    Json,
};
use sqlx::Row;

use crate::{
    access::{self, Need},
    db, AppState,
};

// ── session lifetime ────────────────────────────────────────────────────────────

/// A session ends after this long without a request…
pub const IDLE_TIMEOUT: i64 = 8 * 3600;
/// …and this long after sign-in, however busy it has been.
pub const MAX_SESSION_AGE: i64 = 24 * 3600;
/// `last_seen` is written at most this often, not on every request.
const TOUCH_INTERVAL: i64 = 60;

#[derive(Debug, PartialEq)]
pub enum SessionState {
    /// `touch`: update `last_seen` to now.
    Valid { touch: bool },
    Expired,
}

pub fn session_state(created_at: i64, last_seen: i64, now: i64) -> SessionState {
    if now - created_at >= MAX_SESSION_AGE || now - last_seen >= IDLE_TIMEOUT {
        SessionState::Expired
    } else {
        SessionState::Valid { touch: now - last_seen >= TOUCH_INTERVAL }
    }
}

// ── passwords ───────────────────────────────────────────────────────────────────

/// bcrypt takes about a quarter of a second, on purpose. It runs on the
/// blocking pool, never on the threads that serve pages, and only a few at a
/// time, so a burst of sign-ins cannot stall EasyDC for everyone else.
static HASHING: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

pub async fn verify_password(password: &str, hash: &str) -> bool {
    let (password, hash) = (password.to_string(), hash.to_string());
    let Ok(_turn) = HASHING.acquire().await else { return false };
    tokio::task::spawn_blocking(move || bcrypt::verify(password, &hash).unwrap_or(false)).await.unwrap_or(false)
}

pub async fn hash_password(password: &str) -> Result<String, String> {
    let password = password.to_string();
    let _turn = HASHING.acquire().await.map_err(|e| e.to_string())?;
    tokio::task::spawn_blocking(move || bcrypt::hash(password, bcrypt::DEFAULT_COST).map_err(|e| e.to_string()))
        .await
        .map_err(|e| e.to_string())?
}

// ── failed sign-ins ─────────────────────────────────────────────────────────────

/// Wrong passwords allowed for one name within FAIL_WINDOW…
const FAILS_ALLOWED: u32 = 5;
const FAIL_WINDOW: i64 = 15 * 60;
/// …before a pause: a minute, doubling each time up to FAIL_PAUSE_MAX. A
/// pause, not a lockout, so someone guessing cannot keep the real admin out
/// for long; an hour without a pause starts over.
const FAIL_PAUSE: i64 = 60;
const FAIL_PAUSE_MAX: i64 = 15 * 60;
/// More names than this and the stale ones are dropped.
const FAILS_KEPT: usize = 10_000;

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Fails {
    count: u32,
    first: i64,
    pauses: u32,
    until: i64,
}

/// Failed sign-ins by the name typed, lowercase, whether or not an account has it.
#[derive(Default)]
pub struct SignInFails(std::collections::HashMap<String, Fails>);

impl SignInFails {
    /// Seconds until this name may try again, if it must wait.
    pub fn paused(&self, name: &str, now: i64) -> Option<i64> {
        self.0.get(&name.to_lowercase()).filter(|f| f.until > now).map(|f| f.until - now)
    }

    pub fn failed(&mut self, name: &str, now: i64) {
        if self.0.len() >= FAILS_KEPT {
            self.0.retain(|_, f| f.until > now || now - f.first < FAIL_WINDOW);
        }
        let f = self.0.entry(name.to_lowercase()).or_insert_with(|| Fails { first: now, ..Fails::default() });
        if f.until != 0 && now - f.until >= 3600 {
            *f = Fails { first: now, ..Fails::default() };
        } else if now - f.first >= FAIL_WINDOW {
            f.count = 0;
            f.first = now;
        }
        f.count += 1;
        if f.count >= FAILS_ALLOWED {
            f.until = now + (FAIL_PAUSE << f.pauses.min(8)).min(FAIL_PAUSE_MAX);
            f.pauses += 1;
            f.count = 0;
            f.first = now;
        }
    }

    pub fn succeeded(&mut self, name: &str) {
        self.0.remove(&name.to_lowercase());
    }
}

pub static SIGN_IN_FAILS: std::sync::LazyLock<std::sync::Mutex<SignInFails>> = std::sync::LazyLock::new(Default::default);

pub fn sign_in_paused(name: &str) -> Option<i64> {
    SIGN_IN_FAILS.lock().map(|f| f.paused(name, db::unix_now())).unwrap_or(None)
}

pub fn sign_in_failed(name: &str) {
    if let Ok(mut f) = SIGN_IN_FAILS.lock() {
        f.failed(name, db::unix_now());
    }
}

pub fn sign_in_succeeded(name: &str) {
    if let Ok(mut f) = SIGN_IN_FAILS.lock() {
        f.succeeded(name);
    }
}

// ── cookie ──────────────────────────────────────────────────────────────────────

pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("session=").map(String::from))
}

/// True when the browser reached EasyDC over HTTPS: directly, where the
/// listener in `tls` sets this header itself, or through a reverse proxy.
/// A client faking it on plain HTTP gains nothing: it skips the redirect and
/// makes its own cookie Secure.
pub fn via_https(headers: &HeaderMap) -> bool {
    let first = |name: &str| {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|v| v.trim().to_ascii_lowercase())
    };
    if first("x-forwarded-proto").as_deref() == Some("https") {
        return true;
    }
    // RFC 7239: Forwarded: for=…;proto=https
    first("forwarded").is_some_and(|v| v.split(';').any(|p| p.trim() == "proto=https"))
}

/// The cookie set at sign-in. No Max-Age: it is a browser-session cookie, and
/// the server enforces the real lifetime.
pub fn session_cookie(token: &str, secure: bool) -> String {
    let mut c = format!("session={}; Path=/; HttpOnly; SameSite=Strict", token);
    if secure {
        c.push_str("; Secure");
    }
    c
}

/// The cookie of a sign-in waiting for its code. Sent only to the sign-in pages.
pub fn challenge_cookie(token: &str, secure: bool) -> String {
    let mut c = format!(
        "easydc_challenge={token}; Path=/login; HttpOnly; SameSite=Strict; Max-Age={}",
        crate::totp::CHALLENGE_SECONDS
    );
    if secure {
        c.push_str("; Secure");
    }
    c
}

pub fn clear_challenge_cookie(secure: bool) -> HeaderValue {
    HeaderValue::from_static(if secure {
        "easydc_challenge=; Path=/login; HttpOnly; SameSite=Strict; Max-Age=0; Secure"
    } else {
        "easydc_challenge=; Path=/login; HttpOnly; SameSite=Strict; Max-Age=0"
    })
}

pub fn extract_challenge_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("easydc_challenge=").map(String::from))
}

pub fn clear_session_cookie(secure: bool) -> HeaderValue {
    HeaderValue::from_static(if secure {
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0; Secure"
    } else {
        "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
    })
}

// ── middleware ──────────────────────────────────────────────────────────────────

pub async fn require_auth(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let Some(token) = extract_session_cookie(request.headers()) else {
        return Redirect::to("/login").into_response();
    };
    let row = sqlx::query("SELECT created_at, last_seen, username FROM sessions WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    let Some(row) = row else {
        return Redirect::to("/login").into_response();
    };

    let created: i64 = row.get("created_at");
    let seen: i64 = row.get::<Option<i64>, _>("last_seen").unwrap_or(created);
    let username: String = row.get::<Option<String>, _>("username").unwrap_or_default();
    let now = db::unix_now();
    // An account removed since sign-in has no permissions left.
    let access = match session_state(created, seen, now) {
        SessionState::Valid { .. } => db::access_for(&state.db, &username).await.ok().flatten(),
        SessionState::Expired => None,
    };
    let Some(access) = access else {
        let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
            .bind(&token)
            .execute(&state.db)
            .await;
        let mut response = Redirect::to("/login?expired=1").into_response();
        response
            .headers_mut()
            .insert(header::SET_COOKIE, clear_session_cookie(via_https(request.headers())));
        return response;
    };
    if let SessionState::Valid { touch: true } = session_state(created, seen, now) {
        let _ = sqlx::query("UPDATE sessions SET last_seen = ? WHERE token = ?")
            .bind(now)
            .bind(&token)
            .execute(&state.db)
            .await;
    }

    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string())
        .unwrap_or_default();
    if access.admin && !open_before_two_factor(&route) && db::must_set_up_two_factor(&state.db, &access.username).await {
        if wants_json(request.headers()) {
            let error = "EasyDC requires two-factor sign-in for admins. Set it up first.";
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": error }))).into_response();
        }
        return Redirect::to("/account/two-factor").into_response();
    }
    let need = access::need(request.method(), &route);
    if !access.allows(need) {
        return refuse(&state, &access.username, request.headers(), request.uri().path(), need).await;
    }
    access::scope(access, next.run(request)).await
}

/// What a local admin can still reach while two-factor is required of them
/// and not set up yet.
fn open_before_two_factor(route: &str) -> bool {
    matches!(route, "/logout" | "/account/two-factor" | "/account/two-factor/start" | "/account/two-factor/confirm")
}

/// Answer a change the account may not make: a line in the audit log, and
/// the reason on the page it came from — or, to a script that asked for
/// JSON, `{"error": reason}`.
pub async fn refuse(state: &AppState, actor: &str, headers: &HeaderMap, path: &str, need: Need) -> Response {
    let reason = access::refusal(need);
    let server_id = path
        .strip_prefix("/servers/")
        .and_then(|r| r.split('/').next())
        .and_then(|id| id.parse::<i64>().ok());
    db::log_action(&state.db, actor, "access.refused", path, server_id, &Err(reason.clone())).await;

    if wants_json(headers) {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": reason }))).into_response();
    }
    let mut response = Redirect::to(&back_to(headers)).into_response();
    if let Ok(v) = HeaderValue::from_str(&flash_cookie(&reason, via_https(headers))) {
        response.headers_mut().insert(header::SET_COOKIE, v);
    }
    response
}

/// Whether a script sent the request and wants JSON back, not a page.
pub fn wants_json(headers: &HeaderMap) -> bool {
    headers
        .get(header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.contains("application/json"))
}

/// The page a form was sent from, when the browser says and it is this site;
/// otherwise the Servers page.
pub fn back_to(headers: &HeaderMap) -> String {
    let host = headers.get(header::HOST).and_then(|v| v.to_str().ok());
    let referer = headers.get(header::REFERER).and_then(|v| v.to_str().ok());
    let (Some(host), Some(referer)) = (host, referer) else { return "/".to_string() };
    let Some((_, rest)) = referer.split_once("://") else { return "/".to_string() };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.eq_ignore_ascii_case(host) && !path.starts_with("//") {
        path.split('#').next().unwrap_or("/").to_string()
    } else {
        "/".to_string()
    }
}

/// A one-minute cookie the next page shows as a notice and then clears. Not
/// HttpOnly, since the page's script reads it; it only ever holds a message.
pub fn flash_cookie(message: &str, secure: bool) -> String {
    let mut encoded = String::new();
    for b in message.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            encoded.push(b as char);
        } else {
            encoded.push_str(&format!("%{b:02X}"));
        }
    }
    let mut c = format!("easydc_flash={encoded}; Path=/; Max-Age=60; SameSite=Strict");
    if secure {
        c.push_str("; Secure");
    }
    c
}

// ── current user extractor ──────────────────────────────────────────────────────

/// The username behind the request's session, for audit attribution.
/// Always succeeds: routes are already guarded by `require_auth`, which
/// knows the account.
pub struct CurrentUser(pub String);

#[axum::async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        _parts: &mut Parts,
        _state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let name = access::current().username;
        Ok(CurrentUser(if name.is_empty() { "unknown".to_string() } else { name }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_800_000_000;

    #[test]
    fn five_wrong_passwords_pause_that_name_and_the_pause_grows() {
        let mut f = SignInFails::default();
        for i in 0..4 {
            f.failed("Admin", T + i);
        }
        assert_eq!(f.paused("admin", T + 4), None, "four is fine");
        f.failed("ADMIN", T + 4);
        assert_eq!(f.paused("admin", T + 4), Some(60));
        assert_eq!(f.paused("someone-else", T + 4), None, "only that name");
        assert_eq!(f.paused("admin", T + 64), None, "the pause ends");
        for i in 0..5 {
            f.failed("admin", T + 64 + i);
        }
        assert_eq!(f.paused("admin", T + 68), Some(120), "longer the second time");
        f.succeeded("Admin");
        assert_eq!(f.paused("admin", T + 68), None, "a right password clears it");
    }

    #[test]
    fn failures_spread_out_do_not_add_up() {
        let mut f = SignInFails::default();
        for i in 0..10 {
            f.failed("admin", T + i * FAIL_WINDOW);
        }
        assert_eq!(f.paused("admin", T + 10 * FAIL_WINDOW), None);
    }

    #[test]
    fn the_pause_stops_growing() {
        let mut f = SignInFails::default();
        let mut now = T;
        for _ in 0..12 {
            for _ in 0..5 {
                f.failed("admin", now);
            }
            now += FAIL_PAUSE_MAX;
        }
        f.failed("admin", now);
        for _ in 0..4 {
            f.failed("admin", now);
        }
        assert_eq!(f.paused("admin", now), Some(FAIL_PAUSE_MAX));
    }

    #[test]
    fn a_fresh_session_is_valid_and_not_rewritten() {
        assert_eq!(session_state(T, T, T + 5), SessionState::Valid { touch: false });
        assert_eq!(session_state(T, T, T + 60), SessionState::Valid { touch: true });
    }

    #[test]
    fn eight_idle_hours_end_a_session() {
        let last = T + 3600;
        assert_eq!(session_state(T, last, last + IDLE_TIMEOUT - 1), SessionState::Valid { touch: true });
        assert_eq!(session_state(T, last, last + IDLE_TIMEOUT), SessionState::Expired);
    }

    #[test]
    fn a_busy_session_still_ends_after_a_day() {
        let now = T + MAX_SESSION_AGE;
        assert_eq!(session_state(T, now - 1, now), SessionState::Expired);
        assert_eq!(session_state(T, now - 2, now - 1), SessionState::Valid { touch: false });
    }

    #[test]
    fn a_clock_step_backwards_does_not_end_a_session() {
        assert_eq!(session_state(T, T, T - 300), SessionState::Valid { touch: false });
    }

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn https_is_read_from_the_proxy_headers() {
        assert!(!via_https(&headers(&[])));
        assert!(via_https(&headers(&[("x-forwarded-proto", "https")])));
        assert!(via_https(&headers(&[("x-forwarded-proto", "HTTPS")])));
        assert!(!via_https(&headers(&[("x-forwarded-proto", "http")])));
        // Chained proxies: the first value is the client's side.
        assert!(via_https(&headers(&[("x-forwarded-proto", "https, http")])));
        assert!(!via_https(&headers(&[("x-forwarded-proto", "http, https")])));
        assert!(via_https(&headers(&[("forwarded", "for=192.0.2.1;proto=https;host=dc")])));
        assert!(!via_https(&headers(&[("forwarded", "for=192.0.2.1;proto=http")])));
    }

    #[test]
    fn a_refused_change_goes_back_to_its_page() {
        let h = |host: &'static str, referer: &'static str| headers(&[("host", host), ("referer", referer)]);
        assert_eq!(back_to(&h("easydc:3000", "http://easydc:3000/servers/2/users?q=1#x")), "/servers/2/users?q=1");
        assert_eq!(back_to(&h("easydc:3000", "https://evil.example/servers/2/users")), "/");
        assert_eq!(back_to(&h("easydc:3000", "http://easydc:3000//evil.example/")), "/");
        assert_eq!(back_to(&h("easydc:3000", "http://easydc:3000")), "/");
        assert_eq!(back_to(&headers(&[("host", "easydc")])), "/");
    }

    #[test]
    fn a_script_asking_for_json_is_told_in_json() {
        let mut h = HeaderMap::new();
        assert!(!wants_json(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("application/json"));
        assert!(wants_json(&h));
        h.insert(header::ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml"));
        assert!(!wants_json(&h));
    }

    #[test]
    fn the_notice_cookie_holds_only_safe_characters() {
        let c = flash_cookie("You can view Users; not \"change\" them.", false);
        assert_eq!(c, "easydc_flash=You%20can%20view%20Users%3B%20not%20%22change%22%20them.; Path=/; Max-Age=60; SameSite=Strict");
        assert!(flash_cookie("x", true).ends_with("; Secure"));
    }

    #[test]
    fn the_cookie_is_secure_only_over_https() {
        assert!(!session_cookie("t", false).contains("Secure"));
        assert!(session_cookie("t", true).ends_with("; Secure"));
        assert!(session_cookie("t", true).contains("HttpOnly; SameSite=Strict"));
        assert!(clear_session_cookie(true).to_str().unwrap().contains("Max-Age=0; Secure"));
        assert!(!clear_session_cookie(false).to_str().unwrap().contains("Secure"));
    }
}
