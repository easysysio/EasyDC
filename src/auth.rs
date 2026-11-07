use axum::{
    extract::{FromRequestParts, Request, State},
    http::{header, request::Parts, HeaderMap, HeaderValue},
    middleware::Next,
    response::{IntoResponse, Redirect, Response},
};
use sqlx::Row;

use crate::{db, AppState};

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

// ── cookie ──────────────────────────────────────────────────────────────────────

pub fn extract_session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("session=").map(String::from))
}

/// True when the browser reached EasyDC over HTTPS through a reverse proxy.
/// EasyDC itself only speaks HTTP, so the proxy's header is the only signal.
/// A client faking it gains nothing: it only makes its own cookie Secure.
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
    let row = sqlx::query("SELECT created_at, last_seen FROM sessions WHERE token = ?")
        .bind(&token)
        .fetch_optional(&state.db)
        .await
        .unwrap_or(None);
    let Some(row) = row else {
        return Redirect::to("/login").into_response();
    };

    let created: i64 = row.get("created_at");
    let seen: i64 = row.get::<Option<i64>, _>("last_seen").unwrap_or(created);
    let now = db::unix_now();
    match session_state(created, seen, now) {
        SessionState::Valid { touch } => {
            if touch {
                let _ = sqlx::query("UPDATE sessions SET last_seen = ? WHERE token = ?")
                    .bind(now)
                    .bind(&token)
                    .execute(&state.db)
                    .await;
            }
            next.run(request).await
        }
        SessionState::Expired => {
            let _ = sqlx::query("DELETE FROM sessions WHERE token = ?")
                .bind(&token)
                .execute(&state.db)
                .await;
            let mut response = Redirect::to("/login?expired=1").into_response();
            response
                .headers_mut()
                .insert(header::SET_COOKIE, clear_session_cookie(via_https(request.headers())));
            response
        }
    }
}

// ── current user extractor ──────────────────────────────────────────────────────

/// The username behind the request's session, for audit attribution.
/// Always succeeds (routes are already guarded by `require_auth`); falls back
/// to "unknown" if the session has no recorded username (legacy sessions).
pub struct CurrentUser(pub String);

#[axum::async_trait]
impl FromRequestParts<AppState> for CurrentUser {
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let username = match extract_session_cookie(&parts.headers) {
            Some(token) => db::username_for_token(&state.db, &token)
                .await
                .unwrap_or_else(|| "unknown".to_string()),
            None => "unknown".to_string(),
        };
        Ok(CurrentUser(username))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_800_000_000;

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
    fn the_cookie_is_secure_only_over_https() {
        assert!(!session_cookie("t", false).contains("Secure"));
        assert!(session_cookie("t", true).ends_with("; Secure"));
        assert!(session_cookie("t", true).contains("HttpOnly; SameSite=Strict"));
        assert!(clear_session_cookie(true).to_str().unwrap().contains("Max-Age=0; Secure"));
        assert!(!clear_session_cookie(false).to_str().unwrap().contains("Secure"));
    }
}
