//! HTTPS on EasyDC's one port.
//!
//! The first byte of a connection says what it is: 0x16 opens a TLS handshake,
//! and anything else is plain HTTP, which is redirected to the same address
//! over HTTPS. One port means an upgrade needs no new firewall rule, and a
//! remapped Docker port (`-p 8080:3000`) still redirects to the right place,
//! because the address comes from the browser's Host header.
//!
//! Plain HTTP is still answered in two cases: a reverse proxy that says it took
//! the request over HTTPS (X-Forwarded-Proto), and the /healthz check.
//!
//! The certificate and its key are kept in easydc.db, so one file is still the
//! whole backup. No HSTS: with a self-signed certificate it would leave the
//! browser no way past its warning.

use std::{
    convert::Infallible,
    net::IpAddr,
    pin::Pin,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Request, Response, StatusCode, Uri},
    Router,
};
use hyper::{body::Incoming, server::conn::http1, service::service_fn};
use hyper_util::rt::{TokioIo, TokioTimer};
use openssl::{
    asn1::Asn1Time,
    bn::{BigNum, MsbOption},
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    ssl::{Ssl, SslAcceptor, SslMethod},
    x509::{
        extension::{BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName},
        X509NameBuilder, X509NameRef, X509,
    },
};
use serde::Serialize;
use sqlx::sqlite::SqlitePool;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
};
use tokio_openssl::SslStream;
use tower_service::Service;

use crate::{auth, db};

/// How long a new connection may take to say something and finish the
/// handshake, so that idle sockets cannot pile up.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// Apple's limit for a server certificate, so that it can be trusted there too.
const VALID_DAYS: u32 = 825;
/// A generated certificate is replaced this long before it expires.
const RENEW_DAYS: i32 = 30;
const FIRST_BYTE_OF_TLS: u8 = 0x16;

/// EASYDC_TLS: on unless it says off.
pub fn enabled(value: Option<&str>) -> Result<bool, String> {
    match value.unwrap_or("").trim().to_ascii_lowercase().as_str() {
        "" | "on" | "true" | "yes" | "1" => Ok(true),
        "off" | "false" | "no" | "0" => Ok(false),
        other => Err(format!("EASYDC_TLS must be on or off, not \"{other}\"")),
    }
}

/// A certificate (with any intermediates after it) and its private key, in PEM.
#[derive(Clone)]
pub struct Pair {
    pub cert: String,
    pub key: String,
    /// Given by an admin, rather than generated here.
    pub uploaded: bool,
}

/// What the Settings page shows. Nothing secret.
#[derive(Clone, Debug, Serialize)]
pub struct Info {
    pub name: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub not_after: String,
    pub days_left: i32,
    pub expired: bool,
    pub fingerprint: String,
    pub uploaded: bool,
}

// ── certificates ──────────────────────────────────────────────────────────────

/// The machine's name, for the generated certificate. Only a nicety: a
/// self-signed certificate brings a browser warning whatever it names.
fn host_name() -> Option<String> {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .map(|h| h.trim().to_string())
        .filter(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-')))
}

pub fn self_signed() -> Result<Pair, String> {
    generate(host_name().as_deref()).map_err(|e| format!("Could not generate a certificate: {e}"))
}

fn generate(host: Option<&str>) -> Result<Pair, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = PKey::from_ec_key(EcKey::generate(&group)?)?;

    let common_name = host.unwrap_or("EasyDC");
    let mut name = X509NameBuilder::new()?;
    name.append_entry_by_nid(Nid::ORGANIZATIONNAME, "EasyDC")?;
    name.append_entry_by_nid(Nid::COMMONNAME, common_name)?;
    let name = name.build();

    let mut serial = BigNum::new()?;
    serial.rand(128, MsbOption::MAYBE_ZERO, false)?;

    let mut b = X509::builder()?;
    b.set_version(2)?;
    b.set_serial_number(serial.to_asn1_integer()?.as_ref())?;
    b.set_subject_name(&name)?;
    b.set_issuer_name(&name)?;
    b.set_pubkey(&key)?;
    // An hour back, so that a clock slightly behind the server's accepts it.
    b.set_not_before(Asn1Time::from_unix(db::unix_now() - 3600)?.as_ref())?;
    b.set_not_after(Asn1Time::days_from_now(VALID_DAYS)?.as_ref())?;
    b.append_extension(BasicConstraints::new().critical().build()?)?;
    b.append_extension(KeyUsage::new().critical().digital_signature().build()?)?;
    b.append_extension(ExtendedKeyUsage::new().server_auth().build()?)?;
    let san = {
        let ctx = b.x509v3_context(None, None);
        let mut san = SubjectAlternativeName::new();
        if let Some(h) = host.filter(|h| *h != "localhost") {
            san.dns(h);
        }
        san.dns("localhost").ip("127.0.0.1").ip("::1").build(&ctx)?
    };
    b.append_extension(san)?;
    b.sign(&key, MessageDigest::sha256())?;

    Ok(Pair {
        cert: String::from_utf8_lossy(&b.build().to_pem()?).into_owned(),
        key: String::from_utf8_lossy(&key.private_key_to_pem_pkcs8()?).into_owned(),
        uploaded: false,
    })
}

/// An admin's certificate and key, refused with a reason unless they would work.
pub fn check_upload(cert: &str, key: &str) -> Result<Pair, String> {
    const NOT_A_CERT: &str = "That is not a certificate in PEM format (it starts with -----BEGIN CERTIFICATE-----).";
    if cert.trim().is_empty() || key.trim().is_empty() {
        return Err("Give both the certificate and its private key.".to_string());
    }
    let chain = X509::stack_from_pem(cert.trim().as_bytes()).map_err(|_| NOT_A_CERT.to_string())?;
    let leaf = chain.first().ok_or(NOT_A_CERT)?;
    if key.contains("ENCRYPTED") {
        return Err("The private key is protected by a passphrase. Give it without one.".to_string());
    }
    let private = parse_key(key).map_err(|_| {
        "That is not a private key in PEM format (it starts with -----BEGIN PRIVATE KEY-----).".to_string()
    })?;
    let matches = leaf.public_key().map(|p| p.public_eq(&private)).unwrap_or(false);
    if !matches {
        return Err(
            "The private key does not belong to the certificate. The server's own certificate must come first in the file."
                .to_string(),
        );
    }
    let now = Asn1Time::days_from_now(0).map_err(|e| e.to_string())?;
    if leaf.not_after().compare(&now).map_err(|e| e.to_string())? == std::cmp::Ordering::Less {
        return Err(format!("This certificate expired on {}.", leaf.not_after()));
    }
    if leaf.not_before().compare(&now).map_err(|e| e.to_string())? == std::cmp::Ordering::Greater {
        return Err(format!("This certificate is not valid until {}.", leaf.not_before()));
    }
    let pair = Pair { cert: format!("{}\n", cert.trim()), key: format!("{}\n", key.trim()), uploaded: true };
    acceptor(&pair).map_err(|_| "OpenSSL refused this certificate and key. A key that is too weak is the usual reason.".to_string())?;
    Ok(pair)
}

fn parse_key(pem: &str) -> Result<PKey<Private>, ErrorStack> {
    PKey::private_key_from_pem(pem.trim().as_bytes())
}

fn acceptor(pair: &Pair) -> Result<SslAcceptor, ErrorStack> {
    let chain = X509::stack_from_pem(pair.cert.as_bytes())?;
    let key = parse_key(&pair.key)?;
    // TLS 1.2 and 1.3, with Mozilla's "intermediate" ciphers.
    let mut b = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    b.set_private_key(&key)?;
    let mut chain = chain.into_iter();
    if let Some(leaf) = chain.next() {
        b.set_certificate(&leaf)?;
    }
    for extra in chain {
        b.add_extra_chain_cert(extra)?;
    }
    b.check_private_key()?;
    Ok(b.build())
}

fn common_name(name: &X509NameRef) -> String {
    name.entries_by_nid(Nid::COMMONNAME)
        .next()
        .and_then(|e| e.data().to_string().ok())
        .unwrap_or_default()
}

fn describe(pair: &Pair) -> Result<Info, ErrorStack> {
    let chain = X509::stack_from_pem(pair.cert.as_bytes())?;
    let Some(leaf) = chain.first() else {
        return Err(ErrorStack::get());
    };
    let names = leaf
        .subject_alt_names()
        .map(|sans| {
            sans.iter()
                .filter_map(|n| {
                    n.dnsname().map(str::to_string).or_else(|| {
                        let ip = n.ipaddress()?;
                        match ip.len() {
                            4 => <[u8; 4]>::try_from(ip).ok().map(|b| IpAddr::from(b).to_string()),
                            16 => <[u8; 16]>::try_from(ip).ok().map(|b| IpAddr::from(b).to_string()),
                            _ => None,
                        }
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let now = Asn1Time::days_from_now(0)?;
    let days_left = now.diff(leaf.not_after())?.days;
    let expired = leaf.not_after().compare(&now)? == std::cmp::Ordering::Less;
    let fingerprint = leaf
        .digest(MessageDigest::sha256())?
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    Ok(Info {
        name: common_name(leaf.subject_name()),
        issuer: common_name(leaf.issuer_name()),
        names,
        not_after: leaf.not_after().to_string(),
        days_left,
        expired,
        fingerprint,
        uploaded: pair.uploaded,
    })
}

// ── the certificate in use ────────────────────────────────────────────────────

struct Current {
    acceptor: Arc<SslAcceptor>,
    info: Info,
}

/// The certificate being served. Replacing it applies to the next connection,
/// with no restart.
pub struct Live(RwLock<Current>);

impl Live {
    fn new(pair: &Pair) -> Result<Self, String> {
        Ok(Self(RwLock::new(Self::prepare(pair)?)))
    }

    fn prepare(pair: &Pair) -> Result<Current, String> {
        let acceptor = acceptor(pair).map_err(|e| format!("The certificate cannot be used: {e}"))?;
        let info = describe(pair).map_err(|e| format!("The certificate cannot be read: {e}"))?;
        Ok(Current { acceptor: Arc::new(acceptor), info })
    }

    pub fn set(&self, pair: &Pair) -> Result<(), String> {
        let next = Self::prepare(pair)?;
        // The log is where an admin can check the fingerprint a browser shows.
        println!("Certificate SHA-256: {}", next.info.fingerprint);
        *self.0.write().unwrap_or_else(|e| e.into_inner()) = next;
        Ok(())
    }

    pub fn info(&self) -> Info {
        self.0.read().unwrap_or_else(|e| e.into_inner()).info.clone()
    }

    fn acceptor(&self) -> Arc<SslAcceptor> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).acceptor.clone()
    }
}

/// The stored certificate, or a new one on first start. A stored one that can
/// no longer be used is left in the database, and a temporary one served, so
/// that a damaged row cannot lock everyone out of the page that would fix it.
pub async fn load(pool: &SqlitePool) -> Result<Arc<Live>, String> {
    if let Some(pair) = db::tls_pair(pool).await {
        match Live::new(&pair) {
            Ok(live) => return Ok(Arc::new(live)),
            Err(e) => {
                eprintln!("EasyDC: {e}");
                eprintln!("Serving a temporary certificate. Upload a new one in Settings.");
                return Ok(Arc::new(Live::new(&self_signed()?)?));
            }
        }
    }
    let pair = self_signed()?;
    if let Err(e) = db::save_tls_pair(pool, &pair).await {
        eprintln!("EasyDC: could not save the new certificate: {e}");
    }
    Ok(Arc::new(Live::new(&pair)?))
}

/// Replaces a generated certificate as it nears its end. An uploaded one is
/// the admin's to renew; Settings shows when it expires.
pub async fn renew_generated(pool: SqlitePool, live: Arc<Live>) {
    let mut daily = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
    loop {
        daily.tick().await;
        let info = live.info();
        if info.uploaded || info.days_left >= RENEW_DAYS {
            continue;
        }
        let renewed = async {
            let pair = self_signed()?;
            db::save_tls_pair(&pool, &pair).await.map_err(|e| e.to_string())?;
            live.set(&pair)
        };
        if let Err(e) = renewed.await {
            eprintln!("EasyDC: could not renew the certificate: {e}");
        }
    }
}

// ── the port ──────────────────────────────────────────────────────────────────

/// Accepts connections until the listener fails for good.
pub async fn serve(listener: TcpListener, app: Router, live: Arc<Live>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                // Usually out of file descriptors: wait instead of spinning.
                tracing::warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let (app, live) = (app.clone(), live.clone());
        tokio::spawn(async move { connection(stream, app, live).await });
    }
}

async fn connection(stream: TcpStream, app: Router, live: Arc<Live>) {
    let _ = stream.set_nodelay(true);
    let mut first = [0u8; 1];
    let peeked = tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)).await;
    if !matches!(peeked, Ok(Ok(1))) {
        return;
    }
    if first[0] != FIRST_BYTE_OF_TLS {
        return http(stream, app, false).await;
    }
    let acceptor = live.acceptor();
    let Ok(ssl) = Ssl::new(acceptor.context()) else { return };
    let Ok(mut tls) = SslStream::new(ssl, stream) else { return };
    // A browser that refuses the certificate ends here, which is not an error.
    if !matches!(tokio::time::timeout(HANDSHAKE_TIMEOUT, Pin::new(&mut tls).accept()).await, Ok(Ok(()))) {
        return;
    }
    http(tls, app, true).await;
}

async fn http<S>(io: S, app: Router, over_tls: bool)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |request: Request<Incoming>| {
        let mut app = app.clone();
        async move {
            let mut request = request.map(Body::new);
            if over_tls {
                // Overwrites whatever the client sent: this is what makes the
                // session cookie Secure.
                request.headers_mut().insert("x-forwarded-proto", HeaderValue::from_static("https"));
            } else if let Some(answer) = answer_plain(request.headers(), request.uri()) {
                return Ok::<_, Infallible>(answer);
            }
            app.call(request).await
        }
    });
    // Errors here are clients going away.
    let _ = http1::Builder::new().timer(TokioTimer::new()).serve_connection(TokioIo::new(io), service).await;
}

/// What to say to a plain HTTP request instead of serving it, if anything.
fn answer_plain(headers: &HeaderMap, uri: &Uri) -> Option<Response<Body>> {
    if uri.path() == "/healthz" || auth::via_https(headers) {
        return None;
    }
    let response = match https_url(headers, uri).and_then(|u| HeaderValue::from_str(&u).ok()) {
        // 307: not cached, so turning HTTPS off later cannot leave a browser
        // stuck on a redirect it remembers.
        Some(location) => Response::builder()
            .status(StatusCode::TEMPORARY_REDIRECT)
            .header(header::LOCATION, location)
            .header(header::CACHE_CONTROL, "no-store")
            .body(Body::from("EasyDC is served over HTTPS.\n")),
        None => Response::builder().status(StatusCode::BAD_REQUEST).body(Body::from("Bad Host header.\n")),
    };
    response.ok()
}

/// The same address over HTTPS. The Host header is the only thing that knows
/// the address the browser used, so it must look like a host and nothing more.
fn https_url(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let host = headers.get(header::HOST)?.to_str().ok()?;
    let plain = !host.is_empty()
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':' | '[' | ']'));
    if !plain {
        return None;
    }
    let path = uri.path_and_query().map_or("/", |p| p.as_str());
    Some(format!("https://{host}{path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;
    use openssl::ssl::{SslConnector, SslVerifyMode};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(*k, HeaderValue::from_static(v));
        }
        h
    }

    #[test]
    fn it_is_on_unless_told_otherwise() {
        for on in [None, Some(""), Some("on"), Some("TRUE"), Some(" yes "), Some("1")] {
            assert_eq!(enabled(on), Ok(true), "{on:?}");
        }
        for off in [Some("off"), Some("OFF"), Some("false"), Some("no"), Some("0")] {
            assert_eq!(enabled(off), Ok(false), "{off:?}");
        }
        assert!(enabled(Some("maybe")).is_err());
    }

    #[test]
    fn a_generated_certificate_names_the_host_and_can_be_served() {
        let pair = generate(Some("easydc-01")).unwrap();
        assert!(!pair.uploaded);
        acceptor(&pair).unwrap();
        let info = describe(&pair).unwrap();
        assert_eq!(info.name, "easydc-01");
        assert_eq!(info.issuer, "easydc-01");
        assert_eq!(info.names, ["easydc-01", "localhost", "127.0.0.1", "::1"]);
        assert!(!info.expired);
        assert!((823..=825).contains(&info.days_left), "{}", info.days_left);
        assert_eq!(info.fingerprint.len(), 32 * 3 - 1);
    }

    #[test]
    fn an_upload_is_checked() {
        let a = generate(Some("a")).unwrap();
        let b = generate(Some("b")).unwrap();
        let ok = check_upload(&a.cert, &a.key).unwrap();
        assert!(ok.uploaded);

        let refused = |c: &str, k: &str| check_upload(c, k).err().unwrap();
        assert!(refused("", &a.key).contains("both"));
        assert!(refused("junk", &a.key).contains("not a certificate"));
        assert!(refused(&a.cert, "junk").contains("not a private key"));
        assert!(refused(&a.cert, &b.key).contains("does not belong"));
        assert!(refused(&a.cert, "-----BEGIN ENCRYPTED PRIVATE KEY-----").contains("passphrase"));
    }

    #[test]
    fn an_expired_certificate_is_refused() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let mut b = X509::builder().unwrap();
        b.set_version(2).unwrap();
        b.set_pubkey(&key).unwrap();
        b.set_not_before(Asn1Time::from_unix(1_000_000_000).unwrap().as_ref()).unwrap();
        b.set_not_after(Asn1Time::from_unix(1_100_000_000).unwrap().as_ref()).unwrap();
        b.sign(&key, MessageDigest::sha256()).unwrap();
        let cert = String::from_utf8(b.build().to_pem().unwrap()).unwrap();
        let pem = String::from_utf8(key.private_key_to_pem_pkcs8().unwrap()).unwrap();
        assert!(check_upload(&cert, &pem).err().unwrap().contains("expired"));
    }

    #[test]
    fn plain_http_goes_to_the_same_address_over_https() {
        let uri: Uri = "/servers/1/users?status=all".parse().unwrap();
        for (host, url) in [
            ("dc.example.com:3000", "https://dc.example.com:3000/servers/1/users?status=all"),
            ("192.0.2.5:8080", "https://192.0.2.5:8080/servers/1/users?status=all"),
            ("[2001:db8::1]:3000", "https://[2001:db8::1]:3000/servers/1/users?status=all"),
        ] {
            assert_eq!(https_url(&headers(&[("host", host)]), &uri).as_deref(), Some(url));
        }
    }

    #[test]
    fn a_host_header_cannot_send_the_browser_elsewhere() {
        let uri: Uri = "/".parse().unwrap();
        for host in ["evil.example/", "a@evil.example", "evil.example\\x", "a b", ""] {
            assert_eq!(https_url(&headers(&[("host", host)]), &uri), None, "{host}");
        }
        assert_eq!(https_url(&HeaderMap::new(), &uri), None);
        assert_eq!(answer_plain(&HeaderMap::new(), &uri).unwrap().status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn a_proxy_over_https_and_the_health_check_are_not_redirected() {
        let root: Uri = "/".parse().unwrap();
        let proxied = headers(&[("host", "easydc:3000"), ("x-forwarded-proto", "https")]);
        assert!(answer_plain(&proxied, &root).is_none());
        let health: Uri = "/healthz".parse().unwrap();
        assert!(answer_plain(&headers(&[("host", "easydc:3000")]), &health).is_none());
        let plain_proxy = headers(&[("host", "easydc:3000"), ("x-forwarded-proto", "http")]);
        assert_eq!(answer_plain(&plain_proxy, &root).unwrap().status(), StatusCode::TEMPORARY_REDIRECT);
    }

    async fn read_all<S: AsyncRead + Unpin>(mut s: S) -> String {
        let mut out = Vec::new();
        let _ = s.read_to_end(&mut out).await;
        String::from_utf8_lossy(&out).into_owned()
    }

    async fn plain(port: u16, request: &str) -> String {
        let mut s = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        s.write_all(request.as_bytes()).await.unwrap();
        read_all(s).await
    }

    async fn over_tls(port: u16, request: &str) -> (String, String) {
        let mut c = SslConnector::builder(SslMethod::tls_client()).unwrap();
        c.set_verify(SslVerifyMode::NONE);
        let ssl = c.build().configure().unwrap().into_ssl("localhost").unwrap();
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let mut s = SslStream::new(ssl, tcp).unwrap();
        Pin::new(&mut s).connect().await.unwrap();
        let name = common_name(s.ssl().peer_certificate().unwrap().subject_name());
        s.write_all(request.as_bytes()).await.unwrap();
        (read_all(s).await, name)
    }

    /// Both protocols through a real socket on one port, and a certificate
    /// replaced while it runs.
    #[tokio::test]
    async fn one_port_speaks_both() {
        let app = Router::new()
            .route("/", get(|h: HeaderMap| async move { format!("secure={}", auth::via_https(&h)) }))
            .route("/healthz", get(|| async { "ok" }));
        let live = Arc::new(Live::new(&generate(Some("first")).unwrap()).unwrap());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(listener, app, live.clone()));

        let req = |path: &str, extra: &str| format!("GET {path} HTTP/1.1\r\nHost: easydc:{port}\r\n{extra}Connection: close\r\n\r\n");

        let r = plain(port, &req("/?a=1", "")).await;
        assert!(r.starts_with("HTTP/1.1 307"), "{r}");
        assert!(r.to_lowercase().contains(&format!("location: https://easydc:{port}/?a=1")), "{r}");

        let r = plain(port, &req("/healthz", "")).await;
        assert!(r.starts_with("HTTP/1.1 200") && r.ends_with("ok"), "{r}");

        let r = plain(port, &req("/", "X-Forwarded-Proto: https\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("secure=true"), "{r}");

        let (r, name) = over_tls(port, &req("/", "X-Forwarded-Proto: http\r\n")).await;
        assert!(r.starts_with("HTTP/1.1 200") && r.contains("secure=true"), "{r}");
        assert_eq!(name, "first");

        live.set(&generate(Some("second")).unwrap()).unwrap();
        let (_, name) = over_tls(port, &req("/", "")).await;
        assert_eq!(name, "second", "a new certificate applies to the next connection");
    }
}
