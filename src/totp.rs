//! Codes from an authenticator app (TOTP, RFC 6238) and one-time recovery
//! codes. Nothing here touches the database or the network.
//!
//! SHA-1, six digits and 30 seconds are what every authenticator app supports.
//! HMAC-SHA-1 has no known weakness that matters here.

use openssl::{
    error::ErrorStack,
    hash::{hash, MessageDigest},
    memcmp,
    pkey::PKey,
    rand::rand_bytes,
    sign::Signer,
};

const SECRET_BYTES: usize = 20;
const STEP_SECONDS: i64 = 30;
/// A phone's clock may be one step, 30 seconds, either way.
const ALLOWED_DRIFT: i64 = 1;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub const RECOVERY_CODES: usize = 10;
/// Ten of these is 50 random bits. No I, O, 0 or 1, which are easy to misread.
const RECOVERY_ALPHABET: &[u8; 32] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
const RECOVERY_LEN: usize = 10;

/// Wrong codes allowed before the account stops accepting codes for a while.
/// Counted per account, so starting a new sign-in does not earn more guesses.
pub const MAX_WRONG_CODES: i64 = 5;
pub const LOCK_SECONDS: i64 = 15 * 60;
/// How long a person has to scan the QR code and confirm it.
pub const SETUP_SECONDS: i64 = 10 * 60;
/// How long the code step of a sign-in stays open after the password.
pub const CHALLENGE_SECONDS: i64 = 5 * 60;

pub fn new_secret() -> Result<String, ErrorStack> {
    let mut bytes = [0u8; SECRET_BYTES];
    rand_bytes(&mut bytes)?;
    Ok(base32_encode(&bytes))
}

fn base32_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 8 / 5 + 1);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &b in bytes {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

fn base32_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() * 5 / 8);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for c in text.bytes() {
        let value = BASE32.iter().position(|&x| x == c)? as u32;
        buffer = (buffer << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
        buffer &= (1 << bits) - 1;
    }
    Some(out)
}

fn code_at(key: &[u8], step: i64) -> Result<String, ErrorStack> {
    let pkey = PKey::hmac(key)?;
    let mut signer = Signer::new(MessageDigest::sha1(), &pkey)?;
    signer.update(&(step as u64).to_be_bytes())?;
    let mac = signer.sign_to_vec()?;
    let at = (mac[mac.len() - 1] & 0x0f) as usize;
    let number = u32::from_be_bytes([mac[at], mac[at + 1], mac[at + 2], mac[at + 3]]) & 0x7fff_ffff;
    Ok(format!("{:06}", number % 1_000_000))
}

/// The time step a code belongs to, if it is right for now. The caller records
/// the step, so the same code cannot be used twice.
pub fn matching_step(secret: &str, code: &str, now: i64) -> Option<i64> {
    let key = base32_decode(secret)?;
    let current = now.div_euclid(STEP_SECONDS);
    let mut found = None;
    for step in current - ALLOWED_DRIFT..=current + ALLOWED_DRIFT {
        let expected = code_at(&key, step).ok()?;
        if expected.len() == code.len() && memcmp::eq(expected.as_bytes(), code.as_bytes()) && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// What someone typed in the code box.
#[derive(Debug, PartialEq)]
pub enum Typed {
    App(String),
    Recovery(String),
    Neither,
}

/// Spaces and dashes are ignored, and letters may be in either case.
pub fn read_code(text: &str) -> Typed {
    let clean: String = text
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    if clean.len() == 6 && clean.bytes().all(|b| b.is_ascii_digit()) {
        Typed::App(clean)
    } else if clean.len() == RECOVERY_LEN && clean.bytes().all(|b| RECOVERY_ALPHABET.contains(&b)) {
        Typed::Recovery(clean)
    } else {
        Typed::Neither
    }
}

/// New recovery codes as shown to the person, such as `7KQ2M-XH9TC`.
pub fn new_recovery_codes() -> Result<Vec<String>, ErrorStack> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let mut bytes = [0u8; RECOVERY_LEN];
            rand_bytes(&mut bytes)?;
            let code: String = bytes.iter().map(|b| RECOVERY_ALPHABET[(b & 31) as usize] as char).collect();
            Ok(format!("{}-{}", &code[..5], &code[5..]))
        })
        .collect()
}

/// How a recovery code is stored. These codes are long and random, so a fast
/// hash is enough, and it is tied to the account.
pub fn hash_recovery(username: &str, code: &str) -> Result<String, ErrorStack> {
    let clean: String = code.chars().filter(|c| *c != '-').collect();
    let digest = hash(MessageDigest::sha256(), format!("{username}\0{clean}").as_bytes())?;
    Ok(digest.iter().map(|b| format!("{b:02x}")).collect())
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The address an authenticator app reads from the QR code.
pub fn otpauth_url(username: &str, secret: &str) -> String {
    format!(
        "otpauth://totp/EasyDC:{}?secret={secret}&issuer=EasyDC&algorithm=SHA1&digits=6&period={STEP_SECONDS}",
        percent_encode(username)
    )
}

/// The QR code as an `<svg>` element, dark on white in any page theme.
pub fn qr_svg(text: &str) -> Result<String, String> {
    use qrcode::{render::svg, QrCode};
    let code = QrCode::new(text.as_bytes()).map_err(|e| e.to_string())?;
    let image = code
        .render::<svg::Color<'_>>()
        .min_dimensions(220, 220)
        .dark_color(svg::Color("#000000"))
        .light_color(svg::Color("#ffffff"))
        .build();
    let start = image.find("<svg").ok_or("The QR code could not be drawn.")?;
    Ok(image[start..].to_string())
}

/// The secret in groups of four, for typing into an app by hand.
pub fn grouped(secret: &str) -> String {
    secret.as_bytes().chunks(4).map(|c| String::from_utf8_lossy(c).into_owned()).collect::<Vec<_>>().join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238's SHA-1 key, "12345678901234567890".
    const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn base32_matches_rfc_4648() {
        for (plain, encoded) in [("f", "MY"), ("fo", "MZXQ"), ("foo", "MZXW6"), ("foob", "MZXW6YQ"), ("fooba", "MZXW6YTB")] {
            assert_eq!(base32_encode(plain.as_bytes()), encoded);
            assert_eq!(base32_decode(encoded).unwrap(), plain.as_bytes());
        }
        assert_eq!(base32_encode(b"12345678901234567890"), RFC_SECRET);
        assert!(base32_decode("not base32!").is_none());
    }

    #[test]
    fn codes_match_the_rfc_6238_vectors() {
        // The RFC prints eight digits; the last six are the code.
        let key = b"12345678901234567890";
        for (time, code) in [
            (59, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
            (20_000_000_000i64, "353130"),
        ] {
            assert_eq!(code_at(key, time / STEP_SECONDS).unwrap(), code, "at {time}");
        }
    }

    #[test]
    fn a_code_is_accepted_one_step_either_way_and_no_further() {
        let at = 1_111_111_109;
        let step = at / STEP_SECONDS;
        assert_eq!(matching_step(RFC_SECRET, "081804", at), Some(step));
        assert_eq!(matching_step(RFC_SECRET, "081804", at + STEP_SECONDS), Some(step));
        assert_eq!(matching_step(RFC_SECRET, "081804", at - STEP_SECONDS), Some(step));
        assert_eq!(matching_step(RFC_SECRET, "081804", at + 2 * STEP_SECONDS), None);
        assert_eq!(matching_step(RFC_SECRET, "081804", at - 2 * STEP_SECONDS), None);
        assert_eq!(matching_step(RFC_SECRET, "000000", at), None);
        assert_eq!(matching_step("broken!", "081804", at), None);
    }

    #[test]
    fn the_code_box_tells_app_codes_from_recovery_codes() {
        assert_eq!(read_code(" 123 456 "), Typed::App("123456".into()));
        assert_eq!(read_code("7kq2m-xh9tc"), Typed::Recovery("7KQ2MXH9TC".into()));
        assert_eq!(read_code("12345"), Typed::Neither);
        assert_eq!(read_code("1234567"), Typed::Neither);
        assert_eq!(read_code("ABCDEFGHI1"), Typed::Neither, "1 is not in the alphabet");
        assert_eq!(read_code(""), Typed::Neither);
    }

    #[test]
    fn recovery_codes_are_distinct_and_read_back() {
        let codes = new_recovery_codes().unwrap();
        assert_eq!(codes.len(), RECOVERY_CODES);
        assert_eq!(codes.iter().collect::<std::collections::HashSet<_>>().len(), RECOVERY_CODES);
        for code in &codes {
            let Typed::Recovery(clean) = read_code(code) else { panic!("{code}") };
            assert_eq!(hash_recovery("alice", &clean).unwrap(), hash_recovery("alice", code).unwrap());
            assert_ne!(hash_recovery("alice", code).unwrap(), hash_recovery("bob", code).unwrap());
        }
    }

    #[test]
    fn a_new_secret_is_160_bits_of_base32() {
        let secret = new_secret().unwrap();
        assert_eq!(secret.len(), 32);
        assert_eq!(base32_decode(&secret).unwrap().len(), SECRET_BYTES);
        assert_ne!(secret, new_secret().unwrap());
    }

    #[test]
    fn the_app_address_is_escaped_and_drawn() {
        let url = otpauth_url("ann b@lab", "ABCD");
        assert_eq!(url, "otpauth://totp/EasyDC:ann%20b%40lab?secret=ABCD&issuer=EasyDC&algorithm=SHA1&digits=6&period=30");
        let svg = qr_svg(&url).unwrap();
        assert!(svg.starts_with("<svg") && svg.contains("</svg>"));
        assert_eq!(grouped("ABCDEFGHIJ"), "ABCD EFGH IJ");
    }
}
