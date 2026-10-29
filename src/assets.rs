//! Static files (Bootstrap and its icon font), compiled into the binary so the
//! GUI works on networks with no internet access.
//!
//! The files are upstream's, unmodified, under assets/vendor/<name>-<version>/.
//! The version is part of the URL, so browsers may cache them forever: a new
//! version is a new folder and a new URL.

use axum::{
    extract::Path,
    http::{header, StatusCode},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "assets/"]
#[include = "*.css"]
#[include = "*.js"]
#[include = "*.woff"]
#[include = "*.woff2"]
struct Assets;

/// GET /static/*path
pub async fn serve(Path(path): Path<String>) -> Response {
    let (Some(file), Some(mime)) = (Assets::get(&path), content_type(&path)) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    (
        [
            (header::CONTENT_TYPE, mime),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        file.data,
    )
        .into_response()
}

fn content_type(path: &str) -> Option<&'static str> {
    match path.rsplit_once('.')?.1 {
        "css" => Some("text/css; charset=utf-8"),
        "js" => Some("text/javascript; charset=utf-8"),
        "woff2" => Some("font/woff2"),
        "woff" => Some("font/woff"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every /static/ URL in a template, and every font the icon stylesheet
    /// asks for, must be in the binary — or a page loads unstyled.
    #[test]
    fn every_referenced_asset_is_embedded() {
        let mut wanted = Vec::new();
        for entry in std::fs::read_dir("templates").unwrap() {
            let html = std::fs::read_to_string(entry.unwrap().path()).unwrap();
            for part in html.split("\"/static/").skip(1) {
                wanted.push(part.split('"').next().unwrap().to_string());
            }
        }
        assert!(wanted.len() >= 3, "templates should load Bootstrap from /static/");

        let icons = "vendor/bootstrap-icons-1.11.0/";
        let css = Assets::get(&format!("{icons}bootstrap-icons.min.css")).unwrap();
        for part in std::str::from_utf8(&css.data).unwrap().split("url(\"").skip(1) {
            let rel = part.split(['"', '?']).next().unwrap();
            wanted.push(format!("{icons}{rel}"));
        }

        for path in &wanted {
            assert!(Assets::get(path).is_some(), "{path} is not embedded");
            assert!(content_type(path).is_some(), "{path} has no content type");
        }
    }

    #[test]
    fn templates_load_nothing_from_the_internet() {
        for entry in std::fs::read_dir("templates").unwrap() {
            let path = entry.unwrap().path();
            let html = std::fs::read_to_string(&path).unwrap();
            for attr in ["src=\"http", "href=\"http", "src=\"//", "href=\"//"] {
                assert!(!html.contains(attr), "{} has {attr}", path.display());
            }
        }
    }

    #[test]
    fn licenses_are_not_served() {
        assert!(Assets::get("vendor/bootstrap-5.3.0/LICENSE").is_none());
        assert!(content_type("vendor/x.map").is_none());
    }
}
