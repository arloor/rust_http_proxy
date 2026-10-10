//! Keep routing, authentication and filesystem lookup on the same path.
use std::borrow::Cow;

use percent_encoding::percent_decode_str;

/// Decode unreserved characters before routing, preserving other URI escapes.
/// Reject paths whose separators or dot segments could be interpreted differently
/// by an upstream server. The query string is deliberately handled by the caller.
pub(crate) fn normalize_path(path: &str) -> Result<Cow<'_, str>, &'static str> {
    let bytes = path.as_bytes();
    let mut normalized = String::new();
    let mut copied = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            i += 1;
            continue;
        }
        let hex = path.get(i + 1..i + 3).ok_or("invalid path escape")?;
        let byte = u8::from_str_radix(hex, 16).map_err(|_| "invalid path escape")?;
        if matches!(byte, b'/' | b'\\' | b'%' | b'?' | b'#') || byte.is_ascii_control() {
            return Err("ambiguous path escape");
        }
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            normalized.push_str(&path[copied..i]);
            normalized.push(char::from(byte));
            copied = i + 3;
        } else if hex.bytes().any(|byte| byte.is_ascii_lowercase()) {
            normalized.push_str(&path[copied..i]);
            normalized.push('%');
            normalized.extend(hex.chars().map(|ch| ch.to_ascii_uppercase()));
            copied = i + 3;
        }
        i += 3;
    }
    let normalized = if copied == 0 {
        Cow::Borrowed(path)
    } else {
        normalized.push_str(&path[copied..]);
        Cow::Owned(normalized)
    };
    let decoded = percent_decode_str(&normalized)
        .decode_utf8()
        .map_err(|_| "invalid path UTF-8")?;
    validate_segments(&decoded, true)?;
    Ok(normalized)
}

fn validate_segments(path: &str, allow_shortcut: bool) -> Result<(), &'static str> {
    if !path.starts_with('/') || path.contains('\\') || path.chars().any(char::is_control) {
        return Err("invalid path");
    }
    // The embedded scheme is part of the documented /https://host/path shortcut.
    let segments = if allow_shortcut {
        path.strip_prefix("/https://")
            .or_else(|| path.strip_prefix("/http://"))
            .unwrap_or(&path[1..])
    } else {
        &path[1..]
    };
    if segments.contains("//") || segments.starts_with('/') {
        return Err("repeated path separator");
    }
    if segments.split('/').any(|segment| matches!(segment, "." | "..")) {
        return Err("dot path segment");
    }
    Ok(())
}

/// This function takes an already decoded filesystem-relative URL path.
pub(crate) fn valid_static_path(path: &str) -> bool {
    validate_segments(path, false).is_ok()
        && path.split('/').all(|segment| {
            !segment.eq_ignore_ascii_case(".git")
                && (!cfg!(windows)
                    || (!segment.ends_with(['.', ' '])
                        && !segment.contains([':', '~'])
                        && !segment.eq_ignore_ascii_case("CON")
                        && !segment.eq_ignore_ascii_case("NUL")))
        })
}

pub(crate) fn static_prefix_matches(path: &str, prefix: &str) -> bool {
    if cfg!(windows) {
        path.to_lowercase().starts_with(&prefix.to_lowercase())
    } else {
        path.starts_with(prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_path_normalization_preserves_safe_uri_data() {
        for (path, expected) in [
            ("/%61pi/%70rivate", "/api/private"),
            ("/public%20file.txt", "/public%20file.txt"),
            ("/%E4%B8%AD%E6%96%87.txt", "/%E4%B8%AD%E6%96%87.txt"),
            ("/%e4%b8%ad%e6%96%87.txt", "/%E4%B8%AD%E6%96%87.txt"),
            ("/https://github.com/owner/repo", "/https://github.com/owner/repo"),
            ("/http://localhost:8080/item", "/http://localhost:8080/item"),
            ("/a%3Ab", "/a%3Ab"),
        ] {
            assert_eq!(normalize_path(path).unwrap(), expected);
        }
        for path in [
            "/./private",
            "//private",
            "/public/../private",
            "/%2e/private",
            "/a%2fb",
            "/a%5cb",
            "/%252e%252e",
            "/bad%",
            "/%ff",
            "/%00",
            "/https://github.com//private",
        ] {
            assert!(normalize_path(path).is_err(), "{path}");
        }
    }
}
