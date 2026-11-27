//! Plain-HTTP loopback backend bases, for developer use only.
//!
//! A plain-HTTP backend base must name this Mac exactly, and is used only when
//! the developer configured that base for this daemon process.

/// The normalized base when `value` is `http://` to exactly `localhost`,
/// `127.0.0.1` or `[::1]` (any letter case), with an optional numeric port and
/// an optional path. `None` for anything else: userinfo, a lookalike or
/// trailing-dot host, a query or fragment, another scheme.
pub(crate) fn loopback_http_base(value: &str) -> Option<String> {
    let rest = value.strip_prefix("http://")?;
    if value.contains(['?', '#']) {
        return None;
    }
    let (authority, path) = match rest.find('/') {
        Some(index) => rest.split_at(index),
        None => (rest, ""),
    };
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (inside, after) = bracketed.split_once(']')?;
        (format!("[{inside}]"), after)
    } else {
        match authority.split_once(':') {
            Some((host, _)) => (host.to_string(), &authority[host.len()..]),
            None => (authority.to_string(), ""),
        }
    };
    let host = host.to_ascii_lowercase();
    if !matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]") {
        return None;
    }
    if !port.is_empty() {
        let digits = port.strip_prefix(':')?;
        if digits.is_empty()
            || !digits.bytes().all(|byte| byte.is_ascii_digit())
            || digits.parse::<u32>().ok()? > 65_535
        {
            return None;
        }
    }
    Some(format!("http://{host}{port}{path}"))
}

/// A plain-HTTP loopback base is trusted only when it is exactly the base the
/// developer configured for this daemon process (`OTTTO_API_BASE_URL`), never
/// one that arrived in a request, a deep link or a saved connection.
pub(crate) fn developer_loopback_base(value: &str, developer_override: Option<&str>) -> bool {
    let Some(base) = loopback_http_base(value.trim().trim_end_matches('/')) else {
        return false;
    };
    developer_override
        .map(|configured| configured.trim().trim_end_matches('/'))
        .and_then(loopback_http_base)
        .is_some_and(|configured| configured == base)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_http_base_accepts_only_exact_loopback_hosts() {
        for (value, normalized) in [
            ("http://localhost", "http://localhost"),
            ("http://localhost:8000", "http://localhost:8000"),
            ("http://127.0.0.1:5/backend", "http://127.0.0.1:5/backend"),
            ("http://[::1]:8080", "http://[::1]:8080"),
            ("http://LOCALHOST:8000", "http://localhost:8000"),
            ("http://LocalHost/api", "http://localhost/api"),
            ("http://[::1]", "http://[::1]"),
            ("http://localhost:08000", "http://localhost:08000"),
        ] {
            assert_eq!(
                loopback_http_base(value).as_deref(),
                Some(normalized),
                "{value}"
            );
        }
        for value in [
            "http://localhost.attacker.example",
            "http://localhost.attacker.example:8000",
            "http://127.0.0.1.nip.io",
            "http://localhost@evil.example",
            "http://localhost:8000@evil.example",
            "http://127.0.0.1:80@evil.example",
            "http://user@localhost",
            "http://localhost.",
            "http://localhost.:8000",
            "http://localhost-evil.example",
            "http://[::1].evil.example",
            "http://[::2]:8000",
            "http://localhost:",
            "http://localhost:99999",
            "http://localhost:80a",
            "http://localhost?x=1",
            "http://localhost#x",
            "https://localhost",
            "HTTP://localhost",
            "http://",
            "http://evil.example",
            "http://localhost\\@evil.example",
            "http://%6cocalhost",
            "http://local%68ost",
            "http://localhost\t",
            "http:// localhost",
            "http://[::1%25en0]:8000",
            "http://2130706433",
            "http://0x7f.1",
            "http://0x7f000001",
            "http://127.1",
            "http://localhost:+80",
            "http://ｌｏｃａｌｈｏｓｔ",
            "http://127.0.0.1.",
            "http:/localhost",
            "http:///localhost",
        ] {
            assert_eq!(loopback_http_base(value), None, "{value}");
        }
    }

    #[test]
    fn developer_loopback_base_needs_the_exact_developer_override() {
        let configured = Some("http://localhost:8000/");
        assert!(developer_loopback_base("http://localhost:8000", configured));
        assert!(developer_loopback_base(
            "http://LOCALHOST:8000/",
            configured
        ));
        assert!(!developer_loopback_base(
            "http://localhost:8001",
            configured
        ));
        assert!(!developer_loopback_base(
            "http://127.0.0.1:8000",
            configured
        ));
        assert!(!developer_loopback_base("http://localhost:8000", None));
        assert!(!developer_loopback_base(
            "http://localhost.attacker.example",
            Some("http://localhost.attacker.example")
        ));
        assert!(!developer_loopback_base(
            "http://localhost:8000",
            Some("https://api.ottto.net")
        ));
    }
}
