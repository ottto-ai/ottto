//! Reserved IDs for internal verification sessions across sources.
//! Claude internal sessions are dropped locally by the relay. Pi internal
//! sessions upload because Verify needs the accepted upload; the server excludes
//! them. Scanners must not reuse the relay exclusion.

const INTERNAL_SESSION_PREFIX: &str = "6f747474-6f00-4f00-8f00-";

pub(crate) fn internal_session_id() -> String {
    let mut bytes = [0_u8; 6];
    getrandom::fill(&mut bytes).expect("system randomness for verification session");
    let suffix = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    format!("{INTERNAL_SESSION_PREFIX}{suffix}")
}

pub(crate) fn is_internal_session_id(id: &str) -> bool {
    id.len() == 36
        && id.starts_with(INTERNAL_SESSION_PREFIX)
        && id[24..].bytes().all(|b| b.is_ascii_hexdigit())
}
