use sha2::{Digest, Sha256};
use std::fmt;

pub(crate) struct SessionHash(Option<[u8; 4]>);

impl SessionHash {
    /// The first 4 bytes of SHA-256(`session`).
    pub(crate) fn of(session: &str) -> Self {
        let digest = Sha256::digest(session.as_bytes());
        Self(Some([digest[0], digest[1], digest[2], digest[3]]))
    }
}

impl fmt::Display for SessionHash {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(bytes) => {
                for byte in bytes {
                    write!(formatter, "{byte:02x}")?;
                }
                Ok(())
            }
            None => formatter.write_str("unavailable"),
        }
    }
}

/// Diagnostic only: associate the response with one exact offered item. Never
/// trust a response identity or search the rest of the scan to fill a miss.
pub(super) fn rejected_session_hash<T, Fingerprint, SessionId>(
    items: &[T],
    indices: &[usize],
    rejected_fingerprint: &str,
    fingerprint: &Fingerprint,
    session_id: &SessionId,
) -> SessionHash
where
    Fingerprint: Fn(&T) -> &str,
    SessionId: Fn(&T) -> Option<&str>,
{
    if indices.len() > super::SNAPSHOT_BATCH_LIMIT {
        return SessionHash(None);
    }
    let mut matched = None;
    for index in indices {
        let Some(item) = items.get(*index) else {
            return SessionHash(None);
        };
        if fingerprint(item) == rejected_fingerprint {
            if matched.is_some() {
                return SessionHash(None);
            }
            matched = Some(item);
        }
    }
    let Some(id) = matched.and_then(session_id).filter(|id| !id.is_empty()) else {
        return SessionHash(None);
    };
    SessionHash::of(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash(items: &[(&str, &str)], indices: &[usize], rejected: &str) -> String {
        rejected_session_hash(items, indices, rejected, &|item| item.0, &|item| {
            Some(item.1)
        })
        .to_string()
    }

    #[test]
    fn rejection_log_hashes_exact_offered_source_session_not_fingerprint() {
        let items = [
            ("other-fingerprint", "other-session"),
            ("fingerprint", "test"),
        ];
        // SHA256("test") starts 9f86d081. Neither array position nor response
        // fingerprint supplies the source identity.
        assert_eq!(hash(&items, &[1, 0], "fingerprint"), "9f86d081");
        assert_ne!(hash(&items, &[0], "other-fingerprint"), "9f86d081");
        assert_eq!(
            hash(&[("new-fingerprint", "test")], &[0], "new-fingerprint"),
            "9f86d081"
        );
    }

    #[test]
    fn rejection_log_missing_or_ambiguous_offered_identity_is_unavailable() {
        let items = [("fp", "test"), ("fp", "another-session"), ("empty", "")];
        for (indices, rejected) in [
            (vec![], "fp"),
            (vec![2], "fp"), // A matching item elsewhere in the scan is not offered.
            (vec![0], "missing"),
            (vec![0, 1], "fp"),
            (vec![0, 0], "fp"),
            (vec![2], "empty"),
            (vec![0, 99], "fp"),
            (vec![0; super::super::SNAPSHOT_BATCH_LIMIT + 1], "fp"),
        ] {
            assert_eq!(hash(&items, &indices, rejected), "unavailable");
        }
        assert_eq!(
            rejected_session_hash(&items, &[0], "fp", &|item| item.0, &|_| None).to_string(),
            "unavailable"
        );
    }
}
