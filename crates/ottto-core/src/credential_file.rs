//! Bounded credential reads; counts use the service's existing local_resources carrier.
use std::fs::File;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::{SystemTime, UNIX_EPOCH};

const LIMIT: u64 = 64 * 1024;
#[derive(Clone, Copy)]
pub(crate) enum Kind {
    DeviceBinding,
    FileSecret,
}
#[cfg(not(test))]
static REFUSED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
#[cfg(test)]
thread_local! {
    static REFUSED: [AtomicU64; 2] = const { [const { AtomicU64::new(0) }; 2] };
    static RECORDS: std::cell::RefCell<Vec<serde_json::Value>> = const { std::cell::RefCell::new(Vec::new()) };
}
impl Kind {
    fn refuse(self) -> io::Error {
        let increment = |counters: &[AtomicU64; 2]| {
            counters[self as usize]
                .fetch_update(Relaxed, Relaxed, |n| Some(n.saturating_add(1)))
                .unwrap_or(u64::MAX)
                .saturating_add(1)
        };
        #[cfg(not(test))]
        let total = increment(&REFUSED);
        #[cfg(test)]
        let total = REFUSED.with(increment);
        let (kind, message) = match self {
            Self::DeviceBinding => ("device_binding", "device binding exceeds 64 KiB"),
            Self::FileSecret => ("file_secret", "file-backed secret exceeds 64 KiB"),
        };
        let record = serde_json::json!({
            "schema_version": 2,
            "process_id": std::process::id(),
            "stage": "credential_file_cap_refusal",
            "source": "unknown",
            "observation": {
                "observed_unix_ms": SystemTime::now().duration_since(UNIX_EPOCH).ok()
                    .and_then(|d| u64::try_from(d.as_millis()).ok()),
                "wall_elapsed_us": 0,
                "shared_process_cpu_delta_us": null,
                "process_lifetime_max_rss_bytes": null,
                "process_lifetime_max_rss_before_bytes": null
            },
            "counts": {"file_kind": kind, "credential_file_cap_refused": 1,
                "credential_file_cap_refused_total": total}
        });
        #[cfg(test)]
        RECORDS.with(|records| records.borrow_mut().push(record.clone()));
        // Same best-effort, counts-only stderr carrier as service diagnostics.
        // No path, account, secret, body length or content is serialized.
        let _ = writeln!(
            io::stderr().lock(),
            "ottto-service: local_resources {record}"
        );
        io::Error::new(io::ErrorKind::InvalidData, message)
    }
}

pub(crate) fn read(file: File, kind: Kind) -> io::Result<String> {
    if file.metadata()?.len() > LIMIT {
        return Err(kind.refuse());
    }
    read_body(file, kind)
}
fn read_body(reader: impl Read, kind: Kind) -> io::Result<String> {
    let mut bytes = Vec::with_capacity((LIMIT + 1) as usize);
    reader.take(LIMIT + 1).read_to_end(&mut bytes)?;
    if bytes.len() > LIMIT as usize {
        return Err(kind.refuse());
    }
    String::from_utf8(bytes).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_refusals_are_counted_once_for_metadata_and_growth_even_invalid_utf8() {
        REFUSED.with(|counts| counts.iter().for_each(|count| count.store(0, Relaxed)));
        let path = std::env::temp_dir().join(format!("credential-cap-{}", std::process::id()));
        let oversized = vec![b'x'; (LIMIT + 1) as usize];
        std::fs::write(&path, &oversized).unwrap();
        for kind in [Kind::DeviceBinding, Kind::FileSecret] {
            RECORDS.with(|records| records.borrow_mut().clear());
            let exact = vec![b'x'; LIMIT as usize];
            assert_eq!(read_body(&exact[..], kind).unwrap().len(), LIMIT as usize);
            assert!(read(File::open(&path).unwrap(), kind).is_err());
            // Simulate growth after metadata admission, including invalid UTF-8.
            let mut grown = oversized.clone();
            grown[0] = 0xff;
            let error = read_body(&grown[..], kind).unwrap_err();
            assert!(error.to_string().contains("exceeds 64 KiB"));
            assert!(read_body(&[0xff][..], kind).is_err());
            RECORDS.with(|records| {
                let records = records.borrow();
                assert_eq!(records.len(), 2);
                for (i, record) in records.iter().enumerate() {
                    assert_eq!(record["schema_version"], 2);
                    assert_eq!(record["stage"], "credential_file_cap_refusal");
                    assert_eq!(record["source"], "unknown");
                    assert_eq!(record["counts"]["credential_file_cap_refused"], 1);
                    assert_eq!(record["counts"]["credential_file_cap_refused_total"], i + 1);
                    assert_eq!(record["counts"].as_object().unwrap().len(), 3);
                    assert_eq!(
                        record["counts"]["file_kind"],
                        match kind {
                            Kind::DeviceBinding => "device_binding",
                            Kind::FileSecret => "file_secret",
                        }
                    );
                }
            });
        }
        std::fs::remove_file(path).unwrap();
    }
}
