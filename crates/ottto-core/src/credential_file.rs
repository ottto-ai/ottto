//! Bounded credential reads; diagnostics belong to the service caller.
use std::fs::File;
use std::io::{self, Read};

const LIMIT: u64 = 64 * 1024;
/// A credential file refused before decoding because it exceeds 64 KiB.
#[derive(Clone, Copy, Debug, thiserror::Error)]
pub enum CredentialFileCapRefused {
    #[error("device binding exceeds 64 KiB")]
    DeviceBinding,
    #[error("file-backed secret exceeds 64 KiB")]
    FileSecret,
    #[error("connection binding exceeds 64 KiB")]
    ConnectionBinding,
    #[error("pending device credential exceeds 64 KiB")]
    PendingDeviceCredential,
}
impl CredentialFileCapRefused {
    fn refuse(self) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, self)
    }
}

pub(crate) fn read(file: File, kind: CredentialFileCapRefused) -> io::Result<String> {
    let len = file.metadata()?.len();
    if len > LIMIT {
        return Err(kind.refuse());
    }
    read_body(file, kind, (len + 1) as usize)
}
fn read_body(
    reader: impl Read,
    kind: CredentialFileCapRefused,
    capacity: usize,
) -> io::Result<String> {
    let mut bytes = Vec::with_capacity(capacity.min((LIMIT + 1) as usize));
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
    fn cap_refusals_are_typed_for_metadata_and_growth_even_invalid_utf8() {
        let path = std::env::temp_dir().join(format!("credential-cap-{}", std::process::id()));
        let oversized = vec![b'x'; (LIMIT + 1) as usize];
        std::fs::write(&path, &oversized).unwrap();
        for kind in [
            CredentialFileCapRefused::DeviceBinding,
            CredentialFileCapRefused::FileSecret,
            CredentialFileCapRefused::ConnectionBinding,
            CredentialFileCapRefused::PendingDeviceCredential,
        ] {
            let exact = vec![b'x'; LIMIT as usize];
            assert_eq!(
                read_body(&exact[..], kind, exact.len() + 1).unwrap().len(),
                LIMIT as usize
            );
            let error = read(File::open(&path).unwrap(), kind).unwrap_err();
            assert!(error.get_ref().unwrap().is::<CredentialFileCapRefused>());
            // Simulate growth after metadata admission, including invalid UTF-8.
            let mut grown = oversized.clone();
            grown[0] = 0xff;
            let error = read_body(&grown[..], kind, 1).unwrap_err();
            assert!(error.to_string().contains("exceeds 64 KiB"));
            assert!(error.get_ref().unwrap().is::<CredentialFileCapRefused>());
            let invalid = read_body(&[0xff][..], kind, 2).unwrap_err();
            assert!(!invalid.get_ref().unwrap().is::<CredentialFileCapRefused>());
        }
        std::fs::remove_file(path).unwrap();
    }
}
