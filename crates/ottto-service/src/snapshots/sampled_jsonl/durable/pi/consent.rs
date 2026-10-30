//! Content-free consent journal. Its own lock also covers store writes, so an
//! observed revocation cannot race a deferred write. Observation needs no store
//! writer: even a skipped scan must remember an off transition across restart.
use super::UploadGates;
use crate::transcript_acquisition::Scope;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const ROW: usize = 74;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct State {
    incarnation: [u8; 32],
    generation: u64,
    pub(crate) gates: UploadGates,
}
impl State {
    /// The existing envelope context carries the generation, leaving the Pi
    /// section and sampled certificate scope independent of store metadata.
    pub(crate) fn namespace(self, base: &Scope) -> Scope {
        let incarnation = self
            .incarnation
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        Scope(format!(
            "{}|pi-consent={incarnation}:{}:{}",
            base.0,
            self.generation,
            self.gates.bits()
        ))
    }
}

pub(crate) struct Guard {
    file: File,
    pub(crate) state: State,
}
impl Drop for Guard {
    fn drop(&mut self) {
        // SAFETY: the descriptor stays live until this guard is dropped.
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn invalid() -> io::Error {
    io::Error::other("Pi consent metadata unavailable")
}

fn open(support: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(support.join("pi-upload-consent"))?;
    let m = file.metadata()?;
    // This inode is both journal and lock; never replace or truncate it.
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || m.mode() & 0o777 != 0o600
    {
        return Err(invalid());
    }
    // SAFETY: the owned descriptor is live. Contention refuses this operation.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(file)
}

fn read(file: &mut File) -> io::Result<Option<State>> {
    let len = file.metadata()?.len();
    if len == 0 {
        return Ok(None);
    }
    if len % ROW as u64 != 0 {
        return Err(invalid());
    }
    file.seek(SeekFrom::End(-(ROW as i64)))?;
    let mut row = [0u8; ROW];
    file.read_exact(&mut row)?;
    if row[0] != 1 || row[1] & !7 != 0 || Sha256::digest(&row[..42])[..] != row[42..] {
        return Err(invalid());
    }
    Ok(Some(State {
        incarnation: row[2..34].try_into().map_err(|_| invalid())?,
        generation: u64::from_le_bytes(row[34..42].try_into().map_err(|_| invalid())?),
        gates: UploadGates::from_bits(row[1]),
    }))
}

/// Records only policy changes. A partial append fails closed on future opens;
/// losing the journal creates a new incarnation, never an old record context.
pub(crate) fn observe(support: &Path, gates: UploadGates) -> io::Result<State> {
    let mut file = open(support)?;
    let prior = read(&mut file)?;
    if let Some(prior) = prior.filter(|prior| prior.gates == gates) {
        return Ok(prior);
    }
    let mut state = match prior {
        Some(prior) => prior,
        None => {
            let mut incarnation = [0; 32];
            getrandom::fill(&mut incarnation).map_err(|_| invalid())?;
            State {
                incarnation,
                generation: 0,
                gates,
            }
        }
    };
    if prior.is_some_and(|prior| prior.gates.bits() & !gates.bits() != 0) {
        state.generation = state.generation.checked_add(1).ok_or_else(invalid)?;
    }
    state.gates = gates;
    let mut row = [0u8; ROW];
    row[0] = 1;
    row[1] = gates.bits();
    row[2..34].copy_from_slice(&state.incarnation);
    row[34..42].copy_from_slice(&state.generation.to_le_bytes());
    let checksum = Sha256::digest(&row[..42]);
    row[42..].copy_from_slice(&checksum);
    file.write_all(&row)?;
    file.sync_all()?;
    File::open(support)?.sync_all()?;
    Ok(state)
}

pub(crate) fn current(support: &Path) -> io::Result<Guard> {
    let mut file = open(support)?;
    let state = read(&mut file)?.ok_or_else(invalid)?;
    Ok(Guard { file, state })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn off_transition_survives_return_to_on_without_a_store_writer() {
        let scratch = crate::test_scratch::ScratchDir::new("pi-consent-generation");
        let on = UploadGates::from_bits(7);
        let a = observe(&scratch, on).unwrap();
        let b = observe(&scratch, UploadGates::from_bits(0)).unwrap();
        let again = observe(&scratch, on).unwrap();
        assert!(b.generation > a.generation);
        assert_eq!(again.generation, b.generation);
        assert_ne!(
            a.namespace(&Scope("synthetic".into())),
            again.namespace(&Scope("synthetic".into()))
        );
        assert_eq!(current(&scratch).unwrap().state, again);
    }
}
