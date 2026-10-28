//! Small private state files: the PIN lockout (`engine`), later the
//! Telegram update offset.
//!
//! Same file rules as the approver store: opened with `O_NOFOLLOW |
//! O_NONBLOCK` and checked through the handle (a regular file with no
//! group/other permission bits), replaced atomically (temp file, `sync_all`,
//! rename, directory fsync).

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const OPEN_FLAGS: i32 = libc::O_NOFOLLOW | libc::O_NONBLOCK;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Read the state file at `path`: `None` if it does not exist. Refused
/// (`InvalidData`) if it is a symlink, not a regular file or longer than
/// `max_len` bytes; refused (`PermissionDenied`) if group or others have
/// any permission bit.
pub(crate) fn read_private(path: &Path, max_len: usize) -> io::Result<Option<Vec<u8>>> {
    let f = match OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_FLAGS)
        .open(path)
    {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {
            return Err(invalid("state file is a symlink"))
        }
        Err(e) => return Err(e),
    };
    let meta = f.metadata()?;
    if !meta.is_file() {
        return Err(invalid("state file is not a regular file"));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "state file is accessible by group or others",
        ));
    }
    let too_long = || invalid("state file is too long");
    if meta.len() > u64::try_from(max_len).unwrap_or(u64::MAX) {
        return Err(too_long());
    }
    let mut bytes = Vec::with_capacity(max_len.min(4096));
    let limit = u64::try_from(max_len).unwrap_or(u64::MAX).saturating_add(1);
    f.take(limit).read_to_end(&mut bytes)?;
    // A file that grew after the length check is also refused.
    if bytes.len() > max_len {
        return Err(too_long());
    }
    Ok(Some(bytes))
}

/// `.<name>.warden-tmp` next to `path`.
fn temp_path(path: &Path) -> io::Result<(PathBuf, PathBuf)> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "state path has no name"))?;
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let mut tmp = OsString::from(".");
    tmp.push(name);
    tmp.push(".warden-tmp");
    Ok((dir.join(tmp), dir))
}

/// Replace the file at `path` with `bytes` atomically: a 0600 temp file in
/// the same directory, `sync_all`, rename over `path`, fsync the directory.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let (tmp, dir) = temp_path(path)?;
    // A stale temp file from a crashed write is never the state.
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let written = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(OPEN_FLAGS)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)
    })();
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
    File::open(&dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn write_atomic_replaces_and_is_0600() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("state");
        assert_eq!(read_private(&p, 16).unwrap(), None);
        write_atomic(&p, b"first").unwrap();
        assert_eq!(mode(&p), 0o600);
        assert_eq!(
            read_private(&p, 16).unwrap().as_deref(),
            Some(&b"first"[..])
        );
        write_atomic(&p, b"second!").unwrap();
        assert_eq!(mode(&p), 0o600);
        assert_eq!(
            read_private(&p, 16).unwrap().as_deref(),
            Some(&b"second!"[..])
        );
        // No temp file is left behind.
        let names: Vec<_> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("state")]);
        // A stale temp file from a crash does not block the next write.
        fs::write(tmp.path().join(".state.warden-tmp"), b"junk").unwrap();
        write_atomic(&p, b"third").unwrap();
        assert_eq!(
            read_private(&p, 16).unwrap().as_deref(),
            Some(&b"third"[..])
        );
        assert!(!tmp.path().join(".state.warden-tmp").exists());
        // Too long for `max_len`.
        assert_eq!(
            read_private(&p, 4).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn read_private_refuses_group_writable_and_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let p = tmp.path().join("state");
        write_atomic(&p, b"x").unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o620)).unwrap();
        assert_eq!(
            read_private(&p, 16).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o604)).unwrap();
        assert_eq!(
            read_private(&p, 16).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let link = tmp.path().join("link");
        symlink(&p, &link).unwrap();
        assert_eq!(
            read_private(&link, 16).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        // A directory is not a regular file.
        let d = tmp.path().join("dir");
        fs::create_dir(&d).unwrap();
        fs::set_permissions(&d, fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(
            read_private(&d, 16).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
