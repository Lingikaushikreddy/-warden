//! Actions the agent wants to perform, and the capabilities they need.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A single permission an action requires.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Capability {
    ReadPath(PathBuf),
    WritePath(PathBuf),
    DeletePath(PathBuf),
    RunNewScript(String),
    OpenApp(String),
    MessagePerson(String),
    SendEmail(String),
    InstallSoftware(String),
    NetworkSend(String),
    FormatDisk,
    EditRegistry,
    DisableSecurityTool,
    ReadSavedPasswords,
}

/// An action proposed by the agent, with the capabilities it needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Action {
    pub id: String,
    pub summary: String,
    pub capabilities: Vec<Capability>,
}

/// Raw bytes of a path, hex-encoded: total and lossless.
fn path_hex(p: &Path) -> String {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        hex::encode(p.as_os_str().as_bytes())
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        let bytes: Vec<u8> = p
            .as_os_str()
            .encode_wide()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        hex::encode(bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = p;
        compile_error!(
            "warden-core: lossless path encoding is only implemented for unix and windows targets"
        );
    }
}

/// Mirror of `Capability` whose paths are hex strings, so encoding cannot fail.
#[derive(Serialize)]
enum CanonCap<'a> {
    ReadPath(String),
    WritePath(String),
    DeletePath(String),
    RunNewScript(&'a str),
    OpenApp(&'a str),
    MessagePerson(&'a str),
    SendEmail(&'a str),
    InstallSoftware(&'a str),
    NetworkSend(&'a str),
    FormatDisk,
    EditRegistry,
    DisableSecurityTool,
    ReadSavedPasswords,
}

impl<'a> From<&'a Capability> for CanonCap<'a> {
    fn from(c: &'a Capability) -> Self {
        match c {
            Capability::ReadPath(p) => CanonCap::ReadPath(path_hex(p)),
            Capability::WritePath(p) => CanonCap::WritePath(path_hex(p)),
            Capability::DeletePath(p) => CanonCap::DeletePath(path_hex(p)),
            Capability::RunNewScript(s) => CanonCap::RunNewScript(s),
            Capability::OpenApp(s) => CanonCap::OpenApp(s),
            Capability::MessagePerson(s) => CanonCap::MessagePerson(s),
            Capability::SendEmail(s) => CanonCap::SendEmail(s),
            Capability::InstallSoftware(s) => CanonCap::InstallSoftware(s),
            Capability::NetworkSend(s) => CanonCap::NetworkSend(s),
            Capability::FormatDisk => CanonCap::FormatDisk,
            Capability::EditRegistry => CanonCap::EditRegistry,
            Capability::DisableSecurityTool => CanonCap::DisableSecurityTool,
            Capability::ReadSavedPasswords => CanonCap::ReadSavedPasswords,
        }
    }
}

impl Action {
    /// Deterministic JSON of `id`, `summary`, `capabilities` (fixed field
    /// order), used for hashing and signing. Paths are encoded as hex of their
    /// raw bytes, so the encoding is total and lossless. Capability order is
    /// significant: reordering capabilities changes the bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            id: &'a str,
            summary: &'a str,
            capabilities: Vec<CanonCap<'a>>,
        }
        let canon = Canonical {
            id: &self.id,
            summary: &self.summary,
            capabilities: self.capabilities.iter().map(CanonCap::from).collect(),
        };
        // Only strings, unit variants and sequences: serialization is infallible.
        serde_json::to_vec(&canon)
            .expect("canonical encoding is infallible: only strings, unit variants and sequences")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn action(path: &str) -> Action {
        Action {
            id: "a1".into(),
            summary: "write a file".into(),
            capabilities: vec![Capability::WritePath(PathBuf::from(path))],
        }
    }

    #[test]
    fn canonical_bytes_is_stable_across_calls() {
        let a = action("/a");
        assert_eq!(a.canonical_bytes(), a.canonical_bytes());
    }

    #[test]
    fn canonical_bytes_differs_when_a_path_differs() {
        assert_ne!(
            action("/a").canonical_bytes(),
            action("/b").canonical_bytes()
        );
    }

    #[test]
    fn canonical_bytes_golden() {
        assert_eq!(
            String::from_utf8(action("/a").canonical_bytes()).unwrap(),
            r#"{"id":"a1","summary":"write a file","capabilities":[{"WritePath":"2f61"}]}"#
        );
    }

    #[test]
    fn canonical_bytes_differs_when_id_or_summary_differs() {
        let base = action("/a");
        let mut a = base.clone();
        a.id = "a2".into();
        let mut b = base.clone();
        b.summary = "other".into();
        assert_ne!(base.canonical_bytes(), a.canonical_bytes());
        assert_ne!(base.canonical_bytes(), b.canonical_bytes());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_paths_do_not_panic_and_do_not_collide() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        let mk = |b: u8| Action {
            id: "x".into(),
            summary: "y".into(),
            capabilities: vec![Capability::ReadPath(PathBuf::from(OsString::from_vec(
                vec![b],
            )))],
        };
        assert_ne!(mk(0xff).canonical_bytes(), mk(0xfe).canonical_bytes());
    }
}
