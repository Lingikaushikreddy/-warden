//! Actions the agent wants to perform, and the capabilities they need.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

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

impl Action {
    /// Deterministic JSON of `id`, `summary`, `capabilities` (fixed field
    /// order), used for hashing and signing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            id: &'a str,
            summary: &'a str,
            capabilities: &'a [Capability],
        }
        serde_json::to_vec(&Canonical {
            id: &self.id,
            summary: &self.summary,
            capabilities: &self.capabilities,
        })
        .expect("action serialization cannot fail")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
        assert_ne!(action("/a").canonical_bytes(), action("/b").canonical_bytes());
    }
}
