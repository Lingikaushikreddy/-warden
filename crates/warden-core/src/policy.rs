//! Tier classification: what approval an action needs, from its capabilities only.

use crate::action::{Action, Capability};
use serde::{Deserialize, Serialize};
use std::path::{Component, Path, PathBuf};

/// Approval tier, ordered from least to most restrictive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Tier {
    Auto,
    Yes,
    YesPin,
    Blocked,
}

/// Policy configuration.
///
/// Note: an allowed root of `/` makes every absolute read `Auto`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub allowed_roots: Vec<PathBuf>,
}

/// Lexically normalize an absolute path (resolve `.` and `..` without touching
/// the filesystem). Returns `None` for relative paths, so they can never count
/// as inside any root. `..` at the filesystem root stays at the root.
///
/// Lexical only: symlinks are NOT resolved and the filesystem is never touched.
fn normalize(p: &Path) -> Option<PathBuf> {
    if !p.is_absolute() {
        return None;
    }
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Prefix(_) | Component::RootDir => out.push(c.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                // Never pop the root/prefix itself.
                if out.components().count() > 1 {
                    out.pop();
                }
            }
            Component::Normal(s) => out.push(s),
        }
    }
    Some(out)
}

/// True if `path` lies under any allowed root, compared lexically.
///
/// Symlinks are not resolved, so `/root/link/id_rsa` with `link -> ~/.ssh` is
/// reported inside. Roots containing `..` are normalized lexically too.
/// The executor MUST canonicalize or open with no-follow before acting.
fn inside_any_root(path: &Path, cfg: &PolicyConfig) -> bool {
    let Some(p) = normalize(path) else {
        return false;
    };
    cfg.allowed_roots
        .iter()
        .filter_map(|r| normalize(r))
        .any(|r| p.starts_with(&r))
}

fn tier_of(cap: &Capability, cfg: &PolicyConfig) -> Tier {
    match cap {
        Capability::ReadPath(p) => {
            if inside_any_root(p, cfg) {
                Tier::Auto
            } else {
                Tier::Yes
            }
        }
        Capability::WritePath(_) | Capability::RunNewScript(_) | Capability::OpenApp(_) => {
            Tier::Yes
        }
        Capability::MessagePerson(_)
        | Capability::SendEmail(_)
        | Capability::InstallSoftware(_)
        | Capability::NetworkSend(_)
        | Capability::DeletePath(_) => Tier::YesPin,
        Capability::FormatDisk
        | Capability::EditRegistry
        | Capability::DisableSecurityTool
        | Capability::ReadSavedPasswords => Tier::Blocked,
    }
}

/// Highest tier over all capabilities; an empty list is `Auto`.
///
/// Pure and lexical: symlinks are not resolved and roots containing `..` are
/// normalized lexically. The executor MUST canonicalize or open with no-follow
/// before acting on an `Auto` read (snapshot.rs does not cover reads); see
/// docs/SECURITY-NOTES.md.
pub fn classify(action: &Action, cfg: &PolicyConfig) -> Tier {
    action
        .capabilities
        .iter()
        .map(|c| tier_of(c, cfg))
        .max()
        .unwrap_or(Tier::Auto)
}
