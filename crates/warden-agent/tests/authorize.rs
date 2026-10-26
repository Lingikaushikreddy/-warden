//! Tests for the persisted approver store and the `Authorized` token.
//! Needs the `test-hooks` feature (enabled by the crate's self dev-dependency).

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use warden_agent::authorize::{action_hash, ApproverStore, AuthorizeError};
use warden_core::{Action, ApprovalError, Approver, Capability, PolicyConfig, MAX_TTL_MS};

const NOW: u64 = 1_700_000_000_000;
const TTL: u64 = 60_000;

fn cfg() -> PolicyConfig {
    PolicyConfig {
        allowed_roots: vec![PathBuf::from("/work")],
    }
}

fn action(id: &str, cap: Capability) -> Action {
    Action {
        id: id.into(),
        summary: "test action".into(),
        capabilities: vec![cap],
    }
}

/// Classified `Yes`.
fn write_action() -> Action {
    action("w1", Capability::WritePath(PathBuf::from("/work/a.txt")))
}

/// Classified `Auto` (read inside the allowed root).
fn auto_action() -> Action {
    action("r1", Capability::ReadPath(PathBuf::from("/work/a.txt")))
}

/// Classified `Blocked`.
fn blocked_action() -> Action {
    action("b1", Capability::FormatDisk)
}

fn spent_path(home: &Path) -> PathBuf {
    home.join("spent-nonces")
}

fn spent_len(home: &Path) -> u64 {
    fs::metadata(spent_path(home)).unwrap().len()
}

fn mode(p: &Path) -> u32 {
    fs::metadata(p).unwrap().permissions().mode() & 0o777
}

/// Parse the spent file the way the store documents it.
fn records(home: &Path) -> Vec<([u8; 16], u64)> {
    let bytes = fs::read(spent_path(home)).unwrap();
    assert_eq!(bytes.len() % 24, 0);
    bytes
        .chunks(24)
        .map(|r| {
            let mut n = [0u8; 16];
            n.copy_from_slice(&r[..16]);
            (n, u64::from_be_bytes(r[16..].try_into().unwrap()))
        })
        .collect()
}

fn key_bytes(home: &Path) -> [u8; 32] {
    fs::read(home.join("approver.key"))
        .unwrap()
        .try_into()
        .unwrap()
}

fn new_home() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path().join("home");
    (dir, home)
}

#[test]
fn authorize_returns_token_bound_to_action() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let a = write_action();
    let tok = store.authorize(&a, &cfg(), NOW, TTL).unwrap();
    let expected: [u8; 32] = Sha256::digest(a.canonical_bytes()).into();
    assert_eq!(action_hash(&a), expected);
    assert_eq!(tok.action_hash(), &action_hash(&a));

    let other = action("w2", Capability::WritePath(PathBuf::from("/work/b.txt")));
    let tok2 = store.authorize(&other, &cfg(), NOW, TTL).unwrap();
    assert_ne!(tok2.action_hash(), tok.action_hash());
    assert_eq!(tok2.action_hash(), &action_hash(&other));
}

#[test]
fn blocked_action_cannot_be_authorized() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let before = fs::read(spent_path(&home)).unwrap();
    let err = store
        .authorize(&blocked_action(), &cfg(), NOW, TTL)
        .unwrap_err();
    assert_eq!(err, AuthorizeError::Approval(ApprovalError::Blocked));
    assert_eq!(fs::read(spent_path(&home)).unwrap(), before);
    assert!(store.last_approval_for_test().is_none());
    assert_eq!(
        ApproverStore::authorize_auto(&blocked_action(), &cfg()).unwrap_err(),
        AuthorizeError::NotAuto
    );
}

#[test]
fn authorize_auto_refuses_non_auto_actions() {
    assert_eq!(
        ApproverStore::authorize_auto(&write_action(), &cfg()).unwrap_err(),
        AuthorizeError::NotAuto
    );
    let del = action("d1", Capability::DeletePath(PathBuf::from("/work/a.txt")));
    assert_eq!(
        ApproverStore::authorize_auto(&del, &cfg()).unwrap_err(),
        AuthorizeError::NotAuto
    );
    // Outside the allowed root a read is `Yes`, not `Auto`.
    let outside = action("r2", Capability::ReadPath(PathBuf::from("/etc/passwd")));
    assert_eq!(
        ApproverStore::authorize_auto(&outside, &cfg()).unwrap_err(),
        AuthorizeError::NotAuto
    );
}

#[test]
fn authorize_auto_accepts_auto_actions() {
    let a = auto_action();
    let tok = ApproverStore::authorize_auto(&a, &cfg()).unwrap();
    assert_eq!(tok.action_hash(), &action_hash(&a));
}

#[test]
fn restart_does_not_reset_spent_nonces() {
    let (_d, home) = new_home();
    let a = write_action();
    let approval = {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        store.authorize(&a, &cfg(), NOW, TTL).unwrap();
        store.last_approval_for_test().unwrap().clone()
    }; // store dropped: lock released, in-memory state gone

    // Control: the same key with an EMPTY spent set would accept the replay,
    // so the approval is otherwise valid and only persisted state stops it.
    let key = SigningKey::from_bytes(&key_bytes(&home));
    let mut fresh = Approver::from_signing_key(key.clone());
    assert_eq!(fresh.redeem(&a, &cfg(), &approval, NOW + 1), Ok(()));

    // Rebuilt the way the store does: key + persisted records.
    let nonces: Vec<[u8; 16]> = records(&home).into_iter().map(|(n, _)| n).collect();
    assert_eq!(nonces, vec![approval.nonce]);
    let mut rebuilt = Approver::from_signing_key_with_spent(key, nonces);
    assert_eq!(
        rebuilt.redeem(&a, &cfg(), &approval, NOW + 1),
        Err(ApprovalError::AlreadyUsed)
    );

    // And the reopened store itself loaded the spent set.
    let mut store = ApproverStore::open(&home, NOW + 1).unwrap();
    assert_eq!(store.spent_for_test(), vec![approval.nonce]);
    assert_eq!(
        store.redeem_for_test(&a, &cfg(), &approval, NOW + 1),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn expired_records_are_pruned_on_open() {
    let (_d, home) = new_home();
    let a = write_action();
    let long = {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        store.authorize(&a, &cfg(), NOW, 1_000).unwrap();
        store.authorize(&a, &cfg(), NOW, MAX_TTL_MS).unwrap();
        store.last_approval_for_test().unwrap().clone()
    };
    assert_eq!(spent_len(&home), 48);
    let ino_before = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(spent_path(&home)).unwrap().ino()
    };

    // expires_at == now counts as expired.
    let store = ApproverStore::open(&home, NOW + 1_000).unwrap();
    assert_eq!(spent_len(&home), 24);
    assert_eq!(records(&home), vec![(long.nonce, NOW + MAX_TTL_MS)]);
    assert_eq!(store.spent_for_test(), vec![long.nonce]);
    assert_eq!(mode(&spent_path(&home)), 0o600);
    // Rewritten by rename (new inode), and no temp file left behind.
    let ino_after = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(spent_path(&home)).unwrap().ino()
    };
    assert_ne!(ino_before, ino_after);
    let mut names: Vec<String> = fs::read_dir(&home)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(names, vec!["approver.key", "approver.lock", "spent-nonces"]);
}

#[test]
fn records_not_yet_expired_are_kept() {
    let (_d, home) = new_home();
    let a = write_action();
    let first = {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        store.authorize(&a, &cfg(), NOW, 1_000).unwrap();
        let first = store.last_approval_for_test().unwrap().clone();
        store.authorize(&a, &cfg(), NOW, MAX_TTL_MS).unwrap();
        first
    };
    let before = fs::read(spent_path(&home)).unwrap();
    let mut store = ApproverStore::open(&home, NOW + 999).unwrap();
    assert_eq!(fs::read(spent_path(&home)).unwrap(), before);
    assert_eq!(store.spent_for_test().len(), 2);
    assert_eq!(
        store.redeem_for_test(&a, &cfg(), &first, NOW + 999),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn truncated_spent_file_fails_open_with_invalid_data() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    fs::write(spent_path(&home), [0u8; 25]).unwrap();
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    // Not repaired.
    assert_eq!(spent_len(&home), 25);
}

#[test]
fn partial_record_after_crash_fails_open_with_invalid_data() {
    let (_d, home) = new_home();
    {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    }
    // Simulate a crash mid-append: half of a second record.
    let mut bytes = fs::read(spent_path(&home)).unwrap();
    bytes.extend_from_slice(&[0xAB; 12]);
    fs::write(spent_path(&home), &bytes).unwrap();
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    assert_eq!(spent_len(&home), 36);
}

#[test]
fn persist_failure_returns_no_token() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    fs::set_permissions(spent_path(&home), fs::Permissions::from_mode(0o400)).unwrap();
    let res = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert!(matches!(
        res,
        Err(AuthorizeError::Persist(ErrorKind::PermissionDenied))
    ));
    assert_eq!(spent_len(&home), 0);
}

#[test]
fn persist_failure_when_spent_file_replaced_by_directory() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    fs::remove_file(spent_path(&home)).unwrap();
    fs::create_dir(spent_path(&home)).unwrap();
    let res = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert!(matches!(res, Err(AuthorizeError::Persist(_))), "{res:?}");
}

#[test]
fn persist_failure_when_spent_file_deleted_does_not_recreate_it() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    fs::remove_file(spent_path(&home)).unwrap();
    let res = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert!(matches!(
        res,
        Err(AuthorizeError::Persist(ErrorKind::NotFound))
    ));
    assert!(!spent_path(&home).exists());
}

#[test]
fn key_and_spent_and_lock_files_are_0600_and_home_is_0700() {
    let (_d, home) = new_home();
    let _store = ApproverStore::open(&home, NOW).unwrap();
    assert_eq!(mode(&home), 0o700);
    assert_eq!(mode(&home.join("approver.key")), 0o600);
    assert_eq!(mode(&spent_path(&home)), 0o600);
    assert_eq!(mode(&home.join("approver.lock")), 0o600);
    assert_eq!(fs::metadata(home.join("approver.key")).unwrap().len(), 32);
    assert_eq!(spent_len(&home), 0);
}

#[test]
fn key_is_reused_across_opens() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    let k1 = key_bytes(&home);
    drop(ApproverStore::open(&home, NOW).unwrap());
    assert_eq!(key_bytes(&home), k1);
}

fn write_key(home: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(home).unwrap();
    let p = home.join("approver.key");
    fs::write(&p, bytes).unwrap();
    fs::set_permissions(&p, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn wrong_size_key_file_is_invalid_data() {
    for len in [0usize, 31, 33, 64] {
        let (_d, home) = new_home();
        write_key(&home, &vec![7u8; len], 0o600);
        let err = ApproverStore::open(&home, NOW).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::InvalidData, "len {len}");
        // Not replaced.
        assert_eq!(fs::read(home.join("approver.key")).unwrap().len(), len);
    }
}

#[test]
fn key_file_with_loose_permissions_is_refused() {
    for m in [0o640, 0o604, 0o644, 0o660] {
        let (_d, home) = new_home();
        write_key(&home, &[7u8; 32], m);
        let err = ApproverStore::open(&home, NOW).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied, "mode {m:o}");
    }
}

#[test]
fn second_open_on_same_home_is_would_block() {
    let (_d, home) = new_home();
    let store = ApproverStore::open(&home, NOW).unwrap();
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    drop(store);
    ApproverStore::open(&home, NOW).unwrap();
}

#[test]
fn debug_output_never_contains_key_bytes() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    let key = key_bytes(&home);
    let dbg = format!("{store:?} {store:#?}");
    assert!(!dbg.contains(&hex::encode(key)), "{dbg}");
    assert!(
        !dbg.to_lowercase().contains(&hex::encode(&key[..8])),
        "{dbg}"
    );
    assert!(!dbg.contains(&format!("{:?}", key)), "{dbg}");
    assert!(!dbg.contains(&format!("{:?}", &key[..8])), "{dbg}");
    let err = format!(
        "{} {:?}",
        AuthorizeError::Persist(ErrorKind::PermissionDenied),
        AuthorizeError::NotAuto
    );
    assert!(!err.contains(&hex::encode(key)));
}

#[test]
fn bad_ttl_is_refused_without_writing_a_record() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    for ttl in [0, MAX_TTL_MS + 1, u64::MAX] {
        let err = store
            .authorize(&write_action(), &cfg(), NOW, ttl)
            .unwrap_err();
        assert_eq!(
            err,
            AuthorizeError::Approval(ApprovalError::BadTtl),
            "{ttl}"
        );
    }
    assert_eq!(spent_len(&home), 0);
    assert!(store.spent_for_test().is_empty());
}

#[test]
fn repeated_authorizations_use_fresh_nonces_and_append_24_bytes_each() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let a = write_action();
    store.authorize(&a, &cfg(), NOW, TTL).unwrap();
    assert_eq!(spent_len(&home), 24);
    let n1 = store.last_approval_for_test().unwrap().nonce;
    store.authorize(&a, &cfg(), NOW, TTL).unwrap();
    assert_eq!(spent_len(&home), 48);
    let n2 = store.last_approval_for_test().unwrap().nonce;
    assert_ne!(n1, n2);
    assert_eq!(records(&home), vec![(n1, NOW + TTL), (n2, NOW + TTL)]);
}

#[test]
fn authorize_error_implements_error_and_display() {
    fn is_error<E: std::error::Error>(_: &E) {}
    let e = AuthorizeError::Approval(ApprovalError::Expired);
    is_error(&e);
    assert!(!e.to_string().is_empty());
    assert!(!AuthorizeError::NotAuto.to_string().is_empty());
    assert!(AuthorizeError::Persist(ErrorKind::PermissionDenied)
        .to_string()
        .contains("persist"));
}
