//! Tests for the persisted approver store and the `Authorized` token.
//! Needs the `test-hooks` feature (enabled by the crate's self dev-dependency).
// Local exception to the crate's `forbid(unsafe_code)`: `libc::mkfifo`
// replaces spawning `mkfifo` (see `make_fifo`).
#![allow(unsafe_code)]

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::Duration;
use warden_agent::authorize::{action_hash, ApproverStore, AuthorizeError};
use warden_core::{
    Action, ApprovalError, Approver, Capability, PolicyConfig, Tier, MAX_SKEW_MS, MAX_TTL_MS,
};

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

fn chmod(p: &Path, m: u32) {
    fs::set_permissions(p, fs::Permissions::from_mode(m)).unwrap();
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

fn dir_names(home: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(home)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

/// Run `f` on another thread; fail if it does not return within 10 s.
fn within_timeout<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(Duration::from_secs(10))
        .expect("operation hung")
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
    assert_eq!(tok.tier(), Tier::Yes);
    assert_eq!(tok.expires_at_ms(), NOW + TTL);
    assert_eq!(
        tok.expires_at_ms(),
        store.last_approval_for_test().unwrap().expires_at_ms
    );

    let other = action("w2", Capability::DeletePath(PathBuf::from("/work/b.txt")));
    let tok2 = store.authorize(&other, &cfg(), NOW, TTL).unwrap();
    assert_ne!(tok2.action_hash(), tok.action_hash());
    assert_eq!(tok2.action_hash(), &action_hash(&other));
    assert_eq!(tok2.tier(), Tier::YesPin);
}

#[test]
fn blocked_action_cannot_be_authorized() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    let before = fs::read(spent_path(&home)).unwrap();
    let spent_before = store.spent_for_test();
    let err = store
        .authorize(&blocked_action(), &cfg(), NOW, TTL)
        .unwrap_err();
    assert_eq!(err, AuthorizeError::Approval(ApprovalError::Blocked));
    assert_eq!(fs::read(spent_path(&home)).unwrap(), before);
    assert_eq!(store.spent_for_test(), spent_before);
    assert_eq!(
        ApproverStore::authorize_auto(&blocked_action(), &cfg(), NOW, TTL).unwrap_err(),
        AuthorizeError::NotAuto
    );
}

#[test]
fn authorize_auto_refuses_non_auto_actions() {
    assert_eq!(
        ApproverStore::authorize_auto(&write_action(), &cfg(), NOW, TTL).unwrap_err(),
        AuthorizeError::NotAuto
    );
    let del = action("d1", Capability::DeletePath(PathBuf::from("/work/a.txt")));
    assert_eq!(
        ApproverStore::authorize_auto(&del, &cfg(), NOW, TTL).unwrap_err(),
        AuthorizeError::NotAuto
    );
    // Outside the allowed root a read is `Yes`, not `Auto`.
    let outside = action("r2", Capability::ReadPath(PathBuf::from("/etc/passwd")));
    assert_eq!(
        ApproverStore::authorize_auto(&outside, &cfg(), NOW, TTL).unwrap_err(),
        AuthorizeError::NotAuto
    );
}

#[test]
fn authorize_auto_accepts_auto_actions() {
    let a = auto_action();
    let tok = ApproverStore::authorize_auto(&a, &cfg(), NOW, TTL).unwrap();
    assert_eq!(tok.action_hash(), &action_hash(&a));
    assert_eq!(tok.tier(), Tier::Auto);
    assert_eq!(tok.expires_at_ms(), NOW + TTL);
}

#[test]
fn authorize_auto_applies_ttl_bounds() {
    for ttl in [0, MAX_TTL_MS + 1] {
        assert_eq!(
            ApproverStore::authorize_auto(&auto_action(), &cfg(), NOW, ttl).unwrap_err(),
            AuthorizeError::Approval(ApprovalError::BadTtl),
            "{ttl}"
        );
    }
    assert_eq!(
        ApproverStore::authorize_auto(&auto_action(), &cfg(), u64::MAX - 1, 10).unwrap_err(),
        AuthorizeError::Approval(ApprovalError::BadTtl)
    );
    let tok = ApproverStore::authorize_auto(&auto_action(), &cfg(), NOW, MAX_TTL_MS).unwrap();
    assert_eq!(tok.expires_at_ms(), NOW + MAX_TTL_MS);
}

#[test]
fn restart_does_not_reset_spent_nonces() {
    let (_d, home) = new_home();
    let a = write_action();
    let approval = {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        let _tok = store.authorize(&a, &cfg(), NOW, TTL).unwrap();
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

/// Two records: one expiring at NOW + 1000, one at NOW + MAX_TTL_MS.
fn two_records(home: &Path) -> (warden_core::Approval, warden_core::Approval) {
    let mut store = ApproverStore::open(home, NOW).unwrap();
    let _t1 = store
        .authorize(&write_action(), &cfg(), NOW, 1_000)
        .unwrap();
    let short = store.last_approval_for_test().unwrap().clone();
    let _t2 = store
        .authorize(&write_action(), &cfg(), NOW, MAX_TTL_MS)
        .unwrap();
    let long = store.last_approval_for_test().unwrap().clone();
    (short, long)
}

#[test]
fn expired_records_are_pruned_on_open() {
    let (_d, home) = new_home();
    let (_short, long) = two_records(&home);
    assert_eq!(spent_len(&home), 48);
    let ino_before = {
        use std::os::unix::fs::MetadataExt;
        fs::metadata(spent_path(&home)).unwrap().ino()
    };

    // Dropped only once expires_at + MAX_SKEW_MS <= now.
    let store = ApproverStore::open(&home, NOW + 1_000 + MAX_SKEW_MS).unwrap();
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
    assert_eq!(
        dir_names(&home),
        vec!["approver.key", "approver.lock", "spent-nonces"]
    );
}

#[test]
fn records_not_yet_expired_are_kept() {
    let (_d, home) = new_home();
    let (short, _long) = two_records(&home);
    let before = fs::read(spent_path(&home)).unwrap();
    // Past the short record's expiry but within the skew tolerance: kept.
    for now in [NOW + 1_000, NOW + 1_000 + MAX_SKEW_MS - 1] {
        let mut store = ApproverStore::open(&home, now).unwrap();
        assert_eq!(fs::read(spent_path(&home)).unwrap(), before);
        assert_eq!(store.spent_for_test().len(), 2);
        assert!(store.spent_for_test().contains(&short.nonce));
        assert_ne!(
            store.redeem_for_test(&write_action(), &cfg(), &short, NOW + 999),
            Ok(())
        );
    }
}

#[test]
fn stale_spent_tmp_is_removed_by_prune_rewrite() {
    let (_d, home) = new_home();
    let _ = two_records(&home);
    fs::write(home.join("spent-nonces.tmp"), b"garbage").unwrap();
    drop(ApproverStore::open(&home, NOW + 1_000 + MAX_SKEW_MS).unwrap());
    assert_eq!(spent_len(&home), 24);
    assert!(!home.join("spent-nonces.tmp").exists());
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
        let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
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
fn missing_spent_log_with_existing_key_fails_closed() {
    let (_d, home) = new_home();
    {
        let mut store = ApproverStore::open(&home, NOW).unwrap();
        let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    }
    fs::remove_file(spent_path(&home)).unwrap();
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    // Not recreated.
    assert!(!spent_path(&home).exists());

    // A fresh home still gets both files.
    let (_d2, home2) = new_home();
    let mut store = ApproverStore::open(&home2, NOW).unwrap();
    assert_eq!(spent_len(&home2), 0);
    let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
}

#[test]
fn spent_log_with_loose_permissions_is_refused() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    chmod(&spent_path(&home), 0o644);
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn lock_file_with_loose_permissions_is_refused() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    chmod(&home.join("approver.lock"), 0o666);
    let err = ApproverStore::open(&home, NOW).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::PermissionDenied);
}

#[test]
fn symlinked_spent_log_is_refused() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    let real = home.join("elsewhere");
    fs::rename(spent_path(&home), &real).unwrap();
    std::os::unix::fs::symlink(&real, spent_path(&home)).unwrap();
    assert!(ApproverStore::open(&home, NOW).is_err());
}

/// `mkfifo` without spawning a process: a forked child would share the open
/// file description of another test's `approver.lock` (and its `flock`) until
/// it execs, so a concurrent reopen could see `WouldBlock`.
fn make_fifo(path: &Path) -> std::io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    // SAFETY: `c` is a valid NUL-terminated path that outlives the call.
    if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[test]
fn fifo_spent_log_is_refused_without_hanging() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    fs::remove_file(spent_path(&home)).unwrap();
    make_fifo(&spent_path(&home)).unwrap();
    let h = home.clone();
    let res = within_timeout(move || ApproverStore::open(&h, NOW).map(|_| ()));
    assert_eq!(res.unwrap_err().kind(), ErrorKind::InvalidData);
}

#[test]
fn persist_failure_returns_no_token() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    chmod(&spent_path(&home), 0o400);
    if fs::OpenOptions::new()
        .append(true)
        .open(spent_path(&home))
        .is_ok()
    {
        eprintln!("skipping: read-only file is writable (running as root?)");
        return;
    }
    let res = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert!(matches!(
        res,
        Err(AuthorizeError::Persist(ErrorKind::PermissionDenied))
    ));
    assert_eq!(spent_len(&home), 0);
    // The nonce stays spent in memory: the approval is burned, not reusable.
    let approval = store.last_approval_for_test().unwrap().clone();
    assert_eq!(store.spent_for_test(), vec![approval.nonce]);
    assert_eq!(
        store.redeem_for_test(&write_action(), &cfg(), &approval, NOW + 1),
        Err(ApprovalError::AlreadyUsed)
    );
}

#[test]
fn failed_append_poisons_the_store_until_reopen() {
    let (_d, home) = new_home();
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    store.fail_next_append_for_test(12);
    let first = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert!(
        matches!(first, Err(AuthorizeError::Persist(_))),
        "{first:?}"
    );
    // The torn record was truncated back.
    assert_eq!(spent_len(&home), 24);
    // Burned nonce stays spent in memory.
    assert_eq!(store.spent_for_test().len(), 2);

    // Poisoned: no token, nothing granted, nothing written.
    let second = store.authorize(&write_action(), &cfg(), NOW, TTL);
    assert_eq!(second.unwrap_err(), AuthorizeError::Poisoned);
    assert_eq!(spent_len(&home), 24);
    assert_eq!(store.spent_for_test().len(), 2);
    // Auto actions need no persistence and stay allowed.
    let _auto = ApproverStore::authorize_auto(&auto_action(), &cfg(), NOW, TTL).unwrap();

    // Reopening clears the poison.
    drop(store);
    let mut store = ApproverStore::open(&home, NOW).unwrap();
    let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
    assert_eq!(spent_len(&home), 48);
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
    assert_eq!(
        dir_names(&home),
        vec!["approver.key", "approver.lock", "spent-nonces"]
    );
}

#[test]
fn key_is_reused_across_opens() {
    let (_d, home) = new_home();
    drop(ApproverStore::open(&home, NOW).unwrap());
    let k1 = key_bytes(&home);
    drop(ApproverStore::open(&home, NOW).unwrap());
    assert_eq!(key_bytes(&home), k1);
}

#[test]
fn leftover_tmp_key_does_not_block_open() {
    // Crash before the link: no key yet, a garbage temp key.
    let (_d, home) = new_home();
    fs::create_dir_all(&home).unwrap();
    fs::write(home.join("approver.key.tmp"), b"short").unwrap();
    drop(ApproverStore::open(&home, NOW).unwrap());
    assert_eq!(fs::metadata(home.join("approver.key")).unwrap().len(), 32);
    assert!(!home.join("approver.key.tmp").exists());

    // Crash after the link: key present, temp still there.
    let k = key_bytes(&home);
    fs::write(home.join("approver.key.tmp"), k).unwrap();
    drop(ApproverStore::open(&home, NOW).unwrap());
    assert_eq!(key_bytes(&home), k);
    assert!(!home.join("approver.key.tmp").exists());
}

fn write_key(home: &Path, bytes: &[u8], mode: u32) {
    fs::create_dir_all(home).unwrap();
    let p = home.join("approver.key");
    fs::write(&p, bytes).unwrap();
    chmod(&p, mode);
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
    let _tok = store.authorize(&write_action(), &cfg(), NOW, TTL).unwrap();
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
    let _t1 = store.authorize(&a, &cfg(), NOW, TTL).unwrap();
    assert_eq!(spent_len(&home), 24);
    let n1 = store.last_approval_for_test().unwrap().nonce;
    let _t2 = store.authorize(&a, &cfg(), NOW, TTL).unwrap();
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
    assert!(AuthorizeError::Poisoned.to_string().contains("reopen"));
    assert!(AuthorizeError::Persist(ErrorKind::PermissionDenied)
        .to_string()
        .contains("persist"));
}
