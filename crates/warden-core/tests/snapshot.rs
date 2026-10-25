use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use tempfile::TempDir;
use warden_core::{SnapshotError, SnapshotId, SnapshotStore};

#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    store_dir: TempDir,
    root: TempDir,
    store: SnapshotStore,
}

fn fixture() -> Fixture {
    let store_dir = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let store = SnapshotStore::open(store_dir.path()).unwrap();
    Fixture {
        store_dir,
        root,
        store,
    }
}

impl Fixture {
    fn root(&self) -> &Path {
        self.root.path()
    }
    fn file(&self, rel: &str, contents: &str) -> PathBuf {
        let p = self.root().join(rel);
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&p, contents).unwrap();
        p
    }
    fn manifest_path(&self, id: &SnapshotId) -> PathBuf {
        self.store_dir
            .path()
            .join("manifests")
            .join(format!("{}.json", id.0))
    }
    fn manifest(&self, id: &SnapshotId) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.manifest_path(id)).unwrap()).unwrap()
    }
    fn write_manifest(&self, id: &SnapshotId, v: &serde_json::Value) {
        fs::write(self.manifest_path(id), serde_json::to_vec(v).unwrap()).unwrap();
    }
    fn blobs(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.store_dir.path().join("blobs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }
    fn blob_path(&self, hash: &str) -> PathBuf {
        self.store_dir.path().join("blobs").join(hash)
    }
}

fn canon(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap()
}

fn read(p: &Path) -> String {
    fs::read_to_string(p).unwrap()
}

#[test]
fn snapshot_and_restore_roundtrip() {
    let f = fixture();
    let a = f.file("a.txt", "one");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::write(&a, "two").unwrap();
    f.store.record_after(&id, f.root()).unwrap();
    let restored = f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(read(&a), "one");
    assert_eq!(restored, vec![canon(&a)]);
}

#[test]
fn identical_files_share_one_blob() {
    let f = fixture();
    let a = f.file("a.txt", "same bytes");
    let b = f.file("sub/b.txt", "same bytes");
    f.store.snapshot(&[a, b], f.root()).unwrap();
    assert_eq!(f.blobs().len(), 1);
}

#[test]
fn missing_file_is_recorded_and_removed_on_restore() {
    let f = fixture();
    let new = f.root().join("new.txt");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&new), f.root())
        .unwrap();
    let m = f.manifest(&id);
    assert_eq!(m["entries"][0]["existed"], serde_json::Value::Bool(false));
    fs::write(&new, "created by the agent").unwrap();
    f.store.record_after(&id, f.root()).unwrap();
    let restored = f.store.restore(&id, f.root(), false).unwrap();
    assert!(!new.exists());
    assert_eq!(restored, vec![canon(f.root()).join("new.txt")]);
}

#[test]
fn missing_file_absent_at_restore_is_a_no_op() {
    let f = fixture();
    let new = f.root().join("new.txt");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&new), f.root())
        .unwrap();
    let restored = f.store.restore(&id, f.root(), false).unwrap();
    assert!(restored.is_empty());
    assert!(!new.exists());
}

#[cfg(unix)]
#[test]
fn symlink_is_rejected() {
    let f = fixture();
    let target = f.file("target.txt", "secret");
    let link = f.root().join("link.txt");
    symlink(&target, &link).unwrap();
    let err = f.store.snapshot(&[link], f.root()).unwrap_err();
    assert!(matches!(err, SnapshotError::Symlink(_)), "{err:?}");
}

#[cfg(unix)]
#[test]
fn symlinked_parent_is_rejected_at_snapshot() {
    let f = fixture();
    f.file("real/f.txt", "x");
    symlink(f.root().join("real"), f.root().join("alias")).unwrap();
    let err = f
        .store
        .snapshot(&[f.root().join("alias/f.txt")], f.root())
        .unwrap_err();
    assert!(matches!(err, SnapshotError::Symlink(_)), "{err:?}");
}

#[test]
fn path_outside_root_is_rejected() {
    let f = fixture();
    let other = TempDir::new().unwrap();
    let outside = other.path().join("o.txt");
    fs::write(&outside, "o").unwrap();
    let err = f.store.snapshot(&[outside], f.root()).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");

    let dotdot = f.root().join("..").join("o.txt");
    let err = f.store.snapshot(&[dotdot], f.root()).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");

    let err = f
        .store
        .snapshot(&[PathBuf::from("relative.txt")], f.root())
        .unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
}

#[test]
fn directory_is_not_a_file() {
    let f = fixture();
    let d = f.root().join("dir");
    fs::create_dir(&d).unwrap();
    let err = f.store.snapshot(&[d], f.root()).unwrap_err();
    assert!(matches!(err, SnapshotError::NotAFile(_)), "{err:?}");
}

#[test]
fn restore_refuses_if_changed_again_without_force() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let b = f.file("b.txt", "b1");
    let id = f.store.snapshot(&[a.clone(), b.clone()], f.root()).unwrap();
    fs::write(&a, "a2").unwrap();
    fs::write(&b, "b2").unwrap();
    f.store.record_after(&id, f.root()).unwrap();
    fs::write(&b, "b3").unwrap();
    let err = f.store.restore(&id, f.root(), false).unwrap_err();
    match err {
        SnapshotError::ChangedSinceSnapshot(p) => assert_eq!(p, canon(&b)),
        other => panic!("unexpected {other:?}"),
    }
    // All-or-nothing: `a` was unchanged since record_after but must not be
    // written back because `b` failed.
    assert_eq!(read(&a), "a2");
    assert_eq!(read(&b), "b3");
}

#[test]
fn restore_refuses_if_deleted_file_was_recreated() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::remove_file(&a).unwrap();
    f.store.record_after(&id, f.root()).unwrap();
    fs::write(&a, "new").unwrap();
    let err = f.store.restore(&id, f.root(), false).unwrap_err();
    assert!(
        matches!(err, SnapshotError::ChangedSinceSnapshot(_)),
        "{err:?}"
    );
    assert_eq!(read(&a), "new");
    f.store.restore(&id, f.root(), true).unwrap();
    assert_eq!(read(&a), "a1");
}

#[test]
fn restore_with_force_overwrites() {
    let f = fixture();
    let a = f.file("a.txt", "one");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::write(&a, "two").unwrap();
    f.store.record_after(&id, f.root()).unwrap();
    fs::write(&a, "three").unwrap();
    f.store.restore(&id, f.root(), true).unwrap();
    assert_eq!(read(&a), "one");
}

#[test]
fn restore_without_record_after_skips_changed_check() {
    let f = fixture();
    let a = f.file("a.txt", "one");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::write(&a, "two").unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(read(&a), "one");
}

#[test]
fn restore_recreates_missing_parent_directories() {
    let f = fixture();
    let a = f.file("d/e/a.txt", "deep");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::remove_dir_all(f.root().join("d")).unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(read(&a), "deep");
}

#[test]
fn prune_removes_old_manifests_and_orphan_blobs() {
    let f = fixture();
    let a = f.file("a.txt", "only in old");
    let b = f.file("b.txt", "shared");
    let old = f.store.snapshot(&[a.clone(), b.clone()], f.root()).unwrap();
    let c = f.file("c.txt", "shared");
    let new = f.store.snapshot(&[c], f.root()).unwrap();
    assert_eq!(f.blobs().len(), 2);

    // Age the first manifest by its recorded timestamp, not its mtime.
    let mut m = f.manifest(&old);
    m["created_unix_ms"] = serde_json::json!(0);
    f.write_manifest(&old, &m);

    let removed = f.store.prune(Duration::from_secs(30 * 24 * 3600)).unwrap();
    assert_eq!(removed, 1);
    assert!(!f.manifest_path(&old).exists());
    assert!(f.manifest_path(&new).exists());
    let blobs = f.blobs();
    assert_eq!(blobs.len(), 1, "orphan blob must go, shared blob must stay");
    let new_hash = f.manifest(&new)["entries"][0]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    assert_eq!(blobs, vec![new_hash]);
    assert!(matches!(
        f.store.restore(&old, f.root(), false).unwrap_err(),
        SnapshotError::UnknownSnapshot
    ));
}

#[test]
fn prune_with_corrupt_manifest_deletes_no_blobs() {
    let f = fixture();
    let a = f.file("a.txt", "keep me");
    let id = f.store.snapshot(&[a], f.root()).unwrap();
    let bogus = SnapshotId("0123456789abcdef0123456789abcdef".into());
    fs::write(f.manifest_path(&bogus), b"{not json").unwrap();
    assert!(f.store.prune(Duration::ZERO).is_err());
    assert_eq!(f.blobs().len(), 1);
    assert!(f.manifest_path(&id).exists());
}

#[test]
fn tampered_manifest_with_dotdot_is_rejected_and_nothing_written() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let b = f.file("b.txt", "b1");
    let id = f.store.snapshot(&[a.clone(), b], f.root()).unwrap();
    fs::write(&a, "a2").unwrap();
    let mut m = f.manifest(&id);
    let evil = format!("{}/../escaped.txt", canon(f.root()).display());
    m["entries"][1]["path"] = serde_json::json!(evil);
    f.write_manifest(&id, &m);
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
    assert_eq!(read(&a), "a2");
    assert!(!canon(f.root())
        .parent()
        .unwrap()
        .join("escaped.txt")
        .exists());
}

#[test]
fn tampered_manifest_outside_root_is_rejected() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f.store.snapshot(&[a], f.root()).unwrap();
    let other = TempDir::new().unwrap();
    let victim = other.path().join("victim.txt");
    fs::write(&victim, "precious").unwrap();
    let mut m = f.manifest(&id);
    m["entries"][0]["path"] = serde_json::json!(canon(other.path()).join("victim.txt"));
    f.write_manifest(&id, &m);
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
    assert_eq!(read(&victim), "precious");

    // Rewriting the recorded root itself to "/" with a relative entry path
    // is also refused.
    let mut m = f.manifest(&id);
    m["allowed_root"] = serde_json::json!("/");
    m["entries"][0]["path"] = serde_json::json!("relative.txt");
    f.write_manifest(&id, &m);
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
}

#[test]
fn tampered_blob_hash_name_is_rejected() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f.store.snapshot(&[a], f.root()).unwrap();
    let mut m = f.manifest(&id);
    m["entries"][0]["sha256"] = serde_json::json!("../../../etc/passwd");
    f.write_manifest(&id, &m);
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::CorruptManifest), "{err:?}");
}

#[test]
fn invalid_snapshot_id_is_rejected() {
    let f = fixture();
    for bad in [
        "../x",
        "../../manifests/x",
        "",
        "0123456789ABCDEF0123456789ABCDEF",
        "0123456789abcdef0123456789abcde",
    ] {
        let id = SnapshotId(bad.into());
        assert!(
            matches!(
                f.store.restore(&id, f.root(), true),
                Err(SnapshotError::UnknownSnapshot)
            ),
            "restore accepted {bad:?}"
        );
        assert!(
            matches!(
                f.store.record_after(&id, f.root()),
                Err(SnapshotError::UnknownSnapshot)
            ),
            "record_after accepted {bad:?}"
        );
    }
    let missing = SnapshotId("0123456789abcdef0123456789abcdef".into());
    assert!(matches!(
        f.store.restore(&missing, f.root(), true),
        Err(SnapshotError::UnknownSnapshot)
    ));
}

#[test]
fn snapshot_ids_are_32_lowercase_hex() {
    let f = fixture();
    let a = f.file("a.txt", "x");
    let id = f.store.snapshot(&[a], f.root()).unwrap();
    assert_eq!(id.0.len(), 32);
    assert!(id
        .0
        .bytes()
        .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)));
}

#[test]
fn corrupt_blob_is_detected_and_nothing_written() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let b = f.file("b.txt", "b1");
    let id = f.store.snapshot(&[a.clone(), b.clone()], f.root()).unwrap();
    fs::write(&a, "a2").unwrap();
    fs::write(&b, "b2").unwrap();
    let hash_b = f.manifest(&id)["entries"][1]["sha256"]
        .as_str()
        .unwrap()
        .to_string();
    fs::write(f.blob_path(&hash_b), "bit rot").unwrap();
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::CorruptBlob(_)), "{err:?}");
    assert_eq!(read(&a), "a2");
    assert_eq!(read(&b), "b2");
}

#[test]
fn swapped_blob_is_detected() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let b = f.file("b.txt", "b1");
    let id = f.store.snapshot(&[a.clone(), b], f.root()).unwrap();
    fs::write(&a, "a2").unwrap();
    let m = f.manifest(&id);
    let ha = m["entries"][0]["sha256"].as_str().unwrap().to_string();
    let hb = m["entries"][1]["sha256"].as_str().unwrap().to_string();
    fs::copy(f.blob_path(&hb), f.blob_path(&ha)).unwrap();
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::CorruptBlob(_)), "{err:?}");
    assert_eq!(read(&a), "a2");
}

#[cfg(unix)]
#[test]
fn symlinked_parent_is_rejected_at_restore() {
    let f = fixture();
    let a = f.file("d/a.txt", "a1");
    let id = f.store.snapshot(&[a], f.root()).unwrap();
    let outside = TempDir::new().unwrap();
    fs::remove_dir_all(f.root().join("d")).unwrap();
    symlink(outside.path(), f.root().join("d")).unwrap();
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::Symlink(_)), "{err:?}");
    assert!(!outside.path().join("a.txt").exists());
}

#[cfg(unix)]
#[test]
fn symlinked_target_is_rejected_at_restore() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    let outside = TempDir::new().unwrap();
    let victim = outside.path().join("victim.txt");
    fs::write(&victim, "precious").unwrap();
    fs::remove_file(&a).unwrap();
    symlink(&victim, &a).unwrap();
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::Symlink(_)), "{err:?}");
    assert_eq!(read(&victim), "precious");
}

#[cfg(unix)]
#[test]
fn permission_bits_are_preserved() {
    let f = fixture();
    let a = f.file("run.sh", "#!/bin/sh\n");
    fs::set_permissions(&a, fs::Permissions::from_mode(0o750)).unwrap();
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::write(&a, "changed").unwrap();
    fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o750
    );
    assert_eq!(read(&a), "#!/bin/sh\n");

    // A file deleted after the snapshot comes back with its mode too.
    fs::remove_file(&a).unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o750
    );
}

#[test]
fn file_over_size_cap_is_too_large() {
    let store_dir = TempDir::new().unwrap();
    let root = TempDir::new().unwrap();
    let store = SnapshotStore::open(store_dir.path())
        .unwrap()
        .with_max_file_size(8);
    let small = root.path().join("small.txt");
    fs::write(&small, "12345678").unwrap();
    store.snapshot(&[small], root.path()).unwrap();
    let big = root.path().join("big.txt");
    fs::write(&big, "123456789").unwrap();
    let err = store.snapshot(&[big], root.path()).unwrap_err();
    assert!(matches!(err, SnapshotError::TooLarge(_)), "{err:?}");
}

#[test]
fn default_size_cap_is_512_mib() {
    assert_eq!(SnapshotStore::DEFAULT_MAX_FILE_SIZE, 512 * 1024 * 1024);
}

#[cfg(unix)]
#[test]
fn root_replaced_by_symlink_is_rejected_at_restore() {
    let store_dir = TempDir::new().unwrap();
    let base = TempDir::new().unwrap();
    let root = base.path().join("root");
    fs::create_dir(&root).unwrap();
    let a = root.join("a.txt");
    fs::write(&a, "a1").unwrap();
    let store = SnapshotStore::open(store_dir.path()).unwrap();
    let id = store.snapshot(&[a], &root).unwrap();
    let outside = TempDir::new().unwrap();
    fs::remove_dir_all(&root).unwrap();
    symlink(outside.path(), &root).unwrap();
    let err = store.restore(&id, &root, true).unwrap_err();
    assert!(matches!(err, SnapshotError::Symlink(_)), "{err:?}");
    assert!(!outside.path().join("a.txt").exists());
}

#[test]
fn manifest_root_widened_to_slash_is_refused_and_nothing_written() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    let other = TempDir::new().unwrap();
    let victim = other.path().join("victim.txt");
    fs::write(&victim, "precious").unwrap();
    let mut m = f.manifest(&id);
    m["allowed_root"] = serde_json::json!("/");
    m["entries"][0]["path"] = serde_json::json!(canon(&victim));
    f.write_manifest(&id, &m);
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
    assert_eq!(read(&victim), "precious");
    let err = f.store.record_after(&id, f.root()).unwrap_err();
    assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
}

#[test]
fn caller_root_different_from_recorded_root_is_refused() {
    let f = fixture();
    let a = f.file("sub/a.txt", "a1");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    fs::write(&a, "a2").unwrap();
    let other = TempDir::new().unwrap();
    for wrong in [other.path().to_path_buf(), f.root().join("sub")] {
        let err = f.store.restore(&id, &wrong, true).unwrap_err();
        assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
        let err = f.store.record_after(&id, &wrong).unwrap_err();
        assert!(matches!(err, SnapshotError::OutsideRoot(_)), "{err:?}");
    }
    assert_eq!(read(&a), "a2");
    // The canonical spelling of the right root is accepted.
    f.store.restore(&id, &canon(f.root()), false).unwrap();
    assert_eq!(read(&a), "a1");
}

#[cfg(unix)]
#[test]
fn store_dirs_are_0700_and_blobs_and_restores_are_0600() {
    let f = fixture();
    let nested = f.store_dir.path().join("fresh/store");
    let s2 = SnapshotStore::open(&nested).unwrap();
    for d in [
        nested.clone(),
        nested.join("blobs"),
        nested.join("manifests"),
    ] {
        assert_eq!(
            fs::metadata(&d).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }
    let a = f.file("secret.txt", "private");
    fs::set_permissions(&a, fs::Permissions::from_mode(0o600)).unwrap();
    let id = s2.snapshot(std::slice::from_ref(&a), f.root()).unwrap();
    let blob_dir = nested.join("blobs");
    for e in fs::read_dir(&blob_dir).unwrap() {
        let mode = e.unwrap().metadata().unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "blob must not be group/other readable");
    }
    let mpath = nested.join("manifests").join(format!("{}.json", id.0));
    assert_eq!(
        fs::metadata(&mpath).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::write(&a, "changed").unwrap();
    s2.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o777,
        0o600
    );
    fs::remove_file(&a).unwrap();
    s2.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o600
    );
}

#[cfg(unix)]
#[test]
fn setuid_bits_are_stripped() {
    let f = fixture();
    let a = f.file("tool", "#!/bin/sh\n");
    fs::set_permissions(&a, fs::Permissions::from_mode(0o4755)).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o4755
    );
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    assert_eq!(
        f.manifest(&id)["entries"][0]["mode"],
        serde_json::json!(0o755)
    );
    fs::remove_file(&a).unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o755
    );

    // A tampered manifest mode cannot reintroduce setuid/setgid/sticky.
    let mut m = f.manifest(&id);
    m["entries"][0]["mode"] = serde_json::json!(0o7755);
    f.write_manifest(&id, &m);
    fs::remove_file(&a).unwrap();
    f.store.restore(&id, f.root(), false).unwrap();
    assert_eq!(
        fs::metadata(&a).unwrap().permissions().mode() & 0o7777,
        0o755
    );
}

#[test]
fn manifest_id_mismatching_file_name_is_rejected() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let id = f
        .store
        .snapshot(std::slice::from_ref(&a), f.root())
        .unwrap();
    let other = SnapshotId("0123456789abcdef0123456789abcdef".into());
    fs::copy(f.manifest_path(&id), f.manifest_path(&other)).unwrap();
    fs::write(&a, "a2").unwrap();
    let err = f.store.restore(&other, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::CorruptManifest), "{err:?}");
    assert_eq!(read(&a), "a2");
}

#[test]
fn absent_entry_now_a_directory_is_not_a_file_and_deletes_nothing() {
    let f = fixture();
    let a = f.file("a.txt", "a1");
    let gone = f.root().join("made-later");
    let id = f
        .store
        .snapshot(&[a.clone(), gone.clone()], f.root())
        .unwrap();
    fs::write(&a, "a2").unwrap();
    fs::create_dir(&gone).unwrap();
    fs::write(gone.join("inner.txt"), "keep").unwrap();
    let err = f.store.restore(&id, f.root(), true).unwrap_err();
    assert!(matches!(err, SnapshotError::NotAFile(_)), "{err:?}");
    assert_eq!(read(&a), "a2");
    assert_eq!(read(&gone.join("inner.txt")), "keep");
}
