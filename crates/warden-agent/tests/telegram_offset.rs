use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use warden_agent::telegram::OffsetStore;

#[test]
fn offset_roundtrip_and_0600() {
    let home = tempfile::tempdir().unwrap();
    let (mut store, start) = OffsetStore::open(home.path()).unwrap();
    assert_eq!(start, 0);
    store.save(42).unwrap();
    let p = home.path().join("telegram-offset");
    assert_eq!(fs::read(&p).unwrap(), 42i64.to_be_bytes());
    assert_eq!(
        fs::metadata(&p).unwrap().permissions().mode() & 0o777,
        0o600
    );
    store.save(-7).unwrap();
    store.save(i64::MAX).unwrap();
    let (_, again) = OffsetStore::open(home.path()).unwrap();
    assert_eq!(again, i64::MAX);
}

#[test]
fn wrong_size_offset_is_invalid_data() {
    let home = tempfile::tempdir().unwrap();
    let p = home.path().join("telegram-offset");
    for bytes in [&b""[..], &b"1234567"[..], &b"123456789"[..]] {
        fs::write(&p, bytes).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o600)).unwrap();
        let e = OffsetStore::open(home.path()).unwrap_err();
        assert_eq!(
            e.kind(),
            io::ErrorKind::InvalidData,
            "{} bytes",
            bytes.len()
        );
    }
}

#[test]
fn missing_offset_is_zero() {
    let home = tempfile::tempdir().unwrap();
    let (_, start) = OffsetStore::open(home.path()).unwrap();
    assert_eq!(start, 0);
    assert!(!home.path().join("telegram-offset").exists());
}
