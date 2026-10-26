use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use warden_core::{AuditEntry, AuditLog, Tier, VerifyReport};

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn tmp_log() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    (dir, path)
}

/// A deterministic clock: 1000, 1001, 1002, ...
fn counting_clock(start: u64) -> Box<dyn Fn() -> u64 + Send> {
    let t = Arc::new(AtomicU64::new(start));
    Box::new(move || t.fetch_add(1, Ordering::SeqCst))
}

fn write_entries(path: &Path, n: u64) -> Vec<AuditEntry> {
    let mut log = AuditLog::open_with_clock(path, counting_clock(1000)).unwrap();
    (0..n)
        .map(|i| {
            log.append(
                &format!("act-{i}"),
                &format!("summary {i}"),
                Tier::Yes,
                "approved",
            )
            .unwrap()
        })
        .collect()
}

fn lines(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

fn write_lines(path: &Path, lines: &[String]) {
    let mut s = String::new();
    for l in lines {
        s.push_str(l);
        s.push('\n');
    }
    fs::write(path, s).unwrap();
}

fn parse(line: &str) -> AuditEntry {
    serde_json::from_str(line).unwrap()
}

fn line_of(e: &AuditEntry) -> String {
    serde_json::to_string(e).unwrap()
}

fn assert_broken_at(path: &Path, expected: u64) -> String {
    match AuditLog::verify(path).unwrap() {
        VerifyReport::Broken {
            first_bad_index,
            reason,
        } => {
            assert_eq!(first_bad_index, expected, "reason: {reason}");
            reason
        }
        other => panic!("expected Broken at {expected}, got {other:?}"),
    }
}

// ---- brief tests ----

#[test]
fn append_then_verify_ok() {
    let (_d, path) = tmp_log();
    let entries = write_entries(&path, 3);
    assert_eq!(entries[0].index, 0);
    assert_eq!(entries[0].prev_hash, ZERO_HASH);
    assert_eq!(entries[1].prev_hash, entries[0].hash);
    assert_eq!(entries[2].prev_hash, entries[1].hash);
    assert_eq!(entries[2].timestamp_ms, 1002);
    assert_eq!(entries[0].hash.len(), 64);
    assert_eq!(lines(&path).len(), 3);
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 3 }
    );
}

#[test]
fn reopen_continues_chain() {
    let (_d, path) = tmp_log();
    let first = write_entries(&path, 2);
    let mut log = AuditLog::open_with_clock(&path, counting_clock(5000)).unwrap();
    assert_eq!(log.head(), (2, first[1].hash.clone()));
    let e = log.append("act-2", "third", Tier::Auto, "auto").unwrap();
    assert_eq!(e.index, 2);
    assert_eq!(e.prev_hash, first[1].hash);
    assert_eq!(log.head(), (3, e.hash.clone()));
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 3 }
    );
}

#[test]
fn edited_summary_reports_that_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 4);
    let mut ls = lines(&path);
    let mut e = parse(&ls[2]);
    e.summary = "nothing to see here".into();
    ls[2] = line_of(&e);
    write_lines(&path, &ls);
    assert_broken_at(&path, 2);
}

#[test]
fn deleted_middle_line_reports_first_bad_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 4);
    let mut ls = lines(&path);
    ls.remove(1);
    write_lines(&path, &ls);
    assert_broken_at(&path, 1);
}

#[test]
fn truncated_last_line_reports_broken() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let bytes = fs::read(&path).unwrap();
    // Cut the last line roughly in half (no trailing newline, invalid JSON).
    let last_start = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|&b| b == b'\n')
        .unwrap()
        + 1;
    let cut = last_start + (bytes.len() - last_start) / 2;
    fs::write(&path, &bytes[..cut]).unwrap();
    assert_broken_at(&path, 2);
}

#[test]
fn open_refuses_a_broken_log() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let mut ls = lines(&path);
    let mut e = parse(&ls[1]);
    e.decision = "denied".into();
    ls[1] = line_of(&e);
    write_lines(&path, &ls);
    let err = AuditLog::open(&path).expect_err("open must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
}

// ---- extra corruption cases ----

#[test]
fn wrong_prev_hash_with_consistent_hash_reports_that_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let mut ls = lines(&path);
    let mut e = parse(&ls[1]);
    e.prev_hash = "ab".repeat(32);
    e.hash = e.compute_hash();
    ls[1] = line_of(&e);
    write_lines(&path, &ls);
    let reason = assert_broken_at(&path, 1);
    assert!(reason.contains("prev_hash"), "{reason}");
}

#[test]
fn wrong_hash_reports_that_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let mut ls = lines(&path);
    let mut e = parse(&ls[2]);
    e.hash = "cd".repeat(32);
    ls[2] = line_of(&e);
    write_lines(&path, &ls);
    let reason = assert_broken_at(&path, 2);
    assert!(reason.contains("hash"), "{reason}");
}

#[test]
fn non_sequential_index_reports_that_position() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let mut ls = lines(&path);
    let mut e = parse(&ls[1]);
    e.index = 7;
    e.hash = e.compute_hash();
    ls[1] = line_of(&e);
    write_lines(&path, &ls);
    let reason = assert_broken_at(&path, 1);
    assert!(reason.contains("index"), "{reason}");
}

#[test]
fn reordered_lines_report_first_bad_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 4);
    let mut ls = lines(&path);
    ls.swap(1, 2);
    write_lines(&path, &ls);
    assert_broken_at(&path, 1);
}

#[test]
fn blank_line_reports_its_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 3);
    let mut ls = lines(&path);
    ls.insert(1, String::new());
    write_lines(&path, &ls);
    assert_broken_at(&path, 1);
}

#[test]
fn trailing_blank_line_reports_next_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fs::write(&path, bytes).unwrap();
    assert_broken_at(&path, 2);
}

#[test]
fn trailing_garbage_reports_next_index() {
    let (_d, path) = tmp_log();
    write_entries(&path, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(b"garbage\n");
    fs::write(&path, &bytes).unwrap();
    assert_broken_at(&path, 2);

    // Unterminated garbage too.
    bytes.truncate(bytes.len() - 1);
    fs::write(&path, &bytes).unwrap();
    assert_broken_at(&path, 2);
}

#[test]
fn missing_trailing_newline_after_good_entry_is_broken() {
    let (_d, path) = tmp_log();
    write_entries(&path, 2);
    let mut bytes = fs::read(&path).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    fs::write(&path, &bytes).unwrap();
    let reason = assert_broken_at(&path, 1);
    assert!(reason.contains("newline"), "{reason}");
}

#[test]
fn open_refuses_log_without_trailing_newline() {
    let (_d, path) = tmp_log();
    write_entries(&path, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes.pop();
    fs::write(&path, &bytes).unwrap();
    let err = AuditLog::open(&path).expect_err("open must refuse");
    assert_eq!(err.kind(), ErrorKind::InvalidData);
    // And it must not have touched the file.
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn invalid_utf8_reports_broken_without_panicking() {
    let (_d, path) = tmp_log();
    write_entries(&path, 2);
    let mut bytes = fs::read(&path).unwrap();
    bytes.extend_from_slice(&[0xff, 0xfe, 0x80, b'\n']);
    fs::write(&path, &bytes).unwrap();
    assert_broken_at(&path, 2);
}

#[test]
fn verify_never_panics_on_arbitrary_bytes() {
    let (_d, path) = tmp_log();
    // A cheap deterministic PRNG (xorshift) over many lengths.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    for len in 0..300usize {
        let mut buf = Vec::with_capacity(len);
        for _ in 0..len {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let b = (x & 0xff) as u8;
            // Bias toward newlines and JSON-ish bytes to reach more branches.
            buf.push(match b % 8 {
                0 => b'\n',
                1 => b'{',
                2 => b'"',
                _ => b,
            });
        }
        fs::write(&path, &buf).unwrap();
        let report = AuditLog::verify(&path).unwrap();
        if len == 0 {
            assert_eq!(report, VerifyReport::Ok { entries: 0 });
        } else {
            assert!(matches!(report, VerifyReport::Broken { .. }), "{report:?}");
        }
    }
}

#[test]
fn verify_missing_file_is_an_error() {
    let (_d, path) = tmp_log();
    let err = AuditLog::verify(&path).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::NotFound);
}

// ---- open behaviour ----

#[test]
fn open_nonexistent_creates_empty_log() {
    let (_d, path) = tmp_log();
    let log = AuditLog::open(&path).unwrap();
    assert!(path.exists());
    assert_eq!(log.head(), (0, ZERO_HASH.to_string()));
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 0 }
    );
}

#[test]
fn second_open_while_locked_is_refused() {
    let (_d, path) = tmp_log();
    let log = AuditLog::open(&path).unwrap();
    let err = AuditLog::open(&path).expect_err("second open must fail");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    assert!(err.to_string().contains("locked"), "{err}");
    // Verify (read-only) still works while locked.
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 0 }
    );
    drop(log);
    AuditLog::open(&path).expect("lock released on drop");
}

#[test]
fn system_clock_open_appends() {
    let (_d, path) = tmp_log();
    let mut log = AuditLog::open(&path).unwrap();
    let e = log.append("a", "s", Tier::Blocked, "blocked").unwrap();
    // After 2020-01-01 in ms.
    assert!(e.timestamp_ms > 1_577_836_800_000);
}

// ---- encoding ----

#[test]
fn newlines_in_fields_still_produce_one_line() {
    let (_d, path) = tmp_log();
    let mut log = AuditLog::open_with_clock(&path, counting_clock(1)).unwrap();
    let e = log
        .append(
            "id\nwith\r\nbreaks",
            "line one\nline two\u{2028}line three\u{2029}end",
            Tier::YesPin,
            "approved\n",
        )
        .unwrap();
    log.append("next", "ok", Tier::Auto, "auto").unwrap();
    drop(log);
    let ls = lines(&path);
    assert_eq!(ls.len(), 2);
    let back = parse(&ls[0]);
    assert_eq!(back, e);
    assert_eq!(
        back.summary,
        "line one\nline two\u{2028}line three\u{2029}end"
    );
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 2 }
    );
}

#[test]
fn golden_hash_is_pinned() {
    let e = AuditEntry {
        index: 0,
        timestamp_ms: 1_700_000_000_000,
        action_id: "act-1".into(),
        summary: "delete ~/tmp/x".into(),
        tier: Tier::YesPin,
        decision: "approved".into(),
        prev_hash: ZERO_HASH.into(),
        hash: String::new(),
    };
    assert_eq!(e.compute_hash(), GOLDEN);

    // Same through the public append path with a fixed clock.
    let (_d, path) = tmp_log();
    let mut log = AuditLog::open_with_clock(&path, Box::new(|| 1_700_000_000_000)).unwrap();
    let got = log
        .append("act-1", "delete ~/tmp/x", Tier::YesPin, "approved")
        .unwrap();
    assert_eq!(got.hash, GOLDEN);
}

/// Computed independently (Python hashlib) from the layout in the module doc.
const GOLDEN: &str = "44a9a4c6f6ef39729e52ac09c6c785fef28d4c20f2f0dd94dfcde622945eb88c";

#[test]
fn field_boundaries_are_unambiguous() {
    let base = AuditEntry {
        index: 0,
        timestamp_ms: 0,
        action_id: "ab".into(),
        summary: "c".into(),
        tier: Tier::Auto,
        decision: "d".into(),
        prev_hash: ZERO_HASH.into(),
        hash: String::new(),
    };
    let mut shifted = base.clone();
    shifted.action_id = "a".into();
    shifted.summary = "bc".into();
    assert_ne!(base.compute_hash(), shifted.compute_hash());
}

/// Pins the documented limit: the hash is unkeyed, so anyone who can write
/// the file can edit entry k and re-chain k..end, and verify passes it.
/// Only an externally anchored `head()` detects the forgery.
#[test]
fn rechained_forged_suffix_passes_verify_documented_limit() {
    let (_d, path) = tmp_log();
    write_entries(&path, 4);
    let anchored_head = AuditLog::open(&path).unwrap().head();

    let mut ls = lines(&path);
    let mut prev = parse(&ls[0]).hash;
    for (k, line) in ls.iter_mut().enumerate().skip(1) {
        let mut e = parse(line);
        if k == 1 {
            e.summary = "forged".into();
            e.decision = "denied".into();
        }
        e.prev_hash = prev.clone();
        e.hash = e.compute_hash();
        prev.clone_from(&e.hash);
        *line = line_of(&e);
    }
    write_lines(&path, &ls);

    // The limit: verify cannot tell.
    assert_eq!(
        AuditLog::verify(&path).unwrap(),
        VerifyReport::Ok { entries: 4 }
    );
    // The mitigation: the anchored head no longer matches.
    let forged_head = AuditLog::open(&path).unwrap().head();
    assert_eq!(forged_head.0, anchored_head.0);
    assert_ne!(forged_head.1, anchored_head.1);
}

#[cfg(unix)]
#[test]
fn new_log_is_created_0600() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, path) = tmp_log();
    let log = AuditLog::open(&path).unwrap();
    drop(log);
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "{mode:o}");
}
