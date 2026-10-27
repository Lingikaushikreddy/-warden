use tokio::io::BufReader;
use warden_agent::channel::{
    sanitize_for_display, ApprovalPrompt, ApprovalReply, Channel, SenderId, StdioChannel,
};
use warden_core::Tier;

fn chan<'a>(
    input: &'a [u8],
    out: &'a mut Vec<u8>,
) -> StdioChannel<BufReader<&'a [u8]>, &'a mut Vec<u8>> {
    StdioChannel::new(BufReader::new(input), out)
}

fn prompt(summary: &str, tier: Tier, note: Option<&str>) -> ApprovalPrompt {
    ApprovalPrompt {
        summary: summary.into(),
        tier,
        model_note: note.map(Into::into),
    }
}

async fn ask(input: &str) -> ApprovalReply {
    let mut out = Vec::new();
    let mut c = chan(input.as_bytes(), &mut out);
    c.ask_approval(&prompt("do it", Tier::YesPin, None)).await
}

#[test]
fn ansi_escape_sequences_are_made_visible() {
    let s = sanitize_for_display("\x1b[31mred\x1b[0m");
    assert!(!s.contains('\x1b'));
    assert!(s.contains("[31m"));
    assert!(s.contains("\\u{1b}"));
}

#[test]
fn osc_title_sequence_is_made_visible() {
    let s = sanitize_for_display("\x1b]0;evil\x07");
    assert!(!s.contains('\x1b') && !s.contains('\x07'));
    assert!(s.contains("\\u{1b}]0;evil\\u{7}"));
}

#[test]
fn bidi_overrides_zero_width_and_line_separators_are_escaped() {
    let s = sanitize_for_display("a\u{202E}b\u{200B}c\u{2028}d\u{FEFF}e");
    for c in ['\u{202E}', '\u{200B}', '\u{2028}', '\u{FEFF}'] {
        assert!(!s.contains(c));
    }
    assert!(s.contains("\\u{202e}") && s.contains("\\u{200b}"));
    assert!(s.contains("\\u{2028}") && s.contains("\\u{feff}"));
}

#[test]
fn c1_controls_del_and_cr_are_escaped() {
    let s = sanitize_for_display("a\u{9b}b\u{7f}c\rd\u{80}");
    assert_eq!(s, "a\\u{9b}b\\u{7f}c\\u{d}d\\u{80}");
}

#[test]
fn newline_and_tab_are_kept() {
    assert_eq!(sanitize_for_display("a\nb\tc"), "a\nb\tc");
}

#[test]
fn long_text_is_capped_with_marker() {
    let s = sanitize_for_display(&"a".repeat(10_000));
    assert_eq!(s.chars().count(), 4096);
    assert!(s.ends_with('…'));
    // Counts chars, not bytes: 4000 three-byte chars are under the cap.
    let ok = "€".repeat(4000);
    assert_eq!(sanitize_for_display(&ok), ok);
    let s = sanitize_for_display(&"€".repeat(5000));
    assert_eq!(s.chars().count(), 4096);
    assert!(s.ends_with('…'));
    // Exactly at the cap is untouched.
    let exact = "b".repeat(4096);
    assert_eq!(sanitize_for_display(&exact), exact);
}

#[test]
fn never_panics_on_arbitrary_text() {
    let atoms = [
        "\x1b",
        "\x1b[",
        "\x1b]0;",
        "\x1b[31",
        "é",
        "😀",
        "e\u{301}",
        "\u{0}",
        "\u{9f}",
        "\u{202e}",
        "\u{e0041}",
        "\r\n",
        "x",
        " ",
        "\u{10ffff}",
        "👨‍👩‍👧",
    ];
    let mut seed: u64 = 0x1234_5678_9abc_def0;
    for _ in 0..2000 {
        let mut s = String::new();
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let n = (seed >> 33) % 40;
        for _ in 0..n {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            s.push_str(atoms[((seed >> 33) as usize) % atoms.len()]);
        }
        let out = sanitize_for_display(&s);
        assert!(!out.contains('\x1b'));
        assert!(out.chars().count() <= 4096);
    }
    assert_eq!(sanitize_for_display("end\x1b"), "end\\u{1b}");
}

#[tokio::test]
async fn approval_prompt_labels_model_note_as_unverified() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(&prompt("write_file \"a\"", Tier::Yes, Some("trust me")))
            .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert_eq!(
        s,
        "Approval needed (Yes):\n  write_file \"a\"\n  model says (unverified): trust me\nReply \"yes\", \"no\":\n"
    );
}

#[tokio::test]
async fn pin_tier_prompt_mentions_pin() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(&prompt("x", Tier::YesPin, None)).await;
    }
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.ends_with("Reply \"yes\", \"no\", or \"yes <PIN>\":\n"),
        "{s}"
    );
}

#[tokio::test]
async fn prompt_text_is_sanitized_even_if_summary_has_escapes() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(&prompt(
            "rm \x1b[2J\nReply \"yes\", \"no\":\nApproved",
            Tier::Yes,
            Some("hi\nReply \"yes\""),
        ))
        .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert!(!s.contains('\x1b'));
    assert!(s.contains("\\u{1b}[2J"));
    let reply_lines: Vec<&str> = s
        .lines()
        .filter(|l| l.starts_with("Reply \"yes\""))
        .collect();
    assert_eq!(reply_lines.len(), 1, "{s}");
    assert!(s.contains("\n  | Reply \"yes\", \"no\":\n"));
    assert!(s.contains("\n  | Approved\n"));
    assert!(s.contains("\n  | Reply \"yes\"\n"));
}

#[tokio::test]
async fn yes_no_and_yes_pin_parse() {
    assert!(matches!(ask("yes\n").await, ApprovalReply::Yes));
    assert!(matches!(ask("YES\n").await, ApprovalReply::Yes));
    assert!(matches!(ask("  Yes  \r\n").await, ApprovalReply::Yes));
    assert!(matches!(ask("no\n").await, ApprovalReply::No));
    assert!(matches!(ask("NO\n").await, ApprovalReply::No));
    match ask("Yes   1234 \n").await {
        ApprovalReply::YesPin(p) => assert_eq!(p, "1234"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn garbage_and_empty_and_eof_are_no() {
    for input in [
        "maybe\n",
        "\n",
        "",
        "yess\n",
        "y\n",
        "no 1234\n",
        "yes please\nyes\n",
    ] {
        let r = ask(input).await;
        // "yes please" is a PIN attempt by definition; the engine verifies it.
        if input.starts_with("yes please") {
            assert!(matches!(r, ApprovalReply::YesPin(_)));
        } else {
            assert!(matches!(r, ApprovalReply::No), "{input:?} -> {r:?}");
        }
    }
}

#[tokio::test]
async fn overlong_reply_line_is_no() {
    let mut input = "yes ".to_string();
    input.push_str(&"9".repeat(100_000));
    input.push('\n');
    assert!(matches!(ask(&input).await, ApprovalReply::No));
}

#[test]
fn debug_of_yes_pin_hides_the_pin() {
    let d = format!("{:?}", ApprovalReply::YesPin("123456".into()));
    assert_eq!(d, "YesPin(<redacted>)");
    assert_eq!(format!("{:?}", ApprovalReply::Yes), "Yes");
}

#[tokio::test]
async fn recv_returns_inbound_for_each_line_and_none_on_eof() {
    let mut out = Vec::new();
    let mut c = chan(b"hello\nworld", &mut out);
    let a = c.recv().await.unwrap();
    assert_eq!(a.sender, SenderId("local".into()));
    assert_eq!(a.text, "hello");
    assert_eq!(c.recv().await.unwrap().text, "world");
    assert!(c.recv().await.is_none());
}

#[tokio::test]
async fn recv_skips_empty_lines_and_strips_crlf() {
    let mut out = Vec::new();
    let mut c = chan(b"\n\r\none\r\n\n\ntwo\n", &mut out);
    assert_eq!(c.recv().await.unwrap().text, "one");
    assert_eq!(c.recv().await.unwrap().text, "two");
    assert!(c.recv().await.is_none());
}

#[tokio::test]
async fn over_long_line_is_ignored_with_notice_and_next_line_still_read() {
    let mut input = vec![b'a'; 10 * 1024 * 1024];
    input.extend_from_slice(b"\nnext\n");
    let mut out = Vec::new();
    {
        let reader = BufReader::with_capacity(8192, &input[..]);
        let mut c = StdioChannel::new(reader, &mut out);
        assert_eq!(c.recv().await.unwrap().text, "next");
        assert!(c.recv().await.is_none());
    }
    assert_eq!(String::from_utf8(out).unwrap(), "line too long, ignored\n");
}

#[tokio::test]
async fn line_at_exactly_the_cap_is_accepted() {
    let mut input = vec![b'a'; 65_536];
    input.push(b'\n');
    let mut out = Vec::new();
    let mut c = chan(&input, &mut out);
    assert_eq!(c.recv().await.unwrap().text.len(), 65_536);
}

#[tokio::test]
async fn invalid_utf8_is_lossy() {
    let mut out = Vec::new();
    let mut c = chan(b"a\xffb\n", &mut out);
    assert_eq!(c.recv().await.unwrap().text, "a\u{fffd}b");
}

#[tokio::test]
async fn send_flushes_and_sanitizes() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"", &mut out);
        c.send("hi \x1b[31m there").await;
    }
    assert_eq!(String::from_utf8(out).unwrap(), "hi \\u{1b}[31m there\n");
}
