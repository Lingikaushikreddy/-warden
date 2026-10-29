use tokio::io::BufReader;
use warden_agent::channel::{
    sanitize_for_display, ApprovalPrompt, ApprovalReply, Channel, SenderId, StdioChannel,
};
use warden_core::Tier;
use zeroize::Zeroizing;

/// The only sender a `StdioChannel` knows.
fn local() -> SenderId {
    SenderId("local".into())
}

fn chan<'a>(
    input: &'a [u8],
    out: &'a mut Vec<u8>,
) -> StdioChannel<BufReader<&'a [u8]>, &'a mut Vec<u8>> {
    StdioChannel::new(BufReader::new(input), out)
}

/// The challenge code every helper prompt shows.
const CODE: &str = "4821";

fn prompt(summary: &str, tier: Tier, note: Option<&str>) -> ApprovalPrompt {
    prompt_with(summary, tier, note, CODE)
}

fn prompt_with(summary: &str, tier: Tier, note: Option<&str>, code: &str) -> ApprovalPrompt {
    ApprovalPrompt {
        summary: summary.into(),
        tier,
        model_note: note.map(Into::into),
        challenge: code.into(),
    }
}

async fn ask_tier(input: &str, tier: Tier) -> ApprovalReply {
    let mut out = Vec::new();
    let mut c = chan(input.as_bytes(), &mut out);
    c.ask_approval(&local(), &prompt("do it", tier, None)).await
}

async fn ask(input: &str) -> ApprovalReply {
    ask_tier(input, Tier::Yes).await
}

async fn ask_pin(input: &str) -> ApprovalReply {
    ask_tier(input, Tier::YesPin).await
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
        c.ask_approval(
            &local(),
            &prompt("write_file \"a\"", Tier::Yes, Some("trust me")),
        )
        .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert_eq!(
        s,
        "Approval needed (Yes):\n  write_file \"a\"\n  model says (unverified): trust me\nReply \"yes 4821\" or \"no\":\n"
    );
}

#[tokio::test]
async fn pin_tier_prompt_mentions_pin() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(&local(), &prompt("x", Tier::YesPin, None))
            .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert!(s.ends_with("Reply \"yes 4821 <PIN>\" or \"no\":\n"), "{s}");
}

#[tokio::test]
async fn prompt_text_is_sanitized_even_if_summary_has_escapes() {
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(
            &local(),
            &prompt(
                "rm \x1b[2J\nReply \"yes\", \"no\":\nApproved",
                Tier::Yes,
                Some("hi\nReply \"yes\""),
            ),
        )
        .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert!(!s.contains('\x1b'));
    assert!(s.contains("\\u{1b}[2J"));
    let reply_lines: Vec<&str> = s.lines().filter(|l| l.starts_with("Reply \"yes")).collect();
    assert_eq!(reply_lines.len(), 1, "{s}");
    assert!(s.contains("\n  | Reply \"yes\", \"no\":\n"));
    assert!(s.contains("\n  | Approved\n"));
    assert!(s.contains("\n  | Reply \"yes\"\n"));
}

#[tokio::test]
async fn yes_tier_accepts_only_yes_with_the_code() {
    assert_eq!(ask("yes 4821\n").await, ApprovalReply::Yes);
    assert_eq!(ask("YES 4821\n").await, ApprovalReply::Yes);
    assert_eq!(ask("  Yes \t 4821  \r\n").await, ApprovalReply::Yes);
    assert_eq!(ask("no\n").await, ApprovalReply::No);
    assert_eq!(ask("NO\n").await, ApprovalReply::No);
    // A stale or typed-ahead `yes` cannot contain the code.
    assert_eq!(ask("yes\n").await, ApprovalReply::No);
    assert_eq!(ask("yes please go ahead\n").await, ApprovalReply::No);
    assert_eq!(ask("yes 1234\n").await, ApprovalReply::No, "wrong code");
    assert_eq!(ask("yes 4821 extra\n").await, ApprovalReply::No);
    assert_eq!(ask("yes 48210\n").await, ApprovalReply::No);
    assert_eq!(ask("4821\n").await, ApprovalReply::No);
}

#[tokio::test]
async fn yes_pin_tier_requires_code_then_pin() {
    assert_eq!(
        ask_pin("Yes   4821   1234 \n").await,
        ApprovalReply::YesPin(Zeroizing::new("1234".into()))
    );
    assert_eq!(ask_pin("yes\n").await, ApprovalReply::No);
    assert_eq!(ask_pin("yes 4821\n").await, ApprovalReply::No, "no PIN");
    assert_eq!(
        ask_pin("yes 1234\n").await,
        ApprovalReply::No,
        "PIN without code"
    );
    assert_eq!(
        ask_pin("yes 9999 1234\n").await,
        ApprovalReply::No,
        "wrong code"
    );
    assert_eq!(ask_pin("no\n").await, ApprovalReply::No);
    let ok = format!("yes 4821 {}\n", "9".repeat(128));
    assert!(matches!(ask_pin(&ok).await, ApprovalReply::YesPin(p) if p.len() == 128));
    let long = format!("yes 4821 {}\n", "9".repeat(129));
    assert_eq!(ask_pin(&long).await, ApprovalReply::No);
}

#[tokio::test]
async fn previous_prompts_code_does_not_answer_the_next_prompt() {
    let mut out = Vec::new();
    let mut c = chan(b"yes 1111\nyes 2222\n", &mut out);
    // The first prompt (code 1111) got its answer; the same line again,
    // sent for the second prompt (code 2222), would be stale.
    let mut out2 = Vec::new();
    let mut c2 = chan(b"yes 1111\n", &mut out2);
    assert_eq!(
        c.ask_approval(&local(), &prompt_with("a", Tier::Yes, None, "1111"))
            .await,
        ApprovalReply::Yes
    );
    assert_eq!(
        c2.ask_approval(&local(), &prompt_with("b", Tier::Yes, None, "2222"))
            .await,
        ApprovalReply::No
    );
    assert_eq!(
        c.ask_approval(&local(), &prompt_with("b", Tier::Yes, None, "2222"))
            .await,
        ApprovalReply::Yes
    );
}

#[tokio::test]
async fn prompt_without_a_valid_challenge_is_refused_unasked() {
    for code in ["", "12 34", "12\n34", &"9".repeat(17), "é1"] {
        let mut out = Vec::new();
        {
            let mut c = chan(b"yes \n", &mut out);
            let r = c
                .ask_approval(&local(), &prompt_with("x", Tier::Yes, None, code))
                .await;
            assert_eq!(r, ApprovalReply::No, "{code:?}");
            assert_eq!(c.recv().await.unwrap().text, "yes ", "reply not consumed");
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "approval prompt has no valid code; refused\n"
        );
    }
}

#[tokio::test]
async fn garbage_and_empty_are_no_and_eof_is_closed() {
    assert_eq!(ask("").await, ApprovalReply::Closed);
    assert_eq!(ask_pin("").await, ApprovalReply::Closed);
    for input in ["maybe\n", "\n", "yess\n", "y\n", "no 1234\n"] {
        assert_eq!(ask(input).await, ApprovalReply::No, "{input:?}");
    }
    for input in ["maybe\n", "\n", "yess 1\n", "y 1\n", "no 1234\n", "1234\n"] {
        assert_eq!(ask_pin(input).await, ApprovalReply::No, "{input:?}");
    }
}

#[tokio::test]
async fn eof_in_the_middle_of_a_reply_line_is_closed() {
    assert_eq!(ask("yes 4821").await, ApprovalReply::Closed);
    assert_eq!(ask_pin("yes 4821 1234").await, ApprovalReply::Closed);
}

#[tokio::test]
async fn overlong_reply_is_no_notice_sent_and_next_line_still_read() {
    let mut input = "yes ".to_string();
    input.push_str(&"9".repeat(100_000));
    input.push_str("\nhello\n");
    let mut out = Vec::new();
    {
        let mut c = chan(input.as_bytes(), &mut out);
        let r = c
            .ask_approval(&local(), &prompt("x", Tier::Yes, None))
            .await;
        assert_eq!(r, ApprovalReply::No);
        assert_eq!(c.recv().await.unwrap().text, "hello");
    }
    assert!(String::from_utf8(out)
        .unwrap()
        .ends_with("reply too long, treated as no\n"));
}

#[tokio::test]
async fn truncated_summary_or_note_is_refused_without_prompting() {
    for (summary, note) in [
        ("a".repeat(10_000), None),
        ("ok".to_string(), Some("n".repeat(10_000))),
    ] {
        let mut out = Vec::new();
        {
            let mut c = chan(b"yes\nyes\n", &mut out);
            let p = ApprovalPrompt {
                summary,
                tier: Tier::Yes,
                model_note: note,
                challenge: CODE.into(),
            };
            assert_eq!(c.ask_approval(&local(), &p).await, ApprovalReply::No);
            // The queued "yes" was not consumed as an answer.
            assert_eq!(c.recv().await.unwrap().text, "yes");
        }
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "request too long to approve safely; refused\n"
        );
    }
}

#[test]
fn debug_of_yes_pin_hides_the_pin() {
    let d = format!(
        "{:?}",
        ApprovalReply::YesPin(Zeroizing::new("123456".into()))
    );
    assert_eq!(d, "YesPin(<redacted>)");
    assert_eq!(format!("{:?}", ApprovalReply::Yes), "Yes");
    assert_eq!(format!("{:?}", ApprovalReply::Closed), "Closed");
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
async fn cap_is_on_content_excluding_line_ending() {
    for (n, eol, ok) in [
        (65_536, "\n", true),
        (65_537, "\n", false),
        (65_536, "\r\n", true),
        (65_537, "\r\n", false),
    ] {
        let mut input = "a".repeat(n);
        input.push_str(eol);
        input.push_str("next\n");
        let mut out = Vec::new();
        let mut c = chan(input.as_bytes(), &mut out);
        let first = c.recv().await.unwrap().text;
        if ok {
            assert_eq!(first.len(), n, "{n} {eol:?}");
            assert_eq!(c.recv().await.unwrap().text, "next");
        } else {
            assert_eq!(first, "next", "{n} {eol:?}");
        }
    }
}

#[tokio::test]
async fn crlf_split_across_buffer_boundaries() {
    let mut out = Vec::new();
    let reader = BufReader::with_capacity(1, &b"ab\r\ncd\r\n"[..]);
    let mut c = StdioChannel::new(reader, &mut out);
    assert_eq!(c.recv().await.unwrap().text, "ab");
    assert_eq!(c.recv().await.unwrap().text, "cd");
    assert!(c.recv().await.is_none());
    let reader = BufReader::with_capacity(1, &b"yes 4821\r\n"[..]);
    let mut out = Vec::new();
    let mut c = StdioChannel::new(reader, &mut out);
    assert_eq!(
        c.ask_approval(&local(), &prompt("x", Tier::Yes, None))
            .await,
        ApprovalReply::Yes
    );
}

/// Endless newline-free input that errors after `limit` bytes.
struct Endless {
    served: usize,
    limit: usize,
}

impl tokio::io::AsyncRead for Endless {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        if self.served >= self.limit {
            return std::task::Poll::Ready(Err(std::io::Error::other("asked for too much")));
        }
        let n = buf.remaining().min(self.limit - self.served);
        buf.put_slice(&vec![b'a'; n]);
        self.served += n;
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn unbounded_input_is_discarded_not_buffered() {
    let reader = BufReader::with_capacity(
        8192,
        Endless {
            served: 0,
            limit: 200_000,
        },
    );
    let mut out = Vec::new();
    {
        let mut c = StdioChannel::new(reader, &mut out);
        assert!(c.recv().await.is_none());
    }
    assert_eq!(String::from_utf8(out).unwrap(), "line too long, ignored\n");
}

#[test]
fn invisible_code_points_are_visible_and_rejected_in_paths() {
    use serde_json::json;
    use warden_agent::tools::{parse_call, ToolCall, ToolError};
    let cps = [
        0xFE00u32, 0xFE0F, 0xE0100, 0xE01EF, 0x034F, 0x180B, 0x180E, 0x17B4, 0x17B5, 0x1D173,
        0x1D17A, 0xFFFC,
    ];
    for cp in cps {
        let c = char::from_u32(cp).unwrap();
        let shown = sanitize_for_display(&format!("a{c}b"));
        assert_eq!(shown, format!("a\\u{{{cp:x}}}b"), "{cp:x}");
        let call = ToolCall {
            id: "1".into(),
            name: "read_file".into(),
            args: json!({"path": format!("/root/a{c}b")}),
        };
        assert!(
            matches!(
                parse_call(&call, std::path::Path::new("/root")),
                Err(ToolError::BadArgs(_))
            ),
            "{cp:x}"
        );
    }
}

#[tokio::test]
async fn blank_looking_spaces_are_escaped_in_display_but_allowed_in_paths() {
    use serde_json::json;
    use warden_agent::tools::{parse_call, ToolCall};
    for cp in [0xA0u32, 0x2000, 0x200A, 0x202F, 0x205F, 0x3000] {
        let c = char::from_u32(cp).unwrap();
        assert_eq!(
            sanitize_for_display(&format!("a{c}b")),
            format!("a\\u{{{cp:x}}}b")
        );
    }
    assert_eq!(sanitize_for_display("a b"), "a b");
    let call = ToolCall {
        id: "1".into(),
        name: "read_file".into(),
        args: json!({"path": "/root/a\u{a0}b"}),
    };
    assert!(parse_call(&call, std::path::Path::new("/root")).is_ok());
    let mut out = Vec::new();
    {
        let mut c = chan(b"no\n", &mut out);
        c.ask_approval(
            &local(),
            &prompt("read_file \"/root/a\u{a0}b\"", Tier::Yes, None),
        )
        .await;
    }
    let s = String::from_utf8(out).unwrap();
    assert!(s.contains("a\\u{a0}b") && !s.contains('\u{a0}'));
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
        c.send(&local(), "hi \x1b[31m there").await;
    }
    assert_eq!(String::from_utf8(out).unwrap(), "hi \\u{1b}[31m there\n");
}

/// A reader that yields half a line, then nothing until more is written.
/// A cancelled `ask_approval` must not lose the half already read, and the
/// rest must not come back as a separate message.
#[tokio::test(start_paused = true)]
async fn cancelled_ask_approval_keeps_the_partial_line() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let (mut client, server) = tokio::io::duplex(1024);
    let mut c = StdioChannel::new(BufReader::new(server), tokio::io::sink());
    client.write_all(b"yes 12").await.unwrap();
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        c.ask_approval(&local(), &prompt("delete \"/r/a\"", Tier::YesPin, None)),
    )
    .await;
    assert!(r.is_err(), "the prompt was cancelled while waiting");
    client.write_all(b"34\nnext\n").await.unwrap();
    let m = c.recv().await.unwrap();
    assert_eq!(m.text, "yes 1234", "the whole line, not just its tail");
    assert_eq!(c.recv().await.unwrap().text, "next");
}

#[tokio::test(start_paused = true)]
async fn stale_buffered_reply_is_discarded_before_a_prompt() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let (mut client, server) = tokio::io::duplex(1024);
    let mut c = StdioChannel::new(BufReader::new(server), tokio::io::sink());
    let p = prompt("write \"/r/b\" (4 bytes)", Tier::Yes, None);
    client.write_all(b"yes 4821\n").await.unwrap();
    assert_eq!(c.discard_pending_input(&local()).await, 9, "bytes dropped");
    let waited = tokio::time::timeout(Duration::from_secs(5), c.ask_approval(&local(), &p)).await;
    assert!(waited.is_err(), "the stale yes did not answer the prompt");
    assert_eq!(
        c.discard_pending_input(&local()).await,
        0,
        "nothing new to drop"
    );
    client.write_all(b"yes 4821\n").await.unwrap();
    assert_eq!(
        c.ask_approval(&local(), &p).await,
        ApprovalReply::Yes,
        "a fresh reply does"
    );
}

#[tokio::test(start_paused = true)]
async fn discarded_half_line_is_not_completed_by_later_input() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let (mut client, server) = tokio::io::duplex(1024);
    let mut c = StdioChannel::new(BufReader::new(server), tokio::io::sink());
    let p = prompt("write \"/r/b\" (4 bytes)", Tier::Yes, None);
    client.write_all(b"ye").await.unwrap();
    assert_eq!(c.discard_pending_input(&local()).await, 2);
    // "s" completes the dropped line and is skipped; only the next line counts.
    client.write_all(b"s\n").await.unwrap();
    let waited = tokio::time::timeout(Duration::from_secs(5), c.ask_approval(&local(), &p)).await;
    assert!(waited.is_err(), "\"s\" is not a reply");
    client.write_all(b"no\n").await.unwrap();
    assert_eq!(c.ask_approval(&local(), &p).await, ApprovalReply::No);
}

#[tokio::test]
async fn discard_on_an_empty_reader_does_not_block() {
    let mut out = Vec::new();
    let mut c = chan(b"", &mut out);
    c.discard_pending_input(&local()).await;
    assert!(c.recv().await.is_none());
}

/// Code points added in Plan 3: shown escaped (and rejected in paths, see
/// `tests/tools.rs`).
const NEW_DEFAULT_IGNORABLES: [u32; 17] = [
    0x180F, 0x1BCA0, 0x1BCA3, 0x13430, 0x13438, 0x1343F, 0xE0080, 0xE00C0, 0xE00FF, 0xE01F0,
    0xE0800, 0xE0FFF, 0xFFF0, 0xFFF4, 0xFFF8, 0x1BCA1, 0x1BCA2,
];

#[test]
fn default_ignorables_are_escaped() {
    for cp in NEW_DEFAULT_IGNORABLES {
        let c = char::from_u32(cp).unwrap();
        assert_eq!(
            sanitize_for_display(&format!("a{c}b")),
            format!("a\\u{{{cp:x}}}b"),
            "{cp:x}"
        );
    }
}

#[test]
fn ogham_space_is_escaped_for_display() {
    use serde_json::json;
    use warden_agent::tools::{parse_call, ToolCall};
    assert_eq!(sanitize_for_display("a\u{1680}b"), "a\\u{1680}b");
    // Blank-looking, not invisible: still legal in a path.
    let call = ToolCall {
        id: "1".into(),
        name: "read_file".into(),
        args: json!({"path": "/root/a\u{1680}b"}),
    };
    assert!(parse_call(&call, std::path::Path::new("/root")).is_ok());
}

// ---------------------------------------------------------------- Pair

use std::sync::{Arc, Mutex};
use warden_agent::channel::{Inbound, Pair};

fn remote() -> SenderId {
    SenderId("remote".into())
}

/// What a [`Remote`] channel was asked to do.
#[derive(Default, Clone)]
struct RemoteLog {
    sent: Arc<Mutex<Vec<(SenderId, String)>>>,
    asked: Arc<Mutex<Vec<SenderId>>>,
    discarded: Arc<Mutex<Vec<SenderId>>>,
    retracted: Arc<Mutex<Vec<SenderId>>>,
}

impl RemoteLog {
    fn is_empty(&self) -> bool {
        self.sent.lock().unwrap().is_empty()
            && self.asked.lock().unwrap().is_empty()
            && self.discarded.lock().unwrap().is_empty()
            && self.retracted.lock().unwrap().is_empty()
    }
}

/// A channel serving only `remote`, fed through an mpsc queue (whose
/// `recv` is cancel-safe). It answers every prompt `Yes`, has 3 bytes of
/// pending input and does not accept PINs.
struct Remote {
    rx: tokio::sync::mpsc::UnboundedReceiver<String>,
    log: RemoteLog,
}

fn remote_chan() -> (
    Remote,
    tokio::sync::mpsc::UnboundedSender<String>,
    RemoteLog,
) {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let log = RemoteLog::default();
    (
        Remote {
            rx,
            log: log.clone(),
        },
        tx,
        log,
    )
}

impl Channel for Remote {
    async fn recv(&mut self) -> Option<Inbound> {
        self.rx.recv().await.map(|text| Inbound {
            sender: remote(),
            text,
        })
    }
    async fn send(&mut self, to: &SenderId, text: &str) {
        self.log
            .sent
            .lock()
            .unwrap()
            .push((to.clone(), text.into()));
    }
    async fn ask_approval(&mut self, to: &SenderId, _prompt: &ApprovalPrompt) -> ApprovalReply {
        self.log.asked.lock().unwrap().push(to.clone());
        ApprovalReply::Yes
    }
    async fn discard_pending_input(&mut self, to: &SenderId) -> usize {
        self.log.discarded.lock().unwrap().push(to.clone());
        3
    }
    fn accepts_pin(&self, _to: &SenderId) -> bool {
        false
    }
    async fn retract_last(&mut self, to: &SenderId) {
        self.log.retracted.lock().unwrap().push(to.clone());
    }
    fn serves(&self, who: &SenderId) -> bool {
        *who == remote()
    }
}

#[tokio::test]
async fn pair_routes_by_sender() {
    let mut out = Vec::new();
    let (r, _tx, log) = remote_chan();
    {
        let mut p = Pair::new(chan(b"pending\n", &mut out), r);
        assert!(p.serves(&local()) && p.serves(&remote()));
        assert!(!p.serves(&SenderId("stranger".into())));
        p.send(&local(), "to local").await;
        p.send(&remote(), "to remote").await;
        assert!(p.accepts_pin(&local()));
        assert!(!p.accepts_pin(&remote()));
        assert_eq!(p.discard_pending_input(&remote()).await, 3);
        assert_eq!(p.discard_pending_input(&local()).await, 8, "stdio dropped");
        let pr = prompt("do it", Tier::Yes, None);
        assert_eq!(p.ask_approval(&remote(), &pr).await, ApprovalReply::Yes);
        // The stdio side has no reply left: EOF.
        assert_eq!(p.ask_approval(&local(), &pr).await, ApprovalReply::Closed);
        p.retract_last(&remote()).await;
    }
    let out = String::from_utf8(out).unwrap();
    assert!(out.starts_with("to local\n"), "{out:?}");
    assert!(!out.contains("to remote"));
    assert!(out.contains(&format!("yes {CODE}")), "local prompt shown");
    assert_eq!(
        *log.sent.lock().unwrap(),
        vec![(remote(), "to remote".to_string())]
    );
    assert_eq!(*log.asked.lock().unwrap(), vec![remote()]);
    assert_eq!(*log.discarded.lock().unwrap(), vec![remote()]);
    assert_eq!(*log.retracted.lock().unwrap(), vec![remote()]);
}

#[tokio::test]
async fn pair_unknown_recipient_gets_no_and_nothing_sent() {
    let mut out = Vec::new();
    let (r, _tx, log) = remote_chan();
    let stranger = SenderId("stranger".into());
    {
        let mut p = Pair::new(chan(b"yes 4821\n", &mut out), r);
        p.send(&stranger, "hello").await;
        let pr = prompt("do it", Tier::Yes, None);
        assert_eq!(p.ask_approval(&stranger, &pr).await, ApprovalReply::No);
        assert_eq!(p.discard_pending_input(&stranger).await, 0);
        assert!(!p.accepts_pin(&stranger));
        p.retract_last(&stranger).await;
        // The stdio input was not touched: its line is still there.
        assert_eq!(p.recv().await.unwrap().text, "yes 4821");
    }
    assert!(out.is_empty(), "{out:?}");
    assert!(log.is_empty());
}

#[tokio::test(start_paused = true)]
async fn pair_recv_keeps_going_after_one_side_closes() {
    use std::time::Duration;
    let mut out = Vec::new();
    let (r, tx, _log) = remote_chan();
    let mut p = Pair::new(chan(b"", &mut out), r);
    let feed = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send("one".into()).unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
        tx.send("two".into()).unwrap();
        // Dropping `tx` closes the remote side.
    });
    for want in ["one", "two"] {
        let m = p.recv().await.expect("the remote side still delivers");
        assert_eq!((m.sender, m.text.as_str()), (remote(), want));
    }
    assert!(p.recv().await.is_none(), "both sides closed");
    assert!(p.recv().await.is_none());
    feed.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn pair_recv_is_cancel_safe() {
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    let (mut client, server) = tokio::io::duplex(1024);
    let (r, tx, _log) = remote_chan();
    let mut p = Pair::new(
        StdioChannel::new(BufReader::new(server), tokio::io::sink()),
        r,
    );
    // Several rounds so both polling orders are cancelled mid-line.
    for i in 0..4 {
        client
            .write_all(format!("line {i} first ha").as_bytes())
            .await
            .unwrap();
        let r = tokio::time::timeout(Duration::from_secs(1), p.recv()).await;
        assert!(r.is_err(), "nothing complete yet");
        tx.send(format!("remote {i}")).unwrap();
        client.write_all(b"lf\n").await.unwrap();
        let mut got = [p.recv().await.unwrap(), p.recv().await.unwrap()];
        got.sort_by(|a, b| a.text.cmp(&b.text));
        assert_eq!(got[0].text, format!("line {i} first half"));
        assert_eq!(got[0].sender, local());
        assert_eq!(got[1].text, format!("remote {i}"));
    }
}
