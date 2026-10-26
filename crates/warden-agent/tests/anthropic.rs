use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::Duration;
use warden_agent::anthropic::AnthropicPlanner;
use warden_agent::planner::{Block, PlanRequest, Planner, PlannerError, Role, Turn};
use warden_agent::redact::redact;
use warden_agent::tools::tool_specs;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY: &str = "test-key-0123456789-DO-NOT-LEAK";
const MODEL: &str = "claude-sonnet-5-5";

fn planner(base: &str) -> AnthropicPlanner {
    AnthropicPlanner::new(KEY.into(), MODEL.into(), base.into()).unwrap()
}

fn request() -> PlanRequest {
    PlanRequest {
        system: redact("system prompt here").0,
        turns: vec![Turn {
            role: Role::User,
            blocks: vec![Block::Text(redact("list the files").0)],
        }],
        tools: tool_specs(),
    }
}

fn ok_body() -> Value {
    json!({
        "id": "msg_1", "type": "message", "role": "assistant",
        "content": [{"type": "text", "text": "ok"}],
        "stop_reason": "end_turn"
    })
}

async fn mount_ok(server: &MockServer, body: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(server)
        .await;
}

async fn sent_body(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    serde_json::from_slice(&reqs[0].body).unwrap()
}

fn assert_clean(err: &PlannerError, needles: &[&str]) {
    let shown = format!("{err} {err:?}");
    for n in needles {
        assert!(!shown.contains(n), "error {shown:?} contains {n:?}");
    }
}

#[tokio::test]
async fn sends_key_version_and_tools() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", KEY))
        .and(header("anthropic-version", "2023-06-01"))
        .and(header("content-type", "application/json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(1)
        .mount(&server)
        .await;
    let out = planner(&server.uri()).plan(&request()).await.unwrap();
    assert_eq!(out.text.as_deref(), Some("ok"));

    let reqs = server.received_requests().await.unwrap();
    let ua = reqs[0].headers.get("user-agent").unwrap().to_str().unwrap();
    assert!(ua.starts_with("warden-agent/"), "{ua}");
    let body: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(body["model"], MODEL);
    assert_eq!(body["max_tokens"], 1024);
    assert_eq!(body["system"], "system prompt here");
    let names: Vec<&str> = body["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["list_dir", "read_file", "write_file", "delete_file"]
    );
    for t in body["tools"].as_array().unwrap() {
        assert!(t["description"].is_string());
        assert_eq!(t["input_schema"]["type"], "object");
    }
    assert_eq!(
        body["messages"],
        json!([{"role": "user", "content": [{"type": "text", "text": "list the files"}]}])
    );
}

#[tokio::test]
async fn merges_consecutive_same_role_turns() {
    let server = MockServer::start().await;
    mount_ok(&server, ok_body()).await;
    let req = PlanRequest {
        system: redact("s").0,
        turns: vec![
            Turn {
                role: Role::User,
                blocks: vec![Block::Text(redact("a").0)],
            },
            Turn {
                role: Role::User,
                blocks: vec![Block::Text(redact("b").0)],
            },
            Turn {
                role: Role::Assistant,
                blocks: vec![Block::Text(redact("thinking").0)],
            },
            Turn {
                role: Role::Assistant,
                blocks: vec![Block::tool_use("tu_1", "list_dir", &json!({"path": "."}))],
            },
            Turn {
                role: Role::User,
                blocks: vec![Block::ToolResult {
                    id: "tu_1".into(),
                    content: redact("a.txt").0,
                    is_error: false,
                }],
            },
        ],
        tools: tool_specs(),
    };
    planner(&server.uri()).plan(&req).await.unwrap();
    let body = sent_body(&server).await;
    assert_eq!(
        body["messages"],
        json!([
            {"role": "user", "content": [
                {"type": "text", "text": "a"},
                {"type": "text", "text": "b"}
            ]},
            {"role": "assistant", "content": [
                {"type": "text", "text": "thinking"},
                {"type": "tool_use", "id": "tu_1", "name": "list_dir", "input": {"path": "."}}
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "tu_1", "content": "a.txt", "is_error": false}
            ]}
        ])
    );
}

#[tokio::test]
async fn parses_text_and_tool_use() {
    let server = MockServer::start().await;
    mount_ok(
        &server,
        json!({"content": [
            {"type": "text", "text": "Let me look. "},
            {"type": "tool_use", "id": "toolu_01A", "name": "read_file", "input": {"path": "a.txt"}},
            {"type": "text", "text": "Then delete."},
            {"type": "tool_use", "id": "toolu_01B", "name": "delete_file", "input": {"path": "b.txt"}}
        ]}),
    )
    .await;
    let out = planner(&server.uri()).plan(&request()).await.unwrap();
    assert_eq!(out.text.as_deref(), Some("Let me look. Then delete."));
    assert_eq!(out.calls.len(), 2);
    assert_eq!(out.calls[0].id, "toolu_01A");
    assert_eq!(out.calls[0].name, "read_file");
    assert_eq!(out.calls[0].args, json!({"path": "a.txt"}));
    assert_eq!(out.calls[1].name, "delete_file");
}

#[tokio::test]
async fn long_text_is_truncated() {
    let server = MockServer::start().await;
    let long = "é".repeat(40_000); // 80,000 bytes
    mount_ok(
        &server,
        json!({"content": [{"type": "text", "text": long}]}),
    )
    .await;
    let out = planner(&server.uri()).plan(&request()).await.unwrap();
    let text = out.text.unwrap();
    assert!(text.len() <= 64 * 1024);
    assert!(text.len() > 60 * 1024);
}

#[tokio::test]
async fn ignores_unknown_block_types() {
    let server = MockServer::start().await;
    mount_ok(
        &server,
        json!({"content": [
            {"type": "thinking", "thinking": "hmm", "signature": "x"},
            {"type": "redacted_thinking", "data": "zzz"},
            {"type": "server_tool_use", "id": "srv_1", "name": "web_search", "input": {}},
            {"type": "tool_use", "id": "t-1", "name": "list_dir", "input": {"path": "."}}
        ]}),
    )
    .await;
    let out = planner(&server.uri()).plan(&request()).await.unwrap();
    assert_eq!(out.text, None);
    assert_eq!(out.calls.len(), 1);
    assert_eq!(out.calls[0].id, "t-1");
}

#[tokio::test]
async fn bad_tool_id_is_malformed() {
    let long = "a".repeat(65);
    let cases = [
        json!({"type": "tool_use", "id": "", "name": "list_dir", "input": {}}),
        json!({"type": "tool_use", "id": "a\nb", "name": "list_dir", "input": {}}),
        json!({"type": "tool_use", "id": "a b", "name": "list_dir", "input": {}}),
        json!({"type": "tool_use", "id": long, "name": "list_dir", "input": {}}),
        json!({"type": "tool_use", "id": "ok", "name": "", "input": {}}),
        json!({"type": "tool_use", "id": "ok", "name": "list dir", "input": {}}),
        json!({"type": "tool_use", "id": "ok", "name": long, "input": {}}),
        json!({"type": "tool_use", "id": "ok", "name": "lïst", "input": {}}),
    ];
    for block in cases {
        let server = MockServer::start().await;
        mount_ok(&server, json!({"content": [block]})).await;
        let err = planner(&server.uri()).plan(&request()).await.unwrap_err();
        assert_eq!(
            err,
            PlannerError::Malformed("bad tool id".into()),
            "{block}"
        );
    }
    // Exactly 64 is fine.
    let server = MockServer::start().await;
    let id64 = "A".repeat(64);
    mount_ok(
        &server,
        json!({"content": [{"type": "tool_use", "id": id64, "name": "list_dir", "input": {}}]}),
    )
    .await;
    assert!(planner(&server.uri()).plan(&request()).await.is_ok());
}

#[tokio::test]
async fn too_many_tool_use_blocks_is_malformed() {
    let block = |i: usize| json!({"type": "tool_use", "id": format!("t{i}"), "name": "list_dir", "input": {}});
    let server = MockServer::start().await;
    mount_ok(
        &server,
        json!({"content": (0..64).map(block).collect::<Vec<_>>()}),
    )
    .await;
    assert_eq!(
        planner(&server.uri())
            .plan(&request())
            .await
            .unwrap()
            .calls
            .len(),
        64
    );

    let server = MockServer::start().await;
    mount_ok(
        &server,
        json!({"content": (0..65).map(block).collect::<Vec<_>>()}),
    )
    .await;
    assert!(matches!(
        planner(&server.uri()).plan(&request()).await.unwrap_err(),
        PlannerError::Malformed(_)
    ));
}

#[tokio::test]
async fn non_2xx_is_status_error() {
    for code in [429u16, 500, 401] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(code).set_body_string(
                r#"{"type":"error","error":{"message":"BODY-MARKER-SHOULD-NOT-APPEAR"}}"#,
            ))
            .mount(&server)
            .await;
        let err = planner(&server.uri()).plan(&request()).await.unwrap_err();
        assert_eq!(err, PlannerError::Status(code));
        assert_clean(&err, &["BODY-MARKER", KEY]);
    }
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let server = MockServer::start().await;
    let big = format!(
        r#"{{"content":[{{"type":"text","text":"{}"}}]}}"#,
        "x".repeat(1_100_000)
    );
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(big, "application/json"))
        .mount(&server)
        .await;
    let err = planner(&server.uri()).plan(&request()).await.unwrap_err();
    assert_eq!(err, PlannerError::TooLarge);
}

/// A one-shot raw HTTP server: reads the request head and body, writes
/// `response` verbatim, then closes. Returns the base URL.
fn raw_server(response: Vec<u8>) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            s.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut buf = [0u8; 65536];
            let mut seen = Vec::new();
            // Read until the request body has arrived (or the client pauses).
            while let Ok(n) = s.read(&mut buf) {
                if n == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..n]);
                if let Some(head_end) = seen.windows(4).position(|w| w == b"\r\n\r\n") {
                    let head = String::from_utf8_lossy(&seen[..head_end]).to_lowercase();
                    let len = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length:"))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if seen.len() >= head_end + 4 + len {
                        break;
                    }
                }
            }
            let _ = s.write_all(&response);
            let _ = s.flush();
        }
    });
    format!("http://{addr}")
}

#[tokio::test]
async fn lying_content_length_is_not_trusted() {
    // A chunked body with no Content-Length: the size is only known by
    // reading, and reading stops at 1 MiB.
    let mut resp = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\nconnection: close\r\n\r\n".to_vec();
    let chunk = vec![b'x'; 256 * 1024];
    for _ in 0..8 {
        resp.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        resp.extend_from_slice(&chunk);
        resp.extend_from_slice(b"\r\n");
    }
    resp.extend_from_slice(b"0\r\n\r\n");
    let base = raw_server(resp);
    let err = planner(&base).plan(&request()).await.unwrap_err();
    assert_eq!(err, PlannerError::TooLarge);

    // A header that claims a huge body is not grounds for TooLarge on its
    // own (the header is not consulted); the short body is a transport error.
    let small = br#"{"content":[]}"#;
    let mut resp = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        50 * 1024 * 1024
    )
    .into_bytes();
    resp.extend_from_slice(small);
    let base = raw_server(resp);
    let err = planner(&base).plan(&request()).await.unwrap_err();
    assert!(matches!(err, PlannerError::Transport(_)), "{err:?}");

    // A header that claims a tiny body: only that many bytes are read, so a
    // larger trailing payload never reaches the parser.
    let mut resp = b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 14\r\nconnection: close\r\n\r\n".to_vec();
    resp.extend_from_slice(small);
    resp.extend_from_slice(&vec![b'y'; 2 * 1024 * 1024]);
    let base = raw_server(resp);
    let out = planner(&base).plan(&request()).await.unwrap();
    assert_eq!(out.text, None);
    assert!(out.calls.is_empty());
}

#[tokio::test]
async fn garbage_json_is_malformed() {
    let bodies = [
        "not json at all SECRET-BODY".to_string(),
        r#"{"no_content": true, "x": "SECRET-BODY"}"#.to_string(),
        r#"{"content": "SECRET-BODY"}"#.to_string(),
        r#"{"content": [{"type": "text", "text": 5}], "x": "SECRET-BODY"}"#.to_string(),
        r#"{"content": [{"type": "tool_use", "id": 5, "name": "x", "input": {}}], "x": "SECRET-BODY"}"#.to_string(),
        r#"{"content": [{"type": "tool_use", "id": "a", "name": "x"}], "x": "SECRET-BODY"}"#.to_string(),
        r#"{"content": ["SECRET-BODY"]}"#.to_string(),
        r#"{"content": [{"text": "SECRET-BODY"}]}"#.to_string(),
    ];
    for b in bodies {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/v1/messages"))
            .respond_with(ResponseTemplate::new(200).set_body_raw(b.clone(), "application/json"))
            .mount(&server)
            .await;
        let err = planner(&server.uri()).plan(&request()).await.unwrap_err();
        assert!(matches!(err, PlannerError::Malformed(_)), "{b}: {err:?}");
        assert_clean(&err, &["SECRET-BODY"]);
    }
}

#[tokio::test]
async fn debug_output_never_contains_the_key() {
    let server = MockServer::start().await;
    let p = planner(&server.uri());
    let dbg = format!("{p:?}");
    assert!(!dbg.contains(KEY), "{dbg}");
    assert!(dbg.contains(MODEL), "{dbg}");
    assert!(dbg.contains("127.0.0.1"), "{dbg}");

    let mut errors = Vec::new();
    // Status
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(403).set_body_string(KEY))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    errors.push(p.plan(&request()).await.unwrap_err());
    // Malformed (the body even echoes the key)
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_string(format!("oops {KEY}")))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    errors.push(p.plan(&request()).await.unwrap_err());
    // Timeout
    let slow = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_secs(2)))
        .mount(&slow)
        .await;
    errors.push(
        planner(&slow.uri())
            .with_timeout(Duration::from_millis(100))
            .plan(&request())
            .await
            .unwrap_err(),
    );
    // Connect failure
    errors.push(
        planner(&closed_port_base())
            .plan(&request())
            .await
            .unwrap_err(),
    );
    // Constructor
    errors.push(
        AnthropicPlanner::new(KEY.into(), MODEL.into(), "http://example.com".into()).unwrap_err(),
    );
    errors.push(AnthropicPlanner::new(format!("{KEY}\n"), MODEL.into(), server.uri()).unwrap_err());
    assert_eq!(errors.len(), 6);
    for e in &errors {
        assert_clean(e, &[KEY]);
    }
}

#[tokio::test]
async fn request_contains_no_unredacted_secret() {
    let secret = "sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789";
    let server = MockServer::start().await;
    mount_ok(&server, ok_body()).await;
    let req = PlanRequest {
        system: redact(&format!("system with {secret}")).0,
        turns: vec![
            Turn {
                role: Role::User,
                blocks: vec![Block::Text(
                    redact(&format!("my key is {secret} please use it")).0,
                )],
            },
            Turn {
                role: Role::Assistant,
                blocks: vec![Block::tool_use(
                    "t1",
                    "write_file",
                    &json!({"path": "k.txt", "content": secret}),
                )],
            },
            Turn {
                role: Role::User,
                blocks: vec![Block::ToolResult {
                    id: "t1".into(),
                    content: redact(&format!("wrote {secret}")).0,
                    is_error: false,
                }],
            },
        ],
        tools: tool_specs(),
    };
    planner(&server.uri()).plan(&req).await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    let raw = String::from_utf8(reqs[0].body.clone()).unwrap();
    assert!(!raw.contains(secret), "raw secret sent: {raw}");
    assert!(!raw.contains("AbCdEfGhIjKlMnOp"));
    assert!(raw.contains("[REDACTED:api_key]"));
    let body: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(
        body["messages"][0]["content"][0]["text"],
        "my key is [REDACTED:api_key] please use it"
    );
}

#[tokio::test]
async fn timeout_is_transport_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(ok_body())
                .set_delay(Duration::from_secs(3)),
        )
        .mount(&server)
        .await;
    let start = std::time::Instant::now();
    let err = planner(&server.uri())
        .with_timeout(Duration::from_millis(200))
        .plan(&request())
        .await
        .unwrap_err();
    assert!(matches!(err, PlannerError::Transport(_)), "{err:?}");
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(302).insert_header("location", format!("{}/other", server.uri())),
        )
        .mount(&server)
        .await;
    Mock::given(path("/other"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(0)
        .named("redirect target")
        .mount(&server)
        .await;
    let err = planner(&server.uri()).plan(&request()).await.unwrap_err();
    assert_eq!(err, PlannerError::Status(302));
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.path(), "/v1/messages");
}

#[test]
fn http_non_loopback_base_url_is_rejected() {
    let mk = |b: &str| AnthropicPlanner::new(KEY.into(), MODEL.into(), b.into());
    for bad in [
        "http://example.com",
        "http://10.0.0.1:8080",
        "http://127.0.0.2",
        "http://localhost.evil.com",
        "ftp://127.0.0.1",
        "file:///etc/passwd",
        "not a url",
        "",
        "https://user:pw@api.anthropic.com",
        "https://api.anthropic.com/?q=1",
        "https://api.anthropic.com/#frag",
    ] {
        assert!(mk(bad).is_err(), "accepted {bad:?}");
    }
    for good in [
        "https://api.anthropic.com",
        "https://api.anthropic.com/",
        "https://proxy.example.com/anthropic",
        "http://127.0.0.1:8090",
        "http://localhost:8090",
        "http://[::1]:8090",
    ] {
        assert!(mk(good).is_ok(), "rejected {good:?}");
    }
}

#[test]
fn empty_key_or_model_rejected() {
    let base = "https://api.anthropic.com".to_string();
    assert!(AnthropicPlanner::new(String::new(), MODEL.into(), base.clone()).is_err());
    assert!(AnthropicPlanner::new(KEY.into(), String::new(), base.clone()).is_err());
    assert!(AnthropicPlanner::new("bad\nkey".into(), MODEL.into(), base.clone()).is_err());
    assert!(AnthropicPlanner::new(KEY.into(), MODEL.into(), base).is_ok());
}

#[tokio::test]
async fn trailing_slash_base_url_handled() {
    let server = MockServer::start().await;
    mount_ok(&server, ok_body()).await;
    let base = format!("{}/", server.uri());
    planner(&base).plan(&request()).await.unwrap();
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs[0].url.path(), "/v1/messages");

    // A base path is kept.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/proxy/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(ok_body()))
        .expect(1)
        .mount(&server)
        .await;
    planner(&format!("{}/proxy/", server.uri()))
        .plan(&request())
        .await
        .unwrap();
}

fn closed_port_base() -> String {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    format!("http://127.0.0.1:{port}")
}

#[tokio::test]
async fn transport_error_message_has_no_url() {
    let base = closed_port_base();
    let port = base.rsplit(':').next().unwrap().to_string();
    let err = planner(&base).plan(&request()).await.unwrap_err();
    let PlannerError::Transport(msg) = &err else {
        panic!("expected transport error, got {err:?}");
    };
    assert!(!msg.is_empty());
    assert_clean(&err, &["127.0.0.1", &port, "http://", "/v1/messages", KEY]);
}
