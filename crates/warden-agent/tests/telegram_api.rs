use serde_json::{json, Value};
use std::time::Duration;
use warden_agent::telegram::{BotToken, TelegramApi, TelegramError};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "123456789:AAH-secret_half_0123456789abcdefDONOTLEAK";
const SECRET: &str = "AAH-secret_half_0123456789abcdefDONOTLEAK";

fn token() -> BotToken {
    BotToken::new(TOKEN.to_string()).unwrap()
}

fn api(base: &str) -> TelegramApi {
    TelegramApi::new(token(), base).unwrap()
}

fn method_path(m: &str) -> String {
    format!("/bot{TOKEN}/{m}")
}

async fn mount_ok(server: &MockServer, m: &str, result: Value) {
    Mock::given(method("POST"))
        .and(path(method_path(m)))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "result": result})),
        )
        .mount(server)
        .await;
}

async fn sent_body(server: &MockServer) -> Value {
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].method.as_str(), "POST");
    serde_json::from_slice(&reqs[0].body).unwrap()
}

fn assert_clean(shown: &str) {
    assert!(!shown.contains(TOKEN), "{shown:?} contains the token");
    assert!(
        !shown.contains(SECRET),
        "{shown:?} contains the secret half"
    );
}

#[tokio::test]
async fn get_me_requires_is_bot() {
    let server = MockServer::start().await;
    mount_ok(
        &server,
        "getMe",
        json!({"id": 42, "is_bot": true, "username": "warden_bot", "first_name": "W"}),
    )
    .await;
    let me = api(&server.uri()).get_me().await.unwrap();
    assert_eq!(me.id, 42);
    assert_eq!(me.username.as_deref(), Some("warden_bot"));

    let server = MockServer::start().await;
    mount_ok(&server, "getMe", json!({"id": 42, "is_bot": false})).await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Malformed("not a bot")), "{e:?}");

    let server = MockServer::start().await;
    mount_ok(&server, "getMe", json!({"id": 42})).await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Malformed("not a bot")), "{e:?}");
}

#[tokio::test]
async fn get_updates_posts_offset_timeout_limit_and_allowed_updates() {
    let server = MockServer::start().await;
    mount_ok(
        &server,
        "getUpdates",
        json!([{"update_id": 7, "message": {"message_id": 1}}]),
    )
    .await;
    let ups = api(&server.uri()).get_updates(5, 0, 10).await.unwrap();
    assert_eq!(ups.len(), 1);
    assert_eq!(ups[0]["update_id"], 7);
    let body = sent_body(&server).await;
    assert_eq!(
        body,
        json!({"offset": 5, "timeout": 0, "limit": 10, "allowed_updates": ["message"]})
    );
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(
        reqs[0].headers.get("content-type").unwrap(),
        "application/json"
    );
}

#[tokio::test]
async fn send_message_disables_previews_and_uses_no_parse_mode() {
    let server = MockServer::start().await;
    mount_ok(
        &server,
        "sendMessage",
        json!({"message_id": 99, "chat": {"id": 5}}),
    )
    .await;
    let text = "[x](https://evil.example/?d=1) <b>";
    let id = api(&server.uri()).send_message(5, text).await.unwrap();
    assert_eq!(id, 99);
    let body = sent_body(&server).await;
    let o = body.as_object().unwrap();
    assert!(!o.contains_key("parse_mode"), "{body}");
    assert_eq!(body["link_preview_options"]["is_disabled"], true);
    assert_eq!(body["protect_content"], true);
    assert_eq!(body["chat_id"], 5);
    assert_eq!(body["text"].as_str(), Some(text));
    let mut keys: Vec<&str> = o.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["chat_id", "link_preview_options", "protect_content", "text"]
    );
}

#[tokio::test]
async fn delete_message_posts_ids() {
    let server = MockServer::start().await;
    mount_ok(&server, "deleteMessage", json!(true)).await;
    api(&server.uri()).delete_message(5, 77).await.unwrap();
    assert_eq!(
        sent_body(&server).await,
        json!({"chat_id": 5, "message_id": 77})
    );
}

#[tokio::test]
async fn api_error_maps_code_and_retry_after() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429).set_body_json(json!({
            "ok": false,
            "error_code": 429,
            "description": "Too Many Requests: retry after 7",
            "parameters": {"retry_after": 7}
        })))
        .mount(&server)
        .await;
    let e = api(&server.uri()).send_message(5, "hi").await.unwrap_err();
    assert!(
        matches!(
            e,
            TelegramError::Api {
                code: 429,
                retry_after: Some(7)
            }
        ),
        "{e:?}"
    );
    assert!(!format!("{e} {e:?}").contains("Too Many"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "ok": false, "error_code": 400, "description": "Bad Request: chat not found"
        })))
        .mount(&server)
        .await;
    let e = api(&server.uri()).send_message(5, "hi").await.unwrap_err();
    assert!(
        matches!(
            e,
            TelegramError::Api {
                code: 400,
                retry_after: None
            }
        ),
        "{e:?}"
    );

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(502).set_body_string("<html>bad gateway</html>"))
        .mount(&server)
        .await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Status(502)), "{e:?}");
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; (1 << 20) + 1]))
        .mount(&server)
        .await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::TooLarge), "{e:?}");
}

#[tokio::test]
async fn garbage_json_is_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not json"))
        .mount(&server)
        .await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Malformed(_)), "{e:?}");

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;
    let e = api(&server.uri()).get_updates(0, 0, 1).await.unwrap_err();
    assert!(matches!(e, TelegramError::Malformed(_)), "{e:?}");
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let target = MockServer::start().await;
    mount_ok(&target, "getMe", json!({"id": 1, "is_bot": true})).await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}{}", target.uri(), method_path("getMe")),
        ))
        .mount(&server)
        .await;
    let e = api(&server.uri()).get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Status(302)), "{e:?}");
    assert!(target.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn errors_and_debug_never_contain_the_token() {
    // A closed loopback port: bind, read the port, release it.
    let port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let api_closed = api(&format!("http://127.0.0.1:{port}"));
    let e = api_closed.get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Transport("connect")), "{e:?}");
    assert_clean(&format!("{e} {e:?} {api_closed:?}"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(404).set_body_string(format!("no such path {TOKEN}")))
        .mount(&server)
        .await;
    let api_404 = api(&server.uri());
    let e = api_404.get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Status(404)), "{e:?}");
    assert_clean(&format!("{e} {e:?} {api_404:?}"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"ok": true, "result": {"id": 1, "is_bot": true}}))
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let api_slow = api(&server.uri()).with_timeout(Duration::from_millis(200));
    let e = api_slow.get_me().await.unwrap_err();
    assert!(matches!(e, TelegramError::Transport("timeout")), "{e:?}");
    assert_clean(&format!("{e} {e:?} {api_slow:?}"));

    let t = token();
    assert_eq!(format!("{t:?}"), "BotToken(<redacted>)");
}

#[test]
fn token_shape_is_validated() {
    let secret65 = "a".repeat(65);
    let bad = [
        "abc".to_string(),
        "123:short".to_string(),
        format!("{TOKEN}\n"),
        "123456789:AAH-secret\n_half_0123456789abcdefDONOTLEAK".to_string(),
        format!("123456789:{secret65}"),
        format!("1234:{}", "a".repeat(30)),
        format!("12345678901234567:{}", "a".repeat(30)),
        format!("123456789:{}", "a".repeat(29)),
        format!("123456789:{}!", "a".repeat(30)),
        format!(" 123456789:{}", "a".repeat(30)),
    ];
    for b in bad {
        let e = BotToken::new(b.clone()).unwrap_err();
        assert!(
            matches!(e, TelegramError::Config("invalid bot token")),
            "{b:?}: {e:?}"
        );
        assert!(!format!("{e} {e:?}").contains(&b));
    }
    for good in [
        TOKEN.to_string(),
        format!("12345:{}", "a".repeat(30)),
        format!("1234567890123456:{}", "Z_-9".repeat(16)),
    ] {
        BotToken::new(good).unwrap();
    }
}

#[test]
fn api_base_must_be_https_or_loopback() {
    for bad in [
        "http://api.telegram.org",
        "http://evil.example:8080",
        "ftp://127.0.0.1",
        "https://user:pw@api.telegram.org",
        "https://api.telegram.org/?q=1",
        "not a url",
    ] {
        let e = TelegramApi::new(token(), bad).unwrap_err();
        assert!(matches!(e, TelegramError::Config(_)), "{bad}: {e:?}");
    }
    for good in [
        "https://api.telegram.org",
        "https://api.telegram.org/",
        "http://127.0.0.1:8097",
        "http://localhost:8097",
        "http://[::1]:8097",
    ] {
        let a = TelegramApi::new(token(), good).unwrap();
        assert_clean(&format!("{a:?}"));
    }
}
