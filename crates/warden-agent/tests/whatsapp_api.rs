use serde_json::{json, Value};
use std::time::Duration;
use warden_agent::whatsapp::{AccessToken, ErrorClass, GraphApi, WhatsAppError};
use wiremock::matchers::{body_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "EAAGm0PX4ZCpsBAsecret_0123456789-abcdef.DONOTLEAK";
const PHONE_ID: &str = "106540352242922";
const VERSION: &str = "v26.0";
const WAMID: &str = "wamid.HBgLMTU1NTEyMzQ1NjcVAgARGBI5QTNDQTVCM0Q0Q0Q2RTY3RTcA";

fn token() -> AccessToken {
    AccessToken::new(TOKEN.to_string()).unwrap()
}

fn api(base: &str) -> GraphApi {
    GraphApi::new(token(), base, VERSION, PHONE_ID).unwrap()
}

fn messages_path() -> String {
    format!("/{VERSION}/{PHONE_ID}/messages")
}

fn bearer() -> String {
    format!("Bearer {TOKEN}")
}

fn assert_clean(shown: &str) {
    assert!(!shown.contains(TOKEN), "{shown:?} contains the token");
}

fn sent_ok() -> Value {
    json!({
        "messaging_product": "whatsapp",
        "contacts": [{"input": "15551234567", "wa_id": "15551234567"}],
        "messages": [{"id": WAMID}],
    })
}

/// A server answering every request with `status` and `body`.
async fn answering(status: u16, body: Value) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(status).set_body_json(body))
        .mount(&server)
        .await;
    server
}

fn graph_error(code: i64, subcode: Option<i64>) -> Value {
    let mut e = json!({
        "message": "LEAKME (#{code}) something went wrong",
        "type": "OAuthException",
        "code": code,
        "error_user_msg": "LEAKME user message",
        "fbtrace_id": "LEAKMEtrace",
    });
    if let Some(s) = subcode {
        e["error_subcode"] = json!(s);
    }
    json!({ "error": e })
}

#[tokio::test]
async fn send_text_body_is_exact() {
    let text = "[x](https://evil.example/?d=1) <b>";
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(messages_path()))
        .and(header("authorization", bearer().as_str()))
        .and(body_json(json!({
            "messaging_product": "whatsapp",
            "recipient_type": "individual",
            "to": "15551234567",
            "type": "text",
            "text": {"preview_url": false, "body": text},
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(sent_ok()))
        .mount(&server)
        .await;
    api(&server.uri())
        .send_text("15551234567", text)
        .await
        .unwrap();

    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_eq!(reqs[0].url.query(), None);
    assert_clean(reqs[0].url.as_str());
    let v: Value = serde_json::from_slice(&reqs[0].body).unwrap();
    assert_eq!(
        v["text"]["body"].as_str().unwrap().as_bytes(),
        text.as_bytes()
    );
}

#[tokio::test]
async fn send_text_returns_wamid() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path(messages_path()))
        .respond_with(ResponseTemplate::new(200).set_body_json(sent_ok()))
        .mount(&server)
        .await;
    let id = api(&server.uri())
        .send_text("15551234567", "hello")
        .await
        .unwrap();
    assert_eq!(id, WAMID);

    // No messages[0].id is Malformed.
    let server = answering(
        200,
        json!({"messaging_product": "whatsapp", "messages": []}),
    )
    .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hello")
        .await
        .unwrap_err();
    assert!(matches!(e, WhatsAppError::Malformed(_)), "{e:?}");
}

#[tokio::test]
async fn phone_number_uses_get_bearer_and_fields() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{VERSION}/{PHONE_ID}")))
        .and(query_param("fields", "display_phone_number,verified_name"))
        .and(header("authorization", bearer().as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "display_phone_number": "+1 555-010-0000",
            "verified_name": "Warden Test",
            "id": PHONE_ID,
        })))
        .mount(&server)
        .await;
    let info = api(&server.uri()).phone_number().await.unwrap();
    assert_eq!(info.display_phone_number, "+1 555-010-0000");
    assert_eq!(info.verified_name.as_deref(), Some("Warden Test"));
    let reqs = server.received_requests().await.unwrap();
    assert_eq!(reqs.len(), 1);
    assert_clean(reqs[0].url.as_str());

    // verified_name is optional; display_phone_number is not.
    let server = answering(
        200,
        json!({"display_phone_number": "+1 555", "id": PHONE_ID}),
    )
    .await;
    let info = api(&server.uri()).phone_number().await.unwrap();
    assert_eq!(info.verified_name, None);
    let server = answering(200, json!({"id": PHONE_ID})).await;
    let e = api(&server.uri()).phone_number().await.unwrap_err();
    assert!(matches!(e, WhatsAppError::Malformed(_)), "{e:?}");
}

#[tokio::test]
async fn graph_error_keeps_code_and_subcode_only() {
    let server = answering(400, graph_error(100, Some(33))).await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(
        e,
        WhatsAppError::Graph {
            status: 400,
            code: 100,
            subcode: Some(33)
        }
    );
    assert_eq!(e.class(), ErrorClass::Other);
    let shown = format!("{e} {e:?}");
    assert!(!shown.contains("LEAKME"), "{shown}");
}

#[tokio::test]
async fn auth_errors_are_auth_rejected() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(e, WhatsAppError::Status(401));
    assert_eq!(e.class(), ErrorClass::AuthRejected);

    let server = answering(400, graph_error(190, Some(463))).await;
    let e = api(&server.uri()).phone_number().await.unwrap_err();
    assert_eq!(
        e,
        WhatsAppError::Graph {
            status: 400,
            code: 190,
            subcode: Some(463)
        }
    );
    assert_eq!(e.class(), ErrorClass::AuthRejected);
}

#[tokio::test]
async fn rate_limits_are_rate_limited() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(429))
        .mount(&server)
        .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(e, WhatsAppError::Status(429));
    assert_eq!(e.class(), ErrorClass::RateLimited);

    for code in [130429, 131056] {
        let server = answering(400, graph_error(code, None)).await;
        let e = api(&server.uri())
            .send_text("15551234567", "hi")
            .await
            .unwrap_err();
        assert_eq!(
            e,
            WhatsAppError::Graph {
                status: 400,
                code,
                subcode: None
            }
        );
        assert_eq!(e.class(), ErrorClass::RateLimited, "{code}");
    }
    for code in [4, 80007, 131048] {
        let e = WhatsAppError::Graph {
            status: 400,
            code,
            subcode: None,
        };
        assert_eq!(e.class(), ErrorClass::RateLimited, "{code}");
    }
}

#[tokio::test]
async fn code_131047_is_outside_window() {
    let server = answering(400, graph_error(131047, None)).await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(
        e,
        WhatsAppError::Graph {
            status: 400,
            code: 131047,
            subcode: None
        }
    );
    assert_eq!(e.class(), ErrorClass::OutsideWindow);
    assert_eq!(WhatsAppError::Status(500).class(), ErrorClass::Other);
    assert_eq!(WhatsAppError::TooLarge.class(), ErrorClass::Other);
}

#[tokio::test]
async fn oversized_body_is_too_large() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b' '; (64 << 10) + 1]))
        .mount(&server)
        .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(e, WhatsAppError::TooLarge);
}

#[tokio::test]
async fn garbage_json_is_malformed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_string("{not json"))
        .mount(&server)
        .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert!(matches!(e, WhatsAppError::Malformed(_)), "{e:?}");
}

#[tokio::test]
async fn redirect_is_not_followed() {
    let target = MockServer::start().await;
    Mock::given(wiremock::matchers::any())
        .respond_with(ResponseTemplate::new(200).set_body_json(sent_ok()))
        .mount(&target)
        .await;
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("location", format!("{}{}", target.uri(), messages_path())),
        )
        .mount(&server)
        .await;
    let e = api(&server.uri())
        .send_text("15551234567", "hi")
        .await
        .unwrap_err();
    assert_eq!(e, WhatsAppError::Status(302));
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
    let e = api_closed.phone_number().await.unwrap_err();
    assert_eq!(e, WhatsAppError::Transport("connect"));
    assert_clean(&format!("{e} {e:?} {api_closed:?}"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401).set_body_string(format!("bad token {TOKEN}")))
        .mount(&server)
        .await;
    let api_401 = api(&server.uri());
    let e = api_401.send_text("15551234567", "hi").await.unwrap_err();
    assert_eq!(e, WhatsAppError::Status(401));
    assert_clean(&format!("{e} {e:?} {api_401:?}"));

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(sent_ok())
                .set_delay(Duration::from_secs(5)),
        )
        .mount(&server)
        .await;
    let api_slow = api(&server.uri()).with_timeout(Duration::from_millis(200));
    let e = api_slow.send_text("15551234567", "hi").await.unwrap_err();
    assert_eq!(e, WhatsAppError::Transport("timeout"));
    assert_clean(&format!("{e} {e:?} {api_slow:?}"));

    let t = token();
    assert_eq!(format!("{t:?}"), "AccessToken(<redacted>)");
    let shown = format!("{:?}", api(&server.uri()));
    assert!(
        shown.contains(VERSION) && shown.contains(PHONE_ID),
        "{shown}"
    );
}

#[test]
fn token_shape_is_validated() {
    let bad = [
        "a".repeat(31),
        format!("{} x", "a".repeat(40)),
        format!("{}\n", "a".repeat(40)),
        format!("{TOKEN}\n"),
        "a".repeat(2049),
        format!("{}!", "a".repeat(40)),
        format!("{}/", "a".repeat(40)),
        String::new(),
    ];
    for b in bad {
        let e = AccessToken::new(b.clone()).unwrap_err();
        assert_eq!(e, WhatsAppError::Config("invalid access token"), "{b:?}");
        assert!(b.is_empty() || !format!("{e} {e:?}").contains(&b));
    }
    for good in [
        TOKEN.to_string(),
        "a".repeat(32),
        "Z9._-".repeat(400) + "abcdefgh",
    ] {
        assert!((32..=2048).contains(&good.len()));
        AccessToken::new(good).unwrap();
    }
}

#[test]
fn api_base_must_be_https_or_loopback() {
    for bad in [
        "http://graph.facebook.com",
        "http://evil.example:8080",
        "ftp://127.0.0.1",
        "https://user:pw@graph.facebook.com",
        "https://graph.facebook.com/?q=1",
        "not a url",
    ] {
        let e = GraphApi::new(token(), bad, VERSION, PHONE_ID).unwrap_err();
        assert!(matches!(e, WhatsAppError::Config(_)), "{bad}: {e:?}");
    }
    for good in [
        "https://graph.facebook.com",
        "https://graph.facebook.com/",
        "http://127.0.0.1:8097",
        "http://localhost:8097",
        "http://[::1]:8097",
    ] {
        let a = GraphApi::new(token(), good, VERSION, PHONE_ID).unwrap();
        assert_clean(&format!("{a:?}"));
    }
}

#[test]
fn version_and_phone_number_id_are_validated() {
    let base = "https://graph.facebook.com";
    for bad in [
        "",
        "26.0",
        "v26",
        "v26.",
        "v.0",
        "V26.0",
        "v26.0/",
        "v26.0/../x",
        "v26.0?a",
        "v 26.0",
        "v1234.0",
        "v26.100",
    ] {
        let e = GraphApi::new(token(), base, bad, PHONE_ID).unwrap_err();
        assert!(matches!(e, WhatsAppError::Config(_)), "{bad:?}: {e:?}");
    }
    for good in ["v26.0", "v1.0", "v100.12"] {
        GraphApi::new(token(), base, good, PHONE_ID).unwrap();
    }
    let too_long = "1".repeat(33);
    for bad in [
        "",
        "abc",
        "1065403522429a2",
        "106540352242922/messages",
        "../106540352242922",
        " 106540352242922",
        "-1",
        too_long.as_str(),
    ] {
        let e = GraphApi::new(token(), base, VERSION, bad).unwrap_err();
        assert!(matches!(e, WhatsAppError::Config(_)), "{bad:?}: {e:?}");
    }
    for good in ["1", PHONE_ID, "1".repeat(32).as_str()] {
        GraphApi::new(token(), base, VERSION, good).unwrap();
    }
}
