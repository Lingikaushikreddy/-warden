//! Proxy environment variables must be ignored. In its own test binary
//! because it sets process-wide environment variables (one test only, so no
//! other test in this process can race with it).

use serde_json::json;
use std::net::TcpListener;
use warden_agent::anthropic::AnthropicPlanner;
use warden_agent::planner::{Block, PlanRequest, Planner, Role, Turn};
use warden_agent::redact::redact;
use warden_agent::tools::tool_specs;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
async fn proxy_env_is_ignored() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"content": [{"type": "text", "text": "ok"}]})),
        )
        .expect(1)
        .mount(&server)
        .await;

    let proxy = TcpListener::bind("127.0.0.1:0").unwrap();
    proxy.set_nonblocking(true).unwrap();
    let proxy_url = format!("http://{}", proxy.local_addr().unwrap());
    for k in [
        "HTTP_PROXY",
        "http_proxy",
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
    ] {
        std::env::set_var(k, &proxy_url);
    }
    for k in ["NO_PROXY", "no_proxy"] {
        std::env::remove_var(k);
    }

    let p = AnthropicPlanner::new(
        "k-0123456789".into(),
        "claude-sonnet-5-5".into(),
        server.uri(),
    )
    .unwrap()
    .with_timeout(std::time::Duration::from_secs(3));
    let req = PlanRequest {
        system: redact("s").0,
        turns: vec![Turn {
            role: Role::User,
            blocks: vec![Block::Text(redact("hi").0)],
        }],
        tools: tool_specs(),
    };
    let res = p.plan(&req).await;

    let proxied = proxy.accept();
    assert!(
        matches!(&proxied, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "the proxy received a connection"
    );
    assert_eq!(res.unwrap().text.as_deref(), Some("ok"));
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}
