//! The loopback webhook listener, driven by a real loopback client:
//! reqwest for well-formed requests, a raw `TcpStream` for slow, partial
//! and oversized ones.

use hmac::{Hmac, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use warden_agent::whatsapp::{
    AppSecret, ListenerConfig, StatsSnapshot, VerifyToken, WaEvent, WebhookBatch, WebhookListener,
    WebhookStats, WEBHOOK_PATH,
};

const SECRET: &str = "0123456789abcdefABCDEF0123456789";
const OTHER_SECRET: &str = "ffffffffffffffffffffffffffffffff";
const TOKEN: &str = "verify-token_0123.~xyz";
const PNID: &str = "106540352242922";
const OWNER: &str = "15551234567";
const MIB: usize = 1024 * 1024;

fn config() -> ListenerConfig {
    ListenerConfig::new(
        AppSecret::new(SECRET.into()).unwrap(),
        VerifyToken::new(TOKEN.into()).unwrap(),
        PNID.into(),
    )
}

fn sign(secret: &str, body: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body);
    format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
}

fn envelope_from(pnid: &str) -> Vec<u8> {
    json!({
        "object": "whatsapp_business_account",
        "entry": [{"id": "WABA_ID", "changes": [{"field": "messages", "value": {
            "messaging_product": "whatsapp",
            "metadata": {"display_phone_number": "15550000000", "phone_number_id": pnid},
            "contacts": [{"profile": {"name": "K"}, "wa_id": OWNER}],
            "messages": [{
                "from": OWNER,
                "id": "wamid.HBgLMTU1NTEyMzQ1NjcVAgASGBQzQTk=",
                "timestamp": "1700000000",
                "type": "text",
                "text": {"body": "list the files"}
            }]
        }}]}]
    })
    .to_string()
    .into_bytes()
}

fn envelope() -> Vec<u8> {
    envelope_from(PNID)
}

struct Harness {
    addr: SocketAddr,
    rx: mpsc::Receiver<WebhookBatch>,
    stats: Arc<WebhookStats>,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<()>,
    client: reqwest::Client,
}

impl Harness {
    fn url(&self, path_and_query: &str) -> String {
        format!("http://{}{}", self.addr, path_and_query)
    }

    fn snap(&self) -> StatsSnapshot {
        self.stats.snapshot()
    }

    async fn post(&self, sig: Option<String>, body: Vec<u8>) -> (u16, String) {
        let mut req = self.client.post(self.url(WEBHOOK_PATH)).body(body);
        if let Some(sig) = sig {
            req = req.header("x-hub-signature-256", sig);
        }
        let resp = req.send().await.expect("request");
        let status = resp.status().as_u16();
        (status, resp.text().await.unwrap())
    }

    async fn signed_post(&self, body: Vec<u8>) -> (u16, String) {
        let sig = sign(SECRET, &body);
        self.post(Some(sig), body).await
    }
}

async fn start_with(cap: usize, f: impl FnOnce(&mut ListenerConfig)) -> Harness {
    let mut cfg = config();
    f(&mut cfg);
    let listener = WebhookListener::bind("127.0.0.1:0".parse().unwrap())
        .await
        .expect("bind loopback");
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(cap);
    let stats = Arc::new(WebhookStats::default());
    let (shutdown, shutdown_rx) = watch::channel(false);
    let task = tokio::spawn(listener.serve(cfg, tx, stats.clone(), shutdown_rx));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    Harness {
        addr,
        rx,
        stats,
        shutdown,
        task,
        client,
    }
}

async fn start() -> Harness {
    start_with(8, |_| {}).await
}

/// Read until EOF (or a reset) and return what arrived. Panics if the
/// connection is still open after `limit`.
async fn read_until_closed(s: &mut TcpStream, limit: Duration) -> String {
    let mut out = Vec::new();
    let res = timeout(limit, async {
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::ConnectionReset => break,
                Err(e) => panic!("read: {e}"),
            }
        }
    })
    .await;
    assert!(res.is_ok(), "connection still open after {limit:?}");
    String::from_utf8_lossy(&out).into_owned()
}

// ---------- handshake ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_echoes_digit_challenge_with_the_right_token() {
    let h = start().await;
    let resp = h
        .client
        .get(h.url(&format!(
            "{WEBHOOK_PATH}?hub.mode=subscribe&hub.verify_token={TOKEN}&hub.challenge=1158201444"
        )))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    assert_eq!(
        resp.headers()["content-type"].to_str().unwrap(),
        "text/plain"
    );
    assert_eq!(resp.text().await.unwrap(), "1158201444");
    assert!(h.snap().is_zero());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn handshake_wrong_token_or_mode_is_403() {
    let h = start().await;
    let queries = [
        "hub.mode=subscribe&hub.verify_token=wrongtokenwrongtoken&hub.challenge=987654".to_string(),
        format!("hub.mode=unsubscribe&hub.verify_token={TOKEN}&hub.challenge=987654"),
        format!("hub.mode=subscribe&hub.verify_token={TOKEN}&hub.challenge=98x7654"),
        String::new(),
    ];
    for q in &queries {
        let resp = h
            .client
            .get(h.url(&format!("{WEBHOOK_PATH}?{q}")))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 403, "query {q:?}");
        let body = resp.text().await.unwrap();
        for part in ["987654", "98x7654", "wrongtoken", "subscribe", TOKEN, "hub"] {
            assert!(!body.contains(part), "body {body:?} echoes {part:?}");
        }
    }
    let resp = h.client.get(h.url(WEBHOOK_PATH)).send().await.unwrap();
    assert_eq!(resp.status().as_u16(), 403);
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            handshake_refused: 5,
            ..StatsSnapshot::default()
        }
    );
}

// ---------- signed and unsigned POSTs ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_post_is_200_and_forwarded() {
    let mut h = start().await;
    let (status, _) = h.signed_post(envelope()).await;
    assert_eq!(status, 200);
    let batch = h.rx.try_recv().expect("one batch");
    assert_eq!(batch.events.len(), 1);
    match &batch.events[0] {
        WaEvent::Text { from, body, .. } => {
            assert_eq!(from, OWNER);
            assert_eq!(body, "list the files");
        }
        other => panic!("expected text, got {other:?}"),
    }
    assert!(h.rx.try_recv().is_err());
    assert!(h.snap().is_zero());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn unsigned_post_is_401_and_not_forwarded() {
    let mut h = start().await;
    let (status, _) = h.post(None, envelope()).await;
    assert_eq!(status, 401);
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            unsigned: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bad_signature_is_401_and_not_forwarded() {
    let mut h = start().await;
    let body = envelope();
    let other_secret = sign(OTHER_SECRET, &body);
    let other_body = sign(SECRET, b"{\"object\":\"whatsapp_business_account\"}");
    let good = sign(SECRET, &body);
    let sha1 = format!("sha1={}", good.strip_prefix("sha256=").unwrap());
    for sig in [other_secret, other_body, sha1] {
        let (status, _) = h.post(Some(sig), body.clone()).await;
        assert_eq!(status, 401);
    }
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            bad_signature: 3,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn foreign_phone_number_id_is_200_and_not_forwarded() {
    let mut h = start().await;
    let (status, _) = h.signed_post(envelope_from("999999999999")).await;
    assert_eq!(status, 200);
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            foreign: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn malformed_signed_json_is_200_and_not_forwarded() {
    let mut h = start().await;
    let not_wa: Value = json!({"object": "page", "entry": []});
    for body in [b"{not json".to_vec(), not_wa.to_string().into_bytes()] {
        let (status, _) = h.signed_post(body).await;
        assert_eq!(status, 200);
    }
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            malformed: 2,
            ..StatsSnapshot::default()
        }
    );
}

// ---------- abuse limits ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn oversized_body_is_413_and_never_parsed() {
    let mut h = start().await;

    // A declared length one byte over the cap: 413 before any body read.
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(
        format!(
            "POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\nX-Hub-Signature-256: {}\r\n\
             Content-Length: {}\r\n\r\n",
            sign(SECRET, b""),
            MIB + 1
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let resp = read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 413"), "got {resp:?}");

    // A chunked body that runs past the cap.
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    let mut req = format!(
        "POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\nX-Hub-Signature-256: {}\r\n\
         Transfer-Encoding: chunked\r\n\r\n",
        sign(SECRET, b"")
    )
    .into_bytes();
    let chunk = vec![b'{'; 64 * 1024];
    for _ in 0..(MIB / chunk.len() + 2) {
        req.extend_from_slice(format!("{:x}\r\n", chunk.len()).as_bytes());
        req.extend_from_slice(&chunk);
        req.extend_from_slice(b"\r\n");
    }
    req.extend_from_slice(b"0\r\n\r\n");
    // The server may close while we are still writing.
    let _ = s.write_all(&req).await;
    let resp = read_until_closed(&mut s, Duration::from_secs(2)).await;
    // The 413 can be lost to the reset that closing with unread bytes
    // causes; the counters below are the proof either way.
    assert!(
        resp.is_empty() || resp.starts_with("HTTP/1.1 413"),
        "got {resp:?}"
    );

    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            too_large: 2,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_headers_are_cut_off() {
    let h = start_with(8, |c| c.header_timeout = Duration::from_millis(200)).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(b"POST /webh").await.unwrap();
    let t = Instant::now();
    read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_body_is_cut_off() {
    let mut h = start_with(8, |c| c.body_timeout = Duration::from_millis(200)).await;
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(
        format!(
            "POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\nX-Hub-Signature-256: {}\r\n\
             Content-Length: 100\r\n\r\n{{\"object\"",
            sign(SECRET, b"")
        )
        .as_bytes(),
    )
    .await
    .unwrap();
    let resp = read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(
        resp.is_empty() || resp.starts_with("HTTP/1.1 408"),
        "got {resp:?}"
    );
    assert!(h.rx.try_recv().is_err());
    let snap = h.snap();
    assert!(snap.timed_out >= 1, "{snap:?}");
    assert_eq!(snap.malformed + snap.unsigned + snap.bad_signature, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_limit_holds() {
    let h = start_with(8, |c| {
        c.max_connections = 2;
        c.header_timeout = Duration::from_millis(800);
        c.body_timeout = Duration::from_millis(200);
    })
    .await;
    let opened = Instant::now();
    let mut idle1 = TcpStream::connect(h.addr).await.unwrap();
    let mut idle2 = TcpStream::connect(h.addr).await.unwrap();
    // Let the listener accept both before the third arrives.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut third = TcpStream::connect(h.addr).await.unwrap();
    let resp = read_until_closed(&mut third, Duration::from_millis(400)).await;
    assert!(resp.is_empty(), "got {resp:?}");
    assert!(h.snap().busy >= 1);

    // The header timeout (0.8 s), not the overall cap (about 6 s), frees
    // the slots.
    read_until_closed(&mut idle1, Duration::from_secs(2)).await;
    read_until_closed(&mut idle2, Duration::from_secs(2)).await;
    assert!(
        opened.elapsed() < Duration::from_secs(2),
        "{:?}",
        opened.elapsed()
    );
    // The permits are released when the connection tasks end.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let (status, _) = h.signed_post(envelope()).await;
    assert_eq!(status, 200);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_queue_is_503() {
    let h = start_with(1, |_| {}).await;
    let (status, _) = h.signed_post(envelope()).await;
    assert_eq!(status, 200);
    let (status, _) = h.signed_post(envelope()).await;
    assert_eq!(status, 503);
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            queue_full: 1,
            ..StatsSnapshot::default()
        }
    );
}

/// Send `req` on a fresh raw connection and read until it closes.
async fn raw_request(h: &Harness, req: &[u8]) -> String {
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(req).await.unwrap();
    read_until_closed(&mut s, Duration::from_secs(2)).await
}

fn raw_post(sig_lines: &[String], body: &[u8]) -> Vec<u8> {
    let mut req = format!("POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\n").into_bytes();
    for line in sig_lines {
        req.extend_from_slice(format!("X-Hub-Signature-256: {line}\r\n").as_bytes());
    }
    req.extend_from_slice(format!("Content-Length: {}\r\n\r\n", body.len()).as_bytes());
    req.extend_from_slice(body);
    req
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn duplicate_signature_headers_are_refused() {
    let mut h = start().await;
    let body = envelope();
    let good = sign(SECRET, &body);
    let cases = [
        vec![good.clone(), good.clone()],
        vec![good.clone(), "sha256=junk".to_string()],
        vec!["sha256=junk".to_string(), good.clone()],
        vec![format!("{good}, {good}")],
        vec![format!("{good},{good}")],
    ];
    for lines in &cases {
        let resp = raw_request(&h, &raw_post(lines, &body)).await;
        assert!(resp.starts_with("HTTP/1.1 401"), "{lines:?}: got {resp:?}");
    }
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            bad_signature: cases.len() as u64,
            ..StatsSnapshot::default()
        }
    );
    // The same body with one valid header still goes through.
    let resp = raw_request(&h, &raw_post(&[good], &body)).await;
    assert!(resp.starts_with("HTTP/1.1 200"), "got {resp:?}");
    assert!(h.rx.try_recv().is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn missing_signature_is_refused_without_reading_the_body() {
    let mut h = start().await;
    // A full 1 MiB is declared and none of it is sent: only a refusal
    // that does not wait for the body answers before the 10 s body timeout.
    let mut s = TcpStream::connect(h.addr).await.unwrap();
    s.write_all(
        format!("POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\nContent-Length: {MIB}\r\n\r\n")
            .as_bytes(),
    )
    .await
    .unwrap();
    let t = Instant::now();
    let resp = read_until_closed(&mut s, Duration::from_secs(2)).await;
    assert!(resp.starts_with("HTTP/1.1 401"), "got {resp:?}");
    assert!(t.elapsed() < Duration::from_secs(1), "{:?}", t.elapsed());
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            unsigned: 1,
            ..StatsSnapshot::default()
        }
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broken_body_framing_is_400_bad_request_not_malformed() {
    let mut h = start().await;
    let mut req = format!(
        "POST {WEBHOOK_PATH} HTTP/1.1\r\nHost: x\r\nX-Hub-Signature-256: {}\r\n\
         Transfer-Encoding: chunked\r\n\r\n",
        sign(SECRET, b"")
    )
    .into_bytes();
    req.extend_from_slice(b"zz\r\nnot a chunk\r\n0\r\n\r\n");
    let resp = raw_request(&h, &req).await;
    assert!(
        resp.is_empty() || resp.starts_with("HTTP/1.1 400"),
        "got {resp:?}"
    );
    assert!(h.rx.try_recv().is_err());
    assert_eq!(
        h.snap(),
        StatsSnapshot {
            bad_request: 1,
            ..StatsSnapshot::default()
        }
    );
}

// ---------- routing and lifecycle ----------

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn other_paths_404_and_methods_405() {
    let mut h = start().await;
    for path in ["/", "/webhook/", "/webhook/x", "/other", "/Webhook"] {
        let resp = h.client.get(h.url(path)).send().await.unwrap();
        assert_eq!(resp.status().as_u16(), 404, "GET {path}");
        let body = envelope();
        let sig = sign(SECRET, &body);
        let resp = h
            .client
            .post(h.url(path))
            .header("x-hub-signature-256", sig)
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 404, "POST {path}");
    }
    for method in ["PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"] {
        let m = reqwest::Method::from_bytes(method.as_bytes()).unwrap();
        let resp = h
            .client
            .request(m, h.url(WEBHOOK_PATH))
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 405, "{method}");
    }
    assert!(h.rx.try_recv().is_err());
    assert!(h.snap().is_zero());
}

#[tokio::test]
async fn bind_refuses_non_loopback() {
    for addr in ["0.0.0.0:0", "[::]:0", "192.168.1.10:0", "10.0.0.1:8097"] {
        let err = WebhookListener::bind(addr.parse().unwrap())
            .await
            .err()
            .unwrap_or_else(|| panic!("{addr} accepted"));
        assert_eq!(err.kind(), ErrorKind::InvalidInput, "{addr}");
    }
    assert!(
        WebhookListener::bind("[::1]:0".parse().unwrap())
            .await
            .is_ok()
            || std::net::TcpListener::bind("[::1]:0").is_err()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_stops_accepting() {
    let h = start().await;
    let (status, _) = h.signed_post(envelope()).await;
    assert_eq!(status, 200);
    h.shutdown.send(true).unwrap();
    timeout(Duration::from_secs(3), h.task)
        .await
        .expect("serve returns after shutdown")
        .unwrap();
    assert!(TcpStream::connect(h.addr).await.is_err());
}

#[test]
fn listener_config_new_sets_defaults() {
    let c = config();
    assert_eq!(c.max_body_bytes, MIB);
    assert_eq!(c.header_timeout, Duration::from_secs(10));
    assert_eq!(c.body_timeout, Duration::from_secs(10));
    assert_eq!(c.max_connections, 16);
    assert_eq!(c.phone_number_id, PNID);
    assert!(StatsSnapshot::default().is_zero());
}
