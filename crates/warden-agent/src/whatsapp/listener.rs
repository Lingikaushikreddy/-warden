//! The loopback webhook listener.
//!
//! The owner exposes it to Meta with their own tunnel, so anyone on the
//! internet can reach it. It therefore binds loopback only, speaks HTTP/1.1
//! only, serves one path, and fails closed:
//! - at most `max_connections` connections at once; a socket accepted
//!   beyond that is closed at once (`busy`);
//! - headers must arrive within `header_timeout` (at most 16 KiB of
//!   buffer), the body within `body_timeout`, and every connection ends
//!   after `header_timeout + body_timeout + 5 s` whatever it is doing;
//! - a body over `max_body_bytes` is refused (413) before or while it is
//!   read, and is never parsed;
//! - `X-Hub-Signature-256` is checked over the raw bytes before anything
//!   is parsed; a POST without one is refused before its body is read,
//!   and a badly signed body (or two signature headers) is never parsed
//!   (401);
//! - a signed batch goes on the channel queue without waiting for the
//!   engine (200), or gets 503 when the queue is full so Meta retries.
//!
//! Every response is `text/plain` with `connection: close` and a fixed
//! short ASCII body, or the digit challenge of a valid handshake. Nothing
//! is printed: refused requests are only counted in [`WebhookStats`].

use super::webhook::{
    check_signature, handshake, parse_notification, AppSecret, SignatureCheck, VerifyToken,
    WebhookBatch,
};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::{Body as _, Bytes, Incoming};
use hyper::header::{HeaderValue, CONNECTION, CONTENT_TYPE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioIo, TokioTimer};
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// The only path served.
pub const WEBHOOK_PATH: &str = "/webhook";

const SIGNATURE_HEADER: &str = "x-hub-signature-256";
/// hyper's read buffer cap, which bounds the request line plus headers.
const MAX_BUF: usize = 16 * 1024;
/// Added to the header and body timeouts for a connection's overall cap.
const CONN_GRACE: Duration = Duration::from_secs(5);
/// How long connections in progress may run on after shutdown.
const DRAIN: Duration = Duration::from_secs(2);
/// The pause after a failed `accept` (for example, out of descriptors).
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// What the listener needs to answer requests.
#[derive(Debug)]
pub struct ListenerConfig {
    pub app_secret: AppSecret,
    pub verify_token: VerifyToken,
    /// Changes for any other `metadata.phone_number_id` are dropped.
    pub phone_number_id: String,
    pub max_body_bytes: usize,
    pub header_timeout: Duration,
    pub body_timeout: Duration,
    pub max_connections: usize,
}

impl ListenerConfig {
    /// The defaults: a 1 MiB body, 10 s for headers, 10 s for the body,
    /// and 16 connections at once.
    pub fn new(
        app_secret: AppSecret,
        verify_token: VerifyToken,
        phone_number_id: String,
    ) -> ListenerConfig {
        ListenerConfig {
            app_secret,
            verify_token,
            phone_number_id,
            max_body_bytes: 1024 * 1024,
            header_timeout: Duration::from_secs(10),
            body_timeout: Duration::from_secs(10),
            max_connections: 16,
        }
    }
}

macro_rules! stats {
    ($($(#[$doc:meta])* $field:ident,)*) => {
        /// Counts of refused or dropped requests, shared with whoever
        /// reports them. Never reset.
        #[derive(Debug, Default)]
        pub struct WebhookStats {
            $($(#[$doc])* pub $field: AtomicU64,)*
        }

        /// A copy of [`WebhookStats`] at one moment.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
        pub struct StatsSnapshot {
            $($(#[$doc])* pub $field: u64,)*
        }

        impl WebhookStats {
            pub fn snapshot(&self) -> StatsSnapshot {
                StatsSnapshot {
                    $($field: self.$field.load(Ordering::Relaxed),)*
                }
            }
        }

        impl StatsSnapshot {
            /// True when nothing was counted.
            pub fn is_zero(&self) -> bool {
                true $(&& self.$field == 0)*
            }
        }
    };
}

stats! {
    /// POSTs with no `X-Hub-Signature-256` (401, before the body is read).
    unsigned,
    /// POSTs whose signature is malformed or does not match (401).
    bad_signature,
    /// Bodies over the cap, declared or streamed (413).
    too_large,
    /// Bodies not complete within the body timeout (408), and connections
    /// cut off by the header timeout or the overall cap.
    timed_out,
    /// Signed bodies that are not a WhatsApp notification (200, dropped).
    malformed,
    /// Bodies the client broke off or framed wrongly, neither over the cap
    /// nor timed out (400).
    bad_request,
    /// Changes for another `phone_number_id` (dropped).
    foreign,
    /// Events past the per-notification cap (dropped; the rest is
    /// forwarded and answered 200).
    truncated,
    /// Signed batches refused because the queue was full or closed (503).
    queue_full,
    /// Sockets closed at once because every connection slot was taken.
    busy,
    /// GET handshakes refused (403).
    handshake_refused,
}

fn bump(c: &AtomicU64) {
    c.fetch_add(1, Ordering::Relaxed);
}

/// A bound, not yet serving, loopback listener.
#[derive(Debug)]
pub struct WebhookListener {
    inner: TcpListener,
}

impl WebhookListener {
    /// Bind `addr`. Anything whose IP is not loopback is refused with
    /// `InvalidInput` before a socket is opened.
    pub async fn bind(addr: SocketAddr) -> io::Result<WebhookListener> {
        if !addr.ip().is_loopback() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "the webhook listener binds a loopback address only",
            ));
        }
        Ok(WebhookListener {
            inner: TcpListener::bind(addr).await?,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    /// Serve until `shutdown` holds `true`. Then the listening socket is
    /// closed at once and connections in progress get at most 2 s more.
    /// If every shutdown sender is dropped without sending `true`, this
    /// serves on.
    pub async fn serve(
        self,
        cfg: ListenerConfig,
        tx: mpsc::Sender<WebhookBatch>,
        stats: Arc<WebhookStats>,
        shutdown: watch::Receiver<bool>,
    ) {
        let slots = Arc::new(Semaphore::new(cfg.max_connections));
        let shared = Arc::new(Shared { cfg, tx, stats });
        let mut conns = JoinSet::new();
        let stop = shutdown_requested(shutdown);
        tokio::pin!(stop);
        loop {
            tokio::select! {
                biased;
                () = &mut stop => break,
                Some(_) = conns.join_next(), if !conns.is_empty() => {}
                accepted = self.inner.accept() => match accepted {
                    Ok((sock, _)) => match slots.clone().try_acquire_owned() {
                        Ok(permit) => {
                            conns.spawn(serve_conn(sock, shared.clone(), permit));
                        }
                        Err(_) => {
                            bump(&shared.stats.busy);
                            drop(sock);
                        }
                    },
                    Err(_) => tokio::time::sleep(ACCEPT_BACKOFF).await,
                },
            }
        }
        drop(self.inner);
        let _ =
            tokio::time::timeout(DRAIN, async { while conns.join_next().await.is_some() {} }).await;
        conns.shutdown().await;
    }
}

/// Resolves once `rx` holds `true`; never once every sender is gone
/// without having asked for shutdown.
async fn shutdown_requested(mut rx: watch::Receiver<bool>) {
    if rx.wait_for(|&v| v).await.is_ok() {
        return;
    }
    std::future::pending::<()>().await;
}

struct Shared {
    cfg: ListenerConfig,
    tx: mpsc::Sender<WebhookBatch>,
    stats: Arc<WebhookStats>,
}

/// One connection: one request at most (no keep-alive), under the
/// header timeout and an overall cap. The permit is held until it ends.
async fn serve_conn(sock: TcpStream, shared: Arc<Shared>, _permit: OwnedSemaphorePermit) {
    let cfg = &shared.cfg;
    let cap = cfg.header_timeout + cfg.body_timeout + CONN_GRACE;
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(cfg.header_timeout)
        .keep_alive(false)
        .max_buf_size(MAX_BUF);
    let svc_shared = shared.clone();
    let svc = service_fn(move |req| {
        let shared = svc_shared.clone();
        async move { Ok::<_, Infallible>(handle(req, &shared).await) }
    });
    let conn = builder.serve_connection(TokioIo::new(sock), svc);
    match tokio::time::timeout(cap, conn).await {
        Err(_) => bump(&shared.stats.timed_out),
        Ok(Err(e)) if e.is_timeout() => bump(&shared.stats.timed_out),
        Ok(_) => {}
    }
}

fn reply(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(body.into()));
    *resp.status_mut() = status;
    let h = resp.headers_mut();
    h.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
    h.insert(CONNECTION, HeaderValue::from_static("close"));
    resp
}

async fn handle(req: Request<Incoming>, s: &Shared) -> Response<Full<Bytes>> {
    if req.uri().path() != WEBHOOK_PATH {
        return reply(StatusCode::NOT_FOUND, "not found");
    }
    match *req.method() {
        Method::GET => match handshake(req.uri().query(), &s.cfg.verify_token) {
            Some(challenge) => reply(StatusCode::OK, challenge),
            None => {
                bump(&s.stats.handshake_refused);
                reply(StatusCode::FORBIDDEN, "forbidden")
            }
        },
        Method::POST => notification(req, s).await,
        _ => reply(StatusCode::METHOD_NOT_ALLOWED, "method not allowed"),
    }
}

async fn notification(req: Request<Incoming>, s: &Shared) -> Response<Full<Bytes>> {
    let cap = s.cfg.max_body_bytes;
    // A declared Content-Length is the body's exact size hint.
    if req.body().size_hint().lower() > cap as u64 {
        bump(&s.stats.too_large);
        return reply(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
    }
    // More than one signature header is refused, not resolved. With none
    // at all the body is not even read.
    let mut sigs = req.headers().get_all(SIGNATURE_HEADER).iter();
    let sig = match (sigs.next(), sigs.next()) {
        (None, _) => {
            bump(&s.stats.unsigned);
            return reply(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        (Some(v), None) => Some(v.as_bytes().to_vec()),
        (Some(_), Some(_)) => None,
    };
    let read = tokio::time::timeout(
        s.cfg.body_timeout,
        Limited::new(req.into_body(), cap).collect(),
    )
    .await;
    let raw = match read {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) if e.downcast_ref::<LengthLimitError>().is_some() => {
            bump(&s.stats.too_large);
            return reply(StatusCode::PAYLOAD_TOO_LARGE, "payload too large");
        }
        Ok(Err(_)) => {
            bump(&s.stats.bad_request);
            return reply(StatusCode::BAD_REQUEST, "bad request");
        }
        Err(_) => {
            bump(&s.stats.timed_out);
            return reply(StatusCode::REQUEST_TIMEOUT, "request timeout");
        }
    };

    let check = match &sig {
        Some(sig) => check_signature(&s.cfg.app_secret, Some(sig), &raw),
        None => SignatureCheck::Invalid,
    };
    match check {
        SignatureCheck::Valid => {}
        SignatureCheck::Missing => {
            bump(&s.stats.unsigned);
            return reply(StatusCode::UNAUTHORIZED, "unauthorized");
        }
        SignatureCheck::Invalid => {
            bump(&s.stats.bad_signature);
            return reply(StatusCode::UNAUTHORIZED, "unauthorized");
        }
    }

    let n = match parse_notification(&raw, &s.cfg.phone_number_id) {
        Ok(n) => n,
        Err(_) => {
            bump(&s.stats.malformed);
            return reply(StatusCode::OK, "ok");
        }
    };
    s.stats
        .foreign
        .fetch_add(n.foreign as u64, Ordering::Relaxed);
    s.stats
        .truncated
        .fetch_add(n.truncated as u64, Ordering::Relaxed);
    if n.events.is_empty() {
        return reply(StatusCode::OK, "ok");
    }
    match s.tx.try_send(WebhookBatch { events: n.events }) {
        Ok(()) => reply(StatusCode::OK, "ok"),
        Err(_) => {
            bump(&s.stats.queue_full);
            reply(StatusCode::SERVICE_UNAVAILABLE, "unavailable")
        }
    }
}
