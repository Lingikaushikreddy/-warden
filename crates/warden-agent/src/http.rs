//! The HTTP client settings and base-URL rules shared by every network
//! client in this crate (the Anthropic planner and the Telegram channel).
//!
//! Errors carry no detail from reqwest: callers reduce them to their own
//! fixed messages, so a URL (which may hold a token in its path) never
//! reaches an error string.

use reqwest::redirect::Policy;
use reqwest::Url;
use std::time::Duration;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const USER_AGENT_VALUE: &str = concat!("warden-agent/", env!("CARGO_PKG_VERSION"));

/// A client with rustls, no redirects, a 10 s connect timeout and the
/// `warden-agent/<version>` user agent.
///
/// Proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`)
/// are ignored: the client always connects directly.
pub(crate) fn client() -> Result<reqwest::Client, ()> {
    reqwest::Client::builder()
        .redirect(Policy::none())
        .no_proxy()
        .use_rustls_tls()
        .connect_timeout(CONNECT_TIMEOUT)
        .user_agent(USER_AGENT_VALUE)
        .build()
        .map_err(|_| ())
}

/// Parse and check a base URL: `https://`, or `http://` only to
/// `127.0.0.1`, `localhost` or `[::1]`; a host; no credentials, query or
/// fragment. The error is a fixed message with no part of the URL.
pub(crate) fn check_base_url(base: &str) -> Result<Url, &'static str> {
    let url = Url::parse(base).map_err(|_| "invalid base url")?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    match url.scheme() {
        "https" => {}
        "http" if loopback => {}
        _ => return Err("base url must be https (http only for loopback)"),
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err("base url has no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("base url must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err("base url must not have a query or fragment");
    }
    Ok(url)
}
