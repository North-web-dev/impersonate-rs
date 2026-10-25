//! A small async HTTP client that drives the impersonated TLS stack.

use std::io::Read as _;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::{Method, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;

use crate::profile::Profile;
use crate::tls;

/// Boxed error type for the client surface.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

/// A fetched HTTP response with its body already decompressed.
#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
    /// The ALPN protocol the TLS layer negotiated (`h2` or `http/1.1`).
    pub alpn: String,
}

impl Response {
    /// The response body as a UTF-8 string (lossy).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// An HTTP client that presents a browser's TLS fingerprint.
///
/// Cheap to clone; one connector is shared across requests. Each request opens
/// a fresh connection (full handshake) — matching the Go counterpart's default.
#[derive(Clone)]
pub struct Client {
    profile: Profile,
    connector: boring::ssl::SslConnector,
}

impl Client {
    /// Build a client for a browser profile.
    pub fn new(profile: Profile) -> Result<Self, Error> {
        let connector = tls::connector(profile)?;
        Ok(Client { profile, connector })
    }

    /// The profile this client impersonates.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// Issue a `GET` request.
    pub async fn get(&self, url: &str) -> Result<Response, Error> {
        self.request(Method::GET, url, &[], Bytes::new()).await
    }

    /// Issue an arbitrary request. Caller headers win over profile defaults.
    pub async fn request(
        &self,
        method: Method,
        url: &str,
        headers: &[(&str, &str)],
        body: Bytes,
    ) -> Result<Response, Error> {
        let parsed = url::Url::parse(url)?;
        if parsed.scheme() != "https" {
            return Err("only https is supported".into());
        }
        let host = parsed.host_str().ok_or("url has no host")?.to_string();
        let port = parsed.port().unwrap_or(443);
        let authority = if port == 443 {
            host.clone()
        } else {
            format!("{host}:{port}")
        };
        let mut path = parsed.path().to_string();
        if let Some(q) = parsed.query() {
            path.push('?');
            path.push_str(q);
        }

        // --- TLS ---
        let tcp = TcpStream::connect((host.as_str(), port)).await?;
        tcp.set_nodelay(true)?;
        let mut cfg = self.connector.configure()?;
        tls::configure_connection(self.profile, &mut cfg);
        let tls_stream = tokio_boring::connect(cfg, &host, tcp)
            .await
            .map_err(|e| format!("tls handshake failed: {e}"))?;
        let alpn = tls_stream
            .ssl()
            .selected_alpn_protocol()
            .map(|p| String::from_utf8_lossy(p).into_owned())
            .unwrap_or_else(|| "http/1.1".to_string());

        // --- build request ---
        let uri: hyper::Uri = format!("https://{authority}{path}").parse()?;
        let mut builder = Request::builder().method(method).uri(uri);

        // Caller headers first, so we know which to skip from defaults.
        let mut set: std::collections::HashSet<String> = std::collections::HashSet::new();
        for (k, v) in headers {
            set.insert(k.to_ascii_lowercase());
            builder = builder.header(*k, *v);
        }
        for (k, v) in self.profile.default_headers() {
            if !set.contains(&k.to_ascii_lowercase()) {
                builder = builder.header(*k, *v);
            }
        }
        // Host header for HTTP/1.1 (harmless for h2).
        if !set.contains("host") {
            builder = builder.header("host", &authority);
        }

        let req = builder.body(Full::new(body))?;
        let io = TokioIo::new(tls_stream);

        let resp = if alpn == "h2" {
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        } else {
            let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
            tokio::spawn(async move {
                let _ = conn.await;
            });
            sender.send_request(req).await?
        };

        self.collect(resp, alpn).await
    }

    async fn collect(
        &self,
        resp: hyper::Response<Incoming>,
        alpn: String,
    ) -> Result<Response, Error> {
        let status = resp.status().as_u16();
        let mut encoding = String::new();
        let mut out_headers = Vec::new();
        for (k, v) in resp.headers() {
            let name = k.as_str().to_string();
            let val = String::from_utf8_lossy(v.as_bytes()).into_owned();
            if name.eq_ignore_ascii_case("content-encoding") {
                encoding = val.to_ascii_lowercase();
            }
            out_headers.push((name, val));
        }
        let raw = resp.into_body().collect().await?.to_bytes();
        let body = decode_body(&encoding, &raw)?;
        Ok(Response {
            status,
            headers: out_headers,
            body,
            alpn,
        })
    }
}

fn decode_body(encoding: &str, raw: &[u8]) -> Result<Bytes, Error> {
    let mut out = Vec::new();
    match encoding.trim() {
        "" | "identity" => return Ok(Bytes::copy_from_slice(raw)),
        "gzip" | "x-gzip" => {
            flate2::read::GzDecoder::new(raw).read_to_end(&mut out)?;
        }
        "deflate" => {
            flate2::read::ZlibDecoder::new(raw).read_to_end(&mut out)?;
        }
        "br" => {
            brotli::Decompressor::new(raw, 4096).read_to_end(&mut out)?;
        }
        "zstd" => {
            zstd::stream::read::Decoder::new(raw)?.read_to_end(&mut out)?;
        }
        _ => return Ok(Bytes::copy_from_slice(raw)),
    }
    Ok(Bytes::from(out))
}
