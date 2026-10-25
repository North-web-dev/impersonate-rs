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
    max_response_bytes: Option<usize>,
}

/// Default cap on a decoded response body: 64 MiB.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

impl Client {
    /// Build a client for a browser profile, with the default 64 MiB response
    /// body cap. Use [`Client::with_max_response_bytes`] to change it.
    pub fn new(profile: Profile) -> Result<Self, Error> {
        let connector = tls::connector(profile)?;
        Ok(Client {
            profile,
            connector,
            max_response_bytes: Some(DEFAULT_MAX_RESPONSE_BYTES),
        })
    }

    /// Set the maximum decoded (and raw) response body size, in bytes.
    ///
    /// This guards against decompression bombs: a tiny compressed body that
    /// expands to gigabytes. `Some(n)` caps both the compressed bytes read off
    /// the wire and the decompressed output at `n`; a response that exceeds
    /// either is rejected with an error rather than buffered. `None` removes
    /// the cap entirely — only opt out if you fully trust the server.
    pub fn with_max_response_bytes(mut self, max: Option<usize>) -> Self {
        self.max_response_bytes = max;
        self
    }

    /// The profile this client impersonates.
    pub fn profile(&self) -> Profile {
        self.profile
    }

    /// The configured response body cap, if any.
    pub fn max_response_bytes(&self) -> Option<usize> {
        self.max_response_bytes
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
        // Bound the raw (compressed) body before buffering it, so a huge
        // payload cannot blow memory even before we decode.
        let raw = match self.max_response_bytes {
            Some(max) => http_body_util::Limited::new(resp.into_body(), max)
                .collect()
                .await
                .map_err(|_| {
                    Box::<dyn std::error::Error + Send + Sync>::from(
                        "response body exceeds max decoded size",
                    )
                })?
                .to_bytes(),
            None => resp.into_body().collect().await?.to_bytes(),
        };
        let body = decode_body(&encoding, &raw, self.max_response_bytes)?;
        Ok(Response {
            status,
            headers: out_headers,
            body,
            alpn,
        })
    }
}

/// Error returned when a response body exceeds the configured cap.
const OVERSIZE_MSG: &str = "response body exceeds max decoded size";

fn decode_body(encoding: &str, raw: &[u8], max: Option<usize>) -> Result<Bytes, Error> {
    // Build a reader bounded to `max + 1` so we can detect overflow after the
    // read: if we ever produce more than `max` bytes, it's oversized.
    fn read_capped<R: std::io::Read>(reader: R, max: Option<usize>) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match max {
            Some(m) => {
                reader.take(m as u64 + 1).read_to_end(&mut out)?;
                if out.len() > m {
                    return Err(OVERSIZE_MSG.into());
                }
            }
            None => {
                let mut reader = reader;
                reader.read_to_end(&mut out)?;
            }
        }
        Ok(out)
    }

    let out = match encoding.trim() {
        "" | "identity" => {
            if let Some(m) = max {
                if raw.len() > m {
                    return Err(OVERSIZE_MSG.into());
                }
            }
            return Ok(Bytes::copy_from_slice(raw));
        }
        "gzip" | "x-gzip" => read_capped(flate2::read::GzDecoder::new(raw), max)?,
        "deflate" => read_capped(flate2::read::ZlibDecoder::new(raw), max)?,
        "br" => read_capped(brotli::Decompressor::new(raw, 4096), max)?,
        "zstd" => read_capped(zstd::stream::read::Decoder::new(raw)?, max)?,
        _ => return Ok(Bytes::copy_from_slice(raw)),
    };
    Ok(Bytes::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn gzip_bomb_rejected_over_cap() {
        // 1 MiB of zeros compresses tiny but decompresses past a 1 KiB cap.
        let compressed = gzip(&vec![0u8; 1024 * 1024]);
        let err = decode_body("gzip", &compressed, Some(1024)).unwrap_err();
        assert!(
            err.to_string().contains("exceeds max decoded size"),
            "expected oversize error, got: {err}"
        );
    }

    #[test]
    fn zstd_bomb_rejected_over_cap() {
        let compressed = zstd::stream::encode_all(&vec![0u8; 1024 * 1024][..], 3).unwrap();
        let err = decode_body("zstd", &compressed, Some(1024)).unwrap_err();
        assert!(err.to_string().contains("exceeds max decoded size"));
    }

    #[test]
    fn normal_body_under_cap_decodes() {
        let payload = b"hello, world".repeat(4);
        let compressed = gzip(&payload);
        let out = decode_body("gzip", &compressed, Some(64 * 1024)).unwrap();
        assert_eq!(out.as_ref(), payload.as_slice());
    }

    #[test]
    fn identity_over_cap_rejected() {
        let raw = vec![1u8; 2048];
        assert!(decode_body("identity", &raw, Some(1024)).is_err());
        assert!(decode_body("identity", &raw, Some(4096)).is_ok());
    }

    #[test]
    fn no_cap_decodes_large() {
        let compressed = gzip(&vec![7u8; 256 * 1024]);
        let out = decode_body("gzip", &compressed, None).unwrap();
        assert_eq!(out.len(), 256 * 1024);
    }
}
