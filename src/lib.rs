//! `impersonate-rs` — a Rust HTTP client that presents a byte-exact browser TLS
//! fingerprint (matched on **JA4**), the Rust counterpart to the Go
//! [`impersonate-http`](https://github.com/North-web-dev/impersonate-http).
//!
//! The TLS layer is BoringSSL (via the `boring` crate — the stack Chrome itself
//! ships), configured to reproduce a browser's ClientHello: exact cipher list,
//! curves (incl. a post-quantum key share), signature algorithms, ALPN, GREASE,
//! per-connection extension permutation, certificate-compression advertisement
//! and the ALPS extension. See [`tls`] for why BoringSSL and not rustls.
//!
//! ```no_run
//! # async fn run() -> Result<(), impersonate_rs::Error> {
//! use impersonate_rs::{Client, Profile};
//!
//! let client = Client::new(Profile::Chrome)?;
//! let resp = client.get("https://tls.peet.ws/api/all").await?;
//! println!("{} {} bytes", resp.status, resp.body.len());
//! # Ok(()) }
//! ```

pub mod capture;
pub mod client;
pub mod ja4;
pub mod profile;
pub mod tls;

pub use client::{Client, Error, Response};
pub use profile::Profile;

/// Compute the JA4 fingerprint of a profile's ClientHello, offline.
///
/// Captures the real ClientHello the profile emits (via a loopback handshake)
/// and fingerprints it with the bundled [`ja4`] calculator.
pub async fn measured_ja4(profile: Profile) -> std::io::Result<String> {
    let hello = capture::capture_client_hello(profile).await?;
    ja4::ja4_from_bytes(&hello)
        .ok_or_else(|| std::io::Error::other("failed to parse captured ClientHello"))
}
