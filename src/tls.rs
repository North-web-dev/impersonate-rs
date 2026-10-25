//! BoringSSL-backed TLS configuration that reproduces a browser's ClientHello.
//!
//! Why BoringSSL and not rustls: a byte-exact browser ClientHello needs control
//! over the exact cipher list, the elliptic curves (including a post-quantum key
//! share), the signature-algorithm list, ALPN, GREASE, per-connection extension
//! permutation, certificate-compression advertisement and the ALPS extension.
//! `rustls` deliberately does not expose extension ordering/forgery. BoringSSL
//! is the TLS stack Chrome itself ships, and the `boring` crate (Cloudflare's
//! fork) exposes exactly these knobs — the same foundation `curl-impersonate`
//! and `rquest` build on.

use boring::error::ErrorStack;
use foreign_types_shared::ForeignTypeRef;

use boring::ssl::{
    CertificateCompressionAlgorithm, CertificateCompressor, ConnectConfiguration, SslConnector,
    SslMethod, SslVersion,
};

use crate::profile::Profile;

/// Chrome's TLS 1.2 cipher list (the TLS 1.3 suites are BoringSSL defaults and
/// already emitted in Chrome's order). Together these are the 15 cipher suites
/// behind JA4's `8daaf6152771` core.
const CHROME_CIPHERS: &str = "ECDHE-ECDSA-AES128-GCM-SHA256:\
ECDHE-RSA-AES128-GCM-SHA256:\
ECDHE-ECDSA-AES256-GCM-SHA384:\
ECDHE-RSA-AES256-GCM-SHA384:\
ECDHE-ECDSA-CHACHA20-POLY1305:\
ECDHE-RSA-CHACHA20-POLY1305:\
ECDHE-RSA-AES128-SHA:\
ECDHE-RSA-AES256-SHA:\
AES128-GCM-SHA256:\
AES256-GCM-SHA384:\
AES128-SHA:\
AES256-SHA";

/// Chrome's signature_algorithms extension, in order.
const CHROME_SIGALGS: &str = "ecdsa_secp256r1_sha256:\
rsa_pss_rsae_sha256:\
rsa_pkcs1_sha256:\
ecdsa_secp384r1_sha384:\
rsa_pss_rsae_sha384:\
rsa_pkcs1_sha384:\
rsa_pss_rsae_sha512:\
rsa_pkcs1_sha512";

/// Chrome's ALPN offer.
const CHROME_ALPN: &[u8] = b"\x02h2\x08http/1.1";

/// Brotli certificate decompression, advertised via the `compress_certificate`
/// extension (0x1b) — Chrome advertises brotli. We implement real
/// decompression so a server that responds with a brotli-compressed
/// certificate chain still completes the handshake.
#[derive(Debug, Clone, Copy)]
pub struct BrotliCertDecompressor;

impl CertificateCompressor for BrotliCertDecompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = false;
    const CAN_DECOMPRESS: bool = true;

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: std::io::Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        std::io::copy(&mut reader, output)?;
        Ok(())
    }
}

/// Build the [`SslConnector`] for a profile.
pub fn connector(profile: Profile) -> Result<SslConnector, ErrorStack> {
    match profile {
        Profile::Chrome => chrome_connector(),
    }
}

fn chrome_connector() -> Result<SslConnector, ErrorStack> {
    let mut b = SslConnector::builder(SslMethod::tls())?;

    b.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    b.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // GREASE + per-connection extension permutation: Chrome >= 110 shuffles its
    // TLS extension order on every connection, so its JA3 is non-deterministic.
    // JA4 sorts extensions, so it stays stable — this is the whole point.
    b.set_grease_enabled(true);
    b.set_permute_extensions(true);

    b.set_cipher_list(CHROME_CIPHERS)?;

    // supported_groups / key_share: X25519MLKEM768 (post-quantum, 0x11ec),
    // X25519, secp256r1, secp384r1 — Chrome's current set. (A GREASE group is
    // prepended automatically because GREASE is enabled.)
    b.set_curves_list("X25519MLKEM768:X25519:P-256:P-384")?;

    b.set_sigalgs_list(CHROME_SIGALGS)?;
    b.set_alpn_protos(CHROME_ALPN)?;

    // status_request (OCSP, ext 0x05) and signed_certificate_timestamp (ext 0x12).
    b.enable_ocsp_stapling();
    b.enable_signed_cert_timestamps();

    // compress_certificate (ext 0x1b) advertising brotli.
    b.add_certificate_compression_algorithm(BrotliCertDecompressor)?;

    Ok(b.build())
}

/// Apply per-connection, per-profile tweaks that are not expressible on the
/// shared `SslConnector` — currently the ALPS (`application_settings`, ext
/// 0x4469) extension, which the high-level `boring` API does not wrap but whose
/// FFI entry point BoringSSL exposes.
pub fn configure_connection(profile: Profile, cfg: &mut ConnectConfiguration) {
    match profile {
        Profile::Chrome => {
            // ECH GREASE: emits the encrypted_client_hello (0xfe0d) extension,
            // Chrome's 16th extension.
            cfg.set_enable_ech_grease(true);

            // ALPS (application_settings) for "h2", with Chrome's *new*
            // codepoint (0x44cd rather than the legacy 0x4469).
            let proto = b"h2";
            // SAFETY: `cfg` derefs to a live `SslRef`; `as_ptr()` yields its
            // `*mut SSL`. We pass a valid, non-null proto slice with its length;
            // BoringSSL copies the bytes, retaining nothing past the call.
            unsafe {
                let ssl = (**cfg).as_ptr();
                boring_sys::SSL_set_alps_use_new_codepoint(ssl, 1);
                boring_sys::SSL_add_application_settings(
                    ssl,
                    proto.as_ptr(),
                    proto.len(),
                    std::ptr::null(),
                    0,
                );
            }
        }
    }
}
