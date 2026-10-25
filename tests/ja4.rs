//! Verification tests for the Chrome TLS fingerprint.
//!
//! The offline tests are deterministic and need no network: they fingerprint a
//! committed ClientHello fixture and a freshly captured one (over loopback).
//! The online test (`#[ignore]`) cross-checks against the independent
//! tls.peet.ws reflector; run it with `cargo test -- --ignored`.

use impersonate_rs::{capture, ja4, Profile};

/// The JA4 of desktop Chrome (measured against a real Chrome 149 and the
/// tls.peet.ws reflector on 2026-10-25). Cipher core `8daaf6152771` is the
/// published Chrome/Edge desktop value.
const CHROME_JA4: &str = "t13d1516h2_8daaf6152771_d8a2da3f94cd";

const FIXTURE: &[u8] = include_bytes!("fixtures/chrome_clienthello.bin");

#[test]
fn fixture_fingerprints_to_chrome_ja4() {
    let got = ja4::ja4_from_bytes(FIXTURE).expect("fixture must parse");
    assert_eq!(got, CHROME_JA4, "committed fixture JA4 drifted");
}

#[test]
fn fixture_has_chrome_shape() {
    let ch = ja4::parse_client_hello(FIXTURE).expect("parse");
    let ciphers = ch.ciphers.iter().filter(|c| !ja4::is_grease(**c)).count();
    let exts = ch
        .extensions
        .iter()
        .filter(|e| !ja4::is_grease(**e))
        .count();
    assert_eq!(ciphers, 15, "Chrome offers 15 cipher suites (excl. GREASE)");
    assert_eq!(exts, 16, "Chrome offers 16 extensions (excl. GREASE)");
    assert!(ch.sni_present, "SNI must be present");
    assert_eq!(ch.alpn, vec!["h2".to_string(), "http/1.1".to_string()]);
    // The two extensions that pin *current* Chrome: ECH GREASE and ALPS (new
    // codepoint).
    assert!(
        ch.extensions.contains(&0xfe0d),
        "ECH GREASE (0xfe0d) present"
    );
    assert!(
        ch.extensions.contains(&0x44cd),
        "ALPS new codepoint (0x44cd) present"
    );
    assert!(
        !ch.extensions.contains(&0x4469),
        "legacy ALPS codepoint (0x4469) must NOT be present"
    );
}

#[tokio::test]
async fn live_clienthello_matches_chrome_ja4() {
    // Capture a freshly built ClientHello over loopback (no external network).
    // Because extension order is permuted per connection, this exercises JA4's
    // shuffle-invariance: the raw bytes differ run-to-run, the JA4 does not.
    let hello = capture::capture_client_hello(Profile::Chrome)
        .await
        .expect("capture ClientHello");
    let got = ja4::ja4_from_bytes(&hello).expect("parse captured ClientHello");
    assert_eq!(got, CHROME_JA4, "live Chrome ClientHello JA4 drifted");
}

#[tokio::test]
async fn permutation_shuffles_bytes_but_not_ja4() {
    let a = capture::capture_client_hello(Profile::Chrome)
        .await
        .unwrap();
    let b = capture::capture_client_hello(Profile::Chrome)
        .await
        .unwrap();
    // Same fingerprint...
    assert_eq!(ja4::ja4_from_bytes(&a), ja4::ja4_from_bytes(&b));
    // ...almost certainly different raw bytes (GREASE + permutation + random).
    assert_ne!(a, b, "two ClientHellos should differ byte-for-byte");
}

/// Online cross-check against the independent reflector. Ignored by default
/// (needs network). Run: `cargo test -- --ignored`.
#[tokio::test]
#[ignore]
async fn reflector_reports_chrome_ja4() {
    let client = impersonate_rs::Client::new(Profile::Chrome).unwrap();
    let resp = client.get("https://tls.peet.ws/api/all").await.unwrap();
    assert_eq!(resp.status, 200);
    let text = resp.text();
    let marker = "\"ja4\"";
    let after = &text[text.find(marker).unwrap() + marker.len()..];
    let open = after.find('"').unwrap();
    let rest = &after[open + 1..];
    let ja4 = &rest[..rest.find('"').unwrap()];
    assert_eq!(ja4, CHROME_JA4, "reflector-reported JA4 mismatch");
}
