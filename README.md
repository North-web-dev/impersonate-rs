# impersonate-rs

[![CI](https://github.com/North-web-dev/impersonate-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/North-web-dev/impersonate-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust async HTTP client whose **TLS ClientHello is byte-exact to a real
browser's**, so requests survive **JA4 / JA3 TLS fingerprinting**
(Cloudflare, Akamai, DataDome, PerimeterX, …).

The Rust counterpart to [`impersonate-http`](https://github.com/North-web-dev/impersonate-http)
(Go/uTLS). Where the Go library uses uTLS, the Rust library uses **BoringSSL** —
the TLS stack Chrome itself ships — via the [`boring`](https://crates.io/crates/boring)
crate, the same foundation `curl-impersonate` and `rquest` are built on.

> **Verified, not claimed.** The Chrome profile's JA4 was measured against a real
> Chrome 149 **and** the independent [tls.peet.ws](https://tls.peet.ws) reflector.
> Both report the same string this client produces. See
> [Measured parity](#measured-parity) and [How it's verified](#how-its-verified).

## Quickstart

```toml
[dependencies]
impersonate-rs = { git = "https://github.com/North-web-dev/impersonate-rs" }
tokio = { version = "1", features = ["full"] }
```

```rust
use impersonate_rs::{Client, Profile};

#[tokio::main]
async fn main() -> Result<(), impersonate_rs::Error> {
    let client = Client::new(Profile::Chrome)?;
    let resp = client.get("https://tls.peet.ws/api/all").await?;
    println!("{} ({}), {} bytes", resp.status, resp.alpn, resp.body.len());
    Ok(())
}
```

The client is async (tokio + hyper). It negotiates ALPN, speaks HTTP/2 or
HTTP/1.1 accordingly, decodes `gzip` / `deflate` / `br` / `zstd` response bodies,
and injects the browser's default headers (only those the caller didn't set).
Response bodies are capped at 64 MiB by default — both the compressed bytes and
the decoded output — to prevent decompression-bomb OOMs; change or disable it
with `Client::with_max_response_bytes`.

## Measured parity

Captured on **2026-10-25** with `boring`/`boring-sys` **5.3.0** (which vendors a
recent BoringSSL). "Real browser" is a locally installed Google Chrome 149;
"reflector" is what tls.peet.ws computes from this client's live handshake.

| Profile | This client's JA4 | Real Chrome 149 JA4 | tls.peet.ws | Match |
| --- | --- | --- | --- | --- |
| `Chrome` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | `t13d1516h2_8daaf6152771_d8a2da3f94cd` | ✅ byte-exact |

Reproduce it yourself:

```
cargo run --bin measure
```

```
profile            : chrome
clienthello bytes  : 1721
ciphers (no GREASE): 15
exts    (no GREASE): 16
ext ids            : 0x002b 0xfe0d 0x0005 0xff01 0x000a 0x000d 0x002d 0x0023 0x001b 0x0017 0x44cd 0x0033 0x0012 0x0000 0x0010 0x000b
alpn offered       : ["h2", "http/1.1"]
JA4 (local calc)   : t13d1516h2_8daaf6152771_d8a2da3f94cd
--- tls.peet.ws ---
http status        : 200
JA4 (peet.ws)      : t13d1516h2_8daaf6152771_d8a2da3f94cd
JA3 (peet.ws)      : 0a9d85ccb6f676d4b09749064da3905a  (varies per connection by design)
JA4 agreement      : MATCH
```

**JA4 is the fingerprint to match on, not JA3.** Chrome permutes its TLS
extension order on every connection (Chromium ≥ 110), so its JA3 hash is
non-deterministic — exactly like a real Chrome. This client enables the same
permutation, so its JA3 also varies per connection. JA4 sorts ciphers and
extensions before hashing, so it is stable; that's what you pin on. The cipher
core `8daaf6152771` is the published Chrome/Edge desktop value.

What makes the Chrome ClientHello byte-exact here:

- 15 cipher suites + 1 GREASE, in Chrome's order (TLS 1.3 suites + 12 TLS 1.2).
- `X25519MLKEM768` post-quantum key share first, then X25519, P-256, P-384.
- Chrome's 8 signature algorithms, in order.
- ALPN `h2, http/1.1`; status_request (OCSP); signed_certificate_timestamp.
- `compress_certificate` advertising **brotli** (with a real decompressor).
- **ALPS** (`application_settings`) with Chrome's **new** codepoint `0x44cd`.
- **ECH GREASE** (`encrypted_client_hello`, `0xfe0d`).
- GREASE cipher/group/extension values + per-connection extension permutation.

## How it's verified

Three independent signals agree, and the tests enforce it on every run:

1. **Our own JA4 calculator** ([`src/ja4.rs`](src/ja4.rs)) parses the exact
   ClientHello bytes this client puts on the wire and derives the JA4.
2. **A committed fixture** (`tests/fixtures/chrome_clienthello.bin`) — a real
   captured ClientHello — is re-fingerprinted offline in CI.
3. **The independent tls.peet.ws reflector** computes JA4 from the live
   handshake; `cargo test -- --ignored` asserts it equals the expected value.

The offline tests need no network: they capture the ClientHello over loopback
(the handshake never completes, but the first flight is already on the wire).
`permutation_shuffles_bytes_but_not_ja4` proves two handshakes differ
byte-for-byte yet share one JA4 — Chrome's actual behaviour.

## Why BoringSSL, not rustls

A byte-exact browser ClientHello needs control over the exact cipher list, the
curves (including a post-quantum key share), the signature-algorithm list, ALPN,
GREASE, **per-connection extension permutation**, certificate-compression
advertisement, ALPS and ECH GREASE. `rustls` deliberately does **not** expose
extension ordering/forgery, and cannot reproduce Chrome's shuffle. BoringSSL is
the stack Chrome ships, and the `boring` crate exposes exactly these knobs
(`set_grease_enabled`, `set_permute_extensions`, `set_curves_list`,
`set_sigalgs_list`, cert-compression) plus the raw FFI for ALPS
(`SSL_add_application_settings` + `SSL_set_alps_use_new_codepoint`) and ECH
(`set_enable_ech_grease`). This is the same approach `curl-impersonate` and
`rquest` take. A pure-rustls path was evaluated and rejected: it cannot forge
the extension order byte-for-byte.

## Limitations (honest)

- **TLS only, HTTP/2 frames are not browser-exact.** This library reproduces the
  **TLS ClientHello / JA4**. It does **not** yet reproduce Chrome's HTTP/2
  "Akamai" fingerprint (SETTINGS order/values, WINDOW_UPDATE, pseudo-header
  order) — it uses hyper's HTTP/2 defaults. The Go counterpart does reproduce
  the HTTP/2 fingerprint; doing the same in Rust is on the roadmap. If your
  target fingerprints HTTP/2, this is a real gap.
- **One profile.** Only `Chrome` is implemented and verified. Firefox/Safari were
  not shipped: Firefox needs a different cipher/curve/extension template and
  `rustls`-incompatible quirks, and we only claim what we measured. Adding them
  is mechanical (new cipher/curve/sigalg/extension sets) but each must be
  measured before being claimed.
- **HTTP/3 (QUIC)** — out of scope.
- **JA4 tracks a browser version.** The third JA4 segment
  (`d8a2da3f94cd`) is a hash of Chrome's current extension + signature-algorithm
  set; a future Chrome that changes that set will change the segment, and this
  profile would then match an older Chrome until updated. It matched Chrome 149
  on 2026-10-25.
- **JA4 is a fingerprint, not a disguise.** Matching JA4 defeats *passive* TLS
  fingerprinting. It does not run JavaScript, solve challenges, or make you
  indistinguishable from a browser under active/behavioural analysis. JA4 is
  itself spoofable — which is the entire point of this library — so defenders
  increasingly combine it with HTTP/2, header-order and behavioural signals.
- **Each request opens a fresh connection** (full handshake); no connection
  pooling or TLS session resumption yet.

## Build requirements

`boring-sys` compiles a vendored BoringSSL, so a build needs a C/C++ toolchain
plus:

```
sudo apt-get install -y cmake clang libclang-dev perl
```

(`libclang` is needed because `boring-sys` runs `bindgen`.) No system OpenSSL or
`libcurl` is required; the result is self-contained.

## Prior art & credit

This library stands on well-trodden ground and credits it honestly:

- [**curl-impersonate**](https://github.com/lwthiker/curl-impersonate) — the
  original "patch the TLS stack to look like a browser" project (patched
  libcurl + BoringSSL).
- [**utls**](https://github.com/refraction-networking/utls) — the Go library that
  pioneered hand-built browser ClientHellos; powers the Go `impersonate-http`.
- [**rquest**](https://github.com/penumbra-x/rquest) /
  [**boring**](https://github.com/cloudflare/boring) — the Rust BoringSSL
  binding and the high-level client that proved byte-exact Chrome in Rust. This
  project uses the same BoringSSL knobs directly rather than wrapping rquest.
- [**JA4**](https://github.com/FoxIO-LLC/ja4) by FoxIO — the fingerprint standard.

## Support

If this saved you time, a ⭐ on the repo is appreciated — and donations keep the work going.

| Coin | Address |
|---|---|
| **BTC** | `bc1q0sfghv7yfl594gjurhyhlhdgm0dtwh4dkjha36` |
| **ETH / USDT-ERC20 / BNB-BEP20** | `0xB827b5a8B6c5111946c5D872933b2C23484E87dE` |
| **SOL** | `3ch5aHrPp3CierhiNXmqmtFH2dMHh6Gfv7a97KtLMMCh` |
| **USDT-TRC20 / TRX** | `TUAyz7TjgJdFVD2oFHWUUTNrzzAnBRgySG` |
| **TON** | `UQAJmYVuR3hh02etjaPKJF-h6jcpdSnq9ZIFvI64NEskS6tx` |

## License

MIT — see [LICENSE](LICENSE).
