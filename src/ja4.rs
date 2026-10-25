//! A self-contained JA4 (TLS client) fingerprint calculator.
//!
//! JA4 is the FoxIO fingerprint that, unlike JA3, sorts the cipher and
//! extension lists before hashing. That makes it stable across Chrome's
//! per-connection extension shuffle (Chromium >= 110) while still pinning the
//! exact cipher/extension/signature-algorithm *set* a client offers.
//!
//! Spec: <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>
//!
//! This parser takes the raw bytes a client writes as its first TLS flight
//! (a TLS record whose first byte is `0x16`, handshake) and derives the JA4
//! string. We use it both to measure our own client and to verify, offline,
//! that a committed ClientHello fixture still fingerprints to the expected
//! value.

use sha2::{Digest, Sha256};

/// A parsed TLS ClientHello, reduced to the fields JA4 cares about.
#[derive(Debug, Clone)]
pub struct ClientHello {
    pub tls_version: u16,
    pub sni_present: bool,
    pub ciphers: Vec<u16>,
    pub extensions: Vec<u16>,
    pub alpn: Vec<String>,
    pub sig_algs: Vec<u16>,
}

/// GREASE values (RFC 8701). Both octets are equal and of the form `0x?a`.
pub fn is_grease(v: u16) -> bool {
    let hi = (v >> 8) & 0xff;
    let lo = v & 0xff;
    hi == lo && (lo & 0x0f) == 0x0a
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(((*b.get(i)? as u16) << 8) | *b.get(i + 1)? as u16)
}

/// Parse a raw first-flight buffer (starting with the `0x16` handshake record)
/// into a [`ClientHello`]. Returns `None` on malformed input.
pub fn parse_client_hello(buf: &[u8]) -> Option<ClientHello> {
    // TLS record header: type(1) version(2) length(2)
    if buf.first().copied()? != 0x16 {
        return None;
    }
    let rec_len = be16(buf, 3)? as usize;
    let body = buf.get(5..5 + rec_len).or_else(|| buf.get(5..))?;

    // Handshake header: type(1)=0x01 length(3)
    if body.first().copied()? != 0x01 {
        return None;
    }
    let mut p = 4usize; // skip handshake type + 3-byte length

    // client_version(2) + random(32)
    p += 2 + 32;

    // session_id
    let sid_len = *body.get(p)? as usize;
    p += 1 + sid_len;

    // cipher_suites
    let cs_len = be16(body, p)? as usize;
    p += 2;
    let cs_end = p + cs_len;
    let mut ciphers = Vec::new();
    while p + 1 < cs_end {
        ciphers.push(be16(body, p)?);
        p += 2;
    }
    p = cs_end;

    // compression_methods
    let cm_len = *body.get(p)? as usize;
    p += 1 + cm_len;

    // extensions
    let mut sni_present = false;
    let mut alpn = Vec::new();
    let mut sig_algs = Vec::new();
    let mut extensions = Vec::new();
    let mut tls_version = 0x0303u16; // default = record client_version (TLS 1.2)

    if p + 1 < body.len() {
        let ext_total = be16(body, p)? as usize;
        p += 2;
        let ext_end = (p + ext_total).min(body.len());
        while p + 4 <= ext_end {
            let etype = be16(body, p)?;
            let elen = be16(body, p + 2)? as usize;
            let edata = body.get(p + 4..p + 4 + elen)?;
            p += 4 + elen;

            extensions.push(etype);
            match etype {
                0x0000 => sni_present = true,
                0x0010 => {
                    // ALPN: list_len(2) then (len(1) + bytes)*
                    if edata.len() >= 2 {
                        let mut q = 2usize;
                        while q < edata.len() {
                            let l = edata[q] as usize;
                            q += 1;
                            if let Some(s) = edata.get(q..q + l) {
                                alpn.push(String::from_utf8_lossy(s).into_owned());
                            }
                            q += l;
                        }
                    }
                }
                0x000d => {
                    // signature_algorithms: list_len(2) then 2-byte entries
                    if edata.len() >= 2 {
                        let mut q = 2usize;
                        while q + 1 < edata.len() {
                            sig_algs.push(((edata[q] as u16) << 8) | edata[q + 1] as u16);
                            q += 2;
                        }
                    }
                }
                0x002b if !edata.is_empty() => {
                    // supported_versions: list_len(1) then 2-byte versions
                    let mut q = 1usize;
                    let mut best = 0u16;
                    while q + 1 < edata.len() {
                        let v = ((edata[q] as u16) << 8) | edata[q + 1] as u16;
                        if !is_grease(v) && v > best {
                            best = v;
                        }
                        q += 2;
                    }
                    if best != 0 {
                        tls_version = best;
                    }
                }
                _ => {}
            }
        }
    }

    Some(ClientHello {
        tls_version,
        sni_present,
        ciphers,
        extensions,
        alpn,
        sig_algs,
    })
}

fn version_str(v: u16) -> &'static str {
    match v {
        0x0304 => "13",
        0x0303 => "12",
        0x0302 => "11",
        0x0301 => "10",
        0x0300 => "s3",
        _ => "00",
    }
}

fn alpn_code(alpn: &[String]) -> String {
    // JA4 uses the first and last byte of the first ALPN value.
    match alpn.first() {
        Some(s) if !s.is_empty() => {
            let bytes = s.as_bytes();
            let first = bytes[0] as char;
            let last = bytes[bytes.len() - 1] as char;
            // Non-alphanumeric bytes are rendered as their first/last hex nibble
            // per spec; our browser profiles only ever use ASCII ("h2"/"http/1.1").
            format!("{first}{last}")
        }
        _ => "00".to_string(),
    }
}

fn hash12(input: &str) -> String {
    if input.is_empty() {
        return "000000000000".to_string();
    }
    let digest = Sha256::digest(input.as_bytes());
    hex::encode(digest)[..12].to_string()
}

/// Compute the full JA4 string from a parsed [`ClientHello`].
pub fn ja4(ch: &ClientHello) -> String {
    // --- JA4_a ---
    let ciphers_no_grease: Vec<u16> = ch
        .ciphers
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();
    let exts_no_grease: Vec<u16> = ch
        .extensions
        .iter()
        .copied()
        .filter(|v| !is_grease(*v))
        .collect();

    let proto = "t";
    let ver = version_str(ch.tls_version);
    let sni = if ch.sni_present { "d" } else { "i" };
    let nc = ciphers_no_grease.len().min(99);
    let ne = exts_no_grease.len().min(99);
    let alpn = alpn_code(&ch.alpn);
    let ja4_a = format!("{proto}{ver}{sni}{nc:02}{ne:02}{alpn}");

    // --- JA4_b: sorted ciphers ---
    let mut cipher_hex: Vec<String> = ciphers_no_grease
        .iter()
        .map(|c| format!("{c:04x}"))
        .collect();
    cipher_hex.sort();
    let ja4_b = hash12(&cipher_hex.join(","));

    // --- JA4_c: sorted extensions (minus SNI 0x0000 and ALPN 0x0010) + "_" + sig algs (in order) ---
    let mut ext_hex: Vec<String> = exts_no_grease
        .iter()
        .filter(|&&e| e != 0x0000 && e != 0x0010)
        .map(|e| format!("{e:04x}"))
        .collect();
    ext_hex.sort();
    let sig_hex: Vec<String> = ch.sig_algs.iter().map(|s| format!("{s:04x}")).collect();

    let ja4_c_input = if sig_hex.is_empty() {
        ext_hex.join(",")
    } else {
        format!("{}_{}", ext_hex.join(","), sig_hex.join(","))
    };
    let ja4_c = hash12(&ja4_c_input);

    format!("{ja4_a}_{ja4_b}_{ja4_c}")
}

/// Convenience: parse a raw first-flight buffer and return its JA4, or `None`.
pub fn ja4_from_bytes(buf: &[u8]) -> Option<String> {
    parse_client_hello(buf).as_ref().map(ja4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grease_detection() {
        for v in [0x0a0a, 0x1a1a, 0x2a2a, 0x7a7a, 0xdada, 0xfafa] {
            assert!(is_grease(v), "{v:#06x} should be GREASE");
        }
        for v in [0x1301u16, 0x0000, 0xff01, 0x44cd, 0xfe0d, 0x1234] {
            assert!(!is_grease(v), "{v:#06x} should not be GREASE");
        }
    }

    #[test]
    fn empty_hash_is_zeroes() {
        assert_eq!(hash12(""), "000000000000");
    }

    #[test]
    fn rejects_non_handshake() {
        assert!(parse_client_hello(&[0x17, 0x03, 0x03, 0x00, 0x00]).is_none());
    }
}
