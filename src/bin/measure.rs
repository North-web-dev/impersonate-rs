//! Measure the real JA4 our client produces, two ways:
//!   1. Offline: capture our own ClientHello and fingerprint it locally.
//!   2. Online: fetch `https://tls.peet.ws/api/all` and read the JA4 the
//!      independent reflector computes from our handshake.
//!
//! Run: `cargo run --bin measure`

use impersonate_rs::{capture, ja4, Client, Profile};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let profile = Profile::Chrome;

    // 1. Offline self-measurement.
    let hello = capture::capture_client_hello(profile).await?;
    let parsed = ja4::parse_client_hello(&hello).ok_or("parse failed")?;
    let local_ja4 = ja4::ja4(&parsed);
    println!("profile            : {}", profile.name());
    println!("clienthello bytes  : {}", hello.len());
    println!(
        "ciphers (no GREASE): {}",
        parsed
            .ciphers
            .iter()
            .filter(|v| !ja4::is_grease(**v))
            .count()
    );
    println!(
        "exts    (no GREASE): {}",
        parsed
            .extensions
            .iter()
            .filter(|v| !ja4::is_grease(**v))
            .count()
    );
    let ext_list: Vec<String> = parsed
        .extensions
        .iter()
        .filter(|v| !ja4::is_grease(**v))
        .map(|e| format!("{e:#06x}"))
        .collect();
    println!("ext ids            : {}", ext_list.join(" "));
    println!("alpn offered       : {:?}", parsed.alpn);
    println!("JA4 (local calc)   : {local_ja4}");

    // 2. Online cross-check against the reflector.
    match fetch_reflector(profile).await {
        Ok((status, remote_ja4, remote_ja3)) => {
            println!("--- tls.peet.ws ---");
            println!("http status        : {status}");
            println!("JA4 (peet.ws)      : {remote_ja4}");
            println!("JA3 (peet.ws)      : {remote_ja3}  (varies per connection by design)");
            println!(
                "JA4 agreement      : {}",
                if remote_ja4 == local_ja4 {
                    "MATCH"
                } else {
                    "DIFFER"
                }
            );
        }
        Err(e) => println!("--- tls.peet.ws unreachable: {e} ---"),
    }

    Ok(())
}

async fn fetch_reflector(
    profile: Profile,
) -> Result<(u16, String, String), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::new(profile)?;
    let resp = client.get("https://tls.peet.ws/api/all").await?;
    let text = resp.text();
    let ja4 = json_str_field(&text, "ja4").unwrap_or_else(|| "<none>".into());
    let ja3 = json_str_field(&text, "ja3_hash").unwrap_or_else(|| "<none>".into());
    Ok((resp.status, ja4, ja3))
}

/// Pull the string value of `"<key>":"<value>"` out of a JSON blob. Good enough
/// for reading one scalar field without pulling in a JSON dependency.
fn json_str_field(json: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after_key = &json[json.find(&needle)? + needle.len()..];
    // Skip past ':' and any whitespace, then the opening quote.
    let open = after_key.find('"')?;
    let rest = &after_key[open + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}
