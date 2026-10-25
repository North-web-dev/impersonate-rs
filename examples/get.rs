//! Minimal usage: fetch a URL with Chrome's TLS fingerprint.
//!
//! Run: `cargo run --example get -- https://example.com`

use impersonate_rs::{Client, Profile};

#[tokio::main]
async fn main() -> Result<(), impersonate_rs::Error> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://tls.peet.ws/api/all".to_string());

    let client = Client::new(Profile::Chrome)?;
    let resp = client.get(&url).await?;

    println!("status : {}", resp.status);
    println!("alpn   : {}", resp.alpn);
    println!("bytes  : {}", resp.body.len());
    println!("{}", resp.text());
    Ok(())
}
