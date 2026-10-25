//! Browser profiles: the TLS and default-header identity of a target browser.

/// A browser whose network fingerprint this client reproduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Profile {
    /// Desktop Google Chrome (recent stable, post-quantum key share, GREASE +
    /// per-connection extension permutation). The profile verified byte-exact.
    Chrome,
}

impl Profile {
    /// Look a profile up by (case-insensitive) name.
    pub fn by_name(name: &str) -> Option<Profile> {
        match name.to_ascii_lowercase().as_str() {
            "chrome" => Some(Profile::Chrome),
            _ => None,
        }
    }

    /// Short lowercase identifier.
    pub fn name(self) -> &'static str {
        match self {
            Profile::Chrome => "chrome",
        }
    }

    /// The default request headers this browser sends, in browser order. Only
    /// applied when the caller has not set the header themselves.
    pub fn default_headers(self) -> &'static [(&'static str, &'static str)] {
        match self {
            Profile::Chrome => &[
                ("sec-ch-ua", "\"Chromium\";v=\"131\", \"Not_A Brand\";v=\"24\", \"Google Chrome\";v=\"131\""),
                ("sec-ch-ua-mobile", "?0"),
                ("sec-ch-ua-platform", "\"Linux\""),
                ("upgrade-insecure-requests", "1"),
                (
                    "user-agent",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
                ),
                (
                    "accept",
                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                ),
                ("sec-fetch-site", "none"),
                ("sec-fetch-mode", "navigate"),
                ("sec-fetch-user", "?1"),
                ("sec-fetch-dest", "document"),
                ("accept-encoding", "gzip, deflate, br, zstd"),
                ("accept-language", "en-US,en;q=0.9"),
            ],
        }
    }
}
