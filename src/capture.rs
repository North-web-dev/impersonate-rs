//! Capture the raw ClientHello a profile's connector actually emits.
//!
//! We bind a throwaway TCP listener, start a TLS handshake against it, and read
//! the client's first flight — the ClientHello TLS record. The server side
//! never replies, so the handshake aborts, but by then the ClientHello bytes
//! are on the wire. This is how we generate the committed test fixture and how
//! the offline test re-derives the JA4 deterministically (no network).

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};

use crate::profile::Profile;
use crate::tls;

/// Capture the ClientHello (one full TLS handshake record, starting at `0x16`)
/// that `profile`'s connector emits.
pub async fn capture_client_hello(profile: Profile) -> std::io::Result<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let connector = tls::connector(profile).map_err(|e| std::io::Error::other(e.to_string()))?;

    let client = tokio::spawn(async move {
        let tcp = TcpStream::connect(addr).await?;
        let mut cfg = connector
            .configure()
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        tls::configure_connection(profile, &mut cfg);
        // The peer never answers, so this resolves to an error once aborted;
        // the ClientHello has already been written by then.
        let _ = tokio_boring::connect(cfg, "tls.peet.ws", tcp).await;
        Ok::<(), std::io::Error>(())
    });

    let accepted = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    let (mut sock, _) = accepted;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    let deadline = Duration::from_secs(5);
    loop {
        let read = tokio::time::timeout(deadline, sock.read(&mut chunk)).await;
        match read {
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                buf.extend_from_slice(&chunk[..n]);
                // Once we have the 5-byte record header we know the record
                // length; stop as soon as the whole ClientHello record is in.
                if buf.len() >= 5 {
                    let rec_len = ((buf[3] as usize) << 8) | buf[4] as usize;
                    if buf.len() >= 5 + rec_len {
                        buf.truncate(5 + rec_len);
                        break;
                    }
                }
            }
            _ => break,
        }
    }

    drop(sock);
    client.abort();
    Ok(buf)
}
