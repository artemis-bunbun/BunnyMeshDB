//! TLS termination for the HTTP API (optional).
//!
//! Wraps a tokio `TcpListener` with a `tokio-rustls` server acceptor so the
//! axum `serve` gets an encrypted `AsyncRead + AsyncWrite` stream per
//! connection. Certs/keys are loaded from PEM via `rustls-pemfile` at boot;
//! the whole server fails fast if they are missing or mismatched. Capability
//! auth is still the application boundary — TLS merely stops tokens and
//! payloads from riding the wire in cleartext.

use crate::server::config::Tls;
use tokio_rustls::rustls::server::ServerConfig;
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer};
use axum::serve::Listener;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use std::io::BufReader;

/// A `TcpListener` whose accepted streams are TLS-terminated before handoff.
pub struct TlsListener {
    inner: tokio::net::TcpListener,
    acceptor: tokio_rustls::TlsAcceptor,
}

impl Listener for TlsListener {
    type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Addr = std::net::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let accepted = match self.inner.accept().await {
                Ok(a) => a,
                Err(e) => {
                    tracing::warn!(%e, "tcp accept error (retrying)");
                    continue;
                }
            };
            let (stream, addr) = accepted;
            // Bound the handshake: a hanging client must not pin a worker.
            match tokio::time::timeout(Duration::from_secs(5), self.acceptor.accept(stream)).await {
                Ok(Ok(tls)) => return (tls, addr),
                _ => {
                    tracing::warn!("tls handshake failed or timed out (dropping)");
                    continue;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// Load PEM cert chain + private key and build a TLS listener bound to
/// `addr`. Fails fast (returning `Err`) on unreadable/mismatched material.
pub async fn build(addr: &str, tls: &Tls) -> Result<TlsListener, String> {
    let cert_chain = load_certs(&Path::new(&tls.cert_path))?;
    let key_der = load_key(&Path::new(&tls.key_path))?;
    let config = match ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key_der)
    {
        Ok(mut c) => {
            // Advertise HTTP/2 (and HTTP/1.1 fallback) so h2 clients get
            // multiplexing over TLS; plaintext HTTP/1.1 remains the default
            // when not using TLS (std axum serve negotiates h1).
            c.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            c
        }
        Err(e) => return Err(format!("tls: invalid cert/key for {}: {e}", tls.cert_path)),
    };
    let inner = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => return Err(format!("bind {}: {e}", addr)),
    };
    Ok(TlsListener {
        inner,
        acceptor: tokio_rustls::TlsAcceptor::from(Arc::new(config)),
    })
}

fn load_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(format!("tls: open cert {}: {e}", path.display())),
    };
    let mut rd = BufReader::new(f);
    let ders = match rustls_pemfile::certs(&mut rd) {
        Ok(v) => v,
        Err(e) => return Err(format!("tls: read certs from {}: {e}", path.display())),
    };
    if ders.is_empty() {
        return Err(format!("tls: no certificates in {}", path.display()));
    }
    Ok(ders.iter().map(|d| CertificateDer::from(d.clone())).collect::<Vec<_>>())
}

/// First DER for a PEM key format (`pkcs8` | `sec1` | `rsa`), or `None` when
/// the file holds no key of that format.
fn first_key_der(bytes: &[u8], kind: &str) -> Result<Option<PrivateKeyDer<'static>>, String> {
    let mut rd = BufReader::new(bytes);
    let parsed = match kind {
        "pkcs8" => rustls_pemfile::pkcs8_private_keys(&mut rd),
        "sec1" => rustls_pemfile::ec_private_keys(&mut rd),
        "rsa" => rustls_pemfile::rsa_private_keys(&mut rd),
        _ => Err(std::io::Error::from_raw_os_error(0)),
    };
    match parsed {
        Ok(v) if !v.is_empty() => match PrivateKeyDer::try_from(v[0].clone()) {
            Ok(d) => Ok(Some(d)),
            Err(e) => Err(format!("tls: malformed {kind} key: {e}")),
        },
        Ok(_) => Ok(None),
        Err(e) => Err(format!("tls: parse {kind} key: {e}")),
    }
}

/// Private keys: PKCS#8, then SEC1 EC, then PKCS#1 RSA.
fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>, String> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => return Err(format!("tls: read key {}: {e}", path.display())),
    };
    for kind in ["pkcs8", "sec1", "rsa"] {
        match first_key_der(&bytes, kind) {
            Ok(Some(der)) => return Ok(der),
            Ok(None) => {}
            Err(e) => return Err(e),
        }
    }
    Err(format!("tls: no PKCS#8 / SEC1 / PKCS#1 private key found in {}", path.display()))
}