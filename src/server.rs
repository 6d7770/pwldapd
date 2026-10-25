//! Listener management. `bind_all` opens every configured listener;
//! `serve` runs one accept loop per listener in a `JoinSet` until the
//! supplied shutdown future resolves, then removes any Unix socket files.
//! `run` wires the two together with SIGTERM/SIGINT as the shutdown signal.

use crate::config::{Config, UnixSocket};
use crate::handler::{handle_connection, Backend};
use crate::pam_auth::PamAuthenticator;
use crate::passwd::{self, SystemDirectory};
use anyhow::{bail, Context, Result};
use std::future::Future;
use std::net::SocketAddr;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// State shared by every accept loop.
#[derive(Clone)]
struct Shared {
    config: Arc<Config>,
    backend: Arc<Backend>,
    limiter: Arc<Semaphore>,
}

/// Pause after a failed accept so that a persistent error (e.g. EMFILE)
/// does not spin the loop.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Every bound listener, ready to be served.
pub struct Listeners {
    plain: Vec<TcpListener>,
    tls: Vec<(TcpListener, TlsAcceptor)>,
    unix: Vec<(UnixListener, PathBuf)>,
}

impl Listeners {
    /// Local addresses of the plain TCP listeners, in config order.
    pub fn plain_addrs(&self) -> Vec<SocketAddr> {
        self.plain.iter().filter_map(|l| l.local_addr().ok()).collect()
    }

    /// Local addresses of the TLS listeners, in config order.
    pub fn tls_addrs(&self) -> Vec<SocketAddr> {
        self.tls.iter().filter_map(|(l, _)| l.local_addr().ok()).collect()
    }

    fn is_empty(&self) -> bool {
        self.plain.is_empty() && self.tls.is_empty() && self.unix.is_empty()
    }
}

impl std::fmt::Debug for Listeners {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Listeners")
            .field("plain", &self.plain_addrs())
            .field("tls", &self.tls_addrs())
            .field("unix", &self.unix.iter().map(|(_, p)| p).collect::<Vec<_>>())
            .finish()
    }
}

/// Run the server with the system directory and PAM until SIGTERM or
/// SIGINT.
pub async fn run(config: Config) -> Result<()> {
    let listeners = bind_all(&config).await?;
    let backend = Arc::new(Backend {
        dir: Arc::new(SystemDirectory),
        auth: Arc::new(PamAuthenticator),
    });
    serve(listeners, Arc::new(config), backend, shutdown_signal()).await
}

/// Bind every listener named in the configuration. Fails if any bind
/// fails or if nothing is configured.
pub async fn bind_all(config: &Config) -> Result<Listeners> {
    let tls_acceptor = if config.tls_listen.is_empty() {
        None
    } else {
        let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) else {
            bail!("tls_listen requires tls_cert and tls_key");
        };
        Some(build_tls_acceptor(cert, key)?)
    };

    let mut listeners = Listeners { plain: vec![], tls: vec![], unix: vec![] };

    for addr in &config.listen {
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {}", local_label(&listener, addr));
        listeners.plain.push(listener);
    }

    for addr in &config.tls_listen {
        let Some(acceptor) = tls_acceptor.clone() else {
            bail!("tls_listen requires tls_cert and tls_key");
        };
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {} (TLS)", local_label(&listener, addr));
        listeners.tls.push((listener, acceptor));
    }

    for sock in &config.unix_listen {
        let listener = bind_unix_socket(sock)?;
        info!("Listening on {:?} (unix)", sock.path);
        listeners.unix.push((listener, sock.path.clone()));
    }

    if listeners.is_empty() {
        bail!("no listeners configured (listen, tls_listen, and unix_listen are all empty)");
    }
    Ok(listeners)
}

fn local_label(listener: &TcpListener, configured: &str) -> String {
    listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| configured.to_string())
}

/// Accept connections on all listeners until `shutdown` resolves. Unix
/// socket files are removed on the way out.
pub async fn serve(
    listeners: Listeners,
    config: Arc<Config>,
    backend: Arc<Backend>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let shared = Shared {
        limiter: Arc::new(Semaphore::new(config.max_connections)),
        config,
        backend,
    };
    let mut set: JoinSet<()> = JoinSet::new();
    let mut unix_paths = Vec::new();

    for listener in listeners.plain {
        set.spawn(accept_plain(listener, shared.clone()));
    }
    for (listener, acceptor) in listeners.tls {
        set.spawn(accept_tls(listener, acceptor, shared.clone()));
    }
    for (listener, path) in listeners.unix {
        unix_paths.push(path.clone());
        set.spawn(accept_unix(listener, shared.clone(), path));
    }

    tokio::select! {
        _ = shutdown => {
            info!("Shutting down");
        }
        // Accept loops never return normally; a completion here means a
        // panic, which should not take the whole server down silently.
        Some(res) = set.join_next() => {
            if let Err(e) = res {
                error!("Listener task failed: {e}");
            }
        }
    }

    set.shutdown().await;
    for path in unix_paths {
        if let Err(e) = std::fs::remove_file(&path) {
            warn!("Could not remove socket {:?}: {e}", path);
        }
    }
    Ok(())
}

/// Resolve when SIGTERM or SIGINT arrives. If the handlers cannot be
/// installed the server logs the problem and simply never shuts down on a
/// signal.
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let (Ok(mut term), Ok(mut int)) = (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) else {
        error!("Cannot install signal handlers; signals will not stop the server");
        std::future::pending::<()>().await;
        return;
    };
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

/// Reserve a connection slot, or return `None` (after logging) when the
/// server is at `max_connections`.
fn try_reserve(shared: &Shared, label: &str) -> Option<OwnedSemaphorePermit> {
    match Arc::clone(&shared.limiter).try_acquire_owned() {
        Ok(permit) => Some(permit),
        Err(_) => {
            warn!("Connection limit reached, rejecting {label}");
            None
        }
    }
}

/// Run the protocol handler for one accepted stream on its own task. The
/// permit is released when the task finishes.
fn spawn_connection<S>(
    stream: S,
    shared: Shared,
    label: String,
    permit: OwnedSemaphorePermit,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let _permit = permit;
        info!("Connection from {label}");
        if let Err(e) =
            handle_connection(stream, shared.config, shared.backend, &label).await
        {
            error!("Connection error from {label}: {e}");
        }
    });
}

async fn accept_failed(label: &str, e: std::io::Error) {
    error!("Accept error on {label}: {e}");
    tokio::time::sleep(ACCEPT_RETRY_DELAY).await;
}

/// Accept loop for plain (non-TLS) connections. Accept errors are logged
/// and retried; individual connection errors never affect the listener.
async fn accept_plain(listener: TcpListener, shared: Shared) {
    let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                accept_failed(&local, e).await;
                continue;
            }
        };
        let label = peer.to_string();
        if let Some(permit) = try_reserve(&shared, &label) {
            spawn_connection(stream, shared.clone(), label, permit);
        }
    }
}

/// Accept loop for TLS (LDAPS) connections. The TLS handshake is performed
/// before handing off to the connection handler; handshake errors are logged
/// and the connection is dropped without affecting the listener.
async fn accept_tls(listener: TcpListener, acceptor: TlsAcceptor, shared: Shared) {
    let local = listener.local_addr().map(|a| a.to_string()).unwrap_or_default();
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                accept_failed(&local, e).await;
                continue;
            }
        };
        let label = peer.to_string();
        let Some(permit) = try_reserve(&shared, &label) else { continue };
        let acc = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            match acc.accept(stream).await {
                Ok(s) => spawn_connection(s, shared, label, permit),
                Err(e) => error!("TLS handshake error from {label}: {e}"),
            }
        });
    }
}

/// Accept loop for Unix domain socket connections.
async fn accept_unix(listener: UnixListener, shared: Shared, path: PathBuf) {
    let label = format!("unix:{}", path.display());
    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                accept_failed(&label, e).await;
                continue;
            }
        };
        if let Some(permit) = try_reserve(&shared, &label) {
            spawn_connection(stream, shared.clone(), label.clone(), permit);
        }
    }
}

/// Create a Unix listening socket, replacing a stale socket file from a
/// previous run but refusing to clobber anything that is not a socket.
fn bind_unix_socket(sock: &UnixSocket) -> Result<UnixListener> {
    match std::fs::symlink_metadata(&sock.path) {
        Ok(meta) if meta.file_type().is_socket() => {
            std::fs::remove_file(&sock.path).with_context(|| {
                format!("removing stale socket {:?}", sock.path)
            })?;
        }
        Ok(_) => bail!(
            "{:?} exists and is not a socket; refusing to replace it",
            sock.path
        ),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => bail!("cannot stat {:?}: {e}", sock.path),
    }
    let listener = UnixListener::bind(&sock.path)
        .with_context(|| format!("cannot bind to {:?}", sock.path))?;
    if let Some(mode) = sock.mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock.path, std::fs::Permissions::from_mode(mode))
            .with_context(|| format!("cannot set mode on {:?}", sock.path))?;
    }
    if let Some(owner) = &sock.owner {
        let uid = resolve_uid(owner)?;
        std::os::unix::fs::chown(&sock.path, Some(uid), None)
            .with_context(|| format!("cannot set owner of {:?}", sock.path))?;
    }
    if let Some(group) = &sock.group {
        let gid = resolve_gid(group)?;
        std::os::unix::fs::chown(&sock.path, None, Some(gid)).with_context(|| {
            format!(
                "cannot set group of {:?} (the daemon process must be a \
                 member of group {:?} or have CAP_CHOWN)",
                sock.path, group
            )
        })?;
    }
    Ok(listener)
}

/// Build a `TlsAcceptor` from PEM certificate and private-key files.
fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    use tokio_rustls::rustls::ServerConfig;

    let certs = load_certs(cert_path)?;
    let key = load_private_key(key_path)?;
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn load_certs(
    path: &Path,
) -> Result<Vec<tokio_rustls::rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening certificate {:?}", path))?;
    let mut reader = std::io::BufReader::new(file);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("reading certificate {:?}", path))?;
    if certs.is_empty() {
        bail!("no certificates found in {:?}", path);
    }
    Ok(certs)
}

fn load_private_key(
    path: &Path,
) -> Result<tokio_rustls::rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("opening private key {:?}", path))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("reading private key {:?}", path))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {:?}", path))
}

fn annotate_bind_error(e: std::io::Error, addr: &str) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::PermissionDenied {
        // Parse the port from the address to give a targeted hint.
        let port: Option<u16> = addr
            .rsplit(':')
            .next()
            .and_then(|p| p.trim_end_matches(']').parse().ok());
        if let Some(port) = port.filter(|&p| p < 1024) {
            return anyhow::anyhow!(
                "cannot bind to {addr}: permission denied\n\
                 Port {port} requires elevated privileges. Either:\n\
                 \x20 sudo setcap cap_net_bind_service=ep {}\n\
                 or set a high port in the config file (listen = [\"127.0.0.1:3389\"])",
                std::env::current_exe()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| "pwldapd".into()),
            );
        }
    }
    anyhow::anyhow!("cannot bind to {addr}: {e}")
}

/// Resolve a user name or decimal UID string to a numeric UID.
fn resolve_uid(name: &str) -> Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    passwd::get_user_by_name(name)
        .map(|u| u.uid)
        .ok_or_else(|| anyhow::anyhow!("user not found: {name:?}"))
}

/// Resolve a group name or decimal GID string to a numeric GID.
fn resolve_gid(name: &str) -> Result<u32> {
    if let Ok(n) = name.parse::<u32>() {
        return Ok(n);
    }
    passwd::get_group_by_name(name)
        .map(|g| g.gid)
        .ok_or_else(|| anyhow::anyhow!("group not found: {name:?}"))
}

#[cfg(test)]
mod tests {
    // Host assumptions: the `root` user and group exist; a writable
    // std::env::temp_dir(); loopback IPv4. The `[::1]` test skips itself
    // when IPv6 loopback is unavailable.
    use super::*;
    use crate::handler::testutil::{cfg_with, test_backend};
    use crate::ldap::testutil::*;
    use crate::ldap;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;

    fn temp_path(suffix: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pwldapd-{}-{suffix}", std::process::id()
        ))
    }

    /// Read one LDAP message from any async stream.
    async fn read_msg<S: AsyncRead + Unpin>(s: &mut S) -> (i64, u8, Vec<u8>) {
        let mut head = [0u8; 2];
        s.read_exact(&mut head).await.expect("message header");
        let mut buf = head.to_vec();
        let len = if head[1] & 0x80 == 0 {
            head[1] as usize
        } else {
            let n = (head[1] & 0x7f) as usize;
            let mut extra = vec![0u8; n];
            s.read_exact(&mut extra).await.unwrap();
            buf.extend_from_slice(&extra);
            extra.iter().fold(0usize, |l, b| (l << 8) | *b as usize)
        };
        let mut body = vec![0u8; len];
        s.read_exact(&mut body).await.unwrap();
        buf.extend_from_slice(&body);
        decode_envelope(&buf)
    }

    /// Anonymous bind plus a root DSE search; asserts both succeed.
    async fn round_trip<S: AsyncRead + AsyncWrite + Unpin>(s: &mut S) {
        s.write_all(&bind_msg(1, "", "")).await.unwrap();
        let (id, tag, value) = read_msg(s).await;
        assert_eq!((id, tag, result_code(&value)), (1, BIND_RESPONSE, ldap::SUCCESS));
        s.write_all(&search_msg(2, "", 0, 0, false, f_present("objectClass"))).await.unwrap();
        let (_, tag, _) = read_msg(s).await;
        assert_eq!(tag, SEARCH_RESULT_ENTRY);
        let (id, tag, value) = read_msg(s).await;
        assert_eq!((id, tag, result_code(&value)), (2, SEARCH_RESULT_DONE, ldap::SUCCESS));
    }

    /// Bind the listeners in `cfg`, serve them on a task, and return the
    /// listeners' addresses plus a handle to stop the server.
    async fn start(
        cfg: Config,
    ) -> (Vec<SocketAddr>, Vec<SocketAddr>, oneshot::Sender<()>, tokio::task::JoinHandle<Result<()>>) {
        let listeners = bind_all(&cfg).await.expect("bind");
        let plain = listeners.plain_addrs();
        let tls = listeners.tls_addrs();
        let (tx, rx) = oneshot::channel();
        let task = tokio::spawn(serve(
            listeners,
            Arc::new(cfg),
            test_backend(),
            async move { let _ = rx.await; },
        ));
        (plain, tls, tx, task)
    }

    #[tokio::test]
    async fn plain_tcp_round_trip_and_shutdown() {
        let cfg = cfg_with(|c| c.listen = vec!["127.0.0.1:0".into()]);
        let (plain, _, stop, task) = start(cfg).await;
        let mut s = TcpStream::connect(plain[0]).await.unwrap();
        round_trip(&mut s).await;
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        // Listener is gone after shutdown.
        assert!(TcpStream::connect(plain[0]).await.is_err());
    }

    #[tokio::test]
    async fn ipv6_loopback_listener() {
        let cfg = cfg_with(|c| c.listen = vec!["[::1]:0".into()]);
        if TcpListener::bind("[::1]:0").await.is_err() {
            eprintln!("skipping: no IPv6 loopback");
            return;
        }
        let (plain, _, stop, task) = start(cfg).await;
        assert!(plain[0].is_ipv6());
        let mut s = TcpStream::connect(plain[0]).await.unwrap();
        round_trip(&mut s).await;
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn max_connections_rejects_then_frees_slot() {
        let cfg = cfg_with(|c| {
            c.listen = vec!["127.0.0.1:0".into()];
            c.max_connections = 1;
        });
        let (plain, _, stop, task) = start(cfg).await;
        let mut first = TcpStream::connect(plain[0]).await.unwrap();
        round_trip(&mut first).await;
        // Second connection is accepted and closed without a response.
        let mut second = TcpStream::connect(plain[0]).await.unwrap();
        second.write_all(&bind_msg(1, "", "")).await.unwrap();
        let mut buf = [0u8; 1];
        let closed = matches!(second.read(&mut buf).await, Ok(0) | Err(_));
        assert!(closed, "second connection should have been dropped");
        // First connection still works.
        round_trip(&mut first).await;
        // Release the slot and try again.
        first.write_all(&unbind_msg(9)).await.unwrap();
        drop(first);
        let mut third = None;
        for _ in 0..50 {
            let mut s = TcpStream::connect(plain[0]).await.unwrap();
            s.write_all(&bind_msg(1, "", "")).await.unwrap();
            let mut hdr = [0u8; 2];
            if s.read_exact(&mut hdr).await.is_ok() {
                third = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(third.is_some(), "slot was never released");
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn unix_listener_round_trip_and_cleanup() {
        let path = temp_path("serve.sock");
        let cfg = cfg_with(|c| {
            c.unix_listen = vec![UnixSocket {
                path: path.clone(), owner: None, group: None, mode: Some(0o600),
            }];
        });
        let (_, _, stop, task) = start(cfg).await;
        let mut s = tokio::net::UnixStream::connect(&path).await.unwrap();
        round_trip(&mut s).await;
        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert!(!path.exists(), "socket file should be removed on shutdown");
    }

    /// Write a fresh self-signed certificate and key; return their paths
    /// and the certificate DER for the client's trust store.
    fn self_signed(suffix: &str) -> (PathBuf, PathBuf, Vec<u8>) {
        let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert = temp_path(&format!("{suffix}.crt"));
        let key = temp_path(&format!("{suffix}.key"));
        std::fs::write(&cert, ck.cert.pem()).unwrap();
        std::fs::write(&key, ck.key_pair.serialize_pem()).unwrap();
        (cert, key, ck.cert.der().to_vec())
    }

    #[tokio::test]
    async fn tls_round_trip() {
        use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName};
        use tokio_rustls::rustls::{ClientConfig, RootCertStore};
        let (cert, key, der) = self_signed("tls");
        let cfg = cfg_with(|c| {
            c.tls_listen = vec!["127.0.0.1:0".into()];
            c.tls_cert = Some(cert.clone());
            c.tls_key = Some(key.clone());
        });
        let (_, tls, stop, task) = start(cfg).await;

        let mut roots = RootCertStore::empty();
        roots.add(CertificateDer::from(der)).unwrap();
        let client_cfg = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let tcp = TcpStream::connect(tls[0]).await.unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        let mut s = connector.connect(name, tcp).await.expect("TLS handshake");
        round_trip(&mut s).await;

        // A plaintext client on the TLS port fails the handshake and is
        // dropped without disturbing the listener.
        let mut plain = TcpStream::connect(tls[0]).await.unwrap();
        plain.write_all(&bind_msg(1, "", "")).await.unwrap();
        // rustls answers with an alert record (content type 0x15) and then
        // the connection is dropped; nothing LDAP-shaped ever comes back.
        let mut got = Vec::new();
        let mut buf = [0u8; 64];
        loop {
            match plain.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&buf[..n]),
            }
        }
        assert!(got.is_empty() || got[0] == 0x15, "unexpected bytes {got:?}");
        round_trip(&mut s).await;

        stop.send(()).unwrap();
        task.await.unwrap().unwrap();
        let _ = std::fs::remove_file(cert);
        let _ = std::fs::remove_file(key);
    }

    #[tokio::test]
    async fn tls_configuration_errors() {
        // Missing key path.
        let cfg = cfg_with(|c| {
            c.tls_listen = vec!["127.0.0.1:0".into()];
            c.tls_cert = Some("/nonexistent.pem".into());
        });
        assert!(bind_all(&cfg).await.unwrap_err().to_string().contains("tls_key"));
        // Unreadable certificate.
        let cfg = cfg_with(|c| {
            c.tls_listen = vec!["127.0.0.1:0".into()];
            c.tls_cert = Some("/nonexistent.pem".into());
            c.tls_key = Some("/nonexistent.key".into());
        });
        assert!(bind_all(&cfg).await.unwrap_err().to_string().contains("certificate"));
        // PEM with no certificate, and a key file with no key.
        let empty = temp_path("empty.pem");
        std::fs::write(&empty, "not a pem\n").unwrap();
        let (cert, key, _) = self_signed("tlserr");
        let cfg = cfg_with(|c| {
            c.tls_listen = vec!["127.0.0.1:0".into()];
            c.tls_cert = Some(empty.clone());
            c.tls_key = Some(key.clone());
        });
        assert!(bind_all(&cfg).await.unwrap_err().to_string().contains("no certificates"));
        let cfg = cfg_with(|c| {
            c.tls_listen = vec!["127.0.0.1:0".into()];
            c.tls_cert = Some(cert.clone());
            c.tls_key = Some(empty.clone());
        });
        assert!(bind_all(&cfg).await.unwrap_err().to_string().contains("no private key"));
        for p in [empty, cert, key] {
            let _ = std::fs::remove_file(p);
        }
    }

    #[tokio::test]
    async fn bind_all_requires_a_listener() {
        let err = bind_all(&cfg_with(|_| {})).await.unwrap_err().to_string();
        assert!(err.contains("no listeners configured"));
    }

    #[tokio::test]
    async fn bind_all_reports_unbindable_address() {
        let cfg = cfg_with(|c| c.listen = vec!["203.0.113.1:0".into()]);
        let err = bind_all(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("cannot bind to 203.0.113.1:0"), "{err}");
    }

    #[test]
    fn resolve_numeric_and_named_ids() {
        assert_eq!(resolve_uid("42").unwrap(), 42);
        assert_eq!(resolve_uid("root").unwrap(), 0);
        assert!(resolve_uid("no-such-user-pwldapd").is_err());
        assert_eq!(resolve_gid("7").unwrap(), 7);
        assert_eq!(resolve_gid("root").unwrap(), 0);
        assert!(resolve_gid("no-such-group-pwldapd").is_err());
    }

    #[test]
    fn bind_error_hint_for_privileged_port() {
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = annotate_bind_error(e, "0.0.0.0:389").to_string();
        assert!(msg.contains("setcap"));
        let e = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let msg = annotate_bind_error(e, "[::1]:3389").to_string();
        assert!(!msg.contains("setcap"));
        let e = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let msg = annotate_bind_error(e, "127.0.0.1:389").to_string();
        assert!(msg.contains("cannot bind") && !msg.contains("setcap"));
    }

    #[tokio::test]
    async fn unix_socket_refuses_to_replace_regular_file() {
        let path = temp_path("not-a-socket");
        std::fs::write(&path, b"x").unwrap();
        let sock = UnixSocket { path: path.clone(), owner: None, group: None, mode: None };
        let err = bind_unix_socket(&sock).unwrap_err().to_string();
        assert!(err.contains("not a socket"), "{err}");
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn unix_socket_replaces_stale_socket_and_sets_mode_and_owner() {
        use std::os::unix::fs::PermissionsExt;
        let path = temp_path("stale.sock");
        let _ = std::fs::remove_file(&path);
        // Owner/group given numerically as our own ids: a no-op chown that
        // still exercises the code path without privileges.
        let me = unsafe { libc::getuid() }.to_string();
        let my_group = unsafe { libc::getgid() }.to_string();
        let sock = UnixSocket {
            path: path.clone(),
            owner: Some(me),
            group: Some(my_group),
            mode: Some(0o600),
        };
        let first = bind_unix_socket(&sock).unwrap();
        drop(first); // leaves the socket file behind
        assert!(path.exists());
        let _second = bind_unix_socket(&sock).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&path).unwrap();
    }

    #[tokio::test]
    async fn unix_socket_unknown_owner_is_an_error() {
        let path = temp_path("owner.sock");
        let _ = std::fs::remove_file(&path);
        let sock = UnixSocket {
            path: path.clone(),
            owner: Some("no-such-user-pwldapd".into()),
            group: None,
            mode: None,
        };
        let err = bind_unix_socket(&sock).unwrap_err().to_string();
        assert!(err.contains("user not found"), "{err}");
        let _ = std::fs::remove_file(&path);
    }
}
