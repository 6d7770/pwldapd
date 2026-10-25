//! Listener management. Spawns one accept loop per listener address; plain,
//! TLS and Unix-socket listeners run concurrently in a `JoinSet`. The server
//! runs until SIGTERM or SIGINT, then stops accepting and removes any Unix
//! socket files it created.

use crate::config::{Config, UnixSocket};
use crate::handler::{handle_connection, SharedDirectory};
use crate::passwd::{self, SystemDirectory};
use anyhow::{bail, Context, Result};
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
    dir: SharedDirectory,
    limiter: Arc<Semaphore>,
}

/// Pause after a failed accept so that a persistent error (e.g. EMFILE)
/// does not spin the loop.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

pub async fn run(config: Config) -> Result<()> {
    let shared = Shared {
        limiter: Arc::new(Semaphore::new(config.max_connections)),
        config: Arc::new(config),
        dir: Arc::new(SystemDirectory),
    };
    let config = &shared.config;

    let tls_acceptor = if config.tls_listen.is_empty() {
        None
    } else {
        let (Some(cert), Some(key)) = (&config.tls_cert, &config.tls_key) else {
            bail!("tls_listen requires tls_cert and tls_key");
        };
        Some(build_tls_acceptor(cert, key)?)
    };

    let mut set: JoinSet<()> = JoinSet::new();

    for addr in &config.listen {
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {addr}");
        set.spawn(accept_plain(listener, shared.clone()));
    }

    for addr in &config.tls_listen {
        let Some(acceptor) = tls_acceptor.clone() else {
            bail!("tls_listen requires tls_cert and tls_key");
        };
        let listener = TcpListener::bind(addr).await
            .map_err(|e| annotate_bind_error(e, addr))?;
        info!("Listening on {addr} (TLS)");
        set.spawn(accept_tls(listener, acceptor, shared.clone()));
    }

    let mut unix_paths: Vec<PathBuf> = Vec::new();
    for sock in &config.unix_listen {
        let listener = bind_unix_socket(sock)?;
        info!("Listening on {:?} (unix)", sock.path);
        unix_paths.push(sock.path.clone());
        set.spawn(accept_unix(listener, shared.clone(), sock.path.clone()));
    }

    if set.is_empty() {
        bail!("no listeners configured (listen, tls_listen, and unix_listen are all empty)");
    }

    tokio::select! {
        res = shutdown_signal() => {
            res?;
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

/// Resolve when SIGTERM or SIGINT arrives.
async fn shutdown_signal() -> Result<()> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate())
        .context("installing SIGTERM handler")?;
    let mut int = signal(SignalKind::interrupt())
        .context("installing SIGINT handler")?;
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
    Ok(())
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
            handle_connection(stream, shared.config, shared.dir, &label).await
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
    use super::*;

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
    }

    #[test]
    fn unix_socket_refuses_to_replace_regular_file() {
        let path = std::env::temp_dir().join(format!(
            "pwldapd-not-a-socket-{}", std::process::id()
        ));
        std::fs::write(&path, b"x").unwrap();
        let sock = UnixSocket { path: path.clone(), owner: None, group: None, mode: None };
        let err = bind_unix_socket(&sock).unwrap_err().to_string();
        assert!(err.contains("not a socket"), "{err}");
        assert!(path.exists());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn unix_socket_replaces_stale_socket_and_sets_mode() {
        use std::os::unix::fs::PermissionsExt;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all().build().unwrap();
        let _guard = rt.enter();
        let path = std::env::temp_dir().join(format!(
            "pwldapd-stale-{}.sock", std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        let sock = UnixSocket { path: path.clone(), owner: None, group: None, mode: Some(0o600) };
        let first = bind_unix_socket(&sock).unwrap();
        drop(first); // leaves the socket file behind
        assert!(path.exists());
        let _second = bind_unix_socket(&sock).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        std::fs::remove_file(&path).unwrap();
    }
}
