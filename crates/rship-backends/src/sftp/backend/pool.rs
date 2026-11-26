//! Encapsulated SSH/SFTP multiplexed session pool, host-key verification handler,
//! opt-in healthy RAII connection lease, and SFTP/SSH protocol error classification.

use rship_core::{Error, ErrorKind, Result, RetryClass};
use russh::client::{self, AuthResult, KeyboardInteractiveAuthResponse};
use russh::keys::{
    HashAlg, PrivateKey, PrivateKeyWithHashAlg, PublicKeyOrCertificate, decode_secret_key,
    load_secret_key,
};
use russh_sftp::client::SftpSession;
use russh_sftp::client::error::Error as SftpClientError;
use russh_sftp::protocol::StatusCode as SftpStatus;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::common::lock_unpoisoned;
use crate::sftp::config::{HostKeyPolicy, SftpAuth, SftpConfig};

use super::SftpBackend;
use super::known_hosts::{KnownHostsError, verify_and_maybe_learn};

const SFTP_MAX_PACKET_LEN: u32 = 262_144;
/// SFTP v3 / OpenSSH / rclone safe 32 KiB write packet ceiling.
pub(super) const SFTP_MAX_WRITE_PACKET_LEN: u32 = 32_768;
const SFTP_PIPELINE_DEPTH: usize = 32;
/// 4 MiB SSH channel flow-control window so 2+ MiB pipelined SFTP windows never stall on WAN BDP.
const SSH_CHANNEL_WINDOW_BYTES: u32 = 4 * 1024 * 1024;
/// Total concurrent SFTP session slots (multiplexed over shared SSH handles).
pub(super) const MAX_SFTP_CONNS: usize = 16;
/// Cap listing concurrency below `MAX_SFTP_CONNS` so active crawls never starve `stat`/`open_read`/`put`/`abort`.
pub(super) const MAX_LIST_CONCURRENCY: usize = 4;
/// Bounded SFTP subsystem channels multiplexed per authenticated SSH connection.
const MAX_CHANNELS_PER_SSH: usize = 4;
/// Bound concurrent unauthenticated SSH KEX+auth handshakes below OpenSSH `MaxStartups 10:30:100`.
const MAX_CONCURRENT_HANDSHAKES: usize = 2;
/// Bound multi-round keyboard-interactive auth exchanges.
const MAX_KB_INTERACTIVE_ROUNDS: usize = 8;

#[derive(Debug)]
enum SshHandlerError {
    Russh(russh::Error),
    HostKeyMismatch(String),
    HostKeyRevoked(String),
    HostKeyUnknown(String),
    KnownHostsInvalid(String),
}

impl std::fmt::Display for SshHandlerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Russh(e) => write!(f, "{e}"),
            Self::HostKeyMismatch(m)
            | Self::HostKeyRevoked(m)
            | Self::HostKeyUnknown(m)
            | Self::KnownHostsInvalid(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for SshHandlerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Russh(e) => Some(e),
            _ => None,
        }
    }
}

impl From<russh::Error> for SshHandlerError {
    fn from(value: russh::Error) -> Self {
        Self::Russh(value)
    }
}

impl From<KnownHostsError> for SshHandlerError {
    fn from(value: KnownHostsError) -> Self {
        match value {
            KnownHostsError::Mismatch(m) => Self::HostKeyMismatch(m),
            KnownHostsError::Revoked(m) => Self::HostKeyRevoked(m),
            KnownHostsError::Unknown(m) => Self::HostKeyUnknown(m),
            KnownHostsError::Invalid(m) => Self::KnownHostsInvalid(m),
        }
    }
}

struct SshClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts_path: Option<PathBuf>,
}

impl client::Handler for SshClientHandler {
    type Error = SshHandlerError;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.policy == HostKeyPolicy::Insecure {
            return Ok(true);
        }
        verify_and_maybe_learn(
            &self.host,
            self.port,
            self.policy,
            self.known_hosts_path.as_deref(),
            server_public_key,
        )?;
        Ok(true)
    }
}

struct SharedSshHandle {
    ssh: client::Handle<SshClientHandler>,
    active_channels: AtomicUsize,
    saturated: AtomicBool,
}

impl SharedSshHandle {
    fn new(ssh: client::Handle<SshClientHandler>) -> Arc<Self> {
        Arc::new(Self {
            ssh,
            active_channels: AtomicUsize::new(0),
            saturated: AtomicBool::new(false),
        })
    }

    fn try_reserve_channel(&self) -> bool {
        if self.ssh.is_closed() || self.saturated.load(Ordering::Acquire) {
            return false;
        }
        let mut cur = self.active_channels.load(Ordering::Acquire);
        while cur < MAX_CHANNELS_PER_SSH {
            match self.active_channels.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
        false
    }

    fn release_channel(&self) {
        self.active_channels.fetch_sub(1, Ordering::AcqRel);
    }

    fn is_retirable(&self) -> bool {
        self.ssh.is_closed()
            || (self.saturated.load(Ordering::Acquire)
                && self.active_channels.load(Ordering::Acquire) == 0)
    }
}

struct ChannelLeaseGuard {
    handle: Arc<SharedSshHandle>,
    armed: bool,
}

impl ChannelLeaseGuard {
    fn new(handle: Arc<SharedSshHandle>) -> Self {
        Self {
            handle,
            armed: true,
        }
    }

    fn into_handle(mut self) -> Arc<SharedSshHandle> {
        self.armed = false;
        Arc::clone(&self.handle)
    }
}

impl Drop for ChannelLeaseGuard {
    fn drop(&mut self) {
        if self.armed {
            self.handle.release_channel();
        }
    }
}

struct LiveSftpConn {
    ssh: Arc<SharedSshHandle>,
    sftp: Arc<SftpSession>,
}

impl Drop for LiveSftpConn {
    fn drop(&mut self) {
        self.ssh.release_channel();
    }
}

pub(super) struct SftpPool {
    conn_slots: Arc<Semaphore>,
    handshake_gate: Arc<Semaphore>,
    ssh_handles: StdMutex<Vec<Arc<SharedSshHandle>>>,
    idle: StdMutex<Vec<LiveSftpConn>>,
}

impl SftpPool {
    pub(super) fn new() -> Arc<Self> {
        Arc::new(Self {
            conn_slots: Arc::new(Semaphore::new(MAX_SFTP_CONNS)),
            handshake_gate: Arc::new(Semaphore::new(MAX_CONCURRENT_HANDSHAKES)),
            ssh_handles: StdMutex::new(Vec::new()),
            idle: StdMutex::new(Vec::new()),
        })
    }

    fn pop_idle(&self) -> Option<LiveSftpConn> {
        let mut pool = lock_unpoisoned(&self.idle);
        loop {
            match pool.pop() {
                Some(c) if !c.ssh.ssh.is_closed() => return Some(c),
                Some(_) => continue,
                None => return None,
            }
        }
    }

    fn reserve_existing_handle(&self) -> Option<ChannelLeaseGuard> {
        let mut handles = lock_unpoisoned(&self.ssh_handles);
        handles.retain(|h| !h.is_retirable());
        for h in handles.iter() {
            if h.try_reserve_channel() {
                return Some(ChannelLeaseGuard::new(Arc::clone(h)));
            }
        }
        None
    }

    fn register_handle(&self, handle: Arc<SharedSshHandle>) {
        let mut handles = lock_unpoisoned(&self.ssh_handles);
        handles.retain(|h| !h.is_retirable());
        handles.push(handle);
    }

    async fn try_acquire_from_existing(&self, cfg: &SftpConfig) -> Result<Option<LiveSftpConn>> {
        while let Some(reserved) = self.reserve_existing_handle() {
            match tokio::time::timeout(
                cfg.connect_timeout,
                open_sftp_channel(&reserved.handle.ssh, cfg),
            )
            .await
            {
                Ok(Ok(sftp)) => {
                    return Ok(Some(LiveSftpConn {
                        ssh: reserved.into_handle(),
                        sftp,
                    }));
                }
                Ok(Err(OpenChannelOutcome::HandleSaturatedOrClosed(_))) => {
                    reserved.handle.saturated.store(true, Ordering::Release);
                    drop(reserved);
                    continue;
                }
                Ok(Err(OpenChannelOutcome::Fatal(e))) => {
                    drop(reserved);
                    return Err(e);
                }
                Err(_) => {
                    reserved.handle.saturated.store(true, Ordering::Release);
                    drop(reserved);
                    return Err(Error::timeout(format!(
                        "SFTP subsystem open to {}:{} timed out",
                        cfg.host, cfg.port
                    )));
                }
            }
        }
        Ok(None)
    }

    pub(super) async fn acquire(self: &Arc<Self>, cfg: &SftpConfig) -> Result<PooledSftpConn> {
        let permit = self
            .conn_slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::protocol("SFTP connection pool closed"))?;

        if let Some(cached) = self.pop_idle() {
            return Ok(PooledSftpConn {
                pool: Arc::clone(self),
                live: Some(cached),
                _slot_permit: permit,
                was_reused: true,
                healthy: false,
            });
        }

        // First try multiplexing an SFTP subsystem channel over an existing healthy SSH handle.
        if let Some(live) = self.try_acquire_from_existing(cfg).await? {
            return Ok(PooledSftpConn {
                pool: Arc::clone(self),
                live: Some(live),
                _slot_permit: permit,
                was_reused: false,
                healthy: false,
            });
        }

        // Open a fresh authenticated SSH handle under the handshake gate (`MaxStartups` guard).
        let _hs_permit = self
            .handshake_gate
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::protocol("SFTP handshake gate closed"))?;

        // Re-check after acquiring the handshake gate: a concurrent task may have created a handle.
        if let Some(cached) = self.pop_idle() {
            return Ok(PooledSftpConn {
                pool: Arc::clone(self),
                live: Some(cached),
                _slot_permit: permit,
                was_reused: true,
                healthy: false,
            });
        }
        if let Some(live) = self.try_acquire_from_existing(cfg).await? {
            return Ok(PooledSftpConn {
                pool: Arc::clone(self),
                live: Some(live),
                _slot_permit: permit,
                was_reused: false,
                healthy: false,
            });
        }

        let live = connect_fresh(cfg, self).await?;
        Ok(PooledSftpConn {
            pool: Arc::clone(self),
            live: Some(live),
            _slot_permit: permit,
            was_reused: false,
            healthy: false,
        })
    }
}

/// Opt-in healthy RAII lease over a pooled SFTP connection.
///
/// Connections start with `healthy = false` so cancelled futures, mid-stream drops, or
/// connection errors NEVER poison the pool with half-consumed or leaked SFTP handle state.
/// Callers must call [`Self::mark_healthy`] once their RPC & file handle shutdown succeed.
pub(super) struct PooledSftpConn {
    pool: Arc<SftpPool>,
    live: Option<LiveSftpConn>,
    _slot_permit: OwnedSemaphorePermit,
    was_reused: bool,
    healthy: bool,
}

impl PooledSftpConn {
    pub(super) fn session(&self) -> &SftpSession {
        &self.live.as_ref().expect("active sftp lease").sftp
    }

    pub(super) fn session_arc(&self) -> Arc<SftpSession> {
        Arc::clone(&self.live.as_ref().expect("active sftp lease").sftp)
    }

    pub(super) fn mark_healthy(&mut self) {
        self.healthy = true;
    }

    pub(super) fn can_retry_stale(&self, err: &SftpClientError) -> bool {
        self.was_reused && is_sftp_connection_error(err)
    }
}

impl Drop for PooledSftpConn {
    fn drop(&mut self) {
        if !self.healthy {
            return;
        }
        if let Some(live) = self.live.take()
            && !live.ssh.ssh.is_closed()
        {
            let mut pool = lock_unpoisoned(&self.pool.idle);
            if pool.len() < MAX_SFTP_CONNS {
                pool.push(live);
            }
        }
    }
}

pub(super) enum SftpOpError {
    Sftp(SftpClientError),
    Core(Error),
}

impl From<SftpClientError> for SftpOpError {
    fn from(value: SftpClientError) -> Self {
        Self::Sftp(value)
    }
}

impl From<Error> for SftpOpError {
    fn from(value: Error) -> Self {
        Self::Core(value)
    }
}

impl SftpBackend {
    pub(super) async fn with_sftp_retry<T, F, Fut>(&self, context: &str, mut f: F) -> Result<T>
    where
        F: FnMut(Arc<SftpSession>) -> Fut,
        Fut: Future<Output = std::result::Result<T, SftpOpError>>,
    {
        loop {
            let mut conn = self.acquire_conn().await?;
            match f(conn.session_arc()).await {
                Ok(val) => {
                    conn.mark_healthy();
                    return Ok(val);
                }
                Err(SftpOpError::Sftp(e)) if conn.can_retry_stale(&e) => {
                    drop(conn);
                    continue;
                }
                Err(SftpOpError::Sftp(e)) => {
                    if !is_sftp_connection_error(&e) {
                        conn.mark_healthy();
                    }
                    return Err(map_sftp_err(context, e));
                }
                Err(SftpOpError::Core(e)) => {
                    if !e.is_retryable() {
                        conn.mark_healthy();
                    }
                    return Err(e);
                }
            }
        }
    }

    pub(super) async fn open_with_sftp_retry<T, F, Fut>(
        &self,
        context: &str,
        mut f: F,
    ) -> Result<(PooledSftpConn, T)>
    where
        F: FnMut(Arc<SftpSession>) -> Fut,
        Fut: Future<Output = std::result::Result<T, SftpOpError>>,
    {
        loop {
            let mut conn = self.acquire_conn().await?;
            match f(conn.session_arc()).await {
                Ok(val) => return Ok((conn, val)),
                Err(SftpOpError::Sftp(e)) if conn.can_retry_stale(&e) => {
                    drop(conn);
                    continue;
                }
                Err(SftpOpError::Sftp(e)) => {
                    if !is_sftp_connection_error(&e) {
                        conn.mark_healthy();
                    }
                    return Err(map_sftp_err(context, e));
                }
                Err(SftpOpError::Core(e)) => {
                    if !e.is_retryable() {
                        conn.mark_healthy();
                    }
                    return Err(e);
                }
            }
        }
    }
}

fn load_auth_key(auth: &SftpAuth) -> Result<Option<PrivateKey>> {
    match auth {
        SftpAuth::Password(_) => Ok(None),
        SftpAuth::KeyFile { path, passphrase } => load_secret_key(path, passphrase.as_deref())
            .map(Some)
            .map_err(|e| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!("load SSH private key `{}`: {e}", path.display()),
                )
            }),
        SftpAuth::KeyPem { pem, passphrase } => decode_secret_key(pem, passphrase.as_deref())
            .map(Some)
            .map_err(|e| {
                Error::new(
                    ErrorKind::PermissionDenied,
                    RetryClass::Permanent,
                    format!("decode SSH PEM private key: {e}"),
                )
            }),
    }
}

fn resolve_rsa_hash_alg(
    supported: std::result::Result<Option<Option<HashAlg>>, russh::Error>,
) -> Option<HashAlg> {
    match supported {
        Ok(Some(alg)) => alg, // preserves `Some(None)` -> legacy `ssh-rsa`
        Ok(None) | Err(_) => Some(HashAlg::Sha256),
    }
}

async fn authenticate_pubkey(
    handle: &mut client::Handle<SshClientHandler>,
    user: &str,
    key: PrivateKey,
) -> Result<bool> {
    let hash_alg = if key.algorithm().is_rsa() {
        resolve_rsa_hash_alg(handle.best_supported_rsa_hash().await)
    } else {
        None
    };
    let res = handle
        .authenticate_publickey(user, PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg))
        .await
        .map_err(|e| map_russh_err("SSH pubkey auth", e, true))?;
    Ok(res.success())
}

async fn authenticate_keyboard_interactive_fallback(
    handle: &mut client::Handle<SshClientHandler>,
    user: &str,
    password: &str,
) -> Result<bool> {
    let mut resp = handle
        .authenticate_keyboard_interactive_start(user, None)
        .await
        .map_err(|e| map_russh_err("SSH keyboard-interactive auth", e, true))?;

    for _ in 0..MAX_KB_INTERACTIVE_ROUNDS {
        match resp {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. } => {
                let answers = if prompts.is_empty() {
                    Vec::new()
                } else if prompts.len() == 1 && !prompts[0].echo {
                    vec![password.to_string()]
                } else {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        RetryClass::Permanent,
                        format!(
                            "SSH keyboard-interactive auth requested {} prompt(s) incompatible with non-interactive password fallback",
                            prompts.len()
                        ),
                    ));
                };
                resp = handle
                    .authenticate_keyboard_interactive_respond(answers)
                    .await
                    .map_err(|e| map_russh_err("SSH keyboard-interactive respond", e, true))?;
            }
        }
    }
    Err(Error::new(
        ErrorKind::PermissionDenied,
        RetryClass::Permanent,
        "SSH keyboard-interactive auth exceeded maximum challenge rounds",
    ))
}

enum OpenChannelOutcome {
    HandleSaturatedOrClosed(Error),
    Fatal(Error),
}

fn is_russh_mux_disconnect_or_saturated(err: &russh::Error) -> bool {
    matches!(
        err,
        russh::Error::ChannelOpenFailure(_)
            | russh::Error::Disconnect
            | russh::Error::HUP
            | russh::Error::IO(_)
            | russh::Error::SendError
            | russh::Error::RecvError
            | russh::Error::RequestDenied
    )
}

fn is_sftp_mux_disconnect(err: &SftpClientError) -> bool {
    match err {
        SftpClientError::IO(_) | SftpClientError::UnexpectedBehavior(_) => true,
        SftpClientError::Status(s) => matches!(
            s.status_code,
            SftpStatus::ConnectionLost | SftpStatus::NoConnection
        ),
        _ => false,
    }
}

async fn open_sftp_channel(
    handle: &client::Handle<SshClientHandler>,
    cfg: &SftpConfig,
) -> std::result::Result<Arc<SftpSession>, OpenChannelOutcome> {
    let mut channel = match handle.channel_open_session().await {
        Ok(ch) => ch,
        Err(e) => {
            let retry_mux = is_russh_mux_disconnect_or_saturated(&e);
            let mapped = map_russh_err("SSH open session channel", e, false);
            return Err(if retry_mux {
                OpenChannelOutcome::HandleSaturatedOrClosed(mapped)
            } else {
                OpenChannelOutcome::Fatal(mapped)
            });
        }
    };
    if let Err(e) = channel.request_subsystem(true, "sftp").await {
        let retry_mux = is_russh_mux_disconnect_or_saturated(&e);
        let mapped = map_russh_err("SSH request sftp subsystem", e, false);
        return Err(if retry_mux {
            OpenChannelOutcome::HandleSaturatedOrClosed(mapped)
        } else {
            OpenChannelOutcome::Fatal(mapped)
        });
    }
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::Success) => break,
            Some(russh::ChannelMsg::Failure) => {
                return Err(OpenChannelOutcome::HandleSaturatedOrClosed(map_russh_err(
                    "open SFTP subsystem",
                    russh::Error::RequestDenied,
                    false,
                )));
            }
            None | Some(russh::ChannelMsg::Eof | russh::ChannelMsg::Close) => {
                return Err(OpenChannelOutcome::HandleSaturatedOrClosed(map_russh_err(
                    "open SFTP subsystem",
                    russh::Error::Disconnect,
                    false,
                )));
            }
            Some(_) => continue,
        }
    }
    let sftp_cfg = russh_sftp::client::Config {
        max_packet_len: SFTP_MAX_PACKET_LEN,
        max_concurrent_reads: SFTP_PIPELINE_DEPTH,
        max_concurrent_writes: SFTP_PIPELINE_DEPTH,
        max_write_packet_len: SFTP_MAX_WRITE_PACKET_LEN,
        request_timeout_secs: cfg.io_timeout.as_secs().max(10),
    };
    let sftp = match SftpSession::new_with_config(channel.into_stream(), sftp_cfg).await {
        Ok(s) => s,
        Err(e) => {
            let retry_mux = is_sftp_mux_disconnect(&e);
            let mapped = map_sftp_err("init SFTP session", e);
            return Err(if retry_mux {
                OpenChannelOutcome::HandleSaturatedOrClosed(mapped)
            } else {
                OpenChannelOutcome::Fatal(mapped)
            });
        }
    };
    Ok(Arc::new(sftp))
}

async fn connect_fresh(cfg: &SftpConfig, pool: &SftpPool) -> Result<LiveSftpConn> {
    // Decode private key before starting connect timeout (or lazily inside connect_fresh so
    // `SftpBackend::new` never fails on stub/unreadable keys prior to real connection).
    let maybe_key = load_auth_key(&cfg.auth)?;

    let fut = async {
        let ssh_cfg = Arc::new(client::Config {
            keepalive_interval: Some(Duration::from_secs(30)),
            keepalive_max: 3,
            nodelay: true,
            window_size: SSH_CHANNEL_WINDOW_BYTES,
            preferred: russh::Preferred {
                host_key_certificates: russh::Preferred::DEFAULT.key,
                ..russh::Preferred::default()
            },
            ..client::Config::default()
        });
        let handler = SshClientHandler {
            host: cfg.host.clone(),
            port: cfg.port,
            policy: cfg.host_key_policy,
            known_hosts_path: cfg.known_hosts_path.clone(),
        };
        let addr = (cfg.host.as_str(), cfg.port);
        let mut handle = client::connect(ssh_cfg, addr, handler).await.map_err(|e| {
            map_ssh_handler_err(&format!("SSH connect to {}:{}", cfg.host, cfg.port), e)
        })?;

        let authed = match (&cfg.auth, maybe_key) {
            (SftpAuth::Password(pw), _) => {
                match handle
                    .authenticate_password(cfg.user.as_str(), pw.as_str())
                    .await
                    .map_err(|e| map_russh_err("SSH password auth", e, true))?
                {
                    AuthResult::Success => true,
                    AuthResult::Failure {
                        remaining_methods, ..
                    } if remaining_methods.is_empty()
                        || remaining_methods.contains(&russh::MethodKind::KeyboardInteractive) =>
                    {
                        authenticate_keyboard_interactive_fallback(
                            &mut handle,
                            cfg.user.as_str(),
                            pw.as_str(),
                        )
                        .await?
                    }
                    AuthResult::Failure { .. } => false,
                }
            }
            (_, Some(key)) => authenticate_pubkey(&mut handle, cfg.user.as_str(), key).await?,
            (_, None) => false,
        };

        if !authed {
            return Err(Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!(
                    "SSH authentication rejected for `{}@{}:{}`",
                    cfg.user, cfg.host, cfg.port
                ),
            ));
        }

        let shared = SharedSshHandle::new(handle);
        assert!(shared.try_reserve_channel());
        let guard = ChannelLeaseGuard::new(Arc::clone(&shared));
        let sftp = open_sftp_channel(&shared.ssh, cfg)
            .await
            .map_err(|outcome| match outcome {
                OpenChannelOutcome::HandleSaturatedOrClosed(e) | OpenChannelOutcome::Fatal(e) => e,
            })?;
        pool.register_handle(Arc::clone(&shared));
        Ok(LiveSftpConn {
            ssh: guard.into_handle(),
            sftp,
        })
    };

    tokio::time::timeout(cfg.connect_timeout, fut)
        .await
        .map_err(|_| {
            Error::timeout(format!(
                "SFTP connect to {}:{} timed out",
                cfg.host, cfg.port
            ))
        })?
}

fn map_ssh_handler_err(context: &str, err: SshHandlerError) -> Error {
    match err {
        SshHandlerError::HostKeyMismatch(m)
        | SshHandlerError::HostKeyRevoked(m)
        | SshHandlerError::HostKeyUnknown(m) => Error::protocol(m),
        SshHandlerError::KnownHostsInvalid(m) => Error::config(m),
        SshHandlerError::Russh(e) => map_russh_err(context, e, false),
    }
}

pub(super) fn map_russh_err(context: &str, err: russh::Error, is_auth: bool) -> Error {
    match &err {
        // Permanent security / MITM / host-key errors: NEVER retryable!
        russh::Error::UnknownKey
        | russh::Error::KeyChanged { .. }
        | russh::Error::WrongServerSig
        | russh::Error::Keys(_)
        | russh::Error::StrictKeyExchangeViolation { .. } => {
            Error::protocol(format!("{context}: {err}"))
        }
        // Permanent authentication rejections:
        russh::Error::NoAuthMethod
        | russh::Error::UnsupportedAuthMethod
        | russh::Error::NotAuthenticated => Error::permission_denied(format!("{context}: {err}")),
        // Transient SSH/TCP disconnects:
        russh::Error::Disconnect
        | russh::Error::HUP
        | russh::Error::IO(_)
        | russh::Error::SendError
        | russh::Error::RecvError
        | russh::Error::Pending => Error::network(format!("{context}: {err}")),
        // Timeouts:
        russh::Error::ConnectionTimeout
        | russh::Error::KeepaliveTimeout
        | russh::Error::InactivityTimeout
        | russh::Error::Elapsed(_) => Error::timeout(format!("{context}: {err}")),
        // RequestDenied during auth -> PermissionDenied, otherwise Protocol:
        russh::Error::RequestDenied if is_auth => {
            Error::permission_denied(format!("{context}: {err}"))
        }
        _ => Error::protocol(format!("{context}: {err}")),
    }
}

pub(super) fn is_sftp_not_found(err: &SftpClientError) -> bool {
    matches!(
        err,
        SftpClientError::Status(s) if s.status_code == SftpStatus::NoSuchFile
    )
}

pub(super) fn is_sftp_connection_error(err: &SftpClientError) -> bool {
    match err {
        SftpClientError::IO(_)
        | SftpClientError::Timeout
        | SftpClientError::UnexpectedBehavior(_) => true,
        SftpClientError::Status(s) => matches!(
            s.status_code,
            SftpStatus::ConnectionLost | SftpStatus::NoConnection
        ),
        _ => false,
    }
}

pub(super) fn map_sftp_err(context: &str, err: SftpClientError) -> Error {
    match &err {
        SftpClientError::Status(s) => match s.status_code {
            SftpStatus::NoSuchFile => Error::not_found(format!("{context}: {err}")),
            SftpStatus::PermissionDenied => Error::new(
                ErrorKind::PermissionDenied,
                RetryClass::Permanent,
                format!("{context}: {err}"),
            ),
            SftpStatus::ConnectionLost | SftpStatus::NoConnection => {
                Error::network(format!("{context}: {err}"))
            }
            _ => Error::protocol(format!("{context}: {err}")),
        },
        SftpClientError::Timeout => Error::timeout(format!("{context}: {err}")),
        SftpClientError::IO(_) | SftpClientError::UnexpectedBehavior(_) => {
            Error::network(format!("{context}: {err}"))
        }
        _ => Error::protocol(format!("{context}: {err}")),
    }
}

pub(super) fn map_sftp_io_err(context: &str, err: io::Error) -> Error {
    if let Some(sftp_err) = err
        .get_ref()
        .and_then(|src| src.downcast_ref::<SftpClientError>())
    {
        return map_sftp_err(context, sftp_err.clone());
    }
    match err.kind() {
        io::ErrorKind::NotFound => Error::not_found(format!("{context}: {err}")),
        io::ErrorKind::PermissionDenied => Error::permission_denied(format!("{context}: {err}")),
        io::ErrorKind::TimedOut => Error::timeout(format!("{context}: {err}")),
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::NotConnected
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => Error::network(format!("{context}: {err}")),
        _ => Error::io(context, err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_write_packet_ceiling_is_32_kib() {
        assert_eq!(SFTP_MAX_WRITE_PACKET_LEN, 32_768);
    }

    #[test]
    fn resolve_rsa_hash_alg_preserves_legacy_some_none() {
        assert_eq!(resolve_rsa_hash_alg(Ok(Some(None))), None);
        assert_eq!(
            resolve_rsa_hash_alg(Ok(Some(Some(HashAlg::Sha512)))),
            Some(HashAlg::Sha512)
        );
        assert_eq!(resolve_rsa_hash_alg(Ok(None)), Some(HashAlg::Sha256));
        assert_eq!(
            resolve_rsa_hash_alg(Err(russh::Error::RequestDenied)),
            Some(HashAlg::Sha256)
        );
    }

    #[test]
    fn map_sftp_io_err_classifies_sender_dropped_other_as_retryable_network() {
        let sftp_err = SftpClientError::UnexpectedBehavior("sender dropped".into());
        let io_err = io::Error::from(sftp_err);
        assert_eq!(io_err.kind(), io::ErrorKind::Other);
        let mapped = map_sftp_io_err("SFTP read chunk", io_err);
        assert_eq!(mapped.kind(), ErrorKind::Network);
        assert!(mapped.is_retryable());
    }

    #[test]
    fn map_sftp_io_err_keeps_plain_protocol_status_permanent() {
        let io_err = io::Error::other("Failure");
        let mapped = map_sftp_io_err("SFTP write", io_err);
        assert!(!mapped.is_retryable());
        assert!(mapped.is_permanent());
    }

    #[test]
    fn map_sftp_err_maps_unexpected_behavior_retryable_and_perm_denied_permanent() {
        let net = map_sftp_err(
            "op",
            SftpClientError::UnexpectedBehavior("SendError: closed".into()),
        );
        assert_eq!(net.kind(), ErrorKind::Network);
        assert!(net.is_retryable());

        let perm = map_sftp_err(
            "op",
            SftpClientError::Status(russh_sftp::protocol::Status {
                id: 1,
                status_code: SftpStatus::PermissionDenied,
                error_message: "denied".into(),
                language_tag: "en".into(),
            }),
        );
        assert_eq!(perm.kind(), ErrorKind::PermissionDenied);
        assert!(perm.is_permanent());
    }

    #[test]
    fn map_russh_err_never_retries_host_key_or_mitm_errors() {
        let perm_cases = [
            russh::Error::UnknownKey,
            russh::Error::KeyChanged { line: 4 },
            russh::Error::WrongServerSig,
            russh::Error::StrictKeyExchangeViolation {
                message_type: 20,
                sequence_number: 1,
            },
            russh::Error::Keys(russh::keys::Error::NoHomeDir),
            russh::Error::NoAuthMethod,
        ];
        for err in perm_cases {
            let mapped = map_russh_err("connect", err, false);
            assert!(mapped.is_permanent(), "must be permanent: {mapped:?}");
            assert!(!mapped.is_retryable(), "must not retry: {mapped:?}");
        }

        let retry_cases = [
            russh::Error::Disconnect,
            russh::Error::HUP,
            russh::Error::IO(io::Error::new(io::ErrorKind::ConnectionReset, "reset")),
            russh::Error::SendError,
            russh::Error::ConnectionTimeout,
        ];
        for err in retry_cases {
            let mapped = map_russh_err("connect", err, true);
            assert!(mapped.is_retryable(), "must be retryable: {mapped:?}");
        }
    }

    #[test]
    fn map_ssh_handler_err_maps_host_key_and_config_errors_permanently() {
        let mismatch =
            map_ssh_handler_err("connect", SshHandlerError::HostKeyMismatch("mitm".into()));
        assert_eq!(mismatch.kind(), ErrorKind::Protocol);
        assert!(mismatch.is_permanent());

        let invalid =
            map_ssh_handler_err("connect", SshHandlerError::KnownHostsInvalid("bad".into()));
        assert_eq!(invalid.kind(), ErrorKind::Config);
        assert!(invalid.is_permanent());
    }

    #[test]
    fn mux_disconnect_classifiers_cover_channel_and_sftp_disconnects() {
        assert!(is_russh_mux_disconnect_or_saturated(
            &russh::Error::Disconnect
        ));
        assert!(is_russh_mux_disconnect_or_saturated(&russh::Error::HUP));
        assert!(is_russh_mux_disconnect_or_saturated(
            &russh::Error::SendError
        ));
        assert!(is_russh_mux_disconnect_or_saturated(
            &russh::Error::RecvError
        ));
        assert!(is_russh_mux_disconnect_or_saturated(
            &russh::Error::RequestDenied
        ));
        assert!(is_russh_mux_disconnect_or_saturated(
            &russh::Error::ChannelOpenFailure(
                russh::ChannelOpenFailure::AdministrativelyProhibited
            )
        ));
        assert!(is_russh_mux_disconnect_or_saturated(&russh::Error::IO(
            io::Error::new(io::ErrorKind::ConnectionReset, "reset")
        )));
        assert!(!is_russh_mux_disconnect_or_saturated(
            &russh::Error::KexInit
        ));

        assert!(is_sftp_mux_disconnect(
            &SftpClientError::UnexpectedBehavior("sender dropped".into())
        ));
        assert!(is_sftp_mux_disconnect(&SftpClientError::IO("eof".into())));
        assert!(is_sftp_mux_disconnect(&SftpClientError::Status(
            russh_sftp::protocol::Status {
                id: 1,
                status_code: SftpStatus::ConnectionLost,
                error_message: "lost".into(),
                language_tag: "en".into(),
            }
        )));
        assert!(!is_sftp_mux_disconnect(&SftpClientError::Timeout));
    }
}
