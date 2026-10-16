//! The daemon: proxy, control API and configuration watcher.

pub mod logging;
pub mod process;
mod reload;
pub mod service;

pub use reload::{ConfigWatcher, DEBOUNCE, Reloader};

use crate::config;
use crate::control::{ControlContext, ControlServer, StatusInfo};
use crate::events::now_ms;
use crate::paths::Paths;
use crate::proxy::ProxyServer;
use crate::state::AppState;
use crate::tls::{LocalCa, client_config};
use anyhow::Context;
use process::PidFile;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Time open connections get to finish on shutdown.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

const WATCH_ERROR: &str =
    "cannot watch the configuration files (use --no-watch to disable hot reload)";

#[derive(Debug, Clone, Default)]
pub struct RunOptions {
    /// Alternative global configuration file.
    pub config_file: Option<PathBuf>,
    /// Disables hot reload.
    pub no_watch: bool,
    /// Replaces the port of `listen` for this run (`fauxy run --port`).
    pub port: Option<u16>,
}

pub struct Daemon {
    proxy: ProxyServer,
    control: ControlServer,
    watcher: Option<ConfigWatcher>,
    state: Arc<AppState>,
    shutdown: CancellationToken,
    pid_file: PidFile,
}

impl Daemon {
    /// Loads the configuration and starts every component. Only one daemon
    /// may run per state directory.
    pub async fn start(paths: Paths, options: RunOptions) -> anyhow::Result<Self> {
        paths
            .ensure_state_dir()
            .with_context(|| format!("cannot create {}", paths.state_dir.display()))?;
        let socket = paths.checked_socket()?;
        let pid_file = PidFile::acquire(&paths.pid_file(), std::process::id())?;
        // Holding the lock means no other daemon owns the socket.
        if socket.exists() {
            std::fs::remove_file(&socket)
                .with_context(|| format!("cannot remove {}", socket.display()))?;
        }

        let mut loaded = config::load(&paths, options.config_file.as_deref())
            .map_err(|errors| anyhow::anyhow!("invalid configuration:\n{errors}"))?;
        if let Some(port) = options.port {
            loaded.listen.set_port(port);
        }
        for warning in &loaded.warnings {
            tracing::warn!("{warning}");
        }

        let (ca, created) = LocalCa::load_or_create(&paths)?;
        if created {
            let cert = ca.cert_path().display();
            tracing::info!("local CA created at {cert}; run 'fauxy ca install' to trust it");
        }
        let upstream = client_config(&loaded.upstream_ca_files)?;
        let listener = TcpListener::bind(loaded.listen)
            .await
            .map_err(|err| bind_error(&err, loaded.listen, &loaded.config_file, options.port))?;

        let state = Arc::new(AppState::new(Default::default()));
        let shutdown = CancellationToken::new();
        // Stops whatever already started if a later step fails.
        let cleanup = shutdown.clone().drop_guard();
        let shared = Arc::clone(&state);
        let proxy = ProxyServer::spawn(listener, &ca, upstream, shared, shutdown.clone())?;
        let proxy_addr = proxy.local_addr();
        let reloader = Arc::new(Reloader::new(
            paths.clone(),
            options.config_file.clone(),
            Arc::clone(&state),
            loaded,
            options.port,
        ));

        let started_at_ms = now_ms();
        let ca_cert = ca.cert_path().display().to_string();
        let status_state = Arc::clone(&state);
        let reload_handle = Arc::clone(&reloader);
        let context = ControlContext {
            state: Arc::clone(&state),
            status: Arc::new(move || {
                build_status(&status_state, proxy_addr, started_at_ms, &ca_cert)
            }),
            reload: Arc::new(move || reload_handle.reload()),
            shutdown: shutdown.clone(),
        };
        let control = ControlServer::bind(&socket, context)
            .with_context(|| format!("cannot open the control socket {}", socket.display()))?;

        let watcher = if options.no_watch {
            None
        } else {
            let watcher = ConfigWatcher::start(Arc::clone(&reloader), DEBOUNCE);
            Some(watcher.context(WATCH_ERROR)?)
        };

        cleanup.disarm();
        let (version, rules) = (env!("CARGO_PKG_VERSION"), state.rules().len());
        tracing::info!("fauxy {version} listening on {proxy_addr} ({rules} rule(s))");
        Ok(Self {
            proxy,
            control,
            watcher,
            state,
            shutdown,
            pid_file,
        })
    }

    pub fn proxy_addr(&self) -> SocketAddr {
        self.proxy.local_addr()
    }

    pub fn state(&self) -> &Arc<AppState> {
        &self.state
    }

    /// Cancelling the token stops the daemon.
    pub fn shutdown_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Waits until a shutdown is requested, then stops every component.
    pub async fn wait(self) -> anyhow::Result<()> {
        self.shutdown.cancelled().await;
        tracing::info!("shutting down");
        // Joining the watcher thread blocks until its current reload finishes.
        let watcher = self.watcher;
        let _ = tokio::task::spawn_blocking(move || drop(watcher)).await;
        if tokio::time::timeout(SHUTDOWN_GRACE, self.proxy.wait())
            .await
            .is_err()
        {
            tracing::warn!("closed connections that were still open");
        }
        self.control.wait().await;
        drop(self.pid_file);
        Ok(())
    }
}

/// Says how to free the port or pick another one when it is already taken.
fn bind_error(
    err: &std::io::Error,
    listen: SocketAddr,
    config_file: &Path,
    from_flag: Option<u16>,
) -> anyhow::Error {
    if err.kind() != std::io::ErrorKind::AddrInUse {
        return anyhow::anyhow!("cannot listen on {listen}: {err}");
    }
    let port = listen.port();
    let fix = match from_flag {
        Some(_) => "pass another --port".to_owned(),
        None => format!(
            "'fauxy init --port <port>' sets 'listen' in {}, then run 'fauxy restart'",
            config_file.display()
        ),
    };
    anyhow::anyhow!(
        "port {port} is already in use ({listen}). Stop the program that uses it (find it with 'lsof -nP -iTCP:{port} -sTCP:LISTEN') or choose another port: {fix}"
    )
}

fn build_status(
    state: &AppState,
    listen: SocketAddr,
    started_at_ms: u64,
    ca_cert: &str,
) -> StatusInfo {
    let info = state.info();
    let rules = state.rules();
    StatusInfo {
        version: env!("CARGO_PKG_VERSION").to_owned(),
        pid: std::process::id(),
        listen: listen.to_string(),
        started_at_ms,
        config_file: info.config_file.display().to_string(),
        mock_files: info
            .mock_files
            .iter()
            .map(|p| p.display().to_string())
            .collect(),
        rules_total: rules.len(),
        rules_enabled: rules.rules().iter().filter(|r| state.is_enabled(r)).count(),
        intercepted_hosts: state.intercepted_hosts(),
        ca_cert: ca_cert.to_owned(),
        last_reload_ms: info.last_reload_ms,
        last_reload_error: info.last_reload_error,
        warnings: info.warnings,
    }
}

/// Runs the daemon until SIGINT, SIGTERM or a shutdown request.
pub async fn run_foreground(paths: Paths, options: RunOptions) -> anyhow::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let daemon = Daemon::start(paths, options).await?;
    let token = daemon.shutdown_token();
    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
        token.cancel();
    });
    daemon.wait().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;
    use crate::rules::test_support::rule;

    #[test]
    fn bind_errors_explain_how_to_change_the_port() {
        let listen = "127.0.0.1:8899".parse().unwrap();
        let in_use = std::io::Error::from(std::io::ErrorKind::AddrInUse);
        let message = bind_error(&in_use, listen, Path::new("/c/config.yaml"), None).to_string();
        assert!(
            message.starts_with("port 8899 is already in use (127.0.0.1:8899)."),
            "{message}"
        );
        assert!(
            message.contains("lsof -nP -iTCP:8899 -sTCP:LISTEN"),
            "{message}"
        );
        assert!(
            message.contains("'fauxy init --port <port>' sets 'listen' in /c/config.yaml"),
            "{message}"
        );

        let flagged =
            bind_error(&in_use, listen, Path::new("/c/config.yaml"), Some(8899)).to_string();
        assert!(
            flagged.ends_with("or choose another port: pass another --port"),
            "{flagged}"
        );

        let other = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        let message = bind_error(&other, listen, Path::new("/c/config.yaml"), None).to_string();
        assert_eq!(
            message,
            "cannot listen on 127.0.0.1:8899: permission denied"
        );
    }

    #[test]
    fn status_reports_rules_and_hosts() {
        let mut off = rule("b", "b.com", None, "");
        off.enabled = false;
        let state = AppState::new(RuleSet::new(vec![rule("a", "a.com", None, ""), off]));
        state.update_info(|info| {
            info.config_file = "/c/config.yaml".into();
            info.mock_files = vec!["/c/mocks/a.yaml".into()];
        });
        let status = build_status(&state, "127.0.0.1:8899".parse().unwrap(), 5, "/s/ca.pem");
        assert_eq!(status.listen, "127.0.0.1:8899");
        assert_eq!(status.rules_total, 2);
        assert_eq!(status.rules_enabled, 1);
        assert_eq!(status.intercepted_hosts, vec!["a.com"]);
        assert_eq!(status.config_file, "/c/config.yaml");
        assert_eq!(status.mock_files, vec!["/c/mocks/a.yaml"]);
        assert_eq!(status.pid, std::process::id());
        assert_eq!(status.started_at_ms, 5);
        assert_eq!(status.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.ca_cert, "/s/ca.pem");
    }
}
