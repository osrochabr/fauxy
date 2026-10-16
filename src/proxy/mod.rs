mod handler;

pub use handler::FauxyHandler;

use crate::state::AppState;
use crate::tls::{LocalCa, crypto_provider};
use hudsucker::Proxy;
use hudsucker::tokio_tungstenite::Connector;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error(transparent)]
    Ca(#[from] crate::tls::CaError),
    #[error("proxy error: {0}")]
    Proxy(#[from] hudsucker::Error),
    #[error("proxy socket error: {0}")]
    Io(#[from] std::io::Error),
    #[error("proxy task failed: {0}")]
    Task(String),
}

#[derive(Debug)]
pub struct ProxyServer {
    local_addr: SocketAddr,
    task: JoinHandle<Result<(), hudsucker::Error>>,
}

impl ProxyServer {
    /// Serves on `listener` until `shutdown` is canceled. Only hosts with
    /// enabled rules are decrypted; everything else is tunneled untouched.
    pub fn spawn(
        listener: TcpListener,
        ca: &LocalCa,
        upstream: rustls::ClientConfig,
        state: Arc<AppState>,
        shutdown: CancellationToken,
    ) -> Result<Self, ProxyError> {
        let local_addr = listener.local_addr()?;
        let upstream = Arc::new(upstream);
        let connector = hyper_rustls::HttpsConnectorBuilder::new()
            .with_tls_config((*upstream).clone())
            .https_or_http()
            .enable_http1()
            .build();

        let proxy = Proxy::builder()
            .with_listener(listener)
            .with_ca(ca.authority(crypto_provider())?)
            .with_http_connector(connector)
            .with_websocket_connector(Connector::Rustls(upstream))
            .with_http_handler(FauxyHandler::new(state))
            .with_graceful_shutdown(async move { shutdown.cancelled().await })
            .build()?;

        let task = tokio::spawn(proxy.start());
        Ok(Self { local_addr, task })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub async fn wait(self) -> Result<(), ProxyError> {
        Ok(self
            .task
            .await
            .map_err(|err| ProxyError::Task(err.to_string()))??)
    }
}
