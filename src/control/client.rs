use super::api::{ApiError, EventsPage, ReloadResult, RuleInfo, StatusInfo};
use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use serde::de::DeserializeOwned;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::net::UnixStream;

pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("fauxy is not running (use 'fauxy start')")]
    NotRunning,
    /// The daemon answered with an error message.
    #[error("{0}")]
    Api(String),
    #[error("failed to talk to the daemon: {0}")]
    Transport(String),
}

impl ClientError {
    fn transport(err: &dyn std::fmt::Display) -> Self {
        Self::Transport(err.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct ControlClient {
    socket: PathBuf,
    timeout: Duration,
}

impl ControlClient {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn socket(&self) -> &Path {
        &self.socket
    }

    pub async fn status(&self) -> Result<StatusInfo, ClientError> {
        self.call(Method::GET, "/v1/status").await
    }

    pub async fn rules(&self) -> Result<Vec<RuleInfo>, ClientError> {
        self.call(Method::GET, "/v1/rules").await
    }

    /// Returns the updated rules.
    pub async fn set_rule_enabled(
        &self,
        name: &str,
        enabled: bool,
    ) -> Result<Vec<RuleInfo>, ClientError> {
        let action = if enabled { "enable" } else { "disable" };
        let path = format!("/v1/rules/{}/{action}", encode_segment(name));
        self.call(Method::POST, &path).await
    }

    pub async fn reload(&self) -> Result<ReloadResult, ClientError> {
        self.call(Method::POST, "/v1/reload").await
    }

    pub async fn events(&self, after: u64, limit: usize) -> Result<EventsPage, ClientError> {
        let path = format!("/v1/events?after={after}&limit={limit}");
        self.call(Method::GET, &path).await
    }

    pub async fn shutdown(&self) -> Result<(), ClientError> {
        let _: serde_json::Value = self.call(Method::POST, "/v1/shutdown").await?;
        Ok(())
    }

    async fn call<T: DeserializeOwned>(
        &self,
        method: Method,
        path: &str,
    ) -> Result<T, ClientError> {
        let body = tokio::time::timeout(self.timeout, self.request(method, path))
            .await
            .map_err(|_| ClientError::Transport("timed out".to_owned()))??;
        serde_json::from_slice(&body).map_err(|err| ClientError::transport(&err))
    }

    /// Body of a successful (200) answer.
    async fn request(&self, method: Method, path: &str) -> Result<Bytes, ClientError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|err| match err.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    ClientError::NotRunning
                }
                std::io::ErrorKind::InvalidInput => ClientError::Transport(format!(
                    "{err} ({}); set FAUXY_STATE_DIR to a shorter directory",
                    self.socket.display()
                )),
                _ => ClientError::transport(&err),
            })?;
        let transport = |err: hyper::Error| ClientError::transport(&err);
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .map_err(transport)?;
        tokio::spawn(connection);

        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(http::header::HOST, "fauxy")
            .body(Empty::<Bytes>::new())
            .map_err(|err| ClientError::transport(&err))?;
        let response = sender.send_request(request).await.map_err(transport)?;
        let status = response.status();
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(transport)?
            .to_bytes();
        if status == StatusCode::OK {
            return Ok(body);
        }
        let message = serde_json::from_slice::<ApiError>(&body)
            .map_or_else(|_| format!("unexpected response ({status})"), |e| e.error);
        Err(ClientError::Api(message))
    }
}

/// Percent-encodes a path segment.
fn encode_segment(value: &str) -> String {
    value
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                char::from(byte).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::server::ControlServer;
    use crate::control::server::tests::context;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;

    #[test]
    fn segments_are_encoded() {
        assert_eq!(encode_segment("a#1"), "a%231");
        assert_eq!(encode_segment("ação x"), "a%C3%A7%C3%A3o%20x");
        assert_eq!(encode_segment("ok-_.~"), "ok-_.~");
    }

    #[tokio::test]
    async fn missing_socket_means_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let client = ControlClient::new(dir.path().join("none.sock"));
        assert_eq!(client.socket(), dir.path().join("none.sock"));
        let err = client.status().await.unwrap_err();
        assert!(matches!(err, ClientError::NotRunning));
        assert_eq!(err.to_string(), "fauxy is not running (use 'fauxy start')");
    }

    #[tokio::test]
    async fn stale_socket_means_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&path).unwrap());
        let client = ControlClient::new(&path);
        // On macOS std marks sockets close-on-exec in a second step, so a
        // process forked by a parallel test may briefly inherit the listener.
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        let mut result = client.status().await;
        while matches!(result, Err(ClientError::Transport(_)))
            && std::time::Instant::now() < deadline
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
            result = client.status().await;
        }
        assert!(matches!(result, Err(ClientError::NotRunning)), "{result:?}");
    }

    #[tokio::test]
    async fn unusable_socket_paths_are_transport_errors() {
        let long = format!("/tmp/{}.sock", "x".repeat(200));
        let err = ControlClient::new(long).status().await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
        assert!(err.to_string().starts_with("failed to talk to the daemon"));
        assert!(
            err.to_string()
                .ends_with("set FAUXY_STATE_DIR to a shorter directory")
        );
    }

    #[tokio::test]
    async fn inaccessible_sockets_are_transport_errors() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let locked = dir.path().join("locked");
        std::fs::create_dir(&locked).unwrap();
        let _listener = std::os::unix::net::UnixListener::bind(locked.join("c.sock")).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = ControlClient::new(locked.join("c.sock")).status().await;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        let err = result.unwrap_err();
        assert!(err.to_string().contains("ermission denied"), "{err}");
    }

    #[tokio::test]
    async fn round_trip_over_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sock");
        let ctx = context();
        let server = ControlServer::bind(&path, ctx.clone()).unwrap();
        let client = ControlClient::new(&path);

        assert_eq!(client.status().await.unwrap().pid, 1);
        assert_eq!(client.rules().await.unwrap().len(), 2);
        let rules = client.set_rule_enabled("a#1", false).await.unwrap();
        assert!(!rules[0].enabled);
        let rules = client.set_rule_enabled("a#1", true).await.unwrap();
        assert!(rules[0].enabled);
        let err = client.set_rule_enabled("zzz", true).await.unwrap_err();
        assert_eq!(err.to_string(), "rule not found: zzz");
        assert!(client.reload().await.unwrap().ok);
        assert_eq!(client.events(0, 10).await.unwrap().last_id, 0);

        client.shutdown().await.unwrap();
        server.wait().await;
        assert!(!path.exists(), "the socket must be removed");
    }

    /// Serves one connection with a canned raw HTTP answer (or none).
    async fn canned_server(path: &Path, answer: Option<&'static [u8]>) {
        let listener = UnixListener::bind(path).unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 1024];
            let _ = stream.read(&mut buffer).await;
            if let Some(answer) = answer {
                stream.write_all(answer).await.unwrap();
            } else {
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        });
    }

    #[tokio::test]
    async fn unexpected_responses_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canned.sock");
        canned_server(
            &path,
            Some(b"HTTP/1.1 500 Internal Server Error\r\ncontent-length: 4\r\n\r\noops"),
        )
        .await;
        let err = ControlClient::new(&path).status().await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "unexpected response (500 Internal Server Error)"
        );
    }

    #[tokio::test]
    async fn invalid_json_is_a_transport_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canned.sock");
        canned_server(
            &path,
            Some(b"HTTP/1.1 200 OK\r\ncontent-length: 4\r\n\r\nnope"),
        )
        .await;
        let err = ControlClient::new(&path).status().await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn truncated_bodies_are_transport_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canned.sock");
        canned_server(
            &path,
            Some(b"HTTP/1.1 200 OK\r\ncontent-length: 99\r\n\r\n{}"),
        )
        .await;
        let err = ControlClient::new(&path).status().await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
    }

    #[tokio::test]
    async fn silent_daemons_time_out() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("canned.sock");
        canned_server(&path, None).await;
        let client = ControlClient::new(&path).with_timeout(Duration::from_millis(200));
        let err = client.status().await.unwrap_err();
        assert_eq!(err.to_string(), "failed to talk to the daemon: timed out");
    }

    #[tokio::test]
    async fn invalid_request_paths_are_transport_errors() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("c.sock");
        let ctx = context();
        let _server = ControlServer::bind(&path, ctx.clone()).unwrap();
        let client = ControlClient::new(&path);
        let err = client.request(Method::GET, "bad uri").await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
        ctx.shutdown.cancel();
    }
}
