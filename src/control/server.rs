use super::api::{ApiError, EventsPage, ReloadResult, RuleInfo, StatusInfo};
use crate::rules::{parse_query, percent_decode};
use crate::state::AppState;
use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{Method, Request, Response, StatusCode};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use std::convert::Infallible;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

pub const MAX_EVENTS_PER_PAGE: usize = 500;

pub type StatusFn = Arc<dyn Fn() -> StatusInfo + Send + Sync>;
pub type ReloadFn = Arc<dyn Fn() -> ReloadResult + Send + Sync>;

/// Everything the control API needs from the daemon.
#[derive(Clone)]
pub struct ControlContext {
    pub state: Arc<AppState>,
    pub status: StatusFn,
    pub reload: ReloadFn,
    /// Canceled to stop the daemon.
    pub shutdown: CancellationToken,
}

#[derive(Debug)]
pub struct ControlServer {
    path: PathBuf,
    task: JoinHandle<()>,
}

impl ControlServer {
    /// Binds the socket (mode 0600) and serves until `ctx.shutdown` is
    /// canceled. Only processes of the current user are answered.
    pub fn bind(path: &Path, ctx: ControlContext) -> std::io::Result<Self> {
        Self::bind_for_uid(path, ctx, crate::sys::euid())
    }

    pub(crate) fn bind_for_uid(
        path: &Path,
        ctx: ControlContext,
        uid: u32,
    ) -> std::io::Result<Self> {
        use std::os::unix::fs::PermissionsExt;

        let listener = UnixListener::bind(path)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        let shutdown = ctx.shutdown.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        if let Ok((stream, _)) = accepted && peer_uid(&stream) == Some(uid) {
                            tokio::spawn(serve(stream, ctx.clone()));
                        }
                    }
                    () = shutdown.cancelled() => break,
                }
            }
        });
        Ok(Self {
            path: path.to_path_buf(),
            task,
        })
    }

    /// Waits for the accept loop to finish and removes the socket file.
    pub async fn wait(self) {
        let _ = self.task.await;
        let _ = std::fs::remove_file(&self.path);
    }
}

fn peer_uid(stream: &UnixStream) -> Option<u32> {
    stream.peer_cred().ok().map(|cred| cred.uid())
}

async fn serve(stream: UnixStream, ctx: ControlContext) {
    let service = service_fn(move |req| {
        let ctx = ctx.clone();
        async move { Ok::<_, Infallible>(handle(&ctx, req).await) }
    });
    if let Err(err) = http1::Builder::new()
        .serve_connection(TokioIo::new(stream), service)
        .await
    {
        tracing::debug!("control connection closed: {err}");
    }
}

pub async fn handle<B>(ctx: &ControlContext, req: Request<B>) -> Response<Full<Bytes>> {
    let path = req.uri().path().to_owned();
    let segments: Vec<&str> = path.trim_matches('/').split('/').collect();

    match (req.method(), segments.as_slice()) {
        (&Method::GET, ["v1", "status"]) => json(StatusCode::OK, &(ctx.status)()),
        (&Method::GET, ["v1", "rules"]) => json(StatusCode::OK, &RuleInfo::all(&ctx.state)),
        (&Method::POST, ["v1", "rules", name, action @ ("enable" | "disable")]) => {
            match ctx
                .state
                .set_enabled(&percent_decode(name), *action == "enable")
            {
                Ok(()) => json(StatusCode::OK, &RuleInfo::all(&ctx.state)),
                Err(err) => error(StatusCode::NOT_FOUND, &err.to_string()),
            }
        }
        (&Method::POST, ["v1", "reload"]) => {
            let reload = Arc::clone(&ctx.reload);
            match tokio::task::spawn_blocking(move || reload()).await {
                Ok(result) => json(StatusCode::OK, &result),
                Err(err) => error(StatusCode::INTERNAL_SERVER_ERROR, &err.to_string()),
            }
        }
        (&Method::GET, ["v1", "events"]) => {
            let params = parse_query(req.uri().query().unwrap_or_default());
            let param = |name: &str| {
                let found = params.iter().find(|(key, _)| key == name);
                found.map(|(_, value)| value.as_str()).unwrap_or_default()
            };
            let after = param("after").parse().unwrap_or(0);
            let limit = param("limit").parse().unwrap_or(MAX_EVENTS_PER_PAGE);
            let limit = limit.min(MAX_EVENTS_PER_PAGE);
            let events = ctx.state.events();
            let page = EventsPage {
                events: events.since(after, limit),
                last_id: events.last_id(),
            };
            json(StatusCode::OK, &page)
        }
        (&Method::POST, ["v1", "shutdown"]) => {
            ctx.shutdown.cancel();
            json(StatusCode::OK, &serde_json::json!({ "ok": true }))
        }
        _ => error(StatusCode::NOT_FOUND, &format!("unknown route: {path}")),
    }
}

fn json<T: Serialize>(status: StatusCode, value: &T) -> Response<Full<Bytes>> {
    let body = serde_json::to_vec(value).expect("control API types always serialize");
    let mut response = Response::new(Full::new(Bytes::from(body)));
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    response
}

fn error(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    json(
        status,
        &ApiError {
            error: message.to_owned(),
        },
    )
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::control::{ClientError, ControlClient};
    use crate::events::{Event, EventKind};
    use crate::rules::RuleSet;
    use crate::rules::test_support::rule;
    use http_body_util::BodyExt;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub(crate) fn status_stub() -> StatusInfo {
        StatusInfo {
            version: "0.0.0".into(),
            pid: 1,
            listen: "127.0.0.1:1".into(),
            started_at_ms: 0,
            config_file: "c.yaml".into(),
            mock_files: Vec::new(),
            rules_total: 0,
            rules_enabled: 0,
            intercepted_hosts: Vec::new(),
            ca_cert: "ca.pem".into(),
            last_reload_ms: 0,
            last_reload_error: None,
            warnings: Vec::new(),
        }
    }

    pub(crate) fn context() -> ControlContext {
        let state = Arc::new(AppState::new(RuleSet::new(vec![
            rule("a#1", "a.com", None, ""),
            rule("b", "b.com", None, ""),
        ])));
        ControlContext {
            state,
            status: Arc::new(status_stub),
            reload: Arc::new(|| ReloadResult {
                ok: true,
                rules: 2,
                error: None,
                warnings: Vec::new(),
            }),
            shutdown: CancellationToken::new(),
        }
    }

    async fn call(
        ctx: &ControlContext,
        method: Method,
        uri: &str,
    ) -> (StatusCode, serde_json::Value) {
        let req = Request::builder().method(method).uri(uri).body(()).unwrap();
        let response = handle(ctx, req).await;
        let status = response.status();
        assert_eq!(response.headers()[CONTENT_TYPE], "application/json");
        let body = response.into_body().collect().await.unwrap().to_bytes();
        (status, serde_json::from_slice(&body).unwrap())
    }

    #[tokio::test]
    async fn status_and_rules() {
        let ctx = context();
        let (status, body) = call(&ctx, Method::GET, "/v1/status").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["listen"], "127.0.0.1:1");

        let (status, body) = call(&ctx, Method::GET, "/v1/rules").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body.as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn toggling_rules_accepts_encoded_names() {
        let ctx = context();
        let (status, body) = call(&ctx, Method::POST, "/v1/rules/a%231/disable").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body[0]["enabled"], false);
        assert_eq!(body[0]["overridden"], true);

        let (status, _) = call(&ctx, Method::POST, "/v1/rules/a%231/enable").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(ctx.state.override_for("a#1"), None);

        let (status, body) = call(&ctx, Method::POST, "/v1/rules/zzz/enable").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "rule not found: zzz");
    }

    #[tokio::test]
    async fn reload_calls_the_callback() {
        let (status, body) = call(&context(), Method::POST, "/v1/reload").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["rules"], 2);
    }

    #[tokio::test]
    async fn panicking_reload_is_reported_as_server_error() {
        let mut ctx = context();
        ctx.reload = Arc::new(|| panic!("reload exploded"));
        let (status, body) = call(&ctx, Method::POST, "/v1/reload").await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body["error"].as_str().unwrap().contains("panicked"));
    }

    #[tokio::test]
    async fn events_support_after_and_limit() {
        let ctx = context();
        for i in 0..5 {
            ctx.state
                .events()
                .push(Event::new(EventKind::Pass, "GET", format!("u{i}")));
        }
        let (_, body) = call(&ctx, Method::GET, "/v1/events?after=3").await;
        assert_eq!(body["last_id"], 5);
        assert_eq!(body["events"].as_array().unwrap().len(), 2);

        let (_, body) = call(&ctx, Method::GET, "/v1/events?limit=1").await;
        assert_eq!(body["events"].as_array().unwrap().len(), 1);
        assert_eq!(body["events"][0]["id"], 5);

        let (_, body) = call(&ctx, Method::GET, "/v1/events?limit=99999&after=x").await;
        assert_eq!(body["events"].as_array().unwrap().len(), 5);
    }

    #[tokio::test]
    async fn shutdown_cancels_the_token() {
        let ctx = context();
        let (status, _) = call(&ctx, Method::POST, "/v1/shutdown").await;
        assert_eq!(status, StatusCode::OK);
        assert!(ctx.shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn unknown_routes_return_404() {
        let ctx = context();
        let (status, body) = call(&ctx, Method::GET, "/v1/nothing").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(body["error"], "unknown route: /v1/nothing");
        let (status, _) = call(&ctx, Method::GET, "/v1/reload").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn socket_is_private_and_removed_on_shutdown() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sock");
        let ctx = context();
        let server = ControlServer::bind(&path, ctx.clone()).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        ctx.shutdown.cancel();
        server.wait().await;
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn binding_twice_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sock");
        let ctx = context();
        let _server = ControlServer::bind(&path, ctx.clone()).unwrap();
        assert!(ControlServer::bind(&path, ctx.clone()).is_err());
        ctx.shutdown.cancel();
    }

    #[tokio::test]
    async fn connections_from_other_users_are_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sock");
        let ctx = context();
        let other_uid = crate::sys::euid().wrapping_add(1);
        let _server = ControlServer::bind_for_uid(&path, ctx.clone(), other_uid).unwrap();
        let err = ControlClient::new(&path).status().await.unwrap_err();
        assert!(matches!(err, ClientError::Transport(_)), "{err:?}");
        ctx.shutdown.cancel();
    }

    #[tokio::test]
    async fn malformed_requests_close_the_connection() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.sock");
        let ctx = context();
        let _server = ControlServer::bind(&path, ctx.clone()).unwrap();
        let mut stream = UnixStream::connect(&path).await.unwrap();
        stream.write_all(b"NOT HTTP\r\n\r\n").await.unwrap();
        let mut answer = Vec::new();
        stream.read_to_end(&mut answer).await.unwrap();
        assert!(String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 400"));
        ctx.shutdown.cancel();
    }
}
