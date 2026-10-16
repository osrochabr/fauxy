use crate::events::{Event, EventKind, body_preview, header_pairs};
use crate::rules::{RequestInfo, Rule};
use crate::state::AppState;
use hudsucker::hyper::header::{CONNECTION, CONTENT_TYPE, HeaderValue, UPGRADE};
use hudsucker::hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hudsucker::{Body, HttpContext, HttpHandler, RequestOrResponse};
use std::sync::Arc;
use std::time::Instant;

/// hudsucker clones the handler for every request, so `pending` links a
/// forwarded request to its response.
#[derive(Clone)]
pub struct FauxyHandler {
    state: Arc<AppState>,
    pending: Option<Pending>,
}

#[derive(Clone)]
struct Pending {
    started: Instant,
    event: Event,
}

impl FauxyHandler {
    pub fn new(state: Arc<AppState>) -> Self {
        Self {
            state,
            pending: None,
        }
    }

    async fn mock_response(&self, req: &Request<Body>, rule: Rule) -> Response<Body> {
        let started = Instant::now();
        let mut event = request_event(EventKind::Mock, req);
        event.rule = Some(rule.name.clone());

        if let Some(delay) = rule.response.delay {
            tokio::time::sleep(delay).await;
        }

        let response = match rule.response.render(&rule.name).await {
            Ok(rendered) => {
                event.status = Some(rendered.status.as_u16());
                event.response_headers = header_pairs(&rendered.headers);
                event.response_body = Some(body_preview(&rendered.body));
                self.state.record_hit(&rule.name);
                rendered.into_response()
            }
            Err(err) => {
                event.kind = EventKind::Error;
                event.status = Some(StatusCode::INTERNAL_SERVER_ERROR.as_u16());
                event.error = Some(err.to_string());
                let message = format!("fauxy: rule '{}': {err}", rule.name);
                error_response(StatusCode::INTERNAL_SERVER_ERROR, &message)
            }
        };
        event.duration_ms = Some(elapsed_ms(started));
        self.state.record(event);
        response
    }
}

impl HttpHandler for FauxyHandler {
    async fn handle_request(
        &mut self,
        _ctx: &HttpContext,
        req: Request<Body>,
    ) -> RequestOrResponse {
        if req.method() == Method::CONNECT {
            return req.into();
        }
        // Proxied requests carry an absolute URI. Anything else was sent to
        // fauxy directly (for example by a web page through DNS rebinding).
        if req.uri().authority().is_none() {
            let message = "fauxy is a proxy: configure it as the HTTP proxy of your client";
            return error_response(StatusCode::BAD_REQUEST, message).into();
        }
        let matched = RequestInfo::from_request(&req).and_then(|info| self.state.find_match(&info));
        if let Some(rule) = matched {
            return self.mock_response(&req, rule).await.into();
        }

        let event = request_event(EventKind::Pass, &req);
        if is_websocket_upgrade(req.headers()) {
            // hudsucker does not call handle_response for WebSocket upgrades.
            self.state.record(event);
        } else {
            self.pending = Some(Pending {
                started: Instant::now(),
                event,
            });
        }
        req.into()
    }

    async fn handle_response(&mut self, _ctx: &HttpContext, res: Response<Body>) -> Response<Body> {
        if let Some(Pending { started, mut event }) = self.pending.take() {
            event.status = Some(res.status().as_u16());
            event.response_headers = header_pairs(res.headers());
            event.duration_ms = Some(elapsed_ms(started));
            self.state.record(event);
        }
        res
    }

    async fn handle_error(
        &mut self,
        _ctx: &HttpContext,
        err: hudsucker::hyper_util::client::legacy::Error,
    ) -> Response<Body> {
        let message = error_chain(&err);
        if let Some(Pending { started, mut event }) = self.pending.take() {
            event.kind = EventKind::Error;
            event.status = Some(StatusCode::BAD_GATEWAY.as_u16());
            event.duration_ms = Some(elapsed_ms(started));
            event.error = Some(message.clone());
            self.state.record(event);
        }
        let message = format!("fauxy: failed to reach the upstream server: {message}");
        error_response(StatusCode::BAD_GATEWAY, &message)
    }

    async fn should_intercept_connect(&mut self, _ctx: &HttpContext, req: &Request<Body>) -> bool {
        let uri = req.uri();
        let host = uri.host().unwrap_or_default();
        let host = host.trim_start_matches('[').trim_end_matches(']');
        let intercept = self
            .state
            .should_intercept(host, uri.port_u16().unwrap_or(443));
        if !intercept {
            let event = Event::new(EventKind::Tunnel, "CONNECT", uri.to_string());
            self.state.record(event);
        }
        intercept
    }
}

fn request_event(kind: EventKind, req: &Request<Body>) -> Event {
    let mut event = Event::new(kind, req.method().as_str(), display_url(req.uri()));
    event.request_headers = header_pairs(req.headers());
    event
}

/// Same test as hudsucker, which skips `handle_response` for these requests.
fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    let has = |name, token: &str| {
        headers.get_all(name).iter().any(|value| {
            let mut tokens = value.as_bytes().split(|byte| *byte == b',');
            tokens.any(|part| part.trim_ascii().eq_ignore_ascii_case(token.as_bytes()))
        })
    };
    has(CONNECTION, "upgrade") && has(UPGRADE, "websocket")
}

/// Formats a request URI omitting the default port of its scheme.
fn display_url(uri: &Uri) -> String {
    let default_port = match uri.scheme_str() {
        Some("https") => Some(443),
        Some("http") => Some(80),
        _ => None,
    };
    match (uri.scheme_str(), uri.host(), uri.port_u16()) {
        (Some(scheme), Some(host), port) if port == default_port => {
            let path = uri.path_and_query().map_or("/", |pq| pq.as_str());
            format!("{scheme}://{host}{path}")
        }
        _ => uri.to_string(),
    }
}

fn error_response(status: StatusCode, message: &str) -> Response<Body> {
    let mut response = Response::new(Body::from(format!("{message}\n")));
    *response.status_mut() = status;
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    response
}

fn error_chain(err: &(dyn std::error::Error + 'static)) -> String {
    let mut message = err.to_string();
    let mut source = err.source();
    while let Some(cause) = source {
        message.push_str(": ");
        message.push_str(&cause.to_string());
        source = cause.source();
    }
    message
}

fn elapsed_ms(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;
    use crate::rules::test_support::rule;
    use http_body_util::BodyExt;

    // `HttpContext` is non-exhaustive, so the `HttpHandler` methods are covered
    // by the integration tests in `tests/`; the helpers are tested here.

    fn handler(rules: Vec<Rule>) -> (FauxyHandler, Arc<AppState>) {
        let state = Arc::new(AppState::new(RuleSet::new(rules)));
        (FauxyHandler::new(Arc::clone(&state)), state)
    }

    async fn body_text(response: Response<Body>) -> String {
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn matching_request_gets_mock_and_is_recorded() {
        let (handler, state) = handler(vec![rule("r", "x.com", None, "hello")]);
        let req = Request::get("https://x.com/a").body(Body::empty()).unwrap();
        let rule = state
            .find_match(&RequestInfo::from_request(&req).unwrap())
            .unwrap();
        let response = handler.mock_response(&req, rule).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[crate::rules::RULE_HEADER], "r");
        assert_eq!(body_text(response).await, "hello");

        assert_eq!(state.hits("r"), 1);
        let events = state.events().since(0, 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, EventKind::Mock);
        assert_eq!(events[0].rule.as_deref(), Some("r"));
        assert_eq!(events[0].response_body.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn unreadable_mock_file_yields_500() {
        let mut broken = rule("r", "x.com", None, "");
        broken.response.body = crate::rules::MockBody::File {
            path: "/does/not/exist".into(),
            root: "/does".into(),
        };
        let (handler, state) = handler(vec![broken.clone()]);
        let req = Request::get("https://x.com/").body(Body::empty()).unwrap();
        let response = handler.mock_response(&req, broken).await;
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let text = body_text(response).await;
        assert!(
            text.starts_with("fauxy: rule 'r': failed to read '/does/not/exist'"),
            "{text}"
        );
        let events = state.events().since(0, 10);
        assert_eq!(events[0].kind, EventKind::Error);
        assert_eq!(state.hits("r"), 0);
    }

    #[tokio::test]
    async fn delay_is_applied() {
        let mut slow = rule("r", "x.com", None, "");
        slow.response.delay = Some(std::time::Duration::from_millis(120));
        let (handler, _state) = handler(vec![slow.clone()]);
        let req = Request::get("https://x.com/").body(Body::empty()).unwrap();
        let started = Instant::now();
        handler.mock_response(&req, slow).await;
        assert!(started.elapsed() >= std::time::Duration::from_millis(120));
    }

    #[test]
    fn display_url_omits_default_ports() {
        let url = |raw: &str| display_url(&raw.parse().unwrap());
        assert_eq!(url("https://x.com:443/a?b=1"), "https://x.com/a?b=1");
        assert_eq!(url("http://x.com:80/"), "http://x.com/");
        assert_eq!(url("https://x.com:8443/a"), "https://x.com:8443/a");
        assert_eq!(url("http://x.com/a"), "http://x.com/a");
        assert_eq!(url("/path-only"), "/path-only");
    }

    #[test]
    fn websocket_upgrades_are_detected() {
        let headers = |pairs: &[(&str, &str)]| {
            let mut map = HeaderMap::new();
            for (name, value) in pairs {
                map.append(
                    hudsucker::hyper::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                );
            }
            map
        };
        assert!(is_websocket_upgrade(&headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "WebSocket"),
        ])));
        assert!(!is_websocket_upgrade(&headers(&[("upgrade", "websocket")])));
        assert!(!is_websocket_upgrade(&headers(&[
            ("connection", "upgrade"),
            ("upgrade", "h2c"),
        ])));
        assert!(!is_websocket_upgrade(&headers(&[
            ("connection", "upgraded"),
            ("upgrade", "websocket"),
        ])));
    }

    #[test]
    fn error_chain_joins_sources() {
        let outer = OuterError(std::io::Error::other("root cause"));
        assert_eq!(error_chain(&outer), "outer: root cause");
        assert_eq!(outer.to_string(), "outer");
    }

    #[derive(Debug)]
    struct OuterError(std::io::Error);

    impl std::fmt::Display for OuterError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("outer")
        }
    }

    impl std::error::Error for OuterError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }
}
