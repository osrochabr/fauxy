//! Integration tests for the proxy: mocks, pass-through, MITM and tunnels.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{MAIL_API, TestEnv, TestProxy, client_via, start_upstream_http, start_upstream_https};
use fauxy::events::EventKind;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn https_mail_api_is_mocked_per_route() {
    let env = TestEnv::new();
    env.write_mock("mail.yaml", MAIL_API);
    let proxy = TestProxy::start(&env).await;
    let client = proxy.client_trusting_ca();
    let base = "https://mail.example.com";

    let response = client
        .get(format!("{base}/templates/WELCOME"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.headers()["x-fauxy-rule"], "mail-template");
    let template: serde_json::Value =
        serde_json::from_str(&response.text().await.unwrap()).unwrap();
    assert_eq!(template["subject"], "Welcome");

    let response = client
        .post(format!("{base}/messages"))
        .body(r#"{"to":"a@example.com"}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.text().await.unwrap(), "{}");

    let response = client
        .put(format!("{base}/anything?x=1"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-fauxy-rule"], "mail-catch-all");

    assert_eq!(proxy.state.hits("mail-template"), 1);
    assert_eq!(proxy.state.hits("mail-send"), 1);
    let events = proxy.state.events().since(0, 10);
    assert_eq!(events.len(), 3);
    assert!(events.iter().all(|e| e.kind == EventKind::Mock));
    assert_eq!(events[1].url, "https://mail.example.com/messages");
    assert_eq!(events[1].status, Some(201));
}

#[tokio::test]
async fn http_requests_are_mocked_or_forwarded() {
    let env = TestEnv::new();
    let upstream = start_upstream_http().await;
    let fixture = env.write_mock("fixtures/user.json", r#"{"id": 7}"#);
    env.write_mock(
        "http.yaml",
        &format!(
            r#"
host: 127.0.0.1
rules:
  - name: user
    match: {{ method: GET, path: /users/:id }}
    respond: {{ file: {} }}
  - name: created
    match: {{ method: POST, path: /users }}
    respond: {{ status: 201, headers: {{ Location: /users/9 }}, body: created }}
"#,
            fixture.display()
        ),
    );
    let proxy = TestProxy::start(&env).await;
    let client = proxy.client(&[]);
    let base = format!("http://{upstream}");

    let response = client.get(format!("{base}/users/7")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["content-type"], "application/json");
    assert_eq!(response.text().await.unwrap(), r#"{"id": 7}"#);

    let response = client.post(format!("{base}/users")).send().await.unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.headers()["location"], "/users/9");
    assert_eq!(response.text().await.unwrap(), "created");

    let response = client.get(format!("{base}/other")).send().await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["x-upstream"], "yes");
    assert!(response.headers().get("x-fauxy-rule").is_none());
    assert_eq!(response.text().await.unwrap(), "upstream GET /other");

    let events = proxy.state.events().since(0, 10);
    let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
    assert_eq!(
        kinds,
        vec![EventKind::Mock, EventKind::Mock, EventKind::Pass]
    );
    assert_eq!(events[2].status, Some(200));
    assert!(events[2].duration_ms.is_some());
    assert!(
        events[2]
            .response_headers
            .iter()
            .any(|(name, _)| name == "x-upstream")
    );
}

#[tokio::test]
async fn deleted_response_files_yield_server_errors() {
    let env = TestEnv::new();
    let fixture = env.write_mock("fixtures/gone.json", "{}");
    env.write_mock(
        "gone.yaml",
        &format!(
            "host: gone.test\nrules:\n  - respond: {{ file: {} }}\n",
            fixture.display()
        ),
    );
    let proxy = TestProxy::start(&env).await;
    std::fs::remove_file(&fixture).unwrap();
    let response = proxy
        .client(&[])
        .get("http://gone.test/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 500);
    assert!(
        response
            .text()
            .await
            .unwrap()
            .starts_with("fauxy: rule 'gone#1': failed to read")
    );
    assert_eq!(proxy.state.events().since(0, 1)[0].kind, EventKind::Error);
}

#[tokio::test]
async fn runtime_toggle_switches_between_mock_and_upstream() {
    let env = TestEnv::new();
    let upstream = start_upstream_http().await;
    env.write_mock(
        "toggle.yaml",
        "host: 127.0.0.1\nrules:\n  - name: target\n    respond: { body: mock }\n",
    );
    let proxy = TestProxy::start(&env).await;
    let client = proxy.client(&[]);
    let url = format!("http://{upstream}/x");
    let fetch = || async { client.get(&url).send().await.unwrap().text().await.unwrap() };

    assert_eq!(fetch().await, "mock");
    proxy.state.set_enabled("target", false).unwrap();
    assert_eq!(fetch().await, "upstream GET /x");
    proxy.state.set_enabled("target", true).unwrap();
    assert_eq!(fetch().await, "mock");
}

#[tokio::test]
async fn delay_is_applied_to_mocked_responses() {
    let env = TestEnv::new();
    env.write_mock(
        "slow.yaml",
        "host: slow.test\nrules:\n  - respond: { body: ok, delay: 300ms }\n",
    );
    let proxy = TestProxy::start(&env).await;
    let started = Instant::now();
    let response = proxy
        .client(&[])
        .get("http://slow.test/")
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().await.unwrap(), "ok");
    assert!(started.elapsed() >= Duration::from_millis(300));
}

#[tokio::test]
async fn hosts_without_rules_are_tunneled_without_interception() {
    let env = TestEnv::new();
    let upstream = start_upstream_https(env.dir.path()).await;
    env.write_mock(
        "other.yaml",
        "host: other-host.test\nrules:\n  - respond: {}\n",
    );
    let proxy = TestProxy::start(&env).await;
    let url = format!("https://localhost:{}/tunnel", upstream.addr.port());

    // A client trusting only the upstream CA succeeds: it sees the real
    // certificate, so the connection was not intercepted.
    let client = proxy.client(&[&upstream.ca_pem]);
    let response = client.get(&url).send().await.unwrap();
    assert_eq!(response.text().await.unwrap(), "upstream GET /tunnel");

    // A client trusting only the fauxy CA fails for the same reason.
    assert!(proxy.client_trusting_ca().get(&url).send().await.is_err());

    let events = proxy.state.events().since(0, 10);
    assert!(events.iter().all(|e| e.kind == EventKind::Tunnel));
    assert_eq!(events[0].url, format!("localhost:{}", upstream.addr.port()));
}

#[tokio::test]
async fn unmatched_paths_on_intercepted_hosts_reach_the_real_server() {
    let env = TestEnv::new();
    let upstream = start_upstream_https(env.dir.path()).await;
    env.write_config(
        "config.yaml",
        &format!("upstream:\n  ca_files: [{}]\n", upstream.ca_file.display()),
    );
    env.write_mock(
        "local.yaml",
        "host: localhost\nrules:\n  - name: only-mock\n    match: { path: /mock }\n    respond: { body: intercepted }\n",
    );
    let proxy = TestProxy::start(&env).await;
    let client = proxy.client_trusting_ca();
    let base = format!("https://localhost:{}", upstream.addr.port());

    let mocked = client.get(format!("{base}/mock")).send().await.unwrap();
    assert_eq!(mocked.text().await.unwrap(), "intercepted");

    let forwarded = client.get(format!("{base}/real")).send().await.unwrap();
    assert_eq!(forwarded.headers()["x-upstream"], "yes");
    assert_eq!(forwarded.text().await.unwrap(), "upstream GET /real");

    let events = proxy.state.events().since(0, 10);
    let kinds: Vec<EventKind> = events.iter().map(|e| e.kind).collect();
    assert_eq!(kinds, vec![EventKind::Mock, EventKind::Pass]);
    assert_eq!(
        events[1].url,
        format!("https://localhost:{}/real", upstream.addr.port())
    );
}

#[tokio::test]
async fn upstream_without_trusted_certificate_yields_bad_gateway() {
    let env = TestEnv::new();
    let upstream = start_upstream_https(env.dir.path()).await;
    env.write_mock(
        "local.yaml",
        "host: localhost\nrules:\n  - match: { path: /mock }\n    respond: {}\n",
    );
    let proxy = TestProxy::start(&env).await;
    let response = proxy
        .client_trusting_ca()
        .get(format!("https://localhost:{}/real", upstream.addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    let text = response.text().await.unwrap();
    assert!(
        text.starts_with("fauxy: failed to reach the upstream server"),
        "{text}"
    );
    let events = proxy.state.events().since(0, 10);
    assert_eq!(events[0].kind, EventKind::Error);
    assert_eq!(events[0].status, Some(502));
    assert!(events[0].error.is_some());
}

#[tokio::test]
async fn unreachable_upstream_yields_bad_gateway() {
    let env = TestEnv::new();
    let proxy = TestProxy::start(&env).await;
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap()
    };
    let response = client_via(&proxy.url(), &[])
        .get(format!("http://{closed}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 502);
    assert_eq!(proxy.state.events().since(0, 10)[0].kind, EventKind::Error);
}

#[tokio::test]
async fn websocket_upgrades_are_relayed_and_recorded_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = hudsucker::tokio_tungstenite::accept_async(stream).await;
    });
    let env = TestEnv::new();
    let proxy = TestProxy::start(&env).await;

    let mut stream = tokio::net::TcpStream::connect(proxy.addr).await.unwrap();
    let request = format!(
        "GET http://{upstream}/ws HTTP/1.1\r\nHost: {upstream}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
    );
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = [0_u8; 12];
    stream.read_exact(&mut answer).await.unwrap();
    assert_eq!(&answer, b"HTTP/1.1 101");

    let events = proxy.state.events().since(0, 10);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, EventKind::Pass);
    assert_eq!(events[0].url, format!("http://{upstream}/ws"));
}

#[tokio::test]
async fn requests_sent_directly_to_the_proxy_are_refused() {
    // A web page reaching 127.0.0.1 through DNS rebinding sends origin-form
    // requests with its own Host header; they must never get mocks.
    let env = TestEnv::new();
    env.write_mock(
        "local.yaml",
        "host: 127.0.0.1\nrules:\n  - respond: { body: secret }\n",
    );
    let proxy = TestProxy::start(&env).await;
    let direct = reqwest::Client::builder().no_proxy().build().unwrap();
    let response = direct.get(proxy.url()).send().await.unwrap();
    assert_eq!(response.status(), 400);
    assert_eq!(
        response.text().await.unwrap(),
        "fauxy is a proxy: configure it as the HTTP proxy of your client\n"
    );
    assert_eq!(proxy.state.hits("local#1"), 0);
}

#[tokio::test]
async fn wildcard_hosts_are_intercepted_over_tls() {
    let env = TestEnv::new();
    env.write_mock(
        "wild.yaml",
        "host: '*.example.test'\nrules:\n  - respond: { body: wildcard }\n",
    );
    let proxy = TestProxy::start(&env).await;
    let response = proxy
        .client_trusting_ca()
        .get("https://api.eu.example.test/x")
        .send()
        .await
        .unwrap();
    assert_eq!(response.headers()["x-fauxy-rule"], "wild#1");
    assert_eq!(response.text().await.unwrap(), "wildcard");
}
