//! Integration tests for the daemon: control API, hot reload, single instance.
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{TestEnv, client_via, eventually, free_port, start_upstream_http};
use fauxy::control::ControlClient;
use fauxy::daemon::process::locked_pid;
use fauxy::daemon::{Daemon, RunOptions};
use std::time::{Duration, Instant};

const CONFIG: &str = "listen: 127.0.0.1:0\n";

fn mock_for(host: &str, name: &str, body: &str) -> String {
    format!("host: {host}\nrules:\n  - name: {name}\n    respond: {{ body: {body} }}\n")
}

#[tokio::test]
async fn control_api_toggles_rules_and_reports_status() {
    let env = TestEnv::new();
    let upstream = start_upstream_http().await;
    env.write_config("config.yaml", CONFIG);
    env.write_mock("a.yaml", &mock_for("127.0.0.1", "local", "mock"));

    let daemon = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();
    let client = ControlClient::new(env.paths.socket());

    let status = client.status().await.unwrap();
    assert_eq!(status.listen, daemon.proxy_addr().to_string());
    assert_eq!(status.pid, std::process::id());
    assert_eq!(status.rules_total, 1);
    assert_eq!(status.intercepted_hosts, vec!["127.0.0.1"]);
    assert_eq!(locked_pid(&env.paths.pid_file()), Some(std::process::id()));

    let http = client_via(&format!("http://{}", daemon.proxy_addr()), &[]);
    let url = format!("http://{upstream}/x");
    assert_eq!(
        http.get(&url).send().await.unwrap().text().await.unwrap(),
        "mock"
    );

    let rules = client.set_rule_enabled("local", false).await.unwrap();
    assert!(!rules[0].enabled && rules[0].overridden);
    assert_eq!(
        http.get(&url).send().await.unwrap().text().await.unwrap(),
        "upstream GET /x"
    );

    let page = client.events(0, 10).await.unwrap();
    assert_eq!(page.events.len(), 2);
    assert_eq!(client.rules().await.unwrap()[0].hits, 1);

    client.shutdown().await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), daemon.wait())
        .await
        .expect("the daemon must stop")
        .unwrap();
    assert!(!env.paths.socket().exists());
    assert_eq!(locked_pid(&env.paths.pid_file()), None);
}

#[tokio::test]
async fn rules_are_reloaded_when_files_change() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    env.write_mock("a.yaml", &mock_for("a.test", "a", "a"));

    let daemon = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();
    let state = daemon.state().clone();
    let http = client_via(&format!("http://{}", daemon.proxy_addr()), &[]);

    env.write_mock("b.yaml", &mock_for("b.test", "b", "new"));
    assert!(
        eventually(Duration::from_secs(10), || state.rules().len() == 2).await,
        "the new rule must be loaded automatically"
    );
    let body = http
        .get("http://b.test/")
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert_eq!(body, "new");

    env.write_mock("a.yaml", &mock_for("a.test", "a", "changed"));
    let changed = eventually(Duration::from_secs(10), || {
        state.rules().get("a").is_some_and(|rule| {
            matches!(&rule.response.body, fauxy::rules::MockBody::Inline { data, .. } if data.as_ref() == b"changed")
        })
    })
    .await;
    assert!(changed, "the edited rule must be reloaded");

    // An invalid file keeps the previous rules and reports the error.
    env.write_mock("c.yaml", "rules: [\n");
    assert!(
        eventually(Duration::from_secs(10), || state
            .info()
            .last_reload_error
            .is_some())
        .await
    );
    assert_eq!(state.rules().len(), 2);
    let status = ControlClient::new(env.paths.socket())
        .status()
        .await
        .unwrap();
    assert!(status.last_reload_error.unwrap().contains("c.yaml"));

    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
}

#[tokio::test]
async fn manual_reload_reports_errors() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    env.write_mock("a.yaml", &mock_for("a.test", "a", "a"));
    let options = RunOptions {
        no_watch: true,
        ..RunOptions::default()
    };
    let daemon = Daemon::start(env.paths.clone(), options).await.unwrap();
    let client = ControlClient::new(env.paths.socket());

    env.write_mock("b.yaml", &mock_for("b.test", "b", "b"));
    let result = client.reload().await.unwrap();
    assert!(result.ok);
    assert_eq!(result.rules, 2);

    env.write_mock(
        "b.yaml",
        "host: b.test\nrules:\n  - respond: { status: 1 }\n",
    );
    let result = client.reload().await.unwrap();
    assert!(!result.ok);
    assert!(result.error.unwrap().contains("invalid status 1"));
    assert_eq!(client.rules().await.unwrap().len(), 2);

    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
}

#[tokio::test]
async fn only_one_instance_runs_per_state_dir() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    let first = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();

    let second = Daemon::start(env.paths.clone(), RunOptions::default()).await;
    let message = second
        .err()
        .expect("a second instance must fail")
        .to_string();
    assert_eq!(
        message,
        format!(
            "fauxy is already running (pid {}); stop it first, or set FAUXY_STATE_DIR to run another instance",
            std::process::id()
        )
    );
    assert!(
        env.paths.socket().exists(),
        "the running daemon keeps its socket"
    );

    first.shutdown_token().cancel();
    first.wait().await.unwrap();
}

#[tokio::test]
async fn stale_socket_and_pid_files_are_replaced() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    env.paths.ensure_state_dir().unwrap();
    drop(std::os::unix::net::UnixListener::bind(env.paths.socket()).unwrap());
    std::fs::write(env.paths.pid_file(), "999999\n").unwrap();

    let daemon = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();
    let status = ControlClient::new(env.paths.socket())
        .status()
        .await
        .unwrap();
    assert_eq!(status.pid, std::process::id());
    assert_eq!(locked_pid(&env.paths.pid_file()), Some(std::process::id()));
    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
}

#[tokio::test]
async fn invalid_configuration_prevents_start() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    env.write_mock("bad.yaml", "rules:\n  - respond: {}\n");
    let result = Daemon::start(env.paths.clone(), RunOptions::default()).await;
    let message = format!("{:#}", result.err().unwrap());
    assert!(message.starts_with("invalid configuration:"), "{message}");
    assert!(message.contains("rule has no host"), "{message}");
    assert!(!env.paths.socket().exists());
    assert_eq!(
        locked_pid(&env.paths.pid_file()),
        None,
        "the lock is released on failure"
    );
}

#[tokio::test]
async fn port_option_overrides_the_configuration() {
    let env = TestEnv::new();
    let config = env.write_config("config.yaml", "listen: 127.0.0.1:8899\n");
    let mut attempts = 0;
    let (daemon, port) = loop {
        let port = free_port();
        let options = RunOptions {
            port: Some(port),
            ..RunOptions::default()
        };
        match Daemon::start(env.paths.clone(), options).await {
            Ok(daemon) => break (daemon, port),
            Err(err) if attempts < 3 && format!("{err:#}").contains("already in use") => {
                attempts += 1;
            }
            Err(err) => panic!("{err:#}"),
        }
    };
    assert_eq!(daemon.proxy_addr().port(), port);
    let status = ControlClient::new(env.paths.socket())
        .status()
        .await
        .unwrap();
    assert_eq!(status.listen, format!("127.0.0.1:{port}"));
    assert_eq!(
        std::fs::read_to_string(config).unwrap(),
        "listen: 127.0.0.1:8899\n",
        "the configuration is not changed"
    );
    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
}

#[tokio::test]
async fn busy_port_given_as_option_is_reported() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let options = RunOptions {
        port: Some(busy.local_addr().unwrap().port()),
        ..RunOptions::default()
    };
    let result = Daemon::start(env.paths.clone(), options).await;
    let message = format!("{:#}", result.err().unwrap());
    assert!(message.contains("is already in use"), "{message}");
    assert!(message.ends_with("pass another --port"), "{message}");
}

#[tokio::test]
async fn busy_port_is_reported() {
    let env = TestEnv::new();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = busy.local_addr().unwrap();
    env.write_config("config.yaml", &format!("listen: {addr}\n"));
    let result = Daemon::start(env.paths.clone(), RunOptions::default()).await;
    let message = format!("{:#}", result.err().unwrap());
    let port = addr.port();
    assert!(
        message.starts_with(&format!("port {port} is already in use ({addr}); ")),
        "{message}"
    );
    assert!(message.contains("fauxy init --port <port>"), "{message}");
    assert!(
        message.ends_with("then run 'fauxy restart' (or restart the service)"),
        "{message}"
    );
}

#[tokio::test]
async fn unusable_state_directories_are_reported() {
    let env = TestEnv::new();
    let blocker = env.dir.path().join("file");
    std::fs::write(&blocker, "").unwrap();
    let mut paths = env.paths.clone();
    paths.state_dir = blocker.join("state");
    let message = format!(
        "{:#}",
        Daemon::start(paths, RunOptions::default())
            .await
            .err()
            .unwrap()
    );
    assert!(message.starts_with("cannot create"), "{message}");
}

#[tokio::test]
async fn sockets_that_cannot_be_replaced_are_reported() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    std::fs::create_dir_all(env.paths.socket().join("occupied")).unwrap();
    let result = Daemon::start(env.paths.clone(), RunOptions::default()).await;
    let message = format!("{:#}", result.err().unwrap());
    assert!(message.starts_with("cannot remove"), "{message}");
}

#[tokio::test]
async fn overlong_socket_paths_are_reported() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    let mut paths = env.paths.clone();
    paths.state_dir = env.dir.path().join("s".repeat(120));
    let result = Daemon::start(paths, RunOptions::default()).await;
    let message = format!("{:#}", result.err().unwrap());
    assert!(message.starts_with("the control socket path"), "{message}");
    assert!(message.contains("is too long"), "{message}");
}

#[tokio::test]
async fn shutdown_does_not_wait_forever_for_open_connections() {
    let env = TestEnv::new();
    env.write_config("config.yaml", CONFIG);
    env.write_mock(
        "hang.yaml",
        "host: hang.test\nrules:\n  - respond: { body: late, delay: 60s }\n",
    );
    let daemon = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();
    let http = client_via(&format!("http://{}", daemon.proxy_addr()), &[]);
    let pending = tokio::spawn(async move { http.get("http://hang.test/").send().await });
    tokio::time::sleep(Duration::from_millis(300)).await;

    let started = Instant::now();
    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
    let elapsed = started.elapsed();
    assert!(elapsed >= Duration::from_secs(4), "{elapsed:?}");
    assert!(elapsed < Duration::from_secs(15), "{elapsed:?}");
    pending.abort();
}
