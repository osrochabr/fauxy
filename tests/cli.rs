//! Integration tests running the real `fauxy` binary.
//!
//! System integrations (keychain, launchd/systemd, keytool) run against fake
//! executables placed first on the PATH, so the tests never touch the real
//! system configuration.
#![allow(clippy::unwrap_used, clippy::expect_used, unsafe_code)]

mod common;

use common::{MAIL_API, TestEnv, client_via, write_script};
use fauxy::control::ControlClient;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn command(env: &TestEnv, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fauxy"));
    command
        .args(args)
        .env("HOME", env.dir.path())
        .env("FAUXY_CONFIG_DIR", &env.paths.config_dir)
        .env("FAUXY_STATE_DIR", &env.paths.state_dir)
        .env("SHELL", "/bin/zsh")
        .env_remove("FAUXY_CONFIG")
        .env_remove("FAUXY_LOG")
        .env_remove("XDG_CONFIG_HOME")
        .env_remove("XDG_STATE_HOME")
        .env_remove("JAVA_HOME")
        .env_remove("VISUAL")
        .env_remove("EDITOR");
    command
}

fn fauxy(env: &TestEnv, args: &[&str]) -> Output {
    command(env, args).output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn wait_until(timeout: Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while !condition() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    true
}

fn wait_for_exit(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "the process did not exit");
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn signal(child: &Child, signal: i32) {
    fauxy::sys::send_signal(i32::try_from(child.id()).unwrap(), signal).unwrap();
}

/// Stops the background daemon even if the test fails midway.
struct StopOnDrop<'a>(&'a TestEnv);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = fauxy(self.0, &["stop"]);
    }
}

/// A directory with fake system tools that log their arguments.
struct FakeBin {
    dir: PathBuf,
    log: PathBuf,
}

impl FakeBin {
    fn new(env: &TestEnv) -> Self {
        let dir = env.dir.path().join("fake-bin");
        let log = env.dir.path().join("fake.log");
        std::fs::create_dir_all(&dir).unwrap();
        Self { dir, log }
    }

    /// A tool that records `name args...` and exits with `code`.
    fn tool(&self, name: &str, code: i32) -> &Self {
        let body = format!(
            "echo \"{name} $*\" >> '{}'\nexit {code}",
            self.log.display()
        );
        write_script(&self.dir.join(name), &body);
        self
    }

    fn script(&self, name: &str, body: &str) -> &Self {
        write_script(&self.dir.join(name), body);
        self
    }

    /// Only the fake tools are reachable.
    fn path(&self) -> &Path {
        &self.dir
    }

    fn calls(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// A fake JDK whose keytool writes every keystore named in its arguments.
fn fake_jdk(env: &TestEnv, exit_code: i32) -> PathBuf {
    let home = env.dir.path().join(format!("jdk-{exit_code}"));
    let body = format!(
        r#"while [ $# -gt 0 ]; do
  case "$1" in -destkeystore|-keystore) echo keystore >> "$2";; esac
  shift
done
[ {exit_code} -eq 0 ] || echo 'keytool exploded' >&2
exit {exit_code}"#
    );
    write_script(&home.join("bin/keytool"), &body);
    std::fs::create_dir_all(home.join("lib/security")).unwrap();
    std::fs::write(home.join("lib/security/cacerts"), "").unwrap();
    home
}

#[test]
fn init_creates_configuration_and_ca() {
    let env = TestEnv::new();
    std::fs::remove_dir_all(&env.paths.config_dir).unwrap();
    let output = fauxy(&env, &["init"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    let config = env.paths.config_file();
    assert!(
        text.contains(&format!("created: {}", config.display())),
        "{text}"
    );
    assert!(text.contains("local CA created: "), "{text}");
    assert!(text.contains("proxy address: 127.0.0.1:8899\n"), "{text}");
    assert!(text.contains("Next steps:"), "{text}");
    assert!(config.exists());
    assert!(env.paths.default_mocks_dir().join("example.yaml").exists());
    assert!(env.paths.ca_cert().exists());

    let again = stdout(&fauxy(&env, &["init"]));
    assert!(again.contains("kept (already exists): "), "{again}");
    assert!(again.contains("local CA already exists: "), "{again}");

    let forced = stdout(&fauxy(&env, &["init", "--force"]));
    assert!(forced.contains("created: "), "{forced}");
}

#[test]
fn init_port_sets_listen_in_the_configuration() {
    let env = TestEnv::new();
    std::fs::remove_dir_all(&env.paths.config_dir).unwrap();
    let config = env.paths.config_file();

    let text = stdout(&fauxy(&env, &["init", "--port", "9100"]));
    assert!(
        text.contains(&format!("created: {}", config.display())),
        "{text}"
    );
    assert!(text.contains("proxy address: 127.0.0.1:9100\n"), "{text}");
    assert!(
        std::fs::read_to_string(&config)
            .unwrap()
            .contains("\nlisten: 127.0.0.1:9100\n")
    );

    let text = stdout(&fauxy(&env, &["init", "--port", "9101"]));
    assert!(
        text.contains(&format!("updated the port in: {}", config.display())),
        "{text}"
    );
    assert!(
        !text.contains(&format!("kept (already exists): {}", config.display())),
        "{text}"
    );
    assert!(text.contains("proxy address: 127.0.0.1:9101\n"), "{text}");
    let content = std::fs::read_to_string(&config).unwrap();
    assert!(
        content.starts_with("# fauxy global configuration."),
        "comments are kept"
    );
    assert!(content.contains("\nlisten: 127.0.0.1:9101\n"), "{content}");

    let output = fauxy(&env, &["init", "--port", "0"]);
    assert_eq!(output.status.code(), Some(2), "port 0 is rejected");

    env.write_mock("broken.yaml", "rules: [\n");
    let output = fauxy(&env, &["init", "--port", "9102"]);
    assert!(output.status.success(), "broken mocks do not block init");
    assert!(!stdout(&output).contains("proxy address"));
}

#[test]
fn init_port_asks_to_restart_a_running_daemon() {
    let env = TestEnv::new();
    env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
    let _guard = StopOnDrop(&env);
    assert!(fauxy(&env, &["start"]).status.success());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let running = runtime
        .block_on(ControlClient::new(env.paths.socket()).status())
        .unwrap();

    let text = stdout(&fauxy(&env, &["init", "--port", "9103"]));
    assert!(
        text.contains(&format!(
            "fauxy is running on {}; restart it to use 127.0.0.1:9103: fauxy restart (or restart the service)",
            running.listen
        )),
        "{text}"
    );
}

#[test]
fn init_reports_unwritable_directories() {
    let env = TestEnv::new();
    let blocker = env.dir.path().join("file");
    std::fs::write(&blocker, "").unwrap();
    let output = command(&env, &["init"])
        .env("FAUXY_CONFIG_DIR", blocker.join("config"))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).starts_with("error: cannot write to"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn check_validates_configuration() {
    let env = TestEnv::new();
    env.write_mock("mail.yaml", MAIL_API);
    let output = fauxy(&env, &["check"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with("valid configuration: 1 file(s), 3 rule(s), 3 enabled"),
        "{text}"
    );
    assert!(
        text.contains("intercepted hosts: mail.example.com"),
        "{text}"
    );

    env.write_mock("bad.yaml", "host: x.com\nrules:\n  - respnd: {}\n");
    let output = fauxy(&env, &["check"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(
        text.starts_with("invalid configuration (1 problem(s)):"),
        "{text}"
    );
    assert!(text.contains("bad.yaml"), "{text}");
    assert!(text.contains("respnd"), "{text}");
}

#[test]
fn bundled_examples_are_valid() {
    let env = TestEnv::new();
    let config = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/config.yaml");
    let output = fauxy(&env, &["check", "--config", config.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with("valid configuration: 2 file(s), 7 rule(s), 6 enabled"),
        "{text}"
    );
    assert!(
        text.contains("intercepted hosts: mail.example.com, api.example.com, *.cdn.example.com"),
        "{text}"
    );
}

#[test]
fn alternative_config_files_are_honored() {
    let env = TestEnv::new();
    let project = env.dir.path().join("project");
    std::fs::create_dir_all(project.join("mocks")).unwrap();
    std::fs::write(project.join("fauxy.yaml"), "listen: 9123\nmocks: [mocks]\n").unwrap();
    std::fs::write(project.join("mocks/x.yaml"), MAIL_API).unwrap();
    let config = project.join("fauxy.yaml");

    let output = fauxy(&env, &["check", "--config", config.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("proxy: 127.0.0.1:9123"));

    let output = command(&env, &["check"])
        .env("FAUXY_CONFIG", &config)
        .output()
        .unwrap();
    assert!(stdout(&output).contains("proxy: 127.0.0.1:9123"));

    let output = fauxy(&env, &["check", "--config", ""]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "rejected by the argument parser"
    );
    assert!(stderr(&output).starts_with("error: "));
}

#[test]
fn missing_home_is_reported() {
    let env = TestEnv::new();
    let output = command(&env, &["check"])
        .env_remove("HOME")
        .env_remove("FAUXY_CONFIG_DIR")
        .env_remove("FAUXY_STATE_DIR")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(
        stderr(&output),
        "error: could not determine the home directory (HOME is not set)\n"
    );
}

#[test]
fn test_shows_which_rule_answers() {
    let env = TestEnv::new();
    env.write_mock("mail.yaml", MAIL_API);
    let output = fauxy(&env, &["test", "POST", "https://mail.example.com/messages"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with("HTTPS: intercepted host"), "{text}");
    assert!(text.contains("rule: mail-send ("), "{text}");
    assert!(text.ends_with("response: 201 Created\n"), "{text}");

    let text = stdout(&fauxy(&env, &["test", "GET", "https://other.example.org/"]));
    assert!(text.contains("no rule"), "{text}");

    let output = fauxy(&env, &["test", "GET", "/relative"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).contains("the URL must be absolute"));

    env.write_mock("bad.yaml", "rules: [\n");
    let output = fauxy(&env, &["test", "GET", "https://x.com/"]);
    assert!(stderr(&output).starts_with("error: invalid configuration:"));
}

#[test]
fn env_prints_shell_commands() {
    let env = TestEnv::new();
    let output = fauxy(&env, &["env"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.contains("export HTTPS_PROXY='http://127.0.0.1:8899'\n"),
        "{text}"
    );
    assert!(text.contains("export NODE_EXTRA_CA_CERTS="), "{text}");
    assert!(!text.contains("JAVA_TOOL_OPTIONS"), "{text}");
    assert!(env.paths.ca_bundle().exists(), "the bundle must be written");

    let text = stdout(&fauxy(&env, &["env", "--shell", "fish"]));
    assert!(
        text.contains("set -gx HTTP_PROXY 'http://127.0.0.1:8899'\n"),
        "{text}"
    );

    let text = stdout(&fauxy(&env, &["env", "--unset"]));
    assert!(text.contains("unset HTTPS_PROXY\n"), "{text}");
    assert!(text.contains("unset JAVA_TOOL_OPTIONS\n"), "{text}");

    env.write_mock("bad.yaml", "rules: [\n");
    assert_eq!(fauxy(&env, &["env"]).status.code(), Some(1));
}

#[test]
fn env_for_java_builds_the_truststore_once() {
    let env = TestEnv::new();
    let jdk = fake_jdk(&env, 0);
    let output = command(&env, &["env", "--java"])
        .env("JAVA_HOME", &jdk)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("export JAVA_TOOL_OPTIONS='-Dhttp.proxyHost=127.0.0.1"));
    assert!(stderr(&output).starts_with("# Java truststore created at"));
    assert!(env.paths.java_truststore().exists());

    let output = command(&env, &["env", "--java"])
        .env("JAVA_HOME", &jdk)
        .output()
        .unwrap();
    assert!(
        stderr(&output).is_empty(),
        "the existing truststore is reused"
    );

    let jdk_path = jdk.to_str().unwrap();
    let output = fauxy(&env, &["env", "--jvm-flags", "--java-home", jdk_path]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        stderr(&output).starts_with("# Java truststore created at"),
        "--java-home rebuilds"
    );
    let flags = stdout(&output);
    assert!(
        flags.starts_with("-Dhttp.proxyHost=127.0.0.1 -Dhttp.proxyPort=8899"),
        "{flags}"
    );
    assert!(
        flags
            .trim_end()
            .ends_with("-Djavax.net.ssl.trustStoreType=PKCS12"),
        "{flags}"
    );
}

#[test]
fn ca_path_and_dry_runs() {
    let env = TestEnv::new();
    let output = fauxy(&env, &["ca", "path"]);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output).trim(),
        env.paths.ca_cert().display().to_string()
    );

    for action in ["install", "uninstall"] {
        let output = fauxy(&env, &["ca", action, "--dry-run"]);
        assert!(output.status.success(), "{}", stderr(&output));
        let text = stdout(&output);
        assert!(text.starts_with("trust store: "), "{text}");
        assert!(text.contains("\n$ "), "{text}");
        assert!(!text.contains("installed;"), "{text}");
        assert!(!text.contains("removed"), "{text}");
    }
}

/// `ca install`, confirming the system-wide scope where the OS requires it.
const INSTALL: &[&str] = if cfg!(target_os = "linux") {
    &["ca", "install", "--system"]
} else {
    &["ca", "install"]
};

/// Fakes for every tool the trust store commands may use on macOS or Linux.
fn trust_tools(env: &TestEnv, code: i32) -> FakeBin {
    let fake = FakeBin::new(env);
    for tool in [
        "security",
        "sudo",
        "install",
        "rm",
        "update-ca-certificates",
        "update-ca-trust",
        "trust",
    ] {
        fake.tool(tool, code);
    }
    fake
}

#[test]
fn ca_install_and_uninstall_run_the_system_commands() {
    let env = TestEnv::new();
    let fake = trust_tools(&env, 0);

    let output = command(&env, INSTALL)
        .env("PATH", fake.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("local CA installed; bundle with "), "{text}");
    assert!(
        text.contains("Firefox uses its own certificate store"),
        "{text}"
    );
    assert!(env.paths.ca_bundle().exists());
    #[cfg(target_os = "macos")]
    assert!(
        fake.calls()
            .starts_with("security add-trusted-cert -r trustRoot -p ssl -k "),
        "{}",
        fake.calls()
    );
    #[cfg(target_os = "linux")]
    assert!(
        fake.calls().contains("install -D -m 644 ")
            && fake.calls().contains("update-ca-certificates"),
        "{}",
        fake.calls()
    );

    let output = command(&env, &["ca", "uninstall"])
        .env("PATH", fake.path())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).ends_with("local CA removed from the system trust store\n"));
    #[cfg(target_os = "macos")]
    assert!(
        fake.calls().contains("security delete-certificate -Z "),
        "{}",
        fake.calls()
    );
    #[cfg(target_os = "linux")]
    assert!(
        fake.calls()
            .contains("rm -f /usr/local/share/ca-certificates/fauxy-ca.crt"),
        "{}",
        fake.calls()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn system_wide_installs_need_confirmation() {
    let env = TestEnv::new();
    let fake = trust_tools(&env, 0);
    let output = command(&env, &["ca", "install"])
        .env("PATH", fake.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("pass --system to confirm"),
        "{}",
        stderr(&output)
    );
    assert!(fake.calls().is_empty(), "nothing was run");
}

#[test]
fn failing_trust_commands_are_reported() {
    let env = TestEnv::new();
    let fake = trust_tools(&env, 1);
    let output = command(&env, INSTALL)
        .env("PATH", fake.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).starts_with("error: command failed ("),
        "{}",
        stderr(&output)
    );
    assert!(!env.paths.ca_bundle().exists());
}

#[test]
fn ca_java_builds_the_truststore() {
    let env = TestEnv::new();
    let jdk = fake_jdk(&env, 0);
    let output = fauxy(&env, &["ca", "java", "--java-home", jdk.to_str().unwrap()]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with(&format!(
        "Java truststore built with the JDK at {}:",
        jdk.display()
    )));
    assert!(text.contains("password: changeit\n"), "{text}");

    let broken = fake_jdk(&env, 2);
    let output = fauxy(
        &env,
        &["ca", "java", "--java-home", broken.to_str().unwrap()],
    );
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "error: keytool failed: keytool exploded\n");

    let output = fauxy(
        &env,
        &[
            "ca",
            "java",
            "--java-home",
            env.dir.path().to_str().unwrap(),
        ],
    );
    assert!(stderr(&output).contains("does not look like a JDK"));
}

#[test]
fn commands_report_a_stopped_daemon() {
    let env = TestEnv::new();
    let output = fauxy(&env, &["status"]);
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(stdout(&output), "fauxy is not running\n");

    let output = fauxy(&env, &["stop"]);
    assert!(output.status.success());
    assert_eq!(stdout(&output), "fauxy is not running\n");

    for args in [
        &["reload"][..],
        &["rules", "enable", "x"],
        &["rules", "disable", "x"],
    ] {
        let output = fauxy(&env, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(stderr(&output).contains("fauxy is not running"), "{args:?}");
    }
}

/// A socket at the daemon's location that answers garbage.
fn broken_daemon(env: &TestEnv) -> std::thread::JoinHandle<()> {
    env.paths.ensure_state_dir().unwrap();
    let listener = std::os::unix::net::UnixListener::bind(env.paths.socket()).unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let _ = stream.write_all(b"garbage\r\n\r\n");
        }
    })
}

#[test]
fn unhealthy_daemons_are_reported() {
    let env = TestEnv::new();
    let _server = broken_daemon(&env);
    for args in [&["status"][..], &["rules"], &["stop"], &["restart"]] {
        let output = fauxy(&env, args);
        assert_eq!(output.status.code(), Some(1), "{args:?}");
        assert!(
            stderr(&output).contains("failed to talk to the daemon"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
    let output = fauxy(&env, &["env"]);
    assert!(
        output.status.success(),
        "env falls back to the configuration"
    );

    let empty = FakeBin::new(&env);
    let output = command(&env, &["service", "install"])
        .env("PATH", empty.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output)
            .starts_with("error: stop the running daemon before installing the service:"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn start_fails_with_invalid_configuration() {
    let env = TestEnv::new();
    env.write_mock("bad.yaml", "rules:\n  - respond: {}\n");
    let output = fauxy(&env, &["start"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("rule has no host"),
        "{}",
        stderr(&output)
    );
    assert!(!env.paths.socket().exists());
}

#[test]
fn start_reports_daemons_that_exit_during_startup() {
    let env = TestEnv::new();
    let busy = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    env.write_config(
        "config.yaml",
        &format!("listen: {}\n", busy.local_addr().unwrap()),
    );
    let output = fauxy(&env, &["start"]);
    assert_eq!(output.status.code(), Some(1));
    let text = stderr(&output);
    assert!(
        text.starts_with("error: fauxy exited during startup; last lines of"),
        "{text}"
    );
    assert!(text.contains("is already in use"), "{text}");
    assert!(text.contains("fauxy init --port <port>"), "{text}");
}

#[tokio::test(flavor = "multi_thread")]
async fn background_daemon_lifecycle() {
    let env = TestEnv::new();
    env.write_config(
        "config.yaml",
        "listen: 127.0.0.1:0\nmocks: [mocks, missing]\n",
    );
    env.write_mock("mail.yaml", MAIL_API);
    let _guard = StopOnDrop(&env);

    let output = fauxy(&env, &["start"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.starts_with("fauxy started (pid "), "{text}");
    assert!(text.contains("with 3 enabled rule(s)"), "{text}");
    assert!(text.contains("warning: mock source not found: "), "{text}");

    let output = fauxy(&env, &["start"]);
    let text = stdout(&output);
    assert!(text.starts_with("fauxy is already running (pid "), "{text}");
    assert!(
        text.contains("set FAUXY_STATE_DIR to run another instance"),
        "{text}"
    );

    let output = fauxy(&env, &["status"]);
    assert!(output.status.success());
    let text = stdout(&output);
    assert!(text.starts_with("fauxy is running\n"), "{text}");
    assert!(text.contains("intercepting:  mail.example.com"), "{text}");
    assert!(text.contains("warning: mock source not found"), "{text}");

    // End to end through the background process: HTTPS mock.
    let client = ControlClient::new(env.paths.socket());
    let status = client.status().await.unwrap();
    assert_ne!(status.pid, std::process::id());
    assert_eq!(
        session_of(status.pid),
        i32::try_from(status.pid).unwrap(),
        "the daemon leads its own session"
    );

    let exports = stdout(&fauxy(&env, &["env"]));
    assert!(
        exports.contains(&format!("export HTTPS_PROXY='http://{}'", status.listen)),
        "{exports}"
    );
    let ca = std::fs::read_to_string(env.paths.ca_cert()).unwrap();
    let http = client_via(&format!("http://{}", status.listen), &[&ca]);
    let response = http
        .post("https://mail.example.com/messages")
        .body("{}")
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 201);
    assert_eq!(response.text().await.unwrap(), "{}");

    let output = fauxy(&env, &["rules", "disable", "mail-send"]);
    assert_eq!(
        stdout(&output),
        "rule 'mail-send' disabled (until the daemon restarts)\n"
    );
    let text = stdout(&fauxy(&env, &["rules"]));
    assert!(text.starts_with("STATE"), "{text}");
    assert!(text.contains("off*   mail-send"), "{text}");
    let output = fauxy(&env, &["rules", "enable", "mail-send"]);
    assert_eq!(
        stdout(&output),
        "rule 'mail-send' enabled (until the daemon restarts)\n"
    );

    let output = fauxy(&env, &["rules", "enable", "missing-rule"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stderr(&output), "error: rule not found: missing-rule\n");

    let output = fauxy(&env, &["reload"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("warning: mock source not found"), "{text}");
    assert!(
        text.ends_with("configuration reloaded: 3 rule(s)\n"),
        "{text}"
    );

    let bad = env.write_mock("zz-bad.yaml", "rules: [\n");
    let output = fauxy(&env, &["reload"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output)
            .starts_with("invalid configuration; the previous rules are still in effect:")
    );
    let text = stdout(&fauxy(&env, &["status"]));
    assert!(
        text.contains("last reload failed (previous rules still in effect):"),
        "{text}"
    );
    std::fs::remove_file(bad).unwrap();

    let text = stdout(&fauxy(&env, &["logs", "-n", "500"]));
    assert!(text.contains("listening on"), "{text}");
    assert!(
        text.contains("MOCK   POST https://mail.example.com/messages -> 201"),
        "{text}"
    );

    let output = fauxy(&env, &["restart"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with(&format!(
            "fauxy stopped (pid {})\nfauxy started (pid ",
            status.pid
        )),
        "{text}"
    );
    let restarted = client.status().await.unwrap();
    assert_ne!(restarted.pid, status.pid);

    let output = fauxy(&env, &["stop"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        stdout(&output),
        format!("fauxy stopped (pid {})\n", restarted.pid)
    );
    assert_eq!(fauxy(&env, &["status"]).status.code(), Some(3));
    assert_eq!(
        fauxy::daemon::process::locked_pid(&env.paths.pid_file()),
        None
    );

    let output = fauxy(&env, &["restart"]);
    assert!(
        stdout(&output).starts_with("fauxy started (pid "),
        "restart also starts a stopped daemon"
    );
}

#[test]
fn logs_follow_prints_new_lines_until_interrupted() {
    let env = TestEnv::new();
    env.paths.ensure_state_dir().unwrap();
    let log = env.paths.log_file();
    std::fs::write(&log, "old line\nlast line\n").unwrap();

    let mut child = command(&env, &["logs", "-f", "-n", "1"])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let lines = Arc::new(Mutex::new(Vec::<String>::new()));
    let reader = {
        let lines = Arc::clone(&lines);
        let out = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            for line in BufReader::new(out).lines() {
                lines.lock().unwrap().push(line.unwrap());
            }
        })
    };
    let seen = |text: &str| lines.lock().unwrap().iter().any(|line| line == text);

    assert!(wait_until(Duration::from_secs(10), || seen("last line")));
    std::fs::OpenOptions::new()
        .append(true)
        .open(&log)
        .unwrap()
        .write_all(b"appended\n")
        .unwrap();
    assert!(wait_until(Duration::from_secs(10), || seen("appended")));
    std::fs::write(&log, "after truncation\n").unwrap();
    assert!(wait_until(Duration::from_secs(10), || seen(
        "after truncation"
    )));

    signal(&child, libc::SIGINT);
    assert!(wait_for_exit(&mut child).success());
    reader.join().unwrap();
    assert!(!seen("old line"), "only the last line is shown first");
}

#[test]
fn logs_without_a_log_file() {
    let env = TestEnv::new();
    let text = stdout(&fauxy(&env, &["logs"]));
    assert_eq!(
        text,
        format!("no log at {}\n", env.paths.log_file().display())
    );
}

#[test]
fn rules_list_works_without_daemon() {
    let env = TestEnv::new();
    env.write_mock("mail.yaml", MAIL_API);
    let output = fauxy(&env, &["rules", "list"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(text.contains("on     mail-template"), "{text}");
    assert!(
        text.ends_with("(daemon stopped: state from the configuration files)\n"),
        "{text}"
    );

    env.write_mock("bad.yaml", "rules: [\n");
    assert_eq!(fauxy(&env, &["rules"]).status.code(), Some(1));
}

#[test]
fn version_and_help() {
    let env = TestEnv::new();
    let output = fauxy(&env, &["--version"]);
    assert_eq!(
        stdout(&output),
        format!("fauxy {}\n", env!("CARGO_PKG_VERSION"))
    );
    let text = stdout(&fauxy(&env, &["--help"]));
    for command in [
        "init", "start", "stop", "status", "rules", "check", "env", "ca", "service", "ui",
    ] {
        assert!(text.contains(command), "{command}: {text}");
    }
}

#[test]
fn foreground_run_on_another_port() {
    let env = TestEnv::new();
    let config = env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
        .to_string();
    let mut child = command(&env, &["run", "--port", &port, "--no-watch"])
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let status = || runtime.block_on(ControlClient::new(env.paths.socket()).status());
    assert!(wait_until(Duration::from_secs(15), || status().is_ok()));
    assert_eq!(status().unwrap().listen, format!("127.0.0.1:{port}"));

    let exports = stdout(&fauxy(&env, &["env"]));
    assert!(
        exports.contains(&format!("export HTTPS_PROXY='http://127.0.0.1:{port}'")),
        "{exports}"
    );
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        "listen: 127.0.0.1:0\n"
    );

    let second = fauxy(&env, &["run", "--port", "1"]);
    assert_eq!(second.status.code(), Some(1));
    let text = stderr(&second);
    assert!(text.contains("fauxy is already running (pid "), "{text}");
    assert!(
        text.contains("set FAUXY_STATE_DIR to run another instance"),
        "{text}"
    );

    signal(&child, libc::SIGTERM);
    assert!(wait_for_exit(&mut child).success());
    assert_eq!(fauxy(&env, &["run", "--port", "0"]).status.code(), Some(2));
}

#[test]
fn foreground_run_stops_on_signals() {
    for sig in [libc::SIGTERM, libc::SIGINT] {
        let env = TestEnv::new();
        env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
        let mut child = command(&env, &["run", "--no-watch"])
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let socket = env.paths.socket();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let ready = wait_until(Duration::from_secs(15), || {
            runtime
                .block_on(ControlClient::new(&socket).status())
                .is_ok()
        });
        assert!(ready, "the daemon did not start");
        std::thread::sleep(Duration::from_millis(300));

        signal(&child, sig);
        assert!(wait_for_exit(&mut child).success());
        let mut log = String::new();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut log)
            .unwrap();
        assert!(log.contains("listening on"), "{log}");
        assert!(log.contains("shutting down"), "{log}");
    }
}

#[test]
fn foreground_run_rejects_invalid_configuration() {
    let env = TestEnv::new();
    env.write_mock("bad.yaml", "rules:\n  - respond: {}\n");
    let log = env.dir.path().join("run.log");
    let output = fauxy(&env, &["run", "--log-file", log.to_str().unwrap()]);
    assert_eq!(output.status.code(), Some(1));
    let logged = std::fs::read_to_string(&log).unwrap();
    assert!(
        logged.contains("ERROR invalid configuration:"),
        "services only have the log: {logged}"
    );
    assert!(logged.contains("rule has no host"), "{logged}");

    let output = fauxy(&env, &["run"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr(&output).contains("rule has no host"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn own_bundle_in_ssl_cert_file_is_ignored() {
    let env = TestEnv::new();
    assert!(fauxy(&env, &["env"]).status.success());
    let bundle = env.paths.ca_bundle();
    let certificates = |path: &Path| {
        std::fs::read_to_string(path)
            .unwrap()
            .matches("BEGIN CERTIFICATE")
            .count()
    };
    let full = certificates(&bundle);
    std::fs::remove_file(&bundle).unwrap();

    // What `eval "$(fauxy env)"` leaves in the shell.
    let output = command(&env, &["env"])
        .env("SSL_CERT_FILE", &bundle)
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(
        certificates(&bundle),
        full,
        "rebuilt from the system roots, not from itself"
    );
}

/// Fake launchd (macOS) and systemd (Linux) that keep their state in a file.
fn service_tools(env: &TestEnv) -> FakeBin {
    let fake = FakeBin::new(env);
    let state = env.dir.path().join("service-loaded");
    let log = fake.log.display().to_string();
    let launchctl = format!(
        r#"echo "launchctl $*" >> '{log}'
case "$1" in
  load) : > '{state}' ;;
  unload|remove) /bin/rm -f '{state}' ;;
  print) [ -f '{state}' ] && echo "state = running" && exit 0; exit 64 ;;
esac
exit 0"#,
        state = state.display()
    );
    let systemctl = format!(
        r#"echo "systemctl $*" >> '{log}'
case "$2" in
  enable) : > '{state}' ;;
  disable) /bin/rm -f '{state}' ;;
  status) [ -f '{state}' ] && exit 0; exit 4 ;;
esac
exit 0"#,
        state = state.display()
    );
    fake.script("launchctl", &launchctl)
        .script("systemctl", &systemctl);
    fake
}

fn service(env: &TestEnv, fake: &FakeBin, action: &str) -> Output {
    command(env, &["service", action])
        .env("PATH", fake.path())
        .output()
        .unwrap()
}

#[test]
fn service_install_status_and_uninstall() {
    let env = TestEnv::new();
    env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
    let fake = service_tools(&env);
    let _guard = StopOnDrop(&env);
    assert!(fauxy(&env, &["start"]).status.success());

    assert_eq!(
        stdout(&service(&env, &fake, "status")),
        "service 'dev.fauxy.daemon': not installed\n"
    );

    let output = service(&env, &fake, "install");
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);
    assert!(
        text.starts_with("stopped the background daemon (pid "),
        "{text}"
    );
    assert!(
        text.ends_with(
            "service 'dev.fauxy.daemon' installed and started; fauxy will start with your session\n"
        ),
        "{text}"
    );
    assert_eq!(fauxy(&env, &["status"]).status.code(), Some(3));
    #[cfg(target_os = "macos")]
    {
        let plist = env
            .dir
            .path()
            .join("Library/LaunchAgents/dev.fauxy.daemon.plist");
        let text = std::fs::read_to_string(plist).unwrap();
        assert!(text.contains("<string>run</string>"), "{text}");
        assert!(
            text.contains(&env.paths.state_dir.display().to_string()),
            "{text}"
        );
    }
    assert_eq!(
        stdout(&service(&env, &fake, "status")),
        "service 'dev.fauxy.daemon': installed and running\n"
    );

    let output = service(&env, &fake, "uninstall");
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(stdout(&output), "service 'dev.fauxy.daemon' removed\n");
    assert_eq!(
        stdout(&service(&env, &fake, "status")),
        "service 'dev.fauxy.daemon': not installed\n"
    );
    assert!(!fake.calls().is_empty());

    env.write_mock("bad.yaml", "rules: [\n");
    let output = service(&env, &fake, "install");
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: invalid configuration"));
}

#[test]
fn service_commands_need_a_service_manager() {
    let env = TestEnv::new();
    let empty = FakeBin::new(&env);
    for (action, context) in [
        ("install", "failed to install the service"),
        ("uninstall", "failed to remove the service"),
        ("status", "failed to query the service"),
    ] {
        let output = service(&env, &empty, action);
        assert_eq!(output.status.code(), Some(1), "{action}");
        let text = stderr(&output);
        assert!(text.starts_with(&format!("error: {context}: ")), "{text}");
        assert!(
            text.contains("no supported service manager found"),
            "{text}"
        );
    }
}

/// Runs the child in a new session, without a controlling terminal.
fn new_session(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    // SAFETY: setsid is async-signal-safe, so it may run between fork and exec.
    unsafe {
        command.pre_exec(|| {
            libc::setsid();
            Ok(())
        });
    }
}

fn session_of(pid: u32) -> i32 {
    // SAFETY: getsid only reads process metadata.
    unsafe { libc::getsid(i32::try_from(pid).unwrap()) }
}

/// Opens a pseudo-terminal of 30x120 characters.
fn open_pty() -> (File, File) {
    let (mut master, mut slave) = (0, 0);
    let mut size = libc::winsize {
        ws_row: 30,
        ws_col: 120,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: on success openpty stores two new descriptors that nothing
    // else owns.
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            // `*const` on Linux, `*mut` on macOS.
            &raw mut size,
        )
    };
    assert_eq!(rc, 0, "openpty failed");
    // SAFETY: see above; each descriptor gets exactly one owner.
    unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) }
}

#[test]
fn tui_runs_in_a_terminal() {
    let env = TestEnv::new();
    env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
    env.write_mock("mail.yaml", MAIL_API);
    let _guard = StopOnDrop(&env);
    assert!(fauxy(&env, &["start"]).status.success());

    let (master, slave) = open_pty();
    let mut ui = command(&env, &["ui"]);
    ui.env("EDITOR", "true")
        .stdin(slave.try_clone().unwrap())
        .stdout(slave.try_clone().unwrap())
        .stderr(slave);
    new_session(&mut ui);
    let mut child = ui.spawn().unwrap();
    drop(ui);

    let output = Arc::new(Mutex::new(Vec::<u8>::new()));
    {
        let output = Arc::clone(&output);
        let mut reader = master.try_clone().unwrap();
        std::thread::spawn(move || {
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = reader.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                output.lock().unwrap().extend_from_slice(&buffer[..read]);
            }
        });
    }
    let screen = || Screen::render(&String::from_utf8_lossy(&output.lock().unwrap()));
    let shows = |text: &str| wait_until(Duration::from_secs(15), || screen().contains(text));
    let mut keys = master;

    assert!(shows("Traffic [1]"), "{}", screen());
    keys.write_all(b"2").unwrap();
    assert!(shows("Rules (3)  * = changed at runtime"), "{}", screen());
    assert!(screen().contains("mail-template"), "{}", screen());
    keys.write_all(b"e").unwrap();
    assert!(
        shows("editor closed; saved changes are reloaded automatically"),
        "{}",
        screen()
    );
    keys.write_all(b"q").unwrap();
    assert!(wait_for_exit(&mut child).success());
}

/// Minimal terminal emulator: applies cursor moves and screen clears so the
/// rendered text can be searched.
struct Screen;

impl Screen {
    const ROWS: usize = 30;
    const COLS: usize = 120;

    fn render(output: &str) -> String {
        let mut grid = vec![vec![' '; Self::COLS]; Self::ROWS];
        let (mut row, mut col) = (0_usize, 0_usize);
        let mut chars = output.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\u{1b}' if chars.peek() == Some(&'[') => {
                    chars.next();
                    let mut params = String::new();
                    let mut command = ' ';
                    for next in chars.by_ref() {
                        if ('@'..='~').contains(&next) {
                            command = next;
                            break;
                        }
                        params.push(next);
                    }
                    match command {
                        'H' => {
                            let mut numbers =
                                params.split(';').map(|n| n.parse::<usize>().unwrap_or(1));
                            row = numbers.next().unwrap_or(1).saturating_sub(1);
                            col = numbers.next().unwrap_or(1).saturating_sub(1);
                        }
                        'J' if params == "2" => grid = vec![vec![' '; Self::COLS]; Self::ROWS],
                        _ => {}
                    }
                }
                '\r' => col = 0,
                '\n' => row += 1,
                c if c.is_control() => {}
                c => {
                    if row < Self::ROWS && col < Self::COLS {
                        grid[row][col] = c;
                    }
                    col += 1;
                }
            }
        }
        grid.iter()
            .map(|line| line.iter().collect::<String>() + "\n")
            .collect()
    }
}

#[test]
fn tui_requires_a_terminal() {
    let env = TestEnv::new();
    let mut ui = command(&env, &["ui"]);
    ui.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    new_session(&mut ui);
    let output = ui.output().unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(stderr(&output).starts_with("error: "));
}
