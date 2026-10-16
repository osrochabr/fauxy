//! End-to-end test with a real JVM (skipped when no JDK 11+ is available).
#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;

use common::{MAIL_API, TestEnv};
use fauxy::daemon::{Daemon, RunOptions};
use fauxy::events::EventKind;
use fauxy::java::{CA_ALIAS, JavaHome, TRUSTSTORE_PASSWORD, jvm_flags};
use fauxy::tls::LocalCa;
use std::path::Path;

/// Calls the mocked email API with both JDK HTTP clients.
const JAVA_SOURCE: &str = r#"
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;

public class MailClient {
    public static void main(String[] args) throws Exception {
        String base = "https://mail.example.com";

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder(URI.create(base + "/messages"))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString("{\"to\":\"a@example.com\"}"))
            .build();
        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
        System.out.println("HttpClient " + response.statusCode() + " " + response.body());

        HttpURLConnection connection =
            (HttpURLConnection) URI.create(base + "/templates/WELCOME").toURL().openConnection();
        int status = connection.getResponseCode();
        String body;
        try (InputStream in = connection.getInputStream()) {
            body = new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
        System.out.println("HttpURLConnection " + status + " " + body);
    }
}
"#;

/// A JDK able to run single-file source programs (Java 11+).
fn modern_jdk() -> Option<JavaHome> {
    let java = JavaHome::locate(None).ok()?;
    let output = std::process::Command::new(java.home().join("bin/java"))
        .arg("-version")
        .output()
        .ok()?;
    let version = String::from_utf8_lossy(&output.stderr);
    (!version.contains("version \"1.")).then_some(java)
}

#[tokio::test(flavor = "multi_thread")]
async fn java_clients_receive_the_mocks_through_the_proxy() {
    let Some(java) = modern_jdk() else {
        let required = std::env::var_os("FAUXY_REQUIRE_JDK").is_some();
        assert!(
            !required,
            "FAUXY_REQUIRE_JDK is set but no JDK 11+ was found"
        );
        eprintln!("no JDK 11+: test skipped (set FAUXY_REQUIRE_JDK=1 to fail instead)");
        return;
    };
    let env = TestEnv::new();
    env.write_config("config.yaml", "listen: 127.0.0.1:0\n");
    env.write_mock("mail.yaml", MAIL_API);
    let daemon = Daemon::start(env.paths.clone(), RunOptions::default())
        .await
        .unwrap();

    let ca = LocalCa::load(&env.paths).unwrap().unwrap();
    let truststore = env.paths.java_truststore();
    java.build_truststore(ca.cert_path(), &truststore).unwrap();
    assert!(keystore_aliases(&java, &truststore).contains(CA_ALIAS));

    let source = env.dir.path().join("MailClient.java");
    std::fs::write(&source, JAVA_SOURCE).unwrap();
    let output = run_java(&java, &jvm_flags(daemon.proxy_addr(), &truststore), &source).await;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "stdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(stdout.contains("HttpClient 201 {}"), "{stdout}");
    assert!(
        stdout.contains(r#"HttpURLConnection 200 {"body":"<p>Hello</p>","subject":"Welcome"}"#),
        "{stdout}"
    );

    let events = daemon.state().events().since(0, 10);
    assert_eq!(events.len(), 2);
    assert!(events.iter().all(|e| e.kind == EventKind::Mock));
    assert_eq!(daemon.state().hits("mail-send"), 1);
    assert_eq!(daemon.state().hits("mail-template"), 1);

    daemon.shutdown_token().cancel();
    daemon.wait().await.unwrap();
}

fn keystore_aliases(java: &JavaHome, truststore: &Path) -> String {
    let output = std::process::Command::new(java.keytool())
        .args([
            "-list",
            "-storetype",
            "PKCS12",
            "-storepass",
            TRUSTSTORE_PASSWORD,
            "-keystore",
        ])
        .arg(truststore)
        .output()
        .unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

async fn run_java(java: &JavaHome, flags: &[String], source: &Path) -> std::process::Output {
    tokio::process::Command::new(java.home().join("bin/java"))
        .args(flags)
        .arg(source)
        .env_remove("JAVA_TOOL_OPTIONS")
        .output()
        .await
        .unwrap()
}
