//! Shared helpers for the integration tests.
#![allow(dead_code, unreachable_pub, clippy::unwrap_used, clippy::expect_used)]

use bytes::Bytes;
use fauxy::config::load_file;
use fauxy::paths::Paths;
use fauxy::proxy::ProxyServer;
use fauxy::state::AppState;
use fauxy::tls::{LocalCa, client_config};
use http_body_util::Full;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair, SanType,
};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Mock of an email API, mirroring a typical client library: templates are
/// fetched with GET and messages are created with POST (201).
pub const MAIL_API: &str = r#"
host: mail.example.com
rules:
  - name: mail-template
    match: { method: GET, path: /templates/:id }
    respond:
      json: { subject: "Welcome", body: "<p>Hello</p>" }
  - name: mail-send
    match: { method: POST, path: /messages }
    respond: { status: 201, json: {} }
  - name: mail-catch-all
    match: { path: /** }
    respond: { json: {} }
"#;

/// Installs the process-wide rustls provider used by reqwest.
pub fn init_crypto() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

/// Temporary configuration and state directories.
pub struct TestEnv {
    pub dir: tempfile::TempDir,
    pub paths: Paths,
}

impl TestEnv {
    pub fn new() -> Self {
        init_crypto();
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config_dir: dir.path().join("config"),
            state_dir: dir.path().join("state"),
        };
        std::fs::create_dir_all(paths.default_mocks_dir()).unwrap();
        Self { dir, paths }
    }

    pub fn write_config(&self, rel: &str, content: &str) -> PathBuf {
        let path = self.paths.config_dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, content).unwrap();
        path
    }

    pub fn write_mock(&self, name: &str, content: &str) -> PathBuf {
        self.write_config(&format!("mocks/{name}"), content)
    }
}

/// A proxy started in-process.
pub struct TestProxy {
    pub addr: SocketAddr,
    pub state: Arc<AppState>,
    pub ca: LocalCa,
    shutdown: CancellationToken,
}

impl TestProxy {
    pub async fn start(env: &TestEnv) -> Self {
        let loaded = load_file(&env.paths.config_file(), None).expect("valid configuration");
        let (ca, _) = LocalCa::load_or_create(&env.paths).unwrap();
        let upstream = client_config(&loaded.upstream_ca_files).unwrap();
        let state = Arc::new(AppState::new(loaded.rules));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let shutdown = CancellationToken::new();
        let server = ProxyServer::spawn(
            listener,
            &ca,
            upstream,
            Arc::clone(&state),
            shutdown.clone(),
        )
        .unwrap();
        Self {
            addr: server.local_addr(),
            state,
            ca,
            shutdown,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Client using the proxy and trusting only `roots`.
    pub fn client(&self, roots: &[&str]) -> reqwest::Client {
        client_via(&self.url(), roots)
    }

    pub fn client_trusting_ca(&self) -> reqwest::Client {
        self.client(&[self.ca.cert_pem()])
    }
}

impl Drop for TestProxy {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

pub fn client_via(proxy_url: &str, roots: &[&str]) -> reqwest::Client {
    init_crypto();
    let certs: Vec<reqwest::Certificate> = roots
        .iter()
        .map(|pem| reqwest::Certificate::from_pem(pem.as_bytes()).unwrap())
        .collect();
    let mut builder = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy_url).unwrap())
        .timeout(std::time::Duration::from_secs(60));
    if !certs.is_empty() {
        builder = builder.tls_certs_only(certs);
    }
    builder.build().unwrap()
}

/// Plain HTTP server answering `upstream <METHOD> <PATH>`.
pub async fn start_upstream_http() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service_fn(echo))
                    .await;
            });
        }
    });
    addr
}

async fn echo(req: Request<hyper::body::Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let body = format!("upstream {} {}", req.method(), req.uri().path());
    Ok(Response::builder()
        .header("x-upstream", "yes")
        .body(Full::new(Bytes::from(body)))
        .unwrap())
}

/// HTTPS upstream for `localhost` signed by its own CA.
pub struct UpstreamTls {
    pub addr: SocketAddr,
    pub ca_pem: String,
    pub ca_file: PathBuf,
}

/// Starts an HTTPS server for `localhost`; its CA is written into `dir`.
pub async fn start_upstream_https(dir: &Path) -> UpstreamTls {
    init_crypto();
    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test upstream");
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::new(vec!["localhost".to_owned()]).unwrap();
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    leaf_params
        .subject_alt_names
        .push(SanType::IpAddress("127.0.0.1".parse().unwrap()));
    let leaf = leaf_params.signed_by(&leaf_key, &issuer).unwrap();

    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(leaf_key.serialize_der().into()),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                if let Ok(tls) = acceptor.accept(stream).await {
                    let _ = http1::Builder::new()
                        .serve_connection(TokioIo::new(tls), service_fn(echo))
                        .await;
                }
            });
        }
    });

    let ca_pem = ca_cert.pem();
    let ca_file = dir.join("upstream-ca.pem");
    std::fs::write(&ca_file, &ca_pem).unwrap();
    UpstreamTls {
        addr,
        ca_pem,
        ca_file,
    }
}

/// Waits until `condition` holds or the timeout expires.
pub async fn eventually(timeout: std::time::Duration, mut condition: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if condition() {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    condition()
}

/// Writes an executable shell script.
pub fn write_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}
