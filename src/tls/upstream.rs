//! TLS configuration for connections to real (upstream) servers.

use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use rustls::{ClientConfig, RootCertStore};
use rustls_native_certs::CertificateResult;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("{}: {message}", path.display())]
    CaFile { path: PathBuf, message: String },
    #[error("no root CA available to validate upstream servers")]
    NoRoots,
}

pub fn crypto_provider() -> CryptoProvider {
    rustls::crypto::aws_lc_rs::default_provider()
}

/// Trusts the system roots plus `extra_ca_files`. Upstream certificates are
/// always validated; there is no option to skip verification.
pub fn client_config(extra_ca_files: &[PathBuf]) -> Result<ClientConfig, UpstreamError> {
    build_client_config(rustls_native_certs::load_native_certs(), extra_ca_files)
}

fn build_client_config(
    native: CertificateResult,
    extra_ca_files: &[PathBuf],
) -> Result<ClientConfig, UpstreamError> {
    for error in &native.errors {
        tracing::warn!("failed to load system certificates: {error}");
    }
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(native.certs);
    for file in extra_ca_files {
        roots.add_parsable_certificates(read_pem_certs(file)?);
    }
    if roots.is_empty() {
        return Err(UpstreamError::NoRoots);
    }
    let config = ClientConfig::builder_with_provider(Arc::new(crypto_provider()))
        .with_safe_default_protocol_versions()
        .expect("the default provider supports the safe default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

fn read_pem_certs(path: &Path) -> Result<Vec<CertificateDer<'static>>, UpstreamError> {
    let error = |message: String| UpstreamError::CaFile {
        path: path.to_path_buf(),
        message,
    };
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .map_err(|e| error(e.to_string()))?
        .collect::<Result<_, _>>()
        .map_err(|e| error(e.to_string()))?;
    if certs.is_empty() {
        return Err(error("no PEM certificate found".to_owned()));
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::LocalCa;

    fn ca_file(dir: &Path) -> PathBuf {
        let (cert_pem, _) = LocalCa::generate("extra").unwrap();
        let file = dir.join("extra.pem");
        std::fs::write(&file, cert_pem).unwrap();
        file
    }

    #[test]
    fn extra_ca_files_are_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let file = ca_file(dir.path());
        build_client_config(CertificateResult::default(), &[file]).unwrap();
    }

    #[test]
    fn native_load_errors_are_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let mut native = CertificateResult::default();
        native.errors.push(rustls_native_certs::Error {
            context: "test",
            kind: rustls_native_certs::ErrorKind::Os("unavailable".into()),
        });
        build_client_config(native, &[ca_file(dir.path())]).unwrap();
    }

    #[test]
    fn missing_roots_are_an_error() {
        let err = build_client_config(CertificateResult::default(), &[]).unwrap_err();
        assert!(matches!(err, UpstreamError::NoRoots));
        assert_eq!(
            err.to_string(),
            "no root CA available to validate upstream servers"
        );
    }

    #[test]
    fn invalid_ca_files_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty.pem");
        std::fs::write(&empty, "nothing here").unwrap();
        let err = build_client_config(CertificateResult::default(), std::slice::from_ref(&empty))
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("{}: no PEM certificate found", empty.display())
        );

        let broken = dir.path().join("broken.pem");
        std::fs::write(
            &broken,
            "-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        assert!(build_client_config(CertificateResult::default(), &[broken]).is_err());

        let missing = dir.path().join("missing.pem");
        assert!(build_client_config(CertificateResult::default(), &[missing]).is_err());
    }

    #[test]
    fn system_roots_are_loaded() {
        client_config(&[]).unwrap();
    }
}
