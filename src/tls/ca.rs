//! Local certificate authority used to sign certificates of intercepted hosts.

use crate::paths::{Paths, create_private_dir};
use base64::Engine as _;
use chrono::{Datelike, Duration, Utc};
use hudsucker::certificate_authority::RcgenAuthority;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, date_time_ymd,
};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;
use std::fmt::Display;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Leaf certificates kept in memory by the proxy.
const CERT_CACHE_SIZE: u64 = 1_000;

const CA_VALIDITY_YEARS: i32 = 10;

#[derive(Debug, thiserror::Error)]
pub enum CaError {
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    #[error("invalid CA certificate: {0}")]
    Certificate(String),
}

impl CaError {
    fn io(path: &Path) -> impl FnOnce(io::Error) -> Self + '_ {
        move |source| Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}

fn cert_error(err: impl Display) -> CaError {
    CaError::Certificate(err.to_string())
}

/// A self-signed CA certificate and its private key.
#[derive(Clone)]
pub struct LocalCa {
    cert_pem: String,
    key_pem: String,
    cert_path: PathBuf,
}

impl std::fmt::Debug for LocalCa {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalCa")
            .field("cert_path", &self.cert_path)
            .finish_non_exhaustive()
    }
}

impl LocalCa {
    /// Returns `(certificate_pem, private_key_pem)`. The CA may only sign end
    /// entity certificates (path length 0).
    pub fn generate(common_name: &str) -> Result<(String, String), CaError> {
        let key = KeyPair::generate().map_err(cert_error)?;
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, common_name);
        name.push(DnType::OrganizationName, "fauxy");
        params.distinguished_name = name;
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::CrlSign,
            KeyUsagePurpose::DigitalSignature,
        ];

        let start = Utc::now() - Duration::days(1);
        let month = u8::try_from(start.month()).unwrap_or(1);
        let day = u8::try_from(start.day().min(28)).unwrap_or(1);
        params.not_before = date_time_ymd(start.year(), month, day);
        params.not_after = date_time_ymd(start.year() + CA_VALIDITY_YEARS, month, day);

        let cert = params.self_signed(&key).map_err(cert_error)?;
        Ok((cert.pem(), key.serialize_pem()))
    }

    /// Loads the CA from the state directory, if it exists. A private key
    /// readable by other users is restricted to the owner again.
    pub fn load(paths: &Paths) -> Result<Option<Self>, CaError> {
        let cert_path = paths.ca_cert();
        let key_path = paths.ca_key();
        if !cert_path.exists() || !key_path.exists() {
            return Ok(None);
        }
        let cert_pem = std::fs::read_to_string(&cert_path).map_err(CaError::io(&cert_path))?;
        let key_pem = std::fs::read_to_string(&key_path).map_err(CaError::io(&key_path))?;
        let mode = std::fs::metadata(&key_path)
            .map_err(CaError::io(&key_path))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            let key = key_path.display();
            tracing::warn!("{key} was readable by other users; restricting it to the owner");
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .map_err(CaError::io(&key_path))?;
        }
        let ca = Self {
            cert_pem,
            key_pem,
            cert_path,
        };
        ca.issuer()?;
        Ok(Some(ca))
    }

    /// Loads the CA or creates a new one. Returns whether it was created.
    pub fn load_or_create(paths: &Paths) -> Result<(Self, bool), CaError> {
        if let Some(ca) = Self::load(paths)? {
            return Ok((ca, false));
        }
        let created = Utc::now().format("%Y-%m-%d").to_string();
        let (cert_pem, key_pem) = Self::generate(&format!("fauxy local CA {created}"))?;

        let dir = paths.ca_dir();
        create_private_dir(&dir).map_err(CaError::io(&dir))?;
        write_file(&paths.ca_key(), &key_pem, 0o600)?;
        write_file(&paths.ca_cert(), &cert_pem, 0o644)?;
        let ca = Self {
            cert_pem,
            key_pem,
            cert_path: paths.ca_cert(),
        };
        Ok((ca, true))
    }

    pub fn cert_pem(&self) -> &str {
        &self.cert_pem
    }

    pub fn cert_path(&self) -> &Path {
        &self.cert_path
    }

    pub fn cert_der(&self) -> Result<CertificateDer<'static>, CaError> {
        CertificateDer::from_pem_slice(self.cert_pem.as_bytes()).map_err(cert_error)
    }

    /// Uppercase hex without separators, as `security delete-certificate -Z`
    /// expects.
    pub fn sha256_fingerprint(&self) -> Result<String, CaError> {
        let digest = ring::digest::digest(&ring::digest::SHA256, self.cert_der()?.as_ref());
        Ok(digest
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02X}"))
            .collect())
    }

    fn issuer(&self) -> Result<Issuer<'static, KeyPair>, CaError> {
        let key = KeyPair::from_pem(&self.key_pem).map_err(cert_error)?;
        Issuer::from_ca_cert_pem(&self.cert_pem, key).map_err(cert_error)
    }

    /// Signs the leaf certificates presented for intercepted hosts.
    pub fn authority(&self, provider: CryptoProvider) -> Result<RcgenAuthority, CaError> {
        Ok(RcgenAuthority::new(
            self.issuer()?,
            CERT_CACHE_SIZE,
            provider,
        ))
    }
}

/// Writes `content`; `mode` applies when the file is created.
fn write_file(path: &Path, content: &str, mode: u32) -> Result<(), CaError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)
        .map_err(CaError::io(path))?;
    file.write_all(content.as_bytes())
        .map_err(CaError::io(path))
}

pub fn der_to_pem(der: &[u8]) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

/// Writes a PEM bundle with the system roots followed by the local CA.
/// Tools such as Python `requests` replace (instead of extend) their trust
/// store, so the bundle must contain the regular roots too.
pub fn write_bundle(ca: &LocalCa, path: &Path) -> Result<usize, CaError> {
    let native = rustls_native_certs::load_native_certs();
    let mut bundle: String = native
        .certs
        .iter()
        .map(|cert| der_to_pem(cert.as_ref()))
        .collect();
    bundle.push_str(ca.cert_pem());
    write_file(path, &bundle, 0o644)?;
    Ok(native.certs.len() + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> (tempfile::TempDir, Paths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = Paths {
            config_dir: dir.path().join("config"),
            state_dir: dir.path().join("state"),
        };
        (dir, paths)
    }

    fn mode(path: &Path) -> u32 {
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn generated_certificate_is_a_ca() {
        let (cert_pem, key_pem) = LocalCa::generate("test").unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.contains("PRIVATE KEY"));

        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let constraints = cert.basic_constraints().unwrap().unwrap().value;
        assert!(constraints.ca);
        assert_eq!(constraints.path_len_constraint, Some(0));
        assert!(cert.subject().to_string().contains("CN=test"));
        let validity = cert.validity();
        let years =
            (validity.not_after.timestamp() - validity.not_before.timestamp()) / (365 * 24 * 3600);
        assert!((9..=10).contains(&years), "{years}");
        assert!(validity.is_valid());
    }

    #[test]
    fn load_or_create_persists_with_private_key_permissions() {
        let (_dir, paths) = paths();
        assert!(LocalCa::load(&paths).unwrap().is_none());

        let (ca, created) = LocalCa::load_or_create(&paths).unwrap();
        assert!(created);
        assert_eq!(ca.cert_path(), paths.ca_cert());
        assert_eq!(mode(&paths.ca_key()), 0o600);
        assert_eq!(mode(&paths.ca_dir()), 0o700);
        assert_eq!(
            format!("{ca:?}"),
            format!("LocalCa {{ cert_path: {:?}, .. }}", paths.ca_cert())
        );

        let (again, created) = LocalCa::load_or_create(&paths).unwrap();
        assert!(!created);
        assert_eq!(again.cert_pem(), ca.cert_pem());
    }

    #[test]
    fn loose_key_permissions_are_tightened_on_load() {
        let (_dir, paths) = paths();
        LocalCa::load_or_create(&paths).unwrap();
        std::fs::set_permissions(paths.ca_key(), std::fs::Permissions::from_mode(0o644)).unwrap();
        LocalCa::load(&paths).unwrap().unwrap();
        assert_eq!(mode(&paths.ca_key()), 0o600);
    }

    #[test]
    fn corrupted_files_are_reported() {
        let (_dir, paths) = paths();
        LocalCa::load_or_create(&paths).unwrap();
        std::fs::write(paths.ca_key(), "garbage").unwrap();
        let err = LocalCa::load(&paths).unwrap_err();
        assert!(matches!(err, CaError::Certificate(_)));
        assert!(err.to_string().starts_with("invalid CA certificate"));
    }

    #[test]
    fn unreadable_files_are_reported_with_their_path() {
        let (_dir, paths) = paths();
        LocalCa::load_or_create(&paths).unwrap();
        std::fs::remove_file(paths.ca_cert()).unwrap();
        std::fs::create_dir(paths.ca_cert()).unwrap();
        let err = LocalCa::load(&paths).unwrap_err();
        assert!(
            err.to_string()
                .starts_with(&paths.ca_cert().display().to_string())
        );
    }

    #[test]
    fn creation_fails_when_the_state_dir_is_not_writable() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let paths = Paths {
            config_dir: dir.path().join("config"),
            state_dir: blocker,
        };
        assert!(matches!(
            LocalCa::load_or_create(&paths),
            Err(CaError::Io { .. })
        ));
    }

    #[test]
    fn invalid_pem_has_no_fingerprint() {
        let (_dir, paths) = paths();
        let (mut ca, _) = LocalCa::load_or_create(&paths).unwrap();
        ca.cert_pem = "not a certificate".into();
        assert!(matches!(
            ca.sha256_fingerprint(),
            Err(CaError::Certificate(_))
        ));
    }

    #[test]
    fn fingerprint_is_sha256_hex() {
        let (_dir, paths) = paths();
        let (ca, _) = LocalCa::load_or_create(&paths).unwrap();
        let fingerprint = ca.sha256_fingerprint().unwrap();
        assert_eq!(fingerprint.len(), 64);
        assert!(
            fingerprint
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_lowercase())
        );
    }

    #[test]
    fn authority_can_be_built() {
        let (_dir, paths) = paths();
        let (ca, _) = LocalCa::load_or_create(&paths).unwrap();
        ca.authority(rustls::crypto::aws_lc_rs::default_provider())
            .unwrap();
    }

    #[test]
    fn der_to_pem_round_trips() {
        let (cert_pem, _) = LocalCa::generate("x").unwrap();
        let der = CertificateDer::from_pem_slice(cert_pem.as_bytes()).unwrap();
        let pem = der_to_pem(der.as_ref());
        assert_eq!(
            CertificateDer::from_pem_slice(pem.as_bytes())
                .unwrap()
                .as_ref(),
            der.as_ref()
        );
        assert!(pem.lines().all(|line| line.len() <= 64));
    }

    #[test]
    fn bundle_ends_with_local_ca() {
        let (dir, paths) = paths();
        let (ca, _) = LocalCa::load_or_create(&paths).unwrap();
        let bundle = dir.path().join("bundle.pem");
        let count = write_bundle(&ca, &bundle).unwrap();
        let text = std::fs::read_to_string(&bundle).unwrap();
        assert!(text.ends_with(ca.cert_pem()));
        assert_eq!(text.matches("BEGIN CERTIFICATE").count(), count);
        assert!(
            write_bundle(&ca, dir.path()).is_err(),
            "a directory is not writable as a file"
        );
    }
}
