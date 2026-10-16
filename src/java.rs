//! Java support. The JVM ignores the system trust store and `HTTP(S)_PROXY`,
//! so it needs `-Dhttp(s).proxyHost/proxyPort` pointing at fauxy and a
//! truststore with the regular JDK roots (tunneled hosts present their real
//! certificates) plus the fauxy CA (intercepted hosts).

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

/// The truststore only holds public certificates; `changeit` is the JDK
/// convention.
pub const TRUSTSTORE_PASSWORD: &str = "changeit";

pub const CA_ALIAS: &str = "fauxy-ca";

#[derive(Debug, thiserror::Error)]
pub enum JavaError {
    #[error("no JDK found: set JAVA_HOME, put 'java' on the PATH or use --java-home")]
    NotFound,
    #[error("{} does not look like a JDK (keytool or cacerts is missing)", .0.display())]
    Invalid(PathBuf),
    #[error("keytool failed: {0}")]
    Keytool(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JavaHome {
    home: PathBuf,
}

impl JavaHome {
    pub fn new(home: impl Into<PathBuf>) -> Result<Self, JavaError> {
        let java = Self { home: home.into() };
        if java.keytool().is_file() && java.cacerts().is_some() {
            Ok(java)
        } else {
            Err(JavaError::Invalid(java.home))
        }
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    pub fn keytool(&self) -> PathBuf {
        self.home.join("bin/keytool")
    }

    /// JDK 9+ or JDK 8 layout.
    pub fn cacerts(&self) -> Option<PathBuf> {
        ["lib/security/cacerts", "jre/lib/security/cacerts"]
            .iter()
            .map(|rel| self.home.join(rel))
            .find(|path| path.is_file())
    }

    /// Looks for a JDK in `--java-home`, `JAVA_HOME`, `java` on the `PATH`
    /// and, on macOS, `/usr/libexec/java_home`.
    pub fn locate(explicit: Option<&Path>) -> Result<Self, JavaError> {
        let java_home = std::env::var_os("JAVA_HOME").filter(|v| !v.is_empty());
        let path_var = std::env::var_os("PATH").unwrap_or_default();
        Self::locate_with(
            explicit,
            java_home.as_deref(),
            &path_var,
            platform_java_home,
        )
    }

    pub fn locate_with(
        explicit: Option<&Path>,
        java_home_env: Option<&OsStr>,
        path_var: &OsStr,
        fallback: impl Fn() -> Option<PathBuf>,
    ) -> Result<Self, JavaError> {
        if let Some(home) = explicit.map(Path::as_os_str).or(java_home_env) {
            return Self::new(home);
        }
        std::env::split_paths(path_var)
            .map(|dir| dir.join("java"))
            .filter(|java| java.is_file())
            .filter_map(|java| std::fs::canonicalize(java).ok())
            .filter_map(|java| java.parent()?.parent().map(Path::to_path_buf))
            .chain(fallback())
            .find_map(|home| Self::new(home).ok())
            .ok_or(JavaError::NotFound)
    }

    /// keytool invocations that build the truststore at `out`: copy the JDK
    /// roots, then add the fauxy CA.
    pub fn truststore_commands(
        &self,
        ca_cert: &Path,
        out: &Path,
    ) -> Result<Vec<Vec<OsString>>, JavaError> {
        let cacerts = self
            .cacerts()
            .ok_or_else(|| JavaError::Invalid(self.home.clone()))?;
        let args = |items: &[&OsStr]| items.iter().map(|s| s.to_os_string()).collect::<Vec<_>>();
        let os = OsStr::new;
        Ok(vec![
            args(&[
                os("-importkeystore"),
                os("-noprompt"),
                os("-srckeystore"),
                cacerts.as_os_str(),
                os("-srcstorepass"),
                os(TRUSTSTORE_PASSWORD),
                os("-destkeystore"),
                out.as_os_str(),
                os("-deststoretype"),
                os("PKCS12"),
                os("-deststorepass"),
                os(TRUSTSTORE_PASSWORD),
            ]),
            args(&[
                os("-importcert"),
                os("-noprompt"),
                os("-trustcacerts"),
                os("-alias"),
                os(CA_ALIAS),
                os("-file"),
                ca_cert.as_os_str(),
                os("-keystore"),
                out.as_os_str(),
                os("-storetype"),
                os("PKCS12"),
                os("-storepass"),
                os(TRUSTSTORE_PASSWORD),
            ]),
        ])
    }

    /// Builds (or rebuilds) the truststore at `out`. A partial file is removed
    /// when keytool fails.
    pub fn build_truststore(&self, ca_cert: &Path, out: &Path) -> Result<(), JavaError> {
        let commands = self.truststore_commands(ca_cert, out)?;
        std::fs::create_dir_all(out.parent().unwrap_or(Path::new(".")))?;
        if out.exists() {
            std::fs::remove_file(out)?;
        }
        for args in commands {
            let output = Command::new(self.keytool()).args(&args).output()?;
            if !output.status.success() {
                let _ = std::fs::remove_file(out);
                let text = [output.stdout, output.stderr].concat();
                return Err(JavaError::Keytool(
                    String::from_utf8_lossy(&text).trim().to_owned(),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn platform_java_home() -> Option<PathBuf> {
    let output = Command::new("/usr/libexec/java_home").output().ok()?;
    let home = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    output.status.success().then(|| PathBuf::from(home))
}

#[cfg(not(target_os = "macos"))]
fn platform_java_home() -> Option<PathBuf> {
    None
}

/// Address clients should use to reach the proxy: loopback for wildcard binds.
pub fn proxy_host(listen: SocketAddr) -> IpAddr {
    if listen.ip().is_unspecified() {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    } else {
        listen.ip()
    }
}

/// JVM system properties that route traffic through fauxy.
pub fn jvm_flags(listen: SocketAddr, truststore: &Path) -> Vec<String> {
    let host = proxy_host(listen);
    let port = listen.port();
    vec![
        format!("-Dhttp.proxyHost={host}"),
        format!("-Dhttp.proxyPort={port}"),
        format!("-Dhttps.proxyHost={host}"),
        format!("-Dhttps.proxyPort={port}"),
        format!("-Djavax.net.ssl.trustStore={}", truststore.display()),
        format!("-Djavax.net.ssl.trustStorePassword={TRUSTSTORE_PASSWORD}"),
        "-Djavax.net.ssl.trustStoreType=PKCS12".to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A fake JDK whose keytool runs `script`.
    fn fake_jdk(root: &Path, layout: &str, script: &str) -> PathBuf {
        let home = root.join("jdk");
        std::fs::create_dir_all(home.join("bin")).unwrap();
        let keytool = home.join("bin/keytool");
        std::fs::write(&keytool, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&keytool, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(home.join("bin/java"), "").unwrap();
        let cacerts = home.join(layout);
        std::fs::create_dir_all(cacerts.parent().unwrap()).unwrap();
        std::fs::write(cacerts, "").unwrap();
        home
    }

    #[test]
    fn validates_jdk_layouts() {
        let dir = tempfile::tempdir().unwrap();
        let home = fake_jdk(dir.path(), "lib/security/cacerts", "true");
        let java = JavaHome::new(&home).unwrap();
        assert_eq!(java.cacerts().unwrap(), home.join("lib/security/cacerts"));
        assert_eq!(java.keytool(), home.join("bin/keytool"));

        let dir8 = tempfile::tempdir().unwrap();
        let home8 = fake_jdk(dir8.path(), "jre/lib/security/cacerts", "true");
        assert_eq!(
            JavaHome::new(&home8).unwrap().cacerts().unwrap(),
            home8.join("jre/lib/security/cacerts")
        );

        let err = JavaHome::new(dir.path()).unwrap_err();
        assert!(matches!(err, JavaError::Invalid(_)));
        assert!(
            err.to_string()
                .ends_with("does not look like a JDK (keytool or cacerts is missing)")
        );
    }

    #[test]
    fn lookup_order() {
        let dir = tempfile::tempdir().unwrap();
        let home = fake_jdk(dir.path(), "lib/security/cacerts", "true");
        let none = || None;
        let empty = OsStr::new("");

        let explicit = JavaHome::locate_with(Some(&home), None, empty, none).unwrap();
        assert_eq!(explicit.home(), home);

        let env = JavaHome::locate_with(None, Some(home.as_os_str()), empty, none).unwrap();
        assert_eq!(env.home(), home);

        let path_var =
            std::env::join_paths([dir.path().join("nothing"), home.join("bin")]).unwrap();
        let from_path = JavaHome::locate_with(None, None, &path_var, none).unwrap();
        assert_eq!(from_path.home(), std::fs::canonicalize(&home).unwrap());

        let fallback_home = home.clone();
        let fallback =
            JavaHome::locate_with(None, None, empty, move || Some(fallback_home.clone())).unwrap();
        assert_eq!(fallback.home(), home);

        let err = JavaHome::locate_with(None, None, empty, none).unwrap_err();
        assert!(matches!(err, JavaError::NotFound));
        assert!(err.to_string().starts_with("no JDK found"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn platform_fallback_matches_java_home_tool() {
        let expected = Command::new("/usr/libexec/java_home")
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| PathBuf::from(String::from_utf8_lossy(&output.stdout).trim()));
        assert_eq!(platform_java_home(), expected);
    }

    #[cfg(not(target_os = "macos"))]
    #[test]
    fn platform_fallback_matches_java_home_tool() {
        assert_eq!(platform_java_home(), None);
    }

    #[test]
    fn truststore_commands_import_jdk_roots_then_ca() {
        let dir = tempfile::tempdir().unwrap();
        let home = fake_jdk(dir.path(), "lib/security/cacerts", "true");
        let java = JavaHome::new(&home).unwrap();
        let commands = java
            .truststore_commands(Path::new("/s/ca.pem"), Path::new("/s/ts.p12"))
            .unwrap();
        assert_eq!(commands.len(), 2);
        assert_eq!(commands[0][0], "-importkeystore");
        assert!(commands[0].contains(&home.join("lib/security/cacerts").into_os_string()));
        assert_eq!(commands[1][0], "-importcert");
        assert!(commands[1].contains(&OsString::from(CA_ALIAS)));
        assert!(commands[1].contains(&OsString::from("/s/ca.pem")));

        std::fs::remove_file(home.join("lib/security/cacerts")).unwrap();
        assert!(matches!(
            java.truststore_commands(Path::new("/s/ca.pem"), Path::new("/s/ts.p12")),
            Err(JavaError::Invalid(_))
        ));
    }

    /// Appends a line to every keystore file named in the arguments.
    const WRITE_KEYSTORES: &str = r#"while [ $# -gt 0 ]; do
  case "$1" in -destkeystore|-keystore) echo written >> "$2";; esac
  shift
done"#;

    #[test]
    fn keytool_failures_remove_partial_truststores() {
        let dir = tempfile::tempdir().unwrap();
        let script = format!("{WRITE_KEYSTORES}\necho 'bad things' >&2\nexit 3");
        let home = fake_jdk(dir.path(), "lib/security/cacerts", &script);
        let out = dir.path().join("ts/out.p12");
        let err = JavaHome::new(&home)
            .unwrap()
            .build_truststore(Path::new("/s/ca.pem"), &out)
            .unwrap_err();
        assert_eq!(err.to_string(), "keytool failed: bad things");
        assert!(!out.exists(), "the partial truststore must be removed");
    }

    #[test]
    fn rebuilding_replaces_the_previous_truststore() {
        let dir = tempfile::tempdir().unwrap();
        let home = fake_jdk(dir.path(), "lib/security/cacerts", WRITE_KEYSTORES);
        let out = dir.path().join("out.p12");
        std::fs::write(&out, "old\n").unwrap();
        JavaHome::new(&home)
            .unwrap()
            .build_truststore(Path::new("/s/ca.pem"), &out)
            .unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap(), "written\nwritten\n");
    }

    #[test]
    fn unwritable_targets_are_reported() {
        let dir = tempfile::tempdir().unwrap();
        let home = fake_jdk(dir.path(), "lib/security/cacerts", WRITE_KEYSTORES);
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let err = JavaHome::new(&home)
            .unwrap()
            .build_truststore(Path::new("/s/ca.pem"), &blocker.join("ts.p12"))
            .unwrap_err();
        assert!(matches!(err, JavaError::Io(_)), "{err:?}");
    }

    #[test]
    fn jvm_flags_point_to_proxy_and_truststore() {
        let flags = jvm_flags("0.0.0.0:8899".parse().unwrap(), Path::new("/s/ts.p12"));
        assert_eq!(
            flags,
            vec![
                "-Dhttp.proxyHost=127.0.0.1",
                "-Dhttp.proxyPort=8899",
                "-Dhttps.proxyHost=127.0.0.1",
                "-Dhttps.proxyPort=8899",
                "-Djavax.net.ssl.trustStore=/s/ts.p12",
                "-Djavax.net.ssl.trustStorePassword=changeit",
                "-Djavax.net.ssl.trustStoreType=PKCS12",
            ]
        );
        assert_eq!(
            proxy_host("10.0.0.5:1".parse().unwrap()).to_string(),
            "10.0.0.5"
        );
    }
}
