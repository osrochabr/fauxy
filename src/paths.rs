//! Configuration lives in `~/.config/fauxy`; runtime state (PID, control
//! socket, log and the local CA) in `~/.local/state/fauxy`. Both honor the XDG
//! variables and can be overridden with `FAUXY_CONFIG_DIR` / `FAUXY_STATE_DIR`.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

pub const ENV_CONFIG_DIR: &str = "FAUXY_CONFIG_DIR";
pub const ENV_STATE_DIR: &str = "FAUXY_STATE_DIR";

/// Longest Unix socket path the platform accepts (`sun_path` minus the NUL).
pub const MAX_SOCKET_PATH: usize = if cfg!(target_os = "macos") { 103 } else { 107 };

#[derive(Debug, thiserror::Error)]
pub enum PathsError {
    #[error("could not determine the home directory (HOME is not set)")]
    NoHome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn from_env() -> Result<Self, PathsError> {
        Self::resolve(|name| std::env::var_os(name))
    }

    pub fn resolve(get: impl Fn(&str) -> Option<OsString>) -> Result<Self, PathsError> {
        let non_empty = |name: &str| get(name).filter(|value| !value.is_empty());
        let home = non_empty("HOME").map(PathBuf::from);
        let dir = |override_var: &str, xdg_var: &str, home_rel: &str| match (
            non_empty(override_var),
            non_empty(xdg_var),
        ) {
            (Some(dir), _) => Ok(PathBuf::from(dir)),
            (None, Some(xdg)) => Ok(PathBuf::from(xdg).join("fauxy")),
            (None, None) => home
                .as_ref()
                .map(|home| home.join(home_rel))
                .ok_or(PathsError::NoHome),
        };
        Ok(Self {
            config_dir: dir(ENV_CONFIG_DIR, "XDG_CONFIG_HOME", ".config/fauxy")?,
            state_dir: dir(ENV_STATE_DIR, "XDG_STATE_HOME", ".local/state/fauxy")?,
        })
    }

    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.yaml")
    }

    pub fn default_mocks_dir(&self) -> PathBuf {
        self.config_dir.join("mocks")
    }

    pub fn socket(&self) -> PathBuf {
        self.state_dir.join("fauxy.sock")
    }

    /// The socket path, or a clear error when it is too long for the platform.
    pub fn checked_socket(&self) -> io::Result<PathBuf> {
        let socket = self.socket();
        let len = socket.as_os_str().len();
        if len > MAX_SOCKET_PATH {
            let message = format!(
                "the control socket path {} is too long ({len} bytes, at most {MAX_SOCKET_PATH}); set {ENV_STATE_DIR} to a shorter directory",
                socket.display()
            );
            return Err(io::Error::new(io::ErrorKind::InvalidInput, message));
        }
        Ok(socket)
    }

    pub fn pid_file(&self) -> PathBuf {
        self.state_dir.join("fauxy.pid")
    }

    pub fn log_file(&self) -> PathBuf {
        self.state_dir.join("fauxy.log")
    }

    pub fn ca_dir(&self) -> PathBuf {
        self.state_dir.join("ca")
    }

    pub fn ca_cert(&self) -> PathBuf {
        self.ca_dir().join("fauxy-ca.pem")
    }

    pub fn ca_key(&self) -> PathBuf {
        self.ca_dir().join("fauxy-ca-key.pem")
    }

    /// System roots plus the local CA, for tools that replace their trust
    /// store instead of extending it (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`).
    pub fn ca_bundle(&self) -> PathBuf {
        self.ca_dir().join("ca-bundle.pem")
    }

    pub fn java_truststore(&self) -> PathBuf {
        self.ca_dir().join("java-truststore.p12")
    }

    pub fn ensure_state_dir(&self) -> io::Result<()> {
        create_private_dir(&self.state_dir)
    }
}

/// Creates `dir` (and its parents) and restricts it to the current user. A
/// symbolic link or a directory owned by someone else is refused, since the
/// socket, the PID file and the CA key are written there.
pub fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    std::fs::create_dir_all(dir).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!("cannot create {}: {err}", dir.display()),
        )
    })?;
    let meta = std::fs::symlink_metadata(dir)?;
    let refuse = |reason: &str| {
        let message = format!("refusing to use {}: {reason}", dir.display());
        Err(io::Error::new(io::ErrorKind::PermissionDenied, message))
    };
    if meta.file_type().is_symlink() {
        return refuse("it is a symbolic link");
    }
    if meta.uid() != crate::sys::euid() {
        return refuse("it belongs to another user");
    }
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
}

/// Expands a leading `~` and resolves relative paths against `base`.
pub fn resolve_path(raw: &str, base: &Path, home: Option<&Path>) -> PathBuf {
    let expanded = match (raw.strip_prefix('~'), home) {
        (Some(rest), Some(home)) if rest.is_empty() || rest.starts_with('/') => {
            home.join(rest.trim_start_matches('/'))
        }
        _ => PathBuf::from(raw),
    };
    base.join(expanded)
}

pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(vars: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: HashMap<String, OsString> = vars
            .iter()
            .map(|(k, v)| ((*k).to_owned(), OsString::from(v)))
            .collect();
        move |name| map.get(name).cloned()
    }

    #[test]
    fn defaults_to_home_based_dirs() {
        let paths = Paths::resolve(env(&[("HOME", "/home/ana")])).unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/home/ana/.config/fauxy"));
        assert_eq!(
            paths.state_dir,
            PathBuf::from("/home/ana/.local/state/fauxy")
        );
    }

    #[test]
    fn honors_xdg_variables() {
        let paths = Paths::resolve(env(&[
            ("HOME", "/home/ana"),
            ("XDG_CONFIG_HOME", "/xdg/config"),
            ("XDG_STATE_HOME", "/xdg/state"),
        ]))
        .unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/xdg/config/fauxy"));
        assert_eq!(paths.state_dir, PathBuf::from("/xdg/state/fauxy"));
    }

    #[test]
    fn explicit_overrides_win() {
        let paths = Paths::resolve(env(&[
            ("XDG_CONFIG_HOME", "/xdg/config"),
            (ENV_CONFIG_DIR, "/custom/config"),
            (ENV_STATE_DIR, "/custom/state"),
        ]))
        .unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/custom/config"));
        assert_eq!(paths.state_dir, PathBuf::from("/custom/state"));
    }

    #[test]
    fn empty_variables_are_ignored() {
        let paths = Paths::resolve(env(&[
            ("HOME", "/h"),
            ("XDG_CONFIG_HOME", ""),
            (ENV_STATE_DIR, ""),
        ]))
        .unwrap();
        assert_eq!(paths.config_dir, PathBuf::from("/h/.config/fauxy"));
        assert_eq!(paths.state_dir, PathBuf::from("/h/.local/state/fauxy"));
    }

    #[test]
    fn missing_home_is_an_error() {
        let err = Paths::resolve(env(&[])).unwrap_err();
        assert!(matches!(err, PathsError::NoHome));
        assert!(err.to_string().contains("HOME"));
    }

    #[test]
    fn from_env_uses_the_process_environment() {
        assert!(Paths::from_env().is_ok());
    }

    #[test]
    fn derived_files_live_in_expected_dirs() {
        let paths = Paths {
            config_dir: "/c".into(),
            state_dir: "/s".into(),
        };
        assert_eq!(paths.config_file(), PathBuf::from("/c/config.yaml"));
        assert_eq!(paths.default_mocks_dir(), PathBuf::from("/c/mocks"));
        assert_eq!(paths.socket(), PathBuf::from("/s/fauxy.sock"));
        assert_eq!(paths.pid_file(), PathBuf::from("/s/fauxy.pid"));
        assert_eq!(paths.log_file(), PathBuf::from("/s/fauxy.log"));
        assert_eq!(paths.ca_cert(), PathBuf::from("/s/ca/fauxy-ca.pem"));
        assert_eq!(paths.ca_key(), PathBuf::from("/s/ca/fauxy-ca-key.pem"));
        assert_eq!(paths.ca_bundle(), PathBuf::from("/s/ca/ca-bundle.pem"));
        assert_eq!(
            paths.java_truststore(),
            PathBuf::from("/s/ca/java-truststore.p12")
        );
    }

    #[test]
    fn overlong_socket_paths_are_rejected() {
        let short = Paths {
            config_dir: "/c".into(),
            state_dir: "/s".into(),
        };
        assert_eq!(
            short.checked_socket().unwrap(),
            PathBuf::from("/s/fauxy.sock")
        );
        let long = Paths {
            config_dir: "/c".into(),
            state_dir: PathBuf::from("/").join("s".repeat(MAX_SOCKET_PATH)),
        };
        let err = long.checked_socket().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(
            err.to_string()
                .ends_with("set FAUXY_STATE_DIR to a shorter directory")
        );
    }

    #[test]
    fn resolve_path_expands_tilde_and_relative() {
        let home = Path::new("/home/ana");
        let base = Path::new("/etc/fauxy");
        let resolve = |raw: &str, home: Option<&Path>| resolve_path(raw, base, home);
        assert_eq!(resolve("~/mocks", Some(home)), Path::new("/home/ana/mocks"));
        assert_eq!(resolve("~", Some(home)), Path::new("/home/ana"));
        assert_eq!(resolve("mocks", Some(home)), Path::new("/etc/fauxy/mocks"));
        assert_eq!(resolve("/abs", Some(home)), Path::new("/abs"));
        assert_eq!(
            resolve("~other/x", Some(home)),
            Path::new("/etc/fauxy/~other/x")
        );
        assert_eq!(resolve("~/x", None), Path::new("/etc/fauxy/~/x"));
    }

    #[test]
    fn private_dir_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("a/b");
        create_private_dir(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700);
    }

    #[test]
    fn private_dirs_refuse_symlinks_and_foreign_owners() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let err = create_private_dir(&link).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(err.to_string().ends_with("it is a symbolic link"), "{err}");

        let err = create_private_dir(Path::new("/usr")).unwrap_err();
        assert!(
            err.to_string().ends_with("it belongs to another user"),
            "{err}"
        );
    }
}
