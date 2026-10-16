//! Installation of the local CA into the operating system trust store.

use std::ffi::OsStr;
use std::fmt;
use std::path::{Path, PathBuf};

/// File name used when copying the CA into system directories.
const SYSTEM_CA_NAME: &str = "fauxy-ca";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustStore {
    /// User trust settings of the login keychain.
    MacOs { keychain: PathBuf },
    /// Debian, Ubuntu, Alpine (`update-ca-certificates`).
    Debian,
    /// Fedora, RHEL (`update-ca-trust`).
    RedHat,
    /// Distributions using p11-kit's `trust`, such as Arch.
    P11Kit,
}

impl TrustStore {
    /// Looks for the trust store tools on the `PATH` and the sbin directories.
    pub fn detect() -> Option<Self> {
        let home = crate::paths::home_dir().unwrap_or_default();
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
        dirs.extend(["/usr/sbin", "/sbin", "/usr/local/sbin"].map(PathBuf::from));
        let search = std::env::join_paths(dirs).unwrap_or(path);
        Self::detect_with(std::env::consts::OS, &home, &search)
    }

    pub fn detect_with(os: &str, home: &Path, search_path: &OsStr) -> Option<Self> {
        match os {
            "macos" => Some(Self::MacOs {
                keychain: home.join("Library/Keychains/login.keychain-db"),
            }),
            "linux" => [
                ("update-ca-certificates", Self::Debian),
                ("update-ca-trust", Self::RedHat),
                ("trust", Self::P11Kit),
            ]
            .into_iter()
            .find(|(program, _)| find_program(program, search_path).is_some())
            .map(|(_, store)| store),
            _ => None,
        }
    }

    /// Whether trusting the CA here affects every user and service of the
    /// machine (and not only the current user).
    pub fn is_system_wide(&self) -> bool {
        !matches!(self, Self::MacOs { .. })
    }

    pub fn describe(&self) -> &'static str {
        match self {
            Self::MacOs { .. } => "macOS keychain (user trust settings)",
            Self::Debian => "update-ca-certificates",
            Self::RedHat => "update-ca-trust",
            Self::P11Kit => "p11-kit trust",
        }
    }
}

/// A command to run, optionally through `sudo`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl TrustCommand {
    fn new(program: &str, args: &[&str], sudo: bool) -> Self {
        let args = args.iter().map(|a| (*a).to_owned());
        if sudo {
            Self {
                program: "sudo".to_owned(),
                args: std::iter::once(program.to_owned()).chain(args).collect(),
            }
        } else {
            Self {
                program: program.to_owned(),
                args: args.collect(),
            }
        }
    }

    /// Runs the command inheriting stdio, so password prompts work.
    pub fn run(&self) -> std::io::Result<()> {
        let status = std::process::Command::new(&self.program)
            .args(&self.args)
            .status()?;
        if status.success() {
            Ok(())
        } else {
            Err(std::io::Error::other(format!(
                "command failed ({status}): {self}"
            )))
        }
    }
}

impl fmt::Display for TrustCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&shell_quote(&self.program))?;
        for arg in &self.args {
            write!(f, " {}", shell_quote(arg))?;
        }
        Ok(())
    }
}

/// Quotes a value for display in a POSIX shell.
pub fn shell_quote(value: &str) -> String {
    let safe = !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,".contains(c));
    if safe {
        value.to_owned()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// Commands that trust `ca_cert` system-wide.
pub fn install_commands(store: &TrustStore, ca_cert: &Path, sudo: bool) -> Vec<TrustCommand> {
    let ca = ca_cert.to_string_lossy();
    let copy = |target: &str| TrustCommand::new("install", &["-D", "-m", "644", &ca, target], sudo);
    match store {
        TrustStore::MacOs { keychain } => {
            let keychain = keychain.to_string_lossy();
            // Trusted for TLS server authentication only.
            let args = [
                "add-trusted-cert",
                "-r",
                "trustRoot",
                "-p",
                "ssl",
                "-k",
                &keychain,
                &ca,
            ];
            vec![TrustCommand::new("security", &args, false)]
        }
        TrustStore::Debian => vec![
            copy(&debian_target()),
            TrustCommand::new("update-ca-certificates", &[], sudo),
        ],
        TrustStore::RedHat => vec![
            copy(&redhat_target()),
            TrustCommand::new("update-ca-trust", &["extract"], sudo),
        ],
        TrustStore::P11Kit => vec![TrustCommand::new(
            "trust",
            &["anchor", "--store", &ca],
            sudo,
        )],
    }
}

/// Commands that remove `ca_cert` from the system trust store.
pub fn uninstall_commands(
    store: &TrustStore,
    ca_cert: &Path,
    sha256: &str,
    sudo: bool,
) -> Vec<TrustCommand> {
    let remove = |target: &str| TrustCommand::new("rm", &["-f", target], sudo);
    match store {
        TrustStore::MacOs { keychain } => {
            let keychain = keychain.to_string_lossy();
            let args = ["delete-certificate", "-Z", sha256, "-t", &keychain];
            vec![TrustCommand::new("security", &args, false)]
        }
        TrustStore::Debian => vec![
            remove(&debian_target()),
            TrustCommand::new("update-ca-certificates", &["--fresh"], sudo),
        ],
        TrustStore::RedHat => vec![
            remove(&redhat_target()),
            TrustCommand::new("update-ca-trust", &["extract"], sudo),
        ],
        TrustStore::P11Kit => {
            let ca = ca_cert.to_string_lossy();
            vec![TrustCommand::new(
                "trust",
                &["anchor", "--remove", &ca],
                sudo,
            )]
        }
    }
}

fn debian_target() -> String {
    format!("/usr/local/share/ca-certificates/{SYSTEM_CA_NAME}.crt")
}

fn redhat_target() -> String {
    format!("/etc/pki/ca-trust/source/anchors/{SYSTEM_CA_NAME}.pem")
}

/// Looks up an executable in the directories of `path_var`.
pub fn find_program(name: &str, path_var: &OsStr) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    std::env::split_paths(path_var)
        .map(|dir| dir.join(name))
        .find(|candidate| {
            std::fs::metadata(candidate)
                .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rendered(commands: &[TrustCommand]) -> Vec<String> {
        commands.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn detects_macos() {
        let empty = OsStr::new("");
        let store = TrustStore::detect_with("macos", Path::new("/Users/ana"), empty).unwrap();
        assert_eq!(
            store,
            TrustStore::MacOs {
                keychain: "/Users/ana/Library/Keychains/login.keychain-db".into()
            }
        );
        assert_eq!(store.describe(), "macOS keychain (user trust settings)");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn detects_the_current_system() {
        assert!(matches!(
            TrustStore::detect(),
            Some(TrustStore::MacOs { .. })
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detects_the_current_system() {
        let path = std::env::var_os("PATH").unwrap_or_default();
        let mut dirs: Vec<PathBuf> = std::env::split_paths(&path).collect();
        dirs.extend(["/usr/sbin", "/sbin", "/usr/local/sbin"].map(PathBuf::from));
        let search = std::env::join_paths(dirs).unwrap();
        let explicit = TrustStore::detect_with("linux", Path::new("/"), &search);
        assert_eq!(TrustStore::detect(), explicit);
    }

    #[test]
    fn detects_linux_flavors_in_priority_order() {
        use std::os::unix::fs::PermissionsExt;

        let with = |programs: &[&str]| {
            let dir = tempfile::tempdir().unwrap();
            for program in programs {
                let path = dir.path().join(program);
                std::fs::write(&path, "").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            TrustStore::detect_with("linux", Path::new("/h"), dir.path().as_os_str())
        };
        assert_eq!(
            with(&["update-ca-certificates", "trust"]),
            Some(TrustStore::Debian)
        );
        assert_eq!(
            with(&["update-ca-trust", "trust"]),
            Some(TrustStore::RedHat)
        );
        assert_eq!(with(&["trust"]), Some(TrustStore::P11Kit));
        assert_eq!(with(&[]), None);
        assert_eq!(
            TrustStore::detect_with("windows", Path::new("/"), OsStr::new("")),
            None
        );
    }

    #[test]
    fn macos_commands_use_user_keychain() {
        let store = TrustStore::MacOs {
            keychain: "/Users/ana/Library/Keychains/login.keychain-db".into(),
        };
        let ca = Path::new("/s/ca/fauxy-ca.pem");
        assert_eq!(
            rendered(&install_commands(&store, ca, true)),
            vec![
                "security add-trusted-cert -r trustRoot -p ssl -k /Users/ana/Library/Keychains/login.keychain-db /s/ca/fauxy-ca.pem"
            ]
        );
        assert_eq!(
            rendered(&uninstall_commands(&store, ca, "AB12", true)),
            vec![
                "security delete-certificate -Z AB12 -t /Users/ana/Library/Keychains/login.keychain-db"
            ]
        );
    }

    #[test]
    fn linux_commands_use_sudo_when_requested() {
        let ca = Path::new("/s/ca.pem");
        assert_eq!(
            rendered(&install_commands(&TrustStore::Debian, ca, true)),
            vec![
                "sudo install -D -m 644 /s/ca.pem /usr/local/share/ca-certificates/fauxy-ca.crt",
                "sudo update-ca-certificates",
            ]
        );
        assert_eq!(
            rendered(&install_commands(&TrustStore::RedHat, ca, false)),
            vec![
                "install -D -m 644 /s/ca.pem /etc/pki/ca-trust/source/anchors/fauxy-ca.pem",
                "update-ca-trust extract",
            ]
        );
        assert_eq!(
            rendered(&install_commands(&TrustStore::P11Kit, ca, true)),
            vec!["sudo trust anchor --store /s/ca.pem"]
        );
        assert_eq!(
            rendered(&uninstall_commands(&TrustStore::Debian, ca, "x", true)),
            vec![
                "sudo rm -f /usr/local/share/ca-certificates/fauxy-ca.crt",
                "sudo update-ca-certificates --fresh",
            ]
        );
        assert_eq!(
            rendered(&uninstall_commands(&TrustStore::RedHat, ca, "x", false)),
            vec![
                "rm -f /etc/pki/ca-trust/source/anchors/fauxy-ca.pem",
                "update-ca-trust extract",
            ]
        );
        assert_eq!(
            rendered(&uninstall_commands(&TrustStore::P11Kit, ca, "x", false)),
            vec!["trust anchor --remove /s/ca.pem"]
        );
    }

    #[test]
    fn shell_quoting() {
        assert_eq!(shell_quote("/a/b.pem"), "/a/b.pem");
        assert_eq!(shell_quote("with space"), "'with space'");
        assert_eq!(shell_quote("it's"), "'it'\\''s'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn run_reports_failures() {
        TrustCommand::new("true", &[], false).run().unwrap();
        let err = TrustCommand::new("false", &["x y"], false)
            .run()
            .unwrap_err();
        assert!(err.to_string().starts_with("command failed ("), "{err}");
        assert!(err.to_string().ends_with("): false 'x y'"), "{err}");
        assert!(
            TrustCommand::new("/does/not/exist", &[], false)
                .run()
                .is_err()
        );
    }

    #[test]
    fn find_program_searches_path() {
        let found = find_program("sh", OsStr::new("/bin:/usr/bin")).unwrap();
        assert!(found.ends_with("sh"));
        assert!(find_program("no-such-program", OsStr::new("/bin")).is_none());
    }

    #[test]
    fn only_the_macos_store_is_per_user() {
        let mac = TrustStore::MacOs {
            keychain: "/k".into(),
        };
        assert!(!mac.is_system_wide());
        for store in [TrustStore::Debian, TrustStore::RedHat, TrustStore::P11Kit] {
            assert!(store.is_system_wide(), "{store:?}");
        }
    }

    #[test]
    fn describe_names() {
        assert_eq!(TrustStore::Debian.describe(), "update-ca-certificates");
        assert_eq!(TrustStore::RedHat.describe(), "update-ca-trust");
        assert_eq!(TrustStore::P11Kit.describe(), "p11-kit trust");
    }
}
