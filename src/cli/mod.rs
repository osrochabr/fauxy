//! Command-line interface.

mod commands;
mod output;

use crate::paths::Paths;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit code of `fauxy status` when the daemon is not running (LSB convention).
pub const EXIT_NOT_RUNNING: u8 = 3;

/// Local HTTP/HTTPS mock proxy configured with YAML files.
#[derive(Debug, Parser)]
#[command(name = "fauxy", version, about, long_about = None)]
pub struct Cli {
    /// Global configuration file [default: ~/.config/fauxy/config.yaml].
    #[arg(short, long, global = true, env = "FAUXY_CONFIG", value_name = "FILE")]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create the initial configuration, an example mock file and the local CA.
    Init {
        /// Overwrite existing files.
        #[arg(long)]
        force: bool,
        /// Proxy port to save as 'listen' in config.yaml, also in an existing
        /// file [default for new files: 8899].
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
    },
    /// Run the daemon in the foreground (also used by launchd/systemd).
    Run {
        /// Write the log to this file instead of stderr.
        #[arg(long, value_name = "FILE")]
        log_file: Option<PathBuf>,
        /// Disable hot reload when files change.
        #[arg(long)]
        no_watch: bool,
        /// Listen on this port for this run only; config.yaml is not changed.
        #[arg(long, value_parser = clap::value_parser!(u16).range(1..))]
        port: Option<u16>,
        /// Leave the terminal session (used by `fauxy start`).
        #[arg(long, hide = true)]
        detach: bool,
    },
    /// Start the daemon in the background.
    Start,
    /// Stop the daemon.
    Stop,
    /// Restart the daemon (needed after changing 'listen' or 'upstream').
    Restart,
    /// Show the daemon status.
    Status,
    /// Reload the rules without restarting.
    Reload,
    /// Show the daemon log.
    Logs {
        /// Keep printing new lines.
        #[arg(short, long)]
        follow: bool,
        /// Number of lines to show first.
        #[arg(short = 'n', long, default_value_t = 50)]
        lines: usize,
    },
    /// List, enable or disable rules.
    Rules {
        #[command(subcommand)]
        action: Option<RulesAction>,
    },
    /// Validate the configuration files.
    Check,
    /// Show which rule would answer a request, without sending it.
    Test {
        /// HTTP method (GET, POST, ...).
        method: String,
        #[arg(help = "Absolute URL, e.g. https://api.example.com/v1/login")]
        url: String,
        /// Request header (repeatable).
        #[arg(short = 'H', long = "header", value_name = "NAME:VALUE")]
        headers: Vec<String>,
    },
    /// Manage the local CA used to intercept HTTPS.
    Ca {
        #[command(subcommand)]
        action: CaAction,
    },
    /// Print environment variables that route tools through the proxy: eval "$(fauxy env)".
    Env(EnvArgs),
    /// Install fauxy as a user service (launchd on macOS, systemd on Linux).
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },
    /// Open the terminal UI (live traffic and rules).
    Ui,
}

#[derive(Debug, Subcommand)]
pub enum RulesAction {
    /// List the rules (default).
    List,
    /// Enable a rule in memory until the daemon restarts.
    Enable {
        /// Rule name, as shown by 'fauxy rules'.
        name: String,
    },
    /// Disable a rule in memory until the daemon restarts.
    Disable {
        /// Rule name, as shown by 'fauxy rules'.
        name: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum CaAction {
    /// Trust the local CA (macOS: your login keychain; Linux: the system store).
    Install {
        /// Only print the commands.
        #[arg(long)]
        dry_run: bool,
        /// Confirm trusting the CA for every user and service of the machine
        /// (required where the trust store is system-wide, such as Linux).
        #[arg(long)]
        system: bool,
    },
    /// Remove the local CA from the system trust store.
    Uninstall {
        /// Only print the commands.
        #[arg(long)]
        dry_run: bool,
    },
    /// Print the path of the CA certificate.
    Path,
    /// Build the Java truststore (JDK roots plus the local CA).
    Java {
        /// JDK to use [default: JAVA_HOME, 'java' on the PATH or, on macOS,
        /// /usr/libexec/java_home].
        #[arg(long, value_name = "DIR")]
        java_home: Option<PathBuf>,
    },
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("java_output").args(["java", "jvm_flags"])))]
pub struct EnvArgs {
    /// Shell syntax [default: detected from $SHELL].
    #[arg(long, value_parser = ["bash", "zsh", "sh", "fish"])]
    pub shell: Option<String>,
    /// Include JAVA_TOOL_OPTIONS (builds the Java truststore if needed).
    #[arg(long)]
    pub java: bool,
    /// Print only the JVM -D flags (for IDEs, MAVEN_OPTS, ...).
    #[arg(long, conflicts_with_all = ["java", "unset", "shell"])]
    pub jvm_flags: bool,
    /// Print the commands that remove the variables.
    #[arg(long, conflicts_with = "java")]
    pub unset: bool,
    /// JDK used to build the truststore (with --java or --jvm-flags).
    #[arg(long, value_name = "DIR", requires = "java_output")]
    pub java_home: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum ServiceAction {
    /// Install and start the service; it starts again at every login.
    Install,
    /// Stop and remove the service.
    Uninstall,
    /// Show the service status.
    Status,
}

pub fn main() -> ExitCode {
    let cli = Cli::parse();
    forget_own_bundle();
    match run(cli) {
        Ok(code) => code,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

/// `fauxy env` points `SSL_CERT_FILE` at fauxy's own bundle. Reading it back
/// as the system roots would make new bundles and the daemon's upstream
/// validation depend on a stale copy, so it is ignored. Must run before any
/// thread starts.
fn forget_own_bundle() {
    let own = Paths::from_env().map(|paths| paths.ca_bundle());
    let current = std::env::var_os("SSL_CERT_FILE").map(PathBuf::from);
    if let (Ok(own), Some(current)) = (own, current)
        && own == current
    {
        crate::sys::remove_env_at_startup("SSL_CERT_FILE");
    }
}

pub fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let _ = crate::tls::crypto_provider().install_default();
    let paths = Paths::from_env()?;
    let config = cli.config.map(std::path::absolute).transpose()?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    commands::execute(cli.command, &paths, config.as_deref(), &runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("fauxy").chain(args.iter().copied()))
    }

    #[test]
    fn command_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_common_commands() {
        assert!(matches!(parse(&["start"]).unwrap().command, Command::Start));
        assert!(matches!(
            parse(&["logs", "-f", "-n", "10"]).unwrap().command,
            Command::Logs {
                follow: true,
                lines: 10
            }
        ));
        assert!(matches!(
            parse(&["rules", "disable", "x"]).unwrap().command,
            Command::Rules {
                action: Some(RulesAction::Disable { .. })
            }
        ));
        assert!(matches!(
            parse(&["rules"]).unwrap().command,
            Command::Rules { action: None }
        ));
        let cli = parse(&["-c", "/x.yaml", "test", "POST", "https://a/b", "-H", "a: b"]).unwrap();
        assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/x.yaml")));
        assert!(matches!(
            cli.command,
            Command::Test { method, url, headers }
                if method == "POST" && url == "https://a/b" && headers == vec!["a: b"]
        ));
    }

    #[test]
    fn env_flags_conflicts() {
        assert!(parse(&["env", "--jvm-flags", "--java"]).is_err());
        assert!(parse(&["env", "--unset", "--java"]).is_err());
        assert!(parse(&["env", "--shell", "pwsh"]).is_err());
        assert!(parse(&["env", "--java-home", "/jdk"]).is_err());
        assert!(parse(&["env", "--jvm-flags", "--java-home", "/jdk"]).is_ok());
        let cli = parse(&["env", "--java", "--shell", "fish"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Env(EnvArgs { java: true, shell: Some(shell), .. }) if shell == "fish"
        ));
    }

    #[test]
    fn global_config_flag_works_after_subcommand() {
        let cli = parse(&["check", "--config", "/c.yaml"]).unwrap();
        assert_eq!(cli.config.as_deref(), Some(std::path::Path::new("/c.yaml")));
    }
}
