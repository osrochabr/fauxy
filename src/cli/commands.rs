use super::output;
use super::{CaAction, Command, EXIT_NOT_RUNNING, EnvArgs, RulesAction, ServiceAction};
use crate::config::{self, LoadedConfig, templates};
use crate::control::{ClientError, ControlClient, RuleInfo};
use crate::daemon::logging::{self, tail};
use crate::daemon::process::{self, ProcessError};
use crate::daemon::{self, RunOptions, service};
use crate::envvars::{self, ALL_VARIABLES, EnvSpec, Shell};
use crate::events::printable;
use crate::java::{JavaHome, jvm_flags};
use crate::paths::Paths;
use crate::rules::{RequestInfo, Scheme};
use crate::tls::{LocalCa, TrustStore, install_commands, uninstall_commands, write_bundle};
use anyhow::{Context, bail};
use std::io::{Read, Seek, SeekFrom, Write};
use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::time::Duration;
use tokio::runtime::Runtime;

pub(super) fn execute(
    command: Command,
    paths: &Paths,
    config: Option<&Path>,
    runtime: &Runtime,
) -> anyhow::Result<ExitCode> {
    match command {
        Command::Init { force, port } => init(paths, config, force, port, runtime),
        Command::Run {
            log_file,
            no_watch,
            port,
            detach,
        } => {
            if detach {
                crate::sys::new_session();
            }
            logging::init(log_file.as_deref())?;
            let options = RunOptions {
                config_file: config.map(Path::to_path_buf),
                no_watch,
                port,
            };
            match runtime.block_on(daemon::run_foreground(paths.clone(), options)) {
                Ok(()) => Ok(ExitCode::SUCCESS),
                Err(err) => {
                    // The log is the only output under launchd/systemd and
                    // `fauxy start`, where stderr is the log file.
                    tracing::error!(target: logging::FATAL, "{err:#}");
                    if log_file
                        .as_deref()
                        .is_some_and(|log| !logging::is_stderr(log))
                    {
                        eprintln!("error: {err:#}");
                    }
                    Ok(ExitCode::FAILURE)
                }
            }
        }
        Command::Start => runtime.block_on(start(paths, config)),
        Command::Stop => runtime.block_on(stop(paths)),
        Command::Restart => runtime.block_on(restart(paths, config)),
        Command::Status => runtime.block_on(status(paths)),
        Command::Reload => runtime.block_on(reload(paths)),
        Command::Logs { follow, lines } => runtime.block_on(logs(paths, follow, lines)),
        Command::Rules { action } => runtime.block_on(rules(paths, config, action)),
        Command::Check => check(paths, config),
        Command::Test {
            method,
            url,
            headers,
        } => {
            let loaded = load_config(paths, config)?;
            print!("{}", explain_match(&loaded, &method, &url, &headers)?.0);
            Ok(ExitCode::SUCCESS)
        }
        Command::Ca { action } => ca(paths, action),
        Command::Env(args) => runtime.block_on(env(paths, config, &args)),
        Command::Service { action } => service_command(paths, config, action, runtime),
        Command::Ui => {
            // Short timeout: the UI thread waits for every call.
            let client = ControlClient::new(paths.socket()).with_timeout(Duration::from_secs(1));
            crate::tui::run(runtime.handle(), &client)?;
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_config(paths: &Paths, config: Option<&Path>) -> anyhow::Result<LoadedConfig> {
    config::load(paths, config)
        .map_err(|errors| anyhow::anyhow!("invalid configuration:\n{errors}"))
}

fn current_exe() -> anyhow::Result<std::path::PathBuf> {
    std::env::current_exe().context("cannot locate the fauxy executable")
}

fn init(
    paths: &Paths,
    config: Option<&Path>,
    force: bool,
    port: Option<u16>,
    runtime: &Runtime,
) -> anyhow::Result<ExitCode> {
    // Checked before writing anything: the CA goes there.
    paths.ensure_state_dir()?;
    let config_file = config.map_or_else(|| paths.config_file(), Path::to_path_buf);
    let report = templates::init(&config_file, force, port)?;
    for path in &report.created {
        println!("created: {}", path.display());
    }
    for path in &report.updated {
        println!("updated the port in: {}", path.display());
    }
    for path in &report.skipped {
        println!("kept (already exists): {}", path.display());
    }
    match config::load(paths, config) {
        Ok(loaded) => {
            let listen = loaded.listen;
            println!("proxy address: {listen}");
            for warning in &loaded.warnings {
                println!("warning: {warning}");
            }
            if let Ok(status) = runtime.block_on(ControlClient::new(paths.socket()).status())
                && status.listen != listen.to_string()
            {
                println!(
                    "fauxy is running on {}; run 'fauxy restart' (or restart the service) to listen on {listen}",
                    status.listen
                );
            }
        }
        // Existing mock files may be broken; init itself worked.
        Err(_) => println!("warning: the configuration has errors; run 'fauxy check' to see them"),
    }
    let (ca, created) = LocalCa::load_or_create(paths)?;
    let verb = if created { "created" } else { "already exists" };
    println!("local CA {verb}: {}", ca.cert_path().display());
    let mocks = config_file.parent().unwrap_or(Path::new(".")).join("mocks");
    let fauxy = config.map_or_else(
        || "fauxy".to_owned(),
        |file| format!("fauxy --config {}", file.display()),
    );
    println!(
        "\nNext steps:\n  \
         1. edit the rules in {}\n  \
         2. trust the local CA (needed for HTTPS): fauxy ca install\n  \
         3. start the proxy in the background: {fauxy} start\n  \
         4. use the proxy in this shell: eval \"$({fauxy} env)\" (Java: {fauxy} env --java)",
        mocks.display()
    );
    Ok(ExitCode::SUCCESS)
}

async fn start(paths: &Paths, config: Option<&Path>) -> anyhow::Result<ExitCode> {
    let loaded = load_config(paths, config)?;
    match process::start_background(paths, &current_exe()?, config).await {
        Ok(status) => {
            println!(
                "fauxy started (pid {}) on {} with {} enabled rule(s)",
                status.pid, status.listen, status.rules_enabled
            );
            for warning in &loaded.warnings {
                println!("warning: {warning}");
            }
            println!("use the proxy with: eval \"$(fauxy env)\"   (Java: fauxy env --java)");
        }
        Err(err @ ProcessError::AlreadyRunning(_)) => println!("{err}"),
        Err(err) => return Err(err.into()),
    }
    Ok(ExitCode::SUCCESS)
}

async fn stop(paths: &Paths) -> anyhow::Result<ExitCode> {
    match process::stop(paths).await {
        Ok(pid) => println!("fauxy stopped (pid {pid})"),
        Err(ProcessError::NotRunning) => println!("fauxy is not running"),
        Err(err) => return Err(err.into()),
    }
    Ok(ExitCode::SUCCESS)
}

async fn restart(paths: &Paths, config: Option<&Path>) -> anyhow::Result<ExitCode> {
    match process::stop(paths).await {
        Ok(pid) => println!("fauxy stopped (pid {pid})"),
        Err(ProcessError::NotRunning) => {}
        Err(err) => return Err(err.into()),
    }
    start(paths, config).await
}

async fn status(paths: &Paths) -> anyhow::Result<ExitCode> {
    match ControlClient::new(paths.socket()).status().await {
        Ok(status) => {
            print!("{}", output::status(&status));
            Ok(ExitCode::SUCCESS)
        }
        Err(ClientError::NotRunning) => {
            println!("fauxy is not running");
            Ok(ExitCode::from(EXIT_NOT_RUNNING))
        }
        Err(err) => Err(err.into()),
    }
}

async fn reload(paths: &Paths) -> anyhow::Result<ExitCode> {
    let result = ControlClient::new(paths.socket()).reload().await?;
    for warning in &result.warnings {
        println!("warning: {warning}");
    }
    if result.ok {
        println!("configuration reloaded: {} rule(s)", result.rules);
        return Ok(ExitCode::SUCCESS);
    }
    eprintln!(
        "invalid configuration; the previous rules are still in effect:\n{}",
        result.error.unwrap_or_default()
    );
    Ok(ExitCode::FAILURE)
}

async fn logs(paths: &Paths, follow: bool, lines: usize) -> anyhow::Result<ExitCode> {
    let path = paths.log_file();
    if !path.exists() {
        println!("no log at {}", path.display());
        return Ok(ExitCode::SUCCESS);
    }
    for line in tail(&path, lines)? {
        println!("{}", printable(&line));
    }
    if !follow {
        return Ok(ExitCode::SUCCESS);
    }
    let mut offset = std::fs::metadata(&path)?.len();
    let mut stdout = std::io::stdout();
    // Created once: a SIGINT arriving between two polls must not be lost.
    let mut interrupted = std::pin::pin!(tokio::signal::ctrl_c());
    loop {
        tokio::select! {
            _ = &mut interrupted => return Ok(ExitCode::SUCCESS),
            () = tokio::time::sleep(Duration::from_millis(200)) => {}
        }
        offset = copy_new_lines(&path, offset, &mut stdout)?;
    }
}

/// Prints the complete lines appended to `path` after `offset` and returns
/// the new offset. A shorter file was truncated or rotated, so it is read
/// from the start; a missing file is waited for.
fn copy_new_lines(path: &Path, offset: u64, out: &mut impl Write) -> std::io::Result<u64> {
    let Ok(mut file) = std::fs::File::open(path) else {
        return Ok(offset);
    };
    let len = file.metadata()?.len();
    let start = if len < offset { 0 } else { offset };
    file.seek(SeekFrom::Start(start))?;
    let mut chunk = Vec::new();
    file.read_to_end(&mut chunk)?;
    let complete = chunk
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |end| end + 1);
    out.write_all(printable(&String::from_utf8_lossy(&chunk[..complete])).as_bytes())?;
    out.flush()?;
    Ok(start + complete as u64)
}

async fn rules(
    paths: &Paths,
    config: Option<&Path>,
    action: Option<RulesAction>,
) -> anyhow::Result<ExitCode> {
    let client = ControlClient::new(paths.socket());
    match action.unwrap_or(RulesAction::List) {
        RulesAction::List => match client.rules().await {
            Ok(rules) => print!("{}", output::rules_table(&rules)),
            Err(ClientError::NotRunning) => {
                let loaded = load_config(paths, config)?;
                print!("{}", output::rules_table(&offline_rules(&loaded)));
                println!("(daemon stopped: state from the configuration files)");
            }
            Err(err) => return Err(err.into()),
        },
        RulesAction::Enable { name } => {
            client.set_rule_enabled(&name, true).await?;
            println!("rule '{name}' enabled (until the daemon restarts)");
        }
        RulesAction::Disable { name } => {
            client.set_rule_enabled(&name, false).await?;
            println!("rule '{name}' disabled (until the daemon restarts)");
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn offline_rules(loaded: &LoadedConfig) -> Vec<RuleInfo> {
    loaded
        .rules
        .rules()
        .iter()
        .map(|rule| RuleInfo {
            name: rule.name.clone(),
            enabled: rule.enabled,
            overridden: false,
            matcher: rule.matcher.describe(),
            status: rule.response.status.as_u16(),
            hits: 0,
            source: rule.source.display().to_string(),
        })
        .collect()
}

fn check(paths: &Paths, config: Option<&Path>) -> anyhow::Result<ExitCode> {
    match config::load(paths, config) {
        Ok(loaded) => {
            print!("{}", check_summary(&loaded));
            Ok(ExitCode::SUCCESS)
        }
        Err(errors) => {
            eprintln!(
                "invalid configuration ({} problem(s)):\n{errors}",
                errors.0.len()
            );
            Ok(ExitCode::FAILURE)
        }
    }
}

fn check_summary(loaded: &LoadedConfig) -> String {
    let enabled = loaded.rules.rules().iter().filter(|r| r.enabled).count();
    let mut out = format!(
        "valid configuration: {} file(s), {} rule(s), {} enabled\n  proxy: {}\n",
        loaded.mock_files.len(),
        loaded.rules.len(),
        enabled,
        loaded.listen
    );
    let hosts = loaded.rules.hosts(|r| r.enabled);
    if !hosts.is_empty() {
        out.push_str(&format!("  intercepted hosts: {}\n", hosts.join(", ")));
    }
    for warning in &loaded.warnings {
        out.push_str(&format!("  warning: {warning}\n"));
    }
    out
}

/// Explains which rule answers a request. Returns the text and the rule name.
fn explain_match(
    loaded: &LoadedConfig,
    method: &str,
    url: &str,
    headers: &[String],
) -> anyhow::Result<(String, Option<String>)> {
    if !url.contains("://") {
        bail!("the URL must be absolute, e.g. https://api.example.com/path");
    }
    let mut builder = http::Request::builder()
        .method(method.to_ascii_uppercase().as_str())
        .uri(url);
    for header in headers {
        let (name, value) = header
            .split_once(':')
            .with_context(|| format!("invalid header '{header}': use NAME:VALUE"))?;
        builder = builder.header(name.trim(), value.trim());
    }
    let request = builder
        .body(())
        .with_context(|| format!("invalid request: {method} {url}"))?;
    let info = RequestInfo::from_request(&request)
        .context("the URL must be absolute, e.g. https://api.example.com/path")?;

    let mut out = String::new();
    if info.scheme == Scheme::Https {
        out.push_str(
            if loaded.rules.intercepts(info.host, info.port, |r| r.enabled) {
                "HTTPS: intercepted host (fauxy decrypts its traffic)\n"
            } else {
                "HTTPS: host not intercepted (tunneled to the real server)\n"
            },
        );
    }
    let Some(rule) = loaded.rules.find(&info, |r| r.enabled) else {
        out.push_str("no rule: the request would go to the real server\n");
        return Ok((out, None));
    };
    let delay = rule
        .response
        .delay
        .map(|d| format!(" after {}", humantime::format_duration(d)))
        .unwrap_or_default();
    out.push_str(&format!(
        "rule: {} ({})\nresponse: {}{delay}\n",
        rule.name,
        rule.source.display(),
        rule.response.status
    ));
    Ok((out, Some(rule.name.clone())))
}

fn ca(paths: &Paths, action: CaAction) -> anyhow::Result<ExitCode> {
    let (ca, _) = LocalCa::load_or_create(paths)?;
    match action {
        CaAction::Path => println!("{}", ca.cert_path().display()),
        CaAction::Install { dry_run, system } => {
            let store = require_store(TrustStore::detect(), ca.cert_path())?;
            confirm_scope(&store, system || dry_run)?;
            let commands = install_commands(&store, ca.cert_path(), crate::sys::euid() != 0);
            run_trust_commands(&store, &commands, dry_run)?;
            if !dry_run {
                let count = write_bundle(&ca, &paths.ca_bundle())?;
                let bundle = paths.ca_bundle();
                println!(
                    "local CA installed; bundle with {count} certificate(s) at {}",
                    bundle.display()
                );
                println!("Java uses its own truststore: run 'fauxy ca java' or 'fauxy env --java'");
                println!(
                    "Firefox uses its own certificate store: import {} in the browser settings",
                    ca.cert_path().display()
                );
            }
        }
        CaAction::Uninstall { dry_run } => {
            let store = require_store(TrustStore::detect(), ca.cert_path())?;
            let fingerprint = ca.sha256_fingerprint()?;
            let sudo = crate::sys::euid() != 0;
            let commands = uninstall_commands(&store, ca.cert_path(), &fingerprint, sudo);
            run_trust_commands(&store, &commands, dry_run)?;
            if !dry_run {
                println!("local CA removed from the system trust store");
            }
        }
        CaAction::Java { java_home } => {
            let java = JavaHome::locate(java_home.as_deref())?;
            java.build_truststore(ca.cert_path(), &paths.java_truststore())?;
            println!(
                "Java truststore built with the JDK at {}:\n  {}",
                java.home().display(),
                paths.java_truststore().display()
            );
            println!("password: {}", crate::java::TRUSTSTORE_PASSWORD);
            println!("JVM flags: fauxy env --jvm-flags");
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// A system-wide trust store makes every user and service of the machine
/// trust a key that lives in one user's home, so it needs `--system`.
fn confirm_scope(store: &TrustStore, confirmed: bool) -> anyhow::Result<()> {
    if store.is_system_wide() && !confirmed {
        bail!(
            "{} trusts the CA for every user and service of this machine; pass --system to confirm, or use 'fauxy env' and the Java truststore instead",
            store.describe()
        );
    }
    Ok(())
}

fn require_store(store: Option<TrustStore>, ca_cert: &Path) -> anyhow::Result<TrustStore> {
    match store {
        Some(store) => Ok(store),
        None => bail!(
            "unsupported system trust store; import {} manually",
            ca_cert.display()
        ),
    }
}

fn run_trust_commands(
    store: &TrustStore,
    commands: &[crate::tls::TrustCommand],
    dry_run: bool,
) -> anyhow::Result<()> {
    println!("trust store: {}", store.describe());
    for command in commands {
        println!("$ {command}");
        if !dry_run {
            command.run()?;
        }
    }
    Ok(())
}

async fn proxy_listen(paths: &Paths, config: Option<&Path>) -> anyhow::Result<SocketAddr> {
    if let Ok(status) = ControlClient::new(paths.socket()).status().await
        && let Ok(addr) = status.listen.parse()
    {
        return Ok(addr);
    }
    Ok(load_config(paths, config)?.listen)
}

/// Whether `derived` is missing or older than the CA certificate it contains.
fn is_stale(derived: &Path, ca_cert: &Path) -> bool {
    let modified = |path: &Path| {
        std::fs::metadata(path)
            .and_then(|meta| meta.modified())
            .ok()
    };
    match (modified(derived), modified(ca_cert)) {
        (Some(derived), Some(ca)) => derived < ca,
        _ => true,
    }
}

fn ensure_java_truststore(
    paths: &Paths,
    ca: &LocalCa,
    java_home: Option<&Path>,
) -> anyhow::Result<()> {
    let truststore = paths.java_truststore();
    if java_home.is_some() || is_stale(&truststore, ca.cert_path()) {
        JavaHome::locate(java_home)?.build_truststore(ca.cert_path(), &truststore)?;
        eprintln!("# Java truststore created at {}", truststore.display());
    }
    Ok(())
}

async fn env(paths: &Paths, config: Option<&Path>, args: &EnvArgs) -> anyhow::Result<ExitCode> {
    let shell = args
        .shell
        .as_deref()
        .and_then(Shell::parse)
        .unwrap_or_else(|| Shell::detect(std::env::var("SHELL").ok().as_deref()));
    if args.unset {
        print!("{}", envvars::render_unset(&ALL_VARIABLES, shell));
        return Ok(ExitCode::SUCCESS);
    }

    let listen = proxy_listen(paths, config).await?;
    let (ca, _) = LocalCa::load_or_create(paths)?;
    let truststore = paths.java_truststore();
    if args.jvm_flags || args.java {
        ensure_java_truststore(paths, &ca, args.java_home.as_deref())?;
    }
    if args.jvm_flags {
        println!("{}", jvm_flags(listen, &truststore).join(" "));
        return Ok(ExitCode::SUCCESS);
    }
    if is_stale(&paths.ca_bundle(), ca.cert_path()) {
        write_bundle(&ca, &paths.ca_bundle())?;
    }
    let vars = envvars::variables(&EnvSpec {
        listen,
        ca_cert: ca.cert_path(),
        ca_bundle: &paths.ca_bundle(),
        java_truststore: args.java.then_some(truststore.as_path()),
    });
    print!("{}", envvars::render_exports(&vars, shell));
    Ok(ExitCode::SUCCESS)
}

fn service_command(
    paths: &Paths,
    config: Option<&Path>,
    action: ServiceAction,
    runtime: &Runtime,
) -> anyhow::Result<ExitCode> {
    let label = service::LABEL;
    match action {
        ServiceAction::Install => {
            load_config(paths, config)?;
            // Otherwise the service's daemon would find the PID file locked,
            // exit with an error and be restarted forever.
            match runtime.block_on(process::stop(paths)) {
                Ok(pid) => println!(
                    "stopped the background daemon (pid {pid}) so the service can take over"
                ),
                Err(ProcessError::NotRunning) => {}
                Err(err) => {
                    return Err(err)
                        .context("stop the running daemon before installing the service");
                }
            }
            service::install(&current_exe()?, paths, config)
                .context("failed to install the service")?;
            println!("service '{label}' installed and started; fauxy will start with your session");
        }
        ServiceAction::Uninstall => {
            service::uninstall().context("failed to remove the service")?;
            println!("service '{label}' removed");
        }
        ServiceAction::Status => {
            let status = service::status().context("failed to query the service")?;
            println!("service '{label}': {}", service::describe(&status));
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_file;

    fn loaded(mock: &str) -> (tempfile::TempDir, LoadedConfig) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("mocks")).unwrap();
        std::fs::write(dir.path().join("mocks/m.yaml"), mock).unwrap();
        let loaded = load_file(&dir.path().join("config.yaml"), None).unwrap();
        (dir, loaded)
    }

    const MOCK: &str = "host: mail.example.com\nrules:\n  - name: send\n    match: { method: POST, path: /api/**, headers: { X-Tenant: acme } }\n    respond: { status: 201, json: {}, delay: 1s }\n  - name: templates\n    match: { path: /templates/:id }\n    respond: { json: {} }\n";

    #[test]
    fn explains_matching_rule() {
        let (_dir, loaded) = loaded(MOCK);
        let headers = ["X-Tenant: acme".to_owned()];
        let (text, rule) =
            explain_match(&loaded, "post", "https://mail.example.com/api/v1", &headers).unwrap();
        assert_eq!(rule.as_deref(), Some("send"));
        assert!(text.starts_with("HTTPS: intercepted host"), "{text}");
        assert!(text.contains("rule: send ("), "{text}");
        assert!(text.ends_with("response: 201 Created after 1s\n"), "{text}");

        let (text, _) =
            explain_match(&loaded, "GET", "https://mail.example.com/templates/7", &[]).unwrap();
        assert!(text.ends_with("response: 200 OK\n"), "{text}");
    }

    #[test]
    fn explains_missing_rule() {
        let (_dir, loaded) = loaded(MOCK);
        let (text, rule) =
            explain_match(&loaded, "GET", "https://mail.example.com/api/v1", &[]).unwrap();
        assert!(rule.is_none());
        assert!(text.ends_with("no rule: the request would go to the real server\n"));

        let (text, _) = explain_match(&loaded, "GET", "https://other.example.org/", &[]).unwrap();
        assert!(text.starts_with("HTTPS: host not intercepted"), "{text}");

        let (text, _) = explain_match(&loaded, "GET", "http://other.example.org/", &[]).unwrap();
        assert!(!text.contains("HTTPS"));
    }

    #[test]
    fn explain_rejects_bad_input() {
        let (_dir, loaded) = loaded(MOCK);
        let err = |method: &str, url: &str, headers: &[String]| {
            explain_match(&loaded, method, url, headers)
                .unwrap_err()
                .to_string()
        };
        assert!(err("GET", "/no-host", &[]).starts_with("the URL must be absolute"));
        assert!(err("GET", "api.example.com/x", &[]).starts_with("the URL must be absolute"));
        assert!(err("GET", "https://", &[]).starts_with("invalid request"));
        assert_eq!(
            err("GET", "https://x.com/", &["no-colon".into()]),
            "invalid header 'no-colon': use NAME:VALUE"
        );
        assert_eq!(
            err("G E T", "https://x.com/", &[]),
            "invalid request: G E T https://x.com/"
        );
    }

    #[test]
    fn check_summary_lists_hosts_and_warnings() {
        let (_dir, mut loaded) = loaded(MOCK);
        loaded.warnings.push("something odd".into());
        let text = check_summary(&loaded);
        assert!(text.starts_with("valid configuration: 1 file(s), 2 rule(s), 2 enabled\n"));
        assert!(text.contains("  proxy: 127.0.0.1:8899\n"));
        assert!(text.contains("  intercepted hosts: mail.example.com\n"));
        assert!(text.ends_with("  warning: something odd\n"));
    }

    #[test]
    fn offline_rules_reflect_files() {
        let (_dir, loaded) = loaded(MOCK);
        let rules = offline_rules(&loaded);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].name, "send");
        assert!(rules[0].enabled);
        assert!(!rules[0].overridden);
        assert_eq!(rules[0].status, 201);
        assert_eq!(rules[0].hits, 0);
    }

    #[test]
    fn system_wide_trust_needs_confirmation() {
        let err = confirm_scope(&TrustStore::Debian, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.starts_with("update-ca-certificates trusts the CA for every user"),
            "{err}"
        );
        assert!(err.contains("pass --system to confirm"), "{err}");
        confirm_scope(&TrustStore::Debian, true).unwrap();
        let mac = TrustStore::MacOs {
            keychain: "/k".into(),
        };
        confirm_scope(&mac, false).unwrap();
    }

    #[test]
    fn derived_files_older_than_the_ca_are_stale() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, derived) = (dir.path().join("ca.pem"), dir.path().join("bundle.pem"));
        assert!(is_stale(&derived, &ca), "missing files are stale");
        std::fs::write(&derived, "old").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&ca, "new").unwrap();
        assert!(is_stale(&derived, &ca));
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(&derived, "fresh").unwrap();
        assert!(!is_stale(&derived, &ca));
    }

    #[test]
    fn unsupported_trust_stores_are_reported() {
        let err = require_store(None, Path::new("/s/ca.pem")).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unsupported system trust store; import /s/ca.pem manually"
        );
        assert_eq!(
            require_store(Some(TrustStore::Debian), Path::new("/x")).unwrap(),
            TrustStore::Debian
        );
    }

    #[test]
    fn followed_logs_copy_only_new_complete_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        let mut out = Vec::new();
        assert_eq!(
            copy_new_lines(&log, 3, &mut out).unwrap(),
            3,
            "missing file"
        );

        std::fs::write(&log, "ab\nc").unwrap();
        assert_eq!(
            copy_new_lines(&log, 0, &mut out).unwrap(),
            3,
            "partial line waits"
        );
        std::fs::write(&log, "ab\ncd\u{1b}[2J\n").unwrap();
        assert_eq!(copy_new_lines(&log, 3, &mut out).unwrap(), 10);
        std::fs::write(&log, "xy\n").unwrap();
        assert_eq!(copy_new_lines(&log, 10, &mut out).unwrap(), 3, "truncated");
        assert_eq!(String::from_utf8(out).unwrap(), "ab\ncd\u{fffd}[2J\nxy\n");
    }
}
