//! Files created by `fauxy init`.

use super::load::parse_listen;
use super::schema::GlobalFile;
use anyhow::{Context, bail};
use std::io::{self, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

pub const CONFIG_YAML: &str = r#"# fauxy global configuration.
# Rule files are reloaded automatically; changes to 'listen' and 'upstream'
# require a restart (fauxy restart).

# Proxy address. Keep it on 127.0.0.1 so only local clients can use it.
listen: 127.0.0.1:8899

# Directories or files with mock rules. Directories are scanned for *.yaml and
# *.yml; JSON rule files must be listed explicitly. Relative paths start from
# this file and '~' is expanded.
mocks:
  - mocks

# Real servers are validated with the system CAs. Add extra PEM CAs here if a
# server uses a private chain.
upstream:
  ca_files: []
"#;

/// Example mock file, disabled so it never changes traffic by surprise.
pub const EXAMPLE_MOCK_YAML: &str = r#"# Example rules. Set 'enabled' to true to enable this file.
# The first enabled rule that matches a request wins; requests without a
# matching rule go to the real server.
enabled: false

# Default host of the rules below (wildcards allowed: *.example.com).
host: api.example.com

rules:
  - name: example-login
    match:
      method: POST
      path: /v1/login
    respond:
      status: 200
      json: { token: "abc123", expires_in: 3600 }

  - name: example-user
    match:
      method: GET
      path: /v1/users/:id          # :id and * match one segment, ** any number
      query: { verbose: "true" }   # "*" accepts any value
    respond:
      status: 200
      headers: { X-Mocked-By: fauxy }
      body: '{"id": 1, "name": "Alice"}'
      delay: 300ms

  - name: example-outage
    enabled: false
    match:
      url: https://payments.example.com/v2/charges
    respond:
      status: 503
      headers: { Retry-After: "30" }
      body: service unavailable
"#;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct InitReport {
    pub created: Vec<PathBuf>,
    /// Existing files left untouched.
    pub skipped: Vec<PathBuf>,
    /// Existing files whose `listen` port was changed.
    pub updated: Vec<PathBuf>,
}

/// Writes the default configuration to `config_file` and an example rule file
/// to the `mocks` directory next to it, keeping existing files unless `force`
/// is set. With `port`, a new configuration listens on it and the `listen`
/// setting of an existing one is updated in place.
pub fn init(config_file: &Path, force: bool, port: Option<u16>) -> anyhow::Result<InitReport> {
    let mut report = InitReport::default();
    match port {
        // Done first: a file that cannot be edited leaves everything as it was.
        Some(port) if config_file.symlink_metadata().is_ok() && !force => {
            let text = edit_port(config_file, port)?;
            replace(config_file, &text)
                .with_context(|| format!("cannot write {}", config_file.display()))?;
            report.updated.push(config_file.to_path_buf());
        }
        _ => {
            let content = port.map_or_else(|| CONFIG_YAML.to_owned(), config_yaml);
            create(config_file, &content, force, &mut report)?;
        }
    }
    let dir = config_file.parent().unwrap_or(Path::new("."));
    create(
        &dir.join("mocks/example.yaml"),
        EXAMPLE_MOCK_YAML,
        force,
        &mut report,
    )?;
    Ok(report)
}

/// Writes `path` unless it exists. `force` overwrites regular files but not
/// symbolic links, which may point anywhere.
fn create(path: &Path, content: &str, force: bool, report: &mut InitReport) -> anyhow::Result<()> {
    match path.symlink_metadata() {
        Ok(_) if !force => {
            report.skipped.push(path.to_path_buf());
            return Ok(());
        }
        Ok(meta) if meta.is_symlink() => bail!(
            "{} is a symbolic link; remove it or edit the file it points to by hand",
            path.display()
        ),
        _ => {}
    }
    let write = || {
        std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
        std::fs::write(path, content)
    };
    write().with_context(|| format!("cannot write {}", path.display()))?;
    report.created.push(path.to_path_buf());
    Ok(())
}

/// The default `config.yaml` listening on `port`.
pub fn config_yaml(port: u16) -> String {
    CONFIG_YAML.replacen(
        "listen: 127.0.0.1:8899",
        &format!("listen: 127.0.0.1:{port}"),
        1,
    )
}

/// The content of `config_file` with the port of `listen` set to `port`.
fn edit_port(config_file: &Path, port: u16) -> anyhow::Result<String> {
    let path = config_file.display();
    let read_error = || format!("cannot read {path}");
    if std::fs::symlink_metadata(config_file)
        .with_context(read_error)?
        .is_symlink()
    {
        bail!("{path} is a symbolic link; set 'listen: {port}' in the file it points to by hand");
    }
    let text = std::fs::read_to_string(config_file).with_context(read_error)?;
    with_port(&text, port).with_context(|| {
        format!("cannot set the port of {path} automatically; set 'listen: {port}' in it by hand")
    })
}

/// `text` with its top-level `listen` set to `port`, keeping the host, a
/// trailing comment and the line endings; `listen` is added when missing.
/// `None` when the result does not read back with that port, so a file this
/// cannot edit safely is never written.
fn with_port(text: &str, port: u16) -> Option<String> {
    let (bom, text) = text
        .strip_prefix('\u{feff}')
        .map_or(("", text), |rest| ("\u{feff}", rest));
    let eol = if text.contains("\r\n") { "\r\n" } else { "\n" };
    let mut found = false;
    let mut lines: Vec<String> = text
        .lines()
        .map(|line| match listen_value(line).filter(|_| !found) {
            Some(value) => {
                found = true;
                listen_line(value, port)
            }
            None => line.to_owned(),
        })
        .collect();
    if !found {
        lines.push(listen_line("", port));
    }
    let updated = format!("{bom}{}{eol}", lines.join(eol));
    let reread = serde_saphyr::from_str::<GlobalFile>(&updated).ok()?;
    let listen = parse_listen(&reread.listen?).ok()?;
    (listen.port() == port).then_some(updated)
}

/// What follows a top-level `listen:` key.
fn listen_value(line: &str) -> Option<&str> {
    line.strip_prefix("listen:")
        .filter(|rest| rest.is_empty() || rest.starts_with([' ', '\t']))
}

/// `listen` on `port`, keeping the host of `value` (loopback when it has none)
/// and its comment.
fn listen_line(value: &str, port: u16) -> String {
    let (value, comment) = value.split_once('#').unwrap_or((value, ""));
    let host = parse_listen(value.trim().trim_matches(['\'', '"']))
        .map_or(Ipv4Addr::LOCALHOST.into(), |addr| addr.ip());
    let listen = yaml_listen(SocketAddr::new(host, port));
    if comment.is_empty() {
        format!("listen: {listen}")
    } else {
        format!("listen: {listen}  #{comment}")
    }
}

/// IPv6 addresses start with '[', which YAML reads as a list unless quoted.
fn yaml_listen(listen: SocketAddr) -> String {
    if listen.is_ipv6() {
        format!("'{listen}'")
    } else {
        listen.to_string()
    }
}

/// Replaces `path` through a temporary file next to it, so a daemon watching
/// it never reads a partial file. The permissions are kept, and a read-only
/// file stays untouched as a direct write would.
fn replace(path: &Path, text: &str) -> io::Result<()> {
    let permissions = std::fs::metadata(path)?.permissions();
    if permissions.readonly() {
        let message = "the file is read-only";
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, message));
    }
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let temporary = path.with_file_name(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&temporary);
    let result = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)
        .and_then(|mut file| {
            file.set_permissions(permissions)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_file;

    fn config_in(dir: &tempfile::TempDir) -> PathBuf {
        dir.path().join("config.yaml")
    }

    #[test]
    fn init_creates_valid_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let report = init(&config_in(&dir), false, None).unwrap();
        assert_eq!(
            report.created,
            vec![config_in(&dir), dir.path().join("mocks/example.yaml")]
        );
        assert!(report.skipped.is_empty());
        assert!(report.updated.is_empty());

        let loaded = load_file(&config_in(&dir), None).unwrap();
        assert_eq!(loaded.listen, "127.0.0.1:8899".parse().unwrap());
        assert_eq!(loaded.rules.len(), 3);
        assert!(loaded.rules.rules().iter().all(|rule| !rule.enabled));
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn init_keeps_existing_files_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(config_in(&dir), "listen: 1234\n").unwrap();

        let report = init(&config_in(&dir), false, None).unwrap();
        assert_eq!(report.skipped, vec![config_in(&dir)]);
        assert_eq!(
            std::fs::read_to_string(config_in(&dir)).unwrap(),
            "listen: 1234\n"
        );

        let report = init(&config_in(&dir), true, None).unwrap();
        assert_eq!(report.created.len(), 2);
        assert_eq!(
            std::fs::read_to_string(config_in(&dir)).unwrap(),
            CONFIG_YAML
        );
    }

    #[test]
    fn init_reports_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        let config = blocker.join("config.yaml");
        let err = init(&config, false, None).unwrap_err();
        assert!(
            format!("{err:#}").starts_with(&format!("cannot write {}: ", config.display())),
            "{err:#}"
        );
    }

    #[test]
    fn example_write_failures_name_the_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mocks"), "").unwrap();
        let err = init(&config_in(&dir), false, None).unwrap_err();
        let example = dir.path().join("mocks/example.yaml");
        assert!(
            format!("{err:#}").starts_with(&format!("cannot write {}: ", example.display())),
            "{err:#}"
        );
    }

    #[test]
    fn port_is_written_into_a_new_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let report = init(&config_in(&dir), false, Some(9000)).unwrap();
        assert_eq!(report.created.len(), 2);
        let loaded = load_file(&config_in(&dir), None).unwrap();
        assert_eq!(loaded.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config_yaml(8899), CONFIG_YAML);
    }

    #[test]
    fn port_of_an_existing_configuration_is_updated_in_place() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = config_in(&dir);
        let original = "# mine\nlisten: 0.0.0.0:8899   # all interfaces\nmocks: [rules]\n";
        std::fs::write(&config, original).unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o640)).unwrap();

        let report = init(&config, false, Some(9001)).unwrap();
        assert_eq!(report.updated, vec![config.clone()]);
        assert_eq!(report.created, vec![dir.path().join("mocks/example.yaml")]);
        assert!(report.skipped.is_empty());
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "# mine\nlisten: 0.0.0.0:9001  # all interfaces\nmocks: [rules]\n"
        );
        let mode = std::fs::metadata(&config).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o640, "permissions are kept");
        assert!(!dir.path().join(".config.yaml.tmp").exists());

        let report = init(&config, true, Some(9002)).unwrap();
        assert!(report.updated.is_empty(), "--force rewrites the whole file");
        assert_eq!(std::fs::read_to_string(&config).unwrap(), config_yaml(9002));
    }

    #[test]
    fn files_that_cannot_be_edited_leave_everything_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(&dir);
        std::fs::write(&config, "{\"mocks\": [\"m\"]}\n").unwrap();
        let err = init(&config, false, Some(9000)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "cannot set the port of {} automatically; set 'listen: 9000' in it by hand",
                config.display()
            )
        );
        assert!(
            !dir.path().join("mocks").exists(),
            "nothing is created when the edit fails"
        );
    }

    #[test]
    fn symbolic_links_are_not_edited() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.yaml");
        std::fs::write(&target, "listen: 8899\n").unwrap();
        std::os::unix::fs::symlink(&target, config_in(&dir)).unwrap();
        let err = init(&config_in(&dir), false, Some(9000)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{} is a symbolic link; set 'listen: 9000' in the file it points to by hand",
                config_in(&dir).display()
            )
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "listen: 8899\n");
    }

    #[test]
    fn forced_writes_do_not_follow_symbolic_links() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.yaml");
        std::fs::write(&target, "listen: 8899\n").unwrap();
        std::os::unix::fs::symlink(&target, config_in(&dir)).unwrap();
        let err = init(&config_in(&dir), true, Some(9000)).unwrap_err();
        assert_eq!(
            err.to_string(),
            format!(
                "{} is a symbolic link; remove it or edit the file it points to by hand",
                config_in(&dir).display()
            )
        );
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "listen: 8899\n");

        let dangling = tempfile::tempdir().unwrap();
        let missing = dangling.path().join("missing.yaml");
        std::os::unix::fs::symlink(&missing, config_in(&dangling)).unwrap();
        let report = init(&config_in(&dangling), false, None).unwrap();
        assert_eq!(report.skipped, vec![config_in(&dangling)]);
        assert!(!missing.exists(), "nothing is created through the link");
        let err = init(&config_in(&dangling), false, Some(9000)).unwrap_err();
        assert!(err.to_string().contains("is a symbolic link"), "{err}");
    }

    #[test]
    fn read_only_configurations_are_not_replaced() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = config_in(&dir);
        std::fs::write(&config, "listen: 8899\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o444)).unwrap();
        let err = init(&config, false, Some(9000)).unwrap_err();
        assert_eq!(
            format!("{err:#}"),
            format!("cannot write {}: the file is read-only", config.display())
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "listen: 8899\n");
    }

    #[test]
    fn unreadable_configurations_are_reported() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let config = config_in(&dir);
        std::fs::write(&config, "listen: 8899\n").unwrap();
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000)).unwrap();
        let err = init(&config, false, Some(9000)).unwrap_err();
        assert!(
            format!("{err:#}").starts_with(&format!("cannot read {}: ", config.display())),
            "{err:#}"
        );
    }

    #[test]
    fn failed_replacements_keep_the_original() {
        let dir = tempfile::tempdir().unwrap();
        let config = config_in(&dir);
        std::fs::write(&config, "listen: 8899\n").unwrap();
        std::fs::create_dir_all(dir.path().join(".config.yaml.tmp/busy")).unwrap();
        let err = init(&config, false, Some(9000)).unwrap_err();
        assert!(
            format!("{err:#}").starts_with(&format!("cannot write {}: ", config.display())),
            "{err:#}"
        );
        assert_eq!(std::fs::read_to_string(&config).unwrap(), "listen: 8899\n");

        std::fs::remove_dir_all(dir.path().join(".config.yaml.tmp")).unwrap();
        std::fs::write(dir.path().join(".config.yaml.tmp"), "stale").unwrap();
        init(&config, false, Some(9000)).unwrap();
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "listen: 127.0.0.1:9000\n"
        );
        assert!(!dir.path().join(".config.yaml.tmp").exists());
    }

    #[test]
    fn listen_is_added_or_rebuilt_when_needed() {
        let cases = [
            ("mocks: [m]\n", "mocks: [m]\nlisten: 127.0.0.1:9000\n"),
            ("mocks: [m]", "mocks: [m]\nlisten: 127.0.0.1:9000\n"),
            ("", "listen: 127.0.0.1:9000\n"),
            (
                "listen:\nmocks: [m]\n",
                "listen: 127.0.0.1:9000\nmocks: [m]\n",
            ),
            ("listen: nonsense\n", "listen: 127.0.0.1:9000\n"),
            ("listen: localhost:8899\n", "listen: 127.0.0.1:9000\n"),
            ("listen: '[::1]:8899'\n", "listen: '[::1]:9000'\n"),
            ("listen: \"0.0.0.0:8899\"\n", "listen: 0.0.0.0:9000\n"),
            ("listen:\t8899 # tab\n", "listen: 127.0.0.1:9000  # tab\n"),
            (
                "# listen: 1\nlisten: 8899\r\nmocks: [m]\r\n",
                "# listen: 1\r\nlisten: 127.0.0.1:9000\r\nmocks: [m]\r\n",
            ),
            (
                "\u{feff}listen: 8899\nmocks: [m]\n",
                "\u{feff}listen: 127.0.0.1:9000\nmocks: [m]\n",
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(with_port(text, 9000).as_deref(), Some(expected), "{text:?}");
        }
    }

    #[test]
    fn files_that_cannot_be_edited_safely_are_refused() {
        for text in [
            "{\"mocks\": [\"m\"]}\n",
            "listen: 1\nlisten: 2\n",
            "  listen: 8899\n  mocks: [m]\n",
            "listen:8899\n",
            "listen: >\n  8899\n",
        ] {
            assert_eq!(with_port(text, 9000), None, "{text:?}");
        }
    }
}
