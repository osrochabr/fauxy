//! Files created by `fauxy init`.

use super::load::parse_listen;
use super::schema::GlobalFile;
use std::io;
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

/// Writes the default configuration into `config_dir`, keeping existing files
/// unless `force` is set. With `port`, a new `config.yaml` listens on it and
/// the `listen` setting of an existing one is updated in place.
pub fn init(config_dir: &Path, force: bool, port: Option<u16>) -> io::Result<InitReport> {
    let mut report = InitReport::default();
    let config = config_dir.join("config.yaml");
    let files = [
        (
            config.clone(),
            port.map_or_else(|| CONFIG_YAML.to_owned(), config_yaml),
        ),
        (
            config_dir.join("mocks/example.yaml"),
            EXAMPLE_MOCK_YAML.to_owned(),
        ),
    ];
    for (path, content) in files {
        if path.exists() && !force {
            report.skipped.push(path);
            continue;
        }
        std::fs::create_dir_all(path.parent().unwrap_or(config_dir))?;
        std::fs::write(&path, content)?;
        report.created.push(path);
    }
    if let Some(port) = port
        && report.skipped.contains(&config)
    {
        let text = std::fs::read_to_string(&config)?;
        std::fs::write(&config, with_port(&text, port, &config)?)?;
        report.skipped.retain(|path| path != &config);
        report.updated.push(config);
    }
    Ok(report)
}

/// The default `config.yaml` listening on `port`.
pub fn config_yaml(port: u16) -> String {
    CONFIG_YAML.replacen(
        "listen: 127.0.0.1:8899",
        &format!("listen: 127.0.0.1:{port}"),
        1,
    )
}

/// `text` with its top-level `listen` set to `port`, keeping the host and a
/// trailing comment; `listen` is added when missing. The result is parsed
/// back, so a file this cannot edit safely is reported instead of written.
fn with_port(text: &str, port: u16, path: &Path) -> io::Result<String> {
    let mut found = false;
    let mut lines: Vec<String> = text
        .lines()
        .map(
            |line| match line.strip_prefix("listen:").filter(|_| !found) {
                Some(rest) => {
                    found = true;
                    let (value, comment) = rest.split_once('#').unwrap_or((rest, ""));
                    let host = parse_listen(value.trim().trim_matches(['\'', '"']))
                        .map_or(Ipv4Addr::LOCALHOST.into(), |addr| addr.ip());
                    let listen = yaml_listen(SocketAddr::new(host, port));
                    if comment.is_empty() {
                        format!("listen: {listen}")
                    } else {
                        format!("listen: {listen}  #{comment}")
                    }
                }
                None => line.to_owned(),
            },
        )
        .collect();
    if !found {
        lines.push(format!(
            "listen: {}",
            yaml_listen(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
        ));
    }
    let updated = lines.join("\n") + "\n";
    let reread = serde_saphyr::from_str::<GlobalFile>(&updated).ok();
    match reread
        .and_then(|global| global.listen)
        .map(|raw| parse_listen(&raw))
    {
        Some(Ok(listen)) if listen.port() == port => Ok(updated),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "cannot set the port of {} automatically; set 'listen: {port}' in it by hand",
                path.display()
            ),
        )),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_file;

    #[test]
    fn init_creates_valid_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let report = init(dir.path(), false, None).unwrap();
        assert_eq!(report.created.len(), 2);
        assert!(report.skipped.is_empty());
        assert!(report.updated.is_empty());

        let loaded = load_file(&dir.path().join("config.yaml"), None).unwrap();
        assert_eq!(loaded.listen, "127.0.0.1:8899".parse().unwrap());
        assert_eq!(loaded.rules.len(), 3);
        assert!(loaded.rules.rules().iter().all(|rule| !rule.enabled));
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn init_keeps_existing_files_unless_forced() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("config.yaml"), "listen: 1234\n").unwrap();

        let report = init(dir.path(), false, None).unwrap();
        assert_eq!(report.skipped, vec![dir.path().join("config.yaml")]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.yaml")).unwrap(),
            "listen: 1234\n"
        );

        let report = init(dir.path(), true, None).unwrap();
        assert_eq!(report.created.len(), 2);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.yaml")).unwrap(),
            CONFIG_YAML
        );
    }

    #[test]
    fn init_reports_write_failures() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        assert!(init(&blocker, false, None).is_err());
    }

    #[test]
    fn port_is_written_into_a_new_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let report = init(dir.path(), false, Some(9000)).unwrap();
        assert_eq!(report.created.len(), 2);
        let loaded = load_file(&dir.path().join("config.yaml"), None).unwrap();
        assert_eq!(loaded.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(config_yaml(8899), CONFIG_YAML);
    }

    #[test]
    fn port_of_an_existing_configuration_is_updated_in_place() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let original = "# mine\nlisten: 0.0.0.0:8899   # all interfaces\nmocks: [rules]\n";
        std::fs::write(&config, original).unwrap();

        let report = init(dir.path(), false, Some(9001)).unwrap();
        assert_eq!(report.updated, vec![config.clone()]);
        assert!(!report.skipped.contains(&config));
        assert_eq!(
            std::fs::read_to_string(&config).unwrap(),
            "# mine\nlisten: 0.0.0.0:9001  # all interfaces\nmocks: [rules]\n"
        );

        let report = init(dir.path(), true, Some(9002)).unwrap();
        assert!(report.updated.is_empty(), "--force rewrites the whole file");
        assert_eq!(std::fs::read_to_string(&config).unwrap(), config_yaml(9002));
    }

    #[test]
    fn listen_is_added_or_rebuilt_when_needed() {
        let path = Path::new("config.yaml");
        assert_eq!(
            with_port("mocks: [m]\n", 9000, path).unwrap(),
            "mocks: [m]\nlisten: 127.0.0.1:9000\n"
        );
        assert_eq!(
            with_port("listen: '[::1]:8899'\n", 9000, path).unwrap(),
            "listen: '[::1]:9000'\n"
        );
        assert_eq!(
            with_port("listen: nonsense\n", 9000, path).unwrap(),
            "listen: 127.0.0.1:9000\n"
        );
        assert_eq!(
            with_port("", 9000, path).unwrap(),
            "listen: 127.0.0.1:9000\n"
        );
    }

    #[test]
    fn files_that_cannot_be_edited_safely_are_reported() {
        let err =
            with_port("{\"mocks\": [\"m\"]}\n", 9000, Path::new("/c/config.yaml")).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            err.to_string(),
            "cannot set the port of /c/config.yaml automatically; set 'listen: 9000' in it by hand"
        );
    }
}
