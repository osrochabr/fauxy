//! Files created by `fauxy init`.

use std::io;
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
}

/// Writes the default configuration into `config_dir`, keeping existing files
/// unless `force` is set.
pub fn init(config_dir: &Path, force: bool) -> io::Result<InitReport> {
    let mut report = InitReport::default();
    let files = [
        (config_dir.join("config.yaml"), CONFIG_YAML),
        (config_dir.join("mocks/example.yaml"), EXAMPLE_MOCK_YAML),
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
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_file;

    #[test]
    fn init_creates_valid_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let report = init(dir.path(), false).unwrap();
        assert_eq!(report.created.len(), 2);
        assert!(report.skipped.is_empty());

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

        let report = init(dir.path(), false).unwrap();
        assert_eq!(report.skipped, vec![dir.path().join("config.yaml")]);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("config.yaml")).unwrap(),
            "listen: 1234\n"
        );

        let report = init(dir.path(), true).unwrap();
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
        assert!(init(&blocker, false).is_err());
    }
}
