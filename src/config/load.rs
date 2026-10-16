use super::schema::{GlobalFile, MatchSpec, MockFile, RespondSpec, RuleSpec};
use crate::paths::{Paths, resolve_path};
use crate::rules::{
    HostPattern, MockBody, MockResponse, PathPattern, RequestMatcher, Rule, RuleSet, Scheme,
    ValueMatch, parse_query,
};
use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, StatusCode};
use serde::de::DeserializeOwned;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

pub const DEFAULT_LISTEN: &str = "127.0.0.1:8899";

/// Extensions picked up when scanning a mocks directory. JSON rule files are
/// accepted only when listed explicitly in `mocks`, so `.json` body fixtures
/// can live next to the rules without being parsed as rules.
pub const MOCK_EXTENSIONS: [&str; 2] = ["yaml", "yml"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    #[error("{}: {message}", path.display())]
    File { path: PathBuf, message: String },
    #[error("{}: rule '{rule}': {message}", path.display())]
    Rule {
        path: PathBuf,
        rule: String,
        message: String,
    },
}

impl ConfigError {
    fn file(path: &Path, message: &dyn fmt::Display) -> Self {
        Self::File {
            path: path.to_path_buf(),
            message: message.to_string(),
        }
    }
}

/// Every problem found while loading, so all of them can be fixed at once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigErrors(pub Vec<ConfigError>);

impl fmt::Display for ConfigErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self.0.iter().map(ToString::to_string).collect();
        f.write_str(&lines.join("\n"))
    }
}

impl std::error::Error for ConfigErrors {}

#[derive(Debug, Clone)]
pub struct LoadedConfig {
    /// May not exist: every setting has a default.
    pub config_file: PathBuf,
    pub listen: SocketAddr,
    /// Directories or files as configured.
    pub mock_sources: Vec<PathBuf>,
    /// Files actually loaded, in evaluation order.
    pub mock_files: Vec<PathBuf>,
    pub upstream_ca_files: Vec<PathBuf>,
    pub rules: RuleSet,
    pub warnings: Vec<String>,
}

impl LoadedConfig {
    /// Listens on `port` instead of the configured one (`fauxy run --port`).
    pub fn set_port(&mut self, port: u16) {
        let before = exposure_warning(self.listen);
        self.listen.set_port(port);
        if let Some(warning) = self
            .warnings
            .iter_mut()
            .find(|w| Some(&**w) == before.as_ref())
        {
            *warning = exposure_warning(self.listen).unwrap_or_default();
        }
    }

    /// Existing directories whose changes may affect the configuration. A
    /// missing source is noticed through its parent when the parent exists.
    pub fn watch_dirs(&self) -> Vec<PathBuf> {
        let sources = self.mock_sources.iter().map(|source| {
            if source.is_dir() {
                Some(source.as_path())
            } else {
                source.parent()
            }
        });
        let mut dirs: Vec<PathBuf> = Vec::new();
        for dir in std::iter::once(self.config_file.parent())
            .chain(sources)
            .flatten()
            .filter(|dir| dir.is_dir())
        {
            if !dirs.iter().any(|known| known == dir) {
                dirs.push(dir.to_path_buf());
            }
        }
        dirs
    }

    pub fn is_relevant_change(&self, path: &Path) -> bool {
        path == self.config_file
            || self.mock_sources.iter().any(|source| source == path)
            || has_mock_extension(path)
    }
}

fn has_mock_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| MOCK_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()))
}

pub fn load(paths: &Paths, config_file: Option<&Path>) -> Result<LoadedConfig, ConfigErrors> {
    let config_file = config_file.map_or_else(|| paths.config_file(), Path::to_path_buf);
    load_file(&config_file, crate::paths::home_dir().as_deref())
}

/// Loads the configuration from `config_file`, expanding `~` with `home`.
pub fn load_file(config_file: &Path, home: Option<&Path>) -> Result<LoadedConfig, ConfigErrors> {
    let global: GlobalFile = if config_file.exists() {
        parse_file(config_file).map_err(|err| ConfigErrors(vec![err]))?
    } else {
        GlobalFile::default()
    };
    let base_dir = config_file.parent().unwrap_or(Path::new("."));
    let resolve = |raw: &String| resolve_path(raw, base_dir, home);
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    let listen = parse_listen(global.listen.as_deref().unwrap_or(DEFAULT_LISTEN))
        .inspect(|addr| warnings.extend(exposure_warning(*addr)))
        .unwrap_or_else(|message| {
            errors.push(ConfigError::file(config_file, &message));
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
        });

    let mock_sources: Vec<PathBuf> = match &global.mocks {
        Some(sources) => sources.iter().map(resolve).collect(),
        None => vec![base_dir.join("mocks")],
    };
    let upstream_ca_files: Vec<PathBuf> = global.upstream.ca_files.iter().map(resolve).collect();
    for missing in upstream_ca_files.iter().filter(|file| !file.is_file()) {
        let message = format!("upstream.ca_files: file not found '{}'", missing.display());
        errors.push(ConfigError::file(config_file, &message));
    }

    let mut mock_files = Vec::new();
    for source in &mock_sources {
        match discover(source) {
            Ok(files) => mock_files.extend(files),
            Err(None) => warnings.push(format!("mock source not found: {}", source.display())),
            Err(Some(err)) => errors.push(err),
        }
    }
    let mut seen = HashSet::new();
    mock_files.retain(|file| seen.insert(file.clone()));

    let mut rules = Vec::new();
    let mut names = HashMap::new();
    for file in &mock_files {
        match parse_file::<MockFile>(file) {
            Ok(mock) => compile_file(file, &mock, &mut names, &mut rules, &mut errors),
            Err(err) => errors.push(err),
        }
    }

    if !errors.is_empty() {
        return Err(ConfigErrors(errors));
    }
    Ok(LoadedConfig {
        config_file: config_file.to_path_buf(),
        listen,
        mock_sources,
        mock_files,
        upstream_ca_files,
        rules: RuleSet::new(rules),
        warnings,
    })
}

fn exposure_warning(listen: SocketAddr) -> Option<String> {
    (!listen.ip().is_loopback()).then(|| {
        format!(
            "listen address {listen} accepts connections from other machines: anyone who can reach it can use fauxy as an open proxy"
        )
    })
}

fn compile_file(
    file: &Path,
    mock: &MockFile,
    names: &mut HashMap<String, PathBuf>,
    rules: &mut Vec<Rule>,
    errors: &mut Vec<ConfigError>,
) {
    let file_dir = file.parent().unwrap_or(Path::new("."));
    let stem = file.file_stem().unwrap_or_default().to_string_lossy();
    for (index, spec) in mock.rules.iter().enumerate() {
        let name = spec
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map_or_else(|| format!("{stem}#{}", index + 1), str::to_owned);
        let compiled = match names.entry(name.clone()) {
            Entry::Vacant(slot) => {
                slot.insert(file.to_path_buf());
                compile_rule(spec, mock, file_dir)
            }
            Entry::Occupied(first) => Err(format!(
                "duplicate name, already used in {}; rule names must be unique",
                first.get().display()
            )),
        };
        match compiled {
            Ok((matcher, response)) => rules.push(Rule {
                name,
                source: file.to_path_buf(),
                enabled: mock.enabled && spec.enabled,
                matcher,
                response,
            }),
            Err(message) => errors.push(ConfigError::Rule {
                path: file.to_path_buf(),
                rule: name,
                message,
            }),
        }
    }
}

/// `Err(None)` means the source does not exist (a warning, not an error).
fn discover(source: &Path) -> Result<Vec<PathBuf>, Option<ConfigError>> {
    if source.is_file() {
        return Ok(vec![source.to_path_buf()]);
    }
    if !source.is_dir() {
        return Err(None);
    }
    let entries = std::fs::read_dir(source).map_err(|err| Some(ConfigError::file(source, &err)))?;
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && has_mock_extension(path) && !is_hidden(path))
        .collect();
    files.sort();
    Ok(files)
}

fn is_hidden(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|name| name.to_string_lossy().starts_with('.'))
}

fn parse_file<T: DeserializeOwned>(path: &Path) -> Result<T, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|err| ConfigError::file(path, &err))?;
    let text = if text.trim().is_empty() { "{}" } else { &text };
    serde_saphyr::from_str(text).map_err(|err| {
        let message = err
            .to_string()
            .replace("<input>", &path.display().to_string());
        ConfigError::file(path, &message.strip_prefix("error: ").unwrap_or(&message))
    })
}

/// Parses `host:port`, `localhost:port` or just `port` (loopback).
pub fn parse_listen(raw: &str) -> Result<SocketAddr, String> {
    let raw = raw.trim();
    let port = raw.strip_prefix("localhost:").unwrap_or(raw);
    if let Ok(port) = port.parse::<u16>() {
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    raw.parse()
        .map_err(|_| format!("invalid listen address '{raw}': use 127.0.0.1:8899 or just the port"))
}

fn compile_rule(
    spec: &RuleSpec,
    file: &MockFile,
    file_dir: &Path,
) -> Result<(RequestMatcher, MockResponse), String> {
    let matcher = compile_matcher(&spec.matcher, file.host.as_deref())?;
    let response = compile_response(&spec.respond, file_dir)?;
    Ok((matcher, response))
}

fn compile_matcher(spec: &MatchSpec, default_host: Option<&str>) -> Result<RequestMatcher, String> {
    let (scheme, host, path, mut query) = match &spec.url {
        Some(_) if spec.scheme.is_some() || spec.host.is_some() || spec.path.is_some() => {
            return Err("use either 'url' or 'scheme'/'host'/'path', not both".to_owned());
        }
        Some(url) => {
            let url = parse_url(url)?;
            let query: Vec<(String, ValueMatch)> = url
                .query
                .into_iter()
                .map(|(name, value)| (name, ValueMatch::Exact(value)))
                .collect();
            (Some(url.scheme), url.host, Some(url.path), query)
        }
        None => {
            let scheme = spec.scheme.as_deref().map(parse_scheme).transpose()?;
            let host = spec.host.as_deref().or(default_host).ok_or(
                "rule has no host: set match.host, match.url or a top-level 'host'".to_owned(),
            )?;
            (scheme, host.to_owned(), spec.path.clone(), Vec::new())
        }
    };

    let host = HostPattern::parse(&host).map_err(|e| e.to_string())?;
    let path = path
        .map(|raw| PathPattern::parse(&raw).map_err(|e| e.to_string()))
        .transpose()?;
    let methods = spec.method.clone().map_or_else(
        || Ok(Vec::new()),
        |methods| parse_methods(methods.into_vec()),
    )?;
    query.extend(
        spec.query
            .iter()
            .map(|(name, value)| (name.clone(), ValueMatch::from_config(value))),
    );
    let headers = spec
        .headers
        .iter()
        .map(|(name, value)| Ok((header_name(name)?, ValueMatch::from_config(value))))
        .collect::<Result<Vec<_>, String>>()?;

    Ok(RequestMatcher {
        scheme,
        methods,
        host,
        path,
        query,
        headers,
    })
}

fn parse_scheme(raw: &str) -> Result<Scheme, String> {
    Scheme::parse(raw).ok_or_else(|| format!("invalid scheme '{raw}': use 'http' or 'https'"))
}

/// `*` or `ANY` anywhere in the list accepts every method.
fn parse_methods(raw: Vec<String>) -> Result<Vec<Method>, String> {
    let upper: Vec<String> = raw.iter().map(|m| m.trim().to_ascii_uppercase()).collect();
    if upper.iter().any(|m| m == "*" || m == "ANY") {
        return Ok(Vec::new());
    }
    upper
        .iter()
        .map(|m| Method::from_bytes(m.as_bytes()).map_err(|_| format!("invalid method '{m}'")))
        .collect()
}

fn header_name(raw: &str) -> Result<HeaderName, String> {
    HeaderName::from_bytes(raw.trim().as_bytes())
        .map_err(|_| format!("invalid header name '{raw}'"))
}

struct ParsedUrl {
    scheme: Scheme,
    host: String,
    path: String,
    query: Vec<(String, String)>,
}

fn parse_url(url: &str) -> Result<ParsedUrl, String> {
    let invalid = |reason: &str| format!("invalid url '{url}': {reason}");
    let (scheme, rest) = url
        .trim()
        .split_once("://")
        .ok_or_else(|| invalid("include the scheme, e.g. https://host/path"))?;
    let scheme =
        Scheme::parse(scheme).ok_or_else(|| invalid("the scheme must be http or https"))?;
    if rest.contains('#') {
        return Err(invalid("fragments (#) are not supported"));
    }
    let (host, remainder) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
    if host.is_empty() {
        return Err(invalid("missing host"));
    }
    let (path, query) = remainder.split_once('?').unwrap_or((remainder, ""));
    Ok(ParsedUrl {
        scheme,
        host: host.to_owned(),
        path: if path.is_empty() { "/" } else { path }.to_owned(),
        query: parse_query(query),
    })
}

fn compile_response(spec: &RespondSpec, file_dir: &Path) -> Result<MockResponse, String> {
    let status = StatusCode::from_u16(spec.status)
        .ok()
        .filter(|_| (100..=599).contains(&spec.status))
        .ok_or_else(|| {
            format!(
                "invalid status {}: use a code between 100 and 599",
                spec.status
            )
        })?;

    let headers = spec
        .headers
        .iter()
        .map(|(name, value)| {
            let value = HeaderValue::from_str(value)
                .map_err(|_| format!("invalid value for header '{name}'"))?;
            Ok((header_name(name)?, value))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let body = match (&spec.body, &spec.json, &spec.file) {
        (None, None, None) => MockBody::Empty,
        (Some(body), None, None) => MockBody::Inline {
            data: Bytes::from(body.clone()),
            content_type: "text/plain; charset=utf-8",
        },
        (None, Some(json), None) => MockBody::Inline {
            data: Bytes::from(json.to_string()),
            content_type: "application/json",
        },
        (None, None, Some(file)) => {
            let path = resolve_path(file, file_dir, crate::paths::home_dir().as_deref());
            let missing = || format!("response file not found '{}'", path.display());
            let real = path.canonicalize().map_err(|_| missing())?;
            let root = file_dir.canonicalize().map_err(|err| err.to_string())?;
            if !real.is_file() {
                return Err(missing());
            }
            if !real.starts_with(&root) {
                return Err(format!(
                    "response file '{}' is outside {}; keep response files next to the rules",
                    path.display(),
                    root.display()
                ));
            }
            MockBody::File { path, root }
        }
        _ => return Err("use only one of 'body', 'json' and 'file'".to_owned()),
    };

    let delay = spec
        .delay
        .as_deref()
        .map(|raw| {
            humantime::parse_duration(raw.trim())
                .map_err(|_| format!("invalid delay '{raw}': use values such as 500ms or 2s"))
        })
        .transpose()?;

    Ok(MockResponse {
        status,
        headers,
        body,
        delay,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn path(&self, rel: &str) -> PathBuf {
            self.dir.path().join(rel)
        }

        fn write(&self, rel: &str, content: &str) -> PathBuf {
            let path = self.path(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, content).unwrap();
            path
        }

        fn load(&self) -> Result<LoadedConfig, ConfigErrors> {
            load_file(&self.path("config.yaml"), Some(self.dir.path()))
        }
    }

    fn only_error(result: Result<LoadedConfig, ConfigErrors>) -> String {
        let errors = result.unwrap_err();
        assert_eq!(errors.0.len(), 1, "{errors}");
        errors.0[0].to_string()
    }

    #[test]
    fn defaults_without_config_file() {
        let fx = Fixture::new();
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.listen, DEFAULT_LISTEN.parse().unwrap());
        assert_eq!(loaded.mock_sources, vec![fx.path("mocks")]);
        assert!(loaded.rules.is_empty());
        assert_eq!(
            loaded.warnings,
            vec![format!(
                "mock source not found: {}",
                fx.path("mocks").display()
            )]
        );
    }

    #[test]
    fn default_location_is_used_without_explicit_file() {
        let fx = Fixture::new();
        fx.write("config.yaml", "listen: 9001\n");
        let paths = Paths {
            config_dir: fx.dir.path().to_path_buf(),
            state_dir: fx.path("state"),
        };
        assert_eq!(load(&paths, None).unwrap().listen.port(), 9001);
        let other = fx.write("other.yaml", "listen: 9002\n");
        assert_eq!(load(&paths, Some(&other)).unwrap().listen.port(), 9002);
    }

    #[test]
    fn loads_rules_from_default_mocks_dir_in_order() {
        let fx = Fixture::new();
        fx.write(
            "mocks/b.yaml",
            "host: b.com\nrules:\n  - name: b1\n    respond: { body: b }\n",
        );
        fx.write(
            "mocks/a.yml",
            "host: a.com\nrules:\n  - respond: { status: 204 }\n  - name: '  '\n    respond: {}\n",
        );
        fx.write("mocks/fixture.json", r#"{"any": "thing"}"#);
        fx.write("mocks/ignored.txt", "not a mock");
        fx.write("mocks/.hidden.yaml", "this: [is not valid");
        std::fs::create_dir_all(fx.path("mocks/dir.yaml")).unwrap();

        let loaded = fx.load().unwrap();
        let names: Vec<&str> = loaded
            .rules
            .rules()
            .iter()
            .map(|r| r.name.as_str())
            .collect();
        assert_eq!(names, vec!["a#1", "a#2", "b1"]);
        assert_eq!(loaded.mock_files.len(), 2);
        assert!(loaded.warnings.is_empty());
    }

    #[test]
    fn explicit_json_mock_files_are_loaded_once() {
        let fx = Fixture::new();
        fx.write(
            "rules.json",
            r#"{"host": "c.com", "rules": [{"respond": {}}]}"#,
        );
        fx.write("config.yaml", "mocks: [rules.json, ./rules.json]\n");
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(loaded.rules.rules()[0].name, "rules#1");
        assert!(loaded.is_relevant_change(&fx.path("rules.json")));
    }

    #[test]
    fn global_settings_are_applied() {
        let fx = Fixture::new();
        fx.write("ca/extra.pem", "x");
        fx.write("other/x.yaml", "host: x.com\nrules:\n  - respond: {}\n");
        fx.write(
            "config.yaml",
            "listen: 9000\nmocks: [other, ~/single.yaml]\nupstream:\n  ca_files: [ca/extra.pem]\n",
        );
        fx.write("single.yaml", "host: y.com\nrules:\n  - respond: {}\n");

        let loaded = fx.load().unwrap();
        assert_eq!(loaded.listen, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(
            loaded.mock_sources,
            vec![fx.path("other"), fx.path("single.yaml")]
        );
        assert_eq!(loaded.upstream_ca_files, vec![fx.path("ca/extra.pem")]);
        assert_eq!(loaded.rules.len(), 2);
    }

    #[test]
    fn non_loopback_listen_addresses_are_flagged() {
        let fx = Fixture::new();
        fx.write("config.yaml", "listen: 0.0.0.0:8899\nmocks: []\n");
        let loaded = fx.load().unwrap();
        assert_eq!(loaded.warnings.len(), 1);
        assert!(
            loaded.warnings[0].contains("open proxy"),
            "{:?}",
            loaded.warnings
        );

        fx.write("config.yaml", "listen: '[::1]:8899'\nmocks: []\n");
        assert!(fx.load().unwrap().warnings.is_empty());
    }

    #[test]
    fn port_overrides_keep_the_warnings_accurate() {
        let fx = Fixture::new();
        fx.write("config.yaml", "listen: 0.0.0.0:8899\nmocks: [missing]\n");
        let mut loaded = fx.load().unwrap();
        loaded.set_port(9100);
        assert_eq!(loaded.listen, "0.0.0.0:9100".parse().unwrap());
        assert_eq!(loaded.warnings.len(), 2, "{:?}", loaded.warnings);
        assert!(
            loaded.warnings[0].starts_with("listen address 0.0.0.0:9100 accepts connections"),
            "{:?}",
            loaded.warnings
        );
        assert!(loaded.warnings[1].starts_with("mock source not found"));

        fx.write("config.yaml", "listen: 8899\nmocks: [missing]\n");
        let mut loaded = fx.load().unwrap();
        loaded.set_port(9100);
        assert_eq!(loaded.listen, "127.0.0.1:9100".parse().unwrap());
        assert_eq!(loaded.warnings.len(), 1, "{:?}", loaded.warnings);
    }

    #[test]
    fn missing_upstream_ca_is_an_error() {
        let fx = Fixture::new();
        fx.write("config.yaml", "upstream:\n  ca_files: [missing.pem]\n");
        let message = only_error(fx.load());
        assert!(message.contains("file not found"), "{message}");
        assert!(message.contains("missing.pem"), "{message}");
    }

    #[test]
    fn invalid_listen_is_an_error() {
        let fx = Fixture::new();
        fx.write("config.yaml", "listen: abc\n");
        assert!(only_error(fx.load()).contains("invalid listen address 'abc'"));
    }

    #[test]
    fn unreadable_files_are_reported() {
        let fx = Fixture::new();
        std::fs::create_dir_all(fx.path("config.yaml")).unwrap();
        let message = only_error(fx.load());
        assert!(message.starts_with(&fx.path("config.yaml").display().to_string()));
    }

    #[test]
    fn unreadable_mock_files_are_reported() {
        use std::os::unix::fs::PermissionsExt;

        let fx = Fixture::new();
        let file = fx.write("mocks/secret.yaml", "rules: []\n");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o000)).unwrap();
        let message = only_error(fx.load());
        assert!(
            message.starts_with(&file.display().to_string()),
            "{message}"
        );
        assert!(message.contains("ermission denied"), "{message}");
    }

    #[test]
    fn unreadable_mock_directories_are_reported() {
        use std::os::unix::fs::PermissionsExt;

        let fx = Fixture::new();
        let locked = fx.path("mocks");
        std::fs::create_dir_all(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
        let result = fx.load();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(only_error(result).contains("ermission denied"));
    }

    #[test]
    fn parse_errors_point_to_file_and_line() {
        let fx = Fixture::new();
        let file = fx.write("mocks/x.yaml", "host: x.com\nrules:\n  - respnd: {}\n");
        let message = only_error(fx.load());
        assert!(message.contains(&file.display().to_string()), "{message}");
        assert!(message.contains("line 3"), "{message}");
        assert!(!message.contains("<input>"), "{message}");
        assert!(!message.contains("error: "), "{message}");
    }

    #[test]
    fn invalid_global_file_is_reported() {
        let fx = Fixture::new();
        fx.write("config.yaml", "listen: [\n");
        assert!(only_error(fx.load()).contains("config.yaml"));
    }

    #[test]
    fn all_errors_are_collected() {
        let fx = Fixture::new();
        fx.write("mocks/a.yaml", "rules:\n  - respond: {}\n");
        fx.write(
            "mocks/b.yaml",
            "host: b.com\nrules:\n  - respond: { status: 42 }\n",
        );
        fx.write("mocks/c.yaml", "rules: [\n");
        let errors = fx.load().unwrap_err();
        assert_eq!(errors.0.len(), 3, "{errors}");
        let text = errors.to_string();
        let position = |needle: &str| {
            text.find(needle)
                .unwrap_or_else(|| panic!("{needle}: {text}"))
        };
        assert!(position("rule 'a#1': rule has no host") < position("invalid status 42"));
        assert!(position("invalid status 42") < position("c.yaml"));
        assert!(text.starts_with(&errors.0[0].to_string()));
    }

    #[test]
    fn duplicate_names_are_rejected() {
        let fx = Fixture::new();
        fx.write(
            "mocks/a.yaml",
            "host: a.com\nrules:\n  - name: x\n    respond: {}\n  - name: x\n    respond: {}\n",
        );
        let message = only_error(fx.load());
        assert!(
            message.contains("rule 'x': duplicate name, already used in "),
            "{message}"
        );
    }

    #[test]
    fn empty_files_are_accepted() {
        let fx = Fixture::new();
        fx.write("config.yaml", "");
        fx.write("mocks/empty.yaml", "\n");
        let loaded = fx.load().unwrap();
        assert!(loaded.rules.is_empty());
    }

    #[test]
    fn file_level_enabled_flag_disables_rules() {
        let fx = Fixture::new();
        fx.write(
            "mocks/a.yaml",
            "enabled: false\nhost: a.com\nrules:\n  - respond: {}\n",
        );
        fx.write(
            "mocks/b.yaml",
            "host: b.com\nrules:\n  - enabled: false\n    respond: {}\n  - respond: {}\n",
        );
        let loaded = fx.load().unwrap();
        let enabled: Vec<bool> = loaded.rules.rules().iter().map(|r| r.enabled).collect();
        assert_eq!(enabled, vec![false, false, true]);
    }

    fn compile_one(yaml: &str) -> Result<Rule, String> {
        let fx = Fixture::new();
        fx.write("mocks/r.yaml", yaml);
        fx.write("mocks/data.json", "{\"ok\":true}");
        fx.load()
            .map(|loaded| loaded.rules.rules()[0].clone())
            .map_err(|e| e.to_string())
    }

    #[test]
    fn url_shortcut_sets_scheme_host_path_and_query() {
        let rule = compile_one(
            "rules:\n  - match: { url: 'https://Pay.x.com:8443/v2/charge?mode=test', query: { extra: '*' } }\n    respond: {}\n",
        )
        .unwrap();
        let m = &rule.matcher;
        assert_eq!(m.scheme, Some(Scheme::Https));
        assert_eq!(m.host.to_string(), "pay.x.com:8443");
        assert_eq!(m.path.as_ref().unwrap().as_str(), "/v2/charge");
        assert_eq!(
            m.query,
            vec![
                ("mode".to_owned(), ValueMatch::Exact("test".to_owned())),
                ("extra".to_owned(), ValueMatch::Present),
            ]
        );
    }

    #[test]
    fn url_without_path_means_root() {
        let rule =
            compile_one("rules:\n  - match: { url: 'http://x.com' }\n    respond: {}\n").unwrap();
        assert_eq!(rule.matcher.path.as_ref().unwrap().as_str(), "/");
        let rule = compile_one("rules:\n  - match: { url: 'http://x.com?a=1' }\n    respond: {}\n")
            .unwrap();
        assert_eq!(rule.matcher.path.as_ref().unwrap().as_str(), "/");
        assert_eq!(rule.matcher.query.len(), 1);
    }

    #[test]
    fn invalid_urls_are_rejected() {
        let cases = [
            ("x.com/a", "include the scheme"),
            ("ftp://x.com/", "the scheme must be http or https"),
            ("https:///a", "missing host"),
            ("https://x.com/#a", "fragments"),
        ];
        for (url, reason) in cases {
            let yaml = format!("rules:\n  - match: {{ url: '{url}' }}\n    respond: {{}}\n");
            let err = compile_one(&yaml).unwrap_err();
            assert!(
                err.contains(&format!("invalid url '{url}': {reason}")),
                "{err}"
            );
        }
    }

    #[test]
    fn url_cannot_be_combined_with_host_scheme_or_path() {
        for extra in ["host: y.com", "scheme: http", "path: /a"] {
            let yaml = format!(
                "rules:\n  - match: {{ url: 'https://x.com/', {extra} }}\n    respond: {{}}\n"
            );
            assert!(
                compile_one(&yaml).unwrap_err().contains("not both"),
                "{extra}"
            );
        }
    }

    #[test]
    fn match_fields_are_compiled() {
        let rule = compile_one(
            "host: x.com\nrules:\n  - match:\n      scheme: HTTPS\n      method: [get, post]\n      path: /a/:id\n      query: { q: '*' }\n      headers: { X-Tenant: acme }\n    respond: {}\n",
        )
        .unwrap();
        let m = &rule.matcher;
        assert_eq!(m.scheme, Some(Scheme::Https));
        assert_eq!(m.methods, vec![Method::GET, Method::POST]);
        assert_eq!(m.query, vec![("q".to_owned(), ValueMatch::Present)]);
        assert_eq!(m.headers[0].0, HeaderName::from_static("x-tenant"));
        assert_eq!(m.headers[0].1, ValueMatch::Exact("acme".to_owned()));
    }

    #[test]
    fn match_host_overrides_the_file_host() {
        let rule =
            compile_one("host: x.com\nrules:\n  - match: { host: y.com }\n    respond: {}\n")
                .unwrap();
        assert_eq!(rule.matcher.host.to_string(), "y.com");
    }

    #[test]
    fn any_method_aliases() {
        for method in ["'*'", "ANY", "[GET, any]"] {
            let yaml = format!(
                "host: x.com\nrules:\n  - match: {{ method: {method} }}\n    respond: {{}}\n"
            );
            assert!(
                compile_one(&yaml).unwrap().matcher.methods.is_empty(),
                "{method}"
            );
        }
    }

    #[test]
    fn invalid_match_fields_are_rejected() {
        let cases = [
            ("match: { scheme: ftp }", "invalid scheme 'ftp'"),
            ("match: { method: 'GE T' }", "invalid method 'GE T'"),
            ("match: { path: no-slash }", "must start with '/'"),
            ("match: { host: '*' }", "only allowed as a prefix"),
            (
                "match: { headers: { 'a b': x } }",
                "invalid header name 'a b'",
            ),
        ];
        for (fragment, expected) in cases {
            let yaml = format!("host: x.com\nrules:\n  - {fragment}\n    respond: {{}}\n");
            let err = compile_one(&yaml).unwrap_err();
            assert!(err.contains(expected), "{fragment}: {err}");
        }
    }

    #[test]
    fn json_body_is_serialized() {
        let rule =
            compile_one("host: x.com\nrules:\n  - respond: { json: { a: [1, null] } }\n").unwrap();
        assert_eq!(
            rule.response.body,
            MockBody::Inline {
                data: Bytes::from_static(br#"{"a":[1,null]}"#),
                content_type: "application/json",
            }
        );
    }

    #[test]
    fn empty_json_object_body() {
        let rule = compile_one("host: x.com\nrules:\n  - respond: { json: {} }\n").unwrap();
        assert_eq!(
            rule.response.body,
            MockBody::Inline {
                data: Bytes::from_static(b"{}"),
                content_type: "application/json",
            }
        );
    }

    #[test]
    fn text_body_file_body_and_delay() {
        let rule =
            compile_one("host: x.com\nrules:\n  - respond: { body: hi, delay: 1.5s }\n").unwrap();
        assert_eq!(rule.response.delay, Some(Duration::from_millis(1500)));
        assert_eq!(
            rule.response.body,
            MockBody::Inline {
                data: Bytes::from_static(b"hi"),
                content_type: "text/plain; charset=utf-8",
            }
        );

        let rule = compile_one("host: x.com\nrules:\n  - respond: { file: data.json }\n").unwrap();
        let body = &rule.response.body;
        assert!(
            matches!(body, MockBody::File { path, .. } if path.ends_with("mocks/data.json")),
            "{body:?}"
        );
    }

    #[test]
    fn response_headers_and_status() {
        let rule = compile_one(
            "host: x.com\nrules:\n  - respond: { status: 503, headers: { Retry-After: 30 } }\n",
        )
        .unwrap();
        assert_eq!(rule.response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            rule.response.headers[0].0,
            HeaderName::from_static("retry-after")
        );
        assert_eq!(rule.response.headers[0].1, "30");
    }

    #[test]
    fn invalid_responses_are_rejected() {
        let cases = [
            ("{ status: 99 }", "invalid status 99"),
            ("{ status: 600 }", "invalid status 600"),
            ("{ body: a, json: {} }", "use only one of"),
            ("{ json: {}, file: data.json }", "use only one of"),
            ("{ file: missing.json }", "response file not found"),
            ("{ delay: soon }", "invalid delay 'soon'"),
            ("{ headers: { 'a b': x } }", "invalid header name 'a b'"),
            (
                "{ headers: { a: \"x\\ny\" } }",
                "invalid value for header 'a'",
            ),
        ];
        for (respond, expected) in cases {
            let yaml = format!("host: x.com\nrules:\n  - respond: {respond}\n");
            let err = compile_one(&yaml).unwrap_err();
            assert!(err.contains(expected), "{respond}: {err}");
        }
    }

    #[test]
    fn response_files_must_stay_next_to_the_rules() {
        let fx = Fixture::new();
        fx.write("secret.txt", "private");
        fx.write("mocks/inner/ok.json", "{}");
        std::fs::create_dir_all(fx.path("mocks/dir")).unwrap();
        std::os::unix::fs::symlink(fx.path("secret.txt"), fx.path("mocks/link.json")).unwrap();
        let check = |file: &str| {
            let rule = format!("host: x.com\nrules:\n  - respond: {{ file: '{file}' }}\n");
            fx.write("mocks/r.yaml", &rule);
            fx.load().map(|_| ()).map_err(|e| e.to_string())
        };
        assert!(check("inner/ok.json").is_ok());
        let absolute = fx.path("secret.txt").display().to_string();
        for outside in ["../secret.txt", "link.json", absolute.as_str()] {
            let err = check(outside).unwrap_err();
            assert!(err.contains("is outside"), "{outside}: {err}");
        }
        assert!(
            check("dir")
                .unwrap_err()
                .contains("response file not found")
        );
    }

    #[test]
    fn listen_formats() {
        let parsed = |raw: &str| parse_listen(raw).unwrap().to_string();
        assert_eq!(parsed("8899"), "127.0.0.1:8899");
        assert_eq!(parsed(" localhost:1 "), "127.0.0.1:1");
        assert_eq!(parsed("0.0.0.0:80"), "0.0.0.0:80");
        assert_eq!(parsed("[::1]:80"), "[::1]:80");
        assert!(parse_listen("host:80").is_err());
        assert!(parse_listen("localhost:x").is_err());
    }

    #[test]
    fn watch_dirs_cover_config_and_sources() {
        let fx = Fixture::new();
        fx.write("mocks/a.yaml", "host: a.com\nrules: []\n");
        fx.write("loose.yaml", "rules: []\n");
        fx.write("config.yaml", "mocks: [mocks, loose.yaml, not/there]\n");
        let loaded = fx.load().unwrap();
        let root = fx.dir.path().to_path_buf();
        assert_eq!(loaded.watch_dirs(), vec![root.clone(), root.join("mocks")]);
    }

    #[test]
    fn relevant_changes() {
        let fx = Fixture::new();
        let loaded = fx.load().unwrap();
        assert!(loaded.is_relevant_change(&fx.path("config.yaml")));
        assert!(loaded.is_relevant_change(&fx.path("mocks/x.YML")));
        assert!(loaded.is_relevant_change(&fx.path("mocks")));
        assert!(!loaded.is_relevant_change(&fx.path("mocks/x.swp")));
        assert!(!loaded.is_relevant_change(&fx.path("mocks/fixture.json")));
    }
}
