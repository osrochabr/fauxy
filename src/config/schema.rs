//! Serde mirror of the configuration files. Validation and compilation into
//! [`crate::rules`] types happen in the loader.

use serde::Deserialize;
use std::collections::BTreeMap;

/// `config.yaml`.
#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct GlobalFile {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub mocks: Option<Vec<String>>,
    #[serde(default)]
    pub upstream: UpstreamFile,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct UpstreamFile {
    /// Extra PEM CAs trusted when validating real servers.
    #[serde(default)]
    pub ca_files: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MockFile {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Default host for the rules of the file.
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub rules: Vec<RuleSpec>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(rename = "match", default)]
    pub matcher: MatchSpec,
    pub respond: RespondSpec,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MatchSpec {
    /// Shortcut for `scheme://host[:port]/path[?query]`.
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub method: Option<OneOrMany>,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub query: BTreeMap<String, String>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum OneOrMany {
    One(String),
    Many(Vec<String>),
}

impl OneOrMany {
    pub fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(value) => vec![value],
            Self::Many(values) => values,
        }
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RespondSpec {
    #[serde(default = "default_status")]
    pub status: u16,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: Option<String>,
    #[serde(default)]
    pub json: Option<serde_json::Value>,
    /// Relative to the mock file.
    #[serde(default)]
    pub file: Option<String>,
    /// Duration such as `800ms` or `2s`.
    #[serde(default)]
    pub delay: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_status() -> u16 {
    200
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_mock_file() {
        let yaml = r#"
enabled: true
host: api.example.com
rules:
  - name: login
    match:
      method: [POST, PUT]
      path: /v1/login
      query: { version: 2 }
      headers: { X-Tenant: acme }
    respond:
      status: 201
      headers: { Retry-After: 30 }
      json: { token: abc, expires_in: 3600, ok: true }
      delay: 800ms
"#;
        let file: MockFile = serde_saphyr::from_str(yaml).unwrap();
        assert!(file.enabled);
        assert_eq!(file.host.as_deref(), Some("api.example.com"));
        let rule = &file.rules[0];
        assert_eq!(rule.name.as_deref(), Some("login"));
        assert_eq!(
            rule.matcher.method.clone().unwrap().into_vec(),
            vec!["POST", "PUT"]
        );
        assert_eq!(rule.matcher.query["version"], "2");
        assert_eq!(rule.matcher.headers["X-Tenant"], "acme");
        assert_eq!(rule.respond.status, 201);
        assert_eq!(rule.respond.headers["Retry-After"], "30");
        assert_eq!(
            rule.respond.json.as_ref().unwrap()["expires_in"],
            serde_json::json!(3600)
        );
        assert_eq!(rule.respond.delay.as_deref(), Some("800ms"));
    }

    #[test]
    fn applies_defaults() {
        let file: MockFile = serde_saphyr::from_str("rules:\n  - respond: {}\n").unwrap();
        assert!(file.enabled);
        assert!(file.host.is_none());
        let rule = &file.rules[0];
        assert!(rule.enabled);
        assert_eq!(rule.matcher, MatchSpec::default());
        assert_eq!(rule.respond.status, 200);
        assert!(rule.respond.json.is_none());
    }

    #[test]
    fn empty_json_object_is_kept() {
        let file: MockFile = serde_saphyr::from_str("rules:\n  - respond: { json: {} }\n").unwrap();
        assert_eq!(file.rules[0].respond.json, Some(serde_json::json!({})));
    }

    #[test]
    fn unknown_fields_are_rejected_with_location() {
        let err = serde_saphyr::from_str::<MockFile>("rules:\n  - respnd: {}\n").unwrap_err();
        let message = err.to_string();
        assert!(message.contains("respnd"), "{message}");
        assert!(message.contains("line 2"), "{message}");
    }

    #[test]
    fn single_method_is_accepted() {
        let spec: MatchSpec = serde_saphyr::from_str("method: GET").unwrap();
        assert_eq!(spec.method.unwrap().into_vec(), vec!["GET"]);
    }

    #[test]
    fn parses_global_file() {
        let yaml = "listen: 127.0.0.1:9000\nmocks: [a, ~/b]\nupstream:\n  ca_files: [ca.pem]\n";
        let global: GlobalFile = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(global.listen.as_deref(), Some("127.0.0.1:9000"));
        assert_eq!(global.mocks.unwrap(), vec!["a", "~/b"]);
        assert_eq!(global.upstream.ca_files, vec!["ca.pem"]);
    }

    #[test]
    fn json_syntax_is_accepted() {
        let file: MockFile =
            serde_saphyr::from_str(r#"{"host": "x.com", "rules": [{"respond": {"status": 204}}]}"#)
                .unwrap();
        assert_eq!(file.rules[0].respond.status, 204);
    }
}
