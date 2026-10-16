mod matcher;
mod pattern;
mod response;

pub use matcher::{RequestInfo, RequestMatcher, Scheme, ValueMatch, parse_query, percent_decode};
pub use pattern::{HostPattern, PathPattern, PatternError};
pub use response::{MockBody, MockResponse, RULE_HEADER, RenderedResponse, content_type_for};

use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    pub source: PathBuf,
    /// State declared in the configuration files (runtime overrides live in
    /// [`crate::state::AppState`]).
    pub enabled: bool,
    pub matcher: RequestMatcher,
    pub response: MockResponse,
}

/// Rules in evaluation order: the first enabled rule that matches wins.
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    pub fn new(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn get(&self, name: &str) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.name == name)
    }

    pub fn find(&self, req: &RequestInfo<'_>, is_enabled: impl Fn(&Rule) -> bool) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| is_enabled(rule) && rule.matcher.matches(req))
    }

    /// Whether TLS connections to `host:port` must be decrypted because some
    /// enabled rule could answer requests for that host.
    pub fn intercepts(&self, host: &str, port: u16, is_enabled: impl Fn(&Rule) -> bool) -> bool {
        self.rules
            .iter()
            .any(|rule| is_enabled(rule) && rule.matcher.may_intercept_tls(host, port))
    }

    /// Distinct host patterns of the enabled rules, in order of appearance.
    pub fn hosts(&self, is_enabled: impl Fn(&Rule) -> bool) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        for rule in self.rules.iter().filter(|rule| is_enabled(rule)) {
            let host = rule.matcher.host.to_string();
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        hosts
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use bytes::Bytes;
    use http::StatusCode;

    pub(crate) fn rule(name: &str, host: &str, path: Option<&str>, body: &str) -> Rule {
        Rule {
            name: name.to_owned(),
            source: PathBuf::from("test.yaml"),
            enabled: true,
            matcher: RequestMatcher {
                scheme: None,
                methods: Vec::new(),
                host: HostPattern::parse(host).unwrap(),
                path: path.map(|p| PathPattern::parse(p).unwrap()),
                query: Vec::new(),
                headers: Vec::new(),
            },
            response: MockResponse {
                status: StatusCode::OK,
                headers: Vec::new(),
                body: MockBody::Inline {
                    data: Bytes::from(body.to_owned()),
                    content_type: "text/plain; charset=utf-8",
                },
                delay: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::rule;
    use super::*;
    use http::Request;

    fn find<'a>(set: &'a RuleSet, uri: &str) -> Option<&'a str> {
        let req = Request::get(uri).body(()).unwrap();
        let info = RequestInfo::from_request(&req).unwrap();
        set.find(&info, |r| r.enabled).map(|r| r.name.as_str())
    }

    #[test]
    fn first_matching_rule_wins() {
        let set = RuleSet::new(vec![
            rule("specific", "x.com", Some("/a"), "1"),
            rule("catch-all", "x.com", Some("/**"), "2"),
        ]);
        assert_eq!(find(&set, "https://x.com/a"), Some("specific"));
        assert_eq!(find(&set, "https://x.com/b"), Some("catch-all"));
        assert_eq!(find(&set, "https://y.com/a"), None);
    }

    #[test]
    fn disabled_rules_are_skipped() {
        let mut first = rule("a", "x.com", None, "1");
        first.enabled = false;
        let set = RuleSet::new(vec![first, rule("b", "x.com", None, "2")]);
        assert_eq!(find(&set, "https://x.com/"), Some("b"));
    }

    #[test]
    fn interception_depends_on_enabled_rules() {
        let mut only = rule("a", "*.x.com", None, "1");
        let set = RuleSet::new(vec![only.clone()]);
        assert!(set.intercepts("api.x.com", 443, |r| r.enabled));
        assert!(!set.intercepts("other.com", 443, |r| r.enabled));

        only.enabled = false;
        let set = RuleSet::new(vec![only]);
        assert!(!set.intercepts("api.x.com", 443, |r| r.enabled));
    }

    #[test]
    fn hosts_are_deduplicated() {
        let set = RuleSet::new(vec![
            rule("a", "x.com", Some("/a"), "1"),
            rule("b", "x.com", Some("/b"), "2"),
            rule("c", "*.y.com", None, "3"),
        ]);
        assert_eq!(set.hosts(|_| true), vec!["x.com", "*.y.com"]);
        assert_eq!(set.hosts(|r| r.name == "c"), vec!["*.y.com"]);
    }

    #[test]
    fn lookup_helpers() {
        let set = RuleSet::new(vec![rule("a", "x.com", None, "1")]);
        assert_eq!(set.len(), 1);
        assert!(!set.is_empty());
        assert_eq!(set.rules().len(), 1);
        assert!(set.get("a").is_some());
        assert!(set.get("z").is_none());
        assert!(RuleSet::default().is_empty());
    }
}
