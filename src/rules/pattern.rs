use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct PatternError(String);

/// A host pattern such as `api.example.com`, `*.example.com` or
/// `localhost:8080`. Matching is case-insensitive; `*.` matches any subdomain
/// but not the bare domain; a port, when given, must match too.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPattern {
    name: HostName,
    port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HostName {
    Exact(String),
    /// Suffix including the leading dot, e.g. `.example.com`.
    Subdomains(String),
}

impl HostPattern {
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        let raw = raw.trim();
        let invalid = |reason: &str| PatternError(format!("invalid host '{raw}'{reason}"));
        if raw.is_empty() {
            return Err(PatternError("empty host".to_owned()));
        }
        if raw.contains('/') {
            return Err(invalid(": use only the name, without scheme or path"));
        }

        let (host, port) = split_host_port(raw)?;
        let host = host.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() || host.chars().any(char::is_whitespace) {
            return Err(invalid(""));
        }
        let name = match host.strip_prefix("*.") {
            Some(suffix) if !suffix.is_empty() && !suffix.contains('*') => {
                HostName::Subdomains(format!(".{suffix}"))
            }
            _ if host.contains('*') => {
                return Err(invalid(
                    ": '*' is only allowed as a prefix, as in '*.example.com'",
                ));
            }
            _ => HostName::Exact(host),
        };
        Ok(Self { name, port })
    }

    pub fn matches(&self, host: &str, port: u16) -> bool {
        if self.port.is_some_and(|expected| expected != port) {
            return false;
        }
        let host = host.trim_end_matches('.');
        match &self.name {
            HostName::Exact(expected) => host.eq_ignore_ascii_case(expected),
            HostName::Subdomains(suffix) => {
                host.len() > suffix.len()
                    && host.is_char_boundary(host.len() - suffix.len())
                    && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            }
        }
    }
}

impl fmt::Display for HostPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.name {
            HostName::Exact(host) if host.contains(':') => write!(f, "[{host}]")?,
            HostName::Exact(host) => f.write_str(host)?,
            HostName::Subdomains(suffix) => write!(f, "*{suffix}")?,
        }
        match self.port {
            Some(port) => write!(f, ":{port}"),
            None => Ok(()),
        }
    }
}

fn split_host_port(raw: &str) -> Result<(&str, Option<u16>), PatternError> {
    let invalid_port = || PatternError(format!("invalid port in '{raw}'"));
    let parse_port = |port: &str| port.parse().map(Some).map_err(|_| invalid_port());

    if let Some(rest) = raw.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| PatternError(format!("invalid IPv6 host '{raw}'")))?;
        return match after {
            "" => Ok((host, None)),
            port => Ok((
                host,
                parse_port(port.strip_prefix(':').ok_or_else(invalid_port)?)?,
            )),
        };
    }
    match raw.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Ok((host, parse_port(port)?)),
        _ => Ok((raw, None)),
    }
}

/// A path pattern such as `/v1/users/:id`, `/static/*` or `/api/**`.
///
/// Segments are compared literally (case-sensitive). `:name` and `*` match
/// exactly one segment, `**` matches any number of segments (including none).
/// Empty segments are ignored, so trailing slashes do not matter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    raw: String,
    segments: Vec<Segment>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    Literal(String),
    One,
    Many,
}

impl PathPattern {
    pub fn parse(raw: &str) -> Result<Self, PatternError> {
        let raw = raw.trim();
        let invalid = |reason: String| PatternError(format!("invalid path '{raw}': {reason}"));
        if !raw.starts_with('/') {
            return Err(invalid("it must start with '/'".to_owned()));
        }
        if raw.contains(['?', '#']) {
            return Err(invalid("use 'query' to match query parameters".to_owned()));
        }

        let segments = raw
            .split('/')
            .filter(|segment| !segment.is_empty())
            .map(|segment| match segment {
                "**" => Ok(Segment::Many),
                "*" => Ok(Segment::One),
                s if s.starts_with(':') => valid_param(&s[1..])
                    .then_some(Segment::One)
                    .ok_or_else(|| invalid(format!("invalid parameter '{s}'"))),
                s if s.contains('*') => Err(invalid(format!(
                    "invalid segment '{s}', use '*' or '**' as a whole segment"
                ))),
                s => Ok(Segment::Literal(s.to_owned())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            raw: raw.to_owned(),
            segments,
        })
    }

    /// Whether the request path (without query string) matches.
    pub fn matches(&self, path: &str) -> bool {
        let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
        match_segments(&self.segments, &parts)
    }

    pub fn as_str(&self) -> &str {
        &self.raw
    }
}

impl fmt::Display for PathPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

fn valid_param(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

fn match_segments(pattern: &[Segment], parts: &[&str]) -> bool {
    match (pattern.split_first(), parts.split_first()) {
        (None, _) => parts.is_empty(),
        (Some((Segment::Many, rest)), _) => {
            (0..=parts.len()).any(|skip| match_segments(rest, &parts[skip..]))
        }
        (Some(_), None) => false,
        (Some((Segment::Literal(literal), rest)), Some((part, remaining))) => {
            literal == part && match_segments(rest, remaining)
        }
        (Some((Segment::One, rest)), Some((_, remaining))) => match_segments(rest, remaining),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(raw: &str) -> HostPattern {
        HostPattern::parse(raw).unwrap()
    }

    fn path(raw: &str) -> PathPattern {
        PathPattern::parse(raw).unwrap()
    }

    #[test]
    fn exact_host_is_case_insensitive() {
        let pattern = host("API.Example.com");
        assert!(pattern.matches("api.example.com", 443));
        assert!(pattern.matches("API.EXAMPLE.COM", 80));
        assert!(pattern.matches("api.example.com.", 443));
        assert!(!pattern.matches("x.api.example.com", 443));
        assert!(!pattern.matches("example.com", 443));
    }

    #[test]
    fn wildcard_host_matches_subdomains_only() {
        let pattern = host("*.example.com");
        assert!(pattern.matches("a.example.com", 443));
        assert!(pattern.matches("a.b.example.com", 443));
        assert!(!pattern.matches("example.com", 443));
        assert!(!pattern.matches("aexample.com", 443));
        assert!(!pattern.matches("example.com.br", 443));
        assert!(!pattern.matches("é.example.co", 443), "multi-byte boundary");
    }

    #[test]
    fn host_with_port_requires_same_port() {
        let pattern = host("localhost:8080");
        assert!(pattern.matches("localhost", 8080));
        assert!(!pattern.matches("localhost", 80));
        assert_eq!(pattern.to_string(), "localhost:8080");
    }

    #[test]
    fn ipv6_hosts_are_supported() {
        let pattern = host("[::1]:9000");
        assert!(pattern.matches("::1", 9000));
        assert_eq!(pattern.to_string(), "[::1]:9000");
        assert!(host("[::1]").matches("::1", 1));
        assert_eq!(host("[::1]").to_string(), "[::1]");
    }

    #[test]
    fn invalid_hosts_are_rejected_with_reasons() {
        let cases = [
            ("", "empty host"),
            ("*", "only allowed as a prefix"),
            ("https://x.com", "without scheme or path"),
            ("x.com/path", "without scheme or path"),
            ("a*.com", "only allowed as a prefix"),
            ("*.", "only allowed as a prefix"),
            ("*.a*.com", "only allowed as a prefix"),
            ("x.com:abc", "invalid port"),
            ("[::1", "invalid IPv6 host"),
            ("[::1]x", "invalid port"),
            ("[::1]9000", "invalid port"),
            ("[::1]:x", "invalid port"),
            ("a b", "invalid host 'a b'"),
            (".", "invalid host '.'"),
        ];
        for (raw, reason) in cases {
            let err = HostPattern::parse(raw).unwrap_err().to_string();
            assert!(err.contains(reason), "{raw}: {err}");
        }
    }

    #[test]
    fn host_display_round_trips() {
        assert_eq!(host("*.Example.com").to_string(), "*.example.com");
        assert_eq!(host("api.x.com").to_string(), "api.x.com");
    }

    #[test]
    fn literal_paths_match_exactly() {
        let pattern = path("/v1/login");
        assert!(pattern.matches("/v1/login"));
        assert!(pattern.matches("/v1/login/"));
        assert!(pattern.matches("//v1//login"));
        assert!(!pattern.matches("/v1/login/extra"));
        assert!(!pattern.matches("/v1/LOGIN"));
        assert!(!pattern.matches("/v1"));
    }

    #[test]
    fn root_matches_only_root() {
        let pattern = path("/");
        assert!(pattern.matches("/"));
        assert!(pattern.matches(""));
        assert!(!pattern.matches("/a"));
    }

    #[test]
    fn params_and_single_wildcards_match_one_segment() {
        for raw in ["/v1/users/:id", "/v1/users/*"] {
            let pattern = path(raw);
            assert!(pattern.matches("/v1/users/42"));
            assert!(!pattern.matches("/v1/users"));
            assert!(!pattern.matches("/v1/users/42/posts"));
        }
    }

    #[test]
    fn double_wildcard_matches_any_depth() {
        let all = path("/**");
        assert!(all.matches("/"));
        assert!(all.matches("/a/b/c"));

        let prefixed = path("/api/**");
        assert!(prefixed.matches("/api"));
        assert!(prefixed.matches("/api/v1/x"));
        assert!(!prefixed.matches("/other"));

        let middle = path("/api/**/status");
        assert!(middle.matches("/api/status"));
        assert!(middle.matches("/api/a/b/status"));
        assert!(!middle.matches("/api/a/b"));
    }

    #[test]
    fn invalid_paths_are_rejected_with_reasons() {
        let cases = [
            ("v1/login", "must start with '/'"),
            ("/v1/log*", "invalid segment 'log*'"),
            ("/:", "invalid parameter ':'"),
            ("/:a$b", "invalid parameter ':a$b'"),
            ("/x?y=1", "use 'query'"),
            ("/x#frag", "use 'query'"),
        ];
        for (raw, reason) in cases {
            let err = PathPattern::parse(raw).unwrap_err().to_string();
            assert!(err.contains(reason), "{raw}: {err}");
        }
    }

    #[test]
    fn path_display_keeps_original_text() {
        assert_eq!(path("/v1/users/:id").to_string(), "/v1/users/:id");
        assert_eq!(path("/v1/users/:id").as_str(), "/v1/users/:id");
    }
}
