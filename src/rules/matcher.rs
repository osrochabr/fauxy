use super::pattern::{HostPattern, PathPattern};
use http::{HeaderMap, HeaderName, Method, Request};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_lowercase().as_str() {
            "http" => Some(Self::Http),
            "https" => Some(Self::Https),
            _ => None,
        }
    }

    pub fn default_port(self) -> u16 {
        match self {
            Self::Http => 80,
            Self::Https => 443,
        }
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
        })
    }
}

/// How a query parameter or header value is compared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValueMatch {
    /// Present with any value (`"*"` in the configuration).
    Present,
    Exact(String),
}

impl ValueMatch {
    pub fn from_config(value: &str) -> Self {
        if value == "*" {
            Self::Present
        } else {
            Self::Exact(value.to_owned())
        }
    }

    fn accepts(&self, actual: &str) -> bool {
        match self {
            Self::Present => true,
            Self::Exact(expected) => expected == actual,
        }
    }
}

/// The parts of a request that rules can match on.
#[derive(Debug, Clone)]
pub struct RequestInfo<'a> {
    pub scheme: Scheme,
    pub method: &'a Method,
    pub host: &'a str,
    /// Explicit port or the scheme default.
    pub port: u16,
    pub path: &'a str,
    pub query: Option<&'a str>,
    pub headers: &'a HeaderMap,
}

impl<'a> RequestInfo<'a> {
    /// Proxied requests carry an absolute URI; when it is missing
    /// (origin-form) the `Host` header is used. Returns `None` without a host.
    pub fn from_request<B>(req: &'a Request<B>) -> Option<Self> {
        let uri = req.uri();
        let scheme = uri
            .scheme_str()
            .and_then(Scheme::parse)
            .unwrap_or(Scheme::Http);
        let (host, port) = match uri.host() {
            Some(host) => (host, uri.port_u16()),
            None => split_authority(req.headers().get(http::header::HOST)?.to_str().ok()?),
        };
        Some(Self {
            scheme,
            method: req.method(),
            host: host.trim_start_matches('[').trim_end_matches(']'),
            port: port.unwrap_or_else(|| scheme.default_port()),
            path: uri.path(),
            query: uri.query(),
            headers: req.headers(),
        })
    }
}

fn split_authority(authority: &str) -> (&str, Option<u16>) {
    match authority.rsplit_once(':') {
        Some((host, port)) if !port.contains(']') => match port.parse() {
            Ok(port) => (host, Some(port)),
            Err(_) => (authority, None),
        },
        _ => (authority, None),
    }
}

/// Conditions a request must satisfy for a rule to apply; all must hold.
/// Empty `methods`, `None` scheme or `None` path accept anything.
#[derive(Debug, Clone)]
pub struct RequestMatcher {
    pub scheme: Option<Scheme>,
    pub methods: Vec<Method>,
    pub host: HostPattern,
    pub path: Option<PathPattern>,
    pub query: Vec<(String, ValueMatch)>,
    pub headers: Vec<(HeaderName, ValueMatch)>,
}

impl RequestMatcher {
    pub fn matches(&self, req: &RequestInfo<'_>) -> bool {
        self.scheme.is_none_or(|scheme| scheme == req.scheme)
            && (self.methods.is_empty() || self.methods.contains(req.method))
            && self.host.matches(req.host, req.port)
            && self.path.as_ref().is_none_or(|path| path.matches(req.path))
            && self.query_matches(req.query)
            && self.headers_match(req.headers)
    }

    /// Whether a TLS connection to `host:port` may be answered by this
    /// matcher, i.e. whether it has to be decrypted.
    pub fn may_intercept_tls(&self, host: &str, port: u16) -> bool {
        self.scheme != Some(Scheme::Http) && self.host.matches(host, port)
    }

    fn query_matches(&self, query: Option<&str>) -> bool {
        if self.query.is_empty() {
            return true;
        }
        let pairs = parse_query(query.unwrap_or_default());
        self.query.iter().all(|(name, expected)| {
            pairs
                .iter()
                .any(|(key, value)| key == name && expected.accepts(value))
        })
    }

    fn headers_match(&self, headers: &HeaderMap) -> bool {
        self.headers.iter().all(|(name, expected)| {
            headers
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .any(|value| expected.accepts(value))
        })
    }

    /// Short description used by the CLI and the TUI.
    pub fn describe(&self) -> String {
        let methods = if self.methods.is_empty() {
            "*".to_owned()
        } else {
            let names: Vec<&str> = self.methods.iter().map(Method::as_str).collect();
            names.join("|")
        };
        let scheme = self.scheme.map(|s| format!("{s}://")).unwrap_or_default();
        let path = self.path.as_ref().map_or("/**", PathPattern::as_str);
        format!("{methods} {scheme}{}{path}", self.host)
    }
}

/// Splits a query string into decoded `(name, value)` pairs.
pub fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect()
}

/// Decodes `%XX` escapes and `+` (as space); invalid escapes are kept as is.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let escaped = bytes
            .get(i + 1..i + 3)
            .filter(|_| bytes[i] == b'%')
            .and_then(|hex| Some(hex_value(hex[0])? << 4 | hex_value(hex[1])?));
        match (escaped, bytes[i]) {
            (Some(byte), _) => {
                out.push(byte);
                i += 3;
            }
            (None, b'+') => {
                out.push(b' ');
                i += 1;
            }
            (None, byte) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_value(byte: u8) -> Option<u8> {
    char::from(byte)
        .to_digit(16)
        .and_then(|digit| u8::try_from(digit).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matcher(host: &str) -> RequestMatcher {
        RequestMatcher {
            scheme: None,
            methods: Vec::new(),
            host: HostPattern::parse(host).unwrap(),
            path: None,
            query: Vec::new(),
            headers: Vec::new(),
        }
    }

    fn request(method: &str, uri: &str) -> Request<()> {
        Request::builder().method(method).uri(uri).body(()).unwrap()
    }

    fn matches(m: &RequestMatcher, req: &Request<()>) -> bool {
        m.matches(&RequestInfo::from_request(req).unwrap())
    }

    #[test]
    fn request_info_from_absolute_uri() {
        let req = request("POST", "https://API.x.com:8443/v1/a?b=1");
        let info = RequestInfo::from_request(&req).unwrap();
        assert_eq!(info.scheme, Scheme::Https);
        assert_eq!(info.method, Method::POST);
        assert_eq!(info.host, "API.x.com");
        assert_eq!(info.port, 8443);
        assert_eq!(info.path, "/v1/a");
        assert_eq!(info.query, Some("b=1"));
    }

    #[test]
    fn request_info_uses_default_ports() {
        let req = request("GET", "http://x.com/");
        assert_eq!(RequestInfo::from_request(&req).unwrap().port, 80);
        let req = request("GET", "https://x.com/");
        assert_eq!(RequestInfo::from_request(&req).unwrap().port, 443);
    }

    #[test]
    fn request_info_falls_back_to_host_header() {
        let with_host = |host: &str| {
            Request::builder()
                .uri("/path")
                .header("host", host)
                .body(())
                .unwrap()
        };
        let req = with_host("local.test:9000");
        let info = RequestInfo::from_request(&req).unwrap();
        assert_eq!((info.host, info.port), ("local.test", 9000));
        assert_eq!(info.scheme, Scheme::Http);

        let req = with_host("[::1]:9000");
        let info = RequestInfo::from_request(&req).unwrap();
        assert_eq!((info.host, info.port), ("::1", 9000));

        let req = with_host("[::1]");
        let info = RequestInfo::from_request(&req).unwrap();
        assert_eq!((info.host, info.port), ("::1", 80));

        let req = with_host("odd:port");
        let info = RequestInfo::from_request(&req).unwrap();
        assert_eq!((info.host, info.port), ("odd:port", 80));
    }

    #[test]
    fn request_info_requires_a_host() {
        let req = request("GET", "/only-path");
        assert!(RequestInfo::from_request(&req).is_none());
    }

    #[test]
    fn host_only_matcher_accepts_any_method_and_path() {
        let m = matcher("x.com");
        assert!(matches(&m, &request("GET", "https://x.com/")));
        assert!(matches(&m, &request("DELETE", "http://x.com/a/b?c=d")));
        assert!(!matches(&m, &request("GET", "https://y.com/")));
    }

    #[test]
    fn scheme_and_method_restrictions() {
        let mut m = matcher("x.com");
        m.scheme = Some(Scheme::Https);
        m.methods = vec![Method::POST, Method::PUT];
        assert!(matches(&m, &request("POST", "https://x.com/")));
        assert!(matches(&m, &request("PUT", "https://x.com/")));
        assert!(!matches(&m, &request("GET", "https://x.com/")));
        assert!(!matches(&m, &request("POST", "http://x.com/")));
    }

    #[test]
    fn path_restriction() {
        let mut m = matcher("x.com");
        m.path = Some(PathPattern::parse("/v1/users/:id").unwrap());
        assert!(matches(
            &m,
            &request("GET", "https://x.com/v1/users/7?full=1")
        ));
        assert!(!matches(&m, &request("GET", "https://x.com/v1/users")));
    }

    #[test]
    fn query_restriction_supports_exact_and_presence() {
        let mut m = matcher("x.com");
        m.query = vec![
            ("kind".into(), ValueMatch::from_config("a b")),
            ("token".into(), ValueMatch::from_config("*")),
        ];
        let check = |uri: &str| matches(&m, &request("GET", uri));
        assert!(check("https://x.com/?kind=a+b&token=1"));
        assert!(check("https://x.com/?token=&kind=a%20b"));
        assert!(!check("https://x.com/?kind=a+b"));
        assert!(!check("https://x.com/?kind=c&token=1"));
        assert!(!check("https://x.com/"));
    }

    #[test]
    fn header_restriction_is_case_insensitive_on_names() {
        let mut m = matcher("x.com");
        m.headers = vec![
            (
                HeaderName::from_static("x-tenant"),
                ValueMatch::from_config("acme"),
            ),
            (
                HeaderName::from_static("authorization"),
                ValueMatch::from_config("*"),
            ),
        ];
        let with_headers = |headers: &[(&str, &[u8])]| {
            let mut builder = Request::builder().uri("https://x.com/");
            for (name, value) in headers {
                builder = builder.header(*name, *value);
            }
            matches(&m, &builder.body(()).unwrap())
        };
        assert!(with_headers(&[
            ("X-Tenant", b"acme"),
            ("Authorization", b"t")
        ]));
        assert!(!with_headers(&[
            ("x-tenant", b"other"),
            ("authorization", b"t")
        ]));
        assert!(!with_headers(&[("x-tenant", b"acme")]));
        assert!(
            !with_headers(&[("x-tenant", b"\xff"), ("authorization", b"t")]),
            "non UTF-8 values never match"
        );
    }

    #[test]
    fn tls_interception_respects_scheme_and_host() {
        let mut m = matcher("*.x.com");
        assert!(m.may_intercept_tls("a.x.com", 443));
        assert!(!m.may_intercept_tls("x.com", 443));
        m.scheme = Some(Scheme::Http);
        assert!(!m.may_intercept_tls("a.x.com", 443));
        m.scheme = Some(Scheme::Https);
        assert!(m.may_intercept_tls("a.x.com", 443));
    }

    #[test]
    fn describe_summarizes_conditions() {
        let mut m = matcher("x.com");
        assert_eq!(m.describe(), "* x.com/**");
        m.methods = vec![Method::GET, Method::POST];
        m.scheme = Some(Scheme::Https);
        m.path = Some(PathPattern::parse("/a/:id").unwrap());
        assert_eq!(m.describe(), "GET|POST https://x.com/a/:id");
    }

    #[test]
    fn percent_decoding() {
        assert_eq!(percent_decode("a%20b+c"), "a b c");
        assert_eq!(percent_decode("%C3%A9"), "é");
        assert_eq!(percent_decode("%2b%2B"), "++");
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%4"), "%4");
        assert_eq!(percent_decode("%4g"), "%4g");
    }

    #[test]
    fn query_parsing() {
        assert_eq!(
            parse_query("a=1&b&&c=x%3Dy"),
            vec![
                ("a".to_owned(), "1".to_owned()),
                ("b".to_owned(), String::new()),
                ("c".to_owned(), "x=y".to_owned()),
            ]
        );
    }

    #[test]
    fn scheme_helpers() {
        assert_eq!(Scheme::parse("HTTPS"), Some(Scheme::Https));
        assert_eq!(Scheme::parse("http"), Some(Scheme::Http));
        assert_eq!(Scheme::parse("ftp"), None);
        assert_eq!(Scheme::Http.to_string(), "http");
        assert_eq!(Scheme::Https.to_string(), "https");
        assert_eq!(Scheme::Https.default_port(), 443);
        assert_eq!(Scheme::Http.default_port(), 80);
    }
}
