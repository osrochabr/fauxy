//! Environment variables that route command-line tools through fauxy.

use crate::java::{jvm_flags, proxy_host};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;

pub const NO_PROXY: &str = "localhost,127.0.0.1,::1";

/// Every variable `fauxy env` may set, for `--unset`.
pub const ALL_VARIABLES: [&str; 11] = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "http_proxy",
    "https_proxy",
    "NO_PROXY",
    "no_proxy",
    "NODE_EXTRA_CA_CERTS",
    "REQUESTS_CA_BUNDLE",
    "SSL_CERT_FILE",
    "JAVA_TOOL_OPTIONS",
    "FAUXY_PROXY",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    /// bash, zsh, sh.
    Posix,
    Fish,
}

impl Shell {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "bash" | "zsh" | "sh" | "posix" => Some(Self::Posix),
            "fish" => Some(Self::Fish),
            _ => None,
        }
    }

    /// Detects the shell from `$SHELL`, defaulting to POSIX syntax.
    pub fn detect(shell_env: Option<&str>) -> Self {
        shell_env
            .and_then(|path| path.rsplit('/').next())
            .and_then(Self::parse)
            .unwrap_or(Self::Posix)
    }
}

#[derive(Debug, Clone)]
pub struct EnvSpec<'a> {
    pub listen: SocketAddr,
    pub ca_cert: &'a Path,
    /// System roots plus the fauxy CA.
    pub ca_bundle: &'a Path,
    /// Adds `JAVA_TOOL_OPTIONS` when set.
    pub java_truststore: Option<&'a Path>,
}

/// Variables to export, in order.
pub fn variables(spec: &EnvSpec<'_>) -> Vec<(String, String)> {
    let proxy = match proxy_host(spec.listen) {
        IpAddr::V6(ip) => format!("http://[{ip}]:{}", spec.listen.port()),
        IpAddr::V4(ip) => format!("http://{ip}:{}", spec.listen.port()),
    };
    let ca_cert = spec.ca_cert.display().to_string();
    let ca_bundle = spec.ca_bundle.display().to_string();
    let mut vars: Vec<(String, String)> = [
        ("FAUXY_PROXY", proxy.as_str()),
        ("HTTP_PROXY", &proxy),
        ("HTTPS_PROXY", &proxy),
        ("http_proxy", &proxy),
        ("https_proxy", &proxy),
        ("NO_PROXY", NO_PROXY),
        ("no_proxy", NO_PROXY),
        ("NODE_EXTRA_CA_CERTS", &ca_cert),
        ("REQUESTS_CA_BUNDLE", &ca_bundle),
        ("SSL_CERT_FILE", &ca_bundle),
    ]
    .iter()
    .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
    .collect();
    if let Some(truststore) = spec.java_truststore {
        let options = jvm_flags(spec.listen, truststore).join(" ");
        vars.push(("JAVA_TOOL_OPTIONS".to_owned(), options));
    }
    vars
}

pub fn render_exports(vars: &[(String, String)], shell: Shell) -> String {
    vars.iter()
        .map(|(name, value)| match shell {
            Shell::Posix => format!("export {name}={}\n", posix_quote(value)),
            Shell::Fish => format!("set -gx {name} {}\n", fish_quote(value)),
        })
        .collect()
}

pub fn render_unset(names: &[&str], shell: Shell) -> String {
    names
        .iter()
        .map(|name| match shell {
            Shell::Posix => format!("unset {name}\n"),
            Shell::Fish => format!("set -e {name}\n"),
        })
        .collect()
}

fn posix_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn fish_quote(value: &str) -> String {
    format!("'{}'", value.replace('\\', "\\\\").replace('\'', "\\'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(java: Option<&Path>) -> EnvSpec<'_> {
        EnvSpec {
            listen: "127.0.0.1:8899".parse().unwrap(),
            ca_cert: Path::new("/s/ca.pem"),
            ca_bundle: Path::new("/s/bundle.pem"),
            java_truststore: java,
        }
    }

    fn get<'a>(vars: &'a [(String, String)], name: &str) -> Option<&'a str> {
        vars.iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn proxy_and_certificate_variables() {
        let vars = variables(&spec(None));
        assert_eq!(get(&vars, "HTTPS_PROXY"), Some("http://127.0.0.1:8899"));
        assert_eq!(get(&vars, "http_proxy"), Some("http://127.0.0.1:8899"));
        assert_eq!(get(&vars, "NO_PROXY"), Some(NO_PROXY));
        assert_eq!(get(&vars, "NODE_EXTRA_CA_CERTS"), Some("/s/ca.pem"));
        assert_eq!(get(&vars, "SSL_CERT_FILE"), Some("/s/bundle.pem"));
        assert_eq!(get(&vars, "JAVA_TOOL_OPTIONS"), None);
        assert!(
            vars.iter()
                .all(|(n, _)| ALL_VARIABLES.contains(&n.as_str()))
        );
    }

    #[test]
    fn java_options_are_optional() {
        let vars = variables(&spec(Some(Path::new("/s/ts.p12"))));
        let options = get(&vars, "JAVA_TOOL_OPTIONS").unwrap();
        assert!(options.contains("-Dhttps.proxyPort=8899"));
        assert!(options.contains("-Djavax.net.ssl.trustStore=/s/ts.p12"));
    }

    #[test]
    fn wildcard_and_ipv6_listen_addresses() {
        let mut s = spec(None);
        s.listen = "0.0.0.0:1".parse().unwrap();
        assert_eq!(
            get(&variables(&s), "HTTP_PROXY"),
            Some("http://127.0.0.1:1")
        );
        s.listen = "[::1]:2".parse().unwrap();
        assert_eq!(get(&variables(&s), "HTTP_PROXY"), Some("http://[::1]:2"));
    }

    #[test]
    fn posix_and_fish_syntax() {
        let vars = vec![("A".to_owned(), "it's x\\".to_owned())];
        assert_eq!(
            render_exports(&vars, Shell::Posix),
            "export A='it'\\''s x\\'\n"
        );
        assert_eq!(
            render_exports(&vars, Shell::Fish),
            "set -gx A 'it\\'s x\\\\'\n"
        );
        assert_eq!(
            render_unset(&["A", "B"], Shell::Posix),
            "unset A\nunset B\n"
        );
        assert_eq!(render_unset(&["A"], Shell::Fish), "set -e A\n");
    }

    #[test]
    fn shell_detection() {
        assert_eq!(Shell::detect(Some("/bin/zsh")), Shell::Posix);
        assert_eq!(Shell::detect(Some("/usr/local/bin/fish")), Shell::Fish);
        assert_eq!(Shell::detect(Some("/bin/tcsh")), Shell::Posix);
        assert_eq!(Shell::detect(None), Shell::Posix);
        assert_eq!(Shell::parse("bash"), Some(Shell::Posix));
        assert_eq!(Shell::parse("posix"), Some(Shell::Posix));
        assert_eq!(Shell::parse("pwsh"), None);
    }
}
