use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Header added to every mocked response with the name of the rule.
pub const RULE_HEADER: &str = "x-fauxy-rule";

#[derive(Debug, Clone, PartialEq)]
pub enum MockBody {
    Empty,
    Inline {
        data: Bytes,
        /// Used when the rule does not set `Content-Type` itself.
        content_type: &'static str,
    },
    /// Read at request time, so edits apply without a reload. The file must
    /// resolve inside `root` (the canonical directory of the rule file), even
    /// through symbolic links created after the rules were loaded.
    File {
        path: PathBuf,
        root: PathBuf,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub struct MockResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: MockBody,
    pub delay: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RenderedResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl MockResponse {
    pub async fn render(&self, rule_name: &str) -> std::io::Result<RenderedResponse> {
        let (body, default_type) = match &self.body {
            MockBody::Empty => (Bytes::new(), None),
            MockBody::Inline { data, content_type } => (data.clone(), Some(*content_type)),
            MockBody::File { path, root } => {
                (read_body(path, root).await?, Some(content_type_for(path)))
            }
        };

        let mut headers = HeaderMap::new();
        for (name, value) in &self.headers {
            headers.append(name.clone(), value.clone());
        }
        if let Some(default_type) = default_type
            && !headers.contains_key(CONTENT_TYPE)
        {
            headers.insert(CONTENT_TYPE, HeaderValue::from_static(default_type));
        }
        headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        if let Ok(value) = HeaderValue::from_str(rule_name) {
            headers.insert(HeaderName::from_static(RULE_HEADER), value);
        }

        Ok(RenderedResponse {
            status: self.status,
            headers,
            body,
        })
    }
}

/// Opens the file before checking where it resolves and compares the inode of
/// the opened file with the checked path, so swapping the file for a symbolic
/// link between the check and the read cannot escape `root`.
async fn read_body(path: &Path, root: &Path) -> std::io::Result<Bytes> {
    use std::os::unix::fs::MetadataExt;
    use tokio::io::AsyncReadExt;

    let failure = |err: std::io::Error| {
        std::io::Error::new(
            err.kind(),
            format!("failed to read '{}': {err}", path.display()),
        )
    };
    let mut file = tokio::fs::File::open(path).await.map_err(failure)?;
    let real = tokio::fs::canonicalize(path).await.map_err(failure)?;
    let opened = file.metadata().await.map_err(failure)?;
    let checked = tokio::fs::metadata(&real).await.map_err(failure)?;
    let same_file = (opened.dev(), opened.ino()) == (checked.dev(), checked.ino());
    if !real.starts_with(root) || !same_file {
        let reason = format!("it resolves outside {}", root.display());
        return Err(failure(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            reason,
        )));
    }
    let mut data = Vec::new();
    file.read_to_end(&mut data).await.map_err(failure)?;
    Ok(Bytes::from(data))
}

impl RenderedResponse {
    pub fn into_response<B: From<Bytes>>(self) -> http::Response<B> {
        let mut response = http::Response::new(B::from(self.body));
        *response.status_mut() = self.status;
        *response.headers_mut() = self.headers;
        response
    }
}

/// Guesses a content type from the file extension.
pub fn content_type_for(path: &Path) -> &'static str {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("json") => "application/json",
        Some("xml") => "application/xml",
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("txt" | "text") => "text/plain; charset=utf-8",
        Some("csv") => "text/csv; charset=utf-8",
        Some("js") => "application/javascript",
        Some("css") => "text/css; charset=utf-8",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inline(data: &str, content_type: &'static str) -> MockResponse {
        MockResponse {
            status: StatusCode::OK,
            headers: Vec::new(),
            body: MockBody::Inline {
                data: Bytes::from(data.to_owned()),
                content_type,
            },
            delay: None,
        }
    }

    fn with_body(body: MockBody) -> MockResponse {
        MockResponse {
            status: StatusCode::OK,
            headers: Vec::new(),
            body,
            delay: None,
        }
    }

    #[tokio::test]
    async fn inline_body_gets_default_content_type_and_length() {
        let rendered = inline("{}", "application/json")
            .render("my-rule")
            .await
            .unwrap();
        assert_eq!(rendered.status, StatusCode::OK);
        assert_eq!(rendered.body, Bytes::from_static(b"{}"));
        assert_eq!(rendered.headers[CONTENT_TYPE], "application/json");
        assert_eq!(rendered.headers[CONTENT_LENGTH], "2");
        assert_eq!(rendered.headers[RULE_HEADER], "my-rule");
    }

    #[tokio::test]
    async fn configured_content_type_wins_and_repeated_headers_are_kept() {
        let mut mock = inline("<a/>", "text/plain; charset=utf-8");
        for (name, value) in [("content-type", "text/xml"), ("x-a", "1"), ("x-a", "2")] {
            mock.headers.push((
                HeaderName::from_static(name),
                HeaderValue::from_static(value),
            ));
        }
        let rendered = mock.render("r").await.unwrap();
        assert_eq!(rendered.headers[CONTENT_TYPE], "text/xml");
        assert_eq!(rendered.headers.get_all("x-a").iter().count(), 2);
    }

    #[tokio::test]
    async fn empty_body_has_no_content_type() {
        let mut mock = with_body(MockBody::Empty);
        mock.status = StatusCode::NO_CONTENT;
        let rendered = mock.render("r").await.unwrap();
        assert!(rendered.body.is_empty());
        assert!(!rendered.headers.contains_key(CONTENT_TYPE));
        assert_eq!(rendered.headers[CONTENT_LENGTH], "0");
    }

    #[tokio::test]
    async fn file_body_is_read_at_render_time() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let path = root.join("data.json");
        std::fs::write(&path, "[1]").unwrap();
        let mock = with_body(MockBody::File {
            path: path.clone(),
            root,
        });
        assert_eq!(
            mock.render("r").await.unwrap().body,
            Bytes::from_static(b"[1]")
        );

        std::fs::write(&path, "[2]").unwrap();
        let rendered = mock.render("r").await.unwrap();
        assert_eq!(rendered.body, Bytes::from_static(b"[2]"));
        assert_eq!(rendered.headers[CONTENT_TYPE], "application/json");
    }

    #[tokio::test]
    async fn missing_file_reports_path_and_kind() {
        let mock = with_body(MockBody::File {
            path: "/does/not/exist.json".into(),
            root: "/does".into(),
        });
        let err = mock.render("r").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert!(err.to_string().contains("/does/not/exist.json"));
    }

    #[tokio::test]
    async fn files_that_escape_the_rule_directory_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().canonicalize().unwrap();
        let root = base.join("mocks");
        std::fs::create_dir(&root).unwrap();
        std::fs::write(base.join("secret.txt"), "private").unwrap();
        let link = root.join("data.json");
        std::os::unix::fs::symlink(base.join("secret.txt"), &link).unwrap();

        let mock = with_body(MockBody::File {
            path: link.clone(),
            root: root.clone(),
        });
        let err = mock.render("r").await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            err.to_string()
                .ends_with(&format!("it resolves outside {}", root.display()))
        );
    }

    #[tokio::test]
    async fn rule_names_that_are_not_valid_header_values_are_skipped() {
        let rendered = inline("x", "text/plain").render("a\nb").await.unwrap();
        assert!(!rendered.headers.contains_key(RULE_HEADER));
    }

    #[tokio::test]
    async fn into_response_preserves_parts() {
        let rendered = inline("ok", "text/plain").render("r").await.unwrap();
        let response: http::Response<Bytes> = rendered.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.body(), &Bytes::from_static(b"ok"));
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain");
    }

    #[test]
    fn content_types_by_extension() {
        let cases = [
            ("a.JSON", "application/json"),
            ("a.xml", "application/xml"),
            ("a.htm", "text/html; charset=utf-8"),
            ("a.txt", "text/plain; charset=utf-8"),
            ("a.csv", "text/csv; charset=utf-8"),
            ("a.js", "application/javascript"),
            ("a.css", "text/css; charset=utf-8"),
            ("a.svg", "image/svg+xml"),
            ("a.png", "image/png"),
            ("a.jpeg", "image/jpeg"),
            ("a.gif", "image/gif"),
            ("a.pdf", "application/pdf"),
            ("a.bin", "application/octet-stream"),
            ("a", "application/octet-stream"),
        ];
        for (file, expected) in cases {
            assert_eq!(content_type_for(Path::new(file)), expected, "{file}");
        }
    }
}
