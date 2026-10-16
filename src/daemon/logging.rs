use std::io;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use tracing_subscriber::EnvFilter;

/// Filter in `tracing` `EnvFilter` syntax.
pub const LOG_ENV: &str = "FAUXY_LOG";

pub const DEFAULT_FILTER: &str = "info,hudsucker=warn";

/// Target of fatal errors, which `FAUXY_LOG` cannot hide.
pub const FATAL: &str = "fauxy::fatal";

/// Larger log files are rotated when the daemon starts.
pub const MAX_LOG_BYTES: u64 = 10 * 1024 * 1024;

/// Logs to `log_file` (appending, owner-only) or to stderr.
pub fn init(log_file: Option<&Path>) -> io::Result<()> {
    let mut filter =
        EnvFilter::try_from_env(LOG_ENV).unwrap_or_else(|_| EnvFilter::new(DEFAULT_FILTER));
    if let Ok(fatal) = format!("{FATAL}=error").parse() {
        filter = filter.add_directive(fatal);
    }
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false);
    let result = match log_file {
        Some(path) => {
            std::fs::create_dir_all(path.parent().unwrap_or(Path::new(".")))?;
            rotate_if_large(path, MAX_LOG_BYTES)?;
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(path)?;
            builder
                .with_ansi(false)
                .with_writer(Mutex::new(file))
                .try_init()
        }
        None => builder.with_writer(io::stderr).try_init(),
    };
    // A subscriber may already be installed (tests run in one process).
    drop(result);
    Ok(())
}

/// Whether stderr writes to `path`, as it does under `fauxy start`.
pub fn is_stderr(path: &Path) -> bool {
    use std::os::fd::AsFd;
    use std::os::unix::fs::MetadataExt;

    let stderr = io::stderr().as_fd().try_clone_to_owned();
    match (
        stderr.and_then(|fd| std::fs::File::from(fd).metadata()),
        std::fs::metadata(path),
    ) {
        (Ok(stderr), Ok(file)) => stderr.dev() == file.dev() && stderr.ino() == file.ino(),
        _ => false,
    }
}

/// Renames `path` to `path.1` when it is larger than `max_bytes`.
pub fn rotate_if_large(path: &Path, max_bytes: u64) -> io::Result<bool> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > max_bytes => {
            std::fs::rename(path, rotated_path(path)).map(|()| true)
        }
        Ok(_) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

fn rotated_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".1");
    PathBuf::from(name)
}

pub fn tail(path: &Path, count: usize) -> io::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = text.lines().collect();
    let skip = lines.len().saturating_sub(count);
    Ok(lines[skip..]
        .iter()
        .map(|line| (*line).to_owned())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rotation_happens_only_above_limit() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        assert!(!rotate_if_large(&log, 10).unwrap());

        std::fs::write(&log, "12345").unwrap();
        assert!(!rotate_if_large(&log, 10).unwrap());
        assert!(log.exists());

        std::fs::write(&log, "12345678901").unwrap();
        assert!(rotate_if_large(&log, 10).unwrap());
        assert!(!log.exists());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("f.log.1")).unwrap(),
            "12345678901"
        );
    }

    #[test]
    fn rotation_reports_unexpected_errors() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "").unwrap();
        assert!(rotate_if_large(&blocker.join("f.log"), 10).is_err());
    }

    #[test]
    fn tail_returns_last_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        std::fs::write(&log, "a\nb\nc\n").unwrap();
        assert_eq!(tail(&log, 2).unwrap(), vec!["b", "c"]);
        assert_eq!(tail(&log, 10).unwrap(), vec!["a", "b", "c"]);
        assert!(tail(&dir.path().join("none"), 1).is_err());
    }

    #[test]
    fn init_creates_a_private_log_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("sub/f.log");
        init(Some(&log)).unwrap();
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        init(None).unwrap();
    }

    #[test]
    fn stderr_is_not_an_ordinary_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        assert!(!is_stderr(&log), "missing file");
        std::fs::write(&log, "").unwrap();
        assert!(!is_stderr(&log));
    }

    #[test]
    fn init_reports_unusable_paths() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            init(Some(dir.path())).is_err(),
            "a directory is not a log file"
        );
    }
}
