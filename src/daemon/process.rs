//! Background process management: start, stop and the PID file lock.

use crate::control::{ClientError, ControlClient, StatusInfo};
use crate::paths::Paths;
use std::ffi::OsString;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub const START_TIMEOUT: Duration = Duration::from_secs(10);
pub const STOP_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    #[error("fauxy is already running (pid {0})")]
    AlreadyRunning(u32),
    #[error("fauxy exited during startup; last lines of {}:\n{log}", path.display())]
    StartFailed { path: PathBuf, log: String },
    #[error("fauxy (pid {pid}) did not respond in time; see the log at {}", log.display())]
    Timeout { pid: u32, log: PathBuf },
    #[error("fauxy is not running")]
    NotRunning,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Client(#[from] ClientError),
}

/// Exclusive lock on the PID file, held for the daemon's lifetime and released
/// by the kernel when the process exits. A PID read from a file nobody holds
/// a lock on is stale and must never be signaled: the number may have been
/// reused by an unrelated process.
#[derive(Debug)]
pub struct PidFile {
    file: File,
}

impl PidFile {
    pub fn acquire(path: &Path, pid: u32) -> Result<Self, ProcessError> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        let mut locked = file.try_lock();
        for _ in 0..3 {
            if !matches!(locked, Err(TryLockError::WouldBlock)) {
                break;
            }
            // `locked_pid` (used by `status` and `stop`) holds a shared lock
            // for an instant; only a lasting lock means another daemon.
            std::thread::sleep(Duration::from_millis(20));
            locked = file.try_lock();
        }
        locked.map_err(|err| lock_error(err, path))?;
        file.set_len(0)?;
        writeln!(file, "{pid}")?;
        Ok(Self { file })
    }
}

impl Drop for PidFile {
    /// Empties the file instead of removing it: unlinking it while another
    /// daemon waits on the same inode would let two daemons run at once.
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
    }
}

fn lock_error(err: TryLockError, path: &Path) -> ProcessError {
    match err {
        TryLockError::WouldBlock => {
            ProcessError::AlreadyRunning(read_pid(path).unwrap_or_default())
        }
        TryLockError::Error(err) => ProcessError::Io(err),
    }
}

/// The PID of a live daemon, i.e. one still holding the PID file lock.
pub fn locked_pid(path: &Path) -> Option<u32> {
    let file = File::open(path).ok()?;
    match file.try_lock_shared() {
        Err(TryLockError::WouldBlock) => read_pid(path),
        _ => None,
    }
}

pub fn read_pid(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Arguments of the `run` command used by background launches and services.
pub fn run_args(config_file: Option<&Path>, log_file: &Path) -> Vec<OsString> {
    let mut args: Vec<OsString> = vec!["run".into(), "--log-file".into(), log_file.into()];
    if let Some(config) = config_file {
        args.push("--config".into());
        args.push(config.into());
    }
    args
}

/// Spawns `exe args...` without stdin/stdout and with stderr appended to
/// `log_file`.
pub fn spawn_daemon(exe: &Path, args: &[OsString], log_file: &Path) -> io::Result<Child> {
    std::fs::create_dir_all(log_file.parent().unwrap_or(Path::new(".")))?;
    let log = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(log_file)?;
    Command::new(exe)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(log))
        .spawn()
}

/// Starts the daemon in the background and waits until it answers. The
/// daemon detaches itself from the terminal (`run --detach`).
pub async fn start_background(
    paths: &Paths,
    exe: &Path,
    config_file: Option<&Path>,
) -> Result<StatusInfo, ProcessError> {
    let mut args = run_args(config_file, &paths.log_file());
    args.push("--detach".into());
    launch(paths, exe, &args, START_TIMEOUT).await
}

async fn launch(
    paths: &Paths,
    exe: &Path,
    args: &[OsString],
    timeout: Duration,
) -> Result<StatusInfo, ProcessError> {
    let client = ControlClient::new(paths.socket()).with_timeout(Duration::from_secs(1));
    if let Ok(status) = client.status().await {
        return Err(ProcessError::AlreadyRunning(status.pid));
    }
    paths.ensure_state_dir()?;
    let log_file = paths.log_file();
    // Rotating here keeps the daemon's stderr and the excerpt below on the
    // same file.
    super::logging::rotate_if_large(&log_file, super::logging::MAX_LOG_BYTES)?;
    let log_start = std::fs::metadata(&log_file).map_or(0, |m| m.len());
    let mut child = spawn_daemon(exe, args, &log_file)?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(status) = client.status().await
            && status.pid == child.id()
        {
            return Ok(status);
        }
        if child.try_wait()?.is_some() {
            let log = log_since(&log_file, log_start);
            return Err(ProcessError::StartFailed {
                path: log_file,
                log,
            });
        }
        if tokio::time::Instant::now() >= deadline {
            let pid = child.id();
            return Err(ProcessError::Timeout { pid, log: log_file });
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Stops the daemon through the control API, falling back to SIGTERM when the
/// API does not answer but the PID file is still locked. Returns the PID.
pub async fn stop(paths: &Paths) -> Result<u32, ProcessError> {
    stop_within(paths, STOP_TIMEOUT).await
}

async fn stop_within(paths: &Paths, timeout: Duration) -> Result<u32, ProcessError> {
    let client = ControlClient::new(paths.socket()).with_timeout(Duration::from_secs(2));
    let pid = match client.status().await {
        Ok(status) => {
            client.shutdown().await?;
            status.pid
        }
        Err(ClientError::NotRunning) => {
            let pid = locked_pid(&paths.pid_file()).ok_or(ProcessError::NotRunning)?;
            crate::sys::terminate(as_pid(pid))?;
            pid
        }
        Err(err) => return Err(err.into()),
    };

    // A daemon releases the PID file lock when it exits, even if its parent
    // has not reaped it yet (a zombie still counts as a live process).
    let pid_file = paths.pid_file();
    let running = || crate::sys::process_alive(as_pid(pid)) && locked_pid(&pid_file) == Some(pid);
    let deadline = tokio::time::Instant::now() + timeout;
    while running() {
        if tokio::time::Instant::now() >= deadline {
            return Err(ProcessError::Timeout {
                pid,
                log: paths.log_file(),
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(pid)
}

fn as_pid(pid: u32) -> i32 {
    i32::try_from(pid).unwrap_or_default()
}

/// The last 20 lines written after `offset`.
fn log_since(path: &Path, offset: u64) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let start = usize::try_from(offset)
        .unwrap_or(usize::MAX)
        .min(text.len());
    let recent: Vec<&str> = text.get(start..).unwrap_or_default().lines().collect();
    recent[recent.len().saturating_sub(20)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::ControlServer;
    use crate::control::server::tests::context;

    fn paths(dir: &Path) -> Paths {
        let paths = Paths {
            config_dir: dir.join("c"),
            state_dir: dir.join("s"),
        };
        paths.ensure_state_dir().unwrap();
        paths
    }

    #[test]
    fn run_args_include_log_and_config() {
        let args = run_args(Some(Path::new("/c.yaml")), Path::new("/s/f.log"));
        assert_eq!(
            args,
            vec!["run", "--log-file", "/s/f.log", "--config", "/c.yaml"]
        );
        let args = run_args(None, Path::new("/s/f.log"));
        assert_eq!(args, vec!["run", "--log-file", "/s/f.log"]);
    }

    #[test]
    fn pid_file_is_locked_while_held() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.pid");
        assert_eq!(locked_pid(&path), None);

        let held = PidFile::acquire(&path, 4242).unwrap();
        assert_eq!(read_pid(&path), Some(4242));
        assert_eq!(locked_pid(&path), Some(4242));
        let err = PidFile::acquire(&path, 1).unwrap_err();
        assert_eq!(err.to_string(), "fauxy is already running (pid 4242)");

        drop(held);
        assert_eq!(locked_pid(&path), None);
        assert_eq!(read_pid(&path), None, "the PID file is emptied on drop");
    }

    #[test]
    fn stale_pid_files_are_not_trusted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.pid");
        std::fs::write(&path, "4242\n").unwrap();
        assert_eq!(read_pid(&path), Some(4242));
        assert_eq!(locked_pid(&path), None);

        let fresh = PidFile::acquire(&path, 7).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "7\n");
        drop(fresh);

        std::fs::write(&path, "garbage").unwrap();
        assert_eq!(read_pid(&path), None);
    }

    #[test]
    fn lock_errors_are_classified() {
        let path = Path::new("/does/not/exist.pid");
        assert!(matches!(
            lock_error(TryLockError::WouldBlock, path),
            ProcessError::AlreadyRunning(0)
        ));
        let io = TryLockError::Error(io::Error::other("no locks left"));
        assert_eq!(lock_error(io, path).to_string(), "no locks left");
        assert!(PidFile::acquire(path, 1).is_err());
    }

    #[test]
    fn spawn_daemon_appends_stderr_to_a_private_log() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("logs/out.log");
        let args: Vec<OsString> = vec!["-c".into(), "echo output >&2".into()];
        for _ in 0..2 {
            let mut child = spawn_daemon(Path::new("sh"), &args, &log).unwrap();
            assert!(child.wait().unwrap().success());
        }
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "output\noutput\n");
        let mode = std::fs::metadata(&log).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn log_since_returns_only_new_lines() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("f.log");
        std::fs::write(&log, "old\nnew1\nnew2\n").unwrap();
        assert_eq!(log_since(&log, 4), "new1\nnew2");
        assert_eq!(log_since(&log, 999), "");
        assert_eq!(log_since(&dir.path().join("none"), 0), "");
        let long: String = (0..30).map(|i| format!("{i}\n")).collect();
        std::fs::write(&log, long).unwrap();
        assert!(log_since(&log, 0).starts_with("10\n"));
    }

    #[tokio::test]
    async fn stop_without_daemon_reports_not_running() {
        let dir = tempfile::tempdir().unwrap();
        let err = stop(&paths(dir.path())).await.unwrap_err();
        assert!(matches!(err, ProcessError::NotRunning));
    }

    #[tokio::test]
    async fn stop_never_signals_a_stale_pid() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let mut bystander = Command::new("sleep").arg("30").spawn().unwrap();
        std::fs::write(paths.pid_file(), format!("{}\n", bystander.id())).unwrap();

        let err = stop(&paths).await.unwrap_err();
        assert!(matches!(err, ProcessError::NotRunning));
        assert!(
            bystander.try_wait().unwrap().is_none(),
            "the process must survive"
        );
        bystander.kill().unwrap();
        bystander.wait().unwrap();
    }

    #[tokio::test]
    async fn stop_falls_back_to_sigterm_when_the_pid_file_is_locked() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let _lock = PidFile::acquire(&paths.pid_file(), child.id()).unwrap();

        let waiter = std::thread::spawn(move || child.wait().unwrap());
        let pid = stop(&paths).await.unwrap();
        assert!(pid > 0);
        assert!(!waiter.join().unwrap().success());
    }

    #[tokio::test]
    async fn stop_reports_processes_that_ignore_sigterm() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let mut child = Command::new("sh")
            .args(["-c", "trap '' TERM; echo ready; exec sleep 30"])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        std::io::BufRead::read_line(
            &mut std::io::BufReader::new(child.stdout.take().unwrap()),
            &mut ready,
        )
        .unwrap();
        assert_eq!(ready, "ready\n", "SIGTERM is ignored from now on");
        let _lock = PidFile::acquire(&paths.pid_file(), child.id()).unwrap();

        let err = stop_within(&paths, Duration::from_millis(300))
            .await
            .unwrap_err();
        assert!(matches!(err, ProcessError::Timeout { .. }), "{err}");
        assert!(err.to_string().contains("did not respond in time"));
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[tokio::test]
    async fn stop_uses_the_control_api_when_available() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let ctx = context();
        let _server = ControlServer::bind(&paths.socket(), ctx.clone()).unwrap();
        // The stub reports pid 1, which does not hold the PID file lock, so it
        // counts as stopped once the shutdown request was delivered.
        assert_eq!(stop(&paths).await.unwrap(), 1);
        assert!(ctx.shutdown.is_cancelled());
    }

    #[tokio::test]
    async fn stop_reports_unresponsive_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let _listener = std::os::unix::net::UnixListener::bind(paths.socket()).unwrap();
        let err = stop(&paths).await.unwrap_err();
        assert!(
            matches!(err, ProcessError::Client(ClientError::Transport(_))),
            "{err}"
        );
    }

    #[tokio::test]
    async fn start_reports_early_exit_with_the_log() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let args: Vec<OsString> = vec!["-c".into(), "echo broken config >&2; exit 1".into()];
        let err = launch(&paths, Path::new("sh"), &args, START_TIMEOUT)
            .await
            .unwrap_err();
        assert!(matches!(err, ProcessError::StartFailed { .. }), "{err}");
        assert!(err.to_string().ends_with(":\nbroken config"), "{err}");
    }

    #[tokio::test]
    async fn start_times_out_when_the_daemon_never_answers() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let args: Vec<OsString> = vec!["2".into()];
        let err = launch(
            &paths,
            Path::new("sleep"),
            &args,
            Duration::from_millis(200),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProcessError::Timeout { .. }), "{err}");
    }

    #[tokio::test]
    async fn start_refuses_a_second_instance() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let ctx = context();
        let _server = ControlServer::bind(&paths.socket(), ctx.clone()).unwrap();
        let err = start_background(&paths, Path::new("true"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ProcessError::AlreadyRunning(1)), "{err}");
        ctx.shutdown.cancel();
    }

    #[tokio::test]
    async fn start_reports_missing_executables() {
        let dir = tempfile::tempdir().unwrap();
        let paths = paths(dir.path());
        let err = start_background(&paths, Path::new("/does/not/exist"), None)
            .await
            .unwrap_err();
        assert!(matches!(err, ProcessError::Io(_)), "{err}");
    }
}
