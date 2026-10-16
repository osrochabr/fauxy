//! Thin wrappers over the few POSIX calls fauxy needs. This is the only module
//! allowed to use `unsafe`.
#![allow(unsafe_code)]

use std::io;

pub fn euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// Starts a new session, so the process no longer belongs to the terminal
/// that launched it. It only fails for processes that already lead a session
/// or process group, which are detached enough.
pub fn new_session() {
    // SAFETY: setsid has no preconditions.
    unsafe { libc::setsid() };
}

/// Removes an environment variable. Only for the start of `main`: the
/// environment is not synchronized with threads that read it concurrently.
pub(crate) fn remove_env_at_startup(name: &str) {
    // SAFETY: called from `cli::main` before the runtime or any other thread
    // exists, so nothing reads the environment concurrently.
    unsafe { std::env::remove_var(name) };
}

pub fn send_signal(pid: i32, signal: i32) -> io::Result<()> {
    if pid <= 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"));
    }
    // SAFETY: kill has no memory-safety preconditions; a positive pid targets
    // a single process.
    if unsafe { libc::kill(pid, signal) } == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

pub fn terminate(pid: i32) -> io::Result<()> {
    send_signal(pid, libc::SIGTERM)
}

pub fn process_alive(pid: i32) -> bool {
    match send_signal(pid, 0) {
        Ok(()) => true,
        Err(err) => err.raw_os_error() == Some(libc::EPERM),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn current_process_is_alive() {
        let pid = i32::try_from(std::process::id()).unwrap();
        assert!(process_alive(pid));
    }

    #[test]
    fn invalid_pids_are_rejected() {
        assert!(!process_alive(0));
        assert!(!process_alive(-1));
        let err = send_signal(-5, 0).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn processes_of_other_users_count_as_alive() {
        // pid 1 belongs to root: kill(1, 0) fails with EPERM for regular users.
        assert!(process_alive(1));
    }

    #[test]
    fn terminate_stops_a_child() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        terminate(pid).unwrap();
        assert!(!child.wait().unwrap().success());
    }

    #[test]
    fn signaling_a_missing_process_fails() {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = i32::try_from(child.id()).unwrap();
        child.wait().unwrap();
        assert!(!process_alive(pid));
        assert!(terminate(pid).is_err());
    }

    #[test]
    fn euid_matches_file_ownership() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(std::fs::metadata(dir.path()).unwrap().uid(), euid());
    }
}
