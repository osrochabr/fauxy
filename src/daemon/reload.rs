//! Configuration reloads, manual (control API) or automatic (file watcher).

use crate::config::{self, LoadedConfig};
use crate::control::ReloadResult;
use crate::events::now_ms;
use crate::paths::Paths;
use crate::state::AppState;
use notify_debouncer_mini::notify::{RecursiveMode, Watcher};
use notify_debouncer_mini::{DebounceEventResult, new_debouncer};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

/// Debounce applied to file system events.
pub const DEBOUNCE: Duration = Duration::from_millis(200);

/// How often the watcher thread checks whether it must stop.
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub struct Reloader {
    paths: Paths,
    config_file: Option<PathBuf>,
    state: Arc<AppState>,
    /// Settings that only apply on restart.
    listen: SocketAddr,
    /// `fauxy run --port`, applied to every reload as well.
    port: Option<u16>,
    upstream_ca_files: Vec<PathBuf>,
    current: Mutex<LoadedConfig>,
}

impl Reloader {
    /// Applies `initial` to `state`.
    pub fn new(
        paths: Paths,
        config_file: Option<PathBuf>,
        state: Arc<AppState>,
        initial: LoadedConfig,
        port: Option<u16>,
    ) -> Self {
        let reloader = Self {
            paths,
            config_file,
            listen: initial.listen,
            port,
            upstream_ca_files: initial.upstream_ca_files.clone(),
            state,
            current: Mutex::new(initial.clone()),
        };
        reloader.apply(initial, Vec::new());
        reloader
    }

    /// Loads the configuration again; on errors the current rules are kept.
    pub fn reload(&self) -> ReloadResult {
        let mut current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        let mut loaded = match config::load(&self.paths, self.config_file.as_deref()) {
            Ok(loaded) => loaded,
            Err(errors) => {
                let message = errors.to_string();
                tracing::error!("invalid configuration, keeping the previous rules:\n{message}");
                self.state
                    .update_info(|info| info.last_reload_error = Some(message.clone()));
                return ReloadResult {
                    ok: false,
                    rules: self.state.rules().len(),
                    error: Some(message),
                    warnings: Vec::new(),
                };
            }
        };
        if let Some(port) = self.port {
            loaded.set_port(port);
        }
        let mut notes = Vec::new();
        if loaded.listen != self.listen {
            notes.push(format!(
                "'listen' changed to {}; restart fauxy to apply it",
                loaded.listen
            ));
        }
        if loaded.upstream_ca_files != self.upstream_ca_files {
            notes.push("'upstream.ca_files' changed; restart fauxy to apply it".to_owned());
        }
        let rules = loaded.rules.len();
        let warnings = self.apply(loaded.clone(), notes);
        *current = loaded;
        tracing::info!("configuration reloaded: {rules} rule(s)");
        for warning in &warnings {
            tracing::warn!("{warning}");
        }
        ReloadResult {
            ok: true,
            rules,
            error: None,
            warnings,
        }
    }

    fn apply(&self, loaded: LoadedConfig, notes: Vec<String>) -> Vec<String> {
        let mut warnings = loaded.warnings;
        warnings.extend(notes);
        self.state.replace_rules(loaded.rules);
        self.state.update_info(|info| {
            info.config_file = loaded.config_file;
            info.mock_files = loaded.mock_files;
            info.warnings = warnings.clone();
            info.last_reload_ms = now_ms();
            info.last_reload_error = None;
        });
        warnings
    }

    pub fn watch_dirs(&self) -> Vec<PathBuf> {
        let current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        current.watch_dirs()
    }

    pub fn is_relevant(&self, path: &Path) -> bool {
        let current = self.current.lock().unwrap_or_else(PoisonError::into_inner);
        current.is_relevant_change(path)
    }
}

/// Watches the configuration directories and reloads on changes. Stops when
/// dropped.
#[derive(Debug)]
pub struct ConfigWatcher {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl ConfigWatcher {
    pub fn start(
        reloader: Arc<Reloader>,
        debounce: Duration,
    ) -> notify_debouncer_mini::notify::Result<Self> {
        let (tx, rx) = mpsc::channel::<DebounceEventResult>();
        let mut debouncer = new_debouncer(debounce, tx)?;
        let mut watched = Vec::new();
        sync_watches(debouncer.watcher(), &mut watched, reloader.watch_dirs());

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("fauxy-watcher".to_owned())
            .spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    if let Ok(result) = rx.recv_timeout(POLL)
                        && on_events(&reloader, result)
                    {
                        sync_watches(debouncer.watcher(), &mut watched, reloader.watch_dirs());
                    }
                }
            })
            .map_err(notify_debouncer_mini::notify::Error::io)?;

        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for ConfigWatcher {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Reloads when a relevant file changed. Returns whether it reloaded.
fn on_events(reloader: &Reloader, result: DebounceEventResult) -> bool {
    match result {
        Ok(events) if events.iter().any(|event| reloader.is_relevant(&event.path)) => {
            reloader.reload();
            true
        }
        Ok(_) => false,
        Err(err) => {
            tracing::warn!("file watcher error: {err}");
            false
        }
    }
}

/// Stops watching the directories that are no longer wanted and watches the
/// wanted ones. inotify (Linux) watches inodes, so every wanted directory is
/// added again: that is cheap and picks up a directory deleted and recreated
/// under the same path. FSEvents (macOS) watches paths, and every change to
/// its watch set restarts the event stream, so only new directories are added.
fn sync_watches(watcher: &mut dyn Watcher, watched: &mut Vec<PathBuf>, wanted: Vec<PathBuf>) {
    for dir in watched.iter().filter(|dir| !wanted.contains(dir)) {
        let _ = watcher.unwatch(dir);
    }
    let watch_again = cfg!(target_os = "linux");
    for dir in wanted
        .iter()
        .filter(|dir| watch_again || !watched.contains(dir))
    {
        if let Err(err) = watcher.watch(dir, RecursiveMode::NonRecursive) {
            tracing::warn!("cannot watch {}: {err}", dir.display());
        }
    }
    *watched = wanted;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load;
    use crate::rules::RuleSet;
    use notify_debouncer_mini::{DebouncedEvent, DebouncedEventKind};

    struct Fixture {
        _dir: tempfile::TempDir,
        paths: Paths,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let paths = Paths {
                config_dir: dir.path().join("config"),
                state_dir: dir.path().join("state"),
            };
            std::fs::create_dir_all(paths.default_mocks_dir()).unwrap();
            Self { _dir: dir, paths }
        }

        fn mock(&self, name: &str, content: &str) {
            std::fs::write(self.paths.default_mocks_dir().join(name), content).unwrap();
        }

        fn reloader(&self) -> (Arc<Reloader>, Arc<AppState>) {
            let loaded = load(&self.paths, None).unwrap();
            let state = Arc::new(AppState::new(RuleSet::default()));
            let reloader = Arc::new(Reloader::new(
                self.paths.clone(),
                None,
                Arc::clone(&state),
                loaded,
                None,
            ));
            (reloader, state)
        }
    }

    fn eventually(condition: impl Fn() -> bool) -> bool {
        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !condition() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        condition()
    }

    #[test]
    fn initial_configuration_is_applied() {
        let fx = Fixture::new();
        fx.mock("a.yaml", "host: a.com\nrules:\n  - respond: {}\n");
        let (_reloader, state) = fx.reloader();
        assert_eq!(state.rules().len(), 1);
        let info = state.info();
        assert_eq!(info.mock_files.len(), 1);
        assert!(info.last_reload_ms > 0);
    }

    #[test]
    fn reload_applies_changes_and_keeps_rules_on_error() {
        let fx = Fixture::new();
        fx.mock("a.yaml", "host: a.com\nrules:\n  - respond: {}\n");
        let (reloader, state) = fx.reloader();

        fx.mock("b.yaml", "host: b.com\nrules:\n  - respond: {}\n");
        let result = reloader.reload();
        assert!(result.ok);
        assert_eq!(result.rules, 2);
        assert_eq!(state.rules().len(), 2);

        fx.mock("c.yaml", "rules: [\n");
        let result = reloader.reload();
        assert!(!result.ok);
        assert!(result.error.unwrap().contains("c.yaml"));
        assert_eq!(result.rules, 2);
        assert_eq!(state.rules().len(), 2, "previous rules are kept");
        assert!(state.info().last_reload_error.is_some());

        std::fs::remove_file(fx.paths.default_mocks_dir().join("c.yaml")).unwrap();
        assert!(reloader.reload().ok);
        assert!(state.info().last_reload_error.is_none());
    }

    #[test]
    fn port_given_on_the_command_line_survives_reloads() {
        let fx = Fixture::new();
        std::fs::write(fx.paths.config_file(), "listen: 127.0.0.1:8899\n").unwrap();
        let mut loaded = load(&fx.paths, None).unwrap();
        loaded.set_port(9500);
        let state = Arc::new(AppState::new(RuleSet::default()));
        let reloader = Reloader::new(fx.paths.clone(), None, state, loaded, Some(9500));
        let result = reloader.reload();
        assert!(result.ok);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);

        std::fs::write(fx.paths.config_file(), "listen: 0.0.0.0:8899\n").unwrap();
        let result = reloader.reload();
        assert_eq!(result.warnings.len(), 2, "{:?}", result.warnings);
        assert!(
            result.warnings[0].starts_with("listen address 0.0.0.0:9500 accepts connections"),
            "{:?}",
            result.warnings
        );
        assert_eq!(
            result.warnings[1],
            "'listen' changed to 0.0.0.0:9500; restart fauxy to apply it"
        );
    }

    #[test]
    fn listen_and_upstream_changes_require_restart() {
        let fx = Fixture::new();
        let (reloader, _state) = fx.reloader();
        std::fs::write(fx.paths.config_dir.join("ca.pem"), "x").unwrap();
        std::fs::write(
            fx.paths.config_file(),
            "listen: 9999\nupstream:\n  ca_files: [ca.pem]\n",
        )
        .unwrap();
        let result = reloader.reload();
        assert!(result.ok);
        assert_eq!(
            result.warnings,
            vec![
                "'listen' changed to 127.0.0.1:9999; restart fauxy to apply it".to_owned(),
                "'upstream.ca_files' changed; restart fauxy to apply it".to_owned(),
            ]
        );
    }

    #[test]
    fn events_trigger_reloads_only_for_relevant_files() {
        let fx = Fixture::new();
        let (reloader, state) = fx.reloader();
        fx.mock("a.yaml", "host: a.com\nrules:\n  - respond: {}\n");
        let event = |name: &str| {
            let path = fx.paths.default_mocks_dir().join(name);
            Ok(vec![DebouncedEvent::new(path, DebouncedEventKind::Any)])
        };

        assert!(!on_events(&reloader, event("notes.txt")));
        assert_eq!(state.rules().len(), 0);
        assert!(on_events(&reloader, event("a.yaml")));
        assert_eq!(state.rules().len(), 1);
        let failure = Err(notify_debouncer_mini::notify::Error::generic("boom"));
        assert!(!on_events(&reloader, failure));
    }

    #[test]
    fn watches_are_synchronized() {
        let dir = tempfile::tempdir().unwrap();
        let (a, b) = (dir.path().join("a"), dir.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let mut watcher = notify_debouncer_mini::notify::recommended_watcher(|_| {}).unwrap();
        let mut watched = Vec::new();

        sync_watches(&mut watcher, &mut watched, vec![a.clone()]);
        assert_eq!(watched, vec![a.clone()]);
        let missing = dir.path().join("missing");
        sync_watches(&mut watcher, &mut watched, vec![b.clone(), missing.clone()]);
        assert_eq!(watched, vec![b, missing]);
    }

    #[test]
    fn watcher_reloads_on_file_changes() {
        let fx = Fixture::new();
        let (reloader, state) = fx.reloader();
        let _watcher =
            ConfigWatcher::start(Arc::clone(&reloader), Duration::from_millis(50)).unwrap();

        fx.mock("new.yaml", "host: n.com\nrules:\n  - respond: {}\n");
        assert!(eventually(|| state.rules().len() == 1));
    }

    #[test]
    fn watcher_follows_recreated_mock_directories() {
        let fx = Fixture::new();
        let mocks = fx.paths.default_mocks_dir();
        fx.mock("a.yaml", "host: a.com\nrules:\n  - respond: {}\n");
        let (reloader, state) = fx.reloader();
        let _watcher =
            ConfigWatcher::start(Arc::clone(&reloader), Duration::from_millis(50)).unwrap();

        std::fs::remove_dir_all(&mocks).unwrap();
        assert!(eventually(|| state.rules().is_empty()));
        // Let the watcher settle: changing the watched set restarts the
        // macOS event stream.
        std::thread::sleep(Duration::from_millis(500));
        std::fs::create_dir(&mocks).unwrap();
        fx.mock("b.yaml", "host: b.com\nrules:\n  - respond: {}\n");
        assert!(eventually(|| state.rules().len() == 1));

        std::thread::sleep(Duration::from_millis(300));
        fx.mock("c.yaml", "host: c.com\nrules:\n  - respond: {}\n");
        assert!(
            eventually(|| state.rules().len() == 2),
            "edits inside the new directory are seen"
        );

        // Deleted and recreated within one debounce window.
        std::fs::remove_dir_all(&mocks).unwrap();
        std::fs::create_dir(&mocks).unwrap();
        fx.mock("d.yaml", "host: d.com\nrules:\n  - respond: {}\n");
        assert!(eventually(|| state.rules().len() == 1));
        std::thread::sleep(Duration::from_millis(500));
        fx.mock("e.yaml", "host: e.com\nrules:\n  - respond: {}\n");
        assert!(
            eventually(|| state.rules().len() == 2),
            "the quickly recreated directory is still watched"
        );
    }

    #[test]
    fn watcher_follows_new_mock_directories() {
        let fx = Fixture::new();
        let extra = fx.paths.config_dir.join("extra");
        std::fs::write(fx.paths.config_file(), "mocks: [mocks, extra]\n").unwrap();
        let (reloader, state) = fx.reloader();
        let _watcher =
            ConfigWatcher::start(Arc::clone(&reloader), Duration::from_millis(50)).unwrap();

        std::fs::create_dir_all(&extra).unwrap();
        fx.mock("trigger.yaml", "rules: []\n");
        assert!(eventually(|| reloader.watch_dirs().contains(&extra)));
        std::fs::write(
            extra.join("x.yaml"),
            "host: x.com\nrules:\n  - respond: {}\n",
        )
        .unwrap();
        assert!(eventually(|| state.rules().len() == 1));
    }
}
