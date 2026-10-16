//! Terminal UI (`fauxy ui`): live traffic and rule toggles.

mod app;
mod ui;

pub use app::{Action, App, MAX_EVENTS, Tab};
pub use ui::{clean, detail_lines, draw, format_time};

use crate::control::{ControlClient, MAX_EVENTS_PER_PAGE};
use ratatui::backend::{Backend, ClearType};
use ratatui::crossterm::event::{self, Event as TermEvent, KeyEventKind};
use ratatui::crossterm::terminal::{EnterAlternateScreen, enable_raw_mode};
use ratatui::widgets::Clear;
use ratatui::{Terminal, crossterm};
use std::io;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant};
use tokio::runtime::Handle;

const POLL_INTERVAL: Duration = Duration::from_millis(500);
const INPUT_TIMEOUT: Duration = Duration::from_millis(100);

/// Where key presses come from: the terminal, or a script in tests.
pub trait EventSource {
    fn next(&mut self, timeout: Duration) -> io::Result<Option<TermEvent>>;
}

struct TerminalEvents;

impl EventSource for TerminalEvents {
    fn next(&mut self, timeout: Duration) -> io::Result<Option<TermEvent>> {
        event::poll(timeout)?.then(event::read).transpose()
    }
}

/// Runs the TUI until the user quits. Must be called outside async code.
pub fn run(runtime: &Handle, client: &ControlClient) -> anyhow::Result<()> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(
        &mut terminal,
        &mut TerminalEvents,
        runtime,
        client,
        &mut edit_suspended,
    );
    ratatui::restore();
    result
}

/// Leaves the alternate screen while the editor runs.
fn edit_suspended(path: &Path) -> io::Result<()> {
    ratatui::restore();
    let editor = editor_command(
        std::env::var("VISUAL").ok().as_deref(),
        std::env::var("EDITOR").ok().as_deref(),
    );
    let result = open_editor(path, &editor);
    enable_raw_mode()?;
    crossterm::execute!(io::stdout(), EnterAlternateScreen)?;
    result
}

pub fn event_loop<B: Backend>(
    terminal: &mut Terminal<B>,
    events: &mut dyn EventSource,
    runtime: &Handle,
    client: &ControlClient,
    edit: &mut dyn FnMut(&Path) -> io::Result<()>,
) -> anyhow::Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let mut app = App::new();
    let mut last_poll: Option<Instant> = None;
    loop {
        if last_poll.is_none_or(|at| at.elapsed() >= POLL_INTERVAL) {
            refresh(&mut app, runtime, client);
            last_poll = Some(Instant::now());
        }
        terminal.draw(|frame| draw(frame, &mut app))?;

        let Some(TermEvent::Key(key)) = events.next(INPUT_TIMEOUT)? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        match app.handle_key(key) {
            None => {}
            Some(Action::Quit) => return Ok(()),
            Some(Action::Reload) => {
                app.message = Some(reload_message(runtime.block_on(client.reload())));
                last_poll = None;
            }
            Some(Action::ToggleRule { name, enable }) => {
                app.message = Some(
                    match runtime.block_on(client.set_rule_enabled(&name, enable)) {
                        Ok(rules) => {
                            app.set_rules(rules);
                            let state = if enable { "enabled" } else { "disabled" };
                            format!("rule '{name}' {state}")
                        }
                        Err(err) => err.to_string(),
                    },
                );
            }
            Some(Action::Edit(path)) => {
                let result = edit(&path);
                repaint(terminal)?;
                app.message = Some(match result {
                    Ok(()) => "editor closed; saved changes are reloaded automatically".to_owned(),
                    Err(err) => format!("could not open the editor: {err}"),
                });
            }
        }
    }
}

/// Makes the next draw repaint the whole screen. `Terminal::clear` is avoided
/// because it queries the cursor position, which fails on terminals that do
/// not answer the query.
fn repaint<B: Backend>(terminal: &mut Terminal<B>) -> Result<(), B::Error> {
    terminal.backend_mut().clear_region(ClearType::All)?;
    terminal.draw(|frame| frame.render_widget(Clear, frame.area()))?;
    Ok(())
}

fn reload_message(
    result: Result<crate::control::ReloadResult, crate::control::ClientError>,
) -> String {
    match result {
        Ok(result) if result.ok => format!("configuration reloaded: {} rule(s)", result.rules),
        Ok(result) => {
            let error = result.error.unwrap_or_default();
            format!(
                "invalid configuration: {}",
                error.lines().next().unwrap_or_default()
            )
        }
        Err(err) => err.to_string(),
    }
}

fn refresh(app: &mut App, runtime: &Handle, client: &ControlClient) {
    let Ok(status) = runtime.block_on(client.status()) else {
        app.set_status(None);
        return;
    };
    app.set_status(Some(status));
    if let Ok(page) = runtime.block_on(client.events(app.last_event_id, MAX_EVENTS_PER_PAGE)) {
        app.push_events(page);
    }
    if let Ok(rules) = runtime.block_on(client.rules()) {
        app.set_rules(rules);
    }
}

/// Editor from `VISUAL` or `EDITOR` (default `vi`), split on whitespace.
pub fn editor_command(visual: Option<&str>, editor: Option<&str>) -> Vec<String> {
    let raw = [visual, editor]
        .into_iter()
        .flatten()
        .find(|value| !value.trim().is_empty())
        .unwrap_or("vi");
    raw.split_whitespace().map(str::to_owned).collect()
}

/// Runs the editor directly (no shell) with the file as its last argument.
pub fn open_editor(path: &Path, command: &[String]) -> io::Result<()> {
    let (program, args) = command
        .split_first()
        .ok_or_else(|| io::Error::other("no editor configured"))?;
    let status = Command::new(program).args(args).arg(path).status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("the editor exited with {status}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::server::tests::context;
    use crate::control::{ControlServer, ReloadResult};
    use ratatui::backend::TestBackend;
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// Replays events; quits when the script ends.
    struct Script(VecDeque<Option<TermEvent>>);

    impl EventSource for Script {
        fn next(&mut self, _timeout: Duration) -> io::Result<Option<TermEvent>> {
            Ok(self
                .0
                .pop_front()
                .unwrap_or_else(|| Some(press(KeyCode::Char('q')))))
        }
    }

    fn press(code: KeyCode) -> TermEvent {
        TermEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn release(code: KeyCode) -> TermEvent {
        let mut key = KeyEvent::new(code, KeyModifiers::NONE);
        key.kind = KeyEventKind::Release;
        TermEvent::Key(key)
    }

    struct Harness {
        runtime: tokio::runtime::Runtime,
        _dir: tempfile::TempDir,
        client: ControlClient,
        ctx: crate::control::ControlContext,
    }

    impl Harness {
        fn new(reload_ok: bool) -> Self {
            let runtime = tokio::runtime::Runtime::new().unwrap();
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("c.sock");
            let mut ctx = context();
            ctx.reload = Arc::new(move || ReloadResult {
                ok: reload_ok,
                rules: 2,
                error: (!reload_ok).then(|| "bad.yaml: line 1\nmore".to_owned()),
                warnings: Vec::new(),
            });
            let server_ctx = ctx.clone();
            runtime
                .block_on(async { ControlServer::bind(&socket, server_ctx) })
                .unwrap();
            Self {
                runtime,
                _dir: dir,
                client: ControlClient::new(socket),
                ctx,
            }
        }

        /// Runs the loop and returns the last screen.
        fn run(
            &self,
            script: Vec<Option<TermEvent>>,
            edit: &mut dyn FnMut(&Path) -> io::Result<()>,
        ) -> String {
            let mut terminal = Terminal::new(TestBackend::new(140, 20)).unwrap();
            let mut events = Script(script.into());
            event_loop(
                &mut terminal,
                &mut events,
                self.runtime.handle(),
                &self.client,
                edit,
            )
            .unwrap();
            format!("{:?}", terminal.backend().buffer())
        }
    }

    fn no_edit(_: &Path) -> io::Result<()> {
        Ok(())
    }

    #[test]
    fn shows_traffic_and_quits() {
        let harness = Harness::new(true);
        harness.ctx.state.record(crate::events::Event::new(
            crate::events::EventKind::Pass,
            "GET",
            "http://a.com/x",
        ));
        let screen = harness.run(
            vec![
                None,
                Some(TermEvent::FocusGained),
                Some(release(KeyCode::Char('q'))),
            ],
            &mut no_edit,
        );
        assert!(screen.contains("http://a.com/x"), "{screen}");
        assert!(screen.contains("pid 1"));
        assert!(no_edit(Path::new("unused")).is_ok());
    }

    #[test]
    fn reload_reports_success_and_failure() {
        let ok = Harness::new(true);
        let screen = ok.run(vec![Some(press(KeyCode::Char('r')))], &mut no_edit);
        assert!(
            screen.contains("configuration reloaded: 2 rule(s)"),
            "{screen}"
        );

        let failing = Harness::new(false);
        let screen = failing.run(vec![Some(press(KeyCode::Char('r')))], &mut no_edit);
        assert!(
            screen.contains("invalid configuration: bad.yaml: line 1"),
            "{screen}"
        );
    }

    #[test]
    fn rules_can_be_toggled_and_edited() {
        let harness = Harness::new(true);
        let mut edited = Vec::new();
        let mut edit = |path: &Path| {
            edited.push(path.to_path_buf());
            Ok(())
        };
        let screen = harness.run(
            vec![
                Some(press(KeyCode::Char('2'))),
                Some(press(KeyCode::Char(' '))),
                Some(press(KeyCode::Char('e'))),
            ],
            &mut edit,
        );
        assert!(
            screen.contains("editor closed; saved changes are reloaded automatically"),
            "{screen}"
        );
        assert_eq!(edited, vec![Path::new("test.yaml").to_path_buf()]);
        assert_eq!(harness.ctx.state.override_for("a#1"), Some(false));

        let screen = harness.run(
            vec![
                Some(press(KeyCode::Char('2'))),
                Some(press(KeyCode::Char(' '))),
            ],
            &mut no_edit,
        );
        assert!(screen.contains("rule 'a#1' enabled"), "{screen}");

        let mut failing = |_: &Path| Err(io::Error::other("no editor"));
        let screen = harness.run(
            vec![
                Some(press(KeyCode::Char('2'))),
                Some(press(KeyCode::Char('e'))),
            ],
            &mut failing,
        );
        assert!(
            screen.contains("could not open the editor: no editor"),
            "{screen}"
        );
    }

    #[test]
    fn works_without_a_daemon() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let client = ControlClient::new(dir.path().join("none.sock"));
        let mut terminal = Terminal::new(TestBackend::new(140, 20)).unwrap();
        let mut script = Script(vec![Some(press(KeyCode::Char('r')))].into());
        event_loop(
            &mut terminal,
            &mut script,
            runtime.handle(),
            &client,
            &mut no_edit,
        )
        .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(
            screen.contains("fauxy is not running (use 'fauxy start')"),
            "{screen}"
        );
        assert!(screen.contains("disconnected"), "{screen}");
    }

    /// Removes every rule from the daemon right before the toggle key.
    struct RemoveRulesThenToggle {
        state: Arc<crate::state::AppState>,
        steps: VecDeque<TermEvent>,
    }

    impl EventSource for RemoveRulesThenToggle {
        fn next(&mut self, _timeout: Duration) -> io::Result<Option<TermEvent>> {
            if self.steps.len() == 1 {
                self.state.replace_rules(crate::rules::RuleSet::default());
            }
            Ok(Some(
                self.steps
                    .pop_front()
                    .unwrap_or_else(|| press(KeyCode::Char('q'))),
            ))
        }
    }

    #[test]
    fn toggle_errors_are_shown() {
        let harness = Harness::new(true);
        let mut terminal = Terminal::new(TestBackend::new(140, 20)).unwrap();
        let mut events = RemoveRulesThenToggle {
            state: Arc::clone(&harness.ctx.state),
            steps: vec![press(KeyCode::Char('2')), press(KeyCode::Char(' '))].into(),
        };
        let runtime = harness.runtime.handle();
        event_loop(
            &mut terminal,
            &mut events,
            runtime,
            &harness.client,
            &mut no_edit,
        )
        .unwrap();
        let screen = format!("{:?}", terminal.backend().buffer());
        assert!(screen.contains("rule not found: a#1"), "{screen}");
    }

    #[test]
    fn reload_messages() {
        let ok = ReloadResult {
            ok: true,
            rules: 3,
            error: None,
            warnings: Vec::new(),
        };
        assert_eq!(reload_message(Ok(ok)), "configuration reloaded: 3 rule(s)");
        let failed = ReloadResult {
            ok: false,
            rules: 3,
            error: None,
            warnings: Vec::new(),
        };
        assert_eq!(reload_message(Ok(failed)), "invalid configuration: ");
        let err = crate::control::ClientError::Transport("x".into());
        assert_eq!(reload_message(Err(err)), "failed to talk to the daemon: x");
    }

    #[test]
    fn editor_selection() {
        assert_eq!(editor_command(None, None), vec!["vi"]);
        assert_eq!(editor_command(None, Some("nano")), vec!["nano"]);
        assert_eq!(
            editor_command(Some("code -w"), Some("nano")),
            vec!["code", "-w"]
        );
        assert_eq!(editor_command(Some("  "), Some("vim")), vec!["vim"]);
    }

    #[test]
    fn editor_results() {
        let file = Path::new("/tmp/x.yaml");
        open_editor(file, &["true".to_owned()]).unwrap();
        let err = open_editor(file, &["false".to_owned()]).unwrap_err();
        assert!(
            err.to_string().starts_with("the editor exited with"),
            "{err}"
        );
        assert_eq!(
            open_editor(file, &[]).unwrap_err().to_string(),
            "no editor configured"
        );
        assert!(open_editor(file, &["/does/not/exist".to_owned()]).is_err());
    }
}
