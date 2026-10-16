//! TUI state and key handling, free of I/O.

use crate::control::{EventsPage, RuleInfo, StatusInfo};
use crate::events::Event;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::widgets::TableState;
use std::path::PathBuf;

/// Events kept by the TUI; older ones are dropped.
pub const MAX_EVENTS: usize = 2000;

/// Rows moved by PageUp/PageDown.
const PAGE: isize = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Traffic,
    Rules,
}

/// Side effects requested by a key press.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Quit,
    ToggleRule { name: String, enable: bool },
    Reload,
    Edit(PathBuf),
}

#[derive(Debug)]
pub struct App {
    pub tab: Tab,
    /// Oldest first.
    pub events: Vec<Event>,
    pub last_event_id: u64,
    pub rules: Vec<RuleInfo>,
    /// `None` while the daemon does not answer.
    pub status: Option<StatusInfo>,
    /// Index into [`App::filtered_events`].
    pub traffic_state: TableState,
    pub rules_state: TableState,
    pub show_detail: bool,
    /// Keep the newest event selected.
    pub follow: bool,
    pub filter: String,
    pub editing_filter: bool,
    /// Feedback shown in the footer until the next key press.
    pub message: Option<String>,
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

impl App {
    pub fn new() -> Self {
        Self {
            tab: Tab::Traffic,
            events: Vec::new(),
            last_event_id: 0,
            rules: Vec::new(),
            status: None,
            traffic_state: TableState::default(),
            rules_state: TableState::default(),
            show_detail: false,
            follow: true,
            filter: String::new(),
            editing_filter: false,
            message: None,
        }
    }

    pub fn connected(&self) -> bool {
        self.status.is_some()
    }

    pub fn set_status(&mut self, status: Option<StatusInfo>) {
        self.status = status;
    }

    /// Appends new events; a lower `last_id` means the daemon restarted.
    pub fn push_events(&mut self, page: EventsPage) {
        if page.last_id < self.last_event_id {
            self.events.clear();
            self.last_event_id = 0;
            self.traffic_state.select(None);
        }
        for event in page.events {
            if event.id > self.last_event_id {
                self.last_event_id = event.id;
                self.events.push(event);
            }
        }
        let excess = self.events.len().saturating_sub(MAX_EVENTS);
        self.events.drain(..excess);
        if self.follow {
            self.follow_latest();
        } else {
            self.clamp_selection();
        }
    }

    pub fn set_rules(&mut self, rules: Vec<RuleInfo>) {
        self.rules = rules;
        let last = self.rules.len().checked_sub(1);
        let selected = match self.rules_state.selected() {
            Some(index) => last.map(|last| index.min(last)),
            None => last.map(|_| 0),
        };
        self.rules_state.select(selected);
    }

    /// Events matching the filter (case-insensitive).
    pub fn filtered_events(&self) -> Vec<&Event> {
        let filter = self.filter.to_lowercase();
        self.events
            .iter()
            .filter(|event| filter.is_empty() || event_text(event).contains(&filter))
            .collect()
    }

    pub fn selected_event(&self) -> Option<&Event> {
        let index = self.traffic_state.selected()?;
        self.filtered_events().get(index).copied()
    }

    pub fn selected_rule(&self) -> Option<&RuleInfo> {
        self.rules.get(self.rules_state.selected()?)
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> Option<Action> {
        if self.editing_filter {
            self.edit_filter(key);
            return None;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Some(Action::Quit);
        }
        self.message = None;
        match key.code {
            KeyCode::Char('q') => return Some(Action::Quit),
            KeyCode::Char('r') => return Some(Action::Reload),
            KeyCode::Tab | KeyCode::BackTab => {
                self.tab = match self.tab {
                    Tab::Traffic => Tab::Rules,
                    Tab::Rules => Tab::Traffic,
                };
            }
            KeyCode::Char('1') => self.tab = Tab::Traffic,
            KeyCode::Char('2') => self.tab = Tab::Rules,
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-PAGE),
            KeyCode::PageDown => self.move_selection(PAGE),
            KeyCode::Home | KeyCode::Char('g') => self.select_first(),
            KeyCode::End | KeyCode::Char('G') => self.select_last(),
            code => return self.handle_tab_key(code),
        }
        None
    }

    fn handle_tab_key(&mut self, code: KeyCode) -> Option<Action> {
        match (self.tab, code) {
            (Tab::Traffic, KeyCode::Enter) => self.show_detail = !self.show_detail,
            (Tab::Traffic, KeyCode::Esc) if self.show_detail => self.show_detail = false,
            (Tab::Traffic, KeyCode::Esc) => self.filter.clear(),
            (Tab::Traffic, KeyCode::Char('/')) => self.editing_filter = true,
            (Tab::Traffic, KeyCode::Char('c')) => {
                self.events.clear();
                self.traffic_state.select(None);
            }
            (Tab::Traffic, KeyCode::Char('f')) if self.follow => self.follow = false,
            (Tab::Traffic, KeyCode::Char('f')) => self.follow_latest(),
            (Tab::Rules, KeyCode::Char(' ') | KeyCode::Enter) => {
                let rule = self.selected_rule()?;
                return Some(Action::ToggleRule {
                    name: rule.name.clone(),
                    enable: !rule.enabled,
                });
            }
            (Tab::Rules, KeyCode::Char('e')) => {
                return Some(Action::Edit(PathBuf::from(&self.selected_rule()?.source)));
            }
            _ => {}
        }
        None
    }

    fn edit_filter(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.editing_filter = false;
            }
            KeyCode::Enter => self.editing_filter = false,
            KeyCode::Backspace => {
                self.filter.pop();
            }
            KeyCode::Char(c) => self.filter.push(c),
            _ => {}
        }
        self.follow_latest();
    }

    fn len(&self) -> usize {
        match self.tab {
            Tab::Traffic => self.filtered_events().len(),
            Tab::Rules => self.rules.len(),
        }
    }

    fn state_mut(&mut self) -> &mut TableState {
        match self.tab {
            Tab::Traffic => &mut self.traffic_state,
            Tab::Rules => &mut self.rules_state,
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let Some(last) = self.len().checked_sub(1) else {
            return;
        };
        let current = self.state_mut().selected().unwrap_or(0);
        let next = current.saturating_add_signed(delta).min(last);
        self.state_mut().select(Some(next));
        if self.tab == Tab::Traffic {
            self.follow = next == last;
        }
    }

    fn select_first(&mut self) {
        if self.len() > 0 {
            self.state_mut().select(Some(0));
            self.follow &= self.tab != Tab::Traffic;
        }
    }

    fn select_last(&mut self) {
        match self.tab {
            Tab::Traffic => self.follow_latest(),
            Tab::Rules => self.rules_state.select(self.rules.len().checked_sub(1)),
        }
    }

    /// Selects the newest visible event and keeps following new ones.
    fn follow_latest(&mut self) {
        let len = self.filtered_events().len();
        self.traffic_state.select(len.checked_sub(1));
        self.follow = true;
    }

    fn clamp_selection(&mut self) {
        let last = self.filtered_events().len().checked_sub(1);
        let selected = self.traffic_state.selected();
        self.traffic_state
            .select(selected.and_then(|index| last.map(|last| index.min(last))));
    }
}

fn event_text(event: &Event) -> String {
    let status = event.status.map(|s| s.to_string()).unwrap_or_default();
    let rule = event.rule.as_deref().unwrap_or_default();
    let label = event.kind.label();
    format!("{label} {} {} {status} {rule}", event.method, event.url).to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use ratatui::crossterm::event::KeyEventKind;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new_with_kind(code, KeyModifiers::NONE, KeyEventKind::Press)
    }

    fn event(id: u64, kind: EventKind, url: &str) -> Event {
        let mut event = Event::new(kind, "GET", url);
        event.id = id;
        event
    }

    fn page(ids: std::ops::RangeInclusive<u64>) -> EventsPage {
        let events: Vec<Event> = ids
            .map(|id| event(id, EventKind::Pass, &format!("https://x.com/{id}")))
            .collect();
        let last_id = events.last().map_or(0, |e| e.id);
        EventsPage { events, last_id }
    }

    fn rule(name: &str, enabled: bool) -> RuleInfo {
        RuleInfo {
            name: name.into(),
            enabled,
            overridden: false,
            matcher: "* x.com/**".into(),
            status: 200,
            hits: 0,
            source: format!("/m/{name}.yaml"),
        }
    }

    #[test]
    fn events_are_appended_and_followed() {
        let mut app = App::default();
        app.push_events(page(1..=3));
        assert_eq!(app.events.len(), 3);
        assert_eq!(app.last_event_id, 3);
        assert_eq!(app.traffic_state.selected(), Some(2));

        app.push_events(page(2..=4));
        assert_eq!(app.events.len(), 4, "repeated events are ignored");
        assert_eq!(app.selected_event().unwrap().id, 4);
    }

    #[test]
    fn moving_up_stops_following() {
        let mut app = App::new();
        app.push_events(page(1..=3));
        app.handle_key(key(KeyCode::Up));
        assert!(!app.follow);
        app.push_events(page(4..=4));
        assert_eq!(app.selected_event().unwrap().id, 2);
        app.handle_key(key(KeyCode::Char('j')));
        app.handle_key(key(KeyCode::Char('k')));
        app.handle_key(key(KeyCode::End));
        assert!(app.follow);
        assert_eq!(app.selected_event().unwrap().id, 4);
    }

    #[test]
    fn selection_is_clamped_when_not_following() {
        let mut app = App::new();
        app.push_events(page(1..=3));
        app.handle_key(key(KeyCode::Home));
        assert!(!app.follow);
        app.traffic_state.select(Some(10));
        app.push_events(page(4..=4));
        assert_eq!(app.traffic_state.selected(), Some(3));
        app.events.clear();
        app.push_events(EventsPage {
            events: Vec::new(),
            last_id: 4,
        });
        assert_eq!(app.traffic_state.selected(), None);
    }

    #[test]
    fn daemon_restart_resets_events() {
        let mut app = App::new();
        app.push_events(page(1..=5));
        app.push_events(EventsPage {
            events: Vec::new(),
            last_id: 1,
        });
        assert!(app.events.is_empty());
        assert_eq!(app.last_event_id, 0);
    }

    #[test]
    fn event_buffer_is_bounded() {
        let mut app = App::new();
        let total = u64::try_from(MAX_EVENTS).unwrap() + 10;
        app.push_events(page(1..=total));
        assert_eq!(app.events.len(), MAX_EVENTS);
        assert_eq!(app.events[0].id, 11);
    }

    #[test]
    fn filter_editing() {
        let mut app = App::new();
        let mut mocked = event(1, EventKind::Mock, "https://a.com/login");
        mocked.status = Some(200);
        mocked.rule = Some("login-rule".into());
        app.push_events(EventsPage {
            events: vec![mocked, event(2, EventKind::Pass, "https://b.com/x")],
            last_id: 2,
        });
        app.handle_key(key(KeyCode::Char('/')));
        assert!(app.editing_filter);
        for c in "LOGIN".chars() {
            app.handle_key(key(KeyCode::Char(c)));
        }
        app.handle_key(key(KeyCode::Left));
        app.handle_key(key(KeyCode::Enter));
        assert!(!app.editing_filter);
        assert_eq!(app.filtered_events().len(), 1);
        assert_eq!(app.selected_event().unwrap().id, 1);

        app.handle_key(key(KeyCode::Char('/')));
        app.handle_key(key(KeyCode::Backspace));
        assert_eq!(app.filter, "LOGI");
        app.handle_key(key(KeyCode::Esc));
        assert!(app.filter.is_empty());
        assert_eq!(app.filtered_events().len(), 2);

        for (filter, expected) in [("mock", 1), ("login-rule", 1), ("200", 1), ("pass", 1)] {
            app.filter = filter.into();
            assert_eq!(app.filtered_events().len(), expected, "{filter}");
        }
        app.handle_key(key(KeyCode::Esc));
        assert!(
            app.filter.is_empty(),
            "Esc clears the filter outside the editor"
        );
    }

    #[test]
    fn quit_keys() {
        let mut app = App::new();
        assert_eq!(app.handle_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        let ctrl_c = KeyEvent::new_with_kind(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL,
            KeyEventKind::Press,
        );
        assert_eq!(app.handle_key(ctrl_c), Some(Action::Quit));
    }

    #[test]
    fn tabs_switch() {
        let mut app = App::new();
        app.handle_key(key(KeyCode::Tab));
        assert_eq!(app.tab, Tab::Rules);
        app.handle_key(key(KeyCode::BackTab));
        assert_eq!(app.tab, Tab::Traffic);
        app.handle_key(key(KeyCode::Char('2')));
        assert_eq!(app.tab, Tab::Rules);
        app.handle_key(key(KeyCode::Char('1')));
        assert_eq!(app.tab, Tab::Traffic);
    }

    #[test]
    fn rule_actions() {
        let mut app = App::new();
        app.set_rules(vec![rule("a", true), rule("b", false)]);
        app.handle_key(key(KeyCode::Char('2')));
        assert_eq!(
            app.handle_key(key(KeyCode::Char(' '))),
            Some(Action::ToggleRule {
                name: "a".into(),
                enable: false
            })
        );
        app.handle_key(key(KeyCode::Down));
        assert!(
            app.follow,
            "rule navigation does not change traffic following"
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Enter)),
            Some(Action::ToggleRule {
                name: "b".into(),
                enable: true
            })
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('e'))),
            Some(Action::Edit("/m/b.yaml".into()))
        );
        assert_eq!(
            app.handle_key(key(KeyCode::Char('r'))),
            Some(Action::Reload)
        );
        assert_eq!(app.handle_key(key(KeyCode::Char('x'))), None);
    }

    #[test]
    fn rule_selection_is_kept_in_range() {
        let mut app = App::new();
        app.set_rules(vec![rule("a", true), rule("b", true), rule("c", true)]);
        app.handle_key(key(KeyCode::Char('2')));
        app.handle_key(key(KeyCode::End));
        assert_eq!(app.selected_rule().unwrap().name, "c");
        app.handle_key(key(KeyCode::Home));
        assert_eq!(app.selected_rule().unwrap().name, "a");
        app.handle_key(key(KeyCode::End));
        app.set_rules(vec![rule("a", true)]);
        assert_eq!(app.selected_rule().unwrap().name, "a");
        app.set_rules(Vec::new());
        assert!(app.selected_rule().is_none());
        assert_eq!(app.handle_key(key(KeyCode::Char(' '))), None);
        assert_eq!(app.handle_key(key(KeyCode::Char('e'))), None);
    }

    #[test]
    fn traffic_keys() {
        let mut app = App::new();
        app.push_events(page(1..=30));
        app.handle_key(key(KeyCode::Char('g')));
        assert_eq!(app.traffic_state.selected(), Some(0));
        app.handle_key(key(KeyCode::PageDown));
        assert_eq!(app.traffic_state.selected(), Some(10));
        app.handle_key(key(KeyCode::PageUp));
        app.handle_key(key(KeyCode::PageUp));
        assert_eq!(app.traffic_state.selected(), Some(0));

        app.handle_key(key(KeyCode::Enter));
        assert!(app.show_detail);
        app.handle_key(key(KeyCode::Esc));
        assert!(!app.show_detail);

        app.handle_key(key(KeyCode::Char('f')));
        assert!(app.follow);
        assert_eq!(app.traffic_state.selected(), Some(29));
        app.handle_key(key(KeyCode::Char('f')));
        assert!(!app.follow);
        app.handle_key(key(KeyCode::Char('G')));
        assert!(app.follow);

        app.handle_key(key(KeyCode::Char('c')));
        assert!(app.events.is_empty());
        assert!(app.selected_event().is_none());
    }

    #[test]
    fn movement_on_empty_lists_is_safe() {
        let mut app = App::new();
        for code in [
            KeyCode::Up,
            KeyCode::Down,
            KeyCode::Home,
            KeyCode::End,
            KeyCode::PageDown,
        ] {
            app.handle_key(key(code));
        }
        assert!(app.selected_event().is_none());
        assert!(!app.connected());
    }
}
