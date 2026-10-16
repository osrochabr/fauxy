//! TUI rendering.

use super::app::{App, Tab};
use crate::events::{Event, EventKind};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Cell, Paragraph, Row, Table, Tabs, Wrap};
use std::path::Path;

pub fn draw(frame: &mut Frame<'_>, app: &mut App) {
    let [header, tabs, body, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(3),
        Constraint::Length(1),
    ])
    .areas(frame.area());

    frame.render_widget(Paragraph::new(header_line(app)), header);
    let selected = match app.tab {
        Tab::Traffic => 0,
        Tab::Rules => 1,
    };
    frame.render_widget(
        Tabs::new(["Traffic [1]", "Rules [2]"])
            .select(selected)
            .highlight_style(Style::new().add_modifier(Modifier::BOLD | Modifier::REVERSED)),
        tabs,
    );
    match app.tab {
        Tab::Traffic => draw_traffic(frame, app, body),
        Tab::Rules => draw_rules(frame, app, body),
    }
    frame.render_widget(Paragraph::new(footer_line(app)), footer);
}

/// Single-line text that is safe to show on the terminal, see
/// [`crate::events::printable`].
pub fn clean(text: &str) -> String {
    crate::events::printable(&text.replace('\n', " "))
}

fn header_line(app: &App) -> Line<'static> {
    let Some(status) = &app.status else {
        return Line::from(vec![
            Span::styled(" fauxy ", Style::new().bg(Color::Red).fg(Color::Black)),
            Span::raw(" disconnected: the daemon is not running (fauxy start)"),
        ]);
    };
    let mut spans = vec![
        Span::styled(" fauxy ", Style::new().bg(Color::Green).fg(Color::Black)),
        Span::raw(format!(
            " {}  pid {}  rules {}/{}",
            status.listen, status.pid, status.rules_enabled, status.rules_total
        )),
    ];
    if !status.intercepted_hosts.is_empty() {
        spans.push(Span::raw(format!(
            "  intercepting: {}",
            status.intercepted_hosts.join(", ")
        )));
    }
    if status.last_reload_error.is_some() {
        spans.push(Span::styled(
            "  configuration error (see fauxy logs)",
            Style::new().fg(Color::Red),
        ));
    }
    Line::from(spans)
}

fn footer_line(app: &App) -> Line<'static> {
    if app.editing_filter {
        return Line::from(format!(
            " filter: {}▏ (Enter applies, Esc clears)",
            clean(&app.filter)
        ));
    }
    if let Some(message) = &app.message {
        return Line::styled(
            format!(" {}", clean(message)),
            Style::new().fg(Color::Yellow),
        );
    }
    let hints = match app.tab {
        Tab::Traffic => {
            let follow = if app.follow { "on" } else { "off" };
            let filter = if app.filter.is_empty() {
                String::new()
            } else {
                format!("  [filter: {}]", clean(&app.filter))
            };
            format!(
                " q quit  Tab switch  ↑↓ move  Enter details  / filter  f follow ({follow})  c clear  r reload{filter}"
            )
        }
        Tab::Rules => {
            " q quit  Tab switch  ↑↓ move  Space toggle  e edit file  r reload".to_owned()
        }
    };
    Line::styled(hints, Style::new().fg(Color::DarkGray))
}

fn kind_style(kind: EventKind) -> Style {
    match kind {
        EventKind::Mock => Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
        EventKind::Pass => Style::new().fg(Color::Cyan),
        EventKind::Tunnel => Style::new().fg(Color::DarkGray),
        EventKind::Error => Style::new().fg(Color::Red).add_modifier(Modifier::BOLD),
    }
}

/// Local `HH:MM:SS` of a Unix timestamp in milliseconds.
pub fn format_time(timestamp_ms: u64) -> String {
    i64::try_from(timestamp_ms)
        .ok()
        .and_then(chrono::DateTime::from_timestamp_millis)
        .map(|time| {
            time.with_timezone(&chrono::Local)
                .format("%H:%M:%S")
                .to_string()
        })
        .unwrap_or_default()
}

fn optional<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

fn draw_traffic(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let (table_area, detail_area) = if app.show_detail {
        let [top, bottom] =
            Layout::vertical([Constraint::Percentage(50), Constraint::Percentage(50)]).areas(area);
        (top, Some(bottom))
    } else {
        (area, None)
    };

    let events = app.filtered_events();
    let title = format!(" Traffic ({}) ", events.len());
    let rows: Vec<Row<'static>> = events
        .into_iter()
        .map(|event| {
            Row::new(vec![
                Cell::from(format_time(event.timestamp_ms)),
                Cell::from(event.kind.label()).style(kind_style(event.kind)),
                Cell::from(clean(&event.method)),
                Cell::from(optional(event.status)),
                Cell::from(optional(event.duration_ms)),
                Cell::from(clean(&event.url)),
            ])
        })
        .collect();
    let widths = [
        Constraint::Length(8),
        Constraint::Length(6),
        Constraint::Length(7),
        Constraint::Length(6),
        Constraint::Length(6),
        Constraint::Min(10),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(["Time", "Kind", "Method", "Status", "ms", "URL"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(table, table_area, &mut app.traffic_state);

    if let Some(detail_area) = detail_area {
        let lines = app
            .selected_event()
            .map_or_else(|| vec![Line::from("no event selected")], detail_lines);
        let detail = Paragraph::new(lines)
            .block(Block::bordered().title(" Details "))
            .wrap(Wrap { trim: false });
        frame.render_widget(detail, detail_area);
    }
}

pub fn detail_lines(event: &Event) -> Vec<Line<'static>> {
    let bold = Style::new().add_modifier(Modifier::BOLD);
    let mut lines = vec![Line::from(vec![
        Span::styled(event.kind.label(), kind_style(event.kind)),
        Span::raw(format!(" {} {}", clean(&event.method), clean(&event.url))),
    ])];
    if let Some(status) = event.status {
        lines.push(Line::from(format!("status: {status}")));
    }
    if let Some(rule) = &event.rule {
        lines.push(Line::from(format!("rule: {}", clean(rule))));
    }
    if let Some(error) = &event.error {
        lines.push(Line::styled(
            format!("error: {}", clean(error)),
            Style::new().fg(Color::Red),
        ));
    }
    let sections = [
        ("request headers:", &event.request_headers),
        ("response headers:", &event.response_headers),
    ];
    for (title, pairs) in sections.into_iter().filter(|(_, pairs)| !pairs.is_empty()) {
        lines.push(Line::styled(title, bold));
        for (name, value) in pairs {
            lines.push(Line::from(format!("  {}: {}", clean(name), clean(value))));
        }
    }
    if let Some(body) = &event.response_body {
        lines.push(Line::styled("response body:", bold));
        lines.extend(
            body.lines()
                .map(|line| Line::from(format!("  {}", clean(line)))),
        );
    }
    lines
}

fn draw_rules(frame: &mut Frame<'_>, app: &mut App, area: Rect) {
    let rows: Vec<Row<'static>> = app
        .rules
        .iter()
        .map(|rule| {
            let (state, style) = if rule.enabled {
                (
                    "ON",
                    Style::new().fg(Color::Green).add_modifier(Modifier::BOLD),
                )
            } else {
                ("OFF", Style::new().fg(Color::DarkGray))
            };
            let marker = if rule.overridden { "*" } else { "" };
            let file = Path::new(&rule.source)
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            Row::new(vec![
                Cell::from(format!("{state}{marker}")).style(style),
                Cell::from(clean(&rule.name)),
                Cell::from(clean(&rule.matcher)),
                Cell::from(rule.status.to_string()),
                Cell::from(rule.hits.to_string()),
                Cell::from(clean(&file)),
            ])
        })
        .collect();
    let title = format!(" Rules ({})  * = changed at runtime ", app.rules.len());
    let widths = [
        Constraint::Length(4),
        Constraint::Percentage(20),
        Constraint::Min(20),
        Constraint::Length(6),
        Constraint::Length(5),
        Constraint::Percentage(20),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(["", "Name", "Match", "Status", "Hits", "File"])
                .style(Style::new().add_modifier(Modifier::BOLD)),
        )
        .block(Block::bordered().title(title))
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED));
    frame.render_stateful_widget(table, area, &mut app.rules_state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{EventsPage, RuleInfo, StatusInfo};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    fn render(app: &mut App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 24)).unwrap();
        terminal.draw(|frame| draw(frame, app)).unwrap();
        let buffer = terminal.backend().buffer().clone();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn status() -> StatusInfo {
        StatusInfo {
            version: "0.1.0".into(),
            pid: 42,
            listen: "127.0.0.1:8899".into(),
            started_at_ms: 0,
            config_file: "/c/config.yaml".into(),
            mock_files: Vec::new(),
            rules_total: 2,
            rules_enabled: 1,
            intercepted_hosts: vec!["mail.example.com".into()],
            ca_cert: "/s/ca.pem".into(),
            last_reload_ms: 0,
            last_reload_error: None,
            warnings: Vec::new(),
        }
    }

    fn mock_event() -> Event {
        let mut event = Event::new(EventKind::Mock, "POST", "https://mail.example.com/api");
        event.id = 1;
        event.status = Some(201);
        event.duration_ms = Some(3);
        event.rule = Some("send-mail".into());
        event.request_headers = vec![("accept".into(), "application/json".into())];
        event.response_headers = vec![("content-type".into(), "application/json".into())];
        event.response_body = Some("{}".into());
        event
    }

    #[test]
    fn disconnected_header() {
        let text = render(&mut App::new());
        assert!(text.contains("disconnected: the daemon is not running"));
        assert!(text.contains("Traffic [1]"));
    }

    #[test]
    fn traffic_table_and_detail() {
        let mut app = App::new();
        let mut status = status();
        status.last_reload_error = Some("broken".into());
        app.set_status(Some(status));
        let mut tunnel = Event::new(EventKind::Tunnel, "CONNECT", "other.example.org:443");
        tunnel.id = 2;
        app.push_events(EventsPage {
            events: vec![mock_event(), tunnel],
            last_id: 2,
        });
        app.traffic_state.select(Some(0));
        let text = render(&mut app);
        assert!(text.contains("TUNNEL CONNECT"), "{text}");
        assert!(text.contains("127.0.0.1:8899  pid 42  rules 1/2"));
        assert!(text.contains("intercepting: mail.example.com"));
        assert!(text.contains("configuration error (see fauxy logs)"));
        assert!(text.contains("Traffic (2)"));
        assert!(text.contains("MOCK"));
        assert!(text.contains("https://mail.example.com/api"));
        assert!(text.contains("f follow (on)"));

        app.show_detail = true;
        let text = render(&mut app);
        assert!(text.contains("rule: send-mail"));
        assert!(text.contains("request headers:"));
        assert!(text.contains("content-type: application/json"));
        assert!(text.contains("response body:"));

        app.traffic_state.select(None);
        assert!(render(&mut app).contains("no event selected"));
    }

    #[test]
    fn rules_table() {
        let mut app = App::new();
        app.set_status(Some(status()));
        app.tab = Tab::Rules;
        app.set_rules(vec![
            RuleInfo {
                name: "send-mail".into(),
                enabled: true,
                overridden: false,
                matcher: "POST mail.example.com/messages".into(),
                status: 201,
                hits: 7,
                source: "/c/mocks/mail.yaml".into(),
            },
            RuleInfo {
                name: "off-rule".into(),
                enabled: false,
                overridden: true,
                matcher: "GET x.com/a".into(),
                status: 503,
                hits: 0,
                source: "/c/mocks/x.yaml".into(),
            },
        ]);
        let text = render(&mut app);
        assert!(text.contains("Rules (2)"));
        assert!(text.contains("mail.yaml"));
        assert!(text.contains("OFF*"));
        assert!(text.contains("503"));
        assert!(text.contains("Space toggle"));
    }

    #[test]
    fn footer_shows_filter_follow_state_and_messages() {
        let mut app = App::new();
        app.editing_filter = true;
        app.filter = "login".into();
        assert!(render(&mut app).contains("filter: login▏"));

        app.editing_filter = false;
        app.follow = false;
        let text = render(&mut app);
        assert!(text.contains("f follow (off)"));
        assert!(text.contains("[filter: login]"));

        app.message = Some("configuration reloaded".into());
        assert!(render(&mut app).contains("configuration reloaded"));
    }

    #[test]
    fn error_events_show_error_text() {
        let mut event = Event::new(EventKind::Error, "GET", "http://x");
        event.error = Some("connection refused".into());
        let lines = detail_lines(&event);
        assert!(
            lines
                .iter()
                .any(|l| l.to_string() == "error: connection refused")
        );
        assert_eq!(lines.len(), 2, "no header or body sections");
    }

    #[test]
    fn control_characters_are_neutralized() {
        assert_eq!(
            clean("a\u{1b}[31mb\tc\u{7}\nd"),
            "a\u{fffd}[31mb c\u{fffd} d"
        );
        let mut event = Event::new(EventKind::Pass, "GET", "http://x/\u{1b}]0;pwned\u{7}");
        event.response_headers = vec![("x".into(), "\u{1b}[2J".into())];
        let text: String = detail_lines(&event)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(!text.contains('\u{1b}'), "{text:?}");
    }

    #[test]
    fn time_formatting() {
        assert_eq!(format_time(0).len(), 8);
        assert_eq!(format_time(u64::MAX), "");
    }
}
