//! Text formatting for CLI output.

use crate::control::{RuleInfo, StatusInfo};
use crate::events::now_ms;

/// Left-aligned columns separated by two spaces.
pub(crate) fn table(header: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = header.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let format_row = |cells: &[&str]| {
        let padded: Vec<String> = cells
            .iter()
            .zip(&widths)
            .map(|(cell, width)| format!("{cell:<width$}"))
            .collect();
        padded.join("  ").trim_end().to_owned() + "\n"
    };
    let mut out = format_row(header);
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        out.push_str(&format_row(&cells));
    }
    out
}

pub(crate) fn rules_table(rules: &[RuleInfo]) -> String {
    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|rule| {
            let state = match (rule.enabled, rule.overridden) {
                (true, false) => "on",
                (false, false) => "off",
                (true, true) => "on*",
                (false, true) => "off*",
            };
            let file = std::path::Path::new(&rule.source)
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            vec![
                state.to_owned(),
                rule.name.clone(),
                rule.matcher.clone(),
                rule.status.to_string(),
                rule.hits.to_string(),
                file,
            ]
        })
        .collect();
    table(&["STATE", "NAME", "MATCH", "STATUS", "HITS", "FILE"], &rows)
}

/// Human-readable time elapsed since `since_ms`.
pub(crate) fn uptime(since_ms: u64, now: u64) -> String {
    let seconds = now.saturating_sub(since_ms) / 1000;
    let (days, rest) = (seconds / 86_400, seconds % 86_400);
    let (hours, rest) = (rest / 3600, rest % 3600);
    let (minutes, seconds) = (rest / 60, rest % 60);
    match (days, hours, minutes) {
        (0, 0, 0) => format!("{seconds}s"),
        (0, 0, _) => format!("{minutes}m {seconds}s"),
        (0, _, _) => format!("{hours}h {minutes}m"),
        _ => format!("{days}d {hours}h"),
    }
}

pub(crate) fn status(status: &StatusInfo) -> String {
    let hosts = if status.intercepted_hosts.is_empty() {
        "none".to_owned()
    } else {
        status.intercepted_hosts.join(", ")
    };
    let mut out = format!(
        "fauxy is running\n  \
         pid:           {}\n  \
         proxy:         {}\n  \
         version:       {}\n  \
         uptime:        {}\n  \
         config:        {}\n  \
         rules:         {} of {} enabled\n  \
         intercepting:  {}\n  \
         CA:            {}\n",
        status.pid,
        status.listen,
        status.version,
        uptime(status.started_at_ms, now_ms()),
        status.config_file,
        status.rules_enabled,
        status.rules_total,
        hosts,
        status.ca_cert,
    );
    for warning in &status.warnings {
        out.push_str(&format!("  warning: {warning}\n"));
    }
    if let Some(error) = &status.last_reload_error {
        out.push_str("  last reload failed (previous rules still in effect):\n");
        for line in error.lines() {
            out.push_str(&format!("    {line}\n"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_aligns_columns() {
        let text = table(
            &["A", "BB"],
            &[
                vec!["xxx".into(), "1".into()],
                vec!["y".into(), "22".into()],
            ],
        );
        assert_eq!(text, "A    BB\nxxx  1\ny    22\n");
    }

    #[test]
    fn table_measures_width_in_characters() {
        let text = table(&["ÇÃO", "X"], &[vec!["ç".into(), "1".into()]]);
        assert_eq!(text, "ÇÃO  X\nç    1\n");
    }

    #[test]
    fn rules_table_marks_overrides() {
        let rule = |enabled, overridden| RuleInfo {
            name: "r".into(),
            enabled,
            overridden,
            matcher: "* x.com/**".into(),
            status: 200,
            hits: 4,
            source: "/a/b/rules.yaml".into(),
        };
        let text = rules_table(&[
            rule(true, false),
            rule(false, false),
            rule(true, true),
            rule(false, true),
        ]);
        let states: Vec<&str> = text.lines().map(|l| l.split(' ').next().unwrap()).collect();
        assert_eq!(states, vec!["STATE", "on", "off", "on*", "off*"]);
        assert!(text.contains("rules.yaml"));
        assert!(!text.contains("/a/b"));
    }

    #[test]
    fn uptime_formats() {
        assert_eq!(uptime(0, 5_000), "5s");
        assert_eq!(uptime(0, 125_000), "2m 5s");
        assert_eq!(uptime(0, 7_260_000), "2h 1m");
        assert_eq!(uptime(0, 90_000_000), "1d 1h");
        assert_eq!(uptime(10, 5), "0s");
    }

    #[test]
    fn status_includes_errors_and_warnings() {
        let mut info = StatusInfo {
            version: "0.1.0".into(),
            pid: 7,
            listen: "127.0.0.1:8899".into(),
            started_at_ms: now_ms(),
            config_file: "/c.yaml".into(),
            mock_files: Vec::new(),
            rules_total: 2,
            rules_enabled: 1,
            intercepted_hosts: Vec::new(),
            ca_cert: "/ca.pem".into(),
            last_reload_ms: 0,
            last_reload_error: Some("line 1\nline 2".into()),
            warnings: vec!["missing source".into()],
        };
        let text = status(&info);
        assert!(text.starts_with("fauxy is running\n"));
        assert!(text.contains("pid:           7\n"));
        assert!(text.contains("1 of 2 enabled"));
        assert!(text.contains("intercepting:  none"));
        assert!(text.contains("warning: missing source"));
        assert!(text.contains("    line 2\n"));

        info.intercepted_hosts = vec!["a.com".into(), "*.b.com".into()];
        assert!(status(&info).contains("intercepting:  a.com, *.b.com"));
    }
}
