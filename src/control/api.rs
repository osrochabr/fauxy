use crate::events::Event;
use crate::state::AppState;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusInfo {
    pub version: String,
    pub pid: u32,
    pub listen: String,
    pub started_at_ms: u64,
    pub config_file: String,
    pub mock_files: Vec<String>,
    pub rules_total: usize,
    pub rules_enabled: usize,
    /// Hosts whose HTTPS traffic is decrypted.
    pub intercepted_hosts: Vec<String>,
    pub ca_cert: String,
    pub last_reload_ms: u64,
    pub last_reload_error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    pub name: String,
    /// Effective state, including runtime overrides.
    pub enabled: bool,
    /// Whether the state differs from the configuration files.
    pub overridden: bool,
    pub matcher: String,
    pub status: u16,
    pub hits: u64,
    pub source: String,
}

impl RuleInfo {
    pub fn all(state: &AppState) -> Vec<Self> {
        state
            .rules()
            .rules()
            .iter()
            .map(|rule| {
                let enabled = state.is_enabled(rule);
                Self {
                    name: rule.name.clone(),
                    enabled,
                    overridden: enabled != rule.enabled,
                    matcher: rule.matcher.describe(),
                    status: rule.response.status.as_u16(),
                    hits: state.hits(&rule.name),
                    source: rule.source.display().to_string(),
                }
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReloadResult {
    /// Whether the new configuration was applied; on errors the previous
    /// rules stay active.
    pub ok: bool,
    pub rules: usize,
    pub error: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventsPage {
    /// Oldest first.
    pub events: Vec<Event>,
    /// Newest id known by the daemon; lower than the client's last id after a
    /// daemon restart.
    pub last_id: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::RuleSet;
    use crate::rules::test_support::rule;

    #[test]
    fn rule_info_reflects_overrides_and_hits() {
        let mut disabled = rule("b", "b.com", Some("/x"), "");
        disabled.enabled = false;
        let state = AppState::new(RuleSet::new(vec![rule("a", "a.com", None, ""), disabled]));
        state.set_enabled("b", true).unwrap();
        state.record_hit("a");

        let infos = RuleInfo::all(&state);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].name, "a");
        assert!(infos[0].enabled);
        assert!(!infos[0].overridden);
        assert_eq!(infos[0].hits, 1);
        assert_eq!(infos[0].status, 200);
        assert_eq!(infos[0].matcher, "* a.com/**");
        assert!(infos[1].enabled);
        assert!(infos[1].overridden);
        assert_eq!(infos[1].source, "test.yaml");
    }

    #[test]
    fn types_round_trip_as_json() {
        let result = ReloadResult {
            ok: false,
            rules: 3,
            error: Some("x".into()),
            warnings: vec!["w".into()],
        };
        let json = serde_json::to_string(&result).unwrap();
        assert_eq!(serde_json::from_str::<ReloadResult>(&json).unwrap(), result);
    }
}
