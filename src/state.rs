use crate::events::{Event, EventLog};
use crate::rules::{RequestInfo, Rule, RuleSet};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError, RwLock};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("rule not found: {0}")]
pub struct UnknownRule(pub String);

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RuntimeInfo {
    pub config_file: PathBuf,
    pub mock_files: Vec<PathBuf>,
    pub warnings: Vec<String>,
    pub last_reload_ms: u64,
    /// Cleared by the next successful reload.
    pub last_reload_error: Option<String>,
}

/// State shared by the proxy, the control API and the config watcher.
///
/// Runtime toggles (from the CLI or the TUI) are kept in memory as overrides
/// on top of the configuration files and survive reloads while the rule
/// exists.
#[derive(Debug)]
pub struct AppState {
    rules: RwLock<Arc<RuleSet>>,
    overrides: RwLock<HashMap<String, bool>>,
    hits: Mutex<HashMap<String, u64>>,
    events: EventLog,
    info: RwLock<RuntimeInfo>,
}

impl AppState {
    pub fn new(rules: RuleSet) -> Self {
        Self {
            rules: RwLock::new(Arc::new(rules)),
            overrides: RwLock::default(),
            hits: Mutex::default(),
            events: EventLog::new(crate::events::DEFAULT_CAPACITY),
            info: RwLock::default(),
        }
    }

    pub fn rules(&self) -> Arc<RuleSet> {
        Arc::clone(&self.rules.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the rules, keeping the overrides that still differ from the
    /// new configuration.
    pub fn replace_rules(&self, rules: RuleSet) {
        let mut overrides = self
            .overrides
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        overrides.retain(|name, enabled| rules.get(name).is_some_and(|r| r.enabled != *enabled));
        *self.rules.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(rules);
    }

    /// Effective state: the runtime override or the configured value.
    pub fn is_enabled(&self, rule: &Rule) -> bool {
        self.override_for(&rule.name).unwrap_or(rule.enabled)
    }

    pub fn override_for(&self, name: &str) -> Option<bool> {
        let overrides = self
            .overrides
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        overrides.get(name).copied()
    }

    pub fn set_enabled(&self, name: &str, enabled: bool) -> Result<(), UnknownRule> {
        // Same lock order as `replace_rules`, so a reload cannot slip in
        // between reading the rule and storing the override.
        let mut overrides = self
            .overrides
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        let rules = self.rules();
        let rule = rules
            .get(name)
            .ok_or_else(|| UnknownRule(name.to_owned()))?;
        if rule.enabled == enabled {
            overrides.remove(name);
        } else {
            overrides.insert(name.to_owned(), enabled);
        }
        Ok(())
    }

    pub fn find_match(&self, req: &RequestInfo<'_>) -> Option<Rule> {
        let rules = self.rules();
        rules.find(req, |rule| self.is_enabled(rule)).cloned()
    }

    pub fn should_intercept(&self, host: &str, port: u16) -> bool {
        let rules = self.rules();
        rules.intercepts(host, port, |rule| self.is_enabled(rule))
    }

    pub fn intercepted_hosts(&self) -> Vec<String> {
        self.rules().hosts(|rule| self.is_enabled(rule))
    }

    pub fn record_hit(&self, name: &str) {
        let mut hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        *hits.entry(name.to_owned()).or_default() += 1;
    }

    pub fn hits(&self, name: &str) -> u64 {
        let hits = self.hits.lock().unwrap_or_else(PoisonError::into_inner);
        hits.get(name).copied().unwrap_or_default()
    }

    pub fn events(&self) -> &EventLog {
        &self.events
    }

    /// Stores a traffic event and writes its summary to the daemon log.
    pub fn record(&self, event: Event) -> u64 {
        tracing::info!(target: "fauxy::traffic", "{}", event.summary());
        self.events.push(event)
    }

    pub fn info(&self) -> RuntimeInfo {
        self.info
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn update_info(&self, update: impl FnOnce(&mut RuntimeInfo)) {
        update(&mut self.info.write().unwrap_or_else(PoisonError::into_inner));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventKind;
    use crate::rules::test_support::rule;
    use http::Request;

    fn state() -> AppState {
        let mut disabled = rule("b", "b.com", None, "b");
        disabled.enabled = false;
        AppState::new(RuleSet::new(vec![rule("a", "a.com", None, "a"), disabled]))
    }

    fn matched(state: &AppState, uri: &str) -> Option<String> {
        let req = Request::get(uri).body(()).unwrap();
        state
            .find_match(&RequestInfo::from_request(&req).unwrap())
            .map(|rule| rule.name)
    }

    #[test]
    fn effective_state_uses_configuration_by_default() {
        let state = state();
        assert_eq!(matched(&state, "https://a.com/"), Some("a".into()));
        assert_eq!(matched(&state, "https://b.com/"), None);
        assert!(state.should_intercept("a.com", 443));
        assert!(!state.should_intercept("b.com", 443));
        assert_eq!(state.intercepted_hosts(), vec!["a.com"]);
    }

    #[test]
    fn overrides_toggle_rules() {
        let state = state();
        state.set_enabled("a", false).unwrap();
        state.set_enabled("b", true).unwrap();
        assert_eq!(state.override_for("a"), Some(false));
        assert_eq!(matched(&state, "https://a.com/"), None);
        assert_eq!(matched(&state, "https://b.com/"), Some("b".into()));
        assert_eq!(state.intercepted_hosts(), vec!["b.com"]);

        state.set_enabled("a", true).unwrap();
        assert_eq!(state.override_for("a"), None);
    }

    #[test]
    fn unknown_rules_are_reported() {
        let err = state().set_enabled("zzz", true).unwrap_err();
        assert_eq!(err, UnknownRule("zzz".into()));
        assert_eq!(err.to_string(), "rule not found: zzz");
    }

    #[test]
    fn reload_keeps_overrides_of_existing_rules() {
        let state = state();
        state.set_enabled("a", false).unwrap();
        state.set_enabled("b", true).unwrap();

        let mut b = rule("b", "b.com", None, "new");
        b.enabled = true;
        state.replace_rules(RuleSet::new(vec![rule("a", "a.com", None, "a"), b]));

        assert_eq!(state.override_for("a"), Some(false));
        assert_eq!(
            state.override_for("b"),
            None,
            "an override equal to the file is dropped"
        );

        state.replace_rules(RuleSet::new(vec![rule("c", "c.com", None, "c")]));
        assert_eq!(state.override_for("a"), None);
        assert_eq!(state.rules().len(), 1);
    }

    #[test]
    fn hits_are_counted_per_rule() {
        let state = state();
        state.record_hit("a");
        state.record_hit("a");
        assert_eq!(state.hits("a"), 2);
        assert_eq!(state.hits("b"), 0);
    }

    #[test]
    fn events_and_info() {
        let state = state();
        let id = state.record(Event::new(EventKind::Mock, "GET", "https://a.com/"));
        assert_eq!(id, 1);
        assert_eq!(state.events().since(0, 10).len(), 1);

        state.update_info(|info| info.last_reload_error = Some("x".into()));
        assert_eq!(state.info().last_reload_error.as_deref(), Some("x"));
    }
}
