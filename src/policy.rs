use crate::detect::Kind;
use anyhow::Context;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Pass through without recording.
    Allow,
    /// Pass through but record in the audit log.
    Flag,
    /// Replace the match with a `[REDACTED:<KIND>]` placeholder.
    Redact,
    /// Reject the whole request.
    Block,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub default_action: Action,
    pub actions: HashMap<Kind, Action>,
    pub injection_threshold: f32,
    pub injection_action: Action,
    pub scan_responses: bool,
    pub max_body_bytes: usize,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            default_action: Action::Redact,
            actions: HashMap::from([
                (Kind::IpAddress, Action::Flag),
                (Kind::PrivateKey, Action::Block),
            ]),
            injection_threshold: 0.5,
            injection_action: Action::Block,
            scan_responses: true,
            max_body_bytes: 4 * 1024 * 1024,
        }
    }
}

impl Policy {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading policy {}", path.display()))?;
        let policy: Policy =
            toml::from_str(&raw).with_context(|| format!("parsing policy {}", path.display()))?;
        anyhow::ensure!(
            (0.0..=1.0).contains(&policy.injection_threshold),
            "injection_threshold must be between 0 and 1"
        );
        Ok(policy)
    }

    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        path.map_or_else(|| Ok(Self::default()), Self::from_file)
    }

    pub fn action_for(&self, kind: Kind) -> Action {
        self.actions
            .get(&kind)
            .copied()
            .unwrap_or(self.default_action)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_toml_overrides() {
        let p: Policy = toml::from_str(
            r#"
            default_action = "flag"
            injection_threshold = 0.7
            [actions]
            credit_card = "block"
            "#,
        )
        .unwrap();
        assert_eq!(p.action_for(Kind::CreditCard), Action::Block);
        assert_eq!(p.action_for(Kind::Email), Action::Flag);
        assert_eq!(p.injection_threshold, 0.7);
        assert!(p.scan_responses);
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(toml::from_str::<Policy>("unknown = 1").is_err());
    }
}
