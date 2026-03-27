use plist::{Dictionary, Value};
use std::fmt;
use std::str::FromStr;

/// Rule types supported by the `com.apple.servicemanagement` MDM payload.
///
/// macOS 13+ supports these rule types for managing LaunchDaemons,
/// LaunchAgents, and login items via MDM.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BtmRuleType {
    /// Match by developer Team Identifier
    TeamIdentifier,
    /// Match by exact Bundle Identifier
    BundleIdentifier,
    /// Match by Bundle Identifier prefix
    BundleIdentifierPrefix,
    /// Match by exact launchd label
    Label,
    /// Match by launchd label prefix
    LabelPrefix,
}

impl BtmRuleType {
    /// Returns the Apple-specified string value for this rule type.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TeamIdentifier => "TeamIdentifier",
            Self::BundleIdentifier => "BundleIdentifier",
            Self::BundleIdentifierPrefix => "BundleIdentifierPrefix",
            Self::Label => "Label",
            Self::LabelPrefix => "LabelPrefix",
        }
    }

    /// All available rule types.
    pub fn all() -> &'static [BtmRuleType] {
        &[
            Self::TeamIdentifier,
            Self::BundleIdentifier,
            Self::BundleIdentifierPrefix,
            Self::Label,
            Self::LabelPrefix,
        ]
    }
}

/// Error returned when parsing an invalid BTM rule type string.
#[derive(Debug, Clone)]
pub struct ParseBtmRuleTypeError(pub String);

impl fmt::Display for ParseBtmRuleTypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown BTM rule type: '{}'", self.0)
    }
}

impl std::error::Error for ParseBtmRuleTypeError {}

impl FromStr for BtmRuleType {
    type Err = ParseBtmRuleTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TeamIdentifier" => Ok(Self::TeamIdentifier),
            "BundleIdentifier" => Ok(Self::BundleIdentifier),
            "BundleIdentifierPrefix" => Ok(Self::BundleIdentifierPrefix),
            "Label" => Ok(Self::Label),
            "LabelPrefix" => Ok(Self::LabelPrefix),
            _ => Err(ParseBtmRuleTypeError(s.to_string())),
        }
    }
}

impl fmt::Display for BtmRuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Build a service management rule with a specific rule type.
///
/// Creates the dictionary structure expected inside the `Rules` array
/// of a `com.apple.servicemanagement` payload.
pub fn build_btm_rule(rule_type: BtmRuleType, value: &str, comment: &str) -> Dictionary {
    let mut rule = Dictionary::new();
    rule.insert(
        "RuleType".to_string(),
        Value::String(rule_type.as_str().to_string()),
    );
    rule.insert("RuleValue".to_string(), Value::String(value.to_string()));
    rule.insert("Comment".to_string(), Value::String(comment.to_string()));
    rule
}

/// Build a service management rule for a Team ID.
///
/// Convenience wrapper around [`build_btm_rule`] for the common
/// TeamIdentifier rule type.
pub fn build_service_management_rule(team_id: &str, comment: &str) -> Dictionary {
    build_btm_rule(BtmRuleType::TeamIdentifier, team_id, comment)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_service_management_rule() {
        let rule = build_service_management_rule("ZMCG7MLDV9", "com.northpolesec.santa.daemon");
        assert_eq!(
            rule.get("RuleType").unwrap().as_string().unwrap(),
            "TeamIdentifier"
        );
        assert_eq!(
            rule.get("RuleValue").unwrap().as_string().unwrap(),
            "ZMCG7MLDV9"
        );
        assert_eq!(
            rule.get("Comment").unwrap().as_string().unwrap(),
            "com.northpolesec.santa.daemon"
        );
    }

    #[test]
    fn test_build_btm_rule_team_identifier() {
        let rule = build_btm_rule(BtmRuleType::TeamIdentifier, "ABC123", "Test app");
        assert_eq!(
            rule.get("RuleType").unwrap().as_string().unwrap(),
            "TeamIdentifier"
        );
        assert_eq!(
            rule.get("RuleValue").unwrap().as_string().unwrap(),
            "ABC123"
        );
    }

    #[test]
    fn test_build_btm_rule_bundle_identifier() {
        let rule = build_btm_rule(
            BtmRuleType::BundleIdentifier,
            "com.example.daemon",
            "Example daemon",
        );
        assert_eq!(
            rule.get("RuleType").unwrap().as_string().unwrap(),
            "BundleIdentifier"
        );
        assert_eq!(
            rule.get("RuleValue").unwrap().as_string().unwrap(),
            "com.example.daemon"
        );
    }

    #[test]
    fn test_build_btm_rule_bundle_identifier_prefix() {
        let rule = build_btm_rule(
            BtmRuleType::BundleIdentifierPrefix,
            "com.example.",
            "All example apps",
        );
        assert_eq!(
            rule.get("RuleType").unwrap().as_string().unwrap(),
            "BundleIdentifierPrefix"
        );
    }

    #[test]
    fn test_build_btm_rule_label() {
        let rule = build_btm_rule(
            BtmRuleType::Label,
            "com.example.agent",
            "Example launch agent",
        );
        assert_eq!(rule.get("RuleType").unwrap().as_string().unwrap(), "Label");
        assert_eq!(
            rule.get("RuleValue").unwrap().as_string().unwrap(),
            "com.example.agent"
        );
    }

    #[test]
    fn test_build_btm_rule_label_prefix() {
        let rule = build_btm_rule(
            BtmRuleType::LabelPrefix,
            "com.example.",
            "All example labels",
        );
        assert_eq!(
            rule.get("RuleType").unwrap().as_string().unwrap(),
            "LabelPrefix"
        );
    }

    #[test]
    fn test_btm_rule_type_roundtrip() {
        for rt in BtmRuleType::all() {
            let s = rt.as_str();
            let parsed: BtmRuleType = s.parse().unwrap();
            assert_eq!(*rt, parsed);
        }
    }

    #[test]
    fn test_btm_rule_type_from_str_invalid() {
        assert!("Invalid".parse::<BtmRuleType>().is_err());
    }

    #[test]
    fn test_btm_rule_type_display() {
        assert_eq!(BtmRuleType::TeamIdentifier.to_string(), "TeamIdentifier");
        assert_eq!(BtmRuleType::Label.to_string(), "Label");
    }
}
