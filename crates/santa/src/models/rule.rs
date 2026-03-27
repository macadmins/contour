use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Santa rule type
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RuleType {
    Binary,
    Certificate,
    #[default]
    #[serde(alias = "TEAMID")]
    TeamId,
    #[serde(alias = "SIGNINGID")]
    SigningId,
    #[serde(alias = "CDHASH")]
    Cdhash,
}

impl RuleType {
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleType::Binary => "BINARY",
            RuleType::Certificate => "CERTIFICATE",
            RuleType::TeamId => "TEAMID",
            RuleType::SigningId => "SIGNINGID",
            RuleType::Cdhash => "CDHASH",
        }
    }
}

impl std::fmt::Display for RuleType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Santa rule policy
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Policy {
    Allowlist,
    AllowlistCompiler,
    Blocklist,
    SilentBlocklist,
    Remove,
    /// CEL (Common Expression Language) - dynamic rule evaluation
    #[serde(alias = "cel")]
    Cel,
}

impl Policy {
    pub fn as_str(&self) -> &'static str {
        match self {
            Policy::Allowlist => "ALLOWLIST",
            Policy::AllowlistCompiler => "ALLOWLIST_COMPILER",
            Policy::Blocklist => "BLOCKLIST",
            Policy::SilentBlocklist => "SILENT_BLOCKLIST",
            Policy::Remove => "REMOVE",
            Policy::Cel => "CEL",
        }
    }
}

impl std::fmt::Display for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Rule category for profile separation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum RuleCategory {
    /// Standard Santa software rules
    #[default]
    Software,
    /// CEL (Common Expression Language) rules
    Cel,
    /// FAA (File Access Authorization) rules
    Faa,
}

/// A Santa rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub rule_type: RuleType,
    pub identifier: String,
    pub policy: Policy,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_msg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    /// Rings this rule belongs to (empty = all rings / global)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rings: Vec<String>,

    // === CEL Rule Fields ===
    /// CEL expression for dynamic rule evaluation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cel_expression: Option<String>,

    // === FAA Rule Fields ===
    /// File Access Authorization path pattern
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faa_path: Option<String>,

    /// FAA access type (read, write, execute)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faa_access: Option<String>,

    /// FAA process restrictions
    #[serde(skip_serializing_if = "Option::is_none")]
    pub faa_process: Option<String>,
}

impl Rule {
    /// Create a new rule
    pub fn new(rule_type: RuleType, identifier: impl Into<String>, policy: Policy) -> Self {
        Self {
            rule_type,
            identifier: identifier.into(),
            policy,
            custom_msg: None,
            custom_url: None,
            description: None,
            labels: Vec::new(),
            group: None,
            rings: Vec::new(),
            cel_expression: None,
            faa_path: None,
            faa_access: None,
            faa_process: None,
        }
    }

    /// Create a new CEL rule
    pub fn new_cel(expression: impl Into<String>, policy: Policy) -> Self {
        Self {
            rule_type: RuleType::Binary, // CEL rules use binary type as base
            identifier: "CEL".into(),
            policy,
            custom_msg: None,
            custom_url: None,
            description: None,
            labels: Vec::new(),
            group: None,
            rings: Vec::new(),
            cel_expression: Some(expression.into()),
            faa_path: None,
            faa_access: None,
            faa_process: None,
        }
    }

    /// Create a new FAA rule
    pub fn new_faa(path: impl Into<String>, access: impl Into<String>) -> Self {
        Self {
            rule_type: RuleType::Binary,
            identifier: "FAA".into(),
            policy: Policy::Allowlist,
            custom_msg: None,
            custom_url: None,
            description: None,
            labels: Vec::new(),
            group: None,
            rings: Vec::new(),
            cel_expression: None,
            faa_path: Some(path.into()),
            faa_access: Some(access.into()),
            faa_process: None,
        }
    }

    /// Determine the category of this rule
    pub fn category(&self) -> RuleCategory {
        if self.policy == Policy::Cel || self.cel_expression.is_some() {
            RuleCategory::Cel
        } else if self.faa_path.is_some() {
            RuleCategory::Faa
        } else {
            RuleCategory::Software
        }
    }

    /// Check if this is a CEL rule
    pub fn is_cel(&self) -> bool {
        self.policy == Policy::Cel || self.cel_expression.is_some()
    }

    /// Check if this is an FAA rule
    pub fn is_faa(&self) -> bool {
        self.faa_path.is_some()
    }

    /// Check if this is a standard software rule
    pub fn is_software(&self) -> bool {
        !self.is_cel() && !self.is_faa()
    }

    /// Unique key for deduplication (type + identifier)
    pub fn key(&self) -> String {
        format!("{}:{}", self.rule_type, self.identifier)
    }

    /// Builder: set custom message
    #[must_use]
    pub fn with_custom_msg(mut self, msg: impl Into<String>) -> Self {
        self.custom_msg = Some(msg.into());
        self
    }

    /// Builder: set custom URL
    #[must_use]
    pub fn with_custom_url(mut self, url: impl Into<String>) -> Self {
        self.custom_url = Some(url.into());
        self
    }

    /// Builder: set description
    #[must_use]
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }

    /// Builder: set labels
    #[must_use]
    pub fn with_labels(mut self, labels: Vec<String>) -> Self {
        self.labels = labels;
        self
    }

    /// Builder: set group
    #[must_use]
    pub fn with_group(mut self, group: impl Into<String>) -> Self {
        self.group = Some(group.into());
        self
    }

    /// Builder: set rings
    #[must_use]
    pub fn with_rings(mut self, rings: Vec<String>) -> Self {
        self.rings = rings;
        self
    }

    /// Builder: add a single ring
    #[must_use]
    pub fn with_ring(mut self, ring: impl Into<String>) -> Self {
        self.rings.push(ring.into());
        self
    }

    /// Builder: set CEL expression
    #[must_use]
    pub fn with_cel_expression(mut self, expr: impl Into<String>) -> Self {
        self.cel_expression = Some(expr.into());
        self
    }

    /// Builder: set FAA path
    #[must_use]
    pub fn with_faa_path(mut self, path: impl Into<String>) -> Self {
        self.faa_path = Some(path.into());
        self
    }

    /// Builder: set FAA access type
    #[must_use]
    pub fn with_faa_access(mut self, access: impl Into<String>) -> Self {
        self.faa_access = Some(access.into());
        self
    }

    /// Builder: set FAA process restriction
    #[must_use]
    pub fn with_faa_process(mut self, process: impl Into<String>) -> Self {
        self.faa_process = Some(process.into());
        self
    }

    /// Check if rule is in a specific ring (empty rings = all rings)
    pub fn is_in_ring(&self, ring: &str) -> bool {
        self.rings.is_empty() || self.rings.iter().any(|r| r == ring)
    }

    /// Check if rule is global (applies to all rings)
    pub fn is_global(&self) -> bool {
        self.rings.is_empty()
    }
}

impl PartialEq for Rule {
    fn eq(&self, other: &Self) -> bool {
        self.key() == other.key()
    }
}

impl Eq for Rule {}

impl std::hash::Hash for Rule {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.key().hash(state);
    }
}

/// A collection of Santa rules
#[derive(Debug, Clone, Default)]
pub struct RuleSet {
    rules: Vec<Rule>,
}

impl RuleSet {
    /// Create an empty rule set
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Create a rule set from a vector of rules
    pub fn from_rules(rules: Vec<Rule>) -> Self {
        Self { rules }
    }

    /// Add a rule to the set
    pub fn add(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Get all rules
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Get mutable rules
    pub fn rules_mut(&mut self) -> &mut Vec<Rule> {
        &mut self.rules
    }

    /// Number of rules
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Iterate over rules.
    pub fn iter(&self) -> std::slice::Iter<'_, Rule> {
        self.rules.iter()
    }

    /// Filter rules by type
    pub fn by_type(&self, rule_type: RuleType) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.rule_type == rule_type)
                .cloned()
                .collect(),
        )
    }

    /// Filter rules by policy
    pub fn by_policy(&self, policy: Policy) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.policy == policy)
                .cloned()
                .collect(),
        )
    }

    /// Filter rules by group
    pub fn by_group(&self, group: &str) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.group.as_deref() == Some(group))
                .cloned()
                .collect(),
        )
    }

    /// Filter rules by ring (empty rings = global, included in all)
    pub fn by_ring(&self, ring: &str) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.is_in_ring(ring))
                .cloned()
                .collect(),
        )
    }

    /// Get rules that are global (not assigned to specific rings)
    pub fn global_rules(&self) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.is_global())
                .cloned()
                .collect(),
        )
    }

    /// Filter rules by category (Software, CEL, FAA)
    pub fn by_category(&self, category: RuleCategory) -> RuleSet {
        RuleSet::from_rules(
            self.rules
                .iter()
                .filter(|r| r.category() == category)
                .cloned()
                .collect(),
        )
    }

    /// Get only software rules (not CEL or FAA)
    pub fn software_rules(&self) -> RuleSet {
        self.by_category(RuleCategory::Software)
    }

    /// Get only CEL rules
    pub fn cel_rules(&self) -> RuleSet {
        self.by_category(RuleCategory::Cel)
    }

    /// Get only FAA rules
    pub fn faa_rules(&self) -> RuleSet {
        self.by_category(RuleCategory::Faa)
    }

    /// Get unique groups
    pub fn groups(&self) -> Vec<String> {
        let mut groups: Vec<_> = self.rules.iter().filter_map(|r| r.group.clone()).collect();
        groups.sort();
        groups.dedup();
        groups
    }

    /// Sort rules by category (Software → CEL → FAA), then by rule_type, then by identifier
    pub fn sort(&mut self) {
        self.rules.sort_by(|a, b| {
            let cat_ord = |r: &Rule| match r.category() {
                RuleCategory::Software => 0,
                RuleCategory::Cel => 1,
                RuleCategory::Faa => 2,
            };
            cat_ord(a)
                .cmp(&cat_ord(b))
                .then_with(|| a.rule_type.as_str().cmp(b.rule_type.as_str()))
                .then_with(|| a.identifier.cmp(&b.identifier))
        });
    }

    /// Deduplicate rules by key, keeping the last occurrence
    pub fn deduplicate(&mut self) {
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut indices_to_keep = Vec::new();

        for (i, rule) in self.rules.iter().enumerate() {
            seen.insert(rule.key(), i);
        }

        for &i in seen.values() {
            indices_to_keep.push(i);
        }
        indices_to_keep.sort_unstable();

        self.rules = indices_to_keep
            .into_iter()
            .map(|i| self.rules[i].clone())
            .collect();
    }

    /// Consume and return the inner rules
    pub fn into_rules(self) -> Vec<Rule> {
        self.rules
    }
}

impl IntoIterator for RuleSet {
    type Item = Rule;
    type IntoIter = std::vec::IntoIter<Rule>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.into_iter()
    }
}

impl<'a> IntoIterator for &'a RuleSet {
    type Item = &'a Rule;
    type IntoIter = std::slice::Iter<'a, Rule>;

    fn into_iter(self) -> Self::IntoIter {
        self.rules.iter()
    }
}

impl Extend<Rule> for RuleSet {
    fn extend<T: IntoIterator<Item = Rule>>(&mut self, iter: T) {
        self.rules.extend(iter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_key() {
        let rule = Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist);
        assert_eq!(rule.key(), "TEAMID:EQHXZ8M8AV");
    }

    #[test]
    fn test_rule_key_uniqueness() {
        let rule1 = Rule::new(RuleType::TeamId, "ABC", Policy::Allowlist);
        let rule2 = Rule::new(RuleType::Binary, "ABC", Policy::Allowlist);
        assert_ne!(rule1.key(), rule2.key());
    }

    #[test]
    fn test_ruleset_by_type() {
        let mut set = RuleSet::new();
        set.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));
        set.add(Rule::new(RuleType::Binary, "B", Policy::Allowlist));
        set.add(Rule::new(RuleType::TeamId, "C", Policy::Allowlist));

        let team_rules = set.by_type(RuleType::TeamId);
        assert_eq!(team_rules.len(), 2);
    }

    #[test]
    fn test_ruleset_deduplicate() {
        let mut set = RuleSet::new();
        set.add(Rule::new(RuleType::TeamId, "A", Policy::Allowlist));
        set.add(Rule::new(RuleType::TeamId, "A", Policy::Blocklist)); // duplicate key
        set.add(Rule::new(RuleType::TeamId, "B", Policy::Allowlist));

        set.deduplicate();
        assert_eq!(set.len(), 2);

        // Should keep the last occurrence (Blocklist)
        let rule_a = set.rules().iter().find(|r| r.identifier == "A").unwrap();
        assert_eq!(rule_a.policy, Policy::Blocklist);
    }

    #[test]
    fn test_rule_builder() {
        let rule = Rule::new(RuleType::TeamId, "EQHXZ8M8AV", Policy::Allowlist)
            .with_description("Google LLC")
            .with_group("vendors");

        assert_eq!(rule.description, Some("Google LLC".to_string()));
        assert_eq!(rule.group, Some("vendors".to_string()));
    }
}
