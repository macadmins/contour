use serde::{Deserialize, Serialize};

/// Profile category within a ring
/// Each ring can have multiple profile types: software, CEL, FAA
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileCategory {
    /// Standard Santa software rules (binary, team ID, signing ID, etc.)
    Software,
    /// CEL (Common Expression Language) rules
    Cel,
    /// FAA (File Access Authorization) rules
    Faa,
}

impl ProfileCategory {
    /// Get the suffix letter for this category
    pub fn suffix(&self) -> &'static str {
        match self {
            ProfileCategory::Software => "a",
            ProfileCategory::Cel => "b",
            ProfileCategory::Faa => "c",
        }
    }

    /// Get human-readable name
    pub fn display_name(&self) -> &'static str {
        match self {
            ProfileCategory::Software => "Software Rules",
            ProfileCategory::Cel => "CEL Rules",
            ProfileCategory::Faa => "File Access Authorization",
        }
    }

    /// All categories in order
    pub fn all() -> &'static [ProfileCategory] {
        &[
            ProfileCategory::Software,
            ProfileCategory::Cel,
            ProfileCategory::Faa,
        ]
    }
}

impl std::fmt::Display for ProfileCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display_name())
    }
}

/// Profile naming scheme for ring-based deployment
/// Example: ring1 + software = "name1a", ring1 + cel = "name1b", etc.
#[derive(Debug, Clone)]
pub struct ProfileNaming {
    /// Base prefix (e.g., "santa" or "name")
    pub prefix: String,
    /// Whether to use ring number (1, 2, 3) or ring name (ring0, ring1)
    pub use_ring_number: bool,
}

impl Default for ProfileNaming {
    fn default() -> Self {
        Self {
            prefix: "santa".to_string(),
            use_ring_number: true,
        }
    }
}

impl ProfileNaming {
    pub fn new(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
            use_ring_number: true,
        }
    }

    /// Generate profile name for a ring and category
    /// Example: ring_priority=1, category=Software -> "santa1a"
    pub fn generate(&self, ring_priority: u8, category: ProfileCategory) -> String {
        format!(
            "{}{}{}",
            self.prefix,
            ring_priority + 1, // 1-indexed for user friendliness
            category.suffix()
        )
    }

    /// Generate profile name with split suffix for large rule sets
    /// Example: ring_priority=1, category=Software, part=2 -> "santa1a-002"
    pub fn generate_split(
        &self,
        ring_priority: u8,
        category: ProfileCategory,
        part: usize,
    ) -> String {
        format!(
            "{}{}{}-{:03}",
            self.prefix,
            ring_priority + 1,
            category.suffix(),
            part
        )
    }

    /// Generate full identifier
    /// Example: org=com.example, ring=1, category=Software -> "com.example.santa1a"
    pub fn generate_identifier(
        &self,
        org: &str,
        ring_priority: u8,
        category: ProfileCategory,
    ) -> String {
        format!("{}.{}", org, self.generate(ring_priority, category))
    }

    /// Generate full identifier with split suffix
    /// Example: org=com.example, ring=1, category=Software, part=2 -> "com.example.santa1a-002"
    pub fn generate_identifier_split(
        &self,
        org: &str,
        ring_priority: u8,
        category: ProfileCategory,
        part: usize,
    ) -> String {
        format!(
            "{}.{}",
            org,
            self.generate_split(ring_priority, category, part)
        )
    }
}

/// Ring profile set - all profiles for a single ring
#[derive(Debug, Clone)]
pub struct RingProfileSet {
    pub ring_name: String,
    pub ring_priority: u8,
    pub software_profile: Option<String>,
    pub cel_profile: Option<String>,
    pub faa_profile: Option<String>,
}

impl RingProfileSet {
    pub fn new(ring_name: impl Into<String>, ring_priority: u8, naming: &ProfileNaming) -> Self {
        Self {
            ring_name: ring_name.into(),
            ring_priority,
            software_profile: Some(naming.generate(ring_priority, ProfileCategory::Software)),
            cel_profile: Some(naming.generate(ring_priority, ProfileCategory::Cel)),
            faa_profile: Some(naming.generate(ring_priority, ProfileCategory::Faa)),
        }
    }

    /// Get profile name for a category
    pub fn profile_for(&self, category: ProfileCategory) -> Option<&str> {
        match category {
            ProfileCategory::Software => self.software_profile.as_deref(),
            ProfileCategory::Cel => self.cel_profile.as_deref(),
            ProfileCategory::Faa => self.faa_profile.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_profile_category_suffix() {
        assert_eq!(ProfileCategory::Software.suffix(), "a");
        assert_eq!(ProfileCategory::Cel.suffix(), "b");
        assert_eq!(ProfileCategory::Faa.suffix(), "c");
    }

    #[test]
    fn test_profile_naming() {
        let naming = ProfileNaming::new("santa");

        assert_eq!(naming.generate(0, ProfileCategory::Software), "santa1a");
        assert_eq!(naming.generate(0, ProfileCategory::Cel), "santa1b");
        assert_eq!(naming.generate(0, ProfileCategory::Faa), "santa1c");
        assert_eq!(naming.generate(1, ProfileCategory::Software), "santa2a");
        assert_eq!(naming.generate(4, ProfileCategory::Faa), "santa5c");
    }

    #[test]
    fn test_profile_naming_identifier() {
        let naming = ProfileNaming::new("rules");

        assert_eq!(
            naming.generate_identifier("com.example", 0, ProfileCategory::Software),
            "com.example.rules1a"
        );
        assert_eq!(
            naming.generate_identifier("com.example", 2, ProfileCategory::Cel),
            "com.example.rules3b"
        );
    }

    #[test]
    fn test_ring_profile_set() {
        let naming = ProfileNaming::new("name");
        let set = RingProfileSet::new("ring0", 0, &naming);

        assert_eq!(set.software_profile, Some("name1a".to_string()));
        assert_eq!(set.cel_profile, Some("name1b".to_string()));
        assert_eq!(set.faa_profile, Some("name1c".to_string()));
    }

    #[test]
    fn test_profile_naming_split() {
        let naming = ProfileNaming::new("santa");

        assert_eq!(
            naming.generate_split(0, ProfileCategory::Software, 1),
            "santa1a-001"
        );
        assert_eq!(
            naming.generate_split(0, ProfileCategory::Software, 2),
            "santa1a-002"
        );
        assert_eq!(
            naming.generate_split(2, ProfileCategory::Cel, 15),
            "santa3b-015"
        );
    }

    #[test]
    fn test_profile_naming_split_identifier() {
        let naming = ProfileNaming::new("rules");

        assert_eq!(
            naming.generate_identifier_split("com.example", 0, ProfileCategory::Software, 1),
            "com.example.rules1a-001"
        );
        assert_eq!(
            naming.generate_identifier_split("com.example", 1, ProfileCategory::Faa, 3),
            "com.example.rules2c-003"
        );
    }
}
