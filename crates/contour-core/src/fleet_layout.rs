use std::fmt;

/// Named Fleet GitOps layout versions.
///
/// Add new variants here when Fleet changes its directory conventions.
/// The CLI exposes these as `--layout <name>` values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FleetLayoutVersion {
    /// Fleet v4.82+ (current recommended, March 2026+)
    #[default]
    V4_82,
    /// Legacy layout (pre-v4.82)
    Legacy,
}

impl FleetLayoutVersion {
    /// All known layout versions, newest first.
    pub fn all() -> &'static [Self] {
        &[Self::V4_82, Self::Legacy]
    }

    /// Resolve a layout version from a CLI string.
    ///
    /// Accepts: "v4.82", "v4_82", "current", "latest", "legacy", "v4.81".
    pub fn from_name(name: &str) -> Option<Self> {
        match name.to_lowercase().as_str() {
            "v4.82" | "v4_82" | "current" | "latest" => Some(Self::V4_82),
            "legacy" | "v4.81" | "v4_81" | "pre-v4.82" => Some(Self::Legacy),
            _ => None,
        }
    }

    /// Build the corresponding layout.
    pub fn layout(self) -> FleetLayout {
        match self {
            Self::V4_82 => FleetLayout::v4_82(),
            Self::Legacy => FleetLayout::legacy(),
        }
    }

    /// Human-readable name for help text.
    pub fn display_name(self) -> &'static str {
        match self {
            Self::V4_82 => "v4.82+ (current)",
            Self::Legacy => "legacy (pre-v4.82)",
        }
    }
}

impl fmt::Display for FleetLayoutVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.display_name())
    }
}

/// Centralized Fleet GitOps directory layout conventions.
///
/// All path segments and file names for Fleet GitOps output are defined here.
/// When Fleet changes its conventions, add a new [`FleetLayoutVersion`] variant
/// and a constructor here — all generators pick it up automatically.
#[derive(Debug, Clone)]
pub struct FleetLayout {
    /// Which version this layout represents
    pub version: FleetLayoutVersion,
    /// Top-level directory for platform resources (was "lib", now "platforms")
    pub platforms_dir: &'static str,
    /// Top-level directory for fleet YAML files
    pub fleets_dir: &'static str,
    /// Top-level directory for labels
    pub labels_dir: &'static str,
    /// Filename for unassigned hosts (was "no-team.yml", now "unassigned.yml")
    pub unassigned_filename: &'static str,
    /// Display name for unassigned hosts in YAML
    pub unassigned_name: &'static str,
    /// YAML key for fleet-level settings (was "team_settings", now "settings")
    pub settings_key: &'static str,
    /// Shared agent options file location
    pub agent_options_path: &'static str,
    /// macOS configuration profiles subdirectory
    pub macos_profiles_subdir: &'static str,
    /// macOS scripts subdirectory
    pub macos_scripts_subdir: &'static str,
    /// macOS policies subdirectory
    pub macos_policies_subdir: &'static str,
}

impl FleetLayout {
    /// Fleet v4.82+ layout (current recommended, March 2026+)
    pub fn v4_82() -> Self {
        Self {
            version: FleetLayoutVersion::V4_82,
            platforms_dir: "platforms",
            fleets_dir: "fleets",
            labels_dir: "labels",
            unassigned_filename: "unassigned.yml",
            unassigned_name: "Unassigned",
            settings_key: "settings",
            agent_options_path: "platforms/all/agent-options.yml",
            macos_profiles_subdir: "platforms/macos/configuration-profiles",
            macos_scripts_subdir: "platforms/macos/scripts",
            macos_policies_subdir: "platforms/macos/policies",
        }
    }

    /// Legacy layout (pre-v4.82, for backwards compatibility)
    pub fn legacy() -> Self {
        Self {
            version: FleetLayoutVersion::Legacy,
            platforms_dir: "lib",
            fleets_dir: "fleets",
            labels_dir: "lib/all/labels",
            unassigned_filename: "no-team.yml",
            unassigned_name: "No team",
            settings_key: "team_settings",
            agent_options_path: "lib/agent-options.yml",
            macos_profiles_subdir: "lib/macos/configuration-profiles",
            macos_scripts_subdir: "lib/macos/scripts",
            macos_policies_subdir: "lib/macos/policies",
        }
    }

    /// Build from a named version.
    pub fn from_version(version: FleetLayoutVersion) -> Self {
        version.layout()
    }
}

impl Default for FleetLayout {
    fn default() -> Self {
        Self::v4_82()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_v4_82_layout() {
        let layout = FleetLayout::v4_82();
        assert_eq!(layout.version, FleetLayoutVersion::V4_82);
        assert_eq!(layout.platforms_dir, "platforms");
        assert_eq!(layout.fleets_dir, "fleets");
        assert_eq!(layout.labels_dir, "labels");
        assert_eq!(layout.unassigned_filename, "unassigned.yml");
        assert_eq!(layout.unassigned_name, "Unassigned");
        assert_eq!(layout.settings_key, "settings");
        assert_eq!(layout.agent_options_path, "platforms/all/agent-options.yml");
    }

    #[test]
    fn test_legacy_layout() {
        let layout = FleetLayout::legacy();
        assert_eq!(layout.version, FleetLayoutVersion::Legacy);
        assert_eq!(layout.platforms_dir, "lib");
        assert_eq!(layout.fleets_dir, "fleets");
        assert_eq!(layout.labels_dir, "lib/all/labels");
        assert_eq!(layout.unassigned_filename, "no-team.yml");
        assert_eq!(layout.unassigned_name, "No team");
        assert_eq!(layout.settings_key, "team_settings");
        assert_eq!(layout.agent_options_path, "lib/agent-options.yml");
    }

    #[test]
    fn test_default_is_v4_82() {
        let default = FleetLayout::default();
        assert_eq!(default.version, FleetLayoutVersion::V4_82);
        assert_eq!(default.platforms_dir, "platforms");
    }

    #[test]
    fn test_from_version() {
        let layout = FleetLayout::from_version(FleetLayoutVersion::Legacy);
        assert_eq!(layout.platforms_dir, "lib");
    }

    #[test]
    fn test_version_from_name() {
        assert_eq!(
            FleetLayoutVersion::from_name("v4.82"),
            Some(FleetLayoutVersion::V4_82)
        );
        assert_eq!(
            FleetLayoutVersion::from_name("current"),
            Some(FleetLayoutVersion::V4_82)
        );
        assert_eq!(
            FleetLayoutVersion::from_name("latest"),
            Some(FleetLayoutVersion::V4_82)
        );
        assert_eq!(
            FleetLayoutVersion::from_name("legacy"),
            Some(FleetLayoutVersion::Legacy)
        );
        assert_eq!(
            FleetLayoutVersion::from_name("v4.81"),
            Some(FleetLayoutVersion::Legacy)
        );
        assert_eq!(FleetLayoutVersion::from_name("unknown"), None);
    }

    #[test]
    fn test_version_all_covers_all_variants() {
        let all = FleetLayoutVersion::all();
        assert!(all.contains(&FleetLayoutVersion::V4_82));
        assert!(all.contains(&FleetLayoutVersion::Legacy));
    }

    #[test]
    fn test_version_display() {
        assert_eq!(format!("{}", FleetLayoutVersion::V4_82), "v4.82+ (current)");
        assert_eq!(
            format!("{}", FleetLayoutVersion::Legacy),
            "legacy (pre-v4.82)"
        );
    }
}
