/// Centralized Fleet GitOps directory layout conventions.
///
/// All path segments and file names for Fleet GitOps output are defined here.
/// There is one layout: the structure `fleetctl new` generates today (Fleet
/// v4.83+). Older layouts (`lib/`, v4.82's mixed declarations) are not served;
/// when Fleet changes its conventions, change this one.
#[derive(Debug, Clone)]
pub struct FleetLayout {
    /// Top-level directory for platform resources
    pub platforms_dir: &'static str,
    /// Top-level directory for fleet YAML files
    pub fleets_dir: &'static str,
    /// Top-level directory for labels
    pub labels_dir: &'static str,
    /// Filename for unassigned hosts
    pub unassigned_filename: &'static str,
    /// Display name for unassigned hosts in YAML
    pub unassigned_name: &'static str,
    /// YAML key for fleet-level settings
    pub settings_key: &'static str,
    /// Shared agent options file location (referenced from fleet YAML)
    pub agent_options_path: &'static str,

    // ── macOS paths ──────────────────────────────────────────
    /// macOS configuration profiles (.mobileconfig)
    pub macos_profiles_subdir: &'static str,
    /// macOS declaration profiles (.json DDM)
    pub macos_declarations_subdir: &'static str,
    /// macOS MDM commands
    pub macos_commands_subdir: &'static str,
    /// macOS enrollment profiles (DEP)
    pub macos_enrollment_subdir: &'static str,
    /// macOS scripts
    pub macos_scripts_subdir: &'static str,
    /// macOS policies
    pub macos_policies_subdir: &'static str,
    /// macOS reports
    pub macos_reports_subdir: &'static str,
    /// macOS software
    pub macos_software_subdir: &'static str,

    // ── iOS paths ────────────────────────────────────────────
    /// iOS configuration profiles
    pub ios_profiles_subdir: &'static str,
    /// iOS declaration profiles
    pub ios_declarations_subdir: &'static str,

    // ── iPadOS paths ─────────────────────────────────────────
    /// iPadOS configuration profiles
    pub ipados_profiles_subdir: &'static str,
    /// iPadOS declaration profiles
    pub ipados_declarations_subdir: &'static str,

    // ── Windows paths ────────────────────────────────────────
    /// Windows configuration profiles (.xml)
    pub windows_profiles_subdir: &'static str,
    /// Windows scripts
    pub windows_scripts_subdir: &'static str,
    /// Windows policies
    pub windows_policies_subdir: &'static str,
    /// Windows reports
    pub windows_reports_subdir: &'static str,
    /// Windows software
    pub windows_software_subdir: &'static str,

    // ── Linux paths ──────────────────────────────────────────
    /// Linux scripts
    pub linux_scripts_subdir: &'static str,
    /// Linux policies
    pub linux_policies_subdir: &'static str,
    /// Linux reports
    pub linux_reports_subdir: &'static str,
    /// Linux software
    pub linux_software_subdir: &'static str,

    // ── Android paths ────────────────────────────────────────
    /// Android configuration profiles
    pub android_profiles_subdir: &'static str,
    /// Android managed app configurations
    pub android_managed_apps_subdir: &'static str,

    // ── Cross-platform paths ─────────────────────────────────
    /// Cross-platform policies
    pub all_policies_subdir: &'static str,
    /// Cross-platform reports
    pub all_reports_subdir: &'static str,
    /// Cross-platform icons
    pub all_icons_subdir: &'static str,
}

impl FleetLayout {
    /// Configuration-profile directory for an Apple OS, by mSCP's directory
    /// token (`macos`, `ios`). Fleet has no visionOS directory: it does not
    /// manage visionOS, so callers refuse it before asking.
    pub fn apple_profiles_subdir(&self, os: &str) -> &'static str {
        match os {
            "ios" => self.ios_profiles_subdir,
            _ => self.macos_profiles_subdir,
        }
    }

    /// Declaration (DDM) directory for an Apple OS — see
    /// [`Self::apple_profiles_subdir`].
    pub fn apple_declarations_subdir(&self, os: &str) -> &'static str {
        match os {
            "ios" => self.ios_declarations_subdir,
            _ => self.macos_declarations_subdir,
        }
    }
}

/// The structure `fleetctl new` generates (Fleet v4.83+).
impl Default for FleetLayout {
    fn default() -> Self {
        Self {
            platforms_dir: "platforms",
            fleets_dir: "fleets",
            labels_dir: "labels",
            unassigned_filename: "unassigned.yml",
            unassigned_name: "Unassigned",
            settings_key: "settings",
            agent_options_path: "platforms/all/agent-options.yml",

            // macOS
            macos_profiles_subdir: "platforms/macos/configuration-profiles",
            macos_declarations_subdir: "platforms/macos/declaration-profiles",
            macos_commands_subdir: "platforms/macos/commands",
            macos_enrollment_subdir: "platforms/macos/enrollment-profiles",
            macos_scripts_subdir: "platforms/macos/scripts",
            macos_policies_subdir: "platforms/macos/policies",
            macos_reports_subdir: "platforms/macos/reports",
            macos_software_subdir: "platforms/macos/software",

            // iOS
            ios_profiles_subdir: "platforms/ios/configuration-profiles",
            ios_declarations_subdir: "platforms/ios/declaration-profiles",

            // iPadOS
            ipados_profiles_subdir: "platforms/ipados/configuration-profiles",
            ipados_declarations_subdir: "platforms/ipados/declaration-profiles",

            // Windows
            windows_profiles_subdir: "platforms/windows/configuration-profiles",
            windows_scripts_subdir: "platforms/windows/scripts",
            windows_policies_subdir: "platforms/windows/policies",
            windows_reports_subdir: "platforms/windows/reports",
            windows_software_subdir: "platforms/windows/software",

            // Linux
            linux_scripts_subdir: "platforms/linux/scripts",
            linux_policies_subdir: "platforms/linux/policies",
            linux_reports_subdir: "platforms/linux/reports",
            linux_software_subdir: "platforms/linux/software",

            // Android
            android_profiles_subdir: "platforms/android/configuration-profiles",
            android_managed_apps_subdir: "platforms/android/managed-app-configurations",

            // Cross-platform
            all_policies_subdir: "platforms/all/policies",
            all_reports_subdir: "platforms/all/reports",
            all_icons_subdir: "platforms/all/icons",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Matches `fleetctl new`: declarations apart from configuration profiles.
    #[test]
    fn the_layout_is_the_fleetctl_new_structure() {
        let layout = FleetLayout::default();
        assert_eq!(layout.platforms_dir, "platforms");
        assert_eq!(layout.fleets_dir, "fleets");
        assert_eq!(layout.labels_dir, "labels");
        assert_eq!(layout.unassigned_filename, "unassigned.yml");
        assert_eq!(layout.settings_key, "settings");
        assert_eq!(
            layout.macos_declarations_subdir,
            "platforms/macos/declaration-profiles"
        );
        assert_eq!(
            layout.apple_declarations_subdir("ios"),
            "platforms/ios/declaration-profiles"
        );
        assert_eq!(
            layout.apple_profiles_subdir("ios"),
            "platforms/ios/configuration-profiles"
        );
        assert_eq!(layout.macos_commands_subdir, "platforms/macos/commands");
        assert_eq!(
            layout.macos_enrollment_subdir,
            "platforms/macos/enrollment-profiles"
        );
    }

    #[test]
    fn test_all_platforms_present() {
        let layout = FleetLayout::default();
        assert!(layout.ios_profiles_subdir.contains("ios"));
        assert!(layout.ipados_profiles_subdir.contains("ipados"));
        assert!(layout.android_profiles_subdir.contains("android"));
        assert!(layout.windows_profiles_subdir.contains("windows"));
        assert!(layout.linux_scripts_subdir.contains("linux"));
    }
}
