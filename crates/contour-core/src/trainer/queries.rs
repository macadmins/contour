//! Embedded osquery SQL helpers for trainer workflows.
//!
//! These queries can be run in Fleet or any osquery-compatible tool
//! to gather fleet-wide data for Contour workflows.
//!
//! Note: Some tables require extensions (macadmins, Trail of Bits Santa).
//! TCC data requires Fleet's built-in tcc_access table or ATC configuration.

/// Santa-related osquery queries.
pub mod santa {
    /// Discover applications installed across the fleet.
    ///
    /// This query returns signed applications with their code signing information,
    /// suitable for building Santa allowlists.
    ///
    /// Note: The signature table requires Full Disk Access.
    pub const DISCOVER_APPS: &str = r"
SELECT DISTINCT
    a.name AS app_name,
    a.bundle_short_version AS version,
    a.bundle_identifier,
    s.team_identifier,
    s.team_identifier || ':' || a.bundle_identifier AS signing_id,
    s.authority
FROM apps a
JOIN signature s ON s.path = a.path
WHERE s.signed = 1
    AND a.path LIKE '/Applications/%'
ORDER BY a.name;
";

    /// Get apps grouped by TeamID for vendor analysis.
    /// Run in Fleet to aggregate across hosts.
    pub const APP_COVERAGE: &str = r"
SELECT
    s.team_identifier,
    COUNT(DISTINCT a.bundle_identifier) AS app_count,
    GROUP_CONCAT(DISTINCT a.name) AS apps
FROM apps a
JOIN signature s ON s.path = a.path
WHERE s.signed = 1
    AND s.team_identifier != ''
    AND a.path LIKE '/Applications/%'
GROUP BY s.team_identifier
ORDER BY app_count DESC;
";

    /// Find apps from specific TeamIDs (vendor lookup).
    pub const APPS_BY_TEAMID: &str = r"
-- Replace 'EQHXZ8M8AV' with the TeamID you want to look up
SELECT DISTINCT
    a.name AS app_name,
    a.bundle_identifier,
    s.team_identifier,
    a.bundle_short_version AS version
FROM apps a
JOIN signature s ON s.path = a.path
WHERE s.team_identifier = 'EQHXZ8M8AV'
ORDER BY a.name;
";

    /// List Santa rules currently on devices.
    /// Requires Trail of Bits santa extension.
    pub const SANTA_RULES: &str = r"
SELECT
    shasum,
    state,
    type,
    custom_message
FROM santa_rules
ORDER BY type, state;
";
}

/// PPPC/TCC-related osquery queries.
///
/// Note: TCC data requires Fleet's tcc_access table or ATC configuration
/// to read from the TCC.db SQLite database directly.
pub mod pppc {
    /// Discover apps with code signing info for PPPC profiles.
    /// Use this to find apps that may need TCC permissions.
    pub const DISCOVER_APPS: &str = r"
SELECT DISTINCT
    a.name,
    a.bundle_identifier,
    s.team_identifier,
    s.authority,
    a.path
FROM apps a
JOIN signature s ON s.path = a.path
WHERE s.signed = 1
    AND a.path LIKE '/Applications/%'
ORDER BY a.name;
";

    /// Get code requirements for apps (useful for PPPC CodeRequirement field).
    /// Note: Run `codesign -dr - /path/to/app` locally for full requirement.
    pub const APP_SIGNATURES: &str = r"
SELECT
    a.name,
    a.bundle_identifier,
    s.team_identifier,
    s.identifier AS signing_id,
    s.cdhash
FROM apps a
JOIN signature s ON s.path = a.path
WHERE s.signed = 1
    AND a.bundle_identifier IS NOT NULL
ORDER BY a.name;
";
}

/// mSCP-related osquery queries.
pub mod mscp {
    /// Check screensaver and login window settings.
    pub const SECURITY_SETTINGS: &str = r"
SELECT
    domain,
    key,
    subkey,
    value
FROM preferences
WHERE domain IN (
    'com.apple.screensaver',
    'com.apple.loginwindow'
)
ORDER BY domain, key;
";

    /// Get FileVault disk encryption status.
    pub const FILEVAULT_STATUS: &str = r"
SELECT
    name,
    uuid,
    encrypted,
    type,
    encryption_status
FROM disk_encryption;
";

    /// Check Gatekeeper status.
    pub const GATEKEEPER_STATUS: &str = r"
SELECT
    assessments_enabled,
    dev_id_enabled,
    version,
    opaque_version
FROM gatekeeper;
";

    /// Get System Integrity Protection status.
    pub const SIP_STATUS: &str = r"
SELECT
    config_flag,
    enabled,
    enabled_nvram
FROM sip_config
WHERE config_flag = 'sip';
";
}

/// Fleet/MDM-related queries.
/// Note: macos_profiles requires the macadmins osquery extension.
pub mod fleet {
    /// Get installed configuration profiles.
    /// Requires macadmins osquery extension.
    pub const PROFILE_STATUS: &str = r"
SELECT
    identifier,
    display_name,
    install_date,
    organization,
    verification_state
FROM macos_profiles
ORDER BY identifier;
";

    /// List profiles that failed verification.
    pub const PROFILE_ISSUES: &str = r"
SELECT
    display_name,
    identifier,
    install_date,
    verification_state
FROM macos_profiles
WHERE verification_state != 'verified';
";
}
