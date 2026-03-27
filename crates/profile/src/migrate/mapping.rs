//! MDM to DDM migration mapping registry
//!
//! Maps traditional MDM profile payload types to their DDM declaration equivalents.

use serde::Serialize;
use std::collections::HashMap;

/// Migration status for an MDM payload type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum MigrationStatus {
    /// Direct DDM equivalent available
    Available,
    /// Partial support - some keys can be migrated
    Partial,
    /// Can use legacy profile declaration wrapper
    Legacy,
    /// No DDM support currently
    None,
}

impl MigrationStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            MigrationStatus::Available => "available",
            MigrationStatus::Partial => "partial",
            MigrationStatus::Legacy => "legacy",
            MigrationStatus::None => "none",
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            MigrationStatus::Available => "Direct DDM equivalent exists",
            MigrationStatus::Partial => "Some settings can be migrated to DDM",
            MigrationStatus::Legacy => "Use com.apple.configuration.legacy wrapper",
            MigrationStatus::None => "No DDM migration path available",
        }
    }
}

/// A mapping from MDM payload type to DDM declaration
#[derive(Debug, Clone, Serialize)]
pub struct MigrationMapping {
    /// MDM payload type (e.g., "com.apple.caldav.account")
    pub mdm_type: &'static str,
    /// DDM declaration type (e.g., "com.apple.configuration.account.caldav")
    pub ddm_type: &'static str,
    /// Migration status
    pub status: MigrationStatus,
    /// Human-readable notes about the migration
    pub notes: &'static str,
    /// Keys that map directly
    pub direct_keys: &'static [&'static str],
    /// Keys that need transformation
    pub transformed_keys: &'static [(&'static str, &'static str)],
    /// Keys not supported in DDM
    pub unsupported_keys: &'static [&'static str],
}

/// Registry of all known MDM to DDM mappings
#[derive(Debug)]
pub struct MigrationRegistry {
    mappings: HashMap<&'static str, MigrationMapping>,
}

impl MigrationRegistry {
    /// Create a new migration registry with all known mappings
    pub fn new() -> Self {
        let mut mappings = HashMap::new();

        // Account configurations
        mappings.insert(
            "com.apple.caldav.account",
            MigrationMapping {
                mdm_type: "com.apple.caldav.account",
                ddm_type: "com.apple.configuration.account.caldav",
                status: MigrationStatus::Available,
                notes: "CalDAV account settings migrate directly to DDM",
                direct_keys: &[
                    "CalDAVHost",
                    "CalDAVPort",
                    "CalDAVUsername",
                    "CalDAVPrincipalURL",
                    "CalDAVUseSSL",
                ],
                transformed_keys: &[("CalDAVPassword", "AuthenticationCredentialsAssetReference")],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.carddav.account",
            MigrationMapping {
                mdm_type: "com.apple.carddav.account",
                ddm_type: "com.apple.configuration.account.carddav",
                status: MigrationStatus::Available,
                notes: "CardDAV account settings migrate directly to DDM",
                direct_keys: &[
                    "CardDAVHost",
                    "CardDAVPort",
                    "CardDAVUsername",
                    "CardDAVPrincipalURL",
                    "CardDAVUseSSL",
                ],
                transformed_keys: &[("CardDAVPassword", "AuthenticationCredentialsAssetReference")],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.mail.managed",
            MigrationMapping {
                mdm_type: "com.apple.mail.managed",
                ddm_type: "com.apple.configuration.account.mail",
                status: MigrationStatus::Available,
                notes: "Mail account settings migrate to DDM with some key restructuring",
                direct_keys: &[
                    "EmailAccountDescription",
                    "EmailAddress",
                    "IncomingMailServerHostName",
                    "OutgoingMailServerHostName",
                ],
                transformed_keys: &[
                    (
                        "IncomingMailServerUsername",
                        "IncomingServer.AuthenticationCredentialsAssetReference",
                    ),
                    (
                        "OutgoingMailServerUsername",
                        "OutgoingServer.AuthenticationCredentialsAssetReference",
                    ),
                ],
                unsupported_keys: &["IncomingPassword", "OutgoingPassword"],
            },
        );

        mappings.insert(
            "com.apple.eas.account",
            MigrationMapping {
                mdm_type: "com.apple.eas.account",
                ddm_type: "com.apple.configuration.account.exchange",
                status: MigrationStatus::Available,
                notes: "Exchange ActiveSync accounts migrate to DDM",
                direct_keys: &["Host", "UserName", "EmailAddress"],
                transformed_keys: &[("Password", "AuthenticationCredentialsAssetReference")],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.subscribedcalendar.account",
            MigrationMapping {
                mdm_type: "com.apple.subscribedcalendar.account",
                ddm_type: "com.apple.configuration.account.subscribedcalendar",
                status: MigrationStatus::Available,
                notes: "Subscribed calendar accounts migrate to DDM",
                direct_keys: &[
                    "SubCalAccountURL",
                    "SubCalAccountDescription",
                    "SubCalAccountUsername",
                    "SubCalAccountRefreshInterval",
                ],
                transformed_keys: &[(
                    "SubCalAccountPassword",
                    "AuthenticationCredentialsAssetReference",
                )],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.ldap.account",
            MigrationMapping {
                mdm_type: "com.apple.ldap.account",
                ddm_type: "com.apple.configuration.account.ldap",
                status: MigrationStatus::Available,
                notes: "LDAP account settings migrate to DDM",
                direct_keys: &[
                    "LDAPAccountHostName",
                    "LDAPAccountPort",
                    "LDAPAccountUseSSL",
                    "LDAPAccountUserName",
                ],
                transformed_keys: &[(
                    "LDAPAccountPassword",
                    "AuthenticationCredentialsAssetReference",
                )],
                unsupported_keys: &[],
            },
        );

        // Passcode settings
        mappings.insert(
            "com.apple.mobiledevice.passwordpolicy",
            MigrationMapping {
                mdm_type: "com.apple.mobiledevice.passwordpolicy",
                ddm_type: "com.apple.configuration.passcode.settings",
                status: MigrationStatus::Available,
                notes: "Passcode policy settings migrate to DDM passcode configuration",
                direct_keys: &[
                    "requirePasscode",
                    "allowSimple",
                    "minLength",
                    "maxPINAgeInDays",
                    "pinHistory",
                    "maxInactivity",
                    "maxFailedAttempts",
                ],
                transformed_keys: &[("forcePIN", "RequirePasscode")],
                unsupported_keys: &["changeAtNextAuth"],
            },
        );

        // Security credentials
        mappings.insert(
            "com.apple.security.scep",
            MigrationMapping {
                mdm_type: "com.apple.security.scep",
                ddm_type: "com.apple.asset.credential.scep",
                status: MigrationStatus::Available,
                notes: "SCEP certificate enrollment migrates to DDM asset",
                direct_keys: &[
                    "URL",
                    "Name",
                    "Subject",
                    "Challenge",
                    "KeySize",
                    "KeyType",
                    "KeyUsage",
                ],
                transformed_keys: &[],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.security.acme",
            MigrationMapping {
                mdm_type: "com.apple.security.acme",
                ddm_type: "com.apple.asset.credential.acme",
                status: MigrationStatus::Available,
                notes: "ACME certificate enrollment migrates to DDM asset",
                direct_keys: &["DirectoryURL", "ClientIdentifier", "KeySize", "KeyType"],
                transformed_keys: &[],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.security.pkcs12",
            MigrationMapping {
                mdm_type: "com.apple.security.pkcs12",
                ddm_type: "com.apple.asset.credential.certificate",
                status: MigrationStatus::Available,
                notes: "PKCS#12 certificates migrate to DDM credential asset",
                direct_keys: &["PayloadCertificateFileName"],
                transformed_keys: &[("PayloadContent", "DataAssetReference")],
                unsupported_keys: &[],
            },
        );

        // Software Update
        mappings.insert("com.apple.SoftwareUpdate", MigrationMapping {
            mdm_type: "com.apple.SoftwareUpdate",
            ddm_type: "com.apple.configuration.softwareupdate.settings",
            status: MigrationStatus::Partial,
            notes: "Some software update settings available in DDM, others require MDM commands",
            direct_keys: &["AutomaticCheckEnabled", "AutomaticDownload"],
            transformed_keys: &[],
            unsupported_keys: &["CatalogURL", "SUDisallowInstallOnBattery"],
        });

        // Screen Time
        mappings.insert(
            "com.apple.applicationaccess",
            MigrationMapping {
                mdm_type: "com.apple.applicationaccess",
                ddm_type: "com.apple.configuration.screentime",
                status: MigrationStatus::Partial,
                notes: "Some restrictions available via Screen Time DDM, most require profile",
                direct_keys: &[],
                transformed_keys: &[],
                unsupported_keys: &["allowCamera", "allowScreenShot", "allowAirDrop"],
            },
        );

        // Common MDM payloads that use legacy wrapper
        let legacy_types = [
            "com.apple.wifi.managed",
            "com.apple.vpn.managed",
            "com.apple.proxy.http.global",
            "com.apple.MCX",
            "com.apple.MCX.FileVault2",
            "com.apple.security.firewall",
            "com.apple.ManagedClient.preferences",
            "com.apple.dock",
            "com.apple.finder",
            "com.apple.screensaver",
            "com.apple.loginwindow",
            "com.apple.notificationsettings",
            "com.apple.preference.security",
            "com.apple.preference.network",
        ];

        for mdm_type in legacy_types {
            mappings.insert(
                mdm_type,
                MigrationMapping {
                    mdm_type,
                    ddm_type: "com.apple.configuration.legacy",
                    status: MigrationStatus::Legacy,
                    notes: "Use legacy profile declaration wrapper for this payload type",
                    direct_keys: &[],
                    transformed_keys: &[],
                    unsupported_keys: &[],
                },
            );
        }

        Self { mappings }
    }

    /// Get mapping for a specific MDM payload type
    pub fn get(&self, mdm_type: &str) -> Option<&MigrationMapping> {
        self.mappings.get(mdm_type)
    }

    /// List all mappings
    pub fn all(&self) -> impl Iterator<Item = &MigrationMapping> {
        self.mappings.values()
    }

    /// List mappings filtered by status
    pub fn by_status(&self, status: MigrationStatus) -> Vec<&MigrationMapping> {
        self.mappings
            .values()
            .filter(|m| m.status == status)
            .collect()
    }

    /// Get coverage statistics
    pub fn stats(&self) -> MigrationStats {
        let available = self
            .mappings
            .values()
            .filter(|m| m.status == MigrationStatus::Available)
            .count();
        let partial = self
            .mappings
            .values()
            .filter(|m| m.status == MigrationStatus::Partial)
            .count();
        let legacy = self
            .mappings
            .values()
            .filter(|m| m.status == MigrationStatus::Legacy)
            .count();
        let none = self
            .mappings
            .values()
            .filter(|m| m.status == MigrationStatus::None)
            .count();

        MigrationStats {
            total: self.mappings.len(),
            available,
            partial,
            legacy,
            none,
        }
    }

    /// Search mappings by query
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn search(&self, query: &str) -> Vec<&MigrationMapping> {
        let query_lower = query.to_lowercase();
        self.mappings
            .values()
            .filter(|m| {
                m.mdm_type.to_lowercase().contains(&query_lower)
                    || m.ddm_type.to_lowercase().contains(&query_lower)
                    || m.notes.to_lowercase().contains(&query_lower)
            })
            .collect()
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Statistics about migration coverage
#[derive(Debug, Serialize)]
pub struct MigrationStats {
    pub total: usize,
    pub available: usize,
    pub partial: usize,
    pub legacy: usize,
    pub none: usize,
}

impl MigrationStats {
    pub fn available_percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.available as f64 / self.total as f64) * 100.0
        }
    }

    pub fn ddm_coverage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            ((self.available + self.partial) as f64 / self.total as f64) * 100.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = MigrationRegistry::new();
        assert!(!registry.mappings.is_empty());
    }

    #[test]
    fn test_get_caldav_mapping() {
        let registry = MigrationRegistry::new();
        let mapping = registry.get("com.apple.caldav.account");
        assert!(mapping.is_some());
        let mapping = mapping.unwrap();
        assert_eq!(mapping.ddm_type, "com.apple.configuration.account.caldav");
        assert_eq!(mapping.status, MigrationStatus::Available);
    }

    #[test]
    fn test_by_status() {
        let registry = MigrationRegistry::new();
        let available = registry.by_status(MigrationStatus::Available);
        assert!(!available.is_empty());
    }

    #[test]
    fn test_stats() {
        let registry = MigrationRegistry::new();
        let stats = registry.stats();
        assert!(stats.total > 0);
        assert!(stats.available > 0);
        assert!(stats.legacy > 0);
    }

    #[test]
    fn test_search() {
        let registry = MigrationRegistry::new();
        let results = registry.search("mail");
        assert!(!results.is_empty());
    }
}
