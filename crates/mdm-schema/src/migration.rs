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
    #[allow(dead_code, reason = "reserved for future use")]
    None,
}

impl MigrationStatus {
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn as_str(&self) -> &'static str {
        match self {
            MigrationStatus::Available => "available",
            MigrationStatus::Partial => "partial",
            MigrationStatus::Legacy => "legacy",
            MigrationStatus::None => "none",
        }
    }

    #[allow(dead_code, reason = "reserved for future use")]
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

        // Every name below is checked against the embedded schema by
        // `every_mapping_names_types_and_keys_the_schema_has`: a type or key
        // the schema lacks fails the build. "Direct" means the same key name
        // on both sides; a renamed or moved key is a transformed pair, and
        // the target is the declaration's own dot-path.

        // Account configurations
        mappings.insert(
            "com.apple.caldav.account",
            MigrationMapping {
                mdm_type: "com.apple.caldav.account",
                ddm_type: "com.apple.configuration.account.caldav",
                status: MigrationStatus::Available,
                notes: "CalDAV accounts migrate to DDM; the username and password move to a \
                        credentials asset. CalDAVPrincipalURL is a full URL, \
                        Path only the path on the host",
                direct_keys: &[],
                transformed_keys: &[
                    ("CalDAVAccountDescription", "VisibleName"),
                    ("CalDAVHostName", "HostName"),
                    ("CalDAVPort", "Port"),
                    ("CalDAVPrincipalURL", "Path"),
                    ("CalDAVUsername", "AuthenticationCredentialsAssetReference"),
                    ("CalDAVPassword", "AuthenticationCredentialsAssetReference"),
                ],
                unsupported_keys: &["CalDAVUseSSL", "VPNUUID"],
            },
        );

        mappings.insert(
            "com.apple.carddav.account",
            MigrationMapping {
                mdm_type: "com.apple.carddav.account",
                ddm_type: "com.apple.configuration.account.carddav",
                status: MigrationStatus::Available,
                notes: "CardDAV accounts migrate to DDM; the username and password move to a \
                        credentials asset. CardDAVPrincipalURL is a full URL, \
                        Path only the path on the host",
                direct_keys: &[],
                transformed_keys: &[
                    ("CardDAVAccountDescription", "VisibleName"),
                    ("CardDAVHostName", "HostName"),
                    ("CardDAVPort", "Port"),
                    ("CardDAVPrincipalURL", "Path"),
                    ("CardDAVUsername", "AuthenticationCredentialsAssetReference"),
                    ("CardDAVPassword", "AuthenticationCredentialsAssetReference"),
                ],
                unsupported_keys: &["CardDAVUseSSL", "CommunicationServiceRules", "VPNUUID"],
            },
        );

        mappings.insert(
            "com.apple.mail.managed",
            MigrationMapping {
                mdm_type: "com.apple.mail.managed",
                ddm_type: "com.apple.configuration.account.mail",
                status: MigrationStatus::Available,
                notes: "Mail accounts migrate to DDM: server settings nest under \
                        IncomingServer / OutgoingServer, the user's name and address move to a \
                        user-identity asset, and credentials to credentials assets",
                direct_keys: &[],
                transformed_keys: &[
                    ("EmailAccountDescription", "VisibleName"),
                    ("EmailAccountName", "UserIdentityAssetReference"),
                    ("EmailAddress", "UserIdentityAssetReference"),
                    ("EmailAccountType", "IncomingServer.ServerType"),
                    ("IncomingMailServerHostName", "IncomingServer.HostName"),
                    ("IncomingMailServerPortNumber", "IncomingServer.Port"),
                    (
                        "IncomingMailServerAuthentication",
                        "IncomingServer.AuthenticationMethod",
                    ),
                    (
                        "IncomingMailServerIMAPPathPrefix",
                        "IncomingServer.IMAPPathPrefix",
                    ),
                    (
                        "IncomingMailServerUsername",
                        "IncomingServer.AuthenticationCredentialsAssetReference",
                    ),
                    (
                        "IncomingPassword",
                        "IncomingServer.AuthenticationCredentialsAssetReference",
                    ),
                    ("OutgoingMailServerHostName", "OutgoingServer.HostName"),
                    ("OutgoingMailServerPortNumber", "OutgoingServer.Port"),
                    (
                        "OutgoingMailServerAuthentication",
                        "OutgoingServer.AuthenticationMethod",
                    ),
                    (
                        "OutgoingMailServerUsername",
                        "OutgoingServer.AuthenticationCredentialsAssetReference",
                    ),
                    (
                        "OutgoingPassword",
                        "OutgoingServer.AuthenticationCredentialsAssetReference",
                    ),
                    ("SMIMESigningEnabled", "SMIME.Signing.Enabled"),
                    ("SMIMEEncryptionEnabled", "SMIME.Encryption.Enabled"),
                    (
                        "SMIMEEnablePerMessageSwitch",
                        "SMIME.Encryption.PerMessageSwitchEnabled",
                    ),
                    // The current names; the two above are deprecated.
                    ("SMIMEEncryptByDefault", "SMIME.Encryption.Enabled"),
                    (
                        "SMIMEEnableEncryptionPerMessageSwitch",
                        "SMIME.Encryption.PerMessageSwitchEnabled",
                    ),
                ],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.eas.account",
            MigrationMapping {
                mdm_type: "com.apple.eas.account",
                ddm_type: "com.apple.configuration.account.exchange",
                status: MigrationStatus::Available,
                notes: "Exchange ActiveSync accounts migrate to DDM; the user's address moves to \
                        a user-identity asset and credentials to a credentials asset",
                direct_keys: &[],
                transformed_keys: &[
                    ("Host", "HostName"),
                    ("EmailAddress", "UserIdentityAssetReference"),
                    ("UserName", "AuthenticationCredentialsAssetReference"),
                    ("Password", "AuthenticationCredentialsAssetReference"),
                    ("OAuth", "OAuth.Enabled"),
                    ("SMIMESigningEnabled", "SMIME.Signing.Enabled"),
                    ("SMIMEEncryptionEnabled", "SMIME.Encryption.Enabled"),
                    (
                        "SMIMEEnablePerMessageSwitch",
                        "SMIME.Encryption.PerMessageSwitchEnabled",
                    ),
                    // The current names; the two above are deprecated.
                    ("SMIMEEncryptByDefault", "SMIME.Encryption.Enabled"),
                    (
                        "SMIMEEnableEncryptionPerMessageSwitch",
                        "SMIME.Encryption.PerMessageSwitchEnabled",
                    ),
                    ("EnableMail", "MailServiceActive"),
                    ("EnableContacts", "ContactsServiceActive"),
                    ("EnableCalendars", "CalendarServiceActive"),
                    ("EnableReminders", "RemindersServiceActive"),
                    ("EnableNotes", "NotesServiceActive"),
                ],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.subscribedcalendar.account",
            MigrationMapping {
                mdm_type: "com.apple.subscribedcalendar.account",
                ddm_type: "com.apple.configuration.account.subscribed-calendar",
                status: MigrationStatus::Available,
                notes: "Subscribed calendars migrate to DDM; the username and password move to a \
                        credentials asset",
                direct_keys: &[],
                transformed_keys: &[
                    ("SubCalAccountDescription", "VisibleName"),
                    ("SubCalAccountHostName", "CalendarURL"),
                    (
                        "SubCalAccountUsername",
                        "AuthenticationCredentialsAssetReference",
                    ),
                    (
                        "SubCalAccountPassword",
                        "AuthenticationCredentialsAssetReference",
                    ),
                ],
                unsupported_keys: &["SubCalAccountUseSSL", "VPNUUID"],
            },
        );

        mappings.insert(
            "com.apple.ldap.account",
            MigrationMapping {
                mdm_type: "com.apple.ldap.account",
                ddm_type: "com.apple.configuration.account.ldap",
                status: MigrationStatus::Available,
                notes: "LDAP accounts migrate to DDM; the username and password move to a \
                        credentials asset",
                direct_keys: &[],
                transformed_keys: &[
                    ("LDAPAccountDescription", "VisibleName"),
                    ("LDAPAccountHostName", "HostName"),
                    (
                        "LDAPAccountUserName",
                        "AuthenticationCredentialsAssetReference",
                    ),
                    (
                        "LDAPAccountPassword",
                        "AuthenticationCredentialsAssetReference",
                    ),
                    ("LDAPSearchSettings", "SearchSettings"),
                ],
                unsupported_keys: &["LDAPAccountUseSSL", "VPNUUID"],
            },
        );

        // Passcode settings
        mappings.insert(
            "com.apple.mobiledevice.passwordpolicy",
            MigrationMapping {
                mdm_type: "com.apple.mobiledevice.passwordpolicy",
                ddm_type: "com.apple.configuration.passcode.settings",
                status: MigrationStatus::Available,
                notes: "Passcode policy migrates to the DDM passcode configuration under new \
                        names. allowSimple = false corresponds to RequireComplexPasscode = true \
                        (the sense is inverted). MaximumGracePeriodInMinutes and \
                        MaximumInactivityInMinutes set the longest period a user may choose, \
                        not a fixed value",
                direct_keys: &[],
                transformed_keys: &[
                    ("forcePIN", "RequirePasscode"),
                    ("requireAlphanumeric", "RequireAlphanumericPasscode"),
                    ("minLength", "MinimumLength"),
                    ("minComplexChars", "MinimumComplexCharacters"),
                    ("maxFailedAttempts", "MaximumFailedAttempts"),
                    (
                        "minutesUntilFailedLoginReset",
                        "FailedAttemptsResetInMinutes",
                    ),
                    ("maxGracePeriod", "MaximumGracePeriodInMinutes"),
                    ("maxInactivity", "MaximumInactivityInMinutes"),
                    ("maxPINAgeInDays", "MaximumPasscodeAgeInDays"),
                    ("pinHistory", "PasscodeReuseLimit"),
                    ("changeAtNextAuth", "ChangeAtNextAuth"),
                    ("customRegex", "CustomRegex"),
                ],
                unsupported_keys: &[],
            },
        );

        // Security credentials. A credential asset carries no settings of
        // its own: `Reference.DataURL` points at a document the MDM serves,
        // and that document holds what the profile payload held.
        mappings.insert(
            "com.apple.security.scep",
            MigrationMapping {
                mdm_type: "com.apple.security.scep",
                ddm_type: "com.apple.asset.credential.scep",
                status: MigrationStatus::Available,
                notes: "SCEP enrollment migrates to a credential asset: the SCEP settings are \
                        served as the document at Reference.DataURL, and a configuration \
                        references the asset",
                direct_keys: &[],
                transformed_keys: &[("PayloadContent", "Reference.DataURL")],
                unsupported_keys: &[],
            },
        );

        mappings.insert(
            "com.apple.security.acme",
            MigrationMapping {
                mdm_type: "com.apple.security.acme",
                ddm_type: "com.apple.asset.credential.acme",
                status: MigrationStatus::Available,
                notes: "ACME enrollment migrates to a credential asset: the ACME settings \
                        (DirectoryURL, ClientIdentifier, key type and size, …) are served as the \
                        document at Reference.DataURL, and a configuration references the asset",
                direct_keys: &[],
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
                notes: "PKCS#12 certificates migrate to a credential asset: the certificate \
                        data is served as the document at Reference.DataURL",
                direct_keys: &[],
                transformed_keys: &[("PayloadContent", "Reference.DataURL")],
                unsupported_keys: &[],
            },
        );

        // Software Update
        mappings.insert(
            "com.apple.SoftwareUpdate",
            MigrationMapping {
                mdm_type: "com.apple.SoftwareUpdate",
                ddm_type: "com.apple.configuration.softwareupdate.settings",
                status: MigrationStatus::Partial,
                notes: "Automatic download and install move under AutomaticActions; other software \
                    update settings have no declaration key or need MDM commands. The keys change shape: a boolean becomes \
                    Allowed / AlwaysOn / AlwaysOff (false → AlwaysOff)",
                direct_keys: &[],
                transformed_keys: &[
                    ("AutomaticDownload", "AutomaticActions.Download"),
                    (
                        "AutomaticallyInstallMacOSUpdates",
                        "AutomaticActions.InstallOSUpdates",
                    ),
                    (
                        "CriticalUpdateInstall",
                        "AutomaticActions.InstallSecurityUpdate",
                    ),
                ],
                unsupported_keys: &["CatalogURL", "AutomaticCheckEnabled"],
            },
        );

        // Screen Time
        mappings.insert(
            "com.apple.applicationaccess",
            MigrationMapping {
                mdm_type: "com.apple.applicationaccess",
                // No single replacement: Apple moved individual restriction
                // keys to several declarations, and says which in each key's
                // own notes. `ddm map` reads those; intelligence.settings is
                // named here because most of the moved keys went to it.
                ddm_type: "com.apple.configuration.intelligence.settings",
                status: MigrationStatus::Partial,
                notes: "No single replacement: Apple moved individual restriction keys to \
                        several declarations (intelligence, external-intelligence, keyboard, \
                        siri, app.settings) — `contour profile ddm map` lists which key went \
                        where. Most restrictions still require the profile",
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
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn all(&self) -> impl Iterator<Item = &MigrationMapping> {
        self.mappings.values()
    }

    /// List mappings filtered by status
    #[allow(dead_code, reason = "reserved for future use")]
    pub fn by_status(&self, status: MigrationStatus) -> Vec<&MigrationMapping> {
        self.mappings
            .values()
            .filter(|m| m.status == status)
            .collect()
    }

    /// Get coverage statistics
    #[allow(dead_code, reason = "reserved for future use")]
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
#[allow(dead_code, reason = "reserved for future use")]
pub struct MigrationStats {
    pub total: usize,
    pub available: usize,
    pub partial: usize,
    pub legacy: usize,
    pub none: usize,
}

impl MigrationStats {
    #[allow(dead_code, reason = "reserved for future use")]
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

    /// The map is hand-kept, so every name in it is checked against the
    /// embedded schema: a mapping to a declaration that does not exist
    /// would send `ddm map`, the deprecation lint and the MCP to a type no
    /// MDM can deliver. Keys are checked too: a direct key the declaration
    /// does not define is a migration that silently drops the setting.
    #[test]
    fn every_mapping_names_types_and_keys_the_schema_has() {
        let caps = crate::capabilities::read(crate::embedded_capabilities()).unwrap();
        let find = |t: &str| caps.iter().find(|c| c.payload_type == t);
        let has_key = |t: &str, key: &str| {
            find(t).is_some_and(|c| {
                c.keys.iter().any(|k| {
                    let path = match k.parent_key.as_deref().filter(|p| !p.is_empty()) {
                        Some(p) => format!("{p}.{}", k.name),
                        None => k.name.clone(),
                    };
                    path == key || k.name == key
                })
            })
        };
        let mut problems = Vec::new();
        for m in MigrationRegistry::new().all() {
            if find(m.mdm_type).is_none() {
                problems.push(format!("{}: not a payload type in the schema", m.mdm_type));
            }
            if find(m.ddm_type).is_none() {
                problems.push(format!(
                    "{} → {}: no such declaration",
                    m.mdm_type, m.ddm_type
                ));
                continue;
            }
            for k in m.direct_keys {
                if !has_key(m.mdm_type, k) {
                    problems.push(format!(
                        "{}: direct key {k} not in the profile payload",
                        m.mdm_type
                    ));
                }
                if !has_key(m.ddm_type, k) {
                    problems.push(format!(
                        "{} → {}: direct key {k} not in the declaration",
                        m.mdm_type, m.ddm_type
                    ));
                }
            }
            for (from, to) in m.transformed_keys {
                if !has_key(m.mdm_type, from) {
                    problems.push(format!(
                        "{}: transformed key {from} not in the profile payload",
                        m.mdm_type
                    ));
                }
                if !has_key(m.ddm_type, to) {
                    problems.push(format!(
                        "{} → {}: transformed target {to} not in the declaration",
                        m.mdm_type, m.ddm_type
                    ));
                }
            }
            for k in m.unsupported_keys {
                if !has_key(m.mdm_type, k) {
                    problems.push(format!(
                        "{}: unsupported key {k} not in the profile payload",
                        m.mdm_type
                    ));
                }
            }
        }
        assert!(
            problems.is_empty(),
            "{} problem(s):\n  {}",
            problems.len(),
            problems.join("\n  ")
        );
    }

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
    fn coverage_gap_lists_legacy_only_types() {
        // `ddm coverage` reports native-DDM coverage and the still-legacy gap.
        let registry = MigrationRegistry::new();
        let stats = registry.stats();
        // ddm_coverage = (available + partial) / total.
        let expected = (stats.available + stats.partial) as f64 / stats.total as f64 * 100.0;
        assert!((stats.ddm_coverage() - expected).abs() < 1e-9);
        // The gap (legacy/none) must include known network types with no DDM.
        let legacy: Vec<&str> = registry
            .by_status(MigrationStatus::Legacy)
            .iter()
            .map(|m| m.mdm_type)
            .collect();
        assert!(legacy.contains(&"com.apple.wifi.managed"));
        assert!(legacy.contains(&"com.apple.vpn.managed"));
    }

    #[test]
    fn key_level_mapping_surfaces_renames_and_drops() {
        // `ddm map` relies on the per-key detail: renamed keys (old → new
        // dotted DDM path) and keys with no DDM equivalent.
        let registry = MigrationRegistry::new();
        let m = registry
            .get("com.apple.mail.managed")
            .expect("mail mapping");
        assert!(
            m.transformed_keys.contains(&(
                "IncomingMailServerUsername",
                "IncomingServer.AuthenticationCredentialsAssetReference",
            )),
            "expected the username → asset-reference restructuring"
        );
        // The password moves to the same credentials asset; the address to
        // the user-identity asset. Neither keeps its name, so neither is
        // "direct" (see every_mapping_names_types_and_keys_the_schema_has).
        assert!(m.transformed_keys.contains(&(
            "IncomingPassword",
            "IncomingServer.AuthenticationCredentialsAssetReference",
        )));
        assert!(
            m.transformed_keys
                .contains(&("EmailAddress", "UserIdentityAssetReference"))
        );
        // A drop: CalDAV's SSL switch has no declaration key.
        let caldav = registry.get("com.apple.caldav.account").unwrap();
        assert!(caldav.unsupported_keys.contains(&"CalDAVUseSSL"));
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
