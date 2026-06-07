//! The osquery tables the bridge maps mSCP rules onto.

/// An osquery table that can answer some class of mSCP check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsqueryTable {
    ManagedPolicies,
    SharingPreferences,
    LaunchdOverrides,
    Plist,
    DiskEncryption,
    SipConfig,
    Gatekeeper,
    Alf,
    Nvram,
}

impl OsqueryTable {
    /// The osquery table name as used in SQL.
    pub fn name(self) -> &'static str {
        match self {
            OsqueryTable::ManagedPolicies => "managed_policies",
            OsqueryTable::SharingPreferences => "sharing_preferences",
            OsqueryTable::LaunchdOverrides => "launchd_overrides",
            OsqueryTable::Plist => "plist",
            OsqueryTable::DiskEncryption => "disk_encryption",
            OsqueryTable::SipConfig => "sip_config",
            OsqueryTable::Gatekeeper => "gatekeeper",
            OsqueryTable::Alf => "alf",
            OsqueryTable::Nvram => "nvram",
        }
    }
}
