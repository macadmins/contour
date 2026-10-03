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
    /// Every variant, so the schema test below stays exhaustive.
    #[cfg(test)]
    const ALL: [OsqueryTable; 9] = [
        OsqueryTable::ManagedPolicies,
        OsqueryTable::SharingPreferences,
        OsqueryTable::LaunchdOverrides,
        OsqueryTable::Plist,
        OsqueryTable::DiskEncryption,
        OsqueryTable::SipConfig,
        OsqueryTable::Gatekeeper,
        OsqueryTable::Alf,
        OsqueryTable::Nvram,
    ];

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The bridge names its tables by hand. Each one must be a table the
    /// embedded osquery schema knows, or the Tier-1 query it emits returns
    /// nothing and Fleet reads "no rows" as compliant.
    #[test]
    fn every_bridge_table_exists_in_the_osquery_schema() {
        let known: std::collections::BTreeSet<String> =
            osquery_schema::osquery::read(osquery_schema::embedded())
                .expect("embedded schema")
                .into_iter()
                .map(|e| e.table_name)
                .collect();
        for t in OsqueryTable::ALL {
            assert!(known.contains(t.name()), "`{}` is not an osquery table", t.name());
        }
    }
}
