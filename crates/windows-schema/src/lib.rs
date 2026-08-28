//! Windows STIG compliance schemas with embedded Parquet data.
//!
//! The Windows counterpart to the mSCP corpus, kept in its own crate by
//! design — Apple and Windows corpora never mix (hard platform
//! separation; `mscp-schema`'s `rules_versioned_is_apple_only` test pins
//! the other side). Four datasets:
//!
//! - `windows_rules` — 258 Windows 11 STIG rules (severity, tags,
//!   check/fix flags); same column layout as mSCP's `rules_versioned`,
//!   read via [`mscp_schema::rules_versioned::read`]
//! - `windows_baseline_edges` — baseline → section → rule membership,
//!   read via [`mscp_schema::baseline_edges::read`]
//! - `stig_registry_checks` — registry-backed checks with a generated
//!   osquery query per row (drop-in Fleet compliance policies)
//! - `fleet_stigs` — Fleet-deployable policies: CSP OMA-URI + SyncML
//!   enforcement fragment + `mdm_bridge` compliance query

pub mod fleet_stigs;
pub mod stig_registry_checks;
pub mod types;

pub use types::*;

/// Embedded Windows STIG rules Parquet data.
///
/// Same column layout as mSCP's `rules_versioned` — read with
/// [`mscp_schema::rules_versioned::read`].
pub fn embedded_windows_rules() -> &'static [u8] {
    include_bytes!("../data/windows_rules.parquet")
}

/// Embedded Windows baseline edges Parquet data.
///
/// Same column layout as mSCP's `baseline_edges` — read with
/// [`mscp_schema::baseline_edges::read`].
pub fn embedded_windows_baseline_edges() -> &'static [u8] {
    include_bytes!("../data/windows_baseline_edges.parquet")
}

/// Embedded Windows STIG registry checks Parquet data.
pub fn embedded_stig_registry_checks() -> &'static [u8] {
    include_bytes!("../data/stig_registry_checks.parquet")
}

/// Embedded Fleet STIG policies Parquet data.
pub fn embedded_fleet_stigs() -> &'static [u8] {
    include_bytes!("../data/fleet_stigs.parquet")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The Windows STIG corpus reads through mSCP's rules reader — the
    /// column layouts are deliberately identical.
    #[test]
    fn windows_rules_read_via_mscp_reader() {
        let rules = mscp_schema::rules_versioned::read(embedded_windows_rules())
            .expect("read windows_rules");
        assert!(
            rules.len() >= 200,
            "expected 200+ Windows STIG rules, got {}",
            rules.len()
        );
        assert!(
            rules.iter().all(|r| r.platform == "Windows"),
            "every rule must be platform Windows (hard platform separation)"
        );
        assert!(
            rules.iter().any(|r| r.rule_id == "V-253260"),
            "expected the BitLocker advanced-startup STIG rule"
        );
    }

    #[test]
    fn windows_baseline_edges_read_via_mscp_reader() {
        let edges = mscp_schema::baseline_edges::read(embedded_windows_baseline_edges())
            .expect("read windows_baseline_edges");
        assert!(
            edges.len() >= 200,
            "expected 200+ edges, got {}",
            edges.len()
        );
    }

    /// Registry checks carry a runnable osquery query per row.
    #[test]
    fn stig_registry_checks_read_with_osquery_sql() {
        let checks = stig_registry_checks::read(embedded_stig_registry_checks())
            .expect("read stig_registry_checks");
        assert!(
            checks.len() >= 100,
            "expected 100+ registry checks, got {}",
            checks.len()
        );

        let bitlocker = checks
            .iter()
            .find(|c| c.rule_id == "V-253260")
            .expect("V-253260 registry check");
        assert_eq!(bitlocker.hive, "HKEY_LOCAL_MACHINE");
        assert_eq!(bitlocker.value_name, "UseAdvancedStartup");
        assert_eq!(bitlocker.value_type, "REG_DWORD");
        assert!(
            bitlocker.osquery_sql.starts_with("SELECT"),
            "osquery_sql must be a runnable query, got: {}",
            bitlocker.osquery_sql
        );
        assert!(bitlocker.osquery_sql.contains("registry"));
    }

    /// Fleet STIG policies pair a SyncML enforcement fragment with an
    /// osquery compliance query.
    #[test]
    fn fleet_stigs_carry_syncml_and_compliance_queries() {
        let stigs = fleet_stigs::read(embedded_fleet_stigs()).expect("read fleet_stigs");
        assert!(
            stigs.len() >= 500,
            "expected 500+ Fleet STIG policies, got {}",
            stigs.len()
        );

        let generated: Vec<_> = stigs
            .iter()
            .filter(|s| s.enforcement_status == "generated")
            .collect();
        assert!(!generated.is_empty(), "expected generated enforcements");
        for s in generated.iter().take(20) {
            let xml = s.enforcement_xml.as_deref().unwrap_or_default();
            assert!(
                xml.contains("<LocURI>") && xml.contains(&s.oma_uri),
                "generated enforcement must carry SyncML targeting its OMA-URI"
            );
        }

        // Tags decode from the comma-joined column into a real list.
        assert!(
            stigs
                .iter()
                .any(|s| s.policy_tags.iter().any(|t| t == "platform:windows")),
            "expected platform:windows tags"
        );

        // Blocked rows explain themselves.
        assert!(
            stigs
                .iter()
                .filter(|s| s.enforcement_status == "blocked")
                .all(|s| s.block_reason.is_some()),
            "blocked enforcement must carry a block_reason"
        );
    }
}
