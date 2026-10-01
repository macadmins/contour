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
//! - `windows_admx_policies` — the ADMX element schema behind ADMX-backed
//!   CSP nodes (element ids, kinds, enum values, ranges), which is what a
//!   `<enabled/><data…/>` payload needs and the DDF does not carry
//! - `windows_rule_capability_links` — rule → the ADMX policy that writes
//!   the registry value the rule's check reads. Same columns as mSCP's
//!   `rule_capability_links`, read via
//!   [`mscp_schema::rule_capability_links::read`]; a separate file because
//!   the corpora never share a table. Zero-length on a dataset without it.
//! - `windows_app_policies` — third-party app templates (Chrome, Edge,
//!   Firefox, Brave, Microsoft 365, OneDrive, Adobe DC, FSLogix, winget):
//!   each policy's `{App}~Policy~{category}` LocURIs, its `ADMXInstall`
//!   step, and whether Windows lets MDM ingest where it writes, with the
//!   document that says so. The data behind a two-step delivery that no
//!   in-box table can describe.
//! - `windows_node_details` — what the DDF says about a node beyond its
//!   type: the meaning of each allowed value, dependencies on other nodes,
//!   and `<Atomic>` requirements. Joins `windows_capabilities` on
//!   `(payload_type, key_path)`.

pub mod admx_policies;
pub mod app_policies;
pub mod fleet_stigs;
pub mod node_details;
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

/// Embedded ADMX policy/element schema Parquet data.
///
/// Read with [`admx_policies::read`]; joins `windows_capabilities` on
/// `(payload_type, key_name)`.
pub fn embedded_windows_admx_policies() -> &'static [u8] {
    include_bytes!("../data/windows_admx_policies.parquet")
}

/// Windows rule → ADMX policy links, derived from the registry path both
/// `stig_registry_checks` and `windows_admx_policies` state.
pub fn embedded_windows_rule_capability_links() -> &'static [u8] {
    include_bytes!("../data/windows_rule_capability_links.parquet")
}

/// Third-party app policies (Chrome, Edge, Firefox, Microsoft 365, OneDrive,
/// Adobe, FSLogix, winget) with both delivery steps and Windows' ingestion
/// verdict. Zero-length on a dataset without it.
pub fn embedded_windows_app_policies() -> &'static [u8] {
    include_bytes!("../data/windows_app_policies.parquet")
}

/// Per-CSP-node DDF facts: value meanings, dependencies, Atomic. Zero-length
/// on a dataset without it.
pub fn embedded_windows_node_details() -> &'static [u8] {
    include_bytes!("../data/windows_node_details.parquet")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ADMX dataset is what makes an ADMX-backed CSP settable: without
    /// the element schema a payload can only be guessed at.
    #[test]
    fn admx_policies_read_with_their_elements() {
        let policies = admx_policies::read(embedded_windows_admx_policies())
            .expect("read windows_admx_policies");
        assert!(
            policies.len() > 1500,
            "expected 1500+ ADMX-backed nodes, got {}",
            policies.len()
        );
        assert!(
            policies.iter().all(|p| p.display_name.is_some()),
            "every policy should carry its English title"
        );

        let with_elements: Vec<_> = policies.iter().filter(|p| !p.elements.is_empty()).collect();
        assert!(
            with_elements.len() > 500,
            "expected 500+ policies with elements, got {}",
            with_elements.len()
        );
        let kinds = [
            "boolean",
            "decimal",
            "longDecimal",
            "text",
            "multiText",
            "enum",
            "list",
        ];
        for policy in &with_elements {
            for element in &policy.elements {
                assert!(
                    kinds.contains(&element.kind.as_str()),
                    "{}: {}",
                    policy.key_name,
                    element.kind
                );
            }
        }
        assert!(
            with_elements
                .iter()
                .flat_map(|p| &p.elements)
                .any(|e| e.kind == "enum" && !e.items.is_empty()),
            "enum elements should carry their choices"
        );
    }

    /// The point of the dataset: a payload with no hand-written XML.
    #[test]
    fn a_policy_builds_its_syncml_payload() {
        let policies = admx_policies::read(embedded_windows_admx_policies()).unwrap();
        let policy = policies
            .iter()
            .find(|p| p.key_name == "AxISURLZonePolicies")
            .expect("ActiveX install policy present");
        assert_eq!(policy.class, "Machine");
        assert_eq!(policy.admx_file, "ActiveXInstallService.admx");

        // Scaffolded: every element takes its first/lowest allowed value.
        let scaffold = policy.payload(None);
        assert!(scaffold.starts_with("<enabled/>"), "{scaffold}");
        assert!(
            scaffold.contains(r#"<data id="InstallTrustedOCX" value="0"/>"#),
            "{scaffold}"
        );

        // Chosen values win.
        let mut values = std::collections::HashMap::new();
        values.insert("InstallTrustedOCX".to_string(), "2".to_string());
        let chosen = policy.payload(Some(&values));
        assert!(
            chosen.contains(r#"<data id="InstallTrustedOCX" value="2"/>"#),
            "{chosen}"
        );
        assert_eq!(policy.disabled_payload(), "<disabled/>");
    }

    /// A policy with no elements is enable/disable only — one row, no data.
    #[test]
    fn an_element_less_policy_has_a_bare_payload() {
        let policies = admx_policies::read(embedded_windows_admx_policies()).unwrap();
        let bare = policies
            .iter()
            .find(|p| p.elements.is_empty())
            .expect("some policies are enable/disable only");
        assert_eq!(bare.payload(None), "<enabled/>");
    }

    /// Every ADMX policy names a node that exists in the capability data.
    #[test]
    fn admx_policies_join_the_windows_capabilities() {
        let policies = admx_policies::read(embedded_windows_admx_policies()).unwrap();
        let capabilities =
            mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())
                .expect("read windows_capabilities");
        let nodes: std::collections::HashSet<(String, String)> = capabilities
            .iter()
            .flat_map(|c| {
                c.keys
                    .iter()
                    .map(move |k| (c.payload_type.clone(), k.name.clone()))
            })
            .collect();
        let orphans: Vec<_> = policies
            .iter()
            .filter(|p| !nodes.contains(&(p.payload_type.clone(), p.key_name.clone())))
            .map(|p| format!("{}/{}", p.payload_type, p.key_name))
            .collect();
        assert!(
            orphans.is_empty(),
            "{} policies name no CSP node: {:?}",
            orphans.len(),
            &orphans[..orphans.len().min(5)]
        );
    }

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
