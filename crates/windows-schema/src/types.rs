//! Domain types for the Windows STIG compliance datasets.

/// One registry-backed Windows STIG check (from MITRE's InSpec baseline).
///
/// Joins to the Windows rules (`windows_rules.parquet`) on `rule_id`.
#[derive(Debug, Clone, PartialEq)]
pub struct StigRegistryCheck {
    /// STIG rule id (e.g. `V-253260`).
    pub rule_id: String,
    /// Registry hive (e.g. `HKEY_LOCAL_MACHINE`).
    pub hive: String,
    /// Registry key path under the hive.
    pub path: String,
    /// Value name to check.
    pub value_name: String,
    /// Registry value type (`REG_DWORD`, `REG_SZ`, …).
    pub value_type: String,
    /// Expected value, as the STIG states it.
    pub expected_value: String,
    /// Generated osquery query for the check — usable directly as a
    /// Fleet compliance policy.
    pub osquery_sql: String,
}

/// One Fleet-deployable STIG policy: the CSP enforcement (SyncML) plus
/// the osquery compliance check.
#[derive(Debug, Clone, PartialEq)]
pub struct FleetStig {
    /// STIG profile this policy belongs to.
    pub stig_profile: String,
    /// OMA-URI / LocURI of the CSP node being enforced.
    pub oma_uri: String,
    /// Whether enforcement is available/blocked for this policy.
    pub enforcement_status: String,
    /// Whether a compliance check is available for this policy.
    pub compliance_status: String,
    /// SyncML fragment that enforces the policy (`<Replace>…`).
    pub enforcement_xml: Option<String>,
    /// SyncML `Format` of the enforcement data (`int`, `chr`, …).
    pub enforcement_format: Option<String>,
    /// The enforcement `Data` value.
    pub enforcement_data: Option<String>,
    /// osquery query verifying compliance.
    pub compliance_query: Option<String>,
    /// Human-readable policy name.
    pub policy_name: String,
    /// Policy tags.
    pub policy_tags: Vec<String>,
    /// CSP policy area (e.g. `Update`, `Defender`).
    pub csp_area: Option<String>,
    /// True when the policy is ADMX-backed (CDATA `<enabled/><data/>` payload).
    pub is_admx: bool,
    /// Why enforcement is blocked, when it is.
    pub block_reason: Option<String>,
}
