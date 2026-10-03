//! Fleet "report" (scheduled-query) generators.
//!
//! Reports are osquery snapshot queries Fleet runs on a schedule for data
//! collection — distinct from policies, which are pass/fail. contour emits two
//! kinds: a per-baseline compliance-status report that surfaces the audit plist
//! the [`audit_script`](super::audit_script) writes, and a baseline-independent
//! macOS security-posture pack. Both serialize to Fleet's separate-file report
//! shape — a flat YAML list of report objects in a `*.reports.yml` file, the
//! same format as the `.policies.yml` files contour already emits.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::audit_script::audit_plist_path;

/// The built-in security-posture pack, compiled into the binary. Overridable per
/// repo via `.contour/security-posture.toml` (see [`resolve_security_posture`]).
const EMBEDDED_POSTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../reference/security-posture.toml"
));

/// One Fleet scheduled-query report, matching the GitOps separate-file schema
/// (`name`, `description`, `query`, `platform`, `interval`, `observer_can_run`,
/// `automations_enabled`). Serializes directly to a report list entry; also
/// deserialized from the security-posture TOML, where everything but
/// name/description/query defaults.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FleetReport {
    /// Display name shown in Fleet.
    pub name: String,
    /// What the report collects and why.
    pub description: String,
    /// The osquery SQL run on each interval.
    pub query: String,
    /// Comma-separated osquery platforms (default `darwin`).
    #[serde(default = "default_platform")]
    pub platform: String,
    /// Seconds between runs (default 3600).
    #[serde(default = "default_interval")]
    pub interval: u32,
    /// Whether observers may run the query ad hoc (default true).
    #[serde(default = "default_true")]
    pub observer_can_run: bool,
    /// Whether results are forwarded to the log destination (default false).
    #[serde(default)]
    pub automations_enabled: bool,
}

fn default_platform() -> String {
    "darwin".to_string()
}
fn default_interval() -> u32 {
    3600
}
fn default_true() -> bool {
    true
}

/// The security-posture TOML shape: a list of `[[report]]` tables.
#[derive(Debug, Deserialize)]
struct PostureFile {
    #[serde(default, rename = "report")]
    reports: Vec<FleetReport>,
}

/// A per-baseline report that surfaces the audit-results plist the baseline's
/// audit script writes (one boolean per rule). Each result row is a rule id and
/// whether the host is compliant — the data companion to the pass/fail policies.
///
/// Only meaningful when the osquery bridge's audit script is deployed (it writes
/// the plist); callers emit it alongside the bridge output.
pub fn compliance_report(org_domain: &str, baseline: &str) -> FleetReport {
    let plist = audit_plist_path(org_domain, baseline);
    FleetReport {
        name: format!("mSCP {baseline}: compliance status"),
        description: format!(
            "Per-rule audit results for the {baseline} baseline. The contour audit \
             script writes one boolean per rule to {plist}; each row is a rule id and \
             whether the host is compliant."
        ),
        query: format!("SELECT key AS rule, value AS compliant FROM plist WHERE path = '{plist}';"),
        platform: "darwin".to_string(),
        interval: 3600,
        observer_can_run: true,
        automations_enabled: false,
    }
}

/// Parse a security-posture pack from TOML (`[[report]]` tables).
fn parse_posture(toml_str: &str) -> Result<Vec<FleetReport>> {
    let file: PostureFile = toml::from_str(toml_str).context("parse security-posture TOML")?;
    Ok(file.reports)
}

/// The built-in macOS security-posture pack (OS version, disk encryption, SIP,
/// application firewall, Gatekeeper, screen lock) — baseline-independent live
/// queries over core osquery tables, useful on any macOS fleet.
///
/// Loaded from the embedded `reference/security-posture.toml`. To override or
/// extend it, see [`resolve_security_posture`].
///
/// # Panics
/// Panics if the compiled-in TOML is malformed — guarded by a unit test.
pub fn security_posture_pack() -> Vec<FleetReport> {
    parse_posture(EMBEDDED_POSTURE).expect("embedded security-posture.toml is valid")
}

/// Resolve the security-posture pack for a repo: a repo-local
/// `.contour/security-posture.toml` overrides the embedded default; otherwise the
/// built-in pack is used. This is the editable-content seam — operators tune
/// queries, intervals, and flags without recompiling.
///
/// # Errors
/// Returns an error if a repo-local override exists but can't be read or parsed.
pub fn resolve_security_posture(repo: &Path) -> Result<Vec<FleetReport>> {
    let override_path = repo.join(".contour").join("security-posture.toml");
    if override_path.is_file() {
        let text = std::fs::read_to_string(&override_path)
            .with_context(|| format!("read {}", override_path.display()))?;
        return parse_posture(&text).with_context(|| format!("parse {}", override_path.display()));
    }
    Ok(security_posture_pack())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compliance_report_queries_the_audit_plist_for_the_org_and_baseline() {
        let r = compliance_report("com.acme", "cis_lvl1");
        // Reads the same plist the audit script writes for this org+baseline.
        assert!(r.query.contains(
            "FROM plist WHERE path = '/Library/Preferences/com.acme.cis_lvl1.audit.plist'"
        ));
        assert_eq!(r.platform, "darwin");
        assert_eq!(r.interval, 3600);
    }

    #[test]
    fn embedded_posture_pack_parses_all_darwin_and_serializes_as_flat_list() {
        // Guards the compiled-in reference/security-posture.toml.
        let pack = security_posture_pack();
        assert!(pack.len() >= 6);
        assert!(pack.iter().all(|r| r.platform == "darwin"));

        // Separate-file Fleet report shape: a flat YAML list of report objects,
        // no apiVersion/kind/spec wrapper.
        let yaml = yaml_serde::to_string(&pack).unwrap();
        assert!(yaml.starts_with("- name:"));
        assert!(yaml.contains("query: SELECT name, version, build FROM os_version;"));
        assert!(yaml.contains("observer_can_run: true"));
        assert!(!yaml.contains("apiVersion"));
        assert!(!yaml.contains("kind:"));
    }

    /// Every pack query must pass the schema check: tables, columns, the
    /// declared platform, required columns. The pack is hand-written SQL
    /// copied straight to YAML; this is the one place the schema the binary
    /// already carries checks the embedded copy. A repo override is checked
    /// the same way at generate time, by `check_emitted`.
    #[test]
    fn posture_pack_and_compliance_report_pass_the_schema_check() {
        use contour_core::osquery_validate::{Severity, check_query};
        let index = osquery_schema::index();
        let mut pack = security_posture_pack();
        pack.push(compliance_report("com.acme", "cis_lvl1"));
        for r in &pack {
            let errors: Vec<String> = check_query(&r.query, &r.platform, index)
                .into_iter()
                .filter(|p| p.severity() == Severity::Error)
                .map(|p| p.to_string())
                .collect();
            assert!(errors.is_empty(), "{}: {errors:?}", r.name);
        }
    }

    /// The check must be seen failing, or a green test proves nothing.
    #[test]
    fn schema_check_rejects_a_planted_typo_and_wrong_platform() {
        let bad = "[[report]]\nname = \"SIP\"\ndescription = \"d\"\nquery = \"SELECT config_flag FROM sip_configz;\"\n\
                   [[report]]\nname = \"plist on windows\"\ndescription = \"d\"\nplatform = \"windows\"\nquery = \"SELECT key FROM plist WHERE path = '/x';\"\n";
        let pack = parse_posture(bad).unwrap();
        let err = crate::osquery::check_emitted(
            "test pack",
            pack.iter().map(|r| (r.name.as_str(), r.query.as_str(), r.platform.as_str())),
        )
        .expect_err("planted problems must fail");
        let msg = err.to_string();
        assert!(msg.contains("2 query(s) fail"), "{msg}");
        assert!(msg.contains("did you mean: sip_config"), "{msg}");
        assert!(msg.contains("not available on windows"), "{msg}");
    }

    #[test]
    fn posture_toml_applies_defaults_for_omitted_fields() {
        // Only name/description/query given — platform/interval/flags default.
        let pack =
            parse_posture("[[report]]\nname = \"x\"\ndescription = \"d\"\nquery = \"SELECT 1;\"\n")
                .unwrap();
        assert_eq!(pack.len(), 1);
        assert_eq!(pack[0].platform, "darwin");
        assert_eq!(pack[0].interval, 3600);
        assert!(pack[0].observer_can_run);
        assert!(!pack[0].automations_enabled);
    }

    #[test]
    fn resolve_prefers_repo_override_over_embedded() {
        let tmp = tempfile::TempDir::new().unwrap();
        // No override → embedded default.
        let default = resolve_security_posture(tmp.path()).unwrap();
        assert!(default.len() >= 6);

        // A repo-local override replaces the pack entirely.
        let dir = tmp.path().join(".contour");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("security-posture.toml"),
            "[[report]]\nname = \"custom only\"\ndescription = \"d\"\nquery = \"SELECT 1;\"\ninterval = 600\n",
        )
        .unwrap();
        let overridden = resolve_security_posture(tmp.path()).unwrap();
        assert_eq!(overridden.len(), 1);
        assert_eq!(overridden[0].name, "custom only");
        assert_eq!(overridden[0].interval, 600);
    }
}
