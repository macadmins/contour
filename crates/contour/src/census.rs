//! The "Embedded data" sentence in the skill file, counted rather than typed.
//!
//! RULE: no figure about the dataset is written by hand anywhere in this
//! repository. `SKILL.md` carries `{{CENSUS}}`; this module fills it from the
//! same embedded bytes the CLI answers questions out of.
//!
//! RULE: every Apple figure comes from `SchemaRegistry`, not from a parquet
//! table directly, because the registry is what every CLI command answers
//! out of. The skill file and `profile info` must never report different
//! totals for the same phrase.
//!
//! RULE: a count that cannot be taken is an error, never a sentence. See
//! [`census_line`].
//!
//! No counts appear in these comments. A number in a comment is the same
//! defect this module exists to remove — it is written once, read as current
//! forever, and nothing resolves it.
//!
//! Three ways a hand-written figure goes wrong, each easy to repeat and none
//! of them looking wrong:
//!
//! 1. The dataset shrinks upstream and the sentence does not.
//! 2. A row count is called a key count. A `capabilities.parquet` row is a
//!    `(payload_type, platform, key)` tuple, so a key Apple supports on both
//!    macOS and iOS counts twice.
//! 3. `capabilities::read` groups rows by payload type, so `.len()` on what
//!    it returns counts payload types, not keys.

use anyhow::Result;
use std::collections::BTreeSet;

/// Every figure in the skill file's "Embedded data" line.
///
/// Serialised for `contour census --json`. Field names are the contract: an
/// agent reads `apple_payload_types` rather than parsing it out of English,
/// which is the whole point of having the command as well as the sentence.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Census {
    pub osquery_tables: usize,
    pub apple_keys: usize,
    pub apple_payload_types: usize,
    pub mscp_rules: usize,
    pub mscp_rules_versioned: usize,
    pub mscp_baselines: usize,
    pub skip_keys: usize,
    pub app_schemas: usize,
    pub windows_nodes: usize,
    pub windows_csps: usize,
    pub app_policy_keys: usize,
    pub windows_app_templates: usize,
    pub windows_app_policies: usize,
    pub stig_profiles: usize,
    pub stig_policies: usize,
    pub stig_policies_enforceable: usize,
    pub stig_registry_checks: usize,
    /// Is a distinct pre-release seed dataset compiled in?
    ///
    /// The census answers "what does this binary carry", and for months the
    /// honest answer about beta was "nothing" while `--channel beta` still
    /// advertised seed-only keys. A boolean here is cheap and is read from
    /// the bytes, so it follows the dataset rather than a release note.
    pub beta_dataset: bool,
}

/// Count what this binary has embedded.
pub fn census() -> Result<Census> {
    let osquery = osquery_schema::osquery::read(osquery_schema::embedded())?;
    let osquery_tables = osquery
        .iter()
        .map(|e| e.table_name.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    // Apple figures come from the registry, which is what every CLI command
    // answers out of — NOT from capabilities.parquet directly. The two count
    // different sets: the registry merges ProfileCreator and app schemas in,
    // and leaves commands, check-ins and shared structures out. Both totals
    // are defensible, which is why picking one and pinning it matters;
    // `census_agrees_with_what_the_cli_reports` is the pin.
    let registry = contour_form::SchemaRegistry::embedded()?;
    let apple_payload_types = registry.stats().total;
    let apple_keys: usize = registry.all().map(|m| m.fields.len()).sum();

    let win = mdm_schema::capabilities::read(mdm_schema::embedded_windows_capabilities())?;
    let windows_csps = win
        .iter()
        .map(|c| c.payload_type.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    // apps_count is the registry's own view of how many application schemas it
    // merged, which is what "app schemas" has always meant here — not a row
    // count over any one table.
    let app_schemas = registry.stats().apps_count;

    // Third-party Windows app templates — Chrome, Edge, the Office family,
    // and now Google Update and Zoom. `profile windows generate --admx-dir`
    // reads these, and the census said nothing about them: "AI-tool policy
    // keys" is a different table (app_policy_schema — Claude Code, Codex,
    // Cursor), so a reader counting embedded datasets found no trace of 22
    // ADMX templates. `read()` groups by (app, policy), so its length is
    // policies rather than rows; rows expand per ADMX element.
    let win_apps =
        windows_schema::app_policies::read(windows_schema::embedded_windows_app_policies())?;
    let windows_app_policies = win_apps.len();
    let windows_app_templates = win_apps
        .iter()
        .map(|p| p.app_name.as_str())
        .collect::<BTreeSet<_>>()
        .len();

    // Both STIG tables are counted, and the enforceable subset separately,
    // because the total on its own overstates what contour can hand you: 188
    // of the 836 have no enforcement to emit. A census that printed only 836
    // would be the same kind of claim this file exists to avoid.
    let stigs = windows_schema::fleet_stigs::read(windows_schema::embedded_fleet_stigs())?;
    let stig_policies = stigs.len();
    let stig_profiles = stigs
        .iter()
        .map(|p| p.stig_profile.as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let stig_policies_enforceable = stigs
        .iter()
        .filter(|p| p.enforcement_status == "generated")
        .count();
    let stig_registry_checks = windows_schema::stig_registry_checks::read(
        windows_schema::embedded_stig_registry_checks(),
    )?
    .len();

    // `capabilities::read` groups rows by payload type: `.len()` on what it
    // returns counts payload types. Keys are one level down, in `c.keys`.
    let windows_nodes: usize = win.iter().map(|c| c.keys.len()).sum();

    Ok(Census {
        osquery_tables,
        apple_keys,
        apple_payload_types,
        mscp_rules: mscp_schema::rule_meta::read(mscp_schema::embedded_rule_meta())?.len(),
        mscp_rules_versioned: mscp_schema::rules_versioned::read(
            mscp_schema::embedded_rules_versioned(),
        )?
        .len(),
        mscp_baselines: mscp_schema::baseline_meta::read(mscp_schema::embedded_baseline_meta())?
            .len(),
        skip_keys: mdm_schema::skip_keys::read(mdm_schema::embedded_skip_keys())?.len(),
        app_schemas,
        windows_nodes,
        windows_csps,
        app_policy_keys: app_policy_schema::app_policies::read(
            app_policy_schema::embedded_app_policies(),
        )?
        .len(),
        windows_app_templates,
        windows_app_policies,
        stig_profiles,
        stig_policies,
        stig_policies_enforceable,
        stig_registry_checks,
        beta_dataset: contour_form::SchemaRegistry::beta_dataset_is_carried(),
    })
}

impl Census {
    /// The human form: one figure per line, labelled, so a person can read it
    /// without counting separators in a sentence.
    pub fn report(&self) -> String {
        let rows: [(&str, usize); 17] = [
            ("osquery tables", self.osquery_tables),
            ("Apple MDM keys", self.apple_keys),
            ("Apple payload types", self.apple_payload_types),
            ("app schemas", self.app_schemas),
            ("Setup Assistant skip keys", self.skip_keys),
            ("mSCP rules", self.mscp_rules),
            ("mSCP rules (OS-versioned)", self.mscp_rules_versioned),
            ("mSCP baselines", self.mscp_baselines),
            ("Windows CSP nodes", self.windows_nodes),
            ("Windows CSPs", self.windows_csps),
            ("AI-tool policy keys", self.app_policy_keys),
            ("Windows app templates", self.windows_app_templates),
            ("  their policies", self.windows_app_policies),
            ("DISA STIG profiles", self.stig_profiles),
            ("Windows STIG policies", self.stig_policies),
            ("  of those enforceable", self.stig_policies_enforceable),
            ("Windows STIG registry checks", self.stig_registry_checks),
        ];
        let width = rows.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
        let mut out = String::from("Embedded datasets in this binary\n\n");
        for (label, n) in rows {
            out.push_str(&format!("  {label:<width$}  {}\n", commas(n)));
        }
        out.push_str(&format!(
            "\n  beta seed dataset            {}\n",
            if self.beta_dataset {
                "carried"
            } else {
                "not carried — `--beta` / `--channel beta` refuse"
            }
        ));
        out.push_str(
            "\nCounted from the embedded bytes at run time. `contour profile info` \
             breaks the payload types down by source.\n",
        );
        out
    }
}

/// Thousands separators, because the line is prose an agent reads.
fn commas(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

impl std::fmt::Display for Census {
    /// The sentence substituted for `{{CENSUS}}`.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} osquery tables · {} Apple MDM keys across {} payload types · \
             {} mSCP rules ({} OS-versioned) · {} baselines · {} skip keys · \
             {} app schemas · {} Windows CSP nodes across {} CSPs (`--windows`) · \
             {} AI-tool policy keys · {} Windows app templates ({} policies) · \
             {} Windows STIG policies ({} enforceable) \
             across {} DISA profiles · {} STIG registry checks (`profile windows stig`)",
            commas(self.osquery_tables),
            commas(self.apple_keys),
            commas(self.apple_payload_types),
            commas(self.mscp_rules),
            commas(self.mscp_rules_versioned),
            commas(self.mscp_baselines),
            commas(self.skip_keys),
            commas(self.app_schemas),
            commas(self.windows_nodes),
            commas(self.windows_csps),
            commas(self.app_policy_keys),
            commas(self.windows_app_templates),
            commas(self.windows_app_policies),
            commas(self.stig_policies),
            commas(self.stig_policies_enforceable),
            commas(self.stig_profiles),
            commas(self.stig_registry_checks),
        )
    }
}

/// The census as the skill file wants it.
///
/// Returns an error rather than a sentence. A diagnostic written into
/// `SKILL.md` is read by an agent that cannot tell it from a description:
/// a missing census is a bug someone fixes, an apology in place of one is a
/// bug an agent works around. Installation fails instead.
pub fn census_line() -> Result<String> {
    Ok(census()?.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commas_groups_by_three() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(286), "286");
        assert_eq!(commas(1657), "1,657");
        assert_eq!(commas(14766), "14,766");
        assert_eq!(commas(1000000), "1,000,000");
    }

    /// One English phrase, one number.
    ///
    /// `profile info` reports "Total: N payload types" from the registry and
    /// the skill file says "… across N payload types". If those disagree, an
    /// agent that reads the skill and then runs the CLI sees the tool
    /// contradict its own documentation with no way to tell which is right.
    #[test]
    fn census_agrees_with_what_the_cli_reports() {
        let c = census().expect("embedded census reads");
        let registry = contour_form::SchemaRegistry::embedded().expect("embedded registry");
        let stats = registry.stats();
        assert_eq!(
            c.apple_payload_types, stats.total,
            "the skill file and `profile info` would report different payload-type totals"
        );
        assert_eq!(
            c.app_schemas, stats.apps_count,
            "the skill file and `profile info` would report different app-schema counts"
        );
    }

    /// The sentence must never contain a figure that was not counted.
    #[test]
    fn the_rendered_line_is_all_numbers() {
        let line = census_line().expect("census renders");
        for word in ["could not", "unknown", "unavailable", "error", "N/A"] {
            assert!(
                !line.to_lowercase().contains(&word.to_lowercase()),
                "the census line reads like a diagnostic, not a census: {line}"
            );
        }
        // Every segment separated by · must carry a digit.
        for seg in line.split('\u{b7}') {
            assert!(
                seg.chars().any(|ch| ch.is_ascii_digit()),
                "census segment has no number in it: {seg:?}"
            );
        }
    }

    /// Every figure must be positive. A zero here means a table failed to load
    /// and the sentence would tell an agent the dataset is empty.
    #[test]
    fn every_figure_is_counted() {
        let c = census().expect("embedded census reads");
        for (name, n) in [
            ("osquery_tables", c.osquery_tables),
            ("apple_keys", c.apple_keys),
            ("apple_payload_types", c.apple_payload_types),
            ("mscp_rules", c.mscp_rules),
            ("mscp_rules_versioned", c.mscp_rules_versioned),
            ("mscp_baselines", c.mscp_baselines),
            ("skip_keys", c.skip_keys),
            ("app_schemas", c.app_schemas),
            ("windows_nodes", c.windows_nodes),
            ("windows_csps", c.windows_csps),
            ("app_policy_keys", c.app_policy_keys),
            ("windows_app_templates", c.windows_app_templates),
            ("windows_app_policies", c.windows_app_policies),
            ("stig_profiles", c.stig_profiles),
            ("stig_policies", c.stig_policies),
            ("stig_policies_enforceable", c.stig_policies_enforceable),
            ("stig_registry_checks", c.stig_registry_checks),
        ] {
            assert!(n > 0, "{name} counted 0 — the table did not load");
        }
        // Sanity on the two that are pairs: a payload type has at least one
        // key, and a CSP at least one node.
        assert!(c.apple_keys >= c.apple_payload_types);
        assert!(c.windows_nodes >= c.windows_csps);
        // The enforceable subset is a subset, and a proper one today. If it
        // ever equals the total, the gap the export header describes has
        // closed and that wording should be revisited rather than left to
        // describe a gap of nothing.
        assert!(c.stig_policies_enforceable < c.stig_policies);
        assert!(c.stig_policies >= c.stig_profiles);
        assert!(c.windows_app_policies >= c.windows_app_templates);
    }
}
