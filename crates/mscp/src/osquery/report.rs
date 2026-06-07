//! Coverage report for the osquery bridge.
use crate::osquery::{Classification, Coverage};
use std::fmt::Write as _;

/// Markdown coverage matrix from per-rule [`Coverage`] decisions.
///
/// `coverage[i]` is the *effective* outcome for rule `cs[i]` after query-building,
/// not the optimistic [`crate::osquery::Tier`] classification. A Native-classified
/// rule whose query couldn't be built is reported as `Script` (audit-covered) or
/// `Uncovered` (no check), so the percentages reflect what actually ships.
pub fn coverage_markdown(cs: &[Classification], coverage: &[Coverage], baseline: &str) -> String {
    let n = cs.len().max(1);
    let count = |want: Coverage| coverage.iter().filter(|&&c| c == want).count();
    let native = count(Coverage::Native);
    let script = count(Coverage::Script);
    let uncovered = count(Coverage::Uncovered);
    let excluded = count(Coverage::Excluded);
    let pct = |k: usize| 100.0 * k as f64 / n as f64;

    let mut md = String::new();
    let _ = writeln!(md, "# osquery coverage — {baseline}\n");
    let _ = writeln!(md, "Tier-1 native:     {native} ({:.0}%)  ", pct(native));
    let _ = writeln!(md, "Tier-2 script:     {script} ({:.0}%)  ", pct(script));
    let _ = writeln!(
        md,
        "Uncovered (manual): {uncovered} ({:.0}%)  ",
        pct(uncovered)
    );
    let _ = writeln!(md, "Excluded:          {excluded}\n");
    md.push_str("| rule | coverage | table | reason |\n|---|---|---|---|\n");
    for (c, &cov) in cs.iter().zip(coverage) {
        // Table only meaningful for a rule that actually emitted a native query.
        let table = if cov == Coverage::Native {
            c.table.map(|t| t.name()).unwrap_or("-")
        } else {
            "-"
        };
        let _ = writeln!(
            md,
            "| {} | {:?} | {} | {} |",
            c.rule_id, cov, table, c.reason
        );
    }
    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::osquery::Tier;
    use crate::osquery::catalog::OsqueryTable;

    fn cls(rule_id: &str, tier: Tier, table: Option<OsqueryTable>) -> Classification {
        Classification {
            rule_id: rule_id.to_string(),
            tier,
            table,
            reason: "test",
        }
    }

    #[test]
    fn downgraded_native_is_counted_as_script() {
        // Two rules classified Tier-1 native; only the first emitted a native
        // query. The second downgraded to Script (audit-covered), not native.
        let cs = vec![
            cls(
                "ok_native",
                Tier::Native,
                Some(OsqueryTable::DiskEncryption),
            ),
            cls(
                "downgraded",
                Tier::Native,
                Some(OsqueryTable::LaunchdOverrides),
            ),
        ];
        let md = coverage_markdown(&cs, &[Coverage::Native, Coverage::Script], "disa_stig");
        assert!(md.contains("Tier-1 native:     1 (50%)"));
        assert!(md.contains("Tier-2 script:     1 (50%)"));
        // The downgraded rule's per-rule row shows Script + no table.
        assert!(md.contains("| downgraded | Script | - | test |"));
        assert!(md.contains("| ok_native | Native | disk_encryption | test |"));
    }

    #[test]
    fn uncovered_is_its_own_bucket() {
        // A rule with neither a native query nor a check is reported Uncovered and
        // gets no policy — it must not inflate the script percentage.
        let cs = vec![
            cls("native", Tier::Native, Some(OsqueryTable::DiskEncryption)),
            cls("uncovered", Tier::Residual, None),
        ];
        let md = coverage_markdown(&cs, &[Coverage::Native, Coverage::Uncovered], "cis_lvl1");
        assert!(md.contains("Tier-1 native:     1 (50%)"));
        assert!(md.contains("Tier-2 script:     0 (0%)"));
        assert!(md.contains("Uncovered (manual): 1 (50%)"));
        assert!(md.contains("| uncovered | Uncovered | - | test |"));
    }

    #[test]
    fn excluded_is_counted_separately() {
        let cs = vec![
            cls("native", Tier::Native, Some(OsqueryTable::DiskEncryption)),
            cls("excluded", Tier::Excluded, None),
        ];
        let md = coverage_markdown(&cs, &[Coverage::Native, Coverage::Excluded], "cis_lvl1");
        assert!(md.contains("Tier-1 native:     1 (50%)"));
        assert!(md.contains("Tier-2 script:     0 (0%)"));
        assert!(md.contains("Excluded:          1"));
    }
}
