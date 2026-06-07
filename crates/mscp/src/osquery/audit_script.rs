//! Generate the Tier-2 audit script (slim or full) + its launchd plist, plus the
//! per-rule `plist`-table policy query that reads its results.

use crate::models::MscpRule;

/// The audit results-plist path for an org + baseline. Single source of truth so
/// the audit script and the plist-reading Fleet policies agree on the location.
pub fn audit_plist_path(org: &str, baseline: &str) -> String {
    format!("/Library/Preferences/{org}.{baseline}.audit.plist")
}

/// The generated audit artifacts.
#[derive(Debug, Clone)]
pub struct AuditScript {
    pub sh: String,
    pub launchd_plist: String,
    pub plist_path: String,
    /// rule_ids the script covers (and therefore that get a plist-reading policy).
    pub covered: Vec<String>,
}

/// Build the audit script covering exactly `covered` — the caller ([`super::build`])
/// decides membership from effective coverage so the written keys match the
/// plist-reading policies. `org`/`baseline` form the plist path + launchd label.
pub fn generate(covered: &[&MscpRule], org: &str, baseline: &str) -> AuditScript {
    let plist_path = audit_plist_path(org, baseline);

    let mut sh = String::from(
        "#!/bin/bash\n# Generated mSCP compliance audit — writes results to a plist.\nset -uo pipefail\n",
    );
    sh.push_str(&format!(
        "PLIST=\"{plist_path}\"\n/usr/bin/defaults delete \"$PLIST\" 2>/dev/null || true\n\n"
    ));
    for r in covered {
        let check = r.check.as_deref().unwrap_or("/usr/bin/false").trim();
        // Compliant when the check's stdout equals the rule's expected result
        // (mSCP convention: the check emits a value compared to `result`, e.g.
        // `... | grep -c "..."` expecting `1`). Mirrors the audit pattern in
        // `transformers/rule_script.rs`.
        let expected = r.get_expected_result().unwrap_or_default();
        let expected_esc = expected.replace('\'', "'\\''");
        sh.push_str(&format!(
            "# {id}\nEXPECTED='{expected_esc}'\nACTUAL=$( {check} 2>/dev/null )\nif [ \"$ACTUAL\" = \"$EXPECTED\" ]; then C=true; else C=false; fi\n/usr/bin/defaults write \"$PLIST\" \"{id}\" -bool \"$C\"\n\n",
            id = r.id,
        ));
    }

    let launchd_plist = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n  <key>Label</key><string>{org}.{baseline}.audit</string>\n  <key>ProgramArguments</key><array><string>/usr/local/bin/{baseline}-audit.sh</string></array>\n  <key>StartInterval</key><integer>3600</integer>\n  <key>RunAtLoad</key><true/>\n</dict></plist>\n"
    );

    AuditScript {
        sh,
        launchd_plist,
        plist_path,
        covered: covered.iter().map(|r| r.id.clone()).collect(),
    }
}

/// The `plist`-table policy that reads one rule's cached result.
pub fn plist_policy_sql(plist_path: &str, rule_id: &str) -> String {
    format!(
        "SELECT 1 FROM plist WHERE path = '{plist_path}' AND key = '{rule_id}' AND value = 'true'"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, check: Option<&str>, mobileconfig: bool) -> MscpRule {
        MscpRule {
            id: id.to_string(),
            check: check.map(str::to_string),
            mobileconfig,
            ..Default::default()
        }
    }

    #[test]
    fn covers_exactly_the_given_rules() {
        let r1 = rule("weird_shell_check", Some("/usr/bin/true"), false);
        let r2 = rule("another_check", Some("/usr/bin/false"), false);
        let covered = [&r1, &r2];
        let a = generate(&covered, "com.org", "disa_stig");
        assert_eq!(
            a.covered,
            vec!["weird_shell_check".to_string(), "another_check".to_string()]
        );
        assert!(a.sh.contains("weird_shell_check"));
        // The audit block compares the check's stdout against the expected result,
        // not the check's exit code.
        assert!(a.sh.contains("EXPECTED="));
        assert!(a.sh.contains("ACTUAL=$("));
    }

    #[test]
    fn plist_path_is_derived_from_org_and_baseline() {
        let a = generate(&[], "com.org", "disa_stig");
        assert_eq!(a.plist_path, audit_plist_path("com.org", "disa_stig"));
        assert_eq!(
            a.plist_path,
            "/Library/Preferences/com.org.disa_stig.audit.plist"
        );
    }

    #[test]
    fn audit_block_compares_to_expected_result() {
        let mut r = rule(
            "system_settings_x_configure",
            Some("/usr/bin/foo | grep -c bar"),
            false,
        );
        r.result = Some(yaml_serde::from_str("integer: 1").unwrap());
        let a = generate(&[&r], "com.org", "disa_stig");
        assert!(a.sh.contains("EXPECTED='1'"));
        assert!(a.sh.contains("ACTUAL=$( /usr/bin/foo | grep -c bar 2>/dev/null )"));
        assert!(a.sh.contains("if [ \"$ACTUAL\" = \"$EXPECTED\" ]"));
    }

    #[test]
    fn audit_block_escapes_single_quotes_in_expected() {
        let mut r = rule("os_quote_check", Some("/usr/bin/true"), false);
        r.result = Some(yaml_serde::from_str("string: \"it's on\"").unwrap());
        let a = generate(&[&r], "com.org", "disa_stig");
        assert!(a.sh.contains("EXPECTED='it'\\''s on'"));
    }

    #[test]
    fn plist_policy_reads_results() {
        let q = plist_policy_sql(
            "/Library/Preferences/com.org.disa_stig.audit.plist",
            "weird_shell_check",
        );
        assert!(
            q.contains("FROM plist")
                && q.contains("weird_shell_check")
                && q.contains("value = 'true'")
        );
    }
}
