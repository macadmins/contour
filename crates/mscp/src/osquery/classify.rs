//! Per-rule routing onto an osquery table or the audit script.

use crate::models::MscpRule;
use crate::osquery::catalog::OsqueryTable;
use crate::osquery::{Classification, Tier};

/// rule_id substrings that the `sharing_preferences` table covers.
const SHARING_HINTS: &[&str] = &[
    "screen_sharing",
    "printer_sharing",
    "file_sharing",
    "remote_management",
    "remote_login",
    "remote_apple_events",
    "bluetooth_sharing",
    "internet_sharing",
    "content_caching",
    "disc_sharing",
];

/// Classify one rule onto an osquery table (Tier 1) or the audit script (Tier 2).
pub fn classify(rule: &MscpRule) -> Classification {
    let id = rule.id.as_str();
    let check = rule.check.as_deref().unwrap_or("");
    let mk = |tier, table, reason| Classification {
        rule_id: rule.id.clone(),
        tier,
        table,
        reason,
    };

    // 1. mSCP helper rules, not real checks.
    if id.starts_with("supplemental_") {
        return mk(Tier::Excluded, None, "supplemental helper");
    }

    // 2. Profile-enforced: managed_policies — only when all values are scalar.
    if let (true, Some(info)) = (rule.mobileconfig, rule.mobileconfig_info.as_ref()) {
        if mobileconfig_all_scalar(info) {
            return mk(
                Tier::Native,
                Some(OsqueryTable::ManagedPolicies),
                "mobileconfig scalar",
            );
        }
        return mk(Tier::Residual, None, "mobileconfig array value");
    }

    // 3. Sharing / remote management. `mdmclient QuerySecurityInfo` also reports
    // secure-boot / recovery-lock / authenticated-root, which are NOT sharing
    // columns — so only a sharing-hint id (which covers remote_management) or
    // `cupsctl` routes to sharing_preferences; a bare QuerySecurityInfo check
    // falls through to the audit script.
    if SHARING_HINTS.iter().any(|h| id.contains(h)) || check.contains("cupsctl") {
        return mk(
            Tier::Native,
            Some(OsqueryTable::SharingPreferences),
            "sharing",
        );
    }

    // 4. Service disable.
    if check.contains("launchctl print-disabled") || check.contains("print-disabled system") {
        return mk(
            Tier::Native,
            Some(OsqueryTable::LaunchdOverrides),
            "launchd disabled",
        );
    }

    // 5. Fixed-path defaults read.
    if check.contains("defaults read /Library/Preferences/")
        || check.contains("defaults read /System")
    {
        return mk(Tier::Native, Some(OsqueryTable::Plist), "plist fixed path");
    }

    // 6. Native singletons.
    for (needle, table) in [
        ("fdesetup", OsqueryTable::DiskEncryption),
        ("csrutil", OsqueryTable::SipConfig),
        ("spctl", OsqueryTable::Gatekeeper),
        ("socketfilterfw", OsqueryTable::Alf),
        ("/usr/sbin/nvram", OsqueryTable::Nvram),
    ] {
        if check.contains(needle) {
            return mk(Tier::Native, Some(table), "native tool");
        }
    }

    // 7. Residual → audit script.
    mk(Tier::Residual, None, "no native table")
}

/// True when every value in `mobileconfig_info` is a scalar (no arrays) — only
/// then can a `managed_policies` row check be exact.
fn mobileconfig_all_scalar(info: &yaml_serde::Value) -> bool {
    fn no_arrays(v: &yaml_serde::Value) -> bool {
        match v {
            yaml_serde::Value::Sequence(_) => false,
            yaml_serde::Value::Mapping(m) => m.values().all(no_arrays),
            _ => true,
        }
    }
    no_arrays(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Minimal rule builder for tests.
    fn rule(id: &str, check: Option<&str>, mobileconfig: bool) -> MscpRule {
        MscpRule {
            id: id.to_string(),
            check: check.map(str::to_string),
            mobileconfig,
            ..Default::default()
        }
    }

    #[test]
    fn supplemental_is_excluded() {
        let c = classify(&rule("supplemental_smartcard", None, false));
        assert_eq!(c.tier, Tier::Excluded);
    }

    #[test]
    fn mobileconfig_scalar_is_managed_policies() {
        let mut r = rule("system_settings_screensaver_password", None, true);
        // scalar mobileconfig_info -> managed_policies
        r.mobileconfig_info =
            Some(yaml_serde::from_str("com.apple.screensaver:\n  askForPassword: true\n").unwrap());
        let c = classify(&r);
        assert_eq!(c.tier, Tier::Native);
        assert_eq!(c.table, Some(OsqueryTable::ManagedPolicies));
    }

    #[test]
    fn mobileconfig_array_value_is_residual() {
        let mut r = rule("system_settings_internet_accounts_disable", None, true);
        r.mobileconfig_info = Some(
            yaml_serde::from_str(
                "com.apple.systempreferences:\n  DisabledSystemSettings:\n    - com.apple.x\n",
            )
            .unwrap(),
        );
        let c = classify(&r);
        assert_eq!(c.tier, Tier::Residual, "array value must fall to residual");
    }

    #[test]
    fn sharing_rule_is_sharing_preferences() {
        let c = classify(&rule(
            "system_settings_remote_management_disable",
            Some("/usr/libexec/mdmclient QuerySecurityInfo | grep -c RemoteDesktopEnabled"),
            false,
        ));
        assert_eq!(c.table, Some(OsqueryTable::SharingPreferences));
    }

    #[test]
    fn querysecurityinfo_non_sharing_is_residual() {
        // secure-boot via QuerySecurityInfo is not a sharing_preferences column.
        let c = classify(&rule(
            "os_secure_boot_verify",
            Some("/usr/libexec/mdmclient QuerySecurityInfo | grep -c SecureBoot"),
            false,
        ));
        assert_eq!(c.tier, Tier::Residual);
    }

    #[test]
    fn launchctl_disabled_is_launchd_overrides() {
        let c = classify(&rule(
            "system_settings_smbd_disable",
            Some("/bin/launchctl print-disabled system | grep smbd"),
            false,
        ));
        assert_eq!(c.table, Some(OsqueryTable::LaunchdOverrides));
    }

    #[test]
    fn unknown_shell_is_residual() {
        let c = classify(&rule("some_weird_check", Some("/usr/bin/true"), false));
        assert_eq!(c.tier, Tier::Residual);
        assert_eq!(c.table, None);
    }
}
