//! SQL builders per osquery table. Each returns SQL that yields >=1 row when the
//! host is COMPLIANT (osquery policy convention).
//!
//! Note: `managed_policies` SQL is built by `transformers/fleet_policy.rs::generate_policy_for_rule`
//! (from `mobileconfig_info`) — not duplicated here. `plist`/`nvram` rules are
//! not translated yet and always fall to residual.

use crate::osquery::catalog::OsqueryTable;

/// Build the compliance query for a rule routed to `table`. Returns `None` when
/// the specifics of this rule can't be expressed exactly (caller falls to residual).
pub fn build(table: OsqueryTable, rule: &crate::models::MscpRule) -> Option<String> {
    let rule_id = rule.id.as_str();
    match table {
        OsqueryTable::SharingPreferences => sharing_preferences(rule_id),
        OsqueryTable::LaunchdOverrides => launchd_disabled(rule.check.as_deref().unwrap_or("")),
        OsqueryTable::DiskEncryption => {
            Some("SELECT 1 FROM disk_encryption WHERE encrypted = 1".into())
        }
        OsqueryTable::SipConfig => {
            Some("SELECT 1 FROM sip_config WHERE config_flag = 'sip' AND enabled = 1".into())
        }
        OsqueryTable::Gatekeeper => {
            Some("SELECT 1 FROM gatekeeper WHERE assessments_enabled = 1".into())
        }
        OsqueryTable::Alf => Some("SELECT 1 FROM alf WHERE global_state >= 1".into()),
        // managed_policies SQL is built from mobileconfig_info elsewhere; plist +
        // nvram are not translated yet. None of them is handled here.
        _ => None,
    }
}

/// Map a sharing rule_id to its `sharing_preferences` column and emit the query.
fn sharing_preferences(rule_id: &str) -> Option<String> {
    let col = if rule_id.contains("remote_management") {
        "remote_management"
    } else if rule_id.contains("printer_sharing") {
        "printer_sharing"
    } else if rule_id.contains("screen_sharing") {
        "screen_sharing"
    } else {
        return None;
    };
    Some(format!("SELECT 1 FROM sharing_preferences WHERE {col} = 0"))
}

/// A service-disable rule -> launchd_overrides check.
///
/// mSCP launchd checks look like `... | grep -c '"com.apple.smbd" => disabled'`.
/// We extract the exact service label from the `"<label>" => disabled` pattern in
/// the check rather than guessing from the rule id. Returns `None` when no label
/// can be found, so the caller falls back to the residual audit-plist policy.
fn launchd_disabled(check: &str) -> Option<String> {
    let label = extract_launchd_label(check)?;
    Some(format!(
        "SELECT 1 FROM launchd_overrides WHERE label = '{label}' AND key = 'Disabled' AND value IN ('1','true')"
    ))
}

/// Find the service label in a `"<label>" => enabled|disabled` substring of the
/// check. mSCP phrases the grep either way (compliant = the service is disabled);
/// the label is the quoted token before the ` => ` arrow and the compliance query
/// is identical regardless.
fn extract_launchd_label(check: &str) -> Option<&str> {
    let marker_at = check.find(" => ")?;
    let before = &check[..marker_at];
    let close_quote = before.rfind('"')?;
    let open_quote = before[..close_quote].rfind('"')?;
    let label = &before[open_quote + 1..close_quote];
    (!label.is_empty()).then_some(label)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::MscpRule;

    fn rule(id: &str, check: Option<&str>) -> MscpRule {
        MscpRule {
            id: id.to_string(),
            check: check.map(str::to_string),
            ..Default::default()
        }
    }

    #[test]
    fn sharing_remote_management_query() {
        let q = build(
            OsqueryTable::SharingPreferences,
            &rule("system_settings_remote_management_disable", None),
        )
        .unwrap();
        assert_eq!(
            q,
            "SELECT 1 FROM sharing_preferences WHERE remote_management = 0"
        );
    }

    #[test]
    fn disk_encryption_query() {
        let q = build(
            OsqueryTable::DiskEncryption,
            &rule("filevault_enforce", None),
        )
        .unwrap();
        assert!(q.contains("disk_encryption") && q.contains("encrypted = 1"));
    }

    #[test]
    fn launchd_query_uses_label_from_check() {
        let q = build(
            OsqueryTable::LaunchdOverrides,
            &rule(
                "system_settings_smbd_disable",
                Some("/bin/launchctl print-disabled system | /usr/bin/grep -c '\"com.apple.smbd\" => disabled'"),
            ),
        )
        .unwrap();
        assert_eq!(
            q,
            "SELECT 1 FROM launchd_overrides WHERE label = 'com.apple.smbd' AND key = 'Disabled' AND value IN ('1','true')"
        );
    }

    #[test]
    fn launchd_label_from_enabled_marker() {
        // mSCP checks often grep `"<label>" => enabled` (compliant = service is
        // disabled). The label is still extractable; the compliance query is the
        // same disabled-override check.
        let q = build(
            OsqueryTable::LaunchdOverrides,
            &rule(
                "os_tftpd_disable",
                Some("enabled=$(/bin/launchctl print-disabled system | /usr/bin/grep '\"com.apple.tftpd\" => enabled')"),
            ),
        )
        .unwrap();
        assert_eq!(
            q,
            "SELECT 1 FROM launchd_overrides WHERE label = 'com.apple.tftpd' AND key = 'Disabled' AND value IN ('1','true')"
        );
    }

    /// Every native query the bridge can emit, checked against the embedded
    /// schema: tables, columns, the darwin platform, and required columns.
    #[test]
    fn every_native_query_passes_the_schema_check() {
        use contour_core::osquery_validate::{Severity, check_query};
        let index = osquery_schema::index();
        let cases = [
            (OsqueryTable::SharingPreferences, rule("system_settings_remote_management_disable", None)),
            (OsqueryTable::SharingPreferences, rule("system_settings_printer_sharing_disable", None)),
            (OsqueryTable::SharingPreferences, rule("system_settings_screen_sharing_disable", None)),
            (OsqueryTable::LaunchdOverrides, rule("os_smbd_disable", Some("grep -c '\"com.apple.smbd\" => disabled'"))),
            (OsqueryTable::DiskEncryption, rule("filevault_enforce", None)),
            (OsqueryTable::SipConfig, rule("os_sip_enable", None)),
            (OsqueryTable::Gatekeeper, rule("os_gatekeeper_enable", None)),
            (OsqueryTable::Alf, rule("os_firewall_enable", None)),
        ];
        for (table, r) in cases {
            let sql = build(table, &r).expect("builder returns SQL for its own table");
            let errors: Vec<String> = check_query(&sql, "darwin", index)
                .into_iter()
                .filter(|p| p.severity() == Severity::Error)
                .map(|p| p.to_string())
                .collect();
            assert!(errors.is_empty(), "{sql}: {errors:?}");
        }
    }

    #[test]
    fn launchd_without_label_falls_to_residual() {
        let q = build(
            OsqueryTable::LaunchdOverrides,
            &rule(
                "system_settings_smbd_disable",
                Some("/bin/launchctl print-disabled system | grep smbd"),
            ),
        );
        assert_eq!(q, None);
    }
}
