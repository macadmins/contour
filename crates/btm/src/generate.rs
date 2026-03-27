//! BTM profile generation — mobileconfig and DDM declarations.

use crate::config::BtmAppEntry;
use anyhow::Result;
use contour_profiles::ProfileBuilder;
use plist::{Dictionary, Value};

fn sanitize_id(s: &str) -> String {
    s.replace(['.', '-'], "_")
}

fn parse_btm_rule_type(s: &str) -> Result<contour_profiles::BtmRuleType> {
    s.parse::<contour_profiles::BtmRuleType>()
        .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Generate a service management (managed login items) mobileconfig.
pub fn generate_service_management_profile(app: &BtmAppEntry, org: &str) -> Result<Vec<u8>> {
    let profile_id = format!("{}.service-management.{}", org, sanitize_id(&app.bundle_id));

    let rules: Vec<Value> = if !app.rules.is_empty() {
        app.rules
            .iter()
            .map(|btm| {
                let rule_type = parse_btm_rule_type(&btm.rule_type)?;
                let comment = btm.comment.as_deref().unwrap_or(&app.bundle_id);
                Ok(Value::Dictionary(contour_profiles::build_btm_rule(
                    rule_type,
                    &btm.rule_value,
                    comment,
                )))
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        let extracted = app
            .code_requirement
            .as_deref()
            .and_then(contour_core::extract_team_id);
        let team_id = app.team_id.as_ref().or(extracted.as_ref()).ok_or_else(|| {
            anyhow::anyhow!(
                "Team ID required for '{}'. Provide team_id, rules, or code_requirement.",
                app.name
            )
        })?;
        vec![Value::Dictionary(
            contour_profiles::build_service_management_rule(team_id, &app.bundle_id),
        )]
    };

    let mut payload_content = Dictionary::new();
    payload_content.insert("Rules".to_string(), Value::Array(rules));

    ProfileBuilder::new(org, &profile_id)
        .display_name(&format!("{} Service Management", app.name))
        .description(&format!("Managed login items for {}", app.name))
        .removal_disallowed(true)
        .build("com.apple.servicemanagement", payload_content)
}

/// Generate a combined service management mobileconfig with rules from all apps.
///
/// Merges all BTM rules from every app into a single `com.apple.servicemanagement`
/// payload. This is the typical deployment model — one profile governs all
/// managed login items.
pub fn generate_combined_service_management_profile(
    apps: &[BtmAppEntry],
    org: &str,
    display_name: Option<&str>,
) -> Result<Vec<u8>> {
    let profile_id = format!("{org}.service-management");

    let mut all_rules: Vec<Value> = Vec::new();

    for app in apps {
        if !app.rules.is_empty() {
            for btm in &app.rules {
                let rule_type = parse_btm_rule_type(&btm.rule_type)?;
                let comment = btm.comment.as_deref().unwrap_or(&app.bundle_id);
                all_rules.push(Value::Dictionary(contour_profiles::build_btm_rule(
                    rule_type,
                    &btm.rule_value,
                    comment,
                )));
            }
        } else {
            let extracted = app
                .code_requirement
                .as_deref()
                .and_then(contour_core::extract_team_id);
            if let Some(team_id) = app.team_id.as_ref().or(extracted.as_ref()) {
                all_rules.push(Value::Dictionary(
                    contour_profiles::build_service_management_rule(team_id, &app.bundle_id),
                ));
            }
        }
    }

    if all_rules.is_empty() {
        anyhow::bail!("No BTM rules could be built from any app entry");
    }

    let mut payload_content = Dictionary::new();
    payload_content.insert("Rules".to_string(), Value::Array(all_rules));

    let name = display_name.unwrap_or("Service Management");

    ProfileBuilder::new(org, &profile_id)
        .display_name(name)
        .description("Managed login items and background tasks")
        .removal_disallowed(true)
        .build("com.apple.servicemanagement", payload_content)
}

/// Generate a DDM declaration for background tasks (macOS 15+).
pub fn generate_btm_declaration(app: &BtmAppEntry, org: &str) -> Result<String> {
    let sanitized = sanitize_id(&app.bundle_id);
    let identifier = format!("{org}.btm.{sanitized}");

    // Build LaunchdConfigurations from Label-type BTM rules
    let launchd_configs: Vec<serde_json::Value> = app
        .rules
        .iter()
        .filter(|r| r.rule_type == "Label")
        .map(|r| {
            // Use comment to override context; default to "daemon"
            let context = r
                .comment
                .as_deref()
                .filter(|c| c.eq_ignore_ascii_case("agent"))
                .map_or("daemon", |_| "agent");

            serde_json::json!({
                "FileAssetReference": format!("{org}.asset.launchd.{}", sanitize_id(&r.rule_value)),
                "Context": context,
            })
        })
        .collect();

    let mut payload = serde_json::json!({
        "TaskType": app.bundle_id,
        "TaskDescription": format!("Background tasks for {}", app.name),
    });

    if !launchd_configs.is_empty() {
        payload.as_object_mut().unwrap().insert(
            "LaunchdConfigurations".to_string(),
            serde_json::Value::Array(launchd_configs),
        );
    }

    let declaration = serde_json::json!({
        "Type": "com.apple.configuration.services.background-tasks",
        "Identifier": identifier,
        "Payload": payload,
    });

    serde_json::to_string_pretty(&declaration)
        .map_err(|e| anyhow::anyhow!("Failed to serialize DDM declaration: {e}"))
}

// Re-export shared utilities so existing `crate::generate::sanitize_filename` paths keep working.
pub use contour_core::{resolve_output_dir, sanitize_filename};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BtmAppEntry, BtmRule};

    #[test]
    fn test_service_management_profile_from_code_req() {
        let app = BtmAppEntry {
            name: "Zoom".to_string(),
            bundle_id: "us.zoom.xos".to_string(),
            team_id: None,
            code_requirement: Some(
                r#"identifier "us.zoom.xos" and certificate leaf[subject.OU] = "BJ4HAAB9B3""#
                    .to_string(),
            ),
            rules: vec![],
        };
        let result = generate_service_management_profile(&app, "com.example");
        assert!(result.is_ok());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("com.apple.servicemanagement"));
        assert!(content.contains("BJ4HAAB9B3"));
    }

    #[test]
    fn test_service_management_profile_explicit_team_id() {
        let app = BtmAppEntry {
            name: "Test App".to_string(),
            bundle_id: "com.example.test".to_string(),
            team_id: Some("EXPLICIT123".to_string()),
            code_requirement: None,
            rules: vec![],
        };
        let result = generate_service_management_profile(&app, "com.example");
        assert!(result.is_ok());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("EXPLICIT123"));
    }

    #[test]
    fn test_service_management_profile_with_rules() {
        let app = BtmAppEntry {
            name: "Custom".to_string(),
            bundle_id: "com.example.custom".to_string(),
            team_id: None,
            code_requirement: None,
            rules: vec![
                BtmRule {
                    rule_type: "TeamIdentifier".to_string(),
                    rule_value: "ABC123".to_string(),
                    comment: Some("test team".to_string()),
                },
                BtmRule {
                    rule_type: "Label".to_string(),
                    rule_value: "com.example.daemon".to_string(),
                    comment: None,
                },
            ],
        };
        let result = generate_service_management_profile(&app, "com.example");
        assert!(result.is_ok());
        let content = String::from_utf8(result.unwrap()).unwrap();
        assert!(content.contains("ABC123"));
        assert!(content.contains("com.example.daemon"));
    }

    #[test]
    fn test_service_management_requires_team_id() {
        let app = BtmAppEntry {
            name: "No ID".to_string(),
            bundle_id: "com.example.noid".to_string(),
            team_id: None,
            code_requirement: None,
            rules: vec![],
        };
        let result = generate_service_management_profile(&app, "com.example");
        assert!(result.is_err());
    }

    #[test]
    fn test_btm_declaration_with_labels() {
        let app = BtmAppEntry {
            name: "Test".to_string(),
            bundle_id: "com.example.test".to_string(),
            team_id: Some("ABC123".to_string()),
            code_requirement: None,
            rules: vec![
                BtmRule {
                    rule_type: "Label".to_string(),
                    rule_value: "com.example.daemon".to_string(),
                    comment: None,
                },
                BtmRule {
                    rule_type: "Label".to_string(),
                    rule_value: "com.example.agent".to_string(),
                    comment: Some("agent".to_string()),
                },
            ],
        };
        let result = generate_btm_declaration(&app, "com.example").unwrap();
        assert!(result.contains("com.apple.configuration.services.background-tasks"));
        assert!(result.contains("LaunchdConfigurations"));
        // Labels are sanitized via sanitize_id (dots become underscores) in FileAssetReference
        assert!(result.contains("com_example_daemon"));
        assert!(result.contains("daemon")); // default context
        assert!(result.contains("agent")); // overridden context
    }

    #[test]
    fn test_btm_declaration_no_labels() {
        let app = BtmAppEntry {
            name: "Test".to_string(),
            bundle_id: "com.example.test".to_string(),
            team_id: Some("ABC123".to_string()),
            code_requirement: None,
            rules: vec![BtmRule {
                rule_type: "TeamIdentifier".to_string(),
                rule_value: "ABC123".to_string(),
                comment: None,
            }],
        };
        let result = generate_btm_declaration(&app, "com.example").unwrap();
        assert!(result.contains("com.apple.configuration.services.background-tasks"));
        assert!(!result.contains("LaunchdConfigurations"));
    }

    #[test]
    fn test_combined_service_management_profile() {
        let apps = vec![
            BtmAppEntry {
                name: "Zoom".to_string(),
                bundle_id: "us.zoom.xos".to_string(),
                team_id: Some("BJ4HAAB9B3".to_string()),
                code_requirement: None,
                rules: vec![
                    BtmRule {
                        rule_type: "TeamIdentifier".to_string(),
                        rule_value: "BJ4HAAB9B3".to_string(),
                        comment: Some("Zoom".to_string()),
                    },
                    BtmRule {
                        rule_type: "Label".to_string(),
                        rule_value: "us.zoom.ZoomDaemon".to_string(),
                        comment: Some("Zoom daemon".to_string()),
                    },
                ],
            },
            BtmAppEntry {
                name: "Munki".to_string(),
                bundle_id: "com.googlecode.munki".to_string(),
                team_id: Some("VBG97UB4TA".to_string()),
                code_requirement: None,
                rules: vec![BtmRule {
                    rule_type: "TeamIdentifier".to_string(),
                    rule_value: "VBG97UB4TA".to_string(),
                    comment: Some("Munki".to_string()),
                }],
            },
        ];

        let result =
            generate_combined_service_management_profile(&apps, "com.example", None).unwrap();
        let content = String::from_utf8(result).unwrap();
        assert!(content.contains("com.apple.servicemanagement"));
        // All rules from both apps should be in the single profile
        assert!(content.contains("BJ4HAAB9B3"));
        assert!(content.contains("us.zoom.ZoomDaemon"));
        assert!(content.contains("VBG97UB4TA"));
    }

    #[test]
    fn test_combined_service_management_empty_apps() {
        let apps: Vec<BtmAppEntry> = vec![];
        let result = generate_combined_service_management_profile(&apps, "com.example", None);
        assert!(result.is_err());
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("Zoom Workplace"), "zoom-workplace");
        assert_eq!(sanitize_filename("1Password 8"), "1password-8");
        assert_eq!(sanitize_filename("my_app-v2"), "my_app-v2");
    }
}
