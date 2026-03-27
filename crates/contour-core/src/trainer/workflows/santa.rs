//! Santa GitOps workflow for trainer mode.
//!
//! This workflow guides users through the complete process of building
//! Santa allowlists using Contour's GitOps approach.

use crate::trainer::TrainerWorkflow;
use crate::trainer::queries::santa as queries;
use crate::trainer::step::{CommandPreview, GitOp, OsqueryQuery, StepAction, TrainerStep};
use std::path::PathBuf;

/// The Santa GitOps workflow.
#[derive(Debug)]
pub struct SantaWorkflow {
    /// The output directory for generated files.
    output_dir: PathBuf,
    /// Organization identifier.
    org: String,
}

impl SantaWorkflow {
    /// Create a new Santa workflow.
    #[must_use]
    pub fn new(output_dir: PathBuf, org: String) -> Self {
        Self { output_dir, org }
    }

    /// Create with default settings.
    #[must_use]
    pub fn default_workflow() -> Self {
        Self {
            output_dir: PathBuf::from("."),
            org: "com.example".to_string(),
        }
    }
}

impl TrainerWorkflow for SantaWorkflow {
    fn name(&self) -> &'static str {
        "Santa GitOps Workflow"
    }

    fn description(&self) -> &'static str {
        "Build and deploy Santa allowlists using a GitOps workflow. \
         This process scans applications, builds rule files, \
         and generates MDM-ready profiles for deployment."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let output_dir = &self.output_dir;
        let org = &self.org;

        vec![
            // Step 1: Initialize Project
            TrainerStep::new(1, "Initialize Santa Project")
                .with_explanation(
                    "Start by creating a santa.toml configuration file.\n\
                     This defines your organization identifier and default settings.\n\n\
                     The init command creates a project structure that you can commit to Git.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!("contour santa init --org {org}"),
                        "Create santa.toml in the current directory",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour santa init --org {org} --output {}",
                            output_dir.join("santa.toml").display()
                        ),
                        "Create santa.toml at a specific path",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "santa".to_string(),
                        "init".to_string(),
                        "--org".to_string(),
                        org.clone(),
                    ],
                }),

            // Step 2: Scan Applications
            TrainerStep::new(2, "Scan Applications")
                .with_explanation(
                    "Scan installed applications to discover their code signing\n\
                     information. The scan extracts TeamIDs and SigningIDs that\n\
                     Santa uses for allowlist rules.\n\n\
                     Options:\n\
                     - Local scan: Uses santactl to query the local machine\n\
                     - Fleet query: Export from Fleet for fleet-wide visibility\n\n\
                     The output is a CSV file with app_name, team_id, signing_id.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour santa scan --output {}",
                            output_dir.join("apps.csv").display()
                        ),
                        "Scan /Applications using santactl (requires Santa installed)",
                    ),
                    CommandPreview::new(
                        "contour santa scan --path /Applications --path /usr/local --output apps.csv",
                        "Scan multiple directories",
                    ),
                ])
                .with_osquery(OsqueryQuery::new(
                    "For fleet-wide discovery, run this query in Fleet and export as CSV",
                    queries::DISCOVER_APPS,
                ))
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "santa".to_string(),
                        "scan".to_string(),
                        "--output".to_string(),
                        output_dir.join("apps.csv").display().to_string(),
                    ],
                }),

            // Step 3: Review Scan Results
            TrainerStep::new(3, "Review Scan Results")
                .with_explanation(
                    "Review the discovered applications before building rules.\n\n\
                     The CSV contains:\n\
                     - app_name: The application's display name\n\
                     - team_id: Apple Team ID (10-character developer identifier)\n\
                     - signing_id: TeamID:BundleID (unique app identifier)\n\n\
                     Look for patterns in TeamIDs — apps from the same vendor\n\
                     share a TeamID. This helps you decide between TEAM_ID rules\n\
                     (allow all apps from a vendor) vs SIGNING_ID rules (allow\n\
                     specific apps only).",
                )
                .with_action(StepAction::ShowFile {
                    path: output_dir.join("apps.csv"),
                }),

            // Step 4: Build Rules
            TrainerStep::new(4, "Build Santa Rules")
                .with_explanation(
                    "Add rules to a YAML rule file using `santa add`.\n\n\
                     Rule types:\n\
                     - TEAM_ID: Allow all apps from a developer (broadest)\n\
                     - SIGNING_ID: Allow a specific app (recommended)\n\
                     - BINARY: Allow by exact SHA-256 hash (most restrictive)\n\n\
                     You can also merge scan results directly into a rules file\n\
                     using `santa merge`, which converts CSV rows into rules\n\
                     grouped by TeamID.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour santa add {} --identifier EQHXZ8M8AV --rule-type team-id --policy allowlist --custom-msg \"Google apps\"",
                            output_dir.join("rules.yaml").display()
                        ),
                        "Add a TeamID rule for Google",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour santa merge --input {} --output {}",
                            output_dir.join("apps.csv").display(),
                            output_dir.join("rules.yaml").display()
                        ),
                        "Merge scan results into rules (groups by TeamID)",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "santa".to_string(),
                        "merge".to_string(),
                        "--input".to_string(),
                        output_dir.join("apps.csv").display().to_string(),
                        "--output".to_string(),
                        output_dir.join("rules.yaml").display().to_string(),
                    ],
                }),

            // Step 5: Validate Rules
            TrainerStep::new(5, "Validate Rules")
                .with_explanation(
                    "Validate rule files before generating profiles.\n\n\
                     Validation checks:\n\
                     - YAML syntax\n\
                     - Rule structure (identifier, rule_type, policy)\n\
                     - Duplicate detection\n\n\
                     Use --strict to treat warnings as errors.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour santa validate {}",
                            output_dir.join("rules.yaml").display()
                        ),
                        "Validate the rules file",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour santa validate {} --strict",
                            output_dir.join("rules.yaml").display()
                        ),
                        "Validate with strict mode (warnings become errors)",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "santa".to_string(),
                        "validate".to_string(),
                        output_dir.join("rules.yaml").display().to_string(),
                    ],
                }),

            // Step 6: Generate Profiles
            TrainerStep::new(6, "Generate Santa Profiles")
                .with_explanation(
                    "Generate MDM-ready mobileconfig profiles from rule files.\n\n\
                     Output formats:\n\
                     - mobileconfig: Standard MDM profile (default)\n\
                     - plist: Workspace ONE compatible\n\
                     - plist-full: Jamf Pro custom schema\n\n\
                     Use `prep` for a complete deployment set that includes\n\
                     both rule profiles and Santa configuration.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour santa generate {} --org {} --deterministic-uuids --output {}",
                            output_dir.join("rules.yaml").display(),
                            org,
                            output_dir.join("santa-rules.mobileconfig").display()
                        ),
                        "Generate a mobileconfig from rules",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour santa prep {} --org {} --output-dir {}",
                            output_dir.join("rules.yaml").display(),
                            org,
                            output_dir.join("profiles").display()
                        ),
                        "Generate complete deployment set (rules + config)",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "santa".to_string(),
                        "prep".to_string(),
                        output_dir.join("rules.yaml").display().to_string(),
                        "--org".to_string(),
                        org.clone(),
                        "--output-dir".to_string(),
                        output_dir.join("profiles").display().to_string(),
                        "--deterministic-uuids".to_string(),
                    ],
                }),

            // Step 7: Git Commit
            TrainerStep::new(7, "Commit Changes to Git")
                .with_explanation(
                    "GitOps requires all configuration to be version-controlled.\n\n\
                     The commit should include:\n\
                     - santa.toml (project configuration)\n\
                     - rules.yaml (Santa rules)\n\
                     - profiles/*.mobileconfig (MDM profiles)\n\n\
                     Use a descriptive commit message that explains what changed.",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message: "feat(santa): Update allowlist with discovered applications\n\n\
                                  - Scanned fleet applications\n\
                                  - Generated Santa rules and profiles\n\
                                  - Ready for MDM deployment"
                            .to_string(),
                    },
                }),

            // Step 8: Create PR
            TrainerStep::new(8, "Create Pull Request")
                .with_explanation(
                    "Create a pull request for team review before deploying.\n\n\
                     The PR should:\n\
                     - Explain what applications are being allowed/blocked\n\
                     - Link to any relevant tickets or requests\n\
                     - Note the deployment plan\n\n\
                     After approval, merge and deploy profiles to your MDM.",
                )
                .with_osquery(OsqueryQuery::new(
                    "After deployment, verify Santa rules are synced to devices",
                    queries::SANTA_RULES,
                ))
                .with_action(StepAction::GitOperation {
                    op: GitOp::CreatePr {
                        title: "Update Santa allowlist with fleet applications".to_string(),
                        body: "## Summary\n\n\
                               - Scanned fleet applications\n\
                               - Generated Santa rules and profiles\n\
                               - Ready for MDM deployment\n\n\
                               ## Test Plan\n\n\
                               - [ ] Deploy to test group\n\
                               - [ ] Verify no false positives\n\
                               - [ ] Monitor Santa events for 24 hours\n\
                               - [ ] Roll out to broader fleet"
                            .to_string(),
                    },
                }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_santa_workflow_steps() {
        let workflow = SantaWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 8);
        assert_eq!(steps[0].title, "Initialize Santa Project");
        assert_eq!(steps[7].title, "Create Pull Request");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = SantaWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "Santa GitOps Workflow");
    }
}
