//! Background Task Management (BTM) workflow for trainer mode.
//!
//! This workflow guides users through managing macOS login items and
//! launch agents/daemons with the Background Task Management toolkit:
//! scanning launch items, validating policy, and generating profiles.

use crate::trainer::TrainerWorkflow;
use crate::trainer::step::{CommandPreview, GitOp, StepAction, TrainerStep};
use std::path::PathBuf;

/// The Background Task Management workflow.
#[derive(Debug)]
pub struct BtmWorkflow {
    /// Path to the BTM policy configuration file.
    config_path: PathBuf,
    /// Organization identifier.
    org: String,
}

impl BtmWorkflow {
    /// Create a new BTM workflow.
    #[must_use]
    pub fn new(config_path: PathBuf, org: String) -> Self {
        Self { config_path, org }
    }

    /// Create with default settings.
    #[must_use]
    pub fn default_workflow() -> Self {
        Self {
            config_path: PathBuf::from("btm.toml"),
            org: "com.example".to_string(),
        }
    }
}

impl TrainerWorkflow for BtmWorkflow {
    fn name(&self) -> &'static str {
        "BTM Service Management Workflow"
    }

    fn description(&self) -> &'static str {
        "Manage macOS background task items — managed login items and launch \
         agents/daemons — with the Background Task Management toolkit. This workflow \
         scans launch items, validates a policy file, and generates Service Management \
         profiles and DDM declarations ready for MDM deployment."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let config_path = &self.config_path;
        let org = &self.org;
        let config = config_path.display().to_string();

        vec![
            // Step 1: Understand BTM
            TrainerStep::new(1, "Understand Background Task Management")
                .with_explanation(
                    "macOS 13+ ships Background Task Management (BTM), which tracks\n\
                     managed login items and launch agents/daemons.\n\n\
                     BTM covers:\n\
                     - Managed login items (apps that launch at login)\n\
                     - LaunchAgents (per-user background tasks)\n\
                     - LaunchDaemons (system-wide background tasks)\n\n\
                     Using the Service Management payload, an MDM can pre-approve\n\
                     these items so users are not prompted and cannot disable them.\n\
                     This workflow builds that policy and the profiles to enforce it.",
                )
                .with_action(StepAction::ConfirmContinue),
            // Step 2: Initialize Configuration
            TrainerStep::new(2, "Initialize BTM Configuration")
                .with_explanation(
                    "Create a btm.toml configuration file.\n\n\
                     The configuration file stores:\n\
                     - Organization identifier (reverse domain)\n\
                     - Default settings for scan and generate operations\n\n\
                     This ensures consistent settings across all BTM operations.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour btm init -o {config} --org {org}"),
                    "Create btm.toml configuration",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "btm".to_string(),
                        "init".to_string(),
                        "-o".to_string(),
                        config.clone(),
                        "--org".to_string(),
                        org.clone(),
                    ],
                }),
            // Step 3: Scan Launch Items
            TrainerStep::new(3, "Scan Launch Items")
                .with_explanation(
                    "Scan a directory for background task items.\n\n\
                     The scan inspects applications for:\n\
                     - Managed login items\n\
                     - Bundled LaunchAgents and LaunchDaemons\n\
                     - Code signing identifiers used for the Service Management rules\n\n\
                     The discovered items are written into the btm.toml policy file.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour btm scan -p /Applications -o {config} --org {org}"),
                    "Scan /Applications and populate the policy file",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "btm".to_string(),
                        "scan".to_string(),
                        "-p".to_string(),
                        "/Applications".to_string(),
                        "-o".to_string(),
                        config.clone(),
                        "--org".to_string(),
                        org.clone(),
                    ],
                }),
            // Step 4: Validate the Policy
            TrainerStep::new(4, "Validate the Policy")
                .with_explanation(
                    "Validate the btm.toml policy file before generating profiles.\n\n\
                     Validation checks:\n\
                     - TOML syntax\n\
                     - Required fields present (rule type, identifier)\n\
                     - Rule structure correct\n\
                     - Duplicate detection\n\n\
                     Fix any reported issues before continuing.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour btm validate {config}"),
                    "Validate the BTM policy file",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec!["btm".to_string(), "validate".to_string(), config.clone()],
                }),
            // Step 5: Generate Profiles
            TrainerStep::new(5, "Generate Service Management Profiles")
                .with_explanation(
                    "Generate MDM-ready Service Management mobileconfig profiles\n\
                     from the policy file.\n\n\
                     By default this produces one combined Service Management\n\
                     .mobileconfig covering every managed item.\n\n\
                     Use --per-app to emit one profile per application instead,\n\
                     which makes scoped deployment and review easier.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!("contour btm generate {config} -o ./profiles"),
                        "Generate one combined Service Management profile",
                    ),
                    CommandPreview::new(
                        format!("contour btm generate {config} --per-app -o ./profiles"),
                        "Generate one profile per application",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "btm".to_string(),
                        "generate".to_string(),
                        config.clone(),
                        "-o".to_string(),
                        "./profiles".to_string(),
                    ],
                }),
            // Step 6: DDM Declarations
            TrainerStep::new(6, "Generate DDM Declarations")
                .with_explanation(
                    "On macOS 15+, Declarative Device Management (DDM) can deliver\n\
                     background task policy as JSON declarations instead of profiles.\n\n\
                     The --ddm flag emits declarations of type\n\
                     com.apple.configuration.services.background-tasks, which the\n\
                     device evaluates declaratively.\n\n\
                     Use DDM when your MDM supports it for faster, more reliable\n\
                     state enforcement than legacy profiles.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour btm generate {config} --ddm -o ./ddm"),
                    "Generate DDM background-tasks declarations (macOS 15+)",
                )])
                .with_action(StepAction::ConfirmContinue),
            // Step 7: Recipe & Fragment Output
            TrainerStep::new(7, "Recipe and Fragment Output")
                .with_explanation(
                    "BTM can emit alternative output formats for integration with\n\
                     other Contour workflows and GitOps repositories.\n\n\
                     - --format recipe: emits a Contour recipe .toml carrying BOTH\n\
                       [[profile]] blocks (from mobileconfig rules) and [[ddm]]\n\
                       blocks (from DDM-capable rules) — one reusable template that\n\
                       covers both delivery paths, rendered later with\n\
                       `contour profile generate --recipe`.\n\
                     - --fragment: emits a Fleet GitOps fragment directory that\n\
                       can be referenced from a Fleet GitOps configuration.\n\n\
                     Pick the format that matches how you deploy.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!("contour btm generate {config} --format recipe -o ./recipes"),
                        "Emit a Contour recipe instead of a mobileconfig",
                    ),
                    CommandPreview::new(
                        format!("contour btm generate {config} --fragment -o btm-fragment"),
                        "Emit a Fleet GitOps fragment directory",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),
            // Step 8: Git Commit
            TrainerStep::new(8, "Commit Changes to Git")
                .with_explanation(
                    "Version control your BTM policy and generated profiles.\n\n\
                     The commit should include:\n\
                     - btm.toml (policy configuration)\n\
                     - profiles/*.mobileconfig (Service Management profiles)\n\
                     - ddm/ declarations (if generated)\n\n\
                     This enables auditing and rollback.",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message: "feat(btm): Manage background task items\n\n\
                                  - Scanned launch items into a BTM policy\n\
                                  - Generated Service Management profiles\n\
                                  - Ready for MDM deployment"
                            .to_string(),
                    },
                }),
            // Step 9: Create PR
            TrainerStep::new(9, "Create Pull Request")
                .with_explanation(
                    "Open a pull request for review before deploying.\n\n\
                     BTM changes should be reviewed for:\n\
                     - Only intended login items and daemons are managed\n\
                     - No unexpected applications are pre-approved\n\
                     - Rollout strategy (staged deployment)",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::CreatePr {
                        title: "Manage background task items with BTM".to_string(),
                        body: "## Summary\n\n\
                               Generated Service Management profiles for managed\n\
                               login items and launch agents/daemons.\n\n\
                               ## Changes\n\n\
                               - [ ] Scanned launch items into btm.toml\n\
                               - [ ] Generated Service Management profiles\n\
                               - [ ] Generated DDM declarations (if applicable)\n\n\
                               ## Test Plan\n\n\
                               - [ ] Deploy to test device\n\
                               - [ ] Verify login items are pre-approved\n\
                               - [ ] Confirm no unexpected prompts\n\
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
    fn test_btm_workflow_steps() {
        let workflow = BtmWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 9);
        assert_eq!(steps[0].title, "Understand Background Task Management");
        assert_eq!(steps[8].title, "Create Pull Request");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = BtmWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "BTM Service Management Workflow");
    }
}
