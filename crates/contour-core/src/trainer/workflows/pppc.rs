//! PPPC/TCC GitOps workflow for trainer mode.
//!
//! This workflow guides users through creating Privacy Preferences Policy Control
//! (PPPC/TCC) profiles for MDM deployment.

use crate::trainer::TrainerWorkflow;
use crate::trainer::queries::pppc as queries;
use crate::trainer::step::{CommandPreview, GitOp, OsqueryQuery, StepAction, TrainerStep};
use std::path::PathBuf;

/// The PPPC GitOps workflow.
#[derive(Debug)]
pub struct PppcWorkflow {
    /// The output directory for generated files.
    output_dir: PathBuf,
    /// Organization identifier.
    org: String,
}

impl PppcWorkflow {
    /// Create a new PPPC workflow.
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

impl TrainerWorkflow for PppcWorkflow {
    fn name(&self) -> &'static str {
        "PPPC/TCC GitOps Workflow"
    }

    fn description(&self) -> &'static str {
        "Create Privacy Preferences Policy Control (PPPC/TCC) profiles for MDM deployment. \
         This workflow scans applications, configures privacy permissions, and generates \
         mobileconfig profiles that grant TCC permissions without user prompts."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let output_dir = &self.output_dir;
        let org = &self.org;

        vec![
            // Step 1: Understand TCC
            TrainerStep::new(1, "Understand TCC Permissions")
                .with_explanation(
                    "TCC (Transparency, Consent, and Control) manages privacy permissions on macOS.\n\n\
                     Common TCC services include:\n\
                     - SystemPolicyAllFiles: Full Disk Access\n\
                     - Accessibility: Control the computer\n\
                     - ScreenCapture: Record screen content\n\
                     - Camera/Microphone: Access AV hardware\n\
                     - AddressBook/Calendar: Access user data\n\n\
                     PPPC profiles pre-approve these permissions via MDM, avoiding user prompts.",
                )
                .with_osquery(OsqueryQuery::new(
                    "Find apps that may need TCC permissions",
                    queries::DISCOVER_APPS,
                ))
                .with_action(StepAction::ConfirmContinue),

            // Step 2: Scan Applications
            TrainerStep::new(2, "Scan Applications")
                .with_explanation(
                    "First, we scan applications to extract their code signing requirements.\n\n\
                     The scan extracts:\n\
                     - Bundle identifier (e.g., com.google.Chrome)\n\
                     - Code requirement (cryptographic identity)\n\
                     - Designated requirement (developer identity)\n\n\
                     These identifiers are needed for PPPC profiles to correctly identify apps.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour pppc scan --path /Applications --org {} --output {}",
                            org,
                            output_dir.join("pppc.toml").display()
                        ),
                        "Scan /Applications and create policy file",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour pppc scan --path /Applications --interactive --org {} --output {}",
                            org,
                            output_dir.join("pppc.toml").display()
                        ),
                        "Interactive mode: select apps and permissions",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "pppc".to_string(),
                        "scan".to_string(),
                        "--path".to_string(),
                        "/Applications".to_string(),
                        "--org".to_string(),
                        org.clone(),
                        "--output".to_string(),
                        output_dir.join("pppc.toml").display().to_string(),
                        "--interactive".to_string(),
                    ],
                }),

            // Step 3: Review Policy File
            TrainerStep::new(3, "Review Policy File")
                .with_explanation(
                    "The pppc.toml file contains your policy definitions.\n\n\
                     Each app entry has:\n\
                     - identifier: Bundle ID or path\n\
                     - code_requirement: Cryptographic identity string\n\
                     - services: List of TCC services to grant\n\
                     - comment: Description for documentation\n\n\
                     You can edit this file to add/remove apps or change permissions.",
                )
                .with_action(StepAction::ShowFile {
                    path: output_dir.join("pppc.toml"),
                }),

            // Step 4: Configure Services
            TrainerStep::new(4, "Configure Services (Optional)")
                .with_explanation(
                    "Use the configure command to interactively adjust permissions.\n\n\
                     For each app, you can toggle:\n\
                     - TCC services (FDA, Accessibility, etc.)\n\
                     - Notification settings\n\
                     - Service management (login items)\n\n\
                     This is optional if you already configured during scan.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour pppc configure {}",
                        output_dir.join("pppc.toml").display()
                    ),
                    "Interactively configure app permissions",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "pppc".to_string(),
                        "configure".to_string(),
                        output_dir.join("pppc.toml").display().to_string(),
                    ],
                }),

            // Step 5: Generate Profiles
            TrainerStep::new(5, "Generate mobileconfig Profiles")
                .with_explanation(
                    "Now we generate the actual mobileconfig profiles for MDM.\n\n\
                     Options:\n\
                     - Per-app profiles (default): One profile per app, easier to manage\n\
                     - Combined profile (--combined): Single profile for all apps\n\n\
                     Per-app profiles are recommended for flexibility - you can deploy\n\
                     different apps to different device groups.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour pppc generate {} --output {}",
                            output_dir.join("pppc.toml").display(),
                            output_dir.join("profiles").display()
                        ),
                        "Generate per-app profiles",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour pppc generate {} --combined --output {}",
                            output_dir.join("pppc.toml").display(),
                            output_dir.join("pppc-combined.mobileconfig").display()
                        ),
                        "Generate single combined profile",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "pppc".to_string(),
                        "generate".to_string(),
                        output_dir.join("pppc.toml").display().to_string(),
                        "--output".to_string(),
                        output_dir.join("profiles").display().to_string(),
                    ],
                }),

            // Step 6: Review Generated Profiles
            TrainerStep::new(6, "Review Generated Profiles")
                .with_explanation(
                    "Check the generated profiles before deployment.\n\n\
                     Each profile contains:\n\
                     - PayloadType: com.apple.TCC.configuration-profile-policy\n\
                     - Services dictionary with allowed apps\n\
                     - StaticCode: true (apps verified at install time)\n\n\
                     You can use `plutil -lint` to validate the XML structure.",
                )
                .with_action(StepAction::ShowFile {
                    path: output_dir.join("profiles"),
                }),

            // Step 7: Git Commit
            TrainerStep::new(7, "Commit Changes to Git")
                .with_explanation(
                    "Version control your PPPC configurations.\n\n\
                     Commit should include:\n\
                     - pppc.toml (policy definitions)\n\
                     - profiles/*.mobileconfig (generated profiles)\n\n\
                     This enables GitOps workflows and change tracking.",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message: "feat(pppc): Add privacy permission profiles\n\n\
                                  - Scanned applications for TCC requirements\n\
                                  - Configured privacy permissions\n\
                                  - Generated PPPC mobileconfig profiles"
                            .to_string(),
                    },
                }),

            // Step 8: Create PR
            TrainerStep::new(8, "Create Pull Request")
                .with_explanation(
                    "Open a pull request for review before deploying.\n\n\
                     PPPC profiles grant sensitive permissions, so review carefully:\n\
                     - Are all listed apps legitimate?\n\
                     - Are the permissions appropriate?\n\
                     - Is Full Disk Access really needed?\n\n\
                     After deployment, verify permissions with osquery.",
                )
                .with_osquery(OsqueryQuery::new(
                    "Verify app signatures match profile requirements",
                    queries::APP_SIGNATURES,
                ))
                .with_action(StepAction::GitOperation {
                    op: GitOp::CreatePr {
                        title: "Add PPPC/TCC profiles for fleet applications".to_string(),
                        body: "## Summary\n\n\
                               - Scanned applications for code requirements\n\
                               - Configured TCC permissions per security policy\n\
                               - Generated mobileconfig profiles for MDM\n\n\
                               ## Permissions Granted\n\n\
                               - [ ] List apps and their permissions here\n\n\
                               ## Test Plan\n\n\
                               - [ ] Deploy to test devices\n\
                               - [ ] Verify apps work without TCC prompts\n\
                               - [ ] Confirm no unexpected permission grants"
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
    fn test_pppc_workflow_steps() {
        let workflow = PppcWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 8);
        assert_eq!(steps[0].title, "Understand TCC Permissions");
        assert_eq!(steps[7].title, "Create Pull Request");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = PppcWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "PPPC/TCC GitOps Workflow");
    }
}
