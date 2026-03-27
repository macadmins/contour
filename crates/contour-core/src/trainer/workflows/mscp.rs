//! mSCP baseline workflow for trainer mode.
//!
//! This workflow guides users through generating security baselines using
//! the macOS Security Compliance Project (mSCP).

use crate::trainer::TrainerWorkflow;
use crate::trainer::queries::mscp as queries;
use crate::trainer::step::{CommandPreview, GitOp, OsqueryQuery, StepAction, TrainerStep};
use std::path::PathBuf;

/// The mSCP GitOps workflow.
#[derive(Debug)]
pub struct MscpWorkflow {
    /// The output directory for generated files.
    output_dir: PathBuf,
    /// Path to the mSCP repository.
    mscp_repo: PathBuf,
    /// Organization identifier.
    org: String,
    /// Default baseline to use.
    baseline: String,
}

impl MscpWorkflow {
    /// Create a new mSCP workflow.
    #[must_use]
    pub fn new(output_dir: PathBuf, mscp_repo: PathBuf, org: String, baseline: String) -> Self {
        Self {
            output_dir,
            mscp_repo,
            org,
            baseline,
        }
    }

    /// Create with default settings.
    #[must_use]
    pub fn default_workflow() -> Self {
        Self {
            output_dir: PathBuf::from("./fleet-gitops"),
            mscp_repo: PathBuf::from("./macos_security"),
            org: "com.example".to_string(),
            baseline: "cis_lvl1".to_string(),
        }
    }
}

impl TrainerWorkflow for MscpWorkflow {
    fn name(&self) -> &'static str {
        "mSCP Security Baseline Workflow"
    }

    fn description(&self) -> &'static str {
        "Generate security compliance baselines using the macOS Security Compliance Project (mSCP). \
         This workflow clones mSCP, generates baselines, transforms output for MDM deployment, \
         and creates GitOps-compatible configurations."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let output_dir = &self.output_dir;
        let mscp_repo = &self.mscp_repo;
        let org = &self.org;
        let baseline = &self.baseline;

        vec![
            // Step 1: Understand mSCP
            TrainerStep::new(1, "Understand mSCP Baselines")
                .with_explanation(
                    "The macOS Security Compliance Project (mSCP) provides security baselines\n\
                     based on industry standards:\n\n\
                     - CIS Benchmarks (cis_lvl1, cis_lvl2)\n\
                     - NIST 800-53 (800-53r5_low, 800-53r5_moderate, 800-53r5_high)\n\
                     - DISA STIG (stig)\n\
                     - CMMC (cmmc_lvl1, cmmc_lvl2)\n\n\
                     Each baseline generates mobileconfig profiles and scripts for compliance.\n\n\
                     Note: Platform (macOS/iOS) is determined by the mSCP branch:\n\
                     - tahoe = macOS 26.x, sequoia = macOS 15.x, sonoma = macOS 14.x\n\
                     - ios_18 = iOS 18",
                )
                .with_osquery(OsqueryQuery::new(
                    "Check current security settings on your fleet",
                    queries::SECURITY_SETTINGS,
                ))
                .with_action(StepAction::ConfirmContinue),

            // Step 2: Initialize Project
            TrainerStep::new(2, "Initialize Contour Project")
                .with_explanation(
                    "The init command sets up a Contour mSCP project with configuration files.\n\n\
                     Options:\n\
                     - --fleet: Enable Fleet GitOps mode\n\
                     - --jamf: Enable Jamf Pro mode\n\
                     - --sync: Clone the mSCP repository\n\
                     - --baselines: Pre-select baselines to enable\n\n\
                     This creates mscp.toml with your organization settings.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour mscp init --output {} --org {} --fleet --sync",
                            output_dir.display(),
                            org
                        ),
                        "Initialize project with Fleet mode and clone mSCP",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "mscp".to_string(),
                        "init".to_string(),
                        "--output".to_string(),
                        output_dir.display().to_string(),
                        "--org".to_string(),
                        org.clone(),
                        "--fleet".to_string(),
                        "--sync".to_string(),
                    ],
                }),

            // Step 3: List Available Baselines
            TrainerStep::new(3, "List Available Baselines")
                .with_explanation(
                    "See what baselines are available in the mSCP repository.\n\n\
                     Common baselines:\n\
                     - cis_lvl1: CIS Level 1 (recommended starting point)\n\
                     - cis_lvl2: CIS Level 2 (more restrictive)\n\
                     - 800-53r5_moderate: NIST 800-53 Rev 5 Moderate\n\
                     - stig: DISA STIG for macOS\n\n\
                     Choose based on your compliance requirements.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour mscp list-baselines --mscp-repo {}",
                        mscp_repo.display()
                    ),
                    "List baselines in the mSCP repository",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "mscp".to_string(),
                        "list-baselines".to_string(),
                        "--mscp-repo".to_string(),
                        mscp_repo.display().to_string(),
                    ],
                }),

            // Step 4: Configure Constraints (Optional)
            TrainerStep::new(4, "Configure Constraints (Optional)")
                .with_explanation(
                    "Constraints let you exclude specific rules or categories.\n\n\
                     Common exclusions:\n\
                     - audit: Skip audit-only rules (no remediation)\n\
                     - smartcard: Skip smartcard requirements\n\
                     - supplemental: Skip supplemental rules\n\n\
                     Use the interactive constraints command to select exclusions.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour mscp constraints add-categories --mscp-repo {} --baseline {}",
                            mscp_repo.display(),
                            baseline
                        ),
                        "Interactively select categories to exclude",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),

            // Step 5: Configure ODVs (Optional)
            TrainerStep::new(5, "Configure ODVs (Optional)")
                .with_explanation(
                    "Organization Defined Values (ODVs) let you customize rule parameters.\n\n\
                     Common ODVs:\n\
                     - Password minimum length (default: 15)\n\
                     - Account lockout threshold (default: 3)\n\
                     - Screen saver idle time (default: 1200 seconds)\n\
                     - Inactivity logout time (default: 86400 seconds)\n\n\
                     Initialize an ODV file, edit the values, then pass it to generate.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour mscp odv init --mscp-repo {} --baseline {} --output {}/odv-{}.yaml",
                            mscp_repo.display(),
                            baseline,
                            output_dir.display(),
                            baseline
                        ),
                        "Create ODV file with baseline defaults",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour mscp odv list --mscp-repo {} --baseline {}",
                            mscp_repo.display(),
                            baseline
                        ),
                        "List available ODVs for this baseline",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),

            // Step 6: Generate Baseline
            TrainerStep::new(6, "Generate Security Baseline")
                .with_explanation(
                    "The generate command runs mSCP and transforms the output.\n\n\
                     This produces:\n\
                     - mobileconfig profiles for each rule category\n\
                     - Remediation scripts (check and fix)\n\
                     - Fleet/Jamf manifests for deployment\n\
                     - Documentation and compliance mapping\n\n\
                     Use --odv to apply custom values, --deterministic-uuids for reproducible builds.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour mscp generate --mscp-repo {} --baseline {} --output {} --org {} --fleet-mode --deterministic-uuids",
                            mscp_repo.display(),
                            baseline,
                            output_dir.display(),
                            org
                        ),
                        "Generate baseline with Fleet mode",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour mscp generate --mscp-repo {} --baseline {} --output {} --org {} --odv odv-{}.yaml --fleet-mode",
                            mscp_repo.display(),
                            baseline,
                            output_dir.display(),
                            org,
                            baseline
                        ),
                        "Generate with custom ODV values",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "mscp".to_string(),
                        "generate".to_string(),
                        "--mscp-repo".to_string(),
                        mscp_repo.display().to_string(),
                        "--baseline".to_string(),
                        baseline.clone(),
                        "--output".to_string(),
                        output_dir.display().to_string(),
                        "--org".to_string(),
                        org.clone(),
                        "--fleet-mode".to_string(),
                        "--deterministic-uuids".to_string(),
                    ],
                }),

            // Step 7: Validate Output
            TrainerStep::new(7, "Validate Generated Output")
                .with_explanation(
                    "Validate the generated profiles and scripts.\n\n\
                     Validation checks:\n\
                     - Profile XML structure (plutil -lint)\n\
                     - Required fields present\n\
                     - Cross-references intact\n\
                     - Script syntax valid",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour mscp validate --output {}", output_dir.display()),
                    "Validate all generated files",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "mscp".to_string(),
                        "validate".to_string(),
                        "--output".to_string(),
                        output_dir.display().to_string(),
                    ],
                }),

            // Step 8: Review Diff (if updating)
            TrainerStep::new(8, "Review Changes")
                .with_explanation(
                    "If updating an existing baseline, review what changed.\n\n\
                     The diff command shows:\n\
                     - New rules added\n\
                     - Rules removed\n\
                     - Changed configurations\n\
                     - Version updates",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour mscp diff --output {} --baseline {}",
                        output_dir.display(),
                        baseline
                    ),
                    "Show changes from previous version",
                )])
                .with_osquery(OsqueryQuery::new(
                    "Check FileVault status before enforcing encryption rules",
                    queries::FILEVAULT_STATUS,
                ))
                .with_action(StepAction::ConfirmContinue),

            // Step 9: Git Commit
            TrainerStep::new(9, "Commit Changes to Git")
                .with_explanation(
                    "Version control your security baselines.\n\n\
                     Commit should include:\n\
                     - lib/baselines/<baseline>/ (profiles and scripts)\n\
                     - mscp.toml (configuration)\n\
                     - constraints files (exclusions)\n\n\
                     This enables auditing and rollback.",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message: format!(
                            "feat(mscp): Update {baseline} security baseline\n\n\
                             - Generated from mSCP with Fleet mode\n\
                             - Deterministic UUIDs for reproducible builds\n\
                             - Ready for MDM deployment"
                        ),
                    },
                }),

            // Step 10: Create PR
            TrainerStep::new(10, "Create Pull Request")
                .with_explanation(
                    "Open a pull request for security review.\n\n\
                     Security baseline changes should be reviewed for:\n\
                     - Appropriate restrictions for your environment\n\
                     - User impact (password policies, encryption, etc.)\n\
                     - Compatibility with existing configurations\n\
                     - Rollout strategy (staged deployment)",
                )
                .with_osquery(OsqueryQuery::new(
                    "Check Gatekeeper and SIP status fleet-wide",
                    queries::GATEKEEPER_STATUS,
                ))
                .with_action(StepAction::GitOperation {
                    op: GitOp::CreatePr {
                        title: format!("Update {baseline} security baseline"),
                        body: format!(
                            "## Summary\n\n\
                             Updated {baseline} security baseline from mSCP.\n\n\
                             ## Changes\n\n\
                             - [ ] List significant rule changes\n\n\
                             ## Impact\n\n\
                             - [ ] Password policy changes\n\
                             - [ ] FileVault enforcement\n\
                             - [ ] Screen saver settings\n\n\
                             ## Rollout Plan\n\n\
                             - [ ] Deploy to IT pilot group\n\
                             - [ ] Monitor for 1 week\n\
                             - [ ] Expand to early adopters\n\
                             - [ ] Full fleet deployment"
                        ),
                    },
                }),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mscp_workflow_steps() {
        let workflow = MscpWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 10);
        assert_eq!(steps[0].title, "Understand mSCP Baselines");
        assert_eq!(steps[4].title, "Configure ODVs (Optional)");
        assert_eq!(steps[9].title, "Create Pull Request");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = MscpWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "mSCP Security Baseline Workflow");
    }
}
