//! Profile management workflow for trainer mode.
//!
//! This workflow guides users through working with Apple configuration profiles:
//! validation, normalization, signing, and documentation.

use crate::trainer::TrainerWorkflow;
use crate::trainer::step::{CommandPreview, GitOp, StepAction, TrainerStep};
use std::path::PathBuf;

/// The Profile management workflow.
#[derive(Debug)]
pub struct ProfileWorkflow {
    /// The input profile path.
    profile_path: PathBuf,
    /// Organization identifier.
    org: String,
}

impl ProfileWorkflow {
    /// Create a new Profile workflow.
    #[must_use]
    pub fn new(profile_path: PathBuf, org: String) -> Self {
        Self { profile_path, org }
    }

    /// Create with default settings.
    #[must_use]
    pub fn default_workflow() -> Self {
        Self {
            profile_path: PathBuf::from("."),
            org: "com.example".to_string(),
        }
    }
}

impl TrainerWorkflow for ProfileWorkflow {
    fn name(&self) -> &'static str {
        "Profile Management Workflow"
    }

    fn description(&self) -> &'static str {
        "Work with Apple configuration profiles: scan, validate, normalize, detect \
         cross-profile collisions, sign, and document. \
         This workflow helps ensure profiles are properly formatted, have valid UUIDs, \
         don't split a payload domain across files, and are ready for MDM deployment."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let profile_path = &self.profile_path;
        let org = &self.org;

        vec![
            // Step 1: Initialize Configuration
            TrainerStep::new(1, "Initialize Profile Configuration")
                .with_explanation(
                    "Start by creating a profile.toml configuration file.\n\n\
                     The configuration file stores:\n\
                     - Organization identifier (reverse domain)\n\
                     - Organization name\n\
                     - Default settings for profile operations\n\n\
                     This ensures consistent settings across all profile operations.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour profile init --org {org} --name \"Your Organization\""),
                    "Create profile.toml configuration",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "init".to_string(),
                        "--org".to_string(),
                        org.clone(),
                    ],
                }),
            // Step 2: Scan Profiles
            TrainerStep::new(2, "Scan Existing Profiles")
                .with_explanation(
                    "Scan profiles to see their current metadata.\n\n\
                     The scan shows:\n\
                     - PayloadIdentifier and PayloadUUID\n\
                     - PayloadDisplayName and description\n\
                     - Payload types included\n\
                     - Signature status\n\n\
                     Use --simulate to preview normalization changes.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!("contour profile scan {}", profile_path.display()),
                        "Scan profile metadata",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile scan {} --simulate --org {}",
                            profile_path.display(),
                            org
                        ),
                        "Preview normalization changes",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "scan".to_string(),
                        profile_path.display().to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 3: Scan for Deprecations
            TrainerStep::new(3, "Scan for Deprecations")
                .with_explanation(
                    "Scan profiles for payload types and keys that Apple has retired.\n\n\
                     The --deprecations flag flags settings that:\n\
                     - Use payload types Apple has deprecated\n\
                     - Reference keys that newer OS versions ignore\n\
                     - Should be migrated before they stop working\n\n\
                     Use --md-report deprecations.md to write a Markdown report,\n\
                     and --fail-on-deprecations to turn the scan into a CI gate\n\
                     that fails the build when deprecated settings are found.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour profile scan {} --deprecations --recursive",
                            profile_path.display()
                        ),
                        "Flag deprecated payload types and keys",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile scan {} --deprecations --recursive --md-report deprecations.md",
                            profile_path.display()
                        ),
                        "Write a Markdown deprecations report",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile scan {} --deprecations --recursive --fail-on-deprecations",
                            profile_path.display()
                        ),
                        "Fail the build when deprecated settings are found (CI gate)",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "scan".to_string(),
                        profile_path.display().to_string(),
                        "--deprecations".to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 4: Validate Profiles
            TrainerStep::new(4, "Validate Against Schema")
                .with_explanation(
                    "Validate profiles against Apple's schema definitions.\n\n\
                     Validation checks:\n\
                     - Required fields present\n\
                     - Field types correct\n\
                     - Value ranges valid\n\
                     - Payload structure correct\n\n\
                     Use --strict to treat warnings as errors.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour profile validate {} --recursive",
                        profile_path.display()
                    ),
                    "Validate profiles against schema",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "validate".to_string(),
                        profile_path.display().to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 5: Normalize Profiles
            TrainerStep::new(5, "Normalize Profile Identifiers")
                .with_explanation(
                    "Normalize profiles to use consistent identifiers and UUIDs.\n\n\
                     Normalization:\n\
                     - Sets PayloadIdentifier to org.type.name format\n\
                     - Regenerates UUIDs (unless --no-uuid)\n\
                     - Standardizes PayloadOrganization\n\
                     - Cleans up formatting\n\n\
                     Use --dry-run to preview changes.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour profile normalize {} --org {} --dry-run",
                            profile_path.display(),
                            org
                        ),
                        "Preview normalization changes",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile normalize {} --org {} --output {}",
                            profile_path.display(),
                            org,
                            profile_path.join("normalized").display()
                        ),
                        "Normalize and write to output directory",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "normalize".to_string(),
                        profile_path.display().to_string(),
                        "--org".to_string(),
                        org.clone(),
                        "--dry-run".to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 6: Generate from a Recipe
            TrainerStep::new(6, "Generate from a Recipe")
                .with_explanation(
                    "Recipes are reusable TOML profile templates. Instead of\n\
                     hand-authoring a mobileconfig, you generate one from a recipe.\n\n\
                     Contour ships built-in recipes, and you can build your own\n\
                     library of presets:\n\
                     - List built-in recipes to see what is available\n\
                     - Generate a profile from a named recipe\n\
                     - Create a preset library, then import existing vendor\n\
                       profiles into it as new recipes\n\n\
                     A recipe library keeps profile templates version-controlled\n\
                     and shareable across teams.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        "contour profile generate --list-recipes",
                        "List built-in recipes",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile generate --recipe <name> --org {org} -o build"
                        ),
                        "Generate a profile from a named recipe",
                    ),
                    CommandPreview::new(
                        "contour profile library new ./contour-presets",
                        "Create a new recipe library",
                    ),
                    CommandPreview::new(
                        "contour profile library import ./vendor-profiles --into ./contour-presets",
                        "Import existing vendor profiles into the library",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "generate".to_string(),
                        "--list-recipes".to_string(),
                    ],
                }),
            // Step 7: Secrets & MDM Variables
            TrainerStep::new(7, "Secrets and MDM Variables")
                .with_explanation(
                    "Recipes keep sensitive and deploy-time values out of the\n\
                     template itself. There are two distinct mechanisms.\n\n\
                     (a) Secrets — recipe fields hold a *reference*, never a\n\
                     literal value. Supported reference schemes:\n\
                     - op://vault/item/field  (1Password)\n\
                     - env:NAME               (environment variable / .env)\n\
                     - secret:NAME            ([secrets] config catalogue)\n\
                     Run generate with --sanitize to leave these references\n\
                     unresolved, producing output safe to share or commit.\n\n\
                     (b) MDM deploy-time variables — tokens like $USERNAME or\n\
                     FLEET_VAR_* that the MDM server substitutes on-device at\n\
                     install time. Declare them in [mdm_variables], reference\n\
                     them with var:NAME, and list them per MDM with the\n\
                     variables command.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!(
                            "contour profile generate --recipe <name> --org {org} --sanitize -o build"
                        ),
                        "Generate with secret references left unresolved",
                    ),
                    CommandPreview::new(
                        "contour profile variables --mdm fleet",
                        "List MDM deploy-time variables for Fleet",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),
            // Step 8: Manage UUIDs
            TrainerStep::new(8, "Manage Profile UUIDs")
                .with_explanation(
                    "Control UUID generation for reproducible builds.\n\n\
                     Options:\n\
                     - Random UUIDs (default): New UUID each time\n\
                     - Predictable UUIDs (--predictable): Derived from content\n\n\
                     Predictable UUIDs are useful for GitOps workflows where\n\
                     identical input should produce identical output.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour profile uuid {} --predictable --org {}",
                        profile_path.display(),
                        org
                    ),
                    "Generate predictable UUIDs",
                )])
                .with_action(StepAction::ConfirmContinue),
            // Step 9: Sign Profiles (Optional)
            TrainerStep::new(9, "Sign Profiles (Optional)")
                .with_explanation(
                    "Sign profiles with a Developer ID certificate.\n\n\
                     Signing:\n\
                     - Verifies profile integrity\n\
                     - Shows organization in System Preferences\n\
                     - Required for some MDM workflows\n\n\
                     You need a Developer ID Installer certificate in your keychain.\n\
                     Use 'contour profile identities' to list available certificates.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        "contour profile identities",
                        "List available signing identities",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile sign {} --identity \"Developer ID Installer: Your Org\"",
                            profile_path.display()
                        ),
                        "Sign profiles with certificate",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),
            // Step 10: Verify Signatures
            TrainerStep::new(10, "Verify Signatures")
                .with_explanation(
                    "Verify that signed profiles have valid signatures.\n\n\
                     Verification checks:\n\
                     - Signature is present and valid\n\
                     - Certificate is trusted\n\
                     - Profile hasn't been modified\n\n\
                     Unsigned profiles will be flagged.",
                )
                .with_commands(vec![CommandPreview::new(
                    format!("contour profile verify {}", profile_path.display()),
                    "Verify profile signatures",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "verify".to_string(),
                        profile_path.display().to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 11: Generate Documentation
            TrainerStep::new(11, "Generate Documentation")
                .with_explanation(
                    "Generate markdown documentation for your profiles.\n\n\
                     Documentation includes:\n\
                     - Payload types and their settings\n\
                     - Available keys and their defaults\n\
                     - Configured vs available options\n\n\
                     Useful for internal documentation and onboarding.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        "contour profile docs list",
                        "List available payload documentation",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile docs from-profile {}",
                            profile_path.display()
                        ),
                        "Generate docs from existing profile",
                    ),
                ])
                .with_action(StepAction::ConfirmContinue),
            // Step 12: Detect cross-profile collisions
            TrainerStep::new(12, "Detect Cross-Profile Collisions")
                .with_explanation(
                    "Check whether two separate profiles manage the SAME payload \
                     domain (PayloadType) — macOS does not reliably merge those, so \
                     it's a deployment hazard.\n\n\
                     Per key, `collisions` reports a verdict:\n\
                     - conflict: same key, different values (the dangerous case)\n\
                     - redundant: same value everywhere (safe to dedupe)\n\
                     - complementary: set in only one (the keys to port when merging)\n\n\
                     Scope is per-directory by default (so separate tenants don't \
                     false-positive); --flat asks 'if ONE host got every profile here, \
                     what would be split?'. Use --fail-on-conflict as a CI gate.",
                )
                .with_commands(vec![
                    CommandPreview::new(
                        format!("contour profile collisions {} -r", profile_path.display()),
                        "Per-directory collision scan",
                    ),
                    CommandPreview::new(
                        format!(
                            "contour profile collisions {} -r --flat --fail-on-conflict --md-report collisions.md",
                            profile_path.display()
                        ),
                        "Whole-repo view + CI gate + markdown matrix",
                    ),
                ])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "collisions".to_string(),
                        profile_path.display().to_string(),
                        "--recursive".to_string(),
                    ],
                }),
            // Step 13: Git Commit
            TrainerStep::new(13, "Commit Changes to Git")
                .with_explanation(
                    "Commit your normalized and validated profiles.\n\n\
                     Include:\n\
                     - Updated profile files\n\
                     - profile.toml configuration\n\
                     - Generated documentation (if any)",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message:
                            "chore(profiles): Normalize and validate configuration profiles\n\n\
                                  - Standardized PayloadIdentifiers\n\
                                  - Regenerated UUIDs for consistency\n\
                                  - Validated against Apple schema"
                                .to_string(),
                    },
                }),
            // Step 13: Create PR
            TrainerStep::new(14, "Create Pull Request")
                .with_explanation(
                    "Create a pull request for profile changes.\n\n\
                     Profile changes should be reviewed for:\n\
                     - Correct payload settings\n\
                     - Appropriate targeting\n\
                     - No sensitive data exposed",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::CreatePr {
                        title: "Normalize and validate configuration profiles".to_string(),
                        body: "## Summary\n\n\
                               Normalized and validated configuration profiles.\n\n\
                               ## Changes\n\n\
                               - [ ] Standardized identifiers\n\
                               - [ ] Updated UUIDs\n\
                               - [ ] Fixed validation issues\n\n\
                               ## Validation\n\n\
                               - [ ] All profiles pass schema validation\n\
                               - [ ] Signatures verified (if applicable)\n\n\
                               ## Test Plan\n\n\
                               - [ ] Deploy to test device\n\
                               - [ ] Verify settings applied correctly"
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
    fn test_profile_workflow_steps() {
        let workflow = ProfileWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 14);
        assert_eq!(steps[0].title, "Initialize Profile Configuration");
        assert_eq!(steps[2].title, "Scan for Deprecations");
        assert_eq!(steps[5].title, "Generate from a Recipe");
        assert_eq!(steps[6].title, "Secrets and MDM Variables");
        assert_eq!(steps[11].title, "Detect Cross-Profile Collisions");
        assert_eq!(steps[13].title, "Create Pull Request");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = ProfileWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "Profile Management Workflow");
    }
}
