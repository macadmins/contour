//! Configuration workflow for trainer mode.
//!
//! This workflow guides users through the shared `.contour/config.toml`
//! file: how it is discovered, what each section does, and how the three
//! kinds of reference (`[vars]`, `[secrets]`, `[mdm_variables]`) differ.

use crate::trainer::TrainerWorkflow;
use crate::trainer::step::{CommandPreview, GitOp, StepAction, TrainerStep};

/// The Contour configuration workflow.
#[derive(Debug)]
pub struct ConfigWorkflow {
    /// Organization reverse-domain identifier.
    domain: String,
    /// Organization display name.
    name: String,
}

impl ConfigWorkflow {
    /// Create a new configuration workflow.
    #[must_use]
    pub fn new(domain: String, name: String) -> Self {
        Self { domain, name }
    }

    /// Create with default settings.
    #[must_use]
    pub fn default_workflow() -> Self {
        Self {
            domain: "com.example".to_string(),
            name: "Example Organization".to_string(),
        }
    }
}

impl TrainerWorkflow for ConfigWorkflow {
    fn name(&self) -> &'static str {
        "Contour Configuration Workflow"
    }

    fn description(&self) -> &'static str {
        "Understand the shared `.contour/config.toml` file — how contour discovers it, \
         what every section configures, and how static variables, secrets, and MDM \
         deploy-time variables differ. One config drives every contour toolkit."
    }

    fn steps(&self) -> Vec<TrainerStep> {
        let domain = &self.domain;
        let name = &self.name;

        vec![
            // Step 1: Understand .contour/config.toml
            TrainerStep::new(1, "Understand .contour/config.toml")
                .with_explanation(
                    "`.contour/config.toml` is contour's shared, cross-toolkit\n\
                     configuration — one file that `profile`, `mscp`, `pppc`, `btm`,\n\
                     `santa`, and `notifications` all read, so commands don't need\n\
                     repetitive flags.\n\n\
                     contour discovers it by walking UP the directory tree from two\n\
                     anchors:\n\
                     - the recipe path / recipe-file location (a preset library can\n\
                       carry its own config)\n\
                     - the current working directory\n\n\
                     When both exist, the CWD config wins on conflicts; map sections\n\
                     are merged key-by-key.\n\n\
                     Resolution order for any single value:\n\
                     CLI flag → profile.toml → CWD config → anchor config → built-in\n\
                     default.",
                )
                .with_action(StepAction::ConfirmContinue),

            // Step 2: Create the config
            TrainerStep::new(2, "Create the Config File")
                .with_explanation(
                    "`contour init` scaffolds `.contour/config.toml` at the repo root.\n\n\
                     Useful flags:\n\
                     - --domain: reverse-DNS identifier (the PayloadIdentifier prefix)\n\
                     - --name: organization display name\n\
                     - --mdm: fleet | jamf | apple — writes that platform's MDM\n\
                       variable catalogue into [mdm_variables] as a commented template\n\
                     - --yes: non-interactive (use flags/defaults, no prompts)",
                )
                .with_commands(vec![CommandPreview::new(
                    format!(
                        "contour init --domain {domain} --name \"{name}\" --mdm fleet --yes"
                    ),
                    "Scaffold .contour/config.toml with an MDM variable template",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "init".to_string(),
                        "--domain".to_string(),
                        domain.clone(),
                        "--name".to_string(),
                        name.clone(),
                        "--mdm".to_string(),
                        "fleet".to_string(),
                        "--yes".to_string(),
                    ],
                }),

            // Step 3: [organization] and [defaults]
            TrainerStep::new(3, "[organization] and [defaults]")
                .with_explanation(
                    "`[organization]` (the only required section) sets the identity\n\
                     stamped into every generated profile:\n\
                     - name: sets PayloadOrganization\n\
                     - domain: the reverse-DNS PayloadIdentifier prefix\n\
                     - server_url: optional MDM server URL\n\n\
                     `[defaults]` holds project-wide generation defaults:\n\
                     - platforms: restrict output to specific OSes\n\
                     - deterministic_uuids: reproducible UUIDs for GitOps\n\
                     - library_path: default --recipe-path / --into directory\n\
                     - manifests_path: external schema directory",
                )
                .with_action(StepAction::ConfirmContinue),

            // Step 4: [vars]
            TrainerStep::new(4, "[vars] — Static Substitutions")
                .with_explanation(
                    "`[vars]` defines static `{{PLACEHOLDER}}` substitutions. contour\n\
                     replaces them at GENERATE time — before the profile is written.\n\n\
                     ```toml\n\
                     [vars]\n\
                     OKTA_DOMAIN = \"acme.okta.com\"\n\
                     ```\n\n\
                     A recipe field `Domain = \"{{OKTA_DOMAIN}}\"` becomes\n\
                     `acme.okta.com` in the output. CLI `--set` and recipe-level\n\
                     values override `[vars]`.",
                )
                .with_action(StepAction::ConfirmContinue),

            // Step 5: [secrets]
            TrainerStep::new(5, "[secrets] — Resolved Credentials")
                .with_explanation(
                    "`[secrets]` keeps credentials out of committed recipes. A recipe\n\
                     field holds a REFERENCE; contour resolves it at generate time.\n\n\
                     Reference prefixes:\n\
                     - op://vault/item/field — a 1Password item (via the `op` CLI)\n\
                     - env:NAME — an env var, then a .env file\n\
                     - file:/path — file contents (emitted as binary Data)\n\
                     - secret:NAME — a named entry in the [secrets.refs] catalogue\n\n\
                     `contour profile generate --sanitize` leaves references\n\
                     unresolved, so a profile is safe to share or commit for review.\n\n\
                     Add .env to .gitignore — never commit it.",
                )
                .with_action(StepAction::ConfirmContinue),

            // Step 6: [mdm_variables]
            TrainerStep::new(6, "[mdm_variables] — MDM Deploy-Time Variables")
                .with_explanation(
                    "MDM deploy-time variables are tokens the MDM SERVER substitutes\n\
                     ON-DEVICE at deploy time — Jamf's $USERNAME, Fleet's\n\
                     FLEET_VAR_NDES_SCEP_CHALLENGE, and similar. contour passes them\n\
                     through VERBATIM; it never resolves them.\n\n\
                     `[mdm_variables].mdm` selects the flavour (fleet | jamf | apple) —\n\
                     this picks the catalogue contour validates tokens against.\n\
                     `[mdm_variables.pool]` maps a friendly name to a token (tokens\n\
                     may be combined with static text, e.g. `$USERNAME@acme.com`).\n\n\
                     A recipe field `Challenge = \"var:SCEP_CHALLENGE\"` resolves\n\
                     through the pool to the token, emitted verbatim for the MDM to\n\
                     substitute. List the valid tokens for your flavour with the\n\
                     command below.",
                )
                .with_commands(vec![CommandPreview::new(
                    "contour profile variables --mdm fleet",
                    "List the Fleet MDM variable catalogue and the configured pool",
                )])
                .with_action(StepAction::ContourCommand {
                    args: vec![
                        "profile".to_string(),
                        "variables".to_string(),
                        "--mdm".to_string(),
                        "fleet".to_string(),
                    ],
                }),

            // Step 7: [signing] and [validation]
            TrainerStep::new(7, "[signing] and [validation]")
                .with_explanation(
                    "`[signing]` supplies code-signing defaults for\n\
                     `contour profile sign` when no --identity flag is given:\n\
                     - identity: Developer ID Installer name or SHA-1 hash\n\
                     - team_id: Apple Developer Team ID\n\n\
                     `[validation]` sets the schema-validation policy:\n\
                     - fail_on_errors (default true): non-zero exit on schema errors\n\
                     - fail_on_warnings (default false): also fail on warnings\n\
                     - fail_on_deprecations (default false): the default for\n\
                       `profile scan --fail-on-deprecations`",
                )
                .with_action(StepAction::ConfirmContinue),

            // Step 8: The three reference kinds
            TrainerStep::new(8, "The Three Reference Kinds")
                .with_explanation(
                    "Recipes draw on three distinct kinds of reference — knowing\n\
                     which to use, and who substitutes it, is the key mental model:\n\n\
                     | Kind        | Section          | Syntax       | Substituted by | When     |\n\
                     |-------------|------------------|--------------|----------------|----------|\n\
                     | Static var  | [vars]           | {{NAME}}     | contour        | generate |\n\
                     | Secret      | [secrets]        | secret:NAME  | contour        | generate |\n\
                     | MDM variable| [mdm_variables]  | var:NAME     | the MDM server | deploy   |\n\n\
                     Commit `.contour/config.toml` so the whole team shares the same\n\
                     defaults. The full key-by-key reference is in\n\
                     docs/contour-config.md.",
                )
                .with_action(StepAction::GitOperation {
                    op: GitOp::Commit {
                        message: "chore(config): Add shared .contour/config.toml\n\n\
                                  - Organization identity and project defaults\n\
                                  - Static [vars], [secrets], and [mdm_variables] sections"
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
    fn test_config_workflow_steps() {
        let workflow = ConfigWorkflow::default_workflow();
        let steps = workflow.steps();

        assert_eq!(steps.len(), 8);
        assert_eq!(steps[0].title, "Understand .contour/config.toml");
        assert_eq!(steps[7].title, "The Three Reference Kinds");
    }

    #[test]
    fn test_workflow_description() {
        let workflow = ConfigWorkflow::default_workflow();
        assert!(!workflow.description().is_empty());
        assert_eq!(workflow.name(), "Contour Configuration Workflow");
    }
}
