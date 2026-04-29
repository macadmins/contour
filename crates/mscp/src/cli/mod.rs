//! CLI command definitions and handlers.
//!
//! This module defines all mscp CLI commands using clap derive macros.

pub mod baseline_mgmt;
pub mod config_generate;
pub mod constraints;
pub mod deduplicate;
pub mod diff;
pub mod extract_scripts;
pub mod generate;
pub mod glob_interactive;
pub mod info;
pub mod init;
pub mod odv;
pub mod process;
pub mod schema_cmd;
pub mod validate;

pub use baseline_mgmt::*;
pub use config_generate::*;
pub use constraints::{
    constraints_add, constraints_add_categories, constraints_add_script, constraints_list,
    constraints_list_scripts, constraints_remove, constraints_remove_script,
};
pub use deduplicate::*;
pub use diff::*;
pub use extract_scripts::*;
pub use generate::*;
pub use info::*;
pub use init::*;
pub use odv::{odv_edit, odv_init, odv_list};
pub use process::*;
pub use schema_cmd::*;
pub use validate::*;

use crate::managers::ConstraintType;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

const ABOUT: &str = "mSCP - Transform mSCP baselines into MDM-ready configurations";

#[derive(Debug, Parser)]
#[command(name = "mscp")]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")))]
#[command(about = ABOUT, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format for CI/CD integration
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Display project information and status
    Info {
        /// Path to configuration file
        #[arg(short, long, default_value = "mscp.toml")]
        config: PathBuf,
    },

    /// Initialize a new configuration file
    Init {
        /// Output directory for config files
        #[arg(short, long, default_value = ".")]
        output: PathBuf,

        /// Organization reverse-domain identifier (e.g., com.yourorg)
        #[arg(long)]
        org: Option<String>,

        /// Organization display name
        #[arg(short, long)]
        name: Option<String>,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,

        /// Enable Fleet `GitOps` mode
        #[arg(long)]
        fleet: bool,

        /// Enable Jamf Pro mode
        #[arg(long)]
        jamf: bool,

        /// Enable Munki integration
        #[arg(long)]
        munki: bool,

        /// Clone/sync mSCP repository
        #[arg(long)]
        sync: bool,

        /// mSCP branch to clone (default: tahoe)
        #[arg(long, default_value = "tahoe")]
        branch: String,

        /// Baselines to enable (comma-separated, used with --sync)
        #[arg(long, value_delimiter = ',')]
        baselines: Option<Vec<String>>,
    },

    /// Process pre-built mSCP baseline output (advanced — most users want `generate`)
    ///
    /// Transforms an already-generated mSCP build directory into MDM-ready
    /// configurations. The --input path must point to a build output directory
    /// (e.g., macos_security/build/cis_lvl1), NOT the mSCP repository root.
    ///
    /// For the typical workflow, use `generate` instead — it runs the mSCP
    /// Python script and then processes the output automatically.
    Process {
        /// Path to mSCP build output directory (NOT the repo root!).
        /// Example: ./macos_security/build/cis_lvl1
        #[arg(short, long)]
        input: PathBuf,

        /// Output directory for Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Baseline name (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Path to mSCP repository (for Git version tracking)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Enable Jamf postprocessing mode
        #[arg(long)]
        jamf_mode: bool,

        /// Use deterministic UUIDs based on `PayloadType`
        #[arg(long, help_heading = "Profile Options")]
        deterministic_uuids: bool,

        /// Remove creation dates from descriptions
        #[arg(long)]
        no_creation_date: bool,

        /// Use identical UUID for `PayloadIdentifier` and `PayloadUUID`
        #[arg(long)]
        identical_payload_uuid: bool,

        /// Organization reverse-domain identifier for `PayloadIdentifier` prefix (e.g., me.macadmin)
        #[arg(long)]
        org: Option<String>,

        /// Organization display name for `PayloadOrganization` (e.g., "Macadmin")
        #[arg(long, help_heading = "Profile Options")]
        org_name: Option<String>,

        /// Remove `ConsentText` from profiles
        #[arg(long, help_heading = "Profile Options")]
        remove_consent_text: bool,

        /// Custom `ConsentText` to use (overrides --remove-consent-text)
        #[arg(long, help_heading = "Profile Options")]
        consent_text: Option<String>,

        /// Custom `PayloadDescription` format
        #[arg(long)]
        description_format: Option<String>,

        /// Skip generating Fleet label definitions
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        no_labels: bool,

        /// Enable Fleet conflict filtering (excludes profiles and strips keys conflicting with Fleet native settings)
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fleet_mode: bool,

        /// Enable Jamf conflict filtering (excludes profiles conflicting with Jamf Pro native capabilities)
        #[arg(long)]
        jamf_exclude_conflicts: bool,

        /// Generate Munki compliance flags (nopkg item for osquery/FleetDM scoping)
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_compliance_flags: bool,

        /// Path where compliance plist will be written on target systems
        #[arg(
            long,
            default_value = "/Library/Managed Preferences/mscp_compliance.plist",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_compliance_path: String,

        /// Prefix for compliance flags
        #[arg(
            long,
            default_value = "mscp_",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_flag_prefix: String,

        /// Generate Munki script nopkg items from script rules
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_script_nopkg: bool,

        /// Munki catalog for script nopkg items
        #[arg(
            long,
            default_value = "production",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_script_catalog: String,

        /// Munki category for script nopkg items
        #[arg(
            long,
            default_value = "mSCP Compliance",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_script_category: String,

        /// Embed fix in installcheck (default) or use separate postinstall
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_script_separate_postinstall: bool,

        /// Exclude rule categories (comma-separated, e.g., --exclude audit,smartcard).
        /// Auto-generates constraint entries in the constraints file.
        #[arg(long, value_delimiter = ',', help_heading = "Exclusion Options")]
        exclude: Option<Vec<String>>,

        /// Dry run mode - show what would be processed without writing files
        #[arg(long)]
        dry_run: bool,

        /// [FLEET] Script generation mode (granular, bundled, combined, both)
        #[arg(
            long,
            default_value = "bundled",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        script_mode: ScriptModeArg,

        /// [FLEET] Generate a Fleet fragment directory instead of full GitOps structure
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fragment: bool,
    },

    /// Generate baseline using mSCP and process output (recommended)
    ///
    /// Runs the mSCP Python generation script, then transforms the output
    /// into MDM-ready configurations. This is the standard workflow.
    Generate {
        /// Path to mscp.toml configuration file. When set, `[settings.munki]`,
        /// `[settings.jamf]`, `[settings.fleet]`, and `[output].structure` are
        /// read from config instead of requiring CLI flags.
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to mSCP repository
        #[arg(short, long)]
        mscp_repo: PathBuf,

        /// Git branch to use (e.g., sequoia, `ios_18`, sonoma)
        /// Branch determines the platform and OS version
        #[arg(long)]
        branch: Option<String>,

        /// Baseline name to generate (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Output directory for Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Use uv run instead of python3 (auto-detected if not specified)
        #[arg(long)]
        use_uv: bool,

        /// Force python3 instead of uv (overrides auto-detection)
        #[arg(long)]
        use_python3: bool,

        /// Use container (Docker or Apple container) to run mSCP
        #[arg(long)]
        use_container: bool,

        /// Container image to use (default: ghcr.io/brodjieski/mscp_2.0:latest)
        #[arg(long)]
        container_image: Option<String>,

        /// [JAMF PRO] Enable Jamf Pro mode - generates profiles compatible with Jamf Pro upload
        #[arg(long, help_heading = "Jamf Pro Options")]
        jamf_mode: bool,

        /// Use deterministic UUIDs based on `PayloadType`
        #[arg(long, help_heading = "Profile Options")]
        deterministic_uuids: bool,

        /// [JAMF PRO] Remove creation dates from mobileconfig descriptions (cleaner for Jamf Pro)
        #[arg(long, help_heading = "Jamf Pro Options")]
        no_creation_date: bool,

        /// [JAMF PRO] Use identical UUID for `PayloadIdentifier` and `PayloadUUID` (Jamf Pro compatibility)
        #[arg(long, help_heading = "Jamf Pro Options")]
        identical_payload_uuid: bool,

        /// [JAMF PRO] Exclude profiles conflicting with Jamf Pro native capabilities (e.g., `FileVault`, password policies)
        #[arg(long, help_heading = "Jamf Pro Options")]
        jamf_exclude_conflicts: bool,

        /// [ORG] Organization reverse-domain identifier for `PayloadIdentifier` prefix (e.g., me.macadmin)
        #[arg(long, help_heading = "Organization Options")]
        org: Option<String>,

        /// [ORG] Organization display name for `PayloadOrganization` (e.g., "Macadmin")
        #[arg(long, help_heading = "Organization Options")]
        org_name: Option<String>,

        /// Remove `ConsentText` from profiles
        #[arg(long, help_heading = "Profile Options")]
        remove_consent_text: bool,

        /// Custom `ConsentText` to use (overrides --remove-consent-text)
        #[arg(long, help_heading = "Profile Options")]
        consent_text: Option<String>,

        /// [JAMF PRO] Custom `PayloadDescription` format
        #[arg(long, help_heading = "Jamf Pro Options", default_value = None)]
        description_format: Option<String>,

        /// [MSCP] Generate DDM (Declarative Device Management) artifacts (pass -D flag to mSCP)
        #[arg(long, help_heading = "mSCP Generation Options")]
        generate_ddm: bool,

        /// [FLEET] Enable Fleet conflict filtering (excludes profiles and strips keys conflicting with Fleet native settings)
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fleet_mode: bool,

        /// [FLEET] Skip generating Fleet label definitions
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        no_labels: bool,

        /// [FLEET] Teams to add baseline to (comma-separated). Updates team YAML files and default.yml
        #[arg(
            long,
            value_delimiter = ',',
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        teams: Option<Vec<String>>,

        /// [MUNKI] Generate Munki compliance flags nopkg item (for osquery/FleetDM scoping)
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_compliance_flags: bool,

        /// [MUNKI] Path where compliance plist will be written on target systems
        #[arg(
            long,
            default_value = "/Library/Managed Preferences/mscp_compliance.plist",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_compliance_path: String,

        /// [MUNKI] Prefix for compliance flags
        #[arg(
            long,
            default_value = "mscp_",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_flag_prefix: String,

        /// [MUNKI] Generate Munki script nopkg items from script rules
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_script_nopkg: bool,

        /// [MUNKI] Munki catalog for script nopkg items
        #[arg(
            long,
            default_value = "production",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_script_catalog: String,

        /// [MUNKI] Munki category for script nopkg items
        #[arg(
            long,
            default_value = "mSCP Compliance",
            help_heading = "Experimental - not stable (Munki Options)"
        )]
        munki_script_category: String,

        /// [MUNKI] Embed fix in installcheck (default) or use separate postinstall
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_script_separate_postinstall: bool,

        /// [ODV] Path to ODV override file (auto-detected as `odv_<baseline>.yaml` if not specified)
        #[arg(long, help_heading = "ODV Options")]
        odv: Option<PathBuf>,

        /// Exclude rule categories (comma-separated, e.g., --exclude audit,smartcard).
        /// Auto-generates constraint entries in the constraints file.
        #[arg(long, value_delimiter = ',', help_heading = "Exclusion Options")]
        exclude: Option<Vec<String>>,

        /// Dry run mode - show what would be generated without writing files
        #[arg(long)]
        dry_run: bool,

        /// [FLEET] Script generation mode (granular, bundled, combined, both)
        #[arg(
            long,
            default_value = "bundled",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        script_mode: ScriptModeArg,

        /// [FLEET] Generate a Fleet fragment directory instead of full GitOps structure
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fragment: bool,

        /// [FLEET] Run the interactive GitOps glob builder before generation.
        ///
        /// Requires `--config <mscp.toml>`. For each baseline, asks which
        /// profiles / scripts to collapse into a single `paths:` glob and
        /// which to keep as literal `path:` exceptions (with optional
        /// subfolder placement + Fleet labels). Choices are persisted back
        /// to `mscp.toml` so subsequent non-interactive runs reproduce the
        /// same YAML.
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        interactive: bool,
    },

    /// Generate multiple baselines
    GenerateAll {
        /// Path to configuration file (overrides other options)
        #[arg(short, long)]
        config: Option<PathBuf>,

        /// Path to mSCP repository (ignored if --config is used)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline names to generate (comma-separated, ignored if --config is used)
        #[arg(short, long, value_delimiter = ',')]
        baselines: Option<Vec<String>>,

        /// Output directory for Fleet `GitOps` structure (ignored if --config is used)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Use uv run instead of python3 (auto-detected if not specified)
        #[arg(long)]
        use_uv: bool,

        /// Force python3 instead of uv (overrides auto-detection)
        #[arg(long)]
        use_python3: bool,

        /// Use container (Docker or Apple container) to run mSCP
        #[arg(long)]
        use_container: bool,

        /// [MSCP] Generate DDM (Declarative Device Management) artifacts (pass -D flag to mSCP)
        #[arg(long, help_heading = "mSCP Generation Options")]
        generate_ddm: bool,

        /// [JAMF PRO] Enable Jamf Pro mode - generates profiles compatible with Jamf Pro upload
        #[arg(long, help_heading = "Jamf Pro Options")]
        jamf_mode: bool,

        /// Use deterministic UUIDs based on `PayloadType`
        #[arg(long, help_heading = "Profile Options")]
        deterministic_uuids: bool,

        /// [JAMF PRO] Remove creation dates from mobileconfig descriptions (cleaner for Jamf Pro)
        #[arg(long, help_heading = "Jamf Pro Options")]
        no_creation_date: bool,

        /// [JAMF PRO] Use identical UUID for `PayloadIdentifier` and `PayloadUUID` (Jamf Pro compatibility)
        #[arg(long, help_heading = "Jamf Pro Options")]
        identical_payload_uuid: bool,

        /// [JAMF PRO] Exclude profiles conflicting with Jamf Pro native capabilities
        #[arg(long, help_heading = "Jamf Pro Options")]
        jamf_exclude_conflicts: bool,

        /// [FLEET] Enable Fleet conflict filtering
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fleet_mode: bool,

        /// [MUNKI] Generate Munki compliance flags
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_compliance_flags: bool,

        /// [MUNKI] Generate Munki script nopkg items
        #[arg(long, help_heading = "Experimental - not stable (Munki Options)")]
        munki_script_nopkg: bool,

        /// Dry run mode - show what would be generated without writing files
        #[arg(long)]
        dry_run: bool,

        /// Disable parallel processing
        #[arg(long)]
        no_parallel: bool,

        /// [FLEET] Script generation mode (granular, bundled, combined, both)
        #[arg(
            long,
            default_value = "bundled",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        script_mode: ScriptModeArg,

        /// [FLEET] Generate Fleet fragment directories instead of full GitOps structure
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        fragment: bool,
    },

    /// Compare versions and generate diff report
    Diff {
        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Optional baseline name to filter diff
        #[arg(short, long)]
        baseline: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "console")]
        format: DiffFormatArg,
    },

    /// Validate Fleet `GitOps` output
    Validate {
        /// Output directory to validate
        #[arg(short, long)]
        output: PathBuf,

        /// Path to JSON schema directory (optional)
        #[arg(short, long)]
        schemas: Option<PathBuf>,

        /// Strict mode (fail on warnings)
        #[arg(long)]
        strict: bool,
    },

    /// Deduplicate profiles across baselines
    Deduplicate {
        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Baseline names to deduplicate (comma-separated). If not specified, scans all baselines.
        #[arg(short, long, value_delimiter = ',')]
        baselines: Option<Vec<String>>,

        /// Platform (macOS, iOS, visionOS)
        #[arg(short, long, default_value = "macOS")]
        platform: String,

        /// Generate Jamf Pro Smart Group scoping templates
        #[arg(long)]
        jamf_mode: bool,

        /// Dry run - show what would be deduplicated without making changes
        #[arg(long)]
        dry_run: bool,
    },

    /// List all baselines in output directory
    List {
        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,
    },

    /// List available baselines from mSCP repository
    ListBaselines {
        /// Path to mSCP repository
        #[arg(short, long, default_value = "./macos_security")]
        mscp_repo: PathBuf,
    },

    /// Extract remediation scripts from mSCP rules (separate from detection/audit)
    ExtractScripts {
        /// Path to mSCP repository (falls back to embedded data if omitted)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Output directory for scripts
        #[arg(short, long)]
        output: PathBuf,

        /// Flat output (no category subdirectories)
        #[arg(long)]
        flat: bool,

        /// Dry run - show what would be extracted without writing files
        #[arg(long)]
        dry_run: bool,

        /// Path to constraints file for script exclusions
        #[arg(long)]
        constraints: Option<PathBuf>,

        /// Path to ODV override file (auto-detected as `odv_<baseline>.yaml` if not specified)
        #[arg(long)]
        odv: Option<PathBuf>,
    },

    /// Clean (remove) a baseline and associated files
    Clean {
        /// Baseline name to remove
        #[arg(short, long)]
        baseline: String,

        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Force removal even if referenced by team files
        #[arg(short, long)]
        force: bool,
    },

    /// Migrate team files from one baseline to another
    Migrate {
        /// Baseline to migrate from
        #[arg(long)]
        from: String,

        /// Baseline to migrate to
        #[arg(long)]
        to: String,

        /// Team file to migrate
        #[arg(short, long)]
        team: PathBuf,

        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Skip creating backup file
        #[arg(long)]
        no_backup: bool,
    },

    /// Verify `GitOps` repository for orphaned baseline references
    Verify {
        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Automatically fix orphaned references
        #[arg(long)]
        fix: bool,
    },

    /// Manage profile exclusion constraints interactively
    #[command(name = "constraints")]
    Constraints {
        #[command(subcommand)]
        action: ConstraintsAction,
    },

    /// Manage Organizational Defined Values (ODVs)
    #[command(name = "odv")]
    Odv {
        #[command(subcommand)]
        action: OdvAction,
    },

    /// Manage mSCP container image
    #[command(name = "container")]
    Container {
        #[command(subcommand)]
        action: ContainerAction,
    },

    /// Query the embedded mSCP schema dataset (baselines, rules, statistics)
    #[command(name = "schema")]
    Schema {
        #[command(subcommand)]
        action: SchemaAction,
    },
}

/// Subcommands for the schema query command
#[derive(Debug, Subcommand)]
pub enum SchemaAction {
    /// List all baselines in the embedded schema
    Baselines,

    /// List rules for a specific baseline and platform
    Rules {
        /// Baseline name (e.g., cis_lvl1, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Platform (e.g., macOS, iOS, visionOS)
        #[arg(short, long, default_value = "macOS")]
        platform: String,
    },

    /// Show dataset statistics for the embedded schema
    Stats,

    /// Compare embedded parquet data against mSCP repo YAML files
    Compare {
        /// Path to mSCP repository
        mscp_repo: PathBuf,
        /// Baseline to compare
        baseline: String,
        /// Platform filter
        #[arg(long, default_value = "macOS")]
        platform: String,
    },

    /// Search rules by keyword (rule_id, title, tags)
    Search {
        /// Search query
        query: String,
        /// Platform filter
        #[arg(long)]
        platform: Option<String>,
    },

    /// Show full detail for a specific rule
    Rule {
        /// Rule ID (e.g., os_airdrop_disable)
        rule_id: String,
    },
}

/// Subcommands for the container command
#[derive(Debug, Subcommand)]
pub enum ContainerAction {
    /// Initialize a local mSCP container (creates Dockerfile and builds image)
    Init {
        /// Path to mSCP repository (will be cloned if not present)
        #[arg(short, long, default_value = "./macos_security")]
        mscp_repo: PathBuf,

        /// Git branch to use (e.g., sequoia, sonoma, tahoe)
        #[arg(long, default_value = "tahoe")]
        branch: String,

        /// Custom image name/tag
        #[arg(short, long, default_value = "mscp:local")]
        tag: String,

        /// Skip building the image (only create Dockerfile)
        #[arg(long)]
        no_build: bool,

        /// Force Docker runtime (instead of auto-detect)
        #[arg(long)]
        docker: bool,
    },

    /// Pull the mSCP container image from registry
    Pull {
        /// Container image to pull (default: ghcr.io/brodjieski/mscp_2.0:latest)
        #[arg(short, long)]
        image: Option<String>,
    },

    /// Check container runtime status
    Status,

    /// Test container by running a simple command
    Test {
        /// Container image to test (default: ghcr.io/brodjieski/mscp_2.0:latest)
        #[arg(short, long)]
        image: Option<String>,
    },
}

/// Subcommands for the constraints command
#[derive(Debug, Subcommand)]
pub enum ConstraintsAction {
    /// Add profiles to exclusion list via fuzzy search
    Add {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "fleet")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository for profile discovery
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Specific baseline to scan for profiles (scans all if not specified)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// Remove profiles from exclusion list
    Remove {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "fleet")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository (ignored for remove, accepted for consistency)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (ignored for remove, accepted for consistency)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// List currently excluded profiles
    List {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "fleet")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository (ignored for list, accepted for consistency)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (ignored for list, accepted for consistency)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// Add scripts to exclusion list via fuzzy search
    AddScript {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "jamf")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository for script discovery
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Specific baseline to scan for scripts (scans all if not specified)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// Remove scripts from exclusion list
    RemoveScript {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "jamf")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository (ignored for remove, accepted for consistency)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (ignored for remove, accepted for consistency)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// List currently excluded scripts
    ListScripts {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "jamf")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository (ignored for list, accepted for consistency)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (ignored for list, accepted for consistency)
        #[arg(short, long)]
        baseline: Option<String>,
    },

    /// Add category-based exclusions (interactive picker or direct via --exclude)
    AddCategories {
        /// Constraint type (fleet, jamf, munki)
        #[arg(short, long, default_value = "fleet")]
        r#type: ConstraintType,

        /// Path to constraints file (auto-detected by type if not specified)
        #[arg(short, long)]
        constraints: Option<PathBuf>,

        /// Path to mSCP repository for category discovery
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline to resolve categories against
        #[arg(short, long)]
        baseline: String,

        /// Categories to exclude (comma-separated, skips interactive picker)
        #[arg(short, long, value_delimiter = ',')]
        exclude: Option<Vec<String>>,
    },
}

/// Subcommands for the odv command
#[derive(Debug, Subcommand)]
pub enum OdvAction {
    /// Initialize ODV override file for a baseline (scans rules, creates template)
    Init {
        /// Path to mSCP repository
        #[arg(short, long)]
        mscp_repo: PathBuf,

        /// Baseline name (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Output directory for ODV override file
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
    },

    /// List ODVs for a baseline (shows defaults and any overrides)
    List {
        /// Path to mSCP repository
        #[arg(short, long)]
        mscp_repo: PathBuf,

        /// Baseline name (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(short, long)]
        baseline: String,

        /// Path to ODV override file (auto-detected as `odv_<baseline>.yaml` if not specified)
        #[arg(short = 'O', long)]
        overrides: Option<PathBuf>,
    },

    /// Edit ODV values (opens in $EDITOR)
    Edit {
        /// Path to ODV override file
        #[arg(short = 'O', long)]
        overrides: PathBuf,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum DiffFormatArg {
    Markdown,
    Console,
}

impl From<DiffFormatArg> for diff::DiffFormat {
    fn from(arg: DiffFormatArg) -> Self {
        match arg {
            DiffFormatArg::Markdown => diff::DiffFormat::Markdown,
            DiffFormatArg::Console => diff::DiffFormat::Console,
        }
    }
}

/// Script generation mode for Fleet scripts
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ScriptModeArg {
    /// One combined script with all rules
    Combined,
    /// Individual script per rule (e.g., 70 scripts for cis_lvl1)
    Granular,
    /// Bundled by category prefix (e.g., audit_*, os_*, system_settings_*)
    #[default]
    Bundled,
    /// Both granular and bundled
    Both,
}

impl From<ScriptModeArg> for crate::transformers::ScriptMode {
    fn from(arg: ScriptModeArg) -> Self {
        match arg {
            ScriptModeArg::Combined => crate::transformers::ScriptMode::Combined,
            ScriptModeArg::Granular => crate::transformers::ScriptMode::Granular,
            ScriptModeArg::Bundled => crate::transformers::ScriptMode::Bundled,
            ScriptModeArg::Both => crate::transformers::ScriptMode::Both,
        }
    }
}
