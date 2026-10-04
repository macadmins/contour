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
pub mod presets;
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
#[expect(
    clippy::large_enum_variant,
    reason = "clap subcommand enum: the Generate variant carries many CLI flags; boxing a derive(Subcommand) variant is not worth the ergonomic cost"
)]
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

        /// Enable Fleet `GitOps` mode — writes `[settings.fleet] enabled = true`,
        /// the config form of `generate --fleet-gitops`.
        #[arg(long = "fleet-gitops")]
        fleet: bool,

        // Was `--fleet`. Freed so that `--fleet <NAME>` names a fleet everywhere
        // in contour, the way `[[baselines]] fleet = "…"` already does in
        // mscp.toml. Kept hidden so an old invocation is told what to type
        // instead of getting clap's bare "unexpected argument".
        #[arg(long = "fleet", hide = true)]
        legacy_fleet: bool,

        /// Enable Jamf Pro mode
        #[arg(long)]
        jamf: bool,

        /// Enable Munki integration
        #[arg(long)]
        munki: bool,

        /// Clone/sync mSCP repository
        #[arg(long)]
        sync: bool,

        /// mSCP branch to clone. `main` (default) is mSCP 2.0, the only
        /// layout contour reads; the macOS-version branches (`tahoe`,
        /// `sequoia`, …) are the deprecated 1.x layout — `--sync` warns,
        /// `mscp generate` refuses.
        #[arg(long, default_value = "main")]
        branch: String,

        /// Baselines to enable (comma-separated, used with --sync)
        #[arg(long = "keywords", visible_alias = "baselines", value_delimiter = ',')]
        keywords: Option<Vec<String>>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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

        /// Fleet GitOps output: the Fleet directory layout, plus filtering of profiles and keys that conflict with Fleet's native settings.
        ///
        /// `--fleet-gitops` is the same switch, and the name `mscp init` uses.
        /// Its old one-line help said only "conflict filtering"; it also
        /// selects the Fleet layout.
        #[arg(
            long,
            visible_alias = "fleet-gitops",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
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

        /// [FLEET/OSQUERY] Emit osquery detection (native-table queries + slim/full audit script)
        ///
        /// Two tiers: rules a native osquery table can answer become queries;
        /// the residual gets an audit script plus a launchd job that writes a
        /// results plist, which osquery then reads back.
        ///
        /// Needs the Fleet GitOps layout and an org domain, and refuses the
        /// run rather than emitting nothing if either is missing. Only macOS
        /// baselines produce output; a non-macOS baseline in the run is
        /// reported as skipped, not passed over in silence. Config-driven runs
        /// can set this as `[settings.osquery] enabled = true` instead — this
        /// flag wins where both are given.
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        osquery: bool,

        /// [OSQUERY] Output adapter: `fleet` (default) or `pack`
        #[arg(
            long,
            default_value = "fleet",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        osquery_format: String,

        /// [OSQUERY] Audit-script scope: `slim` (default, residual only) or `full`
        #[arg(
            long,
            default_value = "slim",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        osquery_audit: String,
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

        /// mSCP branch to build from: `main`, or an OS-preview branch such
        /// as `dev_28` when one is open. The branch selects the rule SOURCE,
        /// not the target — on mSCP 2.0 one tree covers every platform and
        /// `--os` / `--os-version` pick what to build. The 1.x release
        /// branches (`sequoia`, `sonoma`, …) carry a schema contour refuses.
        /// Defaults to the checkout's current branch.
        #[arg(long)]
        branch: Option<String>,

        /// Baseline name to generate (e.g., `cis_lvl1`, 800-53r5_high).
        /// Mutually exclusive with `--preset`.
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b',
            required_unless_present = "preset",
            conflicts_with = "preset"
        )]
        keyword: Option<String>,

        /// Compliance preset — a friendly name (see `contour mscp presets`)
        /// that expands to a baseline keyword + platform. Also accepts a raw
        /// baseline keyword (e.g. `800-53r5_high`).
        #[arg(long)]
        preset: Option<String>,

        /// OS target: `macos`, `ios`, or `visionos`. Selects which
        /// `baselines/<os>/` file is built.
        #[arg(long, value_enum, default_value_t = OsArg::Macos)]
        os: OsArg,

        /// OS version (e.g. `26.0`). Defaults to the highest version
        /// available for the baseline.
        #[arg(long)]
        os_version: Option<String>,

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

        /// Container image to use — not yet honoured; the default image (ghcr.io/brodjieski/mscp_2.0:latest) is always used
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

        /// [MSCP] Generate DDM (Declarative Device Management) artifacts (passes `--ddm` to mSCP)
        #[arg(long, help_heading = "mSCP Generation Options")]
        generate_ddm: bool,

        /// [FLEET] Fleet GitOps output: the Fleet directory layout, plus filtering of profiles and keys that conflict with Fleet's native settings.
        ///
        /// `--fleet-gitops` is the same switch, and the name `mscp init` uses.
        /// Its old one-line help said only "conflict filtering"; it also
        /// selects the Fleet layout.
        #[arg(
            long,
            visible_alias = "fleet-gitops",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        fleet_mode: bool,

        /// [FLEET] Skip generating Fleet label definitions
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        no_labels: bool,

        /// [FLEET] Fleets to add the baseline to. Updates fleet YAML files and default.yml.
        ///
        /// `--fleet <NAME>` is the same list — repeat it, or comma-separate
        /// either spelling. Singular `--fleet <NAME>` is how every contour
        /// command names a fleet.
        #[arg(
            long,
            visible_alias = "fleet",
            value_name = "NAME",
            value_delimiter = ',',
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        fleets: Option<Vec<String>>,

        /// [FLEET] With --fleets, attach the baseline as a single *.mobileconfig glob entry instead of one entry per profile
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        glob: bool,

        /// [FLEET] With --fleets, scope the attached profiles to this label (default: unscoped — applies to all hosts in the fleet)
        #[arg(
            long,
            value_name = "LABEL",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        fleet_label: Option<String>,

        /// [FLEET] Attach the baseline to EVERY fleet found under fleets/ (multi-brand: one baseline across all fleets). Overrides --fleets.
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        all_fleets: bool,

        /// [FLEET] With --all-fleets, fleets to skip (comma-separated) — "all or nearly all"
        #[arg(
            long,
            value_delimiter = ',',
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        exclude_fleets: Option<Vec<String>>,

        /// [FLEET] With --fleets/--all-fleets, REMOVE this baseline's injection from the target fleets (manifest-driven) instead of adding it
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        remove: bool,

        /// [FLEET] Greenfield: scaffold canonical workstations + personal-mobile-devices fleets (if absent) and attach the baseline to workstations
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        canonical_fleets: bool,

        /// [FLEET] After generating, write the emitted policy/report queries as osqueryi and `orbit shell` commands to `<output>/osquery/verify-commands.md` (nothing is executed)
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        verify_queries: bool,

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

        /// [FLEET/OSQUERY] Emit osquery detection (native-table queries + slim/full audit script)
        ///
        /// Two tiers: rules a native osquery table can answer become queries;
        /// the residual gets an audit script plus a launchd job that writes a
        /// results plist, which osquery then reads back.
        ///
        /// Needs the Fleet GitOps layout and an org domain, and refuses the
        /// run rather than emitting nothing if either is missing. Only macOS
        /// baselines produce output; a non-macOS baseline in the run is
        /// reported as skipped, not passed over in silence. Config-driven runs
        /// can set this as `[settings.osquery] enabled = true` instead — this
        /// flag wins where both are given.
        #[arg(long, help_heading = "Experimental - not stable (Fleet Options)")]
        osquery: bool,

        /// [OSQUERY] Output adapter: `fleet` (default) or `pack`
        #[arg(
            long,
            default_value = "fleet",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        osquery_format: String,

        /// [OSQUERY] Audit-script scope: `slim` (default, residual only) or `full`
        #[arg(
            long,
            default_value = "slim",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
        osquery_audit: String,
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
        #[arg(
            short = 'k',
            long = "keywords",
            visible_alias = "baselines",
            short_alias = 'b',
            value_delimiter = ','
        )]
        keywords: Option<Vec<String>>,

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

        /// [MSCP] Generate DDM (Declarative Device Management) artifacts (passes `--ddm` to mSCP)
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

        /// [FLEET] Fleet GitOps output: the Fleet directory layout, plus filtering of profiles and keys that conflict with Fleet's native settings.
        ///
        /// `--fleet-gitops` is the same switch, and the name `mscp init` uses.
        /// Its old one-line help said only "conflict filtering"; it also
        /// selects the Fleet layout.
        #[arg(
            long,
            visible_alias = "fleet-gitops",
            help_heading = "Experimental - not stable (Fleet Options)"
        )]
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,

        /// Output format
        #[arg(short, long, default_value = "console")]
        format: DiffFormatArg,
    },

    /// Validate Fleet `GitOps` output
    Validate {
        /// Output directory to validate
        #[arg(short, long)]
        output: PathBuf,

        /// Directory holding Fleet's GitOps JSON Schema (`generated-schema.json`,
        /// from fleetdm/fleet tools/gitops-auto-complete/). Without it, the pinned
        /// schema this build embeds. Overrides `[validation] schemas_path`.
        #[arg(short, long)]
        schemas: Option<PathBuf>,

        /// Strict mode (fail on warnings). Either this or `[validation] strict`
        /// turns it on.
        #[arg(long)]
        strict: bool,

        /// mscp.toml to read `[validation]` from — schemas_path, strict and
        /// validate_paths. Flags given on the command line win.
        #[arg(short, long)]
        config: Option<PathBuf>,
    },

    /// Deduplicate profiles across baselines
    Deduplicate {
        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Baseline names to deduplicate (comma-separated). If not specified, scans all baselines.
        #[arg(
            short = 'k',
            long = "keywords",
            visible_alias = "baselines",
            short_alias = 'b',
            value_delimiter = ','
        )]
        keywords: Option<Vec<String>>,

        /// Platform (macOS, iOS, visionOS)
        #[arg(short, long, default_value = "macOS")]
        platform: String,

        /// [JAMF PRO] Also emit Jamf Smart Group scoping templates (the Jamf counterpart to Fleet labels) for the deduplicated baselines
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

    /// List built-in compliance presets (friendly names → baseline keywords)
    Presets,

    /// Extract remediation scripts from mSCP rules (separate from detection/audit)
    ExtractScripts {
        /// Path to mSCP repository (falls back to embedded data if omitted)
        #[arg(short, long)]
        mscp_repo: Option<PathBuf>,

        /// Baseline name (e.g., `cis_lvl1`, 800-53r5_high)
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

        /// Output directory containing Fleet `GitOps` structure
        #[arg(short, long)]
        output: PathBuf,

        /// Force removal even if referenced by fleet files
        #[arg(short, long)]
        force: bool,
    },

    /// Migrate fleet files from one baseline to another
    Migrate {
        /// Baseline to migrate from
        #[arg(long)]
        from: String,

        /// Baseline to migrate to
        #[arg(long)]
        to: String,

        /// Fleet to migrate, by name — resolves to `<output>/fleets/<NAME>.yml`.
        ///
        /// This was always meant as a name: every documented example passed one
        /// (`-f engineering`). The code took a path and never appended `.yml`,
        /// so those examples failed with "Fleet file not found". A name is what
        /// `--fleet` means everywhere in contour now, and here it finally works.
        #[arg(
            short = 'f',
            long = "fleet",
            value_name = "NAME",
            required_unless_present = "fleet_file",
            conflicts_with = "fleet_file"
        )]
        fleet: Option<String>,

        /// Fleet file to migrate, by path. A relative path resolves under
        /// `<output>/fleets/`.
        #[arg(long = "fleet-file", value_name = "PATH")]
        fleet_file: Option<PathBuf>,

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

    /// Aggregate a baseline's mobileconfig rules into one recipe TOML
    ///
    /// Produces a contour recipe with one `[[profile]]` block per
    /// payload type (e.g. firewall, screensaver) and every rule's
    /// keys merged in. Drop the result into a recipe library and
    /// render via `contour profile generate --recipe …`.
    ///
    /// Reads rule YAML directly from the mSCP repository — does NOT
    /// run the mSCP Python build script.
    Recipe {
        /// Path to the mSCP repository (the directory that contains `rules/`).
        #[arg(short = 'r', long)]
        mscp_repo: PathBuf,

        /// Baseline name (e.g., `cis_lvl1`, `800-53r5_high`).
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

        /// Output recipe TOML path (defaults to `<baseline>.toml`).
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Organization vendor string written to the recipe header.
        #[arg(long)]
        org: Option<String>,

        /// ODV override file. Operator `custom_value`s seed the recipe's
        /// `[odv]` table (or inline values) in place of the rule
        /// defaults. Auto-detected as `odv_<keyword>.yaml` in the
        /// working directory when omitted.
        #[arg(long)]
        odv: Option<PathBuf>,

        /// How to render mSCP `$ODV` placeholders.
        ///
        /// `variable` (default): keep the literal `"$ODV"` placeholder
        /// and emit the resolved defaults into a top-level `[odv]`
        /// table directly under `[recipe]`. Operators edit the `[odv]`
        /// entry once and every reference picks it up. `profile
        /// generate --recipe` substitutes at load time.
        ///
        /// `inline`: bake the resolved per-baseline default directly
        /// into the field, e.g. `timeServer = "time.apple.com"`.
        /// Useful for ad-hoc / one-shot recipes that don't need an
        /// editable surface.
        #[arg(long, value_enum, default_value = "variable")]
        odv_mode: crate::baseline_to_recipe::OdvMode,

        /// OS target: `macos`, `ios`, or `visionos`.
        #[arg(long, value_enum, default_value_t = OsArg::Macos)]
        os: OsArg,

        /// OS version (e.g. `26.0`, `15.0`, `18.0`).
        /// Defaults to the highest version present in the rule set.
        #[arg(long)]
        os_version: Option<String>,
    },
}

/// CLI-facing OS selector. Maps 1:1 to [`crate::models::mscp::Platform`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum OsArg {
    Macos,
    Ios,
    Visionos,
}

impl From<OsArg> for crate::models::mscp::Platform {
    fn from(o: OsArg) -> Self {
        match o {
            OsArg::Macos => Self::MacOS,
            OsArg::Ios => Self::Ios,
            OsArg::Visionos => Self::VisionOS,
        }
    }
}

impl OsArg {
    /// Lowercase OS token used in mSCP 2.0 layout paths — the
    /// `baselines/<os>/` directory and the `<name>_<os>_<version>.yaml`
    /// baseline filename.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Macos => "macos",
            Self::Ios => "ios",
            Self::Visionos => "visionos",
        }
    }
}

/// Subcommands for the schema query command
#[derive(Debug, Subcommand)]
pub enum SchemaAction {
    /// List all baselines in the embedded schema
    Baselines,

    /// List rules for a specific baseline and platform
    Rules {
        /// Baseline name (e.g., cis_lvl1, 800-53r5_high)
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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
        /// mSCP keyword tag to compare (e.g. `cis_lvl1`)
        keyword: String,
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
        /// Query the OS-preview (beta) dataset — mSCP preview-branch rules
        /// (Apple Intelligence PCC, visual intelligence, Siri AI, …)
        #[arg(long)]
        beta: bool,
    },

    /// Show full detail for a specific rule
    Rule {
        /// Rule ID (e.g., os_airdrop_disable)
        rule_id: String,
        /// Query the OS-preview (beta) dataset
        #[arg(long)]
        beta: bool,
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

        /// Git branch to use. `main` (default) is mSCP 2.0, the only
        /// layout contour reads; `tahoe` / `sequoia` / `sonoma` are the
        /// deprecated 1.x layout — not checked here, refused by `mscp generate`.
        #[arg(long, default_value = "main")]
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: Option<String>,
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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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
        #[arg(
            short = 'k',
            long = "keyword",
            visible_alias = "baseline",
            short_alias = 'b'
        )]
        keyword: String,

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

/// Turn `mscp migrate`'s `--fleet <NAME>` / `--fleet-file <PATH>` into the
/// path `migrate_fleet_file` resolves.
///
/// A name becomes `<NAME>.yml`, which `migrate_fleet_file` joins under
/// `<output>/fleets/`. A value that is plainly a file — it has a `/`, or ends
/// in `.yml`/`.yaml` — is refused rather than doubled into `x.yml.yml`: that
/// was the working spelling before `--fleet` became a name, and an old script
/// passing it should be told to use `--fleet-file`, not sent looking for a
/// file that cannot exist.
pub fn resolve_migrate_fleet(
    name: Option<String>,
    file: Option<std::path::PathBuf>,
) -> anyhow::Result<std::path::PathBuf> {
    if let Some(file) = file {
        return Ok(file);
    }
    let name = name.expect("clap requires --fleet or --fleet-file");
    let looks_like_file = name.contains('/')
        || [".yml", ".yaml"]
            .iter()
            .any(|ext| name.to_ascii_lowercase().ends_with(ext));
    if looks_like_file {
        anyhow::bail!(
            "`--fleet` takes a fleet NAME — `{name}` looks like a file.\n\n\
             Use `--fleet-file {name}` for a path, or `--fleet {stem}` to name the fleet \
             (it resolves to <output>/fleets/{stem}.yml).",
            stem = std::path::Path::new(&name)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(&name)
        );
    }
    Ok(std::path::PathBuf::from(format!("{name}.yml")))
}

/// Refuse a retired `--fleet` spelling, naming what replaced it.
///
/// `--fleet` only names a fleet, matching `[[baselines]] fleet = "…"` in
/// mscp.toml. Earlier spellings are kept as hidden arguments purely so this
/// can run: without them an old script would get clap's bare "unexpected
/// argument", which says nothing about what to type instead.
///
/// Shared by the `mscp` binary and `contour mscp`, so both say the same thing.
pub fn refuse_retired_fleet_flag(
    used: bool,
    command: &str,
    replacement: &str,
) -> anyhow::Result<()> {
    if used {
        anyhow::bail!(
            "`{command} --fleet` was renamed to `{replacement}`.\n\n\
             `--fleet <NAME>` now names a fleet in every contour command — the same \
             thing `fleet = \"…\"` means in mscp.toml — so it no longer doubles as a \
             switch here."
        );
    }
    Ok(())
}

#[cfg(test)]
mod fleet_flag_tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("mscp").chain(args.iter().copied()))
    }

    fn fleets_of(args: &[&str]) -> Vec<String> {
        let mut full = vec![
            "generate",
            "--mscp-repo",
            "r",
            "--output",
            "o",
            "--keyword",
            "cis_lvl1",
        ];
        full.extend_from_slice(args);
        match parse(&full).expect("parses").command {
            Commands::Generate { fleets, .. } => fleets.unwrap_or_default(),
            _ => unreachable!("parsed as generate"),
        }
    }

    /// `--fleet <NAME>` is the same list as `--fleets`, however it is spelled.
    ///
    /// The help text shows the alias; that proves nothing about whether a
    /// repeated flag accumulates or quietly keeps only the last value — which
    /// would drop fleets without a word. So the parser is asked directly.
    #[test]
    fn every_spelling_of_the_fleet_list_yields_the_same_list() {
        let want = vec!["a".to_string(), "b".to_string()];
        assert_eq!(fleets_of(&["--fleets", "a,b"]), want);
        assert_eq!(fleets_of(&["--fleet", "a,b"]), want);
        assert_eq!(
            fleets_of(&["--fleet", "a", "--fleet", "b"]),
            want,
            "repeating --fleet must accumulate, not keep only the last name"
        );
        assert_eq!(fleets_of(&["--fleets", "a", "--fleet", "b"]), want);
    }

    /// The retired spellings still parse — so they can be refused by name.
    ///
    /// If clap rejected them first, the operator would get a bare "unexpected
    /// argument" instead of `refuse_retired_fleet_flag`'s pointer to the new
    /// flag. That is the only reason they are still declared.
    #[test]
    fn the_retired_spellings_reach_the_refusal() {
        match parse(&["init", "--fleet"])
            .expect("retired init --fleet parses")
            .command
        {
            Commands::Init { legacy_fleet, .. } => assert!(legacy_fleet),
            _ => unreachable!(),
        }
    }

    /// `mscp migrate --fleet` is a NAME, and the documented form works.
    ///
    /// Every example in docs/contour-mscp.md passed a name (`-f engineering`),
    /// and the flag took a path without appending `.yml`, so each one failed
    /// with "Fleet file not found". It resolves the name now; a filename given
    /// to `--fleet` is refused with a pointer to `--fleet-file` rather than
    /// doubled into `x.yml.yml`.
    #[test]
    fn migrate_resolves_a_fleet_name_and_refuses_a_filename() {
        use std::path::PathBuf;
        assert_eq!(
            resolve_migrate_fleet(Some("engineering".into()), None).unwrap(),
            PathBuf::from("engineering.yml")
        );
        assert_eq!(
            resolve_migrate_fleet(None, Some("/abs/x.yml".into())).unwrap(),
            PathBuf::from("/abs/x.yml"),
            "--fleet-file is taken as given"
        );
        for file_like in [
            "engineering.yml",
            "engineering.YAML",
            "fleets/engineering",
            "a/b",
        ] {
            let e = resolve_migrate_fleet(Some(file_like.into()), None).unwrap_err();
            assert!(e.to_string().contains("--fleet-file"), "{file_like}: {e}");
        }
        // -f is the name form, because that is how every example used it.
        match parse(&[
            "migrate",
            "--from",
            "a",
            "--to",
            "b",
            "-f",
            "engineering",
            "-o",
            "o",
        ])
        .expect("parses")
        .command
        {
            Commands::Migrate {
                fleet, fleet_file, ..
            } => {
                assert_eq!(fleet.as_deref(), Some("engineering"));
                assert!(fleet_file.is_none());
            }
            _ => unreachable!(),
        }
        assert!(
            parse(&[
                "migrate",
                "--from",
                "a",
                "--to",
                "b",
                "--fleet",
                "x",
                "--fleet-file",
                "y",
                "-o",
                "o"
            ])
            .is_err(),
            "a name and a file together are ambiguous and must not parse"
        );
    }

    #[test]
    fn the_refusal_names_the_replacement() {
        let e = refuse_retired_fleet_flag(true, "mscp init", "--fleet-gitops").unwrap_err();
        assert!(e.to_string().contains("--fleet-gitops"), "{e}");
        assert!(refuse_retired_fleet_flag(false, "mscp init", "--fleet-gitops").is_ok());
    }

    /// `--fleet-gitops` and `--fleet-mode` are one switch.
    #[test]
    fn fleet_gitops_is_the_same_switch_as_fleet_mode() {
        for spelling in ["--fleet-mode", "--fleet-gitops"] {
            let cli = parse(&[
                "generate",
                "--mscp-repo",
                "r",
                "--output",
                "o",
                "--keyword",
                "cis_lvl1",
                spelling,
            ])
            .expect("parses");
            match cli.command {
                Commands::Generate { fleet_mode, .. } => assert!(fleet_mode, "{spelling}"),
                _ => unreachable!(),
            }
        }
    }
}
