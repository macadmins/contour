pub mod add;
pub mod allow_cmd;
pub mod app_settings;
pub mod cel_cmd;
pub mod classify;
pub mod completions;
pub mod config;
pub mod diff;
pub mod discover;
pub mod faa_cmd;
pub mod fetch;
pub mod filter;
pub mod fleet;
pub mod generate;
pub mod init;
pub mod merge;
pub mod parity;
pub mod pipeline_cmd;
pub mod prep;
pub mod remove;
pub mod rings;
pub mod rings_output;
pub mod scan;
pub mod select;
pub mod snip;
pub mod stats;
pub mod validate;

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

use crate::bundle::{ConflictPolicy, DedupLevel, OrphanPolicy, RuleTypeStrategy};
use crate::merge::Strategy as MergeStrategy;
use crate::models::{Policy, RuleType};

/// Output format for generated profiles
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum OutputFormat {
    /// Standard Apple mobileconfig format (MDM profile)
    #[default]
    Mobileconfig,
    /// Plist payload without XML header (WS1/Workspace ONE compatible)
    Plist,
    /// Plist payload with XML header (Jamf custom schema compatible)
    PlistFull,
    /// Recipe TOML for the contour preset/recipe library workflow
    Recipe,
}

/// Output format for scan command
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ScanOutputFormat {
    /// CSV file compatible with `contour santa discover` (default)
    #[default]
    Csv,
    /// bundles.toml format - groups by TeamID, skips discover step
    Bundles,
    /// rules.yaml format - direct Santa rules
    Rules,
    /// .mobileconfig format - fully automatic, ready for MDM deployment
    Mobileconfig,
    /// baseline.toml format - curated rules merged with existing file (deny-wins)
    Baseline,
    /// com.apple.configuration.app.settings DDM declaration (macOS 27+).
    /// Emits scanned apps as Allowed.AllowedBinaries by code-signing identifier.
    AppSettings,
}

/// Rule type strategy for scan output
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ScanRuleType {
    /// Generate TeamID rules (vendor-level, fewer rules)
    #[default]
    TeamId,
    /// Generate SigningID rules (app-level, more specific). Requires a
    /// `signing_id` column in the input; rows without one produce no rule.
    SigningId,
    /// Generate CDHash rules (binary-level, most specific). Requires a
    /// `cdhash` column (40 hex characters); rows without a valid hash
    /// produce no rule. One rule per exact binary version.
    Cdhash,
    /// Pick per list. Santa rules and deny entries: SigningID when the column
    /// is present, or when `team_identifier` + `bundle_identifier` can be
    /// composed into one (`TEAMID:bundle_id`); otherwise TeamID. app.settings
    /// allow entries: the vendor's TeamID (`*APPLE*` for Apple), because an
    /// app's helpers run under other signing IDs of the same team. Recommended
    /// for Fleet CSVs built from osquery's `apps` ⋈ `signature` join.
    Auto,
}

/// Target platform for an app.settings declaration.
///
/// The schema gates keys per platform: `AllowedBinaries`/`DeniedBinaries` are
/// macOS-only; `AllowedApps`/`DeniedApps` are iOS/tvOS/visionOS-only; `Privacy`
/// is macOS + iOS. `Combined` (default) emits every applicable key in one
/// `apply: combined` declaration; the others narrow output to a single platform.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum TargetPlatform {
    /// One declaration carrying every platform's applicable keys (default).
    #[default]
    Combined,
    /// macOS only: binaries + Privacy (drops iOS-only keys).
    Macos,
    /// iOS only: app bundle-ID lists + Privacy.
    Ios,
    /// tvOS only: app bundle-ID lists.
    Tvos,
    /// visionOS only: app bundle-ID lists.
    Visionos,
}

impl TargetPlatform {
    /// Whether macOS `AllowedBinaries`/`DeniedBinaries` apply.
    pub fn includes_binaries(self) -> bool {
        matches!(self, TargetPlatform::Combined | TargetPlatform::Macos)
    }

    /// Whether iOS/tvOS/visionOS `AllowedApps`/`DeniedApps` apply.
    pub fn includes_apps(self) -> bool {
        matches!(
            self,
            TargetPlatform::Combined
                | TargetPlatform::Ios
                | TargetPlatform::Tvos
                | TargetPlatform::Visionos
        )
    }

    /// Whether `Privacy.PermissionDefaults` applies (macOS + iOS only).
    pub fn includes_privacy(self) -> bool {
        matches!(
            self,
            TargetPlatform::Combined | TargetPlatform::Macos | TargetPlatform::Ios
        )
    }
}

#[derive(Parser)]
#[command(
    name = "santa",
    about = "Santa mobileconfig profile toolkit",
    long_about = "Transform Santa rule files (YAML, JSON, CSV) into MDM-ready mobileconfig profiles.\n\nPart of the Contour CLI toolkit for macOS fleet management.",
    version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")),
    author
)]
#[derive(Debug)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format (for CI/CD)
    #[arg(long, global = true)]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Create mobileconfig from rule files
    #[command(visible_alias = "gen")]
    Generate {
        /// Input rule files (YAML, JSON, CSV)
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Organization identifier prefix (e.g., com.example)
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Profile identifier (defaults to org.santa.rules)
        #[arg(long)]
        identifier: Option<String>,

        /// Profile display name
        #[arg(long)]
        display_name: Option<String>,

        /// Use deterministic UUIDs for reproducible builds
        #[arg(long)]
        deterministic_uuids: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "mobileconfig")]
        format: OutputFormat,

        /// When `--format=recipe`, also bundle TCC (Full Disk Access),
        /// system-extension, and notification profiles for a complete
        /// Santa deployment in one recipe TOML. Identities default to
        /// Northpole's published Team ID and bundle. Ignored for
        /// non-recipe formats.
        #[arg(long)]
        full_bundle: bool,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory
        #[arg(long)]
        fragment: bool,
    },

    /// Validate rule files
    Validate {
        /// Input rule files to validate
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Strict mode: treat warnings as errors
        #[arg(long)]
        strict: bool,

        /// Warn about rules without group assignment (for large rulesets)
        #[arg(long)]
        warn_groups: bool,
    },

    /// Combine multiple rule sources
    Merge {
        /// Input rule files to merge
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Conflict resolution strategy
        #[arg(long, value_enum, default_value = "last")]
        strategy: MergeStrategy,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Compare two rule sets
    Diff {
        /// First rule file
        file1: PathBuf,

        /// Second rule file
        file2: PathBuf,
    },

    /// Generate Santa configuration profile
    Config {
        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Client mode
        #[arg(long, value_enum, default_value = "monitor")]
        mode: crate::config::ClientMode,

        /// Sync server URL
        #[arg(long)]
        sync_url: Option<String>,

        /// Machine owner plist path
        #[arg(long)]
        machine_owner_plist: Option<String>,

        /// Block USB mass storage
        #[arg(long)]
        block_usb: bool,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Transform external sources into rules
    Fetch {
        #[command(subcommand)]
        command: fetch::FetchCommands,
    },

    /// Generate profiles organized by deployment rings
    ///
    /// Rings enable staged rollouts with separate profiles for each deployment stage.
    /// Each ring can have multiple profile categories:
    ///   - name1a: Software rules for ring 1
    ///   - name1b: CEL rules for ring 1
    ///   - name1c: FAA rules for ring 1
    ///   - name2a: Software rules for ring 2
    ///   - etc.
    Rings {
        #[command(subcommand)]
        command: RingsCommands,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },

    /// Initialize a new santa project with santa.toml
    Init {
        /// Output file path
        #[arg(short, long, default_value = "santa.toml")]
        output: PathBuf,

        /// Organization identifier
        #[arg(long)]
        org: Option<String>,

        /// Organization name
        #[arg(long)]
        name: Option<String>,

        /// Overwrite existing configuration
        #[arg(long)]
        force: bool,
    },

    /// Generate Santa prerequisite profiles for MDM deployment
    ///
    /// Creates the four profiles required for Santa to function properly:
    /// - System Extension Policy (allow Santa's endpoint security extension)
    /// - Service Management (managed login items)
    /// - TCC/PPPC (Full Disk Access for Santa components)
    /// - Notification Settings (enable Santa notifications)
    ///
    /// These profiles should be deployed BEFORE deploying Santa rules.
    ///
    /// Examples:
    ///   contour santa prep --output-dir ./profiles --org com.example
    ///   contour santa prep --org com.yourcompany
    Prep {
        /// Output directory for generated profiles
        #[arg(short, long, default_value = "./santa-prep")]
        output_dir: PathBuf,

        /// Organization identifier prefix
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Preview without writing files
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate per-ring editions for Fleet GitOps
    ///
    /// Each ring profile is a complete, self-contained edition: core rules
    /// (rules with empty `rings:`) merged with that ring's specialized rules.
    /// Hosts receive exactly one edition, scoped by Fleet labels. Santa does
    /// not layer overlapping mobileconfigs on a single host.
    Fleet {
        /// Input rule files (YAML, JSON, CSV)
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output directory for Fleet GitOps structure
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Organization identifier prefix
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Profile name prefix
        #[arg(long, default_value = "santa")]
        prefix: String,

        /// Fleet name — written as `name:` in the fleet file (slugified).
        ///
        /// `--team` still works. Fleet renamed teams to fleets, which is why
        /// the output tree has a `fleets/` directory, so `--fleet` is the
        /// current word and leads. Singular because this names one fleet;
        /// `mscp generate --fleets` takes a list. It names the fleet, not the
        /// file: the file is always `fleets/reference-fleet.yml`.
        #[arg(
            long = "fleet",
            visible_alias = "team",
            value_name = "NAME",
            default_value = "Workstations"
        )]
        team: String,

        /// Number of rings (5 or 7 for built-in configs; otherwise custom)
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=16), conflicts_with = "rings_config")]
        num_rings: Option<u8>,

        /// Ring configuration file (as produced by `rings init`)
        #[arg(long, value_name = "PATH")]
        rings_config: Option<PathBuf>,

        /// Curated baseline TOML applied to every edition; conflicts resolve deny-wins
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,

        /// Maximum rules per edition (splits into santa1a-001, santa1a-002, ...)
        #[arg(long)]
        max_rules: Option<usize>,

        /// Treat unknown ring names in rules as a hard error
        #[arg(long)]
        strict: bool,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory instead of full GitOps structure
        #[arg(long)]
        fragment: bool,
    },

    /// Add a rule to an existing rules file (for posthook integration)
    ///
    /// Designed for Installomator posthooks and scripts that maintain an allowlist.
    ///
    /// Examples:
    ///   contour santa add --file rules.yaml --teamid EQHXZ8M8AV --description "Google"
    ///   contour santa add --file rules.yaml --signingid 276HSJ6V54:de.martinlexow.Theine -d "Theine"
    ///
    /// The identifiers come from the app's signature: `contour app manifest <app>`
    /// prints its team id and signing id.
    Add {
        /// Rules file to update (YAML)
        #[arg(short, long)]
        file: PathBuf,

        /// TeamID to add (10-character identifier)
        #[arg(long, conflicts_with_all = ["binary", "certificate", "signingid", "cdhash"])]
        teamid: Option<String>,

        /// Binary hash (SHA-256)
        #[arg(long, conflicts_with_all = ["teamid", "certificate", "signingid", "cdhash"])]
        binary: Option<String>,

        /// Certificate hash (SHA-256)
        #[arg(long, conflicts_with_all = ["teamid", "binary", "signingid", "cdhash"])]
        certificate: Option<String>,

        /// Signing ID (TeamID:BundleID)
        #[arg(long, conflicts_with_all = ["teamid", "binary", "certificate", "cdhash"])]
        signingid: Option<String>,

        /// CDHash (40-character hash)
        #[arg(long, conflicts_with_all = ["teamid", "binary", "certificate", "signingid"])]
        cdhash: Option<String>,

        /// Policy for the rule
        #[arg(long, value_enum, default_value = "allowlist")]
        policy: Policy,

        /// Rule description (e.g., app name)
        #[arg(short, long)]
        description: Option<String>,

        /// Group for organizing rules
        #[arg(short, long)]
        group: Option<String>,

        /// Regenerate mobileconfig after adding
        #[arg(long)]
        regenerate: Option<PathBuf>,

        /// Organization identifier for regenerated profile
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode: guided rule type selection
        #[arg(short = 'i', long)]
        interactive: bool,
    },

    /// Remove a rule from a rules file
    Remove {
        /// Rules file to update
        #[arg(short, long)]
        file: PathBuf,

        /// Identifier to remove
        identifier: String,

        /// Rule type (to disambiguate if same identifier exists for multiple types)
        #[arg(long)]
        rule_type: Option<String>,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Filter rules by criteria
    Filter {
        /// Input rule files
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output file (prints to stdout if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Filter by rule type (TEAMID, BINARY, etc.)
        #[arg(long, value_enum)]
        rule_type: Option<RuleType>,

        /// Filter by policy (ALLOWLIST, BLOCKLIST, etc.)
        #[arg(long, value_enum)]
        policy: Option<Policy>,

        /// Filter by group
        #[arg(long)]
        group: Option<String>,

        /// Filter by ring assignment
        #[arg(long)]
        ring: Option<String>,

        /// Filter rules with/without description
        #[arg(long)]
        has_description: Option<bool>,

        /// Filter by identifier containing pattern
        #[arg(long)]
        identifier_contains: Option<String>,

        /// Filter by description containing pattern
        #[arg(long)]
        description_contains: Option<String>,
    },

    /// Show statistics about rules
    Stats {
        /// Input rule files
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
    },

    /// Discover patterns in Fleet CSV data and suggest bundle definitions
    ///
    /// Analyzes app data from Fleet exports to identify vendors, common signing IDs,
    /// and other patterns that can be used to create bundle definitions.
    ///
    /// Examples:
    ///   contour santa discover --input fleet-export.csv --output bundles.toml
    ///   contour santa discover --input data.csv --interactive
    #[command(hide = true)]
    Discover {
        /// Input Fleet CSV file
        #[arg(short, long)]
        input: PathBuf,

        /// Output file for suggested bundles (TOML format)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Minimum device coverage percentage (0.0 - 1.0) to include in suggestions
        #[arg(long, default_value = "0.05")]
        threshold: f64,

        /// Minimum number of apps from a vendor to suggest a bundle
        #[arg(long, default_value = "1")]
        min_apps: usize,

        /// Interactive mode: review and edit bundles before saving
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Also discover unsigned / unidentified apps by name similarity
        #[arg(long)]
        include_unsigned: bool,
    },

    /// Classify apps using bundle definitions and report coverage
    ///
    /// Evaluates each app against bundle CEL expressions and generates
    /// a coverage report showing which bundles matched which apps.
    ///
    /// Examples:
    ///   contour santa classify --input fleet.csv --bundles bundles.toml
    ///   contour santa classify --input data.csv --bundles bundles.toml --orphan-policy warn
    #[command(hide = true)]
    Classify {
        /// Input Fleet CSV file
        #[arg(short, long)]
        input: PathBuf,

        /// Bundle definitions file (TOML)
        #[arg(short, long)]
        bundles: PathBuf,

        /// Output file for classification results (YAML)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Policy for apps that match no bundle
        #[arg(long, value_enum, default_value = "catch-all")]
        orphan_policy: OrphanPolicy,

        /// Policy for apps that match multiple bundles
        #[arg(long, value_enum, default_value = "most-specific")]
        conflict_policy: ConflictPolicy,
    },

    /// Run the full pipeline from CSV to mobileconfig profiles
    ///
    /// Combines discovery, classification, and rule generation into a single
    /// command with deterministic, GitOps-friendly output.
    ///
    /// Examples:
    ///   contour santa pipeline --input fleet.csv --bundles bundles.toml --output-dir ./profiles
    ///   contour santa pipeline --input data.csv --bundles bundles.toml --org com.company
    ///   contour santa pipeline --input data.csv --bundles bundles.toml --layer-stage
    #[command(visible_alias = "pipe")]
    Pipeline {
        /// Input Fleet CSV file
        #[arg(short, long)]
        input: PathBuf,

        /// Bundle definitions file (TOML)
        #[arg(short, long)]
        bundles: PathBuf,

        /// Output directory for generated profiles
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Organization identifier prefix
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Deduplication level for apps across devices
        #[arg(long, value_enum, default_value = "signing-id")]
        dedup_level: DedupLevel,

        /// Rule type to generate (team-id for vendor-level, signing-id for app-level)
        #[arg(long, value_enum, default_value = "prefer-signing-id")]
        rule_type: RuleTypeStrategy,

        /// Policy for apps that match no bundle
        #[arg(long, value_enum, default_value = "catch-all")]
        orphan_policy: OrphanPolicy,

        /// Policy for apps that match multiple bundles
        #[arg(long, value_enum, default_value = "most-specific")]
        conflict_policy: ConflictPolicy,

        /// Enable deterministic output (sorted rules, reproducible UUIDs)
        #[arg(long, default_value = "true")]
        deterministic: bool,

        /// Enable Layer × Stage matrix output
        ///
        /// Generates separate profiles for each combination of layer (audience)
        /// and stage (rollout phase). Layers inherit from parent layers and
        /// stages cascade (Alpha includes Beta + Prod rules).
        #[arg(long)]
        layer_stage: bool,

        /// Number of stages (2=test/prod, 3=alpha/beta/prod, 5=canary/alpha/beta/early/prod)
        #[arg(long, default_value = "3")]
        stages: u8,

        /// Preview without writing files
        #[arg(long)]
        dry_run: bool,
    },

    /// Scan local applications with santactl, or codesign when Santa is not installed
    ///
    /// For users without Fleet, this scans local applications and generates
    /// output in various formats for different workflows.
    ///
    /// Uses `santactl fileinfo` when Santa is installed, and `codesign` — which
    /// every Mac has — when it is not. For an app.settings declaration alone,
    /// `contour profile ddm app-control scan` does the same without Santa's
    /// rule formats.
    ///
    /// Examples:
    ///   contour santa scan                                    # Scan /Applications → CSV
    ///   contour santa scan --output-format bundles --output bundles.toml
    ///   contour santa scan --output-format rules --output rules.yaml
    ///   contour santa scan --output-format mobileconfig --output santa.mobileconfig --org com.example
    ///   contour santa scan --output-format baseline --output baseline.toml   # merge-with-existing
    Scan {
        /// Directories to scan for applications
        #[arg(short, long, default_value = "/Applications")]
        path: Vec<PathBuf>,

        /// Output file (extension inferred from format if not specified)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Output format
        #[arg(short = 'f', long, value_enum, default_value = "csv")]
        output_format: ScanOutputFormat,

        /// Include unsigned applications
        #[arg(long)]
        include_unsigned: bool,

        /// Organization identifier (required for mobileconfig format)
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Rule type for rules/mobileconfig output
        #[arg(long, value_enum, default_value = "team-id")]
        rule_type: ScanRuleType,

        /// app-settings output: leave Apple's software out of the allow list.
        /// By default it gets `TeamID = "*APPLE*"`: the list is exclusive, and
        /// without it Apple's own apps stop launching
        #[arg(long)]
        no_apple: bool,

        /// Merge multiple scan CSVs into one (for aggregating from multiple machines)
        #[arg(long)]
        merge: Option<Vec<PathBuf>>,
    },

    /// Report where a Santa ruleset and an app.settings declaration disagree
    ///
    /// Santa and app.settings are independent gates: a binary runs only when
    /// neither blocks it. This reports every app one gate allows and the other
    /// would block, allows cancelled by a deny on the other gate, and Santa
    /// rules app.settings cannot express. Matching is by coverage — a TeamID
    /// allow admits every SigningID allow from that team. Exits non-zero on
    /// drift.
    Parity {
        /// Santa rule file(s)
        #[arg(required = true)]
        rules: Vec<PathBuf>,

        /// The com.apple.configuration.app.settings declaration (JSON)
        #[arg(long)]
        declaration: PathBuf,

        /// Santa's client mode. In monitor mode Santa blocks nothing, so an
        /// app.settings-only allow is harmless; lockdown is the strict default.
        #[arg(long, value_enum, default_value = "lockdown")]
        santa_mode: crate::config::ClientMode,
    },

    /// Generate a com.apple.configuration.app.settings declaration (macOS 27+)
    ///
    /// Converts existing Santa rules (`--from-rules`) or a scan CSV into Apple's
    /// declarative binary-execution-control declaration. Add app privacy
    /// permission defaults from a policy file (`--permissions`) or scaffold an
    /// editable one (`--scaffold`).
    #[command(name = "app-settings")]
    AppSettings {
        /// Input: Santa rule files (with --from-rules) or scan CSV file(s)
        #[arg(required = true)]
        input: Vec<PathBuf>,

        /// Treat input as Santa rules to convert (policy taken per rule)
        #[arg(long)]
        from_rules: bool,

        /// Privacy permission policy file (TOML) → Privacy.PermissionDefaults
        #[arg(long, value_name = "FILE")]
        permissions: Option<PathBuf>,

        /// Emit an editable Privacy policy skeleton from a scan (not a declaration)
        #[arg(long)]
        scaffold: bool,

        /// Implicitly allow managed apps (AlwaysAllowManagedApps)
        #[arg(long)]
        always_allow_managed: bool,

        /// Leave Apple's software out of an allow list. By default an
        /// `AllowedBinaries` list gets `TeamID = "*APPLE*"`: the list is
        /// exclusive, and without it Apple's own apps stop launching
        #[arg(long)]
        no_apple: bool,

        /// Identifier strategy for scan input
        #[arg(long, value_enum, default_value = "auto")]
        rule_type: ScanRuleType,

        /// Target platform (combined emits every applicable key)
        #[arg(long, value_enum, default_value = "combined")]
        platform: TargetPlatform,

        /// Route scan entries to DeniedBinaries instead of AllowedBinaries
        #[arg(long)]
        deny: bool,

        /// Organization reverse domain. Without it: CONTOUR_ORG, then
        /// .contour/config.toml; with none of the three the command stops.
        #[arg(long)]
        org: Option<String>,

        /// Fail if any input entry can't be converted or fails validation
        #[arg(long)]
        strict: bool,

        /// Output file (default: app-settings.json, or app-permissions.toml for --scaffold)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Convert CSV to a Santa allowlist mobileconfig (no bundles needed)
    ///
    /// Takes a CSV from `contour santa scan` or a Fleet export and generates
    /// a mobileconfig profile directly — no discovery or bundle step required.
    ///
    /// Examples:
    ///   contour santa allow --input local-apps.csv
    ///   contour santa allow --input local-apps.csv --output my-rules.mobileconfig --org com.myorg
    ///   contour santa allow --input fleet-export.csv --rule-type team-id --dry-run
    Allow {
        /// Input CSV file (from `contour santa scan` or Fleet export)
        #[arg(short, long)]
        input: PathBuf,

        /// Output file path
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Rule type to generate
        #[arg(long, value_enum, default_value = "signing-id")]
        rule_type: ScanRuleType,

        /// Organization identifier prefix (e.g., com.example)
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Profile display name
        #[arg(long)]
        name: Option<String>,

        /// Disable deterministic UUIDs (deterministic is the default for GitOps)
        #[arg(long)]
        no_deterministic_uuids: bool,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Interactive guided selection of apps to allow
    ///
    /// Walk through Fleet CSV data and interactively select which apps
    /// to include in your Santa allowlist. Supports selection by vendor
    /// (TeamID) or by individual app (SigningID).
    ///
    /// Examples:
    ///   contour santa select --input fleet.csv --output rules.yaml
    ///   contour santa select --input data.csv --rule-type signing-id
    #[command(hide = true)]
    Select {
        /// Input Fleet CSV file
        #[arg(short, long)]
        input: PathBuf,

        /// Output file for selected rules (YAML)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Rule type to generate (signing-id or team-id)
        #[arg(long, default_value = "signing-id")]
        rule_type: String,

        /// Organization identifier for generated profiles
        #[arg(long, default_value = "com.example")]
        org: String,
    },

    /// CEL expression tools (check, evaluate, classify)
    Cel {
        #[command(subcommand)]
        action: CelAction,
    },

    /// File Access Authorization (FAA) policy tools
    ///
    /// Generate, validate, and inspect FAA policies for Santa.
    /// FAA policies control which processes can access specific file paths.
    ///
    /// Examples:
    ///   contour santa faa generate policy.yaml -o policy.plist
    ///   contour santa faa validate policy.yaml
    ///   contour santa faa schema --json
    Faa {
        #[command(subcommand)]
        action: FaaAction,
    },

    /// Extract (snip) matching rules from one file into another
    Snip {
        /// Source rules file
        #[arg(short, long)]
        source: PathBuf,

        /// Destination rules file (created if missing, appended if exists)
        #[arg(short, long)]
        dest: PathBuf,

        /// Snip rules matching this identifier substring
        #[arg(long)]
        identifier: Option<String>,

        /// Snip rules of this type
        #[arg(long, value_enum)]
        rule_type: Option<RuleType>,

        /// Snip rules with this policy
        #[arg(long, value_enum)]
        policy: Option<Policy>,

        /// Snip rules in this group
        #[arg(long)]
        group: Option<String>,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum CelAction {
    /// List available CEL context fields and operators
    Fields,
    /// Check if a CEL expression compiles and validate field references
    Check {
        /// CEL expression to validate
        expression: String,
        /// Allow V2-only fields (ancestors, fds)
        #[arg(long)]
        v2: bool,
    },
    /// Evaluate a CEL expression against an app record
    Eval {
        /// CEL expression to evaluate
        expression: String,
        /// App record fields (KEY=VALUE, e.g., team_id=EQHXZ8M8AV)
        #[arg(long = "field", value_name = "KEY=VALUE", num_args = 1)]
        fields: Vec<String>,
    },
    /// Classify apps from CSV against bundle definitions
    Classify {
        /// Path to bundles TOML file
        bundles: PathBuf,
        /// Input Fleet CSV file
        #[arg(long, short)]
        input: PathBuf,
    },
    /// Compile structured conditions into a CEL expression
    Compile {
        /// Conditions in "field op value" format (e.g., "target.team_id == EQHXZ8M8AV")
        #[arg(long = "condition", short = 'c', num_args = 1)]
        conditions: Vec<String>,

        /// How to combine conditions: all (AND) or any (OR)
        #[arg(long, default_value = "all")]
        logic: String,

        /// Result when conditions match
        #[arg(long, default_value = "blocklist")]
        result: String,

        /// Result when conditions don't match
        #[arg(long, default_value = "allowlist")]
        else_result: String,
    },
    /// Run CEL expressions against test cases (dry-run simulation)
    DryRun {
        /// Test cases file (YAML or TOML)
        input: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
pub enum FaaAction {
    /// Generate FAA plist from YAML policy
    ///
    /// Reads a YAML policy file and produces an Apple plist file
    /// conforming to Santa's WatchItems schema.
    Generate {
        /// Input YAML policy file
        #[arg(help = "Input YAML policy file")]
        input: PathBuf,

        /// Output plist file path (defaults to <input>.plist)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Validate FAA policy YAML
    ///
    /// Checks that paths are absolute, processes have identity fields,
    /// and rule types have the required process specifications.
    Validate {
        /// Input YAML policy file
        #[arg(help = "Input YAML policy file")]
        input: PathBuf,
    },

    /// Show FAA schema (rule types, options, process fields, placeholders)
    Schema,
}

#[derive(Debug, Subcommand)]
pub enum RingsCommands {
    /// Generate per-ring editions (one mobileconfig per ring × category)
    ///
    /// Each ring profile is a complete, self-contained edition: core rules
    /// (rules with empty `rings:`) merged with that ring's specialized rules.
    Generate {
        /// Input rule files (YAML, JSON, CSV)
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output directory for ring editions
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Organization identifier prefix
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Profile name prefix (e.g., "santa" -> santa1a, santa1b, etc.)
        #[arg(long, default_value = "santa")]
        prefix: String,

        /// Number of rings (5 or 7 for built-in configs; otherwise custom)
        #[arg(long, value_parser = clap::value_parser!(u8).range(1..=16), conflicts_with = "rings_config")]
        num_rings: Option<u8>,

        /// Ring configuration file (as produced by `rings init`)
        #[arg(long, value_name = "PATH")]
        rings_config: Option<PathBuf>,

        /// Curated baseline TOML applied to every edition; conflicts resolve deny-wins
        #[arg(long, value_name = "PATH")]
        baseline: Option<PathBuf>,

        /// Maximum rules per edition (splits into santa1a-001, santa1a-002, etc.)
        #[arg(long)]
        max_rules: Option<usize>,

        /// Treat unknown ring names in rules as a hard error
        #[arg(long)]
        strict: bool,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Initialize a ring configuration file
    Init {
        /// Output file path
        #[arg(short, long, default_value = "rings.yaml")]
        output: PathBuf,

        /// Number of rings
        #[arg(long, default_value = "5", value_parser = clap::value_parser!(u8).range(1..=16))]
        num_rings: u8,
    },
}
