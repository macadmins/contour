pub mod add;
pub mod allow_cmd;
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
pub mod pipeline_cmd;
pub mod prep;
pub mod remove;
pub mod rings;
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
}

/// Rule type strategy for scan output
#[derive(Debug, Clone, Copy, Default, clap::ValueEnum)]
pub enum ScanRuleType {
    /// Generate TeamID rules (vendor-level, fewer rules)
    #[default]
    TeamId,
    /// Generate SigningID rules (app-level, more specific)
    SigningId,
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

    /// Generate Fleet GitOps compatible output
    ///
    /// Creates a directory structure with profiles and manifests compatible
    /// with Fleet's GitOps workflow. Labels are used to target rings.
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

        /// Fleet team name
        #[arg(long, default_value = "Workstations")]
        team: String,

        /// Number of rings
        #[arg(long, default_value = "5")]
        num_rings: u8,

        /// Preview without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory instead of full GitOps structure
        #[arg(long)]
        fragment: bool,
    },

    /// Add a rule to an existing rules file (for posthook integration)
    ///
    /// Designed for use with Installomator posthooks or santactl output to maintain an allowlist.
    ///
    /// Examples:
    ///   contour santa add --file rules.yaml --teamid EQHXZ8M8AV --description "Google"
    ///   santactl fileinfo /path/to/app | contour santa add --file rules.yaml --from-stdin
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

    /// Scan local applications using santactl (alternative to Fleet)
    ///
    /// For users without Fleet, this scans local applications and generates
    /// output in various formats for different workflows.
    ///
    /// Requires Santa to be installed (santactl must be available).
    ///
    /// Examples:
    ///   contour santa scan                                    # Scan /Applications → CSV
    ///   contour santa scan --output-format bundles --output bundles.toml
    ///   contour santa scan --output-format rules --output rules.yaml
    ///   contour santa scan --output-format mobileconfig --output santa.mobileconfig --org com.example
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

        /// Merge multiple scan CSVs into one (for aggregating from multiple machines)
        #[arg(long)]
        merge: Option<Vec<PathBuf>>,
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
    /// Generate profiles for all rings
    Generate {
        /// Input rule files (YAML, JSON, CSV)
        #[arg(required = true)]
        inputs: Vec<PathBuf>,

        /// Output directory for ring profiles
        #[arg(short, long)]
        output_dir: Option<PathBuf>,

        /// Organization identifier prefix
        #[arg(long, default_value = "com.example")]
        org: String,

        /// Profile name prefix (e.g., "santa" -> santa1a, santa1b, etc.)
        #[arg(long, default_value = "santa")]
        prefix: String,

        /// Number of rings (5 or 7 for standard configs, or custom)
        #[arg(long, default_value = "5")]
        num_rings: u8,

        /// Maximum rules per profile (splits into santa1a-001, santa1a-002, etc.)
        #[arg(long)]
        max_rules: Option<usize>,

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
        #[arg(long, default_value = "5")]
        num_rings: u8,
    },
}
