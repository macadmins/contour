//! CLI command definitions and handlers.
//!
//! This module defines the command-line interface using clap, including all
//! subcommands, arguments, and their handlers for profile operations.

// Core modules
pub mod command;
pub mod ddm;
pub mod diff;
pub mod docs;
pub mod duplicate;
pub mod enrollment;
pub mod generate;
pub mod glob_utils;
pub mod import;
pub mod info;
pub mod init;
pub mod jamf_import;
pub mod link;
pub mod normalize;
pub mod payload;
pub mod post_generate;
pub mod scan;
pub mod search;
pub mod sign;
pub mod synthesize;
pub mod unsign;
pub mod uuid;
pub mod validate;

use clap::{Parser, Subcommand};

const ABOUT: &str = "Profile - Apple configuration profile toolkit (Community Edition)";

#[derive(Debug, Parser)]
#[command(name = "profile")]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP"), "\nCopyright (c) 2025 Mac Admins Open Source\nLicense: Apache-2.0"))]
#[command(about = ABOUT, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose logging
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[arg(
        long,
        global = true,
        help = "Output in JSON format for CI/CD integration"
    )]
    pub json: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    #[command(about = "Show Profile CLI version, configuration, and schema statistics")]
    Info,

    #[command(about = "Initialize a new profile.toml configuration file")]
    Init {
        #[arg(short, long, help = "Output file path (default: ./profile.toml)")]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(long, help = "Organization name")]
        name: Option<String>,

        #[arg(short, long, help = "Overwrite existing config")]
        force: bool,
    },

    #[command(about = "Import profiles from a directory with interactive selection")]
    Import {
        #[arg(help = "Source directory containing .mobileconfig files")]
        source: String,

        #[arg(short, long, help = "Output directory for imported profiles")]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(long, help = "Organization name (sets PayloadOrganization)")]
        name: Option<String>,

        #[arg(long, help = "Skip validation after normalization")]
        no_validate: bool,

        #[arg(long, help = "Skip UUID regeneration")]
        no_uuid: bool,

        #[arg(long, help = "Maximum directory depth for recursive search")]
        max_depth: Option<usize>,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,

        #[arg(long, help = "Import all profiles without interactive selection")]
        all: bool,

        /// Import from Jamf backup YAML files (jamf-cli export format)
        #[arg(long)]
        jamf: bool,
    },

    #[command(about = "Normalize a configuration profile (standardize identifiers)")]
    Normalize {
        #[arg(help = "Profile file(s) or directory to normalize", required_unless_present = "pasteboard", num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, help = "Read profile from macOS pasteboard")]
        pasteboard: bool,

        #[arg(
            short,
            long,
            help = "Output file path (single file) or directory (batch)"
        )]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(long, help = "Organization name (sets PayloadOrganization)")]
        name: Option<String>,

        #[arg(long, help = "Skip validation")]
        no_validate: bool,

        #[arg(long, help = "Skip UUID regeneration")]
        no_uuid: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,

        #[arg(long, help = "Write markdown normalize report to file")]
        report: Option<String>,
    },

    #[command(about = "Duplicate a profile with unique identity values (name, identifier, UUIDs)")]
    Duplicate {
        #[arg(help = "Source .mobileconfig file")]
        source: String,

        #[arg(long, help = "New PayloadDisplayName (interactive prompt if omitted)")]
        name: Option<String>,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(long, help = "Use predictable v5 UUIDs based on new identifier")]
        predictable: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,
    },

    #[command(about = "Validate a configuration profile against Apple schema")]
    Validate {
        #[arg(help = "Profile file(s) or directory to validate", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, help = "Skip schema-based validation of payload fields")]
        no_schema: bool,

        #[arg(
            long,
            help = "Path to external schema directory (ProfileManifests, Apple YAML)"
        )]
        schema_path: Option<String>,

        #[arg(
            long,
            help = "Path to ProfileManifests repo for third-party identifier lookup"
        )]
        lookup: Option<String>,

        #[arg(long, help = "Strict mode: treat warnings as errors")]
        strict: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Write markdown validation report to file")]
        report: Option<String>,

        #[arg(
            long,
            help = "Reject MDM template placeholders ($VAR, {{VAR}}, %VAR%) — by default placeholders are accepted with warnings"
        )]
        no_placeholders: bool,
    },

    #[command(about = "Scan profile(s) to show metadata")]
    Scan {
        #[arg(help = "Profile file(s) or directory to scan", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, help = "Simulate normalize with this domain")]
        simulate: bool,

        #[arg(long, help = "Organization reverse domain for simulation")]
        org: Option<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,
    },

    #[command(about = "Search payload schemas by keyword (type, title, description, keys)")]
    Search {
        #[arg(help = "Search query (e.g., passcode, wifi, vpn, filevault)")]
        query: String,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,
    },

    #[command(about = "Manage UUIDs in configuration profile")]
    Uuid {
        #[arg(help = "Profile file(s) or directory to process", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            short,
            long,
            help = "Output file path (single file) or directory (batch)"
        )]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(short, long, help = "Generate predictable UUIDs")]
        predictable: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,
    },

    #[command(about = "Compare two configuration profiles")]
    Diff {
        #[arg(help = "First configuration profile file")]
        file1: String,

        #[arg(help = "Second configuration profile file")]
        file2: String,

        #[arg(short, long, help = "Output diff to file (optional)")]
        output: Option<String>,
    },

    #[command(about = "Remove signature from a signed configuration profile")]
    Unsign {
        #[arg(help = "Profile file(s) or directory to unsign", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            short,
            long,
            help = "Output file path (single file) or directory (batch)"
        )]
        output: Option<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,
    },

    #[command(about = "Sign a configuration profile")]
    Sign {
        #[arg(help = "Profile file(s) or directory to sign", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            short,
            long,
            help = "Output file path (single file) or directory (batch)"
        )]
        output: Option<String>,

        #[arg(short, long, help = "Signing identity (certificate name or SHA-1)")]
        identity: Option<String>,

        #[arg(short, long, help = "Keychain path")]
        keychain: Option<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,
    },

    #[command(about = "Verify a signed profile's signature")]
    Verify {
        #[arg(help = "Profile file(s) or directory to verify", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,
    },

    #[command(about = "List available signing identities")]
    Identities,

    #[command(about = "Link UUID cross-references between profiles")]
    Link {
        #[arg(help = "Profile file(s) or directory to link", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Output file (merged) or directory (separate)")]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain")]
        org: Option<String>,

        #[arg(short, long, help = "Generate predictable UUIDs")]
        predictable: bool,

        #[arg(long, help = "Merge all profiles into a single output profile")]
        merge: bool,

        #[arg(long, help = "Skip validation of cross-references")]
        no_validate: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Preview changes without writing files")]
        dry_run: bool,
    },

    #[command(about = "Generate markdown documentation from payload schemas")]
    Docs {
        #[command(subcommand)]
        action: DocsAction,
    },

    #[command(about = "Inspect and extract payloads from profiles")]
    Payload {
        #[command(subcommand)]
        action: PayloadAction,
    },

    #[command(about = "Generate a profile from schema or recipe")]
    Generate {
        #[arg(help = "Payload type(s) — one for generate, multiple for --create-recipe")]
        payload_type: Vec<String>,

        #[arg(short, long, help = "Output file or directory")]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain")]
        org: Option<String>,

        #[arg(long, help = "Include all fields (not just required)")]
        full: bool,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,

        #[arg(long, help = "Generate from a named recipe")]
        recipe: Option<String>,

        #[arg(long, help = "Path to recipe file or directory")]
        recipe_path: Option<String>,

        #[arg(long, help = "List available recipes")]
        list_recipes: bool,

        #[arg(
            long = "set",
            value_name = "KEY=VALUE",
            help = "Set placeholder value (e.g., --set OKTA_DOMAIN=mycompany.okta.com)",
            num_args = 1
        )]
        vars: Vec<String>,

        #[arg(
            long,
            help = "Create a recipe TOML from payload types (e.g., --create-recipe m365 com.microsoft.Edge com.microsoft.Outlook)"
        )]
        create_recipe: Option<String>,

        #[arg(long, help = "Interactive mode — pick segments and set field values")]
        interactive: bool,

        #[arg(
            long,
            value_parser = ["mobileconfig", "plist"],
            default_value = "mobileconfig",
            help = "Output format: mobileconfig (full profile) or plist (raw payload dict for WS1)"
        )]
        format: String,
    },

    #[command(about = "Work with Declarative Device Management (DDM) declarations")]
    Ddm {
        #[command(subcommand)]
        action: DdmAction,
    },

    /// Generate Apple MDM command payloads (.plist)
    Command {
        #[command(subcommand)]
        action: CommandAction,
    },

    /// Work with enrollment profiles (DEP/ADE Setup Assistant)
    Enrollment {
        #[command(subcommand)]
        action: EnrollmentAction,
    },

    /// Synthesize mobileconfig profiles from managed preference plists
    Synthesize {
        #[arg(help = "Plist file(s) or directory of managed preferences", required = true, num_args = 1..)]
        paths: Vec<std::path::PathBuf>,

        #[arg(short, long, help = "Output directory for generated mobileconfigs")]
        output: Option<std::path::PathBuf>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(long, help = "Validate keys against Apple schema")]
        validate: bool,

        #[arg(long, help = "Preview without writing files")]
        dry_run: bool,

        #[arg(long, help = "Interactive mode -- select which plists to synthesize")]
        interactive: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum DocsAction {
    #[command(about = "Generate markdown documentation")]
    Generate {
        #[arg(short, long, help = "Output directory")]
        output: String,

        #[arg(long, help = "Specific payload type (optional)")]
        payload: Option<String>,

        #[arg(short, long, help = "Filter by category: apple, apps, prefs")]
        category: Option<String>,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,
    },

    #[command(about = "List available payloads for documentation")]
    List {
        #[arg(short, long, help = "Filter by category: apple, apps, prefs")]
        category: Option<String>,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,
    },

    #[command(
        about = "Generate documentation from an existing profile (shows configured vs available keys)"
    )]
    FromProfile {
        #[arg(help = "Path to the configuration profile")]
        file: String,

        #[arg(short, long, help = "Output file path (default: stdout)")]
        output: Option<String>,
    },

    #[command(about = "Generate markdown documentation for DDM declarations (42 types)")]
    Ddm {
        #[arg(short, long, help = "Output directory")]
        output: String,

        #[arg(long, help = "Specific declaration type (optional)")]
        declaration: Option<String>,

        #[arg(
            short,
            long,
            help = "Filter by category: configuration, activation, asset, management"
        )]
        category: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum PayloadAction {
    #[command(about = "List payloads in a profile")]
    List {
        #[arg(help = "Path to the configuration profile")]
        file: String,
    },

    #[command(about = "Read a specific value from a payload")]
    Read {
        #[arg(help = "Path to the configuration profile")]
        file: String,

        #[arg(
            short,
            long,
            help = "Payload type (e.g., wifi, com.apple.wifi.managed)"
        )]
        r#type: String,

        #[arg(short, long, help = "Key to read")]
        key: String,

        #[arg(long, help = "Payload index if multiple of same type (0-based)")]
        index: Option<usize>,
    },

    #[command(about = "Extract specific payload types into a new profile")]
    Extract {
        #[arg(help = "Path to the configuration profile")]
        file: String,

        #[arg(short, long, help = "Payload type(s) to extract", num_args = 1..)]
        r#type: Vec<String>,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum DdmAction {
    #[command(about = "Parse and display DDM declaration(s)")]
    Parse {
        #[arg(help = "DDM JSON file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,
    },

    #[command(about = "Validate DDM declaration(s) against schema")]
    Validate {
        #[arg(help = "DDM JSON file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            short = 'p',
            long,
            help = "Path to Apple device-management repo (optional, uses embedded)"
        )]
        schema_path: Option<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,
    },

    #[command(about = "List available DDM declaration types (42 embedded)")]
    List {
        #[arg(
            short,
            long,
            help = "Filter by category: configuration, activation, asset, management"
        )]
        category: Option<String>,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo"
        )]
        schema_path: Option<String>,
    },

    #[command(about = "Show DDM declaration schema info")]
    Info {
        #[arg(help = "Declaration type name")]
        name: String,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo"
        )]
        schema_path: Option<String>,
    },

    #[command(about = "Generate a DDM declaration JSON from schema")]
    Generate {
        #[arg(help = "Declaration type name (e.g., passcode.settings)")]
        name: String,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,

        #[arg(long, help = "Include all fields (not just required)")]
        full: bool,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo"
        )]
        schema_path: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum CommandAction {
    /// List available MDM commands
    List,
    /// Generate a command plist payload
    Generate {
        /// Command type (e.g., RestartDevice, DeviceLock, RemoveProfile)
        #[arg(required_unless_present = "interactive")]
        command_type: Option<String>,
        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
        /// Set command parameters (KEY=VALUE)
        #[arg(long = "set", value_name = "KEY=VALUE", num_args = 1)]
        params: Vec<String>,
        /// Add a CommandUUID for tracking
        #[arg(long)]
        uuid: bool,
        /// Output as base64-encoded string (ready for Fleet API)
        #[arg(long)]
        base64: bool,
        /// Interactive mode — search, select command, configure params
        #[arg(long)]
        interactive: bool,
    },
    /// Show schema for a specific command
    Info {
        /// Command type
        command_type: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum EnrollmentAction {
    /// List available skip keys for a platform and OS version
    List {
        /// Platform (macOS, iOS, iPadOS, tvOS, visionOS)
        #[arg(long, default_value = "macOS")]
        platform: String,
        /// Filter by OS version (only show keys available for this version)
        #[arg(long)]
        os_version: Option<String>,
    },
    /// Generate a DEP enrollment profile JSON
    Generate {
        /// Platform
        #[arg(long, default_value = "macOS")]
        platform: String,
        /// OS version to target
        #[arg(long)]
        os_version: Option<String>,
        /// Skip ALL available setup items
        #[arg(long)]
        skip_all: bool,
        /// Skip specific items (comma-separated)
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
        /// Profile name
        #[arg(long, default_value = "Automatic enrollment profile")]
        profile_name: String,
        /// Interactive mode — select which items to skip
        #[arg(long)]
        interactive: bool,
    },
}
