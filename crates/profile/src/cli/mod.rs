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
pub mod library;
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
    #[command(
        about = "Show CLI info, OR detailed schema for a payload type if one is given",
        long_about = "Without arguments: show CLI version, config, and schema statistics.\n\
                      \n\
                      With `<payload_type>`: dump the full Apple schema for that\n\
                      payload — title, description, platforms, and every field's\n\
                      type + plist tag (`<real>`, `<integer>`, …) + required flag\n\
                      + default + allowed values. Mirrors `profile ddm info <name>`\n\
                      so schema-introspection has one consistent surface.\n\
                      \n\
                      Examples:\n  \
                      contour profile info\n  \
                      contour profile info com.apple.applicationaccess --json\n  \
                      contour profile info com.apple.applicationaccess --full"
    )]
    Info {
        /// Payload type for schema lookup (optional). Omit to show CLI metadata.
        #[arg(value_name = "PAYLOAD_TYPE")]
        payload_type: Option<String>,

        #[arg(long, help = "External schema directory (overrides embedded)")]
        schema_path: Option<String>,

        #[arg(long, help = "Include all fields (not just required + top-level)")]
        full: bool,

        #[arg(
            long,
            value_name = "NAME",
            help = "Restrict output to one OS (macOS|iOS|tvOS|watchOS|visionOS)",
            long_help = "Restrict output to a single platform.\n\
                         \n\
                         When set, `os_support` is scoped to that platform's\n\
                         metadata, and the call fails fast if the payload is\n\
                         not supported on that OS at all — preventing agents\n\
                         from generating profiles that won't install on the\n\
                         target.\n\
                         \n\
                         Accepts: macOS|mac, iOS|ipad|ipados, tvOS|tv,\n\
                         watchOS|watch, visionOS|vision (case-insensitive)."
        )]
        os: Option<String>,
    },

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

        #[arg(
            long,
            value_delimiter = ',',
            value_name = "NAMES",
            long_help = "Opt into org-policy lint checks (Tier-2). Default\n\
                         `validate` runs Apple-schema checks only; this\n\
                         flag adds authoring-convention checks on top.\n\
                         \n\
                         Pass `all` to enable every Tier-2 check, or a\n\
                         comma-separated list of names. Unknown names\n\
                         exit non-zero with the valid list.\n\
                         \n\
                         Composes with --strict: when both are set,\n\
                         Tier-2 warnings are promoted to errors.\n\
                         \n\
                         Valid names:\n  \
                         - all\n  \
                         - payload-identifier-reverse-dns\n  \
                         - payload-organization-required\n  \
                         - payload-scope-consistency\n  \
                         - nested-payload-identifier-prefix",
            help = "Opt into org-policy lint checks (comma-separated names, or `all`)"
        )]
        lint_policy: Vec<String>,

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

    #[command(
        about = "Search payload schemas by keyword, by exact field name, or in polymorphic mode",
        long_about = "Three modes:\n\
                      \n\
                      Substring search (default): match against payload type,\n\
                      title, description, and field names — returns matching\n\
                      payloads.\n\
                      \n\
                      `--field <NAME>`: exact field-name lookup across every\n\
                      payload. Returns each match with the payload_type plus\n\
                      full field detail (type, plist tag, required, default,\n\
                      allowed values). Single-call answer to 'what type does\n\
                      Apple expect for <key>?'.\n\
                      \n\
                      `--include-fields`: polymorphic mode. Substring-matches\n\
                      across payload-level metadata AND field-level metadata,\n\
                      returns categorized JSON with `payload_matches[]` and\n\
                      `field_matches[]` arrays — each hit carries a\n\
                      `matched_in[]` tag naming where the substring landed\n\
                      (name / title / description / payload_type).\n\
                      \n\
                      Examples:\n  \
                      contour profile search wifi\n  \
                      contour profile search --field safariAcceptCookies --json\n  \
                      contour profile search cookie --include-fields --json"
    )]
    Search {
        #[arg(
            help = "Substring query (e.g., passcode, wifi). Required unless --field is given.",
            required_unless_present = "field",
            conflicts_with = "field"
        )]
        query: Option<String>,

        #[arg(
            long,
            value_name = "NAME",
            conflicts_with_all = ["query", "include_fields"],
            help = "Exact field-name lookup across all payloads — returns field detail per match"
        )]
        field: Option<String>,

        #[arg(
            long,
            requires = "query",
            conflicts_with = "field",
            help = "Polymorphic mode: also walk field metadata; returns {payload_matches, field_matches}"
        )]
        include_fields: bool,

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

    /// Scaffold or manage an external preset/recipe library
    #[command(
        about = "Scaffold an external preset/recipe library",
        long_about = "Create a starter directory for hosting your own DDM\n\
                      presets and MDM recipes that contour can resolve via\n\
                      `--preset-path` / `--recipe-path`. The scaffold copies\n\
                      every embedded built-in into the new tree, alongside\n\
                      a `.meaning.md` sidecar per file and a CI workflow\n\
                      that lints the library on every push.\n\
                      \n\
                      Example:\n  \
                      contour profile library new ./contour-presets"
    )]
    Library {
        #[command(subcommand)]
        action: LibraryAction,
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
        #[arg(
            short,
            long,
            help = "Output directory (required unless --stdout)",
            conflicts_with = "stdout",
            required_unless_present = "stdout"
        )]
        output: Option<String>,

        #[arg(
            long,
            help = "Print markdown to stdout instead of writing files (no /tmp clutter)",
            conflicts_with = "output"
        )]
        stdout: bool,

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

    #[command(
        about = "Compose a DDM bundle (asset + configuration + activation) from one TOML input",
        long_about = "Compose a DDM bundle from a single TOML input describing one DDM intent.\n\
                      \n\
                      Reads the bundle, computes identifiers from the org domain + intent_name,\n\
                      auto-wires the asset reference into the configuration's *AssetReference\n\
                      field, and writes asset.json / configuration.json / activation.json into\n\
                      the output directory in BUILD ORDER. By construction, dangling references\n\
                      and identifier collisions become impossible.\n\
                      \n\
                      Bundle format documented in sop-ddm.md."
    )]
    Compose {
        /// Path to a bundle TOML. Required unless `--preset` or
        /// `--list-presets` is set.
        #[arg(
            help = "Bundle TOML file describing a DDM intent",
            required_unless_present_any = ["preset", "list_presets"],
            conflicts_with_all = ["preset", "list_presets"]
        )]
        bundle: Option<String>,

        #[arg(
            short,
            long,
            help = "Output directory for the emitted .json declarations",
            required_unless_present = "list_presets"
        )]
        output: Option<String>,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo (overrides embedded schema)"
        )]
        schema_path: Option<String>,

        #[arg(
            long,
            help = "Allow assets that are declared but not referenced by the configuration"
        )]
        allow_orphans: bool,

        #[arg(
            long,
            value_name = "ORG",
            help = "Organization reverse-DNS (overrides CONTOUR_ORG env / profile.toml)"
        )]
        org: Option<String>,

        #[arg(
            long,
            value_name = "NAME",
            conflicts_with_all = ["bundle", "list_presets"],
            help = "Compose a preset by name — embedded or from --preset-path",
            long_help = "Compose a preset bundle by name instead of supplying a\n\
                         path. Resolution: --preset-path (file or directory)\n\
                         → ~/.contour/presets/ → embedded. External presets\n\
                         win on name collisions.\n\
                         \n  \
                         contour profile ddm compose \\\n    \
                           --preset disable-apple-intelligence-macos \\\n    \
                           --org com.acme -o ./out/\n\
                         \n\
                         List available presets with --list-presets."
        )]
        preset: Option<String>,

        #[arg(
            long,
            value_name = "DIR_OR_FILE",
            help = "External preset library (directory of .toml or single file). Builds a preset library by name.",
            long_help = "Path to an external preset library — either a directory\n\
                         of `.toml` bundle files (filename = preset name) or a\n\
                         single bundle file. Used by --preset and --list-presets.\n\
                         \n\
                         Library convention: one .toml per preset, alphabetic\n\
                         filenames. The repo can be a simple github clone,\n\
                         e.g. `git clone https://github.com/yourorg/contour-presets`.\n\
                         \n\
                         Resolution: --preset-path → ~/.contour/presets/ →\n\
                         embedded. External wins on name collisions; listings\n\
                         flag overrides via the `source` field."
        )]
        preset_path: Option<String>,

        #[arg(
            long,
            help = "List presets available via --preset (embedded + external)",
            conflicts_with_all = ["bundle", "preset", "output"]
        )]
        list_presets: bool,
    },

    #[command(
        about = "Verify cross-references across a directory of DDM declarations",
        long_about = "Walks every .json declaration in a directory and checks:\n\
                      \n\
                      - reference DAG: configurations resolve to assets, activations\n\
                        resolve to configurations\n\
                      - predicate gating: every @status('key') in an activation\n\
                        predicate is covered by a status-subscriptions declaration\n\
                      - ServerToken absence (server-managed field, never authored)\n\
                      \n\
                      Exits 0 on a clean directory; exits 1 on any error. Warnings\n\
                      (orphan assets / configurations, unused subscription keys) do not\n\
                      fail unless --strict is set."
    )]
    Verify {
        #[arg(help = "Directory containing DDM .json declaration files")]
        directory: String,

        #[arg(short, long, help = "Recurse into subdirectories")]
        recursive: bool,

        #[arg(
            long,
            help = "Treat warnings as errors (orphans, unused subscriptions)"
        )]
        strict: bool,
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

#[derive(Debug, Subcommand)]
pub enum LibraryAction {
    #[command(
        about = "Scaffold a new preset/recipe library at PATH",
        long_about = "Create a starter directory tree for hosting your\n\
                      own DDM presets and MDM recipes. Copies every\n\
                      embedded built-in into the new tree as a starting\n\
                      point and writes a CI workflow that lints the\n\
                      library. Each TOML ships with a `.meaning.md`\n\
                      sidecar for human-readable intent docs.\n\
                      \n\
                      Refuses to overwrite a non-empty target unless\n\
                      `--force` is passed.\n\
                      \n\
                      Example:\n  \
                      contour profile library new ./contour-presets"
    )]
    New {
        /// Target directory for the scaffold (created if missing)
        #[arg(value_name = "PATH")]
        path: String,

        /// Skip the `ddm/` directory and embedded DDM presets
        #[arg(long)]
        no_presets: bool,

        /// Skip the `recipes/` directory and embedded MDM recipes
        #[arg(long)]
        no_recipes: bool,

        /// Overwrite files in a non-empty target directory
        #[arg(short, long)]
        force: bool,
    },
}
