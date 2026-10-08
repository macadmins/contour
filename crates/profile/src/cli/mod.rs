//! CLI command definitions and handlers.
//!
//! This module defines the command-line interface using clap, including all
//! subcommands, arguments, and their handlers for profile operations.

// Core modules
pub mod audit;
pub mod classify;
pub mod collisions;
pub mod command;
pub mod ddm;
pub mod ddm_app_control;
pub mod ddm_app_privacy;
pub mod ddm_beta;
pub mod ddm_legacy;
pub mod ddm_reidentify;
pub mod ddm_service_config;
pub mod ddm_status;
pub mod diff;
pub mod dispatch;
pub mod docs;
pub mod duplicate;
pub mod enrollment;
pub mod form;
pub mod fragment;
pub mod generate;
pub mod glob_utils;
pub mod import;
pub mod import_recipe;
pub mod info;
pub mod init;
pub mod jamf_import;
pub mod jamf_preset;
pub mod library;
pub mod library_diff;
pub mod library_validate;
pub mod link;
pub mod mcx;
pub mod normalize;
pub mod payload;
pub mod plan;
pub mod post_generate;
pub mod reidentify;
pub mod report;
pub mod rollback;
pub mod scan;
pub mod search;
pub mod sign;
pub mod synthesize;
pub mod transform;
pub mod unsign;
pub mod uuid;
pub mod validate;
pub mod variables;
pub mod windows_apps;
pub mod windows_generate;
pub mod windows_stig;

use clap::{Parser, Subcommand};

const ABOUT: &str = "Profile - Apple configuration profile toolkit (Community Edition)";

/// Newcomer tips appended to `profile --help` — shown under both the
/// `contour profile` group and the standalone `profile` binary. Points at the
/// discovery aids a first-time user can't see from the command list alone
/// (search, guided SOP, tab-completion, tutorial).
pub const PROFILE_AFTER_HELP: &str = "\
Getting started:
  contour profile find <term>        search these commands (typo-tolerant)
  contour profile generate --help    generate a profile (alias: gen)
  contour help-ai --sop profile      guided profile workflow for AI agents
  contour completions zsh --install  enable <TAB> shell completion
  contour trainer profile            step-by-step interactive tutorial";

/// `--channel` help: says "disabled" only in a build without a seed dataset.
pub const CHANNEL_HELP: &str = if mdm_schema::SEED_DATASET {
    "Schema channel: stable (released), or beta (pre-release OS seed)"
} else {
    "Schema channel: stable (released), or beta (pre-release OS seed — currently disabled)"
};
const BETA_SCHEMA_HELP: &str = if mdm_schema::SEED_DATASET {
    "Use the beta seed schema (shorthand for --channel beta)"
} else {
    "Use the beta seed schema (shorthand for --channel beta) — currently disabled"
};
const BETA_SEARCH_HELP: &str = if mdm_schema::SEED_DATASET {
    "Search the beta seed schema (shorthand for --channel beta)"
} else {
    "Search the beta seed schema (shorthand for --channel beta) — currently disabled"
};
const BETA_GENERATE_HELP: &str = if mdm_schema::SEED_DATASET {
    "Generate against the beta seed schema (shorthand for --channel beta)"
} else {
    "Generate against the beta seed schema (shorthand for --channel beta) — currently disabled"
};
const BETA_COUNT_HELP: &str = if mdm_schema::SEED_DATASET {
    "Count seed declaration types (shorthand for --channel beta)"
} else {
    "Count seed declaration types (shorthand for --channel beta) — currently disabled"
};

#[derive(Debug, Parser)]
#[command(name = "profile")]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP"), "\nCopyright (c) 2025 Mac Admins Open Source\nLicense: Apache-2.0"))]
#[command(about = ABOUT, long_about = None)]
#[command(after_help = PROFILE_AFTER_HELP)]
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

    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = crate::schema::Channel::Stable,
        help = CHANNEL_HELP
    )]
    pub channel: crate::schema::Channel,
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

        #[arg(
            long,
            help = BETA_SCHEMA_HELP
        )]
        beta: bool,

        #[arg(
            long,
            conflicts_with = "beta",
            help = "Look up the Windows CSP dataset (DDF v2) instead of the Apple schema"
        )]
        windows: bool,
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

    #[command(
        about = "Draft a recipe preset from a Jamf Application & Custom Settings manifest",
        long_about = "Read a Jamf manifest (JSON) and write a recipe you own and edit.\n\n                      The manifest is NOT imported into contour's schema. A Jamf manifest                       states no OS availability and carries no version, so nothing built from                       one can say which release of the app it describes — contour will not                       assert it. Every setting in the output is commented out.\n\n                      Dotted keys are reported separately and not resolved: a dot may be part                       of a key's name or a path into a nested dictionary, the manifest cannot                       say which, and the wrong choice writes a profile the app never reads."
    )]
    Preset {
        #[arg(help = "Jamf manifest JSON file")]
        manifest: String,

        #[arg(short, long, help = "Write here instead of stdout")]
        output: Option<String>,

        #[arg(
            long,
            help = "Provenance line(s) for the header, e.g. the repository and commit"
        )]
        source_note: Option<String>,

        #[arg(
            long,
            help = "The preference domain, when the filename and the manifest title disagree"
        )]
        domain: Option<String>,
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

        #[arg(
            long,
            help = "Reject profiles with auto-fixable defects instead of repairing them",
            long_help = "By default, profiles missing a required field that has a known \
                         default (e.g. PayloadVersion) are repaired on the fly with a \
                         warning. With --strict, such profiles are rejected as parse \
                         failures instead."
        )]
        strict: bool,

        /// Import from Jamf backup YAML files (jamf-cli export format)
        #[arg(long)]
        jamf: bool,
    },

    #[command(
        visible_alias = "norm",
        about = "Normalize identifiers / rename org across .mobileconfig and DDM .json declarations"
    )]
    Normalize {
        #[arg(help = "Profile/DDM file(s) or directory to normalize (.mobileconfig + DDM .json)", required_unless_present = "pasteboard", num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, help = "Read profile from macOS pasteboard")]
        pasteboard: bool,

        #[arg(
            short,
            long,
            help = "Output file path (single file) or directory (batch)"
        )]
        output: Option<String>,

        #[arg(
            long = "in-place",
            help = "Overwrite the original files instead of writing -normalized siblings",
            conflicts_with = "output"
        )]
        in_place: bool,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(
            long = "from-org",
            help = "Existing org prefix to replace exactly (DDM .json; default infers a same-depth prefix)"
        )]
        from_org: Option<String>,

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

    #[command(
        visible_alias = "check",
        about = "Validate a configuration profile against Apple schema"
    )]
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

        #[arg(long, help = "Scan for deprecated payload types and keys")]
        deprecations: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Write a Markdown deprecation report to this path (implies --deprecations)"
        )]
        md_report: Option<String>,

        #[arg(
            long,
            help = "Exit non-zero if any deprecation is found (overrides [validation].fail_on_deprecations)"
        )]
        fail_on_deprecations: bool,
    },

    #[command(about = "Make PayloadIdentifiers consistent with UUIDs")]
    Reidentify {
        #[arg(help = "Profile file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(
            long,
            value_name = "SCHEME",
            default_value = "uuid",
            help = "Identifier scheme: uuid (sync to PayloadUUID) or name (slug from display name). Ignored when --from-prefix is given"
        )]
        scheme: String,

        #[arg(
            long,
            requires = "to_prefix",
            help = "Batch mode: rewrite this identifier prefix across the envelope and every payload (matches on dot boundaries)"
        )]
        from_prefix: Option<String>,

        #[arg(long, requires = "from_prefix", help = "Replacement prefix")]
        to_prefix: Option<String>,

        #[arg(
            long,
            help = "Also regenerate PayloadUUIDs (and remap cross-references). Off by default: MDM keys installed payloads by UUID, so keeping them makes this an update rather than a remove-and-reinstall"
        )]
        regenerate_uuid: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(long, help = "Maximum directory depth (requires --recursive)")]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(long, help = "Apply changes (default is a dry-run preview)")]
        write: bool,
    },

    #[command(about = "Classify a profile and rewrite its display name (Kind: Subject)")]
    Classify {
        #[arg(help = "Profile file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(long, help = "Maximum directory depth (requires --recursive)")]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Reference map to use (overrides the default)"
        )]
        map: Option<String>,

        #[arg(
            long,
            help = "Apply the new display names (default is a dry-run preview)"
        )]
        write: bool,

        #[arg(
            long,
            help = "Also rebuild PayloadIdentifier/UUIDs to match (requires --org)"
        )]
        sync_identity: bool,

        #[arg(
            long,
            help = "Organization reverse domain (required with --sync-identity)"
        )]
        org: Option<String>,

        #[arg(
            long = "scheme",
            value_name = "SCHEME",
            default_value = "name",
            help = "Identity scheme for --sync-identity: name (default) or uuid"
        )]
        identity_scheme: String,

        #[arg(
            long,
            value_name = "PATH",
            help = "Scan the profiles and write a name.toml naming scaffold (with best-guess app names) instead of renaming"
        )]
        emit_map: Option<String>,
    },

    #[command(
        about = "Audit profile(s) for binary content, certificates, and secrets",
        long_about = "Classify each payload's content and security posture:\n\
                      \n\
                      - binary: which payloads embed <data> blobs (fonts, certs)\n\
                      - cert: which are certificates, and of what kind\n  \
                        (root / intermediate / leaf / identity) via DER parsing\n\
                      - secrets: schema-sensitive fields, known credential field\n  \
                        names, PKCS#12 private keys, MDM deploy-time variables,\n  \
                        and high-entropy literals\n\
                      \n\
                      With --route-into, matching profiles are moved into\n\
                      category subfolders (certs/ secrets/ binary/ clean/);\n\
                      a profile lands in every bucket it matches. Use --dry-run\n\
                      to preview the routing plan without moving anything.\n\
                      \n\
                      Examples:\n  \
                      contour profile audit ./profiles -r --json\n  \
                      contour profile audit ./profiles -r --certs-only\n  \
                      contour profile audit ./profiles -r --route-into ./triage --dry-run"
    )]
    Audit {
        #[arg(help = "Profile file(s) or directory to audit", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Skip the cross-reference graph (which payload references which certificate, and what references each certificate)"
        )]
        no_links: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(
            long,
            conflicts_with = "secrets_only",
            help = "Only report/route cert payloads"
        )]
        certs_only: bool,

        #[arg(long, help = "Only report/route secret-bearing payloads")]
        secrets_only: bool,

        #[arg(long, help = "Also scan for deprecated payload types and keys")]
        with_deprecations: bool,

        #[arg(long, help = "Exit non-zero if any secret is found")]
        fail_on_secrets: bool,

        #[arg(
            long,
            value_name = "DIR",
            help = "Move matching profiles into category subfolders under DIR"
        )]
        route_into: Option<String>,

        #[arg(
            long,
            help = "With --route-into: print the routing plan without moving anything"
        )]
        dry_run: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Write a Markdown audit report to this path"
        )]
        md_report: Option<String>,
    },

    #[command(
        about = "Detect cross-profile payload-domain collisions (two profiles managing the same PayloadType)",
        long_about = "Recursively scan .mobileconfig profiles and DDM .json declarations and \
                      report any payload domain (PayloadType / declaration Type) managed by 2+ \
                      separate files that co-apply to the same host — which macOS doesn't reliably \
                      merge. Per key, classifies each as a value conflict, redundant, or \
                      complementary. Scope is per-directory by default (so different tenants don't \
                      collide); use --flat to treat the whole tree as one scope."
    )]
    Collisions {
        #[arg(help = "Profile/declaration file(s) or directory to scan", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(
            long,
            help = "Treat the whole tree as one co-apply scope (default: each directory is a scope)"
        )]
        flat: bool,

        #[arg(
            long,
            help = "Exit non-zero if any key is set to conflicting values across profiles"
        )]
        fail_on_conflict: bool,

        #[arg(long, help = "Exit non-zero if any domain is split across 2+ profiles")]
        fail_on_split: bool,

        #[arg(long, help = "Disable parallel processing")]
        no_parallel: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Write a Markdown collision report to this path"
        )]
        md_report: Option<String>,
    },

    #[command(
        about = "Consolidated repo-hygiene report (audit + collisions + deprecations + validate)",
        long_about = "Run all four hygiene analyses over a profile repo and merge them into ONE \
                      markdown report: audit (secrets/certs/binary), cross-profile collisions, \
                      deprecations, and schema validation. Writes to --output or stdout; --json \
                      for structured output. Gate CI with --fail-on-secrets / --fail-on-conflict."
    )]
    Report {
        #[arg(help = "Profile/declaration file(s) or directory to scan", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Maximum directory depth for recursive search (requires --recursive)"
        )]
        max_depth: Option<usize>,

        #[arg(
            long,
            help = "Collisions: treat the whole tree as one co-apply scope (default: per-directory)"
        )]
        flat: bool,

        #[arg(
            short,
            long,
            value_name = "PATH",
            help = "Write the Markdown report to this path (default: stdout)"
        )]
        output: Option<String>,

        #[arg(long, help = "Exit non-zero if any profile carries a secret")]
        fail_on_secrets: bool,

        #[arg(
            long,
            help = "Exit non-zero if any payload domain has value conflicts across profiles"
        )]
        fail_on_conflict: bool,
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

        #[arg(
            long,
            help = BETA_SEARCH_HELP
        )]
        beta: bool,

        #[arg(
            long,
            conflicts_with = "beta",
            help = "Search the Windows CSP dataset (DDF v2) instead of the Apple schema"
        )]
        windows: bool,

        #[arg(
            long,
            value_name = "KIND",
            help = "Only this kind: profile, declaration, command, checkin, preference, csp, \
                    admx. Without it, commands and check-in messages are hidden — they \
                    have schemas but cannot be authored as profiles"
        )]
        kind: Option<String>,
    },

    #[command(
        about = "Inspect or surgically rename managed-preference (MCX) domains",
        subcommand
    )]
    Mcx(McxAction),

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

    #[command(
        about = "Compare two configuration profiles",
        long_about = "Compare two configuration profiles.\n\n\
                      By default this is a line diff of the serialised XML — right for \
                      a review, wrong for a script, because every PayloadUUID and \
                      PayloadIdentifier line differs between two generated profiles by \
                      construction.\n\n\
                      --structural (implied by --json) pairs payloads by PayloadType \
                      and PayloadDisplayName instead, walks each pair to its leaves, and \
                      reports added / removed / changed / unchanged per dotted path. \
                      Bookkeeping keys are marked rather than hidden; --settings-only \
                      drops them."
    )]
    Diff {
        #[arg(help = "First configuration profile file")]
        file1: String,

        #[arg(help = "Second configuration profile file")]
        file2: String,

        #[arg(short, long, help = "Output diff to file (optional)")]
        output: Option<String>,

        #[arg(
            long,
            value_name = "PATH",
            help = "Also write a markdown report to PATH"
        )]
        md_report: Option<String>,

        #[arg(
            long,
            help = "Payload-by-payload, key-by-key comparison instead of a text diff"
        )]
        structural: bool,

        #[arg(
            long,
            requires = "structural",
            help = "Drop the Payload* bookkeeping keys (UUID, identifier, version, …) \
                    from a structural diff"
        )]
        settings_only: bool,
    },

    #[command(
        about = "Classify changes between baseline and proposed profiles \
                 (terraform-plan-style change impact)",
        long_about = "Compare a baseline profile (file or directory) against \
                      a proposed one and classify every payload-level delta \
                      into a tier that maps to MDM behavior on enrolled \
                      devices: NOOP / IN_PLACE_UPDATE / ADD / REMOVE / \
                      REPLACE / REF_BROKEN / SCOPE_BROADENED / TYPE_INVALID \
                      / DEPRECATED.\n\n\
                      Exits non-zero when the plan contains blocking changes \
                      (REPLACE, REF_BROKEN, SCOPE_BROADENED, TYPE_INVALID, \
                      DEPRECATED) so CI can gate destructive PRs.\n\n\
                      See `contour help-ai --sop profile-changes` for the \
                      operational doctrine."
    )]
    Plan {
        #[arg(help = "Baseline profile (file or directory)")]
        baseline: String,

        #[arg(help = "Proposed profile (file or directory)")]
        proposed: String,

        #[arg(short, long, help = "Walk directory pairs recursively")]
        recursive: bool,

        #[arg(long, help = "Organization reverse domain (for predictable UUIDs)")]
        org: Option<String>,

        #[arg(
            long,
            help = "Normalize both sides with v5 UUIDs derived from \
                    (org, identifier) before classifying — collapses \
                    cosmetic UUID churn so REPLACE only fires on real \
                    PayloadIdentifier renames"
        )]
        predictable: bool,

        #[arg(
            long,
            value_enum,
            default_value_t = plan::OutputFormat::Text,
            help = "Output format"
        )]
        format: plan::OutputFormat,

        #[arg(
            long,
            help = "Treat REPLACE as a warning instead of a blocker \
                    (use after a security-aware human approves the churn)"
        )]
        accept_replace: bool,

        #[arg(long, help = "Treat SCOPE_BROADENED as a warning instead of a blocker")]
        accept_scope_change: bool,

        #[arg(long, help = "Fleet size (used for blast-radius narrative on REPLACE)")]
        fleet_size: Option<usize>,

        #[arg(
            long,
            value_name = "PATH",
            help = "Also write a markdown report to PATH"
        )]
        md_report: Option<String>,
    },

    #[command(
        about = "Cherry-pick UUID restore from baseline → current",
        long_about = "Take a baseline profile (or directory), find every \
                      payload whose PayloadUUID changed in the current set, \
                      and restore the baseline UUID. Cross-references that \
                      pointed at the new UUID are rewritten to point at the \
                      restored one. Fail-closed: a rollback that would \
                      orphan a cross-reference aborts before any file is \
                      written.\n\n\
                      See `contour help-ai --sop profile-changes` for the \
                      operational doctrine."
    )]
    Rollback {
        #[arg(help = "Baseline profile (file or directory)")]
        baseline: String,

        #[arg(help = "Current profile (file or directory) to repair")]
        current: String,

        #[arg(short, long, help = "Walk directory pairs recursively")]
        recursive: bool,

        #[arg(
            long,
            help = "Restore PayloadUUID values only — leave content untouched"
        )]
        uuids_only: bool,

        #[arg(
            long = "payload-type",
            value_name = "T",
            help = "Restore only payloads of these PayloadType values (repeatable)"
        )]
        payload_types: Vec<String>,

        #[arg(
            long,
            help = "Restore only payloads referenced by another payload (high-blast-radius)"
        )]
        refs_only: bool,

        #[arg(
            long,
            help = "Skip the cross-reference rewrite pass (default: rewrite)"
        )]
        no_rewrite_refs: bool,

        #[arg(long, help = "Print the rollback plan; do not write")]
        dry_run: bool,

        #[arg(
            long,
            value_name = "PATH",
            help = "Write restored profiles here (default: in-place)"
        )]
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

    #[command(
        about = "List known MDM deploy-time variables (Fleet/Jamf/Apple) and the config pool"
    )]
    Variables {
        #[arg(
            long,
            help = "MDM flavour to list (fleet|jamf|apple); defaults to the configured one"
        )]
        mdm: Option<String>,
    },

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

    #[command(
        visible_alias = "gen",
        about = "Generate a profile from schema or recipe"
    )]
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

        #[arg(
            long,
            num_args = 1..,
            value_name = "RECIPE",
            help = "Recipe to generate. Accepts either a bare name (looked up via --recipe-path → ~/.contour/recipes/ → embedded) OR a path to a .toml file. Repeat or pass multiple to generate from several recipes in one run (shell glob supported: `--recipe ./recipes/crowdstrike-*.toml`)."
        )]
        recipe: Vec<String>,

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

        /// Exit 0 even when a recipe's `{{KEY}}` placeholders are left unfilled, to fill them by hand
        #[arg(long)]
        allow_placeholders: bool,

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

        #[arg(
            long,
            overrides_with = "no_combined",
            help = "Force combined emission: bundle every [[profile]] into ONE .mobileconfig (overrides recipe.output.combined)"
        )]
        combined: bool,

        #[arg(
            long = "no-combined",
            overrides_with = "combined",
            help = "Force separate emission: one .mobileconfig per [[profile]] (overrides recipe.output.combined)"
        )]
        no_combined: bool,

        #[arg(
            long,
            help = "Leave secret references (op://, env:, file:, secret:) unresolved in the output so it is safe to share"
        )]
        sanitize: bool,

        #[arg(
            long,
            help = BETA_GENERATE_HELP
        )]
        beta: bool,

        /// Write a Fleet GitOps fragment: the profiles and declarations in
        /// Fleet's layout, a fleet file listing them under
        /// apple_settings.configuration_profiles, and fragment.toml. Refuses
        /// what Fleet would refuse at upload.
        #[arg(long)]
        fragment: bool,
    },

    #[command(about = "Work with Declarative Device Management (DDM) declarations")]
    #[command(
        about = "Generate Windows CSP profiles (SyncML) from the embedded schema",
        long_about = "contour embeds 4,347 Windows settings across 311 CSPs plus the ADMX \
                      element schema. This turns a settings TOML into the SyncML an MDM \
                      delivers.\n\
                      \n\
                      Its own subcommand rather than a flag on `profile generate`: that \
                      command's 19 flags are shaped for Apple payloads and --org has no \
                      Windows meaning.\n\
                      \n\
                      Paths are built by the rule verified against every LocURI \
                      in Microsoft's DDF drop, and the output is checked against the 648 \
                      working fragments in fleet_stigs.",
        subcommand
    )]
    Windows(WindowsAction),

    #[command(
        subcommand,
        about = "The FormSpec contract: render-ready schema out, documents back in",
        long_about = "What a form-driven authoring tool — web, native or CI — needs from \
                      contour without re-deriving Apple's rules.\n\n\
                      `spec` projects a payload type (or every authorable type) onto the \
                      FormSpec v1 contract: every key by dotted path with its control, \
                      label, options, range, availability and scope, per platform and \
                      never unioned. `emit` takes values for a type and produces the \
                      deployable document — a JSON declaration or a .mobileconfig — \
                      choosing format and nesting from the schema, and splitting a \
                      declaration into `.user` and `.system` when its keys span both \
                      delivery channels."
    )]
    Form(FormAction),

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
        about = "Scaffold and manage an external preset/recipe library",
        long_about = "Create and maintain a directory of MDM recipes and\n\
                      DDM presets that contour can resolve via\n\
                      `--preset-path` / `--recipe-path`. Each TOML lives\n\
                      next to a `.meaning.md` sidecar carrying schema-\n\
                      enriched docs (Apple title, platforms, per-key\n\
                      descriptions).\n\
                      \n\
                      Subcommands\n  \
                      new        Scaffold a fresh library tree (copies every\n             \
                      embedded built-in + a CI workflow)\n  \
                      import     Convert an existing .mobileconfig (or DDM\n             \
                      JSON) into a recipe in the library\n  \
                      validate   Lint every recipe/preset; flags unknown\n             \
                      payload types and DDM compose failures\n  \
                      diff       Semantic diff between two recipe TOMLs\n             \
                      (matches diff(1) exit semantics)\n  \
                      normalize  Restyle every TOML to flat or nested\n             \
                      indentation (idempotent)\n  \
                      \n\
                      Worked examples\n  \
                      contour profile library new ./contour-presets\n  \
                      contour profile library import ~/Profiles --into ./contour-presets\n  \
                      contour profile library validate ./contour-presets --json\n  \
                      contour profile library diff old.toml new.toml\n  \
                      contour profile library normalize ./contour-presets --style flat\n  \
                      \n\
                      Resolution order at lookup time\n  \
                      1. Explicit `--preset-path` / `--recipe-path`\n  \
                      2. `~/.contour/{presets,recipes}/`\n  \
                      3. Embedded built-ins (compiled into contour)"
    )]
    Library {
        #[command(subcommand)]
        action: LibraryAction,
    },

    /// Synthesize mobileconfig profiles from managed preference plists
    #[command(visible_alias = "synth")]
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

        #[arg(
            long = "keys-md",
            value_name = "FILE",
            help = "Also write a Markdown key reference (keys, descriptions, Apple source links)"
        )]
        keys_md: Option<std::path::PathBuf>,
    },

    #[command(
        about = "Search profile commands by keyword (typo-tolerant)",
        long_about = "Fuzzy-search the profile command tree by keyword — the fast way\n\
                      to reach a command without memorizing the full name.\n\
                      \n\
                      Matches command names, descriptions, and (with --deep)\n\
                      flag help. Tolerant of typos.\n\
                      \n\
                      Examples:\n  \
                      contour profile find cache\n  \
                      contour profile find \"rename org\"\n  \
                      contour profile find sign --deep"
    )]
    Find {
        /// Search term (e.g. "cache", "rename org")
        term: String,
        /// Also match flag names and flag help (broader, noisier)
        #[arg(long)]
        deep: bool,
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

        #[arg(
            long,
            value_parser = ["mobileconfig", "plist"],
            default_value = "mobileconfig",
            help = "Output format: mobileconfig (default, full profile) or plist (raw payload dict for WS1 Custom Settings — requires exactly one --type)"
        )]
        format: String,
    },
}

#[derive(Debug, Subcommand)]
pub enum DdmAction {
    #[command(
        about = "List the status items a device can report (the other half of DDM)",
        long_about = "A declaration says what a device should be; a status item is what \
                      the device reports back — software update state, installed apps, \
                      disk usage, management state. Apple defines the item types and an \
                      MDM subscribes to them, so this is read-only: it says what exists, \
                      with each item's value type, scopes and enrollments."
    )]
    Status {
        #[arg(help = "Substring of the item type, title or description")]
        query: Option<String>,

        #[arg(long, value_name = "NAME", help = "Restrict to one platform")]
        platform: Option<String>,

        #[arg(
            long,
            help = "List the MDM error codes Apple documents instead — the failure side \
                    of the same channel"
        )]
        errors: bool,

        #[arg(long, help = BETA_SCHEMA_HELP)]
        beta: bool,
    },

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

        #[arg(
            long,
            help = "Validate against the pre-release OS seed schema, when one is open (between seeds it is the released schema)"
        )]
        beta: bool,

        #[arg(
            long = "platform",
            value_name = "OS",
            help = "Warn about keys Apple does not offer on this platform (repeatable: macOS, iOS, tvOS, watchOS, visionOS)"
        )]
        platforms: Vec<String>,
    },

    #[command(
        about = "Search DDM declaration types by keyword (substring match across name, title, description, field names)"
    )]
    Search {
        #[arg(help = "Search query (case-insensitive substring)")]
        query: String,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo"
        )]
        schema_path: Option<String>,

        #[arg(
            long,
            help = "Include the pre-release OS seed schema, when one is open (between seeds it is the released schema)"
        )]
        beta: bool,
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

        #[arg(
            long,
            help = "Include the pre-release OS seed schema, when one is open (between seeds it is the released schema)"
        )]
        beta: bool,
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

        #[arg(
            long,
            help = "Use the pre-release OS seed schema, when one is open (between seeds it is the released schema)"
        )]
        beta: bool,

        #[arg(long, help = "Expand nested dictionary keys as an indented tree")]
        full: bool,
    },

    #[command(
        about = "Show the legacy MDM → DDM migration mapping for a payload type",
        long_about = "Map a legacy configuration-profile payload type to its DDM \
                      declaration equivalent, with per-key detail: keys that carry \
                      over directly, keys that are renamed/restructured (old → new), \
                      and keys with no DDM equivalent.\n\n\
                      With no <name>, prints the whole mapping table plus coverage \
                      stats. Pair with `--json` for agent/LLM consumption.\n\n\
                      Examples:\n  \
                      contour profile ddm map com.apple.caldav.account\n  \
                      contour profile ddm map --json"
    )]
    Map {
        #[arg(help = "Legacy MDM payload type (omit to list all mappings)")]
        name: Option<String>,
    },

    #[command(
        about = "Report DDM migration coverage — what is declarative vs. still legacy",
        long_about = "Summarize how much of the legacy MDM surface has a DDM \
                      equivalent today: assessed types by status (available / \
                      partial / legacy / none), the native-DDM coverage percentage, \
                      the list of types that still require legacy configuration \
                      profiles, and the embedded schema counts. Honors `--channel \
                      beta` to count seed declaration types.\n\n\
                      Example:\n  \
                      contour profile ddm coverage --json"
    )]
    Coverage {
        #[arg(
            long,
            help = BETA_COUNT_HELP
        )]
        beta: bool,
    },

    #[command(about = "Generate a DDM declaration JSON from schema")]
    #[command(
        about = "Rewrite declaration Identifiers in place, keeping cross-references consistent",
        long_about = "Replace one exact Identifier, or rewrite a whole prefix across a \
                      directory so every declaration reads `com.acme.*`. Activation \
                      references (StandardConfigurations, asset references) follow the \
                      rename, so a bundle never dangles.\n\
                      \n\
                      Defaults to a dry-run preview; pass --write to apply.\n\
                      \n\
                      Examples:\n  \
                      contour profile ddm reidentify decl.json \\\n    \
                        --from com.fleetdm.settings \\\n    \
                        --to com.acme.config.softwareupdate.settings.beta --write\n  \
                      contour profile ddm reidentify ./decls -r \\\n    \
                        --from-prefix com.fleetdm --to-prefix com.acme --write"
    )]
    Reidentify {
        #[arg(help = "Declaration file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            long,
            requires = "to",
            conflicts_with = "from_prefix",
            help = "Exact Identifier to replace"
        )]
        from: Option<String>,

        #[arg(long, requires = "from", help = "Replacement Identifier")]
        to: Option<String>,

        #[arg(
            long,
            requires = "to_prefix",
            help = "Identifier prefix to replace (matches on dot boundaries)"
        )]
        from_prefix: Option<String>,

        #[arg(long, requires = "from_prefix", help = "Replacement prefix")]
        to_prefix: Option<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(long, help = "Write changes in place (default is a dry-run preview)")]
        write: bool,
    },

    #[command(
        about = "Build a beta-enrollment declaration (AppleSeed for IT) in one step",
        long_about = "Emit a com.apple.configuration.softwareupdate.settings declaration whose \
                      Beta object matches the outcome you want:\n  \
                      offer      — users may self-enroll; your programs are also offered\n  \
                      always-on  — only your programs; users cannot self-enroll\n  \
                      require    — device auto-enrolls into exactly one program\n  \
                      block      — no beta enrollment; removes the device from any program\n\
                      \n\
                      Seeding tokens come from Apple (ABM MDM-server token -> DEP API \
                      /os-beta-enrollment/tokens). Run without --tokens to print those \
                      manual steps."
    )]
    Beta {
        #[arg(long, value_enum, help = "Desired outcome on the device")]
        mode: crate::cli::ddm_beta::BetaMode,

        #[arg(
            long,
            value_name = "FILE",
            help = "Seeding tokens: Apple's /os-beta-enrollment/tokens response, or a bare JSON array"
        )]
        tokens: Option<String>,

        #[arg(
            long,
            value_name = "PROGRAM",
            help = "Limit to these programs (by title or token); repeatable. Required for --mode require when the file has several"
        )]
        select: Vec<String>,

        #[arg(
            long,
            help = "Emit one declaration per platform into -o <DIR> (a device only enrols with a token for its own OS)"
        )]
        split_by_os: bool,

        #[arg(
            long,
            conflicts_with = "select",
            help = "Pick programs interactively from the tokens file (not available in CI)"
        )]
        interactive: bool,

        #[arg(
            short,
            long,
            help = "Output file path, or directory with --split-by-os"
        )]
        output: Option<String>,

        #[arg(long, help = "Organization reverse domain (derives the Identifier)")]
        org: Option<String>,

        #[arg(
            long,
            help = "Set the declaration Identifier verbatim (no --org needed)"
        )]
        identifier: Option<String>,
    },

    Generate {
        #[arg(help = "Declaration type name (e.g., passcode.settings)")]
        name: String,

        #[arg(short, long, help = "Output file path")]
        output: Option<String>,

        #[arg(long, help = "Include all fields (not just required)")]
        full: bool,

        #[arg(
            long,
            help = "Organization reverse domain (e.g., com.acme). Overrides profile.toml / .contour/config.toml / CONTOUR_ORG"
        )]
        org: Option<String>,

        #[arg(
            long,
            help = "Set the declaration Identifier verbatim (skips org-derived naming; no --org needed)"
        )]
        identifier: Option<String>,

        #[arg(
            short = 'p',
            long,
            help = "Path to external Apple device-management repo"
        )]
        schema_path: Option<String>,

        #[arg(
            long,
            value_name = "FILE",
            help = "JSON or TOML file whose key/values fill the declaration's Payload (e.g. {\"hello\":\"world\"} for management.properties). Merged over the schema skeleton."
        )]
        payload: Option<String>,

        #[arg(
            long,
            help = "Use the pre-release OS seed schema, when one is open (between seeds it is the released schema)"
        )]
        beta: bool,
    },

    #[command(about = "Transform an Apple example declaration into a working config")]
    Transform {
        #[arg(help = "Path to an example declaration JSON file (or use --type + --example)")]
        example_file: Option<String>,

        #[arg(
            long,
            value_name = "FILE",
            help = "find→replace values map (JSON/TOML)"
        )]
        values: Option<String>,

        #[arg(long, help = "Organization reverse domain (or set CONTOUR_ORG)")]
        org: Option<String>,

        #[arg(short, long, help = "Output file (default: stdout)")]
        output: Option<String>,

        #[arg(long, help = "Fail if known placeholders remain after transform")]
        strict: bool,

        #[arg(
            long,
            value_name = "CSV",
            help = "santa scan CSV — fill app.settings lists with real entries"
        )]
        scan: Vec<String>,

        #[arg(long, value_name = "FILE", help = "Privacy permission policy (TOML)")]
        permissions: Option<String>,

        #[arg(long, help = "Route scanned entries to DeniedBinaries")]
        deny: bool,

        #[arg(
            long = "type",
            value_name = "TYPE",
            help = "Declaration type for an embedded example (instead of <example-file>)"
        )]
        type_name: Option<String>,

        #[arg(long, value_name = "N", help = "Embedded example index (with --type)")]
        example: Option<u32>,

        #[arg(long, help = "Use beta seed examples (with --type)")]
        beta: bool,
    },

    #[command(about = "List Apple-provided examples for a declaration type")]
    Examples {
        #[arg(help = "Declaration type name (e.g., app.settings)")]
        name: String,

        #[arg(long, help = "Use the beta seed examples")]
        beta: bool,
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
            long = "platform",
            value_name = "OS",
            help = "Refuse keys Apple does not offer on this platform (repeatable; overrides the bundle's `platforms`)"
        )]
        platforms: Vec<String>,

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

    #[command(
        about = "Wrap classic .mobileconfig profiles in com.apple.configuration.legacy declarations",
        long_about = "DDM activations gate declarations, not profiles, so a mobileconfig that \
                      needs gating must be wrapped in com.apple.configuration.legacy pointing \
                      at it by URL.\n\
                      \n\
                      A device re-downloads ProfileURL only when the declaration's ServerToken \
                      changes, and editing the profile does not touch the declaration — so an \
                      edited profile silently keeps serving the old copy while the declaration \
                      still reports Verified. contour records each profile's SHA-256 in a \
                      sidecar index so `ddm legacy refresh` can re-point exactly the \
                      declarations whose profiles actually changed.\n\
                      \n\
                      Dry-run by default; pass --write to apply.",
        subcommand
    )]
    Legacy(LegacyAction),

    #[command(
        name = "service-config",
        about = "Build and re-host the zip a service-configuration-files declaration points at",
        long_about = "com.apple.configuration.services.configuration-files replaces a service's \
                      on-disk configuration with a zip the device expands into a SIP-protected \
                      location (macOS 14+, supervised). The declaration is two keys; the work is \
                      the archive.\n\
                      \n\
                      Two things change independently. CONTENT changes when a config file is \
                      edited: re-run `build`, which re-packs, re-hashes and re-points. LOCATION \
                      changes when the artifact moves host — Azure Blob today, Cloudflare \
                      tomorrow: run `rehost`, which rewrites DataURL and leaves every \
                      Hash-SHA-256 exactly as it was, because the bytes did not move, only their \
                      address did.\n\
                      \n\
                      Archives pack reproducibly (sorted entries, fixed timestamps), so an \
                      untouched tree keeps its hash and devices do not re-download identical \
                      bytes.\n\
                      \n\
                      Dry-run by default; pass --write to apply.",
        subcommand
    )]
    ServiceConfig(ServiceConfigAction),

    #[command(
        name = "app-privacy",
        about = "Pre-answer app privacy prompts (com.apple.configuration.app.settings)",
        long_about = "macOS 26+ lets an MDM answer an app's privacy prompts up front \
                      instead of the user meeting them one at a time. The declaration is a \
                      Privacy.PermissionDefaults map keyed by bundle id PLUS the app's \
                      designated requirement.\n\
                      \n\
                      That key is the whole difficulty: it is a long codesign expression, \
                      and a wrong one produces a declaration that validates, deploys, \
                      reports Verified and manages nothing. `scan` reads it from the app \
                      with codesign and refuses any app it cannot read, rather than \
                      emitting a placeholder somebody ships by accident.\n\
                      \n\
                      Note Apple has no \"Deny\": values are Allow or None, and None means \
                      UNMANAGED — the user is still prompted. Omitting a permission does \
                      the same. contour refuses \"Deny\" by name rather than dropping it.",
        subcommand
    )]
    AppPrivacy(AppPrivacyAction),

    #[command(
        name = "app-control",
        about = "Allow or deny which binaries run on macOS (com.apple.configuration.app.settings)",
        long_about = "Scans installed apps' code signatures with codesign — no Santa \
                      needed — into app-control.toml, then composes the declaration \
                      and its activation. macOS 27+, supervised.\n\
                      \n\
                      An allow list is exclusive: only matching binaries run, apart \
                      from system-critical processes. The file adds Apple's software \
                      (TeamID *APPLE*) by default, and a scanned allow entry is the \
                      vendor's TeamID, because an app's helpers run under other \
                      signing IDs of the same team.",
        subcommand
    )]
    AppControl(AppControlAction),
}

/// Subcommands for `profile windows`.
#[derive(Debug, Subcommand)]
pub enum WindowsAction {
    #[command(
        about = "DISA STIG compliance policies and registry checks",
        long_about = "contour embeds 836 Fleet STIG policies across 8 DISA profiles and 122 \
                      registry checks. A policy pairs the OMA-URI and SyncML that ENFORCE a \
                      rule with the query that VERIFIES it; this surfaces both together.\n\
                      \n\
                      contour does not run queries or talk to Fleet — it hands you policies \
                      to deploy elsewhere. And the claim is narrower than compliance: a \
                      query reads what the CSP or registry REPORTS, not the behaviour the \
                      rule is about.\n\
                      \n\
                      The corpus is community-generated from DISA content and Microsoft's \
                      DDF, pinned and held against the DDF contour embeds by a test. Output \
                      carries that provenance."
    )]
    Stig {
        #[command(subcommand)]
        action: StigAction,
    },

    #[command(
        about = "Third-party app templates (Chrome, Edge, Firefox, Office, Zoom, …) and their policies",
        long_about = "The vendors' own Administrative Templates, embedded with both LocURIs, \
                      the element schema, and Windows' verdict on whether MDM may ingest each \
                      policy. `show` ends with the [[setting]] entry `windows generate` takes."
    )]
    Apps {
        #[command(subcommand)]
        action: AppsAction,
    },

    #[command(
        about = "Generate SyncML from a windows.toml",
        long_about = "Every setting is resolved and validated before anything is emitted, \
                      and all refusals are reported together — a settings file is edited \
                      as a whole, so failing on the first of thirty turns one review into \
                      thirty.\n\
                      \n\
                      Refused: a path the capability data does not know, a value outside \
                      its enum or range, a channel the setting does not offer, an unfilled \
                      instance placeholder, and action-only nodes. Deprecated settings \
                      warn and still generate — they apply on builds before their removal."
    )]
    Generate {
        #[arg(default_value = crate::cli::windows_generate::DEFAULT_POLICY_FILE,
              help = "Settings file")]
        input: String,

        #[arg(
            short,
            long,
            help = "Write to this file (implies --write). Without -o or --write, prints to stdout"
        )]
        output: Option<String>,

        #[arg(
            long,
            help = "Wrap the commands in a <SyncML> envelope for a DM session. \
                    Omitted emits bare fragments, which is what Fleet and GitOps want"
        )]
        envelope: bool,

        #[arg(
            long,
            help = "Write to a file instead of stdout (windows-profile.xml unless -o)"
        )]
        write: bool,

        #[arg(
            long,
            value_name = "DIR",
            help = "Directory holding vendor .admx files (chrome.admx, msedge.admx, …) for \
                    `app = …` settings. Each template is sent once as an ADMXInstall step \
                    ahead of its policies; contour does not ship the XML"
        )]
        admx_dir: Option<String>,
    },
}

/// Subcommands for `profile windows apps`.
#[derive(Debug, Subcommand)]
pub enum AppsAction {
    #[command(about = "Every template, and how many of its policies MDM can deliver")]
    List,

    #[command(about = "Search policy names, titles, categories and registry paths")]
    Search {
        #[arg(help = "Term to match")]
        term: String,

        #[arg(long, help = "Restrict to one template, e.g. chrome")]
        app: Option<String>,
    },

    #[command(about = "One policy in full, with the windows.toml entry that deploys it")]
    Show {
        #[arg(help = "Template (`chrome`) or app name (`Chrome`)")]
        app: String,

        #[arg(help = "Policy name, as `apps search` prints it")]
        policy: String,
    },
}

/// Subcommands for `profile windows stig`.
#[derive(Debug, Subcommand)]
pub enum StigAction {
    #[command(
        about = "The STIG profiles, and how much of each contour can enforce",
        long_about = "Printed before anything else because the gap is the point: a profile \
                      with 167 of 198 rules enforceable is not the STIG, and an operator \
                      exporting it should know that before they deploy."
    )]
    List,

    #[command(about = "Search policies and registry checks")]
    Search {
        #[arg(
            help = "Term to match against policy name, OMA-URI, CSP area, tags, or a registry path"
        )]
        term: String,

        #[arg(long, help = "Restrict to one STIG profile")]
        profile: Option<String>,
    },

    #[command(about = "Show one policy or check: how to enforce it, and how to verify it")]
    Show {
        #[arg(help = "An OMA-URI, a policy name, or a registry rule id such as V-253444")]
        target: String,
    },

    #[command(
        about = "Export a STIG profile as Fleet policies",
        long_about = "Only rules with both an enforcement and a compliance query — a policy \
                      Fleet cannot check is not a policy. The count is written against the \
                      profile's total so the gap is visible rather than implied."
    )]
    Export {
        #[arg(long, help = "STIG profile name, as `stig list` prints it")]
        profile: String,

        #[arg(short, long, help = "Write here instead of stdout")]
        output: Option<String>,
    },
}

/// Subcommands for `profile ddm app-control`.
#[derive(Debug, Subcommand)]
pub enum AppControlAction {
    #[command(
        about = "Read installed apps' code signatures into app-control.toml",
        long_about = "Apps under the given paths (bundles or directories; default \
                      /Applications and /Applications/Utilities) become [[allow]] \
                      entries, or [[deny]] with --deny. Unsigned and team-less apps \
                      are listed as skipped: there is nothing a rule can match."
    )]
    Scan {
        #[arg(help = "App bundles or directories to scan")]
        paths: Vec<String>,

        #[arg(
            short = 'I',
            long,
            help = "Pick which apps to allow and which to deny, and whether to include \
                    Apple's software, from the scanned list"
        )]
        interactive: bool,

        #[arg(
            long,
            help = "Write [[deny]] entries (DeniedBinaries) instead of [[allow]]"
        )]
        deny: bool,

        #[arg(
            long,
            help = "Set allow_apple = false: leave Apple's software out of the allow list \
                    (it is exclusive — unlisted Apple apps will not launch)"
        )]
        no_apple: bool,

        #[arg(
            long,
            value_enum,
            default_value = "auto",
            help = "auto: vendor TeamID for allow, the app's SigningID for deny"
        )]
        rule_type: santa::cli::ScanRuleType,

        #[arg(
            long,
            help = "Set always_allow_managed: MDM-installed apps join the allow list"
        )]
        always_allow_managed: bool,

        #[arg(short, long, help = "Output file (default: app-control.toml)")]
        output: Option<String>,
    },

    #[command(
        about = "Compose the declaration and its activation from app-control.toml",
        long_about = "Validates every entry against Apple's rules for app.settings \
                      binaries and reports all problems at once, then hands the \
                      result to `ddm compose`.\n\nDry-run by default; pass --write."
    )]
    Generate {
        #[arg(default_value = crate::cli::ddm_app_control::DEFAULT_POLICY_FILE,
              help = "Policy file")]
        input: String,

        #[arg(long, help = "Organization domain for computed identifiers")]
        org: Option<String>,

        #[arg(short, long, help = "Output directory (default: .)")]
        output: Option<String>,

        #[arg(long, help = "Write the files instead of listing them")]
        write: bool,
    },
}

/// Subcommands for `profile ddm app-privacy`.
#[derive(Debug, Subcommand)]
pub enum AppPrivacyAction {
    #[command(
        about = "Read installed apps into app-privacy.toml",
        long_about = "Extracts each app's bundle id and designated requirement with \
                      codesign. An app whose requirement cannot be read is an error \
                      naming it, never a placeholder: a declaration keyed on a bad \
                      requirement manages nothing while reporting success.\n\
                      \n\
                      --skip-unreadable relaxes the batch, not that rule: the broken \
                      apps are omitted and listed, never guessed at, and a run where \
                      nothing could be read is still an error."
    )]
    Scan {
        #[arg(
            help = "App bundles, e.g. /Applications/zoom.us.app. With --interactive, \
                    directories to search instead (default: /Applications)"
        )]
        apps: Vec<String>,

        #[arg(
            short = 'I',
            long,
            help = "Choose apps and permissions interactively, as `pppc scan -I` does"
        )]
        interactive: bool,

        #[arg(
            long,
            help = "Keep going when an app cannot be read, and name each one that was \
                    skipped. Without this, one unreadable bundle discards the whole batch"
        )]
        skip_unreadable: bool,

        #[arg(short, long, help = "Output policy file (default: app-privacy.toml)")]
        output: Option<String>,
    },

    #[command(
        about = "Compose the declaration bundle from app-privacy.toml",
        long_about = "Validates every permission value against Apple's allowed set, then \
                      hands a synthesized bundle to `ddm compose` so identifiers and the \
                      activation are wired on the same code path as every other \
                      declaration.\n\
                      \n\
                      Dry-run by default; pass --write to apply."
    )]
    Generate {
        #[arg(default_value = crate::cli::ddm_app_privacy::DEFAULT_POLICY_FILE,
              help = "Policy file")]
        input: String,

        #[arg(long, help = "Organization domain for computed identifiers")]
        org: Option<String>,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(
            long,
            value_name = "SCOPE",
            help = "Add a top-level PayloadScope (system|user). FLEET-SPECIFIC — not \
                    part of Apple's DDM spec; other MDMs ignore it. Privacy is macOS \
                    user-only, so Fleet needs `user` here or the declaration is \
                    delivered on the device channel and ignored"
        )]
        payload_scope: Option<String>,

        #[arg(long, help = "Write the declarations (default: dry run)")]
        write: bool,
    },

    #[command(
        name = "import-pppc",
        about = "Seed app-privacy.toml from an existing pppc.toml",
        long_about = "Carries across the five permissions the two surfaces share (camera, \
                      microphone, accessibility, bluetooth, speech-recognition → \
                      Dictation). Every other PPPC grant — fda, apple-events, \
                      screen-capture, the folder policies — has no app.settings \
                      equivalent and is listed as unmapped, never dropped in silence: \
                      those apps still need the PPPC profile deployed."
    )]
    ImportPppc {
        #[arg(default_value = "pppc.toml", help = "Existing PPPC policy file")]
        input: String,

        #[arg(short, long, help = "Output policy file (default: app-privacy.toml)")]
        output: Option<String>,
    },
}

/// Subcommands for `profile ddm service-config`.
#[derive(Debug, Subcommand)]
pub enum ServiceConfigAction {
    #[command(
        about = "Pack a staged tree into the asset a service-config declaration references",
        long_about = "The staged directory mirrors the filesystem from `/`: to manage \
                      /etc/ssh, stage <dir>/etc/ssh/... An archive rooted one level too deep \
                      expands into a directory the service never reads while the declaration \
                      still reports Verified, so the layout is checked against the service \
                      before anything is written."
    )]
    Build {
        #[arg(help = "Staged directory, mirroring the filesystem from /")]
        source: String,

        #[arg(
            long,
            help = "ServiceType, e.g. com.apple.sshd. A com.apple.* type Apple does not \
                    document is refused; any other reverse-DNS type is allowed (files are \
                    delivered, but only read if the service opts in)"
        )]
        service: String,

        #[arg(
            long,
            value_name = "BASE",
            help = "Hosting base, host and container without scheme, e.g. \
                    acct.blob.core.windows.net/ddm. Omitted leaves a placeholder to fill \
                    with `rehost` after uploading"
        )]
        base_url: Option<String>,

        #[arg(
            long,
            value_name = "TEMPLATE",
            default_value = crate::cli::ddm_service_config::DEFAULT_URL_TEMPLATE,
            help = "URL template. Placeholders: {base} {sha256} {name} {service}. Keeping \
                    {sha256} in the path makes the URL content-addressed, so a provider \
                    migration substitutes {base} alone"
        )]
        url_template: String,

        #[arg(
            long,
            help = "Short name for the intent and archive (default: derived from --service)"
        )]
        intent: Option<String>,

        #[arg(
            long,
            help = "Activation predicate; omit for an always-on configuration"
        )]
        predicate: Option<String>,

        #[arg(
            long,
            help = "Do not emit a status-subscriptions declaration for @status keys in the \
                    predicate"
        )]
        no_subscriptions: bool,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(
            short,
            long,
            help = "Output directory for the archive and declarations"
        )]
        output: Option<String>,

        #[arg(long, help = "Apply (default is a dry-run preview)")]
        write: bool,
    },

    #[command(
        about = "Re-point tracked assets at a new hosting base, without rebuilding them",
        long_about = "For a provider migration: the artifact is not recreated, only the asset \
                      that says where it lives. DataURL is rewritten from the recorded template \
                      with the new base; Hash-SHA-256 is asserted unchanged and never written, \
                      so this cannot become a silent republish.\n\
                      \n\
                      Upload the same archives to the new host first — the URLs are \
                      content-addressed, so the path after the base stays identical."
    )]
    Rehost {
        #[arg(help = "Directory holding the declarations and their index")]
        declarations: String,

        #[arg(
            long,
            value_name = "BASE",
            help = "New hosting base, e.g. cdn.example.org/ddm"
        )]
        base_url: String,

        #[arg(
            long,
            help = "Re-pack each staged source and refuse if its hash moved — catches a \
                    content change riding along with the move. Requires the sources to be present"
        )]
        verify: bool,

        #[arg(long, help = "Apply (default is a dry-run preview)")]
        write: bool,
    },
}

/// Subcommands for `profile ddm legacy`.
#[derive(Debug, Subcommand)]
pub enum LegacyAction {
    #[command(
        about = "Convert .mobileconfig profiles into legacy declarations",
        long_about = "Emits one com.apple.configuration.legacy declaration per profile, plus an \
                      activation when --predicate is given, and writes a .contour-legacy.toml \
                      index recording each profile's hash.\n\
                      \n\
                      The URL is pinned to an immutable commit SHA on purpose: a URL tracking a \
                      branch would always resolve and could never be verified stale."
    )]
    Convert {
        #[arg(help = "Profile file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(
            long,
            value_name = "TEMPLATE",
            help = "URL template. Placeholders: {sha} {name} {stem} {path}. Must yield an https:// URL"
        )]
        url_template: String,

        #[arg(
            long,
            help = "Commit SHA to pin the URL to. Omitted leaves a REPLACE-WITH-COMMIT-SHA placeholder"
        )]
        sha: Option<String>,

        #[arg(
            long,
            help = "Activation predicate, e.g. \"@status(softwareupdate.install-state) == 'prepared'\""
        )]
        predicate: Option<String>,

        #[arg(
            long,
            help = "Do not emit a status-subscriptions declaration for @status keys in the predicate. \
                    Matches Fleet's current shape, which ships no subscriptions declaration — but \
                    contour's compose documents Error.UnableToEvaluatePredicate on device for an \
                    unsubscribed key, so this is opt-in rather than the default"
        )]
        no_subscriptions: bool,

        #[arg(long, help = "Organization reverse domain (e.g., com.yourorg)")]
        org: Option<String>,

        #[arg(short, long, help = "Output directory for the declarations")]
        output: Option<String>,

        #[arg(short, long, help = "Recurse into subdirectories")]
        recursive: bool,

        #[arg(
            long,
            value_name = "MODE",
            default_value = "contour",
            help = "Output file naming: contour (<stem>.configuration.json) or fleet (\"<Name> settings.json\", matching Fleet's declaration-profiles convention)"
        )]
        naming: String,

        #[arg(
            long,
            help = "Also print the Fleet GitOps entry for each profile — the path:/activation: pair to paste into configuration_profiles"
        )]
        gitops: bool,

        #[arg(long, help = "Apply (default is a dry-run preview)")]
        write: bool,
    },

    #[command(
        about = "Re-point legacy declarations whose profiles changed",
        long_about = "Compares each indexed profile's current hash against the hash recorded when \
                      its URL was written. Declarations whose profiles are byte-identical are left \
                      alone — bumping their SHA would mint new ServerTokens and make every device \
                      re-download profiles that did not change."
    )]
    Refresh {
        #[arg(help = "Directory containing the declarations and their index")]
        declarations: String,

        #[arg(long, help = "Directory the wrapped profiles live in")]
        against: String,

        #[arg(long, help = "New commit SHA to pin re-pointed URLs to")]
        sha: String,

        #[arg(long, help = "Apply (default is a dry-run preview)")]
        write: bool,
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
    /// Decode an MDM InstallProfile command into its inner profile
    Decode {
        /// MDM command plist file, or `-` to read from stdin
        input: String,
        /// Write the inner profile to this file (default: stdout)
        #[arg(short, long)]
        output: Option<String>,
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
        /// Include the beta seed skip keys (pre-release OS only; keys that have since shipped, such as LiquidGlass in 27.0, are already in the stable set)
        #[arg(long)]
        beta: bool,
        /// Show only keys Apple has deprecated or removed (with the version)
        #[arg(long)]
        deprecated: bool,
    },
    /// Generate a DEP enrollment profile JSON
    Generate {
        /// Platform
        #[arg(long, default_value = "macOS")]
        platform: String,
        /// OS version to target
        #[arg(long)]
        os_version: Option<String>,
        /// Include the beta seed skip keys (pre-release OS only; keys that have since shipped, such as LiquidGlass in 27.0, are already in the stable set)
        #[arg(long)]
        beta: bool,
        /// Skip every setup item that may be skipped (FileVault and SoftwareUpdate never are)
        #[arg(long, conflicts_with_all = ["skip_list", "interactive"])]
        skip_all: bool,
        /// Skip specific items (comma-separated); unions with --skip-list when both are given
        #[arg(long, value_delimiter = ',')]
        skip: Vec<String>,
        /// Reusable skip-list TOML file (platform, os_version, profile_name, skip[])
        #[arg(long, value_name = "PATH", conflicts_with = "interactive")]
        skip_list: Option<std::path::PathBuf>,
        /// Output file
        #[arg(short, long)]
        output: Option<String>,
        /// Profile name
        #[arg(long, default_value = "Automatic enrollment profile")]
        profile_name: String,
        /// Interactive mode — select which items to skip
        #[arg(long)]
        interactive: bool,

        /// Use a built-in preset (auto-advance, shared-ipad, manual). Overrides
        /// platform and the skip selection. See `enrollment presets`.
        #[arg(long, conflicts_with_all = ["skip_all", "skip_list", "interactive"])]
        preset: Option<String>,

        /// ISO 639 language code for Setup Assistant (e.g. de, fr, es). Default: en
        #[arg(long)]
        language: Option<String>,

        /// ISO 3166 region code (e.g. DE, FR, ES). Default: derived from --language (de→DE, fr→FR, es→ES, else US)
        #[arg(long)]
        region: Option<String>,

        /// Also write a companion <output>.md documenting the skip keys + Apple doc links
        #[arg(long)]
        readme: bool,
    },

    /// List the built-in enrollment presets
    Presets,

    /// Migrate an enrollment JSON to a target OS version, dropping skip keys
    /// Apple removed or deprecated by then, plus any key unknown for the
    /// platform (remove-only; never adds keys).
    Migrate {
        /// Existing enrollment profile JSON
        input: std::path::PathBuf,
        /// Target OS version (e.g. 26)
        #[arg(long)]
        to_version: String,
        /// Platform the profile targets (skip keys are platform-scoped)
        #[arg(long, default_value = "macOS")]
        platform: String,
        /// Output file (default: overwrite input)
        #[arg(short, long)]
        output: Option<String>,
        /// Use the beta seed skip-key data
        #[arg(long)]
        beta: bool,
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

    #[command(
        about = "Import an existing .mobileconfig as a recipe in a library",
        long_about = "Parses an existing `.mobileconfig` (signed or\n\
                      unsigned, XML or binary plist) and writes a TOML\n\
                      recipe at <INTO>/recipes/<NAME>.toml plus a stub\n\
                      `<NAME>.meaning.md` sidecar. The recipe round-trips\n\
                      through `contour profile generate --recipe <NAME>`\n\
                      to reproduce the same payload structure.\n\
                      \n\
                      MCX-style profiles (com.apple.ManagedClient.preferences)\n\
                      in the canonical shape are flattened to [profile.fields]\n\
                      with the domain recorded in mcx_domain; anything else\n\
                      passes through as nested TOML sub-tables.\n\
                      \n\
                      Refuses to overwrite an existing recipe unless\n\
                      --force is passed.\n\
                      \n\
                      Example:\n  \
                      contour profile library import ./Privileges.mobileconfig --into ./contour-presets"
    )]
    Import {
        /// One or more paths to ingest. Accepts `.mobileconfig` files,
        /// `.json` DDM declarations, directories (walked recursively),
        /// or shell-expanded globs (`crowdstrike-*.mobileconfig`).
        #[arg(value_name = "INPUT", num_args = 1..)]
        inputs: Vec<String>,

        /// Library root (the `recipes/` subdirectory is created if
        /// missing). Falls back to `defaults.library_path` from
        /// `.contour/config.toml` when omitted.
        #[arg(long, value_name = "DIR")]
        into: Option<String>,

        /// Override the derived recipe name (default: kebab-cased input file stem)
        #[arg(long, value_name = "NAME")]
        name: Option<String>,

        /// Bundle all inputs into ONE recipe with N `[[profile]]` blocks
        /// (instead of one recipe per source file). Requires `--name`
        /// to disambiguate the combined recipe.
        #[arg(long)]
        combine: bool,

        /// Overwrite an existing recipe of the same name
        #[arg(short, long)]
        force: bool,
    },

    #[command(
        about = "Restyle every TOML in a library to a chosen indentation style",
        long_about = "Rewrites every `.toml` under <PATH>/ddm/ and\n\
                      <PATH>/recipes/ so headers and key/value lines\n\
                      line up with the chosen style. Indentation in\n\
                      TOML is purely cosmetic — semantics are preserved\n\
                      bit-for-bit. Comments and blank lines pass\n\
                      through verbatim.\n\
                      \n\
                      Idempotent: running twice produces byte-identical\n\
                      output, so this is safe to run in CI.\n\
                      \n\
                      Examples:\n  \
                      contour profile library normalize ./contour-presets --style flat\n  \
                      contour profile library normalize ./contour-presets --style nested"
    )]
    Normalize {
        /// Library root (must contain `ddm/` and/or `recipes/`).
        /// Falls back to `defaults.library_path` from
        /// `.contour/config.toml` when omitted.
        #[arg(value_name = "PATH")]
        path: Option<String>,

        /// Indentation style: `flat` (no indent) or `nested` (2-space per dot-depth)
        #[arg(long, value_name = "STYLE", default_value = "nested")]
        style: LibraryStyle,
    },

    #[command(
        about = "Lint a preset/recipe library and report compose-time issues",
        long_about = "Walks <PATH>/recipes/ and <PATH>/ddm/, reporting\n\
                      issues that would break end-user `generate` /\n\
                      `compose` runs:\n  \
                      - TOML parse failures\n  \
                      - payload types unknown to the embedded schema\n  \
                      - DDM bundles that fail to compose against a\n    \
                      synthetic CI org\n\
                      \n\
                      Designed for CI: exits non-zero if any finding\n\
                      is at error severity. JSON output is structured\n\
                      for dashboards / reviewers.\n\
                      \n\
                      Example:\n  \
                      contour profile library validate ./contour-presets\n  \
                      contour profile library validate ./contour-presets --json"
    )]
    Validate {
        /// Library root (must contain `ddm/` and/or `recipes/`).
        /// Falls back to `defaults.library_path` from
        /// `.contour/config.toml` when omitted.
        #[arg(value_name = "PATH")]
        path: Option<String>,
    },

    #[command(
        about = "Semantic diff between two recipe TOML files",
        long_about = "Compares two recipe TOML files and reports the\n\
                      semantic differences — recipe metadata, profile\n\
                      adds/removes/changes, DDM bundle adds/removes/\n\
                      changes, per-key field changes inside each\n\
                      profile.\n\
                      \n\
                      Useful for PR review when two team members fork\n\
                      a library recipe. Match `diff(1)` semantics:\n\
                      exits 0 if identical, 1 if any change found.\n\
                      \n\
                      Example:\n  \
                      contour profile library diff old.toml new.toml\n  \
                      contour profile library diff old.toml new.toml --json"
    )]
    Diff {
        /// Recipe TOML on the "before" side
        #[arg(value_name = "A")]
        a: String,

        /// Recipe TOML on the "after" side
        #[arg(value_name = "B")]
        b: String,
    },
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum LibraryStyle {
    Flat,
    Nested,
}

/// Subcommands for `profile mcx`.
#[derive(Debug, Subcommand)]
pub enum McxAction {
    #[command(about = "List managed-preference domains and where they are in scope")]
    List {
        #[arg(help = "Profile file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,
    },

    #[command(
        about = "Rename a managed-preference domain in place, without reformatting the file",
        long_about = "Renames the domain KEY inside com.apple.ManagedClient.preferences \
                      payloads. The scope is verified by parsing before any edit, and the \
                      edit itself touches only the <key> tags accounted for — a value that \
                      happens to contain the same string (a support path, for example) is \
                      left alone, and the rest of the file stays byte-for-byte.\n\
                      \n\
                      Dry-run by default; pass --write to apply."
    )]
    Rename {
        #[arg(help = "Profile file(s) or directory", required = true, num_args = 1..)]
        paths: Vec<String>,

        #[arg(long, requires = "to", conflicts_with_all = ["from_prefix", "interactive"],
              help = "Exact domain to rename")]
        from: Option<String>,

        #[arg(long, requires = "from", help = "Replacement domain")]
        to: Option<String>,

        #[arg(
            long,
            requires = "to_prefix",
            conflicts_with = "interactive",
            help = "Domain prefix to rename, including sibling domains (dot-boundary matched)"
        )]
        from_prefix: Option<String>,

        #[arg(long, requires = "from_prefix", help = "Replacement prefix")]
        to_prefix: Option<String>,

        #[arg(
            long,
            help = "Pick the domain from those found, then enter the replacement"
        )]
        interactive: bool,

        #[arg(short, long, help = "Process directories recursively")]
        recursive: bool,

        #[arg(long, help = "Apply the rename (default is a dry-run preview)")]
        write: bool,
    },
}

/// Subcommands for `profile form`.
#[derive(Debug, Subcommand)]
pub enum FormAction {
    #[command(about = "Emit the FormSpec for one payload type, or for every authorable type")]
    Spec {
        #[arg(help = "Payload or declaration type (omit for every authorable type)")]
        name: Option<String>,

        #[arg(
            long,
            value_name = "NAME",
            help = "Target platform; resolves scope_class and verdicts"
        )]
        os: Option<String>,

        #[arg(
            long,
            value_name = "VERSION",
            requires = "os",
            help = "Target OS version, e.g. 26.0"
        )]
        os_version: Option<String>,

        #[arg(
            long,
            help = "Attach what mSCP's baselines say about each top-level key (rule, \
                    confidence, mechanism, baselines) as node.annotations[]"
        )]
        annotate: bool,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,

        #[arg(long, help = "Use the beta seed schema")]
        beta: bool,

        #[arg(short, long, help = "Write the document to a file instead of stdout")]
        output: Option<String>,
    },

    #[command(
        about = "Read an existing declaration or .mobileconfig back into values a form can populate"
    )]
    Parse {
        #[arg(help = "A JSON declaration or a .mobileconfig (XML or binary)")]
        file: String,

        #[arg(
            long,
            value_name = "NAME",
            help = "Target platform for the accompanying FormSpec"
        )]
        os: Option<String>,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,

        #[arg(long, help = "Use the beta seed schema")]
        beta: bool,
    },

    #[command(about = "Turn values for a type into its deployable document(s)")]
    Emit {
        #[arg(help = "Payload or declaration type")]
        name: String,

        #[arg(
            long,
            value_name = "FILE",
            help = "JSON object of values keyed by top-level key"
        )]
        values: String,

        #[arg(
            long,
            help = "Organization reverse domain (or CONTOUR_ORG / profile.toml)"
        )]
        org: Option<String>,

        #[arg(long, help = "Intent segment of the identifier, e.g. `wifi-corp`")]
        intent: String,

        #[arg(
            long,
            value_name = "NAME",
            help = "Platform whose scope rules decide the channel split"
        )]
        os: Option<String>,

        #[arg(
            long,
            value_name = "VERSION",
            requires = "os",
            help = "OS version to target; a key Apple removed by this version is refused"
        )]
        os_version: Option<String>,

        #[arg(
            long,
            conflicts_with = "direct",
            help = "Force the MCX envelope for a .mobileconfig"
        )]
        mcx: bool,

        #[arg(
            long,
            conflicts_with = "mcx",
            help = "Force keys directly in the inner payload"
        )]
        direct: bool,

        #[arg(short, long, help = "Output directory")]
        output: Option<String>,

        #[arg(long, help = "Write the files (default: dry run)")]
        write: bool,

        #[arg(long, help = "External schema directory")]
        schema_path: Option<String>,

        #[arg(long, help = "Use the beta seed schema")]
        beta: bool,
    },
}
