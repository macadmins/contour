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
pub mod diff;
pub mod docs;
pub mod duplicate;
pub mod enrollment;
pub mod generate;
pub mod glob_utils;
pub mod import;
pub mod import_recipe;
pub mod info;
pub mod init;
pub mod jamf_import;
pub mod library;
pub mod library_diff;
pub mod library_validate;
pub mod link;
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

    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = crate::schema::Channel::Stable,
        help = "Schema channel: stable (released) or beta (pre-release OS seed)"
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

        #[arg(long, help = "Use the beta seed schema (shorthand for --channel beta)")]
        beta: bool,
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
            help = "Identifier scheme: uuid (sync to PayloadUUID) or name (slug from display name)"
        )]
        scheme: String,

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
            help = "Search the beta seed schema (shorthand for --channel beta)"
        )]
        beta: bool,
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

        #[arg(
            long,
            value_name = "PATH",
            help = "Also write a markdown report to PATH"
        )]
        md_report: Option<String>,
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
            help = "Generate against the beta seed schema (shorthand for --channel beta)"
        )]
        beta: bool,
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
            help = "Validate against the beta seed schema (pre-release OS keys, e.g. app.settings)"
        )]
        beta: bool,
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
            help = "Include the beta seed schema (pre-release OS types, e.g. app.settings)"
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
            help = "Include the beta seed schema (pre-release OS types, e.g. app.settings)"
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
            help = "Use the beta seed schema (pre-release OS types, e.g. app.settings)"
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
            help = "Count seed declaration types (shorthand for --channel beta)"
        )]
        beta: bool,
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
            long,
            help = "Organization reverse domain (e.g., com.acme). Overrides profile.toml / .contour/config.toml / CONTOUR_ORG"
        )]
        org: Option<String>,

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
            help = "Use the beta seed schema (pre-release OS keys, e.g. app.settings, package UninstallBehavior)"
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
        /// Include the beta seed skip keys (pre-release OS, e.g. AccessibilityAppearance, LiquidGlass)
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
        /// Include the beta seed skip keys (pre-release OS, e.g. AccessibilityAppearance, LiquidGlass)
        #[arg(long)]
        beta: bool,
        /// Skip ALL available setup items
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

        /// ISO 3166 region code (e.g. DE, FR, ES). Default: US
        #[arg(long)]
        region: Option<String>,
    },

    /// List the built-in enrollment presets
    Presets,

    /// Migrate an enrollment JSON to a target OS version, dropping skip keys
    /// Apple removed or deprecated by then (remove-only; never adds keys).
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
                      pass through faithfully — the deep nesting becomes\n\
                      nested TOML sub-tables. No payload-type-specific\n\
                      unwrapping.\n\
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

        /// Override the derived recipe name (default: snake-cased input file stem)
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
