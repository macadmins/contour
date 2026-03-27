pub mod batch;
pub mod configure;
pub mod diff;
pub mod generate;
pub mod info;
pub mod init;
pub mod scan;
pub mod validate;

/// Sentinel label for "select all" in interactive service prompts.
pub const ALL_SERVICES_LABEL: &str = "── All Services ──";

use clap::{Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

pub use contour_core::output::{
    OutputMode, print_error, print_info, print_json, print_kv, print_success, print_warning,
};

#[derive(Parser)]
#[command(
    name = "pppc",
    about = "PPPC/TCC mobileconfig profile toolkit for macOS privacy permissions",
    long_about = "Generate Privacy Preferences Policy Control (PPPC/TCC) profiles for MDM deployment.\n\nPart of the Contour CLI toolkit for macOS fleet management.",
    version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")),
    author
)]
#[derive(Debug)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format (for CI/CD)
    #[arg(long, global = true)]
    pub json: bool,

    // --- One-shot mode arguments (when no subcommand is given) ---
    /// Directories or app bundles to scan (one-shot mode)
    #[arg(short, long, default_value = "/Applications")]
    pub path: Vec<PathBuf>,

    /// Output directory for generated profiles (one-shot mode)
    #[arg(short, long)]
    pub output: Option<PathBuf>,

    /// Organization identifier (required for one-shot mode)
    #[arg(long)]
    pub org: Option<String>,

    /// TCC service to configure (can be repeated, one-shot mode)
    #[arg(long, value_enum)]
    pub service: Option<Vec<crate::pppc::PppcService>>,

    /// Interactive mode to select apps and permissions (one-shot mode)
    #[arg(short = 'I', long)]
    pub interactive: bool,

    /// Preview what would be generated without writing (one-shot mode)
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan applications and create a policy file (pppc.toml)
    ///
    /// This is the first step in the GitOps workflow. Scan directories for
    /// applications, extract code requirements, and save to a TOML file
    /// that can be version-controlled and edited.
    ///
    /// Examples:
    ///   contour pppc scan --path /Applications --org com.example --output pppc.toml
    ///   contour pppc scan --path /Applications -I --org com.example
    ///   contour pppc scan --from-csv apps.csv --org com.example
    Scan {
        /// Directories or app bundles to scan
        #[arg(short, long, default_value = "/Applications")]
        path: Vec<PathBuf>,

        /// CSV file with app names/paths to scan (columns: name, path)
        ///
        /// Use this to scan specific apps from custom locations instead of
        /// scanning entire directories. The CSV should have columns:
        ///   name,path
        ///   "osquery","/opt/osquery/osquery.app"
        ///   "Zoom","/Applications/zoom.us.app"
        #[arg(long, conflicts_with = "path")]
        from_csv: Option<PathBuf>,

        /// Output file path for scan results (.toml)
        #[arg(short, long, default_value = "pppc.toml")]
        output: PathBuf,

        /// Organization identifier (reads from .contour/config.toml if not provided)
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode to select apps and permissions
        #[arg(short = 'I', long)]
        interactive: bool,
    },

    /// Generate mobileconfig profiles from a policy file
    ///
    /// This is the second step in the GitOps workflow. Read a pppc.toml
    /// file and generate TCC/PPPC profiles for MDM deployment.
    ///
    /// By default, generates individual profiles per app.
    /// Use --combined to merge all TCC entries into a single profile.
    ///
    /// Examples:
    ///   contour pppc generate pppc.toml --output ./profiles/
    ///   contour pppc generate pppc.toml --combined
    ///   contour pppc generate pppc.toml --dry-run
    Generate {
        /// Input policy file (pppc.toml)
        input: PathBuf,

        /// Output mobileconfig file or directory
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Combine all TCC entries into a single profile instead of per-app
        #[arg(long)]
        combined: bool,

        /// Preview what would be generated without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory instead of plain profiles
        ///
        /// Creates a directory with fragment.toml manifest and lib/ structure
        /// for merging into a Fleet GitOps repository.
        #[arg(long)]
        fragment: bool,
    },

    /// Interactively configure services in an existing policy file
    ///
    /// Walk through each app in a pppc.toml and toggle TCC services.
    ///
    /// Examples:
    ///   contour pppc configure pppc.toml
    Configure {
        /// Input policy file (pppc.toml)
        input: PathBuf,

        /// Skip apps that already have services configured
        ///
        /// Useful for resuming an interrupted configuration session.
        #[arg(long)]
        skip_configured: bool,
    },

    /// Initialize a new pppc.toml policy file
    ///
    /// Creates a blank policy file with default structure that you can
    /// populate by scanning apps or editing manually.
    ///
    /// Examples:
    ///   contour pppc init
    ///   contour pppc init --org com.acme --output policies/pppc.toml
    Init {
        /// Output file path
        #[arg(short, long, default_value = "pppc.toml")]
        output: PathBuf,

        /// Organization identifier
        #[arg(long)]
        org: Option<String>,

        /// Organization name
        #[arg(long)]
        name: Option<String>,

        /// Overwrite existing file
        #[arg(long)]
        force: bool,
    },

    /// Show PPPC toolkit info, available services, and local config summary
    ///
    /// Displays version, build info, all 24 TCC services, and a summary
    /// of any pppc.toml found in the current directory.
    Info,

    /// Validate a pppc.toml policy file
    ///
    /// Checks structural correctness: TOML parses, org is set, each app
    /// has bundle_id and code_requirement, and no duplicate bundle_ids.
    ///
    /// Examples:
    ///   contour pppc validate pppc.toml
    ///   contour pppc validate pppc.toml --strict
    Validate {
        /// Input policy file
        #[arg(default_value = "pppc.toml")]
        input: PathBuf,

        /// Strict mode: treat warnings as errors
        #[arg(long)]
        strict: bool,
    },

    /// Compare two pppc.toml policy files
    ///
    /// Shows apps added, removed, and modified between two policy files.
    /// Changes to TCC services are detected.
    ///
    /// Examples:
    ///   contour pppc diff pppc.toml pppc-new.toml
    Diff {
        /// First policy file (old)
        file1: PathBuf,

        /// Second policy file (new)
        file2: PathBuf,
    },

    /// Batch-update TCC services for apps
    ///
    /// Non-interactive bulk editing of a pppc.toml file. Add, remove, or
    /// replace TCC services for all or cherry-picked apps in one command.
    ///
    /// Examples:
    ///   contour pppc batch pppc.toml --add-services desktop,documents,downloads
    ///   contour pppc batch pppc.toml --add-services fda --apps "Slack,Chrome"
    ///   contour pppc batch pppc.toml --set-services fda,camera --apps "Zoom"
    ///   contour pppc batch pppc.toml --remove-services downloads --dry-run
    Batch {
        /// Input policy file (pppc.toml)
        input: std::path::PathBuf,

        /// Append services (won't duplicate existing)
        #[arg(long, value_delimiter = ',', value_enum)]
        add_services: Vec<crate::pppc::PppcService>,

        /// Remove specific services
        #[arg(long, value_delimiter = ',', value_enum)]
        remove_services: Vec<crate::pppc::PppcService>,

        /// Replace services entirely (conflicts with --add-services / --remove-services)
        #[arg(long, value_delimiter = ',', value_enum, conflicts_with_all = ["add_services", "remove_services"])]
        set_services: Option<Vec<crate::pppc::PppcService>>,

        /// Cherry-pick apps by name (case-insensitive substring). Omit = all apps
        #[arg(long, value_delimiter = ',')]
        apps: Vec<String>,

        /// Preview changes without writing
        #[arg(long)]
        dry_run: bool,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}
