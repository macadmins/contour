//! BTM CLI command definitions and dispatch.

pub mod diff;
pub mod generate;
pub mod info;
pub mod init;
pub mod merge;
pub mod scan;
pub mod validate;

use clap::{Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

pub use contour_core::output::{
    OutputMode, print_error, print_info, print_json, print_kv, print_success, print_warning,
};

/// BTM subcommands.
#[derive(Debug, Subcommand)]
pub enum BtmCommands {
    /// Initialize a blank btm.toml
    ///
    /// Creates a policy file pre-configured for service management work.
    ///
    /// Examples:
    ///   contour btm init
    ///   contour btm init --org com.acme --output btm-policy.toml
    Init {
        /// Output file path
        #[arg(short, long, default_value = "btm.toml")]
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

    /// Show BTM info (scan modes, rule types, local config)
    ///
    /// Displays version, build info, available rule types and scan modes,
    /// and a summary of any btm.toml found in the current directory.
    Info,

    /// Scan for LaunchDaemons/LaunchAgents and generate BTM rules
    ///
    /// Discovers launchd jobs on the filesystem or within app bundles,
    /// extracts labels, team IDs, and bundle identifiers, then merges
    /// the resulting rules into a btm.toml file.
    Scan {
        /// Scan mode: system launch items or app bundles
        #[arg(long, value_enum, default_value = "launch-items")]
        mode: BtmScanMode,

        /// Directories to scan (defaults to /Library/LaunchDaemons + /Library/LaunchAgents)
        #[arg(short, long)]
        path: Vec<PathBuf>,

        /// Output file path for scan results (.toml)
        #[arg(short, long, default_value = "btm.toml")]
        output: PathBuf,

        /// Organization identifier (reads from .contour/config.toml if not provided)
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode to select which launch items to include
        #[arg(short = 'I', long)]
        interactive: bool,
    },

    /// Merge BTM rules from one config file into another
    ///
    /// Matches apps by bundle_id and merges rules from source into target.
    Merge {
        /// Source policy file with BTM rules
        source: PathBuf,
        /// Target policy file to merge into
        target: PathBuf,
    },

    /// Generate service management profiles or DDM declarations
    ///
    /// Reads a btm.toml and generates mobileconfig or DDM JSON for apps
    /// that have BTM rules configured.
    ///
    /// Examples:
    ///   contour btm generate btm.toml --output ./profiles/
    ///   contour btm generate btm.toml --ddm --output ./ddm/
    ///   contour btm generate btm.toml --fragment
    Generate {
        /// Input policy file (btm.toml)
        input: PathBuf,

        /// Output directory for generated profiles
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Preview what would be generated without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory instead of plain profiles
        #[arg(long)]
        fragment: bool,

        /// Generate DDM declarations (JSON) instead of mobileconfig
        ///
        /// Outputs com.apple.configuration.services.background-tasks declarations
        /// (macOS 15+) instead of com.apple.servicemanagement mobileconfig profiles.
        #[arg(long)]
        ddm: bool,

        /// Generate one profile per app instead of a single combined profile
        #[arg(long)]
        per_app: bool,
    },

    /// Validate BTM rules in a btm.toml
    ///
    /// Checks that BTM rules have valid rule types and non-empty values,
    /// and detects duplicate rules within each app.
    ///
    /// Examples:
    ///   contour btm validate btm.toml
    ///   contour btm validate btm.toml --strict
    Validate {
        /// Input policy file
        #[arg(default_value = "btm.toml")]
        input: PathBuf,

        /// Strict mode: treat warnings as errors
        #[arg(long)]
        strict: bool,
    },

    /// Compare BTM rules between two config files
    ///
    /// Shows differences in BTM rules between two btm.toml files.
    ///
    /// Examples:
    ///   contour btm diff btm.toml btm-new.toml
    Diff {
        /// First policy file (old)
        file1: PathBuf,

        /// Second policy file (new)
        file2: PathBuf,
    },

    /// Generate shell completions
    #[command(hide = true)]
    Completions {
        /// Shell to generate completions for
        #[arg(value_enum)]
        shell: Shell,
    },
}

/// BTM scan mode.
#[derive(Debug, Clone, ValueEnum)]
pub enum BtmScanMode {
    /// Scan /Library/LaunchDaemons and /Library/LaunchAgents
    LaunchItems,
    /// Scan inside .app bundles for embedded launch items
    Apps,
}
