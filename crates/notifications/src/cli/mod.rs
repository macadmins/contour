//! Notifications CLI command definitions and dispatch.

pub mod configure;
pub mod diff;
pub mod generate;
pub mod init;
pub mod scan;
pub mod validate;

use clap::Subcommand;
use clap_complete::Shell;
use std::path::PathBuf;

pub use contour_core::output::{
    OutputMode, print_error, print_info, print_json, print_kv, print_success, print_warning,
};

/// Notification subcommands.
#[derive(Debug, Subcommand)]
pub enum NotificationCommands {
    /// Initialize a blank notifications.toml
    ///
    /// Creates a notification settings file pre-configured for your organization.
    ///
    /// Examples:
    ///   contour notifications init
    ///   contour notifications init --org com.acme --output notif.toml
    Init {
        /// Output file path
        #[arg(short, long, default_value = "notifications.toml")]
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

    /// Scan for installed applications
    ///
    /// Discovers .app bundles, extracts bundle IDs, and merges them
    /// into a notifications.toml file.
    ///
    /// Examples:
    ///   contour notifications scan
    ///   contour notifications scan --path /Applications --interactive
    Scan {
        /// Directories to scan (defaults to /Applications)
        #[arg(short, long)]
        path: Vec<PathBuf>,

        /// Output file path for scan results (.toml)
        #[arg(short, long, default_value = "notifications.toml")]
        output: PathBuf,

        /// Organization identifier (reads from .contour/config.toml if not provided)
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode to select which apps to include
        #[arg(short = 'I', long)]
        interactive: bool,
    },

    /// Interactively configure per-app notification settings
    ///
    /// Walks through each app in the config and lets you toggle
    /// notification settings field by field.
    ///
    /// Examples:
    ///   contour notifications configure notifications.toml
    Configure {
        /// Input config file
        #[arg(default_value = "notifications.toml")]
        input: PathBuf,
    },

    /// Generate notification mobileconfig profiles
    ///
    /// Reads a notifications.toml and generates mobileconfig profiles
    /// for notification settings.
    ///
    /// Examples:
    ///   contour notifications generate notifications.toml --output ./profiles/
    ///   contour notifications generate notifications.toml --combined
    ///   contour notifications generate notifications.toml --fragment
    Generate {
        /// Input config file (notifications.toml)
        input: PathBuf,

        /// Output directory for generated profiles
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Generate a single combined profile instead of per-app profiles
        #[arg(long)]
        combined: bool,

        /// Preview what would be generated without writing
        #[arg(long)]
        dry_run: bool,

        /// Generate Fleet GitOps fragment directory
        #[arg(long)]
        fragment: bool,
    },

    /// Validate notification settings
    ///
    /// Checks that notification settings have valid values:
    /// non-empty bundle IDs, alert_type in range 0..=2, etc.
    ///
    /// Examples:
    ///   contour notifications validate notifications.toml
    ///   contour notifications validate --strict
    Validate {
        /// Input config file
        #[arg(default_value = "notifications.toml")]
        input: PathBuf,

        /// Strict mode: treat warnings as errors
        #[arg(long)]
        strict: bool,
    },

    /// Compare two notification config files
    ///
    /// Shows differences in notification settings between two files.
    ///
    /// Examples:
    ///   contour notifications diff old.toml new.toml
    Diff {
        /// First config file (old)
        file1: PathBuf,

        /// Second config file (new)
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
