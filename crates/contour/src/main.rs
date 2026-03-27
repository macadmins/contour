//! Contour CLI - Unified macOS MDM configuration toolkit.
//!
//! Contour consolidates five domain-specific tools into a single CLI:
//! - `profile` - Apple configuration profile toolkit
//! - `pppc` - Privacy/TCC profile toolkit
//! - `santa` - Santa allowlist/blocklist toolkit
//! - `mscp` - mSCP baseline transformation toolkit

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod dispatch;
mod init;

use anyhow::Result;
use clap::{Parser, Subcommand};

const ABOUT: &str = "Contour - macOS MDM configuration toolkit";

#[derive(Parser)]
#[command(name = "contour")]
#[command(author = env!("CARGO_PKG_AUTHORS"))]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")))]
#[command(about = ABOUT, long_about = None)]
#[command(
    after_help = "Tip: AI agents should run `contour help-ai` for a machine-readable CLI reference."
)]
#[derive(Debug)]
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
pub enum Commands {
    /// Apple configuration profile toolkit (normalize, validate, sign, etc.)
    Profile {
        #[command(subcommand)]
        action: profile::cli::Commands,
    },

    /// Privacy/PPPC mobileconfig profile toolkit
    Pppc {
        #[command(subcommand)]
        action: Option<pppc::cli::Commands>,

        // --- One-shot mode arguments (when no subcommand is given) ---
        /// Directories or app bundles to scan (one-shot mode)
        #[arg(short, long, default_value = "/Applications")]
        path: Vec<std::path::PathBuf>,

        /// Output directory for generated profiles (one-shot mode)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Organization identifier (required for one-shot mode)
        #[arg(long)]
        org: Option<String>,

        /// TCC service to configure (can be repeated, one-shot mode)
        #[arg(long, value_enum)]
        service: Option<Vec<pppc::pppc::PppcService>>,

        /// Interactive mode to select apps and permissions (one-shot mode)
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Preview what would be generated without writing (one-shot mode)
        #[arg(long)]
        dry_run: bool,
    },

    /// Santa mobileconfig profile toolkit
    Santa {
        #[command(subcommand)]
        action: santa::cli::Commands,
    },

    /// mSCP baseline transformation toolkit
    Mscp {
        #[command(subcommand)]
        action: mscp::cli::Commands,
    },

    /// Root3 Support App profile generator
    ///
    /// One-shot mode: `contour support` launches an interactive wizard
    /// that generates a mobileconfig directly.
    Support {
        #[command(subcommand)]
        action: Option<support::cli::Commands>,

        // --- Wizard mode (when no subcommand) ---
        /// Output file path (wizard mode)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Organization identifier (wizard mode)
        #[arg(long)]
        org: Option<String>,

        /// Preview without writing (wizard mode)
        #[arg(long)]
        dry_run: bool,
    },

    /// Background Task Management — service management profiles
    ///
    /// Scan for LaunchDaemons/LaunchAgents, generate service management
    /// profiles or DDM declarations for MDM deployment.
    ///
    /// One-shot mode: `contour btm --path /Applications --org com.example`
    /// generates profiles directly (scan + generate in one step).
    Btm {
        #[command(subcommand)]
        action: Option<btm::cli::BtmCommands>,

        // --- One-shot mode arguments (when no subcommand is given) ---
        /// Scan mode (one-shot mode)
        #[arg(long, value_enum, default_value = "launch-items")]
        mode: btm::cli::BtmScanMode,

        /// Directories to scan (one-shot mode)
        #[arg(short, long, default_value = "/Applications")]
        path: Vec<std::path::PathBuf>,

        /// Output directory for generated profiles (one-shot mode)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Organization identifier
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode to select items (one-shot mode)
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Generate DDM declarations instead of mobileconfig (one-shot mode)
        #[arg(long)]
        ddm: bool,

        /// Preview without writing (one-shot mode)
        #[arg(long)]
        dry_run: bool,
    },

    /// Notification settings profile toolkit
    ///
    /// Scan for installed applications and generate notification settings
    /// mobileconfig profiles for MDM deployment.
    ///
    /// One-shot mode: `contour notifications --path /Applications --org com.example`
    /// generates profiles directly (scan + generate in one step).
    Notifications {
        #[command(subcommand)]
        action: Option<notifications::cli::NotificationCommands>,

        // --- One-shot mode arguments (when no subcommand is given) ---
        /// Directories or app bundles to scan (one-shot mode)
        #[arg(short, long, default_value = "/Applications")]
        path: Vec<std::path::PathBuf>,

        /// Output directory for generated profiles (one-shot mode)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,

        /// Organization identifier
        #[arg(long)]
        org: Option<String>,

        /// Interactive mode to select apps (one-shot mode)
        #[arg(short = 'I', long)]
        interactive: bool,

        /// Generate a single combined profile (one-shot mode)
        #[arg(long)]
        combined: bool,

        /// Preview without writing (one-shot mode)
        #[arg(long)]
        dry_run: bool,
    },

    /// Initialize contour configuration for this repository
    ///
    /// Creates .contour/config.toml with organization identity and defaults.
    /// Other commands (profile, pppc, santa, mscp) read from this
    /// config instead of requiring --org flags on every invocation.
    Init {
        /// Repository root (default: current directory)
        #[arg(default_value = ".")]
        path: std::path::PathBuf,
        /// Organization name
        #[arg(long)]
        name: Option<String>,
        /// Reverse-domain identifier (e.g., com.acme)
        #[arg(long)]
        domain: Option<String>,
        /// Fleet server URL
        #[arg(long)]
        server_url: Option<String>,
        /// Platforms (comma-separated: macos,windows,linux,ios)
        #[arg(long, value_delimiter = ',')]
        platforms: Option<Vec<String>>,
        /// Use deterministic/predictable UUIDs (recommended for GitOps)
        #[arg(long)]
        deterministic_uuids: Option<bool>,
        /// Non-interactive mode (uses flags or defaults)
        #[arg(short, long)]
        yes: bool,
    },

    /// Interactive training mode with step-by-step guidance
    Trainer {
        #[command(subcommand)]
        tool: TrainerTool,
    },

    /// Output CLI reference for AI agents (default: command index)
    #[command(name = "help-agents", alias = "help-ai")]
    HelpAgents {
        /// Show full detail for a specific command (dot notation, e.g. santa.add)
        #[arg(long)]
        command: Option<String>,

        /// Domain sections to include (comma-separated). Available: cli, profile, pppc, santa, notifications, btm, mscp, ddm
        #[arg(long, value_delimiter = ',')]
        section: Option<Vec<String>>,

        /// Show standard operating procedures for a tool (profile, mscp, santa, pppc, ddm)
        #[arg(long)]
        sop: Option<String>,

        /// Output the complete reference (all commands, all flags, all domain data)
        #[arg(long)]
        full: bool,
    },

    /// Output CLI schema as JSON for tooling integration
    #[command(name = "help-json", hide = true)]
    HelpJson {
        /// Command path to scope output (dot notation, e.g. profile.validate)
        command: Option<String>,
    },

    /// Generate shell completions
    #[command(
        hide = true,
        after_long_help = "\
Install completions for your shell:

  Zsh:
    contour completions zsh > ~/.zfunc/_contour
    autoload -Uz compinit && compinit

  Bash:
    contour completions bash > ~/.bash_completion.d/contour
    source ~/.bash_completion.d/contour

  Fish:
    contour completions fish > ~/.config/fish/completions/contour.fish"
    )]
    Completions {
        /// Target shell
        #[arg(value_enum)]
        shell: clap_complete::Shell,
    },
}

/// Tools available in trainer mode
#[derive(Debug, Subcommand)]
pub enum TrainerTool {
    /// Learn Santa GitOps workflow
    Santa,
    /// Learn PPPC/TCC profile workflow
    Pppc,
    /// Learn mSCP security baseline workflow
    Mscp,
    /// Learn profile management workflow
    Profile,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    dispatch::run(cli)
}
