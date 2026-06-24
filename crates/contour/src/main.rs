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

mod completions;
mod dispatch;
mod init;
mod osquery;

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

    /// Schema channel: stable (released) or beta (pre-release OS seed)
    #[arg(
        long,
        global = true,
        value_enum,
        default_value_t = profile::schema::Channel::Stable
    )]
    pub channel: profile::schema::Channel,
}

#[derive(Debug, Subcommand)]
#[allow(
    clippy::large_enum_variant,
    reason = "constructed once per process from CLI parsing; boxing the largest variant would force the dispatch sites to deref through a Box for no measurable benefit"
)]
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

    /// Query embedded osquery table/column schema
    Osquery {
        #[command(subcommand)]
        action: osquery::OsqueryAction,
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
        /// Default preset/recipe library path. Used as the fallback for
        /// `--recipe-path`, `library import --into`, `library validate`,
        /// `library normalize`. Run `contour profile library new <PATH>`
        /// to scaffold a fresh library at this location.
        #[arg(long, value_name = "DIR")]
        library_path: Option<String>,
        /// MDM platform for the [mdm_variables] section (fleet|jamf|apple).
        /// Writes that platform's variable catalogue as a commented template.
        #[arg(long)]
        mdm: Option<String>,
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

        /// Fuzzy-search commands by term (e.g. "secrets", "shared ipad")
        #[arg(long)]
        search: Option<String>,

        /// With --search: also match flag names and flag help (broader, noisier)
        #[arg(long)]
        deep: bool,

        /// Domain sections to include (comma-separated). Available: cli, profile, pppc, santa, notifications, btm, mscp, ddm
        #[arg(long, value_delimiter = ',')]
        section: Option<Vec<String>>,

        /// Show standard operating procedures for a tool (profile, profile-naming, mscp, osquery, fleet-migrate, enrollment, ddm, santa, pppc, btm, notifications, support, ci, precommit)
        #[arg(long)]
        sop: Option<String>,

        /// With --sop: print only the section whose heading matches (substring)
        #[arg(long, value_name = "HEADING")]
        at: Option<String>,

        /// Output the complete reference (all commands, all flags, all domain data)
        #[arg(long)]
        full: bool,

        /// Install a Claude Code / Kilo Code skill file for contour
        #[arg(long)]
        install_skill: bool,
    },

    /// Fuzzy-search commands by term when you can't recall the exact name
    #[command(
        long_about = "Fuzzy-search the whole command tree for a term and get a \
                      ranked list of matching commands.\n\n\
                      Examples:\n  \
                      contour find secrets\n  \
                      contour find \"shared ipad\"\n  \
                      contour find depricated        # typo-tolerant\n  \
                      contour find org --deep        # also search flag help\n  \
                      contour find secrets --json"
    )]
    Find {
        /// Search term (e.g. "secrets", "shared ipad")
        term: String,
        /// Also match flag names and flag help (broader, noisier)
        #[arg(long)]
        deep: bool,
    },

    /// Install AI agent skill file (.claude/skills/contour.md)
    #[command(name = "setup-agent")]
    SetupAgent,

    /// Output CLI schema as JSON for tooling integration
    #[command(name = "help-json", hide = true)]
    HelpJson {
        /// Command path to scope output (dot notation, e.g. profile.validate)
        command: Option<String>,
    },

    /// Shell completions — install guide, installer, or raw script
    #[command(long_about = "Set up shell tab-completion for contour.\n\
                      \n\
                      With no shell argument the current shell is detected from\n\
                      $SHELL and confirmed interactively. By default a per-shell\n\
                      install guide is printed; `--install` writes the completion\n\
                      file to its conventional location; `--script` emits only the\n\
                      raw completion script (for piping or packaging).\n\
                      \n\
                      Supported shells: zsh, bash, fish.\n\
                      \n\
                      Examples:\n  \
                      contour completions                 # detect + interactive guide\n  \
                      contour completions zsh --install   # write the completion file\n  \
                      contour completions fish --script > ~/.config/fish/completions/contour.fish")]
    Completions {
        /// Target shell (zsh, bash, fish). Omit to detect and pick interactively.
        #[arg(value_enum)]
        shell: Option<crate::completions::ShellKind>,
        /// Write the completion file to its conventional location
        #[arg(long)]
        install: bool,
        /// Emit only the raw completion script to stdout (for piping/packaging)
        #[arg(long, conflicts_with = "install")]
        script: bool,
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
    /// Learn Background Task Management workflow
    Btm,
    /// Learn the shared .contour/config.toml configuration
    Config,
}

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;

    if let Err(e) = dispatch::run(cli) {
        if json_mode {
            // Phase B3: emit a parseable JSON error envelope on stderr so agents
            // and CI receive a structured failure shape, matching the BatchResult
            // error_code enum documented in the procedural SOP format spec.
            let msg = format!("{e:#}");
            let code = contour_core::classify_error(&msg);
            contour_core::print_error_json(&msg, Some(code));
        } else {
            eprintln!("Error: {e:#}");
        }
        std::process::exit(1);
    }
}
