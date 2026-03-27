use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use notifications::cli::{NotificationCommands, OutputMode};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "notifications")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")))]
#[command(about = "Notification settings profile toolkit for macOS")]
pub struct NotificationsCli {
    #[command(subcommand)]
    pub command: Option<NotificationCommands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format (for CI/CD)
    #[arg(long, global = true)]
    pub json: bool,

    // --- One-shot mode arguments (when no subcommand is given) ---
    /// Directories or app bundles to scan (one-shot mode)
    #[arg(short, long, default_value = "/Applications")]
    pub path: Vec<std::path::PathBuf>,

    /// Output directory for generated profiles (one-shot mode)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,

    /// Organization identifier
    #[arg(long)]
    pub org: Option<String>,

    /// Interactive mode to select apps (one-shot mode)
    #[arg(short = 'I', long)]
    pub interactive: bool,

    /// Generate a single combined profile (one-shot mode)
    #[arg(long)]
    pub combined: bool,

    /// Preview without writing (one-shot mode)
    #[arg(long)]
    pub dry_run: bool,
}

fn main() -> Result<()> {
    let cli = NotificationsCli::parse();

    // Set up logging based on flags
    let filter = if cli.json {
        "error"
    } else if cli.verbose {
        "debug"
    } else {
        "info"
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_target(false)
        .without_time()
        .init();

    let output_mode = if cli.json {
        OutputMode::Json
    } else {
        OutputMode::Human
    };

    match cli.command {
        Some(NotificationCommands::Init {
            output,
            org,
            name,
            force,
        }) => notifications::cli::init::run(
            &output,
            org.as_deref(),
            name.as_deref(),
            force,
            output_mode,
        ),
        Some(NotificationCommands::Scan {
            path,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            notifications::cli::scan::run(&path, &output, &org, interactive, output_mode)
        }
        Some(NotificationCommands::Configure { input }) => {
            notifications::cli::configure::run(&input)
        }
        Some(NotificationCommands::Generate {
            input,
            output,
            combined,
            dry_run,
            fragment,
        }) => notifications::cli::generate::run(
            &input,
            output.as_deref(),
            combined,
            dry_run,
            fragment,
            output_mode,
        ),
        Some(NotificationCommands::Validate { input, strict }) => {
            notifications::cli::validate::run(&input, strict, output_mode)
        }
        Some(NotificationCommands::Diff { file1, file2 }) => {
            notifications::cli::diff::run(&file1, &file2, output_mode)
        }
        Some(NotificationCommands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(
                &mut NotificationsCli::command(),
                "notifications",
                shell,
            );
            Ok(())
        }
        None => {
            let org = contour_core::resolve_org(cli.org)?;
            notifications::cli::scan::run_oneshot(
                &cli.path,
                cli.output.as_deref(),
                &org,
                cli.interactive,
                cli.combined,
                cli.dry_run,
                output_mode,
            )
        }
    }
}
