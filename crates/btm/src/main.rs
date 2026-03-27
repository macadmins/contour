use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use btm::cli::{BtmCommands, OutputMode};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Debug, Parser)]
#[command(name = "btm")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")))]
#[command(about = "BTM - Background Task Management profile toolkit")]
pub struct BtmCli {
    #[command(subcommand)]
    pub command: Option<BtmCommands>,

    /// Enable verbose output
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Output in JSON format (for CI/CD)
    #[arg(long, global = true)]
    pub json: bool,

    // --- One-shot mode arguments (when no subcommand is given) ---
    /// Scan mode (one-shot mode)
    #[arg(long, value_enum, default_value = "launch-items")]
    pub mode: btm::cli::BtmScanMode,

    /// Directories to scan (one-shot mode)
    #[arg(short, long, default_value = "/Applications")]
    pub path: Vec<std::path::PathBuf>,

    /// Output directory for generated profiles (one-shot mode)
    #[arg(short, long)]
    pub output: Option<std::path::PathBuf>,

    /// Organization identifier
    #[arg(long)]
    pub org: Option<String>,

    /// Interactive mode to select items (one-shot mode)
    #[arg(short = 'I', long)]
    pub interactive: bool,

    /// Generate DDM declarations instead of mobileconfig (one-shot mode)
    #[arg(long)]
    pub ddm: bool,

    /// Preview without writing (one-shot mode)
    #[arg(long)]
    pub dry_run: bool,
}

fn main() -> Result<()> {
    let cli = BtmCli::parse();

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
        Some(BtmCommands::Init {
            output,
            org,
            name,
            force,
        }) => btm::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode),
        Some(BtmCommands::Info) => btm::cli::info::run(output_mode),
        Some(BtmCommands::Scan {
            mode,
            path,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            btm::cli::scan::run(&mode, &path, &output, &org, interactive, output_mode)
        }
        Some(BtmCommands::Merge { source, target }) => {
            btm::cli::merge::run(&source, &target, output_mode)
        }
        Some(BtmCommands::Generate {
            input,
            output,
            dry_run,
            fragment,
            ddm,
            per_app,
        }) => btm::cli::generate::run(
            &input,
            output.as_deref(),
            dry_run,
            fragment,
            ddm,
            per_app,
            output_mode,
        ),
        Some(BtmCommands::Validate { input, strict }) => {
            btm::cli::validate::run(&input, strict, output_mode)
        }
        Some(BtmCommands::Diff { file1, file2 }) => {
            btm::cli::diff::run(&file1, &file2, output_mode)
        }
        Some(BtmCommands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut BtmCli::command(), "btm", shell);
            Ok(())
        }
        None => {
            let org = contour_core::resolve_org(cli.org)?;
            btm::cli::scan::run_oneshot(
                &cli.mode,
                &cli.path,
                cli.output.as_deref(),
                &org,
                cli.interactive,
                cli.ddm,
                cli.dry_run,
                output_mode,
            )
        }
    }
}
