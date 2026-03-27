use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use anyhow::Result;
use clap::Parser;
use contour_core::OutputMode;

#[derive(Parser)]
#[command(name = "support")]
#[command(version = concat!(env!("CARGO_PKG_VERSION"), "+", env!("BUILD_TIMESTAMP")))]
#[command(about = "Root3 Support App mobileconfig profile generator")]
struct Cli {
    #[command(subcommand)]
    command: Option<support::cli::Commands>,

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
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(support::cli::Commands::Init { path, output }) => {
            support::cli::init::run(&path, output.as_deref())
        }
        Some(support::cli::Commands::Generate {
            config,
            output,
            dry_run,
            brand,
            fragment,
        }) => support::cli::generate::run(
            &config,
            output.as_deref(),
            dry_run,
            brand.as_deref(),
            fragment,
            OutputMode::Human,
        ),

        None => support::cli::wizard::run_wizard(
            cli.output.as_deref(),
            cli.org.as_deref(),
            cli.dry_run,
            OutputMode::Human,
        ),
    }
}
