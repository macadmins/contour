use anyhow::Result;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use pppc::cli::OutputMode;
use pppc::cli::{Cli, Commands};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> Result<()> {
    let cli = Cli::parse();

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
        Some(Commands::Scan {
            path,
            from_csv,
            output,
            org,
            interactive,
        }) => {
            let org = contour_core::resolve_org(org)?;
            pppc::cli::scan::run(
                &path,
                from_csv.as_deref(),
                &output,
                &org,
                interactive,
                output_mode,
            )
        }

        Some(Commands::Configure {
            input,
            skip_configured,
        }) => pppc::cli::configure::run(&input, skip_configured),

        Some(Commands::Generate {
            input,
            output,
            combined,
            dry_run,
            fragment,
        }) => pppc::cli::generate::run(
            &input,
            output.as_deref(),
            combined,
            dry_run,
            fragment,
            output_mode,
        ),

        Some(Commands::Batch {
            input,
            add_services,
            remove_services,
            set_services,
            apps,
            dry_run,
        }) => pppc::cli::batch::run(
            &input,
            &add_services,
            &remove_services,
            &set_services,
            &apps,
            dry_run,
            output_mode,
        ),

        Some(Commands::Init {
            output,
            org,
            name,
            force,
        }) => pppc::cli::init::run(&output, org.as_deref(), name.as_deref(), force, output_mode),

        Some(Commands::Info) => pppc::cli::info::run(output_mode),

        Some(Commands::Validate { input, strict }) => {
            pppc::cli::validate::run(&input, strict, output_mode)
        }

        Some(Commands::Diff { file1, file2 }) => pppc::cli::diff::run(&file1, &file2, output_mode),

        Some(Commands::Completions { shell }) => {
            use clap::CommandFactory;
            contour_core::generate_completions(&mut Cli::command(), "pppc", shell);
            Ok(())
        }

        None => {
            // One-shot mode (backwards compatibility)
            let org = contour_core::resolve_org(cli.org)?;
            pppc::cli::scan::run_oneshot(
                &cli.path,
                cli.output.as_deref(),
                &org,
                cli.interactive,
                cli.service,
                cli.dry_run,
                output_mode,
            )
        }
    }
}
