//! Profile CLI - Apple configuration profile management toolkit (Community Edition).
//!
//! Profile provides commands for importing, validating, and normalizing
//! Apple configuration profiles (.mobileconfig) for MDM deployments.

mod audit;
mod classify;
mod cli;
mod collisions;
mod config;
mod ddm;
mod detect;
mod diff;
mod docs;
mod example;
mod link;
mod mdm_vars;
mod migrate;
mod output;
mod plan;
mod profile;
mod recipe;
mod reidentify;
mod rollback;
mod schema;
mod signing;
mod uuid;
mod validation;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use mimalloc::MiMalloc;

use cli::Cli;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    // Parse CLI first so we know whether to render errors as JSON.
    let cli = Cli::parse();
    let json_mode = cli.json;

    if let Err(e) = run(cli) {
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

fn run(cli: Cli) -> Result<()> {
    // Setup logging (suppress in JSON mode for clean output)
    let log_level = if cli.json {
        tracing::Level::ERROR // Only show errors in JSON mode
    } else if cli.verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };

    tracing_subscriber::fmt()
        .with_max_level(log_level)
        .with_target(false)
        .init();

    // Wrap the standalone profile tree under a synthetic `contour` root so
    // `find` results and help-ai hints match the unified `contour profile …`
    // surface (the standalone binary has no top-level `find`/`help-ai`).
    let clap_root = || clap::Command::new("contour").subcommand(Cli::command().name("profile"));

    // One dispatcher, shared with `contour profile …`.
    cli::dispatch::dispatch(cli.command, cli.json, cli.channel, &clap_root)
}
