pub mod generate;
pub mod init;
pub mod wizard;

use std::path::PathBuf;

use clap::Subcommand;

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Scan asset folders and create a support.toml config
    Init {
        /// Parent directory containing brand subfolders (e.g., acme/, globex/, initech/)
        path: PathBuf,

        /// Output config file path
        #[arg(short, long, default_value = "support.toml")]
        output: Option<PathBuf>,
    },

    /// Generate mobileconfig profiles from a support.toml config
    Generate {
        /// Path to support.toml config file
        config: PathBuf,

        /// Output directory (default: same directory as config file)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Preview what would be generated without writing files
        #[arg(long)]
        dry_run: bool,

        /// Generate for a single brand only
        #[arg(long)]
        brand: Option<String>,

        /// Generate Fleet GitOps fragment directory
        #[arg(long)]
        fragment: bool,
    },
}
