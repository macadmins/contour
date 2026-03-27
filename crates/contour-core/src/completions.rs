//! Shell completion generation.
//!
//! Provides shell completion generation for all supported shells.
//! Based on Sleigh's implementation using clap_complete.

use clap::Command;
use clap_complete::{Shell, generate};
use std::io;

/// Generate shell completions for a CLI command.
///
/// # Arguments
///
/// * `cmd` - The clap Command to generate completions for
/// * `bin_name` - The name of the binary (e.g., "fleet", "mscp", "santa")
/// * `shell` - The target shell
///
/// # Example
///
/// ```ignore
/// use clap::Parser;
/// use contour_core::generate_completions;
/// use clap_complete::Shell;
///
/// #[derive(Parser)]
/// struct Cli { /* ... */ }
///
/// let mut cmd = Cli::command();
/// generate_completions(&mut cmd, "myapp", Shell::Bash);
/// ```
pub fn generate_completions(cmd: &mut Command, bin_name: &str, shell: Shell) {
    generate(shell, cmd, bin_name, &mut io::stdout());
}

/// Shell completion generator that can be embedded in CLI tools.
#[derive(Debug)]
pub struct CompletionGenerator {
    bin_name: String,
}

impl CompletionGenerator {
    /// Create a new completion generator.
    #[must_use]
    pub fn new(bin_name: impl Into<String>) -> Self {
        Self {
            bin_name: bin_name.into(),
        }
    }

    /// Generate completions for the given shell.
    pub fn generate(&self, cmd: &mut Command, shell: Shell) {
        generate(shell, cmd, &self.bin_name, &mut io::stdout());
    }

    /// Generate completions to a writer.
    pub fn generate_to<W: io::Write>(&self, cmd: &mut Command, shell: Shell, writer: &mut W) {
        generate(shell, cmd, &self.bin_name, writer);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_completion_generator_new() {
        let generator = CompletionGenerator::new("test-cli");
        assert_eq!(generator.bin_name, "test-cli");
    }

    #[test]
    fn test_generate_to_buffer() {
        let generator = CompletionGenerator::new("test");
        let mut cmd = Command::new("test").subcommand(Command::new("sub"));
        let mut buf = Vec::new();
        generator.generate_to(&mut cmd, Shell::Bash, &mut buf);
        let output = String::from_utf8(buf).unwrap();
        assert!(output.contains("test"));
    }
}
