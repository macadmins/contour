//! Logging initialization for CLI tools.
//!
//! Provides consistent logging setup across all Contour tools:
//! - Suppresses logs in JSON mode to keep output clean
//! - Supports verbose mode for debugging
//! - Uses tracing for structured logging

use tracing::Level;
use tracing_subscriber::fmt;

/// Logging configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct LogConfig {
    /// Enable verbose (debug) logging.
    pub verbose: bool,
    /// Enable JSON output mode (suppresses most logs).
    pub json_mode: bool,
}

impl LogConfig {
    /// Create a new logging configuration.
    #[must_use]
    pub fn new(verbose: bool, json_mode: bool) -> Self {
        Self { verbose, json_mode }
    }

    /// Get the appropriate log level.
    #[must_use]
    pub fn level(&self) -> Level {
        if self.json_mode {
            Level::ERROR // Minimal logging in JSON mode
        } else if self.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        }
    }
}

/// Initialize logging with the given configuration.
///
/// Should be called once at the start of the CLI tool.
///
/// # Example
///
/// ```
/// use contour_core::{init_logging, logging::LogConfig};
///
/// let config = LogConfig::new(false, false);
/// init_logging(config);
/// ```
pub fn init_logging(config: LogConfig) {
    fmt()
        .with_max_level(config.level())
        .with_target(false)
        .with_thread_ids(false)
        .with_thread_names(false)
        .without_time()
        .init();
}

/// Initialize logging from CLI flags.
///
/// Convenience function that creates a `LogConfig` and initializes logging.
///
/// # Example
///
/// ```ignore
/// use contour_core::logging::init_from_flags;
///
/// init_from_flags(cli.verbose, cli.json);
/// ```
pub fn init_from_flags(verbose: bool, json: bool) {
    init_logging(LogConfig::new(verbose, json));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_default() {
        let config = LogConfig::default();
        assert_eq!(config.level(), Level::INFO);
    }

    #[test]
    fn test_log_level_verbose() {
        let config = LogConfig::new(true, false);
        assert_eq!(config.level(), Level::DEBUG);
    }

    #[test]
    fn test_log_level_json_mode() {
        let config = LogConfig::new(false, true);
        assert_eq!(config.level(), Level::ERROR);
    }

    #[test]
    fn test_json_mode_overrides_verbose() {
        // JSON mode should take precedence over verbose
        let config = LogConfig::new(true, true);
        assert_eq!(config.level(), Level::ERROR);
    }
}
