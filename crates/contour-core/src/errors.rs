//! Common error types for Contour tools.

use thiserror::Error;

/// Common result type for Contour operations.
pub type ContourResult<T> = Result<T, ContourError>;

/// Common errors across Contour tools.
#[derive(Debug, Error)]
pub enum ContourError {
    /// File not found.
    #[error("File not found: {path}")]
    FileNotFound { path: String },

    /// Invalid file format.
    #[error("Invalid file format: {message}")]
    InvalidFormat { message: String },

    /// Parse error.
    #[error("Parse error in {file}: {message}")]
    ParseError { file: String, message: String },

    /// Validation failed.
    #[error("Validation failed: {message}")]
    ValidationFailed { message: String },

    /// Configuration error.
    #[error("Configuration error: {message}")]
    ConfigError { message: String },

    /// IO error wrapper.
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// JSON error wrapper.
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    /// Plist error wrapper.
    #[error("Plist error: {0}")]
    Plist(#[from] plist::Error),

    /// Generic error with context.
    #[error("{context}: {source}")]
    WithContext {
        context: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl ContourError {
    /// Create a file not found error.
    #[must_use]
    pub fn file_not_found(path: impl Into<String>) -> Self {
        Self::FileNotFound { path: path.into() }
    }

    /// Create an invalid format error.
    #[must_use]
    pub fn invalid_format(message: impl Into<String>) -> Self {
        Self::InvalidFormat {
            message: message.into(),
        }
    }

    /// Create a parse error.
    #[must_use]
    pub fn parse_error(file: impl Into<String>, message: impl Into<String>) -> Self {
        Self::ParseError {
            file: file.into(),
            message: message.into(),
        }
    }

    /// Create a validation error.
    #[must_use]
    pub fn validation_failed(message: impl Into<String>) -> Self {
        Self::ValidationFailed {
            message: message.into(),
        }
    }

    /// Create a configuration error.
    #[must_use]
    pub fn config_error(message: impl Into<String>) -> Self {
        Self::ConfigError {
            message: message.into(),
        }
    }

    /// Add context to an error.
    pub fn with_context<E>(context: impl Into<String>, source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::WithContext {
            context: context.into(),
            source: Box::new(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = ContourError::file_not_found("/path/to/file.yaml");
        assert_eq!(format!("{err}"), "File not found: /path/to/file.yaml");
    }

    #[test]
    fn test_parse_error() {
        let err = ContourError::parse_error("config.toml", "unexpected token");
        let display = format!("{err}");
        assert!(display.contains("config.toml"));
        assert!(display.contains("unexpected token"));
    }
}
