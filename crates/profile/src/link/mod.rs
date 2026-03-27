//! Profile cross-reference linking module.
//!
//! This module handles UUID cross-references between Apple configuration profiles.
//! It allows linking separate profiles so their UUID references are consistent,
//! and optionally merging them into a single profile.
//!
//! # Example
//!
//! ```ignore
//! use profile::link::{link_profiles, LinkConfig};
//!
//! let profiles = vec![
//!     (PathBuf::from("wifi.mobileconfig"), wifi_profile),
//!     (PathBuf::from("cert.mobileconfig"), cert_profile),
//! ];
//!
//! let config = LinkConfig {
//!     org_domain: Some("com.example".to_string()),
//!     predictable: true,
//!     merge: false,
//!     validate: true,
//! };
//!
//! let result = link_profiles(profiles, &config)?;
//! ```

pub mod extractor;
pub mod linker;
pub mod types;
pub mod validator;

// Re-export main types and functions
pub use extractor::{extract_references, summarize_extraction};
pub use linker::{link_profiles, merge_profiles_v2};
pub use types::LinkConfig;
pub use validator::{format_validation_errors, validate_references};
