//! MDM to DDM migration support
//!
//! This module provides migration guidance for transitioning from
//! traditional MDM profile payloads to DDM declarations.

pub mod mapping;

#[allow(unused_imports, reason = "reserved for future use")]
pub use mapping::{MigrationRegistry, MigrationStatus};
