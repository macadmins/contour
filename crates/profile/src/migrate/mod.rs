//! MDM to DDM migration support
//!
//! This module provides migration guidance for transitioning from
//! traditional MDM profile payloads to DDM declarations.

pub mod mapping;

pub use mapping::{MigrationRegistry, MigrationStatus};
