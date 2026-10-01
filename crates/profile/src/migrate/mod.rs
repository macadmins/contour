//! MDM to DDM migration support
//!
//! This module provides migration guidance for transitioning from
//! traditional MDM profile payloads to DDM declarations.
//!
//! The registry itself now lives in [`mdm_schema::migration`]. It is schema
//! data — "which DDM declaration supersedes this payload type?" — with no I/O
//! and no dependency on anything in this crate, and read-only consumers need
//! it: the MCP server answers deprecation questions without linking a crate
//! that can write MDM artifacts. This module re-exports it so the existing
//! `crate::migrate::mapping::…` paths keep working.

/// The migration registry, re-exported from its home in `mdm-schema`.
pub mod mapping {
    pub use mdm_schema::migration::*;
}

#[allow(unused_imports, reason = "reserved for future use")]
pub use mapping::{MigrationRegistry, MigrationStatus};
