//! Generate `com.apple.configuration.app.settings` declarations.
//!
//! macOS 27 controls which apps and binaries may run through declarative
//! management, enforced by the Endpoint Security framework: it allows or denies
//! binary execution and shuts down processes of a denied binary. This module
//! populates an `app.settings` declaration from the same identifier data the
//! Santa scanner already collects (sha256 / TeamID / SigningID / CDHash), and
//! can convert existing Santa rules into the DDM-native equivalent.
//!
//! - [`model`] — schema-faithful types (`BinaryIdentifier`, `PermissionDefault`, …).
//! - [`map`] — adapters from scans / Santa rules to those types (the converter).
//! - [`build`] — assemble the declaration JSON from validated entries.
//! - [`validate`] — the schema `notes` rules (allow/deny identifier requirements).
//! - [`privacy`] — `Privacy.PermissionDefaults` policy file + `--scaffold`.

pub mod build;
pub mod map;
pub mod model;
pub mod privacy;
pub mod validate;

pub use build::{APP_SETTINGS_TYPE, AppSettings};
pub use model::{
    AppIdentifier, BinaryIdentifier, BinaryPolicy, ComposedIdentifier, Permission,
    PermissionDefault, SigningState,
};
pub use privacy::{PermissionPolicyFile, from_permission_policy, scaffold_policy};
pub use validate::{Violation, partition_binaries, validate_binary, validate_permission_default};
