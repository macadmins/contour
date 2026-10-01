//! Declarative Device Management (DDM) support
//!
//! DDM is Apple's modern approach to device management using JSON-based
//! declarations instead of traditional XML plist profiles.
//!
//! Note: This module is reserved for future DDM declaration support.
#![allow(dead_code, reason = "module under development")]

pub mod app_privacy;
pub mod compose;
/// Wrapping classic .mobileconfig profiles in com.apple.configuration.legacy
/// declarations, with a content-hash index so a changed profile cannot
/// silently keep serving its old URL.
pub mod legacy;
pub mod notes;
pub mod parser;
pub mod predicate;
pub mod presets;
pub mod rename;
pub mod schema;
pub mod scope;
/// Building and re-hosting the zip asset a
/// `com.apple.configuration.services.configuration-files` declaration points
/// at, with reproducible packing so an untouched tree keeps its hash.
pub mod service_config;
pub mod types;
pub mod verify;

#[allow(unused_imports, reason = "reserved for future use")]
pub use parser::parse_declaration;
pub use parser::{is_ddm_file, parse_declaration_file, write_declaration};
#[allow(unused_imports, reason = "reserved for future use")]
pub use types::DeclarationType;
pub use types::{Declaration, DeclarationPayload};
