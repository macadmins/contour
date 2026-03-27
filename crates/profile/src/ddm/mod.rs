//! Declarative Device Management (DDM) support
//!
//! DDM is Apple's modern approach to device management using JSON-based
//! declarations instead of traditional XML plist profiles.
//!
//! Note: This module is reserved for future DDM declaration support.
#![allow(dead_code, reason = "module under development")]

pub mod parser;
pub mod schema;
pub mod types;

#[allow(unused_imports, reason = "conditionally used")]
pub use parser::parse_declaration;
pub use parser::{is_ddm_file, parse_declaration_file, write_declaration};
#[allow(unused_imports, reason = "conditionally used")]
pub use types::DeclarationType;
pub use types::{Declaration, DeclarationPayload};
