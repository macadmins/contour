//! Documentation generator
//!
//! Generate markdown documentation from embedded payload schemas.

pub mod generator;

pub use generator::{generate_ddm_docs, generate_docs, generate_profile_doc};

// Also export for tests
#[allow(unused_imports, reason = "conditionally used")]
pub use generator::{
    generate_ddm_declaration_doc, generate_ddm_index, generate_index, generate_payload_doc,
};
