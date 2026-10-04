//! Schema registry — lives in `contour-form` now, re-exported here so every
//! `crate::schema::…` path in this crate keeps resolving.
//!
//! The move exists so the schema core can be built without a filesystem;
//! see `crates/contour-form/src/lib.rs` for the rule and what enforces it.
//! New schema code goes there, not here.

pub use contour_form::*;
