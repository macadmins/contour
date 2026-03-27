//! Profile - Apple configuration profile toolkit (Community Edition)
//!
//! This library provides functionality for:
//! - Parsing and writing Apple configuration profiles (.mobileconfig)
//! - Validating profiles against schemas
//! - Managing DDM (Declarative Device Management) declarations
//! - Profile normalization and UUID management
//! - Code signing and verification

pub mod cli;
pub mod config;
pub mod ddm;
pub mod diff;
pub mod docs;
pub mod link;
pub mod migrate;
pub mod output;
pub mod profile;
pub mod recipe;
pub mod schema;
pub mod signing;
pub mod uuid;
pub mod validation;
