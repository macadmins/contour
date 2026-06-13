//! Profile - Apple configuration profile toolkit (Community Edition)
//!
//! This library provides functionality for:
//! - Parsing and writing Apple configuration profiles (.mobileconfig)
//! - Validating profiles against schemas
//! - Managing DDM (Declarative Device Management) declarations
//! - Profile normalization and UUID management
//! - Code signing and verification

pub mod audit;
pub mod classify;
pub mod cli;
pub mod collisions;
pub mod config;
pub mod ddm;
pub mod diff;
pub mod docs;
pub mod example;
pub mod link;
pub mod mdm_vars;
pub mod migrate;
pub mod output;
pub mod plan;
pub mod profile;
pub mod recipe;
pub mod reidentify;
pub mod rollback;
pub mod schema;
pub mod signing;
pub mod uuid;
pub mod validation;
