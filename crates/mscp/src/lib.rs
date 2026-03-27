//! mscp - Transform mSCP baselines into MDM-ready configurations.
//!
//! This library provides functionality for:
//! - Processing macOS Security Compliance Project (mSCP) baselines
//! - Generating Fleet GitOps, Jamf Pro, and Munki compatible output
//! - Managing profile constraints and ODV overrides

pub mod api;
pub mod cli;
pub mod config;
pub mod deduplicator;
pub mod extractors;
pub mod filters;
pub mod generators;
pub mod managers;
pub mod models;
pub mod output;
pub mod registry;
pub mod transformers;
pub mod updaters;
pub mod validators;
pub mod versioning;
