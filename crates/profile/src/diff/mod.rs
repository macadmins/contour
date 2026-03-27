//! Diff module - profile comparison
//!
//! This module provides profile comparison functionality.

pub mod profile_diff;

// Re-export profile diff
pub use profile_diff::{diff_profiles, print_diff, save_diff};
