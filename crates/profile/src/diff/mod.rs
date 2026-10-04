//! Diff module - profile comparison
//!
//! This module provides profile comparison functionality.

pub mod profile_diff;
pub mod structural;

// Re-export profile diff
pub use profile_diff::{diff_markdown, diff_profiles, print_diff, save_diff};
pub use structural::structural_diff;
