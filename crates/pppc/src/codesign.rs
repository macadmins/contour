//! Code signing utilities for extracting code requirements.
//!
//! This module re-exports the canonical implementations from `contour_core::codesign`.

pub use contour_core::codesign::{
    find_main_executable, get_app_name, get_bundle_id, get_code_requirement,
};
