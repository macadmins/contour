//! # Contour Core
//!
//! Shared library for Contour CLI tools: profile, mscp, and santa.
//!
//! This crate provides common functionality:
//! - Output formatting (Human/JSON modes)
//! - Validation result types with warnings
//! - Shell completion generation
//! - Logging initialization
//! - Common error types
//! - Trainer mode for interactive learning

pub mod app_discovery;
pub mod codesign;
pub mod completions;
pub mod config;
pub mod errors;
pub mod fleet_layout;
pub mod fragment;
pub mod help_agents;
pub mod logging;
pub mod output;
pub mod scan;
pub mod string_utils;
pub mod trainer;
pub mod validation;
pub mod yaml_edit;

pub use app_discovery::{extract_team_id, find_apps_recursive};
pub use codesign::{find_main_executable, get_app_name, get_bundle_id, get_code_requirement};
pub use completions::generate_completions;
pub use config::{ConfigSettings, ContourConfig, resolve_name, resolve_org};
pub use errors::{ContourError, ContourResult};
pub use fleet_layout::{FleetLayout, FleetLayoutVersion};
pub use logging::init_logging;
pub use output::{
    CommandResult, OutputMode, format_elapsed, print_error, print_info, print_json, print_kv,
    print_success, print_warning, resolve_output_dir, sanitize_filename,
};
pub use scan::{AppInfo, discover_apps, multi_select, select_apps};
pub use string_utils::levenshtein_distance;
pub use trainer::workflows::{MscpWorkflow, PppcWorkflow, ProfileWorkflow, SantaWorkflow};
pub use trainer::{TrainerContext, TrainerWorkflow};
pub use validation::{ValidationIssue, ValidationResult, ValidationSeverity};
