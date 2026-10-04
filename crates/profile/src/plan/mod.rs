//! Profile change planning.
//!
//! Compare a *baseline* configuration profile (what's already deployed
//! or in `git`) against a *proposed* one (the working tree / a vendor
//! pack / a generated artifact) and classify every payload-level delta
//! into a [`ChangeTier`] that maps directly to MDM behavior on the
//! device.
//!
//! See `crates/contour-core/skills/contour/references/sop-profile-changes.md`
//! for the operational risk model and the tier taxonomy.
//!
//! Module layout:
//! - [`change`] — `ChangeTier` enum and `PayloadChange` struct.
//! - [`classifier`] — pair payloads across baseline/proposed and emit
//!   NOOP / IN_PLACE_UPDATE / ADD / REMOVE / REPLACE records.
//! - [`refs`] — REF_BROKEN: dangling cross-references in the proposed profile.
//! - [`types`] — TYPE_INVALID: values that fail their payload schema.
//! - [`scope`] — SCOPE_BROADENED: TCC ACL / PayloadScope widening vs baseline.
//! - [`deprecated`] — DEPRECATED: newly introduced deprecated payload types.
//!
//! `cli::plan` runs each detector and merges the results into one `Plan`.

pub mod change;
pub mod classifier;
pub mod deprecated;
pub mod refs;
pub mod scope;
pub mod types;

pub use change::{ChangeTier, PayloadChange, Plan, PlanSummary};
pub use classifier::plan_profiles;
pub use deprecated::check_new_deprecations;
pub use refs::check_proposed_refs;
pub use scope::check_scope_broadening;
pub use types::check_type_validity;
