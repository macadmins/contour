//! Profile rollback — cherry-pick UUID restore.
//!
//! Inverse of `profile plan`. When a PR (or in-flight branch) has
//! regenerated `PayloadUUID` values, rollback walks the proposed
//! profiles, copies the original UUIDs back from a baseline, and —
//! crucially — rewrites every cross-reference (`PayloadCertificateUUID`,
//! `PayloadCertificateAnchorUUID`, EAP/IKEv2, FileVault escrow) in the
//! proposed profile that pointed at the new UUID so it points at the
//! restored one. This is exactly what the Fleet GitOps PR forgot.
//!
//! Fail-closed semantics: a rollback that would produce a broken
//! reference graph aborts before writing any file. See
//! `sop-profile-changes.md::PROCEDURE rollback_profile_changes` for
//! the doctrine.

pub mod restorer;

pub use restorer::{RollbackFilter, RollbackOptions, RollbackResult, restore_uuids};
