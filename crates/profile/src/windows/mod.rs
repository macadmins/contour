//! Windows CSP profile generation.
//!
//! `syncml` turns a setting and a value into the SyncML an MDM delivers.
//! Everything it needs is already embedded: `windows_capabilities` in
//! `mdm-schema` for the settings, `windows_admx_policies` in `windows-schema`
//! for ADMX element bodies.

pub mod syncml;
