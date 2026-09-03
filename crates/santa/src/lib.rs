/// North Pole Security's Apple Developer Team ID — the identity that
/// signs every `com.northpolesec.santa*` binary.
///
/// Single source of truth on purpose. TCC code requirements,
/// system-extension allowlists, and managed-login-item rules must all
/// name the same team; when they disagree the profile still installs
/// cleanly and Santa silently fails to get its system extension
/// approved or Full Disk Access granted.
///
/// Not to be confused with `EQHXZ8M8AV`, which is Google's Team ID —
/// it signs Chrome, and signed the pre-fork Google Santa.
pub const NORTHPOLE_TEAM_ID: &str = "ZMCG7MLDV9";

pub mod app_settings;
pub mod bundle;
pub mod cel;
pub mod cli;
pub mod config;
pub mod coverage;
pub mod diff;
pub mod discovery;
pub mod faa;
pub mod fleet;
pub mod generator;
pub mod merge;
pub mod models;
pub mod output;
pub mod parser;
pub mod pipeline;
pub mod transform;
pub mod validator;
