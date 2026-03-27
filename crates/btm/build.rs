//! Build script for reproducible build timestamps.

use chrono::{DateTime, Utc};
use std::env;

fn main() {
    // Support SOURCE_DATE_EPOCH for reproducible builds
    let timestamp = if let Ok(epoch) = env::var("SOURCE_DATE_EPOCH") {
        if let Ok(secs) = epoch.parse::<i64>() {
            DateTime::from_timestamp(secs, 0).unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        }
    } else {
        Utc::now()
    };

    // Round to 10-minute intervals for cache-friendly builds
    let rounded_minute = (timestamp
        .format("%M")
        .to_string()
        .parse::<u32>()
        .unwrap_or(0)
        / 10)
        * 10;
    let build_timestamp = format!("{}{:02}", timestamp.format("%Y%m%d.%H"), rounded_minute);

    println!("cargo:rustc-env=BUILD_TIMESTAMP={build_timestamp}");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
