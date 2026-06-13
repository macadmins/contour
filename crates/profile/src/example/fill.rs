//! Type-specific generator fill (app.settings): replace the example's list
//! sections with real entries from a scan and/or permission policy.

use anyhow::Result;
use santa::app_settings::{
    AppSettings, BinaryPolicy, from_permission_policy, map, partition_binaries,
};
use santa::cli::ScanRuleType;
use santa::cli::scan::read_scan_csvs;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// Replace `Payload.Allowed` (and `Payload.Privacy` when a policy is given) of an
/// app.settings example with real entries built from the scan/policy. Other
/// payload keys from the example are preserved.
pub fn fill_app_settings(
    base: &mut Value,
    scan: &[PathBuf],
    permissions: Option<&Path>,
    deny: bool,
) -> Result<()> {
    let policy = if deny {
        BinaryPolicy::Deny
    } else {
        BinaryPolicy::Allow
    };
    let apps = read_scan_csvs(scan)?;
    let raw: Vec<_> = apps
        .iter()
        .filter_map(|a| map::from_scanned_app(a, ScanRuleType::Auto, policy))
        .collect();
    let (binaries, _violations) = partition_binaries(raw);
    let privacy = match permissions {
        Some(p) => from_permission_policy(p)?,
        None => Vec::new(),
    };
    let settings = AppSettings {
        binaries,
        apps: Vec::new(),
        privacy,
        always_allow_managed: false,
    };
    let built = settings.to_declaration("placeholder", "x");

    if let (Some(dst), Some(src)) = (base.get_mut("Payload"), built.get("Payload")) {
        if let (Some(dst_obj), Some(src_obj)) = (dst.as_object_mut(), src.as_object()) {
            for key in ["Allowed", "Privacy"] {
                if let Some(val) = src_obj.get(key) {
                    dst_obj.insert(key.to_string(), val.clone());
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    #[test]
    fn fill_replaces_app_settings_lists_from_scan_csv() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            f,
            "name,path,version,team_id,signing_id,sha256,bundle_id,device_name"
        )
        .unwrap();
        writeln!(
            f,
            "Ex,/Applications/Ex.app,1,ABCDE12345,ABCDE12345:com.ex,,com.ex,m1"
        )
        .unwrap();
        let mut base = json!({
            "Type": "com.apple.configuration.app.settings",
            "Identifier": "com.acme.app.settings.0",
            "Payload": { "Allowed": { "AllowedBinaries": [ {"TeamID": "OLD0000000"} ] } }
        });
        fill_app_settings(&mut base, &[f.path().to_path_buf()], None, false).unwrap();
        assert_eq!(
            base["Payload"]["Allowed"]["AllowedBinaries"][0]["TeamID"],
            "ABCDE12345"
        );
    }
}
