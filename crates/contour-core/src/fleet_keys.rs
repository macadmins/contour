//! The Fleet GitOps keys a profile list lives under, in every spelling.
//!
//! Fleet v4.83.0 renamed `controls.macos_settings` to `apple_settings` and its
//! `custom_settings` list to `configuration_profiles` (fleetdm/fleet #40959),
//! keeping the old names as deprecated aliases. A file may use either, but not
//! both in one scope: Fleet rejects that with "Conflicting field names: cannot
//! specify both `macos_settings` (deprecated) and `apple_settings`"
//! (server/platform/endpointer/json_key_rewriter.go).
//!
//! So contour writes the current names in a file it creates, and in a file it
//! edits uses whatever that file already says. Readers look under every
//! spelling, and under `ios_settings` — not a Fleet key at all (Fleet's schema
//! has none, and takes iOS and iPadOS profiles in `apple_settings`), but one
//! contour used to write, so its files still carry it.

use yaml_serde::Value;

/// The settings key contour writes: `controls.apple_settings`.
pub const APPLE_SETTINGS: &str = "apple_settings";
/// The profile-list key contour writes: `…configuration_profiles`.
pub const CONFIGURATION_PROFILES: &str = "configuration_profiles";

/// Settings keys a profile list may sit under, current first.
pub const SETTINGS_KEYS: &[&str] = &["apple_settings", "macos_settings"];
/// Settings keys only readers accept: contour's former, invalid iOS output.
pub const LEGACY_SETTINGS_KEYS: &[&str] = &["ios_settings"];
/// List keys inside the settings block, current first.
pub const LIST_KEYS: &[&str] = &["configuration_profiles", "custom_settings"];

fn is_settings(k: &Value) -> bool {
    k.as_str()
        .is_some_and(|k| SETTINGS_KEYS.contains(&k) || LEGACY_SETTINGS_KEYS.contains(&k))
}

fn is_list(k: &Value) -> bool {
    k.as_str().is_some_and(|k| LIST_KEYS.contains(&k))
}

/// Every Apple profile list in a fleet file, under any spelling.
pub fn apple_profile_lists(doc: &Value) -> Vec<&Vec<Value>> {
    let Some(controls) = doc.get("controls").and_then(Value::as_mapping) else {
        return Vec::new();
    };
    controls
        .iter()
        .filter(|(k, _)| is_settings(k))
        .filter_map(|(_, s)| s.as_mapping())
        .flat_map(|s| {
            s.iter()
                .filter(|(k, _)| is_list(k))
                .filter_map(|(_, l)| l.as_sequence())
        })
        .collect()
}

/// [`apple_profile_lists`], for changing the entries in place.
pub fn apple_profile_lists_mut(doc: &mut Value) -> Vec<&mut Vec<Value>> {
    let Some(controls) = doc.get_mut("controls").and_then(Value::as_mapping_mut) else {
        return Vec::new();
    };
    controls
        .iter_mut()
        .filter(|(k, _)| is_settings(k))
        .filter_map(|(_, s)| s.as_mapping_mut())
        .flat_map(|s| {
            s.iter_mut()
                .filter(|(k, _)| is_list(k))
                .filter_map(|(_, l)| l.as_sequence_mut())
        })
        .collect()
}

/// The spelling an existing file uses, at each level, for a writer to keep.
///
/// Returns `(settings_key, list_key)`: what the file already has, else the
/// current names. A file contour edits keeps its spelling, so contour never
/// adds `apple_settings` beside `macos_settings` — the file Fleet rejects.
pub fn spelling_in(lines: &[&str]) -> (&'static str, &'static str) {
    let settings = present(lines, "controls", SETTINGS_KEYS).unwrap_or(APPLE_SETTINGS);
    let list = present(lines, settings, LIST_KEYS).unwrap_or(CONFIGURATION_PROFILES);
    (settings, list)
}

/// The first of `keys` that appears as a direct child of `parent`.
fn present(lines: &[&str], parent: &str, keys: &[&'static str]) -> Option<&'static str> {
    let (start, indent) = lines.iter().enumerate().find_map(|(i, l)| {
        let t = l.trim_start();
        (t == format!("{parent}:") || t.starts_with(&format!("{parent}: ")))
            .then(|| (i, l.len() - t.len()))
    })?;
    let mut child_indent = None;
    for l in &lines[start + 1..] {
        let t = l.trim_start();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        let ind = l.len() - t.len();
        if ind <= indent {
            break;
        }
        let ci = *child_indent.get_or_insert(ind);
        if ind != ci {
            continue;
        }
        if let Some(k) = keys
            .iter()
            .find(|k| t == format!("{k}:") || t.starts_with(&format!("{k}: ")))
        {
            return Some(k);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(s: &str) -> Value {
        yaml_serde::from_str(s).unwrap()
    }

    #[test]
    fn every_spelling_is_read() {
        for (settings, list) in [
            ("apple_settings", "configuration_profiles"),
            ("macos_settings", "custom_settings"),
            ("apple_settings", "custom_settings"),
            ("macos_settings", "configuration_profiles"),
            ("ios_settings", "custom_settings"),
        ] {
            let d = doc(&format!(
                "controls:\n  {settings}:\n    {list}:\n      - path: a.mobileconfig\n"
            ));
            let lists = apple_profile_lists(&d);
            assert_eq!(lists.len(), 1, "{settings}.{list}");
            assert_eq!(lists[0][0]["path"], "a.mobileconfig");
        }
    }

    #[test]
    fn lists_can_be_changed_in_place() {
        let mut d = doc(
            "controls:\n  macos_settings:\n    custom_settings:\n      - path: a\n      - path: b\n",
        );
        for l in apple_profile_lists_mut(&mut d) {
            l.retain(|e| e["path"] != "a");
        }
        assert_eq!(apple_profile_lists(&d)[0].len(), 1);
    }

    #[test]
    fn a_writer_keeps_the_files_spelling_and_defaults_to_the_current_one() {
        let old = "name: x\ncontrols:\n  macos_settings:\n    custom_settings:\n      - path: a\n";
        assert_eq!(
            spelling_in(&old.lines().collect::<Vec<_>>()),
            ("macos_settings", "custom_settings")
        );
        let mixed = "controls:\n  apple_settings:\n    custom_settings: []\n";
        assert_eq!(
            spelling_in(&mixed.lines().collect::<Vec<_>>()),
            ("apple_settings", "custom_settings")
        );
        let bare = "name: x\ncontrols:\n  scripts: []\n";
        assert_eq!(
            spelling_in(&bare.lines().collect::<Vec<_>>()),
            ("apple_settings", "configuration_profiles")
        );
        assert_eq!(
            spelling_in(&[]),
            ("apple_settings", "configuration_profiles")
        );
    }

    #[test]
    fn a_key_nested_deeper_is_not_mistaken_for_the_settings_key() {
        let s = "controls:\n  scripts:\n    macos_settings: {}\n";
        assert_eq!(
            spelling_in(&s.lines().collect::<Vec<_>>()).0,
            "apple_settings"
        );
    }
}
