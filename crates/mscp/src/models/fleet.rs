// Fleet models - part of public API for planned features
#![allow(dead_code, reason = "module under development")]

use serde::{Deserialize, Serialize};

/// Fleet global configuration structure (default.yml)
///
/// Based on Fleet `GitOps` spec for org-wide settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetGlobalConfig {
    /// Policies that run on all hosts ("All teams" for Premium)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<yaml_serde::Value>>,

    /// Reports that run on all hosts
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<yaml_serde::Value>>,

    /// Agent options — retained for reading existing repos; contour no longer
    /// emits it (the `fleetctl new` scaffold ships none). Always serialized as
    /// absent via `skip_serializing_if`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_options: Option<yaml_serde::Value>,

    /// Controls - only set here OR in no-team.yml, not both
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Controls>,

    /// Organization-wide settings
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_settings: Option<OrgSettings>,

    /// Labels - can be inline or path references
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<LabelPathRef>>,
}

/// Label path reference for default.yml.
///
/// Exactly one of `path` (single literal file) or `paths` (glob pattern
/// matching many files, e.g. `./lib/labels/mscp-*.labels.yml`) must be set.
/// Fleet disallows labels on entries that use `paths`, but label-path-refs
/// themselves carry no labels, so that constraint does not apply here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LabelPathRef {
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,
}

/// Organization settings for default.yml
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_settings: Option<ServerSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_info: Option<OrgInfo>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<EnrollSecret>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,
}

/// Server settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub server_url: String,
}

/// Organization info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrgInfo {
    pub org_name: String,
}

/// Enrollment secret
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollSecret {
    pub secret: String,
}

/// Feature flags
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Features {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_host_users: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_software_inventory: Option<bool>,
}

/// Fleet settings for fleet files
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<EnrollSecret>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub features: Option<Features>,
}

/// `FleetDM` fleet configuration structure (Fleet v4.82+)
///
/// Based on Fleet `GitOps` spec: `pkg/spec/gitops.go`
/// Top-level keys: `name`, `settings`, `org_settings`, `agent_options`, `controls`, `policies`, `reports`, `software`, `labels`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetConfig {
    /// Fleet name (top-level, NOT nested under `team:`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    // NOTE: Fleet GitOps does NOT have a `team:` block - name is at top level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controls: Option<Controls>,

    /// Required by Fleet `GitOps` - can be empty array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policies: Option<Vec<yaml_serde::Value>>,

    /// Required by Fleet `GitOps` - can be empty array
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reports: Option<Vec<yaml_serde::Value>>,

    /// Required by Fleet `GitOps` - path reference or inline config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_options: Option<yaml_serde::Value>,

    /// Fleet-level settings (Fleet v4.82+: `settings` key in YAML output)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings: Option<yaml_serde::Value>,

    /// Required for fleet files - software packages (can be empty)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub software: Option<Software>,
}

/// Software configuration for fleet files
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Software {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub packages: Vec<yaml_serde::Value>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub app_store_apps: Vec<yaml_serde::Value>,

    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub fleet_maintained_apps: Vec<yaml_serde::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Controls {
    /// Fleet's `apple_settings`: macOS, iOS and iPadOS profiles alike. Written
    /// under the current name; the deprecated `macos_settings` is read too.
    /// See `contour_core::fleet_keys`.
    #[serde(
        rename = "apple_settings",
        alias = "macos_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub macos_settings: Option<PlatformSettings>,

    /// Read, never written. Fleet has no `ios_settings` — its schema closes
    /// `controls` and takes iOS profiles in `apple_settings` — but contour once
    /// wrote one for iOS baselines, so files it made may still carry it.
    #[serde(default, skip_serializing)]
    pub ios_settings: Option<PlatformSettings>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub scripts: Option<Vec<Script>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformSettings {
    /// Fleet's `configuration_profiles`; the deprecated `custom_settings` is read too.
    #[serde(
        rename = "configuration_profiles",
        alias = "custom_settings",
        skip_serializing_if = "Option::is_none"
    )]
    pub custom_settings: Option<Vec<CustomSetting>>,
}

/// Configuration profile entry (`configuration_profiles` or `controls.*_settings.custom_settings`).
///
/// Exactly one of `path` or `paths` must be set. Fleet disallows labels on
/// entries that use `paths`, so `labels_*` fields must remain `None` whenever
/// `paths` is set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomSetting {
    /// Relative path to a single mobileconfig file
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    /// Glob pattern matching multiple mobileconfig files (e.g. `../profiles/*.mobileconfig`).
    /// Cannot be combined with any `labels_*` field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_all: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_include_any: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels_exclude_any: Option<Vec<String>>,
}

/// Script reference - Fleet `GitOps` only supports path (`BaseItem` struct).
/// NOTE: Fleet does NOT support label targeting for scripts (only for profiles),
/// so label conflicts with `paths` cannot arise here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Script {
    /// Relative path to a single script file
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub path: Option<String>,

    /// Glob pattern matching multiple script files (e.g. `../scripts/*.sh`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub paths: Option<String>,
}

/// Policy entry — either a `path:` reference, a `paths:` glob, or an inline value.
///
/// Fleet GitOps supports all three shapes; the generator picks between them
/// based on the baseline's `gitops_glob.policies` configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyEntry {
    /// Reference to a separate YAML file containing policies
    PathRef { path: String },
    /// Glob pattern matching multiple policy YAML files
    PathsRef { paths: String },
    /// Inline policy value (passthrough)
    Inline(yaml_serde::Value),
}

/// Characters forbidden in a literal `path:` field by Fleet GitOps
/// (any one of these makes the path a glob pattern, which must use `paths:`).
pub const PATH_GLOB_METACHARS: &[char] = &['*', '?', '[', '{'];

/// Validate that exactly one of `path` / `paths` is set on an entry,
/// and that literal `path:` values contain no glob metacharacters.
///
/// Used by the generator before serialization to fail fast on invalid output.
pub fn validate_path_xor_paths(
    kind: &str,
    path: Option<&str>,
    paths: Option<&str>,
) -> anyhow::Result<()> {
    match (path, paths) {
        (Some(_), Some(_)) => {
            anyhow::bail!("{kind} entry has both `path` and `paths` set — exactly one is allowed")
        }
        (None, None) => anyhow::bail!(
            "{kind} entry has neither `path` nor `paths` set — exactly one is required"
        ),
        (Some(p), None) if p.contains(PATH_GLOB_METACHARS) => anyhow::bail!(
            "{kind} `path` contains a glob metacharacter ({}) — use `paths` instead: {p}",
            PATH_GLOB_METACHARS
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(" ")
        ),
        _ => Ok(()),
    }
}

impl CustomSetting {
    /// Validate `path`/`paths` invariants plus the Fleet rule that `paths:`
    /// entries cannot carry labels.
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths(
            "configuration_profiles",
            self.path.as_deref(),
            self.paths.as_deref(),
        )?;
        if self.paths.is_some()
            && (self.labels_include_all.is_some()
                || self.labels_include_any.is_some()
                || self.labels_exclude_any.is_some())
        {
            anyhow::bail!(
                "configuration_profiles entry uses `paths:` but also sets labels_* — \
                 Fleet GitOps does not allow labels on glob entries"
            );
        }
        // Fleet takes at most ONE label field per entry. `--sop fleet-migrate`
        // has said so in prose since it was written; nothing checked it, and
        // `mscp process --interactive` prompts for all three in a row and
        // stores whatever is typed. Two of them reaching one entry produces a
        // GitOps file Fleet rejects, at apply time, far from here.
        let set: Vec<&str> = [
            ("labels_include_all", self.labels_include_all.is_some()),
            ("labels_include_any", self.labels_include_any.is_some()),
            ("labels_exclude_any", self.labels_exclude_any.is_some()),
        ]
        .into_iter()
        .filter(|(_, present)| *present)
        .map(|(name, _)| name)
        .collect();
        if set.len() > 1 {
            anyhow::bail!(
                "configuration_profiles entry for {} sets {} — Fleet allows only one \
                 label field per entry. Pick the one that expresses the targeting: \
                 labels_include_all narrows (every label must match), \
                 labels_include_any widens, labels_exclude_any subtracts.",
                self.path.as_deref().unwrap_or("<no path>"),
                set.join(" and ")
            );
        }
        Ok(())
    }
}

impl Script {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths("scripts", self.path.as_deref(), self.paths.as_deref())
    }
}

impl LabelPathRef {
    pub fn validate(&self) -> anyhow::Result<()> {
        validate_path_xor_paths("labels", self.path.as_deref(), self.paths.as_deref())
    }
}

/// Output structure that will be generated
#[derive(Debug, Clone)]
pub struct FleetGitOpsOutput {
    /// Base output directory
    pub output_dir: std::path::PathBuf,

    /// Fleet configurations to be written
    pub fleets: Vec<(String, FleetConfig)>, // (filename, config)

    /// Files to be copied (source, destination)
    pub files_to_copy: Vec<(std::path::PathBuf, std::path::PathBuf)>,
}

#[cfg(test)]
mod tests {

    /// Files contour made under every earlier spelling still read; what is
    /// written is the current one. Both spellings in one file fail to parse —
    /// Fleet rejects that file too.
    #[test]
    fn controls_read_every_spelling_and_write_the_current_one() {
        for text in [
            "apple_settings:\n  configuration_profiles:\n    - path: a.mobileconfig\n",
            "macos_settings:\n  custom_settings:\n    - path: a.mobileconfig\n",
            "apple_settings:\n  custom_settings:\n    - path: a.mobileconfig\n",
        ] {
            let c: Controls = yaml_serde::from_str(text).unwrap();
            let list = c
                .macos_settings
                .as_ref()
                .and_then(|m| m.custom_settings.as_ref())
                .unwrap();
            assert_eq!(list.len(), 1, "{text}");
            let out = yaml_serde::to_string(&c).unwrap();
            assert!(
                out.contains("apple_settings:") && out.contains("configuration_profiles:"),
                "{out}"
            );
            assert!(
                !out.contains("macos_settings") && !out.contains("custom_settings"),
                "{out}"
            );
        }
        let legacy: Controls =
            yaml_serde::from_str("ios_settings:\n  custom_settings:\n    - path: a.mobileconfig\n")
                .unwrap();
        assert!(
            legacy.ios_settings.is_some(),
            "contour's former iOS output still reads"
        );
        assert!(
            !yaml_serde::to_string(&legacy)
                .unwrap()
                .contains("ios_settings"),
            "and is never written"
        );
        assert!(
            yaml_serde::from_str::<Controls>("apple_settings: {}\nmacos_settings: {}\n").is_err(),
            "both spellings at once is the file Fleet rejects"
        );
    }

    use super::*;

    #[test]
    fn validate_path_xor_paths_rejects_both_set() {
        let err = validate_path_xor_paths("scripts", Some("a.sh"), Some("*.sh")).unwrap_err();
        assert!(err.to_string().contains("both"));
    }

    #[test]
    fn validate_path_xor_paths_rejects_neither_set() {
        let err = validate_path_xor_paths("scripts", None, None).unwrap_err();
        assert!(err.to_string().contains("neither"));
    }

    #[test]
    fn validate_path_xor_paths_rejects_glob_metachars_in_path() {
        for bad in ["a*.sh", "a?.sh", "a[1].sh", "a{x}.sh"] {
            let err = validate_path_xor_paths("scripts", Some(bad), None).unwrap_err();
            assert!(
                err.to_string().contains("glob metacharacter"),
                "expected rejection for {bad}"
            );
        }
    }

    #[test]
    fn validate_path_xor_paths_accepts_valid_literal() {
        validate_path_xor_paths("scripts", Some("foo/bar.sh"), None).unwrap();
    }

    #[test]
    fn validate_path_xor_paths_accepts_valid_glob() {
        validate_path_xor_paths("scripts", None, Some("foo/*.sh")).unwrap();
    }

    #[test]
    fn custom_setting_rejects_labels_with_paths() {
        let cs = CustomSetting {
            path: None,
            paths: Some("../profiles/*.mobileconfig".to_string()),
            labels_include_all: Some(vec!["mscp-cis_lvl1".to_string()]),
            labels_include_any: None,
            labels_exclude_any: None,
        };
        let err = cs.validate().unwrap_err();
        assert!(err.to_string().contains("does not allow labels"));
    }

    #[test]
    fn custom_setting_accepts_path_with_labels() {
        let cs = CustomSetting {
            path: Some("../profiles/a.mobileconfig".to_string()),
            paths: None,
            labels_include_all: Some(vec!["mscp-cis_lvl1".to_string()]),
            labels_include_any: None,
            labels_exclude_any: None,
        };
        cs.validate().unwrap();
    }

    #[test]
    fn custom_setting_accepts_paths_without_labels() {
        let cs = CustomSetting {
            path: None,
            paths: Some("../profiles/*.mobileconfig".to_string()),
            labels_include_all: None,
            labels_include_any: None,
            labels_exclude_any: None,
        };
        cs.validate().unwrap();
    }

    #[test]
    fn script_accepts_path_or_paths() {
        Script {
            path: Some("../scripts/a.sh".to_string()),
            paths: None,
        }
        .validate()
        .unwrap();
        Script {
            path: None,
            paths: Some("../scripts/*.sh".to_string()),
        }
        .validate()
        .unwrap();
    }
}

#[cfg(test)]
mod label_field_tests {
    use super::*;

    fn setting(all: Option<&[&str]>, any: Option<&[&str]>, excl: Option<&[&str]>) -> CustomSetting {
        let v = |o: Option<&[&str]>| o.map(|s| s.iter().map(|x| x.to_string()).collect());
        CustomSetting {
            path: Some("../profiles/cis_lvl1/com.apple.dock.mobileconfig".into()),
            paths: None,
            labels_include_all: v(all),
            labels_include_any: v(any),
            labels_exclude_any: v(excl),
        }
    }

    /// Fleet takes at most one label field per entry.
    ///
    /// `--sop fleet-migrate` has said so in prose since it was written and
    /// nothing checked it, while `mscp process --interactive` prompts for all
    /// three in a row and stores whatever is typed. Two of them on one entry
    /// produces a GitOps file Fleet rejects at apply time — far from here,
    /// and long after the generate that caused it.
    #[test]
    fn only_one_label_field_is_allowed_per_entry() {
        setting(Some(&["a"]), None, None)
            .validate()
            .expect("one is fine");
        setting(None, Some(&["a"]), None)
            .validate()
            .expect("one is fine");
        setting(None, None, Some(&["a"]))
            .validate()
            .expect("one is fine");
        setting(None, None, None).validate().expect("none is fine");

        for bad in [
            setting(Some(&["a"]), Some(&["b"]), None),
            setting(Some(&["a"]), None, Some(&["b"])),
            setting(None, Some(&["a"]), Some(&["b"])),
            setting(Some(&["a"]), Some(&["b"]), Some(&["c"])),
        ] {
            let err = bad
                .validate()
                .expect_err("two label fields must be refused");
            let msg = err.to_string();
            assert!(msg.contains("only one label field"), "{msg}");
            // The message has to say which ones, or the operator is left
            // diffing a generated file against a rule they cannot see.
            assert!(msg.contains("labels_"), "{msg}");
        }
    }

    /// Many labels in one field is the normal case, not a violation.
    #[test]
    fn several_labels_in_one_field_are_fine() {
        setting(Some(&["mscp-cis_lvl1", "pilot-ring-1"]), None, None)
            .validate()
            .expect("include_all with two labels is how narrowing works");
    }
}
