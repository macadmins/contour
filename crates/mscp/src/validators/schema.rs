// Schema validators - public API
#![allow(dead_code, reason = "module under development")]

use anyhow::{Context, Result};
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// Where the schema a validation run checks against came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaOrigin {
    /// `--schemas <dir>` or `[validation] schemas_path`: this file.
    Dir(PathBuf),
    /// The pinned schema, embedded through `mscp-schema`.
    Embedded {
        /// SHA-256 of the embedded bytes — the pin, so a reader can match it
        /// against the dataset's record.
        sha256: String,
    },
    /// No directory was given and this build embeds no schema: its
    /// `mscp-schema` dataset does not carry one.
    Absent,
}

impl std::fmt::Display for SchemaOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Dir(p) => write!(f, "{}", p.display()),
            Self::Embedded { sha256 } => write!(
                f,
                "Fleet GitOps schema embedded in this build (sha256 {})",
                &sha256[..12.min(sha256.len())]
            ),
            Self::Absent => f.write_str("none — this build embeds no Fleet GitOps schema"),
        }
    }
}

/// Schema validator for `FleetDM` YAML files
pub struct SchemaValidator {
    schema: Option<jsonschema::Validator>,
    /// The parsed root document, kept so one `$defs` entry can be compiled
    /// into a list validator for Fleet's separate-file shapes.
    root: Option<Value>,
}

impl std::fmt::Debug for SchemaValidator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchemaValidator")
            .field("schema", &self.schema.as_ref().map(|_| "compiled"))
            .field("root", &self.root.as_ref().map(|_| "parsed"))
            .finish()
    }
}

impl SchemaValidator {
    /// Find Fleet's GitOps schema in `schemas_dir`, or say why not.
    ///
    /// Fleet publishes it as `generated-schema.json` (fleetdm/fleet,
    /// tools/gitops-auto-complete/).
    ///
    /// A missing schema means the requested check never ran, which is a
    /// configuration error rather than a per-file finding, so `resolve`
    /// fails on it once, before any file is read.
    pub fn resolve_schema_path(schemas_dir: &Path) -> Result<PathBuf> {
        const SCHEMA_NAMES: &[&str] = &["generated-schema.json", "team.schema.json"];
        SCHEMA_NAMES
            .iter()
            .map(|n| schemas_dir.join(n))
            .find(|p| p.exists())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no Fleet GitOps schema in {}. Looked for {}.\n\
                     Fleet publishes one at tools/gitops-auto-complete/generated-schema.json \
                     in fleetdm/fleet — point --schemas at a directory holding it, or drop \
                     the flag to use the schema this build embeds.",
                    schemas_dir.display(),
                    SCHEMA_NAMES.join(" or ")
                )
            })
    }

    /// Pick the schema for one run, compile it once, and say where it came from.
    ///
    /// A directory wins, and a directory without a schema is an error. With
    /// none, the pinned schema this build embeds is used — so `mscp validate` checks
    /// against Fleet's definition by default, not only when someone knows to
    /// fetch it. A build that embeds none says so through `SchemaOrigin::Absent`
    /// and runs the structural checks; it does not pretend to have checked.
    pub fn resolve(schemas_dir: Option<&Path>) -> Result<(Self, SchemaOrigin)> {
        let (bytes, origin): (std::borrow::Cow<'static, [u8]>, SchemaOrigin) = match schemas_dir {
            Some(dir) => {
                let path = Self::resolve_schema_path(dir)?;
                let bytes = fs::read(&path)
                    .with_context(|| format!("Failed to read schema file {}", path.display()))?;
                (bytes.into(), SchemaOrigin::Dir(path))
            }
            None => match mscp_schema::embedded_fleet_gitops_schema() {
                Some(bytes) => (
                    bytes.into(),
                    SchemaOrigin::Embedded {
                        sha256: sha256_hex(bytes),
                    },
                ),
                None => {
                    return Ok((
                        Self {
                            schema: None,
                            root: None,
                        },
                        SchemaOrigin::Absent,
                    ));
                }
            },
        };
        let value: Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("Failed to parse schema JSON ({origin})"))?;
        let compiled = jsonschema::validator_for(&value)
            .map_err(|e| anyhow::anyhow!("Failed to compile schema ({origin}): {e}"))?;
        Ok((
            Self {
                schema: Some(compiled),
                root: Some(value),
            },
            origin,
        ))
    }

    /// Validate a flat YAML list against one `$defs` entry of Fleet's schema —
    /// `GitOpsPolicySpec` for `*.policies.yml`, `Query` for `*.reports.yml`,
    /// `LabelSpec` for `*.labels.yml`. These separate files have no root
    /// object, so the root validator cannot read them.
    ///
    /// `Ok(None)` when this build embeds no schema (nothing to check against).
    pub fn validate_list<P: AsRef<Path>>(&self, yaml_path: P, def: &str) -> Result<Option<ValidationResult>> {
        let Some(root) = &self.root else {
            return Ok(None);
        };
        let yaml_path = yaml_path.as_ref();
        let content = fs::read_to_string(yaml_path)
            .context(format!("Failed to read YAML file: {}", yaml_path.display()))?;
        let yaml_value: yaml_serde::Value =
            yaml_serde::from_str(&content).context("Failed to parse YAML")?;
        let json_value: Value =
            serde_json::to_value(&yaml_value).context("Failed to convert YAML to JSON")?;
        if root.pointer(&format!("/$defs/{def}")).is_none() {
            anyhow::bail!("Fleet's schema has no $defs/{def}");
        }
        let list_schema = serde_json::json!({
            "$defs": root["$defs"],
            "type": "array",
            "items": {"$ref": format!("#/$defs/{def}")},
        });
        let compiled = jsonschema::validator_for(&list_schema)
            .map_err(|e| anyhow::anyhow!("Failed to compile $defs/{def}: {e}"))?;
        Ok(Some(Self::validate_with_schema(&compiled, &json_value)))
    }

    /// Validate a YAML file against a JSON schema
    pub fn validate_fleet_yaml<P: AsRef<Path>>(&self, yaml_path: P) -> Result<ValidationResult> {
        let yaml_path = yaml_path.as_ref();

        // Read the YAML file
        let content = fs::read_to_string(yaml_path)
            .context(format!("Failed to read YAML file: {}", yaml_path.display()))?;

        // Parse YAML to JSON value
        let yaml_value: yaml_serde::Value =
            yaml_serde::from_str(&content).context("Failed to parse YAML")?;

        let json_value: Value =
            serde_json::to_value(&yaml_value).context("Failed to convert YAML to JSON")?;

        match self.schema {
            Some(ref schema) => Ok(Self::validate_with_schema(schema, &json_value)),
            None => self.basic_validation(&json_value),
        }
    }

    /// Validate against the compiled schema.
    fn validate_with_schema(schema: &jsonschema::Validator, value: &Value) -> ValidationResult {
        let errors: Vec<String> = schema
            .iter_errors(value)
            .map(|e| {
                let at = e.instance_path().to_string();
                format!("{e} at {}", if at.is_empty() { "the root" } else { &at })
            })
            .collect();
        ValidationResult {
            valid: errors.is_empty(),
            errors,
        }
    }

    /// Basic validation without schema
    fn basic_validation(&self, value: &Value) -> Result<ValidationResult> {
        let mut errors = Vec::new();

        // Check basic structure
        if !value.is_object() {
            errors.push("Root must be an object".to_string());
            return Ok(ValidationResult {
                valid: false,
                errors,
            });
        }

        let obj = value.as_object().unwrap();

        // Check for required fields (basic Fleet team structure).
        // Treat `controls: null` (a YAML key with no value) as absent — that's
        // how Fleet GitOps templates ship the empty placeholder. Only an
        // explicitly non-null, non-object `controls` is a structural error.
        if let Some(controls) = obj.get("controls") {
            if controls.is_null() {
                // Empty `controls:` key — same as absent. No further checks.
            } else if controls.is_object() {
                // Every Apple profile list, under any spelling
                // (contour_core::fleet_keys) — current `apple_settings.
                // configuration_profiles` and the deprecated aliases.
                for (key, list) in apple_profile_lists(controls) {
                    if let Some(items) = list.as_array() {
                        for (i, setting) in items.iter().enumerate() {
                            if !setting.is_object() {
                                errors.push(format!("{key}[{i}] must be an object"));
                            } else if setting.get("path").is_none()
                                && setting.get("paths").is_none()
                            {
                                errors.push(format!("{key}[{i}] needs a 'path' or 'paths' field"));
                            }
                        }
                    } else {
                        errors.push(format!("'{key}' must be an array"));
                    }
                }
            } else {
                errors.push("'controls' must be an object".to_string());
            }
        }

        Ok(ValidationResult {
            valid: errors.is_empty(),
            errors,
        })
    }

    /// Validate file paths referenced in YAML exist
    pub fn validate_file_paths<P: AsRef<Path>>(
        &self,
        yaml_path: P,
        _base_dir: P,
    ) -> Result<PathValidationResult> {
        let yaml_path = yaml_path.as_ref();

        let content = fs::read_to_string(yaml_path)?;
        let yaml_value: yaml_serde::Value = yaml_serde::from_str(&content)?;
        let json_value: Value = serde_json::to_value(&yaml_value)?;

        let mut missing_paths = Vec::new();
        let mut found_paths = Vec::new();

        // Resolve paths relative to the YAML file's own directory.
        // Team YAMLs at `fleets/{team}.yml` reference artifacts via `../platforms/...`;
        // those `..` segments must be resolved from the yaml file's parent, NOT
        // from the repo root, or `..` walks out of the repo entirely.
        let yaml_dir = yaml_path.parent().unwrap_or_else(|| Path::new("."));

        let mut check_path = |path_str: &str| {
            let path_clean = path_str.trim_start_matches("./");
            let full_path = yaml_dir.join(path_clean);

            if full_path.exists() {
                found_paths.push(path_str.to_string());
            } else {
                missing_paths.push(path_str.to_string());
            }
        };

        if let Some(controls) = json_value.get("controls") {
            // Paths from every Apple profile list, under any spelling.
            for (_, list) in apple_profile_lists(controls) {
                for setting in list.as_array().into_iter().flatten() {
                    if let Some(path_str) = setting.get("path").and_then(|p| p.as_str()) {
                        check_path(path_str);
                    }
                }
            }

            // Extract paths from scripts
            if let Some(scripts) = controls.get("scripts")
                && let Some(scripts_array) = scripts.as_array()
            {
                for script in scripts_array {
                    if let Some(path_str) = script.get("path").and_then(|p| p.as_str()) {
                        check_path(path_str);
                    }
                }
            }
        }

        Ok(PathValidationResult {
            valid: missing_paths.is_empty(),
            found_paths,
            missing_paths,
        })
    }
}

/// Validation result
#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// Path validation result
#[derive(Debug, Clone)]
pub struct PathValidationResult {
    pub valid: bool,
    pub found_paths: Vec<String>,
    pub missing_paths: Vec<String>,
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

/// `(settings.list, list)` for every Apple profile list under `controls`.
fn apple_profile_lists(controls: &Value) -> Vec<(String, &Value)> {
    use contour_core::fleet_keys::{LEGACY_SETTINGS_KEYS, LIST_KEYS, SETTINGS_KEYS};
    SETTINGS_KEYS
        .iter()
        .chain(LEGACY_SETTINGS_KEYS)
        .filter_map(|s| controls.get(*s).map(|v| (*s, v)))
        .flat_map(|(s, v)| {
            LIST_KEYS
                .iter()
                .filter_map(move |l| v.get(*l).map(|list| (format!("{s}.{l}"), list)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_directory_without_a_schema_is_an_error_not_a_fallback() {
        let empty = tempfile::tempdir().expect("tempdir");
        let err = SchemaValidator::resolve(Some(empty.path()))
            .expect_err("a --schemas dir holding no schema must not resolve");
        assert!(err.to_string().contains("no Fleet GitOps schema"), "{err}");
    }

    #[test]
    fn a_directory_schema_wins_over_the_embedded_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("generated-schema.json"),
            r#"{"type":"object","required":["name"]}"#,
        )
        .expect("write");
        let (v, origin) = SchemaValidator::resolve(Some(dir.path())).expect("resolves");
        assert_eq!(
            origin,
            SchemaOrigin::Dir(dir.path().join("generated-schema.json"))
        );
        let yaml = dir.path().join("t.yml");
        std::fs::write(&yaml, "controls: {}\n").expect("write");
        assert!(!v.validate_fleet_yaml(&yaml).expect("validates").valid);
    }

    #[test]
    fn without_a_directory_the_embedded_schema_is_used() {
        let (_, origin) = SchemaValidator::resolve(None).expect("resolves");
        match mscp_schema::embedded_fleet_gitops_schema() {
            Some(bytes) => assert_eq!(
                origin,
                SchemaOrigin::Embedded {
                    sha256: sha256_hex(bytes)
                }
            ),
            None => assert_eq!(origin, SchemaOrigin::Absent),
        }
    }
}
