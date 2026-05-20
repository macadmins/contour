//! mSCP 2.0 raw rule deserializer + adapter to the normalized [`MscpRule`].
//!
//! The 2.0 schema (`schema/mscp_rule.json` v2.0.0) restructures rules to
//! support multi-OS targeting under a single rule file. This module mirrors
//! that schema as Rust types and adapts each rule into the 1.x-shaped
//! [`MscpRule`] that all downstream extractors and aggregators consume.
//!
//! The adapter is parameterized on `(os, os_version)` so that a single
//! 2.0 rule can yield distinct normalized views per platform target — e.g.
//! "this rule under iOS 18 has these benchmarks and that enforcement check;
//! the same rule under macOS 15 has different ones."

use crate::models::mscp::Platform;
use crate::models::rule::MscpRule;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeMap};
use std::collections::{BTreeMap, HashMap};
use yaml_serde::Value;

/// 2.0 raw rule, deserialized from `config/default/rules/<cat>/<id>.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MscpRuleV2x {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub discussion: String,
    #[serde(default)]
    pub references: Value,
    #[serde(default)]
    pub platforms: Platforms,
    #[serde(default)]
    pub mobileconfig_info: Vec<MobileconfigPayloadV2x>,
    #[serde(default)]
    pub ddm_info: Option<Value>,
    #[serde(default)]
    pub odv: Option<Value>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// `platforms:` block — keyed by OS family. Each OS may carry per-version
/// benchmark/supervised data plus an OS-level [`EnforcementInfo`] shared
/// across all versions.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Platforms {
    #[serde(rename = "macOS", default)]
    pub macos: Option<PlatformOs>,
    #[serde(rename = "iOS", default)]
    pub ios: Option<PlatformOs>,
    #[serde(rename = "visionOS", default)]
    pub visionos: Option<PlatformOs>,
}

/// `platforms.<OS>:` — version keys (`"26.0"`, `"15.0"`) sit alongside
/// special keys (`enforcement_info`, `introduced`). The custom Deserialize
/// splits them.
#[derive(Debug, Clone, Default)]
pub struct PlatformOs {
    pub enforcement_info: Option<EnforcementInfo>,
    pub introduced: Option<String>,
    pub versions: BTreeMap<String, OsVersion>,
}

impl<'de> Deserialize<'de> for PlatformOs {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let map: BTreeMap<String, Value> = BTreeMap::deserialize(d)?;
        let mut out = PlatformOs::default();
        for (k, v) in map {
            match k.as_str() {
                "enforcement_info" => {
                    out.enforcement_info =
                        Some(yaml_serde::from_value(v).map_err(serde::de::Error::custom)?);
                }
                "introduced" => {
                    out.introduced = v.as_str().map(String::from);
                }
                _ => {
                    let osv: OsVersion =
                        yaml_serde::from_value(v).map_err(serde::de::Error::custom)?;
                    out.versions.insert(k, osv);
                }
            }
        }
        Ok(out)
    }
}

impl Serialize for PlatformOs {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        let len = self.versions.len()
            + usize::from(self.enforcement_info.is_some())
            + usize::from(self.introduced.is_some());
        let mut map = s.serialize_map(Some(len))?;
        if let Some(ref ei) = self.enforcement_info {
            map.serialize_entry("enforcement_info", ei)?;
        }
        if let Some(ref intro) = self.introduced {
            map.serialize_entry("introduced", intro)?;
        }
        for (k, v) in &self.versions {
            map.serialize_entry(k, v)?;
        }
        map.end()
    }
}

/// Per-version data — what benchmarks this rule belongs to on this OS
/// version, plus optional iOS/visionOS-only flags.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsVersion {
    #[serde(default)]
    pub benchmarks: Vec<Benchmark>,
    #[serde(default)]
    pub supervised: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Benchmark {
    pub name: String,
    #[serde(default)]
    pub severity: Option<String>,
}

/// `enforcement_info:` — the check/fix logic. In 2.0 this lives under
/// `platforms.<OS>.enforcement_info` (a single block per OS, not per
/// version), replacing 1.x's top-level `check`/`fix`/`result`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementInfo {
    #[serde(default)]
    pub check: Option<EnforcementCheck>,
    #[serde(default)]
    pub fix: Option<EnforcementFix>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementCheck {
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default)]
    pub result: Option<Value>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EnforcementFix {
    #[serde(default)]
    pub shell: Option<String>,
    #[serde(default)]
    pub additional_info: Option<String>,
}

/// 2.0 mobileconfig payload — array shape replaces 1.x's
/// `{PayloadType: {key: value}}` dict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MobileconfigPayloadV2x {
    #[serde(rename = "PayloadType")]
    pub payload_type: String,
    #[serde(rename = "PayloadContent", default)]
    pub payload_content: Vec<HashMap<String, Value>>,
}

impl MscpRuleV2x {
    /// Adapt this 2.0 rule into the normalized [`MscpRule`] for a chosen
    /// `(os, os_version)`. Downstream code (recipe aggregator, ODV, fleet
    /// conflicts, etc.) consumes [`MscpRule`] regardless of source layout.
    ///
    /// If the rule doesn't target the requested `(os, os_version)`, the
    /// returned `MscpRule` will have empty `tags` (i.e. won't match any
    /// baseline). Callers can filter by `tags.contains(baseline)`.
    pub fn into_normalized(self, os: Platform, os_version: &str) -> MscpRule {
        let platform_os = match os {
            Platform::MacOS => self.platforms.macos.as_ref(),
            Platform::Ios => self.platforms.ios.as_ref(),
            Platform::VisionOS => self.platforms.visionos.as_ref(),
        };

        // Benchmarks for this (os, version): the set of baseline names
        // this rule belongs to. If the requested version isn't listed,
        // tags are empty and no baseline filter will match.
        let (benchmarks, severity) = platform_os
            .and_then(|p| p.versions.get(os_version))
            .map(|v| {
                let names: Vec<String> = v.benchmarks.iter().map(|b| b.name.clone()).collect();
                let sev = v.benchmarks.iter().find_map(|b| b.severity.clone());
                (names, sev)
            })
            .unwrap_or_default();

        // Free-form tags from the rule's top-level `tags` get unioned in
        // alongside benchmark names, mirroring the 1.x behaviour where
        // both lived in `tags`.
        let mut tags = benchmarks;
        for t in &self.tags {
            if !tags.contains(t) {
                tags.push(t.clone());
            }
        }

        // Enforcement: 2.0 nests under `platforms.<os>.enforcement_info`;
        // 1.x had top-level `check` / `fix` / `result`.
        let enforcement = platform_os.and_then(|p| p.enforcement_info.as_ref());
        let check = enforcement
            .and_then(|e| e.check.as_ref())
            .and_then(|c| c.shell.clone());
        let result = enforcement
            .and_then(|e| e.check.as_ref())
            .and_then(|c| c.result.clone());
        let fix = enforcement.and_then(|e| e.fix.as_ref()).and_then(|f| {
            // Prefer shell when present; else fall back to the human
            // explanation so `has_executable_fix()` correctly returns false.
            f.shell.clone().or_else(|| f.additional_info.clone())
        });

        // mobileconfig_info: collapse 2.0 array shape to 1.x dict shape.
        let mobileconfig = !self.mobileconfig_info.is_empty();
        let mobileconfig_info = if mobileconfig {
            Some(collapse_mobileconfig(&self.mobileconfig_info))
        } else {
            None
        };

        // references: hoist OS-keyed maps to flat 1.x lookups.
        let references = flatten_references_for(&self.references, os, os_version);

        // macos field: list of versions targeted on macOS (regardless of
        // the requested `os` — keeps the 1.x semantic of "supported macOS").
        let macos: Vec<String> = self
            .platforms
            .macos
            .as_ref()
            .map(|p| p.versions.keys().cloned().collect())
            .unwrap_or_default();

        MscpRule {
            id: self.id,
            title: self.title,
            discussion: self.discussion,
            check,
            result,
            fix,
            references,
            macos,
            tags,
            severity,
            mobileconfig,
            mobileconfig_info,
            ddm_info: self.ddm_info,
            odv: self.odv,
        }
    }
}

/// Collapse 2.0 array-shaped `mobileconfig_info` into 1.x dict shape:
/// `[{PayloadType: T, PayloadContent: [{k1:v1},{k2:v2}]}]` becomes
/// `{T: {k1:v1, k2:v2}}`. Multiple entries with the same `PayloadType`
/// merge their content; later wins on key collision (matches Apple's
/// payload-merge semantics).
fn collapse_mobileconfig(payloads: &[MobileconfigPayloadV2x]) -> Value {
    let mut out: BTreeMap<String, BTreeMap<String, Value>> = BTreeMap::new();
    for p in payloads {
        let entry = out.entry(p.payload_type.clone()).or_default();
        for content in &p.payload_content {
            for (k, v) in content {
                entry.insert(k.clone(), v.clone());
            }
        }
    }
    let mut top = yaml_serde::Mapping::new();
    for (ptype, fields) in out {
        let mut field_map = yaml_serde::Mapping::new();
        for (k, v) in fields {
            field_map.insert(Value::String(k), v);
        }
        top.insert(Value::String(ptype), Value::Mapping(field_map));
    }
    Value::Mapping(top)
}

/// Hoist 2.0's `references.{vendor}.{name}.{os_<major>}: [...]` to
/// 1.x's flat `references.{name}: [...]`. Falls back to the array as-is
/// when the value isn't OS-keyed (e.g. NIST 800-53r5 controls are not
/// per-OS). Keeps unknown shapes verbatim under their leaf key so callers
/// don't lose data.
fn flatten_references_for(refs: &Value, os: Platform, os_version: &str) -> HashMap<String, Value> {
    let mut out: HashMap<String, Value> = HashMap::new();
    let Some(top) = refs.as_mapping() else {
        return out;
    };
    let os_key = format!("{}_{}", os_short_key(os), major_version(os_version));

    for (vendor_key, vendor_val) in top {
        let Value::Mapping(vendor_map) = vendor_val else {
            continue;
        };
        for (leaf_key, leaf_val) in vendor_map {
            let Some(leaf_name) = leaf_key.as_str() else {
                continue;
            };
            let normalized = match leaf_val {
                // OS-keyed map: pick this OS's array.
                Value::Mapping(os_map) => os_map
                    .get(Value::String(os_key.clone()))
                    .cloned()
                    .unwrap_or_else(|| Value::Sequence(vec![])),
                // Flat array (e.g. 800-53r5): keep as-is.
                other => other.clone(),
            };
            // Last vendor wins on leaf-key collision (rare; mostly distinct).
            out.insert(leaf_name.to_string(), normalized);
        }
        // Also retain a copy under the vendor key for callers that look
        // up by vendor (e.g. `references.nist`).
        if let Some(s) = vendor_key.as_str() {
            out.insert(s.to_string(), vendor_val.clone());
        }
    }
    out
}

fn os_short_key(os: Platform) -> &'static str {
    match os {
        Platform::MacOS => "macos",
        Platform::Ios => "ios",
        Platform::VisionOS => "visionos",
    }
}

/// Strip a SemVer-ish version like `"26.0"` to its major component `"26"`.
/// 2.0's reference OS keys use `macos_26`, `ios_18`, etc. — never minor.
fn major_version(v: &str) -> &str {
    v.split('.').next().unwrap_or(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_DDM_RULE: &str = r#"
id: system_settings_download_software_update_enforce
title: Enforce Software Update Downloads
discussion: |
  Software Update _MUST_ be configured to enforce automatic downloads.
references:
  nist:
    cce:
      macos_26:
        - CCE-95403-2
    800-53r5:
      - SI-2
  cis:
    controls_v8:
      - 7.3
platforms:
  macOS:
    '26.0': {}
    '15.0':
      benchmarks:
        - name: cis_lvl1
        - name: disa_stig
          severity: medium
    enforcement_info:
      check:
        shell: "/usr/bin/plutil -convert json /var/db/x.plist -o -"
        result:
          integer: 1
      fix:
        additional_info: This is implemented by Declarative Device Management (DDM).
tags:
  - cisv8
  - ddm
ddm_info:
  declarationtype: com.apple.configuration.softwareupdate.settings
  ddm_key: AutomaticActions
  ddm_value:
    Download: AlwaysOn
"#;

    const SAMPLE_MOBILECONFIG_RULE: &str = r"
id: system_settings_screensaver_password_enforce
title: Enforce Password On Screensaver
discussion: A screensaver _MUST_ require a password.
references:
  nist:
    cce:
      macos_26:
        - CCE-99999-9
    800-53r5:
      - AC-11
platforms:
  macOS:
    '15.0':
      benchmarks:
        - name: cis_lvl1
        - name: cis_lvl2
mobileconfig_info:
  - PayloadType: com.apple.screensaver
    PayloadContent:
      - askForPassword: true
        askForPasswordDelay: 5
";

    #[test]
    fn parses_ddm_rule_with_enforcement_info() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_DDM_RULE).unwrap();
        assert_eq!(rule.id, "system_settings_download_software_update_enforce");
        let macos = rule.platforms.macos.as_ref().unwrap();
        assert!(macos.versions.contains_key("26.0"));
        assert!(macos.versions.contains_key("15.0"));
        assert!(macos.enforcement_info.is_some());
        assert_eq!(rule.tags, vec!["cisv8", "ddm"]);
    }

    #[test]
    fn normalizes_to_macos_26_picks_empty_benchmarks_keeps_enforcement() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_DDM_RULE).unwrap();
        let n = rule.into_normalized(Platform::MacOS, "26.0");
        // 26.0 has empty `{}` so no benchmarks, but free-form tags hoist.
        assert!(n.tags.contains(&"cisv8".to_string()));
        assert!(n.tags.contains(&"ddm".to_string()));
        // enforcement_info is OS-level so check/fix populate.
        assert!(
            n.check
                .as_ref()
                .is_some_and(|s| s.contains("/usr/bin/plutil"))
        );
        assert!(n.fix.as_ref().is_some_and(|s| s.contains("DDM")));
        assert!(n.ddm_info.is_some());
    }

    #[test]
    fn normalizes_to_macos_15_picks_benchmarks_and_severity() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_DDM_RULE).unwrap();
        let n = rule.into_normalized(Platform::MacOS, "15.0");
        assert!(n.tags.contains(&"cis_lvl1".to_string()));
        assert!(n.tags.contains(&"disa_stig".to_string()));
        assert!(n.tags.contains(&"cisv8".to_string())); // free-form
        assert_eq!(n.severity.as_deref(), Some("medium"));
    }

    #[test]
    fn normalizes_to_unrequested_os_yields_empty_baseline_tags() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_DDM_RULE).unwrap();
        let n = rule.into_normalized(Platform::Ios, "18.0");
        // No iOS data in this rule — only free-form tags survive.
        assert_eq!(
            n.tags.iter().filter(|t| t.starts_with("cis_")).count(),
            0,
            "no iOS benchmarks should survive: tags={:?}",
            n.tags
        );
        assert!(n.tags.contains(&"cisv8".to_string()));
    }

    #[test]
    fn collapses_mobileconfig_array_to_dict() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_MOBILECONFIG_RULE).unwrap();
        let n = rule.into_normalized(Platform::MacOS, "15.0");
        assert!(n.mobileconfig);
        let info = n.mobileconfig_info.unwrap();
        let map = info.as_mapping().unwrap();
        let payload = map
            .get(Value::String("com.apple.screensaver".into()))
            .unwrap();
        let inner = payload.as_mapping().unwrap();
        assert_eq!(
            inner.get(Value::String("askForPassword".into())),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            inner
                .get(Value::String("askForPasswordDelay".into()))
                .unwrap()
                .as_i64(),
            Some(5)
        );
    }

    #[test]
    fn flattens_os_keyed_references_for_chosen_os() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_MOBILECONFIG_RULE).unwrap();
        let n = rule.into_normalized(Platform::MacOS, "26.0");
        // OS-keyed `nist.cce.macos_26` should hoist to flat `cce: [CCE-99999-9]`.
        let cce = n.references.get("cce").unwrap();
        let arr = cce.as_sequence().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0].as_str(), Some("CCE-99999-9"));
        // Flat 800-53r5 array passes through.
        let nist_controls = n.references.get("800-53r5").unwrap();
        let arr = nist_controls.as_sequence().unwrap();
        assert_eq!(arr[0].as_str(), Some("AC-11"));
    }

    #[test]
    fn macos_field_lists_all_supported_macos_versions() {
        let rule: MscpRuleV2x = yaml_serde::from_str(SAMPLE_DDM_RULE).unwrap();
        let n = rule.into_normalized(Platform::MacOS, "26.0");
        // Both 26.0 and 15.0 are listed under platforms.macOS, so both appear.
        assert!(n.macos.contains(&"26.0".to_string()));
        assert!(n.macos.contains(&"15.0".to_string()));
    }
}
