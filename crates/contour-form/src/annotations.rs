//! Annotations — what the compliance frameworks say about a key.
//!
//! mSCP is not an authoring source: it creates no fields. It maps rules onto
//! keys that already exist, and each rule belongs to baselines — CIS, STIG,
//! NIST 800-53 tiers, CMMC. In the contract this is `node.annotations[]`:
//! a badge a renderer can show without knowing what mSCP is, which is the
//! property that lets a new framework arrive as data rather than code.
//!
//! Built from three tables the dataset publishes for `mscp-schema`:
//! `rule_capability_links` (rule → payload key, with confidence and the
//! mechanism the rule ships), `baseline_edges` (rule → baselines) and
//! `rule_meta` (title, severity). Joined on `(capability_ref,
//! capability_key)`, which is a **top-level** key — the links table has no
//! deeper paths, so nested nodes carry nothing.
//!
//! Windows rides the same index from its own three files
//! (`windows_rule_capability_links`, `windows_baseline_edges`,
//! `windows_rules`): identical column layouts, so the same
//! readers and the same join, and an ADMX key such as
//! `BitLocker.SystemDrivesRequireStartupAuthentication` carries the STIG
//! rule whose check reads the registry value that policy writes. The two
//! corpora are separate files all the way here and are merged only into the
//! lookup, keyed by payload type — an Apple type and a Windows CSP area
//! cannot collide.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

/// One rule's claim on one key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub rule_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,
    /// `Exact` when the rule names the type itself; `Heuristic` when the
    /// link was inferred. A renderer should show the difference.
    pub confidence: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// Which of Apple's two mechanisms the rule actually ships —
    /// `ProfileCapable` or `DeclarativeReady`. 1,058 rules carry a
    /// mobileconfig and 256 DDM info, so for most the honest answer is
    /// still the legacy profile; a form that shows this is more useful than
    /// one that pretends parity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enforcement_preference: Option<String>,
    /// Baselines that demand this rule, deduplicated and sorted.
    pub baselines: Vec<String>,
    /// Controls this rule satisfies, as `framework: control_id` — NIST
    /// 800-53, CIS, the per-OS CCE numbers. The language a compliance
    /// auditor speaks, where a baseline name is only the shopping list.
    /// Empty when the dataset carries no control edges.
    pub controls: Vec<String>,
    /// Platforms the link was stated for.
    pub platforms: Vec<String>,
}

/// The joined, indexed tables. Build once, annotate many.
#[derive(Debug, Default)]
pub struct Annotations {
    by_key: HashMap<(String, String), Vec<Annotation>>,
}

impl Annotations {
    /// From the three tables as Parquet bytes. An empty links table yields an
    /// empty index, not an error.
    pub fn from_parquet(links: &[u8], edges: &[u8], meta: &[u8]) -> anyhow::Result<Self> {
        Self::from_parquet_with_controls(links, edges, meta, &[])
    }

    /// [`Self::from_parquet`] plus `rule_control_edges`, so each annotation
    /// names the controls its rule satisfies.
    pub fn from_parquet_with_controls(
        links: &[u8],
        edges: &[u8],
        meta: &[u8],
        controls: &[u8],
    ) -> anyhow::Result<Self> {
        Ok(Self {
            by_key: index_from(links, edges, meta, controls)?,
        })
    }

    /// The tables contour embeds: Apple's, then Windows' folded in. Either
    /// corpus may be empty on an older dataset without failing the other.
    pub fn embedded() -> anyhow::Result<Self> {
        let mut by_key = index_from(
            mscp_schema::embedded_rule_capability_links(),
            mscp_schema::embedded_baseline_edges(),
            mscp_schema::embedded_rule_meta(),
            mscp_schema::embedded_rule_control_edges(),
        )?;
        let windows = index_from(
            windows_schema::embedded_windows_rule_capability_links(),
            windows_schema::embedded_windows_baseline_edges(),
            windows_schema::embedded_windows_rules(),
            &[],
        )?;
        for (k, v) in windows {
            by_key.entry(k).or_default().extend(v);
        }
        Ok(Self { by_key })
    }
}

/// One corpus' three tables (plus optional control edges) → the per-key
/// index. Empty links yield an empty index, not an error.
fn index_from(
    links: &[u8],
    edges: &[u8],
    meta: &[u8],
    controls: &[u8],
) -> anyhow::Result<HashMap<(String, String), Vec<Annotation>>> {
    {
        let links = mscp_schema::rule_capability_links::read(links)?;
        if links.is_empty() {
            return Ok(HashMap::new());
        }
        let edges = mscp_schema::baseline_edges::read(edges)?;
        let meta = mscp_schema::rule_meta::read(meta)?;
        let control_edges = mscp_schema::rule_control_edges::read(controls)?;
        let mut by_rule_controls: HashMap<&str, BTreeSet<String>> = HashMap::new();
        for e in &control_edges {
            by_rule_controls
                .entry(e.rule_id.as_str())
                .or_default()
                .insert(format!("{}: {}", e.framework, e.control_id));
        }

        let mut baselines: HashMap<&str, BTreeSet<&str>> = HashMap::new();
        for e in &edges {
            baselines
                .entry(e.rule_id.as_str())
                .or_default()
                .insert(e.baseline.as_str());
        }
        let meta_by_id: HashMap<&str, &mscp_schema::RuleMeta> =
            meta.iter().map(|m| (m.rule_id.as_str(), m)).collect();

        // One annotation per (type, key, rule); platforms and the best
        // confidence gathered across the per-OS-version rows.
        let mut grouped: BTreeMap<(String, String, String), Annotation> = BTreeMap::new();
        for l in &links {
            let Some(key) = l.capability_key.as_deref() else {
                continue;
            };
            let entry = grouped
                .entry((l.capability_ref.clone(), key.to_string(), l.rule_id.clone()))
                .or_insert_with(|| {
                    let m = meta_by_id.get(l.rule_id.as_str());
                    Annotation {
                        rule_id: l.rule_id.clone(),
                        title: m.map(|m| m.title.clone()).filter(|t| !t.is_empty()),
                        severity: m
                            .and_then(|m| m.severity.clone())
                            .filter(|s| !s.is_empty() && s != "None"),
                        confidence: l.confidence.clone(),
                        evidence: l.evidence.clone(),
                        enforcement_preference: l.enforcement_preference.clone(),
                        baselines: baselines
                            .get(l.rule_id.as_str())
                            .map(|b| b.iter().map(|s| (*s).to_string()).collect())
                            .unwrap_or_default(),
                        controls: by_rule_controls
                            .get(l.rule_id.as_str())
                            .map(|c| c.iter().cloned().collect())
                            .unwrap_or_default(),
                        platforms: Vec::new(),
                    }
                });
            if confidence_rank(&l.confidence) > confidence_rank(&entry.confidence) {
                entry.confidence = l.confidence.clone();
                entry.evidence = l.evidence.clone();
            }
            if let Some(p) = &l.platform
                && !entry.platforms.contains(p)
            {
                entry.platforms.push(p.clone());
            }
        }

        let mut by_key: HashMap<(String, String), Vec<Annotation>> = HashMap::new();
        for ((ty, key, _), a) in grouped {
            by_key.entry((ty, key)).or_default().push(a);
        }
        Ok(by_key)
    }
}

impl Annotations {
    /// Annotations for a top-level key of a payload type.
    pub fn for_key(&self, type_id: &str, key: &str) -> Option<&[Annotation]> {
        self.by_key
            .get(&(type_id.to_string(), key.to_string()))
            .map(Vec::as_slice)
    }

    /// The payload and declaration types the rule corpus enforces through,
    /// with how many rules use each — derived from the rules, since mSCP 2.0
    /// publishes no such list. Empty on a dataset without
    /// the table.
    pub fn covered_payloads() -> anyhow::Result<Vec<mscp_schema::SupportedPayload>> {
        mscp_schema::supported_payloads::read(mscp_schema::embedded_supported_payloads())
    }

    /// Number of `(type, key)` pairs with at least one annotation.
    pub fn len(&self) -> usize {
        self.by_key.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_key.is_empty()
    }
}

/// Higher is surer. The dataset's `Confidence` order: Exact, Strong,
/// Heuristic, Manual — `Manual` is a curated mapping and ranks with `Exact`.
fn confidence_rank(c: &str) -> u8 {
    match c {
        "Exact" | "Manual" => 3,
        "Strong" => 2,
        "Heuristic" => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the rule corpus addresses at all — 45 types today, split
    /// between profiles and declarations, each with a rule count.
    #[test]
    fn covered_payloads_names_types_and_kinds() {
        let covered = Annotations::covered_payloads().expect("read supported_payloads");
        assert!(
            !covered.is_empty(),
            "supported_payloads has no rows — the dataset did not carry it. The placeholder \
             guard should have failed before this test ran; do not skip here"
        );
        assert!(covered.iter().any(|p| p.kind == "MdmProfile"));
        assert!(covered.iter().any(|p| p.kind == "DdmDeclaration"));
        assert!(covered.iter().all(|p| !p.payload_type.is_empty()));
        assert!(
            covered.iter().any(|p| p.rule_count > 1),
            "a type used by several rules must count them"
        );
    }

    /// R9's bridge, consumed: a Windows ADMX key carries the STIG rules whose
    /// checks read the registry value that policy writes — through the same
    /// index Apple keys use, from Windows' own files.
    #[test]
    fn windows_admx_keys_carry_stig_annotations() {
        let a = Annotations::embedded().unwrap();
        let anns = a
            .for_key("BitLocker", "SystemDrivesRequireStartupAuthentication")
            .unwrap_or_else(|| {
                panic!(
                    "no Windows annotations — the dataset ({}) predates \
                     windows_rule_capability_links; republish, do not skip",
                    mdm_schema::schema_versions().generation_source
                )
            });
        let v = anns
            .iter()
            .find(|x| x.rule_id == "V-253260")
            .expect("V-253260 checks HKLM\\SOFTWARE\\Policies\\Microsoft\\FVE\\UseAdvancedStartup");
        assert_eq!(v.confidence, "Exact");
        assert!(
            v.platforms.contains(&"Windows".to_string()),
            "{:?}",
            v.platforms
        );
        assert!(
            v.baselines.iter().any(|b| b == "disa_stig"),
            "{:?}",
            v.baselines
        );
        assert!(
            v.title.as_deref().is_some_and(|t| !t.is_empty()),
            "title from windows_rules"
        );
        assert!(v.severity.is_some(), "severity from windows_rules");
        assert!(
            v.evidence
                .as_deref()
                .is_some_and(|e| e.contains("UseAdvancedStartup")),
            "{:?}",
            v.evidence
        );
    }

    /// The corpora meet only in the lookup. No STIG rule reaches an Apple
    /// key and no mSCP rule reaches a Windows one.
    #[test]
    fn apple_and_windows_annotations_do_not_cross() {
        let a = Annotations::embedded().unwrap();
        let apple = a
            .for_key("com.apple.systempreferences", "DisabledSystemSettings")
            .expect("the documented Apple link");
        assert!(
            apple.iter().all(|x| !x.rule_id.starts_with("V-")),
            "STIG rule on an Apple key"
        );
        if let Some(win) = a.for_key("BitLocker", "SystemDrivesRequireStartupAuthentication") {
            assert!(
                win.iter().all(|x| x.rule_id.starts_with("V-")),
                "mSCP rule on a Windows key"
            );
            assert!(
                win.iter().all(|x| x.controls.is_empty()),
                "Windows carries no control edges yet"
            );
        }
    }

    #[test]
    fn empty_links_table_is_an_empty_index_not_an_error() {
        let a = Annotations::from_parquet(&[], &[], &[]).unwrap();
        assert!(a.is_empty());
    }

    /// The link the dataset's own sample row documents: internet-accounts rule
    /// → com.apple.systempreferences.DisabledSystemSettings, Exact,
    /// ProfileCapable, in several baselines.
    #[test]
    fn embedded_tables_join_on_type_and_key() {
        let a = Annotations::embedded().unwrap();
        assert!(
            !a.is_empty(),
            "rule_capability_links has no rows — the dataset did not carry it; do not skip"
        );
        let anns = a
            .for_key("com.apple.systempreferences", "DisabledSystemSettings")
            .expect("the documented link exists");
        let ia = anns
            .iter()
            .find(|x| x.rule_id == "system_settings_internet_accounts_disable")
            .expect("internet accounts rule");
        assert_eq!(ia.confidence, "Exact");
        assert_eq!(ia.enforcement_preference.as_deref(), Some("ProfileCapable"));
        assert!(!ia.baselines.is_empty(), "rule belongs to baselines");
        assert!(
            ia.controls.iter().any(|c| c.contains(':')),
            "controls are `framework: control_id`, got {:?}",
            ia.controls
        );
        assert!(ia.platforms.contains(&"macOS".to_string()));
        assert!(ia.title.is_some());
        assert!(
            a.len() > 100,
            "expected hundreds of annotated keys, saw {}",
            a.len()
        );
    }
}
