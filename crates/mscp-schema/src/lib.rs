//! Shared mSCP (macOS Security Compliance Project) metadata and embedded Parquet data.
//!
//! Twelve datasets:
//! - `baseline_meta` — baseline names, titles, preambles, authors
//! - `sections` — mSCP section names and descriptions
//! - `control_tiers` — NIST 800-53 control → impact tier mappings
//! - `rule_meta` — lightweight rule metadata (no scripts/fixes)
//! - `baseline_edges` — baseline → section → rule membership
//! - `rules_versioned` — full versioned rules with enforcement metadata
//! - `rule_payloads` — rule enforcement payloads (scripts, mobileconfig, DDM)
//! - `envelope_patterns` — XML envelope nesting patterns for mobileconfig
//! - `envelope_meta_keys` — required metadata keys for envelope layers
//! - `rule_capability_links` — rule → payload/declaration key it enforces through
//! - `rule_control_edges` — rule → framework control it satisfies
//! - `supported_payloads` — payload types the rule corpus enforces through
//!
//! Plus Fleet's GitOps JSON Schema, pinned and shipped beside them.

pub mod baseline_edges;
pub mod baseline_meta;
pub mod control_tiers;
pub mod envelope_meta_keys;
pub mod envelope_patterns;
pub mod rule_capability_links;
pub mod rule_control_edges;
pub mod rule_meta;
pub mod rule_payloads;
pub mod rules_versioned;
pub mod sections;
pub mod supported_payloads;
pub mod types;

pub use types::*;

/// Embedded baseline metadata Parquet data.
pub fn embedded_baseline_meta() -> &'static [u8] {
    include_bytes!("../data/baseline_meta.parquet")
}

/// Embedded sections Parquet data.
pub fn embedded_sections() -> &'static [u8] {
    include_bytes!("../data/sections.parquet")
}

/// Embedded NIST control tiers Parquet data.
pub fn embedded_control_tiers() -> &'static [u8] {
    include_bytes!("../data/control_tiers.parquet")
}

/// Embedded rule metadata Parquet data.
pub fn embedded_rule_meta() -> &'static [u8] {
    include_bytes!("../data/rule_meta.parquet")
}

/// Embedded baseline edges Parquet data.
pub fn embedded_baseline_edges() -> &'static [u8] {
    include_bytes!("../data/baseline_edges.parquet")
}

/// Embedded versioned rules Parquet data.
pub fn embedded_rules_versioned() -> &'static [u8] {
    include_bytes!("../data/rules_versioned.parquet")
}

/// Embedded rule payloads Parquet data.
pub fn embedded_rule_payloads() -> &'static [u8] {
    include_bytes!("../data/rule_payloads.parquet")
}

/// Embedded rule → capability links, for FormSpec annotations. Zero bytes
/// when the dataset predates the table; the reader treats that as empty.
pub fn embedded_rule_capability_links() -> &'static [u8] {
    include_bytes!("../data/rule_capability_links.parquet")
}

/// Embedded rule → framework → control edges, for FormSpec annotations.
pub fn embedded_rule_control_edges() -> &'static [u8] {
    include_bytes!("../data/rule_control_edges.parquet")
}

/// Embedded list of the payload types the rule corpus enforces through.
pub fn embedded_supported_payloads() -> &'static [u8] {
    include_bytes!("../data/supported_payloads.parquet")
}

/// Embedded envelope patterns Parquet data.
pub fn embedded_envelope_patterns() -> &'static [u8] {
    include_bytes!("../data/envelope_patterns.parquet")
}

/// Embedded envelope meta keys Parquet data.
pub fn embedded_envelope_meta_keys() -> &'static [u8] {
    include_bytes!("../data/envelope_meta_keys.parquet")
}

/// Fleet's GitOps JSON Schema, as the dataset pinned and verified it.
///
/// `tools/gitops-auto-complete/generated-schema.json` from fleetdm/fleet at
/// one commit, shipped only when its bytes match the pinned sha256. `None`
/// when this build embeds a dataset without it: the build script writes an
/// empty placeholder then, and an empty schema is no schema.
pub fn embedded_fleet_gitops_schema() -> Option<&'static [u8]> {
    let bytes: &'static [u8] = include_bytes!("../data/fleet-gitops-schema.json");
    (!bytes.is_empty()).then_some(bytes)
}

// ── Beta channel (dormant) ──────────────────────────────────────────────
//
// Every `*_beta` accessor below returns the STABLE bytes: no mSCP preview
// dataset is carried today, and `--beta` refuses rather than serve the
// released rules under another name (`beta_dataset_is_carried` is the
// check). When a preview branch (e.g. `dev_NN`) is published again, point
// these at their own `include_bytes!`. Mirrors mdm-schema's `*_beta`
// accessors.

/// Embedded **beta** baseline metadata Parquet data.
pub fn embedded_baseline_meta_beta() -> &'static [u8] {
    embedded_baseline_meta()
}

/// Embedded **beta** sections Parquet data.
pub fn embedded_sections_beta() -> &'static [u8] {
    embedded_sections()
}

/// Embedded **beta** NIST control tiers Parquet data.
pub fn embedded_control_tiers_beta() -> &'static [u8] {
    embedded_control_tiers()
}

/// Embedded **beta** rule metadata Parquet data.
pub fn embedded_rule_meta_beta() -> &'static [u8] {
    embedded_rule_meta()
}

/// Embedded **beta** baseline edges Parquet data.
pub fn embedded_baseline_edges_beta() -> &'static [u8] {
    embedded_baseline_edges()
}

/// Embedded **beta** versioned rules Parquet data.
pub fn embedded_rules_versioned_beta() -> &'static [u8] {
    embedded_rules_versioned()
}

/// Embedded **beta** rule payloads Parquet data.
pub fn embedded_rule_payloads_beta() -> &'static [u8] {
    embedded_rule_payloads()
}

/// Embedded **beta** envelope patterns Parquet data.
pub fn embedded_envelope_patterns_beta() -> &'static [u8] {
    embedded_envelope_patterns()
}

/// Embedded **beta** envelope meta keys Parquet data.
pub fn embedded_envelope_meta_keys_beta() -> &'static [u8] {
    embedded_envelope_meta_keys()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// One edge on every axis: (baseline, platform, os_version, section, rule_id).
    /// Two rows sharing all five are the collapse signature the guard rejects.
    type EdgeKey<'a> = (&'a str, Option<&'a str>, Option<&'a str>, &'a str, &'a str);

    /// Structural invariants for embedded baseline data — checked on BOTH
    /// channels, because a refresh can corrupt one and not the other.
    ///
    /// The parquet is gitignored: a bad republish produces no diff, no status
    /// line, and no failing build. A dataset whose file-defined baselines
    /// collapsed into one phantom name (an ODV selector, not a baseline),
    /// with duplicate edges and real baselines missing, would pass
    /// everything else. This is the check that turns that into a red build.
    ///
    /// Returns the first violated invariant as a message rather than
    /// panicking, so the same check can be aimed at a deliberately corrupted
    /// copy to prove it fires — a guard that has never been seen failing is a
    /// guess.
    fn baseline_invariants(
        channel: &str,
        edges: &[types::BaselineEdge],
        meta: &[types::BaselineMeta],
    ) -> Result<(), String> {
        if edges.is_empty() {
            return Err(format!("[{channel}] baseline_edges is empty"));
        }

        // 1. No exact-duplicate edge. The same (baseline, rule) legitimately
        //    recurs across platforms and OS versions; a row identical on every
        //    axis is the collapse signature.
        let mut seen: HashSet<EdgeKey<'_>> = HashSet::new();
        let dups: Vec<String> = edges
            .iter()
            .filter(|e| {
                !seen.insert((
                    e.baseline.as_str(),
                    e.platform.as_deref(),
                    e.os_version.as_deref(),
                    e.section.as_str(),
                    e.rule_id.as_str(),
                ))
            })
            .map(|e| format!("{}/{:?}/{}", e.baseline, e.platform, e.rule_id))
            .collect();
        if !dups.is_empty() {
            return Err(format!(
                "[{channel}] {} exact-duplicate baseline_edges rows, e.g. {:?}",
                dups.len(),
                &dups[..dups.len().min(3)]
            ));
        }

        // 2. Every edge names a baseline that baseline_meta knows about.
        let meta_names: HashSet<&str> = meta.iter().map(|m| m.baseline.as_str()).collect();
        let mut orphans: Vec<&str> = edges
            .iter()
            .map(|e| e.baseline.as_str())
            .filter(|b| !meta_names.contains(b))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        orphans.sort_unstable();
        if !orphans.is_empty() {
            return Err(format!(
                "[{channel}] edges reference baselines absent from baseline_meta: {orphans:?}"
            ));
        }

        // 3. Baseline names must not be ODV selectors. `parent_values` is the
        //    mSCP parent-values choice (`recommended`, or another baseline it
        //    inherits ODVs from); treating it as the name is the exact bug.
        //    `recommended` is never a baseline. And the two sets must differ
        //    overall — if every baseline name is also a parent_values value,
        //    the name column was filled from the wrong field.
        let names: HashSet<&str> = edges.iter().map(|e| e.baseline.as_str()).collect();
        let parents: HashSet<&str> = edges.iter().map(|e| e.parent_values.as_str()).collect();
        if names.contains("recommended") {
            return Err(format!(
                "[{channel}] a baseline is named `recommended` — that is an ODV selector, \
                 not a baseline"
            ));
        }
        if names == parents {
            return Err(format!(
                "[{channel}] baseline names == parent_values values; the name column was \
                 filled from the ODV selector"
            ));
        }

        // 4. File-defined macOS baselines that must be present. These are the
        //    ones the collapse deleted; their absence is the loudest symptom.
        let macos: HashSet<&str> = edges
            .iter()
            .filter(|e| e.platform.as_deref() == Some("macOS"))
            .map(|e| e.baseline.as_str())
            .collect();
        for required in ["cis_lvl1", "cis_lvl2", "disa_stig", "800-171", "all_rules"] {
            if !macos.contains(required) {
                return Err(format!(
                    "[{channel}] macOS baseline `{required}` has no edges — refresh dropped it"
                ));
            }
        }

        // 5. The other platforms must not collapse either. Check 4 names macOS
        //    files explicitly, so a collapse confined to `baselines/ios/` —
        //    same bug, different directory — would sail past it. iOS and
        //    visionOS each ship 12 baselines; require most of them rather than
        //    an exact count, so adding or retiring one upstream is not a
        //    failure while a collapse to one or two still is.
        const MIN_PER_PLATFORM: usize = 10;
        for platform in ["iOS", "visionOS"] {
            let count = edges
                .iter()
                .filter(|e| e.platform.as_deref() == Some(platform))
                .map(|e| e.baseline.as_str())
                .collect::<HashSet<_>>()
                .len();
            if count < MIN_PER_PLATFORM {
                return Err(format!(
                    "[{channel}] {platform} carries only {count} distinct baselines                      (expected at least {MIN_PER_PLATFORM}) — a platform-local collapse"
                ));
            }
        }

        // 6. Meta for a file-defined baseline must carry the file's prose.
        //    2.0 meta is built from the baseline YAML, so every baseline with
        //    edges has a real title and description. The older
        //    author-tag-derived meta had `title == baseline` and no preamble;
        //    reverting to it would leave every name intact and quietly strip
        //    what makes the rows useful, which no other check here notices.
        let by_name: std::collections::HashMap<&str, &types::BaselineMeta> =
            meta.iter().map(|m| (m.baseline.as_str(), m)).collect();
        let mut hollow: Vec<&str> = edges
            .iter()
            .map(|e| e.baseline.as_str())
            .collect::<HashSet<_>>()
            .into_iter()
            .filter(|b| {
                by_name
                    .get(b)
                    .is_some_and(|m| m.preamble.as_deref().unwrap_or("").trim().is_empty())
            })
            .collect();
        hollow.sort_unstable();
        if !hollow.is_empty() {
            return Err(format!(
                "[{channel}] {} baselines with edges have an empty baseline_meta preamble,                  e.g. {:?} — meta regressed to tag-only rows",
                hollow.len(),
                &hollow[..hollow.len().min(3)]
            ));
        }
        Ok(())
    }

    fn decoded(edges: &[u8], meta: &[u8]) -> (Vec<types::BaselineEdge>, Vec<types::BaselineMeta>) {
        (
            baseline_edges::read(edges).expect("read baseline_edges"),
            baseline_meta::read(meta).expect("read baseline_meta"),
        )
    }

    #[test]
    fn stable_baseline_data_holds_invariants() {
        let (e, m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        baseline_invariants("stable", &e, &m).unwrap_or_else(|msg| panic!("{msg}"));
    }

    #[test]
    fn beta_baseline_data_holds_invariants() {
        let (e, m) = decoded(
            embedded_baseline_edges_beta(),
            embedded_baseline_meta_beta(),
        );
        baseline_invariants("beta", &e, &m).unwrap_or_else(|msg| panic!("{msg}"));
    }

    // The break-tests: each takes the REAL stable data, corrupts one thing the
    // way a bad refresh would, and proves the guard catches exactly that.
    // Without these, a green guard only proves the data is currently fine —
    // not that the guard would notice if it were not.

    #[test]
    fn guard_fires_on_a_duplicated_edge() {
        let (mut e, m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        let dup = e[0].clone();
        e.push(dup);
        let msg = baseline_invariants("stable", &e, &m).expect_err("duplicate must be rejected");
        assert!(msg.contains("exact-duplicate"), "wrong reason: {msg}");
    }

    #[test]
    fn guard_fires_on_the_recommended_phantom() {
        let (mut e, m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        // Recreate the collapse: a baseline named after the ODV selector.
        e[0].baseline = "recommended".to_string();
        let msg = baseline_invariants("stable", &e, &m).expect_err("phantom must be rejected");
        // It is caught as an orphan first (no such meta row) — either reason is
        // a correct refusal; assert the guard did not stay silent.
        assert!(
            msg.contains("recommended") || msg.contains("absent from baseline_meta"),
            "wrong reason: {msg}"
        );
    }

    #[test]
    fn guard_fires_when_a_platform_collapses_to_one_baseline() {
        // The collapse shape, confined to iOS: every iOS edge renamed to a
        // single bucket. Every macOS check still passes; only the per-platform
        // count notices.
        let (mut e, m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        let survivor = e
            .iter()
            .find(|x| x.platform.as_deref() == Some("iOS"))
            .expect("corpus must have iOS edges")
            .baseline
            .clone();
        for edge in &mut e {
            if edge.platform.as_deref() == Some("iOS") {
                edge.baseline.clone_from(&survivor);
            }
        }
        // De-duplicate so the collapse is caught as a collapse, not as check 1.
        let mut seen = HashSet::new();
        e.retain(|x| {
            seen.insert((
                x.baseline.clone(),
                x.platform.clone(),
                x.os_version.clone(),
                x.section.clone(),
                x.rule_id.clone(),
            ))
        });
        let msg = baseline_invariants("stable", &e, &m).expect_err("iOS collapse must be rejected");
        assert!(msg.contains("iOS carries only"), "wrong reason: {msg}");
    }

    #[test]
    fn guard_fires_when_meta_loses_its_preamble() {
        // Author-tag-derived meta: names intact, prose gone. Nothing else in the guard looks at meta content.
        let (e, mut m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        for row in &mut m {
            row.preamble = None;
        }
        let msg = baseline_invariants("stable", &e, &m).expect_err("hollow meta must be rejected");
        assert!(msg.contains("preamble"), "wrong reason: {msg}");
    }

    #[test]
    fn guard_fires_when_a_required_macos_baseline_vanishes() {
        let (e, m) = decoded(embedded_baseline_edges(), embedded_baseline_meta());
        let e: Vec<_> = e.into_iter().filter(|x| x.baseline != "800-171").collect();
        let msg =
            baseline_invariants("stable", &e, &m).expect_err("dropped baseline must be rejected");
        assert!(msg.contains("800-171"), "wrong reason: {msg}");
    }

    /// The beta channel must be a readable superset of stable.
    ///
    /// With no preview seed carried the two channels are identical, so a pin
    /// on a beta-only rule cannot hold. What must be true regardless of
    /// whether a seed is active: beta reads, and it never *lacks* a rule
    /// stable has.
    ///
    /// When a new OS seed diverges the channels again, re-add a pin on one of
    /// its preview-only rules here so `--beta` adding nothing is caught.
    #[test]
    fn beta_rules_are_a_superset_of_stable() {
        let beta = rules_versioned::read(embedded_rules_versioned_beta())
            .expect("read beta rules_versioned");
        let stable =
            rules_versioned::read(embedded_rules_versioned()).expect("read stable rules_versioned");
        assert!(!beta.is_empty(), "beta channel is empty");

        let beta_ids: HashSet<&str> = beta.iter().map(|r| r.rule_id.as_str()).collect();
        let missing: Vec<&str> = stable
            .iter()
            .map(|r| r.rule_id.as_str())
            .filter(|id| !beta_ids.contains(id))
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        assert!(
            missing.is_empty(),
            "beta channel lacks {} rule(s) that stable has, e.g. {:?} — a beta \
             publish dropped rules",
            missing.len(),
            &missing[..missing.len().min(3)]
        );
    }

    /// Hard platform separation: the mSCP corpus is Apple-only. Windows
    /// STIG rules live in the windows-schema crate — a Windows row here
    /// means the pipelines re-merged and the separation regressed.
    #[test]
    fn rules_versioned_is_apple_only() {
        let rules =
            rules_versioned::read(embedded_rules_versioned()).expect("read stable rules_versioned");
        assert!(
            rules.iter().all(|r| r.platform != "Windows"),
            "rules_versioned must not carry Windows rows (hard platform separation)"
        );
    }

    #[test]
    fn test_read_embedded_baseline_meta() {
        let metas = baseline_meta::read(embedded_baseline_meta())
            .expect("Failed to read embedded baseline_meta");
        assert!(
            metas.len() >= 10,
            "Expected at least 10 baselines, got {}",
            metas.len()
        );
        for m in &metas {
            assert!(!m.baseline.is_empty());
            assert!(!m.title.is_empty());
        }
    }

    #[test]
    fn test_read_embedded_sections() {
        let sections =
            sections::read(embedded_sections()).expect("Failed to read embedded sections");
        assert!(
            sections.len() >= 5,
            "Expected at least 5 sections, got {}",
            sections.len()
        );
    }

    #[test]
    fn test_read_embedded_control_tiers() {
        let tiers = control_tiers::read(embedded_control_tiers())
            .expect("Failed to read embedded control_tiers");
        assert!(
            tiers.len() >= 100,
            "Expected at least 100 control tiers, got {}",
            tiers.len()
        );
    }

    #[test]
    fn test_read_embedded_rule_meta() {
        let rules =
            rule_meta::read(embedded_rule_meta()).expect("Failed to read embedded rule_meta");
        assert!(
            rules.len() >= 100,
            "Expected at least 100 rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_read_embedded_baseline_edges() {
        let edges = baseline_edges::read(embedded_baseline_edges())
            .expect("Failed to read embedded baseline_edges");
        assert!(
            edges.len() >= 100,
            "Expected at least 100 edges, got {}",
            edges.len()
        );
    }

    #[test]
    fn test_read_embedded_rules_versioned() {
        let rules = rules_versioned::read(embedded_rules_versioned())
            .expect("Failed to read embedded rules_versioned");
        assert!(
            rules.len() >= 100,
            "Expected at least 100 versioned rules, got {}",
            rules.len()
        );
    }

    #[test]
    fn test_read_embedded_rule_payloads() {
        let payloads = rule_payloads::read(embedded_rule_payloads())
            .expect("Failed to read embedded rule_payloads");
        assert!(
            payloads.len() >= 100,
            "Expected at least 100 rule payloads, got {}",
            payloads.len()
        );
    }

    #[test]
    fn test_read_embedded_envelope_patterns() {
        let patterns = envelope_patterns::read(embedded_envelope_patterns())
            .expect("Failed to read embedded envelope_patterns");
        assert!(
            patterns.len() >= 3,
            "Expected at least 3 envelope patterns, got {}",
            patterns.len()
        );
    }

    #[test]
    fn test_read_embedded_envelope_meta_keys() {
        let keys = envelope_meta_keys::read(embedded_envelope_meta_keys())
            .expect("Failed to read embedded envelope_meta_keys");
        assert!(
            keys.len() >= 10,
            "Expected at least 10 envelope meta keys, got {}",
            keys.len()
        );
    }

    #[test]
    fn test_rules_have_platform_distinction() {
        // mSCP 2.0 stamps platform on the rule (`rules_versioned`) as well
        // as on the baseline edge; this pins the rule-side stamp.
        let rules = rules_versioned::read(embedded_rules_versioned())
            .expect("Failed to read embedded rules_versioned");
        let platforms: HashSet<&str> = rules.iter().map(|r| r.platform.as_str()).collect();
        assert!(
            platforms.contains("macOS")
                && platforms.contains("iOS")
                && platforms.contains("visionOS"),
            "Expected macOS + iOS + visionOS, got: {platforms:?}"
        );
    }
}

/// Is a distinct mSCP preview dataset compiled in?
///
/// The mSCP half of the same question `mdm_schema::beta_dataset_is_carried`
/// answers for Apple's schema. Asked separately because the crates carry
/// different tables, and the mSCP preview and Apple's seed can open and close
/// at different times.
///
/// Compares the bytes for the reason given there: the `*_beta` accessors
/// delegate today, so the slices are the same memory, and a real preview
/// table would be a separate `include_bytes!`.
pub fn beta_dataset_is_carried() -> bool {
    let stable = embedded_rules_versioned();
    let beta = embedded_rules_versioned_beta();
    !std::ptr::eq(stable.as_ptr(), beta.as_ptr()) || stable.len() != beta.len()
}
