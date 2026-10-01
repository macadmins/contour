//! `profile windows stig` — the DISA STIG compliance corpus contour embeds.
//!
//! Two tables, both verified against sources contour already carries:
//!
//! * `fleet_stigs` — 836 policies across 8 STIG profiles, pairing an OMA-URI
//!   and SyncML fragment that ENFORCE a rule with an `mdm_bridge` query that
//!   VERIFIES it. 648 are enforceable; every one targets a node Microsoft's
//!   DDF describes, with a value that node accepts.
//! * `stig_registry_checks` — 122 registry checks, each an osquery query over
//!   the `registry` table. Every rule_id resolves, every query names a real
//!   osquery table and real columns, and every row's SQL agrees with its own
//!   hive, path and value name. 112 of the 122 carry a comparison; the other 10 cannot be expressed as one value
//!   test (six say absence is also compliant, two accept several values, two
//!   state no value at all).
//!
//! ## What this is not
//!
//! contour does not run queries or talk to Fleet. It hands you policies and
//! checks to deploy elsewhere, like everything else it does.
//!
//! And the claim is narrower than "this machine is compliant": an
//! `mdm_bridge` query reads what the CSP reports it was set to, and a
//! registry check reads a registry value. Neither observes the behaviour the
//! rule is about. That is how Fleet does Windows compliance, but it is worth
//! an operator knowing which question is being answered.
//!
//! ## Provenance travels with the output
//!
//! The policies come from tux234/windows-fleet-stigs, a third-party
//! repository that pairs DISA's content with Microsoft's DDF by machine. It
//! is pinned and vendored and its agreement with the DDF is held by a test,
//! but it is derived rather than published, and an export says so.

use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;
use windows_schema::types::{FleetStig, StigRegistryCheck};

/// Where the STIG corpus comes from, carried into anything written out.
const UPSTREAM: &str = "tux234/windows-fleet-stigs @ 63208c7";

fn policies() -> Result<Vec<FleetStig>> {
    windows_schema::fleet_stigs::read(windows_schema::embedded_fleet_stigs())
        .context("reading the embedded Fleet STIG policies")
}

fn registry_checks() -> Result<Vec<StigRegistryCheck>> {
    windows_schema::stig_registry_checks::read(windows_schema::embedded_stig_registry_checks())
        .context("reading the embedded STIG registry checks")
}

fn matches(hay: &str, needle: &str) -> bool {
    hay.to_lowercase().contains(needle)
}

/// `profile windows stig list` — the STIG profiles, and how much of each is
/// enforceable.
///
/// Printed before anything else because the gap is the point: a profile with
/// 167 of 198 rules enforceable is not the STIG, and an operator who exports
/// it should know that before they deploy.
pub fn handle_list(json: bool) -> Result<()> {
    let all = policies()?;
    let mut by: BTreeMap<&str, (usize, usize, usize, usize)> = BTreeMap::new();
    for p in &all {
        let e = by.entry(p.stig_profile.as_str()).or_default();
        e.0 += 1;
        match p.enforcement_status.as_str() {
            "generated" => e.1 += 1,
            "unmapped" => e.2 += 1,
            "blocked" => e.3 += 1,
            _ => {}
        }
    }

    if json {
        let rows: Vec<_> = by
            .iter()
            .map(|(name, (total, ok_count, unmapped, blocked))| {
                serde_json::json!({
                    "stig_profile": name,
                    "rules": total,
                    "enforceable": ok_count,
                    "unmapped": unmapped,
                    "blocked": blocked,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source": UPSTREAM,
                "profiles": rows,
                "registry_checks": registry_checks()?.len(),
            }))?
        );
        return Ok(());
    }

    // Width from the data, not a guess. The guess was 48, and
    // `dod-microsoft-defender-antivirus-stig-computer-v2r4` is 51 — one row
    // pushed every column right of it out of line.
    let w = by.keys().map(|n| n.len()).chain([7]).max().unwrap_or(48);
    println!("STIG profiles  (source: {UPSTREAM})\n");
    println!(
        "  {:<w$} {:>6} {:>12} {:>9} {:>8}",
        "PROFILE", "RULES", "ENFORCEABLE", "UNMAPPED", "BLOCKED"
    );
    println!("  {}", "-".repeat(w + 40));
    for (name, (total, ok_count, unmapped, blocked)) in &by {
        println!("  {name:<w$} {total:>6} {ok_count:>12} {unmapped:>9} {blocked:>8}");
    }
    println!(
        "\n  {} registry check(s) over osquery's `registry` table.",
        registry_checks()?.len()
    );
    println!(
        "\n  Unmapped and blocked rules have no enforcement contour can emit. An export\n  \
         carries the enforceable ones, which is fewer rules than the STIG has."
    );
    Ok(())
}

/// `profile windows stig search <term>` — across both tables.
pub fn handle_search(term: &str, profile: Option<&str>, json: bool) -> Result<()> {
    let needle = term.to_lowercase();
    let all = policies()?;
    let hits: Vec<&FleetStig> = all
        .iter()
        .filter(|p| profile.is_none_or(|f| p.stig_profile == f))
        .filter(|p| {
            matches(&p.policy_name, &needle)
                || matches(&p.oma_uri, &needle)
                || p.csp_area.as_deref().is_some_and(|a| matches(a, &needle))
                || p.policy_tags.iter().any(|t| matches(t, &needle))
        })
        .collect();
    let checks = registry_checks()?;
    let check_hits: Vec<&StigRegistryCheck> = checks
        .iter()
        .filter(|c| {
            matches(&c.rule_id, &needle)
                || matches(&c.path, &needle)
                || matches(&c.value_name, &needle)
        })
        .collect();

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source": UPSTREAM,
                "policies": hits,
                "registry_checks": check_hits,
            }))?
        );
        return Ok(());
    }

    if hits.is_empty() && check_hits.is_empty() {
        println!("no STIG policy or registry check matching '{term}'");
        return Ok(());
    }
    if !hits.is_empty() {
        println!("= {} policy(ies) matching '{term}':\n", hits.len());
        // Two things live in the `oma_uri` column, and the printer has to
        // tell them apart. All 648 generated rows and all 6 blocked rows
        // carry a real OMA-URI. All 182 unmapped rows carry a DISA
        // *definition ID* instead: upstream found no DDF node for the rule,
        // so there is no node, and deriving a setting name from the slug
        // would name a setting that does not exist.
        //
        // The profile is on the line because without it a search for
        // "inactivity" printed three identical rows — the Windows 10,
        // Windows 11 and multi-session STIGs each carry that rule, and
        // nothing on screen said which was which. The URI stays because it
        // is what `stig show` takes, and so is the definition ID.
        for p in &hits {
            if is_node(&p.oma_uri) {
                println!(
                    "  [{}] {}\n      {} · {}",
                    p.enforcement_status,
                    policy_name(p),
                    p.stig_profile,
                    p.oma_uri
                );
            } else {
                println!(
                    "  [{}] {}\n      {} · no CSP node — upstream found no DDF match",
                    p.enforcement_status, p.oma_uri, p.stig_profile
                );
            }
        }
    }
    if !check_hits.is_empty() {
        println!(
            "\n= {} registry check(s) matching '{term}':\n",
            check_hits.len()
        );
        for c in &check_hits {
            println!("  {}  {}\\{}  {}", c.rule_id, c.hive, c.path, c.value_name);
        }
    }
    Ok(())
}

/// `profile windows stig show <oma-uri or rule id>` — enforcement and
/// verification together.
///
/// Together is the point. The two halves live in different tables and an
/// operator needs both: what to set, and what proves it was set.
pub fn handle_show(target: &str, json: bool) -> Result<()> {
    let needle = target.to_lowercase();
    let all = policies()?;
    // Several STIG profiles carry the same rule — the Windows 10, Windows 11
    // and multi-session STIGs all set DeviceLock/PreventEnablingLockScreenCamera
    // — so a lookup by node or definition ID can match more than one row,
    // and every match is shown, not the first as if it were the only one.
    let hits: Vec<&FleetStig> = all
        .iter()
        .filter(|p| p.oma_uri.eq_ignore_ascii_case(target) || matches(&p.policy_name, &needle))
        .collect();
    let policy = hits.first().copied();
    let checks = registry_checks()?;
    let check = checks
        .iter()
        .find(|c| c.rule_id.eq_ignore_ascii_case(target));

    if policy.is_none() && check.is_none() {
        anyhow::bail!(
            "no STIG policy or registry check matches '{target}'. \
             `profile windows stig search {target}` looks across both."
        );
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "source": UPSTREAM,
                "policies": hits,
                "registry_check": check,
            }))?
        );
        return Ok(());
    }

    if let Some(p) = policy {
        // An unmapped row has no CSP node, so it gets no derived setting
        // name and no `OMA-URI` label — both would assert something the row
        // does not contain. It is the rule's DISA definition ID and says so.
        if is_node(&p.oma_uri) {
            println!("{}\n", policy_name(p));
        } else {
            println!("{}\n", p.oma_uri);
        }
        println!("  STIG profile : {}", p.stig_profile);
        println!("  CSP area     : {}", p.csp_area.as_deref().unwrap_or("—"));
        if is_node(&p.oma_uri) {
            println!("  OMA-URI      : {}", p.oma_uri);
        } else {
            println!("  definition   : {}  (no CSP node)", p.oma_uri);
        }
        println!("  enforcement  : {}", p.enforcement_status);
        // Upstream keeps this in a column called `block_reason`, but it
        // carries the reason for both statuses — a blocked row says Fleet
        // refuses the path, an unmapped row says the DDF had no match.
        // Labelling it "blocked" told every unmapped row it was blocked.
        if let Some(r) = &p.block_reason {
            println!("  why          : {r}");
        }
        if hits.len() > 1 {
            let others: Vec<&str> = hits[1..].iter().map(|o| o.stig_profile.as_str()).collect();
            println!(
                "\n  Also in      : {}\n  \
                 Shown above is {}. Use `--profile` on `stig search` to pick one.",
                others.join(", "),
                p.stig_profile
            );
        }
        if let (Some(fmt), Some(data)) = (&p.enforcement_format, &p.enforcement_data) {
            println!("\n  ENFORCE  (format {fmt})\n    {data}");
        }
        if let Some(xml) = &p.enforcement_xml {
            println!("\n  SyncML");
            for line in xml.lines() {
                println!("    {line}");
            }
        }
        if let Some(q) = &p.compliance_query {
            println!("\n  VERIFY  (Fleet mdm_bridge)\n    {q}");
        }
    }
    if let Some(c) = check {
        println!("\n{}  (registry check)\n", c.rule_id);
        println!("  {}\\{}", c.hive, c.path);
        println!(
            "  {} = {} ({})",
            c.value_name, c.expected_value, c.value_type
        );
        println!("\n  VERIFY  (osquery)\n    {}", c.osquery_sql);
    }
    println!(
        "\n  Source: {UPSTREAM} — community-generated from DISA STIG content and\n  \
         Microsoft's DDF, pinned and verified against the DDF contour embeds.\n  \
         A check reads what the CSP or registry reports, not the behaviour itself."
    );
    Ok(())
}

/// Does this row point at a CSP node, or only at a DISA definition ID?
///
/// Upstream keeps both in one column called `oma_uri`. Every generated and
/// blocked row holds a real node path; every unmapped row holds the rule's
/// definition ID, because upstream found no DDF match for it. The column's
/// name and type say none of this, so nothing but the shape of the value
/// distinguishes them — and a slug pushed into a SyncML `LocURI` would
/// produce a profile targeting a node that does not exist.
fn is_node(oma_uri: &str) -> bool {
    oma_uri.starts_with("./")
}

/// A name Fleet can key a policy by, derived from the OMA-URI.
///
/// Upstream truncates every policy name to the same string: all 648
/// generated policies are called `STIG - Ensure `. Fleet identifies a policy
/// BY name, so exporting them as-is has one policy overwrite another as many
/// times as the profile has rules — silently, because nothing in Fleet or in
/// YAML objects to a duplicate key.
///
/// The name is the OMA-URI with only its boilerplate removed: the leading
/// `./` and the `Vendor/MSFT` pair every node carries. `Device` and `User`
/// stay, and so does `Policy/Config`, because a segment that reads as noise
/// is still the segment that can tell two nodes apart. Everything that
/// distinguishes one node from another survives, so two policies collide
/// only if they target the same node — and within a STIG profile, no two do.
///
/// That is why the name derives from the URI and not from `csp_area`. The
/// first attempt was `csp_area / leaf`, which read well on Windows 11 and
/// collapsed the firewall STIG from 11 policies to 5: there `csp_area` IS
/// the leaf (`EnableFirewall`), and the Domain, Private and Public profiles
/// each set a node by that name. The segment that told them apart was the
/// one the name dropped.
///
/// Uniqueness is asserted, not assumed —
/// `every_exported_policy_has_a_distinct_name` holds it per profile, which
/// is the unit an export writes.
fn policy_name(p: &FleetStig) -> String {
    /// `(prefix, what replaces it)` — boilerplate only.
    const BOILERPLATE: &[(&str, &str)] = &[
        ("./Device/Vendor/MSFT/", "Device/"),
        ("./User/Vendor/MSFT/", "User/"),
        ("./Vendor/MSFT/", ""),
        ("./", ""),
    ];
    let path = BOILERPLATE
        .iter()
        .find_map(|(pre, rep)| {
            p.oma_uri
                .strip_prefix(pre)
                .map(|rest| format!("{rep}{rest}"))
        })
        .unwrap_or_else(|| p.oma_uri.clone());
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if parts.is_empty() {
        return format!("STIG — {}", p.oma_uri);
    }
    format!("STIG — {}", parts.join(" / "))
}

/// A Fleet policy, the shape Fleet's GitOps expects.
#[derive(Debug, Serialize)]
struct FleetPolicyOut {
    name: String,
    query: String,
    description: String,
    resolution: String,
    platform: String,
}

/// `profile windows stig export --profile <name>` — Fleet policies.
///
/// Only rules with BOTH a compliance query and an enforcement, because a
/// policy Fleet cannot check is not a policy. The count is printed against
/// the profile's total so the gap is visible rather than implied.
pub fn handle_export(profile: &str, output: Option<&Path>, json: bool) -> Result<()> {
    let all = policies()?;
    let in_profile: Vec<&FleetStig> = all.iter().filter(|p| p.stig_profile == profile).collect();
    if in_profile.is_empty() {
        let names: Vec<&str> = {
            let mut n: Vec<&str> = all.iter().map(|p| p.stig_profile.as_str()).collect();
            n.sort_unstable();
            n.dedup();
            n
        };
        anyhow::bail!("no STIG profile '{profile}'. Known: {}", names.join(", "));
    }

    let exportable: Vec<&FleetStig> = in_profile
        .iter()
        .copied()
        .filter(|p| p.enforcement_status == "generated" && p.compliance_query.is_some())
        .collect();

    let out: Vec<FleetPolicyOut> = exportable
        .iter()
        .map(|p| FleetPolicyOut {
            name: policy_name(p),
            // `expect`, not `unwrap_or_default`. The filter above already
            // required a query, so a default here could only ever be an empty
            // one — a Fleet policy whose check is the empty string, which
            // reports nothing and fails nothing. Emptiness standing in for
            // absence is the failure this codebase keeps finding; it does not
            // get to enter through a convenience method.
            query: p
                .compliance_query
                .clone()
                .expect("filtered to rows with a compliance query"),
            description: format!("{} — {}", p.stig_profile, p.oma_uri),
            resolution: format!(
                "Set {} to {} (format {}).",
                p.oma_uri,
                p.enforcement_data.as_deref().unwrap_or("the STIG value"),
                p.enforcement_format.as_deref().unwrap_or("chr"),
            ),
            platform: "windows".to_string(),
        })
        .collect();

    let body = if json {
        serde_json::to_string_pretty(&serde_json::json!({
            "source": UPSTREAM,
            "stig_profile": profile,
            "rules_in_profile": in_profile.len(),
            "exported": out.len(),
            "policies": out,
        }))?
    } else {
        let header = format!(
            "# Fleet policies for {profile}\n\
             #\n\
             # {} of {} rules in this STIG profile. The rest have no enforcement\n\
             # contour can emit — see `profile windows stig list`.\n\
             #\n\
             # Source: {UPSTREAM} — community-generated from DISA STIG content and\n\
             # Microsoft's DDF, pinned and verified against the DDF contour embeds.\n\
             # Each query reads what the CSP reports it was set to, not the behaviour.\n\
             #\n\
             # Policy names are unique within this profile. Other STIG profiles set many\n\
             # of the same CSP nodes, so merging two exports into one Fleet team can\n\
             # collide — keep them separate, or prefix on merge.\n",
            out.len(),
            in_profile.len(),
        );
        format!("{header}{}", yaml_serde::to_string(&out)?)
    };

    match output {
        Some(p) => {
            std::fs::write(p, &body).with_context(|| format!("writing {}", p.display()))?;
            eprintln!("✓ {} — {} policy(ies)", p.display(), out.len());
        }
        None => print!("{body}"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Fleet keys a policy by name, and upstream gives every one the same one.
    ///
    /// All 648 generated policies are called `STIG - Ensure ` — truncated at
    /// the source. Exporting those verbatim produces a set where one policy
    /// overwrites another as many times as the profile has rules, silently,
    /// because nothing in Fleet or in YAML objects to a duplicate name.
    #[test]
    fn every_exported_policy_has_a_distinct_name() {
        let all = policies().expect("embedded policies");
        let generated: Vec<&FleetStig> = all
            .iter()
            .filter(|p| p.enforcement_status == "generated")
            .collect();
        assert!(!generated.is_empty());

        // The defect this guards against, stated so it is not re-introduced
        // by "just use the upstream name".
        let upstream: BTreeSet<&str> = generated.iter().map(|p| p.policy_name.as_str()).collect();
        assert_eq!(
            upstream.len(),
            1,
            "upstream names are no longer uniformly truncated — if they carry real \
             names now, policy_name() should prefer them"
        );

        // Uniqueness holds WITHIN a profile, which is the unit an export
        // writes, and is checked here for all eight rather than spot-checked
        // on the one I happened to export. It does NOT hold across profiles:
        // the Windows 10 and Windows 11 STIGs set many of the same CSP nodes,
        // so the same name appears in both. Merging two exports into one Fleet
        // team would collide, which is why the export header names its profile.
        //
        // If this fails after a pin bump, the derivation has started dropping
        // a segment that distinguishes two nodes — widen policy_name(), do not
        // widen the test.
        let mut by_profile: BTreeMap<&str, Vec<&FleetStig>> = BTreeMap::new();
        for p in &generated {
            by_profile
                .entry(p.stig_profile.as_str())
                .or_default()
                .push(p);
        }
        for (profile, rows) in &by_profile {
            // The premise: a name is only as unique as what it derives from.
            // Stated separately so a failure below reads as "the derivation
            // lost something" and not as "upstream ships duplicate rules".
            let uris: BTreeSet<&str> = rows.iter().map(|p| p.oma_uri.as_str()).collect();
            assert_eq!(
                uris.len(),
                rows.len(),
                "{profile}: upstream ships {} rules across {} distinct OMA-URIs — no name \
                 derived from the URI can separate them",
                rows.len(),
                uris.len()
            );
            let derived: BTreeSet<String> = rows.iter().map(|p| policy_name(p)).collect();
            assert_eq!(
                derived.len(),
                rows.len(),
                "{profile}: {} policies collapsed to {} names",
                rows.len(),
                derived.len()
            );
        }
    }

    /// An export must never build a SyncML `LocURI` out of a definition ID.
    ///
    /// The `oma_uri` column holds two kinds of value — CSP node paths and
    /// DISA definition IDs — with nothing but the leading `./` to tell them
    /// apart, and `export` puts that value straight into a `<LocURI>`. Today
    /// the split is exactly along `enforcement_status`: all 648 generated
    /// rows are nodes, all 182 unmapped rows are slugs. That is upstream's
    /// invariant, not ours, so it is checked rather than trusted. If a pin
    /// bump breaks it, contour would emit profiles targeting nodes that do
    /// not exist, and every one would fail silently on the device.
    #[test]
    fn every_exported_policy_targets_a_real_node() {
        let all = policies().expect("embedded policies");
        let bad: Vec<&str> = all
            .iter()
            .filter(|p| p.enforcement_status == "generated")
            .filter(|p| !is_node(&p.oma_uri))
            .map(|p| p.oma_uri.as_str())
            .collect();
        assert!(
            bad.is_empty(),
            "{} generated policies carry a definition ID where a CSP node path belongs, \
             e.g. {:?} — exporting them would emit a <LocURI> for a node that does not exist",
            bad.len(),
            &bad[..bad.len().min(3)]
        );

        // And the converse, so the check cannot pass by the column quietly
        // becoming all-URIs and the unmapped rows disappearing.
        let unmapped_slugs = all
            .iter()
            .filter(|p| p.enforcement_status == "unmapped")
            .filter(|p| !is_node(&p.oma_uri))
            .count();
        assert!(
            unmapped_slugs > 0,
            "no unmapped row carries a definition ID any more — if upstream now resolves \
             every rule to a node, is_node() and the search printer have nothing left to \
             tell apart and should go"
        );
    }

    /// The figures in this module's doc comment are pinned, not remembered.
    ///
    /// The header states 836 policies, 8 profiles, 648 enforceable and 122
    /// registry checks. Those are read by an agent as facts about the binary
    /// it is holding, and a pin bump moves all four at once while the prose
    /// stays put. `contour census` counts them at run time for the same
    /// reason; this is the same promise kept for the source.
    ///
    /// When this fails, update the doc comment to the numbers in the message
    /// — and check the SOP's Recipe 6 and the export header, which describe
    /// the same corpus.
    #[test]
    fn the_doc_comment_figures_match_the_data() {
        let all = policies().expect("embedded policies");
        let profiles: BTreeSet<&str> = all.iter().map(|p| p.stig_profile.as_str()).collect();
        let enforceable = all
            .iter()
            .filter(|p| p.enforcement_status == "generated")
            .count();
        let checks = registry_checks().expect("embedded checks").len();
        assert_eq!(
            (all.len(), profiles.len(), enforceable, checks),
            (836, 8, 648, 122),
            "the corpus moved: {} policies across {} profiles, {} enforceable, \
             {} registry checks — the module doc still says 836 / 8 / 648 / 122",
            all.len(),
            profiles.len(),
            enforceable,
            checks
        );
    }

    /// Names must not grow to where something downstream truncates them.
    ///
    /// This is the collision defect again, one step further along: two names
    /// that differ only past a cut-off are the same name once cut, and the
    /// uniqueness test above would still pass because it runs on the full
    /// strings. Truncation would restore exactly the silent overwrite that
    /// deriving the name from the URI was meant to end.
    ///
    /// 255 is a conservative ceiling chosen here, NOT a limit read off
    /// Fleet's schema — I have not verified Fleet's column width. The longest
    /// name the pinned corpus produces is around 150 characters, so the
    /// margin is real. If a pin bump trips this, check what Fleet actually
    /// accepts before raising the number.
    #[test]
    fn a_policy_name_stays_short_enough_to_survive_storage() {
        let all = policies().expect("embedded policies");
        let longest = all
            .iter()
            .filter(|p| p.enforcement_status == "generated")
            .map(|p| policy_name(p))
            .max_by_key(String::len)
            .expect("generated policies exist");
        assert!(
            longest.len() <= 255,
            "a derived policy name is {} characters: {longest}\n\
             Anything that stores this in a narrower column truncates it, and two \
             names that differ only past the cut become one policy overwriting \
             another — the defect policy_name() exists to prevent.",
            longest.len()
        );
    }

    /// A name says what the policy is about.
    #[test]
    fn a_policy_name_names_the_setting() {
        let all = policies().expect("embedded policies");
        let p = all
            .iter()
            .find(|p| p.oma_uri.ends_with("/PreventEnablingLockScreenCamera"))
            .expect("a known policy");
        let name = policy_name(p);
        assert!(name.contains("PreventEnablingLockScreenCamera"), "{name}");
        assert!(name.contains("DeviceLock"), "{name}");
    }

    /// Both tables are reachable, which is the whole point of this module.
    ///
    /// They were embedded and read by nothing — `stig_registry_checks` was
    /// the sole entry in contour's ALLOWED_UNREAD list.
    #[test]
    fn both_embedded_tables_are_read() {
        assert!(!policies().expect("policies").is_empty());
        assert!(!registry_checks().expect("checks").is_empty());
    }

    /// An export carries fewer rules than the STIG, and must not imply otherwise.
    #[test]
    fn an_export_is_a_subset_and_the_gap_is_countable() {
        let all = policies().expect("embedded policies");
        let profile = "dod-windows-11-stig-v2r4";
        let in_profile: Vec<&FleetStig> =
            all.iter().filter(|p| p.stig_profile == profile).collect();
        let exportable = in_profile
            .iter()
            .filter(|p| p.enforcement_status == "generated" && p.compliance_query.is_some())
            .count();
        assert!(
            exportable < in_profile.len(),
            "this profile is fully enforceable, so the header's gap wording would mislead"
        );
        assert!(exportable > 0);
    }
}
