//! `profile windows apps` — the third-party Administrative Templates contour
//! embeds.
//!
//! `windows_app_policies` carries every policy from the vendors' own ADMX
//! templates — Chrome, Edge, Firefox, the Microsoft 365 apps, OneDrive,
//! Adobe, FSLogix, winget, Zoom, Google Update — with both LocURIs, the
//! element schema, and Windows' verdict on whether MDM may ingest it. `census`
//! counted 25 templates and `profile windows generate` accepted `app = …`,
//! but nothing let an operator find a policy's name to put there: the corpus
//! was usable only by someone who already knew what was in it.
//!
//! `show` ends with the `[[setting]]` entry that deploys the policy, because
//! finding a policy and using it are one task.
//!
//! ## Three states, said out loud
//!
//! * **usable** — ingest the template, then set the policy.
//! * **native** — Windows already ships this template as a Policy CSP area
//!   (`in_box_area`). `generate` refuses the ingested route and names the
//!   area; so does this.
//! * **blocked** — the policy writes where Windows will not let MDM ingest
//!   (`Software\Policies\Microsoft\` and two other roots, unless
//!   allow-listed). The device accepts it and silently drops it, so
//!   `generate` refuses it, with the document the verdict rests on.

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use windows_schema::WindowsAppPolicy;

fn policies() -> Result<Vec<WindowsAppPolicy>> {
    windows_schema::app_policies::read(windows_schema::embedded_windows_app_policies())
        .context("reading the embedded Windows app policies")
}

fn status(p: &WindowsAppPolicy) -> &'static str {
    if p.in_box_area.is_some() {
        "native"
    } else if !p.ingestable {
        "blocked"
    } else {
        "usable"
    }
}

fn matches_app(p: &WindowsAppPolicy, app: &str) -> bool {
    p.template.eq_ignore_ascii_case(app) || p.app_name.eq_ignore_ascii_case(app)
}

fn contains(hay: Option<&str>, needle: &str) -> bool {
    hay.is_some_and(|h| h.to_lowercase().contains(needle))
}

#[derive(Default)]
struct TemplateRow<'a> {
    app_name: &'a str,
    vendor: &'a str,
    provenance: &'a str,
    source_url: &'a str,
    admx_file: &'a str,
    policies: usize,
    usable: usize,
    native: usize,
    blocked: usize,
}

/// `profile windows apps list` — every template, and how much of it MDM can
/// deliver.
pub fn handle_list(json: bool) -> Result<()> {
    let all = policies()?;
    let mut by: BTreeMap<&str, TemplateRow> = BTreeMap::new();
    for p in &all {
        let r = by
            .entry(p.template.as_str())
            .or_insert_with(|| TemplateRow {
                app_name: &p.app_name,
                vendor: &p.vendor,
                provenance: &p.provenance,
                source_url: &p.source_url,
                admx_file: &p.admx_file,
                ..Default::default()
            });
        r.policies += 1;
        match status(p) {
            "usable" => r.usable += 1,
            "native" => r.native += 1,
            _ => r.blocked += 1,
        }
    }

    if json {
        let rows: Vec<_> = by
            .iter()
            .map(|(template, r)| {
                serde_json::json!({
                    "template": template,
                    "app_name": r.app_name,
                    "vendor": r.vendor,
                    "provenance": r.provenance,
                    "admx_file": r.admx_file,
                    "source_url": r.source_url,
                    "policies": r.policies,
                    "usable": r.usable,
                    "native": r.native,
                    "blocked": r.blocked,
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "templates": rows,
                "policies": all.len(),
            }))?
        );
        return Ok(());
    }

    let w = by.keys().map(|k| k.len()).chain([8]).max().unwrap_or(8);
    let v = by
        .values()
        .map(|r| r.vendor.len())
        .chain([6])
        .max()
        .unwrap_or(6);
    println!(
        "Windows app templates  ({} templates, {} policies)\n",
        by.len(),
        all.len()
    );
    println!(
        "  {:<w$}  {:<v$}  {:>8} {:>7} {:>7} {:>8}  PROVENANCE",
        "TEMPLATE", "VENDOR", "POLICIES", "USABLE", "NATIVE", "BLOCKED"
    );
    println!("  {}", "-".repeat(w + v + 50));
    for (template, r) in &by {
        println!(
            "  {template:<w$}  {:<v$}  {:>8} {:>7} {:>7} {:>8}  {}",
            r.vendor, r.policies, r.usable, r.native, r.blocked, r.provenance
        );
    }
    println!(
        "\n  usable   ingest the template, then set the policy\n  \
         native   Windows ships this template as a Policy CSP area; use that instead\n  \
         blocked  writes where Windows will not let MDM ingest — accepted, then dropped\n\n  \
         The ADMX files are not shipped with contour; `generate --admx-dir` points at\n  \
         them, and `apps show` names where each is fetched from."
    );
    Ok(())
}

/// `profile windows apps search <term>` — policy name, title, category and
/// registry path.
pub fn handle_search(term: &str, app: Option<&str>, json: bool) -> Result<()> {
    let needle = term.to_lowercase();
    let all = policies()?;
    if let Some(a) = app
        && !all.iter().any(|p| matches_app(p, a))
    {
        anyhow::bail!("no app template '{a}'. `contour profile windows apps list` names them.");
    }
    let hits: Vec<&WindowsAppPolicy> = all
        .iter()
        .filter(|p| app.is_none_or(|a| matches_app(p, a)))
        .filter(|p| {
            p.policy_name.to_lowercase().contains(&needle)
                || contains(p.display_name.as_deref(), &needle)
                || p.category_path.to_lowercase().contains(&needle)
                || contains(p.registry_key.as_deref(), &needle)
                || contains(p.registry_value.as_deref(), &needle)
        })
        .collect();

    if json {
        let rows: Vec<_> = hits
            .iter()
            .map(|p| {
                serde_json::json!({
                    "template": p.template,
                    "policy_name": p.policy_name,
                    "display_name": p.display_name,
                    "class": p.class,
                    "category_path": p.category_path,
                    "status": status(p),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "count": rows.len(),
                "results": rows,
            }))?
        );
        return Ok(());
    }

    if hits.is_empty() {
        println!("No app policy matches '{term}'.");
        return Ok(());
    }
    println!("{} app polic(ies) matching '{term}':\n", hits.len());
    for p in &hits {
        println!(
            "  {:<14} {:<48} {:<7} {}",
            p.template,
            p.policy_name,
            p.class,
            status(p)
        );
        if let Some(t) = &p.display_name {
            println!("  {:<14} {}", "", t);
        }
    }
    println!("\n  `contour profile windows apps show <template> <policy>` for one in full.");
    Ok(())
}

/// `profile windows apps show <app> <policy>` — everything, then the
/// settings entry that deploys it.
pub fn handle_show(app: &str, policy: &str, json: bool) -> Result<()> {
    let all = policies()?;
    let Some(p) = all
        .iter()
        .find(|p| matches_app(p, app) && p.policy_name == policy)
        .or_else(|| {
            all.iter()
                .find(|p| matches_app(p, app) && p.policy_name.eq_ignore_ascii_case(policy))
        })
    else {
        if !all.iter().any(|p| matches_app(p, app)) {
            anyhow::bail!(
                "no app template '{app}'. `contour profile windows apps list` names them."
            );
        }
        anyhow::bail!(
            "'{app}' has no policy '{policy}'. `contour profile windows apps search <term> \
             --app {app}` finds one."
        );
    };

    let snippet = settings_entry(p);
    if json {
        let elements: Vec<_> = p
            .elements
            .iter()
            .map(|e| {
                serde_json::json!({
                    "id": e.id,
                    "kind": e.kind,
                    "label": e.label,
                    "required": e.required,
                    "min": e.min,
                    "max": e.max,
                    "max_length": e.max_length,
                    "items": e.items.iter().map(|i| serde_json::json!({
                        "value": i.value, "display": i.display,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "template": p.template,
                "app_name": p.app_name,
                "vendor": p.vendor,
                "provenance": p.provenance,
                "source_url": p.source_url,
                "admx_file": p.admx_file,
                "policy_name": p.policy_name,
                "display_name": p.display_name,
                "explain_text": p.explain_text,
                "class": p.class,
                "category_path": p.category_path,
                "supported_on": p.supported_on,
                "status": status(p),
                "in_box_area": p.in_box_area,
                "ingest_reason": p.ingest_reason,
                "ingest_evidence": p.ingest_evidence,
                "device_loc_uri": p.device_loc_uri,
                "user_loc_uri": p.user_loc_uri,
                "admx_install_loc_uri": p.admx_install_loc_uri,
                "registry_key": p.registry_key,
                "registry_value": p.registry_value,
                "elements": elements,
                "settings_entry": snippet,
            }))?
        );
        return Ok(());
    }

    println!("{} / {}", p.app_name, p.policy_name);
    if let Some(t) = &p.display_name {
        println!("  {t}");
    }
    println!();
    println!(
        "  Template   {} ({}, {})",
        p.admx_file, p.vendor, p.provenance
    );
    println!("  Fetch from {}", p.source_url);
    println!("  Category   {}", p.category_path);
    println!("  Class      {}", p.class);
    if let Some(s) = &p.supported_on {
        println!("  Supported  {s}");
    }
    if let (Some(k), v) = (&p.registry_key, &p.registry_value) {
        println!(
            "  Registry   {k}{}",
            v.as_deref().map(|v| format!(" \\ {v}")).unwrap_or_default()
        );
    }
    println!();
    match status(p) {
        "native" => println!(
            "  NATIVE — Windows ships this template as the Policy CSP area `{}`. Use that\n  \
             area instead; `generate` refuses the ingested route.",
            p.in_box_area.as_deref().unwrap_or("?")
        ),
        "blocked" => println!(
            "  BLOCKED — {}. The device accepts the policy and drops it, so `generate`\n  \
             refuses it.\n  Evidence: {}",
            p.ingest_reason
                .as_deref()
                .unwrap_or("writes where Windows blocks MDM ingestion"),
            p.ingest_evidence
        ),
        _ => {
            println!("  Ingest     {}", p.admx_install_loc_uri);
            if !p.device_loc_uri.is_empty() {
                println!("  Device     {}", p.device_loc_uri);
            }
            if !p.user_loc_uri.is_empty() {
                println!("  User       {}", p.user_loc_uri);
            }
        }
    }
    if !p.elements.is_empty() {
        println!("\n  Elements (values go in [setting.elements]):");
        for e in &p.elements {
            let mut facts = vec![e.kind.clone()];
            if e.required == Some(true) {
                facts.push("required".into());
            }
            match (e.min, e.max) {
                (Some(lo), Some(hi)) => facts.push(format!("{lo}..={hi}")),
                (Some(lo), None) => facts.push(format!(">= {lo}")),
                (None, Some(hi)) => facts.push(format!("<= {hi}")),
                _ => {}
            }
            if let Some(n) = e.max_length {
                facts.push(format!("max {n} chars"));
            }
            println!(
                "    {:<32} {}{}",
                e.id,
                facts.join(", "),
                e.label
                    .as_deref()
                    .map(|l| format!("  — {l}"))
                    .unwrap_or_default()
            );
            for i in &e.items {
                println!("      {:<8} {}", i.value, i.display);
            }
        }
    }
    if let Some(x) = &p.explain_text {
        println!("\n  {}", x.replace('\n', "\n  "));
    }
    if status(p) == "usable" {
        println!("\n  windows.toml:\n");
        for line in snippet.lines() {
            println!("    {line}");
        }
    }
    Ok(())
}

/// The `[[setting]]` entry `profile windows generate` takes for this policy.
///
/// Values come from [`AdmxElement::example_value`] — `true`, a number's
/// minimum, an enum's first choice — written as native TOML and commented
/// with what else each takes. A text or list element has no stand-in and is
/// written empty; `generate` refuses an empty required text, and every
/// element must be given, so the entry cannot deploy without a decision.
fn settings_entry(p: &WindowsAppPolicy) -> String {
    let mut s = format!(
        "[[setting]]\napp = {:?}\nkey = {:?}\n",
        p.template, p.policy_name
    );
    if p.class == "Both" {
        s.push_str("# channel = \"user\"   # Both: device unless asked\n");
    }
    if !p.elements.is_empty() {
        s.push_str("[setting.elements]\n");
        for e in &p.elements {
            let line = match (e.kind.as_str(), e.example_value()) {
                ("boolean", Some(v)) => format!("{} = {v}   # true or false", e.id),
                ("decimal" | "longDecimal", Some(v)) => match (e.min, e.max) {
                    (Some(lo), Some(hi)) => format!("{} = {v}   # {lo}..={hi}", e.id),
                    _ => format!("{} = {v}", e.id),
                },
                ("enum", Some(v)) => format!(
                    "{} = {v:?}   # one of {}",
                    e.id,
                    e.items
                        .iter()
                        .map(|i| i.value.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                ("multiText" | "list", _) => {
                    format!("{} = []   # {} — supply the strings", e.id, e.kind)
                }
                (_, Some(v)) => format!("{} = {v:?}", e.id),
                (_, None) => format!("{} = \"\"   # {} — supply a value", e.id, e.kind),
            };
            s.push_str(&line);
            s.push('\n');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_template_lists_and_every_usable_policy_has_an_entry() {
        let all = policies().unwrap();
        assert!(!all.is_empty(), "the dataset carries app policies");
        for p in all.iter().filter(|p| status(p) == "usable") {
            let entry = settings_entry(p);
            let parsed: toml::Value = toml::from_str(&entry).unwrap_or_else(|e| {
                panic!(
                    "{}/{}: entry is not TOML: {e}\n{entry}",
                    p.template, p.policy_name
                )
            });
            let setting = &parsed["setting"][0];
            assert_eq!(setting["app"].as_str(), Some(p.template.as_str()));
            assert_eq!(setting["key"].as_str(), Some(p.policy_name.as_str()));
        }
    }

    /// The snippet names a policy `generate` can find by the same spelling.
    #[test]
    fn the_entry_resolves_through_the_generator_lookup() {
        let all = policies().unwrap();
        let p = all
            .iter()
            .find(|p| p.template == "chrome" && p.policy_name == "DefaultCookiesSetting")
            .expect("chrome DefaultCookiesSetting is in the dataset");
        let entry: toml::Value = toml::from_str(&settings_entry(p)).unwrap();
        let s = &entry["setting"][0];
        let found = crate::windows::syncml::find_app_policy(
            &all,
            s["app"].as_str().unwrap(),
            s["key"].as_str().unwrap(),
        );
        assert_eq!(found.map(|f| &f.policy_name), Some(&p.policy_name));
    }
}
