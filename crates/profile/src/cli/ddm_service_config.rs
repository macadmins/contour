//! `profile ddm service-config` — build the zip a service-configuration-files
//! declaration points at, and re-point it when hosting moves.
//!
//! The decisions live in [`crate::ddm::service_config`] as pure functions;
//! this module is the I/O shell: read the staged tree, write the archive and
//! declarations, maintain the index.
//!
//! Declarations go through [`crate::ddm::compose::compose`] rather than being
//! assembled here, so identifier derivation, the org-domain refusal and the
//! asset-reference wiring are inherited rather than duplicated.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use colored::Colorize;
use serde_json::{Map, Value};

use crate::cli::ddm::{load_registry_opts, resolve_ddm_org_domain};
use crate::config::ProfileConfig;
use crate::ddm::compose::{
    Bundle, BundleActivation, BundleAsset, BundleConfiguration, BundleSubscriptions,
    ComposeOptions, compose,
};
use crate::ddm::predicate::extract_predicate_keys;
use crate::ddm::service_config::{
    RehostOutcome, SERVICE_CONFIG_TYPE, ServiceConfigEntry, ServiceConfigError, ServiceConfigIndex,
    UrlContext, expand_url, missing_expected_members, pack_and_hash, plan_rehost, resolve_service,
    verify_layout,
};
use crate::output::OutputMode;

/// Default template. `{base}` is the only part a provider migration touches,
/// and `{sha256}` makes the rest content-addressed, so the same bytes keep the
/// same URL suffix on every host they are served from.
pub const DEFAULT_URL_TEMPLATE: &str = "https://{base}/{sha256}/{name}";

/// Short name used for the intent and the archive file.
fn intent_for(service_type: &str, explicit: Option<&str>) -> String {
    if let Some(name) = explicit {
        return name.to_string();
    }
    // `com.apple.apache.httpd` → `apache-httpd`; `com.apple.sshd` → `sshd`.
    service_type
        .strip_prefix("com.apple.")
        .unwrap_or(service_type)
        .replace('.', "-")
}

/// Build the archive and its declarations from a staged directory.
#[expect(
    clippy::too_many_arguments,
    reason = "CLI shell carries the flag surface it describes"
)]
pub fn handle_build(
    source: &str,
    service_type: &str,
    base_url: Option<&str>,
    url_template: &str,
    intent: Option<&str>,
    predicate: Option<&str>,
    no_subscriptions: bool,
    org_flag: Option<&str>,
    output: Option<&str>,
    write: bool,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    let source_dir = Path::new(source);
    if !source_dir.is_dir() {
        bail!("staged directory not found: {source}");
    }

    // A documented Apple service brings layout rules; a third-party one does
    // not, and that is deliberate — any reverse-DNS type delivers files.
    let spec = resolve_service(service_type).map_err(|e| anyhow::anyhow!("{e}"))?;

    let Some(domain) = resolve_ddm_org_domain(org_flag, config) else {
        bail!(
            "organization domain is required\n  \
             • --org <domain>\n  \
             • CONTOUR_ORG\n  \
             • organization.domain in profile.toml or .contour/config.toml"
        );
    };

    let (entries, archive_bytes, hash) =
        pack_and_hash(source_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Layout first: an archive rooted one level too deep expands into a
    // directory the service never reads, and the declaration still reports
    // Verified. Refuse before anything is written.
    let mut warnings: Vec<String> = Vec::new();
    if let Some(spec) = spec {
        verify_layout(spec, &entries).map_err(|e| anyhow::anyhow!("{e}"))?;
        let missing = missing_expected_members(spec, &entries);
        if !missing.is_empty() {
            warnings.push(format!(
                "archive has no {} — the service reads ONLY what this archive \
                 provides and ignores its default directory, so a drop-in-only \
                 archive removes the main configuration. Include the full \
                 directory unless a minimal one is intended.",
                missing.join(", ")
            ));
        }
    } else {
        warnings.push(format!(
            "`{service_type}` is not a service Apple documents. The files WILL be \
             delivered and expanded, but nothing reads them unless the service \
             calls mcf_service_path_for_service_type, or something local points \
             at the managed path."
        ));
    }

    let name = intent_for(service_type, intent);
    let archive_name = format!("{name}.zip");

    // No --base-url yet is a legitimate state: the archive has to exist before
    // it can be uploaded. Emit a placeholder rather than an unusable URL, and
    // say so on every run.
    let base = base_url.unwrap_or("REPLACE-WITH-HOSTING-BASE").to_string();
    if base_url.is_none() {
        warnings.push(
            "no --base-url given: DataURL carries a REPLACE-WITH-HOSTING-BASE \
             placeholder. Upload the archive, then run `ddm service-config rehost` \
             with the real base."
                .to_string(),
        );
    }

    let ctx = UrlContext {
        base: base.clone(),
        sha256: hash.clone(),
        name: archive_name.clone(),
        service: service_type.to_string(),
    };
    let url = expand_url(url_template, &ctx).map_err(|e| anyhow::anyhow!("{e}"))?;

    let status_keys = predicate
        .map(|p| extract_predicate_keys(p).status)
        .unwrap_or_default();

    let mut config_payload: Map<String, Value> = Map::new();
    config_payload.insert(
        "ServiceType".to_string(),
        Value::String(service_type.to_string()),
    );

    let bundle = Bundle {
        intent_name: name.clone(),
        platforms: Vec::new(),
        asset: Some(BundleAsset {
            type_name: "com.apple.asset.data".to_string(),
            identifier: None,
            payload: Map::new(),
            // The archive is hashed here, not re-read by compose: this is the
            // one place that knows the bytes it just packed.
            zip: None,
            url: Some(url.clone()),
            auth: Some("none".to_string()),
            authentication: None,
        }),
        configuration: BundleConfiguration {
            type_name: SERVICE_CONFIG_TYPE.to_string(),
            identifier: None,
            asset_ref_field: None,
            payload: config_payload,
        },
        activation: predicate.map(|p| BundleActivation {
            type_name: None,
            identifier: None,
            predicate: Some(p.to_string()),
            references: None,
        }),
        subscriptions: (!no_subscriptions && !status_keys.is_empty()).then(|| {
            BundleSubscriptions {
                keys: status_keys.clone(),
                identifier: None,
            }
        }),
    };

    let registry = load_registry_opts(None, false)?;
    let mut bundle = bundle;
    // Fill the asset Reference from the bytes we packed, rather than letting
    // compose re-read a file from disk that may not be written yet in a dry run.
    if let Some(asset) = bundle.asset.as_mut() {
        let mut reference = Map::new();
        reference.insert(
            "ContentType".to_string(),
            Value::String("application/zip".to_string()),
        );
        reference.insert("DataURL".to_string(), Value::String(url.clone()));
        reference.insert("Hash-SHA-256".to_string(), Value::String(hash.clone()));
        asset
            .payload
            .insert("Reference".to_string(), Value::Object(reference));
    }

    let composed = compose(&bundle, &domain, &registry, &ComposeOptions::default())
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    let out_dir = PathBuf::from(output.unwrap_or("."));
    let archive_path = out_dir.join(&archive_name);

    let mut planned: Vec<(PathBuf, String, String)> = Vec::new();
    if let Some(asset) = &composed.asset {
        planned.push((
            out_dir.join(format!("{name}.asset.json")),
            serde_json::to_string_pretty(asset)?,
            asset.identifier.clone(),
        ));
    }
    planned.push((
        out_dir.join(format!("{name}.configuration.json")),
        serde_json::to_string_pretty(&composed.configuration)?,
        composed.configuration.identifier.clone(),
    ));
    if let Some(act) = &composed.activation {
        planned.push((
            out_dir.join(format!("{name}.activation.json")),
            serde_json::to_string_pretty(act)?,
            act.identifier.clone(),
        ));
    }
    if let Some(subs) = &composed.subscriptions {
        planned.push((
            out_dir.join(format!("{name}.subscriptions.json")),
            serde_json::to_string_pretty(subs)?,
            subs.identifier.clone(),
        ));
    }

    let asset_identifier = composed
        .asset
        .as_ref()
        .map(|a| a.identifier.clone())
        .unwrap_or_default();

    if write {
        std::fs::create_dir_all(&out_dir)?;
        std::fs::write(&archive_path, &archive_bytes)
            .with_context(|| format!("writing {}", archive_path.display()))?;
        for (path, body, _) in &planned {
            std::fs::write(path, format!("{body}\n"))
                .with_context(|| format!("writing {}", path.display()))?;
        }

        let index_path = out_dir.join(ServiceConfigIndex::FILE_NAME);
        let mut index: ServiceConfigIndex = std::fs::read_to_string(&index_path)
            .ok()
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default();
        index.upsert(ServiceConfigEntry {
            identifier: asset_identifier.clone(),
            service_type: service_type.to_string(),
            source: source.to_string(),
            archive: archive_name.clone(),
            sha256: hash.clone(),
            base: base.clone(),
            url_template: url_template.to_string(),
            url: url.clone(),
        });
        std::fs::write(&index_path, toml::to_string_pretty(&index)?)?;
    }

    report_build(
        &planned,
        &archive_path,
        entries.len(),
        &hash,
        &url,
        &warnings,
        write,
        output_mode,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "reporting mirrors what the build produced"
)]
fn report_build(
    planned: &[(PathBuf, String, String)],
    archive: &Path,
    file_count: usize,
    hash: &str,
    url: &str,
    warnings: &[String],
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    if output_mode == OutputMode::Json {
        let files: Vec<_> = planned
            .iter()
            .map(
                |(p, _, id)| serde_json::json!({"path": p.display().to_string(), "identifier": id}),
            )
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": !write,
                "archive": archive.display().to_string(),
                "files_in_archive": file_count,
                "sha256": hash,
                "data_url": url,
                "warnings": warnings,
                "files": files,
            }))?
        );
        return Ok(());
    }

    println!(
        "  {} {}  ({file_count} files)",
        "archive".bold(),
        archive.display()
    );
    println!("  {}  {hash}", "sha256 ".bold());
    println!("  {}     {url}", "url".bold());
    println!();
    for (path, _, id) in planned {
        println!("  ✓ {}  {id}", path.display());
    }
    println!();
    for w in warnings {
        println!("  {} {w}", "⚠".yellow());
    }
    if !warnings.is_empty() {
        println!();
    }
    if !write {
        println!("Dry run — no files written (pass --write to apply)");
    }
    println!("Deploy order: asset, then configuration.");
    Ok(())
}

/// Re-point every tracked asset at a new hosting base.
///
/// The artifact is not rebuilt. When the staged tree is still available the
/// hash is re-verified against the index, because a changed hash means this is
/// a republish wearing a move's clothes — and re-pointing would then publish a
/// URL whose content no longer matches what devices verify against.
pub fn handle_rehost(
    declarations: &str,
    new_base: &str,
    verify: bool,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let decl_dir = Path::new(declarations);
    let index_path = decl_dir.join(ServiceConfigIndex::FILE_NAME);
    let text = std::fs::read_to_string(&index_path).map_err(|e| {
        anyhow::anyhow!(
            "{} ({e})",
            ServiceConfigError::NoIndex {
                path: index_path.clone()
            }
        )
    })?;
    let mut index: ServiceConfigIndex = toml::from_str(&text)?;

    let mut outcomes = Vec::new();
    for entry in &index.entries.clone() {
        if verify {
            let source = Path::new(&entry.source);
            if source.is_dir() {
                let (_, _, current) = pack_and_hash(source).map_err(|e| anyhow::anyhow!("{e}"))?;
                if current != entry.sha256 {
                    bail!(
                        "{}",
                        ServiceConfigError::ContentMoved {
                            identifier: entry.identifier.clone(),
                            recorded: entry.sha256.clone(),
                            current,
                        }
                    );
                }
            }
        }

        let outcome = plan_rehost(entry, new_base).map_err(|e| anyhow::anyhow!("{e}"))?;
        if let RehostOutcome::Repointed { new_url, .. } = &outcome {
            let mut updated = entry.clone();
            updated.url = new_url.clone();
            updated.base = new_base.to_string();
            index.upsert(updated);
        }
        outcomes.push(outcome);
    }

    if write {
        for outcome in &outcomes {
            let RehostOutcome::Repointed { identifier, .. } = outcome else {
                continue;
            };
            let Some(entry) = index.get(identifier) else {
                continue;
            };
            rewrite_data_url(decl_dir, identifier, &entry.url, &entry.sha256)?;
        }
        std::fs::write(&index_path, toml::to_string_pretty(&index)?)?;
    }

    report_rehost(&outcomes, new_base, write, output_mode)
}

/// Rewrite `Payload.Reference.DataURL` in the asset declaration carrying
/// `identifier`, leaving every other key — `Hash-SHA-256` above all — alone.
///
/// The hash is re-asserted rather than rewritten: this function must be
/// incapable of changing what a device verifies against.
fn rewrite_data_url(dir: &Path, identifier: &str, url: &str, expect_hash: &str) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "json") {
            let text = std::fs::read_to_string(&path)?;
            let mut doc: Value = serde_json::from_str(&text)
                .with_context(|| format!("parsing {}", path.display()))?;
            if doc.get("Identifier").and_then(Value::as_str) != Some(identifier) {
                continue;
            }
            let Some(reference) = doc
                .get_mut("Payload")
                .and_then(|p| p.get_mut("Reference"))
                .and_then(Value::as_object_mut)
            else {
                continue;
            };
            let found = reference.get("Hash-SHA-256").and_then(Value::as_str);
            if found != Some(expect_hash) {
                bail!(
                    "{} carries hash {:?}, index says {expect_hash} — refusing to \
                     re-point a URL at content that does not match",
                    path.display(),
                    found.unwrap_or("<none>")
                );
            }
            reference.insert("DataURL".to_string(), Value::String(url.to_string()));
            std::fs::write(&path, format!("{}\n", serde_json::to_string_pretty(&doc)?))?;
            return Ok(());
        }
    }
    bail!(
        "no asset declaration with Identifier `{identifier}` under {}",
        dir.display()
    )
}

fn report_rehost(
    outcomes: &[RehostOutcome],
    new_base: &str,
    write: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let changed = outcomes.iter().filter(|o| o.changed()).count();

    if output_mode == OutputMode::Json {
        let rows: Vec<_> = outcomes
            .iter()
            .map(|o| match o {
                RehostOutcome::Unchanged { identifier } => {
                    serde_json::json!({"identifier": identifier, "changed": false})
                }
                RehostOutcome::Repointed {
                    identifier,
                    old_url,
                    new_url,
                } => serde_json::json!({
                    "identifier": identifier,
                    "changed": true,
                    "old_url": old_url,
                    "new_url": new_url,
                }),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "success": true,
                "dry_run": !write,
                "base": new_base,
                "repointed": changed,
                "entries": rows,
            }))?
        );
        return Ok(());
    }

    for outcome in outcomes {
        match outcome {
            RehostOutcome::Unchanged { identifier } => {
                println!("  • {identifier}  already on this base");
            }
            RehostOutcome::Repointed {
                identifier,
                new_url,
                ..
            } => {
                println!("  ✓ {identifier}  → {new_url}");
            }
        }
    }
    println!();
    if changed > 0 {
        println!(
            "  {} the archives are unchanged, so every Hash-SHA-256 stays as it was; \
             upload the same files to the new host before deploying.",
            "note:".bold()
        );
    }
    if !write {
        println!("Dry run — no files written (pass --write to apply)");
    }
    println!(
        "{changed} re-pointed, {} unchanged",
        outcomes.len() - changed
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intent_names_drop_the_apple_prefix_and_dots() {
        assert_eq!(intent_for("com.apple.sshd", None), "sshd");
        assert_eq!(intent_for("com.apple.apache.httpd", None), "apache-httpd");
        assert_eq!(
            intent_for("org.example.demoapp", None),
            "org-example-demoapp"
        );
        assert_eq!(
            intent_for("com.apple.sshd", Some("ssh-hardening")),
            "ssh-hardening"
        );
    }

    #[test]
    fn rewriting_a_url_refuses_when_the_hash_does_not_match() {
        // The guard that keeps a re-host from becoming a silent republish.
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(
            tmp.path().join("a.asset.json"),
            serde_json::to_string_pretty(&serde_json::json!({
                "Type": "com.apple.asset.data",
                "Identifier": "com.acme.asset.sshd",
                "Payload": {"Reference": {
                    "ContentType": "application/zip",
                    "DataURL": "https://old.example.org/x.zip",
                    "Hash-SHA-256": "aaaa"
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        let err = rewrite_data_url(
            tmp.path(),
            "com.acme.asset.sshd",
            "https://new.example.org/x.zip",
            "bbbb",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("refusing to re-point"),
            "got: {err}"
        );
    }

    #[test]
    fn rewriting_a_url_leaves_the_hash_untouched() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("a.asset.json");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&serde_json::json!({
                "Type": "com.apple.asset.data",
                "Identifier": "com.acme.asset.sshd",
                "Payload": {"Reference": {
                    "ContentType": "application/zip",
                    "DataURL": "https://acct.blob.core.windows.net/ddm/aaaa/sshd.zip",
                    "Hash-SHA-256": "aaaa"
                }}
            }))
            .unwrap(),
        )
        .unwrap();

        rewrite_data_url(
            tmp.path(),
            "com.acme.asset.sshd",
            "https://cdn.example.org/ddm/aaaa/sshd.zip",
            "aaaa",
        )
        .unwrap();

        let doc: Value = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let reference = &doc["Payload"]["Reference"];
        assert_eq!(
            reference["DataURL"].as_str().unwrap(),
            "https://cdn.example.org/ddm/aaaa/sshd.zip"
        );
        assert_eq!(reference["Hash-SHA-256"].as_str().unwrap(), "aaaa");
        assert_eq!(
            reference["ContentType"].as_str().unwrap(),
            "application/zip"
        );
    }
}
