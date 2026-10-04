//! `contour app manifest` — app code identities as a first-class artifact.
//!
//! `Privacy.PermissionDefaults` is keyed by bundle id plus designated
//! requirement; `Allowed.AllowedBinaries` by `TeamID`, `SigningID` or
//! `CDHash`. A wrong requirement yields a declaration that reports Verified
//! and manages nothing, and only **19 of 55** locally scanned apps
//! reconstruct their requirement from the Developer ID template — the
//! requirement encodes the certificate chain. So the requirement is read
//! from the binary with `codesign`, never synthesised, and this crate makes
//! the result something a tool without `codesign` — a CI job, a web
//! composer, a Linux host — can consume.
//!
//! Two tables, because the facts have two lifetimes: **identity** is stable
//! across builds of an app (signing id × team id × requirement);
//! **builds** is one row per architecture slice and changes with every
//! release (the CDHash). JSON carries both nested; the Parquet pair keeps
//! them apart.
//!
//! One unreadable bundle costs one entry in `failed[]`, not the scan.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Serialize;

pub mod cli;

/// Contract version of the manifest document.
pub const MANIFEST_VERSION: &str = "1";

/// One app, as `codesign` and `Info.plist` describe it. Every field is
/// observed; nothing here is inferred from a template.
#[derive(Debug, Clone, Serialize)]
pub struct AppIdentity {
    pub name: String,
    pub bundle_id: String,
    pub path: String,
    /// `CFBundleShortVersionString`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// `CFBundleVersion` — the build number.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build: Option<String>,
    /// Bare signing identifier — Apple's `SigningID` shape.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_id: Option<String>,
    /// `*APPLE*` for Apple platform binaries; absent when ad-hoc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// Apple's `SigningState` value, plus `adhoc` / `unknown` where the
    /// chain does not say. Never guessed: `leaf_authority` is beside it so
    /// a reader can check the classification.
    pub signing_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leaf_authority: Option<String>,
    /// Exactly as `codesign -d -r-` printed it.
    pub designated_requirement: String,
    /// Code directory hash per slice, keyed as `codesign` names them.
    pub cdhash: BTreeMap<String, String>,
    /// Always `observed`. The field exists so a consumer merging manifests
    /// from several sources can tell a read requirement from a
    /// reconstructed one.
    pub provenance: &'static str,
}

/// One input that could not be read.
#[derive(Debug, Clone, Serialize)]
pub struct Failed {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Counts {
    pub apps: usize,
    pub failed: usize,
    /// Rows the `builds` table would have — one per slice.
    pub slices: usize,
}

/// The whole document.
#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub manifest_version: &'static str,
    pub generated: String,
    /// The paths the caller asked to scan, as given.
    pub sources: Vec<String>,
    pub apps: Vec<AppIdentity>,
    pub failed: Vec<Failed>,
    pub counts: Counts,
}

/// Above this many apps the artifact goes to Parquet by default: JSON is
/// still valid but a 2,000-row nested document is nobody's preferred input.
pub const PARQUET_THRESHOLD: usize = 2_000;

/// Find every `.app` bundle under `sources` (a bundle given directly counts
/// as itself), read each, and keep the failures.
pub fn scan(sources: &[PathBuf], generated: String) -> Result<Manifest> {
    let mut bundles: Vec<PathBuf> = Vec::new();
    let mut failed: Vec<Failed> = Vec::new();
    for s in sources {
        if s.extension().is_some_and(|e| e == "app") {
            bundles.push(s.clone());
        } else if s.is_dir() {
            contour_core::app_discovery::find_apps_recursive(s, &mut bundles)
                .with_context(|| format!("scanning {}", s.display()))?;
        } else {
            failed.push(Failed {
                path: s.display().to_string(),
                reason: if s.exists() {
                    "not an .app bundle or a directory".into()
                } else {
                    "no such path".into()
                },
            });
        }
    }
    bundles.sort();
    bundles.dedup();

    let mut apps = Vec::new();
    for b in &bundles {
        match read_app(b) {
            Ok(a) => apps.push(a),
            Err(e) => failed.push(Failed {
                path: b.display().to_string(),
                // codesign's errors arrive as several lines with a blank
                // stdout; one line reads better in a table and in JSON.
                reason: e
                    .to_string()
                    .lines()
                    .map(str::trim)
                    .filter(|l| !l.is_empty() && *l != "stdout:")
                    .collect::<Vec<_>>()
                    .join(" — "),
            }),
        }
    }
    apps.sort_by(|a, b| a.bundle_id.cmp(&b.bundle_id).then(a.path.cmp(&b.path)));

    let slices = apps.iter().map(|a| a.cdhash.len()).sum();
    Ok(Manifest {
        manifest_version: MANIFEST_VERSION,
        generated,
        sources: sources.iter().map(|p| p.display().to_string()).collect(),
        counts: Counts {
            apps: apps.len(),
            failed: failed.len(),
            slices,
        },
        apps,
        failed,
    })
}

/// One bundle. The requirement is read first: an app without one is not
/// worth the rest, and the error names why.
pub fn read_app(path: &Path) -> Result<AppIdentity> {
    if !path.exists() {
        anyhow::bail!("no such path");
    }
    let requirement =
        contour_core::get_code_requirement(path).map_err(|e| anyhow::anyhow!("{e}"))?;
    if requirement.trim().is_empty() {
        anyhow::bail!("codesign reported no designated requirement (unsigned?)");
    }
    let bundle_id = contour_core::get_bundle_id(path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let identity = contour_core::read_code_identity(path).map_err(|e| anyhow::anyhow!("{e}"))?;
    let (version, build) = contour_core::get_bundle_versions(path);

    Ok(AppIdentity {
        name: contour_core::get_app_name(path),
        bundle_id,
        path: path.display().to_string(),
        version,
        build,
        signing_id: identity.signing_id,
        team_id: identity.team_id,
        signing_state: identity.signing_state.as_str().to_string(),
        leaf_authority: identity.authorities.first().cloned(),
        designated_requirement: requirement.trim().to_string(),
        cdhash: identity
            .slices
            .into_iter()
            .map(|s| (s.arch, s.cdhash))
            .collect(),
        provenance: "observed",
    })
}

// ---------------------------------------------------------------------------
// Parquet
// ---------------------------------------------------------------------------

/// Write the two tables beside `stem`: `<stem>.identity.parquet` and
/// `<stem>.builds.parquet`. Returns the two paths.
pub fn write_parquet(m: &Manifest, stem: &Path) -> Result<(PathBuf, PathBuf)> {
    use arrow::array::{ArrayRef, StringArray};
    use arrow::datatypes::{DataType, Field, Schema};
    use arrow::record_batch::RecordBatch;
    use parquet::arrow::ArrowWriter;
    use std::sync::Arc;

    fn col<I: IntoIterator<Item = Option<String>>>(v: I) -> ArrayRef {
        Arc::new(StringArray::from(v.into_iter().collect::<Vec<_>>()))
    }
    fn s(v: &str) -> Option<String> {
        Some(v.to_string())
    }
    fn write(path: &Path, schema: Schema, cols: Vec<ArrayRef>) -> Result<()> {
        let schema = Arc::new(schema);
        let batch = RecordBatch::try_new(Arc::clone(&schema), cols)?;
        let file =
            std::fs::File::create(path).with_context(|| format!("creating {}", path.display()))?;
        let mut w = ArrowWriter::try_new(file, schema, None)?;
        w.write(&batch)?;
        w.close()?;
        Ok(())
    }
    let field = |n: &str| Field::new(n, DataType::Utf8, true);

    let identity_path = stem.with_extension("identity.parquet");
    write(
        &identity_path,
        Schema::new(vec![
            field("bundle_id"),
            field("name"),
            field("path"),
            field("version"),
            field("build"),
            field("signing_id"),
            field("team_id"),
            field("signing_state"),
            field("leaf_authority"),
            field("designated_requirement"),
            field("provenance"),
            field("generated"),
        ]),
        vec![
            col(m.apps.iter().map(|a| s(&a.bundle_id))),
            col(m.apps.iter().map(|a| s(&a.name))),
            col(m.apps.iter().map(|a| s(&a.path))),
            col(m.apps.iter().map(|a| a.version.clone())),
            col(m.apps.iter().map(|a| a.build.clone())),
            col(m.apps.iter().map(|a| a.signing_id.clone())),
            col(m.apps.iter().map(|a| a.team_id.clone())),
            col(m.apps.iter().map(|a| s(&a.signing_state))),
            col(m.apps.iter().map(|a| a.leaf_authority.clone())),
            col(m.apps.iter().map(|a| s(&a.designated_requirement))),
            col(m.apps.iter().map(|a| s(a.provenance))),
            col(m.apps.iter().map(|_| s(&m.generated))),
        ],
    )?;

    let rows: Vec<(&AppIdentity, &String, &String)> = m
        .apps
        .iter()
        .flat_map(|a| a.cdhash.iter().map(move |(arch, h)| (a, arch, h)))
        .collect();
    let builds_path = stem.with_extension("builds.parquet");
    write(
        &builds_path,
        Schema::new(vec![
            field("bundle_id"),
            field("path"),
            field("version"),
            field("build"),
            field("arch"),
            field("cdhash"),
        ]),
        vec![
            col(rows.iter().map(|(a, _, _)| s(&a.bundle_id))),
            col(rows.iter().map(|(a, _, _)| s(&a.path))),
            col(rows.iter().map(|(a, _, _)| a.version.clone())),
            col(rows.iter().map(|(a, _, _)| a.build.clone())),
            col(rows.iter().map(|(_, arch, _)| s(arch))),
            col(rows.iter().map(|(_, _, h)| s(h))),
        ],
    )?;
    Ok((identity_path, builds_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> String {
        "2026-09-23T00:00:00Z".to_string()
    }

    /// R9's acceptance case: one broken bundle beside a readable one — exit
    /// 0, the readable one in `apps[]`, the broken one named in `failed[]`.
    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "needs /System/Applications/Calculator.app as a readable fixture — run with \
                --include-ignored on a Mac"]
    fn a_broken_bundle_costs_one_entry_not_the_scan() {
        let calc = PathBuf::from("/System/Applications/Calculator.app");
        assert!(
            calc.exists(),
            "asked to run (--include-ignored) but Calculator.app is not on this host"
        );
        let tmp = tempfile::tempdir().unwrap();
        let broken = tmp.path().join("Broken.app");
        std::fs::create_dir_all(broken.join("Contents")).unwrap(); // no Info.plist, no signature

        let m = scan(&[calc.clone(), broken.clone()], now()).unwrap();
        assert_eq!(m.counts.apps, 1, "{m:?}");
        assert_eq!(m.counts.failed, 1);
        assert_eq!(m.failed[0].path, broken.display().to_string());

        let a = &m.apps[0];
        assert_eq!(a.bundle_id, "com.apple.calculator");
        assert_eq!(a.team_id.as_deref(), Some("*APPLE*"));
        assert_eq!(a.signing_state, "Apple");
        assert!(
            a.designated_requirement
                .starts_with("identifier \"com.apple.calculator\"")
        );
        assert!(!a.cdhash.is_empty(), "every slice must be present");
        assert_eq!(a.provenance, "observed");
        assert!(a.version.is_some());
    }

    #[test]
    fn missing_paths_are_failures_not_errors() {
        let m = scan(&[PathBuf::from("/definitely/not/here.app")], now()).unwrap();
        assert_eq!(m.counts.apps, 0);
        assert_eq!(m.failed.len(), 1);
        assert!(
            m.failed[0].reason.contains("no such path"),
            "{:?}",
            m.failed[0]
        );
    }

    #[test]
    fn parquet_pair_round_trips_row_counts() {
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        let app = |id: &str, slices: &[(&str, &str)]| AppIdentity {
            name: id.into(),
            bundle_id: id.into(),
            path: format!("/Applications/{id}.app"),
            version: Some("1.0".into()),
            build: None,
            signing_id: Some(id.into()),
            team_id: Some("ABCDE12345".into()),
            signing_state: "DeveloperID".into(),
            leaf_authority: Some("Developer ID Application: X (ABCDE12345)".into()),
            designated_requirement: format!("identifier \"{id}\" and anchor apple generic"),
            cdhash: slices
                .iter()
                .map(|(a, h)| (String::from(*a), String::from(*h)))
                .collect(),
            provenance: "observed",
        };
        let apps = vec![
            app("com.a", &[("arm64", "a1"), ("x86_64", "a2")]),
            app("com.b", &[("arm64", "b1")]),
        ];
        let m = Manifest {
            manifest_version: MANIFEST_VERSION,
            generated: now(),
            sources: vec!["/Applications".into()],
            counts: Counts {
                apps: 2,
                failed: 0,
                slices: 3,
            },
            apps,
            failed: vec![],
        };
        let tmp = tempfile::tempdir().unwrap();
        let (id_path, builds_path) = write_parquet(&m, &tmp.path().join("apps")).unwrap();
        let rows = |p: &Path| -> usize {
            let f = std::fs::File::open(p).unwrap();
            ParquetRecordBatchReaderBuilder::try_new(f)
                .unwrap()
                .build()
                .unwrap()
                .map(|b| b.unwrap().num_rows())
                .sum()
        };
        assert_eq!(rows(&id_path), 2, "one identity row per app");
        assert_eq!(rows(&builds_path), 3, "one build row per slice");
        assert!(id_path.to_string_lossy().ends_with("apps.identity.parquet"));
    }
}
