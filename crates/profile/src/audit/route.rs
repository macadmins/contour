//! Triage routing: sort audited profiles into category subfolders.
//!
//! A profile is assigned to every category bucket it matches (certs, secrets,
//! binary, or clean). [`plan_moves`] turns those assignments into concrete
//! destination paths — disambiguating basename collisions within a bucket — and
//! [`execute_move`] performs a move-with-fan-out: copy into each destination,
//! then remove the source only after every copy succeeds.

use std::path::{Path, PathBuf};

use super::ProfileAudit;

/// A destination category for a routed profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    Certs,
    Secrets,
    Binary,
    Clean,
}

impl Bucket {
    /// Subfolder name for this bucket.
    pub fn dir_name(self) -> &'static str {
        match self {
            Bucket::Certs => "certs",
            Bucket::Secrets => "secrets",
            Bucket::Binary => "binary",
            Bucket::Clean => "clean",
        }
    }
}

/// Compute the buckets a profile belongs to.
///
/// With neither focus flag set, a profile lands in every matching category, or
/// `[Clean]` when nothing is flagged. `certs_only`/`secrets_only` restrict the
/// result to that single category (and yield an empty list when the profile
/// does not match it, so it is not routed at all).
pub fn buckets_for(audit: &ProfileAudit, certs_only: bool, secrets_only: bool) -> Vec<Bucket> {
    if certs_only {
        return if audit.has_certs() {
            vec![Bucket::Certs]
        } else {
            vec![]
        };
    }
    if secrets_only {
        return if audit.has_secrets() {
            vec![Bucket::Secrets]
        } else {
            vec![]
        };
    }

    let mut buckets = Vec::new();
    if audit.has_certs() {
        buckets.push(Bucket::Certs);
    }
    if audit.has_secrets() {
        buckets.push(Bucket::Secrets);
    }
    if audit.has_noncert_binary() {
        buckets.push(Bucket::Binary);
    }
    if buckets.is_empty() {
        buckets.push(Bucket::Clean);
    }
    buckets
}

/// A planned move: copy `source` into every path in `destinations`, then delete
/// `source`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedMove {
    pub source: PathBuf,
    pub destinations: Vec<PathBuf>,
}

/// Build destination paths under `dest_root` for each `(source, buckets)` item.
///
/// When two distinct source files share a basename within the same bucket, both
/// are disambiguated by inserting a short hash of their source path so nothing
/// is silently overwritten.
pub fn plan_moves(items: &[(PathBuf, Vec<Bucket>)], dest_root: &Path) -> Vec<PlannedMove> {
    use std::collections::HashMap;

    // First pass: which (bucket, basename) pairs are claimed by >1 source?
    let mut counts: HashMap<(Bucket, String), usize> = HashMap::new();
    for (source, buckets) in items {
        let base = basename(source);
        for &b in buckets {
            *counts.entry((b, base.clone())).or_insert(0) += 1;
        }
    }

    items
        .iter()
        .map(|(source, buckets)| {
            let base = basename(source);
            let destinations = buckets
                .iter()
                .map(|&b| {
                    let collides = counts.get(&(b, base.clone())).copied().unwrap_or(0) > 1;
                    let file_name = if collides {
                        disambiguated_name(source)
                    } else {
                        base.clone()
                    };
                    dest_root.join(b.dir_name()).join(file_name)
                })
                .collect();
            PlannedMove {
                source: source.clone(),
                destinations,
            }
        })
        .collect()
}

/// Execute a planned move: copy into every destination, then remove the source.
///
/// The source is removed only after all copies succeed, so a failure partway
/// through leaves the original intact.
///
/// # Errors
/// Returns the first I/O error from creating a destination directory, copying,
/// or removing the source.
pub fn execute_move(plan: &PlannedMove) -> std::io::Result<()> {
    for dest in &plan.destinations {
        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::copy(&plan.source, dest)?;
    }
    std::fs::remove_file(&plan.source)?;
    Ok(())
}

/// The file name component of a path, lossily, as an owned string.
fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `stem.<hash>.ext` (or `stem.<hash>` with no extension), using a short FNV-1a
/// hash of the full source path so distinct sources never collide.
fn disambiguated_name(source: &Path) -> String {
    let hash = short_hash(&source.to_string_lossy());
    let stem = source
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    match source.extension() {
        Some(ext) => format!("{stem}.{hash}.{}", ext.to_string_lossy()),
        None => format!("{stem}.{hash}"),
    }
}

/// Short (6 hex char) FNV-1a hash of `s`.
fn short_hash(s: &str) -> String {
    // FNV-1a 32-bit. Deterministic across runs/platforms (std's DefaultHasher
    // is not), which keeps routed filenames stable and testable.
    let mut h: u32 = 0x811c_9dc5;
    for b in s.bytes() {
        h ^= u32::from(b);
        h = h.wrapping_mul(0x0100_0193);
    }
    format!("{h:08x}")[..6].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::cert::{CertInfo, CertKind};
    use crate::audit::{BinaryInfo, PayloadAudit, SecretFinding, SecretKind};

    fn binary(present: bool) -> BinaryInfo {
        BinaryInfo {
            present,
            fields: if present { vec!["Font".into()] } else { vec![] },
            bytes: if present { 16 } else { 0 },
        }
    }

    fn cert() -> CertInfo {
        CertInfo {
            kind: CertKind::Root,
            subject_cn: Some("Acme Root CA".into()),
            issuer_cn: Some("Acme Root CA".into()),
            self_signed: true,
            is_ca: true,
            not_after: None,
            expired: false,
            serial: "01".into(),
        }
    }

    fn secret() -> SecretFinding {
        SecretFinding {
            field: "Password".into(),
            kind: SecretKind::KnownSensitive,
            token: None,
            entropy: None,
        }
    }

    /// Build a ProfileAudit whose flags match the requested categories.
    fn audit(has_cert: bool, has_secret: bool, has_binary: bool) -> ProfileAudit {
        let mut payloads = Vec::new();
        if has_cert {
            payloads.push(PayloadAudit {
                index: 0,
                r#type: "com.apple.security.root".into(),
                identifier: "p.cert".into(),
                display_name: None,
                binary: binary(true), // cert bytes are binary, but cert wins the bucket
                cert: Some(cert()),
                secrets: vec![],
            });
        }
        if has_secret {
            payloads.push(PayloadAudit {
                index: 1,
                r#type: "com.apple.wifi.managed".into(),
                identifier: "p.wifi".into(),
                display_name: None,
                binary: binary(false),
                cert: None,
                secrets: vec![secret()],
            });
        }
        if has_binary {
            payloads.push(PayloadAudit {
                index: 2,
                r#type: "com.apple.font".into(),
                identifier: "p.font".into(),
                display_name: None,
                binary: binary(true),
                cert: None,
                secrets: vec![],
            });
        }
        ProfileAudit {
            path: "p.mobileconfig".into(),
            display_name: "P".into(),
            identifier: "p".into(),
            organization: None,
            signed: false,
            payloads,
        }
    }

    #[test]
    fn cert_and_secret_profile_routes_to_both() {
        let buckets = buckets_for(&audit(true, true, false), false, false);
        assert_eq!(buckets, vec![Bucket::Certs, Bucket::Secrets]);
    }

    #[test]
    fn clean_profile_routes_to_clean() {
        let buckets = buckets_for(&audit(false, false, false), false, false);
        assert_eq!(buckets, vec![Bucket::Clean]);
    }

    #[test]
    fn font_only_profile_routes_to_binary() {
        let buckets = buckets_for(&audit(false, false, true), false, false);
        assert_eq!(buckets, vec![Bucket::Binary]);
    }

    #[test]
    fn certs_only_filter_restricts_buckets() {
        assert_eq!(
            buckets_for(&audit(true, true, false), true, false),
            vec![Bucket::Certs]
        );
        assert_eq!(
            buckets_for(&audit(false, true, false), true, false),
            Vec::<Bucket>::new()
        );
    }

    #[test]
    fn plan_disambiguates_basename_collision_in_same_bucket() {
        let root = Path::new("/triage");
        let items = vec![
            (PathBuf::from("/a/wifi.mobileconfig"), vec![Bucket::Certs]),
            (PathBuf::from("/b/wifi.mobileconfig"), vec![Bucket::Certs]),
        ];
        let plans = plan_moves(&items, root);
        let d0 = &plans[0].destinations[0];
        let d1 = &plans[1].destinations[0];
        assert_ne!(d0, d1, "collision must produce distinct names");
        assert!(d0.starts_with("/triage/certs"));
        assert!(d1.starts_with("/triage/certs"));
    }

    #[test]
    fn plan_keeps_plain_basename_when_no_collision() {
        let root = Path::new("/triage");
        let items = vec![(PathBuf::from("/a/wifi.mobileconfig"), vec![Bucket::Secrets])];
        let plans = plan_moves(&items, root);
        assert_eq!(
            plans[0].destinations[0],
            PathBuf::from("/triage/secrets/wifi.mobileconfig")
        );
    }

    #[test]
    fn execute_copies_to_all_buckets_then_removes_source() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("p.mobileconfig");
        std::fs::write(&src, b"hello").unwrap();
        let dest_root = tmp.path().join("triage");
        let plan = PlannedMove {
            source: src.clone(),
            destinations: vec![
                dest_root.join("certs/p.mobileconfig"),
                dest_root.join("secrets/p.mobileconfig"),
            ],
        };
        execute_move(&plan).unwrap();

        assert!(!src.exists(), "source removed after move");
        assert_eq!(
            std::fs::read(dest_root.join("certs/p.mobileconfig")).unwrap(),
            b"hello"
        );
        assert_eq!(
            std::fs::read(dest_root.join("secrets/p.mobileconfig")).unwrap(),
            b"hello"
        );
    }
}
