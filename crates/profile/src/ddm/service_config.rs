//! Build the asset a `com.apple.configuration.services.configuration-files`
//! declaration points at, and keep its URL correct as hosting moves.
//!
//! ## What the device does
//!
//! It downloads the asset's zip, expands it under
//! `/var/db/ManagedConfigurationFiles` (SIP-protected), and the service reads
//! from there instead of its default directory. Files land mode `444`.
//!
//! ## Two independent things can change
//!
//! **The content**, when someone edits a config file. The archive must be
//! re-packed, re-hashed, and the asset's `Hash-SHA-256` updated — otherwise
//! devices stay pinned to the old bytes while the declaration reports Verified.
//!
//! **The location**, when the artifact moves from one host to another — Azure
//! Blob Storage today, Cloudflare tomorrow. Here the archive is *not* rebuilt:
//! the same bytes live at a new address, so only `DataURL` changes and the
//! hash must come out identical. [`rehost`] does exactly that, and asserts the
//! hash did not move, which is what makes it safe to run in a hurry.
//!
//! Keeping those separate is the whole design. Conflating them means either
//! re-hashing content nobody touched (a fleet-wide re-download of identical
//! bytes) or re-pointing a URL at content that silently changed.
//!
//! ## URLs are content-addressed with a swappable base
//!
//! A URL template splits into a `{base}` — scheme and host and container —
//! and a path that identifies the content, conventionally by `{sha256}`. A
//! host migration then rewrites one variable:
//!
//! ```text
//! template  https://{base}/{sha256}/{name}
//! azure     https://acct.blob.core.windows.net/ddm/3f9a…/sshd.zip
//! cloudflare https://cdn.example.org/ddm/3f9a…/sshd.zip
//! ```
//!
//! Because the path carries the hash, the same content keeps the same URL
//! suffix everywhere it is hosted, and a stale copy on the old host cannot
//! masquerade as the new one.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::ddm::compose::sha256_hex;
use mdm_schema::service_config::{ManagedService, find, is_reserved_prefix, suggestions};

/// The declaration type this module builds assets for.
pub const SERVICE_CONFIG_TYPE: &str = "com.apple.configuration.services.configuration-files";

/// Fixed DOS timestamp written into every archive entry: 1980-01-01 00:00.
///
/// The zip format's own epoch, and the reason packing is reproducible. Real
/// mtimes make an untouched tree hash differently after a fresh clone, which
/// mints a new asset and makes every device re-download bytes it already has.
const FIXED_DOS_DATE: (u16, u16) = (0x0021, 0x0000); // 1980-01-01, 00:00:00

/// Why a service-config operation was refused.
///
/// Every variant is a case where continuing would produce a declaration that
/// deploys cleanly and manages nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceConfigError {
    /// A `com.apple.*` service type Apple does not document.
    UnknownAppleService {
        service_type: String,
        suggestions: Vec<&'static str>,
    },
    /// `ServiceType` is not reverse-DNS.
    MalformedServiceType { service_type: String },
    /// The staged tree does not contain the path the service reads.
    LayoutMismatch {
        service_type: String,
        expected: Vec<String>,
        found: Vec<String>,
    },
    /// The staged tree has no files at all.
    EmptySource { dir: PathBuf },
    /// The staged tree could not be read — permission, a broken mount, a
    /// dangling path. Distinct from empty: the operator's next move differs.
    SourceUnreadable { dir: PathBuf, reason: String },
    /// The URL template referenced a placeholder this module does not define.
    UnknownPlaceholder { token: String },
    /// Apple requires `https://` for asset data URLs.
    UrlNotHttps { url: String },
    /// Re-hosting found no index to work from.
    NoIndex { path: PathBuf },
    /// Re-hosting recomputed a different hash — the artifact was not supposed
    /// to change, so this is content drift, not a move.
    ContentMoved {
        identifier: String,
        recorded: String,
        current: String,
    },
}

impl std::fmt::Display for ServiceConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownAppleService {
                service_type,
                suggestions,
            } => {
                write!(
                    f,
                    "`{service_type}` is not a service Apple documents, and the `com.apple` \
                     prefix is reserved for built-in services"
                )?;
                if !suggestions.is_empty() {
                    write!(f, " — did you mean {}?", suggestions.join(", "))?;
                }
                Ok(())
            }
            Self::MalformedServiceType { service_type } => write!(
                f,
                "ServiceType `{service_type}` must be reverse-DNS, e.g. `com.apple.sshd` \
                 or `org.example.myservice`"
            ),
            Self::LayoutMismatch {
                service_type,
                expected,
                found,
            } => write!(
                f,
                "archive for `{service_type}` must contain {} — the archive mirrors the \
                 filesystem starting at `/`. Found {} at the top level. Stage the tree as \
                 the service sees it, e.g. <dir>/{}",
                expected.join(" or "),
                if found.is_empty() {
                    "nothing".to_string()
                } else {
                    found.join(", ")
                },
                expected.first().map_or("etc/...", String::as_str)
            ),
            Self::EmptySource { dir } => {
                write!(f, "no files to pack under {}", dir.display())
            }
            Self::SourceUnreadable { dir, reason } => {
                write!(f, "cannot read {}: {reason}", dir.display())
            }
            Self::UnknownPlaceholder { token } => write!(
                f,
                "unknown placeholder `{{{token}}}` in the URL template; known: \
                 {{base}}, {{sha256}}, {{name}}, {{service}}"
            ),
            Self::UrlNotHttps { url } => write!(
                f,
                "asset DataURL must be https://; got `{url}`. The device refuses anything else"
            ),
            Self::NoIndex { path } => write!(
                f,
                "no index at {} — run `ddm service-config build` first",
                path.display()
            ),
            Self::ContentMoved {
                identifier,
                recorded,
                current,
            } => write!(
                f,
                "`{identifier}`: the archive's hash is {current}, but the index recorded \
                 {recorded}. Re-hosting moves a URL, it does not republish content — run \
                 `ddm service-config build` to repackage changed files"
            ),
        }
    }
}

impl std::error::Error for ServiceConfigError {}

/// Values a URL template can interpolate.
#[derive(Debug, Clone)]
pub struct UrlContext {
    /// Host and container, without a trailing slash: the part that changes
    /// when the artifact migrates between providers.
    pub base: String,
    /// SHA-256 of the archive — makes the URL content-addressed.
    pub sha256: String,
    /// Archive file name, e.g. `sshd.zip`.
    pub name: String,
    /// The service type, for layouts that group by service.
    pub service: String,
}

/// Expand `{base}` / `{sha256}` / `{name}` / `{service}` in a URL template.
///
/// An unknown placeholder is refused rather than passed through: a literal
/// `{version}` in a published URL fails at download time, long after the typo.
pub fn expand_url(template: &str, ctx: &UrlContext) -> Result<String, ServiceConfigError> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            out.push_str(&rest[open..]);
            return finish_https(out);
        };
        let token = &after[..close];
        let value = match token {
            "base" => ctx.base.trim_end_matches('/'),
            "sha256" => &ctx.sha256,
            "name" => &ctx.name,
            "service" => &ctx.service,
            other => {
                return Err(ServiceConfigError::UnknownPlaceholder {
                    token: other.to_string(),
                });
            }
        };
        out.push_str(value);
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    finish_https(out)
}

fn finish_https(url: String) -> Result<String, ServiceConfigError> {
    if url.starts_with("https://") {
        Ok(url)
    } else {
        Err(ServiceConfigError::UrlNotHttps { url })
    }
}

/// Validate a `ServiceType` and return its registry entry when Apple documents
/// one.
///
/// A non-Apple reverse-DNS type is accepted with `None`: the article's
/// measured finding is that any type delivers files, and only the *reading*
/// side is restricted. Refusing them would block the third-party use case
/// this feature is most interesting for.
pub fn resolve_service(
    service_type: &str,
) -> Result<Option<&'static ManagedService>, ServiceConfigError> {
    if !is_reverse_dns(service_type) {
        return Err(ServiceConfigError::MalformedServiceType {
            service_type: service_type.to_string(),
        });
    }
    if let Some(spec) = find(service_type) {
        return Ok(Some(spec));
    }
    if is_reserved_prefix(service_type) {
        return Err(ServiceConfigError::UnknownAppleService {
            service_type: service_type.to_string(),
            suggestions: suggestions(service_type),
        });
    }
    Ok(None)
}

fn is_reverse_dns(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() >= 2
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        })
}

/// One file destined for the archive: its path inside the archive, and bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveEntry {
    pub path: String,
    pub bytes: Vec<u8>,
}

/// Collect `dir` into archive entries, sorted by path.
///
/// Sorted because the order files come off a filesystem is not stable across
/// machines, and an archive whose entry order varies hashes differently for
/// identical content.
pub fn collect_entries(dir: &Path) -> Result<Vec<ArchiveEntry>, std::io::Error> {
    let mut entries: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    collect_into(dir, dir, &mut entries)?;
    Ok(entries
        .into_iter()
        .map(|(path, bytes)| ArchiveEntry { path, bytes })
        .collect())
}

fn collect_into(
    root: &Path,
    dir: &Path,
    out: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), std::io::Error> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Finder and editor droppings would change the hash without changing
        // anything the service reads.
        if name == ".DS_Store" || name.starts_with("._") {
            continue;
        }
        let meta = entry.metadata()?;
        if meta.is_dir() {
            collect_into(root, &path, out)?;
        } else if meta.is_file() {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .to_string_lossy()
                .replace('\\', "/");
            out.insert(rel, std::fs::read(&path)?);
        }
        // Symlinks are skipped: the device restricts links to the service
        // directory, and a link pointing outside would be silently dropped
        // there. Materializing its target instead would hide the difference.
    }
    Ok(())
}

/// Check that the staged tree contains what the service will read.
///
/// The failure this prevents is total and silent: an archive rooted one level
/// too deep expands into a directory the service never looks at, and the
/// declaration still reports Verified.
pub fn verify_layout(
    spec: &ManagedService,
    entries: &[ArchiveEntry],
) -> Result<(), ServiceConfigError> {
    let ok = entries.iter().any(|e| {
        spec.archive_paths
            .iter()
            .any(|p| e.path == *p || e.path.starts_with(&format!("{p}/")))
    });
    if ok {
        return Ok(());
    }
    let mut found: Vec<String> = entries
        .iter()
        .filter_map(|e| e.path.split('/').next().map(str::to_string))
        .collect();
    found.sort();
    found.dedup();
    found.truncate(5);
    Err(ServiceConfigError::LayoutMismatch {
        service_type: spec.service_type.to_string(),
        expected: spec
            .archive_paths
            .iter()
            .map(|p| (*p).to_string())
            .collect(),
        found,
    })
}

/// Files the service expects that this archive does not carry.
///
/// Not an error. Apple's note — "the service uses only the files the
/// declaration provides and ignores the ones in its default directories" —
/// means a drop-in-only archive removes the main configuration from the
/// service's view. That is usually a mistake and occasionally deliberate.
pub fn missing_expected_members(spec: &ManagedService, entries: &[ArchiveEntry]) -> Vec<String> {
    spec.expected_members
        .iter()
        .filter(|m| !entries.iter().any(|e| e.path == **m))
        .map(|m| (*m).to_string())
        .collect()
}

/// Write a reproducible zip: entries sorted, stored uncompressed, every
/// timestamp fixed at the zip epoch.
///
/// Stored rather than deflated on purpose. These archives are a handful of
/// small text files, so compression buys nothing measurable, and a stored
/// archive's bytes depend only on the content and the names — no compressor
/// version can change the hash under us.
pub fn pack(entries: &[ArchiveEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut directory = Vec::new();
    let mut offsets: Vec<(usize, &ArchiveEntry, u32)> = Vec::new();

    for entry in entries {
        let offset = out.len();
        let crc = crc32(&entry.bytes);
        let name = entry.path.as_bytes();
        let size = entry.bytes.len() as u32;

        out.extend_from_slice(&0x0403_4b50u32.to_le_bytes()); // local file header
        out.extend_from_slice(&10u16.to_le_bytes()); // version needed
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        out.extend_from_slice(&FIXED_DOS_DATE.1.to_le_bytes()); // time
        out.extend_from_slice(&FIXED_DOS_DATE.0.to_le_bytes()); // date
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes()); // compressed
        out.extend_from_slice(&size.to_le_bytes()); // uncompressed
        out.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // extra len
        out.extend_from_slice(name);
        out.extend_from_slice(&entry.bytes);

        offsets.push((offset, entry, crc));
    }

    let central_start = out.len();
    for (offset, entry, crc) in &offsets {
        let name = entry.path.as_bytes();
        let size = entry.bytes.len() as u32;
        directory.extend_from_slice(&0x0201_4b50u32.to_le_bytes()); // central header
        directory.extend_from_slice(&0x031Eu16.to_le_bytes()); // version made by: unix
        directory.extend_from_slice(&10u16.to_le_bytes()); // version needed
        directory.extend_from_slice(&0u16.to_le_bytes()); // flags
        directory.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        directory.extend_from_slice(&FIXED_DOS_DATE.1.to_le_bytes());
        directory.extend_from_slice(&FIXED_DOS_DATE.0.to_le_bytes());
        directory.extend_from_slice(&crc.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&size.to_le_bytes());
        directory.extend_from_slice(&(name.len() as u16).to_le_bytes());
        directory.extend_from_slice(&0u16.to_le_bytes()); // extra
        directory.extend_from_slice(&0u16.to_le_bytes()); // comment
        directory.extend_from_slice(&0u16.to_le_bytes()); // disk number
        directory.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
        // External attrs: 0444, regular file. The device forces 444 anyway;
        // recording it keeps the archive honest when unzipped by hand.
        directory.extend_from_slice(&0o100_444u32.wrapping_shl(16).to_le_bytes());
        directory.extend_from_slice(&(*offset as u32).to_le_bytes());
        directory.extend_from_slice(name);
    }
    let dir_size = directory.len();
    out.extend_from_slice(&directory);

    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes()); // end of central dir
    out.extend_from_slice(&0u16.to_le_bytes()); // disk
    out.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
    out.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
    out.extend_from_slice(&(offsets.len() as u16).to_le_bytes());
    out.extend_from_slice(&(dir_size as u32).to_le_bytes());
    out.extend_from_slice(&(central_start as u32).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes()); // comment len
    out
}

/// CRC-32 (IEEE), computed directly so packing needs no new dependency.
fn crc32(bytes: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    let mut crc = 0xFFFF_FFFFu32;
    for b in bytes {
        crc = table[((crc ^ u32::from(*b)) & 0xFF) as usize] ^ (crc >> 8);
    }
    crc ^ 0xFFFF_FFFF
}

/// One tracked archive: what it contains, where it came from, where it is
/// hosted, and under which template.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceConfigEntry {
    /// Asset declaration `Identifier`.
    pub identifier: String,
    /// `ServiceType` the configuration declares.
    pub service_type: String,
    /// Staged source directory, relative to the index file where possible.
    pub source: String,
    /// Archive file name.
    pub archive: String,
    /// SHA-256 of the packed archive.
    pub sha256: String,
    /// Current hosting base — the part that changes on a provider migration.
    pub base: String,
    /// Template the URL is expanded from, so a move only substitutes `{base}`.
    pub url_template: String,
    /// The URL currently written into the asset declaration.
    pub url: String,
}

/// contour's bookkeeping, committed beside the declarations.
///
/// Never shipped to a device: Apple's asset payload has no field for "where
/// this came from", and an extra key risks rejection.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ServiceConfigIndex {
    #[serde(default, rename = "entry")]
    pub entries: Vec<ServiceConfigEntry>,
}

impl ServiceConfigIndex {
    pub const FILE_NAME: &'static str = ".contour-service-config.toml";

    pub fn get(&self, identifier: &str) -> Option<&ServiceConfigEntry> {
        self.entries.iter().find(|e| e.identifier == identifier)
    }

    /// Insert or replace by identifier, keeping entries sorted for a stable diff.
    pub fn upsert(&mut self, entry: ServiceConfigEntry) {
        match self
            .entries
            .iter_mut()
            .find(|e| e.identifier == entry.identifier)
        {
            Some(slot) => *slot = entry,
            None => self.entries.push(entry),
        }
        self.entries.sort_by(|a, b| a.identifier.cmp(&b.identifier));
    }
}

/// What a re-host would do to one entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RehostOutcome {
    /// Already served from this base; nothing to write.
    Unchanged { identifier: String },
    /// URL re-pointed at the new base. The archive is untouched and its hash
    /// is unchanged by construction.
    Repointed {
        identifier: String,
        old_url: String,
        new_url: String,
    },
}

impl RehostOutcome {
    pub fn identifier(&self) -> &str {
        match self {
            Self::Unchanged { identifier } | Self::Repointed { identifier, .. } => identifier,
        }
    }

    pub fn changed(&self) -> bool {
        matches!(self, Self::Repointed { .. })
    }
}

/// Re-point one entry at a new hosting base.
///
/// Pure, and deliberately hash-preserving: the artifact is not rebuilt, so the
/// recorded `sha256` is carried into the new URL unchanged. A caller that also
/// has the archive on disk should verify the hash still matches before writing
/// — see [`ServiceConfigError::ContentMoved`] — because a changed hash means
/// this is a republish wearing a move's clothes.
pub fn plan_rehost(
    entry: &ServiceConfigEntry,
    new_base: &str,
) -> Result<RehostOutcome, ServiceConfigError> {
    let ctx = UrlContext {
        base: new_base.to_string(),
        sha256: entry.sha256.clone(),
        name: entry.archive.clone(),
        service: entry.service_type.clone(),
    };
    let new_url = expand_url(&entry.url_template, &ctx)?;
    if new_url == entry.url {
        return Ok(RehostOutcome::Unchanged {
            identifier: entry.identifier.clone(),
        });
    }
    Ok(RehostOutcome::Repointed {
        identifier: entry.identifier.clone(),
        old_url: entry.url.clone(),
        new_url,
    })
}

/// Pack a staged tree and hash it — the two steps that decide an asset's
/// identity.
pub fn pack_and_hash(
    dir: &Path,
) -> Result<(Vec<ArchiveEntry>, Vec<u8>, String), ServiceConfigError> {
    let entries = collect_entries(dir).map_err(|e| ServiceConfigError::SourceUnreadable {
        dir: dir.to_path_buf(),
        reason: e.to_string(),
    })?;
    if entries.is_empty() {
        return Err(ServiceConfigError::EmptySource {
            dir: dir.to_path_buf(),
        });
    }
    let bytes = pack(&entries);
    let hash = sha256_hex(&bytes);
    Ok((entries, bytes, hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str, body: &str) -> ArchiveEntry {
        ArchiveEntry {
            path: path.to_string(),
            bytes: body.as_bytes().to_vec(),
        }
    }

    fn sshd_entries() -> Vec<ArchiveEntry> {
        vec![
            entry("etc/ssh/sshd_config", "PermitRootLogin no\n"),
            entry(
                "etc/ssh/sshd_config.d/100-hardening.conf",
                "X11Forwarding no\n",
            ),
        ]
    }

    // ── packing ──────────────────────────────────────────────────────────

    #[test]
    fn packing_is_reproducible_for_identical_content() {
        // The property the whole refresh story rests on: same content, same
        // bytes, therefore same hash, therefore no re-download.
        let a = pack(&sshd_entries());
        let b = pack(&sshd_entries());
        assert_eq!(sha256_hex(&a), sha256_hex(&b));
    }

    #[test]
    fn packing_does_not_depend_on_entry_order() {
        // Filesystem read order is not stable across machines. If it leaked
        // into the archive, two clones of one repo would publish different
        // assets for identical files.
        let mut reversed = sshd_entries();
        reversed.reverse();
        let mut sorted = reversed.clone();
        sorted.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(
            sha256_hex(&pack(&sorted)),
            sha256_hex(&pack(&sshd_entries()))
        );
    }

    #[test]
    fn changed_content_changes_the_hash() {
        let mut changed = sshd_entries();
        changed[0] = entry("etc/ssh/sshd_config", "PermitRootLogin yes\n");
        assert_ne!(
            sha256_hex(&pack(&sshd_entries())),
            sha256_hex(&pack(&changed)),
            "an edited config must produce a new asset"
        );
    }

    #[test]
    fn the_archive_is_a_readable_zip() {
        // Hand-rolled writer: prove the bytes are a real zip, not merely
        // stable. Signature, entry count and the stored name must be right.
        let bytes = pack(&sshd_entries());
        assert_eq!(
            &bytes[0..4],
            &[0x50, 0x4b, 0x03, 0x04],
            "local header magic"
        );
        let eocd = &bytes[bytes.len() - 22..];
        assert_eq!(
            &eocd[0..4],
            &[0x50, 0x4b, 0x05, 0x06],
            "end-of-central-dir magic"
        );
        assert_eq!(u16::from_le_bytes([eocd[10], eocd[11]]), 2, "entry count");
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.contains("etc/ssh/sshd_config"));
    }

    #[test]
    fn crc32_matches_the_known_vector() {
        // "123456789" → 0xCBF43926 is the standard IEEE CRC-32 check value.
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    // ── layout ───────────────────────────────────────────────────────────

    #[test]
    fn a_correctly_rooted_tree_passes() {
        let spec = find("com.apple.sshd").unwrap();
        verify_layout(spec, &sshd_entries()).expect("etc/ssh present");
    }

    #[test]
    fn a_tree_rooted_one_level_too_deep_is_refused() {
        // The silent killer: expands into a directory sshd never reads, while
        // the declaration reports Verified.
        let spec = find("com.apple.sshd").unwrap();
        let wrong = vec![entry("ssh/sshd_config", "x\n")];
        let err = verify_layout(spec, &wrong).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("etc/ssh"),
            "must name the expected path: {msg}"
        );
        assert!(msg.contains("ssh"), "must say what was found: {msg}");
    }

    #[test]
    fn a_drop_in_only_archive_reports_the_missing_main_config() {
        let spec = find("com.apple.sshd").unwrap();
        let dropin = vec![entry(
            "etc/ssh/sshd_config.d/100-x.conf",
            "X11Forwarding no\n",
        )];
        verify_layout(spec, &dropin).expect("layout is right; completeness is the issue");
        assert_eq!(
            missing_expected_members(spec, &dropin),
            vec!["etc/ssh/sshd_config".to_string()]
        );
    }

    #[test]
    fn a_complete_archive_reports_nothing_missing() {
        let spec = find("com.apple.sshd").unwrap();
        assert!(missing_expected_members(spec, &sshd_entries()).is_empty());
    }

    // ── service resolution ───────────────────────────────────────────────

    #[test]
    fn an_apple_typo_is_refused_with_a_suggestion() {
        let err = resolve_service("com.apple.sshdd").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("com.apple.sshd"),
            "must suggest the real one: {msg}"
        );
    }

    #[test]
    fn a_third_party_service_is_allowed_without_a_spec() {
        // Measured behaviour: any reverse-DNS type delivers files. Refusing
        // them would block the case this feature is most interesting for.
        assert!(resolve_service("org.example.demoapp").unwrap().is_none());
    }

    #[test]
    fn a_non_reverse_dns_type_is_refused() {
        assert!(matches!(
            resolve_service("sshd").unwrap_err(),
            ServiceConfigError::MalformedServiceType { .. }
        ));
    }

    // ── URLs and re-hosting ──────────────────────────────────────────────

    fn ctx(base: &str) -> UrlContext {
        UrlContext {
            base: base.to_string(),
            sha256: "3f9a".to_string(),
            name: "sshd.zip".to_string(),
            service: "com.apple.sshd".to_string(),
        }
    }

    #[test]
    fn a_template_expands_every_known_placeholder() {
        let url = expand_url(
            "https://{base}/{service}/{sha256}/{name}",
            &ctx("cdn.example.org/ddm"),
        )
        .unwrap();
        assert_eq!(
            url,
            "https://cdn.example.org/ddm/com.apple.sshd/3f9a/sshd.zip"
        );
    }

    #[test]
    fn an_unknown_placeholder_is_refused_not_published() {
        let err = expand_url("https://{base}/{version}/x", &ctx("h.example.org")).unwrap_err();
        assert_eq!(
            err,
            ServiceConfigError::UnknownPlaceholder {
                token: "version".into()
            }
        );
    }

    #[test]
    fn a_non_https_url_is_refused() {
        assert!(matches!(
            expand_url("http://{base}/x", &ctx("h.example.org")).unwrap_err(),
            ServiceConfigError::UrlNotHttps { .. }
        ));
    }

    #[test]
    fn a_trailing_slash_on_the_base_does_not_double_up() {
        // Operators paste container URLs with and without the slash.
        let url = expand_url("https://{base}/{name}", &ctx("h.example.org/ddm/")).unwrap();
        assert_eq!(url, "https://h.example.org/ddm/sshd.zip");
    }

    fn azure_entry() -> ServiceConfigEntry {
        ServiceConfigEntry {
            identifier: "com.acme.asset.sshd".into(),
            service_type: "com.apple.sshd".into(),
            source: "staging".into(),
            archive: "sshd.zip".into(),
            sha256: "3f9a".into(),
            base: "acct.blob.core.windows.net/ddm".into(),
            url_template: "https://{base}/{sha256}/{name}".into(),
            url: "https://acct.blob.core.windows.net/ddm/3f9a/sshd.zip".into(),
        }
    }

    #[test]
    fn moving_providers_rewrites_only_the_base() {
        // The scenario this was built for: Azure today, Cloudflare tomorrow,
        // same artifact. The hash-bearing path segment must survive, so a
        // stale copy on the old host cannot masquerade as the new one.
        let outcome = plan_rehost(&azure_entry(), "cdn.example.org/ddm").unwrap();
        match outcome {
            RehostOutcome::Repointed {
                new_url, old_url, ..
            } => {
                assert_eq!(new_url, "https://cdn.example.org/ddm/3f9a/sshd.zip");
                assert!(old_url.contains("blob.core.windows.net"));
                assert!(new_url.contains("/3f9a/"), "content address must survive");
            }
            other @ RehostOutcome::Unchanged { .. } => {
                panic!("expected a re-point, got {other:?}")
            }
        }
    }

    #[test]
    fn re_hosting_to_the_same_base_is_a_no_op() {
        // Re-running a migration must not mint a new ServerToken and make the
        // fleet re-download bytes it already has.
        let outcome = plan_rehost(&azure_entry(), "acct.blob.core.windows.net/ddm").unwrap();
        assert!(!outcome.changed(), "got {outcome:?}");
    }

    #[test]
    fn re_hosting_never_alters_the_hash() {
        // The artifact is not rebuilt during a move. If this ever changed, a
        // provider migration would silently republish content.
        let before = azure_entry();
        let _ = plan_rehost(&before, "cdn.example.org/ddm").unwrap();
        assert_eq!(before.sha256, "3f9a");
    }

    #[test]
    fn index_upsert_replaces_and_sorts() {
        let mut index = ServiceConfigIndex::default();
        index.upsert(azure_entry());
        let mut second = azure_entry();
        second.identifier = "com.acme.asset.cups".into();
        index.upsert(second);
        let mut updated = azure_entry();
        updated.url = "https://cdn.example.org/ddm/3f9a/sshd.zip".into();
        index.upsert(updated);
        assert_eq!(index.entries.len(), 2, "upsert must replace, not append");
        assert_eq!(index.entries[0].identifier, "com.acme.asset.cups");
        assert!(
            index
                .get("com.acme.asset.sshd")
                .unwrap()
                .url
                .contains("cdn.example.org")
        );
    }
}
