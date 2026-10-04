// Shared build-script support: resolve, fetch and verify the datasets each
// schema crate embeds.
//
// `include!`d by every schema crate's build.rs rather than living in a crate
// of its own — a build-dependency crate would be compiled once per consumer
// anyway, and this keeps the logic in one file without adding a workspace
// member that only build scripts can see.
//
// # Why the dataset is pinned
//
// `crates/*/data/*.parquet` is gitignored, so the tree itself has to say
// which dataset a build embeds. `schema-data.toml` pins a release and the
// sha256 of each archive; an optional dataset repository can be pinned at a
// commit instead, which makes a dataset change a reviewable diff.
//
// # Resolution order — see [`resolve_dataset`]
//
// 1. `CONTOUR_SCHEMA_SRC` — a local dataset build. Development only, and it
//    announces itself with a cargo:warning.
// 2. The pinned dataset repository, when `schema-data.toml` names one.
// 3. The zip: `CONTOUR_*_SCHEMA_URL`, or the pinned archive under
//    `CONTOUR_SCHEMA_ZIP_BASE`, held to its recorded sha256. The base URL
//    is deliberately not in the tree: CI supplies it from a repository
//    secret, a developer exports it once.
//
// Before 2 or 3 fetches anything, the stamp in `data/` is compared with what
// that source would write. A match with every required file present is
// taken as is, so a tree stamped with the current pin never touches the
// network. See dataset_stamp.rs for why this is a stamp and not "a file
// exists".

include!("dataset_stamp.rs");

use std::process::Command as SchemaDataCommand;

/// Where the pinned dataset lives.
struct DataRepoPin {
    repo: String,
    reference: String,
}

/// The URL each crate's zip is fetched from, when the environment names no
/// explicit one: `CONTOUR_SCHEMA_ZIP_BASE`, the archive name, and a query
/// string built from whichever of `zip_release` and the archive's recorded
/// sha256 `schema-data.toml` carries.
///
/// The query string is not decoration. The archives are overwritten in
/// place at a fixed path, and a CDN caches GETs per URL, so the plain URL
/// can keep serving a previous release after a new one is uploaded. Putting
/// the pin in the URL makes a pin bump fetch the new object. The object
/// store ignores the query; the cache does not.
///
/// `CONTOUR_*_SCHEMA_URL` still wins where set, so a developer can point
/// a single crate at a local `file://` zip or a beta archive.
pub fn zip_url_default(manifest_dir: &Path, archive: &str) -> Option<String> {
    let base = zip_base()?;
    let release = pinned_release(manifest_dir);
    // The release alone is a weak cache key: a request made for a release
    // before its upload lands caches the previous bytes under the new key,
    // and a purge by URL matches the query string exactly, so purging the
    // bare object does not clear it.
    //
    // The expected content hash fixes that by construction. A hash is only
    // knowable after the build that produced it, so nothing can warm the key
    // early, and any change to the bytes changes the key, so a stale entry
    // can never be served for new content. The release stays in the URL
    // because it is what a human reads in a build log.
    let sha = expected_zip_sha256(manifest_dir, archive);
    Some(match (release, sha.as_deref()) {
        (Some(r), Some(h)) => format!("{base}/{archive}.zip?release={r}&sha={}", &h[..16.min(h.len())]),
        (Some(r), None) => format!("{base}/{archive}.zip?release={r}"),
        (None, Some(h)) => format!("{base}/{archive}.zip?sha={}", &h[..16.min(h.len())]),
        (None, None) => format!("{base}/{archive}.zip"),
    })
}

/// Read `schema-data.toml` from the workspace root, letting the environment
/// override either field.
///
/// Returns `None` when no repository is configured; the build then uses the
/// zip download.
fn schema_data_pin(manifest_dir: &Path) -> Option<DataRepoPin> {
    let mut repo = std::env::var("CONTOUR_DATA_REPO")
        .ok()
        .filter(|s| !s.is_empty());
    let mut reference = std::env::var("CONTOUR_DATA_REF")
        .ok()
        .filter(|s| !s.is_empty());

    // crates/<name>/ -> workspace root
    let root = manifest_dir.parent().and_then(|p| p.parent());
    if let Some(root) = root {
        let config = root.join("schema-data.toml");
        println!("cargo:rerun-if-changed={}", config.display());
        if let Ok(text) = std::fs::read_to_string(&config) {
            for line in text.lines() {
                let line = line.trim();
                if line.starts_with('#') {
                    continue;
                }
                let Some((key, value)) = line.split_once('=') else {
                    continue;
                };
                let value = value.trim().trim_matches('"').to_string();
                match key.trim() {
                    "repo" if repo.is_none() && !value.is_empty() => repo = Some(value),
                    "ref" if reference.is_none() && !value.is_empty() => reference = Some(value),
                    _ => {}
                }
            }
        }
    }

    println!("cargo:rerun-if-env-changed=CONTOUR_DATA_REPO");
    println!("cargo:rerun-if-env-changed=CONTOUR_DATA_REF");

    Some(DataRepoPin {
        repo: repo?,
        reference: reference.unwrap_or_else(|| "main".to_string()),
    })
}

/// Clone the pinned dataset once per (repo, ref) and share it between crates.
///
/// Five build scripts run for one workspace build, often in parallel. Cloning
/// per crate would fetch the same bytes five times, so the checkout is cached
/// under the workspace root and keyed by repository and ref. The cache is published by
/// renaming a fully-populated temporary directory into place: `rename` is
/// atomic, so a crate either sees a complete checkout or none at all, and a
/// loser of the race simply finds the directory already there.
fn ensure_data_checkout(root: &Path, pin: &DataRepoPin) -> Option<std::path::PathBuf> {
    // Keyed by repository AND ref, not ref alone: tag names are not unique
    // across repositories, and two repos sharing `v2026.09.19` would
    // otherwise serve each other's data from the cache. That failure is
    // silent — the build succeeds, with the wrong dataset.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in pin.repo.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let safe_ref: String = pin
        .reference
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let cache = root
        .join(".schema-data")
        .join(format!("{safe_ref}-{hash:016x}"));

    if cache.join(".complete").is_file() {
        return Some(cache);
    }

    std::fs::create_dir_all(cache.parent()?).ok()?;
    let staging = cache.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);

    println!(
        "cargo:warning=Fetching schema data from {} at {}",
        pin.repo, pin.reference
    );

    let status = SchemaDataCommand::new("git")
        .args(["clone", "--quiet", "--depth", "1", "--branch"])
        .arg(&pin.reference)
        .arg(&pin.repo)
        .arg(&staging)
        .status();

    let ok = matches!(status, Ok(s) if s.success());
    if !ok {
        let _ = std::fs::remove_dir_all(&staging);
        // Not fatal: fall through to the zip download, so a checkout that
        // cannot reach the repository still builds.
        println!(
            "cargo:warning=Could not fetch {} at {} — falling back to the schema zip",
            pin.repo, pin.reference
        );
        return None;
    }

    // Mark completeness inside the staging dir, so the published directory is
    // never observable without it.
    let _ = std::fs::write(staging.join(".complete"), pin.reference.as_bytes());

    match std::fs::rename(&staging, &cache) {
        Ok(()) => Some(cache),
        Err(_) => {
            // Another crate won the race and published first.
            let _ = std::fs::remove_dir_all(&staging);
            cache.join(".complete").is_file().then_some(cache)
        }
    }
}

/// Copy this crate's files out of the pinned dataset.
///
/// Returns true when every file was placed, which tells the caller it can skip
/// the zip download entirely. A partial checkout returns false rather than
/// leaving `data/` half-populated: mixing datasets is the failure mode that
/// makes a wrong answer look like a right one.
fn fetch_from_data_repo(data_dir: &Path, files: &[&str]) -> bool {
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let Some(pin) = schema_data_pin(&manifest_dir) else {
        return false;
    };
    let Some(root) = manifest_dir.parent().and_then(|p| p.parent()) else {
        return false;
    };
    let Some(checkout) = ensure_data_checkout(root, &pin) else {
        return false;
    };

    // Verify the whole set before copying any of it.
    let sources: Vec<std::path::PathBuf> = files.iter().map(|f| checkout.join(f)).collect();
    if let Some(missing) = sources.iter().find(|p| !p.is_file()) {
        println!(
            "cargo:warning={} is not in the pinned dataset ({} at {}) — falling back to the \
             schema zip",
            missing.display(),
            pin.repo,
            pin.reference
        );
        return false;
    }

    if std::fs::create_dir_all(data_dir).is_err() {
        return false;
    }
    for (source, name) in sources.iter().zip(files) {
        // Track the pinned file: a re-pin must rebuild what embeds it.
        println!("cargo:rerun-if-changed={}", source.display());
        if std::fs::copy(source, data_dir.join(name)).is_err() {
            return false;
        }
    }

    println!(
        "cargo:warning=Schema data pinned at {} ({})",
        pin.reference, pin.repo
    );
    true
}

/// Where the archives are published: `CONTOUR_SCHEMA_ZIP_BASE`, without a
/// trailing slash. Not read from `schema-data.toml` on purpose — the pin and
/// the hashes are facts about the data and belong in the tree; the host is
/// deployment configuration and does not.
fn zip_base() -> Option<String> {
    println!("cargo:rerun-if-env-changed=CONTOUR_SCHEMA_ZIP_BASE");
    std::env::var("CONTOUR_SCHEMA_ZIP_BASE")
        .ok()
        .map(|v| v.trim().trim_end_matches('/').to_string())
        .filter(|v| !v.is_empty())
}

/// The sha256 `schema-data.toml` records for `archive`, if any.
///
/// Recorded as flat `sha256_<archive>` keys so the same line parser reads
/// them; the file has no section handling and does not need any.
pub fn expected_zip_sha256(manifest_dir: &Path, archive: &str) -> Option<String> {
    let root = manifest_dir.parent().and_then(|p| p.parent())?;
    let text = std::fs::read_to_string(root.join("schema-data.toml")).ok()?;
    let want = format!("sha256_{archive}");
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            if key.trim() == want {
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Fail the build when a downloaded archive is not the release that was pinned.
///
/// `zip_release` decides which object the build asks for. It does not decide
/// which one it gets: the archives are overwritten at a fixed path, so
/// `?release=<pin>` is a cache key, not a version selector, and a request
/// made before an upload completes can cache the previous release's bytes
/// under the new pin — served afterwards with a 200 and no warning.
///
/// So the pin is checked against the bytes rather than trusted. Each release
/// publishes a sha256 per archive; the one for the pinned release goes into
/// `schema-data.toml`, and this holds the build to it.
///
/// Skipped when no hash is recorded (an older pin, or a checkout that does not
/// carry them) and when the URL is not under `CONTOUR_SCHEMA_ZIP_BASE` — a
/// `CONTOUR_*_SCHEMA_URL` pointing elsewhere exists precisely to fetch a
/// different zip, and the recorded hash says nothing about it.
pub fn verify_zip_sha256(zip_path: &Path, manifest_dir: &Path, archive: &str, url: &str) {
    // Only the recorded origin is held to the recorded hash. A
    // `CONTOUR_*_SCHEMA_URL` pointing at a local or beta zip is a deliberate
    // substitution, and failing it would make the override useless.
    match zip_base() {
        Some(base) if url.starts_with(&base) => {}
        _ => return,
    }
    let Some(expected) = expected_zip_sha256(manifest_dir, archive) else {
        println!(
            "cargo:warning={archive}: schema-data.toml records no sha256 for the pinned \
             release — the downloaded archive is NOT verified"
        );
        return;
    };
    let Some(actual) = sha256_of(zip_path) else {
        println!(
            "cargo:warning={archive}: no sha256 tool available, downloaded archive not verified"
        );
        return;
    };
    if actual.eq_ignore_ascii_case(&expected) {
        return;
    }
    panic!(
        "\n{archive}.zip is not the archive this checkout pins.\n\
         \n  expected  {expected}\n  got       {actual}\n  from      {url}\n\
         \n\
         The pin in schema-data.toml names which object to ask for. It cannot make\n\
         the CDN send that one: the archives are overwritten at a fixed path, so the\n\
         release in the URL is a cache key. A request made for this pin before the\n\
         upload finished will have cached the previous release under it, and every\n\
         build since has been served those bytes with a 200 and no warning.\n\
         \n\
         See what the origin currently holds in one request — the bucket publishes\n\
         a SHA256SUMS for the CURRENT release, and a nonce shares no cache key:\n\
         \n    curl -s \"<base>/SHA256SUMS?n=NONCE\"\n\
         \n\
         If it lists the expected hash, the object is right and this exact URL is\n\
         serving a stale cache entry — purge it INCLUDING its query string\n\
         (a CDN purge-by-URL is exact match; purging the bare .zip does not\n\
         touch the ?release= variant). If it lists something else, the upload did\n\
         not land, or this checkout pins a release the bucket has moved past.\n\
         \n\
         schema-data.toml is the pin. SHA256SUMS is not: it is overwritten with\n\
         each release, so it always agrees with whatever is live. A checkout left\n\
         on an old pin would fetch the new archive AND the new sums and see them\n\
         match — which is the failure this check exists to catch. The hash in git\n\
         is what ties the bytes to the release this checkout asked for.\n"
    );
}

/// sha256 of a file, via whichever tool this machine has.
///
/// Shelling out rather than taking a crate dependency: the build already
/// requires `curl` and `unzip`, and a hash check that adds a dependency to
/// every schema crate is a poor trade for one comparison.
fn sha256_of(path: &Path) -> Option<String> {
    let try_tool = |program: &str, args: &[&str]| -> Option<String> {
        let out = std::process::Command::new(program)
            .args(args)
            .arg(path)
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        String::from_utf8(out.stdout)
            .ok()?
            .split_whitespace()
            .next()
            .map(str::to_string)
    };
    try_tool("shasum", &["-a", "256"]).or_else(|| try_tool("sha256sum", &[]))
}

/// `zip_release` from `schema-data.toml`, if it records one.
fn pinned_release(manifest_dir: &Path) -> Option<String> {
    let root = manifest_dir.parent().and_then(|p| p.parent())?;
    let text = std::fs::read_to_string(root.join("schema-data.toml")).ok()?;
    text.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == "zip_release")
        .map(|(_, v)| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
}

/// One schema crate's dataset: which archive, which override variable, which
/// files it embeds, and which of those an older dataset may lack.
pub struct DatasetSpec {
    /// Archive name without `.zip`, e.g. `mdm-schema`. The zip nests the
    /// files under `<archive>/data/`.
    pub archive: &'static str,
    /// `CONTOUR_*_SCHEMA_URL`.
    pub url_var: &'static str,
    /// Every file the crate embeds, as the dataset release publishes them.
    pub files: &'static [&'static str],
    /// Files a dataset published before they existed does not carry; the
    /// crate writes placeholders for them after this returns.
    pub optional: &'static [&'static str],
}

const DATA_DIR: &str = "data";
const STAMP: &str = ".dataset-pin";

fn required_present(dir: &Path, spec: &DatasetSpec) -> bool {
    spec.files
        .iter()
        .filter(|f| !spec.optional.contains(f))
        .all(|f| dir.join(f).is_file())
}

fn read_stamp(dir: &Path) -> Option<String> {
    std::fs::read_to_string(dir.join(STAMP)).ok()
}

/// Fill `data/` for one schema crate. The only entry point a build.rs calls.
pub fn resolve_dataset(spec: &DatasetSpec) {
    let data = Path::new(DATA_DIR);
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    println!("cargo:rerun-if-changed={DATA_DIR}/{STAMP}");
    println!("cargo:rerun-if-env-changed=CONTOUR_SCHEMA_SKIP_DOWNLOAD");
    println!("cargo:rerun-if-env-changed={}", spec.url_var);

    if sync_local_src(data, spec) {
        return;
    }

    let skip = std::env::var("CONTOUR_SCHEMA_SKIP_DOWNLOAD").is_ok();
    let found = read_stamp(data);
    let complete = required_present(data, spec);

    // The data repository, when configured, answers first.
    if let Some(pin) = schema_data_pin(&manifest_dir) {
        let wanted = dataset_stamp("repo", &format!("{}@{}", pin.repo, pin.reference));
        match decide_data_action(found.as_deref(), &wanted, complete, skip) {
            DataAction::Use => return,
            DataAction::KeepWithWarning(why) => return keep_warning(spec, &why),
            DataAction::Fetch(why) => {
                println!("cargo:warning={}: {why} — fetching", spec.archive);
                if replace_data(data, spec, &wanted, |staging| {
                    fetch_from_data_repo(staging, spec.files)
                }) {
                    return;
                }
                // Not fatal: fall through to the zip, as before stamps.
            }
        }
    }

    let (url, wanted) = match std::env::var(spec.url_var).ok().filter(|u| !u.is_empty()) {
        Some(u) => (u.clone(), dataset_stamp("url", &u)),
        None => {
            let Some(url) = zip_url_default(&manifest_dir, spec.archive) else {
                if complete {
                    println!(
                        "cargo:warning={}: neither CONTOUR_SCHEMA_ZIP_BASE nor {} is \
                         set; building with the unverified data/ already present",
                        spec.archive, spec.url_var
                    );
                    return;
                }
                panic!(
                    "Neither CONTOUR_SCHEMA_ZIP_BASE nor {var} is set, and \
                     crates/{a}/data/ is missing files.\n\
                     Export CONTOUR_SCHEMA_ZIP_BASE (the dataset host; CI gets it from the \
                     repository secret of the same name), set {var} to the URL of {a}.zip, \
                     or copy the parquet files into crates/{a}/data/ manually.",
                    var = spec.url_var,
                    a = spec.archive
                );
            };
            let wanted = match (
                pinned_release(&manifest_dir),
                expected_zip_sha256(&manifest_dir, spec.archive),
            ) {
                (Some(r), Some(h)) => dataset_stamp("release", &format!("{r} sha256 {h}")),
                _ => dataset_stamp("url", &url),
            };
            (url, wanted)
        }
    };

    match decide_data_action(found.as_deref(), &wanted, complete, skip) {
        DataAction::Use => {}
        DataAction::KeepWithWarning(why) => keep_warning(spec, &why),
        DataAction::Fetch(why) => {
            println!("cargo:warning={}: {why} — downloading {url}", spec.archive);
            let ok = replace_data(data, spec, &wanted, |staging| {
                download_zip_into(&url, staging, spec, &manifest_dir)
            });
            if !ok {
                panic!(
                    "{a}.zip from {url} did not carry every file crates/{a} embeds: {files:?}. \
                     data/ was left as it was.",
                    a = spec.archive,
                    files = spec.files
                );
            }
        }
    }
}

fn keep_warning(spec: &DatasetSpec, why: &str) {
    println!(
        "cargo:warning={}: CONTOUR_SCHEMA_SKIP_DOWNLOAD is set and {why}. Building with it — \
         this binary does NOT embed the pinned dataset.",
        spec.archive
    );
}

/// Fill a fresh staging directory with `fill`, check it, stamp it, and swap it
/// in for `data/`. Whole, so a file an older archive carried and a newer one
/// dropped does not survive, and atomic enough that a failed fetch leaves
/// `data/` as it was: the old directory is moved aside only once the new one
/// is complete, and removed only after the new one is in place.
fn replace_data(
    data: &Path,
    spec: &DatasetSpec,
    stamp: &str,
    fill: impl FnOnce(&Path) -> bool,
) -> bool {
    // Leftovers from an earlier build that stopped midway — a hash mismatch
    // panics inside `fill` — carry another process id. Cargo runs one build
    // script per crate at a time, so any of them is safe to clear.
    if let Ok(entries) = std::fs::read_dir(".") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name.starts_with(&format!("{DATA_DIR}.staging-"))
                || name.starts_with(&format!("{DATA_DIR}.replaced-"))
            {
                let _ = std::fs::remove_dir_all(e.path());
            }
        }
    }
    let pid = std::process::id();
    let staging = std::path::PathBuf::from(format!("{DATA_DIR}.staging-{pid}"));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging).expect("creating the data staging directory");

    if !fill(&staging) || !required_present(&staging, spec) {
        let _ = std::fs::remove_dir_all(&staging);
        return false;
    }
    std::fs::write(staging.join(STAMP), format!("{stamp}\n")).expect("writing the data stamp");

    let aside = std::path::PathBuf::from(format!("{DATA_DIR}.replaced-{pid}"));
    let _ = std::fs::remove_dir_all(&aside);
    if data.exists() {
        std::fs::rename(data, &aside).expect("moving the previous data/ aside");
    }
    std::fs::rename(&staging, data).expect("moving the new dataset into data/");
    let _ = std::fs::remove_dir_all(&aside);
    println!("cargo:warning={}: data/ is now `{stamp}`", spec.archive);
    true
}

/// Download `url`, check it against the pinned sha256, and put the files from
/// the zip's `<archive>/data/` into `dest`.
fn download_zip_into(url: &str, dest: &Path, spec: &DatasetSpec, manifest_dir: &Path) -> bool {
    let zip = dest.join("_schema.zip");
    let tmp = dest.join("_unzipped");
    let ok = std::process::Command::new("curl")
        .args(["-fsSL", "-o"])
        .arg(&zip)
        .arg(url)
        .status()
        .expect("running curl — is it installed?")
        .success();
    if !ok {
        panic!("could not download {url}");
    }
    // Panics with the full story on a mismatch; see its docs.
    verify_zip_sha256(&zip, manifest_dir, spec.archive, url);

    let ok = std::process::Command::new("unzip")
        .args(["-o", "-q"])
        .arg(&zip)
        .arg("-d")
        .arg(&tmp)
        .status()
        .expect("running unzip — is it installed?")
        .success();
    if !ok {
        panic!("could not extract {url}");
    }
    // The archives nest their files at <archive>/data/. A flat zip is taken
    // as it is, as the per-crate copies of this did.
    let nested = tmp.join(spec.archive).join("data");
    let from = if nested.is_dir() { nested } else { tmp.clone() };
    for entry in std::fs::read_dir(&from).expect("reading the extracted archive").flatten() {
        let p = entry.path();
        if p.is_file() {
            let to = dest.join(entry.file_name());
            if std::fs::rename(&p, &to).is_err() {
                std::fs::copy(&p, &to).expect("copying an extracted file");
            }
        }
    }
    let _ = std::fs::remove_file(&zip);
    let _ = std::fs::remove_dir_all(&tmp);
    true
}

/// `CONTOUR_SCHEMA_SRC`: copy this crate's files from a local dataset build.
///
/// Local development only, and loud about it. Every file must be there before
/// any is copied — a half-updated data/ is the failure this prevents — and
/// the directory is stamped `local <path>`, so the next build without the
/// variable sees a dataset that is not the pin and fetches the pin again.
fn sync_local_src(data: &Path, spec: &DatasetSpec) -> bool {
    println!("cargo:rerun-if-env-changed=CONTOUR_SCHEMA_SRC");
    let Ok(src) = std::env::var("CONTOUR_SCHEMA_SRC") else {
        return false;
    };
    let src = Path::new(&src);
    let mut missing = Vec::new();
    for f in spec.files {
        let from = src.join(f);
        // Every source file, so rebuilding any table re-runs this.
        println!("cargo:rerun-if-changed={}", from.display());
        if !from.is_file() {
            missing.push(from.display().to_string());
        }
    }
    if !missing.is_empty() {
        panic!(
            "CONTOUR_SCHEMA_SRC is set to {} but {} of {} file(s) are missing:\n  {}\n\
             data/ was left untouched. Build the dataset first, or unset CONTOUR_SCHEMA_SRC to \
             build against the published data.",
            src.display(),
            missing.len(),
            spec.files.len(),
            missing.join("\n  ")
        );
    }
    let stamp = dataset_stamp("local", &src.display().to_string());
    let ok = replace_data(data, spec, &stamp, |staging| {
        spec.files.iter().all(|f| std::fs::copy(src.join(f), staging.join(f)).is_ok())
    });
    assert!(ok, "copying from CONTOUR_SCHEMA_SRC failed");
    println!(
        "cargo:warning=Using LOCAL schema data from {} — NOT the published dataset",
        src.display()
    );
    true
}
