// What a schema crate's build does with the `data/` it finds.
//
// Pure, and in a file of its own, so it can be tested: build scripts run no
// tests, and this is the rule that decides whether a pin bump reaches the
// binary. `schema_data.rs` includes it for the build; a test in
// crates/contour/tests includes it to hold the rule.
//
// # Why a stamp
//
// "A file exists in `data/`" says nothing about which dataset it is. A pin
// bump re-runs the build script (the pin file is a rerun-if-changed input),
// and a check on file presence alone would keep the previous dataset under
// the new pin — the sha256 check runs on a fresh download only, so it would
// never see those bytes.
//
// So `data/.dataset-pin` records which source filled the directory, written
// only after that source's bytes were verified and every required file is
// present, and a build compares it with what the checkout asks for now.

/// The source the checkout currently asks for, as the stamp spells it.
///
/// One line, so a person reading `data/.dataset-pin` sees the same words a
/// build log prints:
///
/// * `release <pin> sha256 <hex>` — the pinned archive, held to its hash;
/// * `url <url>` — a `CONTOUR_*_SCHEMA_URL` override, or a pin missing its
///   `zip_release` or hash (then the URL is all there is to record);
/// * `repo <repo>@<ref>` — the pinned data repository;
/// * `local <path>` — `CONTOUR_SCHEMA_SRC`, a local dataset build.
pub fn dataset_stamp(kind: &str, detail: &str) -> String {
    format!("{kind} {detail}")
}

/// What to do with `data/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataAction {
    /// The stamp is the source asked for and every required file is there.
    Use,
    /// Fetch, verify, and replace `data/` whole. The reason goes in the log.
    Fetch(String),
    /// `CONTOUR_SCHEMA_SKIP_DOWNLOAD` is set and `data/` is not what the pin
    /// asks for: build with it, and say so. An offline build is legitimate;
    /// a silent one is how the stale dataset shipped.
    KeepWithWarning(String),
}

/// Decide from the stamp found, the stamp wanted, whether every required file
/// is present, and whether downloads are switched off.
///
/// No stamp is a mismatch, not a pass: every checkout from before stamps
/// existed has an unstamped `data/`, and that is exactly the population
/// whose contents nobody can vouch for. Fetching once costs a few MB.
pub fn decide_data_action(
    found: Option<&str>,
    wanted: &str,
    complete: bool,
    skip_download: bool,
) -> DataAction {
    let found = found.map(str::trim).filter(|s| !s.is_empty());
    let reason = match found {
        Some(f) if f == wanted && complete => return DataAction::Use,
        Some(f) if f == wanted => format!("data/ is stamped `{f}` but files are missing"),
        Some(f) => format!("data/ holds `{f}`, the checkout asks for `{wanted}`"),
        None if complete => format!(
            "data/ carries no stamp, so nothing says which dataset it is; the checkout asks \
             for `{wanted}`"
        ),
        None => format!("data/ is empty or incomplete; the checkout asks for `{wanted}`"),
    };
    if skip_download {
        DataAction::KeepWithWarning(reason)
    } else {
        DataAction::Fetch(reason)
    }
}
