//! Code signing utilities for extracting code requirements.
//!
//! Uses the `codesign` command to extract code requirements from macOS
//! application bundles, which are needed for PPPC profile generation.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Extract the designated code requirement from an application bundle.
///
/// This runs `codesign -d -r - <path>` and parses the output to extract
/// the designated requirement string.
///
/// # Example output from codesign:
/// ```text
/// Executable=/Applications/Example.app/Contents/MacOS/Example
/// designated => identifier "com.example.app" and anchor apple generic and ...
/// ```
pub fn get_code_requirement(path: &Path) -> Result<String> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Code requirement extraction requires macOS (uses `codesign` command)");
    }
    let output = Command::new("codesign")
        .args(["-d", "-r", "-"])
        .arg(path)
        .output()
        .context("Failed to run codesign command")?;

    // codesign outputs the requirement to stdout (designated => ...)
    // and info messages to stderr (Executable=...)
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Look for "designated => " line in stdout
    for line in stdout.lines() {
        if let Some(requirement) = line.strip_prefix("designated => ") {
            return Ok(requirement.trim().to_string());
        }
    }

    // If no designated requirement found, check if unsigned
    if stderr.contains("code object is not signed at all") {
        anyhow::bail!("Application is not signed");
    }

    anyhow::bail!(
        "Could not extract code requirement from codesign output.\nstdout: {stdout}\nstderr: {stderr}"
    )
}

/// Why a string is not a usable designated requirement.
///
/// The requirement is a *predicate*, compiled by `csreq` and evaluated by
/// the device. Anything that is not part of the predicate makes the whole
/// document unusable — and, in a TCC payload or a `PermissionDefaults` key,
/// does so silently: the profile installs, reports Verified, and matches
/// nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequirementFlaw {
    /// Empty or whitespace.
    Empty,
    /// Carries `codesign`'s `Executable=…` trailer. `codesign -d -r-` prints
    /// it on **stderr** to say which binary it read; pasting both streams
    /// together carries it into the requirement, and `csreq` refuses the
    /// result: "line 2:1: expecting EOF, found 'Executable'".
    ExecutableTrailer,
    /// Carries the `designated => ` prefix `codesign` writes before the
    /// requirement itself.
    DesignatedPrefix,
    /// More than one line. A requirement is a single expression; a second
    /// line is always something `codesign` printed around it.
    MultiLine,
}

impl std::fmt::Display for RequirementFlaw {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementFlaw::Empty => write!(f, "is empty"),
            RequirementFlaw::ExecutableTrailer => write!(
                f,
                "carries codesign's `Executable=…` trailer, which is not part of the \
                 requirement — csreq rejects it (\"expecting EOF, found 'Executable'\"). \
                 That line comes from stderr; keep only the text after `designated => `"
            ),
            RequirementFlaw::DesignatedPrefix => write!(
                f,
                "still carries the `designated => ` prefix; keep only the text after it"
            ),
            RequirementFlaw::MultiLine => write!(
                f,
                "spans several lines; a designated requirement is one expression, and \
                 anything else on its own line is something codesign printed around it"
            ),
        }
    }
}

/// Check a designated requirement that came from **outside** — a recipe, a
/// values file, a pasted terminal buffer. [`get_code_requirement`] already
/// returns a clean one; this is for everything contour did not read itself.
///
/// Deliberately syntactic: it does not compile the expression (that is
/// `csreq`'s job and needs macOS), it catches the ways a correct
/// requirement arrives wrapped in the output around it.
pub fn requirement_flaw(req: &str) -> Option<RequirementFlaw> {
    let t = req.trim();
    if t.is_empty() {
        return Some(RequirementFlaw::Empty);
    }
    if t.starts_with("designated =>") || t.starts_with("designated=>") {
        return Some(RequirementFlaw::DesignatedPrefix);
    }
    if t.lines().any(|l| l.trim_start().starts_with("Executable=")) {
        return Some(RequirementFlaw::ExecutableTrailer);
    }
    if t.lines().filter(|l| !l.trim().is_empty()).count() > 1 {
        return Some(RequirementFlaw::MultiLine);
    }
    None
}

/// Get the bundle identifier from an application's Info.plist.
pub fn get_bundle_id(app_path: &Path) -> Result<String> {
    let info_plist = app_path.join("Contents/Info.plist");

    if !info_plist.exists() {
        anyhow::bail!("Info.plist not found at {}", info_plist.display());
    }

    let content = std::fs::read(&info_plist)
        .with_context(|| format!("Failed to read {}", info_plist.display()))?;

    let plist: plist::Value = plist::from_bytes(&content)
        .with_context(|| format!("Failed to parse {}", info_plist.display()))?;

    if let Some(dict) = plist.as_dictionary()
        && let Some(bundle_id) = dict.get("CFBundleIdentifier")
        && let Some(id) = bundle_id.as_string()
    {
        return Ok(id.to_string());
    }

    anyhow::bail!("CFBundleIdentifier not found in Info.plist")
}

/// `CFBundleShortVersionString` and `CFBundleVersion`, where Info.plist
/// has them. Neither is guessed from the other.
pub fn get_bundle_versions(app_path: &Path) -> (Option<String>, Option<String>) {
    let info_plist = app_path.join("Contents/Info.plist");
    let Ok(content) = std::fs::read(&info_plist) else {
        return (None, None);
    };
    let Ok(plist) = plist::from_bytes::<plist::Value>(&content) else {
        return (None, None);
    };
    let Some(dict) = plist.as_dictionary() else {
        return (None, None);
    };
    let get = |k: &str| {
        dict.get(k)
            .and_then(plist::Value::as_string)
            .filter(|v| !v.is_empty())
            .map(str::to_string)
    };
    (get("CFBundleShortVersionString"), get("CFBundleVersion"))
}

/// Get the application name from Info.plist or fallback to directory name.
pub fn get_app_name(app_path: &Path) -> String {
    // Try to get from Info.plist
    let info_plist = app_path.join("Contents/Info.plist");
    if info_plist.exists()
        && let Ok(content) = std::fs::read(&info_plist)
        && let Ok(plist) = plist::from_bytes::<plist::Value>(&content)
        && let Some(dict) = plist.as_dictionary()
    {
        // Try CFBundleDisplayName first, then CFBundleName
        for key in &["CFBundleDisplayName", "CFBundleName"] {
            if let Some(name) = dict.get(key)
                && let Some(s) = name.as_string()
                && !s.is_empty()
            {
                return s.to_string();
            }
        }
    }

    // Fallback to directory name without .app extension
    app_path.file_stem().map_or_else(
        || "Unknown".to_string(),
        |s| s.to_string_lossy().to_string(),
    )
}

/// Find the main executable path within an app bundle.
pub fn find_main_executable(app_path: &Path) -> Result<std::path::PathBuf> {
    let contents = app_path.join("Contents");
    let macos = contents.join("MacOS");
    let info_plist = contents.join("Info.plist");

    // Try to read Info.plist to get the executable name
    if info_plist.exists()
        && let Ok(content) = std::fs::read(&info_plist)
        && let Ok(plist) = plist::from_bytes::<plist::Value>(&content)
        && let Some(dict) = plist.as_dictionary()
        && let Some(exec) = dict.get("CFBundleExecutable")
        && let Some(exec_name) = exec.as_string()
    {
        let exec_path = macos.join(exec_name);
        if exec_path.exists() {
            return Ok(exec_path);
        }
    }

    // Fallback: use the app name as executable name
    if let Some(app_name) = app_path.file_stem() {
        let exec_path = macos.join(app_name);
        if exec_path.exists() {
            return Ok(exec_path);
        }
    }

    // Last resort: find any executable in MacOS folder
    if macos.exists() {
        for entry in std::fs::read_dir(&macos)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                return Ok(path);
            }
        }
    }

    anyhow::bail!("No executable found in {}", app_path.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_app_name_fallback() {
        let path = Path::new("/Applications/Test.app");
        // Should fall back to directory name
        let name = get_app_name(path);
        assert_eq!(name, "Test");
    }
}

/// One architecture slice's code directory hash.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SliceCdHash {
    /// The slice, as `codesign` names it: `arm64`, `arm64e`, `x86_64`.
    pub arch: String,
    /// The 40-character code directory hash — what `app.settings`
    /// `BinaryIdentifier.CDHash` wants. NOT a file SHA-256.
    pub cdhash: String,
}

/// How a binary was signed, read from the certificate chain — Apple's
/// `SigningState` values plus the two the chain can also say.
///
/// Classification is by the **leaf** authority string and nothing else;
/// where it does not match a known issuer the answer is `Unknown`, and the
/// leaf string travels beside it so a reader can see why.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SigningState {
    DeveloperId,
    AppStore,
    TestFlight,
    Enterprise,
    Apple,
    Adhoc,
    Unknown,
}

impl SigningState {
    /// Apple's spelling where one exists (`DeveloperID`, `AppStore`, …).
    pub fn as_str(self) -> &'static str {
        match self {
            SigningState::DeveloperId => "DeveloperID",
            SigningState::AppStore => "AppStore",
            SigningState::TestFlight => "TestFlight",
            SigningState::Enterprise => "Enterprise",
            SigningState::Apple => "Apple",
            SigningState::Adhoc => "adhoc",
            SigningState::Unknown => "unknown",
        }
    }

    /// From the leaf authority and `codesign`'s `Signature=` line.
    pub fn classify(leaf_authority: Option<&str>, signature: Option<&str>) -> Self {
        if signature.is_some_and(|s| s.trim() == "adhoc") {
            return SigningState::Adhoc;
        }
        let Some(leaf) = leaf_authority else {
            return SigningState::Unknown;
        };
        if leaf.starts_with("Developer ID Application") {
            SigningState::DeveloperId
        } else if leaf.starts_with("Apple Mac OS Application Signing")
            || leaf.starts_with("Apple iPhone OS Application Signing")
        {
            SigningState::AppStore
        } else if leaf.starts_with("TestFlight Beta Distribution") {
            SigningState::TestFlight
        } else if leaf.starts_with("iPhone Distribution") {
            SigningState::Enterprise
        } else if leaf.ends_with("Software Signing") {
            SigningState::Apple
        } else {
            SigningState::Unknown
        }
    }
}

/// A binary's signing identity, in the shape `app.settings` binary rules need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeIdentity {
    /// Team identifier, or `*APPLE*` for an Apple platform binary.
    ///
    /// Apple's schema asks for `*APPLE*` rather than an empty string, because
    /// Apple's own binaries carry no team identifier at all. `None` means
    /// neither — ad-hoc or otherwise team-less signing.
    pub team_id: Option<String>,
    /// The bare signing identifier, e.g. `us.zoom.xos`.
    ///
    /// Bare on purpose: Santa writes `TEAMID:us.zoom.xos`, but Apple's
    /// `SigningID` is the identifier alone, with the team in `TeamID`.
    pub signing_id: Option<String>,
    /// One entry per architecture slice, in the order `codesign` lists them.
    ///
    /// Every slice, not just the native one. A universal binary has a
    /// different CDHash per slice, and a CDHash rule only matches the slice
    /// that actually executes — so which ones become rules is a policy
    /// decision for the caller, not a fact this reader can settle.
    pub slices: Vec<SliceCdHash>,
    /// The `Authority=` chain, leaf first, exactly as `codesign` printed it.
    pub authorities: Vec<String>,
    /// Classified from the leaf authority; see [`SigningState`].
    pub signing_state: SigningState,
}

/// Read a bundle's or binary's signing identity through `codesign`.
///
/// No `santactl` needed, which is the point: this is what makes CDHash, TeamID
/// and SigningID reachable on a Mac without Santa or Fleet.
pub fn read_code_identity(path: &Path) -> Result<CodeIdentity> {
    if cfg!(not(target_os = "macos")) {
        anyhow::bail!("Code identity extraction requires macOS (uses `codesign` command)");
    }

    let info = codesign_details(path, None)?;
    if info.contains("code object is not signed at all") {
        anyhow::bail!("{}: not signed", path.display());
    }

    let team_id = team_id_from(detail(&info, "TeamIdentifier"), detail(&info, "Authority"));
    let signing_id = detail(&info, "Identifier").map(str::to_string);

    let mut slices = Vec::new();
    for arch in archs_from_format(detail(&info, "Format").unwrap_or_default()) {
        // Per slice: the default CDHash is only the native slice's.
        let per_arch = codesign_details(path, Some(&arch))?;
        if let Some(cdhash) = detail(&per_arch, "CDHash") {
            slices.push(SliceCdHash {
                arch,
                cdhash: cdhash.to_string(),
            });
        }
    }

    let authorities: Vec<String> = info
        .lines()
        .filter_map(|l| l.strip_prefix("Authority="))
        .map(|a| a.trim().to_string())
        .collect();
    let signing_state = SigningState::classify(
        authorities.first().map(String::as_str),
        detail(&info, "Signature"),
    );

    Ok(CodeIdentity {
        team_id,
        signing_id,
        slices,
        authorities,
        signing_state,
    })
}

/// `codesign -dvvv`, optionally for one slice. Its details go to stderr.
fn codesign_details(path: &Path, arch: Option<&str>) -> Result<String> {
    let mut cmd = Command::new("codesign");
    cmd.arg("-dvvv");
    if let Some(arch) = arch {
        cmd.args(["--arch", arch]);
    }
    let output = cmd
        .arg(path)
        .output()
        .context("Failed to run codesign command")?;
    Ok(String::from_utf8_lossy(&output.stderr).into_owned())
}

/// The first `Key=value` line for `key`. First, because `Authority` repeats
/// down the chain and the leaf certificate is the one that names the signer.
fn detail<'a>(output: &'a str, key: &str) -> Option<&'a str> {
    output
        .lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(str::trim)
}

/// The slice names in `codesign`'s `Format=` line.
///
/// `app bundle with Mach-O universal (x86_64 arm64)` → `[x86_64, arm64]`;
/// a thin binary lists one. No parenthesised list means nothing to read.
fn archs_from_format(format: &str) -> Vec<String> {
    let Some(open) = format.rfind('(') else {
        return Vec::new();
    };
    let Some(close) = format[open..].find(')') else {
        return Vec::new();
    };
    format[open + 1..open + close]
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// TeamID as Apple's schema wants it.
///
/// `codesign` reports `TeamIdentifier=not set` for both Apple platform
/// binaries and ad-hoc signing. The leaf authority tells them apart: Apple's
/// own binaries are signed by "… Software Signing".
fn team_id_from(team_identifier: Option<&str>, leaf_authority: Option<&str>) -> Option<String> {
    match team_identifier {
        Some(team) if team != "not set" && !team.is_empty() => Some(team.to_string()),
        _ if leaf_authority.is_some_and(|a| a.ends_with("Software Signing")) => {
            Some("*APPLE*".to_string())
        }
        _ => None,
    }
}

#[cfg(test)]
mod identity_tests {
    use super::*;

    // Captured from `codesign -dvvv` on real bundles.
    const ZOOM: &str = "Identifier=us.zoom.xos\n\
        Format=app bundle with Mach-O universal (x86_64 arm64)\n\
        Authority=Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)\n\
        Authority=Developer ID Certification Authority\n\
        Authority=Apple Root CA\n\
        TeamIdentifier=BJ4HAAB9B3\n";

    const SAFARI: &str = "Identifier=com.apple.Safari\n\
        Format=app bundle with Mach-O universal (x86_64 arm64e)\n\
        Authority=macOS Software Signing\n\
        Authority=Apple Code Signing Certification Authority\n\
        Authority=Apple Root CA\n\
        TeamIdentifier=not set\n";

    /// The trap: `codesign -d -r-` writes the requirement to stdout and
    /// `Executable=…` to stderr. A human copying the terminal gets both, and
    /// csreq refuses the result — but a profile carrying it installs and
    /// matches nothing.
    #[test]
    fn requirement_flaws_catch_what_codesign_prints_around_the_predicate() {
        let good = r#"identifier "com.apple.Safari" and anchor apple"#;
        assert_eq!(requirement_flaw(good), None);

        assert_eq!(
            requirement_flaw(&format!(
                "{good}\nExecutable=/Applications/Safari.app/Contents/MacOS/Safari"
            )),
            Some(RequirementFlaw::ExecutableTrailer)
        );
        assert_eq!(
            requirement_flaw(&format!("designated => {good}")),
            Some(RequirementFlaw::DesignatedPrefix)
        );
        assert_eq!(
            requirement_flaw(&format!("{good}\nand anchor apple generic")),
            Some(RequirementFlaw::MultiLine)
        );
        assert_eq!(requirement_flaw("   "), Some(RequirementFlaw::Empty));

        // Trailing whitespace and a trailing newline are not flaws.
        assert_eq!(requirement_flaw(&format!("  {good}  \n")), None);
    }

    /// Classification is by the leaf issuer only. A string the chain does
    /// not name is `Unknown`, not the nearest guess.
    #[test]
    fn signing_state_is_read_from_the_leaf_not_guessed() {
        fn leaf(s: &str) -> Option<&str> {
            detail(s, "Authority")
        }
        assert_eq!(
            SigningState::classify(leaf(ZOOM), None),
            SigningState::DeveloperId
        );
        assert_eq!(
            SigningState::classify(leaf(SAFARI), None),
            SigningState::Apple
        );
        assert_eq!(
            SigningState::classify(Some("Apple Mac OS Application Signing"), None),
            SigningState::AppStore
        );
        assert_eq!(
            SigningState::classify(Some("TestFlight Beta Distribution"), None),
            SigningState::TestFlight
        );
        assert_eq!(
            SigningState::classify(Some("iPhone Distribution: Acme Corp (ABCDE12345)"), None),
            SigningState::Enterprise
        );
        assert_eq!(
            SigningState::classify(Some("Apple Development: Jane Doe (ABCDE12345)"), None),
            SigningState::Unknown
        );
        assert_eq!(
            SigningState::classify(None, Some("adhoc")),
            SigningState::Adhoc
        );
        assert_eq!(SigningState::classify(None, None), SigningState::Unknown);
    }

    #[test]
    fn third_party_team_is_read_verbatim() {
        let team = team_id_from(detail(ZOOM, "TeamIdentifier"), detail(ZOOM, "Authority"));
        assert_eq!(team.as_deref(), Some("BJ4HAAB9B3"));
    }

    #[test]
    fn apple_platform_binary_becomes_star_apple() {
        let team = team_id_from(
            detail(SAFARI, "TeamIdentifier"),
            detail(SAFARI, "Authority"),
        );
        assert_eq!(team.as_deref(), Some("*APPLE*"));
    }

    #[test]
    fn ad_hoc_signing_has_no_team() {
        let adhoc = "Identifier=a.out\nTeamIdentifier=not set\n";
        let team = team_id_from(detail(adhoc, "TeamIdentifier"), detail(adhoc, "Authority"));
        assert_eq!(team, None);
    }

    #[test]
    fn the_leaf_authority_is_the_one_read() {
        // The chain ends at Apple Root CA for every signer. Reading the last
        // Authority line would call Zoom an Apple binary.
        assert_eq!(
            detail(ZOOM, "Authority"),
            Some("Developer ID Application: Zoom Video Communications, Inc. (BJ4HAAB9B3)")
        );
    }

    #[test]
    fn universal_and_arm64e_slices_are_listed() {
        assert_eq!(
            archs_from_format(detail(ZOOM, "Format").unwrap()),
            ["x86_64", "arm64"]
        );
        assert_eq!(
            archs_from_format(detail(SAFARI, "Format").unwrap()),
            ["x86_64", "arm64e"]
        );
    }

    #[test]
    fn a_thin_binary_lists_one_slice() {
        assert_eq!(
            archs_from_format("app bundle with Mach-O thin (arm64)"),
            ["arm64"]
        );
    }

    #[test]
    fn detail_does_not_match_a_longer_key() {
        // `Identifier` must not match `TeamIdentifier=`.
        let only_team = "TeamIdentifier=BJ4HAAB9B3\n";
        assert_eq!(detail(only_team, "Identifier"), None);
    }
}
