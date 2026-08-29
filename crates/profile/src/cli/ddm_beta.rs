//! `profile ddm beta` — build a beta-enrollment declaration in one step.
//!
//! Apple's beta (AppleSeed for IT) enrollment is delivered through
//! `com.apple.configuration.softwareupdate.settings`'s `Beta` object, whose
//! four legal shapes are easy to get wrong (see `cross_key_errors`). This
//! command takes the *desired outcome* — offer / always-on / require / block —
//! plus the seeding tokens, and emits the matching declaration.
//!
//! ## Where the tokens come from (manual, by Apple's design)
//!
//! The seeding tokens are not something contour can mint. They are fetched
//! from Apple's DEP API with an MDM server token, which itself comes out of a
//! manual Apple Business/School Manager round-trip. [`MANUAL_TOKEN_STEPS`]
//! documents that; when a mode needs tokens and none are present, the command
//! prints those steps and exits non-zero so a human — or an agent driving the
//! workflow — knows exactly which artifact to produce before retrying.

use anyhow::{Context, Result};
use colored::Colorize;
use std::path::Path;

use crate::cli::ddm::{declaration_errors, resolve_declaration_identifier};
use crate::config::ProfileConfig;
use crate::ddm::parser::{write_declaration, write_declaration_file};
use crate::ddm::types::{Declaration, DeclarationPayload};
use crate::output::OutputMode;
use crate::schema::SchemaRegistry;

/// The declaration type that carries beta enrollment.
const SWU_SETTINGS: &str = "com.apple.configuration.softwareupdate.settings";

/// What the operator wants to happen on the device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum BetaMode {
    /// Users may self-enroll with their Apple Account; your programs are also
    /// offered. (`ProgramEnrollment: Allowed` + `OfferPrograms`)
    Offer,
    /// Only your programs; users cannot self-enroll but choose from your list.
    /// (`ProgramEnrollment: AlwaysOn` + `OfferPrograms`)
    AlwaysOn,
    /// The device is enrolled automatically into exactly one program.
    /// (`ProgramEnrollment: AlwaysOn` + `RequireProgram`)
    Require,
    /// No beta enrollment at all; removes the device from any program it is
    /// already in. (`ProgramEnrollment: AlwaysOff`)
    Block,
}

impl BetaMode {
    /// The `ProgramEnrollment` value this mode maps to.
    pub fn enrollment(self) -> &'static str {
        match self {
            BetaMode::Offer => "Allowed",
            BetaMode::AlwaysOn | BetaMode::Require => "AlwaysOn",
            BetaMode::Block => "AlwaysOff",
        }
    }

    /// True when the mode needs at least one seeding token.
    pub fn needs_tokens(self) -> bool {
        !matches!(self, BetaMode::Block)
    }
}

/// One seeding token as Apple's DEP API returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BetaToken {
    /// Human-readable program name → the declaration's `Description`.
    pub title: String,
    /// Apple's OS tag (`OSX`, `iOS`, …); informational, used for filtering.
    pub os: String,
    /// The seeding-service token → the declaration's `Token`.
    pub token: String,
}

/// The manual Apple Business/School Manager round-trip that produces the
/// tokens. Printed verbatim when a token artifact is missing, so a human or
/// an agent can complete the step and re-run.
pub const MANUAL_TOKEN_STEPS: &str = "\
Seeding tokens come from Apple and cannot be generated locally.

  MANUAL STEP 1 — MDM server record (Apple Business/School Manager)
    Generate a keypair, upload the public certificate to a new MDM server
    record (ABM → Preferences → Your MDM servers), then download that
    server's token file (`.p7m`).

  MANUAL STEP 2 — decrypt the server token
    The `.p7m` is CMS *EnvelopedData* (encrypted, not merely signed), so it
    needs the matching private key:
      openssl smime -decrypt -inform DER -in token.der \\
        -recip mdm_public_cert.pem -inkey mdm_private.key -out server_token.json
    The plaintext holds the DEP OAuth credentials.

  MANUAL STEP 3 — fetch the seeding tokens
    Authenticate to Apple's DEP API with those credentials and call
      GET /os-beta-enrollment/tokens
    Save the response — `{\"betaEnrollmentTokens\": [ … ]}` — to a file.

Then re-run this command with --tokens <that file>.";

/// Parse a tokens file. Accepts Apple's DEP response shape
/// (`{\"betaEnrollmentTokens\": [...]}`) or a bare array, and tolerates both
/// Apple's field names (`title`/`os`/`token`) and the declaration's own
/// (`Description`/`Token`) so an operator can hand-write a file.
///
/// # Errors
/// When the JSON is malformed, carries no recognizable token array, or an
/// entry is missing its token.
pub fn parse_beta_tokens(json: &str) -> Result<Vec<BetaToken>> {
    let root: serde_json::Value =
        serde_json::from_str(json).context("tokens file is not valid JSON")?;

    let array = root
        .get("betaEnrollmentTokens")
        .or_else(|| root.get("tokens"))
        .or(Some(&root))
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "tokens file has no token array — expected Apple's \
                 {{\"betaEnrollmentTokens\": [...]}} or a bare JSON array"
            )
        })?;

    let pick = |entry: &serde_json::Value, keys: [&str; 2]| -> Option<String> {
        keys.iter()
            .find_map(|k| entry.get(*k).and_then(|v| v.as_str()))
            .map(str::to_string)
    };

    let mut out = Vec::new();
    for (i, entry) in array.iter().enumerate() {
        let token = pick(entry, ["token", "Token"])
            .ok_or_else(|| anyhow::anyhow!("token entry {i} has no `token` (or `Token`) field"))?;
        let title = pick(entry, ["title", "Description"])
            .unwrap_or_else(|| format!("Beta program {}", i + 1));
        let os = pick(entry, ["os", "OS"]).unwrap_or_default();
        out.push(BetaToken { title, os, token });
    }

    if out.is_empty() {
        anyhow::bail!("tokens file contains no tokens");
    }
    Ok(out)
}

/// Keep only the tokens the operator selected, matching on title or token
/// value (case-insensitive on title). An empty selection keeps everything.
///
/// # Errors
/// When a selector matches nothing — a silent drop would ship a declaration
/// missing a program the operator asked for.
pub fn select_tokens(tokens: &[BetaToken], selectors: &[String]) -> Result<Vec<BetaToken>> {
    if selectors.is_empty() {
        return Ok(tokens.to_vec());
    }
    let mut out: Vec<BetaToken> = Vec::new();
    for sel in selectors {
        let hit = tokens
            .iter()
            .find(|t| t.token == *sel || t.title.eq_ignore_ascii_case(sel))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no beta program matches '{sel}' — available: {}",
                    tokens
                        .iter()
                        .map(|t| t.title.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            })?;
        if !out.contains(hit) {
            out.push(hit.clone());
        }
    }
    Ok(out)
}

/// Canonical platform label for Apple's OS tag. Apple returns `OSX` for
/// macOS in the seeding API; everything else passes through unchanged so new
/// platforms (HomePodOS, visionOS) group correctly without a code change.
pub fn normalize_os(os: &str) -> String {
    match os.trim() {
        "" => "unspecified".to_string(),
        s if s.eq_ignore_ascii_case("OSX") || s.eq_ignore_ascii_case("macOS") => {
            "macOS".to_string()
        }
        s => s.to_string(),
    }
}

/// Group tokens by canonical platform, preserving first-seen order so the
/// emitted per-OS declarations are deterministic.
pub fn group_by_os(tokens: &[BetaToken]) -> Vec<(String, Vec<BetaToken>)> {
    let mut groups: Vec<(String, Vec<BetaToken>)> = Vec::new();
    for t in tokens {
        let os = normalize_os(&t.os);
        match groups.iter_mut().find(|(g, _)| *g == os) {
            Some((_, list)) => list.push(t.clone()),
            None => groups.push((os, vec![t.clone()])),
        }
    }
    groups
}

/// Identifier for a per-OS declaration — the base identifier suffixed with
/// the lowercased platform, so a split emits distinct, non-clobbering
/// declarations.
pub fn per_os_identifier(base: &str, os: &str) -> String {
    format!("{base}.{}", os.to_lowercase())
}

/// Build the `Beta` payload object for a mode.
///
/// # Errors
/// When the mode's token cardinality is not met: `require` takes exactly one
/// program, `offer`/`always-on` take at least one.
pub fn build_beta_payload(mode: BetaMode, tokens: &[BetaToken]) -> Result<serde_json::Value> {
    let program = |t: &BetaToken| serde_json::json!({"Description": t.title, "Token": t.token});

    // A device enrols with a token for its own OS; a macOS device cannot use
    // a tvOS token. Apple issues one token per OS *and* release, so several
    // releases of one platform are fine — several platforms are not.
    let platforms = group_by_os(tokens);
    if platforms.len() > 1 {
        anyhow::bail!(
            "cannot mix platforms in one declaration ({}) — a device only enrols with \
             a token for its own OS. Use --split-by-os to emit one declaration per \
             platform, or --select to pick one platform's programs",
            platforms
                .iter()
                .map(|(os, list)| format!("{os} x{}", list.len()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let mut beta = serde_json::Map::new();
    beta.insert(
        "ProgramEnrollment".to_string(),
        serde_json::Value::String(mode.enrollment().to_string()),
    );

    match mode {
        BetaMode::Offer | BetaMode::AlwaysOn => {
            if tokens.is_empty() {
                anyhow::bail!("mode needs at least one beta program (pass --tokens)");
            }
            let programs: Vec<serde_json::Value> = tokens
                .iter()
                .map(|t| serde_json::json!({"Program": program(t)}))
                .collect();
            beta.insert(
                "OfferPrograms".to_string(),
                serde_json::Value::Array(programs),
            );
        }
        BetaMode::Require => {
            let [only] = tokens else {
                anyhow::bail!(
                    "`require` enrolls the device in exactly one program, but {} were selected — \
                     narrow it with --select <program>",
                    tokens.len()
                );
            };
            beta.insert("RequireProgram".to_string(), program(only));
        }
        // Block carries ProgramEnrollment only — any program key would be
        // rejected by Apple's own cross-key rules.
        BetaMode::Block => {}
    }

    Ok(serde_json::Value::Object(beta))
}

/// Handle `profile ddm beta`.
#[allow(clippy::too_many_arguments, reason = "CLI handler mirrors clap args")]
pub fn handle_ddm_beta(
    mode: BetaMode,
    tokens_file: Option<&str>,
    select: &[String],
    split_by_os: bool,
    interactive: bool,
    org: Option<&str>,
    identifier: Option<&str>,
    output: Option<&str>,
    config: Option<&ProfileConfig>,
    output_mode: OutputMode,
) -> Result<()> {
    // --- Gate: the manual artifact ---
    let tokens = match (mode.needs_tokens(), tokens_file) {
        (true, None) => {
            if output_mode == OutputMode::Json {
                contour_core::output::print_error_json(
                    "beta seeding tokens are required for this mode; see manual steps",
                    Some("MISSING_INPUT"),
                );
            } else {
                eprintln!(
                    "{} --tokens is required for `--mode {}`\n\n{MANUAL_TOKEN_STEPS}",
                    "✗".red(),
                    format!("{mode:?}").to_lowercase()
                );
            }
            anyhow::bail!("missing beta seeding tokens");
        }
        (true, Some(path)) => {
            let raw = std::fs::read_to_string(path)
                .with_context(|| format!("reading tokens file '{path}'"))?;
            let all = parse_beta_tokens(&raw)?;
            if interactive {
                pick_tokens_interactively(&all)?
            } else {
                select_tokens(&all, select)?
            }
        }
        (false, _) => Vec::new(),
    };

    let base_identifier = resolve_declaration_identifier(identifier, org, config, "settings")?;

    // --split-by-os: one declaration per platform, written into a directory.
    if split_by_os && mode.needs_tokens() {
        return emit_per_os(mode, &tokens, &base_identifier, output, output_mode);
    }

    let mut payload = DeclarationPayload::new();
    payload.insert("Beta".to_string(), build_beta_payload(mode, &tokens)?);

    let decl = Declaration {
        declaration_type: SWU_SETTINGS.to_string(),
        identifier: base_identifier,
        server_token: None,
        authentication: None,
        payload,
    };

    // Fail closed — same gate as `ddm generate`, and it now includes the
    // Beta cross-key rules.
    let registry = SchemaRegistry::embedded()?;
    let (errors, _) = declaration_errors(&decl, &registry);
    if !errors.is_empty() {
        anyhow::bail!(
            "generated beta declaration is invalid:\n  - {}",
            errors.join("\n  - ")
        );
    }

    match output {
        Some(path) => {
            write_declaration_file(&decl, Path::new(path))?;
            if output_mode == OutputMode::Json {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "output": path,
                        "identifier": decl.identifier,
                        "mode": format!("{mode:?}").to_lowercase(),
                        "programs": tokens.iter().map(|t| &t.title).collect::<Vec<_>>(),
                    })
                );
            } else {
                println!("{} Generated beta declaration: {path}", "✓".green());
                println!("  Identifier: {}", decl.identifier);
                println!("  Enrollment: {}", mode.enrollment());
                for t in &tokens {
                    println!("  Program:    {} ({})", t.title, t.os);
                }
            }
        }
        None => println!("{}", write_declaration(&decl)?),
    }

    Ok(())
}

/// Validate + write one declaration, returning it so callers can report.
fn build_and_check(mode: BetaMode, tokens: &[BetaToken], identifier: &str) -> Result<Declaration> {
    let mut payload = DeclarationPayload::new();
    payload.insert("Beta".to_string(), build_beta_payload(mode, tokens)?);
    let decl = Declaration {
        declaration_type: SWU_SETTINGS.to_string(),
        identifier: identifier.to_string(),
        server_token: None,
        authentication: None,
        payload,
    };
    let registry = SchemaRegistry::embedded()?;
    let (errors, _) = declaration_errors(&decl, &registry);
    if !errors.is_empty() {
        anyhow::bail!(
            "generated beta declaration is invalid:\n  - {}",
            errors.join("\n  - ")
        );
    }
    Ok(decl)
}

/// Emit one declaration per platform into `output` (a directory).
fn emit_per_os(
    mode: BetaMode,
    tokens: &[BetaToken],
    base_identifier: &str,
    output: Option<&str>,
    output_mode: OutputMode,
) -> Result<()> {
    let dir = output.ok_or_else(|| {
        anyhow::anyhow!("--split-by-os writes one file per platform; pass -o <DIRECTORY>")
    })?;
    std::fs::create_dir_all(dir).with_context(|| format!("creating output directory '{dir}'"))?;

    let groups = group_by_os(tokens);
    let mut written: Vec<serde_json::Value> = Vec::new();

    for (os, list) in &groups {
        // `require` is one program per declaration — per OS, take the single
        // selected program; more than one is ambiguous and build_beta_payload
        // will say so.
        let identifier = per_os_identifier(base_identifier, os);
        let decl = build_and_check(mode, list, &identifier)?;
        let file = format!("{dir}/beta-{}.json", os.to_lowercase());
        write_declaration_file(&decl, Path::new(&file))?;
        written.push(serde_json::json!({
            "os": os,
            "file": file,
            "identifier": identifier,
            "programs": list.iter().map(|t| &t.title).collect::<Vec<_>>(),
        }));
        if output_mode == OutputMode::Human {
            println!("{} {file}", "✓".green());
            println!("  Identifier: {identifier}");
            for t in list {
                println!("  Program:    {}", t.title);
            }
        }
    }

    if output_mode == OutputMode::Json {
        println!(
            "{}",
            serde_json::json!({
                "success": true,
                "mode": format!("{mode:?}").to_lowercase(),
                "declarations": written,
            })
        );
    } else {
        println!(
            "\n{} {} platform declaration(s) written to {dir}",
            "→".cyan(),
            groups.len()
        );
    }
    Ok(())
}

/// Interactive multi-select over the tokens, grouped by platform in the
/// prompt so an operator sees which OS each program belongs to.
fn pick_tokens_interactively(tokens: &[BetaToken]) -> Result<Vec<BetaToken>> {
    let labels: Vec<String> = tokens
        .iter()
        .map(|t| format!("[{}] {}", normalize_os(&t.os), t.title))
        .collect();
    let chosen = inquire::MultiSelect::new("Select beta programs:", labels.clone())
        .with_help_message("space toggles · enter confirms — mixing platforms needs --split-by-os")
        .prompt()
        .context("interactive selection cancelled")?;
    let picked: Vec<BetaToken> = labels
        .iter()
        .enumerate()
        .filter(|(_, l)| chosen.contains(l))
        .map(|(i, _)| tokens[i].clone())
        .collect();
    if picked.is_empty() {
        anyhow::bail!("no beta programs selected");
    }
    Ok(picked)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tok(title: &str, token: &str) -> BetaToken {
        BetaToken {
            title: title.into(),
            os: "OSX".into(),
            token: token.into(),
        }
    }

    /// Apple's DEP response shape goes in unmodified — an agent can pipe
    /// `/os-beta-enrollment/tokens` straight to a file.
    #[test]
    fn parses_apple_dep_response_shape() {
        let json = r#"{"betaEnrollmentTokens":[
            {"title":"macOS 27 Beta","os":"OSX","token":"AAA"},
            {"title":"iOS 27 Beta","os":"iOS","token":"BBB"}]}"#;
        let got = parse_beta_tokens(json).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].title, "macOS 27 Beta");
        assert_eq!(got[0].token, "AAA");
        assert_eq!(got[1].os, "iOS");
    }

    /// A bare array, and the declaration's own field names, also parse — so a
    /// hand-written file works without knowing Apple's wire format.
    #[test]
    fn parses_bare_array_and_declaration_field_names() {
        let json = r#"[{"Description":"Pilot ring","Token":"CCC"}]"#;
        let got = parse_beta_tokens(json).unwrap();
        assert_eq!(got[0].title, "Pilot ring");
        assert_eq!(got[0].token, "CCC");
    }

    #[test]
    fn rejects_entry_without_token() {
        let err = parse_beta_tokens(r#"[{"title":"No token here"}]"#).unwrap_err();
        assert!(err.to_string().contains("token"));
    }

    #[test]
    fn offer_mode_builds_allowed_with_offer_programs() {
        let payload = build_beta_payload(BetaMode::Offer, &[tok("Pilot", "AAA")]).unwrap();
        assert_eq!(payload["ProgramEnrollment"], "Allowed");
        assert_eq!(payload["OfferPrograms"][0]["Program"]["Token"], "AAA");
        assert_eq!(
            payload["OfferPrograms"][0]["Program"]["Description"],
            "Pilot"
        );
    }

    #[test]
    fn always_on_mode_builds_alwayson_with_offer_programs() {
        let payload =
            build_beta_payload(BetaMode::AlwaysOn, &[tok("A", "1"), tok("B", "2")]).unwrap();
        assert_eq!(payload["ProgramEnrollment"], "AlwaysOn");
        assert_eq!(payload["OfferPrograms"].as_array().unwrap().len(), 2);
        assert!(payload.get("RequireProgram").is_none());
    }

    #[test]
    fn require_mode_builds_alwayson_with_one_require_program() {
        let payload = build_beta_payload(BetaMode::Require, &[tok("Pilot", "AAA")]).unwrap();
        assert_eq!(payload["ProgramEnrollment"], "AlwaysOn");
        assert_eq!(payload["RequireProgram"]["Token"], "AAA");
        assert!(payload.get("OfferPrograms").is_none());
    }

    /// `require` is single-program by definition; two would be ambiguous.
    #[test]
    fn require_mode_rejects_multiple_programs() {
        let err = build_beta_payload(BetaMode::Require, &[tok("A", "1"), tok("B", "2")])
            .unwrap_err()
            .to_string();
        assert!(err.contains("exactly one"), "got: {err}");
        assert!(err.contains("--select"), "error should name the fix: {err}");
    }

    #[test]
    fn block_mode_carries_no_programs() {
        let payload = build_beta_payload(BetaMode::Block, &[]).unwrap();
        assert_eq!(payload["ProgramEnrollment"], "AlwaysOff");
        assert!(payload.get("OfferPrograms").is_none());
        assert!(payload.get("RequireProgram").is_none());
    }

    /// Every mode this command can emit must satisfy Apple's cross-key rules —
    /// the command cannot produce the illegal combinations by construction.
    #[test]
    fn every_mode_satisfies_apple_cross_key_rules() {
        let tokens = [tok("Pilot", "AAA")];
        for mode in [
            BetaMode::Offer,
            BetaMode::AlwaysOn,
            BetaMode::Require,
            BetaMode::Block,
        ] {
            let mut payload = DeclarationPayload::new();
            payload.insert(
                "Beta".to_string(),
                build_beta_payload(mode, &tokens).unwrap(),
            );
            let decl = Declaration {
                declaration_type: SWU_SETTINGS.to_string(),
                identifier: "com.acme.settings".to_string(),
                server_token: None,
                authentication: None,
                payload,
            };
            let registry = SchemaRegistry::embedded().unwrap();
            let (errors, _) = declaration_errors(&decl, &registry);
            assert!(errors.is_empty(), "{mode:?} produced errors: {errors:?}");
        }
    }

    #[test]
    fn select_filters_by_title_or_token_and_errors_on_miss() {
        let tokens = [tok("Pilot ring", "AAA"), tok("Security ring", "BBB")];
        assert_eq!(
            select_tokens(&tokens, &["pilot ring".to_string()]).unwrap(),
            vec![tok("Pilot ring", "AAA")]
        );
        assert_eq!(
            select_tokens(&tokens, &["BBB".to_string()]).unwrap(),
            vec![tok("Security ring", "BBB")]
        );
        assert!(select_tokens(&tokens, &[]).unwrap().len() == 2);
        let err = select_tokens(&tokens, &["nope".to_string()]).unwrap_err();
        assert!(err.to_string().contains("Pilot ring"), "lists options");
    }

    /// A macOS device cannot enrol with a tvOS seeding token. Apple returns
    /// one token per OS *and* release, so a single declaration must not mix
    /// platforms — the device would silently fail to enrol.
    #[test]
    fn mixing_os_tokens_is_rejected_with_the_fix_named() {
        let mixed = [
            BetaToken {
                title: "macOS 27".into(),
                os: "OSX".into(),
                token: "M".into(),
            },
            BetaToken {
                title: "tvOS 27".into(),
                os: "tvOS".into(),
                token: "T".into(),
            },
        ];
        let err = build_beta_payload(BetaMode::Offer, &mixed)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("macOS") && err.contains("tvOS"),
            "names the platforms: {err}"
        );
        assert!(err.contains("--split-by-os"), "names the fix: {err}");
    }

    /// Several releases of the SAME OS are legitimate in one declaration —
    /// that is exactly what OfferPrograms is for.
    #[test]
    fn multiple_releases_of_one_os_are_allowed() {
        let same = [
            BetaToken {
                title: "macOS 26 Tahoe".into(),
                os: "OSX".into(),
                token: "A".into(),
            },
            BetaToken {
                title: "macOS 27 Golden Gate".into(),
                os: "OSX".into(),
                token: "B".into(),
            },
        ];
        let payload = build_beta_payload(BetaMode::Offer, &same).unwrap();
        assert_eq!(payload["OfferPrograms"].as_array().unwrap().len(), 2);
    }

    /// Apple labels macOS tokens "OSX"; grouping must not treat that as a
    /// different platform from "macOS".
    #[test]
    fn os_labels_are_normalised() {
        assert_eq!(normalize_os("OSX"), "macOS");
        assert_eq!(normalize_os("macOS"), "macOS");
        assert_eq!(normalize_os("iOS"), "iOS");
        assert_eq!(normalize_os("HomePodOS"), "HomePodOS");
        assert_eq!(normalize_os(""), "unspecified");
    }

    /// Splitting yields one group per platform, in stable order, so
    /// `--split-by-os` emits deterministic per-platform declarations.
    #[test]
    fn group_by_os_splits_into_platform_groups() {
        let tokens = [
            BetaToken {
                title: "macOS 27".into(),
                os: "OSX".into(),
                token: "M1".into(),
            },
            BetaToken {
                title: "tvOS 27".into(),
                os: "tvOS".into(),
                token: "T1".into(),
            },
            BetaToken {
                title: "macOS 26".into(),
                os: "OSX".into(),
                token: "M2".into(),
            },
        ];
        let groups = group_by_os(&tokens);
        assert_eq!(groups.len(), 2);
        assert_eq!(groups[0].0, "macOS");
        assert_eq!(groups[0].1.len(), 2, "both macOS releases in one group");
        assert_eq!(groups[1].0, "tvOS");
    }

    /// Per-OS identifiers must be distinct, or the split would emit several
    /// declarations that overwrite each other on device.
    #[test]
    fn per_os_identifier_is_suffixed() {
        assert_eq!(
            per_os_identifier("com.acme.settings", "macOS"),
            "com.acme.settings.macos"
        );
        assert_eq!(
            per_os_identifier("com.acme.settings", "tvOS"),
            "com.acme.settings.tvos"
        );
    }

    /// The manual steps must name the artifact and the endpoint an operator
    /// (or agent) needs — this text is the workflow's handoff contract.
    #[test]
    fn manual_steps_name_the_artifacts() {
        assert!(MANUAL_TOKEN_STEPS.contains(".p7m"));
        assert!(MANUAL_TOKEN_STEPS.contains("/os-beta-enrollment/tokens"));
        assert!(MANUAL_TOKEN_STEPS.contains("--tokens"));
    }
}
