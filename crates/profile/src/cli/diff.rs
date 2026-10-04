use crate::diff;
use crate::profile::parser;
use anyhow::Result;
use colored::Colorize;

/// How `profile diff` should compare and report.
#[derive(Debug, Clone, Copy, Default)]
pub struct DiffMode {
    /// Pair payloads and walk to the leaves instead of diffing XML lines.
    pub structural: bool,
    /// Drop `Payload*` bookkeeping leaves. Only meaningful with `structural`.
    pub settings_only: bool,
    /// Emit JSON. A line diff has no JSON form, so this implies `structural`.
    pub json: bool,
}

pub fn handle_diff(
    file1: &str,
    file2: &str,
    output: Option<&str>,
    md_report: Option<&str>,
    mode: DiffMode,
) -> Result<()> {
    if mode.structural || mode.json {
        return handle_structural(file1, file2, output, mode);
    }

    println!("{}", "Comparing configuration profiles...".cyan());

    let profile1 = parser::parse_profile_auto_unsign(file1)?;
    println!("{}", format!("✓ Loaded: {file1}").green());

    let profile2 = parser::parse_profile_auto_unsign(file2)?;
    println!("{}", format!("✓ Loaded: {file2}").green());

    println!();
    let diff_result = diff::diff_profiles(&profile1, &profile2)?;

    if let Some(output_path) = output {
        diff::save_diff(&diff_result, output_path)?;
        println!("{}", format!("✓ Diff saved to: {output_path}").green());
    } else {
        diff::print_diff(&diff_result);
    }

    if let Some(md_path) = md_report {
        let md = diff::diff_markdown(&profile1, &profile2, file1, file2)?;
        std::fs::write(md_path, md).map_err(|e| anyhow::anyhow!("writing {md_path}: {e}"))?;
        println!("{}", format!("✓ Report written to: {md_path}").green());
    }

    if diff_result.has_differences {
        println!();
        println!("{}", "Profiles are different".yellow());
    } else {
        println!();
        println!("{}", "Profiles are identical".green());
    }

    Ok(())
}

/// Structural comparison. Nothing is printed before the result so that JSON
/// on stdout is exactly one document.
fn handle_structural(file1: &str, file2: &str, output: Option<&str>, mode: DiffMode) -> Result<()> {
    let profile1 = parser::parse_profile_auto_unsign(file1)?;
    let profile2 = parser::parse_profile_auto_unsign(file2)?;

    let mut d = diff::structural_diff(&profile1, &profile2, file1, file2);
    if mode.settings_only {
        d = d.settings_only();
    }

    let rendered = if mode.json {
        serde_json::to_string_pretty(&d)?
    } else {
        diff::structural::render_text(&d)
    };

    match output {
        Some(path) => {
            std::fs::write(path, &rendered).map_err(|e| anyhow::anyhow!("writing {path}: {e}"))?;
            if !mode.json {
                println!("{}", format!("✓ Diff saved to: {path}").green());
            }
        }
        None => print!("{rendered}"),
    }

    if mode.json {
        // Trailing newline for the shell; the document itself has none.
        if output.is_none() {
            println!();
        }
    } else {
        println!();
        if d.has_differences {
            println!("{}", "Profiles are different".yellow());
        } else {
            println!("{}", "Profiles are identical".green());
        }
    }
    Ok(())
}
