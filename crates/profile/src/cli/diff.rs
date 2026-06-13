use crate::diff;
use crate::profile::parser;
use anyhow::Result;
use colored::Colorize;

pub fn handle_diff(
    file1: &str,
    file2: &str,
    output: Option<&str>,
    md_report: Option<&str>,
) -> Result<()> {
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
