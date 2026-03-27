use crate::diff;
use crate::profile::parser;
use anyhow::Result;
use colored::Colorize;

pub fn handle_diff(file1: &str, file2: &str, output: Option<&str>) -> Result<()> {
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

    if diff_result.has_differences {
        println!();
        println!("{}", "Profiles are different".yellow());
    } else {
        println!();
        println!("{}", "Profiles are identical".green());
    }

    Ok(())
}
