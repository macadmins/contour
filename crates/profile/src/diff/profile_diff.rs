//! Profile diff - compare two configuration profiles

use crate::profile::ConfigurationProfile;
use anyhow::Result;
use colored::Colorize;
use similar::{ChangeTag, TextDiff};
use std::fs;

#[derive(Debug)]
pub struct DiffResult {
    pub has_differences: bool,
    pub diff_text: String,
}

pub fn diff_profiles(
    profile1: &ConfigurationProfile,
    profile2: &ConfigurationProfile,
) -> Result<DiffResult> {
    let profile1_str = serialize_for_diff(profile1)?;
    let profile2_str = serialize_for_diff(profile2)?;

    let diff = TextDiff::from_lines(&profile1_str, &profile2_str);

    let mut diff_text = String::new();
    let mut has_differences = false;

    for change in diff.iter_all_changes() {
        let sign = match change.tag() {
            ChangeTag::Delete => {
                has_differences = true;
                format!("{}", "- ".red())
            }
            ChangeTag::Insert => {
                has_differences = true;
                format!("{}", "+ ".green())
            }
            ChangeTag::Equal => "  ".to_string(),
        };

        let line = format!("{sign}{change}");
        diff_text.push_str(&line);
    }

    Ok(DiffResult {
        has_differences,
        diff_text,
    })
}

fn serialize_for_diff(profile: &ConfigurationProfile) -> Result<String> {
    let mut buffer = Vec::new();
    plist::to_writer_xml(&mut buffer, profile)?;
    Ok(String::from_utf8(buffer)?)
}

pub fn print_diff(diff_result: &DiffResult) {
    if !diff_result.has_differences {
        println!("{}", "No differences found.".green());
    } else {
        println!("{}", "Differences found:".yellow());
        println!("{}", diff_result.diff_text);
    }
}

pub fn save_diff(diff_result: &DiffResult, path: &str) -> Result<()> {
    fs::write(path, &diff_result.diff_text)?;
    Ok(())
}
