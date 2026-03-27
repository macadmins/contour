//! Interactive selection command for curating Santa allowlists.
//!
//! Provides a guided workflow to review apps from Fleet CSV and
//! select which ones to allow.

use crate::cel::AppRecord;
use crate::discovery::parse_fleet_csv_file;
use crate::models::{Policy, Rule, RuleSet, RuleType};
use crate::output::{print_info, print_kv, print_success};
use anyhow::Result;
use colored::Colorize;
use inquire::{Confirm, MultiSelect, Select};
use std::collections::HashMap;
use std::path::Path;

/// Vendor grouping for selection.
#[derive(Debug, Clone)]
struct VendorGroup {
    team_id: String,
    name: String,
    apps: Vec<AppInfo>,
}

impl VendorGroup {
    /// Get a display string showing vendor name and sample apps.
    fn display_with_samples(&self) -> String {
        let sample_apps: Vec<&str> = self
            .apps
            .iter()
            .take(3)
            .map(|a| a.app_name.as_str())
            .collect();
        let samples = sample_apps.join(", ");
        let more = if self.apps.len() > 3 {
            format!(", +{} more", self.apps.len() - 3)
        } else {
            String::new()
        };
        format!(
            "{} [{}] - {} apps ({}{})",
            self.name,
            self.team_id,
            self.apps.len(),
            samples,
            more
        )
    }
}

/// App information for selection.
#[derive(Debug, Clone)]
struct AppInfo {
    signing_id: String,
    app_name: String,
    device_count: usize,
}

impl std::fmt::Display for AppInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} - {} devices", self.app_name, self.device_count)
    }
}

/// Run the interactive select command.
pub fn run(
    input: &Path,
    output: Option<&Path>,
    rule_type: &str,
    org: &str,
    json_output: bool,
) -> Result<()> {
    let _ = org; // reserved for future use
    // Parse CSV
    print_info(&format!("Loading apps from: {}", input.display()));
    let apps = parse_fleet_csv_file(input)?;
    print_kv("Apps loaded", &apps.len().to_string());

    // Group by vendor (TeamID)
    let vendors = group_by_vendor(apps.apps());
    print_kv("Vendors found", &vendors.len().to_string());

    if vendors.is_empty() {
        print_info("No signed apps found in the CSV.");
        return Ok(());
    }

    // Print welcome banner
    println!();
    println!("{}", "=".repeat(70));
    println!(
        "{}",
        "  Santa Allowlist Builder - Interactive Selection"
            .bold()
            .cyan()
    );
    println!("{}", "=".repeat(70));
    println!();
    println!("This wizard helps you build a Santa allowlist from your fleet's apps.");
    println!();
    println!("{}", "What is Santa?".bold());
    println!("Santa is a binary authorization system for macOS. It controls which");
    println!("applications can run on your fleet by maintaining allow/block lists.");
    println!();
    println!("{}", "How this works:".bold());
    println!("1. Your Fleet CSV contains apps detected across your devices");
    println!(
        "2. Apps are grouped by {} (Apple's developer identifier)",
        "TeamID".cyan()
    );
    println!("3. You'll select which vendors/apps to allow");
    println!("4. We generate Santa rules for your MDM to deploy");
    println!();

    // Show quick summary of what we found
    let total_apps: usize = vendors.iter().map(|v| v.apps.len()).sum();
    println!("{}", "Fleet Summary:".bold());
    println!(
        "  {} unique vendors (companies/developers)",
        vendors.len().to_string().green()
    );
    println!("  {} unique applications", total_apps.to_string().green());
    println!();

    // Step 1: Choose selection mode
    let mode = Select::new(
        "How would you like to select apps to allow?",
        vec![
            SelectionMode::ByVendor,
            SelectionMode::ByApp,
            SelectionMode::ReviewAll,
        ],
    )
    .with_help_message("Use arrow keys to navigate, Enter to select")
    .prompt()?;

    let selected_rules = match mode {
        SelectionMode::ByVendor => select_by_vendor(&vendors, rule_type)?,
        SelectionMode::ByApp => select_by_app(&vendors, rule_type)?,
        SelectionMode::ReviewAll => review_all(&vendors, rule_type)?,
    };

    if selected_rules.is_empty() {
        print_info("No apps selected. No rules generated.");
        return Ok(());
    }

    // Show summary
    println!();
    println!("{}", "Selection Summary".bold());
    println!("{}", "-".repeat(50));
    println!(
        "  Rules to generate: {}",
        selected_rules.len().to_string().green()
    );

    let rule_type_desc = if rule_type == "team-id" {
        "TeamID (vendor-level, allows all apps from selected vendors)"
    } else {
        "SigningID (app-level, allows specific applications)"
    };
    println!("  Rule type: {}", rule_type_desc);
    println!();

    // Confirm
    if !Confirm::new("Generate these rules?")
        .with_default(true)
        .with_help_message("Rules will be written to the output file")
        .prompt()?
    {
        print_info("Cancelled. No rules generated.");
        return Ok(());
    }

    // Generate rules
    let ruleset = RuleSet::from_rules(selected_rules.clone());

    if json_output {
        println!("{}", serde_json::to_string_pretty(ruleset.rules())?);
        return Ok(());
    }

    // Write single output
    if let Some(output_path) = output {
        let yaml = yaml_serde::to_string(ruleset.rules())?;
        std::fs::write(output_path, yaml)?;
        print_success(&format!(
            "Generated {} rules -> {}",
            ruleset.len(),
            output_path.display()
        ));
        println!();
        println!("{}", "Next steps:".bold());
        println!("  1. Review the generated rules: {}", output_path.display());
        println!(
            "  2. Generate mobileconfig: contour santa generate {} -o santa.mobileconfig",
            output_path.display()
        );
        println!("  3. Deploy via your MDM (Fleet, Jamf, etc.)");
    } else {
        // Print to stdout
        println!();
        println!("{}", "Generated Rules (YAML)".bold());
        println!("{}", "-".repeat(50));
        println!("{}", yaml_serde::to_string(ruleset.rules())?);
    }

    Ok(())
}

/// Selection mode enum for better display.
#[derive(Debug, Clone, Copy)]
enum SelectionMode {
    ByVendor,
    ByApp,
    ReviewAll,
}

impl std::fmt::Display for SelectionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SelectionMode::ByVendor => write!(
                f,
                "By vendor - Trust entire companies (e.g., allow ALL Microsoft apps)"
            ),
            SelectionMode::ByApp => write!(
                f,
                "By app - Review each vendor and pick specific apps to allow"
            ),
            SelectionMode::ReviewAll => {
                write!(f, "Review all - See complete inventory first, then decide")
            }
        }
    }
}

/// Group apps by vendor (TeamID).
fn group_by_vendor(apps: &[AppRecord]) -> Vec<VendorGroup> {
    let mut by_team: HashMap<String, VendorGroup> = HashMap::new();

    for app in apps {
        let Some(team_id) = &app.team_id else {
            continue;
        };
        let Some(signing_id) = &app.signing_id else {
            continue;
        };

        // Try to derive a vendor name from the app
        let vendor_name = app
            .vendor
            .clone()
            .or_else(|| derive_vendor_name(app))
            .unwrap_or_else(|| format!("Unknown Vendor ({})", team_id));

        let entry = by_team
            .entry(team_id.clone())
            .or_insert_with(|| VendorGroup {
                team_id: team_id.clone(),
                name: vendor_name,
                apps: Vec::new(),
            });

        // Check if we already have this signing_id
        if !entry.apps.iter().any(|a| a.signing_id == *signing_id) {
            entry.apps.push(AppInfo {
                signing_id: signing_id.clone(),
                app_name: app
                    .app_name
                    .clone()
                    .unwrap_or_else(|| "Unknown App".to_string()),
                device_count: app.device_count,
            });
        }
    }

    let mut vendors: Vec<_> = by_team.into_values().collect();
    // Sort by number of apps (most apps first)
    vendors.sort_by(|a, b| b.apps.len().cmp(&a.apps.len()));

    // Sort apps within each vendor by device count
    for vendor in &mut vendors {
        vendor
            .apps
            .sort_by(|a, b| b.device_count.cmp(&a.device_count));
    }

    vendors
}

/// Try to derive a friendly vendor name from app metadata.
fn derive_vendor_name(app: &AppRecord) -> Option<String> {
    // Known Team ID -> vendor name mappings
    if let Some(team_id) = &app.team_id {
        let known_teams = [("7R5ZEU67FQ", "SAP")];
        for (tid, name) in known_teams {
            if team_id == tid {
                return Some(name.to_string());
            }
        }
    }

    // Try to extract from signing_id (e.g., "EQHXZ8M8AV:com.google.Chrome" -> "Google")
    if let Some(signing_id) = &app.signing_id {
        if let Some(bundle_part) = signing_id.split(':').nth(1) {
            // Common bundle ID patterns -> vendor names
            let known_vendors = [
                // Major vendors
                ("com.google.", "Google"),
                ("com.apple.", "Apple"),
                ("com.microsoft.", "Microsoft"),
                ("com.tinyspeck.", "Slack"),
                ("us.zoom.", "Zoom"),
                ("com.1password.", "1Password (AgileBits)"),
                ("com.vmware.", "VMware"),
                ("org.mozilla.", "Mozilla"),
                ("com.grammarly.", "Grammarly"),
                ("com.docker.", "Docker"),
                ("com.jetbrains.", "JetBrains"),
                ("com.sublimetext.", "Sublime Text"),
                ("com.sublimehq.", "Sublime HQ"),
                ("com.github.", "GitHub"),
                ("io.github.", "GitHub"),
                ("com.logi.", "Logitech"),
                ("org.wireshark.", "Wireshark Foundation"),
                ("com.spotify.", "Spotify"),
                ("com.dropbox.", "Dropbox"),
                ("com.adobe.", "Adobe"),
                ("com.notion.", "Notion"),
                ("com.figma.", "Figma"),
                ("com.linear.", "Linear"),
                ("com.postman.", "Postman"),
                ("com.insomnia.", "Insomnia"),
                ("com.iterm2.", "iTerm2"),
                ("com.brave.", "Brave"),
                ("io.ray.", "Raycast"),
                ("com.raycast.", "Raycast"),
                ("com.alfredapp.", "Alfred"),
                ("com.bitwarden.", "Bitwarden"),
                ("com.lastpass.", "LastPass"),
                ("com.nordvpn.", "NordVPN"),
                ("com.expressvpn.", "ExpressVPN"),
                ("com.cisco.", "Cisco"),
                ("com.crowdstrike.", "CrowdStrike"),
                ("com.sentinelone.", "SentinelOne"),
                ("com.jamf.", "Jamf"),
                ("com.kandji.", "Kandji"),
                ("com.mosyle.", "Mosyle"),
                ("com.hexnode.", "Hexnode"),
                ("dev.warp.", "Warp"),
                ("com.hashicorp.", "HashiCorp"),
                ("com.sap.", "SAP"),
            ];

            for (prefix, name) in known_vendors {
                if bundle_part.starts_with(prefix) {
                    return Some(name.to_string());
                }
            }
        }
    }

    // Try to extract from app name patterns
    if let Some(app_name) = &app.app_name {
        let name_lower = app_name.to_lowercase();
        let known_apps = [
            // Browsers
            ("chrome", "Google"),
            ("firefox", "Mozilla"),
            ("safari", "Apple"),
            ("brave", "Brave"),
            // Communication
            ("slack", "Slack"),
            ("zoom", "Zoom"),
            ("teams", "Microsoft"),
            ("discord", "Discord"),
            // Productivity
            ("1password", "1Password (AgileBits)"),
            ("microsoft", "Microsoft"),
            ("word", "Microsoft"),
            ("excel", "Microsoft"),
            ("powerpoint", "Microsoft"),
            ("outlook", "Microsoft"),
            ("visual studio", "Microsoft"),
            ("vscode", "Microsoft"),
            ("keynote", "Apple"),
            ("pages", "Apple"),
            ("numbers", "Apple"),
            ("garageband", "Apple"),
            ("imovie", "Apple"),
            ("xcode", "Apple"),
            // Development
            ("vmware", "VMware"),
            ("docker", "Docker"),
            ("intellij", "JetBrains"),
            ("pycharm", "JetBrains"),
            ("webstorm", "JetBrains"),
            ("goland", "JetBrains"),
            ("rider", "JetBrains"),
            ("sublime", "Sublime HQ"),
            ("github", "GitHub"),
            ("postman", "Postman"),
            ("insomnia", "Insomnia"),
            ("iterm", "iTerm2"),
            ("warp", "Warp"),
            // Utilities
            ("grammarly", "Grammarly"),
            ("logitech", "Logitech"),
            ("logi options", "Logitech"),
            ("wireshark", "Wireshark Foundation"),
            ("spotify", "Spotify"),
            ("dropbox", "Dropbox"),
            ("adobe", "Adobe"),
            ("photoshop", "Adobe"),
            ("illustrator", "Adobe"),
            ("premiere", "Adobe"),
            ("notion", "Notion"),
            ("figma", "Figma"),
            ("linear", "Linear"),
            ("raycast", "Raycast"),
            ("alfred", "Alfred"),
            ("bitwarden", "Bitwarden"),
            ("lastpass", "LastPass"),
            // Security
            ("crowdstrike", "CrowdStrike"),
            ("falcon", "CrowdStrike"),
            ("sentinelone", "SentinelOne"),
            // MDM
            ("jamf", "Jamf"),
            ("kandji", "Kandji"),
            ("mosyle", "Mosyle"),
            ("nudge", "macadmins (Nudge)"),
            // Additional apps
            ("virtualbuddy", "VirtualBuddy"),
            ("unblocked", "Next Chapter Software"),
            ("imazing", "DigiDNA"),
            ("logioptionsplus", "Logitech"),
        ];

        for (pattern, vendor) in known_apps {
            if name_lower.contains(pattern) {
                return Some(vendor.to_string());
            }
        }
    }

    // Try to extract vendor from bundle ID's second component
    // e.g., "TEAMID:com.sindresorhus.Gifski" -> "sindresorhus"
    if let Some(signing_id) = &app.signing_id {
        if let Some(bundle_part) = signing_id.split(':').nth(1) {
            let parts: Vec<&str> = bundle_part.split('.').collect();
            if parts.len() >= 2 {
                let vendor_part = parts[1];
                // Skip generic prefixes
                if !["apple", "app", "apps", "mac"].contains(&vendor_part.to_lowercase().as_str())
                    && vendor_part.len() > 2
                {
                    // Capitalize first letter
                    let mut name = vendor_part.to_string();
                    if let Some(first) = name.get_mut(..1) {
                        first.make_ascii_uppercase();
                    }
                    return Some(name);
                }
            }
        }
    }

    None
}

/// Select by vendor - allow entire vendors.
fn select_by_vendor(vendors: &[VendorGroup], rule_type: &str) -> Result<Vec<Rule>> {
    println!();
    println!("{}", "Vendor Selection Mode".bold());
    println!("{}", "-".repeat(50));
    println!();
    println!("Select vendors to trust. All apps from selected vendors will be allowed.");
    println!(
        "This is the {} approach - fewer rules, broader trust.",
        "recommended".green()
    );
    println!();

    let options: Vec<String> = vendors.iter().map(|v| v.display_with_samples()).collect();

    let selected = MultiSelect::new(
        "Select vendors to allow (Space to toggle, Enter to confirm):",
        options.clone(),
    )
    .with_page_size(15)
    .with_help_message("Use arrow keys to navigate, Space to select/deselect, Enter to confirm")
    .prompt()?;

    let mut rules = Vec::new();

    for selection in &selected {
        // Map back to vendor using index position in the labels list
        let Some(idx) = options.iter().position(|l| l == selection) else {
            anyhow::bail!("selected item not found in options list: {selection}");
        };
        let vendor = &vendors[idx];

        if rule_type == "team-id" {
            // Single TeamID rule for entire vendor
            rules.push(
                Rule::new(RuleType::TeamId, &vendor.team_id, Policy::Allowlist)
                    .with_description(&vendor.name)
                    .with_group("selected"),
            );
        } else {
            // SigningID rules for each app
            for app in &vendor.apps {
                rules.push(
                    Rule::new(RuleType::SigningId, &app.signing_id, Policy::Allowlist)
                        .with_description(&app.app_name)
                        .with_group(&vendor.name),
                );
            }
        }
    }

    Ok(rules)
}

/// Select by app - allow individual apps.
fn select_by_app(vendors: &[VendorGroup], rule_type: &str) -> Result<Vec<Rule>> {
    println!();
    println!("{}", "App-by-App Selection Mode".bold());
    println!("{}", "-".repeat(50));
    println!();
    println!("You'll review each vendor and select specific apps to allow.");
    println!(
        "This gives you {} control over your allowlist.",
        "fine-grained".cyan()
    );
    println!();

    let mut rules = Vec::new();
    let mut skipped_vendors = 0;

    for vendor in vendors {
        println!();
        println!("{}", "=".repeat(60));
        println!("{} {}", "Vendor:".bold(), vendor.name.cyan());
        println!("  TeamID: {}", vendor.team_id.dimmed());
        println!("  Apps: {}", vendor.apps.len());
        println!();

        // Show sample apps
        println!("  {}", "Sample apps from this vendor:".dimmed());
        for app in vendor.apps.iter().take(5) {
            println!(
                "    {} {} (on {} devices)",
                "•".dimmed(),
                app.app_name,
                app.device_count
            );
        }
        if vendor.apps.len() > 5 {
            println!("    {} ...and {} more", "•".dimmed(), vendor.apps.len() - 5);
        }
        println!();

        let review = Confirm::new(&format!("Review and select apps from {}?", vendor.name))
            .with_default(true)
            .with_help_message("Press 'n' to skip this vendor entirely")
            .prompt()?;

        if !review {
            skipped_vendors += 1;
            continue;
        }

        let options: Vec<String> = vendor.apps.iter().map(|a| a.to_string()).collect();

        let selected = MultiSelect::new(
            &format!(
                "Select apps to allow from {} (Space to toggle):",
                vendor.name
            ),
            options.clone(),
        )
        .with_page_size(15)
        .with_help_message("Space to select, Enter to confirm, Esc to cancel")
        .prompt()?;

        if selected.is_empty() {
            println!("  {} No apps selected from this vendor", "→".dimmed());
            continue;
        }

        println!("  {} Selected {} apps", "✓".green(), selected.len());

        for selection in &selected {
            // Map back to app using index position in the labels list
            let Some(idx) = options.iter().position(|l| l == selection) else {
                anyhow::bail!("selected app not found in options list: {selection}");
            };
            let app = &vendor.apps[idx];

            if rule_type == "team-id" {
                // Use TeamID (will deduplicate later)
                if !rules.iter().any(|r: &Rule| r.identifier == vendor.team_id) {
                    rules.push(
                        Rule::new(RuleType::TeamId, &vendor.team_id, Policy::Allowlist)
                            .with_description(&vendor.name)
                            .with_group("selected"),
                    );
                }
            } else {
                rules.push(
                    Rule::new(RuleType::SigningId, &app.signing_id, Policy::Allowlist)
                        .with_description(&app.app_name)
                        .with_group(&vendor.name),
                );
            }
        }
    }

    if skipped_vendors > 0 {
        println!();
        println!("  {} Skipped {} vendors", "ℹ".dimmed(), skipped_vendors);
    }

    Ok(rules)
}

/// Review all apps and decide.
fn review_all(vendors: &[VendorGroup], rule_type: &str) -> Result<Vec<Rule>> {
    println!();
    println!("{}", "Complete Fleet Inventory".bold());
    println!("{}", "=".repeat(60));
    println!();

    // Show summary first
    let total_apps: usize = vendors.iter().map(|v| v.apps.len()).sum();
    println!(
        "Your fleet has {} apps from {} vendors:\n",
        total_apps.to_string().green(),
        vendors.len().to_string().green()
    );

    // Show each vendor with their apps
    for vendor in vendors {
        println!(
            "{} {} {}",
            "▸".green(),
            vendor.name.bold(),
            format!("[{}]", vendor.team_id).dimmed()
        );
        for app in &vendor.apps {
            println!(
                "    {} {} {}",
                "•".dimmed(),
                app.app_name,
                format!("({} devices)", app.device_count).dimmed()
            );
        }
        println!();
    }

    // Now ask how to proceed
    println!("{}", "-".repeat(60));
    let action = Select::new(
        "Now that you've seen everything, how would you like to proceed?",
        vec![
            ReviewAction::AllowAll,
            ReviewAction::SelectByVendor,
            ReviewAction::SelectByApp,
            ReviewAction::Cancel,
        ],
    )
    .with_help_message("Choose how to build your allowlist")
    .prompt()?;

    match action {
        ReviewAction::AllowAll => {
            println!();
            println!(
                "{} This will allow ALL {} apps from ALL {} vendors.",
                "Warning:".yellow().bold(),
                total_apps,
                vendors.len()
            );

            let confirm = Confirm::new("Are you sure you want to allow everything?")
                .with_default(false)
                .prompt()?;

            if !confirm {
                return Ok(Vec::new());
            }

            let mut rules = Vec::new();
            for vendor in vendors {
                if rule_type == "team-id" {
                    rules.push(
                        Rule::new(RuleType::TeamId, &vendor.team_id, Policy::Allowlist)
                            .with_description(&vendor.name)
                            .with_group("all"),
                    );
                } else {
                    for app in &vendor.apps {
                        rules.push(
                            Rule::new(RuleType::SigningId, &app.signing_id, Policy::Allowlist)
                                .with_description(&app.app_name)
                                .with_group(&vendor.name),
                        );
                    }
                }
            }
            Ok(rules)
        }
        ReviewAction::SelectByVendor => select_by_vendor(vendors, rule_type),
        ReviewAction::SelectByApp => select_by_app(vendors, rule_type),
        ReviewAction::Cancel => Ok(Vec::new()),
    }
}

/// Review action enum for better display.
#[derive(Debug, Clone, Copy)]
enum ReviewAction {
    AllowAll,
    SelectByVendor,
    SelectByApp,
    Cancel,
}

impl std::fmt::Display for ReviewAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReviewAction::AllowAll => write!(f, "Allow everything (trust all vendors and apps)"),
            ReviewAction::SelectByVendor => {
                write!(f, "Select by vendor (pick which companies to trust)")
            }
            ReviewAction::SelectByApp => write!(f, "Select by app (pick specific applications)"),
            ReviewAction::Cancel => write!(f, "Cancel (generate no rules)"),
        }
    }
}
