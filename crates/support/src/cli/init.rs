use std::path::Path;

use colored::Colorize;

use crate::config::{BrandEntry, CommonSettings, SupportConfig};
use crate::discovery;

/// Run the `support init` command: scan asset folders and write a config file.
pub fn run(asset_path: &Path, output: Option<&Path>) -> anyhow::Result<()> {
    let output_path = output.unwrap_or_else(|| Path::new("support.toml"));

    println!(
        "{} Scanning {}",
        "scanning:".cyan().bold(),
        asset_path.display()
    );

    let brands = discovery::scan_brands(asset_path)?;

    if brands.is_empty() {
        anyhow::bail!(
            "No brand folders found in {}. Expected subdirectories with logo.png, logo_darkmode.png, and support-app-menubar-icon.png",
            asset_path.display()
        );
    }

    let brand_names: Vec<String> = brands.iter().map(|b| b.name.clone()).collect();

    let config = SupportConfig {
        common: CommonSettings::defaults(),
        brands: brands
            .into_iter()
            .map(|b| BrandEntry {
                name: b.name,
                folder: b.folder,
                logo: b.logo,
                logo_darkmode: b.logo_darkmode,
                menubar_icon: b.menubar_icon,
                title: None,
                footer_text: None,
                error_message: None,
                password_type: None,
                storage_limit: None,
                show_welcome_screen: None,
                open_at_login: None,
                disable_configurator_mode: None,
                disable_privileged_helper_tool: None,
                status_bar_icon_allows_color: None,
                status_bar_icon_notifier_enabled: None,
                custom_color: None,
                custom_color_darkmode: None,
                info_items: None,
                uptime_days_limit: None,
                rows: None,
            })
            .collect(),
    };

    config.save(output_path)?;

    println!(
        "\n{} Found {} brands ({}). Created {}",
        "success:".green().bold(),
        brand_names.len(),
        brand_names.join(", "),
        output_path.display(),
    );
    println!(
        "\n{} Edit {} to customize settings, then run:",
        "next:".cyan().bold(),
        output_path.display()
    );
    println!("  contour support generate {}", output_path.display());

    Ok(())
}
