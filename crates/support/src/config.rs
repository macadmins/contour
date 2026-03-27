use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level config loaded from `support.toml`.
#[derive(Debug, Deserialize, Serialize)]
pub struct SupportConfig {
    pub common: CommonSettings,
    pub brands: Vec<BrandEntry>,
}

/// Shared settings applied to all brands unless overridden.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct CommonSettings {
    pub org: String,
    pub payload_display_name: String,
    pub error_message: String,
    pub footer_text: String,
    pub password_type: String,
    pub storage_limit: u32,
    pub show_welcome_screen: bool,
    pub open_at_login: bool,
    pub disable_configurator_mode: bool,
    pub disable_privileged_helper_tool: bool,
    pub status_bar_icon_allows_color: bool,
    pub status_bar_icon_notifier_enabled: bool,
    pub title: String,
    pub custom_color: Option<String>,
    pub custom_color_darkmode: Option<String>,
    pub info_items: Option<Vec<String>>,
    pub uptime_days_limit: Option<u32>,
    #[serde(default)]
    pub rows: Vec<RowDef>,
}

/// Per-brand entry with asset paths and optional overrides.
#[derive(Debug, Deserialize, Serialize)]
pub struct BrandEntry {
    pub name: String,
    pub folder: PathBuf,
    pub logo: PathBuf,
    pub logo_darkmode: PathBuf,
    pub menubar_icon: PathBuf,
    // Optional per-brand overrides
    pub title: Option<String>,
    pub footer_text: Option<String>,
    pub error_message: Option<String>,
    pub password_type: Option<String>,
    pub storage_limit: Option<u32>,
    pub show_welcome_screen: Option<bool>,
    pub open_at_login: Option<bool>,
    pub disable_configurator_mode: Option<bool>,
    pub disable_privileged_helper_tool: Option<bool>,
    pub status_bar_icon_allows_color: Option<bool>,
    pub status_bar_icon_notifier_enabled: Option<bool>,
    pub custom_color: Option<String>,
    pub custom_color_darkmode: Option<String>,
    pub info_items: Option<Vec<String>>,
    pub uptime_days_limit: Option<u32>,
    pub rows: Option<Vec<RowDef>>,
}

/// A row of button items in the Support App UI.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RowDef {
    pub items: Vec<ButtonItemDef>,
}

/// A single button item within a row.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ButtonItemDef {
    pub title: String,
    pub subtitle: String,
    pub symbol: String,
    #[serde(rename = "type")]
    pub item_type: String,
    pub link: Option<String>,
}

impl SupportConfig {
    /// Load config from a TOML file.
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&content)?;
        Ok(config)
    }

    /// Save config to a TOML file.
    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

impl CommonSettings {
    /// Returns sensible defaults for a new config.
    pub fn defaults() -> Self {
        Self {
            org: "Root3".to_string(),
            payload_display_name: "Support App Configuration".to_string(),
            error_message: "Please contact IT support".to_string(),
            footer_text: "Provided by Fleet with \u{2764}\u{fe0f}".to_string(),
            password_type: "Apple".to_string(),
            storage_limit: 90,
            show_welcome_screen: true,
            open_at_login: false,
            disable_configurator_mode: false,
            disable_privileged_helper_tool: false,
            status_bar_icon_allows_color: false,
            status_bar_icon_notifier_enabled: false,
            title: "Discover Support".to_string(),
            custom_color: None,
            custom_color_darkmode: None,
            info_items: None,
            uptime_days_limit: None,
            rows: vec![
                RowDef {
                    items: vec![
                        ButtonItemDef {
                            title: "Title".to_string(),
                            subtitle: "Subtitle".to_string(),
                            symbol: "cart.fill.badge.plus".to_string(),
                            item_type: "Button".to_string(),
                            link: None,
                        },
                        ButtonItemDef {
                            title: "Title".to_string(),
                            subtitle: "Subtitle".to_string(),
                            symbol: "cart.fill.badge.plus".to_string(),
                            item_type: "Button".to_string(),
                            link: None,
                        },
                    ],
                },
                RowDef {
                    items: vec![
                        ButtonItemDef {
                            title: "Title".to_string(),
                            subtitle: "Subtitle".to_string(),
                            symbol: "cart.fill.badge.plus".to_string(),
                            item_type: "Button".to_string(),
                            link: None,
                        },
                        ButtonItemDef {
                            title: "Title".to_string(),
                            subtitle: "Subtitle".to_string(),
                            symbol: "cart.fill.badge.plus".to_string(),
                            item_type: "Button".to_string(),
                            link: None,
                        },
                    ],
                },
            ],
        }
    }
}
