use anyhow::Result;
use plist::{Dictionary, Value};

use crate::config::{BrandEntry, CommonSettings, RowDef, SupportConfig};
use contour_profiles::ProfileBuilder;

/// Output files generated for a single brand.
#[derive(Debug)]
pub struct GeneratedBrand {
    pub name: String,
    /// `<brand>_nl.root3.support_discover.mobileconfig`
    pub discover_profile: Vec<u8>,
    pub discover_filename: String,
    /// `<brand>_default_nl.root3.support.mobileconfig`
    pub default_profile: Vec<u8>,
    pub default_filename: String,
    /// `<brand>_nl.root3.support_default.plist`
    pub raw_plist: Vec<u8>,
    pub raw_plist_filename: String,
}

/// Resolved settings for a single brand after merging common + brand overrides.
struct ResolvedSettings<'a> {
    org: &'a str,
    payload_display_name: &'a str,
    title: String,
    footer_text: String,
    error_message: String,
    password_type: String,
    storage_limit: u32,
    show_welcome_screen: bool,
    open_at_login: bool,
    disable_configurator_mode: bool,
    disable_privileged_helper_tool: bool,
    status_bar_icon_allows_color: bool,
    status_bar_icon_notifier_enabled: bool,
    custom_color: Option<String>,
    custom_color_darkmode: Option<String>,
    info_items: Option<Vec<String>>,
    uptime_days_limit: Option<u32>,
    rows: Vec<RowDef>,
}

fn resolve_settings<'a>(common: &'a CommonSettings, brand: &'a BrandEntry) -> ResolvedSettings<'a> {
    ResolvedSettings {
        org: &common.org,
        payload_display_name: &common.payload_display_name,
        title: brand.title.clone().unwrap_or_else(|| common.title.clone()),
        footer_text: brand
            .footer_text
            .clone()
            .unwrap_or_else(|| common.footer_text.clone()),
        error_message: brand
            .error_message
            .clone()
            .unwrap_or_else(|| common.error_message.clone()),
        password_type: brand
            .password_type
            .clone()
            .unwrap_or_else(|| common.password_type.clone()),
        storage_limit: brand.storage_limit.unwrap_or(common.storage_limit),
        show_welcome_screen: brand
            .show_welcome_screen
            .unwrap_or(common.show_welcome_screen),
        open_at_login: brand.open_at_login.unwrap_or(common.open_at_login),
        disable_configurator_mode: brand
            .disable_configurator_mode
            .unwrap_or(common.disable_configurator_mode),
        disable_privileged_helper_tool: brand
            .disable_privileged_helper_tool
            .unwrap_or(common.disable_privileged_helper_tool),
        status_bar_icon_allows_color: brand
            .status_bar_icon_allows_color
            .unwrap_or(common.status_bar_icon_allows_color),
        status_bar_icon_notifier_enabled: brand
            .status_bar_icon_notifier_enabled
            .unwrap_or(common.status_bar_icon_notifier_enabled),
        custom_color: brand
            .custom_color
            .clone()
            .or_else(|| common.custom_color.clone()),
        custom_color_darkmode: brand
            .custom_color_darkmode
            .clone()
            .or_else(|| common.custom_color_darkmode.clone()),
        info_items: brand
            .info_items
            .clone()
            .or_else(|| common.info_items.clone()),
        uptime_days_limit: brand.uptime_days_limit.or(common.uptime_days_limit),
        rows: brand.rows.clone().unwrap_or_else(|| common.rows.clone()),
    }
}

/// Convert row definitions into plist array values matching the Support App schema.
fn rows_to_plist(rows: &[RowDef]) -> Value {
    let row_values: Vec<Value> = rows
        .iter()
        .map(|row| {
            let items: Vec<Value> = row
                .items
                .iter()
                .map(|item| {
                    let mut d = Dictionary::new();
                    if let Some(ref link) = item.link {
                        d.insert("Link".to_string(), Value::String(link.clone()));
                    }
                    d.insert("Title".to_string(), Value::String(item.title.clone()));
                    d.insert("Subtitle".to_string(), Value::String(item.subtitle.clone()));
                    d.insert("Symbol".to_string(), Value::String(item.symbol.clone()));
                    d.insert("Type".to_string(), Value::String(item.item_type.clone()));
                    Value::Dictionary(d)
                })
                .collect();
            let mut row_dict = Dictionary::new();
            row_dict.insert("Items".to_string(), Value::Array(items));
            Value::Dictionary(row_dict)
        })
        .collect();
    Value::Array(row_values)
}

/// Build the inner payload dictionary for the **discover** profile (full config with assets).
fn build_discover_payload(settings: &ResolvedSettings, brand: &BrandEntry) -> Dictionary {
    let mut d = Dictionary::new();

    if let Some(ref color) = settings.custom_color {
        d.insert("CustomColor".to_string(), Value::String(color.clone()));
    }
    if let Some(ref color) = settings.custom_color_darkmode {
        d.insert(
            "CustomColorDarkMode".to_string(),
            Value::String(color.clone()),
        );
    }
    d.insert(
        "DisableConfiguratorMode".to_string(),
        Value::Boolean(settings.disable_configurator_mode),
    );
    d.insert(
        "DisablePrivilegedHelperTool".to_string(),
        Value::Boolean(settings.disable_privileged_helper_tool),
    );
    d.insert(
        "ErrorMessage".to_string(),
        Value::String(settings.error_message.clone()),
    );
    d.insert(
        "FooterText".to_string(),
        Value::String(settings.footer_text.clone()),
    );

    // Emit positional info item keys (InfoItemOne through InfoItemSix)
    if let Some(ref items) = settings.info_items {
        let names = [
            "InfoItemOne",
            "InfoItemTwo",
            "InfoItemThree",
            "InfoItemFour",
            "InfoItemFive",
            "InfoItemSix",
        ];
        for (i, item) in items.iter().enumerate().take(names.len()) {
            d.insert(names[i].to_string(), Value::String(item.clone()));
        }
    }

    d.insert(
        "Logo".to_string(),
        Value::String(brand.logo.to_string_lossy().to_string()),
    );
    d.insert(
        "LogoDarkMode".to_string(),
        Value::String(brand.logo_darkmode.to_string_lossy().to_string()),
    );
    d.insert(
        "NotificationIcon".to_string(),
        Value::String(brand.menubar_icon.to_string_lossy().to_string()),
    );
    d.insert("OnAppearAction".to_string(), Value::String(String::new()));
    d.insert(
        "OpenAtLogin".to_string(),
        Value::Boolean(settings.open_at_login),
    );
    d.insert(
        "PasswordType".to_string(),
        Value::String(settings.password_type.clone()),
    );
    d.insert("Rows".to_string(), rows_to_plist(&settings.rows));
    d.insert(
        "ShowWelcomeScreen".to_string(),
        Value::Boolean(settings.show_welcome_screen),
    );
    d.insert(
        "StatusBarIcon".to_string(),
        Value::String(brand.menubar_icon.to_string_lossy().to_string()),
    );
    d.insert(
        "StatusBarIconAllowsColor".to_string(),
        Value::Boolean(settings.status_bar_icon_allows_color),
    );
    d.insert(
        "StatusBarIconNotifierEnabled".to_string(),
        Value::Boolean(settings.status_bar_icon_notifier_enabled),
    );
    d.insert(
        "StorageLimit".to_string(),
        Value::Integer(i64::from(settings.storage_limit).into()),
    );
    d.insert("Title".to_string(), Value::String(settings.title.clone()));

    if let Some(limit) = settings.uptime_days_limit {
        d.insert(
            "UptimeDaysLimit".to_string(),
            Value::Integer(i64::from(limit).into()),
        );
    }

    d
}

/// Build the inner payload dictionary for the **default** profile (minimal behavioral config).
fn build_default_payload(settings: &ResolvedSettings) -> Dictionary {
    let mut d = Dictionary::new();

    d.insert(
        "DisableConfiguratorMode".to_string(),
        Value::Boolean(settings.disable_configurator_mode),
    );
    d.insert(
        "DisablePrivilegedHelperTool".to_string(),
        Value::Boolean(settings.disable_privileged_helper_tool),
    );
    d.insert("OnAppearAction".to_string(), Value::String(String::new()));
    d.insert(
        "OpenAtLogin".to_string(),
        Value::Boolean(settings.open_at_login),
    );
    d.insert("Rows".to_string(), Value::Array(vec![]));
    d.insert("ShowWelcomeScreen".to_string(), Value::Boolean(false));
    d.insert(
        "StatusBarIconAllowsColor".to_string(),
        Value::Boolean(settings.status_bar_icon_allows_color),
    );
    d.insert(
        "StatusBarIconNotifierEnabled".to_string(),
        Value::Boolean(settings.status_bar_icon_notifier_enabled),
    );
    d.insert("Title".to_string(), Value::String(String::new()));

    d
}

/// Generate all output files for a single brand.
fn generate_brand(common: &CommonSettings, brand: &BrandEntry) -> Result<GeneratedBrand> {
    let settings = resolve_settings(common, brand);
    let brand_lower = brand.name.to_lowercase();

    // --- 1. Discover profile ---
    let discover_id = format!("nl.root3.support.{}.discover", brand_lower);
    let discover_payload = build_discover_payload(&settings, brand);
    let discover_bytes = ProfileBuilder::new(settings.org, &discover_id)
        .display_name(settings.payload_display_name)
        .removal_disallowed(true)
        .build("nl.root3.support", discover_payload)?;

    // --- 2. Default profile ---
    let default_id = format!("nl.root3.support.{}.default", brand_lower);
    let default_payload = build_default_payload(&settings);
    let default_bytes = ProfileBuilder::new(settings.org, &default_id)
        .display_name(settings.payload_display_name)
        .removal_disallowed(true)
        .build("nl.root3.support", default_payload)?;

    // --- 3. Raw plist (same keys as default, no mobileconfig envelope) ---
    let raw_dict = build_default_payload(&settings);
    let mut raw_buffer = Vec::new();
    plist::to_writer_xml(&mut raw_buffer, &Value::Dictionary(raw_dict))?;

    Ok(GeneratedBrand {
        name: brand.name.clone(),
        discover_profile: discover_bytes,
        discover_filename: format!("{}_nl.root3.support_discover.mobileconfig", brand.name),
        default_profile: default_bytes,
        default_filename: format!("{}_default_nl.root3.support.mobileconfig", brand.name),
        raw_plist: raw_buffer,
        raw_plist_filename: format!("{}_nl.root3.support_default.plist", brand.name),
    })
}

/// Generate output files for all brands (or a single brand if filtered).
pub fn generate_all(
    config: &SupportConfig,
    brand_filter: Option<&str>,
) -> Result<Vec<GeneratedBrand>> {
    let brands: Vec<&BrandEntry> = if let Some(filter) = brand_filter {
        let matched: Vec<_> = config
            .brands
            .iter()
            .filter(|b| b.name.eq_ignore_ascii_case(filter))
            .collect();
        if matched.is_empty() {
            let available: Vec<_> = config.brands.iter().map(|b| b.name.as_str()).collect();
            anyhow::bail!(
                "Brand '{}' not found. Available: {}",
                filter,
                available.join(", ")
            );
        }
        matched
    } else {
        config.brands.iter().collect()
    };

    brands
        .iter()
        .map(|brand| generate_brand(&config.common, brand))
        .collect()
}
