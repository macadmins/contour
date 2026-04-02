//! MDM Command CLI handlers
//!
//! Commands for generating Apple MDM command plist payloads.
//! Uses embedded capabilities (65 unique MDM command types) from the
//! `capabilities.parquet` dataset.

use crate::output::OutputMode;
use anyhow::{Context, Result};
use colored::Colorize;
use inquire::{Confirm, Select, Text};
use std::collections::BTreeMap;
use std::io::Write;

/// A deduplicated MDM command entry.
#[derive(Debug)]
struct MdmCommand {
    payload_type: String,
    title: String,
    description: String,
    keys: Vec<MdmCommandKey>,
    platforms: Vec<String>,
}

/// A key within an MDM command.
#[derive(Debug)]
struct MdmCommandKey {
    name: String,
    data_type: String,
    presence: String,
    description: Option<String>,
    default_value: Option<serde_json::Value>,
    allowed_values: Option<Vec<String>>,
}

/// Load all MDM command capabilities, deduplicated by payload_type.
fn load_commands() -> Result<Vec<MdmCommand>> {
    let capabilities = mdm_schema::capabilities::read(mdm_schema::embedded_capabilities())
        .context("Failed to read embedded capabilities from Parquet")?;

    let mut commands_map: BTreeMap<String, MdmCommand> = BTreeMap::new();

    for cap in capabilities
        .iter()
        .filter(|c| c.kind == mdm_schema::PayloadKind::MdmCommand)
    {
        let entry = commands_map
            .entry(cap.payload_type.clone())
            .or_insert_with(|| {
                let platforms: Vec<String> = cap
                    .supported_os
                    .iter()
                    .map(|os| match os.platform {
                        mdm_schema::Platform::MacOS => "macOS".to_string(),
                        mdm_schema::Platform::IOS => "iOS".to_string(),
                        mdm_schema::Platform::TvOS => "tvOS".to_string(),
                        mdm_schema::Platform::WatchOS => "watchOS".to_string(),
                        mdm_schema::Platform::VisionOS => "visionOS".to_string(),
                    })
                    .collect();

                MdmCommand {
                    payload_type: cap.payload_type.clone(),
                    title: cap.title.clone(),
                    description: cap.description.clone(),
                    keys: Vec::new(),
                    platforms,
                }
            });

        // Merge keys (deduplicate by name across all caps for this command)
        let mut existing_names: std::collections::HashSet<String> =
            entry.keys.iter().map(|k| k.name.clone()).collect();

        for key in &cap.keys {
            if existing_names.insert(key.name.clone()) {
                entry.keys.push(MdmCommandKey {
                    name: key.name.clone(),
                    data_type: key.data_type.clone(),
                    presence: key.presence.clone(),
                    description: key.key_description.clone(),
                    default_value: key.default_value.clone(),
                    allowed_values: key.range_list.clone(),
                });
            }
        }
    }

    Ok(commands_map.into_values().collect())
}

/// Find a specific command by type name (case-insensitive match).
fn find_command(commands: &[MdmCommand], command_type: &str) -> Option<usize> {
    commands.iter().position(|c| {
        c.payload_type.eq_ignore_ascii_case(command_type)
            || c.payload_type
                .to_lowercase()
                .ends_with(&format!(".{}", command_type.to_lowercase()))
    })
}

/// List available MDM commands.
pub fn handle_command_list(output_mode: OutputMode) -> Result<()> {
    let commands = load_commands()?;

    if output_mode == OutputMode::Json {
        let list: Vec<_> = commands
            .iter()
            .map(|cmd| {
                serde_json::json!({
                    "command_type": cmd.payload_type,
                    "title": cmd.title,
                    "key_count": cmd.keys.len(),
                    "platforms": cmd.platforms,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&list)?);
        return Ok(());
    }

    println!(
        "{} ({} command types)\n",
        "MDM Command Types".bold(),
        commands.len()
    );

    for cmd in &commands {
        let platforms = cmd.platforms.join(", ");
        println!(
            "  {} - {} [{} keys] [{}]",
            cmd.payload_type.cyan(),
            cmd.title,
            cmd.keys.len().to_string().yellow(),
            platforms.dimmed()
        );
    }

    println!();
    println!(
        "{}",
        "Use 'contour profile command info <type>' for detailed schema information.".dimmed()
    );
    println!(
        "{}",
        "Use 'contour profile command generate <type> -o <file>' to generate a plist.".dimmed()
    );

    Ok(())
}

/// Show schema for a specific MDM command.
pub fn handle_command_info(command_type: &str, output_mode: OutputMode) -> Result<()> {
    let commands = load_commands()?;

    let idx = find_command(&commands, command_type).ok_or_else(|| {
        anyhow::anyhow!(
            "MDM command type '{command_type}' not found.\n\
             Use 'contour profile command list' to see available commands."
        )
    })?;

    let cmd = &commands[idx];

    if output_mode == OutputMode::Json {
        let keys: Vec<_> = cmd
            .keys
            .iter()
            .map(|k| {
                serde_json::json!({
                    "name": k.name,
                    "type": k.data_type,
                    "required": k.presence == "required",
                    "description": k.description,
                    "default": k.default_value,
                    "allowed_values": k.allowed_values,
                })
            })
            .collect();

        let info = serde_json::json!({
            "command_type": cmd.payload_type,
            "title": cmd.title,
            "description": cmd.description,
            "platforms": cmd.platforms,
            "keys": keys,
        });
        println!("{}", serde_json::to_string_pretty(&info)?);
        return Ok(());
    }

    // Human output
    println!("{}\n", cmd.title.bold());
    println!("{}: {}", "Command Type".cyan(), cmd.payload_type);
    println!("{}: {}", "Platforms".cyan(), cmd.platforms.join(", "));
    println!("\n{}", "Description:".cyan());
    println!("  {}", cmd.description);

    if !cmd.keys.is_empty() {
        println!("\n{} ({}):", "Command Keys".cyan().bold(), cmd.keys.len());

        for key in &cmd.keys {
            let required_marker = if key.presence == "required" {
                format!(" [{}]", "required".red())
            } else {
                String::new()
            };

            println!(
                "  {} ({}){}",
                key.name.yellow(),
                key.data_type.dimmed(),
                required_marker
            );

            if let Some(ref desc) = key.description {
                if !desc.is_empty() {
                    println!("    {}", desc.dimmed());
                }
            }

            if let Some(ref default) = key.default_value {
                println!("    Default: {}", default.to_string().dimmed());
            }

            if let Some(ref allowed) = key.allowed_values {
                if !allowed.is_empty() {
                    println!("    Allowed: {}", allowed.join(", ").dimmed());
                }
            }
        }
    }

    // Required fields summary
    let required: Vec<_> = cmd
        .keys
        .iter()
        .filter(|k| k.presence == "required")
        .collect();
    if !required.is_empty() {
        println!(
            "\n{}: {}",
            "Required fields".red(),
            required
                .iter()
                .map(|k| k.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}

/// Generate a command plist payload.
pub fn handle_command_generate(
    command_type: &str,
    output: Option<&str>,
    params: &[String],
    uuid: bool,
    base64_output: bool,
    output_mode: OutputMode,
) -> Result<()> {
    let commands = load_commands()?;

    let idx = find_command(&commands, command_type).ok_or_else(|| {
        anyhow::anyhow!(
            "MDM command type '{command_type}' not found.\n\
             Use 'contour profile command list' to see available commands."
        )
    })?;

    let cmd = &commands[idx];

    // Build the Command inner dict
    let mut command_dict = plist::Dictionary::new();
    command_dict.insert(
        "RequestType".to_string(),
        plist::Value::String(cmd.payload_type.clone()),
    );

    // Parse --set KEY=VALUE params
    for param in params {
        let (key, value) = param.split_once('=').ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid parameter '{param}'. Expected KEY=VALUE format (e.g., --set PIN=123456)"
            )
        })?;

        let plist_value = parse_plist_value(value);
        command_dict.insert(key.to_string(), plist_value);
    }

    // Build the top-level dict
    let mut root_dict = plist::Dictionary::new();
    root_dict.insert(
        "Command".to_string(),
        plist::Value::Dictionary(command_dict),
    );

    if uuid {
        let uuid_val = ::uuid::Uuid::new_v4().to_string().to_uppercase();
        root_dict.insert("CommandUUID".to_string(), plist::Value::String(uuid_val));
    }

    let root = plist::Value::Dictionary(root_dict);

    // Serialize to XML plist
    let mut plist_bytes = Vec::new();
    plist::to_writer_xml(&mut plist_bytes, &root).context("Failed to serialize command plist")?;

    let plist_string =
        String::from_utf8(plist_bytes).context("Generated plist is not valid UTF-8")?;

    // Base64 output for Fleet API
    if base64_output {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(plist_string.as_bytes());
        if output_mode == OutputMode::Json {
            let result = serde_json::json!({
                "command_type": cmd.payload_type,
                "title": cmd.title,
                "base64": encoded,
                "params": params,
                "uuid": uuid,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else if let Some(output_path) = output {
            std::fs::write(output_path, &encoded)
                .with_context(|| format!("Failed to write base64 to {output_path}"))?;
            println!(
                "{} Base64 command written to {}",
                "OK".green(),
                output_path.cyan()
            );
        } else {
            println!("{encoded}");
        }
        return Ok(());
    }

    if let Some(output_path) = output {
        // Create parent directories if needed
        if let Some(parent) = std::path::Path::new(output_path).parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        std::fs::write(output_path, &plist_string)
            .with_context(|| format!("Failed to write plist to {output_path}"))?;

        if output_mode == OutputMode::Json {
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(plist_string.as_bytes());
            let result = serde_json::json!({
                "success": true,
                "command_type": cmd.payload_type,
                "title": cmd.title,
                "output": output_path,
                "base64": encoded,
                "params": params,
                "uuid": uuid,
            });
            println!("{}", serde_json::to_string_pretty(&result)?);
        } else {
            println!(
                "{} Generated MDM command plist: {}",
                "OK".green(),
                output_path.cyan()
            );
            println!("  {} {}", "Command:".bold(), cmd.payload_type);
            if !params.is_empty() {
                println!("  {} {}", "Params:".bold(), params.join(", "));
            }
            if uuid {
                println!("  {} included", "CommandUUID:".bold());
            }
        }
    } else {
        // Write to stdout
        let mut stdout = std::io::stdout().lock();
        stdout
            .write_all(plist_string.as_bytes())
            .context("Failed to write plist to stdout")?;
    }

    Ok(())
}

/// Parse a string value into the appropriate plist type.
fn parse_plist_value(value: &str) -> plist::Value {
    match value {
        "true" => plist::Value::Boolean(true),
        "false" => plist::Value::Boolean(false),
        _ => {
            // Try integer
            if let Ok(n) = value.parse::<i64>() {
                return plist::Value::Integer(n.into());
            }
            // Otherwise string
            plist::Value::String(value.to_string())
        }
    }
}

/// Convert a payload type to kebab-case for default filenames.
fn to_kebab_case(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 4);
    for (i, ch) in s.chars().enumerate() {
        if ch.is_uppercase() && i > 0 {
            result.push('-');
        }
        result.push(ch.to_ascii_lowercase());
    }
    result
}

/// Interactive mode for generating MDM command plists.
///
/// Walks the user through searching, selecting, and configuring an MDM command.
pub fn handle_command_generate_interactive(output_mode: OutputMode) -> Result<()> {
    let commands = load_commands()?;

    // Step 1: Search
    let search_term = Text::new("Search for a command:")
        .with_help_message("Enter a keyword to filter commands (e.g., restart, lock, profile)")
        .prompt()
        .context("Search prompt cancelled")?;

    let search_lower = search_term.to_lowercase();
    let matches: Vec<&MdmCommand> = commands
        .iter()
        .filter(|c| {
            c.payload_type.to_lowercase().contains(&search_lower)
                || c.title.to_lowercase().contains(&search_lower)
        })
        .collect();

    if matches.is_empty() {
        anyhow::bail!(
            "No commands match '{search_term}'.\n\
             Use 'contour profile command list' to see all available commands."
        );
    }

    // Step 2: Select (always show list, even for single match)
    let labels: Vec<String> = matches
        .iter()
        .map(|c| format!("{} — {} [{} keys]", c.payload_type, c.title, c.keys.len()))
        .collect();

    println!(
        "{} {} command(s) match '{}'",
        "→".cyan(),
        matches.len(),
        search_term
    );

    let selection = Select::new("Select a command:", labels)
        .prompt()
        .context("Command selection cancelled")?;

    let selected_type = selection.split(" — ").next().unwrap_or_default();
    let selected_cmd = matches
        .iter()
        .find(|c| c.payload_type == selected_type)
        .ok_or_else(|| anyhow::anyhow!("Selected command not found"))?;

    // Step 3: Configure params
    let mut command_dict = plist::Dictionary::new();
    command_dict.insert(
        "RequestType".to_string(),
        plist::Value::String(selected_cmd.payload_type.clone()),
    );

    let configurable_keys: Vec<&MdmCommandKey> = selected_cmd
        .keys
        .iter()
        .filter(|k| k.name != "RequestType")
        .collect();

    if !configurable_keys.is_empty() {
        println!(
            "\n{} Configure parameters for {} ({} keys):\n",
            "▶".cyan(),
            selected_cmd.payload_type.bold(),
            configurable_keys.len()
        );

        for key in &configurable_keys {
            let is_required = key.presence == "required";
            let type_hint = &key.data_type;

            // Show key info
            let required_label = if is_required {
                format!(" [{}]", "required".red())
            } else {
                String::new()
            };
            println!(
                "  {} ({}){}",
                key.name.yellow(),
                type_hint.dimmed(),
                required_label
            );
            if let Some(ref desc) = key.description {
                if !desc.is_empty() {
                    println!("    {}", desc.dimmed());
                }
            }
            if let Some(ref allowed) = key.allowed_values {
                if !allowed.is_empty() {
                    println!("    Allowed: {}", allowed.join(", ").dimmed());
                }
            }

            let is_bool = type_hint.to_lowercase() == "boolean";

            if is_bool {
                // Boolean fields use Confirm
                let default_val = key
                    .default_value
                    .as_ref()
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                if is_required {
                    let val = Confirm::new(&format!("  {} ?", key.name))
                        .with_default(default_val)
                        .prompt()
                        .with_context(|| format!("Prompt cancelled for {}", key.name))?;
                    command_dict.insert(key.name.clone(), plist::Value::Boolean(val));
                } else {
                    let set_it = Confirm::new(&format!("  Set {}?", key.name))
                        .with_default(false)
                        .prompt()
                        .with_context(|| format!("Prompt cancelled for {}", key.name))?;
                    if set_it {
                        let val = Confirm::new(&format!("  {} ?", key.name))
                            .with_default(default_val)
                            .prompt()
                            .with_context(|| format!("Prompt cancelled for {}", key.name))?;
                        command_dict.insert(key.name.clone(), plist::Value::Boolean(val));
                    }
                }
            } else if is_required {
                // Required non-bool: must fill in
                let prompt_label = format!("  {} =", key.name);
                let default_str = key.default_value.as_ref().map(|v| match v {
                    serde_json::Value::String(s) => s.clone(),
                    other => other.to_string(),
                });
                let help_msg = key.allowed_values.as_ref().and_then(|a| {
                    if a.is_empty() {
                        None
                    } else {
                        Some(format!("Allowed: {}", a.join(", ")))
                    }
                });

                let mut prompt = Text::new(&prompt_label);
                if let Some(ref ds) = default_str {
                    prompt = prompt.with_default(ds);
                }
                if let Some(ref hm) = help_msg {
                    prompt = prompt.with_help_message(hm);
                }

                let val = prompt
                    .prompt()
                    .with_context(|| format!("Prompt cancelled for {}", key.name))?;

                if !val.is_empty() {
                    command_dict.insert(key.name.clone(), parse_plist_value(&val));
                }
            } else {
                // Optional non-bool: ask whether to set
                let set_label = format!("  Set {}?", key.name);
                let set_it = Confirm::new(&set_label)
                    .with_default(false)
                    .prompt()
                    .with_context(|| format!("Prompt cancelled for {}", key.name))?;

                if set_it {
                    let prompt_label = format!("  {} =", key.name);
                    let default_str = key.default_value.as_ref().map(|v| match v {
                        serde_json::Value::String(s) => s.clone(),
                        other => other.to_string(),
                    });
                    let help_msg = key.allowed_values.as_ref().and_then(|a| {
                        if a.is_empty() {
                            None
                        } else {
                            Some(format!("Allowed: {}", a.join(", ")))
                        }
                    });

                    let mut prompt = Text::new(&prompt_label);
                    if let Some(ref ds) = default_str {
                        prompt = prompt.with_default(ds);
                    }
                    if let Some(ref hm) = help_msg {
                        prompt = prompt.with_help_message(hm);
                    }

                    let val = prompt
                        .prompt()
                        .with_context(|| format!("Prompt cancelled for {}", key.name))?;

                    if !val.is_empty() {
                        command_dict.insert(key.name.clone(), parse_plist_value(&val));
                    }
                }
            }
        }
    }

    // Step 4: UUID
    let mut root_dict = plist::Dictionary::new();
    root_dict.insert(
        "Command".to_string(),
        plist::Value::Dictionary(command_dict),
    );

    let add_uuid = Confirm::new("Add CommandUUID for tracking?")
        .with_default(true)
        .prompt()
        .context("UUID prompt cancelled")?;

    if add_uuid {
        let uuid_val = ::uuid::Uuid::new_v4().to_string().to_uppercase();
        root_dict.insert("CommandUUID".to_string(), plist::Value::String(uuid_val));
    }

    let root = plist::Value::Dictionary(root_dict);

    // Step 5: Output
    let default_filename = format!("{}.plist", to_kebab_case(&selected_cmd.payload_type));
    let output_path = Text::new("Output file path:")
        .with_default(&default_filename)
        .prompt()
        .context("Output path prompt cancelled")?;

    // Step 6: Generate
    let mut plist_bytes = Vec::new();
    plist::to_writer_xml(&mut plist_bytes, &root).context("Failed to serialize command plist")?;

    let plist_string =
        String::from_utf8(plist_bytes).context("Generated plist is not valid UTF-8")?;

    // Create parent directories if needed
    if let Some(parent) = std::path::Path::new(&output_path).parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    std::fs::write(&output_path, &plist_string)
        .with_context(|| format!("Failed to write plist to {output_path}"))?;

    if output_mode == OutputMode::Json {
        let result = serde_json::json!({
            "success": true,
            "command_type": selected_cmd.payload_type,
            "title": selected_cmd.title,
            "output": output_path,
            "uuid": add_uuid,
        });
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "\n{} Generated MDM command plist: {}",
            "OK".green(),
            output_path.cyan()
        );
        println!("  {} {}", "Command:".bold(), selected_cmd.payload_type);
        println!("  {} {}", "Title:".bold(), selected_cmd.title);
        if add_uuid {
            println!("  {} included", "CommandUUID:".bold());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_commands() {
        let commands = load_commands().expect("Failed to load MDM commands");
        assert!(!commands.is_empty(), "Should have at least one MDM command");

        // Check we have some well-known commands
        let has_restart = commands.iter().any(|c| c.payload_type == "RestartDevice");
        let has_lock = commands.iter().any(|c| c.payload_type == "DeviceLock");

        // At least one common command should exist
        assert!(
            has_restart || has_lock,
            "Should have RestartDevice or DeviceLock command"
        );
    }

    #[test]
    fn test_find_command_exact() {
        let commands = load_commands().unwrap();
        if commands.is_empty() {
            return;
        }

        let first_type = &commands[0].payload_type;
        let found = find_command(&commands, first_type);
        assert!(found.is_some(), "Should find command by exact name");
    }

    #[test]
    fn test_find_command_case_insensitive() {
        let commands = load_commands().unwrap();
        if commands.is_empty() {
            return;
        }

        let first_type = commands[0].payload_type.to_lowercase();
        let found = find_command(&commands, &first_type);
        assert!(
            found.is_some(),
            "Should find command by case-insensitive name"
        );
    }

    #[test]
    fn test_parse_plist_value_bool() {
        assert_eq!(parse_plist_value("true"), plist::Value::Boolean(true));
        assert_eq!(parse_plist_value("false"), plist::Value::Boolean(false));
    }

    #[test]
    fn test_parse_plist_value_integer() {
        assert_eq!(
            parse_plist_value("123456"),
            plist::Value::Integer(123456.into())
        );
        assert_eq!(parse_plist_value("0"), plist::Value::Integer(0.into()));
    }

    #[test]
    fn test_parse_plist_value_string() {
        assert_eq!(
            parse_plist_value("hello"),
            plist::Value::String("hello".to_string())
        );
        assert_eq!(
            parse_plist_value("com.example.wifi"),
            plist::Value::String("com.example.wifi".to_string())
        );
    }

    #[test]
    fn test_command_list_json() {
        // Smoke test: list should not error
        let result = handle_command_list(OutputMode::Json);
        assert!(result.is_ok(), "handle_command_list should succeed");
    }
}
