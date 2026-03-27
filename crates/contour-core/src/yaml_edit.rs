//! Line-based YAML section editing.
//!
//! Operates on raw text lines to insert new entries into YAML files
//! without destroying comments or formatting. This is the core innovation
//! over round-trip serde approaches.

/// Find the line index where new entries should be inserted for a given
/// top-level section (e.g., `labels:`, `reports:`).
///
/// Walks forward through `- path:` entries in the section, tracking
/// indentation. Returns the line index after the last entry in the section.
///
/// Returns `None` if the section is not found.
pub fn find_section_insert_point(lines: &[&str], section_key: &str) -> Option<InsertPoint> {
    let needle = format!("{section_key}:");

    // Find the section header line
    let mut section_line = None;
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        if trimmed == needle || trimmed.starts_with(&format!("{needle} ")) {
            section_line = Some(i);
            break;
        }
    }

    let section_start = section_line?;

    // Detect the indentation of list items in this section
    let mut item_indent = None;
    let mut last_item_end = section_start;

    for (i, line) in lines.iter().enumerate().skip(section_start + 1) {
        let trimmed = line.trim();

        // Skip blank lines and comments
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect indent level of first list item
        if item_indent.is_none() {
            if trimmed.starts_with("- ") {
                let indent = line.len() - line.trim_start().len();
                item_indent = Some(indent);
                last_item_end = i;
                continue;
            }
            // Non-list content at section level means empty section
            break;
        }

        let indent = line.len() - line.trim_start().len();
        let expected_indent = item_indent.expect("invariant: set in preceding loop iteration");

        // A line at or less than the section header indent = new section
        if indent <= (section_start_indent(lines, section_start))
            && !trimmed.is_empty()
            && !trimmed.starts_with('#')
        {
            break;
        }

        // A list item at the expected indent
        if trimmed.starts_with("- ") && indent == expected_indent {
            last_item_end = i;
        } else if indent > expected_indent {
            // Continuation of a multi-line entry
            last_item_end = i;
        } else {
            break;
        }
    }

    Some(InsertPoint {
        line: last_item_end + 1,
        indent: item_indent.unwrap_or(2),
        section_exists: true,
    })
}

/// Find insert point within a nested section path like
/// `controls.macos_settings.custom_settings`.
pub fn find_nested_section_insert_point(
    lines: &[&str],
    section_path: &[&str],
) -> Option<InsertPoint> {
    if section_path.is_empty() {
        return None;
    }

    // Find each nested key in sequence
    let mut search_start = 0;
    let mut parent_indent = 0;

    for (depth, key) in section_path.iter().enumerate() {
        let needle = format!("{key}:");
        let mut found = false;

        for (i, line) in lines.iter().enumerate().skip(search_start) {
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Must be at correct nesting depth
            if depth > 0 && indent <= parent_indent && !trimmed.is_empty() && i > search_start {
                break;
            }

            if trimmed == needle || trimmed.starts_with(&format!("{needle} ")) {
                search_start = i + 1;
                parent_indent = indent;
                found = true;
                break;
            }
        }

        if !found {
            return None;
        }
    }

    // Now find the last list item in this section
    let mut item_indent = None;
    let mut last_item_end = search_start - 1;

    for (i, line) in lines.iter().enumerate().skip(search_start) {
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        if item_indent.is_none() {
            if trimmed.starts_with("- ") && indent > parent_indent {
                item_indent = Some(indent);
                last_item_end = i;
                continue;
            }
            break;
        }

        let expected = item_indent.expect("invariant: set in preceding loop iteration");

        if indent <= parent_indent && !trimmed.is_empty() {
            break;
        }

        if (trimmed.starts_with("- ") && indent == expected) || indent > expected {
            last_item_end = i;
        } else {
            break;
        }
    }

    Some(InsertPoint {
        line: last_item_end + 1,
        indent: item_indent.unwrap_or(parent_indent + 2),
        section_exists: true,
    })
}

/// Insert new lines into content at a specific position.
pub fn insert_lines_at(content: &str, insert_point: &InsertPoint, new_lines: &[String]) -> String {
    if new_lines.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut result = Vec::with_capacity(lines.len() + new_lines.len());

    for line in &lines[..insert_point.line.min(lines.len())] {
        result.push((*line).to_string());
    }

    for new_line in new_lines {
        result.push(new_line.clone());
    }

    for line in lines.iter().skip(insert_point.line) {
        result.push((*line).to_string());
    }

    let mut output = result.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Format a simple `- path: <value>` entry at a given indent.
pub fn format_path_entry(path: &str, indent: usize) -> String {
    let pad = " ".repeat(indent);
    format!("{pad}- path: {path}")
}

/// Format a profile entry with optional label filters.
pub fn format_profile_entry(
    path: &str,
    labels_include_any: Option<&[String]>,
    labels_include_all: Option<&[String]>,
    labels_exclude_any: Option<&[String]>,
    indent: usize,
) -> Vec<String> {
    let pad = " ".repeat(indent);
    let sub_pad = " ".repeat(indent + 2);
    let mut lines = vec![format!("{pad}- path: {path}")];

    if let Some(labels) = labels_include_any
        && !labels.is_empty()
    {
        lines.push(format!("{sub_pad}labels_include_any:"));
        for label in labels {
            lines.push(format!("{sub_pad}  - \"{label}\""));
        }
    }

    if let Some(labels) = labels_include_all
        && !labels.is_empty()
    {
        lines.push(format!("{sub_pad}labels_include_all:"));
        for label in labels {
            lines.push(format!("{sub_pad}  - \"{label}\""));
        }
    }

    if let Some(labels) = labels_exclude_any
        && !labels.is_empty()
    {
        lines.push(format!("{sub_pad}labels_exclude_any:"));
        for label in labels {
            lines.push(format!("{sub_pad}  - \"{label}\""));
        }
    }

    lines
}

/// Format a Fleet-maintained app entry (slug-based, no path).
pub fn format_fma_entry(
    slug: &str,
    self_service: bool,
    categories: Option<&[String]>,
    labels_include_any: Option<&[String]>,
    indent: usize,
) -> Vec<String> {
    let pad = " ".repeat(indent);
    let sub_pad = " ".repeat(indent + 2);
    let mut lines = vec![format!("{pad}- slug: {slug}")];

    if self_service {
        lines.push(format!("{sub_pad}self_service: true"));
    }

    if let Some(labels) = labels_include_any
        && !labels.is_empty()
    {
        lines.push(format!("{sub_pad}labels_include_any:"));
        for label in labels {
            lines.push(format!("{sub_pad}  - {label}"));
        }
    }

    if let Some(cats) = categories
        && !cats.is_empty()
    {
        lines.push(format!("{sub_pad}categories:"));
        for cat in cats {
            lines.push(format!("{sub_pad}  - {cat}"));
        }
    }

    lines
}

/// Append entries to the `software.fleet_maintained_apps` section, creating it if needed.
pub fn append_fleet_maintained_apps(content: &str, entries: &[Vec<String>]) -> String {
    if entries.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();

    // Try to find existing software.fleet_maintained_apps section
    if let Some(insert) =
        find_nested_section_insert_point(&lines, &["software", "fleet_maintained_apps"])
    {
        let flat: Vec<String> = entries.iter().flatten().cloned().collect();
        return insert_lines_at(content, &insert, &flat);
    }

    // Check if `software:` exists — inject `fleet_maintained_apps:` under it
    let software_line = lines.iter().enumerate().find(|(_, l)| {
        let t = l.trim();
        t == "software:" || t.starts_with("software: ")
    });

    if let Some((sw_idx, _)) = software_line {
        // Find end of software section to insert fleet_maintained_apps before next top-level key
        let sw_indent = lines[sw_idx].len() - lines[sw_idx].trim_start().len();
        let mut insert_at = sw_idx + 1;
        for (i, line) in lines.iter().enumerate().skip(sw_idx + 1) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                insert_at = i + 1;
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent <= sw_indent {
                break;
            }
            insert_at = i + 1;
        }

        let mut result: Vec<String> = lines[..insert_at].iter().map(|l| l.to_string()).collect();
        let sub_pad = " ".repeat(sw_indent + 2);
        result.push(format!("{sub_pad}fleet_maintained_apps:"));
        for entry_lines in entries {
            for line in entry_lines {
                result.push(line.clone());
            }
        }
        for line in lines.iter().skip(insert_at) {
            result.push(line.to_string());
        }
        let mut out = result.join("\n");
        if content.ends_with('\n') && !out.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    // Neither software nor fleet_maintained_apps exists — append both
    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str("\nsoftware:\n  fleet_maintained_apps:\n");
    for entry_lines in entries {
        for line in entry_lines {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Format a software entry.
pub fn format_software_entry(
    path: &str,
    self_service: bool,
    labels_include_any: Option<&[String]>,
    categories: Option<&[String]>,
    indent: usize,
) -> Vec<String> {
    let pad = " ".repeat(indent);
    let sub_pad = " ".repeat(indent + 2);
    let mut lines = vec![format!("{pad}- path: {path}")];

    if self_service {
        lines.push(format!("{sub_pad}self_service: true"));
    }

    if let Some(labels) = labels_include_any
        && !labels.is_empty()
    {
        lines.push(format!("{sub_pad}labels_include_any:"));
        for label in labels {
            lines.push(format!("{sub_pad}  - \"{label}\""));
        }
    }

    if let Some(cats) = categories
        && !cats.is_empty()
    {
        lines.push(format!("{sub_pad}categories:"));
        for cat in cats {
            lines.push(format!("{sub_pad}  - {cat}"));
        }
    }

    lines
}

/// Insert point information.
#[derive(Debug, Clone)]
pub struct InsertPoint {
    /// Line index to insert at (0-based).
    pub line: usize,
    /// Detected indent level for list items.
    pub indent: usize,
    /// Whether the section already exists.
    pub section_exists: bool,
}

/// Get the indentation of a section header line.
fn section_start_indent(lines: &[&str], line_idx: usize) -> usize {
    lines
        .get(line_idx)
        .map_or(0, |l| l.len() - l.trim_start().len())
}

/// Append entries to a top-level section, handling all three cases:
/// 1. Section has items → append after last item
/// 2. Section exists but is empty → inject entries inline
/// 3. Section missing → append section at end of file
///
/// Each entry should be a pre-formatted line (e.g. `"  - path: ./foo.yml"`).
pub fn append_to_section(content: &str, section: &str, entries: &[String]) -> String {
    if entries.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();

    // Case 1: Section exists and has items
    if let Some(insert) = find_section_insert_point(&lines, section) {
        return insert_lines_at(content, &insert, entries);
    }

    // Case 2: Section exists but is empty
    if let Some(key_line) = find_empty_top_level_key(&lines, section) {
        let mut result: Vec<String> = lines[..=key_line].iter().map(|l| l.to_string()).collect();
        for entry in entries {
            result.push(entry.clone());
        }
        for line in lines.iter().skip(key_line + 1) {
            result.push(line.to_string());
        }
        let mut out = result.join("\n");
        if content.ends_with('\n') && !out.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    // Case 3: Section missing — append at end
    append_section(content, section, entries)
}

/// Append an entire new section to the end of a YAML file.
pub fn append_section(content: &str, section_name: &str, entries: &[String]) -> String {
    let mut result = content.to_string();

    // Ensure trailing newline
    if !result.ends_with('\n') {
        result.push('\n');
    }

    result.push('\n');
    result.push_str(section_name);
    result.push_str(":\n");
    for entry in entries {
        result.push_str(entry);
        result.push('\n');
    }

    result
}

/// Append profile entries to the `controls.macos_settings.custom_settings` section,
/// creating the nested structure if it doesn't exist.
pub fn append_custom_settings(content: &str, entries: &[Vec<String>]) -> String {
    if entries.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();

    // Try to find existing controls.macos_settings.custom_settings section
    if let Some(insert) =
        find_nested_section_insert_point(&lines, &["controls", "macos_settings", "custom_settings"])
    {
        let flat: Vec<String> = entries.iter().flatten().cloned().collect();
        return insert_lines_at(content, &insert, &flat);
    }

    // Check if controls: exists but macos_settings doesn't
    let controls_exists = lines
        .iter()
        .any(|l| l.trim() == "controls:" || l.trim().starts_with("controls: "));

    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }

    if controls_exists {
        // controls: exists — find it and insert macos_settings underneath
        let mut output_lines: Vec<String> = content.lines().map(String::from).collect();
        let controls_idx = output_lines
            .iter()
            .position(|l| l.trim() == "controls:" || l.trim().starts_with("controls: "))
            .expect("invariant: verified by preceding controls_exists check");

        // Find where the controls section's children end
        let controls_indent =
            output_lines[controls_idx].len() - output_lines[controls_idx].trim_start().len();
        let mut insert_at = controls_idx + 1;
        for (i, line) in output_lines.iter().enumerate().skip(controls_idx + 1) {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                insert_at = i + 1;
                continue;
            }
            let indent = line.len() - line.trim_start().len();
            if indent <= controls_indent {
                break;
            }
            insert_at = i + 1;
        }

        // Insert macos_settings.custom_settings block
        let pad = " ".repeat(controls_indent + 2);
        let sub_pad = " ".repeat(controls_indent + 4);
        let mut new_lines = vec![
            format!("{pad}macos_settings:"),
            format!("{sub_pad}custom_settings:"),
        ];
        for entry_lines in entries {
            for line in entry_lines {
                new_lines.push(line.clone());
            }
        }

        for (offset, line) in new_lines.into_iter().enumerate() {
            output_lines.insert(insert_at + offset, line);
        }

        let mut out = output_lines.join("\n");
        if content.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    // controls: doesn't exist at all — append the entire block
    result.push_str("\ncontrols:\n  macos_settings:\n    custom_settings:\n");
    for entry_lines in entries {
        for line in entry_lines {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Set key-value pairs within a nested YAML section.
///
/// Finds the section at `section_path` (e.g. `["controls", "macos_updates"]`)
/// and replaces or inserts scalar key-value pairs. Handles three scenarios:
///
/// 1. Key exists with empty or existing value → replace the line
/// 2. Key doesn't exist in the section → insert after last child
/// 3. Section doesn't exist → build and insert the full block
///
/// Returns the modified content.
pub fn set_nested_key_values(content: &str, section_path: &[&str], kvs: &[(&str, &str)]) -> String {
    if kvs.is_empty() || section_path.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();

    // Find the deepest section header
    let mut search_start = 0;
    let mut parent_indent: Option<usize> = None;
    let mut section_found = true;

    for (depth, key) in section_path.iter().enumerate() {
        let needle = format!("{key}:");
        let mut found = false;

        for (i, line) in lines.iter().enumerate().skip(search_start) {
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Must be at correct nesting depth
            if depth > 0 {
                if let Some(pi) = parent_indent {
                    if indent <= pi && !trimmed.is_empty() && i > search_start {
                        break;
                    }
                }
            }

            if trimmed == needle || trimmed.starts_with(&format!("{needle} ")) {
                search_start = i + 1;
                parent_indent = Some(indent);
                found = true;
                break;
            }
        }

        if !found {
            section_found = false;
            break;
        }
    }

    if !section_found {
        // Section doesn't exist — build and insert the full block.
        // Find or create the parent sections, then insert the leaf section with kvs.
        return insert_missing_section_with_kvs(content, section_path, kvs);
    }

    // Section exists — the section header was at line (search_start - 1)
    let section_header_line = search_start - 1;
    let section_indent = parent_indent.expect("invariant: set when section_found is true");
    let child_indent = section_indent + 2;

    // Find the range of child lines belonging to this section
    let mut section_end = section_header_line; // last line of the section
    for (i, line) in lines.iter().enumerate().skip(search_start) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= section_indent {
            break;
        }
        section_end = i;
    }

    // Process each key-value pair
    let mut result_lines: Vec<String> = lines.iter().map(|l| l.to_string()).collect();
    let mut insert_offset: usize = 0; // track insertions shifting line numbers

    for (key, value) in kvs {
        let key_needle = format!("{key}:");
        let pad = " ".repeat(child_indent);

        // Search for existing key within the section
        let mut found_at = None;
        let scan_start = search_start + insert_offset;
        let scan_end = section_end + 1 + insert_offset;

        for i in scan_start..scan_end.min(result_lines.len()) {
            let trimmed = result_lines[i].trim();
            let indent = result_lines[i].len() - result_lines[i].trim_start().len();

            if indent <= section_indent && !trimmed.is_empty() && !trimmed.starts_with('#') {
                break;
            }

            if indent == child_indent
                && (trimmed == key_needle || trimmed.starts_with(&format!("{key_needle} ")))
            {
                found_at = Some(i);
                break;
            }
        }

        if let Some(idx) = found_at {
            // Replace existing line
            result_lines[idx] = format!("{pad}{key}: {value}");
        } else {
            // Insert after last child of the section
            let insert_at = section_end + 1 + insert_offset;
            result_lines.insert(insert_at, format!("{pad}{key}: {value}"));
            insert_offset += 1;
        }
    }

    let mut output = result_lines.join("\n");
    if content.ends_with('\n') && !output.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Insert a missing nested section with key-value pairs.
///
/// Walks `section_path` to find existing ancestor sections, then builds
/// the missing portion. If no ancestors exist, appends at end of file.
fn insert_missing_section_with_kvs(
    content: &str,
    section_path: &[&str],
    kvs: &[(&str, &str)],
) -> String {
    let lines: Vec<&str> = content.lines().collect();

    // Find how deep we can get into the existing section hierarchy
    let mut search_start = 0;
    let mut last_found_indent: Option<usize> = None;
    let mut last_found_line: Option<usize> = None;
    let mut depth_found = 0;

    for (depth, key) in section_path.iter().enumerate() {
        let needle = format!("{key}:");
        let mut found = false;

        for (i, line) in lines.iter().enumerate().skip(search_start) {
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            if depth > 0 {
                if let Some(pi) = last_found_indent {
                    if indent <= pi && !trimmed.is_empty() && i > search_start {
                        break;
                    }
                }
            }

            if trimmed == needle || trimmed.starts_with(&format!("{needle} ")) {
                search_start = i + 1;
                last_found_indent = Some(indent);
                last_found_line = Some(i);
                depth_found = depth + 1;
                found = true;
                break;
            }
        }

        if !found {
            break;
        }
    }

    if depth_found == 0 {
        // No part of the section path exists — append the whole block
        let mut result = content.to_string();
        if !result.ends_with('\n') {
            result.push('\n');
        }

        let mut indent = 0;
        for key in section_path {
            let pad = " ".repeat(indent);
            result.push_str(&format!("{pad}{key}:\n"));
            indent += 2;
        }
        for (key, value) in kvs {
            let pad = " ".repeat(indent);
            result.push_str(&format!("{pad}{key}: {value}\n"));
        }
        return result;
    }

    // Some ancestor exists. Find the end of that ancestor's section to insert.
    let ancestor_indent =
        last_found_indent.expect("invariant: set when partial ancestor match found");
    let ancestor_line = last_found_line.expect("invariant: set when partial ancestor match found");

    let mut insert_at = ancestor_line + 1;
    for (i, line) in lines.iter().enumerate().skip(ancestor_line + 1) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            insert_at = i + 1;
            continue;
        }
        let indent = line.len() - line.trim_start().len();
        if indent <= ancestor_indent {
            break;
        }
        insert_at = i + 1;
    }

    // Build the missing section levels + kvs
    let mut new_lines: Vec<String> = Vec::new();
    let mut indent = ancestor_indent + 2;
    for key in &section_path[depth_found..] {
        let pad = " ".repeat(indent);
        new_lines.push(format!("{pad}{key}:"));
        indent += 2;
    }
    for (key, value) in kvs {
        let pad = " ".repeat(indent);
        new_lines.push(format!("{pad}{key}: {value}"));
    }

    let mut result: Vec<String> = lines[..insert_at].iter().map(|l| l.to_string()).collect();
    result.extend(new_lines);
    for line in lines.iter().skip(insert_at) {
        result.push(line.to_string());
    }

    let mut output = result.join("\n");
    if content.ends_with('\n') && !output.ends_with('\n') {
        output.push('\n');
    }
    output
}

/// Append entries to the `software.packages` section, creating it if needed.
pub fn append_software_packages(content: &str, entries: &[Vec<String>]) -> String {
    if entries.is_empty() {
        return content.to_string();
    }

    let lines: Vec<&str> = content.lines().collect();

    // Try to find existing software.packages section
    if let Some(insert) = find_nested_section_insert_point(&lines, &["software", "packages"]) {
        let flat: Vec<String> = entries.iter().flatten().cloned().collect();
        return insert_lines_at(content, &insert, &flat);
    }

    // Check if `software:` exists but has no `packages:` subkey (empty section).
    // In that case, inject `packages:` + entries right after the `software:` line
    // instead of appending a duplicate top-level block.
    if let Some(sw_line) = find_empty_top_level_key(&lines, "software") {
        let mut result: Vec<String> = lines[..=sw_line].iter().map(|l| l.to_string()).collect();
        result.push("  packages:".to_string());
        for entry_lines in entries {
            for line in entry_lines {
                result.push(line.clone());
            }
        }
        for line in lines.iter().skip(sw_line + 1) {
            result.push(line.to_string());
        }
        let mut out = result.join("\n");
        if content.ends_with('\n') && !out.ends_with('\n') {
            out.push('\n');
        }
        return out;
    }

    // Neither software nor software.packages exists — append both
    let mut result = content.to_string();
    if !result.ends_with('\n') {
        result.push('\n');
    }
    result.push_str("\nsoftware:\n  packages:\n");
    for entry_lines in entries {
        for line in entry_lines {
            result.push_str(line);
            result.push('\n');
        }
    }
    result
}

/// Find a top-level key that exists but has no nested content (next non-empty
/// line is at the same or lesser indent, or is another top-level key).
fn find_empty_top_level_key(lines: &[&str], key: &str) -> Option<usize> {
    let needle = format!("{key}:");
    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();
        let indent = line.len() - line.trim_start().len();
        if indent == 0 && (trimmed == needle || trimmed.starts_with(&format!("{needle} "))) {
            // Check if next non-empty line is at indent 0 (i.e. this key is empty)
            for next in lines.iter().skip(i + 1) {
                let nt = next.trim();
                if nt.is_empty() || nt.starts_with('#') {
                    continue;
                }
                let ni = next.len() - next.trim_start().len();
                if ni == 0 {
                    return Some(i); // empty section
                }
                return None; // has nested content
            }
            return Some(i); // last key in file, empty
        }
    }
    None
}

/// Add a label scope to an existing profile entry in team YAML.
///
/// Scans for `- path: {target_path}` and injects a label scope block.
/// Returns `(modified_content, was_modified)`.
///
/// Rules:
/// - If the path isn't found → `(content, false)`
/// - If the same label is already in the same scope → `(content, false)` (idempotent)
/// - If a different scope type exists → error (mutual exclusivity)
/// - Otherwise → inserts the label under the appropriate scope key
pub fn add_label_to_entry(
    content: &str,
    target_path: &str,
    scope_key: &str, // "labels_include_any" | "labels_include_all" | "labels_exclude_any"
    label_name: &str,
) -> anyhow::Result<(String, bool)> {
    let lines: Vec<&str> = content.lines().collect();

    // All scope keys we need to check for mutual exclusivity
    let all_scope_keys = [
        "labels_include_any",
        "labels_include_all",
        "labels_exclude_any",
    ];

    // Find the `- path: {target_path}` line
    let entry_line = lines.iter().enumerate().find(|(_, line)| {
        let trimmed = line.trim();
        trimmed == format!("- path: {target_path}").as_str()
            || trimmed == format!("- path: \"{target_path}\"").as_str()
    });

    let (entry_idx, entry_line_str) = match entry_line {
        Some((idx, line)) => (idx, *line),
        None => return Ok((content.to_string(), false)),
    };

    // Determine entry indent (the `- ` line's indent)
    let entry_indent = entry_line_str.len() - entry_line_str.trim_start().len();
    // Sub-properties are indented by 2 more than the `- `
    let prop_indent = entry_indent + 2;
    let list_indent = prop_indent + 2;

    // Scan subsequent lines to find any existing scope field or end of entry
    let mut existing_scope: Option<(usize, &str)> = None; // (line_idx, scope_key_found)
    let mut entry_end = entry_idx; // last line of this entry

    for i in (entry_idx + 1)..lines.len() {
        let line = lines[i];
        let trimmed = line.trim();

        // Blank line or comment — skip but track
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let indent = line.len() - line.trim_start().len();

        // If we hit a line at or less than entry_indent that starts with `- `,
        // it's the next entry
        if indent <= entry_indent && trimmed.starts_with("- ") {
            break;
        }

        // If we hit a line at less than entry_indent (not a continuation), stop
        if indent < entry_indent {
            break;
        }

        // This line is part of our entry
        entry_end = i;

        // Check if this line is a scope key
        for &sk in &all_scope_keys {
            if trimmed == format!("{sk}:") || trimmed.starts_with(&format!("{sk}: ")) {
                existing_scope = Some((i, sk));
            }
        }
    }

    // Check mutual exclusivity
    if let Some((_, found_key)) = existing_scope {
        if found_key != scope_key {
            anyhow::bail!(
                "Profile {target_path} already has {found_key}, cannot add {scope_key} (mutual exclusivity)"
            );
        }

        // Same scope type — check if label already present, append if not
        let scope_line_idx = existing_scope
            .expect("invariant: guarded by if-let Some check above")
            .0;

        // Scan list items under this scope key
        let mut last_list_item = scope_line_idx;
        let mut label_exists = false;

        for i in (scope_line_idx + 1)..lines.len() {
            let line = lines[i];
            let trimmed = line.trim();

            if trimmed.is_empty() {
                continue;
            }

            let indent = line.len() - line.trim_start().len();

            // Still in the list?
            if indent >= list_indent && trimmed.starts_with("- ") {
                last_list_item = i;
                // Check if this is our label
                let item_val = trimmed.trim_start_matches("- ").trim();
                let unquoted = item_val.trim_matches('"');
                if unquoted == label_name {
                    label_exists = true;
                }
            } else {
                break;
            }
        }

        if label_exists {
            return Ok((content.to_string(), false));
        }

        // Append label to existing list
        let pad = " ".repeat(list_indent);
        let new_line = format!("{pad}- \"{label_name}\"");
        let insert = InsertPoint {
            line: last_list_item + 1,
            indent: list_indent,
            section_exists: true,
        };
        let modified = insert_lines_at(content, &insert, &[new_line]);
        return Ok((modified, true));
    }

    // No existing scope — insert new scope block after the entry's last line
    let pad = " ".repeat(prop_indent);
    let list_pad = " ".repeat(list_indent);
    let new_lines = vec![
        format!("{pad}{scope_key}:"),
        format!("{list_pad}- \"{label_name}\""),
    ];

    let insert = InsertPoint {
        line: entry_end + 1,
        indent: prop_indent,
        section_exists: true,
    };
    let modified = insert_lines_at(content, &insert, &new_lines);
    Ok((modified, true))
}

/// Remove entries matching any of `paths_to_remove` from YAML content.
///
/// Handles both single-line entries (`- path: <ref>`) and multi-line entries
/// (e.g. profiles with `labels_include_any`, `self_service`, etc. blocks).
///
/// When a `- path:` line matches, all subsequent continuation lines (deeper-indented,
/// not starting a new `- ` at the same level) are also removed.
///
/// Returns `(modified_content, removed_count)`.
pub fn remove_path_entries(content: &str, paths_to_remove: &[String]) -> (String, usize) {
    if paths_to_remove.is_empty() {
        return (content.to_string(), 0);
    }

    let lines: Vec<&str> = content.lines().collect();
    let mut keep = vec![true; lines.len()];
    let mut removed = 0;

    let mut i = 0;
    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Check if this line is a `- path: <something>` that we want to remove
        let matched = if trimmed.starts_with("- path: ") {
            let path_val = trimmed
                .strip_prefix("- path: ")
                .expect("invariant: guarded by starts_with check")
                .trim();
            // Handle both quoted and unquoted path values
            let unquoted = path_val.trim_matches('"').trim_matches('\'');
            paths_to_remove.iter().any(|p| p == unquoted)
        } else {
            false
        };

        if matched {
            let entry_indent = lines[i].len() - lines[i].trim_start().len();
            keep[i] = false;
            removed += 1;
            i += 1;

            // Remove continuation lines (deeper-indented, not a new `- ` at same level)
            while i < lines.len() {
                let next_trimmed = lines[i].trim();

                // Blank lines within an entry block — remove them too
                if next_trimmed.is_empty() {
                    // Peek ahead: if the next non-blank line is still a continuation, remove
                    // Otherwise stop (blank line between entries)
                    let mut peek = i + 1;
                    while peek < lines.len() && lines[peek].trim().is_empty() {
                        peek += 1;
                    }
                    if peek < lines.len() {
                        let peek_indent = lines[peek].len() - lines[peek].trim_start().len();
                        let peek_trimmed = lines[peek].trim();
                        if peek_indent > entry_indent
                            || (peek_indent == entry_indent
                                && !peek_trimmed.starts_with("- ")
                                && !peek_trimmed.is_empty())
                        {
                            keep[i] = false;
                            i += 1;
                            continue;
                        }
                    }
                    break;
                }

                let next_indent = lines[i].len() - lines[i].trim_start().len();

                // A new list entry at same or lesser indent → stop
                if next_trimmed.starts_with("- ") && next_indent <= entry_indent {
                    break;
                }

                // A line at lesser indent → stop (we've left the section)
                if next_indent <= entry_indent && !next_trimmed.is_empty() {
                    break;
                }

                // Continuation line — remove it
                keep[i] = false;
                i += 1;
            }
        } else {
            i += 1;
        }
    }

    let mut result: Vec<&str> = Vec::with_capacity(lines.len());
    for (idx, line) in lines.iter().enumerate() {
        if keep[idx] {
            result.push(line);
        }
    }

    let mut output = result.join("\n");
    if content.ends_with('\n') && !output.ends_with('\n') {
        output.push('\n');
    }

    (output, removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_section_insert_point_labels() {
        let content = "labels:\n  - path: ./lib/a.yml\n  - path: ./lib/b.yml\n\nreports:\n";
        let lines: Vec<&str> = content.lines().collect();
        let point = find_section_insert_point(&lines, "labels").unwrap();
        assert_eq!(point.line, 3);
        assert_eq!(point.indent, 2);
    }

    #[test]
    fn test_insert_lines() {
        let content = "labels:\n  - path: ./lib/a.yml\n\nreports:\n";
        let lines: Vec<&str> = content.lines().collect();
        let point = find_section_insert_point(&lines, "labels").unwrap();
        let new_lines = vec!["  - path: ./lib/b.yml".to_string()];
        let result = insert_lines_at(content, &point, &new_lines);
        assert!(result.contains("./lib/b.yml"));
        assert!(result.find("./lib/b.yml").unwrap() < result.find("reports:").unwrap());
    }

    #[test]
    fn test_find_nested_section() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: a.mobileconfig\n        labels_include_any:\n          - \"Foo\"\n      - path: b.mobileconfig\n\nreports:\n";
        let lines: Vec<&str> = content.lines().collect();
        let point = find_nested_section_insert_point(
            &lines,
            &["controls", "macos_settings", "custom_settings"],
        )
        .unwrap();
        assert_eq!(point.line, 7);
        assert_eq!(point.indent, 6);
    }

    #[test]
    fn test_add_label_to_entry_new_scope() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/foo.mobileconfig\n      - path: ../lib/macos/configuration-profiles/bar.mobileconfig\n";
        let (result, modified) = add_label_to_entry(
            content,
            "../lib/macos/configuration-profiles/foo.mobileconfig",
            "labels_include_any",
            "AI Pilot",
        )
        .unwrap();
        assert!(modified);
        assert!(result.contains("labels_include_any:"));
        assert!(result.contains("\"AI Pilot\""));
    }

    #[test]
    fn test_add_label_to_entry_existing_scope_append() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/foo.mobileconfig\n        labels_include_any:\n          - \"Existing Label\"\n";
        let (result, modified) = add_label_to_entry(
            content,
            "../lib/macos/configuration-profiles/foo.mobileconfig",
            "labels_include_any",
            "New Label",
        )
        .unwrap();
        assert!(modified);
        assert!(result.contains("\"Existing Label\""));
        assert!(result.contains("\"New Label\""));
    }

    #[test]
    fn test_add_label_to_entry_idempotent() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/foo.mobileconfig\n        labels_include_any:\n          - \"AI Pilot\"\n";
        let (_, modified) = add_label_to_entry(
            content,
            "../lib/macos/configuration-profiles/foo.mobileconfig",
            "labels_include_any",
            "AI Pilot",
        )
        .unwrap();
        assert!(!modified);
    }

    #[test]
    fn test_add_label_to_entry_mutual_exclusivity() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/foo.mobileconfig\n        labels_include_any:\n          - \"Existing\"\n";
        let result = add_label_to_entry(
            content,
            "../lib/macos/configuration-profiles/foo.mobileconfig",
            "labels_exclude_any",
            "New Label",
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutual exclusivity"));
    }

    #[test]
    fn test_add_label_to_entry_path_not_found() {
        let content = "controls:\n  macos_settings:\n    custom_settings:\n      - path: ../lib/macos/configuration-profiles/foo.mobileconfig\n";
        let (_, modified) = add_label_to_entry(
            content,
            "../lib/macos/configuration-profiles/nonexistent.mobileconfig",
            "labels_include_any",
            "Label",
        )
        .unwrap();
        assert!(!modified);
    }

    // ── append_to_section tests ──

    #[test]
    fn test_append_to_section_empty_reports() {
        let content = "name: Test\nreports:\npolicies:\n  - path: ./lib/pol.yml\n";
        let entries = vec!["  - path: ./lib/all/reports/new.yml".to_string()];
        let result = append_to_section(content, "reports", &entries);
        assert!(result.contains("reports:\n  - path: ./lib/all/reports/new.yml"));
        // policies section should still be intact
        assert!(result.contains("policies:\n  - path: ./lib/pol.yml"));
    }

    #[test]
    fn test_append_to_section_empty_policies() {
        let content = "name: Test\npolicies:\nlabels:\n  - path: ./lib/lbl.yml\n";
        let entries = vec!["  - path: ./lib/macos/policies/filevault.yml".to_string()];
        let result = append_to_section(content, "policies", &entries);
        assert!(result.contains("policies:\n  - path: ./lib/macos/policies/filevault.yml"));
        assert!(result.contains("labels:\n  - path: ./lib/lbl.yml"));
    }

    #[test]
    fn test_append_to_section_empty_labels() {
        let content = "name: Test\nlabels:\nreports:\n  - path: ./lib/q.yml\n";
        let entries = vec!["  - path: ./lib/all/labels/my-label.yml".to_string()];
        let result = append_to_section(content, "labels", &entries);
        assert!(result.contains("labels:\n  - path: ./lib/all/labels/my-label.yml"));
        assert!(result.contains("reports:\n  - path: ./lib/q.yml"));
    }

    #[test]
    fn test_append_to_section_existing_items() {
        let content = "reports:\n  - path: ./lib/existing.yml\npolicies:\n";
        let entries = vec!["  - path: ./lib/new.yml".to_string()];
        let result = append_to_section(content, "reports", &entries);
        assert!(result.contains("- path: ./lib/existing.yml"));
        assert!(result.contains("- path: ./lib/new.yml"));
        // new entry should be before policies
        let new_pos = result.find("./lib/new.yml").unwrap();
        let pol_pos = result.find("policies:").unwrap();
        assert!(new_pos < pol_pos);
    }

    #[test]
    fn test_append_to_section_missing() {
        let content = "name: Test\n";
        let entries = vec!["  - path: ./lib/q.yml".to_string()];
        let result = append_to_section(content, "reports", &entries);
        assert!(result.contains("reports:\n  - path: ./lib/q.yml"));
    }

    #[test]
    fn test_append_to_section_empty_at_end_of_file() {
        let content = "name: Test\nreports:\n";
        let entries = vec!["  - path: ./lib/q.yml".to_string()];
        let result = append_to_section(content, "reports", &entries);
        assert!(result.contains("reports:\n  - path: ./lib/q.yml"));
    }

    #[test]
    fn test_append_custom_settings_empty_controls() {
        let content = "name: Test\ncontrols:\nreports:\n  - path: ./lib/q.yml\n";
        let entries = vec![vec![
            "      - path: ../lib/macos/foo.mobileconfig".to_string(),
        ]];
        let result = append_custom_settings(content, &entries);
        assert!(result.contains("macos_settings:"));
        assert!(result.contains("custom_settings:"));
        assert!(result.contains("- path: ../lib/macos/foo.mobileconfig"));
        // reports should still be intact
        assert!(result.contains("reports:\n  - path: ./lib/q.yml"));
    }

    // ── remove_path_entries tests ──

    #[test]
    fn test_remove_single_line_entry() {
        let content = "\
reports:
  - path: ../lib/all/reports/a.yml
  - path: ../lib/all/reports/b.yml
  - path: ../lib/all/reports/c.yml
";
        let (result, count) =
            remove_path_entries(content, &["../lib/all/reports/b.yml".to_string()]);
        assert_eq!(count, 1);
        assert!(!result.contains("b.yml"));
        assert!(result.contains("a.yml"));
        assert!(result.contains("c.yml"));
    }

    #[test]
    fn test_remove_multiple_entries() {
        let content = "\
reports:
  - path: ../lib/all/reports/a.yml
  - path: ../lib/all/reports/b.yml
  - path: ../lib/all/reports/c.yml
";
        let (result, count) = remove_path_entries(
            content,
            &[
                "../lib/all/reports/a.yml".to_string(),
                "../lib/all/reports/c.yml".to_string(),
            ],
        );
        assert_eq!(count, 2);
        assert!(!result.contains("a.yml"));
        assert!(result.contains("b.yml"));
        assert!(!result.contains("c.yml"));
    }

    #[test]
    fn test_remove_multiline_profile_entry() {
        let content = "\
controls:
  macos_settings:
    custom_settings:
      - path: ../lib/macos/configuration-profiles/wifi.mobileconfig
        labels_include_any:
          - \"Remote Workers\"
      - path: ../lib/macos/configuration-profiles/vpn.mobileconfig
";
        let (result, count) = remove_path_entries(
            content,
            &["../lib/macos/configuration-profiles/wifi.mobileconfig".to_string()],
        );
        assert_eq!(count, 1);
        assert!(!result.contains("wifi.mobileconfig"));
        assert!(!result.contains("Remote Workers"));
        assert!(result.contains("vpn.mobileconfig"));
    }

    #[test]
    fn test_remove_preserves_unrelated_content() {
        let content = "\
name: TestTeam
controls:
  scripts:
    - path: ../lib/macos/scripts/setup.sh
reports:
  - path: ../lib/all/reports/disk.yml
policies:
  - path: ../lib/macos/policies/filevault.yml
";
        let (result, count) =
            remove_path_entries(content, &["../lib/all/reports/disk.yml".to_string()]);
        assert_eq!(count, 1);
        assert!(!result.contains("disk.yml"));
        assert!(result.contains("name: TestTeam"));
        assert!(result.contains("setup.sh"));
        assert!(result.contains("filevault.yml"));
    }

    #[test]
    fn test_remove_no_match() {
        let content = "\
reports:
  - path: ../lib/all/reports/a.yml
";
        let (result, count) =
            remove_path_entries(content, &["../lib/all/reports/nonexistent.yml".to_string()]);
        assert_eq!(count, 0);
        assert_eq!(result, content);
    }

    #[test]
    fn test_remove_empty_paths() {
        let content = "reports:\n  - path: ../lib/a.yml\n";
        let (result, count) = remove_path_entries(content, &[]);
        assert_eq!(count, 0);
        assert_eq!(result, content);
    }

    #[test]
    fn test_remove_profile_with_self_service() {
        let content = "\
controls:
  macos_settings:
    custom_settings:
      - path: ../lib/macos/configuration-profiles/a.mobileconfig
        labels_include_any:
          - \"Label A\"
        self_service: true
      - path: ../lib/macos/configuration-profiles/b.mobileconfig
";
        let (result, count) = remove_path_entries(
            content,
            &["../lib/macos/configuration-profiles/a.mobileconfig".to_string()],
        );
        assert_eq!(count, 1);
        assert!(!result.contains("a.mobileconfig"));
        assert!(!result.contains("Label A"));
        assert!(!result.contains("self_service"));
        assert!(result.contains("b.mobileconfig"));
    }

    #[test]
    fn test_remove_software_entry() {
        let content = "\
software:
  packages:
    - path: ../lib/macos/software/firefox.yml
      self_service: true
    - path: ../lib/macos/software/slack.yml
";
        let (result, count) =
            remove_path_entries(content, &["../lib/macos/software/firefox.yml".to_string()]);
        assert_eq!(count, 1);
        assert!(!result.contains("firefox.yml"));
        assert!(!result.contains("self_service"));
        assert!(result.contains("slack.yml"));
    }

    #[test]
    fn test_remove_across_sections() {
        let content = "\
controls:
  macos_settings:
    custom_settings:
      - path: ../lib/macos/configuration-profiles/wifi.mobileconfig
  scripts:
    - path: ../lib/macos/scripts/setup.sh
    - path: ../lib/macos/scripts/cleanup.sh
reports:
  - path: ../lib/all/reports/disk.yml
";
        let (result, count) = remove_path_entries(
            content,
            &[
                "../lib/macos/configuration-profiles/wifi.mobileconfig".to_string(),
                "../lib/macos/scripts/cleanup.sh".to_string(),
                "../lib/all/reports/disk.yml".to_string(),
            ],
        );
        assert_eq!(count, 3);
        assert!(!result.contains("wifi.mobileconfig"));
        assert!(!result.contains("cleanup.sh"));
        assert!(!result.contains("disk.yml"));
        assert!(result.contains("setup.sh"));
    }

    // ── set_nested_key_values tests ──

    #[test]
    fn test_set_nested_kvs_replace_empty_values() {
        let content = "\
controls:
  macos_updates:
    deadline:
    minimum_version:
    update_new_hosts:
  scripts:
";
        let result = set_nested_key_values(
            content,
            &["controls", "macos_updates"],
            &[
                ("minimum_version", "15.3"),
                ("deadline", "2025-04-01"),
                ("update_new_hosts", "true"),
            ],
        );
        assert!(result.contains("    minimum_version: 15.3"));
        assert!(result.contains("    deadline: 2025-04-01"));
        assert!(result.contains("    update_new_hosts: true"));
        // scripts section should be untouched
        assert!(result.contains("  scripts:"));
    }

    #[test]
    fn test_set_nested_kvs_replace_existing_values() {
        let content = "\
controls:
  macos_updates:
    deadline: 2024-01-01
    minimum_version: 14.0
    update_new_hosts: false
";
        let result = set_nested_key_values(
            content,
            &["controls", "macos_updates"],
            &[("minimum_version", "15.3"), ("deadline", "2025-04-01")],
        );
        assert!(result.contains("    minimum_version: 15.3"));
        assert!(result.contains("    deadline: 2025-04-01"));
        // Untouched key should remain
        assert!(result.contains("    update_new_hosts: false"));
    }

    #[test]
    fn test_set_nested_kvs_windows_updates() {
        let content = "\
controls:
  windows_updates:
    deadline_days:
    grace_period_days:
";
        let result = set_nested_key_values(
            content,
            &["controls", "windows_updates"],
            &[("deadline_days", "5"), ("grace_period_days", "2")],
        );
        assert!(result.contains("    deadline_days: 5"));
        assert!(result.contains("    grace_period_days: 2"));
    }

    #[test]
    fn test_set_nested_kvs_section_missing() {
        let content = "\
controls:
  macos_settings:
    custom_settings:
      - path: foo.mobileconfig
";
        let result = set_nested_key_values(
            content,
            &["controls", "macos_updates"],
            &[("minimum_version", "15.3"), ("deadline", "2025-04-01")],
        );
        assert!(result.contains("macos_updates:"));
        assert!(result.contains("minimum_version: 15.3"));
        assert!(result.contains("deadline: 2025-04-01"));
    }

    #[test]
    fn test_set_nested_kvs_no_controls_section() {
        let content = "\
name: TestTeam
reports:
  - path: ../lib/q.yml
";
        let result = set_nested_key_values(
            content,
            &["controls", "macos_updates"],
            &[("minimum_version", "15.3")],
        );
        assert!(result.contains("controls:"));
        assert!(result.contains("  macos_updates:"));
        assert!(result.contains("    minimum_version: 15.3"));
    }

    #[test]
    fn test_set_nested_kvs_insert_new_key() {
        let content = "\
controls:
  macos_updates:
    deadline: 2025-04-01
    minimum_version: 15.3
";
        let result = set_nested_key_values(
            content,
            &["controls", "macos_updates"],
            &[("update_new_hosts", "true")],
        );
        assert!(result.contains("    update_new_hosts: true"));
        // Existing keys untouched
        assert!(result.contains("    deadline: 2025-04-01"));
        assert!(result.contains("    minimum_version: 15.3"));
    }
}
