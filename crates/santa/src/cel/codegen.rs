//! CEL code generation: compile structured conditions into CEL expression strings.

use anyhow::{Result, bail};

/// A structured condition for CEL compilation.
#[derive(Debug, Clone)]
pub struct Condition {
    /// The field to compare (e.g., `target.team_id`, `euid`).
    pub field: String,
    /// The operator (e.g., `==`, `<`, `contains`).
    pub op: String,
    /// The raw value string.
    pub value: String,
}

/// How multiple conditions combine.
#[derive(Debug, Clone, Copy, Default)]
pub enum Logic {
    /// All conditions must match (AND).
    #[default]
    All,
    /// Any condition can match (OR).
    Any,
}

/// CEL result action.
#[derive(Debug, Clone)]
pub enum CelResult {
    /// ALLOWLIST
    Allowlist,
    /// BLOCKLIST
    Blocklist,
    /// ALLOWLIST_COMPILER
    AllowlistCompiler,
    /// SILENT_BLOCKLIST
    SilentBlocklist,
    /// REQUIRE_TOUCH_ID
    RequireTouchId,
    /// REQUIRE_TOUCH_ID_ONLY
    RequireTouchIdOnly,
}

impl CelResult {
    /// Parse a result string into a [`CelResult`].
    pub fn from_name(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "allowlist" | "allow" => Ok(Self::Allowlist),
            "blocklist" | "block" => Ok(Self::Blocklist),
            "allowlist_compiler" | "allowlist-compiler" => Ok(Self::AllowlistCompiler),
            "silent_blocklist" | "silent-blocklist" => Ok(Self::SilentBlocklist),
            "require_touch_id" | "require-touch-id" => Ok(Self::RequireTouchId),
            "require_touch_id_only" | "require-touch-id-only" => Ok(Self::RequireTouchIdOnly),
            other => bail!(
                "Unknown result '{other}'. Expected one of: allowlist, blocklist, \
                 allowlist_compiler, silent_blocklist, require_touch_id, require_touch_id_only"
            ),
        }
    }

    /// Convert to the CEL constant name.
    pub fn to_cel(&self) -> &str {
        match self {
            Self::Allowlist => "ALLOWLIST",
            Self::Blocklist => "BLOCKLIST",
            Self::AllowlistCompiler => "ALLOWLIST_COMPILER",
            Self::SilentBlocklist => "SILENT_BLOCKLIST",
            Self::RequireTouchId => "REQUIRE_TOUCH_ID",
            Self::RequireTouchIdOnly => "REQUIRE_TOUCH_ID_ONLY",
        }
    }
}

/// Detected value type for CEL expression generation.
#[derive(Debug, PartialEq, Eq)]
enum ValueType {
    Integer,
    Bool,
    Timestamp,
    List,
    String,
}

/// Detect the type of a raw value string.
fn detect_value_type(value: &str) -> ValueType {
    // Check bool
    if value == "true" || value == "false" {
        return ValueType::Bool;
    }

    // Check integer
    if value.parse::<i64>().is_ok() {
        return ValueType::Integer;
    }

    // Check list
    if value.starts_with('[') && value.ends_with(']') {
        return ValueType::List;
    }

    // Check ISO 8601 timestamp: simplified pattern matching
    // Matches patterns like 2025-01-01T00:00:00Z or 2025-01-01T00:00:00+00:00
    if is_iso8601_timestamp(value) {
        return ValueType::Timestamp;
    }

    ValueType::String
}

/// Check whether a string looks like an ISO 8601 timestamp.
fn is_iso8601_timestamp(s: &str) -> bool {
    // Must contain T separator and at least YYYY-MM-DDTHH:MM:SS
    if s.len() < 19 {
        return false;
    }
    let bytes = s.as_bytes();
    // Check YYYY-MM-DDTHH:MM:SS pattern
    bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
}

/// Format a value for CEL based on its detected type.
fn format_cel_value(value: &str) -> String {
    match detect_value_type(value) {
        ValueType::Bool | ValueType::Integer => value.to_string(),
        ValueType::Timestamp => format!("timestamp('{value}')"),
        ValueType::List => {
            // Parse list items, wrap strings in quotes
            let inner = &value[1..value.len() - 1];
            let items: Vec<String> = inner
                .split(',')
                .map(|item| {
                    let trimmed = item.trim();
                    match detect_value_type(trimmed) {
                        ValueType::Integer | ValueType::Bool => trimmed.to_string(),
                        _ => format!("'{trimmed}'"),
                    }
                })
                .collect();
            format!("[{}]", items.join(", "))
        }
        ValueType::String => format!("'{value}'"),
    }
}

/// Convert a single condition to a CEL expression fragment.
fn condition_to_cel(condition: &Condition) -> Result<String> {
    let field = &condition.field;
    let op = condition.op.as_str();
    let value = &condition.value;

    match op {
        "==" | "!=" | ">" | "<" | ">=" | "<=" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field} {op} {formatted}"))
        }
        "contains" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field}.contains({formatted})"))
        }
        "matches" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field}.matches({formatted})"))
        }
        "starts_with" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field}.startsWith({formatted})"))
        }
        "ends_with" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field}.endsWith({formatted})"))
        }
        "in" => {
            let formatted = format_cel_value(value);
            Ok(format!("{field} in {formatted}"))
        }
        "exists" => {
            // Pattern: field.exists(item, item in [values])
            let formatted = format_cel_value(value);
            Ok(format!("{field}.exists(item, item in {formatted})"))
        }
        other => bail!("Unsupported operator '{other}'"),
    }
}

/// Compile structured conditions into a CEL expression string.
///
/// Produces a ternary expression like:
/// `(condition1 && condition2) ? BLOCKLIST : ALLOWLIST`
pub fn compile_conditions(
    conditions: &[Condition],
    logic: Logic,
    result: &CelResult,
    else_result: Option<&CelResult>,
) -> Result<String> {
    if conditions.is_empty() {
        bail!("At least one condition is required");
    }

    let fragments: Vec<String> = conditions
        .iter()
        .map(condition_to_cel)
        .collect::<Result<Vec<_>>>()?;

    let joiner = match logic {
        Logic::All => " && ",
        Logic::Any => " || ",
    };

    let combined = if fragments.len() == 1 {
        fragments[0].clone()
    } else {
        fragments.join(joiner)
    };

    let result_str = result.to_cel();
    match else_result {
        Some(else_res) => Ok(format!(
            "({combined}) ? {result_str} : {}",
            else_res.to_cel()
        )),
        None => Ok(format!("({combined}) ? {result_str}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_value_type_bool() {
        assert_eq!(detect_value_type("true"), ValueType::Bool);
        assert_eq!(detect_value_type("false"), ValueType::Bool);
    }

    #[test]
    fn test_detect_value_type_integer() {
        assert_eq!(detect_value_type("0"), ValueType::Integer);
        assert_eq!(detect_value_type("42"), ValueType::Integer);
        assert_eq!(detect_value_type("-1"), ValueType::Integer);
    }

    #[test]
    fn test_detect_value_type_timestamp() {
        assert_eq!(
            detect_value_type("2025-01-01T00:00:00Z"),
            ValueType::Timestamp
        );
    }

    #[test]
    fn test_detect_value_type_list() {
        assert_eq!(detect_value_type("[a, b, c]"), ValueType::List);
    }

    #[test]
    fn test_detect_value_type_string() {
        assert_eq!(detect_value_type("EQHXZ8M8AV"), ValueType::String);
    }

    #[test]
    fn test_format_cel_value_string() {
        assert_eq!(format_cel_value("EQHXZ8M8AV"), "'EQHXZ8M8AV'");
    }

    #[test]
    fn test_format_cel_value_timestamp() {
        assert_eq!(
            format_cel_value("2025-01-01T00:00:00Z"),
            "timestamp('2025-01-01T00:00:00Z')"
        );
    }

    #[test]
    fn test_format_cel_value_int() {
        assert_eq!(format_cel_value("0"), "0");
    }

    #[test]
    fn test_format_cel_value_bool() {
        assert_eq!(format_cel_value("true"), "true");
    }

    #[test]
    fn test_format_cel_value_list() {
        assert_eq!(format_cel_value("[a, b]"), "['a', 'b']");
    }

    #[test]
    fn test_condition_to_cel_string_eq() {
        let cond = Condition {
            field: "target.team_id".to_string(),
            op: "==".to_string(),
            value: "EQHXZ8M8AV".to_string(),
        };
        assert_eq!(
            condition_to_cel(&cond).unwrap(),
            "target.team_id == 'EQHXZ8M8AV'"
        );
    }

    #[test]
    fn test_condition_to_cel_timestamp_lt() {
        let cond = Condition {
            field: "target.signing_time".to_string(),
            op: "<".to_string(),
            value: "2025-01-01T00:00:00Z".to_string(),
        };
        assert_eq!(
            condition_to_cel(&cond).unwrap(),
            "target.signing_time < timestamp('2025-01-01T00:00:00Z')"
        );
    }

    #[test]
    fn test_condition_to_cel_int_eq() {
        let cond = Condition {
            field: "euid".to_string(),
            op: "==".to_string(),
            value: "0".to_string(),
        };
        assert_eq!(condition_to_cel(&cond).unwrap(), "euid == 0");
    }

    #[test]
    fn test_condition_to_cel_bool_eq() {
        let cond = Condition {
            field: "target.is_platform_binary".to_string(),
            op: "==".to_string(),
            value: "true".to_string(),
        };
        assert_eq!(
            condition_to_cel(&cond).unwrap(),
            "target.is_platform_binary == true"
        );
    }

    #[test]
    fn test_condition_to_cel_contains() {
        let cond = Condition {
            field: "path".to_string(),
            op: "contains".to_string(),
            value: "/Applications/".to_string(),
        };
        assert_eq!(
            condition_to_cel(&cond).unwrap(),
            "path.contains('/Applications/')"
        );
    }

    #[test]
    fn test_condition_to_cel_exists() {
        let cond = Condition {
            field: "args".to_string(),
            op: "exists".to_string(),
            value: "[--disable, --unsafe]".to_string(),
        };
        assert_eq!(
            condition_to_cel(&cond).unwrap(),
            "args.exists(item, item in ['--disable', '--unsafe'])"
        );
    }

    #[test]
    fn test_compile_single_condition() {
        let conditions = vec![Condition {
            field: "target.team_id".to_string(),
            op: "==".to_string(),
            value: "EQHXZ8M8AV".to_string(),
        }];
        let result = compile_conditions(
            &conditions,
            Logic::All,
            &CelResult::Blocklist,
            Some(&CelResult::Allowlist),
        )
        .unwrap();
        assert_eq!(
            result,
            "(target.team_id == 'EQHXZ8M8AV') ? BLOCKLIST : ALLOWLIST"
        );
    }

    #[test]
    fn test_compile_multiple_conditions_and() {
        let conditions = vec![
            Condition {
                field: "target.signing_time".to_string(),
                op: "<".to_string(),
                value: "2025-01-01T00:00:00Z".to_string(),
            },
            Condition {
                field: "target.team_id".to_string(),
                op: "==".to_string(),
                value: "EQHXZ8M8AV".to_string(),
            },
        ];
        let result = compile_conditions(
            &conditions,
            Logic::All,
            &CelResult::Blocklist,
            Some(&CelResult::Allowlist),
        )
        .unwrap();
        assert_eq!(
            result,
            "(target.signing_time < timestamp('2025-01-01T00:00:00Z') && target.team_id == 'EQHXZ8M8AV') ? BLOCKLIST : ALLOWLIST"
        );
    }

    #[test]
    fn test_compile_multiple_conditions_or() {
        let conditions = vec![
            Condition {
                field: "euid".to_string(),
                op: "==".to_string(),
                value: "0".to_string(),
            },
            Condition {
                field: "target.is_platform_binary".to_string(),
                op: "==".to_string(),
                value: "true".to_string(),
            },
        ];
        let result = compile_conditions(
            &conditions,
            Logic::Any,
            &CelResult::Allowlist,
            Some(&CelResult::Blocklist),
        )
        .unwrap();
        assert_eq!(
            result,
            "(euid == 0 || target.is_platform_binary == true) ? ALLOWLIST : BLOCKLIST"
        );
    }

    #[test]
    fn test_compile_no_else_result() {
        let conditions = vec![Condition {
            field: "euid".to_string(),
            op: "==".to_string(),
            value: "0".to_string(),
        }];
        let result =
            compile_conditions(&conditions, Logic::All, &CelResult::Blocklist, None).unwrap();
        assert_eq!(result, "(euid == 0) ? BLOCKLIST");
    }

    #[test]
    fn test_compile_empty_conditions() {
        let result = compile_conditions(
            &[],
            Logic::All,
            &CelResult::Blocklist,
            Some(&CelResult::Allowlist),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_cel_result_from_str() {
        assert!(CelResult::from_name("allowlist").is_ok());
        assert!(CelResult::from_name("blocklist").is_ok());
        assert!(CelResult::from_name("allow").is_ok());
        assert!(CelResult::from_name("block").is_ok());
        assert!(CelResult::from_name("allowlist-compiler").is_ok());
        assert!(CelResult::from_name("silent-blocklist").is_ok());
        assert!(CelResult::from_name("require-touch-id").is_ok());
        assert!(CelResult::from_name("require-touch-id-only").is_ok());
        assert!(CelResult::from_name("invalid").is_err());
    }

    #[test]
    fn test_cel_result_to_cel() {
        assert_eq!(CelResult::Allowlist.to_cel(), "ALLOWLIST");
        assert_eq!(CelResult::Blocklist.to_cel(), "BLOCKLIST");
        assert_eq!(CelResult::AllowlistCompiler.to_cel(), "ALLOWLIST_COMPILER");
        assert_eq!(CelResult::SilentBlocklist.to_cel(), "SILENT_BLOCKLIST");
        assert_eq!(CelResult::RequireTouchId.to_cel(), "REQUIRE_TOUCH_ID");
        assert_eq!(
            CelResult::RequireTouchIdOnly.to_cel(),
            "REQUIRE_TOUCH_ID_ONLY"
        );
    }
}
