//! Global display-name collision guard for batch classification.
//!
//! Two profiles can classify to the same friendly name (e.g. two restriction
//! profiles with no extractable subject both become `Restriction`). Writing
//! both would create duplicate names on disk. [`resolve_collisions`] makes every
//! assigned name unique by appending ` (N)` suffixes, deterministically and
//! idempotently.

use std::collections::HashSet;

/// One profile's naming inputs for collision resolution.
#[derive(Debug, Clone)]
pub struct NameItem {
    /// Stable key (the file path) that defines suffix order; lower sorts first.
    pub sort_key: String,
    /// The classified target name, or `None` to keep `existing` untouched.
    pub proposed: Option<String>,
    /// The profile's current display name.
    pub existing: String,
}

/// Resolve display-name collisions by appending ` (N)` suffixes.
///
/// Unclassified items (`proposed == None`) keep their existing name and reserve
/// it. Classified items are assigned, in `sort_key` order, the first free name
/// of `base`, `base (2)`, `base (3)`, … Returns the final name per item in the
/// original input order.
///
/// Deterministic (ordering is by `sort_key`, not batch/parallel order) and
/// idempotent: a name already carrying the suffix it would be assigned
/// re-resolves to itself, so a second run reports no change.
pub fn resolve_collisions(items: &[NameItem]) -> Vec<String> {
    let mut final_names: Vec<Option<String>> = vec![None; items.len()];
    let mut used: HashSet<String> = HashSet::new();

    // Reserve fixed (unclassified) names first — they cannot change.
    for (i, item) in items.iter().enumerate() {
        if item.proposed.is_none() {
            used.insert(item.existing.clone());
            final_names[i] = Some(item.existing.clone());
        }
    }

    // Assign classified names in deterministic sort_key order.
    let mut order: Vec<usize> = (0..items.len())
        .filter(|&i| items[i].proposed.is_some())
        .collect();
    order.sort_by(|&a, &b| items[a].sort_key.cmp(&items[b].sort_key));

    for i in order {
        let base = items[i].proposed.as_ref().expect("filtered to Some");
        let name = first_free(base, &used);
        used.insert(name.clone());
        final_names[i] = Some(name);
    }

    final_names
        .into_iter()
        .map(|n| n.expect("every item assigned"))
        .collect()
}

/// Strip a trailing ` (N)` numeric disambiguation suffix — the inverse of the
/// suffixing this module applies.
///
/// Lets re-classification ignore a collision suffix so renaming stays
/// idempotent. Only a purely-numeric parenthetical at the very end is removed,
/// so genuine parenthetical detail like `(disabled)` is preserved.
pub fn strip_suffix(name: &str) -> &str {
    let trimmed = name.trim_end();
    let Some(open) = trimmed.rfind('(') else {
        return name;
    };
    let inner = &trimmed[open + 1..];
    let Some(close) = inner.find(')') else {
        return name;
    };
    let digits = &inner[..close];
    let after = inner[close + 1..].trim();
    if after.is_empty() && !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        trimmed[..open].trim_end()
    } else {
        name
    }
}

/// The first of `base`, `base (2)`, `base (3)`, … not already in `used`.
fn first_free(base: &str, used: &HashSet<String>) -> String {
    if !used.contains(base) {
        return base.to_string();
    }
    let mut n = 2u32;
    loop {
        let candidate = format!("{base} ({n})");
        if !used.contains(&candidate) {
            return candidate;
        }
        n += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(key: &str, proposed: Option<&str>, existing: &str) -> NameItem {
        NameItem {
            sort_key: key.to_string(),
            proposed: proposed.map(str::to_string),
            existing: existing.to_string(),
        }
    }

    #[test]
    fn no_collision_keeps_names() {
        let items = vec![
            item("a", Some("Wi-Fi: Corp"), "old"),
            item("b", Some("Certificate: Root"), "old"),
        ];
        assert_eq!(
            resolve_collisions(&items),
            vec!["Wi-Fi: Corp", "Certificate: Root"]
        );
    }

    #[test]
    fn duplicate_base_gets_numeric_suffix_in_sort_order() {
        let items = vec![
            item("b", Some("Restriction"), "old-b"),
            item("a", Some("Restriction"), "old-a"),
        ];
        // Sort order is by key: a before b → a keeps base, b gets (2).
        // Returned in input order (b, a).
        assert_eq!(
            resolve_collisions(&items),
            vec!["Restriction (2)", "Restriction"]
        );
    }

    #[test]
    fn three_way_collision_increments() {
        let items = vec![
            item("a", Some("Restriction"), "x"),
            item("b", Some("Restriction"), "y"),
            item("c", Some("Restriction"), "z"),
        ];
        assert_eq!(
            resolve_collisions(&items),
            vec!["Restriction", "Restriction (2)", "Restriction (3)"]
        );
    }

    #[test]
    fn already_suffixed_name_is_idempotent() {
        // Second run: the profile that previously became "Restriction (2)" now
        // carries that as its existing name; resolving again yields the same.
        let items = vec![
            item("a", Some("Restriction"), "Restriction"),
            item("b", Some("Restriction"), "Restriction (2)"),
        ];
        let out = resolve_collisions(&items);
        assert_eq!(out, vec!["Restriction", "Restriction (2)"]);
    }

    #[test]
    fn strip_suffix_removes_numeric_disambiguator_only() {
        assert_eq!(strip_suffix("Restriction (2)"), "Restriction");
        assert_eq!(
            strip_suffix("USB Drives Allowed (10)"),
            "USB Drives Allowed"
        );
        // Non-numeric parentheticals are real detail — preserved.
        assert_eq!(
            strip_suffix("Notifications (disabled)"),
            "Notifications (disabled)"
        );
        assert_eq!(strip_suffix("Restriction"), "Restriction");
    }

    #[test]
    fn classified_avoids_a_fixed_unclassified_name() {
        let items = vec![
            item("a", None, "Restriction"),          // unclassified, fixed
            item("b", Some("Restriction"), "old-b"), // classified collides
        ];
        assert_eq!(
            resolve_collisions(&items),
            vec!["Restriction", "Restriction (2)"]
        );
    }
}
