//! Static, offline validation of osquery SQL found in Fleet GitOps YAML.
//!
//! **Tier 1 — table-level only.** Every table named in a `FROM` or `JOIN` is
//! checked against the embedded osquery schema. A typo'd table is the failure
//! worth catching statically: the query does not error loudly, it returns
//! nothing, and a Fleet *policy* reads "no rows" as compliant — so a broken
//! check looks like a passing fleet, forever.
//!
//! Column-level checking is deliberately out of scope here: `*`, aliases,
//! subqueries and CTEs make it false-positive-prone, and a wrong column is
//! rarer than a wrong table name.

use std::collections::BTreeSet;

/// One query extracted from a Fleet YAML document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedQuery {
    /// `policies` or `queries` — the Fleet collection it came from.
    pub kind: String,
    /// Index within that collection, for a locatable message.
    pub index: usize,
    /// The query's `name`, when present.
    pub name: Option<String>,
    /// The SQL itself.
    pub sql: String,
}

/// A table reference that matches no table in the embedded schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownTable {
    /// The name as written in the SQL.
    pub name: String,
    /// Closest known table names, if any look like a typo.
    pub suggestions: Vec<String>,
}

/// Result of validating one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryFinding {
    pub kind: String,
    pub index: usize,
    pub name: Option<String>,
    /// Tables referenced that the schema does not know.
    pub unknown_tables: Vec<UnknownTable>,
}

/// Extract table names appearing after `FROM` or `JOIN`.
///
/// Deliberately lexical rather than a full SQL parse: osquery accepts SQLite
/// dialect, and a parser that rejects valid-but-unusual SQL would be worse
/// than one that occasionally sees nothing. Unmatched tokens simply yield no
/// finding.
///
/// Skips subquery openers (`FROM (`), CTE names bound by `WITH … AS`, and
/// strips schema-ish qualifiers and quoting.
pub fn extract_tables(sql: &str) -> BTreeSet<String> {
    let lowered = sql.to_lowercase();
    let bytes: Vec<char> = lowered.chars().collect();
    let mut out = BTreeSet::new();

    // Names bound by `WITH <name> AS (` are query-local, not schema tables.
    let ctes = cte_names(&lowered);

    let mut i = 0;
    while i < bytes.len() {
        let rest: String = bytes[i..].iter().collect();
        // `FROM` and `JOIN` are both 4 chars and introduce a table the same way.
        let keyword = ((rest.starts_with("from") || rest.starts_with("join"))
            && boundary(&bytes, i, 4))
        .then_some(4);

        if let Some(kw_len) = keyword {
            // Only when the keyword itself starts on a boundary.
            let starts_clean = i == 0 || !bytes[i - 1].is_alphanumeric() && bytes[i - 1] != '_';
            if starts_clean {
                let mut j = i + kw_len;
                while j < bytes.len() && bytes[j].is_whitespace() {
                    j += 1;
                }
                // `FROM (` is a subquery — nothing to check at this position.
                if j < bytes.len() && bytes[j] != '(' {
                    let start = j;
                    while j < bytes.len()
                        && (bytes[j].is_alphanumeric()
                            || bytes[j] == '_'
                            || bytes[j] == '.'
                            || bytes[j] == '"'
                            || bytes[j] == '`')
                    {
                        j += 1;
                    }
                    let raw: String = bytes[start..j].iter().collect();
                    let name = normalise_table(&raw);
                    if !name.is_empty() && !ctes.contains(&name) {
                        out.insert(name);
                    }
                }
                i = j;
                continue;
            }
        }
        i += 1;
    }

    out
}

/// Strip quoting and any `schema.` qualifier from a raw table token.
fn normalise_table(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| *c != '"' && *c != '`').collect();
    cleaned
        .rsplit('.')
        .next()
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// True when position `i + len` ends on a word boundary.
fn boundary(bytes: &[char], i: usize, len: usize) -> bool {
    bytes
        .get(i + len)
        .is_none_or(|c| !c.is_alphanumeric() && *c != '_')
}

/// Names introduced by `WITH <name> AS (`, which are query-local.
fn cte_names(lowered: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (idx, _) in lowered.match_indices(" as ") {
        let before = lowered[..idx].trim_end();
        if let Some(name) = before.rsplit([' ', ',', '(', '\n', '\t']).next() {
            let name = normalise_table(name);
            if !name.is_empty() {
                out.insert(name);
            }
        }
    }
    // Only meaningful if the document actually uses WITH.
    if lowered.contains("with ") {
        out
    } else {
        BTreeSet::new()
    }
}

/// Levenshtein distance, capped for short-circuiting on clearly-unrelated names.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}

/// Up to three known tables close enough to look like a typo of `name`.
pub fn suggest_tables(name: &str, known: &BTreeSet<String>) -> Vec<String> {
    // Threshold scales with length: short names tolerate one edit, longer
    // ones two — enough for a plural/typo, tight enough to avoid noise.
    let max = if name.len() <= 6 { 1 } else { 2 };
    let mut scored: Vec<(usize, &String)> = known
        .iter()
        .map(|k| (edit_distance(name, k), k))
        .filter(|(d, _)| *d <= max)
        .collect();
    scored.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1)));
    scored.into_iter().take(3).map(|(_, k)| k.clone()).collect()
}

/// Validate one query's table references against the known table set.
pub fn validate_query(query: &ExtractedQuery, known: &BTreeSet<String>) -> Option<QueryFinding> {
    let unknown: Vec<UnknownTable> = extract_tables(&query.sql)
        .into_iter()
        .filter(|t| !known.contains(t))
        .map(|t| UnknownTable {
            suggestions: suggest_tables(&t, known),
            name: t,
        })
        .collect();

    (!unknown.is_empty()).then(|| QueryFinding {
        kind: query.kind.clone(),
        index: query.index,
        name: query.name.clone(),
        unknown_tables: unknown,
    })
}

/// Pull queries out of a Fleet GitOps YAML document.
///
/// Reads `policies[]` and `queries[]` wherever they appear (top level or
/// nested under a team/spec key), keyed on structure rather than filename —
/// a hand-written `default.yml` counts just as much as a generated
/// `*.policies.yml`.
pub fn extract_fleet_queries(yaml: &str) -> Vec<ExtractedQuery> {
    let Ok(doc) = yaml_serde::from_str::<yaml_serde::Value>(yaml) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    collect(&doc, &mut out);
    out
}

fn collect(value: &yaml_serde::Value, out: &mut Vec<ExtractedQuery>) {
    match value {
        yaml_serde::Value::Mapping(map) => {
            for (k, v) in map {
                if let Some(key) = k.as_str()
                    && matches!(key, "policies" | "queries")
                    && let Some(items) = v.as_sequence()
                {
                    for (index, item) in items.iter().enumerate() {
                        let Some(sql) = item.get("query").and_then(|q| q.as_str()) else {
                            continue;
                        };
                        out.push(ExtractedQuery {
                            kind: key.to_string(),
                            index,
                            name: item
                                .get("name")
                                .and_then(|n| n.as_str())
                                .map(str::to_string),
                            sql: sql.to_string(),
                        });
                    }
                    continue;
                }
                collect(v, out);
            }
        }
        yaml_serde::Value::Sequence(items) => {
            for item in items {
                collect(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn known() -> BTreeSet<String> {
        [
            "disk_encryption",
            "processes",
            "users",
            "launchd",
            "osquery_info",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    #[test]
    fn extracts_table_from_simple_select() {
        let t = extract_tables("SELECT 1 FROM disk_encryption WHERE encrypted = 1;");
        assert_eq!(t, ["disk_encryption".to_string()].into_iter().collect());
    }

    #[test]
    fn extracts_tables_from_joins() {
        let t = extract_tables(
            "SELECT * FROM processes p JOIN users u ON p.uid = u.uid LEFT JOIN launchd l ON 1=1",
        );
        assert!(t.contains("processes") && t.contains("users") && t.contains("launchd"));
    }

    /// Case and whitespace are cosmetic; the table set must not depend on them.
    #[test]
    fn is_case_and_whitespace_insensitive() {
        let t = extract_tables("select *\n  from\n\tDisk_Encryption");
        assert!(t.contains("disk_encryption"));
    }

    /// `FROM (` opens a subquery — there is no table name at that position,
    /// and inventing one would be a false positive.
    #[test]
    fn ignores_subquery_openers() {
        let t = extract_tables("SELECT * FROM (SELECT uid FROM users) x");
        assert!(t.contains("users"), "inner table still found");
        assert!(!t.iter().any(|s| s.is_empty() || s == "("));
    }

    /// A CTE name is query-local, not a schema table.
    #[test]
    fn ignores_cte_names() {
        let t = extract_tables(
            "WITH encrypted AS (SELECT * FROM disk_encryption) SELECT * FROM encrypted",
        );
        assert!(t.contains("disk_encryption"));
        assert!(
            !t.contains("encrypted"),
            "CTE must not be treated as a table"
        );
    }

    #[test]
    fn strips_quotes_and_qualifiers() {
        assert!(extract_tables("SELECT * FROM \"users\"").contains("users"));
        assert!(extract_tables("SELECT * FROM main.users").contains("users"));
    }

    /// The headline case: a typo'd table returns no rows, and a Fleet policy
    /// reads no rows as compliant — so this must be caught statically.
    #[test]
    fn flags_unknown_table_with_suggestion() {
        let q = ExtractedQuery {
            kind: "policies".into(),
            index: 3,
            name: Some("FileVault enabled".into()),
            sql: "SELECT 1 FROM disk_encryptions WHERE encrypted = 1".into(),
        };
        let finding = validate_query(&q, &known()).expect("typo must be reported");
        assert_eq!(finding.unknown_tables[0].name, "disk_encryptions");
        assert!(
            finding.unknown_tables[0]
                .suggestions
                .contains(&"disk_encryption".to_string()),
            "must suggest the real table"
        );
        assert_eq!(finding.index, 3);
        assert_eq!(finding.name.as_deref(), Some("FileVault enabled"));
    }

    #[test]
    fn valid_query_produces_no_finding() {
        let q = ExtractedQuery {
            kind: "policies".into(),
            index: 0,
            name: None,
            sql: "SELECT 1 FROM disk_encryption".into(),
        };
        assert!(validate_query(&q, &known()).is_none());
    }

    /// An unrelated name gets no suggestion rather than a nonsense one.
    #[test]
    fn unrelated_name_gets_no_suggestion() {
        let s = suggest_tables("zzzzzzzzzzzz", &known());
        assert!(s.is_empty(), "got: {s:?}");
    }

    /// Fleet YAML is identified by structure, not filename — a hand-written
    /// default.yml counts as much as a generated *.policies.yml.
    #[test]
    fn extracts_queries_from_fleet_yaml() {
        let yaml = r"
policies:
  - name: FileVault enabled
    platform: darwin
    query: SELECT 1 FROM disk_encryption WHERE encrypted = 1;
  - name: Santa running
    query: SELECT 1 FROM processes WHERE name = 'santad';
queries:
  - name: Inventory
    query: SELECT * FROM users;
";
        let qs = extract_fleet_queries(yaml);
        assert_eq!(qs.len(), 3);
        assert_eq!(qs[0].kind, "policies");
        assert_eq!(qs[0].index, 0);
        assert_eq!(qs[0].name.as_deref(), Some("FileVault enabled"));
        assert_eq!(qs[2].kind, "queries");
    }

    /// Fleet nests policies under team specs; the walk must reach them.
    #[test]
    fn finds_nested_policies() {
        let yaml = r"
spec:
  team:
    name: Workstations
    policies:
      - name: Nested check
        query: SELECT 1 FROM launchd;
";
        let qs = extract_fleet_queries(yaml);
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].name.as_deref(), Some("Nested check"));
    }

    /// A YAML with no queries, or unparseable YAML, yields nothing rather
    /// than failing the run — a GitOps repo holds many unrelated files.
    #[test]
    fn non_query_yaml_yields_nothing() {
        assert!(extract_fleet_queries("apiVersion: v1\nkind: config\n").is_empty());
        assert!(extract_fleet_queries("{{ not yaml at all").is_empty());
    }
}
