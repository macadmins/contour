//! Static, offline validation of osquery SQL found in Fleet GitOps YAML.
//!
//! **Tier 1 — table-level only.** Every table named in a `FROM` or `JOIN` is
//! checked against the embedded osquery schema. A typo'd table is the failure
//! worth catching statically: the query does not error loudly, it returns
//! nothing, and a Fleet *policy* reads "no rows" as compliant — so a broken
//! check looks like a passing fleet, forever.
//!
//! **Tier 2 — [`check_query`].** Given a [`SchemaIndex`] built from the embedded
//! parquets, also checks the declared `platform` against each table's
//! platforms, that every `required` column is constrained, and — for a
//! single-table query with no subquery or CTE — that every selected or
//! filtered column exists. Any shape the lexical extractors cannot read with
//! confidence yields nothing rather than a false positive.

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
    /// The item's `platform:` field, when it declared one.
    pub platform: Option<String>,
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
/// strips schema-ish qualifiers and quoting. A comma list after `FROM`
/// (`FROM a x, b y`) yields every table in it.
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
                    // `FROM a [AS] x, b [AS] y`: an old-style join lists more
                    // tables after commas. Skip an alias, then take each one.
                    if rest.starts_with("from") {
                        let skip_ws = |mut pos: usize| {
                            while pos < bytes.len() && bytes[pos].is_whitespace() {
                                pos += 1;
                            }
                            pos
                        };
                        let word_end = |mut pos: usize| {
                            while pos < bytes.len() && (bytes[pos].is_alphanumeric() || bytes[pos] == '_') {
                                pos += 1;
                            }
                            pos
                        };
                        loop {
                            let mut pos = skip_ws(j);
                            // Optional alias (`as x` or bare `x`), never a keyword.
                            let end = word_end(pos);
                            let word: String = bytes[pos..end].iter().collect();
                            if word == "as" {
                                pos = word_end(skip_ws(end));
                            } else if !word.is_empty() && !SQL_WORDS.contains(&word.as_str()) {
                                pos = end;
                            }
                            pos = skip_ws(pos);
                            if pos >= bytes.len() || bytes[pos] != ',' {
                                j = pos.min(bytes.len());
                                break;
                            }
                            pos = skip_ws(pos + 1);
                            let start = pos;
                            while pos < bytes.len()
                                && (bytes[pos].is_alphanumeric()
                                    || bytes[pos] == '_'
                                    || bytes[pos] == '.'
                                    || bytes[pos] == '"'
                                    || bytes[pos] == '`')
                            {
                                pos += 1;
                            }
                            let raw: String = bytes[start..pos].iter().collect();
                            let name = normalise_table(&raw);
                            if !name.is_empty() && !ctes.contains(&name) {
                                out.insert(name);
                            }
                            j = pos;
                        }
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

/// Levenshtein distance (full DP, no cap); `suggest_tables` applies the threshold.
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
/// nested under a team/spec key), and a bare top-level list of objects with a
/// `query` key — Fleet's separate-file report shape (`*.reports.yml`), which
/// is what the security-posture pack and the compliance report are written
/// as. Keyed on structure rather than filename, so a hand-written
/// `default.yml` counts just as much as a generated file.
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
                    && matches!(key, "policies" | "queries" | "labels")
                    && let Some(items) = v.as_sequence()
                {
                    for (index, item) in items.iter().enumerate() {
                        // A manual label has no query; nothing to check.
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
                            platform: item
                                .get("platform")
                                .and_then(|p| p.as_str())
                                .map(str::to_string),
                        });
                    }
                    continue;
                }
                collect(v, out);
            }
        }
        yaml_serde::Value::Sequence(items) => {
            for (index, item) in items.iter().enumerate() {
                // A flat list of report objects: no collection key above it.
                if let Some(sql) = item.get("query").and_then(|q| q.as_str()) {
                    out.push(ExtractedQuery {
                        kind: "reports".to_string(),
                        index,
                        name: item
                            .get("name")
                            .and_then(|n| n.as_str())
                            .map(str::to_string),
                        sql: sql.to_string(),
                        platform: item
                            .get("platform")
                            .and_then(|p| p.as_str())
                            .map(str::to_string),
                    });
                    continue;
                }
                collect(item, out);
            }
        }
        _ => {}
    }
}

// ── Schema-aware checks ──────────────────────────────────────────────

/// What the embedded schemas say about one table.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TableInfo {
    /// Listed by upstream osquery.
    pub in_osquery: bool,
    /// Listed by Fleet's schema.
    pub in_fleet: bool,
    /// Lower-case platform names; empty when the schema states none.
    pub platforms: BTreeSet<String>,
    /// Every column, hidden ones included (they are still queryable).
    pub columns: BTreeSet<String>,
    /// Columns the table needs in a WHERE/JOIN to return anything.
    pub required: BTreeSet<String>,
}

/// Table name → [`TableInfo`], folded from both embedded schemas.
pub type SchemaIndex = std::collections::BTreeMap<String, TableInfo>;

/// Tables an agent extension provides that neither embedded schema lists.
/// A query over one is a warning, not an error. A test asserts each is still
/// absent from the index, so a dataset that starts carrying one shrinks this.
pub const EXTENSION_TABLES: &[&str] = &["osquery_labels", "santa_rules"];

/// Platform names Fleet and osquery use.
pub const KNOWN_PLATFORMS: &[&str] = &["darwin", "linux", "windows", "chrome"];

/// Split a schema or policy `platform` string into lower-case names.
/// `posix` expands to darwin and linux; empty or `all` to every platform.
pub fn normalise_platforms(csv: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in csv.split(',') {
        match raw.trim().to_lowercase().as_str() {
            "" | "all" => out.extend(["darwin", "linux", "windows"].map(str::to_string)),
            "posix" => out.extend(["darwin", "linux"].map(str::to_string)),
            p => {
                out.insert(p.to_string());
            }
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The query is wrong as written.
    Error,
    /// The query works somewhere, but not everywhere a reader may assume.
    Warning,
}

/// One thing [`check_query`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Problem {
    UnknownTable { table: String, suggestions: Vec<String> },
    FleetOnlyTable { table: String },
    ExtensionTable { table: String },
    UnknownPlatform { platform: String },
    PlatformMismatch { table: String, platform: String, has: Vec<String> },
    /// No platform declared, and the table is not on every platform.
    NoPlatform { table: String, has: Vec<String> },
    UnknownColumn { table: String, column: String },
    RequiredUnconstrained { table: String, column: String },
}

impl Problem {
    pub fn severity(&self) -> Severity {
        match self {
            Problem::FleetOnlyTable { .. }
            | Problem::ExtensionTable { .. }
            | Problem::NoPlatform { .. } => Severity::Warning,
            _ => Severity::Error,
        }
    }
}

impl std::fmt::Display for Problem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Problem::UnknownTable { table, suggestions } if suggestions.is_empty() => {
                write!(f, "unknown table '{table}'")
            }
            Problem::UnknownTable { table, suggestions } => {
                write!(f, "unknown table '{table}' — did you mean: {}?", suggestions.join(", "))
            }
            Problem::FleetOnlyTable { table } => write!(
                f,
                "'{table}' is a Fleet extension table; requires Fleet's agent, plain osqueryd returns nothing"
            ),
            Problem::ExtensionTable { table } => write!(
                f,
                "'{table}' comes from an osquery extension, not from osquery or Fleet's schema"
            ),
            Problem::UnknownPlatform { platform } if platform == "macos" => {
                write!(f, "unknown platform '{platform}' — osquery calls it 'darwin'")
            }
            Problem::UnknownPlatform { platform } => write!(
                f,
                "unknown platform '{platform}' (known: {})",
                KNOWN_PLATFORMS.join(", ")
            ),
            Problem::PlatformMismatch { table, platform, has } => write!(
                f,
                "'{table}' is not available on {platform} (platforms: {})",
                has.join(", ")
            ),
            Problem::NoPlatform { table, has } => write!(
                f,
                "no platform declared, but '{table}' exists only on {}; scope the query or it runs everywhere",
                has.join(", ")
            ),
            Problem::UnknownColumn { table, column } => {
                write!(f, "'{table}' has no column '{column}'")
            }
            Problem::RequiredUnconstrained { table, column } => write!(
                f,
                "'{table}.{column}' is a required column; without it in WHERE the table returns nothing"
            ),
        }
    }
}

/// Check one query against the schema index.
///
/// `platform` is the policy's or report's declared platform (comma-separated;
/// empty means every platform). The result is empty when nothing is wrong.
pub fn check_query(sql: &str, platform: &str, index: &SchemaIndex) -> Vec<Problem> {
    let mut out = Vec::new();
    let known: BTreeSet<String> = index.keys().cloned().collect();
    let tables = extract_tables(sql);

    // An explicit platform is held to the tables; none declared is a warning
    // when a table is not everywhere, since Fleet then runs it on every host.
    let explicit = !matches!(platform.trim().to_lowercase().as_str(), "" | "all");
    let declared: Vec<String> = normalise_platforms(platform).into_iter().collect();
    for p in &declared {
        if !KNOWN_PLATFORMS.contains(&p.as_str()) {
            out.push(Problem::UnknownPlatform {
                platform: p.clone(),
            });
        }
    }

    let constrained = constrained_columns(sql);
    let lowered = sql.to_lowercase();
    let single_table_plain =
        tables.len() == 1 && !lowered.contains("with ") && !lowered.contains("(select");

    for table in &tables {
        let Some(info) = index.get(table) else {
            if EXTENSION_TABLES.contains(&table.as_str()) {
                out.push(Problem::ExtensionTable {
                    table: table.clone(),
                });
            } else {
                out.push(Problem::UnknownTable {
                    table: table.clone(),
                    suggestions: suggest_tables(table, &known),
                });
            }
            continue;
        };
        if info.in_fleet && !info.in_osquery {
            out.push(Problem::FleetOnlyTable {
                table: table.clone(),
            });
        }
        if !info.platforms.is_empty() {
            let has: Vec<String> = info.platforms.iter().cloned().collect();
            if explicit {
                for p in &declared {
                    if KNOWN_PLATFORMS.contains(&p.as_str()) && !info.platforms.contains(p) {
                        out.push(Problem::PlatformMismatch {
                            table: table.clone(),
                            platform: p.clone(),
                            has: has.clone(),
                        });
                    }
                }
            } else if declared.iter().any(|p| !info.platforms.contains(p)) {
                out.push(Problem::NoPlatform {
                    table: table.clone(),
                    has,
                });
            }
        }
        for r in &info.required {
            if !constrained.contains(r) {
                out.push(Problem::RequiredUnconstrained {
                    table: table.clone(),
                    column: r.clone(),
                });
            }
        }
        if single_table_plain {
            for c in extract_columns(sql) {
                if !info.columns.contains(&c) {
                    out.push(Problem::UnknownColumn {
                        table: table.clone(),
                        column: c,
                    });
                }
            }
        }
    }
    out
}

/// SQL words that can sit where a column name could.
const SQL_WORDS: &[&str] = &[
    "select", "from", "where", "and", "or", "not", "in", "like", "glob", "regexp", "is",
    "null", "as", "on", "join", "left", "right", "inner", "outer", "cross", "cast", "case",
    "when", "then", "else", "end", "distinct", "group", "by", "order", "limit", "offset",
    "having", "exists", "between", "true", "false", "asc", "desc", "union", "intersect",
    "except", "all", "with", "integer", "text", "real", "blob", "collate", "nocase",
];

/// Strip `--` comments and blank the inside of single-quoted literals, so no
/// literal text is mistaken for an identifier. Lower-cases the result.
fn scrub(sql: &str) -> String {
    let mut out = String::with_capacity(sql.len());
    for line in sql.lines() {
        let code = line.split_once("--").map_or(line, |(code, _)| code);
        out.push_str(code);
        out.push('\n');
    }
    let mut cleaned = String::with_capacity(out.len());
    let mut in_literal = false;
    for ch in out.chars() {
        if ch == '\'' {
            in_literal = !in_literal;
            cleaned.push(ch);
        } else if in_literal {
            cleaned.push(' ');
        } else {
            cleaned.push(ch);
        }
    }
    cleaned.to_lowercase()
}

/// A column-shaped identifier: unqualified, unquoted, not a keyword or number.
fn as_column(token: &str) -> Option<String> {
    let t: String = token.chars().filter(|c| *c != '"' && *c != '`').collect();
    let t = t.rsplit('.').next().unwrap_or_default().trim().to_string();
    if t.is_empty()
        || t.starts_with(|c: char| c.is_ascii_digit())
        || SQL_WORDS.contains(&t.as_str())
        || !t.chars().all(|c| c.is_alphanumeric() || c == '_')
    {
        return None;
    }
    Some(t)
}

/// Columns a query selects or filters on — the names a schema can confirm.
///
/// SELECT items that are expressions (`count(*)`, `a || b`), `*`, or
/// numbers are skipped; `a AS b` yields `a`. Combined with
/// [`constrained_columns`] for the predicate side.
pub fn extract_columns(sql: &str) -> BTreeSet<String> {
    let s = scrub(sql);
    let mut out = constrained_columns(sql);
    let Some(start) = s.find("select") else {
        return out;
    };
    let body = &s[start + "select".len()..];
    // The SELECT list ends at the first depth-0 FROM.
    let mut depth = 0i32;
    let mut end = body.len();
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '(' => depth += 1,
            ')' => depth -= 1,
            'f' if depth == 0
                && body[i..].starts_with("from")
                && (i == 0 || !chars[i - 1].is_alphanumeric())
                && chars.get(i + 4).is_none_or(|c| !c.is_alphanumeric() && *c != '_') =>
            {
                end = i;
                break;
            }
            _ => {}
        }
        i += 1;
    }
    let list = &body[..end];
    // Split on depth-0 commas.
    let mut items = Vec::new();
    let mut cur = String::new();
    depth = 0;
    for ch in list.chars() {
        match ch {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                items.push(std::mem::take(&mut cur));
                continue;
            }
            _ => {}
        }
        cur.push(ch);
    }
    items.push(cur);
    for item in items {
        let item = item.trim().trim_start_matches("distinct ").trim();
        if item.is_empty() || item == "*" || item.contains('(') || item.contains("||") {
            continue;
        }
        if let Some(col) = item.split_whitespace().next().and_then(as_column) {
            out.insert(col);
        }
    }
    out
}

/// Columns that appear on the left of a comparison in WHERE / ON clauses,
/// qualifier stripped (`s.path = a.path` yields `path`).
pub fn constrained_columns(sql: &str) -> BTreeSet<String> {
    let s = scrub(sql);
    let mut out = BTreeSet::new();
    // Everything after the first WHERE or ON, up to GROUP/ORDER/LIMIT.
    let starts: Vec<usize> = [" where ", " on ", "\nwhere ", "\non "]
        .iter()
        .filter_map(|k| s.find(k))
        .collect();
    let Some(&start) = starts.iter().min() else {
        return out;
    };
    let tail = &s[start..];
    let end = [" group by", " order by", " limit ", ";"]
        .iter()
        .filter_map(|k| tail.find(k))
        .min()
        .unwrap_or(tail.len());
    let clause = &tail[..end];

    // Tokenise: identifier runs, operator runs, everything else single.
    let mut tokens: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut kind = 0u8; // 0 none, 1 ident, 2 op
    for ch in clause.chars() {
        let k = if ch.is_alphanumeric() || ch == '_' || ch == '.' || ch == '"' || ch == '`' {
            1
        } else if "=!<>".contains(ch) {
            2
        } else {
            0
        };
        if k != kind || k == 0 {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            kind = k;
        }
        if k != 0 {
            cur.push(ch);
        }
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    const OPS: &[&str] = &["in", "like", "glob", "regexp", "is", "between", "not"];
    for i in 1..tokens.len() {
        let op = tokens[i].as_str();
        let is_op = op.starts_with(['=', '!', '<', '>']) || OPS.contains(&op);
        if is_op && let Some(col) = as_column(&tokens[i - 1]) {
            out.insert(col);
        }
    }
    out
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

    /// `FROM a x, b y` is a join too; every table in the comma list counts,
    /// and a two-table query gets no single-table column check.
    #[test]
    fn extracts_tables_from_comma_joins() {
        let t = extract_tables(
            "SELECT 1 FROM mounts m, disk_encryption d WHERE m.device_alias = d.name AND d.encrypted = 1",
        );
        assert_eq!(t, ["disk_encryption", "mounts"].into_iter().map(String::from).collect());
        let t = extract_tables("SELECT 1 FROM users AS u, processes p, launchd WHERE u.uid = p.uid");
        assert_eq!(t.len(), 3, "{t:?}");
        // A bare alias before WHERE is not a table.
        let t = extract_tables("SELECT 1 FROM processes p WHERE p.pid = 1");
        assert_eq!(t, ["processes".to_string()].into_iter().collect());
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
            platform: None,
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
            platform: None,
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

    /// `*.reports.yml` is a bare list of report objects, no `policies:` or
    /// `queries:` key above it. The security-posture pack is written that way,
    /// so a walk that only knew the keyed collections read zero of its queries.
    #[test]
    fn extracts_queries_from_flat_reports_list() {
        let yaml = "- name: OS version\n  query: SELECT name FROM os_version;\n\
                    - name: SIP\n  query: SELECT enabled FROM sip_config;\n";
        let qs = extract_fleet_queries(yaml);
        assert_eq!(qs.len(), 2);
        assert_eq!(qs[0].kind, "reports");
        assert_eq!(qs[1].index, 1);
        assert_eq!(qs[1].name.as_deref(), Some("SIP"));
    }

    /// A YAML with no queries, or unparseable YAML, yields nothing rather
    /// than failing the run — a GitOps repo holds many unrelated files.
    #[test]
    fn non_query_yaml_yields_nothing() {
        assert!(extract_fleet_queries("apiVersion: v1\nkind: config\n").is_empty());
        assert!(extract_fleet_queries("{{ not yaml at all").is_empty());
    }

    fn index() -> SchemaIndex {
        let mut idx = SchemaIndex::new();
        let t = |osq: bool, fleet: bool, platforms: &[&str], cols: &[&str], req: &[&str]| TableInfo {
            in_osquery: osq,
            in_fleet: fleet,
            platforms: platforms.iter().map(|s| (*s).to_string()).collect(),
            columns: cols.iter().map(|s| (*s).to_string()).collect(),
            required: req.iter().map(|s| (*s).to_string()).collect(),
        };
        idx.insert("plist".into(), t(true, true, &["darwin"], &["path", "key", "subkey", "value"], &["path"]));
        idx.insert("os_version".into(), t(true, true, &["darwin", "linux", "windows"], &["name", "version", "build"], &[]));
        idx.insert("mdm_bridge".into(), t(false, true, &["windows"], &["mdm_command_input", "mdm_command_output"], &["mdm_command_input"]));
        idx.insert("sip_config".into(), t(true, true, &["darwin"], &["config_flag", "enabled"], &[]));
        idx
    }

    #[test]
    fn check_query_passes_a_correct_single_table_query() {
        let idx = index();
        let p = check_query("SELECT name, version, build FROM os_version;", "darwin", &idx);
        assert!(p.is_empty(), "{p:?}");
    }

    #[test]
    fn check_query_flags_unknown_column_in_single_table_query() {
        let p = check_query("SELECT name, versoin FROM os_version;", "", &index());
        assert_eq!(
            p,
            vec![Problem::UnknownColumn { table: "os_version".into(), column: "versoin".into() }]
        );
    }

    #[test]
    fn check_query_requires_required_columns_to_be_constrained() {
        let idx = index();
        let p = check_query("SELECT key, value FROM plist WHERE key = 'x';", "darwin", &idx);
        assert!(p.contains(&Problem::RequiredUnconstrained { table: "plist".into(), column: "path".into() }));
        let ok = check_query("SELECT key AS rule, value AS compliant FROM plist WHERE path = '/L/p.plist';", "darwin", &idx);
        assert!(ok.is_empty(), "{ok:?}");
    }

    #[test]
    fn check_query_cross_checks_declared_platform() {
        let idx = index();
        let p = check_query("SELECT config_flag, enabled FROM sip_config;", "windows", &idx);
        assert_eq!(p.len(), 1);
        assert!(matches!(&p[0], Problem::PlatformMismatch { table, platform, .. } if table == "sip_config" && platform == "windows"));
        let p = check_query("SELECT 1 FROM os_version;", "macos", &idx);
        assert!(matches!(&p[0], Problem::UnknownPlatform { platform } if platform == "macos"));
        assert!(p[0].to_string().contains("darwin"));
        // No platform declared: a warning for a table that is not everywhere,
        // nothing for one that is.
        let p = check_query("SELECT 1 FROM sip_config;", "", &idx);
        assert_eq!(p, vec![Problem::NoPlatform { table: "sip_config".into(), has: vec!["darwin".into()] }]);
        assert_eq!(p[0].severity(), Severity::Warning);
        assert!(check_query("SELECT 1 FROM os_version;", "", &idx).is_empty());
    }

    #[test]
    fn check_query_warns_on_fleet_only_and_extension_tables() {
        let idx = index();
        let p = check_query(
            "SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '<x>' AND mdm_command_output LIKE '%1%';",
            "windows",
            &idx,
        );
        assert_eq!(p, vec![Problem::FleetOnlyTable { table: "mdm_bridge".into() }]);
        assert_eq!(p[0].severity(), Severity::Warning);
        let p = check_query("SELECT 1 FROM osquery_labels WHERE name = 'x';", "darwin", &idx);
        assert_eq!(p, vec![Problem::ExtensionTable { table: "osquery_labels".into() }]);
        let p = check_query("SELECT 1 FROM os_versions;", "", &idx);
        assert!(matches!(&p[0], Problem::UnknownTable { suggestions, .. } if suggestions == &["os_version".to_string()]));
        assert_eq!(p[0].severity(), Severity::Error);
    }

    /// Multi-table, subquery and CTE shapes get table/platform/required
    /// checks only — the column extractor is not asked to guess.
    #[test]
    fn column_check_is_skipped_for_joins_and_subqueries() {
        let idx = index();
        let p = check_query(
            "SELECT p.bogus FROM plist p JOIN os_version o ON p.path = o.name WHERE p.path = 'x';",
            "darwin",
            &idx,
        );
        assert!(!p.iter().any(|x| matches!(x, Problem::UnknownColumn { .. })), "{p:?}");
        let p = check_query("SELECT bogus FROM (SELECT * FROM os_version);", "", &idx);
        assert!(!p.iter().any(|x| matches!(x, Problem::UnknownColumn { .. })), "{p:?}");
    }

    #[test]
    fn extractors_read_select_items_and_predicate_columns() {
        let cols = extract_columns(
            "SELECT DISTINCT a.name, count(*), s.team_identifier AS team, 1 \
             FROM apps a JOIN signature s ON s.path = a.path \
             WHERE a.bundle_identifier <> '' AND s.hash_resources = 0 AND path LIKE '%.app' -- comment\n\
             ORDER BY a.name;",
        );
        for c in ["name", "team_identifier", "path", "bundle_identifier", "hash_resources"] {
            assert!(cols.contains(c), "missing {c} in {cols:?}");
        }
        assert!(!cols.contains("count") && !cols.contains("team") && !cols.contains("1"));
        let w = constrained_columns("SELECT 1 FROM plist WHERE path = 'a = b' AND key IN ('x') AND value IS NOT NULL");
        assert_eq!(w, ["path", "key", "value"].into_iter().map(String::from).collect());
    }

    #[test]
    fn extracted_query_carries_platform_and_reads_labels() {
        let yaml = "labels:\n  - name: m\n    label_membership_type: manual\n  - name: d\n    platform: darwin\n    query: SELECT 1 FROM os_version;\n";
        let qs = extract_fleet_queries(yaml);
        assert_eq!(qs.len(), 1);
        assert_eq!(qs[0].kind, "labels");
        assert_eq!(qs[0].platform.as_deref(), Some("darwin"));
    }
}
