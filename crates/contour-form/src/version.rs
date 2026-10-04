//! Dotted OS version comparison, numeric per segment.
//!
//! Apple writes `introduced: '26.0'`, `'13.0'`, `'1.1'`. A string compare
//! puts `9.3` after `15.0`; this does not. The one non-version value Apple
//! uses, `n/a`, parses to `None` and never compares equal to anything.

/// `"26.0.1"` → `[26, 0, 1]`. `None` for anything that is not digits and dots.
pub fn parse(v: &str) -> Option<Vec<u32>> {
    let v = v.trim();
    if v.is_empty() {
        return None;
    }
    v.split('.').map(|seg| seg.parse::<u32>().ok()).collect()
}

/// `have >= need`, with missing trailing segments read as zero, so
/// `26 >= 26.0` holds. `None` when either side is not a version.
pub fn at_least(have: &str, need: &str) -> Option<bool> {
    let (a, b) = (parse(have)?, parse(need)?);
    let len = a.len().max(b.len());
    for i in 0..len {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return Some(x > y);
        }
    }
    Some(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_numerically_not_lexically() {
        assert_eq!(at_least("15.0", "9.3"), Some(true));
        assert_eq!(at_least("9.3", "15.0"), Some(false));
        assert_eq!(at_least("26", "26.0"), Some(true));
        assert_eq!(at_least("26.0.1", "26.0"), Some(true));
        assert_eq!(at_least("25.9", "26.0"), Some(false));
    }

    #[test]
    fn n_a_is_not_a_version() {
        assert_eq!(parse("n/a"), None);
        assert_eq!(at_least("26.0", "n/a"), None);
        assert_eq!(parse(""), None);
    }
}
