// Planned feature: Conflict detection across baselines
#![allow(dead_code, reason = "module under development")]

use crate::models::MscpBaseline;
use anyhow::Result;
use std::collections::{HashMap, HashSet};

/// Conflict detector for mobileconfig profiles
#[derive(Debug)]
pub struct ConflictDetector;

impl ConflictDetector {
    /// Detect conflicts across multiple baselines
    pub fn detect_conflicts(baselines: &[MscpBaseline]) -> Result<ConflictReport> {
        let mut conflicts = Vec::new();
        let mut payload_identifiers: HashMap<String, Vec<(String, String)>> = HashMap::new();
        let mut payload_types: HashMap<String, Vec<(String, String)>> = HashMap::new();

        // Collect all payload identifiers and types from all baselines
        for baseline in baselines {
            for config in &baseline.mobileconfigs {
                if let Some(ref pid) = config.payload_identifier {
                    payload_identifiers
                        .entry(pid.clone())
                        .or_default()
                        .push((baseline.name.clone(), config.filename.clone()));
                }

                if let Some(ref ptype) = config.payload_type {
                    payload_types
                        .entry(ptype.clone())
                        .or_default()
                        .push((baseline.name.clone(), config.filename.clone()));
                }
            }
        }

        // Find duplicates (potential conflicts)
        for (identifier, sources) in &payload_identifiers {
            if sources.len() > 1 {
                // Check if they're from different baselines
                let unique_baselines: HashSet<_> = sources.iter().map(|(b, _)| b).collect();
                if unique_baselines.len() > 1 {
                    conflicts.push(Conflict {
                        conflict_type: ConflictType::DuplicatePayloadIdentifier,
                        identifier: identifier.clone(),
                        affected_baselines: sources.clone(),
                        severity: ConflictSeverity::High,
                        message: format!(
                            "PayloadIdentifier '{identifier}' appears in multiple baselines"
                        ),
                    });
                }
            }
        }

        // Check for overlapping payload types
        for (ptype, sources) in &payload_types {
            if sources.len() > 1 {
                let unique_baselines: HashSet<_> = sources.iter().map(|(b, _)| b).collect();
                if unique_baselines.len() > 1 {
                    conflicts.push(Conflict {
                        conflict_type: ConflictType::OverlappingPayloadType,
                        identifier: ptype.clone(),
                        affected_baselines: sources.clone(),
                        severity: ConflictSeverity::Medium,
                        message: format!(
                            "PayloadType '{ptype}' appears in multiple baselines (may conflict)"
                        ),
                    });
                }
            }
        }

        Ok(ConflictReport {
            total_conflicts: conflicts.len(),
            conflicts,
        })
    }

    /// Detect conflicts within a single baseline
    pub fn detect_internal_conflicts(baseline: &MscpBaseline) -> Result<ConflictReport> {
        let mut conflicts = Vec::new();
        let mut seen_identifiers: HashMap<String, String> = HashMap::new();

        for config in &baseline.mobileconfigs {
            if let Some(ref pid) = config.payload_identifier {
                if let Some(existing_file) = seen_identifiers.get(pid) {
                    conflicts.push(Conflict {
                        conflict_type: ConflictType::DuplicatePayloadIdentifier,
                        identifier: pid.clone(),
                        affected_baselines: vec![
                            (baseline.name.clone(), existing_file.clone()),
                            (baseline.name.clone(), config.filename.clone()),
                        ],
                        severity: ConflictSeverity::Critical,
                        message: format!(
                            "Duplicate PayloadIdentifier '{}' within baseline '{}'",
                            pid, baseline.name
                        ),
                    });
                } else {
                    seen_identifiers.insert(pid.clone(), config.filename.clone());
                }
            }
        }

        Ok(ConflictReport {
            total_conflicts: conflicts.len(),
            conflicts,
        })
    }

    /// Generate a human-readable conflict report
    pub fn format_report(report: &ConflictReport) -> String {
        if report.conflicts.is_empty() {
            return "No conflicts detected.".to_string();
        }

        let mut output = String::new();
        output.push_str(&format!(
            "Found {} conflict(s):\n\n",
            report.total_conflicts
        ));

        for (i, conflict) in report.conflicts.iter().enumerate() {
            output.push_str(&format!(
                "{}. [{}] {}\n",
                i + 1,
                conflict.severity,
                conflict.message
            ));
            output.push_str(&format!("   Type: {:?}\n", conflict.conflict_type));
            output.push_str("   Affected files:\n");
            for (baseline, filename) in &conflict.affected_baselines {
                output.push_str(&format!("   - {filename} in baseline '{baseline}'\n"));
            }
            output.push('\n');
        }

        output.push_str(
            "\nRecommendation: Use separate team configurations for conflicting baselines.\n",
        );
        output
    }
}

/// Conflict report
#[derive(Debug, Clone)]
pub struct ConflictReport {
    pub total_conflicts: usize,
    pub conflicts: Vec<Conflict>,
}

/// Individual conflict
#[derive(Debug, Clone)]
pub struct Conflict {
    pub conflict_type: ConflictType,
    pub identifier: String,
    pub affected_baselines: Vec<(String, String)>, // (baseline_name, filename)
    pub severity: ConflictSeverity,
    pub message: String,
}

/// Type of conflict
#[derive(Debug, Clone)]
pub enum ConflictType {
    DuplicatePayloadIdentifier,
    OverlappingPayloadType,
    ContradictorySettings,
}

/// Conflict severity
#[derive(Debug, Clone)]
pub enum ConflictSeverity {
    Critical, // Same baseline, duplicate identifiers
    High,     // Different baselines, duplicate identifiers
    Medium,   // Overlapping payload types
    Low,      // Potential conflicts, needs investigation
}

impl std::fmt::Display for ConflictSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConflictSeverity::Critical => write!(f, "CRITICAL"),
            ConflictSeverity::High => write!(f, "HIGH"),
            ConflictSeverity::Medium => write!(f, "MEDIUM"),
            ConflictSeverity::Low => write!(f, "LOW"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_conflict_severity_display() {
        assert_eq!(format!("{}", ConflictSeverity::Critical), "CRITICAL");
        assert_eq!(format!("{}", ConflictSeverity::High), "HIGH");
    }
}
