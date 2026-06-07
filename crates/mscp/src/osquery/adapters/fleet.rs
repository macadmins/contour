//! Fleet policy YAML adapter — reuses the existing FleetPolicy shape.
use crate::osquery::OsqueryArtifacts;
use crate::transformers::fleet_policy::FleetPolicy;

/// Map the bridge's queries to Fleet policy structs.
pub fn to_fleet_policies(art: &OsqueryArtifacts) -> Vec<FleetPolicy> {
    art.queries
        .iter()
        .map(|q| FleetPolicy {
            name: q.title.clone(),
            description: format!("mSCP {}", q.rule_id),
            query: q.sql.clone(),
            platform: "darwin".to_string(),
            critical: false,
            calendar_events_enabled: false,
        })
        .collect()
}
