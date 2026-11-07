use crate::{adapters::governance_state::GovernanceState, governance::*, ports::StoreError};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Gate {
    tenant_id: String,
    frozen: bool,
    active_permits: u64,
    revision: u64,
    updated_at: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Permit {
    tenant_id: String,
    permit_id: String,
    deadline: i64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    tenant: String,
    generation: u64,
    policy: Option<GovernancePolicyRecord>,
    manifests: Vec<GovernanceExportManifest>,
    jobs: Vec<GovernanceJobRecord>,
    leases: Vec<GovernanceJobLeaseRecord>,
    gate: Option<Gate>,
    permits: Vec<Permit>,
    continuations: Vec<GovernanceContinuationRecord>,
    consumed_resume_digests: Vec<(String, String, String)>,
    evidence: Vec<GovernanceEvidenceRecord>,
    lifecycle: Option<TenantLifecycleRecord>,
    external_actions: Vec<GovernanceExternalActionRecord>,
}

fn invalid() -> StoreError {
    StoreError::Permanent("Invalid governance authority".into())
}

// Public evidence omits an optional API field. Persistence requires it even
// when null; missing data cannot silently become a defaulted outcome.
fn complete(mut value: Value) -> Value {
    if let Some(evidence) = value.get_mut("evidence").and_then(Value::as_array_mut) {
        for record in evidence {
            if let Some(actions) = record
                .get_mut("payload")
                .and_then(|p| p.get_mut("external_actions"))
                .and_then(Value::as_array_mut)
            {
                for action in actions {
                    if let Some(object) = action.as_object_mut() {
                        object.entry("outcome").or_insert(Value::Null);
                    }
                }
            }
        }
    }
    value
}

pub(super) fn encode(
    tenant: &str,
    generation: u64,
    state: &GovernanceState,
) -> Result<String, StoreError> {
    let snapshot = Snapshot {
        tenant: tenant.into(),
        generation,
        policy: state.policies.get(tenant).cloned(),
        manifests: state.manifests.values().cloned().collect(),
        jobs: state.jobs.values().cloned().collect(),
        leases: state.job_leases.values().cloned().collect(),
        gate: state.mutation_gates.get(tenant).map(|g| Gate {
            tenant_id: g.tenant_id.clone(),
            frozen: g.state == TenantMutationGateState::Frozen,
            active_permits: g.active_permits,
            revision: g.revision,
            updated_at: g.updated_at,
        }),
        permits: state
            .mutation_permits
            .values()
            .map(|p| Permit {
                tenant_id: p.tenant_id.clone(),
                permit_id: p.permit_id.clone(),
                deadline: p.deadline,
            })
            .collect(),
        continuations: state.continuations.values().cloned().collect(),
        consumed_resume_digests: state.continuation_jtis.iter().cloned().collect(),
        evidence: state.evidence.values().cloned().collect(),
        lifecycle: state.tenant_lifecycles.get(tenant).cloned(),
        external_actions: state.external_actions.values().cloned().collect(),
    };
    let value = serde_json::to_value(snapshot).map_err(|_| invalid())?;
    serde_json::to_string(&complete(value)).map_err(|_| invalid())
}

fn insert_unique<K: Ord, V>(map: &mut BTreeMap<K, V>, key: K, value: V) -> Result<(), StoreError> {
    if map.insert(key, value).is_some() {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn decode(
    tenant: &str,
    generation: u64,
    payload: &str,
) -> Result<GovernanceState, StoreError> {
    let value: Value = serde_json::from_str(payload).map_err(|_| invalid())?;
    // Parse typed authority from the original text: a Value intermediary
    // would discard duplicate object fields before serde can reject them.
    let snapshot: Snapshot = serde_json::from_str(payload).map_err(|_| invalid())?;
    if snapshot.tenant != tenant || snapshot.generation != generation {
        return Err(invalid());
    }
    let mut state = GovernanceState::default();
    if let Some(policy) = snapshot.policy {
        if policy.tenant_id != tenant {
            return Err(invalid());
        }
        state.policies.insert(tenant.into(), policy);
    }
    for record in snapshot.manifests {
        if record.tenant_id != tenant {
            return Err(invalid());
        }
        let key = (tenant.into(), record.export_id.clone());
        insert_unique(&mut state.manifests, key, record)?;
    }
    for record in snapshot.jobs {
        if record.tenant_id != tenant {
            return Err(invalid());
        }
        let key = (tenant.into(), record.job_id.clone());
        insert_unique(&mut state.jobs, key, record)?;
    }
    for record in snapshot.leases {
        if record.tenant_id != tenant
            || !state
                .jobs
                .contains_key(&(tenant.into(), record.job_id.clone()))
        {
            return Err(invalid());
        }
        let key = (tenant.into(), record.job_id.clone());
        insert_unique(&mut state.job_leases, key, record)?;
    }
    if let Some(gate) = snapshot.gate {
        if gate.tenant_id != tenant {
            return Err(invalid());
        }
        state.mutation_gates.insert(
            tenant.into(),
            TenantMutationGateRecord {
                tenant_id: gate.tenant_id,
                state: if gate.frozen {
                    TenantMutationGateState::Frozen
                } else {
                    TenantMutationGateState::Active
                },
                active_permits: gate.active_permits,
                revision: gate.revision,
                updated_at: gate.updated_at,
            },
        );
    }
    for permit in snapshot.permits {
        if permit.tenant_id != tenant {
            return Err(invalid());
        }
        let key = (tenant.into(), permit.permit_id.clone());
        insert_unique(
            &mut state.mutation_permits,
            key,
            TenantMutationPermit {
                tenant_id: permit.tenant_id,
                permit_id: permit.permit_id,
                deadline: permit.deadline,
            },
        )?;
    }
    match state.mutation_gates.get(tenant) {
        Some(gate) => {
            if gate.active_permits != state.mutation_permits.len() as u64
                || (gate.state == TenantMutationGateState::Frozen && gate.active_permits != 0)
            {
                return Err(invalid());
            }
        }
        None if !state.mutation_permits.is_empty() => return Err(invalid()),
        None => {}
    }
    for record in snapshot.continuations {
        if record.tenant_id != tenant
            || !state
                .jobs
                .contains_key(&(tenant.into(), record.job_id.clone()))
        {
            return Err(invalid());
        }
        let key = (tenant.into(), record.job_id.clone());
        insert_unique(&mut state.continuations, key, record)?;
    }
    let mut digests = BTreeSet::new();
    for key in snapshot.consumed_resume_digests {
        if key.0 != tenant
            || !state
                .continuations
                .contains_key(&(key.0.clone(), key.1.clone()))
            || key.2.is_empty()
            || !digests.insert(key)
        {
            return Err(invalid());
        }
    }
    state.continuation_jtis = digests;
    for record in snapshot.evidence {
        if record.payload.tenant_id != tenant || !record.verify_hash() {
            return Err(invalid());
        }
        let key = (
            tenant.into(),
            record.payload.job_id.clone(),
            record.payload.evidence_revision,
        );
        insert_unique(&mut state.evidence, key, record)?;
    }
    if let Some(record) = snapshot.lifecycle {
        if record.tenant_id != tenant {
            return Err(invalid());
        }
        state.tenant_lifecycles.insert(tenant.into(), record);
    }
    for record in snapshot.external_actions {
        if record.tenant_id != tenant
            || !state
                .jobs
                .contains_key(&(tenant.into(), record.job_id.clone()))
            || record.resource_fingerprint != resource_fingerprint(&record.resource_ref)
        {
            return Err(invalid());
        }
        let key = (
            tenant.into(),
            record.job_id.clone(),
            record.action_id.clone(),
        );
        insert_unique(&mut state.external_actions, key, record)?;
    }
    let round_trip: Value =
        serde_json::from_str(&encode(tenant, generation, &state)?).map_err(|_| invalid())?;
    if round_trip != value {
        return Err(invalid());
    }
    Ok(state)
}
