use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::attribute_namespace::{
    invalid_inflight_checkpoint, resolve_exact, validate_exact_audiences, validate_namespace_uri,
    AttributeNamespaceStore, AttributeWriteAuthority, AttributeWriteResolution, AudienceBinding,
    AudienceResolution, AudienceState, BeginNamespaceChange, BeginNamespaceChangeOutcome,
    CancelledNamespaceOperation, NamespaceChangeKind, NamespaceChangeOutcome,
    NamespaceMigrationOperation, NamespaceMigrationPhase, NamespaceOperationCheckpoint,
    NamespaceRegistration, RegistrationSnapshot, RegistrationState,
};
use crate::ports::StoreError;

#[derive(Default)]
struct MemoryAttributeNamespaceState {
    registrations: BTreeMap<(String, String), NamespaceRegistration>,
    audiences: BTreeMap<(String, String), AudienceBinding>,
    cancelled_operations: BTreeMap<(String, String), CancelledNamespaceOperation>,
    used_operation_ids: BTreeSet<(String, String, String)>,
}

#[derive(Clone, Default)]
pub struct MemoryAttributeNamespaceStore {
    state: Arc<Mutex<MemoryAttributeNamespaceState>>,
}

impl AttributeNamespaceStore for MemoryAttributeNamespaceStore {
    async fn resolve(
        &self,
        tenant: &str,
        verified_aud: &str,
    ) -> Result<AudienceResolution, StoreError> {
        let state = self.state.lock().await;
        Ok(resolve_exact(
            state
                .audiences
                .get(&(tenant.to_string(), verified_aud.to_string())),
            verified_aud,
        ))
    }

    async fn resolve_write_authority(
        &self,
        tenant: &str,
        namespace: &str,
    ) -> Result<AttributeWriteResolution, StoreError> {
        let state = self.state.lock().await;
        if let Some(registration) = state
            .registrations
            .get(&(tenant.to_string(), namespace.to_string()))
        {
            return Ok(match registration.state {
                RegistrationState::Active => {
                    AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveCanonical {
                        canonical_namespace: registration.canonical_namespace.clone(),
                        registration_revision: registration.revision,
                    })
                }
                RegistrationState::Pending | RegistrationState::Retired => {
                    AttributeWriteResolution::Blocked
                }
            });
        }
        Ok(
            match state
                .audiences
                .get(&(tenant.to_string(), namespace.to_string()))
            {
                Some(binding) if binding.state == AudienceState::Active => {
                    AttributeWriteResolution::Authorized(AttributeWriteAuthority::ActiveAudience {
                        audience: namespace.to_string(),
                        canonical_namespace: binding.canonical_namespace.clone(),
                        registration_revision: binding.registration_revision,
                    })
                }
                Some(_) => AttributeWriteResolution::Blocked,
                None => AttributeWriteResolution::Authorized(AttributeWriteAuthority::Unbound {
                    namespace: namespace.to_string(),
                }),
            },
        )
    }

    async fn get(
        &self,
        tenant: &str,
        canonical_namespace: &str,
    ) -> Result<Option<NamespaceRegistration>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .registrations
            .get(&(tenant.to_string(), canonical_namespace.to_string()))
            .cloned())
    }

    async fn list(&self, tenant: &str) -> Result<Vec<NamespaceRegistration>, StoreError> {
        Ok(self
            .state
            .lock()
            .await
            .registrations
            .iter()
            .filter(|((stored_tenant, _), _)| stored_tenant == tenant)
            .map(|(_, registration)| registration.clone())
            .collect())
    }

    async fn begin_change(
        &self,
        tenant: &str,
        request: BeginNamespaceChange,
    ) -> Result<BeginNamespaceChangeOutcome, StoreError> {
        if request.operation_id.is_empty() || request.operation_id.len() > 256 {
            return Err(StoreError::Permanent(
                "namespace operation id must be 1..=256 bytes".into(),
            ));
        }
        match request.kind {
            NamespaceChangeKind::Upsert => {
                let exact: Vec<String> = request.exact_audiences.iter().cloned().collect();
                validate_exact_audiences(&request.canonical_namespace, &exact)
                    .map_err(|message| StoreError::Permanent(message.into()))?;
            }
            NamespaceChangeKind::Delete => {
                if !validate_namespace_uri(&request.canonical_namespace)
                    || !request.exact_audiences.is_empty()
                {
                    return Err(StoreError::Permanent(
                        "delete requires a valid canonical namespace and no audiences".into(),
                    ));
                }
            }
        }

        let mut state = self.state.lock().await;
        let registration_key = (tenant.to_string(), request.canonical_namespace.clone());
        let operation_key = (
            tenant.to_string(),
            request.canonical_namespace.clone(),
            request.operation_id.clone(),
        );
        let current = state.registrations.get(&registration_key).cloned();
        if let Some(registration) = &current {
            if registration.state == RegistrationState::Pending {
                let operation = registration.operation.as_ref().ok_or_else(|| {
                    StoreError::Permanent("pending registration has no operation".into())
                })?;
                if operation.operation_id == request.operation_id
                    && operation.expected_registration_revision == request.expected_revision
                    && operation.kind == request.kind
                    && operation.desired_exact_audiences == request.exact_audiences
                {
                    return Ok(BeginNamespaceChangeOutcome::Started(Box::new(
                        registration.clone(),
                    )));
                }
                return Ok(BeginNamespaceChangeOutcome::Busy {
                    operation_id: operation.operation_id.clone(),
                });
            }
        }
        if state.used_operation_ids.contains(&operation_key) {
            return Ok(BeginNamespaceChangeOutcome::Busy {
                operation_id: request.operation_id,
            });
        }
        if current
            .as_ref()
            .and_then(|registration| registration.last_operation_id.as_deref())
            == Some(request.operation_id.as_str())
            || state
                .cancelled_operations
                .get(&registration_key)
                .is_some_and(|cancelled| cancelled.operation_id == request.operation_id)
        {
            return Ok(BeginNamespaceChangeOutcome::Busy {
                operation_id: request.operation_id,
            });
        }

        let current_revision = current
            .as_ref()
            .map(|registration| registration.revision)
            .unwrap_or(0);
        if current_revision != request.expected_revision {
            return Ok(BeginNamespaceChangeOutcome::RevisionConflict {
                current: current_revision,
            });
        }
        if request.kind == NamespaceChangeKind::Delete
            && current
                .as_ref()
                .is_none_or(|registration| registration.state == RegistrationState::Retired)
        {
            return Ok(BeginNamespaceChangeOutcome::NotFound);
        }

        let mut affected = request.exact_audiences.clone();
        affected.insert(request.canonical_namespace.clone());
        if let Some(registration) = &current {
            affected.extend(registration.exact_audiences.iter().cloned());
        }
        let mut previous_bindings = BTreeMap::new();
        for audience in &affected {
            let key = (tenant.to_string(), audience.clone());
            let previous = state.audiences.get(&key).cloned();
            if let Some(binding) = &previous {
                if binding.canonical_namespace != request.canonical_namespace
                    && matches!(
                        binding.state,
                        AudienceState::Active
                            | AudienceState::Blocked
                            | AudienceState::CanonicalOnly
                    )
                {
                    return Ok(BeginNamespaceChangeOutcome::AudienceConflict {
                        audience: audience.clone(),
                        canonical_namespace: binding.canonical_namespace.clone(),
                    });
                }
                if binding.state == AudienceState::Blocked
                    && binding.operation_id.as_deref() != Some(request.operation_id.as_str())
                {
                    return Ok(BeginNamespaceChangeOutcome::Busy {
                        operation_id: binding.operation_id.clone().unwrap_or_default(),
                    });
                }
            }
            previous_bindings.insert(audience.clone(), previous);
        }

        let previous_registration = current.as_ref().map(|registration| RegistrationSnapshot {
            revision: registration.revision,
            exact_audiences: registration.exact_audiences.clone(),
            state: registration.state,
            last_operation_id: registration.last_operation_id.clone(),
        });
        let operation = NamespaceMigrationOperation {
            operation_id: request.operation_id.clone(),
            expected_registration_revision: request.expected_revision,
            revision: 1,
            kind: request.kind,
            desired_exact_audiences: request.exact_audiences.clone(),
            source_namespaces: affected.clone(),
            previous_registration,
            previous_bindings,
            phase: NamespaceMigrationPhase::Validating,
            cursor: None,
            scan_complete: false,
            started_mutation: false,
            inflight_user_id: None,
            users_scanned: 0,
            users_completed: 0,
            conflict_count: 0,
            conflict_user_ids: Vec::new(),
        };
        state.cancelled_operations.remove(&registration_key);
        state.used_operation_ids.insert(operation_key);
        for audience in affected {
            state.audiences.insert(
                (tenant.to_string(), audience.clone()),
                AudienceBinding {
                    audience,
                    canonical_namespace: request.canonical_namespace.clone(),
                    registration_revision: current_revision,
                    state: AudienceState::Blocked,
                    operation_id: Some(request.operation_id.clone()),
                },
            );
        }
        let registration = NamespaceRegistration {
            canonical_namespace: request.canonical_namespace,
            revision: current_revision,
            exact_audiences: current
                .as_ref()
                .map(|registration| registration.exact_audiences.clone())
                .unwrap_or_default(),
            state: RegistrationState::Pending,
            last_operation_id: current.and_then(|registration| registration.last_operation_id),
            operation: Some(operation),
        };
        state
            .registrations
            .insert(registration_key, registration.clone());
        Ok(BeginNamespaceChangeOutcome::Started(Box::new(registration)))
    }

    async fn checkpoint(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        checkpoint: NamespaceOperationCheckpoint,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        if checkpoint.conflict_user_ids.len() > 20 {
            return Err(StoreError::Permanent(
                "namespace conflict sample exceeds 20 users".into(),
            ));
        }
        let mut state = self.state.lock().await;
        let key = (tenant.to_string(), canonical_namespace.to_string());
        let Some(mut registration) = state.registrations.get(&key).cloned() else {
            return Ok(NamespaceChangeOutcome::NotFound);
        };
        let Some(mut operation) = registration.operation.clone() else {
            return Ok(NamespaceChangeOutcome::InvalidState);
        };
        if operation.operation_id != operation_id
            || operation.revision != checkpoint.expected_revision
        {
            return Ok(NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            });
        }
        let phase_regressed = operation.phase == NamespaceMigrationPhase::Migrating
            && checkpoint.phase == NamespaceMigrationPhase::Validating;
        let counters_regressed = checkpoint.users_scanned < operation.users_scanned
            || checkpoint.users_completed < operation.users_completed
            || checkpoint.conflict_count < operation.conflict_count;
        if phase_regressed
            || counters_regressed
            || invalid_inflight_checkpoint(&operation, &checkpoint)
            || (operation.started_mutation && !checkpoint.started_mutation)
            || (operation.phase == NamespaceMigrationPhase::Validating
                && checkpoint.phase == NamespaceMigrationPhase::Migrating
                && checkpoint.conflict_count != 0)
        {
            return Ok(NamespaceChangeOutcome::InvalidState);
        }
        operation.revision = operation.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("namespace operation revision exhausted".into())
        })?;
        operation.phase = checkpoint.phase;
        operation.cursor = checkpoint.cursor;
        operation.scan_complete = checkpoint.scan_complete;
        operation.started_mutation = checkpoint.started_mutation;
        operation.inflight_user_id = checkpoint.inflight_user_id;
        operation.users_scanned = checkpoint.users_scanned;
        operation.users_completed = checkpoint.users_completed;
        operation.conflict_count = checkpoint.conflict_count;
        operation.conflict_user_ids = checkpoint.conflict_user_ids;
        registration.operation = Some(operation);
        state.registrations.insert(key, registration.clone());
        Ok(NamespaceChangeOutcome::Updated(registration))
    }

    async fn activate(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let key = (tenant.to_string(), canonical_namespace.to_string());
        let Some(mut registration) = state.registrations.get(&key).cloned() else {
            return Ok(NamespaceChangeOutcome::NotFound);
        };
        let Some(operation) = registration.operation.clone() else {
            if registration.last_operation_id.as_deref() == Some(operation_id) {
                return Ok(NamespaceChangeOutcome::Updated(registration));
            }
            return Ok(NamespaceChangeOutcome::InvalidState);
        };
        if operation.operation_id != operation_id
            || operation.revision != expected_operation_revision
        {
            return Ok(NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            });
        }
        if operation.phase != NamespaceMigrationPhase::Migrating
            || !operation.scan_complete
            || operation.inflight_user_id.is_some()
            || operation.conflict_count != 0
        {
            return Ok(NamespaceChangeOutcome::InvalidState);
        }
        let revision = registration.revision.checked_add(1).ok_or_else(|| {
            StoreError::Permanent("namespace registration revision exhausted".into())
        })?;
        for audience in &operation.source_namespaces {
            let audience_state = match operation.kind {
                NamespaceChangeKind::Delete => AudienceState::Retired,
                NamespaceChangeKind::Upsert
                    if operation.desired_exact_audiences.contains(audience) =>
                {
                    AudienceState::Active
                }
                NamespaceChangeKind::Upsert if audience == canonical_namespace => {
                    AudienceState::CanonicalOnly
                }
                NamespaceChangeKind::Upsert => AudienceState::Retired,
            };
            state.audiences.insert(
                (tenant.to_string(), audience.clone()),
                AudienceBinding {
                    audience: audience.clone(),
                    canonical_namespace: canonical_namespace.to_string(),
                    registration_revision: revision,
                    state: audience_state,
                    operation_id: None,
                },
            );
        }
        registration.revision = revision;
        registration.last_operation_id = Some(operation.operation_id.clone());
        registration.operation = None;
        match operation.kind {
            NamespaceChangeKind::Upsert => {
                registration.exact_audiences = operation.desired_exact_audiences;
                registration.state = RegistrationState::Active;
            }
            NamespaceChangeKind::Delete => {
                registration.exact_audiences.clear();
                registration.state = RegistrationState::Retired;
            }
        }
        state.registrations.insert(key, registration.clone());
        Ok(NamespaceChangeOutcome::Updated(registration))
    }

    async fn cancel(
        &self,
        tenant: &str,
        canonical_namespace: &str,
        operation_id: &str,
        expected_operation_revision: u64,
    ) -> Result<NamespaceChangeOutcome, StoreError> {
        let mut state = self.state.lock().await;
        let key = (tenant.to_string(), canonical_namespace.to_string());
        let Some(registration) = state.registrations.get(&key).cloned() else {
            return Ok(match state.cancelled_operations.get(&key) {
                Some(cancelled)
                    if cancelled.operation_id == operation_id
                        && cancelled.operation_revision == expected_operation_revision =>
                {
                    NamespaceChangeOutcome::Cancelled(cancelled.restored_registration.clone())
                }
                _ => NamespaceChangeOutcome::NotFound,
            });
        };
        let Some(operation) = registration.operation else {
            return Ok(match state.cancelled_operations.get(&key) {
                Some(cancelled)
                    if cancelled.operation_id == operation_id
                        && cancelled.operation_revision == expected_operation_revision =>
                {
                    NamespaceChangeOutcome::Cancelled(cancelled.restored_registration.clone())
                }
                _ => NamespaceChangeOutcome::InvalidState,
            });
        };
        if operation.operation_id != operation_id
            || operation.revision != expected_operation_revision
        {
            return Ok(NamespaceChangeOutcome::OperationConflict {
                operation_id: operation.operation_id,
                revision: operation.revision,
            });
        }
        if operation.started_mutation {
            return Ok(NamespaceChangeOutcome::CannotCancel);
        }
        for (audience, previous) in operation.previous_bindings {
            let audience_key = (tenant.to_string(), audience);
            match previous {
                Some(binding) => {
                    state.audiences.insert(audience_key, binding);
                }
                None => {
                    state.audiences.remove(&audience_key);
                }
            }
        }
        let restored = operation
            .previous_registration
            .map(|snapshot| NamespaceRegistration {
                canonical_namespace: canonical_namespace.to_string(),
                revision: snapshot.revision,
                exact_audiences: snapshot.exact_audiences,
                state: snapshot.state,
                last_operation_id: snapshot.last_operation_id,
                operation: None,
            });
        match &restored {
            Some(registration) => {
                state
                    .registrations
                    .insert(key.clone(), registration.clone());
            }
            None => {
                state.registrations.remove(&key);
            }
        }
        state.cancelled_operations.insert(
            key,
            CancelledNamespaceOperation {
                canonical_namespace: canonical_namespace.to_string(),
                operation_id: operation_id.to_string(),
                operation_revision: expected_operation_revision,
                restored_registration: restored.clone(),
            },
        );
        Ok(NamespaceChangeOutcome::Cancelled(restored))
    }
}
