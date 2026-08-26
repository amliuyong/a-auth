//! Per-tenant EC/RSA signing-key lifecycle.
//!
//! The served snapshot is the only data-plane authority. It is replaced as one
//! revision containing both algorithms, so a request can never observe a new EC
//! generation with an old RSA generation. Provisioning failures retain their
//! partially-created key ARNs for compensation but never create a served
//! snapshot for a tenant that has not completed both local signature probes.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyLifecycle {
    Provisioning,
    Publishing,
    ActiveOverlap,
    RollbackOverlap,
    Ready,
    Failed,
    Offboarding,
    Offboarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyOperationKind {
    Onboard,
    Rotate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyCompletionOutcome {
    Onboarded,
    RolledBack,
    RetiredForward,
    RetiredRollback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TenantKeyAlgorithm {
    Es256,
    Rs256,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EcPublicJwk {
    pub x: String,
    pub y: String,
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RsaPublicJwk {
    pub n: String,
    pub e: String,
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyMaterial<J> {
    pub key_arn: String,
    pub generation: u64,
    pub public_jwk: J,
    pub created_at: i64,
    pub verified_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlgorithmSnapshot<J> {
    pub active: KeyMaterial<J>,
    pub published: Vec<KeyMaterial<J>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeySnapshot {
    pub generation: u64,
    pub ec: AlgorithmSnapshot<EcPublicJwk>,
    pub rsa: AlgorithmSnapshot<RsaPublicJwk>,
    pub committed_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateKey<J> {
    pub key_arn: String,
    pub created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_jwk: Option<J>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replica_readiness_started_at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateGeneration {
    pub generation: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ec: Option<CandidateKey<EcPublicJwk>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rsa: Option<CandidateKey<RsaPublicJwk>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyOperation {
    pub operation_id: String,
    pub kind: TenantKeyOperationKind,
    pub candidate: CandidateGeneration,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_snapshot: Option<TenantKeySnapshot>,
    pub started_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retire_after: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyFailure {
    pub operation_id: String,
    pub kind: TenantKeyOperationKind,
    pub candidate: CandidateGeneration,
    pub error_class: String,
    pub failed_at: i64,
    pub cleanup_pending: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cleanup_arns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantKeyRecord {
    pub tenant_id: String,
    pub revision: u64,
    pub lifecycle: TenantKeyLifecycle,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub served_snapshot: Option<TenantKeySnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<TenantKeyOperation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<TenantKeyFailure>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_completed_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_completed_outcome: Option<TenantKeyCompletionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_emergency_revoke_operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pending_deletion_arns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scheduled_deletion_arns: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offboarding_operation_id: Option<String>,
    pub updated_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TenantKeyStateError {
    InvalidTenant,
    InvalidOperationId,
    InvalidState,
    OperationMismatch,
    AlgorithmAlreadyCreated,
    AlgorithmNotCreated,
    AlgorithmAlreadyVerified,
    EmptyKeyArn,
    InvalidJwk,
    IncompleteGeneration,
    InvalidSnapshot,
    OverlapNotElapsed,
}

fn valid_identifier(value: &str, max_len: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

impl EcPublicJwk {
    fn is_valid(&self) -> bool {
        !self.x.is_empty()
            && !self.y.is_empty()
            && valid_identifier(&self.kid, 128)
            && !self.x.chars().any(char::is_whitespace)
            && !self.y.chars().any(char::is_whitespace)
    }
}

impl RsaPublicJwk {
    fn is_valid(&self) -> bool {
        !self.n.is_empty()
            && !self.e.is_empty()
            && valid_identifier(&self.kid, 128)
            && !self.n.chars().any(char::is_whitespace)
            && !self.e.chars().any(char::is_whitespace)
    }
}

impl TenantKeySnapshot {
    pub fn validate(&self) -> Result<(), TenantKeyStateError> {
        if self.generation == 0
            || self.ec.active.generation != self.generation
            || self.rsa.active.generation != self.generation
            || self.ec.published.is_empty()
            || self.rsa.published.is_empty()
            || !self.ec.active.public_jwk.is_valid()
            || !self.rsa.active.public_jwk.is_valid()
            || !self
                .ec
                .published
                .iter()
                .any(|key| key.key_arn == self.ec.active.key_arn)
            || !self
                .rsa
                .published
                .iter()
                .any(|key| key.key_arn == self.rsa.active.key_arn)
        {
            return Err(TenantKeyStateError::InvalidSnapshot);
        }
        let ec_kids: HashSet<&str> = self
            .ec
            .published
            .iter()
            .map(|key| key.public_jwk.kid.as_str())
            .collect();
        let rsa_kids: HashSet<&str> = self
            .rsa
            .published
            .iter()
            .map(|key| key.public_jwk.kid.as_str())
            .collect();
        let all_kids: HashSet<&str> = self
            .ec
            .published
            .iter()
            .map(|key| key.public_jwk.kid.as_str())
            .chain(
                self.rsa
                    .published
                    .iter()
                    .map(|key| key.public_jwk.kid.as_str()),
            )
            .collect();
        let all_arns: HashSet<&str> = self
            .ec
            .published
            .iter()
            .map(|key| key.key_arn.as_str())
            .chain(self.rsa.published.iter().map(|key| key.key_arn.as_str()))
            .collect();
        let ec_generations: HashSet<u64> =
            self.ec.published.iter().map(|key| key.generation).collect();
        let rsa_generations: HashSet<u64> = self
            .rsa
            .published
            .iter()
            .map(|key| key.generation)
            .collect();
        if ec_kids.len() != self.ec.published.len()
            || rsa_kids.len() != self.rsa.published.len()
            || all_kids.len() != self.ec.published.len() + self.rsa.published.len()
            || all_arns.len() != self.ec.published.len() + self.rsa.published.len()
            || ec_generations != rsa_generations
            || self
                .ec
                .published
                .iter()
                .any(|key| key.key_arn.is_empty() || !key.public_jwk.is_valid())
            || self
                .rsa
                .published
                .iter()
                .any(|key| key.key_arn.is_empty() || !key.public_jwk.is_valid())
        {
            return Err(TenantKeyStateError::InvalidSnapshot);
        }
        Ok(())
    }
}

impl TenantKeyRecord {
    pub fn begin_onboarding(
        tenant_id: impl Into<String>,
        operation_id: impl Into<String>,
        now: i64,
    ) -> Result<Self, TenantKeyStateError> {
        let tenant_id = tenant_id.into();
        let operation_id = operation_id.into();
        if !valid_identifier(&tenant_id, 63) {
            return Err(TenantKeyStateError::InvalidTenant);
        }
        if !valid_identifier(&operation_id, 128) {
            return Err(TenantKeyStateError::InvalidOperationId);
        }
        Ok(Self {
            tenant_id,
            revision: 1,
            lifecycle: TenantKeyLifecycle::Provisioning,
            served_snapshot: None,
            operation: Some(TenantKeyOperation {
                operation_id,
                kind: TenantKeyOperationKind::Onboard,
                candidate: CandidateGeneration {
                    generation: 1,
                    ec: None,
                    rsa: None,
                },
                previous_snapshot: None,
                started_at: now,
                retire_after: None,
            }),
            last_failure: None,
            last_completed_operation_id: None,
            last_completed_outcome: None,
            last_emergency_revoke_operation_id: None,
            pending_deletion_arns: Vec::new(),
            scheduled_deletion_arns: Vec::new(),
            offboarding_operation_id: None,
            updated_at: now,
        })
    }

    /// Irreversibly remove this tenant's signing authority before any KMS
    /// deletion is attempted. Every known key moves to the durable deletion
    /// inventory so a crash cannot restore signing or lose cleanup work.
    pub fn begin_offboarding(
        &mut self,
        operation_id: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation_id = operation_id.into();
        if !valid_identifier(&operation_id, 128) {
            return Err(TenantKeyStateError::InvalidOperationId);
        }
        if matches!(
            self.lifecycle,
            TenantKeyLifecycle::Offboarding | TenantKeyLifecycle::Offboarded
        ) {
            return if self.offboarding_operation_id.as_deref() == Some(&operation_id) {
                Ok(())
            } else {
                Err(TenantKeyStateError::OperationMismatch)
            };
        }

        let mut known_arns = self.known_key_arns();
        known_arns.retain(|key_arn| !self.scheduled_deletion_arns.contains(key_arn));
        self.pending_deletion_arns.extend(known_arns);
        self.pending_deletion_arns.sort();
        self.pending_deletion_arns.dedup();
        self.served_snapshot = None;
        self.operation = None;
        self.last_failure = None;
        self.lifecycle = TenantKeyLifecycle::Offboarding;
        self.offboarding_operation_id = Some(operation_id);
        self.bump(now);
        Ok(())
    }

    pub fn finish_offboarding(
        &mut self,
        operation_id: &str,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        if self.lifecycle == TenantKeyLifecycle::Offboarded
            && self.offboarding_operation_id.as_deref() == Some(operation_id)
        {
            return Ok(());
        }
        if self.lifecycle != TenantKeyLifecycle::Offboarding
            || self.offboarding_operation_id.as_deref() != Some(operation_id)
            || !self.pending_deletion_arns.is_empty()
        {
            return Err(TenantKeyStateError::InvalidState);
        }
        self.lifecycle = TenantKeyLifecycle::Offboarded;
        self.bump(now);
        Ok(())
    }

    pub fn begin_rotation(
        &mut self,
        operation_id: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation_id = operation_id.into();
        if !valid_identifier(&operation_id, 128) {
            return Err(TenantKeyStateError::InvalidOperationId);
        }
        if self.lifecycle != TenantKeyLifecycle::Ready
            || self.operation.is_some()
            || !self.pending_deletion_arns.is_empty()
            || self
                .last_failure
                .as_ref()
                .is_some_and(|failure| failure.cleanup_pending)
        {
            return Err(TenantKeyStateError::InvalidState);
        }
        let previous = self
            .served_snapshot
            .clone()
            .ok_or(TenantKeyStateError::InvalidState)?;
        previous.validate()?;
        self.last_emergency_revoke_operation_id = None;
        self.lifecycle = TenantKeyLifecycle::Provisioning;
        self.operation = Some(TenantKeyOperation {
            operation_id,
            kind: TenantKeyOperationKind::Rotate,
            candidate: CandidateGeneration {
                generation: previous.generation + 1,
                ec: None,
                rsa: None,
            },
            previous_snapshot: Some(previous),
            started_at: now,
            retire_after: None,
        });
        self.bump(now);
        Ok(())
    }

    pub fn retry_onboarding(
        &mut self,
        operation_id: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation_id = operation_id.into();
        if !valid_identifier(&operation_id, 128) {
            return Err(TenantKeyStateError::InvalidOperationId);
        }
        if self.lifecycle != TenantKeyLifecycle::Failed
            || self.served_snapshot.is_some()
            || self.operation.is_some()
            || self
                .last_failure
                .as_ref()
                .is_some_and(|failure| failure.cleanup_pending)
        {
            return Err(TenantKeyStateError::InvalidState);
        }
        self.lifecycle = TenantKeyLifecycle::Provisioning;
        self.operation = Some(TenantKeyOperation {
            operation_id,
            kind: TenantKeyOperationKind::Onboard,
            candidate: CandidateGeneration {
                generation: 1,
                ec: None,
                rsa: None,
            },
            previous_snapshot: None,
            started_at: now,
            retire_after: None,
        });
        self.bump(now);
        Ok(())
    }

    pub fn record_created_key(
        &mut self,
        operation_id: &str,
        algorithm: TenantKeyAlgorithm,
        key_arn: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let key_arn = key_arn.into();
        if key_arn.is_empty() {
            return Err(TenantKeyStateError::EmptyKeyArn);
        }
        let operation = self.operation_mut(operation_id)?;
        match algorithm {
            TenantKeyAlgorithm::Es256 if operation.candidate.ec.is_none() => {
                operation.candidate.ec = Some(CandidateKey {
                    key_arn,
                    created_at: now,
                    public_jwk: None,
                    verified_at: None,
                    replica_readiness_started_at: None,
                });
            }
            TenantKeyAlgorithm::Rs256 if operation.candidate.rsa.is_none() => {
                operation.candidate.rsa = Some(CandidateKey {
                    key_arn,
                    created_at: now,
                    public_jwk: None,
                    verified_at: None,
                    replica_readiness_started_at: None,
                });
            }
            _ => return Err(TenantKeyStateError::AlgorithmAlreadyCreated),
        }
        self.bump(now);
        Ok(())
    }

    pub fn record_replica_readiness_started(
        &mut self,
        operation_id: &str,
        algorithm: TenantKeyAlgorithm,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation = self.operation_mut(operation_id)?;
        let readiness_started_at = match algorithm {
            TenantKeyAlgorithm::Es256 => {
                let key = operation
                    .candidate
                    .ec
                    .as_mut()
                    .ok_or(TenantKeyStateError::AlgorithmNotCreated)?;
                &mut key.replica_readiness_started_at
            }
            TenantKeyAlgorithm::Rs256 => {
                let key = operation
                    .candidate
                    .rsa
                    .as_mut()
                    .ok_or(TenantKeyStateError::AlgorithmNotCreated)?;
                &mut key.replica_readiness_started_at
            }
        };
        if readiness_started_at.is_some() {
            return Err(TenantKeyStateError::InvalidState);
        }
        *readiness_started_at = Some(now);
        self.bump(now);
        Ok(())
    }

    pub fn record_verified_ec(
        &mut self,
        operation_id: &str,
        jwk: EcPublicJwk,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        if !jwk.is_valid() {
            return Err(TenantKeyStateError::InvalidJwk);
        }
        let operation = self.operation_mut(operation_id)?;
        let key = operation
            .candidate
            .ec
            .as_mut()
            .ok_or(TenantKeyStateError::AlgorithmNotCreated)?;
        if key.verified_at.is_some() {
            return Err(TenantKeyStateError::AlgorithmAlreadyVerified);
        }
        key.public_jwk = Some(jwk);
        key.verified_at = Some(now);
        self.bump(now);
        Ok(())
    }

    pub fn record_verified_rsa(
        &mut self,
        operation_id: &str,
        jwk: RsaPublicJwk,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        if !jwk.is_valid() {
            return Err(TenantKeyStateError::InvalidJwk);
        }
        let operation = self.operation_mut(operation_id)?;
        let key = operation
            .candidate
            .rsa
            .as_mut()
            .ok_or(TenantKeyStateError::AlgorithmNotCreated)?;
        if key.verified_at.is_some() {
            return Err(TenantKeyStateError::AlgorithmAlreadyVerified);
        }
        key.public_jwk = Some(jwk);
        key.verified_at = Some(now);
        self.bump(now);
        Ok(())
    }

    /// Commit a fully probed pair. On first onboarding this is the first instant
    /// the tenant becomes ready. During rotation this is publish-ahead: old keys
    /// remain active while both generations are published.
    pub fn publish_candidate(
        &mut self,
        operation_id: &str,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation = self.operation(operation_id)?.clone();
        let candidate = complete_generation(&operation.candidate, now)?;
        match operation.kind {
            TenantKeyOperationKind::Onboard => {
                self.served_snapshot = Some(candidate);
                self.lifecycle = TenantKeyLifecycle::Ready;
                self.operation = None;
                self.last_completed_operation_id = Some(operation.operation_id);
                self.last_completed_outcome = Some(TenantKeyCompletionOutcome::Onboarded);
            }
            TenantKeyOperationKind::Rotate => {
                let previous = operation
                    .previous_snapshot
                    .ok_or(TenantKeyStateError::InvalidState)?;
                let snapshot = overlap_snapshot(&previous, &candidate, false, now)?;
                self.served_snapshot = Some(snapshot);
                self.lifecycle = TenantKeyLifecycle::Publishing;
            }
        }
        self.last_failure = None;
        self.bump(now);
        Ok(())
    }

    pub fn activate_candidate(
        &mut self,
        operation_id: &str,
        now: i64,
        retire_after: i64,
    ) -> Result<(), TenantKeyStateError> {
        if self.lifecycle != TenantKeyLifecycle::Publishing || retire_after <= now {
            return Err(TenantKeyStateError::InvalidState);
        }
        let operation = self.operation(operation_id)?.clone();
        if operation.kind != TenantKeyOperationKind::Rotate {
            return Err(TenantKeyStateError::InvalidState);
        }
        let previous = operation
            .previous_snapshot
            .clone()
            .ok_or(TenantKeyStateError::InvalidState)?;
        let candidate = complete_generation(&operation.candidate, now)?;
        self.served_snapshot = Some(overlap_snapshot(&previous, &candidate, true, now)?);
        self.lifecycle = TenantKeyLifecycle::ActiveOverlap;
        self.operation
            .as_mut()
            .expect("operation checked")
            .retire_after = Some(retire_after);
        self.bump(now);
        Ok(())
    }

    pub fn rollback(
        &mut self,
        operation_id: &str,
        now: i64,
        retire_after: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation = self.operation(operation_id)?.clone();
        let previous = operation
            .previous_snapshot
            .clone()
            .ok_or(TenantKeyStateError::InvalidState)?;
        match self.lifecycle {
            TenantKeyLifecycle::Publishing => {
                self.pending_deletion_arns = candidate_key_arns(&operation.candidate)?;
                self.served_snapshot = Some(previous);
                self.lifecycle = TenantKeyLifecycle::Ready;
                self.operation = None;
                self.last_completed_operation_id = Some(operation.operation_id);
                self.last_completed_outcome = Some(TenantKeyCompletionOutcome::RolledBack);
            }
            TenantKeyLifecycle::ActiveOverlap if retire_after > now => {
                let candidate = complete_generation(&operation.candidate, now)?;
                self.served_snapshot = Some(overlap_snapshot(&previous, &candidate, false, now)?);
                self.lifecycle = TenantKeyLifecycle::RollbackOverlap;
                self.operation
                    .as_mut()
                    .expect("operation checked")
                    .retire_after = Some(retire_after);
            }
            _ => return Err(TenantKeyStateError::InvalidState),
        }
        self.bump(now);
        Ok(())
    }

    pub fn retire(&mut self, operation_id: &str, now: i64) -> Result<(), TenantKeyStateError> {
        let operation = self.operation(operation_id)?.clone();
        if operation.retire_after.is_none_or(|deadline| now < deadline) {
            return Err(TenantKeyStateError::OverlapNotElapsed);
        }
        let completion = match self.lifecycle {
            TenantKeyLifecycle::ActiveOverlap => {
                let previous = operation
                    .previous_snapshot
                    .as_ref()
                    .ok_or(TenantKeyStateError::InvalidState)?;
                self.pending_deletion_arns = vec![
                    previous.ec.active.key_arn.clone(),
                    previous.rsa.active.key_arn.clone(),
                ];
                self.served_snapshot = Some(complete_generation(&operation.candidate, now)?);
                TenantKeyCompletionOutcome::RetiredForward
            }
            TenantKeyLifecycle::RollbackOverlap => {
                self.pending_deletion_arns = candidate_key_arns(&operation.candidate)?;
                self.served_snapshot = operation.previous_snapshot;
                TenantKeyCompletionOutcome::RetiredRollback
            }
            _ => return Err(TenantKeyStateError::InvalidState),
        };
        self.lifecycle = TenantKeyLifecycle::Ready;
        self.operation = None;
        self.last_completed_operation_id = Some(operation.operation_id);
        self.last_completed_outcome = Some(completion);
        self.bump(now);
        Ok(())
    }

    /// Commit the fully probed candidate immediately and remove every prior
    /// published key without waiting for either graceful overlap window.
    pub fn emergency_revoke(
        &mut self,
        operation_id: &str,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        if !matches!(
            self.lifecycle,
            TenantKeyLifecycle::Publishing | TenantKeyLifecycle::ActiveOverlap
        ) {
            return Err(TenantKeyStateError::InvalidState);
        }
        let operation = self.operation(operation_id)?.clone();
        if operation.kind != TenantKeyOperationKind::Rotate {
            return Err(TenantKeyStateError::InvalidState);
        }
        let previous = operation
            .previous_snapshot
            .as_ref()
            .ok_or(TenantKeyStateError::InvalidState)?;
        self.pending_deletion_arns = snapshot_key_arns(previous);
        self.served_snapshot = Some(complete_generation(&operation.candidate, now)?);
        self.lifecycle = TenantKeyLifecycle::Ready;
        self.operation = None;
        self.last_completed_operation_id = Some(operation.operation_id.clone());
        self.last_completed_outcome = None;
        self.last_emergency_revoke_operation_id = Some(operation.operation_id);
        self.bump(now);
        Ok(())
    }

    /// Fail an operation without ever serving a partial pair. A failed rotation
    /// restores the prior ready snapshot; a failed first onboarding stays
    /// unavailable. Created ARNs remain in `last_failure` until compensation.
    pub fn fail_operation(
        &mut self,
        operation_id: &str,
        error_class: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        self.fail_operation_with_cleanup(operation_id, error_class, Vec::new(), now)
    }

    pub fn fail_operation_with_cleanup(
        &mut self,
        operation_id: &str,
        error_class: impl Into<String>,
        mut cleanup_arns: Vec<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let operation = self.operation(operation_id)?.clone();
        cleanup_arns.extend(
            [
                operation
                    .candidate
                    .ec
                    .as_ref()
                    .map(|key| key.key_arn.clone()),
                operation
                    .candidate
                    .rsa
                    .as_ref()
                    .map(|key| key.key_arn.clone()),
            ]
            .into_iter()
            .flatten(),
        );
        if cleanup_arns.iter().any(|key_arn| key_arn.is_empty()) {
            return Err(TenantKeyStateError::EmptyKeyArn);
        }
        cleanup_arns.sort();
        cleanup_arns.dedup();
        let cleanup_pending = !cleanup_arns.is_empty();
        self.last_failure = Some(TenantKeyFailure {
            operation_id: operation.operation_id.clone(),
            kind: operation.kind,
            candidate: operation.candidate.clone(),
            error_class: error_class.into(),
            failed_at: now,
            cleanup_pending,
            cleanup_arns,
        });
        match operation.previous_snapshot {
            Some(snapshot) => {
                self.served_snapshot = Some(snapshot);
                self.lifecycle = TenantKeyLifecycle::Ready;
            }
            None => {
                self.served_snapshot = None;
                self.lifecycle = TenantKeyLifecycle::Failed;
            }
        }
        self.operation = None;
        self.bump(now);
        Ok(())
    }

    pub fn references_key_arn(&self, key_arn: &str) -> bool {
        self.served_snapshot
            .as_ref()
            .is_some_and(|snapshot| snapshot_contains_key_arn(snapshot, key_arn))
            || self
                .operation
                .as_ref()
                .is_some_and(|operation| candidate_contains_key_arn(&operation.candidate, key_arn))
            || self.last_failure.as_ref().is_some_and(|failure| {
                candidate_contains_key_arn(&failure.candidate, key_arn)
                    || failure
                        .cleanup_arns
                        .iter()
                        .any(|cleanup_arn| cleanup_arn == key_arn)
            })
    }

    pub fn tracks_key_arn(&self, key_arn: &str) -> bool {
        self.references_key_arn(key_arn)
            || self
                .pending_deletion_arns
                .iter()
                .any(|pending| pending == key_arn)
            || self
                .scheduled_deletion_arns
                .iter()
                .any(|scheduled| scheduled == key_arn)
    }

    pub fn track_pending_deletion(
        &mut self,
        key_arn: impl Into<String>,
        now: i64,
    ) -> Result<(), TenantKeyStateError> {
        let key_arn = key_arn.into();
        if key_arn.is_empty() {
            return Err(TenantKeyStateError::EmptyKeyArn);
        }
        if self.references_key_arn(&key_arn) {
            return Err(TenantKeyStateError::InvalidState);
        }
        if self.pending_deletion_arns.contains(&key_arn)
            || self.scheduled_deletion_arns.contains(&key_arn)
        {
            return Ok(());
        }
        self.pending_deletion_arns.push(key_arn);
        self.bump(now);
        Ok(())
    }

    pub fn mark_cleanup_complete(&mut self, now: i64) -> Result<(), TenantKeyStateError> {
        let failure = self
            .last_failure
            .as_mut()
            .ok_or(TenantKeyStateError::InvalidState)?;
        failure.cleanup_pending = false;
        self.bump(now);
        Ok(())
    }

    pub fn mark_pending_deletions_complete(&mut self, now: i64) -> Result<(), TenantKeyStateError> {
        if self.pending_deletion_arns.is_empty() {
            return Err(TenantKeyStateError::InvalidState);
        }
        for key_arn in self.pending_deletion_arns.drain(..) {
            if !self.scheduled_deletion_arns.contains(&key_arn) {
                self.scheduled_deletion_arns.push(key_arn);
            }
        }
        self.bump(now);
        Ok(())
    }

    pub fn ready_snapshot(&self) -> Result<&TenantKeySnapshot, TenantKeyStateError> {
        if matches!(
            self.lifecycle,
            TenantKeyLifecycle::Offboarding | TenantKeyLifecycle::Offboarded
        ) {
            return Err(TenantKeyStateError::InvalidState);
        }
        let snapshot = self
            .served_snapshot
            .as_ref()
            .ok_or(TenantKeyStateError::InvalidState)?;
        snapshot.validate()?;
        Ok(snapshot)
    }

    fn operation(&self, operation_id: &str) -> Result<&TenantKeyOperation, TenantKeyStateError> {
        let operation = self
            .operation
            .as_ref()
            .ok_or(TenantKeyStateError::InvalidState)?;
        if operation.operation_id != operation_id {
            return Err(TenantKeyStateError::OperationMismatch);
        }
        Ok(operation)
    }

    fn operation_mut(
        &mut self,
        operation_id: &str,
    ) -> Result<&mut TenantKeyOperation, TenantKeyStateError> {
        let operation = self
            .operation
            .as_mut()
            .ok_or(TenantKeyStateError::InvalidState)?;
        if operation.operation_id != operation_id {
            return Err(TenantKeyStateError::OperationMismatch);
        }
        Ok(operation)
    }

    fn bump(&mut self, now: i64) {
        self.revision += 1;
        self.updated_at = now;
    }

    fn known_key_arns(&self) -> Vec<String> {
        let mut key_arns = Vec::new();
        if let Some(snapshot) = &self.served_snapshot {
            key_arns.extend(snapshot_key_arns(snapshot));
        }
        if let Some(operation) = &self.operation {
            key_arns.extend(candidate_present_key_arns(&operation.candidate));
            if let Some(snapshot) = &operation.previous_snapshot {
                key_arns.extend(snapshot_key_arns(snapshot));
            }
        }
        if let Some(failure) = &self.last_failure {
            key_arns.extend(candidate_present_key_arns(&failure.candidate));
            key_arns.extend(failure.cleanup_arns.iter().cloned());
        }
        key_arns.extend(self.pending_deletion_arns.iter().cloned());
        key_arns.sort();
        key_arns.dedup();
        key_arns
    }
}

fn candidate_present_key_arns(candidate: &CandidateGeneration) -> Vec<String> {
    [
        candidate.ec.as_ref().map(|key| key.key_arn.clone()),
        candidate.rsa.as_ref().map(|key| key.key_arn.clone()),
    ]
    .into_iter()
    .flatten()
    .collect()
}

fn snapshot_key_arns(snapshot: &TenantKeySnapshot) -> Vec<String> {
    snapshot
        .ec
        .published
        .iter()
        .map(|key| key.key_arn.clone())
        .chain(snapshot.rsa.published.iter().map(|key| key.key_arn.clone()))
        .collect()
}

fn candidate_key_arns(candidate: &CandidateGeneration) -> Result<Vec<String>, TenantKeyStateError> {
    Ok(vec![
        candidate
            .ec
            .as_ref()
            .ok_or(TenantKeyStateError::IncompleteGeneration)?
            .key_arn
            .clone(),
        candidate
            .rsa
            .as_ref()
            .ok_or(TenantKeyStateError::IncompleteGeneration)?
            .key_arn
            .clone(),
    ])
}

fn candidate_contains_key_arn(candidate: &CandidateGeneration, key_arn: &str) -> bool {
    candidate
        .ec
        .as_ref()
        .is_some_and(|key| key.key_arn == key_arn)
        || candidate
            .rsa
            .as_ref()
            .is_some_and(|key| key.key_arn == key_arn)
}

fn snapshot_contains_key_arn(snapshot: &TenantKeySnapshot, key_arn: &str) -> bool {
    snapshot
        .ec
        .published
        .iter()
        .any(|key| key.key_arn == key_arn)
        || snapshot
            .rsa
            .published
            .iter()
            .any(|key| key.key_arn == key_arn)
}

fn complete_generation(
    candidate: &CandidateGeneration,
    now: i64,
) -> Result<TenantKeySnapshot, TenantKeyStateError> {
    let ec = candidate
        .ec
        .as_ref()
        .and_then(|key| {
            Some(KeyMaterial {
                key_arn: key.key_arn.clone(),
                generation: candidate.generation,
                public_jwk: key.public_jwk.clone()?,
                created_at: key.created_at,
                verified_at: key.verified_at?,
            })
        })
        .ok_or(TenantKeyStateError::IncompleteGeneration)?;
    let rsa = candidate
        .rsa
        .as_ref()
        .and_then(|key| {
            Some(KeyMaterial {
                key_arn: key.key_arn.clone(),
                generation: candidate.generation,
                public_jwk: key.public_jwk.clone()?,
                created_at: key.created_at,
                verified_at: key.verified_at?,
            })
        })
        .ok_or(TenantKeyStateError::IncompleteGeneration)?;
    let snapshot = TenantKeySnapshot {
        generation: candidate.generation,
        ec: AlgorithmSnapshot {
            active: ec.clone(),
            published: vec![ec],
        },
        rsa: AlgorithmSnapshot {
            active: rsa.clone(),
            published: vec![rsa],
        },
        committed_at: now,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

fn overlap_snapshot(
    previous: &TenantKeySnapshot,
    candidate: &TenantKeySnapshot,
    candidate_active: bool,
    now: i64,
) -> Result<TenantKeySnapshot, TenantKeyStateError> {
    previous.validate()?;
    candidate.validate()?;
    if candidate.generation <= previous.generation {
        return Err(TenantKeyStateError::InvalidSnapshot);
    }
    let mut ec_published = previous.ec.published.clone();
    for key in &candidate.ec.published {
        if !ec_published
            .iter()
            .any(|published| published.public_jwk.kid == key.public_jwk.kid)
        {
            ec_published.push(key.clone());
        }
    }
    let mut rsa_published = previous.rsa.published.clone();
    for key in &candidate.rsa.published {
        if !rsa_published
            .iter()
            .any(|published| published.public_jwk.kid == key.public_jwk.kid)
        {
            rsa_published.push(key.clone());
        }
    }
    let snapshot = TenantKeySnapshot {
        generation: if candidate_active {
            candidate.generation
        } else {
            previous.generation
        },
        ec: AlgorithmSnapshot {
            active: if candidate_active {
                candidate.ec.active.clone()
            } else {
                previous.ec.active.clone()
            },
            published: ec_published,
        },
        rsa: AlgorithmSnapshot {
            active: if candidate_active {
                candidate.rsa.active.clone()
            } else {
                previous.rsa.active.clone()
            },
            published: rsa_published,
        },
        committed_at: now,
    };
    snapshot.validate()?;
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ec(kid: &str) -> EcPublicJwk {
        EcPublicJwk {
            x: format!("x-{kid}"),
            y: format!("y-{kid}"),
            kid: kid.to_string(),
        }
    }

    fn rsa(kid: &str) -> RsaPublicJwk {
        RsaPublicJwk {
            n: format!("n-{kid}"),
            e: "AQAB".to_string(),
            kid: kid.to_string(),
        }
    }

    fn complete_candidate(record: &mut TenantKeyRecord, operation: &str, suffix: &str, now: i64) {
        record
            .record_created_key(
                operation,
                TenantKeyAlgorithm::Es256,
                format!("arn:ec:{suffix}"),
                now,
            )
            .unwrap();
        record
            .record_verified_ec(operation, ec(&format!("ec-{suffix}")), now + 1)
            .unwrap();
        record
            .record_created_key(
                operation,
                TenantKeyAlgorithm::Rs256,
                format!("arn:rsa:{suffix}"),
                now + 2,
            )
            .unwrap();
        record
            .record_verified_rsa(operation, rsa(&format!("rsa-{suffix}")), now + 3)
            .unwrap();
    }

    #[test]
    fn onboarding_is_not_ready_until_both_probes_commit() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        assert!(record.ready_snapshot().is_err());
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:ec:1", 101)
            .unwrap();
        record.record_verified_ec("op-1", ec("ec-1"), 102).unwrap();
        assert_eq!(
            record.publish_candidate("op-1", 103),
            Err(TenantKeyStateError::IncompleteGeneration)
        );
        assert!(record.ready_snapshot().is_err());
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Rs256, "arn:rsa:1", 104)
            .unwrap();
        record
            .record_verified_rsa("op-1", rsa("rsa-1"), 105)
            .unwrap();
        record.publish_candidate("op-1", 106).unwrap();
        let snapshot = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(
            record.last_completed_outcome,
            Some(TenantKeyCompletionOutcome::Onboarded)
        );
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.ec.active.public_jwk.kid, "ec-1");
        assert_eq!(snapshot.rsa.active.public_jwk.kid, "rsa-1");
    }

    #[test]
    fn records_from_before_replica_deadlines_and_completion_outcomes_still_decode() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:ec:1", 101)
            .unwrap();
        let mut encoded = serde_json::to_value(record).unwrap();
        let object = encoded.as_object_mut().unwrap();
        object.remove("last_completed_outcome");
        object["operation"]["candidate"]["ec"]
            .as_object_mut()
            .unwrap()
            .remove("replica_readiness_started_at");

        let decoded: TenantKeyRecord = serde_json::from_value(encoded).unwrap();
        assert_eq!(decoded.last_completed_outcome, None);
        assert_eq!(
            decoded
                .operation
                .unwrap()
                .candidate
                .ec
                .unwrap()
                .replica_readiness_started_at,
            None
        );
    }

    #[test]
    fn failed_onboarding_retains_created_arns_but_never_serves() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:ec:1", 101)
            .unwrap();
        record
            .fail_operation("op-1", "rsa_create_failed", 102)
            .unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Failed);
        assert!(record.ready_snapshot().is_err());
        let failure = record.last_failure.unwrap();
        assert!(failure.cleanup_pending);
        assert_eq!(failure.candidate.ec.unwrap().key_arn, "arn:ec:1");
    }

    #[test]
    fn failed_onboarding_retries_only_after_compensation() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        record
            .record_created_key("op-1", TenantKeyAlgorithm::Es256, "arn:ec:1", 101)
            .unwrap();
        record
            .fail_operation("op-1", "rsa_create_failed", 102)
            .unwrap();
        assert_eq!(
            record.retry_onboarding("op-2", 103),
            Err(TenantKeyStateError::InvalidState)
        );
        record.mark_cleanup_complete(104).unwrap();
        record.retry_onboarding("op-2", 105).unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Provisioning);
        assert_eq!(record.operation.as_ref().unwrap().operation_id, "op-2");
        assert!(record.ready_snapshot().is_err());
    }

    #[test]
    fn snapshot_rejects_cross_algorithm_kid_or_generation_mismatch() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 106).unwrap();
        let mut duplicate_kid = record.ready_snapshot().unwrap().clone();
        duplicate_kid.rsa.active.public_jwk.kid = duplicate_kid.ec.active.public_jwk.kid.clone();
        duplicate_kid.rsa.published[0].public_jwk.kid =
            duplicate_kid.ec.active.public_jwk.kid.clone();
        assert_eq!(
            duplicate_kid.validate(),
            Err(TenantKeyStateError::InvalidSnapshot)
        );

        let mut mismatched_generation = record.ready_snapshot().unwrap().clone();
        mismatched_generation.rsa.published[0].generation = 2;
        assert_eq!(
            mismatched_generation.validate(),
            Err(TenantKeyStateError::InvalidSnapshot)
        );
    }

    #[test]
    fn rotation_publish_activate_and_retire_are_atomic_pairs() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 110).unwrap();
        record.begin_rotation("op-2", 200).unwrap();
        complete_candidate(&mut record, "op-2", "2", 201);
        record.publish_candidate("op-2", 210).unwrap();
        let published = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Publishing);
        assert_eq!(published.generation, 1);
        assert_eq!(published.ec.published.len(), 2);
        assert_eq!(published.rsa.published.len(), 2);

        record.activate_candidate("op-2", 220, 500).unwrap();
        let active = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::ActiveOverlap);
        assert_eq!(active.generation, 2);
        assert_eq!(active.ec.active.public_jwk.kid, "ec-2");
        assert_eq!(active.rsa.active.public_jwk.kid, "rsa-2");
        assert_eq!(
            record.retire("op-2", 499),
            Err(TenantKeyStateError::OverlapNotElapsed)
        );
        record.retire("op-2", 500).unwrap();
        let retired = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(
            record.last_completed_outcome,
            Some(TenantKeyCompletionOutcome::RetiredForward)
        );
        assert_eq!(retired.ec.published.len(), 1);
        assert_eq!(retired.rsa.published.len(), 1);
    }

    #[test]
    fn emergency_revoke_skips_both_rotation_overlap_windows() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 110).unwrap();
        record.begin_rotation("op-2", 200).unwrap();
        complete_candidate(&mut record, "op-2", "2", 201);
        record.publish_candidate("op-2", 210).unwrap();

        record.emergency_revoke("op-2", 211).unwrap();

        let snapshot = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(snapshot.generation, 2);
        assert_eq!(snapshot.ec.published.len(), 1);
        assert_eq!(snapshot.rsa.published.len(), 1);
        assert_eq!(
            record.pending_deletion_arns,
            vec!["arn:ec:1".to_string(), "arn:rsa:1".to_string()]
        );
        assert_eq!(
            record.last_emergency_revoke_operation_id.as_deref(),
            Some("op-2")
        );
        assert_eq!(record.last_completed_outcome, None);

        let mut active = TenantKeyRecord::begin_onboarding("t2", "op-1", 100).unwrap();
        complete_candidate(&mut active, "op-1", "1", 101);
        active.publish_candidate("op-1", 110).unwrap();
        active.begin_rotation("op-2", 200).unwrap();
        complete_candidate(&mut active, "op-2", "2", 201);
        active.publish_candidate("op-2", 210).unwrap();
        active.activate_candidate("op-2", 220, 500).unwrap();
        active.emergency_revoke("op-2", 221).unwrap();
        assert_eq!(active.ready_snapshot().unwrap().generation, 2);
        assert_eq!(active.ready_snapshot().unwrap().ec.published.len(), 1);
        assert_eq!(active.ready_snapshot().unwrap().rsa.published.len(), 1);
    }

    #[test]
    fn rollback_after_activation_keeps_both_generations_until_ttl() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 110).unwrap();
        record.begin_rotation("op-2", 200).unwrap();
        complete_candidate(&mut record, "op-2", "2", 201);
        record.publish_candidate("op-2", 210).unwrap();
        record.activate_candidate("op-2", 220, 500).unwrap();
        record.rollback("op-2", 230, 600).unwrap();
        let rollback = record.ready_snapshot().unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::RollbackOverlap);
        assert_eq!(rollback.generation, 1);
        assert_eq!(rollback.ec.active.public_jwk.kid, "ec-1");
        assert_eq!(rollback.rsa.active.public_jwk.kid, "rsa-1");
        assert_eq!(rollback.ec.published.len(), 2);
        assert_eq!(rollback.rsa.published.len(), 2);
        record.retire("op-2", 600).unwrap();
        assert_eq!(
            record.last_completed_outcome,
            Some(TenantKeyCompletionOutcome::RetiredRollback)
        );
        assert_eq!(record.ready_snapshot().unwrap().ec.published.len(), 1);
    }

    #[test]
    fn failed_rotation_restores_previous_snapshot() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 110).unwrap();
        let old = record.ready_snapshot().unwrap().clone();
        record.begin_rotation("op-2", 200).unwrap();
        record
            .record_created_key("op-2", TenantKeyAlgorithm::Es256, "arn:ec:2", 201)
            .unwrap();
        record.fail_operation("op-2", "probe_failed", 202).unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Ready);
        assert_eq!(record.ready_snapshot().unwrap(), &old);
        assert_eq!(record.last_completed_operation_id.as_deref(), Some("op-1"));
        assert!(record.last_failure.unwrap().cleanup_pending);
    }

    #[test]
    fn offboarding_revokes_signing_before_key_deletion_and_is_idempotent() {
        let mut record = TenantKeyRecord::begin_onboarding("t1", "op-1", 100).unwrap();
        complete_candidate(&mut record, "op-1", "1", 101);
        record.publish_candidate("op-1", 110).unwrap();
        record.begin_rotation("op-2", 200).unwrap();
        record
            .record_created_key("op-2", TenantKeyAlgorithm::Es256, "arn:ec:2", 201)
            .unwrap();

        record.begin_offboarding("offboard-1", 300).unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Offboarding);
        assert!(record.ready_snapshot().is_err());
        assert!(record.served_snapshot.is_none());
        assert!(record.operation.is_none());
        assert_eq!(
            record.pending_deletion_arns,
            vec![
                "arn:ec:1".to_string(),
                "arn:ec:2".to_string(),
                "arn:rsa:1".to_string()
            ]
        );

        let revision = record.revision;
        record.begin_offboarding("offboard-1", 301).unwrap();
        assert_eq!(record.revision, revision);
        assert_eq!(
            record.begin_offboarding("offboard-2", 301),
            Err(TenantKeyStateError::OperationMismatch)
        );

        record.mark_pending_deletions_complete(302).unwrap();
        record.finish_offboarding("offboard-1", 303).unwrap();
        assert_eq!(record.lifecycle, TenantKeyLifecycle::Offboarded);
        assert!(record.ready_snapshot().is_err());
        assert_eq!(record.scheduled_deletion_arns.len(), 3);
    }
}
