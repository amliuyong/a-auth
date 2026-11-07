use super::{database, tenant};
use agent_auth_http::{
    adapters::{memory::MemoryGovernanceStore, postgres::PostgresGovernanceStore},
    governance::*,
    ports::GovernanceStore,
};
use std::sync::Arc;
use tokio::sync::Barrier;

pub(super) fn evidence(job: &GovernanceJobRecord) -> GovernanceEvidenceRecord {
    GovernanceEvidenceRecord::new(GovernanceEvidencePayload {
        schema_version: GOVERNANCE_EVIDENCE_SCHEMA_VERSION.into(),
        tenant_id: job.tenant_id.clone(),
        job_id: job.job_id.clone(),
        job_kind: job.kind,
        job_state: GovernanceJobState::Completed,
        evidence_revision: job.evidence_revision,
        deployment_commit: "contract-fixture".into(),
        started_at: job.created_at,
        verification_at: job.updated_at,
        generated_at: job.updated_at,
        primary_erasure_at: job.primary_erasure_at.unwrap(),
        retention_deadline: job.retention_until.unwrap(),
        residency_jurisdiction: "local".into(),
        configured_regions: vec!["local".into()],
        active_writer_region: "local".into(),
        region_control_revision: 0,
        legal_hold: LegalHoldState::Disabled,
        live_counts: Default::default(),
        retained_counts: Default::default(),
        replica_live_counts: Default::default(),
        alias_tombstone_count: 1,
        retention_resources: Default::default(),
        external_actions: vec![GovernanceEvidenceAction {
            action_id: "optional-outcome".into(),
            kind: GovernanceExternalActionKind::SecretDeletion,
            ownership: GovernanceResourceOwnership::External,
            state: GovernanceExternalActionState::OperatorPending,
            outcome: None,
            retention_until: None,
        }],
        permanent_control_records: vec!["governance_evidence".into()],
    })
    .unwrap()
}

pub(super) fn job(tenant: &str, id: &str, kind: GovernanceJobKind) -> GovernanceJobRecord {
    GovernanceJobRecord {
        job_id: id.into(),
        tenant_id: tenant.into(),
        kind,
        target_id: (kind == GovernanceJobKind::UserErasure).then(|| "user-1".into()),
        target_aliases: vec![],
        verification_target: None,
        active_child_job_id: None,
        processed_records: 0,
        tenant_cleanup_stage: TenantCleanupStage::Users,
        target_epoch: 7,
        state: GovernanceJobState::Running,
        phase: GovernanceJobPhase::PrimaryCleanup,
        policy_revision: 0,
        tenant_revision: 0,
        revision: 1,
        created_at: 100,
        updated_at: 100,
        primary_erasure_at: None,
        retention_anchor_at: None,
        retention_until: None,
        evidence_revision: 0,
        error_class: None,
    }
}

async fn governance_contract(store: impl GovernanceStore + Clone + 'static) {
    let tenant = tenant();
    let foreign = format!("{tenant}-foreign");
    assert_eq!(store.get_policy(&tenant).await.unwrap(), None);
    let policy = GovernancePolicyRecord::default_for(&tenant);
    let policy = match store.put_policy(policy, 0).await.unwrap() {
        GovernancePolicyPutOutcome::Stored(value) => value,
        other => panic!("unexpected policy admission: {other:?}"),
    };
    assert_eq!(policy.revision, 1);
    assert!(matches!(
        store.put_policy(policy.clone(), 0).await.unwrap(),
        GovernancePolicyPutOutcome::Conflict(_)
    ));
    assert_eq!(store.get_policy(&foreign).await.unwrap(), None);
    let manifest = GovernanceExportManifest {
        export_id: "export".into(),
        tenant_id: tenant.clone(),
        actor: "auditor".into(),
        purpose: "port contract".into(),
        policy_revision: 1,
        region: "local".into(),
        region_revision: 0,
        sections: Default::default(),
        created_at: 100,
        expires_at: 150,
    };
    assert!(store.put_export_manifest(manifest.clone()).await.unwrap());
    let mut replacement = manifest.clone();
    replacement.purpose = "must not overwrite".into();
    assert!(!store.put_export_manifest(replacement).await.unwrap());
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 149)
            .await
            .unwrap(),
        Some(manifest)
    );
    assert_eq!(
        store
            .get_export_manifest(&foreign, "export", 149)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 150)
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .get_export_manifest(&tenant, "export", 100)
            .await
            .unwrap(),
        None
    );
    let original = job(&tenant, "erase", GovernanceJobKind::UserErasure);
    let admitted = match store
        .start_or_resume_job(original.clone(), 1, false)
        .await
        .unwrap()
    {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected job admission: {other:?}"),
    };
    assert_eq!(admitted.policy_revision, 1);
    assert_eq!(
        store.get_job(&tenant, "erase").await.unwrap(),
        Some(admitted.clone())
    );
    assert_eq!(store.get_job(&foreign, "erase").await.unwrap(), None);
    assert_eq!(store.list_jobs(&tenant).await.unwrap(), vec![admitted]);
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for actor in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .claim_job_lease(&tenant, "erase", 1, &format!("actor-{actor}"), 100, 200)
                .await
                .unwrap()
        }));
    }
    let mut winner = None;
    for task in tasks {
        match task.await.unwrap() {
            GovernanceJobLeaseOutcome::Acquired(value) => {
                assert!(winner.replace(value).is_none());
            }
            GovernanceJobLeaseOutcome::Conflict(_) => {}
            other => panic!("unexpected lease claim: {other:?}"),
        }
    }
    let lease = winner.unwrap();
    assert!(store
        .tenant_has_active_job_leases(&tenant, 101)
        .await
        .unwrap());
    assert!(!store
        .tenant_has_active_job_leases(&foreign, 101)
        .await
        .unwrap());
    let digest = suppression_digest(&[0x57; 32], &tenant, "user", "canonical_id", 1, "user-1");
    let suppression = GovernanceSuppressionRecord {
        tenant_id: tenant.clone(),
        target_class: "user".into(),
        key_version: 1,
        normalization_version: 1,
        digest: digest.clone(),
        target_epoch: 7,
        created_at: 101,
    };
    assert!(store
        .put_suppression(suppression.clone(), lease.destructive_fence(Some(7)), 101)
        .await
        .unwrap());
    assert!(!store
        .put_suppression(suppression, lease.destructive_fence(Some(7)), 102)
        .await
        .unwrap());
    assert!(store.is_suppressed(&tenant, "user", &digest).await.unwrap());
    assert!(!store
        .is_suppressed(&foreign, "user", &digest)
        .await
        .unwrap());
    assert_eq!(
        store
            .latest_suppression_epoch(&tenant, "user", &digest)
            .await
            .unwrap(),
        Some(7)
    );
    let renewed = match store
        .renew_job_lease(&tenant, lease.destructive_fence(Some(7)), 120, 250)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Renewed(value) => value,
        other => panic!("unexpected lease renewal: {other:?}"),
    };
    assert!(matches!(
        store
            .release_job_lease(&tenant, lease.destructive_fence(Some(7)))
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Conflict(_)
    ));
    assert_eq!(
        store
            .release_job_lease(&tenant, renewed.destructive_fence(Some(7)))
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Released
    );
    assert!(!store
        .tenant_has_active_job_leases(&tenant, 130)
        .await
        .unwrap());
    let mut checkpoint = store.get_job(&tenant, "erase").await.unwrap().unwrap();
    checkpoint.processed_records = 5;
    checkpoint.updated_at = 131;
    let checkpoint = match store.update_job(checkpoint, 1, 1).await.unwrap() {
        GovernanceJobUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected job checkpoint: {other:?}"),
    };
    assert_eq!(checkpoint.revision, 2);
    assert!(matches!(
        store.update_job(checkpoint.clone(), 1, 1).await.unwrap(),
        GovernanceJobUpdateOutcome::Conflict(_)
    ));
    let mut completed = checkpoint;
    completed.state = GovernanceJobState::Completed;
    completed.phase = GovernanceJobPhase::Complete;
    completed.updated_at = 135;
    completed.primary_erasure_at = Some(134);
    completed.retention_until = Some(135);
    completed.evidence_revision = 1;
    completed.target_id = None;
    let proof = evidence(&completed);
    let completed = match store
        .complete_job_with_evidence(completed, proof.clone(), 2, 1)
        .await
        .unwrap()
    {
        GovernanceJobUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected atomic completion: {other:?}"),
    };
    assert_eq!(completed.revision, 3);
    assert_eq!(
        store.latest_evidence(&tenant, "erase").await.unwrap(),
        Some(proof.clone())
    );
    assert_eq!(
        store.latest_evidence(&foreign, "erase").await.unwrap(),
        None
    );
    assert_eq!(
        store.put_evidence(proof.clone()).await.unwrap(),
        GovernanceEvidencePutOutcome::Existing(proof)
    );
    let mut next_proof = evidence(&completed).payload;
    next_proof.evidence_revision = 2;
    let next_proof = GovernanceEvidenceRecord::new(next_proof).unwrap();
    assert_eq!(
        store.put_evidence(next_proof.clone()).await.unwrap(),
        GovernanceEvidencePutOutcome::Stored(next_proof.clone())
    );
    assert_eq!(
        store.latest_evidence(&tenant, "erase").await.unwrap(),
        Some(next_proof)
    );
    let mut held = policy;
    held.legal_hold = LegalHoldState::Enabled;
    held.legal_hold_reason = Some("retained evidence".into());
    held.updated_at = 140;
    let held = match store.put_policy(held, 1).await.unwrap() {
        GovernancePolicyPutOutcome::Stored(value) => value,
        other => panic!("unexpected hold admission: {other:?}"),
    };
    assert!(matches!(
        store
            .claim_job_lease(&tenant, "erase", 1, "late", 140, 250)
            .await
            .unwrap(),
        GovernanceJobLeaseOutcome::Conflict(_)
    ));
    let blocked = job(&tenant, "blocked", GovernanceJobKind::UserErasure);
    let blocked = match store.start_or_resume_job(blocked, 2, false).await.unwrap() {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected held job: {other:?}"),
    };
    assert_eq!(blocked.state, GovernanceJobState::BlockedLegalHold);
    let mut active = held;
    active.legal_hold = LegalHoldState::Disabled;
    active.legal_hold_reason = None;
    active.updated_at = 160;
    assert!(matches!(
        store.put_policy(active, 2).await.unwrap(),
        GovernancePolicyPutOutcome::Stored(_)
    ));
    let resumed = match store.start_or_resume_job(blocked, 3, false).await.unwrap() {
        GovernanceJobStartOutcome::Existing(value) => value,
        other => panic!("unexpected held-job resume: {other:?}"),
    };
    assert_eq!(resumed.state, GovernanceJobState::Queued);
    assert_eq!(resumed.revision, 2);
    assert_eq!(resumed.policy_revision, 3);
    let permit = TenantMutationPermit {
        tenant_id: tenant.clone(),
        permit_id: "writer".into(),
        deadline: 300,
    };
    assert_eq!(
        store
            .acquire_tenant_mutation_permit(permit.clone(), 160)
            .await
            .unwrap(),
        TenantMutationPermitAcquireOutcome::Acquired(permit.clone())
    );
    assert!(store
        .renew_tenant_mutation_permit(&permit, 180, 400)
        .await
        .unwrap());
    assert!(!store
        .release_tenant_mutation_permit(permit.clone(), 181)
        .await
        .unwrap());
    let mut offboard = job(&tenant, "offboard", GovernanceJobKind::TenantOffboarding);
    offboard.target_id = None;
    offboard.updated_at = 190;
    assert_eq!(
        store
            .start_or_resume_job(offboard.clone(), 3, true)
            .await
            .unwrap(),
        GovernanceJobStartOutcome::MutationConflict { active_permits: 1 }
    );
    let mut renewed_permit = permit;
    renewed_permit.deadline = 400;
    assert!(store
        .release_tenant_mutation_permit(renewed_permit, 191)
        .await
        .unwrap());
    offboard.updated_at = 192;
    let frozen = match store.start_or_resume_job(offboard, 3, true).await.unwrap() {
        GovernanceJobStartOutcome::Stored(value) => value,
        other => panic!("unexpected offboarding admission: {other:?}"),
    };
    assert_eq!(frozen.tenant_revision, 1);
    assert_eq!(
        store
            .get_tenant_lifecycle(&tenant)
            .await
            .unwrap()
            .unwrap()
            .state,
        TenantLifecycleState::Offboarding
    );
    assert_eq!(
        store
            .acquire_tenant_mutation_permit(
                TenantMutationPermit {
                    tenant_id: tenant.clone(),
                    permit_id: "too-late".into(),
                    deadline: 300,
                },
                193
            )
            .await
            .unwrap(),
        TenantMutationPermitAcquireOutcome::Frozen {
            lifecycle_revision: Some(1)
        }
    );
    assert_eq!(
        store
            .start_or_resume_job(
                job(&tenant, "new-user", GovernanceJobKind::UserErasure),
                3,
                false
            )
            .await
            .unwrap(),
        GovernanceJobStartOutcome::TenantFrozen {
            lifecycle_revision: 1
        }
    );
    let continuation = store
        .get_continuation(&tenant, "offboard")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(continuation.tenant_revision, 1);
    assert_eq!(continuation.resume_revision, 1);
    assert_eq!(
        store.get_continuation(&foreign, "offboard").await.unwrap(),
        None
    );
    let barrier = Arc::new(Barrier::new(16));
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, tenant, barrier) = (store.clone(), tenant.clone(), barrier.clone());
        tasks.push(tokio::spawn(async move {
            barrier.wait().await;
            store
                .consume_continuation_resume(&tenant, "offboard", "one-time-digest", 1, 300)
                .await
                .unwrap()
        }));
    }
    let mut consumed = 0;
    for task in tasks {
        consumed += usize::from(task.await.unwrap());
    }
    assert_eq!(consumed, 1);
    let mut disabled = continuation;
    disabled.resume_enabled = false;
    disabled.updated_at = 194;
    assert!(matches!(
        store.update_continuation(disabled, 1).await.unwrap(),
        GovernanceContinuationUpdateOutcome::Stored(_)
    ));
    assert!(!store
        .consume_continuation_resume(&tenant, "offboard", "another-digest", 1, 300)
        .await
        .unwrap());
    let lease = match store
        .claim_job_lease(&tenant, "offboard", 1, "external-worker", 195, 300)
        .await
        .unwrap()
    {
        GovernanceJobLeaseOutcome::Acquired(value) => value,
        other => panic!("unexpected external worker lease: {other:?}"),
    };
    let action = GovernanceExternalActionRecord {
        action_id: "secret-delete".into(),
        tenant_id: tenant.clone(),
        job_id: "offboard".into(),
        kind: GovernanceExternalActionKind::SecretDeletion,
        resource_ref: "fixture-secret-reference".into(),
        resource_fingerprint: resource_fingerprint("fixture-secret-reference"),
        ownership: GovernanceResourceOwnership::ProductManaged,
        state: GovernanceExternalActionState::Prepared,
        revision: 1,
        created_at: 196,
        updated_at: 196,
        claim_token_digest: None,
        claim_deadline: None,
        committed_at: None,
        verified_at: None,
        retention_until: None,
        error_class: None,
    };
    let mut rebound = action.clone();
    rebound.resource_fingerprint = resource_fingerprint("another-secret-reference");
    assert!(matches!(
        store
            .prepare_external_action(rebound, lease.external_action_fence())
            .await,
        Err(agent_auth_http::ports::StoreError::Permanent(_))
    ));
    assert_eq!(
        store
            .prepare_external_action(action.clone(), lease.external_action_fence())
            .await
            .unwrap(),
        GovernanceExternalActionPutOutcome::Stored(action.clone())
    );
    assert_eq!(
        store
            .prepare_external_action(action.clone(), lease.external_action_fence())
            .await
            .unwrap(),
        GovernanceExternalActionPutOutcome::Existing(action.clone())
    );
    assert_eq!(
        store
            .get_external_action(&tenant, "offboard", "secret-delete")
            .await
            .unwrap(),
        Some(action.clone())
    );
    assert_eq!(
        store
            .get_external_action(&foreign, "offboard", "secret-delete")
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        store
            .list_external_actions(&tenant, "offboard")
            .await
            .unwrap(),
        vec![action.clone()]
    );
    assert_eq!(
        store.list_tenant_external_actions(&tenant).await.unwrap(),
        vec![action.clone()]
    );
    let mut claimed = action;
    claimed.state = GovernanceExternalActionState::Claimed;
    claimed.claim_token_digest = Some("external-claim-digest".into());
    claimed.claim_deadline = Some(290);
    claimed.updated_at = 197;
    let claimed = match store
        .update_external_action(claimed, 1, lease.external_action_fence())
        .await
        .unwrap()
    {
        GovernanceExternalActionUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected external claim: {other:?}"),
    };
    assert_eq!(claimed.revision, 2);
    let mut verified = claimed;
    verified.state = GovernanceExternalActionState::Verified;
    verified.verified_at = Some(198);
    verified.updated_at = 198;
    let verified = match store
        .reconcile_external_action(
            verified,
            2,
            GovernanceExternalActionReconcileFence {
                job_id: "offboard".into(),
                tenant_revision: 1,
                claim_token_digest: "external-claim-digest".into(),
            },
        )
        .await
        .unwrap()
    {
        GovernanceExternalActionUpdateOutcome::Stored(value) => value,
        other => panic!("unexpected external reconciliation: {other:?}"),
    };
    assert_eq!(verified.revision, 3);
    assert_eq!(
        store.list_tenant_external_actions(&tenant).await.unwrap(),
        vec![verified]
    );
}

#[tokio::test]
async fn memory_governance_contract() {
    governance_contract(MemoryGovernanceStore::default()).await;
}

#[tokio::test]
async fn postgres_governance_contract() {
    governance_contract(PostgresGovernanceStore::new(database().await)).await;
}

#[cfg(feature = "aws")]
#[tokio::test]
async fn aws_governance_contract() {
    use agent_auth_http::adapters::aws::DynamoGovernanceStore;
    use aws_sdk_dynamodb::types::ScalarAttributeType;
    let (db, governance) =
        super::aws_contract_database::table_with_range("pk", Some("sk"), vec![], vec![]).await;
    let (_, suppression) = super::aws_contract_database::table_with_typed_range(
        "pk",
        Some(("epoch", ScalarAttributeType::N)),
        vec![],
        vec![],
    )
    .await;
    governance_contract(DynamoGovernanceStore::new(
        db.clone(),
        &governance,
        &suppression,
    ))
    .await;
    for table in [governance, suppression] {
        db.delete_table().table_name(table).send().await.unwrap();
    }
}
