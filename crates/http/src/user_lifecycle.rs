use crate::ports::{
    DisableStart, EnableOutcome, GraceStore, GrantStore, InvitationStore, PasskeyStore,
    PasswordStore, RecoveryStore, RefreshStore, SessionStore, UserRecord, UsersStore,
};
use crate::state::AppState;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleError {
    Store,
    Cascade,
    ConcurrentChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisableOutcome {
    Disabled {
        record: Box<UserRecord>,
        counts: CascadeCounts,
    },
    NotFound,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleEnableOutcome {
    Enabled(UserRecord),
    NotFound,
    Tombstoned,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CascadeCounts {
    pub sessions: usize,
    pub families: usize,
    pub grants: usize,
    pub passkeys: usize,
    pub recovery_deleted: bool,
    pub password_deleted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuthenticationRevokeCounts {
    pub(crate) sessions: usize,
    pub(crate) families: usize,
}

async fn revoke_authentication_state_inner(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    before_epoch: Option<u64>,
) -> Result<AuthenticationRevokeCounts, LifecycleError> {
    let sessions = match before_epoch {
        Some(epoch) => {
            state
                .sessions
                .delete_by_user_before_epoch(tenant, user_id, epoch)
                .await
        }
        None => state.sessions.delete_by_user(tenant, user_id).await,
    }
    .map_err(|_| LifecycleError::Cascade)?;
    let family_ids = match before_epoch {
        Some(epoch) => {
            state
                .refresh
                .revoke_by_user_before_epoch(tenant, user_id, epoch)
                .await
        }
        None => state.refresh.revoke_by_user(tenant, user_id).await,
    }
    .map_err(|_| LifecycleError::Cascade)?;
    if let Some(grace) = &state.grace {
        for family_id in &family_ids {
            grace
                .delete_family(family_id)
                .await
                .map_err(|_| LifecycleError::Cascade)?;
        }
    }
    Ok(AuthenticationRevokeCounts {
        sessions,
        families: family_ids.len(),
    })
}

pub(crate) async fn revoke_authentication_state(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<AuthenticationRevokeCounts, LifecycleError> {
    revoke_authentication_state_inner(state, tenant, user_id, None).await
}

async fn cascade_revoke_inner(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    before_epoch: Option<u64>,
    tombstone_extras: bool,
) -> Result<CascadeCounts, LifecycleError> {
    let authentication =
        revoke_authentication_state_inner(state, tenant, user_id, before_epoch).await?;
    let invitation_locator =
        crate::invitation::invitation_locator(&state.server_secret, tenant, user_id);
    state
        .invitations
        .invalidate(tenant, &invitation_locator)
        .await
        .map_err(|_| LifecycleError::Cascade)?;
    let grant_list = state
        .grants
        .list_by_user(tenant, user_id)
        .await
        .map_err(|_| LifecycleError::Cascade)?;
    let mut grants = 0usize;
    let mut grant_events = Vec::with_capacity(grant_list.len());
    for grant in &grant_list {
        let revoked = match before_epoch {
            Some(epoch) => {
                state
                    .grants
                    .revoke_if_epoch_before(tenant, &grant.grant_id, epoch)
                    .await
            }
            None => state.grants.revoke(tenant, &grant.grant_id).await,
        };
        if before_epoch.is_none() || !matches!(revoked, Ok(false)) {
            grant_events.push(crate::grants::revoke_event_draft(
                tenant,
                crate::security_event::SecurityActor::system("user-lifecycle"),
                &grant.grant_id,
                revoked.is_ok(),
            ));
        }
        match revoked {
            Ok(revoked) => grants += usize::from(revoked),
            Err(_) => {
                state.record_security_events(grant_events).await;
                return Err(LifecycleError::Cascade);
            }
        }
    }
    state.record_security_events(grant_events).await;

    let (mut passkeys, mut recovery_deleted, mut password_deleted) = (0, false, false);
    if tombstone_extras {
        passkeys = state
            .passkeys
            .delete_by_user(tenant, user_id)
            .await
            .map_err(|_| LifecycleError::Cascade)?;
        state
            .recovery
            .delete_by_lookup(tenant, &crate::recover::user_lookup(user_id))
            .await
            .map_err(|_| LifecycleError::Cascade)?;
        recovery_deleted = true;
        state
            .passwords
            .delete(tenant, user_id)
            .await
            .map_err(|_| LifecycleError::Cascade)?;
        password_deleted = true;
    }

    Ok(CascadeCounts {
        sessions: authentication.sessions,
        families: authentication.families,
        grants,
        passkeys,
        recovery_deleted,
        password_deleted,
    })
}

pub(crate) async fn cascade_revoke(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    tombstone_extras: bool,
) -> Result<CascadeCounts, LifecycleError> {
    cascade_revoke_inner(state, tenant, user_id, None, tombstone_extras).await
}

pub(crate) async fn cascade_revoke_before_epoch(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    epoch: u64,
) -> Result<CascadeCounts, LifecycleError> {
    cascade_revoke_inner(state, tenant, user_id, Some(epoch), false).await
}

pub async fn disable(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    now: i64,
) -> Result<DisableOutcome, LifecycleError> {
    let (record, epoch) = match state
        .users
        .begin_disable(tenant, user_id, now)
        .await
        .map_err(|_| LifecycleError::Store)?
    {
        DisableStart::Ready { record, epoch } => (record, epoch),
        DisableStart::NotFound => return Ok(DisableOutcome::NotFound),
        DisableStart::Tombstoned => return Ok(DisableOutcome::Tombstoned),
    };

    let counts = cascade_revoke_before_epoch(state, tenant, user_id, epoch).await?;
    let completed = state
        .users
        .complete_disable(tenant, user_id, epoch, now)
        .await
        .map_err(|_| LifecycleError::Store)?;
    if !completed {
        return Err(LifecycleError::ConcurrentChange);
    }
    let mut record = record;
    record.revocation_pending = false;
    Ok(DisableOutcome::Disabled {
        record: Box::new(record),
        counts,
    })
}

pub async fn enable(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    now: i64,
) -> Result<LifecycleEnableOutcome, LifecycleError> {
    let mut retries = 0;
    let mut record = loop {
        let Some(record) = state
            .users
            .get_by_id(tenant, user_id)
            .await
            .map_err(|_| LifecycleError::Store)?
        else {
            return Ok(LifecycleEnableOutcome::NotFound);
        };
        if record.status == crate::ports::UserStatus::Tombstoned {
            return Ok(LifecycleEnableOutcome::Tombstoned);
        }
        if record.status == crate::ports::UserStatus::Active && !record.revocation_pending {
            return Ok(LifecycleEnableOutcome::Enabled(record));
        }
        if record.status != crate::ports::UserStatus::Disabled || record.credential_epoch != 0 {
            break record;
        }
        if let Some(upgraded) = state
            .users
            .begin_legacy_disable_cleanup(tenant, user_id, now)
            .await
            .map_err(|_| LifecycleError::Store)?
        {
            break upgraded;
        }
        retries += 1;
        if retries == 3 {
            return Err(LifecycleError::ConcurrentChange);
        }
    };

    if record.revocation_pending {
        cascade_revoke_before_epoch(state, tenant, user_id, record.credential_epoch).await?;
        let completed = state
            .users
            .complete_disable(tenant, user_id, record.credential_epoch, now)
            .await
            .map_err(|_| LifecycleError::Store)?;
        if !completed {
            return Err(LifecycleError::ConcurrentChange);
        }
        record.revocation_pending = false;
    }

    match state
        .users
        .enable_completed(tenant, user_id, record.credential_epoch, now)
        .await
        .map_err(|_| LifecycleError::Store)?
    {
        EnableOutcome::Enabled(record) => Ok(LifecycleEnableOutcome::Enabled(record)),
        EnableOutcome::NotFound => Ok(LifecycleEnableOutcome::NotFound),
        EnableOutcome::Tombstoned => Ok(LifecycleEnableOutcome::Tombstoned),
        EnableOutcome::RevocationPending => Err(LifecycleError::ConcurrentChange),
        EnableOutcome::ConcurrentChange => Err(LifecycleError::ConcurrentChange),
    }
}

#[cfg(test)]
mod tests {
    use super::{cascade_revoke_before_epoch, disable, enable, LifecycleEnableOutcome};
    use crate::{
        ports::{
            GrantStore, RefreshFamilyRecord, RefreshStore, SessionRecord, SessionStore, UserStatus,
            UsersStore,
        },
        security_event::{
            SecurityActor, SecurityEventOutcome, SecurityEventStore, SecuritySubject,
        },
        AppState,
    };
    use agent_auth_grant::{Grant, GrantConstraints, GrantStatus};

    fn grant(grant_id: &str, user_id: &str, credential_epoch: u64) -> Grant {
        Grant {
            grant_id: grant_id.to_string(),
            user_id: user_id.to_string(),
            client_id: "client".to_string(),
            per_resource: vec![],
            effective_per_resource: vec![],
            effective_pv: 0,
            allowed_ip_cidrs: vec![],
            allowed_vpce: vec![],
            credential_epoch,
            revision: 0,
            constraints: GrantConstraints {
                max_act_chain: 1,
                actor_allowlist: vec![],
                expires_at: i64::MAX,
            },
            status: GrantStatus::Active,
        }
    }

    #[tokio::test]
    async fn delayed_disable_cascade_cannot_revoke_current_epoch_artifacts() {
        let state = AppState::dev("localhost");
        let user_id = "user:epoch-fence";
        for (suffix, credential_epoch) in [("old", 0), ("current", 1)] {
            state
                .sessions
                .create(
                    "",
                    SessionRecord {
                        session_id: format!("{suffix}-session"),
                        user_id: user_id.to_string(),
                        credential_epoch,
                        auth_time: 1,
                        created_at: 1,
                        last_used_at: 1,
                        device: "Test browser".into(),
                        expires_at: i64::MAX,
                        acr: None,
                        amr: vec![],
                    },
                )
                .await
                .unwrap();
            state
                .refresh
                .create(
                    "",
                    RefreshFamilyRecord {
                        family_id: format!("{suffix}-family"),
                        current_version: 0,
                        revoked: false,
                        client_id: "client".to_string(),
                        cimd_snapshot: None,
                        user_id: user_id.to_string(),
                        credential_epoch,
                        resources: vec![],
                        scope: vec![],
                        actor_allowlist: vec![],
                        max_act_chain: 1,
                        dpop_jkt: None,
                        pkce_code_challenge: None,
                        auth_time: None,
                        acr: None,
                        password_credential_version: None,
                    },
                )
                .await
                .unwrap();
            state
                .grants
                .put(
                    "",
                    grant(&format!("{suffix}-grant"), user_id, credential_epoch),
                )
                .await
                .unwrap();
        }

        let counts = cascade_revoke_before_epoch(&state, "", user_id, 1)
            .await
            .unwrap();
        assert_eq!(counts.sessions, 1);
        assert_eq!(counts.families, 1);
        assert_eq!(counts.grants, 1);

        assert!(state
            .sessions
            .get("", "old-session")
            .await
            .unwrap()
            .is_none());
        assert!(state
            .sessions
            .get("", "current-session")
            .await
            .unwrap()
            .is_some());
        assert!(
            state
                .refresh
                .get("", "old-family")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert!(
            !state
                .refresh
                .get("", "current-family")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert_eq!(
            state
                .grants
                .get("", "old-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            GrantStatus::Revoked
        );
        assert_eq!(
            state
                .grants
                .get("", "current-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            GrantStatus::Active
        );
        let events = state
            .security_events
            .list_by_tenant("default", 0, i64::MAX, 100)
            .await
            .unwrap();
        let revoked = events
            .iter()
            .filter(|stored| stored.event.action == "grant.revoke")
            .collect::<Vec<_>>();
        assert_eq!(revoked.len(), 1);
        assert_eq!(revoked[0].event.outcome, SecurityEventOutcome::Success);
        assert_eq!(
            revoked[0].event.actor,
            SecurityActor::system("user-lifecycle")
        );
        assert_eq!(
            revoked[0].event.subject,
            SecuritySubject::grant("old-grant")
        );
    }

    #[tokio::test]
    async fn first_enable_of_legacy_disabled_epoch_zero_cleans_before_activation() {
        let state = AppState::dev("localhost");
        let user_id = "user:legacy-disabled@example.com";
        state
            .users
            .create_or_get_by_email("", "legacy-disabled@example.com", user_id, 1)
            .await
            .unwrap();
        state
            .users
            .set_status("", user_id, UserStatus::Disabled, 2)
            .await
            .unwrap();
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: "legacy-session".to_string(),
                    user_id: user_id.to_string(),
                    credential_epoch: 0,
                    auth_time: 1,
                    created_at: 1,
                    last_used_at: 1,
                    device: "Test browser".into(),
                    expires_at: i64::MAX,
                    acr: None,
                    amr: vec![],
                },
            )
            .await
            .unwrap();
        state
            .refresh
            .create(
                "",
                RefreshFamilyRecord {
                    family_id: "legacy-family".to_string(),
                    current_version: 0,
                    revoked: false,
                    client_id: "client".to_string(),
                    cimd_snapshot: None,
                    user_id: user_id.to_string(),
                    credential_epoch: 0,
                    resources: vec![],
                    scope: vec![],
                    actor_allowlist: vec![],
                    max_act_chain: 1,
                    dpop_jkt: None,
                    pkce_code_challenge: None,
                    auth_time: None,
                    acr: None,
                    password_credential_version: None,
                },
            )
            .await
            .unwrap();
        state
            .grants
            .put("", grant("legacy-grant", user_id, 0))
            .await
            .unwrap();

        let LifecycleEnableOutcome::Enabled(user) = enable(&state, "", user_id, 3).await.unwrap()
        else {
            panic!("legacy disabled user was not enabled");
        };
        assert_eq!(user.status, UserStatus::Active);
        assert_eq!(user.credential_epoch, 1);
        assert!(!user.revocation_pending);
        assert!(state
            .sessions
            .get("", "legacy-session")
            .await
            .unwrap()
            .is_none());
        assert!(
            state
                .refresh
                .get("", "legacy-family")
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        assert_eq!(
            state
                .grants
                .get("", "legacy-grant")
                .await
                .unwrap()
                .unwrap()
                .status,
            GrantStatus::Revoked
        );
    }

    #[tokio::test]
    async fn stale_enable_snapshot_cannot_overwrite_a_newer_disable() {
        let state = AppState::dev("localhost");
        let user_id = "user:stale-enable@example.com";
        state
            .users
            .create_or_get_by_email("", "stale-enable@example.com", user_id, 1)
            .await
            .unwrap();
        let stale_epoch = state
            .users
            .get_by_id("", user_id)
            .await
            .unwrap()
            .unwrap()
            .credential_epoch;

        disable(&state, "", user_id, 2).await.unwrap();
        assert_eq!(
            state
                .users
                .enable_completed("", user_id, stale_epoch, 3)
                .await
                .unwrap(),
            crate::ports::EnableOutcome::ConcurrentChange
        );
        let current = state.users.get_by_id("", user_id).await.unwrap().unwrap();
        assert_eq!(current.status, UserStatus::Disabled);
        assert_eq!(current.credential_epoch, stale_epoch + 1);
    }

    #[tokio::test]
    async fn repeated_enable_for_the_same_epoch_is_idempotent() {
        let state = AppState::dev("localhost");
        let user_id = "user:repeated-enable@example.com";
        state
            .users
            .create_or_get_by_email("", "repeated-enable@example.com", user_id, 1)
            .await
            .unwrap();
        disable(&state, "", user_id, 2).await.unwrap();
        let enabled = enable(&state, "", user_id, 3).await.unwrap();
        let super::LifecycleEnableOutcome::Enabled(enabled) = enabled else {
            panic!("first enable did not succeed");
        };

        assert!(matches!(
            state
                .users
                .enable_completed("", user_id, enabled.credential_epoch, 4)
                .await
                .unwrap(),
            crate::ports::EnableOutcome::Enabled(record)
                if record.status == UserStatus::Active
                    && record.credential_epoch == enabled.credential_epoch
        ));
    }
}
