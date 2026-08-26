//! Destructive governance data-plane orchestration.
//!
//! Normal business-store traits deliberately do not carry governance leases.
//! This module is the only bridge from a claimed governance job to physical
//! mutations and pure-read residual inventory.

use std::collections::BTreeMap;

#[cfg(feature = "aws")]
use crate::federation_attributes::FederationAttributeMappingsStore;
#[cfg(feature = "aws")]
use crate::ports::{ClientStore, DomainMapStore, InitialAccessTokenStore};
use crate::{
    governance::{
        GovernanceAliasKind, GovernanceDestructiveFence, GovernanceStoreImpl,
        GovernanceTargetAlias, TenantCleanupStage,
    },
    ports::{StoreError, UserRecord, UsersStore},
    state::{
        AdminAuthStoreImpl, AppState, AuthzSessionStoreImpl, CibaStoreImpl, ClientStoreImpl,
        CodeStoreImpl, DeviceStoreImpl, DomainMapStoreImpl, FederationAttributeMappingsStoreImpl,
        FederationConfigStoreImpl, FederationFlowStoreImpl, GraceStoreImpl, GrantStoreImpl,
        InitialAccessTokenStoreImpl, InvitationStoreImpl, JtiStoreImpl, MagicLinkStoreImpl,
        MessageOutboxImpl, ParStoreImpl, PasskeyChallengeStoreImpl, PasskeyStoreImpl,
        PasswordStoreImpl, PolicyArtifactStoreImpl, PolicyVersionStoreImpl, RateLimitStoreImpl,
        RecoveryStoreImpl, RefreshStoreImpl, ReplayStoreImpl, ScimGroupsStoreImpl,
        SessionStoreImpl, SsfStoreImpl, UsersStoreImpl, WorkloadTrustStoreImpl,
    },
};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct GovernanceInventory {
    pub(crate) live_counts: BTreeMap<String, u64>,
    pub(crate) retained_counts: BTreeMap<String, u64>,
}

impl GovernanceInventory {
    pub(crate) fn live_absent(&self) -> bool {
        self.live_counts.values().all(|count| *count == 0)
    }
}

fn backend_mismatch(expected: &str) -> StoreError {
    StoreError::Permanent(format!(
        "governance data plane requires one coherent {expected} backend"
    ))
}

#[cfg(feature = "aws")]
fn add_count(
    counts: &mut BTreeMap<String, u64>,
    category: &str,
    count: usize,
) -> Result<(), StoreError> {
    counts.insert(
        category.to_string(),
        u64::try_from(count)
            .map_err(|_| StoreError::Permanent("governance inventory count exceeds u64".into()))?,
    );
    Ok(())
}

fn alias_values(aliases: &[GovernanceTargetAlias]) -> Vec<String> {
    aliases
        .iter()
        .filter(|alias| alias.kind != GovernanceAliasKind::CanonicalId)
        .map(|alias| alias.normalized_value.clone())
        .collect()
}

#[cfg(feature = "aws")]
fn alias_by_kind(aliases: &[GovernanceTargetAlias], kind: GovernanceAliasKind) -> Option<&str> {
    aliases
        .iter()
        .find(|alias| alias.kind == kind)
        .map(|alias| alias.normalized_value.as_str())
}

#[cfg_attr(not(feature = "aws"), allow(irrefutable_let_patterns))]
fn memory_user_plane(
    state: &AppState,
) -> Result<crate::adapters::memory::MemoryGovernanceUserDataPlane<'_>, StoreError> {
    let GovernanceStoreImpl::Memory(governance) = state.governance.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let UsersStoreImpl::Memory(users) = state.users.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let CodeStoreImpl::Memory(codes) = state.codes.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let SessionStoreImpl::Memory(sessions) = state.sessions.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let RefreshStoreImpl::Memory(refresh) = state.refresh.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let grace = match state.grace.as_deref() {
        Some(GraceStoreImpl::Memory(grace)) => Some(grace),
        #[cfg(feature = "aws")]
        Some(GraceStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let PasskeyChallengeStoreImpl::Memory(passkey_challenges) = state.passkey_challenges.as_ref()
    else {
        return Err(backend_mismatch("Memory"));
    };
    let PasskeyStoreImpl::Memory(passkeys) = state.passkeys.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let GrantStoreImpl::Memory(grants) = state.grants.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let jtis = match state.jti_store.as_deref() {
        Some(JtiStoreImpl::Memory(jtis)) => Some(jtis),
        #[cfg(feature = "aws")]
        Some(JtiStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let CibaStoreImpl::Memory(ciba) = state.ciba.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let DeviceStoreImpl::Memory(device) = state.device.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let RecoveryStoreImpl::Memory(recovery) = state.recovery.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let PasswordStoreImpl::Memory(passwords) = state.passwords.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let MagicLinkStoreImpl::Memory(magic_links) = state.magic_links.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let InvitationStoreImpl::Memory(invitations) = state.invitations.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let MessageOutboxImpl::Memory(messages) = state.messages.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let ScimGroupsStoreImpl::Memory(scim_groups) = state.scim_groups.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let AdminAuthStoreImpl::Memory(admin_auth) = state.admin_auth.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let AuthzSessionStoreImpl::Memory(authz_sessions) = state.authz_sessions.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };

    Ok(crate::adapters::memory::MemoryGovernanceUserDataPlane {
        governance,
        users,
        codes,
        sessions,
        refresh,
        grace,
        passkey_challenges,
        passkeys,
        grants,
        jtis,
        ciba,
        device,
        recovery,
        passwords,
        magic_links,
        invitations,
        messages,
        scim_groups,
        admin_auth,
        authz_sessions,
    })
}

#[cfg(feature = "aws")]
struct DynamoUserPlane<'a> {
    governance: &'a crate::adapters::aws::DynamoGovernanceStore,
    users: &'a crate::adapters::aws::DynamoUsersStore,
    codes: &'a crate::adapters::aws::DynamoCodeStore,
    sessions: &'a crate::adapters::aws::DynamoSessionStore,
    refresh: &'a crate::adapters::aws::DynamoRefreshStore,
    grace: Option<&'a crate::adapters::aws::DynamoGraceStore>,
    passkey_challenges: &'a crate::adapters::aws::DynamoPasskeyChallengeStore,
    passkeys: &'a crate::adapters::aws::DynamoPasskeyStore,
    grants: &'a crate::adapters::aws::DynamoGrantStore,
    jtis: Option<&'a crate::adapters::aws::DynamoJtiStore>,
    ciba: &'a crate::adapters::aws::DynamoCibaStore,
    device: &'a crate::adapters::aws::DynamoDeviceStore,
    recovery: &'a crate::adapters::aws::DynamoRecoveryStore,
    passwords: &'a crate::adapters::aws::DynamoPasswordStore,
    magic_links: &'a crate::adapters::aws::DynamoMagicLinkStore,
    invitations: &'a crate::adapters::aws::DynamoInvitationStore,
    messages: &'a crate::adapters::aws::DynamoNotifier,
    scim_groups: &'a crate::adapters::aws::DynamoScimGroupsStore,
    admin_auth: &'a crate::adapters::aws::DynamoAdminAuthStore,
    authz_sessions: &'a crate::adapters::aws::DynamoAuthzSessionStore,
}

#[cfg(feature = "aws")]
fn dynamo_user_plane(state: &AppState) -> Result<DynamoUserPlane<'_>, StoreError> {
    let GovernanceStoreImpl::Dynamo(governance) = state.governance.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let UsersStoreImpl::Dynamo(users) = state.users.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let CodeStoreImpl::Dynamo(codes) = state.codes.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let SessionStoreImpl::Dynamo(sessions) = state.sessions.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let RefreshStoreImpl::Dynamo(refresh) = state.refresh.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let grace = match state.grace.as_deref() {
        Some(GraceStoreImpl::Dynamo(grace)) => Some(grace),
        Some(GraceStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let PasskeyChallengeStoreImpl::Dynamo(passkey_challenges) = state.passkey_challenges.as_ref()
    else {
        return Err(backend_mismatch("Dynamo"));
    };
    let PasskeyStoreImpl::Dynamo(passkeys) = state.passkeys.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let GrantStoreImpl::Dynamo(grants) = state.grants.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let jtis = match state.jti_store.as_deref() {
        Some(JtiStoreImpl::Dynamo(jtis)) => Some(jtis),
        Some(JtiStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let CibaStoreImpl::Dynamo(ciba) = state.ciba.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let DeviceStoreImpl::Dynamo(device) = state.device.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let RecoveryStoreImpl::Dynamo(recovery) = state.recovery.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let PasswordStoreImpl::Dynamo(passwords) = state.passwords.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let MagicLinkStoreImpl::Dynamo(magic_links) = state.magic_links.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let InvitationStoreImpl::Dynamo(invitations) = state.invitations.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let MessageOutboxImpl::Dynamo(messages) = state.messages.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let ScimGroupsStoreImpl::Dynamo(scim_groups) = state.scim_groups.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let AdminAuthStoreImpl::Dynamo(admin_auth) = state.admin_auth.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let AuthzSessionStoreImpl::Dynamo(authz_sessions) = state.authz_sessions.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };

    Ok(DynamoUserPlane {
        governance,
        users,
        codes,
        sessions,
        refresh,
        grace,
        passkey_challenges,
        passkeys,
        grants,
        jtis,
        ciba,
        device,
        recovery,
        passwords,
        magic_links,
        invitations,
        messages,
        scim_groups,
        admin_auth,
        authz_sessions,
    })
}

pub(crate) async fn fence_user_identity(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
    user_id: &str,
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<Option<UserRecord>, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => {
            memory_user_plane(state)?
                .fence_identity(logical_tenant, data_tenant, user_id, fence, now)
                .await
        }
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            let target_epoch = fence.target_epoch.ok_or_else(|| {
                StoreError::Permanent("user erasure fence is missing target epoch".into())
            })?;
            let plane = dynamo_user_plane(state)?;
            plane
                .users
                .governance_fence_for_erasure_fenced(
                    plane.governance,
                    logical_tenant,
                    data_tenant,
                    fence,
                    now,
                    user_id,
                    target_epoch,
                )
                .await
        }
    }
}

pub(crate) async fn cleanup_user_authority(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
    user_id: &str,
    aliases: &[GovernanceTargetAlias],
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<u64, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => {
            memory_user_plane(state)?
                .cleanup_user(
                    logical_tenant,
                    data_tenant,
                    user_id,
                    &alias_values(aliases),
                    fence,
                    now,
                )
                .await
        }
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            let plane = dynamo_user_plane(state)?;
            let mut removed = 0usize;
            let authz_session_ids = plane
                .codes
                .governance_authz_session_ids_by_user(data_tenant, user_id)
                .await?;
            removed = removed.saturating_add(
                plane
                    .authz_sessions
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                        &authz_session_ids,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .codes
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .sessions
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );

            let family_ids = plane
                .refresh
                .governance_family_ids_by_user(data_tenant, user_id)
                .await?;
            if let Some(grace) = plane.grace {
                for family_id in &family_ids {
                    removed = removed.saturating_add(
                        grace
                            .governance_delete_family_fenced(
                                plane.governance,
                                logical_tenant,
                                fence,
                                now,
                                family_id,
                            )
                            .await?,
                    );
                }
            }
            removed = removed.saturating_add(
                plane
                    .refresh
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?
                    .len(),
            );
            removed = removed.saturating_add(
                plane
                    .passkey_challenges
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .passkeys
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .grants
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            if let Some(jtis) = plane.jtis {
                removed = removed.saturating_add(
                    jtis.governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                        user_id,
                    )
                    .await?,
                );
            }
            removed = removed.saturating_add(
                plane
                    .ciba
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .device
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            let lookup = crate::recover::user_lookup(user_id);
            removed = removed.saturating_add(
                plane
                    .recovery
                    .governance_delete_by_lookup_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        &lookup,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .passwords
                    .governance_delete_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .invitations
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                    )
                    .await?,
            );
            let aliases = alias_values(aliases);
            removed = removed.saturating_add(
                plane
                    .magic_links
                    .governance_delete_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        user_id,
                        &aliases,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .messages
                    .governance_delete_by_recipients_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                        &aliases,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .scim_groups
                    .governance_remove_member_from_all_fenced(
                        plane.governance,
                        logical_tenant,
                        data_tenant,
                        fence,
                        now,
                        user_id,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .admin_auth
                    .governance_delete_sessions_by_user_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                        user_id,
                    )
                    .await?,
            );
            u64::try_from(removed)
                .map_err(|_| StoreError::Permanent("user cleanup count exceeds u64".into()))
        }
    }
}

pub(crate) async fn delete_user_identity(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
    user_id: &str,
    _aliases: &[GovernanceTargetAlias],
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<bool, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => {
            memory_user_plane(state)?
                .delete_identity(logical_tenant, data_tenant, user_id, fence, now)
                .await
        }
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            let target_epoch = fence.target_epoch.ok_or_else(|| {
                StoreError::Permanent("user erasure fence is missing target epoch".into())
            })?;
            let plane = dynamo_user_plane(state)?;
            plane
                .users
                .governance_delete_erased_identity_fenced(
                    plane.governance,
                    logical_tenant,
                    data_tenant,
                    fence,
                    now,
                    user_id,
                    target_epoch,
                    alias_by_kind(_aliases, GovernanceAliasKind::ScimExternalId),
                    alias_by_kind(_aliases, GovernanceAliasKind::ScimUserName),
                )
                .await
        }
    }
}

pub(crate) async fn inventory_user_authority(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
    user_id: &str,
    aliases: &[GovernanceTargetAlias],
) -> Result<GovernanceInventory, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => Ok(GovernanceInventory {
            live_counts: memory_user_plane(state)?
                .inventory_user(logical_tenant, data_tenant, user_id, &alias_values(aliases))
                .await?,
            retained_counts: BTreeMap::new(),
        }),
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            let plane = dynamo_user_plane(state)?;
            let mut live = BTreeMap::new();
            let identity = plane
                .users
                .governance_user_identity_inventory(
                    data_tenant,
                    user_id,
                    alias_by_kind(aliases, GovernanceAliasKind::ScimExternalId),
                    alias_by_kind(aliases, GovernanceAliasKind::ScimUserName),
                )
                .await?;
            live.insert("identity".into(), u64::from(identity.canonical_exists));
            live.insert(
                "identity_tombstone".into(),
                u64::from(identity.canonical_tombstoned),
            );
            live.insert(
                "identity_epoch".into(),
                u64::from(identity.canonical_epoch.is_some()),
            );
            add_count(
                &mut live,
                "identity_aliases",
                identity
                    .scim_aliases_remaining
                    .saturating_add(identity.scim_create_claims_remaining),
            )?;
            add_count(
                &mut live,
                "codes",
                plane
                    .codes
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            let authz_session_ids = plane
                .codes
                .governance_authz_session_ids_by_user(data_tenant, user_id)
                .await?;
            add_count(
                &mut live,
                "authz_sessions",
                plane
                    .authz_sessions
                    .governance_count_by_user(data_tenant, user_id, &authz_session_ids)
                    .await?,
            )?;
            add_count(
                &mut live,
                "sessions",
                plane
                    .sessions
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            let family_ids = plane
                .refresh
                .governance_family_ids_by_user(data_tenant, user_id)
                .await?;
            add_count(&mut live, "refresh_families", family_ids.len())?;
            let mut grace_rows = 0usize;
            if let Some(grace) = plane.grace {
                for family_id in &family_ids {
                    grace_rows =
                        grace_rows.saturating_add(grace.governance_count_family(family_id).await?);
                }
            }
            add_count(&mut live, "refresh_grace", grace_rows)?;
            add_count(
                &mut live,
                "passkey_challenges",
                plane
                    .passkey_challenges
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            add_count(
                &mut live,
                "passkeys",
                plane
                    .passkeys
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            add_count(
                &mut live,
                "grants",
                plane
                    .grants
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            let jtis = if let Some(jtis) = plane.jtis {
                jtis.governance_count_by_user(logical_tenant, user_id)
                    .await?
            } else {
                0
            };
            add_count(&mut live, "jtis", jtis)?;
            add_count(
                &mut live,
                "ciba",
                plane
                    .ciba
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            add_count(
                &mut live,
                "device_grants",
                plane
                    .device
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            let lookup = crate::recover::user_lookup(user_id);
            add_count(
                &mut live,
                "recovery",
                plane
                    .recovery
                    .governance_count_by_lookup(data_tenant, &lookup, user_id)
                    .await?,
            )?;
            add_count(
                &mut live,
                "passwords",
                plane
                    .passwords
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            add_count(
                &mut live,
                "invitations",
                plane
                    .invitations
                    .governance_count_by_user(data_tenant, user_id)
                    .await?,
            )?;
            let aliases = alias_values(aliases);
            add_count(
                &mut live,
                "magic_links",
                plane
                    .magic_links
                    .governance_count_by_user(data_tenant, user_id, &aliases)
                    .await?,
            )?;
            add_count(
                &mut live,
                "messages",
                plane
                    .messages
                    .governance_count_by_recipients(data_tenant, &aliases)
                    .await?,
            )?;
            let scim = plane
                .scim_groups
                .governance_user_membership_inventory(data_tenant, user_id)
                .await?;
            add_count(&mut live, "scim_membership_rows", scim.membership_rows)?;
            add_count(
                &mut live,
                "scim_live_memberships",
                scim.confirmed_live_memberships,
            )?;
            add_count(&mut live, "scim_role_rows", scim.role_index_rows)?;
            add_count(
                &mut live,
                "admin_sessions",
                plane
                    .admin_auth
                    .governance_count_sessions_by_user(logical_tenant, user_id)
                    .await?,
            )?;
            Ok(GovernanceInventory {
                live_counts: live,
                retained_counts: BTreeMap::new(),
            })
        }
    }
}

#[cfg_attr(not(feature = "aws"), allow(irrefutable_let_patterns))]
fn memory_tenant_plane(
    state: &AppState,
) -> Result<crate::adapters::memory::MemoryGovernanceTenantDataPlane<'_>, StoreError> {
    let GovernanceStoreImpl::Memory(governance) = state.governance.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let UsersStoreImpl::Memory(users) = state.users.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let ClientStoreImpl::Memory(clients) = state.clients.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let InitialAccessTokenStoreImpl::Memory(initial_access_tokens) =
        state.initial_access_tokens.as_ref()
    else {
        return Err(backend_mismatch("Memory"));
    };
    let ScimGroupsStoreImpl::Memory(scim_groups) = state.scim_groups.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let FederationConfigStoreImpl::Memory(federation_config) = state.federation_config.as_ref()
    else {
        return Err(backend_mismatch("Memory"));
    };
    let FederationAttributeMappingsStoreImpl::Memory(federation_attribute_mappings) =
        state.federation_attribute_mappings.as_ref()
    else {
        return Err(backend_mismatch("Memory"));
    };
    let WorkloadTrustStoreImpl::Memory(workload_trust) = state.workload_trust.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let AdminAuthStoreImpl::Memory(admin_auth) = state.admin_auth.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let FederationFlowStoreImpl::Memory(federation_flow) = state.federation_flow.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let CodeStoreImpl::Memory(codes) = state.codes.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let SessionStoreImpl::Memory(sessions) = state.sessions.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let RefreshStoreImpl::Memory(refresh) = state.refresh.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let grace = match state.grace.as_deref() {
        Some(GraceStoreImpl::Memory(grace)) => Some(grace),
        #[cfg(feature = "aws")]
        Some(GraceStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let PasskeyChallengeStoreImpl::Memory(passkey_challenges) = state.passkey_challenges.as_ref()
    else {
        return Err(backend_mismatch("Memory"));
    };
    let PasskeyStoreImpl::Memory(passkeys) = state.passkeys.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let jtis = match state.jti_store.as_deref() {
        Some(JtiStoreImpl::Memory(jtis)) => Some(jtis),
        #[cfg(feature = "aws")]
        Some(JtiStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let PasswordStoreImpl::Memory(passwords) = state.passwords.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let RecoveryStoreImpl::Memory(recovery) = state.recovery.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let MagicLinkStoreImpl::Memory(magic_links) = state.magic_links.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let InvitationStoreImpl::Memory(invitations) = state.invitations.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let MessageOutboxImpl::Memory(messages) = state.messages.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let CibaStoreImpl::Memory(ciba) = state.ciba.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let DeviceStoreImpl::Memory(device) = state.device.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let ParStoreImpl::Memory(par) = state.par.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let replay = match state.replay_store.as_deref() {
        Some(ReplayStoreImpl::Memory(replay)) => Some(replay),
        #[cfg(feature = "aws")]
        Some(ReplayStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let AuthzSessionStoreImpl::Memory(authz_sessions) = state.authz_sessions.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let GrantStoreImpl::Memory(grants) = state.grants.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let DomainMapStoreImpl::Memory(domain_map) = state.domain_map.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let PolicyArtifactStoreImpl::Memory(policy_artifacts) = state.policy_artifacts.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let PolicyVersionStoreImpl::Memory(policy_versions) = state.policy_versions.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };
    let rate_limit = match state.rate_limit.as_deref() {
        Some(RateLimitStoreImpl::Memory(rate_limit)) => Some(rate_limit),
        #[cfg(feature = "aws")]
        Some(RateLimitStoreImpl::Dynamo(_)) => return Err(backend_mismatch("Memory")),
        None => None,
    };
    let SsfStoreImpl::Memory(ssf) = state.ssf.as_ref() else {
        return Err(backend_mismatch("Memory"));
    };

    Ok(crate::adapters::memory::MemoryGovernanceTenantDataPlane {
        governance,
        users,
        clients,
        initial_access_tokens,
        scim_groups,
        federation_config,
        federation_attribute_mappings,
        workload_trust,
        admin_auth,
        federation_flow,
        codes,
        sessions,
        refresh,
        grace,
        passkey_challenges,
        passkeys,
        jtis,
        passwords,
        recovery,
        magic_links,
        invitations,
        messages,
        ciba,
        device,
        par,
        replay,
        authz_sessions,
        grants,
        domain_map,
        policy_artifacts,
        policy_versions,
        rate_limit,
        ssf,
    })
}

#[cfg(feature = "aws")]
struct DynamoTenantPlane<'a> {
    governance: &'a crate::adapters::aws::DynamoGovernanceStore,
    users: &'a crate::adapters::aws::DynamoUsersStore,
    clients: &'a crate::adapters::aws::DynamoClientStore,
    initial_access_tokens: &'a crate::adapters::aws::DynamoInitialAccessTokenStore,
    scim_groups: &'a crate::adapters::aws::DynamoScimGroupsStore,
    federation_config: &'a crate::adapters::aws::DynamoFederationConfigStore,
    federation_attribute_mappings: &'a crate::adapters::aws::DynamoFederationAttributeMappingsStore,
    workload_trust: &'a crate::adapters::aws::DynamoWorkloadTrustStore,
    admin_auth: &'a crate::adapters::aws::DynamoAdminAuthStore,
    federation_flow: &'a crate::adapters::aws::DynamoFederationFlowStore,
    codes: &'a crate::adapters::aws::DynamoCodeStore,
    sessions: &'a crate::adapters::aws::DynamoSessionStore,
    refresh: &'a crate::adapters::aws::DynamoRefreshStore,
    grace: Option<&'a crate::adapters::aws::DynamoGraceStore>,
    passkey_challenges: &'a crate::adapters::aws::DynamoPasskeyChallengeStore,
    passkeys: &'a crate::adapters::aws::DynamoPasskeyStore,
    jtis: Option<&'a crate::adapters::aws::DynamoJtiStore>,
    passwords: &'a crate::adapters::aws::DynamoPasswordStore,
    recovery: &'a crate::adapters::aws::DynamoRecoveryStore,
    magic_links: &'a crate::adapters::aws::DynamoMagicLinkStore,
    invitations: &'a crate::adapters::aws::DynamoInvitationStore,
    messages: &'a crate::adapters::aws::DynamoNotifier,
    ciba: &'a crate::adapters::aws::DynamoCibaStore,
    device: &'a crate::adapters::aws::DynamoDeviceStore,
    par: &'a crate::adapters::aws::DynamoParStore,
    replay: Option<&'a crate::adapters::aws::DynamoReplayStore>,
    authz_sessions: &'a crate::adapters::aws::DynamoAuthzSessionStore,
    grants: &'a crate::adapters::aws::DynamoGrantStore,
    domain_map: &'a crate::adapters::aws::DynamoDomainMapStore,
    policy_artifacts: &'a crate::adapters::aws::DynamoPolicyArtifactStore,
    policy_versions: &'a crate::adapters::aws::DynamoPolicyVersionStore,
    rate_limit: Option<&'a crate::adapters::aws::DynamoRateLimitStore>,
    ssf: &'a crate::adapters::aws::DynamoSsfStore,
}

#[cfg(feature = "aws")]
fn dynamo_tenant_plane(state: &AppState) -> Result<DynamoTenantPlane<'_>, StoreError> {
    let GovernanceStoreImpl::Dynamo(governance) = state.governance.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let UsersStoreImpl::Dynamo(users) = state.users.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let ClientStoreImpl::Dynamo(clients) = state.clients.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let InitialAccessTokenStoreImpl::Dynamo(initial_access_tokens) =
        state.initial_access_tokens.as_ref()
    else {
        return Err(backend_mismatch("Dynamo"));
    };
    let ScimGroupsStoreImpl::Dynamo(scim_groups) = state.scim_groups.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let FederationConfigStoreImpl::Dynamo(federation_config) = state.federation_config.as_ref()
    else {
        return Err(backend_mismatch("Dynamo"));
    };
    let FederationAttributeMappingsStoreImpl::Dynamo(federation_attribute_mappings) =
        state.federation_attribute_mappings.as_ref()
    else {
        return Err(backend_mismatch("Dynamo"));
    };
    let WorkloadTrustStoreImpl::Dynamo(workload_trust) = state.workload_trust.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let AdminAuthStoreImpl::Dynamo(admin_auth) = state.admin_auth.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let FederationFlowStoreImpl::Dynamo(federation_flow) = state.federation_flow.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let CodeStoreImpl::Dynamo(codes) = state.codes.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let SessionStoreImpl::Dynamo(sessions) = state.sessions.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let RefreshStoreImpl::Dynamo(refresh) = state.refresh.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let grace = match state.grace.as_deref() {
        Some(GraceStoreImpl::Dynamo(grace)) => Some(grace),
        Some(GraceStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let PasskeyChallengeStoreImpl::Dynamo(passkey_challenges) = state.passkey_challenges.as_ref()
    else {
        return Err(backend_mismatch("Dynamo"));
    };
    let PasskeyStoreImpl::Dynamo(passkeys) = state.passkeys.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let jtis = match state.jti_store.as_deref() {
        Some(JtiStoreImpl::Dynamo(jtis)) => Some(jtis),
        Some(JtiStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let PasswordStoreImpl::Dynamo(passwords) = state.passwords.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let RecoveryStoreImpl::Dynamo(recovery) = state.recovery.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let MagicLinkStoreImpl::Dynamo(magic_links) = state.magic_links.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let InvitationStoreImpl::Dynamo(invitations) = state.invitations.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let MessageOutboxImpl::Dynamo(messages) = state.messages.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let CibaStoreImpl::Dynamo(ciba) = state.ciba.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let DeviceStoreImpl::Dynamo(device) = state.device.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let ParStoreImpl::Dynamo(par) = state.par.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let replay = match state.replay_store.as_deref() {
        Some(ReplayStoreImpl::Dynamo(replay)) => Some(replay),
        Some(ReplayStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let AuthzSessionStoreImpl::Dynamo(authz_sessions) = state.authz_sessions.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let GrantStoreImpl::Dynamo(grants) = state.grants.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let DomainMapStoreImpl::Dynamo(domain_map) = state.domain_map.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let PolicyArtifactStoreImpl::Dynamo(policy_artifacts) = state.policy_artifacts.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let PolicyVersionStoreImpl::Dynamo(policy_versions) = state.policy_versions.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };
    let rate_limit = match state.rate_limit.as_deref() {
        Some(RateLimitStoreImpl::Dynamo(rate_limit)) => Some(rate_limit),
        Some(RateLimitStoreImpl::Memory(_)) => return Err(backend_mismatch("Dynamo")),
        None => None,
    };
    let SsfStoreImpl::Dynamo(ssf) = state.ssf.as_ref() else {
        return Err(backend_mismatch("Dynamo"));
    };

    Ok(DynamoTenantPlane {
        governance,
        users,
        clients,
        initial_access_tokens,
        scim_groups,
        federation_config,
        federation_attribute_mappings,
        workload_trust,
        admin_auth,
        federation_flow,
        codes,
        sessions,
        refresh,
        grace,
        passkey_challenges,
        passkeys,
        jtis,
        passwords,
        recovery,
        magic_links,
        invitations,
        messages,
        ciba,
        device,
        par,
        replay,
        authz_sessions,
        grants,
        domain_map,
        policy_artifacts,
        policy_versions,
        rate_limit,
        ssf,
    })
}

pub(crate) async fn cleanup_tenant_stage(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
    stage: TenantCleanupStage,
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<u64, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => {
            memory_tenant_plane(state)?
                .cleanup_stage(logical_tenant, data_tenant, stage, fence, now)
                .await
        }
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            cleanup_dynamo_tenant_stage(
                &dynamo_tenant_plane(state)?,
                logical_tenant,
                data_tenant,
                stage,
                fence,
                now,
            )
            .await
        }
    }
}

#[cfg(feature = "aws")]
async fn cleanup_dynamo_tenant_stage(
    plane: &DynamoTenantPlane<'_>,
    logical_tenant: &str,
    data_tenant: &str,
    stage: TenantCleanupStage,
    fence: &GovernanceDestructiveFence,
    now: i64,
) -> Result<u64, StoreError> {
    let mut removed = 0usize;
    match stage {
        TenantCleanupStage::Clients => {
            for client in plane.clients.list(data_tenant).await? {
                for binding in plane.domain_map.list_by_client(&client.client_id).await? {
                    removed = removed.saturating_add(
                        plane
                            .domain_map
                            .governance_delete_if_owner_fenced(
                                plane.governance,
                                logical_tenant,
                                fence,
                                now,
                                logical_tenant,
                                &binding.domain,
                                &client.client_id,
                            )
                            .await?,
                    );
                }
                removed = removed.saturating_add(
                    plane
                        .authz_sessions
                        .governance_delete_by_client_fenced(
                            plane.governance,
                            logical_tenant,
                            fence,
                            now,
                            data_tenant,
                            &client.client_id,
                        )
                        .await?,
                );
                if let Some(rate_limit) = plane.rate_limit {
                    removed = removed.saturating_add(
                        rate_limit
                            .governance_delete_fenced(
                                plane.governance,
                                logical_tenant,
                                fence,
                                now,
                                &crate::tenant::tpk(data_tenant, &client.client_id),
                            )
                            .await?,
                    );
                }
                removed = removed.saturating_add(
                    plane
                        .clients
                        .governance_delete_fenced(
                            plane.governance,
                            logical_tenant,
                            fence,
                            now,
                            data_tenant,
                            &client.client_id,
                        )
                        .await?,
                );
            }
            if let Some(rate_limit) = plane.rate_limit {
                removed = removed.saturating_add(
                    rate_limit
                        .governance_delete_all_by_tenant_fenced(
                            plane.governance,
                            logical_tenant,
                            fence,
                            now,
                            data_tenant,
                        )
                        .await?,
                );
            }
        }
        TenantCleanupStage::InitialAccessTokens => {
            for ticket in plane.initial_access_tokens.list(data_tenant).await? {
                removed = removed.saturating_add(
                    plane
                        .initial_access_tokens
                        .governance_delete_fenced(
                            plane.governance,
                            logical_tenant,
                            fence,
                            now,
                            data_tenant,
                            &ticket.token_id,
                        )
                        .await?,
                );
            }
        }
        TenantCleanupStage::DirectoryGroups => {
            removed = removed.saturating_add(
                plane
                    .scim_groups
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        data_tenant,
                        fence,
                        now,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::Federation => {
            removed = removed.saturating_add(
                plane
                    .federation_config
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .federation_attribute_mappings
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::WorkloadTrust => {
            removed = removed.saturating_add(
                plane
                    .workload_trust
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::AdminAuthority => {
            removed = removed.saturating_add(
                plane
                    .admin_auth
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::ProtocolState => {
            removed = removed.saturating_add(
                plane
                    .federation_flow
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .codes
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .sessions
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            let family_ids = plane
                .refresh
                .governance_family_ids_by_tenant(data_tenant)
                .await?;
            if let Some(grace) = plane.grace {
                for family_id in &family_ids {
                    removed = removed.saturating_add(
                        grace
                            .governance_delete_family_fenced(
                                plane.governance,
                                logical_tenant,
                                fence,
                                now,
                                family_id,
                            )
                            .await?,
                    );
                }
            }
            removed = removed.saturating_add(
                plane
                    .refresh
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .passkey_challenges
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .passkeys
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            if let Some(jtis) = plane.jtis {
                removed = removed.saturating_add(
                    jtis.governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
                );
            }
            removed = removed.saturating_add(
                plane
                    .passwords
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .recovery
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .invitations
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .magic_links
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .messages
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .ciba
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .device
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .par
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            if let Some(replay) = plane.replay {
                removed = removed.saturating_add(
                    replay
                        .governance_delete_all_by_tenant_fenced(
                            plane.governance,
                            logical_tenant,
                            fence,
                            now,
                            data_tenant,
                        )
                        .await?,
                );
            }
            removed = removed.saturating_add(
                plane
                    .authz_sessions
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::PolicyAndDomains => {
            removed = removed.saturating_add(
                plane
                    .grants
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .domain_map
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        logical_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .policy_artifacts
                    .governance_delete_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
            removed = removed.saturating_add(
                plane
                    .policy_versions
                    .governance_delete_fenced(
                        plane.governance,
                        logical_tenant,
                        fence,
                        now,
                        data_tenant,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::SharedSignals => {
            removed = removed.saturating_add(
                plane
                    .ssf
                    .governance_revoke_all_by_tenant_fenced(
                        plane.governance,
                        logical_tenant,
                        logical_tenant,
                        fence,
                        now,
                    )
                    .await?,
            );
        }
        TenantCleanupStage::Users
        | TenantCleanupStage::SigningKeysAndSecrets
        | TenantCleanupStage::Complete => {
            return Err(StoreError::Permanent(
                "tenant cleanup stage is not a governance data-plane stage".into(),
            ));
        }
    }
    u64::try_from(removed)
        .map_err(|_| StoreError::Permanent("tenant cleanup count exceeds u64".into()))
}

pub(crate) async fn inventory_tenant_authority(
    state: &AppState,
    logical_tenant: &str,
    data_tenant: &str,
) -> Result<GovernanceInventory, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => {
            let mut inventory = memory_tenant_plane(state)?
                .inventory_tenant(logical_tenant, data_tenant)
                .await?;
            let retained_keys = inventory
                .keys()
                .filter(|key| key.ends_with("_retained"))
                .cloned()
                .collect::<Vec<_>>();
            let mut retained_counts = BTreeMap::new();
            for key in retained_keys {
                if let Some(count) = inventory.remove(&key) {
                    retained_counts.insert(key, count);
                }
            }
            Ok(GovernanceInventory {
                live_counts: inventory,
                retained_counts,
            })
        }
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            inventory_dynamo_tenant(&dynamo_tenant_plane(state)?, logical_tenant, data_tenant).await
        }
    }
}

pub(crate) async fn first_tenant_user(
    state: &AppState,
    data_tenant: &str,
) -> Result<Option<UserRecord>, StoreError> {
    match state.governance.as_ref() {
        GovernanceStoreImpl::Memory(_) => Ok(memory_user_plane(state)?
            .users
            .list(
                data_tenant,
                1,
                None,
                None,
                crate::ports::UserListStatusFilter::All,
            )
            .await?
            .0
            .into_iter()
            .next()),
        #[cfg(feature = "aws")]
        GovernanceStoreImpl::Dynamo(_) => {
            dynamo_user_plane(state)?
                .users
                .governance_first_user(data_tenant)
                .await
        }
    }
}

#[cfg(feature = "aws")]
async fn inventory_dynamo_tenant(
    plane: &DynamoTenantPlane<'_>,
    logical_tenant: &str,
    data_tenant: &str,
) -> Result<GovernanceInventory, StoreError> {
    let mut live = BTreeMap::new();
    let mut retained = BTreeMap::new();

    let identities = plane
        .users
        .governance_tenant_identity_inventory(data_tenant)
        .await?;
    add_count(&mut live, "identities", identities.canonical_rows)?;
    add_count(
        &mut live,
        "identity_aliases",
        identities
            .scim_alias_rows
            .saturating_add(identities.scim_create_claim_rows),
    )?;
    add_count(
        &mut live,
        "clients",
        plane
            .clients
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "initial_access_tokens",
        plane
            .initial_access_tokens
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    let scim = plane
        .scim_groups
        .governance_tenant_inventory(data_tenant)
        .await?;
    add_count(&mut live, "directory_group_rows", scim.group_rows)?;
    add_count(&mut live, "directory_group_aliases", scim.alias_rows)?;
    add_count(
        &mut live,
        "directory_group_memberships",
        scim.membership_rows,
    )?;
    add_count(&mut live, "directory_groups_live", scim.live_groups)?;
    add_count(&mut live, "directory_group_roles", scim.role_index_rows)?;
    add_count(
        &mut live,
        "federation_configs",
        plane
            .federation_config
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "federation_attribute_mapping_rows",
        plane
            .federation_attribute_mappings
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "workload_trust",
        plane
            .workload_trust
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "admin_authority",
        plane
            .admin_auth
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "federation_flows",
        plane
            .federation_flow
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "codes",
        plane
            .codes
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "sessions",
        plane
            .sessions
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    let family_ids = plane
        .refresh
        .governance_family_ids_by_tenant(data_tenant)
        .await?;
    add_count(&mut live, "refresh_families", family_ids.len())?;
    let mut grace_rows = 0usize;
    if let Some(grace) = plane.grace {
        for family_id in &family_ids {
            grace_rows = grace_rows.saturating_add(grace.governance_count_family(family_id).await?);
        }
    }
    add_count(&mut live, "refresh_grace", grace_rows)?;
    add_count(
        &mut live,
        "passkey_challenges",
        plane
            .passkey_challenges
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "passkeys",
        plane
            .passkeys
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    let jtis = if let Some(jtis) = plane.jtis {
        jtis.governance_count_all_by_tenant(logical_tenant).await?
    } else {
        0
    };
    add_count(&mut live, "jtis", jtis)?;
    add_count(
        &mut live,
        "passwords",
        plane
            .passwords
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "recovery",
        plane
            .recovery
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "invitations",
        plane
            .invitations
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "magic_links",
        plane
            .magic_links
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "messages",
        plane
            .messages
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "ciba",
        plane
            .ciba
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "device_grants",
        plane
            .device
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "par",
        plane
            .par
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    let replay = if let Some(replay) = plane.replay {
        replay.governance_count_all_by_tenant(data_tenant).await?
    } else {
        0
    };
    add_count(&mut live, "replay", replay)?;
    add_count(
        &mut live,
        "authz_sessions",
        plane
            .authz_sessions
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "grants",
        plane
            .grants
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "domains",
        plane
            .domain_map
            .governance_count_all_by_tenant(logical_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "policy_artifacts",
        plane
            .policy_artifacts
            .governance_count_all_by_tenant(data_tenant)
            .await?,
    )?;
    add_count(
        &mut live,
        "policy_versions",
        plane.policy_versions.governance_count(data_tenant).await?,
    )?;
    let rate_limits = if let Some(rate_limit) = plane.rate_limit {
        rate_limit
            .governance_count_all_by_tenant(data_tenant)
            .await?
    } else {
        0
    };
    add_count(&mut live, "rate_limits", rate_limits)?;

    let ssf = plane
        .ssf
        .governance_tenant_inventory(logical_tenant)
        .await?;
    add_count(&mut live, "ssf_streams_live", ssf.live_streams)?;
    add_count(&mut live, "ssf_deliveries_live", ssf.live_deliveries)?;
    add_count(
        &mut retained,
        "ssf_stream_tombstones_retained",
        ssf.revoked_stream_tombstones,
    )?;
    add_count(
        &mut retained,
        "ssf_delivery_tombstones_retained",
        ssf.suppressed_delivery_tombstones,
    )?;
    add_count(
        &mut retained,
        "ssf_delivery_audit_retained",
        ssf.terminal_retained_deliveries,
    )?;
    add_count(&mut retained, "ssf_registry_retained", ssf.registry_rows)?;

    Ok(GovernanceInventory {
        live_counts: live,
        retained_counts: retained,
    })
}
