//! 统一 active-user gate(spec 003 §1.4,评审 codex #1 Blocker)。
//!
//! admin disable/delete(tombstone)后,**所有**建 AS 会话 / 签用户 token / 发或换 code 的入口
//! MUST 先过 `require_active_user`:查 `UserRecord.status`,`Active` 放行,`Disabled`/`Tombstoned`/
//! **查询失败** → fail-closed 拒(不建会话、不签 token、不 consume code)。
//!
//! **范围(canonical-user 落地后,SaaS 审计 K)**:gate 覆盖**所有人类用户**——本地 email 用户
//! (`user:{email}`)**与联邦用户**(`user:fed:*`,现已由联邦登录落 UserRecord)。二者都按 `user_id`
//! 查 `UserRecord.status`。**非 `user:` 前缀主体**(workload/agent,无 UserRecord、非人类)仍 `Allowed`
//! (它们不受本 gate 管辖)。记录不存在 → `Allowed`(JIT 首登未落表的合法窗)。
//!
//! fail-closed 的粒度区分(供调用方映射不同状态码):
//! - `Disabled`/`Tombstoned` = 明确拒(通常 403 / 拒登录);
//! - 查询失败(store error)= 瞬时不可用(503),**绝不放行**(防 disable 期间 store 抖动被绕过)。

use crate::ports::{PasswordStore, SessionStore, UserStatus, UsersStore};
use crate::state::AppState;
use axum::http::StatusCode;

pub(crate) const CREDENTIAL_CHANGE_LEASE_SECS: i64 = 300;

/// `require_active_user` 的判定结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UserGate {
    /// 放行:Active、尚未 JIT 落表的人类用户,或无 UserRecord 的机器主体。
    Allowed,
    /// 明确拒:该用户被 admin disable/delete(tombstone)。
    Blocked,
    /// 瞬时不可用:UserRecord 查询失败(fail-closed,不放行)。
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordGate {
    Allowed,
    ChangeRequired,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuthority {
    Allowed,
    AccountBlocked,
    PasswordChangeRequired,
    Unavailable,
}

/// Map a rejected session authority to the consistent interactive-login error.
pub fn session_authority_error(authority: SessionAuthority) -> Option<(StatusCode, &'static str)> {
    match authority {
        SessionAuthority::Allowed => None,
        SessionAuthority::AccountBlocked => Some((StatusCode::FORBIDDEN, "account disabled")),
        SessionAuthority::PasswordChangeRequired => {
            Some((StatusCode::FORBIDDEN, "password change required"))
        }
        SessionAuthority::Unavailable => {
            Some((StatusCode::SERVICE_UNAVAILABLE, "store unavailable"))
        }
    }
}

/// 尽力而为记录 AS 成功建立用户认证会话的时刻。
///
/// 观测写失败不得把已经完成的认证反向变成失败;固定标记供 CloudWatch metric filter 告警。
pub async fn touch_last_login(state: &AppState, tenant: &str, user_id: &str, now: i64) {
    if let Err(error) = state.users.touch_last_login(tenant, user_id, now).await {
        eprintln!("TOUCH_LAST_LOGIN_FAIL tenant={tenant} err={error:?}");
    }
}

/// 判断 `user_id` 是否为受 gate 管辖的**人类用户**(canonical-user,审计 K)。
///
/// 覆盖本地 email 用户(`user:{email}`)**与联邦用户**(`user:fed:*`)——二者现都有 UserRecord。
/// **非 `user:` 前缀**(workload:/agent: 等机器主体,无 UserRecord)不受管辖 → 调用方 Allowed。
pub(crate) fn is_human_user(user_id: &str) -> bool {
    user_id.starts_with("user:")
}

/// 统一 active-user gate(spec 003 §1.4)。
///
/// **人类用户**(本地 email + 联邦 `user:fed:*`,审计 K):查 UserRecord.status——Active→`Allowed`;
/// Disabled/Tombstoned→`Blocked`;查询失败→`Unavailable`(fail-closed);**记录不存在→`Allowed`**
/// (JIT 尚未落表的首登合法,首登会 `create_or_get_by_*` 建 Active——不存在 ≠ 被禁,不能拒首登)。
///
/// **非 `user:` 主体**(workload/agent 等机器身份,无 UserRecord):直接 `Allowed`(不受本 gate 管辖)。
pub async fn require_active_user(state: &AppState, tenant: &str, user_id: &str) -> UserGate {
    match active_user_epoch(state, tenant, user_id).await {
        Ok(_) => UserGate::Allowed,
        Err(gate) => gate,
    }
}

/// Return the active user's current lifecycle generation using the same strong
/// read as the account-status gate. Non-human and pre-JIT identities use epoch 0.
pub async fn active_user_epoch(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<u64, UserGate> {
    active_user_epoch_with_missing(state, tenant, user_id, true).await
}

/// Return the lifecycle generation only when a human user's canonical record
/// still exists. Authorization-session binding cannot use the pre-JIT
/// missing-user exception because erasure physically removes the same record.
pub async fn active_existing_user_epoch(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<u64, UserGate> {
    active_user_epoch_with_missing(state, tenant, user_id, false).await
}

/// Return the lifecycle generation only when a credential's canonical user
/// record still exists, regardless of the canonical ID's prefix.
pub async fn active_existing_canonical_user_epoch(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<u64, UserGate> {
    active_canonical_user_epoch_with_missing(state, tenant, user_id, false).await
}

async fn active_user_epoch_with_missing(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    allow_missing_human: bool,
) -> Result<u64, UserGate> {
    if !is_human_user(user_id) {
        return Ok(0);
    }
    active_canonical_user_epoch_with_missing(state, tenant, user_id, allow_missing_human).await
}

async fn active_canonical_user_epoch_with_missing(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    allow_missing: bool,
) -> Result<u64, UserGate> {
    match state.users.get_by_id(tenant, user_id).await {
        Ok(Some(rec)) if rec.status == UserStatus::Active && !rec.revocation_pending => {
            Ok(rec.credential_epoch)
        }
        Ok(Some(rec)) if rec.status == UserStatus::Active => {
            let now = crate::current_unix_secs();
            let started_before = now.saturating_sub(CREDENTIAL_CHANGE_LEASE_SECS);
            if rec.updated_at > started_before {
                return Err(UserGate::Unavailable);
            }
            match state
                .users
                .recover_expired_credential_change(
                    tenant,
                    user_id,
                    rec.credential_epoch,
                    started_before,
                    now,
                )
                .await
            {
                Ok(true) => Ok(rec.credential_epoch),
                Ok(false) | Err(_) => Err(UserGate::Unavailable),
            }
        }
        Ok(Some(_)) => Err(UserGate::Blocked),
        Ok(None) if allow_missing => Ok(0),
        Ok(None) => Err(UserGate::Blocked),
        Err(_) => Err(UserGate::Unavailable),
    }
}

/// Require an artifact's captured generation to match the active user.
pub async fn require_active_user_epoch(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    expected_epoch: u64,
) -> Result<(), UserGate> {
    match active_user_epoch(state, tenant, user_id).await {
        Ok(epoch) if epoch == expected_epoch => Ok(()),
        Ok(_) => Err(UserGate::Blocked),
        Err(gate) => Err(gate),
    }
}

/// Version encoded into newly issued password-capable authorization artifacts.
/// Version zero means the user had no password credential at approval.
pub async fn password_authority_snapshot(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> Result<Option<u64>, PasswordGate> {
    if !crate::local_identity::is_password_capable_user_id(user_id) {
        return Ok(None);
    }
    match state.passwords.get(tenant, user_id).await {
        Ok(Some(credential))
            if credential.user_id == user_id
                && !credential.must_change
                && !credential.revocation_pending =>
        {
            Ok(Some(credential.version))
        }
        Ok(None) => Ok(Some(0)),
        Ok(Some(_)) => Err(PasswordGate::ChangeRequired),
        Err(_) => Err(PasswordGate::Unavailable),
    }
}

/// Require the current password authority to match an authorization artifact.
/// Password-capable legacy records without a version fail closed: all newly
/// issued artifacts carry `Some(version)`, including `Some(0)` when no
/// password credential existed at approval.
pub async fn require_password_authority_version(
    state: &AppState,
    tenant: &str,
    user_id: &str,
    expected_version: Option<u64>,
) -> PasswordGate {
    if !crate::local_identity::is_password_capable_user_id(user_id) {
        return PasswordGate::Allowed;
    }
    match state.passwords.get(tenant, user_id).await {
        Ok(Some(credential)) if credential.user_id != user_id => PasswordGate::Unavailable,
        Ok(Some(credential)) if credential.must_change || credential.revocation_pending => {
            PasswordGate::ChangeRequired
        }
        Ok(Some(credential)) if expected_version == Some(credential.version) => {
            PasswordGate::Allowed
        }
        Ok(None) if expected_version == Some(0) => PasswordGate::Allowed,
        Ok(Some(_)) | Ok(None) => PasswordGate::ChangeRequired,
        Err(_) => PasswordGate::Unavailable,
    }
}

/// Existing authentication state must not bypass an Admin temporary-password
/// reset. Physical session/refresh revocation remains cleanup; this credential
/// gate is the fail-closed authority when a cascade is delayed or fails.
pub async fn require_password_change_complete(
    state: &AppState,
    tenant: &str,
    user_id: &str,
) -> PasswordGate {
    if !crate::local_identity::is_password_capable_user_id(user_id) {
        return PasswordGate::Allowed;
    }
    match state.passwords.get(tenant, user_id).await {
        Ok(Some(credential)) if credential.user_id != user_id => PasswordGate::Unavailable,
        Ok(Some(credential)) if credential.must_change || credential.revocation_pending => {
            PasswordGate::ChangeRequired
        }
        Ok(Some(_)) | Ok(None) => PasswordGate::Allowed,
        Err(_) => PasswordGate::Unavailable,
    }
}

/// Recheck authority after a session write to close reset/disable races. A
/// rejected session is deleted before the caller can emit its cookie.
pub async fn validate_session_authority(
    state: &AppState,
    tenant: &str,
    session_id: &str,
    user_id: &str,
) -> SessionAuthority {
    validate_session_authority_with_user_policy(state, tenant, session_id, user_id, false).await
}

/// Recheck authority for credential-backed login, where the canonical user
/// record must still exist and carry the session's exact lifecycle generation.
pub async fn validate_existing_session_authority(
    state: &AppState,
    tenant: &str,
    session_id: &str,
    user_id: &str,
) -> SessionAuthority {
    validate_session_authority_with_user_policy(state, tenant, session_id, user_id, true).await
}

async fn validate_session_authority_with_user_policy(
    state: &AppState,
    tenant: &str,
    session_id: &str,
    user_id: &str,
    require_existing_user: bool,
) -> SessionAuthority {
    let session = match state.sessions.get(tenant, session_id).await {
        Ok(Some(session)) if session.user_id == user_id => session,
        Ok(_) | Err(_) => return SessionAuthority::Unavailable,
    };
    let active_epoch = if require_existing_user {
        active_existing_canonical_user_epoch(state, tenant, user_id).await
    } else {
        active_user_epoch(state, tenant, user_id).await
    };
    let authority = match active_epoch {
        Ok(epoch) if epoch == session.credential_epoch => {
            match require_password_change_complete(state, tenant, user_id).await {
                PasswordGate::Allowed => SessionAuthority::Allowed,
                PasswordGate::ChangeRequired => SessionAuthority::PasswordChangeRequired,
                PasswordGate::Unavailable => SessionAuthority::Unavailable,
            }
        }
        Ok(_) | Err(UserGate::Blocked) => SessionAuthority::AccountBlocked,
        Err(UserGate::Unavailable) => SessionAuthority::Unavailable,
        Err(UserGate::Allowed) => unreachable!(),
    };
    if authority != SessionAuthority::Allowed {
        let _ = state.sessions.delete(tenant, session_id).await;
    }
    authority
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_email_user_is_gated() {
        assert!(is_human_user("user:alice@example.com"));
        assert!(is_human_user("user:bob@x.io"));
    }

    #[test]
    fn federated_user_is_now_gated() {
        // canonical-user(审计 K):联邦用户现有 UserRecord,**纳入 gate**(可被 disable/delete)。
        assert!(is_human_user("user:fed:abcdef123456"));
        assert!(is_human_user("user:fed:v1:xyz"));
    }

    #[test]
    fn machine_subject_is_not_gated() {
        // workload/agent 等机器主体无 UserRecord、非人类用户 → 不受 gate 管辖。
        assert!(!is_human_user("workload:spiffe://x"));
        assert!(!is_human_user("agent:foo"));
        assert!(!is_human_user(""));
    }

    #[tokio::test]
    async fn legacy_existing_user_epoch_keeps_nonhuman_epoch_zero_exception() {
        let state = crate::AppState::dev("localhost");
        for user_id in ["alice", "workload:spiffe://x", "agent:foo"] {
            assert_eq!(
                active_existing_user_epoch(&state, "", user_id).await,
                Ok(0),
                "{user_id}"
            );
        }
    }

    #[test]
    fn session_authority_errors_are_consistent() {
        assert_eq!(session_authority_error(SessionAuthority::Allowed), None);
        assert_eq!(
            session_authority_error(SessionAuthority::AccountBlocked),
            Some((StatusCode::FORBIDDEN, "account disabled"))
        );
        assert_eq!(
            session_authority_error(SessionAuthority::PasswordChangeRequired),
            Some((StatusCode::FORBIDDEN, "password change required"))
        );
        assert_eq!(
            session_authority_error(SessionAuthority::Unavailable),
            Some((StatusCode::SERVICE_UNAVAILABLE, "store unavailable"))
        );
    }

    #[tokio::test]
    async fn temporary_password_blocks_existing_authentication_state() {
        use crate::ports::{PasswordCredential, PasswordStore, SessionRecord, SessionStore};

        let state = crate::AppState::dev("localhost");
        let user_id = "user:temporary@example.com";
        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id: user_id.to_string(),
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: true,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 1,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            require_password_change_complete(&state, "", user_id).await,
            PasswordGate::ChangeRequired
        );
        assert_eq!(
            require_password_change_complete(&state, "", "user:no-password@example.com").await,
            PasswordGate::Allowed
        );
        assert_eq!(
            require_password_change_complete(&state, "", "user:fed:temporary").await,
            PasswordGate::Allowed
        );

        let session_id = "pending-reset-session";
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.to_string(),
                    user_id: user_id.to_string(),
                    credential_epoch: 0,
                    auth_time: 1,
                    created_at: 1,
                    last_used_at: 1,
                    device: "Test browser".into(),
                    expires_at: i64::MAX,
                    acr: None,
                    amr: vec!["webauthn".to_string()],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            validate_session_authority(&state, "", session_id, user_id).await,
            SessionAuthority::PasswordChangeRequired
        );
        assert!(state.sessions.get("", session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn strict_session_authority_removes_inactive_arbitrary_canonical_users() {
        use crate::ports::{SessionRecord, SessionStore, UsersStore};

        let state = crate::AppState::dev("localhost");
        for (user_id, session_id, status) in [
            (
                "disabled-scim-canonical-id",
                "disabled-passkey-session",
                UserStatus::Disabled,
            ),
            (
                "tombstoned-scim-canonical-id",
                "tombstoned-passkey-session",
                UserStatus::Tombstoned,
            ),
        ] {
            state
                .users
                .create_or_get_by_id("", user_id, 1)
                .await
                .unwrap();
            state
                .sessions
                .create(
                    "",
                    SessionRecord {
                        session_id: session_id.to_string(),
                        user_id: user_id.to_string(),
                        credential_epoch: 0,
                        auth_time: 1,
                        created_at: 1,
                        last_used_at: 1,
                        device: "Test browser".into(),
                        expires_at: i64::MAX,
                        acr: None,
                        amr: vec!["webauthn".to_string()],
                    },
                )
                .await
                .unwrap();
            assert!(state
                .users
                .set_status("", user_id, status, 2)
                .await
                .unwrap());

            assert_eq!(
                validate_existing_session_authority(&state, "", session_id, user_id).await,
                SessionAuthority::AccountBlocked
            );
            assert!(state.sessions.get("", session_id).await.unwrap().is_none());
        }

        let removed_user_id = "removed-scim-canonical-id";
        let removed_session_id = "removed-passkey-session";
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: removed_session_id.to_string(),
                    user_id: removed_user_id.to_string(),
                    credential_epoch: 0,
                    auth_time: 1,
                    created_at: 1,
                    last_used_at: 1,
                    device: "Test browser".into(),
                    expires_at: i64::MAX,
                    acr: None,
                    amr: vec!["webauthn".to_string()],
                },
            )
            .await
            .unwrap();
        assert_eq!(
            validate_existing_session_authority(&state, "", removed_session_id, removed_user_id)
                .await,
            SessionAuthority::AccountBlocked
        );
        assert!(state
            .sessions
            .get("", removed_session_id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn strict_session_authority_removes_stale_arbitrary_canonical_epoch() {
        use crate::ports::{
            CredentialChangeOwner, CredentialChangeStart, SessionRecord, SessionStore, UsersStore,
        };

        let state = crate::AppState::dev("localhost");
        let user_id = "changed-scim-canonical-id";
        let session_id = "stale-passkey-session";
        state
            .users
            .create_or_get_by_id("", user_id, 1)
            .await
            .unwrap();
        assert_eq!(
            state
                .users
                .begin_credential_change("", user_id, 0, "changed-passkey-owner", 2)
                .await
                .unwrap(),
            CredentialChangeStart::Started { epoch: 1 }
        );
        assert!(state
            .users
            .complete_credential_change(
                "",
                user_id,
                CredentialChangeOwner {
                    epoch: 1,
                    operation_id: "changed-passkey-owner",
                },
                3,
            )
            .await
            .unwrap());
        state
            .sessions
            .create(
                "",
                SessionRecord {
                    session_id: session_id.to_string(),
                    user_id: user_id.to_string(),
                    credential_epoch: 0,
                    auth_time: 1,
                    created_at: 1,
                    last_used_at: 1,
                    device: "Test browser".into(),
                    expires_at: i64::MAX,
                    acr: None,
                    amr: vec!["webauthn".to_string()],
                },
            )
            .await
            .unwrap();

        assert_eq!(
            validate_existing_session_authority(&state, "", session_id, user_id).await,
            SessionAuthority::AccountBlocked
        );
        assert!(state.sessions.get("", session_id).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn password_authority_version_detects_reset_and_initial_provisioning() {
        use crate::ports::{PasswordCredential, PasswordStore};

        let state = crate::AppState::dev("localhost");
        let user_id = "user:versioned@example.com";
        assert_eq!(
            password_authority_snapshot(&state, "", user_id).await,
            Ok(Some(0))
        );
        assert_eq!(
            require_password_authority_version(&state, "", user_id, Some(0)).await,
            PasswordGate::Allowed
        );

        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id: user_id.to_string(),
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: false,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 2,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();

        assert_eq!(
            password_authority_snapshot(&state, "", user_id).await,
            Ok(Some(2))
        );
        assert_eq!(
            require_password_authority_version(&state, "", user_id, Some(2)).await,
            PasswordGate::Allowed
        );
        assert_eq!(
            require_password_authority_version(&state, "", user_id, Some(0)).await,
            PasswordGate::ChangeRequired
        );
        assert_eq!(
            require_password_authority_version(&state, "", user_id, Some(1)).await,
            PasswordGate::ChangeRequired
        );
        assert_eq!(
            require_password_authority_version(&state, "", user_id, None).await,
            PasswordGate::ChangeRequired,
            "unversioned local-user artifacts fail closed after migration"
        );
        assert_eq!(
            require_password_change_complete(&state, "", user_id).await,
            PasswordGate::Allowed,
            "session authority checks temporary state without treating it as an artifact"
        );

        let scim_user_id = "user:scim:opaque-canonical-id";
        assert_eq!(
            password_authority_snapshot(&state, "", scim_user_id).await,
            Ok(Some(0)),
            "SCIM canonical ids remain eligible for local password provisioning"
        );
        state
            .passwords
            .create_if_absent(
                "",
                PasswordCredential {
                    user_id: scim_user_id.to_string(),
                    password_hash: agent_auth_authn::password::dummy_hash().clone(),
                    must_change: false,
                    revocation_pending: false,
                    credential_change_id: None,
                    version: 4,
                    updated_at: 1,
                },
            )
            .await
            .unwrap();
        assert_eq!(
            password_authority_snapshot(&state, "", scim_user_id).await,
            Ok(Some(4))
        );
        assert_eq!(
            require_password_authority_version(&state, "", scim_user_id, Some(0)).await,
            PasswordGate::ChangeRequired
        );
        assert_eq!(
            require_password_authority_version(&state, "", scim_user_id, Some(4)).await,
            PasswordGate::Allowed
        );

        let federated_user_id = "user:fed:opaque-canonical-id";
        assert_eq!(
            password_authority_snapshot(&state, "", federated_user_id).await,
            Ok(None)
        );
        assert_eq!(
            require_password_authority_version(&state, "", federated_user_id, None).await,
            PasswordGate::Allowed
        );
    }
}
