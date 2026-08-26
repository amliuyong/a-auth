//! 进程内 e2e:SaaS 多租户数据面 tenant 分区隔离(spec 020 §2.3,C10.19)。
//!
//! 验证 `AGENT_AUTH_ENABLE_TENANT_PARTITIONING` 开启后,**每个 store 主键 + 每条二级路径**
//! (by-user / by-client / GSI)都按 tenant 物理隔离——租户 A 上下文绝不读到租户 B 的数据
//! (codex B1:`user:{email}` 等逻辑 id 跨租户碰撞,不 tenant-scope 会泄露)。
//!
//! 覆盖 14 类 store 具代表性的主键、二级查询与维护路径。Memory adapter 固定共享 port
//! 契约；生产 Dynamo 键序列化及 Host 派生 tenant 后的多 store HTTP 流程由独立测试固定。

use agent_auth_http::adapters::memory::{
    MemoryAuthzSessionStore, MemoryCibaStore, MemoryClientStore, MemoryCodeStore,
    MemoryDeviceStore, MemoryGrantStore, MemoryMagicLinkStore, MemoryPasskeyStore,
    MemoryRecoveryStore, MemoryRefreshStore, MemorySessionStore, MemoryUsersStore,
    MemoryWorkloadTrustStore,
};
use agent_auth_http::ports::{
    AuthzSessionRecord, AuthzSessionStore, CibaAuthRequest, CibaStore, ClientRecord, ClientStore,
    CodeRecord, CodeStore, DeviceAuthGrant, DeviceStore, GrantStore, LeaseAcquire, MagicLinkRecord,
    MagicLinkStore, PasskeyStore, RecoveryRecord, RecoveryStore, RefreshFamilyRecord, RefreshStore,
    SessionRecord, SessionStore, UsersStore, WorkloadTrustStore,
};
use agent_auth_http::state::{
    AuthzSessionStoreImpl, CibaStoreImpl, ClientStoreImpl, CodeStoreImpl, DeviceStoreImpl,
    GrantStoreImpl, MagicLinkStoreImpl, PasskeyStoreImpl, RecoveryStoreImpl, RefreshStoreImpl,
    SessionStoreImpl, UsersStoreImpl, WorkloadTrustStoreImpl,
};

const T1: &str = "t1";
const T2: &str = "t2";

fn client(id: &str) -> ClientRecord {
    ClientRecord {
        client_id: id.into(),
        redirect_uris: vec!["https://x/cb".into()],
        token_endpoint_auth_method: "none".into(),
        ..Default::default()
    }
}

fn authorization_code(code: &str) -> CodeRecord {
    CodeRecord {
        code: code.into(),
        client_id: "shared-client".into(),
        cimd_snapshot: None,
        redirect_uri: "https://app.example.com/cb".into(),
        code_challenge: "challenge".into(),
        resources: vec![],
        user_id: "user:alice@example.com".into(),
        scope: vec!["openid".into()],
        expires_at: i64::MAX,
        authz_session_id: None,
        nonce: None,
        auth_time: 1_000,
        authorization_details: vec![],
        acr: None,
        amr: vec![],
        credential_epoch: Some(0),
        password_credential_version: None,
    }
}

// authorization codes:主键、by-client 活跃引用和一次性消费状态均按 tenant 隔离。
#[tokio::test]
async fn authorization_codes_partitioned_by_tenant() {
    let s = CodeStoreImpl::Memory(MemoryCodeStore::default());
    s.put(T1, authorization_code("shared-code")).await.unwrap();

    assert_eq!(
        s.acquire_lease(T2, "shared-code", "t2-probe", 1_000, 1_060)
            .await
            .unwrap(),
        LeaseAcquire::NotFound,
        "t2 MUST NOT acquire t1's authorization code"
    );
    assert!(
        !s.has_unexpired_by_client(T2, "shared-client", 1_000)
            .await
            .unwrap(),
        "t2 MUST NOT observe t1's active code through the by-client authority path"
    );
    assert_eq!(
        s.delete_by_user(T2, "user:alice@example.com")
            .await
            .unwrap(),
        0,
        "t2 governance cleanup MUST NOT delete t1's authorization code"
    );

    s.put(T2, authorization_code("shared-code")).await.unwrap();
    assert!(s
        .has_unexpired_by_client(T1, "shared-client", 1_000)
        .await
        .unwrap());
    assert!(s
        .has_unexpired_by_client(T2, "shared-client", 1_000)
        .await
        .unwrap());

    assert!(matches!(
        s.acquire_lease(T1, "shared-code", "owner-t1", 1_000, 1_060)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    s.finalize(
        T1,
        "shared-code",
        "shared-client",
        i64::MAX,
        1_001,
        "owner-t1",
        Some("grant-t1"),
    )
    .await
    .unwrap();

    assert!(matches!(
        s.acquire_lease(T2, "shared-code", "owner-t2", 1_001, 1_061)
            .await
            .unwrap(),
        LeaseAcquire::Acquired(_)
    ));
    assert!(matches!(
        s.acquire_lease(T1, "shared-code", "t1-replay", 1_001, 1_061)
            .await
            .unwrap(),
        LeaseAcquire::AlreadyConsumed {
            issued_grant_id: Some(grant_id),
            ..
        } if grant_id == "grant-t1"
    ));

    assert_eq!(s.delete_all_by_tenant(T1).await.unwrap(), 1);
    assert_eq!(
        s.acquire_lease(T1, "shared-code", "t1-after-delete", 1_002, 1_062)
            .await
            .unwrap(),
        LeaseAcquire::NotFound
    );
    assert_eq!(
        s.acquire_lease(T2, "shared-code", "t2-still-owned", 1_002, 1_062)
            .await
            .unwrap(),
        LeaseAcquire::Locked,
        "deleting t1's partition MUST NOT mutate t2's in-flight code"
    );
}

// clients:同一 client_id 在 t1 建,t2 读不到;各自 list 只见自己。
#[tokio::test]
async fn clients_partitioned_by_tenant() {
    let s = ClientStoreImpl::Memory(MemoryClientStore::default());
    s.put(T1, client("shared-id")).await.unwrap();
    // 同 id t2 未建 → t2 读 None(物理隔离,不串)。
    assert!(s.get(T1, "shared-id").await.unwrap().is_some());
    assert!(
        s.get(T2, "shared-id").await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的 client(同 client_id 跨租户隔离)"
    );
    // t2 建同 id → 各自独立。
    s.put(T2, client("shared-id")).await.unwrap();
    assert_eq!(s.list(T1).await.unwrap().len(), 1);
    assert_eq!(s.list(T2).await.unwrap().len(), 1, "t2 list 只见自己那条");
}

// users:同一 email 跨租户是**不同用户**;get_by_email / get_by_id 按 tenant 隔离(codex B1)。
#[tokio::test]
async fn users_partitioned_by_tenant() {
    let s = UsersStoreImpl::Memory(MemoryUsersStore::default());
    let email = "alice@example.com";
    let uid = "user:alice@example.com";
    s.create_or_get_by_email(T1, email, uid, 1000)
        .await
        .unwrap();
    // t2 未建 → by-email / by-id 都读不到 t1 的(email/user_id 跨租户碰撞被隔离)。
    assert!(s.get_by_email(T1, email).await.unwrap().is_some());
    assert!(
        s.get_by_email(T2, email).await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的 user(同 email 跨租户是不同用户)"
    );
    assert!(s.get_by_id(T1, uid).await.unwrap().is_some());
    assert!(
        s.get_by_id(T2, uid).await.unwrap().is_none(),
        "t2 get_by_id MUST NOT 命中 t1 的 user"
    );
    // t2 建同 email → 独立记录;各租户 list 只见自己。
    s.create_or_get_by_email(T2, email, uid, 2000)
        .await
        .unwrap();
    assert_eq!(
        s.list(
            T1,
            50,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap()
        .0
        .len(),
        1
    );
    assert_eq!(
        s.list(
            T2,
            50,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap()
        .0
        .len(),
        1
    );
    assert!(s
        .set_status(
            T1,
            uid,
            agent_auth_http::ports::UserStatus::Tombstoned,
            3_000,
        )
        .await
        .unwrap());
    assert_eq!(
        s.list(
            T1,
            50,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::NonDeleted,
        )
        .await
        .unwrap()
        .0
        .len(),
        0,
        "t1 non-deleted filter excludes only t1's tombstone"
    );
    assert_eq!(
        s.list(
            T2,
            50,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::NonDeleted,
        )
        .await
        .unwrap()
        .0
        .len(),
        1,
        "t1 lifecycle changes cannot affect t2's matching page"
    );
}

// canonical-user(审计 K):联邦用户经 create_or_get_by_id 落表 → 可 get/list/disable + 纳入 gate;
// 跨租户隔离;email 为空不影响。
#[tokio::test]
async fn federated_user_canonical_managed() {
    use agent_auth_http::ports::UserStatus;
    let s = UsersStoreImpl::Memory(MemoryUsersStore::default());
    let fed = "user:fed:v1:abcdef";
    // 联邦登录落表(幂等)。
    let rec = s.create_or_get_by_id(T1, fed, 1000).await.unwrap();
    assert_eq!(rec.user_id, fed);
    assert_eq!(rec.email, "", "联邦用户 email 为空(F2:email 不参与身份)");
    assert_eq!(rec.status, UserStatus::Active);
    // 幂等:再调不覆盖 created_at。
    let rec2 = s.create_or_get_by_id(T1, fed, 9999).await.unwrap();
    assert_eq!(rec2.created_at, 1000, "幂等:不覆盖 created_at");
    // get/list 可见(不再隐形)。
    assert!(s.get_by_id(T1, fed).await.unwrap().is_some());
    assert_eq!(
        s.list(
            T1,
            50,
            None,
            None,
            agent_auth_http::ports::UserListStatusFilter::All,
        )
        .await
        .unwrap()
        .0
        .len(),
        1,
        "list 见联邦用户"
    );
    // 跨租户隔离:t2 读不到 t1 的联邦用户。
    assert!(
        s.get_by_id(T2, fed).await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的联邦用户(跨租户隔离)"
    );
    // admin disable → status=Disabled(可被治理,与本地用户对等)。
    assert!(s
        .set_status(T1, fed, UserStatus::Disabled, 2000)
        .await
        .unwrap());
    assert_eq!(
        s.get_by_id(T1, fed).await.unwrap().unwrap().status,
        UserStatus::Disabled,
        "联邦用户可被 admin disable"
    );
    // tombstone → 级联清属性(GDPR),终态不复活。
    assert!(s
        .set_status(T1, fed, UserStatus::Tombstoned, 3000)
        .await
        .unwrap());
    assert!(
        !s.set_status(T1, fed, UserStatus::Active, 4000)
            .await
            .unwrap(),
        "Tombstoned 终态不可复活"
    );
}

// grants:list_by_user 跨租户隔离(codex B1 主威胁:t1 user 列不到 t2 同名 user 的 Grant)。
#[tokio::test]
async fn grants_partitioned_by_tenant() {
    let s = GrantStoreImpl::Memory(MemoryGrantStore::default());
    let user = "user:alice@example.com";
    let mk = |gid: &str| agent_auth_grant::Grant {
        grant_id: gid.into(),
        client_id: "c".into(),
        user_id: user.into(),
        per_resource: vec![],
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 0,
        revision: 0,
        constraints: agent_auth_grant::GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec![],
            expires_at: i64::MAX,
        },
        status: agent_auth_grant::GrantStatus::Active,
    };
    s.put(T1, mk("g-t1")).await.unwrap();
    s.put(T2, mk("g-t2")).await.unwrap();
    // 同 grant_id 隔离 + 同 user_id 的 list 只见本租户。
    assert!(s.get(T1, "g-t1").await.unwrap().is_some());
    assert!(
        s.get(T2, "g-t1").await.unwrap().is_none(),
        "t2 读不到 t1 的 Grant"
    );
    let t1_grants = s.list_by_user(T1, user).await.unwrap();
    assert_eq!(t1_grants.len(), 1);
    assert_eq!(t1_grants[0].grant_id, "g-t1", "t1 只列到自己的 Grant");
    let t2_grants = s.list_by_user(T2, user).await.unwrap();
    assert_eq!(t2_grants.len(), 1);
    assert_eq!(
        t2_grants[0].grant_id, "g-t2",
        "t2 list_by_user(同 user_id)MUST 只见 t2 的 Grant,不泄露 t1"
    );
}

// refresh:by-user / by-client 吊销跨租户隔离;has_active_family_by_client 只见本租户。
#[tokio::test]
async fn refresh_partitioned_by_tenant() {
    let s = RefreshStoreImpl::Memory(MemoryRefreshStore::default());
    let mk = |fid: &str| RefreshFamilyRecord {
        family_id: fid.into(),
        current_version: 0,
        revoked: false,
        client_id: "c".into(),
        cimd_snapshot: None,
        user_id: "user:alice@example.com".into(),
        credential_epoch: 0,
        resources: vec![],
        scope: vec![],
        actor_allowlist: vec![],
        max_act_chain: 1,
        dpop_jkt: None,
        pkce_code_challenge: None,
        auth_time: None,
        acr: None,
        password_credential_version: Some(0),
    };
    s.create(T1, mk("fam-t1")).await.unwrap();
    s.create(T2, mk("fam-t2")).await.unwrap();
    // 同 family_id 隔离。
    assert!(s.get(T1, "fam-t1").await.unwrap().is_some());
    assert!(s.get(T2, "fam-t1").await.unwrap().is_none());
    // revoke_by_user(t1) 只吊 t1 的 family,不碰 t2 同名 user 的。
    let revoked = s
        .revoke_by_user(T1, "user:alice@example.com")
        .await
        .unwrap();
    assert_eq!(revoked, vec!["fam-t1".to_string()]);
    assert!(
        !s.get(T2, "fam-t2").await.unwrap().unwrap().revoked,
        "t2 family MUST 未被 t1 的 revoke_by_user 波及"
    );
    // has_active_family_by_client 各自只见本租户。
    assert!(s.has_active_family_by_client(T2, "c").await.unwrap());
    assert!(
        !s.has_active_family_by_client(T1, "c").await.unwrap(),
        "t1 的 family 已吊销 → t1 无活跃;t2 的不算进 t1"
    );
}

// sessions:by-user 吊销 + count 跨租户隔离。
#[tokio::test]
async fn sessions_partitioned_by_tenant() {
    let s = SessionStoreImpl::Memory(MemorySessionStore::default());
    let mk = |sid: &str| SessionRecord {
        session_id: sid.into(),
        user_id: "user:alice@example.com".into(),
        credential_epoch: 0,
        auth_time: 1000,
        created_at: 1000,
        last_used_at: 1000,
        device: "Test browser".into(),
        expires_at: i64::MAX,
        acr: None,
        amr: vec![],
    };
    s.create(T1, mk("sess-t1")).await.unwrap();
    s.create(T1, mk("sess-t1-other")).await.unwrap();
    s.create(T2, mk("sess-t2")).await.unwrap();
    assert!(s.get(T1, "sess-t1").await.unwrap().is_some());
    assert!(s.get(T2, "sess-t1").await.unwrap().is_none());
    // count_by_user 各租户只计自己。
    assert_eq!(
        s.count_by_user(T1, "user:alice@example.com", 0)
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        s.count_by_user(T2, "user:alice@example.com", 0)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        s.list_by_user(T1, "user:alice@example.com", 0)
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        s.delete_others_by_user(T1, "user:alice@example.com", "sess-t1")
            .await
            .unwrap(),
        Some(1)
    );
    assert!(s.get(T1, "sess-t1").await.unwrap().is_some());
    assert!(
        s.get(T1, "sess-t1-other").await.unwrap().is_none(),
        "stale physical session must fail the generation authority check"
    );
    assert!(
        !s.delete_owned(T1, "user:alice@example.com", "sess-t1-other", "sess-t1",)
            .await
            .unwrap(),
        "an actor fenced out by revoke-others must not delete the retained session"
    );
    assert!(s.get(T1, "sess-t1").await.unwrap().is_some());
    assert!(s.get(T2, "sess-t2").await.unwrap().is_some());
    assert_eq!(
        s.delete_others_by_user(T1, "user:alice@example.com", "sess-t1")
            .await
            .unwrap(),
        Some(0),
        "repeated revoke-others is idempotent"
    );
    assert_eq!(
        s.delete_others_by_user(T1, "user:alice@example.com", "sess-t1-other")
            .await
            .unwrap(),
        Some(0),
        "a retained session that lost authority is an idempotent no-op"
    );
    // delete_by_user(t1) 只删 t1 的。
    assert_eq!(
        s.delete_by_user(T1, "user:alice@example.com")
            .await
            .unwrap(),
        2
    );
    assert_eq!(
        s.count_by_user(T2, "user:alice@example.com", 0)
            .await
            .unwrap(),
        1,
        "t1 的 delete_by_user MUST NOT 删 t2 同名 user 的会话"
    );
}

// passkey:list_by_user / delete_by_user 跨租户隔离(user_id-index GSI 隔离,codex B1)。
#[tokio::test]
async fn passkeys_partitioned_by_tenant() {
    let s = PasskeyStoreImpl::Memory(MemoryPasskeyStore::default());
    let mk = |cid: &str| agent_auth_authn::passkey::PasskeyCredential {
        credential_id: cid.into(),
        user_id: "user:alice@example.com".into(),
        rp_id: "localhost".into(),
        public_key_sec1: vec![1, 2, 3],
        sign_count: 0,
        name: "Passkey".into(),
        created_at: 0,
    };
    assert!(s.put_new(T1, mk("cred-t1")).await.unwrap());
    assert!(s.put_new(T2, mk("cred-t2")).await.unwrap());
    // list_by_user 各租户只见自己。
    let t1 = s.list_by_user(T1, "user:alice@example.com").await.unwrap();
    assert_eq!(t1.len(), 1);
    assert_eq!(t1[0].credential_id, "cred-t1");
    // delete_by_user(t1) 只删 t1 的。
    assert_eq!(
        s.delete_by_user(T1, "user:alice@example.com")
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        s.list_by_user(T2, "user:alice@example.com")
            .await
            .unwrap()
            .len(),
        1,
        "t1 的 delete_by_user MUST NOT 删 t2 同名 user 的 passkey"
    );
}

// recovery:by-lookup 跨租户隔离(键 = user_lookup;同 lookup 跨租户不串)。
#[tokio::test]
async fn recovery_partitioned_by_tenant() {
    let s = RecoveryStoreImpl::Memory(MemoryRecoveryStore::default());
    let mk = || RecoveryRecord {
        user_lookup: "lookup-abc".into(),
        user_id: "user:alice@example.com".into(),
        activation_id: "recovery".into(),
        code_hashes: vec![],
        attempt_count: 0,
        locked_until: 0,
    };
    s.put(T1, mk()).await.unwrap();
    assert!(s.get(T1, "lookup-abc").await.unwrap().is_some());
    assert!(
        s.get(T2, "lookup-abc").await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的恢复码记录(同 lookup 跨租户隔离)"
    );
    // delete_by_lookup(t2) 幂等且不碰 t1。
    s.delete_by_lookup(T2, "lookup-abc").await.unwrap();
    assert!(
        s.get(T1, "lookup-abc").await.unwrap().is_some(),
        "t2 的删除 MUST NOT 碰 t1"
    );
}

// authz_sessions:主键 get + GSI list_by_client + count_active 跨租户隔离
// (codex Blocker:同逻辑 client_id 在 t1/t2 各自建会话,t2 用同 client_id 认证 MUST NOT
// 通过 list_by_client 读到 t1 的会话 id;GSI client_id 值 tpk 化是隔离点)。
#[tokio::test]
async fn authz_sessions_partitioned_by_tenant() {
    let s = AuthzSessionStoreImpl::Memory(MemoryAuthzSessionStore::default());
    let mk = |sid: &str| AuthzSessionRecord {
        session_id: sid.into(),
        client_id: "shared-client".into(),
        user_id: None,
        state: "code_issued_awaiting_exchange".into(),
        session_token_hash: "h".into(),
        sequence: 1,
        last_error: None,
        expires_at: i64::MAX,
    };
    s.create(T1, mk("sess-t1")).await.unwrap();
    s.create(T2, mk("sess-t2")).await.unwrap();
    // 主键 get 跨租户隔离(同 session_id 不会串;此处 id 不同,验各自可读、对方读 None)。
    assert!(s.get(T1, "sess-t1").await.unwrap().is_some());
    assert!(
        s.get(T2, "sess-t1").await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的授权会话(session_id 跨租户隔离)"
    );
    // GSI list_by_client(同 client_id)各租户只见自己 —— 这是 codex Blocker 的核心泄露面。
    let t1_ids = s.list_by_client(T1, "shared-client").await.unwrap();
    assert_eq!(t1_ids, vec!["sess-t1".to_string()], "t1 只列到自己的会话");
    let t2_ids = s.list_by_client(T2, "shared-client").await.unwrap();
    assert_eq!(
        t2_ids,
        vec!["sess-t2".to_string()],
        "t2 list_by_client(同 client_id)MUST 只见 t2 的会话,绝不泄露 t1 的 session_id"
    );
    // count_active 各租户只计自己(overview 按 tenant 隔离)。
    assert_eq!(s.count_active(T1, 0).await.unwrap(), 1);
    assert_eq!(s.count_active(T2, 0).await.unwrap(), 1);
    // **空 tenant MUST 只计无前缀分区,排除 t1/t2 前缀行**(评审 Kiro B1:Memory 曾把空 tenant
    // 当"全租户求和",与 Dynamo `None if contains('\x1f')=>continue` 背离 → 测试谎报)。
    // 此处只有 t1/t2 两条(均带前缀),空 tenant 应计 0。
    assert_eq!(
        s.count_active("", 0).await.unwrap(),
        0,
        "空 tenant count_active MUST 排除他租户前缀行(与 Dynamo 同构),不是全租户求和"
    );
    // 再建一条无前缀(flag 关等价)会话 → 空 tenant 计 1(只这条),t1 仍只计自己。
    s.create("", mk("sess-flat")).await.unwrap();
    assert_eq!(
        s.count_active("", 0).await.unwrap(),
        1,
        "空 tenant 只计无前缀分区那一条"
    );
    assert_eq!(
        s.count_active(T1, 0).await.unwrap(),
        1,
        "t1 不受无前缀行影响"
    );
}

// reclaim 候选扫描(D3b 跨租户维护作业,无请求 Host):空 tenant 全量扫描 MUST 返回
// **每条记录自身所属 tenant**(codex B2),使后续 convert_to_tombstone/hard_delete 用正确
// 物理键回写;非空 tenant 扫描只见本租户候选。
#[tokio::test]
async fn reclaim_candidates_carry_owning_tenant() {
    let s = ClientStoreImpl::Memory(MemoryClientStore::default());
    // t1/t2 各建同 client_id,并 touch 到同一 last_used_day(进回收候选窗)。
    s.put(T1, client("shared-id")).await.unwrap();
    s.put(T2, client("shared-id")).await.unwrap();
    s.touch_last_used(T1, "shared-id", 10).await.unwrap();
    s.touch_last_used(T2, "shared-id", 10).await.unwrap();

    // 空 tenant = 全量维护扫描:两条都在,且各自带正确 tenant。
    let mut all = s.list_reclaim_candidates("", 20).await.unwrap();
    all.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(all.len(), 2, "全量扫描应见两租户各 1 条候选");
    assert_eq!(all[0].0, T1, "第一条所属 tenant = t1");
    assert_eq!(all[1].0, T2, "第二条所属 tenant = t2");
    assert_eq!(all[0].1.client_id, "shared-id");
    assert_eq!(all[1].1.client_id, "shared-id");

    // 非空 tenant 扫描:只见本租户候选。
    let only_t1 = s.list_reclaim_candidates(T1, 20).await.unwrap();
    assert_eq!(only_t1.len(), 1);
    assert_eq!(only_t1[0].0, T1);

    // 用记录所属 tenant 回写 tombstone:只影响该租户,对方不受波及。
    assert!(s
        .convert_to_tombstone(T1, "shared-id", 30, Some(10), 0)
        .await
        .unwrap());
    assert!(
        s.get(T1, "shared-id")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_some(),
        "t1 记录已 tombstone"
    );
    assert!(
        s.get(T2, "shared-id")
            .await
            .unwrap()
            .unwrap()
            .tombstoned_at
            .is_none(),
        "t2 同 client_id 记录 MUST NOT 被 t1 的回收波及"
    );
}

// magic-link:link_id 消费 + per-email 冷却键跨租户隔离(评审 codex High:全局 cool#email 键会让
// 租户 A 请求占掉租户 B 同 email 冷却槽 = 存在性 oracle + 可用性耦合;link 亦不得跨租户消费)。
#[tokio::test]
async fn magic_links_partitioned_by_tenant() {
    let s = MagicLinkStoreImpl::Memory(MemoryMagicLinkStore::default());
    let mk = |id: &str| MagicLinkRecord {
        link_id: id.into(),
        user_id: "user:alice@example.com".into(),
        email: "alice@example.com".into(),
        session_nonce: "n".into(),
        authorize_query: String::new(),
        next: String::new(),
        expires_at: i64::MAX,
    };
    // 冷却键隔离:t1 mark_sent 不影响 t2 同 email 的冷却判定。
    s.mark_sent(T1, "alice@example.com", 1000).await.unwrap();
    assert_eq!(
        s.last_sent_at(T1, "alice@example.com").await.unwrap(),
        Some(1000)
    );
    assert_eq!(
        s.last_sent_at(T2, "alice@example.com").await.unwrap(),
        None,
        "t2 同 email 冷却 MUST 独立(t1 的发信不占 t2 的冷却槽,不成枚举 oracle)"
    );
    // link 消费隔离:同 link_id 在 t1 建,t2 consume 取不到(绝不跨租户消费他租户 link)。
    s.put(T1, mk("shared-link")).await.unwrap();
    assert!(
        s.consume_bound(T2, "shared-link", "n")
            .await
            .unwrap()
            .is_none(),
        "t2 MUST NOT 消费 t1 的 magic-link(同 link_id 跨租户隔离)"
    );
    assert!(
        s.consume_bound(T1, "shared-link", "n")
            .await
            .unwrap()
            .is_some(),
        "t1 自己可消费"
    );
}

// device:device_code 主键 + user_code(8 位短码,~2^37)GSI 跨租户隔离(评审 codex Medium:
// user_code 跨租户碰撞 → 租户 B 用户可能批准租户 A 的 device 请求)。
#[tokio::test]
async fn devices_partitioned_by_tenant() {
    let s = DeviceStoreImpl::Memory(MemoryDeviceStore::default());
    let mk = |dc: &str, uc: &str| DeviceAuthGrant {
        device_code: dc.into(),
        user_code: uc.into(),
        client_id: "c".into(),
        user_id: None,
        authz_session_id: None,
        scope: vec![],
        resources: vec![],
        interval: 5,
        last_poll_at: None,
        expires_at: i64::MAX,
        status: "pending".into(),
        consumed: false,
        password_credential_version: None,
    };
    // 两租户各建 device,故意用**同一 user_code**(短码碰撞场景)。
    s.put(T1, mk("dc-t1", "WDJBMJHT")).await.unwrap();
    s.put(T2, mk("dc-t2", "WDJBMJHT")).await.unwrap();
    // get_by_user_code 各租户只命中自己的 device(codex Medium 核心:短码跨租户碰撞被隔离)。
    let g1 = s.get_by_user_code(T1, "WDJBMJHT").await.unwrap().unwrap();
    assert_eq!(
        g1.device_code, "dc-t1",
        "t1 按 user_code 只命中自己的 device"
    );
    let g2 = s.get_by_user_code(T2, "WDJBMJHT").await.unwrap().unwrap();
    assert_eq!(
        g2.device_code, "dc-t2",
        "t2 同 user_code MUST 命中 t2 自己的 device,绝不批准 t1 的请求"
    );
    // decide(t1) 只决定 t1 的 device;t2 的仍 pending。
    assert!(s.decide(T1, "dc-t1", "alice", None, true, 0).await.unwrap());
    assert_eq!(
        s.get(T2, "dc-t2").await.unwrap().unwrap().status,
        "pending",
        "t1 的批准 MUST NOT 波及 t2 同 user_code 的 device"
    );
    // 主键 get 隔离。
    assert!(s.get(T2, "dc-t1").await.unwrap().is_none());
}

// ciba:auth_req_id 主键 + throttle 键跨租户隔离(SaaS 下 CIBA 请求 MUST NOT 被他租户审批/签发)。
// t1 put 一条 CibaAuthRequest → t2 用同 auth_req_id get 得 None;t2 decide/consume 同 id 不影响 t1。
#[tokio::test]
async fn ciba_partitioned_by_tenant() {
    let s = CibaStoreImpl::Memory(MemoryCibaStore::default());
    let mk = |arid: &str, tenant: &str| CibaAuthRequest {
        auth_req_id: arid.into(),
        tenant: tenant.into(),
        client_id: "c".into(),
        user_id: "user:alice@example.com".into(),
        authz_session_id: None,
        scope: vec!["openid".into()],
        resources: vec![],
        binding_message: None,
        interval: 5,
        last_poll_at: None,
        expires_at: i64::MAX,
        status: "pending".into(),
        consumed: false,
        delivery_mode: None,
        notification_endpoint: None,
        client_notification_token: None,
        password_credential_version: None,
    };
    // 两租户故意用**同一 auth_req_id**(隔离场景:即便 id 撞车也物理隔离)。
    s.put(T1, mk("ar-shared", T1)).await.unwrap();
    // t2 用同 auth_req_id get → None(绝不跨租户读到 t1 的 CIBA 请求)。
    assert!(
        s.get(T2, "ar-shared").await.unwrap().is_none(),
        "t2 MUST NOT 读到 t1 的 auth_req_id(跨租户 CIBA 隔离漏洞)"
    );
    // t1 能读到自己的。
    assert_eq!(
        s.get(T1, "ar-shared").await.unwrap().unwrap().status,
        "pending"
    );
    // t2 decide 同 id → false(t2 分区无此记录),且 t1 的仍 pending(不被波及)。
    assert!(
        !s.decide(T2, "ar-shared", None, true).await.unwrap(),
        "t2 decide 他租户 auth_req_id MUST 失败(本分区无此记录)"
    );
    assert_eq!(
        s.get(T1, "ar-shared").await.unwrap().unwrap().status,
        "pending",
        "t2 的 decide MUST NOT 审批 t1 的 CIBA 请求"
    );
    // t2 consume 同 id → false;t1 的仍未消费(不被他租户签发)。
    assert!(
        !s.consume(T2, "ar-shared").await.unwrap(),
        "t2 consume 他租户 auth_req_id MUST 失败"
    );
    assert!(
        !s.get(T1, "ar-shared").await.unwrap().unwrap().consumed,
        "t2 的 consume MUST NOT 消费 t1 的 CIBA 请求(防他租户签发)"
    );
    // throttle 键 tenant-scope:t1 占窗后,t2 同 user_id 仍可占(不跨租户串扰冷却)。
    assert!(s
        .try_arm_throttle(T1, "user:alice@example.com", 1000, 60)
        .await
        .unwrap());
    assert!(
        s.try_arm_throttle(T2, "user:alice@example.com", 1000, 60)
            .await
            .unwrap(),
        "t2 同 user_id 的冷却窗独立(throttle 键 tenant-scope),不被 t1 占窗串扰"
    );
    // 同租户内窗内再占 → 拒(节流仍生效)。
    assert!(
        !s.try_arm_throttle(T1, "user:alice@example.com", 1010, 60)
            .await
            .unwrap(),
        "同租户窗内再占 MUST 拒(节流语义不变)"
    );
}

// workload-trust:put/delete 按 tenant 隔离(评审 codex Low:binding_id 是 SPIFFE 派生哈希,非随机,
// 跨租户可碰撞 → 租户 A 覆盖/删除租户 B 同 binding_id 绑定)。
#[tokio::test]
async fn workload_trust_partitioned_by_tenant() {
    use agent_auth_workload::{TrustBinding, TrustMechanism};
    let s = WorkloadTrustStoreImpl::Memory(MemoryWorkloadTrustStore::default());
    let mk = |tenant: &str, client: &str| TrustBinding {
        tenant_id: tenant.into(),
        mechanism: TrustMechanism::SpiffeJwt {
            trust_domain: "example.org".into(),
            jwks_uri: "https://bundle/jwks".into(),
            spiffe_id_pattern: "spiffe://example.org/wl".into(),
        },
        mapped_client_id: client.into(),
    };
    // 两租户用**同一 binding_id**(SPIFFE 派生碰撞场景),各映射到自己的 client。
    s.put(T1, "shared-bid".into(), mk(T1, "wl-t1"))
        .await
        .unwrap();
    s.put(T2, "shared-bid".into(), mk(T2, "wl-t2"))
        .await
        .unwrap();
    // 各租户 list 只见自己(put 未跨租户覆盖:t2 的 put 没踩掉 t1 的绑定)。
    let l1 = s.list_by_tenant(T1).await.unwrap();
    assert_eq!(l1.len(), 1);
    assert_eq!(l1[0].binding_id, "shared-bid");
    assert_eq!(
        l1[0].binding.mapped_client_id, "wl-t1",
        "t1 绑定未被 t2 同 binding_id 覆盖"
    );
    let l2 = s.list_by_tenant(T2).await.unwrap();
    assert_eq!(l2.len(), 1);
    assert_eq!(l2[0].binding_id, "shared-bid");
    assert_eq!(l2[0].binding.mapped_client_id, "wl-t2");
    // delete(t1) 只删 t1 的,t2 的同 binding_id 不受影响。
    s.delete(T1, "shared-bid").await.unwrap();
    assert_eq!(s.list_by_tenant(T1).await.unwrap().len(), 0, "t1 已删");
    assert_eq!(
        s.list_by_tenant(T2).await.unwrap().len(),
        1,
        "t1 的 delete MUST NOT 删 t2 同 binding_id 的绑定"
    );
}

// messages outbox:list_recent 跨租户隔离(spec 007 后 P0-A;C10.19)。
// /admin/messages 绝不跨租户泄露 magic-link 登录 URL(可重放凭证)/ email PII。
#[tokio::test]
async fn messages_partitioned_by_tenant() {
    use agent_auth_http::adapters::memory::MemoryOutboxNotifier;
    use agent_auth_http::ports::{MessageOutbox, Notifier};
    let n = MemoryOutboxNotifier::default();
    // t1 发 magic-link、t2 发另一封。
    n.send_magic_link(T1, "alice@t1.com", "https://as/login?link=t1secret")
        .await
        .unwrap();
    n.send_magic_link(T2, "bob@t2.com", "https://as/login?link=t2secret")
        .await
        .unwrap();
    // t1 只见自己的(绝不见 t2 的 magic-link URL / email)。
    let t1 = n.list_recent(T1, 50).await.unwrap();
    assert_eq!(t1.len(), 1, "t1 只见自己那封");
    assert_eq!(t1[0].recipient, "alice@t1.com");
    assert!(
        !t1.iter()
            .any(|m| m.recipient.contains("t2") || m.body.contains("t2secret")),
        "t1 MUST NOT 见到 t2 的 magic-link URL / email(跨租户泄露)"
    );
    // t2 对称。
    let t2 = n.list_recent(T2, 50).await.unwrap();
    assert_eq!(t2.len(), 1);
    assert_eq!(t2[0].recipient, "bob@t2.com");
    // 空 tenant(flag 关)见不到任何具名租户的消息(独立分区)。
    assert_eq!(
        n.list_recent("", 50).await.unwrap().len(),
        0,
        "空 tenant 分区独立"
    );
}

// 空 tenant(flag 关)= 无前缀分区 = 现网单租户行为(byte-identical 回归保护)。
#[tokio::test]
async fn empty_tenant_is_flat_single_partition() {
    let s = ClientStoreImpl::Memory(MemoryClientStore::default());
    s.put("", client("c1")).await.unwrap();
    assert!(
        s.get("", "c1").await.unwrap().is_some(),
        "空 tenant 读写 = 单租户平面"
    );
    // 空 tenant 与具名 tenant 互不串(空是独立的 "" 分区)。
    assert!(s.get(T1, "c1").await.unwrap().is_none());
}
