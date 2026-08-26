//! 进程内测试:GrantStore(spec 011 §5.1)内存适配器 —— put/get/list_by_user/revoke。
//!
//! 校验 IDOR-relevant 行为:list_by_user 只返该 user 的 Grant(不泄露他人);revoke → status=Revoked。
//! Grant 校验纯逻辑(authorize_target/authorize_delegation)在 agent_auth_grant crate 单测,此处只测 IO。

use agent_auth_grant::{Grant, GrantConstraints, GrantStatus, ResourceGrant};
use agent_auth_http::adapters::memory::MemoryGrantStore;
use agent_auth_http::ports::GrantStore;

fn mk_grant(grant_id: &str, user_id: &str) -> Grant {
    Grant {
        grant_id: grant_id.into(),
        user_id: user_id.into(),
        client_id: "app-3lo".into(),
        per_resource: vec![ResourceGrant {
            resource: "https://mcp.kb.example.com".into(),
            scopes: vec!["kb:read".into()],
            authorization_details: vec![],
        }],
        effective_per_resource: vec![],
        effective_pv: 0,
        allowed_ip_cidrs: vec![],
        allowed_vpce: vec![],
        credential_epoch: 0,
        revision: 0,
        constraints: GrantConstraints {
            max_act_chain: 1,
            actor_allowlist: vec!["wl-actor".into()],
            expires_at: 2_000_000_000,
        },
        status: GrantStatus::Active,
    }
}

#[tokio::test]
async fn put_get_roundtrip() {
    let store = MemoryGrantStore::default();
    store.put("", mk_grant("g1", "alice")).await.unwrap();
    let got = store.get("", "g1").await.unwrap().expect("g1 存在");
    assert_eq!(got.user_id, "alice");
    assert_eq!(got.status, GrantStatus::Active);
    assert!(store.get("", "nonexistent").await.unwrap().is_none());
}

// IDOR-safe:list_by_user 只返该 user 的 Grant,不含他人的。
#[tokio::test]
async fn list_by_user_isolates_users() {
    let store = MemoryGrantStore::default();
    store.put("", mk_grant("g1", "alice")).await.unwrap();
    store.put("", mk_grant("g2", "alice")).await.unwrap();
    store.put("", mk_grant("g3", "mallory")).await.unwrap();

    let alice = store.list_by_user("", "alice").await.unwrap();
    assert_eq!(alice.len(), 2, "alice 有 2 个 grant");
    assert!(alice.iter().all(|g| g.user_id == "alice"), "不含他人 grant");
    let ids: Vec<&str> = alice.iter().map(|g| g.grant_id.as_str()).collect();
    assert_eq!(ids, vec!["g1", "g2"], "稳定顺序");

    let mallory = store.list_by_user("", "mallory").await.unwrap();
    assert_eq!(mallory.len(), 1);
    assert_eq!(mallory[0].grant_id, "g3");

    // 无 grant 的 user → 空。
    assert!(store.list_by_user("", "nobody").await.unwrap().is_empty());
}

#[tokio::test]
async fn revoke_sets_status_and_is_idempotent() {
    let store = MemoryGrantStore::default();
    store.put("", mk_grant("g1", "alice")).await.unwrap();
    // revoke → true(存在)+ status=Revoked。
    assert!(store.revoke("", "g1").await.unwrap());
    assert_eq!(
        store.get("", "g1").await.unwrap().unwrap().status,
        GrantStatus::Revoked
    );
    // 幂等:再 revoke 仍 true(已 Revoked,不报错)。
    assert!(store.revoke("", "g1").await.unwrap());
    // 不存在的 grant → false。
    assert!(!store.revoke("", "nonexistent").await.unwrap());
}

// 吊销后 is_usable 拒(与 grant crate 校验一致,IO 层不重复校但确认 status 落地)。
#[tokio::test]
async fn revoked_grant_not_usable() {
    let store = MemoryGrantStore::default();
    store.put("", mk_grant("g1", "alice")).await.unwrap();
    store.revoke("", "g1").await.unwrap();
    let g = store.get("", "g1").await.unwrap().unwrap();
    assert_eq!(
        g.is_usable(1_000_000_000),
        Err(agent_auth_grant::GrantError::NotActive)
    );
}
