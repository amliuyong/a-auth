//! 逐租户 ECC/access Sign 公平闸(spec 020 §3.1 / C10.14)进程内测试。
//!
//! 验:①默认关(未配容量)字节等价现状=放行、无桶;②启用后单租户打满其份额被 503 挡下;
//! ③同 fleet 另一租户不受影响(单 abuser 隔离,低争用);④self-host 空 tenant 走固定 sentinel 键。
//!
//! **env 隔离**:本 gate 参数经进程级 env,故所有断言集中在**一个** `#[test]`(非 tokio 并行 async test)
//! 内串行设置/清理 env,避免与其它 test 竞争进程 env(评审:env 是进程全局)。用 block_on 驱动 async gate。

use agent_auth_http::ratelimit_gate::kms_sign_tenant_gate;
use agent_auth_http::AppState;

const CAP_ENV: &str = "AGENT_AUTH_KMS_TENANT_GATE_CAPACITY";
const REFILL_ENV: &str = "AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC";

/// 单一 test,串行控制进程 env(默认关 → 启用 → 清理)。
#[test]
fn tenant_sign_quota_gate_behavior() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    // ── ① 默认关(未设 CAP)→ 放行、无桶(字节等价现状)──
    std::env::remove_var(CAP_ENV);
    std::env::remove_var(REFILL_ENV);
    let state = AppState::dev("localhost");
    rt.block_on(async {
        for _ in 0..100 {
            assert!(
                kms_sign_tenant_gate(&state, "t1").await.is_none(),
                "默认关:逐租户闸放行(不引入桶)"
            );
        }
    });

    // ── ② 启用:容量小(3)、补充极慢(0.001/s)→ 单租户前几次放行、之后 503 ──
    std::env::set_var(CAP_ENV, "3");
    std::env::set_var(REFILL_ENV, "0.001");
    let state = AppState::dev("localhost"); // 新 state = 新内存桶
    rt.block_on(async {
        // t1 前 3 次放行(容量 3),第 4 次起 503。
        assert!(
            kms_sign_tenant_gate(&state, "t1").await.is_none(),
            "t1 #1 放行"
        );
        assert!(
            kms_sign_tenant_gate(&state, "t1").await.is_none(),
            "t1 #2 放行"
        );
        assert!(
            kms_sign_tenant_gate(&state, "t1").await.is_none(),
            "t1 #3 放行"
        );
        let shed = kms_sign_tenant_gate(&state, "t1").await;
        assert!(shed.is_some(), "t1 打满份额 → 503");
        use axum::http::StatusCode;
        use axum::response::IntoResponse;
        assert_eq!(
            shed.unwrap().into_response().status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "超份额 MUST 503 temporarily_unavailable"
        );

        // ── ③ 单 abuser 隔离:t1 被挡下时,同 fleet 的 t2 仍放行(独立桶,低争用)──
        assert!(
            kms_sign_tenant_gate(&state, "t2").await.is_none(),
            "t2 有独立逐租户桶,不受 t1 打满影响(单 abuser 隔离)"
        );
        assert!(
            kms_sign_tenant_gate(&state, "t2").await.is_none(),
            "t2 #2 放行"
        );

        // ── ④ self-host 空 tenant 走固定 sentinel 键(独立于 t1/t2)──
        assert!(
            kms_sign_tenant_gate(&state, "").await.is_none(),
            "空 tenant #1 放行(sentinel 键)"
        );
        assert!(
            kms_sign_tenant_gate(&state, "").await.is_none(),
            "空 tenant #2 放行"
        );
        assert!(
            kms_sign_tenant_gate(&state, "").await.is_none(),
            "空 tenant #3 放行"
        );
        assert!(
            kms_sign_tenant_gate(&state, "").await.is_some(),
            "空 tenant 打满其 sentinel 桶 → 503(与真租户键隔离)"
        );
    });

    // ── ⑤ fail-open:rate_limit 未配(None)→ 放行(即便启用了容量;env 仍设着)──
    let mut state_no_store = AppState::dev("localhost");
    state_no_store.rate_limit = None;
    rt.block_on(async {
        for _ in 0..10 {
            assert!(
                kms_sign_tenant_gate(&state_no_store, "t1").await.is_none(),
                "rate_limit 未配 → fail-open 放行(anti-abuse 优先可用性)"
            );
        }
    });

    // ── 清理进程 env(不污染其它 test;单 test 内串行完成所有 env 操作,避免并行竞争)──
    std::env::remove_var(CAP_ENV);
    std::env::remove_var(REFILL_ENV);
}
