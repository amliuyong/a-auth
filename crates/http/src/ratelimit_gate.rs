//! per-client 应用层限流闸(spec 005 §3.1 / C10.7)——供各 grant flow **认证后**按不可伪造的 client
//! 主体调用。令牌桶纯逻辑在 `agent_auth_infra_core::ratelimit`,存储层在 `RateLimitStore`(乐观 CAS)。
//!
//! ⚠️ **键必须是认证后主体**(评审 codex/Kiro HIGH#2):调用方 MUST 传经认证/绑定确认的 client_id
//! (refresh=fam_rec.client_id、2LO=identity.client_id、code=code 绑定的 client_id),**绝不用未认证的
//! form client_id**——否则攻击者声称任意 client_id 打满受害者桶(DoS 放大)。
//!
//! **fail-open**:`state.rate_limit=None`(未配)或存储瞬时错误 → 放行(anti-abuse 优先可用性,非安全闸;
//! 与 CIBA 节流 C7b.6 一致)。超额 → `Some(429 + Retry-After + temporarily_unavailable)`。

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

use crate::ports::RateLimitStore;
use crate::state::AppState;
use crate::token::TokenError;

/// per-client /token 令牌桶容量(突发上限)。C10.7;真机可按 client 策略/租户配额调(P2+)。
const TOKEN_RL_CAPACITY: f64 = 60.0;
/// 补充速率(个/秒)——稳态 ~10 req/s/client,足够正常 agent 轮换 + 突发 60。
const TOKEN_RL_REFILL_PER_SEC: f64 = 10.0;

/// per-IP `POST /register`(open 档匿名注册)令牌桶容量(注册洪水粗兜底,C10.8)。注册远低频于 token,
/// 桶更严:突发 10、补充 0.2/s(~1 个/5s 稳态)——正常开发者注册几个 client 够用,批量脚本洪水被挡。
const REGISTER_RL_CAPACITY: f64 = 10.0;
const REGISTER_RL_REFILL_PER_SEC: f64 = 0.2;
/// 匿名 `POST /register` tenant-global 配额(C10.8):多 IP/ASN 并发绕过 per-IP 桶时的共享上限。
/// 突发 100、补充 2/s;单一来源先受更严的 per-IP 10/0.2s 闸约束,只有通过该闸的请求才消耗全局桶。
const REGISTER_GLOBAL_QUOTA_CAPACITY: f64 = 100.0;
const REGISTER_GLOBAL_QUOTA_REFILL_PER_SEC: f64 = 2.0;
const REGISTER_GLOBAL_QUOTA_KEY: &str = "global-register-quota";

/// 全局发信配额桶容量/补充(C9.1 §3.2:跨邮箱发信洪水令牌桶,保护 SES 信誉)。单一逻辑桶(所有邮箱共享)。
/// 容量 100 突发、补充 2/s(~稳态 2 封/s、突发 100)——正常登录远低于此,跨大量邮箱洪水被平滑限速。
const EMAIL_QUOTA_CAPACITY: f64 = 100.0;
const EMAIL_QUOTA_REFILL_PER_SEC: f64 = 2.0;
/// 全局发信配额桶的固定 key(单一逻辑桶,跨所有邮箱共享)。
const EMAIL_QUOTA_KEY: &str = "global-email-quota";

/// 全局发信配额(C9.1:magic-link/OTP 跨邮箱洪水防护,与 per-email 冷却语义不同的另一半)。
/// 单一全局令牌桶取 1 token——超额 `true`(调用方拒新发信,保护 SES 信誉)。store 未配/错误 → false(fail-open)。
/// 与 per-email 冷却叠加:冷却挡单邮箱重复,全局配额挡跨大量邮箱的总发信速率。
pub async fn global_email_quota_exhausted(state: &AppState) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false; // 未配 → 放行
    };
    let now = crate::token::current_unix_secs_pub();
    match rl
        .try_consume(
            EMAIL_QUOTA_KEY,
            now,
            EMAIL_QUOTA_CAPACITY,
            EMAIL_QUOTA_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false, // fail-open
    }
}

/// Stable key helper shared by deterministic live/test evidence.
pub fn global_email_quota_key() -> &'static str {
    EMAIL_QUOTA_KEY
}

/// 全局 CIBA 推送(ping/push)投递配额桶(spec 013 §4,C7b.5+;与全局发信配额同构的另一条外发洪水防线)。
/// CIBA ping/push 是 **AS 主动向 client 回调端点发 HTTP** 的外发面:跨大量 auth_req 的推送洪水会打爆自身
/// 出网 / 拖累回调目标 / 放大 SSRF 尝试面。per-login_hint 冷却(C7b.6)挡"单用户批准疲劳",此桶挡"跨请求
/// 总推送速率"(两者语义不同、叠加)。单一全局逻辑桶。容量 100 突发、补充 2/s(正常 CIBA ping/push 远低于此)。
const CIBA_PUSH_QUOTA_CAPACITY: f64 = 100.0;
const CIBA_PUSH_QUOTA_REFILL_PER_SEC: f64 = 2.0;
/// 全局 CIBA 推送配额桶固定 key(单一逻辑桶,跨所有 auth_req 共享;与发信配额桶 key 隔离)。
const CIBA_PUSH_QUOTA_KEY: &str = "global-ciba-push-quota";

/// 全局 CIBA 推送配额(C7b.5+):投递前取 1 token——超额 `true`(调用方跳过本次主动推送,client 仍可轮询取,
/// fail-safe 天然)。store 未配/错误 → false(fail-open,anti-abuse 优先可用性,与发信配额一致)。
pub async fn ciba_push_quota_exhausted(state: &AppState) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false; // 未配 → 放行
    };
    let now = crate::token::current_unix_secs_pub();
    match rl
        .try_consume(
            CIBA_PUSH_QUOTA_KEY,
            now,
            CIBA_PUSH_QUOTA_CAPACITY,
            CIBA_PUSH_QUOTA_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false, // fail-open
    }
}

/// device `user_code` 尝试桶容量/补充(spec 013 Task 2b.3:防爆破枚举)。批准者仅偶尔提交(正常 1-2 次),
/// 桶严:容量 5、补充 0.1/s(~1 次/10s)——枚举脚本快速触顶。
const USER_CODE_ATTEMPT_CAPACITY: f64 = 5.0;
const USER_CODE_ATTEMPT_REFILL_PER_SEC: f64 = 0.1;

/// device `user_code` 批准提交尝试限流(2b.3 防爆破):按批准者(登录 `user_id`)令牌桶限提交频率。
/// user_code 是 8 位短码,device_code(128-bit)是主防线,但 user_code 提交面须限枚举。返回 `true`=超额(拒),
/// `false`=放行/fail-open。key `devcode-attempt:{user_id}` 与其它桶隔离。store 未配/错误 → false(fail-open)。
pub async fn user_code_attempt_throttled(state: &AppState, tenant: &str, user_id: &str) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false;
    };
    let now = crate::token::current_unix_secs_pub();
    // tenant-scope(spec 020 §3.1):桶键前缀 tenant,防跨租户可用性耦合 + 用户存在性枚举 oracle
    // (同 user_id 跨租户碰撞:不分区则 t1 打满会牵连 t2 同名 user)。空 tenant(flag 关)透传 byte-identical。
    let key = crate::tenant::tpk(tenant, &format!("devcode-attempt:{user_id}"));
    match rl
        .try_consume(
            &key,
            now,
            USER_CODE_ATTEMPT_CAPACITY,
            USER_CODE_ATTEMPT_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false,
    }
}

/// `POST /recovery/generate` 生成桶容量/补充(spec 003 C9.1 类比 §3.2:防滥刷生成)。生成恢复码是
/// 已登录用户偶发操作(正常一生几次),且**每次 regenerate 使此前所有码失效**——滥刷既浪费也可被
/// CSRF 触发"使受害者旧码失效"的破坏性副作用(评审 Kiro 提及的写端点副作用)。桶严:容量 5、
/// 补充 0.02/s(~1 次/50s 稳态),正常用户重生成够用,脚本滥刷快速触顶。
const RECOVERY_GEN_CAPACITY: f64 = 5.0;
const RECOVERY_GEN_REFILL_PER_SEC: f64 = 0.02;

/// `POST /recovery/generate` per-user 限流(防滥刷生成 + 缓解 CSRF 使旧码失效副作用)。
/// 键 = **认证后**的调用方 `user_id`(session 派生,不可伪造),`recovery-gen:` 前缀与其它桶隔离。
/// 返回 `true`=超额(调用方拒),`false`=放行/fail-open。store 未配/瞬时错误 → false(fail-open,
/// anti-abuse 优先可用性,与其它 anti-abuse 桶一致)。
pub async fn recovery_generate_throttled(state: &AppState, tenant: &str, user_id: &str) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false; // 未配限流 → 放行
    };
    let now = crate::token::current_unix_secs_pub();
    // tenant-scope(spec 020 §3.1):防跨租户耦合 + 枚举 oracle。空 tenant 透传 byte-identical。
    let key = crate::tenant::tpk(tenant, &format!("recovery-gen:{user_id}"));
    match rl
        .try_consume(
            &key,
            now,
            RECOVERY_GEN_CAPACITY,
            RECOVERY_GEN_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false, // fail-open
    }
}

/// grant-ref 铸造桶(spec 011 §4:不落存储但打 KMS Sign,防滥刷铸造)。铸 grant-ref 是用户偶发操作
/// (为某 agent 授权一次跨 Grant 换发),桶严:容量 10、补充 0.5/s。key=`grantref:{user}:{grant}:{agent}`。
const GRANT_REF_MINT_CAPACITY: f64 = 10.0;
const GRANT_REF_MINT_REFILL_PER_SEC: f64 = 0.5;

/// grant-ref 铸造限流(spec 011 §4)。key=per session+grant+bound_agent(调用方拼);超额 true(拒),
/// fail-open(store 未配/瞬时错误 → false 放行,anti-abuse 优先可用性)。
pub async fn grant_ref_mint_throttled(state: &AppState, tenant: &str, key: &str) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false;
    };
    let now = crate::token::current_unix_secs_pub();
    // tenant-scope(spec 020 §3.1);空 tenant 透传 byte-identical。
    let tkey = crate::tenant::tpk(tenant, key);
    match rl
        .try_consume(
            &tkey,
            now,
            GRANT_REF_MINT_CAPACITY,
            GRANT_REF_MINT_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false,
    }
}

/// per-IP 注册限流(C10.8 §3.2):open 档匿名 `POST /register` 按来源 IP 令牌桶粗兜底(WAF 只做 IP/Host/ASN
/// 粗兜底、抓不到 body,应用层这层是 per-IP 洪水闸)。返回 `true`=超额(调用方拒),`false`=放行/fail-open。
/// **注**:IP 取 `X-Forwarded-For` 首段(CloudFront/API GW 注入);伪造 XFF 只影响自己的桶键(粗兜底,
/// 精确 per-client 限流靠注册后的 client_id 维度,见 C10.7)。store 未配/错误 → false(fail-open)。
pub async fn register_ip_throttled(state: &AppState, tenant: &str, client_ip: &str) -> bool {
    let Some(rl) = state.rate_limit.as_ref() else {
        return false; // 未配限流 → 放行
    };
    let now = crate::token::current_unix_secs_pub();
    // key 加 "reg-ip:" 前缀,与 per-client_id token 桶隔离;tenant 前缀防跨租户 IP 桶耦合(SaaS)。
    // 空 tenant(flag 关)透传 byte-identical。
    let key = crate::tenant::tpk(tenant, &format!("reg-ip:{client_ip}"));
    match rl
        .try_consume(
            &key,
            now,
            REGISTER_RL_CAPACITY,
            REGISTER_RL_REFILL_PER_SEC,
            1.0,
        )
        .await
    {
        Ok(d) => !d.allowed,
        Err(_) => false, // fail-open(anti-abuse 优先可用性)
    }
}

/// 匿名注册 tenant-global 配额(C10.8)。必须在 per-IP 闸之后调用，阻止攻击者跨 IP/ASN 批量铸造
/// client，同时不让已被 per-IP 拒绝的请求继续消耗共享桶。有效 IAT/software-statement 路径不调用。
/// 与普通粗粒度 anti-abuse 闸不同，该 global quota 是 MUST 级注册准入条件：store 缺失、CAS 重试
/// 耗尽或其它存储错误都必须返回 `Err`，由调用方 503 fail closed，不能在并发压力下继续铸造 client。
pub async fn register_global_quota(
    state: &AppState,
    tenant: &str,
) -> Result<crate::ports::RateLimitDecision, crate::ports::StoreError> {
    let rl = state.rate_limit.as_ref().ok_or_else(|| {
        crate::ports::StoreError::Permanent(
            "anonymous registration global quota store is not configured".to_string(),
        )
    })?;
    let now = crate::token::current_unix_secs_pub();
    let key = register_global_quota_key(tenant);
    rl.try_consume(
        &key,
        now,
        REGISTER_GLOBAL_QUOTA_CAPACITY,
        REGISTER_GLOBAL_QUOTA_REFILL_PER_SEC,
        1.0,
    )
    .await
}

/// Stable key helper shared by deterministic live/test evidence.
pub fn register_global_quota_key(tenant: &str) -> String {
    crate::tenant::tpk(tenant, REGISTER_GLOBAL_QUOTA_KEY)
}

/// 全局 KMS Sign 并发闸(spec 005 §1.4 / C10.2):**KMS Sign 调用前**取 1 token 的单一逻辑桶,全局上限
/// ≈ 该区 KMS Sign 配额——在打满 KMS 前主动 shed(返 503+Retry-After),避免"KMS throttle→重试→更多 Sign"
/// 的正反馈雪崩(反应式 503 是兜底,此为前置)。区别于 per-client `check`:这是**跨所有 client 的单桶**,
/// 保护共享的 KMS 配额,不是防单 client 滥用。
///
/// 容量/补充按区 Sign 配额留裕量配(默认 us-east-1 RSA/ECC Sign ~较宽,取保守突发 200、稳态 100/s;env
/// 可覆盖,真机据实测配额标定)。**默认关**(容量=0 视为不启用):`AGENT_AUTH_KMS_GATE_CAPACITY` 设正值才启用,
/// 避免误配把签发全掐死;未配/store 未配/瞬时错误 → 放行(fail-open,反应式 503 兜底)。
///
/// 真机验收可设置 128-bit 小写十六进制 `AGENT_AUTH_KMS_GATE_TEST_RUN`,使同一 gate 逻辑使用一次性
/// `global-kms-sign:test:<run>` 桶。这样演练不会读写生产固定桶;非法 test run 配置 fail closed 为 503。
const KMS_GATE_KEY: &str = "global-kms-sign";
const KMS_GATE_TEST_RUN_ENV: &str = "AGENT_AUTH_KMS_GATE_TEST_RUN";

/// KMS Sign 前置并发闸。放行/未启用/fail-open → `None`;超额 → `Some(503 + Retry-After)`。
/// 调用点:各签发路径 KMS Sign **之前**(占 lease 后、Sign 前;超额则 release lease、不消费 code——
/// 与反应式 KMS throttle 路径同处置,C10.1 ①/C10.2)。
pub async fn kms_sign_gate(state: &AppState) -> Option<Response> {
    let (capacity, refill) = kms_gate_params();
    if capacity <= 0.0 {
        return None; // 默认关:未配容量 → 不启用前置闸(仅反应式 503)
    }
    let key = match configured_kms_gate_key() {
        Ok(key) => key,
        Err(()) => {
            return Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(TokenError::new(
                        "temporarily_unavailable",
                        "KMS Sign 前置闸测试配置无效",
                    )),
                )
                    .into_response(),
            )
        }
    };
    kms_sign_gate_with_config(state, &key, capacity, refill).await
}

async fn kms_sign_gate_with_config(
    state: &AppState,
    key: &str,
    capacity: f64,
    refill: f64,
) -> Option<Response> {
    let rl = state.rate_limit.as_ref()?;
    let now = crate::token::current_unix_secs_pub();
    match rl.try_consume(key, now, capacity, refill, 1.0).await {
        Ok(d) if !d.allowed => {
            let retry = d.retry_after_secs.unwrap_or(1).max(1);
            Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(axum::http::header::RETRY_AFTER, retry.to_string())],
                    Json(TokenError::new(
                        // temporarily_unavailable + 503(C10.2:签发暂时过载,保护 KMS 配额;客户端退避重试)。
                        "temporarily_unavailable",
                        "签发暂时受限(保护 KMS Sign 配额,请按 Retry-After 退避重试,C10.2)",
                    )),
                )
                    .into_response(),
            )
        }
        _ => None, // 放行 / fail-open
    }
}

fn configured_kms_gate_key() -> Result<String, ()> {
    match std::env::var(KMS_GATE_TEST_RUN_ENV) {
        Ok(run) => kms_gate_key(Some(&run)),
        Err(std::env::VarError::NotPresent) => kms_gate_key(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(()),
    }
}

fn kms_gate_key(test_run: Option<&str>) -> Result<String, ()> {
    match test_run {
        None => Ok(KMS_GATE_KEY.to_string()),
        Some(run)
            if run.len() == 32
                && run
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) =>
        {
            Ok(format!("{KMS_GATE_KEY}:test:{run}"))
        }
        Some(_) => Err(()),
    }
}

/// **逐租户 ECC/access Sign 公平闸**(spec 020 §3.1 / C10.14,SaaS 单 abuser 隔离)。在全局 `kms_sign_gate`
/// **之前**调:先扣逐租户桶 `kms-sign-tenant:<tenant>`——noisy 租户超自己份额即 503、**不扣全局桶**(为守规
/// 租户保全局容量)。放行/未启用/fail-open → `None`;超额 → `Some(503 + Retry-After)`。
///
/// **scope(评审 Blocker 收敛)**:只对 ECC/access 池做逐租户公平——现有 gate 是**每请求扣 1 token**粒度
/// (与全局桶一致),RSA/id_token 池逐租户公平留 P3(需按 key 类型拆 gate)。契约 = **单 abuser 隔离**,
/// 非集体过载保证份额(后者需 Σ 份额 ≤ 全局,P3)。
///
/// **默认关短路**:`AGENT_AUTH_KMS_TENANT_GATE_CAPACITY` 默认 0 → **在任何 store 调用前**返回 `None`
/// (字节等价现状、无额外 round-trip)。**self-host 空 tenant** → 固定 sentinel 键(单租户无 noisy-neighbor;
/// 建议 self-host 保持默认关)。fail-open:store 未配/瞬时错 → 放行(anti-abuse;反应式 503 + 全局桶兜底)。
pub async fn kms_sign_tenant_gate(state: &AppState, tenant: &str) -> Option<Response> {
    let rl = state.rate_limit.as_ref()?;
    let (capacity, refill) = kms_tenant_gate_params();
    if capacity <= 0.0 {
        return None; // 默认关:store 调用前短路(字节等价现状)
    }
    // 逐租户键;空 tenant(self-host)→ 固定 sentinel(稳定、不与真租户碰撞)。
    let key = if tenant.is_empty() {
        format!("{KMS_TENANT_GATE_PREFIX}:_self")
    } else {
        format!("{KMS_TENANT_GATE_PREFIX}:{tenant}")
    };
    let now = crate::token::current_unix_secs_pub();
    match rl.try_consume(&key, now, capacity, refill, 1.0).await {
        Ok(d) if !d.allowed => {
            let retry = d.retry_after_secs.unwrap_or(1).max(1);
            Some(
                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(axum::http::header::RETRY_AFTER, retry.to_string())],
                    Json(TokenError::new(
                        "temporarily_unavailable",
                        "签发暂时受限(本租户 Sign 速率达公平上限,请按 Retry-After 退避重试,C10.14)",
                    )),
                )
                    .into_response(),
            )
        }
        _ => None, // 放行 / fail-open(store 未配/瞬时错/CAS 耗尽 → 全局桶 + 反应式 503 兜底)
    }
}

/// 逐租户桶键前缀(spec 020 §3.1)。
const KMS_TENANT_GATE_PREFIX: &str = "kms-sign-tenant";

/// 逐租户 ECC/access Sign 闸参数(env 覆盖;capacity<=0=关,默认关)。份额据"Σ 份额 ≤ 全局容量"标定
/// (评审:别用 全局/N,桶容量[burst]可加会超订退 FCFS);refill 配宽以吸收 charge-but-no-sign 误扣(评审 Q2)。
fn kms_tenant_gate_params() -> (f64, f64) {
    fn envf(k: &str, d: f64) -> f64 {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(d)
    }
    (
        envf("AGENT_AUTH_KMS_TENANT_GATE_CAPACITY", 0.0),
        envf("AGENT_AUTH_KMS_TENANT_GATE_REFILL_PER_SEC", 20.0),
    )
}

/// KMS 前置闸参数(env 覆盖;capacity<=0=关)。真机据该区 Sign 配额实测标定(留裕量,别贴配额上限)。
fn kms_gate_params() -> (f64, f64) {
    fn envf(k: &str, d: f64) -> f64 {
        std::env::var(k)
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(d)
    }
    // 默认 capacity=0(关):须显式配 AGENT_AUTH_KMS_GATE_CAPACITY 启用,防误配掐死签发。
    (
        envf("AGENT_AUTH_KMS_GATE_CAPACITY", 0.0),
        envf("AGENT_AUTH_KMS_GATE_REFILL_PER_SEC", 100.0),
    )
}

/// 对已认证的 `client_id` 取 1 个 token。放行 → `None`;超额 → `Some(429 响应)`。
/// store 未配/瞬时错误 → `None`(fail-open 放行)。
pub async fn check(state: &AppState, tenant: &str, client_id: &str) -> Option<Response> {
    let rl = state.rate_limit.as_ref()?;
    let now = crate::token::current_unix_secs_pub();
    // tenant-scope(spec 020 §3.1):per-client 桶键前缀 tenant——同 client_id 跨租户碰撞时不互相打满桶
    // (SaaS 跨租户可用性耦合);空 tenant(flag 关)透传 byte-identical。
    let key = crate::tenant::tpk(tenant, client_id);
    match rl
        .try_consume(&key, now, TOKEN_RL_CAPACITY, TOKEN_RL_REFILL_PER_SEC, 1.0)
        .await
    {
        Ok(d) if !d.allowed => {
            // Retry-After:令牌桶估算(cost=1<capacity 故恒 Some);兜底 1s。
            let retry = d.retry_after_secs.unwrap_or(1).max(1);
            Some(
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(axum::http::header::RETRY_AFTER, retry.to_string())],
                    Json(TokenError::new(
                        // temporarily_unavailable(RFC 6749 §5.2;非 slow_down——那是 device/CIBA 轮询码,
                        // 评审 Kiro 与 CIBA 节流 L2 一致):AS 瞬时过载,客户端稍后重试。
                        "temporarily_unavailable",
                        "该 client 请求过于频繁,请稍候重试(应用层限流,C10.7)",
                    )),
                )
                    .into_response(),
            )
        }
        // 放行 / fail-open(存储瞬时错误 → 不阻断合法请求)。
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;

    // spec 020 §3.1 / 审计 P0-B:per-client 限流桶按 tenant 隔离——t1 打满**同一 client_id** 的桶,
    // t2 用同 client_id 不受影响(跨租户可用性耦合 + 用户/客户端存在性枚举 oracle 消除)。
    #[tokio::test]
    async fn check_bucket_isolated_across_tenants() {
        use crate::ports::RateLimitStore;

        let state = AppState::dev("localhost"); // 含 Memory rate_limit
        let client = "shared-client-id";
        let store = state.rate_limit.as_ref().expect("dev rate-limit store");
        let t1_key = crate::tenant::tpk("t1", client);
        assert!(
            store
                .try_consume(&t1_key, i64::MAX / 4, 1.0, 0.0, 1.0)
                .await
                .unwrap()
                .allowed,
            "test setup consumes the only token in a future-dated t1 bucket"
        );
        assert!(
            check(&state, "t1", client).await.is_some(),
            "the production gate must observe the exhausted t1 bucket"
        );
        // t2 用**同一 client_id** 仍应放行(桶键 tenant 隔离,不被 t1 打满波及)。
        assert!(
            check(&state, "t2", client).await.is_none(),
            "t2 同 client_id MUST 不受 t1 打满影响(跨租户桶隔离)"
        );
        // 空 tenant(self-host)独立分区,也不受 t1/t2 影响。
        assert!(
            check(&state, "", client).await.is_none(),
            "空 tenant 桶独立"
        );
    }

    // per-user 桶(recovery-gen / devcode-attempt)同样按 tenant 隔离——消除用户存在性枚举 oracle。
    #[tokio::test]
    async fn per_user_buckets_isolated_across_tenants() {
        let state = AppState::dev("localhost");
        let user = "user:alice@example.com";
        // 打满 t1 的 recovery-gen 桶(容量 5)。
        let mut hit = false;
        for _ in 0..10 {
            if recovery_generate_throttled(&state, "t1", user).await {
                hit = true;
                break;
            }
        }
        assert!(hit, "t1 recovery-gen 应触顶");
        assert!(
            !recovery_generate_throttled(&state, "t2", user).await,
            "t2 同 user recovery-gen MUST 不受 t1 影响(枚举 oracle 隔离)"
        );
    }

    #[test]
    fn kms_gate_test_run_uses_an_isolated_bucket() {
        assert_eq!(
            kms_gate_key(None).unwrap(),
            "global-kms-sign",
            "normal runtime must keep the shared production bucket"
        );
        assert_eq!(
            kms_gate_key(Some("0123456789abcdef0123456789abcdef")).unwrap(),
            "global-kms-sign:test:0123456789abcdef0123456789abcdef"
        );
    }

    #[test]
    fn kms_gate_test_run_rejects_ambiguous_or_weak_ids() {
        for invalid in [
            "",
            "0123456789ab",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(
                kms_gate_key(Some(invalid)).is_err(),
                "invalid test run must fail closed: {invalid}"
            );
        }
    }

    #[tokio::test]
    async fn kms_sign_gate_sheds_with_retry_after_before_another_sign_budget_is_spent() {
        let state = AppState::dev("localhost");
        let key = "global-kms-sign:test:00000000000000000000000000000001";

        assert!(
            kms_sign_gate_with_config(&state, key, 1.0, 0.0)
                .await
                .is_none(),
            "the first request must consume the only proactive sign permit"
        );
        let response = kms_sign_gate_with_config(&state, key, 1.0, 0.0)
            .await
            .expect("the next request must be shed before signing");
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(response.headers()[axum::http::header::RETRY_AFTER], "1");
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["error"], "temporarily_unavailable");
    }

    #[test]
    fn all_public_token_grants_gate_before_their_production_sign_call() {
        let cases = [
            (
                "authorization_code",
                include_str!("token.rs"),
                "let signed_access_token = match sign_tenant_access_token_with_delivery(",
            ),
            (
                "refresh_token",
                include_str!("refresh_flow.rs"),
                "let jwt = match crate::token::sign_tenant_access_token_with_delivery(",
            ),
            (
                "client_credentials",
                include_str!("workload_flow.rs"),
                "let jwt = match crate::token::sign_tenant_access_token(",
            ),
            (
                "token_exchange",
                include_str!("token_exchange.rs"),
                "let jwt = match crate::token::sign_tenant_delegation_token_with_delivery(",
            ),
            (
                "device_code",
                include_str!("device_flow.rs"),
                "let jwt = match sign_tenant_access_token(",
            ),
            (
                "ciba",
                include_str!("ciba_flow.rs"),
                "let jwt = match sign_tenant_access_token(",
            ),
            (
                "ema_jwt_bearer",
                include_str!("ema_flow.rs"),
                "let access_token = match crate::token::sign_tenant_access_token(",
            ),
        ];

        for (grant, source, sign_marker) in cases {
            let sign = source
                .find(sign_marker)
                .unwrap_or_else(|| panic!("{grant} production sign call moved"));
            let function_start = source[..sign].rfind("async fn ").unwrap_or_else(|| {
                panic!("{grant} production sign call must remain in async code")
            });
            let before_sign = &source[function_start..sign];
            for (gate_name, gate_marker) in [
                ("tenant", "crate::ratelimit_gate::kms_sign_tenant_gate("),
                ("global", "crate::ratelimit_gate::kms_sign_gate("),
            ] {
                assert!(
                    before_sign.contains(gate_marker),
                    "{grant} must invoke its {gate_name} KMS gate in the same function before signing"
                );
            }
        }
    }
}
