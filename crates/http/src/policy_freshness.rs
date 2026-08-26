//! 签发热路径的 Cedar 策略新鲜度闸 + §7.2 请求上下文比对(spec 005 §7 / C10.17,T7.4)。
//!
//! **热路径,零 Cedar**:只做 u64 版本比较(is_stale)+ CIDR 匹配(§7.2 纯函数)。**绝不**调 authz::evaluate。
//! - **stale**(`grant.effective_pv < current_pv`)→ **拒 `503 temporarily_unavailable` + Retry-After**
//!   (评审 Blocker:热路径算不出"旧∩新交集"[需 Cedar];stale=待重算,可重试码;交集是重算的产出)。
//! - **ip/vpc 不匹配**(§7.2:`allowed_ip_cidrs`/`allowed_vpce` 非空且来源不在内)→ 拒 `access_denied`(永久)。
//! - **flag 关** → no-op(不 gate,字节等价现网)。
//!
//! current_pv 来源 = **进程内短 TTL 缓存**(补强 ⑭):绝不每请求同步查 DynamoDB;冷启动/过期未预热 → 保守当 stale 拒。

use crate::ports::PolicyVersionStore;
use crate::state::AppState;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;

/// current_pv 缓存 TTL(秒):热路径读本地缓存,过期才后台刷一次。短 TTL 保证 bump 后有界收敛。
const CURRENT_PV_CACHE_TTL_SECS: i64 = 10;

/// 取本租户 current_pv(进程内短 TTL 缓存;过期/未预热 → 刷新一次)。返回 `None` = 取不到(store 错/未预热)
/// → 调用方**保守当 stale**(fail-safe)。**不在锁内做 IO**:先读缓存,过期则释锁、查 store、再写缓存。
async fn current_pv(state: &AppState, tenant: &str, now: i64) -> Option<u64> {
    // 1. 读缓存(命中且未过期 → 直接返回)。
    {
        let cache = state.current_pv_cache.lock().await;
        if let Some(&(pv, at)) = cache.get(tenant) {
            if now - at < CURRENT_PV_CACHE_TTL_SECS {
                return Some(pv);
            }
        }
    }
    // 2. 过期/未命中 → 查 store(锁外),成功则写回缓存。
    match state.policy_versions.get(tenant).await {
        Ok(pv) => {
            state
                .current_pv_cache
                .lock()
                .await
                .insert(tenant.to_string(), (pv, now));
            Some(pv)
        }
        Err(_) => None, // store 瞬时错 → 调用方保守当 stale(fail-safe)
    }
}

/// 取**可信**来源 IP(§7.2,补强 ⑬)。当前**无可信来源接线** → 恒返回 `None`(fail-safe):
///
/// 补强 ⑬ 明令 source_ip MUST 取 API-GW/Lambda **可信 request context**(`requestContext.http.sourceIp`),
/// **绝不信 `X-Forwarded-For`**——CloudFront/API-GW 是**追加**客户端 IP 到 XFF(可信值在**右**段),首段是
/// **调用方完全可控**的伪造位。授权 allowlist 用 XFF 首段 = 攻击者发 `XFF: <白名单内IP>` 即绕过(评审 H2)。
/// 该可信 context 尚未从 Lambda event 线到 handler(§7.2 IP/VPC 端到端未接通:`evaluate` 亦未从策略析出
/// CIDR,见 evaluate.rs);故此处**返回 None** → 调用方对"策略要求 IP 白名单"的 Grant **fail-closed 拒**
/// (纯逻辑 `ip_in_cidrs` 已就位,待可信来源注入 + evaluate 输出 CIDR 一并落地,P3 独立切片)。
fn source_ip(_headers: &HeaderMap) -> Option<String> {
    // 可信来源(requestContext.http.sourceIp)未接线 → None(fail-safe,绝不退回可伪造的 XFF)。
    None
}

/// **热路径 fail-safe 闸**:flag 关 no-op;flag 开则 stale→503 拒、ip/vpc 不匹配→access_denied 拒。
/// `Ok(())` = 放行(签发继续读 effective_view);`Err(resp)` = 调用方直接返回该响应。**零 Cedar**。
pub async fn stale_gate(
    state: &AppState,
    tenant: &str,
    grant: &agent_auth_grant::Grant,
    headers: &HeaderMap,
    now: i64,
) -> Result<(), axum::response::Response> {
    if !state.authz_enabled {
        return Ok(()); // flag 关:不 gate(字节等价)。
    }
    // 1. 新鲜度:current_pv 取不到(未预热/store 错)→ 保守当 stale;grant.effective_pv < current → stale。
    let cur = current_pv(state, tenant, now).await;
    let is_stale = match cur {
        Some(cur_pv) => grant.effective_pv < cur_pv,
        None => true, // fail-safe:拿不到 current_pv 就当 stale 拒(可重试)
    };
    if is_stale {
        return Err(crate::token::err_retry_after(
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
            "授权策略重算中,请稍候重试(policy stale;C10.17 fail-safe)",
            2,
        )
        .into_response());
    }
    // 2. §7.2 请求上下文:allowed_ip_cidrs 非空则来源 IP MUST ∈;坏 CIDR / 取不到 IP → fail-closed 拒。
    if !grant.allowed_ip_cidrs.is_empty() {
        let Some(ip) = source_ip(headers) else {
            return Err(crate::token::err(
                StatusCode::FORBIDDEN,
                "access_denied",
                "来源 IP 不可辨,策略要求 IP 白名单(§7.2)",
            )
            .into_response());
        };
        match agent_auth_authz::ip_in_cidrs(&ip, &grant.allowed_ip_cidrs) {
            Ok(true) => {}
            Ok(false) | Err(_) => {
                // 不在白名单 / 坏 CIDR / 坏 IP → fail-closed 拒(§7.2)。
                return Err(crate::token::err(
                    StatusCode::FORBIDDEN,
                    "access_denied",
                    "来源 IP 不在授权策略允许范围(§7.2)",
                )
                .into_response());
            }
        }
    }
    // 注(§7.2 落地口径,评审 H1/H2):`evaluate` 当前不从策略析出 CIDR/VPCE(恒返回空),且可信来源
    // IP 尚未从 API-GW request context 线到 handler(source_ip 恒 None)。故本闸对"策略要求 IP 白名单"的
    // Grant **fail-closed 拒**、绝不退回可伪造 XFF。纯逻辑(ip_in_cidrs)+ fail-safe 方向已就位;真正端到端
    // 生效(evaluate 输出 CIDR + Lambda event 注入可信 sourceIp/vpce)是 P3 独立切片(见 spec 005 §7.2)。
    Ok(())
}
