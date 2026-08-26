//! issuer host 提取的单一口径(C1.6a)。
//!
//! **CloudFront 统一入口(spec 025)**:CloudFront→API Gateway 时,`Host` 头 MUST 设为 API Gateway
//! 自身域名(否则 `$default` stage 路由不到),故对外 issuer host 经 **`X-Forwarded-Host`** 透传
//! (CloudFront Function 把 viewer 的 `Host` 复制进来)。本函数优先读 `X-Forwarded-Host`、回落 `Host`。
//!
//! **安全**:`X-Forwarded-Host` 只有在 `origin_auth::saas_origin_auth_layer` 已验证托管
//! CloudFront→API Gateway 跳后才可信。SaaS 全局 middleware 在任何 tenant/issuer 推导前执行；
//! 直连 API Gateway 即使伪造一个已配置租户 host 也会先被拒。SelfHosted 不依赖该头建立多租户边界。

use axum::http::HeaderMap;

use crate::state::AppState;

/// **从配置派生 SelfHosted issuer**(spec 012 §1.4 / C5.7,mTLS 用):X.509-mTLS 走独立域名 `mtls.<host>`,
/// **不能**从请求 Host 派生 issuer(评审 B2:`derive_issuer(mtls_host)` 会 HostMismatch)。SelfHosted 的 issuer
/// 恒 = 配置域 `configured_host`,与请求 Host 无关。SaaS 无单一配置 issuer → None(mTLS 仅 SelfHosted,评审 B1)。
pub(crate) fn self_hosted_issuer(
    form: &agent_auth_discovery::Form,
) -> Option<agent_auth_discovery::Issuer> {
    match form {
        agent_auth_discovery::Form::SelfHosted { configured_host } => {
            agent_auth_discovery::derive_issuer(configured_host, form).ok()
        }
        agent_auth_discovery::Form::Saas { .. } => None,
    }
}

/// 取对外 issuer host(去端口、转小写):优先 `X-Forwarded-Host`,回落 `Host`。空/缺失 → None。
pub(crate) fn issuer_host(headers: &HeaderMap) -> Option<String> {
    let raw = headers
        .get("x-forwarded-host")
        .or_else(|| headers.get(axum::http::header::HOST))?
        .to_str()
        .ok()?;
    // X-Forwarded-Host 可能是逗号分隔链(取第一个 = 最靠近 viewer 的);再去端口。
    let first = raw.split(',').next().unwrap_or(raw);
    let host = first
        .split(':')
        .next()
        .unwrap_or(first)
        .trim()
        .to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

/// 浏览器交互页面的当前 origin。SelfHosted 使用部署级公开 SPA origin;SaaS 必须跟随
/// 当前合法租户 Host,绝不能回落到 control host 的全局 `WEB_BASE_URL`。
pub(crate) fn browser_origin(state: &AppState, headers: &HeaderMap) -> Option<String> {
    match &state.form {
        agent_auth_discovery::Form::SelfHosted { .. } => Some(state.web_base_url.clone()),
        agent_auth_discovery::Form::Saas { .. } => {
            let host = issuer_host(headers)?;
            agent_auth_discovery::derive_issuer(&host, &state.form)
                .ok()
                .map(|issuer| issuer.as_str().to_string())
        }
    }
}
