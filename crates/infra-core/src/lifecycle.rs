//! C10.4 / C10.6 — 短命项 `expires_at` 读写校验 + 全局时钟偏移余量。
//!
//! - **C10.4**:DynamoDB TTL 只做异步 GC(可延迟数天),MUST NOT 作有效期判断。短命项
//!   (code/device_code/session_token/jti/宽限缓存)的有效性 MUST 在**读/写路径**校 `expires_at`,
//!   命中已过期项即拒/删,MUST NOT 依赖"TTL 到了会消失"(见 DESIGN §2.1 TTL 只做 GC)。
//! - **C10.6**:跨 Lambda/RS 时钟偏移会误杀极短时效项。系统 MUST 全局声明可接受偏移余量
//!   (默认 ±30s),校 `exp`/`nbf`/`iat` 时统一套用;移除轮换旧 key 也留同样余量(见 DESIGN §2.1)。
//!
//! ⚠️ **两类校验语义相反,不可混用同一余量方向**:
//! - **本系统自存的短命项(C10.4)= fail-closed**:精确 `now >= expires_at` 即判过期、拒/删,
//!   **不加宽限余量**——宁可早拒(客户端重走授权代价小),绝不放行已过期的 code/jti(那会
//!   扩大授权码/重放窗口)。这是安全侧的一次性凭据,不是要跨方兼容的 token。
//! - **校验他方签发的 token 时间戳(C10.6)= 留 skew 宽容**:exp/nbf/iat 套 ±skew,避免因
//!   AS 与 RS 的时钟偏差误杀对方合法 token。
//!
//! 本模块纯时间戳算术、零 AWS 依赖:`now` 一律由上层传入(不读墙上时钟,便于确定性单测)。
//! 时间单位 = Unix 秒。决策真相源:docs/DESIGN §2.1;docs/CONFORMANCE C10.4·C10.6。

/// 全局时钟偏移余量默认值(秒)。**仅**用于校 exp/nbf/iat 与移除旧 key(C10.6);
/// 短命项过期(C10.4)不套此余量(见 `shortlived_is_expired`)。
pub const DEFAULT_CLOCK_SKEW_SECS: i64 = 30;

/// 短命项在读/写路径的有效性判定(C10.4)。**不看 DynamoDB TTL**,只看 `expires_at`。
/// `now`、`expires_at` 均为 Unix 秒。**fail-closed 精确判定**:`now >= expires_at` 即过期,
/// MUST 拒/删——**不加时钟偏移宽限**(那会放行已过期的 authorization code / jti,扩大重放窗口,
/// 违反 C10.4"命中已过期项即拒")。短命项是本系统自存的一次性凭据,不需为跨方时钟兼容留余量。
pub fn shortlived_is_expired(now: i64, expires_at: i64) -> bool {
    now >= expires_at
}

/// 便捷:短命项是否仍**有效**(可放行)。
pub fn shortlived_is_valid(now: i64, expires_at: i64) -> bool {
    !shortlived_is_expired(now, expires_at)
}

/// token 时间戳三元组校验结果(C10.6)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeClaimError {
    /// 已过期:`now - skew >= exp`(连回拨 skew 都过期)。
    Expired,
    /// 尚未生效:`now + skew < nbf`。
    NotYetValid,
    /// `iat` 在未来过多(超出 skew):可能时钟异常 / 伪造。
    IssuedInFuture,
}

/// 校验 token 的 `exp`/`nbf`/`iat`,统一套用偏移余量 `skew`(C10.6)。
/// `nbf`/`iat` 为 `None` 表示 token 未带该 claim(合法,跳过对应检查)。
/// 边界语义:余量内视为"有效/未生效边界的有效侧",而非零容差直接判失效。
pub fn check_time_claims(
    now: i64,
    exp: i64,
    nbf: Option<i64>,
    iat: Option<i64>,
    skew: i64,
) -> Result<(), TimeClaimError> {
    // exp:只有当 now 减去余量后仍 >= exp 才算过期(给对方时钟略慢留余地)。
    if now.saturating_sub(skew) >= exp {
        return Err(TimeClaimError::Expired);
    }
    // nbf:now 加上余量后仍 < nbf 才算未生效(给对方时钟略快留余地)。
    if let Some(nbf) = nbf {
        if now.saturating_add(skew) < nbf {
            return Err(TimeClaimError::NotYetValid);
        }
    }
    // iat:签发时间显著晚于 now(超出余量)→ 可疑。
    if let Some(iat) = iat {
        if iat > now.saturating_add(skew) {
            return Err(TimeClaimError::IssuedInFuture);
        }
    }
    Ok(())
}

/// 轮换 retire:旧公钥可安全移除的最早时刻(C10.6 + C10.11b)。
/// = 最后一枚用旧 key 签的 token 的 `exp` + skew。到此刻前 MUST 保留旧公钥在 JWKS。
pub fn key_retire_earliest(last_signed_token_exp: i64, skew: i64) -> i64 {
    last_signed_token_exp.saturating_add(skew)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SKEW: i64 = DEFAULT_CLOCK_SKEW_SECS;

    // C10.4:expires_at 已过 → 判过期,即使 DynamoDB TTL 未删。
    #[test]
    fn shortlived_expired() {
        assert!(shortlived_is_expired(1000, 900));
        assert!(!shortlived_is_valid(1000, 900));
    }

    // C10.4 fail-closed:刚过期(仅差 1s)也立即判过期,**不给时钟偏移宽限**——
    // 已过期的 authorization code / jti MUST NOT 因 skew 被放行(否则扩大重放窗口)。
    #[test]
    fn shortlived_expired_no_skew_grace() {
        // now=1000, exp=980,已过期 20s → 即使有 30s skew 也必须判过期
        assert!(
            shortlived_is_expired(1000, 980),
            "已过期项 MUST 拒,不套 skew 宽限"
        );
        assert!(!shortlived_is_valid(1000, 980));
    }

    // C10.4:边界 now==expires_at 即过期(精确 fail-closed)。
    #[test]
    fn shortlived_boundary_expired() {
        assert!(shortlived_is_expired(1000, 1000));
        assert!(shortlived_is_valid(999, 1000)); // 差 1s 仍有效
    }

    // C10.4:未过期项放行。
    #[test]
    fn shortlived_future_valid() {
        assert!(shortlived_is_valid(1000, 5000));
    }

    // C10.6:exp 过期。
    #[test]
    fn exp_expired() {
        assert_eq!(
            check_time_claims(2000, 1900, None, None, SKEW),
            Err(TimeClaimError::Expired)
        );
    }

    // C10.6:exp 边界内(余量)视为有效。
    #[test]
    fn exp_within_skew_valid() {
        // now=1000, exp=990, now-skew=970 < 990 → 有效
        assert!(check_time_claims(1000, 990, None, None, SKEW).is_ok());
    }

    // C10.6:nbf 未到(超出余量)→ 未生效。
    #[test]
    fn nbf_not_yet_valid() {
        // now=1000, nbf=1100, now+skew=1030 < 1100 → 未生效
        assert_eq!(
            check_time_claims(1000, 9999, Some(1100), None, SKEW),
            Err(TimeClaimError::NotYetValid)
        );
    }

    // C10.6:nbf 在余量内 → 视为已生效。
    #[test]
    fn nbf_within_skew_valid() {
        // now=1000, nbf=1020, now+skew=1030 >= 1020 → 生效
        assert!(check_time_claims(1000, 9999, Some(1020), None, SKEW).is_ok());
    }

    // C10.6:iat 在未来过多 → 可疑。
    #[test]
    fn iat_in_future_rejected() {
        assert_eq!(
            check_time_claims(1000, 9999, None, Some(1100), SKEW),
            Err(TimeClaimError::IssuedInFuture)
        );
    }

    // C10.6:iat 在余量内的未来 → 接受。
    #[test]
    fn iat_slightly_future_ok() {
        assert!(check_time_claims(1000, 9999, None, Some(1025), SKEW).is_ok());
    }

    // 全部合法。
    #[test]
    fn all_claims_valid() {
        assert!(check_time_claims(1000, 2000, Some(900), Some(1000), SKEW).is_ok());
    }

    // C10.6:retire 时刻 = last exp + skew(移除旧 key 留余量)。
    #[test]
    fn retire_leaves_skew_margin() {
        assert_eq!(key_retire_earliest(5000, SKEW), 5030);
    }

    // skew=0(零容差)边界:token claim 校验下 exp==now 即过期。
    #[test]
    fn zero_skew_boundary() {
        assert_eq!(
            check_time_claims(1000, 1000, None, None, 0),
            Err(TimeClaimError::Expired)
        );
    }
}
