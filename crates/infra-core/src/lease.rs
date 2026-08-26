//! C10.1 — 两阶段 lease 与三失败分治(纯状态机)。
//!
//! code/refresh 兑换走两阶段 lease:①原子条件占 lease(短 TTL,`ConditionExpression` 保证同一
//! code/refresh 并发只有一个进签名)→ ②KMS Sign → ③事务性 finalize(标记 code 已消费 / 轮换
//! refresh family + 写宽限缓存)。三种失败**分治**归因(见 DESIGN §8 两阶段 lease):
//! - ① 签名前/中的**瞬时 KMS 失败**(限流/`server_error`):释放 lease、**不消费**,可安全重试;
//! - ② **授权语义失败**(参数错/策略拒):落 `exchange_failed`、**消费 code**,须重走授权;
//! - ③ **Sign 成功但 finalize 失败**(DynamoDB 事务冲突/限流):code MUST NOT 消费、lease 停
//!   `signing` 态直至 TTL,MUST NOT 归 `exchange_failed`;已签发未 finalize 的那次 Sign 作废、
//!   不可恢复,重试重走完整两阶段(重签)。
//!
//! 本模块只做**状态转移与失败归因的纯逻辑**;DynamoDB 条件写/事务(实际占 lease、finalize、
//! TTL 到期)在 Lambda 层(见 spec 005 实现边界 [c])。`now`/TTL 由上层传入。
//! refresh 的兑换单位 = refresh family(轮换/复用检测语义见 spec 001 / C3.1),本模块对 code 与
//! refresh 对称处理:①/③ 不推进(不消费 code、不轮换 family),② 语义失败仅 code 流落 `exchange_failed`。
//!
//! 决策真相源:docs/DESIGN §8·§2.1;docs/CONFORMANCE C10.1。

/// lease 覆盖的兑换凭据类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantCredential {
    /// authorization code(一次性,消费即标记 used)。
    Code,
    /// refresh token(兑换单位 = family;"消费"= 轮换 family 到新版本 + 写宽限缓存)。
    Refresh,
}

/// lease 生命周期状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseState {
    /// 未占用(尚未进入签名)。
    Idle,
    /// 已原子占 lease、进入签名阶段(短 TTL)。
    Signing,
    /// finalize 成功:code 已消费 / refresh family 已轮换。终态。
    Finalized,
    /// 语义失败:code 已消费、落 exchange_failed。终态。
    ExchangeFailed,
}

/// 签发热路径的三类失败(+ 成功)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignOutcome {
    /// 签名 + finalize 全成功。
    Success,
    /// ① 签名前/中瞬时 KMS 失败(限流/server_error)。
    KmsTransient,
    /// ② 授权语义失败(参数错/策略拒)。
    SemanticFailure,
    /// ③ Sign 成功但 step-3 finalize 事务失败(DynamoDB 冲突/限流)。
    FinalizeFailure,
}

/// 一次兑换尝试后的处置(状态机输出)——上层据此决定 DynamoDB 写与响应码。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseResolution {
    /// lease 的新状态。
    pub lease: LeaseState,
    /// 凭据是否被消费(code=标记 used;refresh=轮换 family)。
    pub credential_consumed: bool,
    /// 是否释放 lease(允许安全重试同一凭据)。
    pub release_lease: bool,
    /// 是否落 `exchange_failed`(仅语义失败)。
    pub exchange_failed: bool,
    /// 建议对客户端返回的处置(便于映射 HTTP)。
    pub client_signal: ClientSignal,
}

/// 对客户端的信号(不含具体 HTTP 码,由 HTTP 层映射)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientSignal {
    /// 成功返回 token。
    TokenIssued,
    /// 可安全重试(瞬时失败;HTTP 层映射 503 + Retry-After,见 C10.2)。
    RetryableTransient,
    /// 处理中(lease 未到期的并发/重试;非 exchange_failed)。
    InProgress,
    /// 明确拒绝、须重走授权(语义失败)。
    Rejected,
}

/// 占 lease:仅当当前为 `Idle` 才能进 `Signing`(模拟 ConditionExpression 的"至多一个")。
/// 已在 `Signing`(并发/重试且 lease 未到期)→ 返回 None(上层给 InProgress,不重复签名)。
/// 终态(Finalized/ExchangeFailed)→ 也 None(凭据已了结)。
pub fn try_acquire_lease(current: LeaseState) -> Option<LeaseState> {
    match current {
        LeaseState::Idle => Some(LeaseState::Signing),
        _ => None,
    }
}

/// 三失败分治:给定已进入 `Signing` 的 lease 与本次签发结局,算出处置(C10.1 核心)。
pub fn resolve(cred: GrantCredential, outcome: SignOutcome) -> LeaseResolution {
    match outcome {
        // 成功:消费凭据、finalize。
        SignOutcome::Success => LeaseResolution {
            lease: LeaseState::Finalized,
            credential_consumed: true,
            release_lease: false,
            exchange_failed: false,
            client_signal: ClientSignal::TokenIssued,
        },
        // ① 瞬时 KMS 失败:释放 lease、不消费、可重试。
        SignOutcome::KmsTransient => LeaseResolution {
            lease: LeaseState::Idle, // 释放回 Idle,允许安全重试
            credential_consumed: false,
            release_lease: true,
            exchange_failed: false,
            client_signal: ClientSignal::RetryableTransient,
        },
        // ② 语义失败:消费 code、落 exchange_failed。
        // refresh 的语义拒绝不落 exchange_failed(该态是 code 流概念),也不轮换 family;
        // 但仍视为明确拒绝(Rejected),复用检测以"呈现非当前版本"为准(spec 001/C3.1)。
        SignOutcome::SemanticFailure => match cred {
            GrantCredential::Code => LeaseResolution {
                lease: LeaseState::ExchangeFailed,
                credential_consumed: true,
                release_lease: false,
                exchange_failed: true,
                client_signal: ClientSignal::Rejected,
            },
            GrantCredential::Refresh => LeaseResolution {
                lease: LeaseState::Idle,
                credential_consumed: false, // 不轮换 family
                release_lease: true,
                exchange_failed: false, // 非 code 流的 exchange_failed 态
                client_signal: ClientSignal::Rejected,
            },
        },
        // ③ finalize 失败:不消费、lease 停 Signing 态直至 TTL、不算 exchange_failed。
        // 已签发未 finalize 的 Sign 作废(token 未返回)。lease TTL 到期后可重试重签。
        SignOutcome::FinalizeFailure => LeaseResolution {
            lease: LeaseState::Signing, // 停在 signing 直至 TTL 到期
            credential_consumed: false,
            release_lease: false,
            exchange_failed: false,
            client_signal: ClientSignal::InProgress,
        },
    }
}

/// lease TTL 是否已到期(到期后 `Signing` 态可被重新占用重签)。`now`/`lease_expires_at` = Unix 秒。
pub fn lease_expired(now: i64, lease_expires_at: i64) -> bool {
    now >= lease_expires_at
}

/// 处理一个到达的兑换请求:结合当前 lease 状态与(若可签)本次结局,给出处置。
/// - `Idle`:占 lease → 按 outcome resolve。
/// - `Signing` 且未到期:并发/重试 → InProgress(不重复签名)。
/// - `Signing` 且已到期:视同可重新占用(上层应先 CAS 抢占;此处按 Idle 语义 resolve)。
/// - 终态:凭据已了结 → Rejected/已消费,不再签。
pub fn handle_request(
    cred: GrantCredential,
    current: LeaseState,
    now: i64,
    lease_expires_at: i64,
    attempt_outcome: SignOutcome,
) -> LeaseResolution {
    match current {
        LeaseState::Idle => resolve(cred, attempt_outcome),
        LeaseState::Signing => {
            if lease_expired(now, lease_expires_at) {
                // TTL 到期:允许重新占用重签(③ 的可重试语义)。
                resolve(cred, attempt_outcome)
            } else {
                // 未到期的并发/重试:处理中,不重复签名、不消费、不失败归因。
                LeaseResolution {
                    lease: LeaseState::Signing,
                    credential_consumed: false,
                    release_lease: false,
                    exchange_failed: false,
                    client_signal: ClientSignal::InProgress,
                }
            }
        }
        LeaseState::Finalized => LeaseResolution {
            lease: LeaseState::Finalized,
            credential_consumed: true, // 已消费
            release_lease: false,
            exchange_failed: false,
            client_signal: ClientSignal::Rejected, // 已兑换过,重放拒
        },
        LeaseState::ExchangeFailed => LeaseResolution {
            lease: LeaseState::ExchangeFailed,
            credential_consumed: true,
            release_lease: false,
            exchange_failed: true,
            client_signal: ClientSignal::Rejected,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // 占 lease:Idle→Signing 唯一成功,再占返回 None(并发只有一个进签名)。
    #[test]
    fn acquire_lease_at_most_one() {
        assert_eq!(
            try_acquire_lease(LeaseState::Idle),
            Some(LeaseState::Signing)
        );
        assert_eq!(try_acquire_lease(LeaseState::Signing), None);
        assert_eq!(try_acquire_lease(LeaseState::Finalized), None);
        assert_eq!(try_acquire_lease(LeaseState::ExchangeFailed), None);
    }

    // C10.1 成功:消费 code + finalize。
    #[test]
    fn success_consumes_and_finalizes() {
        let r = resolve(GrantCredential::Code, SignOutcome::Success);
        assert_eq!(r.lease, LeaseState::Finalized);
        assert!(r.credential_consumed);
        assert!(!r.exchange_failed);
        assert_eq!(r.client_signal, ClientSignal::TokenIssued);
    }

    // C10.1 ①:KMS 瞬时失败释放 lease、不消费 code、可重试。
    #[test]
    fn kms_transient_releases_no_consume() {
        let r = resolve(GrantCredential::Code, SignOutcome::KmsTransient);
        assert_eq!(r.lease, LeaseState::Idle);
        assert!(!r.credential_consumed);
        assert!(r.release_lease);
        assert!(!r.exchange_failed);
        assert_eq!(r.client_signal, ClientSignal::RetryableTransient);
    }

    // C10.1 ②:语义失败消费 code、落 exchange_failed。
    #[test]
    fn semantic_failure_consumes_code_exchange_failed() {
        let r = resolve(GrantCredential::Code, SignOutcome::SemanticFailure);
        assert_eq!(r.lease, LeaseState::ExchangeFailed);
        assert!(r.credential_consumed);
        assert!(r.exchange_failed);
        assert_eq!(r.client_signal, ClientSignal::Rejected);
    }

    // C10.1 ③:finalize 失败不消费、停 signing、不算 exchange_failed。
    #[test]
    fn finalize_failure_stays_signing_no_consume() {
        let r = resolve(GrantCredential::Code, SignOutcome::FinalizeFailure);
        assert_eq!(r.lease, LeaseState::Signing);
        assert!(!r.credential_consumed);
        assert!(!r.exchange_failed, "③ MUST NOT 归为 exchange_failed");
        assert_eq!(r.client_signal, ClientSignal::InProgress);
    }

    // refresh 对称:① 瞬时失败不轮换 family、可重试。
    #[test]
    fn refresh_kms_transient_no_rotate() {
        let r = resolve(GrantCredential::Refresh, SignOutcome::KmsTransient);
        assert!(!r.credential_consumed, "family MUST NOT 轮换");
        assert_eq!(r.client_signal, ClientSignal::RetryableTransient);
    }

    // refresh 对称:③ finalize 失败不轮换 family、停 signing。
    #[test]
    fn refresh_finalize_failure_no_rotate() {
        let r = resolve(GrantCredential::Refresh, SignOutcome::FinalizeFailure);
        assert_eq!(r.lease, LeaseState::Signing);
        assert!(!r.credential_consumed);
        assert!(!r.exchange_failed);
    }

    // refresh 语义失败:不落 exchange_failed(code 流概念)、不轮换 family、明确拒。
    #[test]
    fn refresh_semantic_failure_no_exchange_failed() {
        let r = resolve(GrantCredential::Refresh, SignOutcome::SemanticFailure);
        assert!(!r.exchange_failed);
        assert!(!r.credential_consumed);
        assert_eq!(r.client_signal, ClientSignal::Rejected);
    }

    // 并发/重试在 lease 未到期时 → InProgress(不重复签名、不误标)。
    #[test]
    fn concurrent_within_ttl_in_progress() {
        let r = handle_request(
            GrantCredential::Code,
            LeaseState::Signing,
            100,                  // now
            200,                  // lease_expires_at(未到期)
            SignOutcome::Success, // 即便本次能签,也不该重复签
        );
        assert_eq!(r.client_signal, ClientSignal::InProgress);
        assert!(!r.credential_consumed);
        assert!(!r.exchange_failed);
    }

    // C10.1 ③ 续:lease TTL 到期后用同一 code 重试 → 能成功重签。
    #[test]
    fn expired_lease_allows_resign() {
        let r = handle_request(
            GrantCredential::Code,
            LeaseState::Signing,
            300, // now
            200, // lease_expires_at(已到期)
            SignOutcome::Success,
        );
        assert_eq!(r.lease, LeaseState::Finalized);
        assert!(r.credential_consumed);
        assert!(!r.exchange_failed, "重签全程不被误标 exchange_failed");
        assert_eq!(r.client_signal, ClientSignal::TokenIssued);
    }

    // 终态 Finalized:重放同一 code → 拒(已消费)。
    #[test]
    fn finalized_replay_rejected() {
        let r = handle_request(
            GrantCredential::Code,
            LeaseState::Finalized,
            100,
            200,
            SignOutcome::Success,
        );
        assert_eq!(r.client_signal, ClientSignal::Rejected);
        assert!(r.credential_consumed);
    }

    // 语义失败后重放 → 仍拒(exchange_failed 终态)。
    #[test]
    fn exchange_failed_replay_rejected() {
        let r = handle_request(
            GrantCredential::Code,
            LeaseState::ExchangeFailed,
            100,
            200,
            SignOutcome::Success,
        );
        assert_eq!(r.client_signal, ClientSignal::Rejected);
        assert!(r.exchange_failed);
    }

    // lease_expired 边界。
    #[test]
    fn lease_expiry_boundary() {
        assert!(!lease_expired(199, 200));
        assert!(lease_expired(200, 200));
        assert!(lease_expired(201, 200));
    }
}
