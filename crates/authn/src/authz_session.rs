//! 授权会话状态机纯逻辑(spec 004,C6)。零 IO、零 AWS:只定义态、合法迁移、终态判定、
//! session_token 哈希与常量时间比对、事件回放(按序号去重排序)。
//!
//! **授权会话** = 一次 authorize 流从发起到 complete 的生命周期,与 magic-link **登录会话**
//! (`http::ports::SessionRecord`)是两个独立概念(见 spec 004 Purpose)。持久化/查询在 http 层。
//!
//! 决策真相源:docs/DESIGN §4;docs/CONFORMANCE C6.1–C6.5。

use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

type HmacSha256 = Hmac<Sha256>;

/// session_token 哈希的 HMAC domain(与其它 HMAC 用途隔离)。
const TOKEN_HMAC_DOMAIN: &[u8] = b"authz-session-token:";

/// 授权会话状态(auth-code 流;device/CIBA 等价态 P2,docs §4 表)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzState {
    Created,
    PendingUserAuthentication,
    PendingConsent,
    CodeIssuedAwaitingExchange,
    Complete,
    ExchangeFailed,
    Expired,
    Denied,
    Revoked,
}

impl AuthzState {
    pub fn as_str(self) -> &'static str {
        match self {
            AuthzState::Created => "created",
            AuthzState::PendingUserAuthentication => "pending_user_authentication",
            AuthzState::PendingConsent => "pending_consent",
            AuthzState::CodeIssuedAwaitingExchange => "code_issued_awaiting_exchange",
            AuthzState::Complete => "complete",
            AuthzState::ExchangeFailed => "exchange_failed",
            AuthzState::Expired => "expired",
            AuthzState::Denied => "denied",
            AuthzState::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "created" => AuthzState::Created,
            "pending_user_authentication" => AuthzState::PendingUserAuthentication,
            "pending_consent" => AuthzState::PendingConsent,
            "code_issued_awaiting_exchange" => AuthzState::CodeIssuedAwaitingExchange,
            "complete" => AuthzState::Complete,
            "exchange_failed" => AuthzState::ExchangeFailed,
            "expired" => AuthzState::Expired,
            "denied" => AuthzState::Denied,
            "revoked" => AuthzState::Revoked,
            _ => return None,
        })
    }

    /// 终态:MUST NOT 再迁出(docs §4,exchange_failed 亦为终态)。
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            AuthzState::Complete
                | AuthzState::ExchangeFailed
                | AuthzState::Expired
                | AuthzState::Denied
                | AuthzState::Revoked
        )
    }

    /// 合法迁移判定(docs §4 迁移方向)。终态不可迁出;expired 可由任一非终态因超时进入。
    pub fn can_transition_to(self, to: AuthzState) -> bool {
        use AuthzState::*;
        if self.is_terminal() {
            return false;
        }
        // 任一非终态 → expired(超时);→ revoked(吊销,P2)也从任一非终态可达。
        if matches!(to, Expired | Revoked) {
            return true;
        }
        match (self, to) {
            (Created, PendingUserAuthentication) => true,
            (Created, PendingConsent) => true, // 已登录直接待同意
            (PendingUserAuthentication, PendingConsent) => true,
            (PendingConsent, CodeIssuedAwaitingExchange) => true,
            (PendingConsent, Denied) => true, // 用户拒绝
            (CodeIssuedAwaitingExchange, Complete) => true,
            (CodeIssuedAwaitingExchange, ExchangeFailed) => true,
            _ => false,
        }
    }
}

/// 生成 session_token 的存储哈希:HMAC-SHA256(server_secret, domain‖token)。存哈希不存明文。
pub fn session_token_hash(server_secret: &[u8], token: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC any key len");
    mac.update(TOKEN_HMAC_DOMAIN);
    mac.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// 常量时间比对两个 base64 哈希串(session_token 鉴权,C6.2:不因值早退)。
pub fn token_hash_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Verify a presented authorization-session bearer without exposing a
/// variable-time comparison seam to the HTTP handler.
pub fn session_token_matches(
    server_secret: &[u8],
    presented_token: &str,
    expected_hash: &str,
) -> bool {
    token_hash_eq(
        &session_token_hash(server_secret, presented_token),
        expected_hash,
    )
}

/// 一条投影事件(EventBridge 投射的最小形状:会话 id + 序号 + 目标态)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectionEvent {
    pub session_id: String,
    pub sequence: u64,
    pub state: String,
}

/// 按会话分区,再按每会话单调序号**去重 + 排序**回放(C6.5)。
/// 输入可跨会话、可乱序、可含重复 sequence(重复取首次出现);每个会话输出按 sequence 升序。
pub fn replay_by_sequence(
    events: &[ProjectionEvent],
) -> std::collections::BTreeMap<String, Vec<ProjectionEvent>> {
    let mut by_session = std::collections::BTreeMap::<
        String,
        std::collections::BTreeMap<u64, ProjectionEvent>,
    >::new();
    for e in events {
        by_session
            .entry(e.session_id.clone())
            .or_default()
            .entry(e.sequence)
            .or_insert_with(|| e.clone());
    }
    by_session
        .into_iter()
        .map(|(session_id, events)| (session_id, events.into_values().collect()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"dev-secret-not-for-prod";

    #[test]
    fn happy_path_transitions_legal() {
        use AuthzState::*;
        assert!(Created.can_transition_to(PendingUserAuthentication));
        assert!(PendingUserAuthentication.can_transition_to(PendingConsent));
        assert!(PendingConsent.can_transition_to(CodeIssuedAwaitingExchange));
        assert!(CodeIssuedAwaitingExchange.can_transition_to(Complete));
    }

    #[test]
    fn already_logged_in_skips_to_consent() {
        assert!(AuthzState::Created.can_transition_to(AuthzState::PendingConsent));
    }

    #[test]
    fn deny_and_fail_reachable() {
        assert!(AuthzState::PendingConsent.can_transition_to(AuthzState::Denied));
        assert!(
            AuthzState::CodeIssuedAwaitingExchange.can_transition_to(AuthzState::ExchangeFailed)
        );
    }

    #[test]
    fn terminal_states_cannot_transition_out() {
        use AuthzState::*;
        for t in [Complete, ExchangeFailed, Expired, Denied, Revoked] {
            assert!(t.is_terminal());
            // 终态不可迁到任何态(含 expired/complete)。
            for to in [
                Complete,
                CodeIssuedAwaitingExchange,
                Expired,
                PendingConsent,
            ] {
                assert!(!t.can_transition_to(to), "{:?}→{:?} 应非法", t, to);
            }
        }
    }

    #[test]
    fn exchange_failed_is_terminal_no_reissue() {
        // C6.3b:exchange_failed 不可迁回 code_issued / complete。
        assert!(
            !AuthzState::ExchangeFailed.can_transition_to(AuthzState::CodeIssuedAwaitingExchange)
        );
        assert!(!AuthzState::ExchangeFailed.can_transition_to(AuthzState::Complete));
    }

    #[test]
    fn any_nonterminal_can_expire() {
        use AuthzState::*;
        for s in [
            Created,
            PendingUserAuthentication,
            PendingConsent,
            CodeIssuedAwaitingExchange,
        ] {
            assert!(s.can_transition_to(Expired));
        }
    }

    #[test]
    fn illegal_skips_rejected() {
        // created 不能直接跳到 code_issued(必须过 consent)。
        assert!(!AuthzState::Created.can_transition_to(AuthzState::CodeIssuedAwaitingExchange));
        // pending_consent 不能直接 complete。
        assert!(!AuthzState::PendingConsent.can_transition_to(AuthzState::Complete));
    }

    #[test]
    fn state_str_roundtrip() {
        for s in [
            AuthzState::Created,
            AuthzState::PendingUserAuthentication,
            AuthzState::PendingConsent,
            AuthzState::CodeIssuedAwaitingExchange,
            AuthzState::Complete,
            AuthzState::ExchangeFailed,
            AuthzState::Expired,
            AuthzState::Denied,
            AuthzState::Revoked,
        ] {
            assert_eq!(AuthzState::parse(s.as_str()), Some(s));
        }
        assert_eq!(AuthzState::parse("bogus"), None);
    }

    #[test]
    fn token_hash_deterministic_and_ct_eq() {
        let h1 = session_token_hash(SECRET, "tok-abc");
        let h2 = session_token_hash(SECRET, "tok-abc");
        assert_eq!(h1, h2);
        assert!(token_hash_eq(&h1, &h2));
        let h3 = session_token_hash(SECRET, "tok-xyz");
        assert!(!token_hash_eq(&h1, &h3));
        // 不同 secret → 不同哈希。
        assert_ne!(h1, session_token_hash(b"other", "tok-abc"));
    }

    #[test]
    fn token_hash_eq_length_mismatch_false() {
        assert!(!token_hash_eq("abc", "abcd"));
    }

    #[test]
    fn replay_groups_sessions_dedups_and_orders() {
        let ev = |session_id: &str, seq: u64, st: &str| ProjectionEvent {
            session_id: session_id.into(),
            sequence: seq,
            state: st.into(),
        };
        // 两个会话各自乱序 + 重复投递,相同 sequence 不得跨会话互相覆盖。
        let events = vec![
            ev("s1", 2, "pending_consent"),
            ev("s2", 1, "pending_consent"),
            ev("s1", 0, "created"),
            ev("s2", 0, "created"),
            ev("s1", 3, "code_issued_awaiting_exchange"),
            ev("s2", 0, "created"), // 重复
            ev("s1", 0, "created"), // 重复
            ev("s1", 1, "pending_user_authentication"),
            ev("s1", 4, "complete"),
            ev("s1", 3, "code_issued_awaiting_exchange"), // 重复
        ];
        let replayed = replay_by_sequence(&events);
        let s1 = replayed.get("s1").expect("s1 replay");
        let s1_seq: Vec<u64> = s1.iter().map(|e| e.sequence).collect();
        assert_eq!(s1_seq, vec![0, 1, 2, 3, 4], "s1 去重 + 按序号升序");
        let s1_states: Vec<&str> = s1.iter().map(|e| e.state.as_str()).collect();
        assert_eq!(
            s1_states,
            vec![
                "created",
                "pending_user_authentication",
                "pending_consent",
                "code_issued_awaiting_exchange",
                "complete"
            ]
        );
        let s2 = replayed.get("s2").expect("s2 replay");
        let s2_seq: Vec<u64> = s2.iter().map(|e| e.sequence).collect();
        assert_eq!(s2_seq, vec![0, 1]);
    }
}
