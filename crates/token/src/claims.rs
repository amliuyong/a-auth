//! C2.1 / C2.2a / C2.3 / C2.5a / C2.6 — access / ID token 的 claim 形状(纯逻辑,不签名)。
//!
//! 只负责"组装出符合契约的 claim 结构 + 校验形状",签名(KMS)属 spec 005。
//! 决策真相源:docs/DESIGN §2;pairwise/sub 派生规则见 §2.8(本模块不实现派生,只放已算好的 sub)。

use serde_json::{Map, Value};

/// 私有 claim 命名空间(云无关永久常量,docs/DESIGN §2)。
pub const NAMESPACE: &str = "https://a-auth.com/c";

/// JWT 体积**硬上限**(字节,C8.10 / docs §6):MCP access token 经 HTTP header 传,受 header 体积
/// 上限约束(常见 8KB)。签发前若最终 JWT 串 > 此值 **MUST 拒签**(不静默发超大 token)。
pub const JWT_HARD_LIMIT_BYTES: usize = 7 * 1024;
/// JWT 体积**软目标**(字节,C8.10):目标 access token < 此值;超过(但 ≤ 硬上限)可签但应告警/引导
/// 复杂 RAR 走 introspection。仅信息性,不拒签。
pub const JWT_SOFT_TARGET_BYTES: usize = 4 * 1024;

/// JWT 体积预算判定(C8.10)。`jwt_len` = 最终 JWT 串(`header.payload.signature`)字节数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SizeBudget {
    /// < 软目标:理想。
    WithinTarget,
    /// [软目标, 硬上限]:可签,但复杂 RAR 应优先 introspection(告警)。
    OverTargetWithinLimit,
    /// > 硬上限:MUST 拒签(要求收窄 RAR / 走 introspection)。
    ExceedsHardLimit,
}

/// 按最终 JWT 串长度判体积预算(C8.10)。签发侧组装+签名后调用;`ExceedsHardLimit` MUST 拒签。
pub fn check_jwt_size(jwt_len: usize) -> SizeBudget {
    if jwt_len > JWT_HARD_LIMIT_BYTES {
        SizeBudget::ExceedsHardLimit
    } else if jwt_len >= JWT_SOFT_TARGET_BYTES {
        SizeBudget::OverTargetWithinLimit
    } else {
        SizeBudget::WithinTarget
    }
}

/// 命名空间对象内**允许的预定义键**(C2.2a:只含这些,保留 claim 不得入内)。
pub const NAMESPACE_KEYS: &[&str] = &["sub_type", "auth_grant", "actor_types"];

/// 标准保留 claim(MUST NOT 出现在命名空间对象内;它们是顶层 claim)。
pub const RESERVED_CLAIMS: &[&str] = &[
    "iss",
    "sub",
    "aud",
    "exp",
    "iat",
    "nbf",
    "jti",
    "scope",
    "client_id",
    "azp",
    "cnf",
    "act",
    "auth_time",
    "acr",
    "amr",
    "grant_id",
    "nonce",
];

/// 主体类型(命名空间下 `sub_type`,C2.3)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubType {
    /// 3LO 用户(P0)。
    User,
    /// 2LO workload 客户端(P2)。
    Agent,
    /// 纯服务后端(P2)。
    Service,
}

impl SubType {
    pub fn as_str(self) -> &'static str {
        match self {
            SubType::User => "user",
            SubType::Agent => "agent",
            SubType::Service => "service",
        }
    }
}

/// 组装命名空间对象 `{"sub_type":..., "auth_grant":..., ["actor_types":...]}`(C2.2a)。
///
/// `actor_types`:委托链的 agent_id→类型叠加视图;None 时不放该键(如 2LO 无委托)。
/// 结构钉死:一层嵌套对象、只含预定义键(spec 001 C2.2a)。
pub fn namespace_object(sub_type: SubType, auth_grant: &str, actor_types: Option<Value>) -> Value {
    let mut m = Map::new();
    m.insert("sub_type".into(), Value::String(sub_type.as_str().into()));
    m.insert("auth_grant".into(), Value::String(auth_grant.into()));
    if let Some(at) = actor_types {
        m.insert("actor_types".into(), at);
    }
    Value::Object(m)
}

/// `aud` 编码:恒为**单元素 JSON 数组**(C2.5a,禁裸字符串)。
pub fn encode_aud(resource: &str) -> Value {
    Value::Array(vec![Value::String(resource.into())])
}

/// 校验一份已组装 claim 的**形状契约**(不校验签名/时效)。返回违规列表(空 = 合规)。
///
/// 检查:
/// - C2.1:含顶层 `client_id`(不被 `azp` 顶替)。
/// - C2.2a:私有字段全在命名空间对象下、对象只含预定义键、保留 claim 不入命名空间对象;
///   `act`(若有)只含 `sub`/嵌套 `act`。
/// - C2.5a:`aud`(若有)为单元素数组、非裸字符串。
pub fn validate_shape(claims: &Value) -> Vec<String> {
    let mut errs = Vec::new();
    let Some(obj) = claims.as_object() else {
        return vec!["claims 不是 JSON 对象".into()];
    };

    // C2.1:顶层 client_id 必在(azp 不顶替)。
    if !obj.contains_key("client_id") {
        errs.push("C2.1:缺顶层 client_id(azp 不能顶替)".into());
    }

    // C2.2a:私有 claim MUST 全部收进命名空间对象——顶层散落 sub_type/auth_grant/actor_types 违规。
    for pk in NAMESPACE_KEYS {
        if obj.contains_key(*pk) {
            errs.push(format!(
                "C2.2a:私有 claim {pk:?} MUST 收进命名空间对象,不得散落在顶层"
            ));
        }
    }

    // C2.2a:命名空间对象结构 + 值类型/取值。
    match obj.get(NAMESPACE) {
        Some(Value::Object(ns)) => {
            // 命名空间对象若存在,MUST 至少含 sub_type + auth_grant(签发必填);空对象违规。
            if !ns.contains_key("sub_type") || !ns.contains_key("auth_grant") {
                errs.push(
                    "C2.2a:命名空间对象存在时 MUST 含 sub_type 与 auth_grant(不得为空/缺项)".into(),
                );
            }
            for (k, v) in ns {
                if !NAMESPACE_KEYS.contains(&k.as_str()) {
                    errs.push(format!("C2.2a:命名空间对象含非预定义键 {k:?}"));
                }
                if RESERVED_CLAIMS.contains(&k.as_str()) {
                    errs.push(format!("C2.2a:保留 claim {k:?} 不得出现在命名空间对象内"));
                }
                // 值类型/取值(C2.3:sub_type ∈ {user,agent,service};auth_grant 字符串;actor_types 对象)。
                match k.as_str() {
                    "sub_type" if !matches!(v.as_str(), Some("user" | "agent" | "service")) => {
                        errs.push(format!(
                            "C2.3:sub_type 取值 MUST ∈ {{user,agent,service}},实际 {v}"
                        ));
                    }
                    "auth_grant" if !v.is_string() => {
                        errs.push("C2.2a:auth_grant MUST 是字符串".into());
                    }
                    "actor_types" if !v.is_object() => {
                        errs.push("C2.2a:actor_types MUST 是对象".into());
                    }
                    _ => {}
                }
            }
        }
        Some(_) => errs.push("C2.2a:命名空间必须是一层嵌套对象".into()),
        None => {} // 无命名空间对象是允许的(如某些最小 token),有则须合规
    }

    // act 若存在须纯 RFC 8693。
    if let Some(act) = obj.get("act") {
        if let Some(bad) = act_impurity(act) {
            errs.push(bad);
        }
    }

    // C2.5a:aud 若存在,须单元素数组。
    if let Some(aud) = obj.get("aud") {
        match aud {
            Value::Array(a) if a.len() == 1 && a[0].is_string() => {}
            Value::Array(a) => errs.push(format!("C2.5a:aud 必须单元素数组,实际长度 {}", a.len())),
            _ => errs.push("C2.5a:aud 必须是单元素 JSON 数组,不得用裸字符串".into()),
        }
    }

    errs
}

/// `act` 纯净性(C2.2a):`act` MUST 是对象、只含 `sub`(字符串)与嵌套 `act`(对象);
/// 其它形态即污染。返回 Some(错误) 表示不纯。
fn act_impurity(act: &Value) -> Option<String> {
    // RFC 8693:act 必须是 JSON 对象;裸字符串/数组/数字一律违规(否则漏判)。
    let Some(obj) = act.as_object() else {
        return Some("C2.2a:act 必须是 JSON 对象(RFC 8693)".into());
    };
    // act 对象必须含 sub(RFC 8693 act 的必填);空对象或缺 sub 违规。
    if !obj.contains_key("sub") {
        return Some("C2.2a:act 对象必须含 sub(RFC 8693)".into());
    }
    for (k, v) in obj {
        match k.as_str() {
            "sub" => {
                if !v.is_string() {
                    return Some("C2.2a:act.sub 必须是字符串".into());
                }
            }
            "act" => {
                if let Some(bad) = act_impurity(v) {
                    return Some(bad);
                }
            }
            other => {
                return Some(format!(
                    "C2.2a:act 含非 RFC 8693 字段 {other:?}(act 须纯净)"
                ))
            }
        }
    }
    None
}

/// **委托链深度**(C7.2 深度闸):数 `act` 的嵌套层数——0 = 无 `act`(未委托)、1 = 单层 `act`、
/// N = N 层嵌套(RFC 8693 nested act)。`claims` 是整个 token 的 claims 对象(读其 `act` 字段)。
///
/// 深度闸(token_exchange):`本token深度 = act_chain_depth(subject_claims)`,本跳后 = `+1`,
/// MUST `≤ Grant.max_act_chain`。取代此前"有无 act → 0/1"的二值近似(只支持 max_act_chain=1);
/// 现按真实嵌套深度计,支持 P2 `max_act_chain > 1` 的多级委托。
///
/// 只数嵌套结构(遇非对象或缺 `act` 即止),不做纯净性校验(那是 `validate_shape`/`act_impurity` 的事);
/// 防御性设深度上限 1024,避免超深恶意嵌套导致的计数开销。上限**远超任何合理 `max_act_chain`**
/// (真实委托链个位数),故截断只在病态输入发生,且截断值 ≥ 任何合理阈值 → `depth+1>max` 恒拒(fail-safe;
/// 评审 codex LOW:上限须 > 最大可能 max_act_chain 才保证截断是安全侧)。
pub fn act_chain_depth(claims: &Value) -> u32 {
    const HARD_CAP: u32 = 1024;
    let mut depth = 0u32;
    let mut cur = claims.get("act");
    while let Some(act) = cur {
        // act 须是对象才算有效一层;非对象(污染)不再深入(纯净性另由 validate_shape 拒)。
        let Some(obj) = act.as_object() else { break };
        depth += 1;
        if depth >= HARD_CAP {
            break;
        }
        cur = obj.get("act");
    }
    depth
}

/// 构造嵌套 `act` 链(C2.4:最外层 = 最近执行者、内层 = 更早委托方)。
/// `actors` 按**从最近到最早**顺序给出(actors[0] 是当前执行者)。
pub fn build_act_chain(actors: &[&str]) -> Option<Value> {
    if actors.is_empty() {
        return None;
    }
    // 从最早往最近包裹:最早的在最内层。
    let mut cur: Option<Value> = None;
    for sub in actors.iter().rev() {
        let mut m = Map::new();
        m.insert("sub".into(), Value::String((*sub).into()));
        if let Some(inner) = cur.take() {
            m.insert("act".into(), inner);
        }
        cur = Some(Value::Object(m));
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // C2.2a:命名空间对象结构 + act 纯净。
    #[test]
    fn namespace_object_shape() {
        let ns = namespace_object(SubType::User, "authorization_code", None);
        assert_eq!(ns["sub_type"], json!("user"));
        assert_eq!(ns["auth_grant"], json!("authorization_code"));
        assert!(ns.get("actor_types").is_none());
    }

    // C2.5a:aud 单元素数组。
    #[test]
    fn aud_is_single_element_array() {
        let aud = encode_aud("https://mcp.example.com");
        assert!(aud.is_array());
        assert_eq!(aud.as_array().unwrap().len(), 1);
        assert_eq!(aud[0], json!("https://mcp.example.com"));
    }

    // C2.1:缺 client_id 被判违规。
    #[test]
    fn missing_client_id_flagged() {
        let c = json!({ "sub": "usr_1", "azp": "cli_1" });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("C2.1")));
    }

    // C2.1:有 client_id(即便同时有 azp)合规。
    #[test]
    fn client_id_present_ok() {
        let c = json!({ "client_id": "cli_1", "azp": "cli_1" });
        assert!(validate_shape(&c).iter().all(|e| !e.contains("C2.1")));
    }

    // C2.2a:保留 claim 混进命名空间对象 → 违规。
    #[test]
    fn reserved_claim_in_namespace_flagged() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: { "sub_type": "user", "iss": "x" }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("保留 claim")));
    }

    // C2.2a:命名空间对象含未知键 → 违规。
    #[test]
    fn unknown_namespace_key_flagged() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: { "sub_type": "user", "evil": 1 }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("非预定义键")));
    }

    // C2.2a:命名空间不是对象(扁平前缀式)→ 违规。
    #[test]
    fn flat_namespace_rejected() {
        let c = json!({ "client_id": "cli_1", NAMESPACE: "sub_type=user" });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("一层嵌套对象")));
    }

    // C2.5a:aud 裸字符串 → 违规。
    #[test]
    fn bare_string_aud_rejected() {
        let c = json!({ "client_id": "cli_1", "aud": "https://rs" });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("C2.5a")));
    }

    // C2.5a:aud 多元素 → 违规。
    #[test]
    fn multi_aud_rejected() {
        let c = json!({ "client_id": "cli_1", "aud": ["a", "b"] });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("C2.5a")));
    }

    // C2.2a:act 塞私有字段 → 违规。
    #[test]
    fn impure_act_flagged() {
        let c = json!({
            "client_id": "cli_1",
            "act": { "sub": "agt_1", "sub_type": "agent" }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("act 含非 RFC 8693")));
    }

    // C2.2a(Kiro 边界 6 修复):act 是裸字符串(非对象)→ 违规。
    #[test]
    fn bare_string_act_rejected() {
        let c = json!({ "client_id": "cli_1", "act": "agt_1" });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("act 必须是 JSON 对象")));
    }

    // C2.2a:act 数组(非对象)→ 违规。
    #[test]
    fn array_act_rejected() {
        let c = json!({ "client_id": "cli_1", "act": ["agt_1"] });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("act 必须是 JSON 对象")));
    }

    // C2.2a:act 对象缺 sub → 违规。
    #[test]
    fn act_missing_sub_rejected() {
        let c = json!({ "client_id": "cli_1", "act": { "act": { "sub": "x" } } });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("act 对象必须含 sub")));
    }

    // C2.2a:命名空间空对象 → 违规(须含 sub_type + auth_grant)。
    #[test]
    fn empty_namespace_object_rejected() {
        let c = json!({ "client_id": "cli_1", NAMESPACE: {} });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("sub_type 与 auth_grant")));
    }

    // C2.5a:aud 空数组 → 违规。
    #[test]
    fn empty_aud_array_rejected() {
        let c = json!({ "client_id": "cli_1", "aud": [] });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("C2.5a")));
    }

    // C2.2a(codex 边界):私有键散落顶层 → 违规。
    #[test]
    fn top_level_private_key_rejected() {
        let c = json!({ "client_id": "cli_1", "sub_type": "user" });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("不得散落在顶层")));
    }

    // C2.3(codex 边界):sub_type 取值非法 → 违规。
    #[test]
    fn invalid_sub_type_value_rejected() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: { "sub_type": "sector", "auth_grant": "authorization_code" }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("C2.3")));
    }

    // C2.2a(codex 边界):auth_grant 非字符串 → 违规。
    #[test]
    fn non_string_auth_grant_rejected() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: { "sub_type": "user", "auth_grant": ["x"] }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("auth_grant MUST 是字符串")));
    }

    // C2.2a(codex 边界):actor_types 非对象 → 违规。
    #[test]
    fn non_object_actor_types_rejected() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: { "sub_type": "agent", "auth_grant": "client_credentials", "actor_types": "x" }
        });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("actor_types MUST 是对象")));
    }

    // C2.4(codex 边界):act.sub 非字符串 → 违规。
    #[test]
    fn non_string_act_sub_rejected() {
        let c = json!({ "client_id": "cli_1", "act": { "sub": 123 } });
        let errs = validate_shape(&c);
        assert!(errs.iter().any(|e| e.contains("act.sub 必须是字符串")));
    }

    // 合法命名空间对象(agent + actor_types 对象)通过。
    #[test]
    fn valid_agent_namespace_passes() {
        let c = json!({
            "client_id": "cli_1",
            NAMESPACE: {
                "sub_type": "agent",
                "auth_grant": "token_exchange",
                "actor_types": { "agt_1": "agent" }
            }
        });
        assert!(validate_shape(&c).is_empty(), "{:?}", validate_shape(&c));
    }

    // C2.4:act 深度 >2(service16→77→88)嵌套方向正确。
    #[test]
    fn act_chain_depth_three() {
        let act = build_act_chain(&[
            "https://service16.example.com",
            "https://service77.example.com",
            "https://service88.example.com",
        ])
        .unwrap();
        assert_eq!(act["sub"], json!("https://service16.example.com"));
        assert_eq!(act["act"]["sub"], json!("https://service77.example.com"));
        assert_eq!(
            act["act"]["act"]["sub"],
            json!("https://service88.example.com")
        );
        // 深链本身也须通过纯净校验。
        let c = json!({ "client_id": "cli_1", "act": act });
        assert!(validate_shape(&c).is_empty(), "{:?}", validate_shape(&c));
    }

    // C8.10:JWT 体积预算判定(软目标 4KB / 硬上限 7KB)。
    #[test]
    fn jwt_size_budget_thresholds() {
        assert_eq!(check_jwt_size(100), SizeBudget::WithinTarget);
        assert_eq!(
            check_jwt_size(JWT_SOFT_TARGET_BYTES - 1),
            SizeBudget::WithinTarget
        );
        assert_eq!(
            check_jwt_size(JWT_SOFT_TARGET_BYTES),
            SizeBudget::OverTargetWithinLimit
        );
        assert_eq!(
            check_jwt_size(JWT_HARD_LIMIT_BYTES),
            SizeBudget::OverTargetWithinLimit,
            "恰在硬上限不拒(> 才拒)"
        );
        assert_eq!(
            check_jwt_size(JWT_HARD_LIMIT_BYTES + 1),
            SizeBudget::ExceedsHardLimit
        );
    }

    // C7.2 深度闸:act_chain_depth 按真实嵌套层数计(0/1/N)。
    #[test]
    fn act_chain_depth_counts_nesting() {
        // 无 act → 0。
        assert_eq!(act_chain_depth(&json!({ "client_id": "c" })), 0);
        // 单层 → 1。
        assert_eq!(act_chain_depth(&json!({ "act": { "sub": "a1" } })), 1);
        // 三层嵌套 → 3(用 build_act_chain 造)。
        let act = build_act_chain(&["a1", "a2", "a3"]).unwrap();
        assert_eq!(act_chain_depth(&json!({ "act": act })), 3);
    }

    #[test]
    fn act_chain_depth_stops_at_non_object() {
        // act 是非对象(污染)→ 不算有效层,深度 0(纯净性另由 validate_shape 拒)。
        assert_eq!(act_chain_depth(&json!({ "act": "not-an-object" })), 0);
        // 中途嵌套 act 为非对象 → 只数到有效层。
        assert_eq!(
            act_chain_depth(&json!({ "act": { "sub": "a1", "act": "bad" } })),
            1
        );
    }

    // C2.4:act 嵌套方向 = 外层最近执行者、内层更早委托方(RFC 8693 §4.1 原示例)。
    #[test]
    fn act_chain_nesting_rfc8693_example() {
        // 最近执行者 service16、更早委托方 service77。
        let act = build_act_chain(&[
            "https://service16.example.com",
            "https://service77.example.com",
        ])
        .unwrap();
        assert_eq!(act["sub"], json!("https://service16.example.com"));
        assert_eq!(act["act"]["sub"], json!("https://service77.example.com"));
        assert!(act["act"].get("act").is_none());
    }

    // 组装出的完整 3LO token claim 通过形状校验。
    #[test]
    fn assembled_3lo_claim_passes_shape() {
        let c = json!({
            "iss": "https://t1.aws.example.com",
            "sub": "usr_pairwise_abc",
            "aud": encode_aud("https://mcp.example.com"),
            "client_id": "cli_1",
            "act": { "sub": "agt_1" },
            NAMESPACE: namespace_object(SubType::User, "token_exchange", None),
        });
        assert!(
            validate_shape(&c).is_empty(),
            "3LO claim 应通过形状校验:{:?}",
            validate_shape(&c)
        );
    }
}
