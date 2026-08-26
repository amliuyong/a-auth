//! RAR(RFC 9396 `authorization_details`)**发行侧准入校验**(spec 010 §4 / C8.5a / DESIGN §6)。
//!
//! ⚠️ **职责边界**:本模块只做**发行准入**(AS 侧 `/authorize` 收到 authorization_details 时)——
//! 校验每条结构合法 + `type` ∈ 内建词汇表 + 约束字段 ∈ 词汇表 + 值格式合法。**不做运行时 enforce**
//! (RS 侧 SDK `enforce_rar` 的职责:valid_from/to 时刻比对、resource_subset 命中、max_records 计数)。
//!
//! **词汇表必须与 SDK(sdk/python/agent_auth_rs/rar.py + sdk/ts/src/rar.ts)对齐**——三份定义靠
//! 共享 fixture 语料(tests/fixtures/rar_admission.json)+ 本注释单一来源锚定,防漂移。
//!
//! 词汇表 `type = agent_auth_rar_v1`,约束字段:`valid_from`/`valid_to`(RFC3339 串或 epoch 数)、
//! `resource_subset`(string[])、`max_records`(非负整数)。RFC 9396 元数据字段(type/locations/
//! actions/datatypes/identifier/privileges)不算约束、不触发未知字段拒。
//!
//! **fail-closed 红线(与 SDK enforce 同口径)**:①未知 `type` → 拒;②词汇表外未知约束字段 → 拒
//! (原子性:发行侧就挡住 SDK 会整条 fail-closed 的 RAR,不签发一个到 RS 必被拒的 token)。

use serde_json::Value;

/// 内建 RAR 词汇表版本(与 SDK RAR_TYPE_V1 对齐)。
pub const RAR_TYPE_V1: &str = "agent_auth_rar_v1";

/// 词汇表内的约束字段(执行语义已定义;与 SDK `_VOCAB_CONSTRAINT_FIELDS` 对齐)。
const VOCAB_CONSTRAINT_FIELDS: &[&str] =
    &["valid_from", "valid_to", "resource_subset", "max_records"];
/// RFC 9396 固有元数据字段(非约束,不触发未知字段拒;与 SDK `_RFC9396_META_FIELDS` 对齐)。
const RFC9396_META_FIELDS: &[&str] = &[
    "type",
    "locations",
    "actions",
    "datatypes",
    "identifier",
    "privileges",
];

/// RAR 准入拒绝原因(映射 OAuth 错误码 `invalid_authorization_details` 由 IO 层做)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RarAdmissionError {
    /// authorization_details 顶层不是数组。
    NotArray,
    /// 某条不是 JSON 对象。
    EntryNotObject,
    /// 某条缺 `type` 或 `type` 非字符串。
    MissingType,
    /// `type` 不在内建词汇表(未知 type → SDK 会整条 fail-closed,发行侧即拒)。
    UnknownType(String),
    /// 词汇表外未知约束字段(原子性:防 SDK 侧整条 fail-closed)。
    UnknownConstraintField(String),
    /// 约束字段值格式非法(如 valid_from 非 RFC3339/epoch、resource_subset 非字符串数组、max_records 非非负整数)。
    BadConstraintValue(String),
    /// 超准入体积上限(数组条数 / 单条字节;纵深防御,不只靠末端 JWT 尺寸)。
    TooLarge,
    /// 带 locations 的 RAR 未命中任何授权 resource(越界 → 落空扩权面,fail-closed 拒;评审 codex HIGH)。
    LocationsOutOfBounds,
}

/// 准入体积上限(纵深防御;远小于 JWT 硬上限,发行入口即挡住 DoS 面)。
const MAX_ENTRIES: usize = 16;
const MAX_ENTRY_BYTES: usize = 2048;

/// **校验整个 authorization_details 数组的发行准入**(spec 010 §4)。
/// 通过 → Ok(());任一条不合规 → Err(第一个错因,fail-closed)。空数组合法(等价无 RAR)。
pub fn validate_admission(authorization_details: &Value) -> Result<(), RarAdmissionError> {
    let arr = authorization_details
        .as_array()
        .ok_or(RarAdmissionError::NotArray)?;
    if arr.len() > MAX_ENTRIES {
        return Err(RarAdmissionError::TooLarge);
    }
    for entry in arr {
        validate_entry(entry)?;
    }
    Ok(())
}

/// **发行准入 + locations 越界校验**(spec 010 §4,评审 codex HIGH):在 `validate_admission` 结构校验
/// 之上,额外要求**每条带 `locations` 的 RAR 至少命中一个授权 resource**——否则该条对所有签发 aud 都
/// 不适用(被 locations 过滤掉、claim 消失),而 SDK 视缺失 RAR 为 scope 级放行 → 签出**比 RAR 请求更宽**
/// 的 token(违"AS 准入即挡住 RS 会拒/落空的 RAR")。无 locations 的条目=全局适用,不需此校验。
/// `authorized_resources` = 本次 authorize 声明的 resource 集合。
pub fn validate_admission_for_resources(
    authorization_details: &Value,
    authorized_resources: &[String],
) -> Result<(), RarAdmissionError> {
    validate_admission(authorization_details)?;
    let arr = authorization_details
        .as_array()
        .ok_or(RarAdmissionError::NotArray)?;
    for entry in arr {
        // 有 locations 的条目:MUST 至少命中一个授权 resource(否则越界 = 落空扩权面)。
        if has_locations(entry)
            && !authorized_resources
                .iter()
                .any(|r| location_matches(entry, r))
        {
            return Err(RarAdmissionError::LocationsOutOfBounds);
        }
    }
    Ok(())
}

/// 校验单条 authorization_details。
fn validate_entry(entry: &Value) -> Result<(), RarAdmissionError> {
    let obj = entry.as_object().ok_or(RarAdmissionError::EntryNotObject)?;
    // 单条字节上限(纵深)。
    if serde_json::to_string(entry)
        .map(|s| s.len())
        .unwrap_or(usize::MAX)
        > MAX_ENTRY_BYTES
    {
        return Err(RarAdmissionError::TooLarge);
    }
    // type ∈ 词汇表。
    let type_str = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or(RarAdmissionError::MissingType)?;
    if type_str != RAR_TYPE_V1 {
        return Err(RarAdmissionError::UnknownType(type_str.to_string()));
    }
    // 每个字段:要么是 RFC9396 元数据,要么是词汇表约束(且值格式合法);其余 → 未知约束字段拒。
    for (k, v) in obj {
        if RFC9396_META_FIELDS.contains(&k.as_str()) {
            continue; // 元数据不校约束值(locations 等格式由 §Q3 归属逻辑另处理)
        }
        if VOCAB_CONSTRAINT_FIELDS.contains(&k.as_str()) {
            validate_constraint_value(k, v)?;
        } else {
            return Err(RarAdmissionError::UnknownConstraintField(k.clone()));
        }
    }
    Ok(())
}

/// 校约束字段值格式(与 SDK enforce 的解析口径一致,发行侧提前挡格式错)。
fn validate_constraint_value(field: &str, v: &Value) -> Result<(), RarAdmissionError> {
    let bad = || RarAdmissionError::BadConstraintValue(field.to_string());
    match field {
        // 时刻:RFC3339 字符串 或 epoch 数(与 SDK _parse_instant 口径一致)。
        "valid_from" | "valid_to" => {
            if !is_valid_instant(v) {
                return Err(bad());
            }
        }
        // 资源子集:字符串数组(每元素字符串)。
        "resource_subset" => {
            let arr = v.as_array().ok_or_else(bad)?;
            if !arr.iter().all(Value::is_string) {
                return Err(bad());
            }
        }
        // 记录数上界:非负整数。
        "max_records" => {
            let n = v.as_i64().ok_or_else(bad)?;
            if n < 0 {
                return Err(bad());
            }
        }
        _ => {} // validate_entry 已保证只有词汇表字段进来
    }
    Ok(())
}

/// 时刻值合法性(RFC3339 串或 epoch 数;与 SDK `_parse_instant` 口径一致)。
fn is_valid_instant(v: &Value) -> bool {
    match v {
        Value::Number(_) => true, // epoch 秒
        Value::String(s) => parse_rfc3339(s.trim()).is_some(),
        _ => false,
    }
}

/// RFC3339 校验(不引 chrono,但**校数值范围**——与 SDK `datetime.fromisoformat` 拒非法日期口径靠拢,
/// 评审 codex MEDIUM:仅查字符位置会放过 month=99 等 SDK 会拒的值)。接受 `YYYY-MM-DDTHH:MM:SS[.fff]
/// [Z|±HH:MM]`;date/time 用 'T'/'t' 分隔。校 month 1–12、day 1–31、hour 0–23、min/sec 0–59。
fn parse_rfc3339(s: &str) -> Option<()> {
    let bytes = s.as_bytes();
    if bytes.len() < 19 {
        return None;
    }
    // 取两位十进制(位置须为数字)。
    let two = |i: usize| -> Option<u32> {
        let (a, b) = (bytes[i], bytes[i + 1]);
        if a.is_ascii_digit() && b.is_ascii_digit() {
            Some(((a - b'0') as u32) * 10 + (b - b'0') as u32)
        } else {
            None
        }
    };
    // YYYY 四位数字。
    if !bytes[0..4].iter().all(u8::is_ascii_digit) {
        return None;
    }
    if bytes[4] != b'-' || bytes[7] != b'-' || !(bytes[10] == b'T' || bytes[10] == b't') {
        return None;
    }
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let month = two(5)?;
    let day = two(8)?;
    let hour = two(11)?;
    let min = two(14)?;
    let sec = two(17)?;
    // 数值范围(不查每月天数/闰年,足够挡住 SDK 会拒的明显非法值,如 month=99/hour=88)。
    if (1..=12).contains(&month) && (1..=31).contains(&day) && hour <= 23 && min <= 59 && sec <= 60
    // 允许闰秒 60
    {
        Some(())
    } else {
        None
    }
}

/// resource ∈ 白名单:精确匹配;item 以 `/` 结尾则前缀匹配(**与 SDK `_resource_in_subset` 逐字节一致**:
/// 前缀用带斜杠的 item 本身,`resource.starts_with(item)`,不 strip 斜杠)。非字符串元素跳过。
fn resource_in_subset(resource: &str, subset: &[Value]) -> bool {
    subset.iter().any(|item| match item.as_str() {
        Some(s) if s.ends_with('/') => resource.starts_with(s),
        Some(s) => resource == s,
        None => false,
    })
}

/// 某 resource 是否被该 RAR 条目的 `locations` 选中(**与 SDK `_detail_applies` 逐口径一致**,防 AS/RS 漂移):
/// - `locations` **缺失**(无该字段)→ 全局适用(true);
/// - `locations` 存在但**非数组** → false(fail-closed,与 SDK `isinstance(locs,list)` 一致);
/// - 数组 → `resource_in_subset`(精确 / 带斜杠前缀)。
pub fn location_matches(entry: &Value, resource: &str) -> bool {
    match entry.get("locations") {
        None => true, // 缺失 = 全局
        Some(Value::Array(locs)) => resource_in_subset(resource, locs),
        Some(_) => false, // 存在但非数组 → fail-closed
    }
}

/// 该条 RAR 是否**有 locations**(用于越界准入判定:有 locations 才需校验是否命中授权 resource 集)。
fn has_locations(entry: &Value) -> bool {
    entry.get("locations").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn admits_valid_v1() {
        let ad = json!([{
            "type": "agent_auth_rar_v1",
            "locations": ["https://mcp.kb.example.com"],
            "valid_from": "2026-01-01T00:00:00Z",
            "valid_to": 1798761600,
            "resource_subset": ["https://mcp.kb.example.com/docs/"],
            "max_records": 100
        }]);
        assert_eq!(validate_admission(&ad), Ok(()));
    }

    #[test]
    fn empty_array_ok() {
        assert_eq!(validate_admission(&json!([])), Ok(()));
    }

    #[test]
    fn non_array_rejected() {
        assert_eq!(
            validate_admission(&json!({"type": "x"})),
            Err(RarAdmissionError::NotArray)
        );
    }

    #[test]
    fn unknown_type_rejected() {
        let ad = json!([{"type": "custom_policy_v9", "foo": 1}]);
        assert_eq!(
            validate_admission(&ad),
            Err(RarAdmissionError::UnknownType("custom_policy_v9".into()))
        );
    }

    #[test]
    fn missing_type_rejected() {
        assert_eq!(
            validate_admission(&json!([{"valid_to": 100}])),
            Err(RarAdmissionError::MissingType)
        );
    }

    #[test]
    fn unknown_constraint_field_rejected() {
        // 词汇表外字段(非 RFC9396 元数据)→ fail-closed(否则 SDK 会整条拒)。
        let ad = json!([{"type": "agent_auth_rar_v1", "max_amount": 500}]);
        assert_eq!(
            validate_admission(&ad),
            Err(RarAdmissionError::UnknownConstraintField(
                "max_amount".into()
            ))
        );
    }

    #[test]
    fn rfc9396_meta_fields_allowed() {
        // actions/datatypes/identifier/privileges 是 RFC9396 元数据,不触发未知字段拒。
        let ad = json!([{
            "type": "agent_auth_rar_v1",
            "actions": ["read"],
            "datatypes": ["document"],
            "identifier": "acct-1",
            "privileges": ["admin"]
        }]);
        assert_eq!(validate_admission(&ad), Ok(()));
    }

    #[test]
    fn bad_constraint_values_rejected() {
        // valid_from 非 RFC3339/epoch。
        assert!(matches!(
            validate_admission(&json!([{"type":"agent_auth_rar_v1","valid_from":"not-a-date"}])),
            Err(RarAdmissionError::BadConstraintValue(_))
        ));
        // resource_subset 非字符串数组。
        assert!(matches!(
            validate_admission(&json!([{"type":"agent_auth_rar_v1","resource_subset":[1,2]}])),
            Err(RarAdmissionError::BadConstraintValue(_))
        ));
        // max_records 负数。
        assert!(matches!(
            validate_admission(&json!([{"type":"agent_auth_rar_v1","max_records":-1}])),
            Err(RarAdmissionError::BadConstraintValue(_))
        ));
        // max_records 非整数。
        assert!(matches!(
            validate_admission(&json!([{"type":"agent_auth_rar_v1","max_records":"lots"}])),
            Err(RarAdmissionError::BadConstraintValue(_))
        ));
    }

    #[test]
    fn entry_not_object_rejected() {
        assert_eq!(
            validate_admission(&json!(["a string"])),
            Err(RarAdmissionError::EntryNotObject)
        );
    }

    #[test]
    fn too_many_entries_rejected() {
        let many: Vec<Value> = (0..20)
            .map(|_| json!({"type": "agent_auth_rar_v1"}))
            .collect();
        assert_eq!(
            validate_admission(&Value::Array(many)),
            Err(RarAdmissionError::TooLarge)
        );
    }

    // location_matches 与 SDK `_detail_applies`/`_resource_in_subset` 逐口径一致(评审 codex MEDIUM 收敛)。
    #[test]
    fn locations_matching() {
        let e = json!({"type":"agent_auth_rar_v1","locations":["https://a.example.com","https://b.example.com/"]});
        assert!(location_matches(&e, "https://a.example.com")); // 精确
        assert!(location_matches(&e, "https://b.example.com/docs")); // 带斜杠前缀(item 含斜杠)
        assert!(!location_matches(&e, "https://c.example.com")); // 不匹配
                                                                 // locations 缺失 = 全局适用。
        let g = json!({"type":"agent_auth_rar_v1"});
        assert!(location_matches(&g, "https://anything"));
        // locations 存在但非数组 → fail-closed false(与 SDK isinstance(list) 一致)。
        let bad = json!({"type":"agent_auth_rar_v1","locations":"not-a-list"});
        assert!(!location_matches(&bad, "https://anything"));
        // locations 空数组 → 不命中任何(与 SDK 一致:空白名单 deny-all)。
        let empty = json!({"type":"agent_auth_rar_v1","locations":[]});
        assert!(!location_matches(&empty, "https://anything"));
    }

    // 越界 locations 准入拒(评审 codex HIGH):带 locations 但不命中任何授权 resource → 拒。
    #[test]
    fn out_of_bounds_locations_rejected() {
        let authorized = vec!["https://rs-a.example.com".to_string()];
        // 命中 → Ok。
        let ok = json!([{"type":"agent_auth_rar_v1","locations":["https://rs-a.example.com"]}]);
        assert_eq!(validate_admission_for_resources(&ok, &authorized), Ok(()));
        // 越界(指向未授权 resource)→ 拒。
        let oob = json!([{"type":"agent_auth_rar_v1","locations":["https://evil.example.com"]}]);
        assert_eq!(
            validate_admission_for_resources(&oob, &authorized),
            Err(RarAdmissionError::LocationsOutOfBounds)
        );
        // 无 locations(全局)→ 不受越界校验约束,Ok。
        let global = json!([{"type":"agent_auth_rar_v1","max_records":10}]);
        assert_eq!(
            validate_admission_for_resources(&global, &authorized),
            Ok(())
        );
        // 结构不合规仍先拒(未知 type)。
        let bad = json!([{"type":"custom_v9"}]);
        assert!(matches!(
            validate_admission_for_resources(&bad, &authorized),
            Err(RarAdmissionError::UnknownType(_))
        ));
    }

    #[test]
    fn valid_instant_forms() {
        assert!(is_valid_instant(&json!(1798761600)));
        assert!(is_valid_instant(&json!("2026-01-01T00:00:00Z")));
        assert!(is_valid_instant(&json!("2026-01-01T00:00:00+08:00")));
        assert!(!is_valid_instant(&json!("2026-01-01"))); // 缺时间段
        assert!(!is_valid_instant(&json!("garbage")));
        assert!(!is_valid_instant(&json!(true)));
        // 数值范围(评审 codex MEDIUM:仅查字符位置会放过非法值)。
        assert!(!is_valid_instant(&json!("2026-99-01T00:00:00Z"))); // month 99
        assert!(!is_valid_instant(&json!("2026-01-01T88:00:00Z"))); // hour 88
        assert!(!is_valid_instant(&json!("2026-13-01T00:00:00Z"))); // month 13
        assert!(!is_valid_instant(&json!("2026-00-01T00:00:00Z"))); // month 0
    }
}
