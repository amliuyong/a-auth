//! SigV4 `client_assertion` 封装解析 + audience 头**被签名覆盖**核对(spec 012 C5.2/H3)。
//!
//! 纯逻辑、不真调 STS。核心:预签名 SigV4 的 `Authorization` 头里 `SignedHeaders=` 只列**头名**;
//! 要防"转发前塞入的未签名伪造 audience 头",AS **MUST** 先确认 audience 头名 ∈ `SignedHeaders`、
//! 再核对其值 = 本 AS issuer。STS 只验签名覆盖的内容,不看未签名头——不检查就会被绕过(§3.1)。

use crate::replay::{extract_signature, parse_amz_date, sts_host_allowed, within_ttl};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// SigV4 client_assertion 封装(客户端把预签名 `sts:GetCallerIdentity` 的要素随此传入)。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigV4Assertion {
    pub method: String,
    /// STS endpoint URL(host allowlist 校验在 IO 层)。
    pub url: String,
    /// 请求头(含 `Authorization`、`X-Amz-Date`、audience 头及其**值**)。头名规范化小写。
    pub headers: BTreeMap<String, String>,
    #[serde(default)]
    pub body: String,
}

/// 从 SigV4 `Authorization` 头解析出 `SignedHeaders=` 列表(小写头名集合)。
///
/// 形如:`AWS4-HMAC-SHA256 Credential=...,SignedHeaders=host;x-amz-date;x-agent-auth-audience,Signature=...`
/// 找不到 `SignedHeaders=` 段返回 None(视为无效)。
pub fn parse_signed_headers(authorization: &str) -> Option<Vec<String>> {
    // 定位 "SignedHeaders=" 段(逗号分隔的三段之一)。
    let seg = authorization.split(',').find_map(|s| {
        let s = s.trim();
        s.strip_prefix("SignedHeaders=")
    })?;
    // 段内以 ';' 分隔头名;规范化小写、去空。
    let headers: Vec<String> = seg
        .split(';')
        .map(|h| h.trim().to_ascii_lowercase())
        .filter(|h| !h.is_empty())
        .collect();
    if headers.is_empty() {
        None
    } else {
        Some(headers)
    }
}

/// C5.2 核心判定:audience 头是否**被签名覆盖且值 = 期望的本 AS issuer**。
///
/// 返回 true 仅当:①`Authorization` 头存在且可解析出 `SignedHeaders`;②`audience_header_name`
/// (小写)∈ `SignedHeaders`;③assertion.headers 里该头的值 == `expected_issuer`。
/// 任一不满足返回 false(未签名的伪造头 / 值不符 / 缺头一律拒)。
pub fn audience_signed(
    assertion: &SigV4Assertion,
    audience_header_name: &str,
    expected_issuer: &str,
) -> bool {
    let name = audience_header_name.to_ascii_lowercase();
    // ① 取 Authorization 头(headers 已约定小写键)。
    let Some(authz) = assertion.headers.get("authorization") else {
        return false;
    };
    // ② 解析 SignedHeaders,确认 audience 头名被签名覆盖。
    let Some(signed) = parse_signed_headers(authz) else {
        return false;
    };
    if !signed.iter().any(|h| h == &name) {
        return false; // 未签名的伪造 audience 头 → 拒
    }
    // ③ 核对该头的值 = 本 AS issuer(常量时间无关紧要:非秘密比较)。
    assertion
        .headers
        .get(&name)
        .map(|v| v == expected_issuer)
        .unwrap_or(false)
}

/// SigV4/STS 兜底路径**转发 STS 前**的拒绝原因(C5.2/C5.3;纯判定,IO 层据此拒或转发)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SigV4RejectReason {
    /// 缺 `Authorization` 头 / 无法解析 `SignedHeaders`。
    MissingOrUnparsableAuthorization,
    /// audience 绑定头未被签名覆盖(不在 `SignedHeaders` 内)或值 ≠ 本 AS issuer(C5.2)。
    AudienceNotSignedOrMismatch,
    /// 缺 `X-Amz-Date` 或格式非法。
    MissingOrInvalidAmzDate,
    /// 预签名请求过老/过于未来(超短 TTL±skew,C5.3①)。
    OutsideTtl,
    /// STS host 不在 allowlist(客户端伪造 endpoint,C5.3③)。
    StsHostNotAllowed,
    /// URL 无法解析出 host。
    UnparsableUrl,
    /// 无法从 `Authorization` 提取 `Signature=` 段(算不出 replay key)。
    MissingSignature,
}

/// SigV4 预校验**通过**的产物(供 IO 层:据此做一次性 replay 缓存 + 转发固定 STS host)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigV4Validated {
    /// 经 allowlist 校验的 STS host(转发目标)。
    pub sts_host: String,
    /// `Authorization` 的 `Signature=` 段——replay key 只哈希此段(评审 M1);IO 层 `HMAC(secret, 此值)`。
    pub signature: String,
    /// Signed request creation time, used by a regional activation fence.
    pub issued_at: i64,
}

/// 从 URL 提取 host(`scheme://[userinfo@]host[:port]/...`)。纯解析,失败 None。
///
/// **MUST 剥 userinfo**(评审:`https://sts.amazonaws.com@x.amazonaws.com/` 的真 host 是 `x.amazonaws.com`
/// ——URL 规范里 `@` 前是 userinfo)。不剥的话该串整体会被 `sts_host_allowed` 前后缀匹配误放行,
/// 使 AS 的转发外呼被导向非 STS 的 `*.amazonaws.com` 端点(SSRF-ish 绕过 allowlist 语义)。
/// authority 里在 `path`/`?`/`#` 之前截断,再剥到最后一个 `@` 之后。
fn host_from_url(url: &str) -> Option<String> {
    let after_scheme = url.split("://").nth(1)?;
    // 在 path/query/fragment 之前截断(取 authority)。
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme)
        .trim();
    // 剥 userinfo:host 是最后一个 '@' 之后的部分(userinfo 里可能含 '@',取最后一个最稳妥)。
    let authority = match authority.rsplit_once('@') {
        Some((_userinfo, host)) => host,
        None => authority,
    };
    if authority.is_empty() {
        None
    } else {
        Some(authority.to_string())
    }
}

/// **转发 STS 前的完整校验流水线**(C5.2 + C5.3,评审 H3/M1/M2/M3)——**纯逻辑,不真调 STS**。
///
/// 按 spec 强制顺序判定(任一失败即拒、**不转发**,省 STS 配额):
/// ① `Authorization` 头存在且可解析 `SignedHeaders`;
/// ② audience 绑定头**被签名覆盖**且值 = 本 AS issuer(`audience_signed`,confused-deputy 防护);
/// ③ `X-Amz-Date` 可解析;
/// ④ 短 TTL(签发到 `now` 时差 ≤ 60s±skew,防重放旧预签名);
/// ⑤ STS host(从 `url` 提取)∈ allowlist(拒客户端伪造 endpoint);
/// ⑥ 可提取 `Signature=` 段(供 IO 层算 replay key)。
///
/// 通过 → `Ok(SigV4Validated{sts_host, signature})`;IO 层再做 replay 缓存 + 转发 STS 拿 caller ARN。
pub fn validate_sigv4_pre_sts(
    assertion: &SigV4Assertion,
    audience_header_name: &str,
    expected_issuer: &str,
    now: i64,
) -> Result<SigV4Validated, SigV4RejectReason> {
    use SigV4RejectReason as R;
    // ① Authorization 头。
    let authz = assertion
        .headers
        .get("authorization")
        .ok_or(R::MissingOrUnparsableAuthorization)?;
    if parse_signed_headers(authz).is_none() {
        return Err(R::MissingOrUnparsableAuthorization);
    }
    // ② audience 被签名覆盖 + 值 = 本 AS(先判,不满足直接拒、不查后续)。
    if !audience_signed(assertion, audience_header_name, expected_issuer) {
        return Err(R::AudienceNotSignedOrMismatch);
    }
    // ③ X-Amz-Date。
    let amz = assertion
        .headers
        .get("x-amz-date")
        .and_then(|s| parse_amz_date(s))
        .ok_or(R::MissingOrInvalidAmzDate)?;
    // ④ 短 TTL。
    if !within_ttl(amz, now) {
        return Err(R::OutsideTtl);
    }
    // ⑤ STS host allowlist(从 url 提取 host)。
    let host = host_from_url(&assertion.url).ok_or(R::UnparsableUrl)?;
    if !sts_host_allowed(&host) {
        return Err(R::StsHostNotAllowed);
    }
    // ⑥ Signature 段(replay key)。空段(`Signature=`)视为缺失(评审 LOW:否则空 replay key 全撞同键)。
    let signature = extract_signature(authz)
        .filter(|s| !s.is_empty())
        .ok_or(R::MissingSignature)?;
    Ok(SigV4Validated {
        sts_host: host,
        signature,
        issued_at: amz,
    })
}
/// STS `GetCallerIdentity` 已验证的调用者身份(解析自 STS 200 XML 响应)。
/// `account` + `arn`(assumed-role 形态)供 `trust::match_sigv4` 映射 client_id(docs §3.1)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsCallerIdentity {
    pub account: String,
    pub arn: String,
    pub user_id: String,
}

/// 从 STS `GetCallerIdentity` 的 200 响应 XML 里提取 `<Account>`/`<Arn>`/`<UserId>`(纯解析,零 IO)。
///
/// STS 响应形如(query-protocol XML):
/// ```xml
/// <GetCallerIdentityResponse ...><GetCallerIdentityResult>
///   <Arn>arn:aws:sts::123:assumed-role/Role/Session</Arn>
///   <UserId>AROA...:Session</UserId><Account>123</Account>
/// </GetCallerIdentityResult>...</GetCallerIdentityResponse>
/// ```
/// 只做**元素文本抽取**(不引 XML 依赖):取 `<Tag>...</Tag>` 首个匹配的内文。三者缺一即 None
/// (fail-closed:响应异常不臆测身份)。`arn` 保留 STS 原样(assumed-role 形态,不归一,docs §3.1)。
pub fn parse_get_caller_identity(xml: &str) -> Option<StsCallerIdentity> {
    let extract = |tag: &str| -> Option<String> {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close)? + start;
        let val = xml[start..end].trim();
        if val.is_empty() {
            None
        } else {
            Some(val.to_string())
        }
    };
    Some(StsCallerIdentity {
        account: extract("Account")?,
        arn: extract("Arn")?,
        user_id: extract("UserId")?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ISS: &str = "https://auth.example.com";
    const AUD_HDR: &str = "x-agent-auth-audience";

    fn authz(signed_headers: &str) -> String {
        format!(
            "AWS4-HMAC-SHA256 Credential=AKIA.../20260710/us-east-1/sts/aws4_request,\
             SignedHeaders={signed_headers},Signature=deadbeef"
        )
    }

    fn assertion(signed_headers: &str, aud_value: Option<&str>) -> SigV4Assertion {
        let mut h = BTreeMap::new();
        h.insert("authorization".into(), authz(signed_headers));
        h.insert("x-amz-date".into(), "20260710T131140Z".into());
        if let Some(v) = aud_value {
            h.insert(AUD_HDR.into(), v.into());
        }
        SigV4Assertion {
            method: "POST".into(),
            url: "https://sts.amazonaws.com/".into(),
            headers: h,
            body: "Action=GetCallerIdentity&Version=2011-06-15".into(),
        }
    }

    #[test]
    fn parse_signed_headers_basic() {
        let s = parse_signed_headers(&authz("host;x-amz-date;x-agent-auth-audience")).unwrap();
        assert_eq!(s, vec!["host", "x-amz-date", "x-agent-auth-audience"]);
    }

    #[test]
    fn parse_signed_headers_missing_segment() {
        assert_eq!(
            parse_signed_headers("AWS4-HMAC-SHA256 Credential=x,Signature=y"),
            None
        );
    }

    #[test]
    fn audience_signed_ok_when_covered_and_value_matches() {
        let a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        assert!(
            audience_signed(&a, AUD_HDR, ISS),
            "被签名覆盖 + 值符 → 放行"
        );
    }

    #[test]
    fn audience_not_in_signed_headers_rejected() {
        // audience 头值对,但**不在** SignedHeaders 内(转发前塞的未签名头)→ 拒。
        let a = assertion("host;x-amz-date", Some(ISS));
        assert!(
            !audience_signed(&a, AUD_HDR, ISS),
            "未签名的伪造 audience 头 MUST 拒"
        );
    }

    #[test]
    fn audience_value_mismatch_rejected() {
        // 在 SignedHeaders 内但值指向别的 AS → 拒(confused-deputy 防护)。
        let a = assertion(
            "host;x-amz-date;x-agent-auth-audience",
            Some("https://evil.example"),
        );
        assert!(!audience_signed(&a, AUD_HDR, ISS));
    }

    #[test]
    fn audience_header_absent_rejected() {
        // SignedHeaders 声明了但 headers 里没带值 → 无从核对 → 拒。
        let a = assertion("host;x-amz-date;x-agent-auth-audience", None);
        assert!(!audience_signed(&a, AUD_HDR, ISS));
    }

    #[test]
    fn no_authorization_header_rejected() {
        let a = SigV4Assertion {
            method: "POST".into(),
            url: "https://sts.amazonaws.com/".into(),
            headers: BTreeMap::new(),
            body: String::new(),
        };
        assert!(!audience_signed(&a, AUD_HDR, ISS));
    }

    #[test]
    fn case_insensitive_header_name_match() {
        // SignedHeaders 里大小写混合也应命中(SigV4 规范化小写,我们也小写比)。
        let a = assertion("host;X-Amz-Date;X-Agent-Auth-Audience", Some(ISS));
        assert!(audience_signed(&a, "X-Agent-Auth-Audience", ISS));
    }

    // ===== validate_sigv4_pre_sts(C5.2+C5.3 组合门)=====

    /// 从 assertion 的 X-Amz-Date 取"签发时刻"作 now(时差=0,落在 TTL 内),避免硬编码 Unix 时间戳。
    fn now_at_amz(a: &SigV4Assertion) -> i64 {
        parse_amz_date(a.headers.get("x-amz-date").unwrap()).unwrap()
    }

    #[test]
    fn pre_sts_ok_full_pipeline() {
        let a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        let now = now_at_amz(&a);
        let v = validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now).expect("全部门通过");
        assert_eq!(v.sts_host, "sts.amazonaws.com");
        assert_eq!(v.signature, "deadbeef", "replay key 只取 Signature= 段");
    }

    #[test]
    fn pre_sts_rejects_unsigned_audience() {
        // audience 值对但不在 SignedHeaders 内 → C5.2 拒。
        let a = assertion("host;x-amz-date", Some(ISS));
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::AudienceNotSignedOrMismatch)
        );
    }

    #[test]
    fn pre_sts_rejects_audience_value_mismatch() {
        let a = assertion(
            "host;x-amz-date;x-agent-auth-audience",
            Some("https://evil.example"),
        );
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::AudienceNotSignedOrMismatch)
        );
    }

    #[test]
    fn pre_sts_rejects_stale_request() {
        // 预签名早于 now 超过 TTL+skew(60+30=90s)→ 重放旧预签名,拒。
        let a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        let now = now_at_amz(&a) + 91;
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::OutsideTtl)
        );
    }

    #[test]
    fn pre_sts_rejects_future_request() {
        // 预签名时刻在 now 之后超过 skew(30s)→ 时钟异常,拒。
        let a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        let now = now_at_amz(&a) - 31;
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::OutsideTtl)
        );
    }

    #[test]
    fn pre_sts_rejects_forged_sts_host() {
        // 客户端把 url 指向非 STS host → 拒转发(C5.3③)。
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.url = "https://evil.example.com/".into();
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::StsHostNotAllowed)
        );
    }

    #[test]
    fn pre_sts_accepts_regional_and_fips_sts() {
        for host in [
            "sts.us-east-1.amazonaws.com",
            "sts-fips.us-east-1.amazonaws.com",
        ] {
            let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
            a.url = format!("https://{host}/");
            let now = now_at_amz(&a);
            let v = validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now).expect("区域/FIPS STS 应通过");
            assert_eq!(v.sts_host, host);
        }
    }

    #[test]
    fn pre_sts_rejects_missing_amz_date() {
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.headers.remove("x-amz-date");
        // now 任意(此门在 TTL 之前)。
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, 1_800_000_000),
            Err(SigV4RejectReason::MissingOrInvalidAmzDate)
        );
    }

    #[test]
    fn pre_sts_rejects_missing_authorization() {
        let a = SigV4Assertion {
            method: "POST".into(),
            url: "https://sts.amazonaws.com/".into(),
            headers: BTreeMap::new(),
            body: String::new(),
        };
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, 1_800_000_000),
            Err(SigV4RejectReason::MissingOrUnparsableAuthorization)
        );
    }

    #[test]
    fn pre_sts_rejects_userinfo_host_confusion() {
        // `sts.amazonaws.com@evil.amazonaws.com` 真 host 是 evil.amazonaws.com(@ 前是 userinfo)。
        // 剥 userinfo 后真 host 参与 allowlist:evil.amazonaws.com 不匹配 sts.* / sts-fips.* → 拒。
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.url = "https://sts.amazonaws.com@evil.amazonaws.com/".into();
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::StsHostNotAllowed),
            "userinfo 混淆的真 host MUST 参与 allowlist"
        );
    }

    #[test]
    fn host_from_url_strips_userinfo_and_path() {
        assert_eq!(
            host_from_url("https://sts.amazonaws.com@evil.com/x"),
            Some("evil.com".into()),
            "@ 前是 userinfo,真 host = evil.com"
        );
        assert_eq!(
            host_from_url("https://sts.us-east-1.amazonaws.com/?Action=x"),
            Some("sts.us-east-1.amazonaws.com".into()),
            "query 前截断"
        );
        assert_eq!(
            host_from_url("https://sts.amazonaws.com#frag"),
            Some("sts.amazonaws.com".into()),
            "fragment 前截断"
        );
        assert_eq!(
            host_from_url("no-scheme.example/x"),
            None,
            "无 scheme → None"
        );
    }

    #[test]
    fn pre_sts_rejects_userinfo_with_colon_confusion() {
        // 评审 codex HIGH:`sts.amazonaws.com:443@evil.com` 真 host = evil.com。剥 userinfo 后真 host
        // 参与 allowlist(不能因 userinfo 段含 `sts.…:443` 就误判)→ 拒。
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.url = "https://sts.amazonaws.com:443@evil.com/".into();
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::StsHostNotAllowed),
            "userinfo(带端口)混淆的真 host MUST 参与 allowlist"
        );
        // 直接验 host 解析:真 host = evil.com。
        assert_eq!(
            host_from_url("https://sts.amazonaws.com:443@evil.com/"),
            Some("evil.com".into())
        );
    }

    #[test]
    fn pre_sts_rejects_empty_signature() {
        // 评审 codex LOW:`Signature=`(空)不应被当有效 replay key(否则全撞同键)。
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.headers.insert(
            "authorization".into(),
            "AWS4-HMAC-SHA256 Credential=AKIA/x,\
             SignedHeaders=host;x-amz-date;x-agent-auth-audience,Signature="
                .into(),
        );
        let now = now_at_amz(&a);
        assert_eq!(
            validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now),
            Err(SigV4RejectReason::MissingSignature)
        );
    }

    #[test]
    fn pre_sts_accepts_legit_sts_with_query() {
        // 真 STS host 带 query 仍应通过(截断只取 authority)。
        let mut a = assertion("host;x-amz-date;x-agent-auth-audience", Some(ISS));
        a.url = "https://sts.amazonaws.com/?Action=GetCallerIdentity".into();
        let now = now_at_amz(&a);
        let v = validate_sigv4_pre_sts(&a, AUD_HDR, ISS, now).expect("带 query 的真 STS 应通过");
        assert_eq!(v.sts_host, "sts.amazonaws.com");
    }

    // GetCallerIdentity XML 解析:提取 assumed-role ARN + account + user_id。
    #[test]
    fn parse_get_caller_identity_assumed_role() {
        let xml = "<GetCallerIdentityResponse xmlns=\"https://sts.amazonaws.com/doc/2011-06-15/\">\
            <GetCallerIdentityResult>\
            <Arn>arn:aws:sts::123456789012:assumed-role/AgentRuntime-kb/session-xyz</Arn>\
            <UserId>AROAEXAMPLEID:session-xyz</UserId>\
            <Account>123456789012</Account>\
            </GetCallerIdentityResult>\
            <ResponseMetadata><RequestId>req-1</RequestId></ResponseMetadata>\
            </GetCallerIdentityResponse>";
        let id = parse_get_caller_identity(xml).expect("应解析出身份");
        assert_eq!(id.account, "123456789012");
        assert_eq!(
            id.arn, "arn:aws:sts::123456789012:assumed-role/AgentRuntime-kb/session-xyz",
            "ARN 保留 STS 原样 assumed-role 形态(不归一)"
        );
        assert_eq!(id.user_id, "AROAEXAMPLEID:session-xyz");
    }

    #[test]
    fn parse_get_caller_identity_missing_fields_fail_closed() {
        // 缺 Account → None(fail-closed,不臆测)。
        let no_account = "<GetCallerIdentityResult><Arn>arn:aws:sts::1:assumed-role/R/S</Arn>\
            <UserId>U</UserId></GetCallerIdentityResult>";
        assert_eq!(parse_get_caller_identity(no_account), None);
        // 空 Arn → None。
        let empty_arn = "<Arn></Arn><UserId>U</UserId><Account>1</Account>";
        assert_eq!(parse_get_caller_identity(empty_arn), None);
        // 完全无关文本 → None。
        assert_eq!(parse_get_caller_identity("not xml"), None);
    }
}
