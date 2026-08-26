//! DPoP(RFC 9449)**AS token endpoint 侧** proof 校验 + `cnf.jkt` 计算(spec 010 §5.2,C8.7b,P3)。
//!
//! `/token` 收到 `DPoP` 请求头时,AS 校验 proof 并把 `cnf:{jkt}` 写进签发的 access token。
//! 本模块是**纯逻辑**(零 IO):输入 (proof_jwt, expected_htu, expected_htm, now, iat_window)→
//! `Ok(jkt)` / `Err`。jti 重放缓存(IO)与各 grant handler 接线在 token/flow 层做。
//!
//! **AS 侧校验 = RFC 9449 §4.3 的子集**(比 RS SDK `verify_dpop_proof` 少两项):
//! - 不比对 `cnf.jkt`(AS 从 proof.jwk **算出** jkt 写进 token,RS 才是"比对 token 里已有的 jkt");
//! - 不校 `ath`(access token 此刻才签发,还没有)。
//!
//! 其余与 RS SDK 逐条对齐(typ/alg/jwk 拒私钥/自验签/htm/htu 规范化/iat 窗),行为参照 sdk/python/dpop.py。
//! **v1 仅 ES256**(EC P-256);RSA/其它非对称 proof 暂拒(不加宽解析面,评审收敛)。jkt 计算复用
//! `infra-core::ec_thumbprint`(与 RS SDK `compute_jkt` EC 分支逐字节等价:canonical `{crv,kty,x,y}`)。

use agent_auth_infra_core::jwks::ec_thumbprint;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

/// DPoP proof 校验失败原因(调用方一律映射为 `invalid_dpop_proof` 400,不泄露细节差异)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DpopError {
    /// 结构非法(非三段 JWT / base64 / JSON 解析失败)。
    Malformed,
    /// header.typ != dpop+jwt。
    BadTyp,
    /// alg 非 ES256(v1 仅 ES256;alg=none / RSA / 其它一律拒)。
    BadAlg,
    /// 缺内嵌 jwk / jwk 非 EC P-256 / 含私钥字段。
    BadJwk,
    /// 自验签失败(proof 未由内嵌 jwk 对应私钥签)。
    BadSignature,
    /// htm != 期望方法。
    HtmMismatch,
    /// htu 规范化后 != 期望 token endpoint URL。
    HtuMismatch,
    /// iat 缺失/超出接受窗(陈旧/未来)。
    BadIat,
    /// 缺 jti(重放去重需要)。
    MissingJti,
}

/// 校验通过的 proof 结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpopVerified {
    /// proof 公钥的 RFC 7638 thumbprint(base64url;写进 access token 的 `cnf.jkt`)。
    pub jkt: String,
    /// proof 的 jti(供调用方做 iat 窗内重放去重,ReplayStore::check_and_set)。
    pub jti: String,
    /// proof 的 iat(供调用方把 replay 项 TTL 锚到 `iat + window` 而非 `now + window`,评审 H1:
    /// 否则 future-dated proof 的 replay 项会先于其 iat 有效窗过期,留重放缺口)。
    pub iat: i64,
}

/// htu 规范化(RFC 9449 §4.3):去 fragment 再去 query,只留 scheme://host[:port]/path。
fn normalize_htu(url: &str) -> &str {
    let no_frag = url.split('#').next().unwrap_or(url);
    no_frag.split('?').next().unwrap_or(no_frag)
}

/// 校验 AS token endpoint 收到的 DPoP proof。成功返回 {jkt, jti};失败 Err(调用方拒 invalid_dpop_proof)。
///
/// - `expected_htu`:本 AS **已派生可信 issuer** 的 token endpoint URL(`<issuer>/token`;绝不用请求里
///   proof 自称的 htu 当权威——proof.htu 是被校验方,与本值比对)。
/// - `expected_htm`:期望 HTTP 方法(token endpoint 恒 "POST")。
/// - `now` / `iat_window_secs`:iat 接受窗(|now - iat| ≤ window)。
pub fn verify_as_proof(
    proof_jwt: &str,
    expected_htu: &str,
    expected_htm: &str,
    now: i64,
    iat_window_secs: i64,
) -> Result<DpopVerified, DpopError> {
    let parts: Vec<&str> = proof_jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(DpopError::Malformed);
    }
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| DpopError::Malformed)?,
    )
    .map_err(|_| DpopError::Malformed)?;
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| DpopError::Malformed)?,
    )
    .map_err(|_| DpopError::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| DpopError::Malformed)?;

    // 1. header.typ == dpop+jwt(RFC 9449 §4.2)。
    if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
        return Err(DpopError::BadTyp);
    }
    // 2. alg == ES256(v1 仅 ES256;alg=none / RSA 一律拒)。
    if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
        return Err(DpopError::BadAlg);
    }
    // 3. 内嵌 jwk:EC P-256 公钥,MUST NOT 含私钥字段(d/p/q/dp/dq/qi)。
    let jwk = header
        .get("jwk")
        .and_then(|v| v.as_object())
        .ok_or(DpopError::BadJwk)?;
    if ["d", "p", "q", "dp", "dq", "qi"]
        .iter()
        .any(|k| jwk.contains_key(*k))
    {
        return Err(DpopError::BadJwk); // proof jwk 只该是公钥
    }
    if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
        || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
    {
        return Err(DpopError::BadJwk); // 与 alg=ES256 自洽(防 alg 混淆)
    }
    let x = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::BadJwk)?;
    let y = jwk
        .get("y")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::BadJwk)?;

    // 4. 用内嵌 jwk 自验签(证明出示者持私钥)。
    let vk = verifying_key_from_xy(x, y).ok_or(DpopError::BadJwk)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| DpopError::BadSignature)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| DpopError::BadSignature)?;

    // 5. htm == 期望方法。
    if claims.get("htm").and_then(|v| v.as_str()) != Some(expected_htm) {
        return Err(DpopError::HtmMismatch);
    }
    // 6. htu 规范化 == 期望 token endpoint(两侧都规范化再比)。
    let proof_htu = claims
        .get("htu")
        .and_then(|v| v.as_str())
        .ok_or(DpopError::HtuMismatch)?;
    if normalize_htu(proof_htu) != normalize_htu(expected_htu) {
        return Err(DpopError::HtuMismatch);
    }
    // 7. iat 在接受窗(|now - iat| ≤ window;过旧/未来均拒)。
    let iat = claims
        .get("iat")
        .and_then(|v| v.as_i64())
        .ok_or(DpopError::BadIat)?;
    let iat_window_secs = u64::try_from(iat_window_secs).map_err(|_| DpopError::BadIat)?;
    if now.abs_diff(iat) > iat_window_secs {
        return Err(DpopError::BadIat);
    }
    // 8. jti 必在(供重放去重)。
    let jti = claims
        .get("jti")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .ok_or(DpopError::MissingJti)?
        .to_string();

    // 9. jkt = RFC 7638 thumbprint(与 RS SDK compute_jkt EC 分支逐字节等价)。
    let jkt = URL_SAFE_NO_PAD.encode(ec_thumbprint("P-256", x, y));

    Ok(DpopVerified { jkt, jti, iat })
}

/// DPoP proof iat 接受窗(秒):±5min(RFC 9449 建议分钟级;比 access token 时钟偏移宽,容 proof 传输)。
pub(crate) const DPOP_IAT_WINDOW_SECS: i64 = 300;

/// HTTP 接线:从 `/token` 请求解析 + 校验 DPoP proof,返回绑定结果(spec 010 §5.2)。
/// - `Ok(None)`:无 `DPoP` 头 → bearer(opt-in;调用方照常签 bearer,但若 client `require_dpop` 须调用方另拒)。
/// - `Ok(Some(jkt))`:合法 proof → 签发 token 绑 `cnf.jkt=jkt`。
/// - `Err(resp)`:有 `DPoP` 头但校验失败/重放 → `invalid_dpop_proof` 400(**不降级 bearer**)。
///
/// htu 用**本 AS 已派生可信 issuer** 的 `<issuer>/token`(绝不用 proof 自称的 htu 当权威);jti 重放走
/// `state.replay_store`(iat 窗内 `(issuer, jkt, jti)` 条件插入,复用 SigV4 同款短命项)。
pub(crate) async fn resolve_dpop_binding(
    state: &crate::state::AppState,
    headers: &axum::http::HeaderMap,
    tenant: &str,
    issuer: &str,
    require_dpop: bool,
) -> Result<Option<String>, axum::response::Response> {
    resolve_dpop_binding_with_mode(
        state,
        headers,
        tenant,
        issuer,
        require_dpop,
        DependencyErrorMode::InvalidProof,
    )
    .await
}

/// EMA publishes a stricter dependency-error contract than the existing grant paths.
/// Keep that mapping local so enabling EMA cannot change established DPoP responses.
pub(crate) async fn resolve_dpop_binding_for_ema(
    state: &crate::state::AppState,
    headers: &axum::http::HeaderMap,
    tenant: &str,
    issuer: &str,
    require_dpop: bool,
) -> Result<Option<String>, axum::response::Response> {
    resolve_dpop_binding_with_mode(
        state,
        headers,
        tenant,
        issuer,
        require_dpop,
        DependencyErrorMode::OAuthDependency,
    )
    .await
}

#[derive(Clone, Copy)]
enum DependencyErrorMode {
    InvalidProof,
    OAuthDependency,
}

async fn resolve_dpop_binding_with_mode(
    state: &crate::state::AppState,
    headers: &axum::http::HeaderMap,
    tenant: &str,
    issuer: &str,
    require_dpop: bool,
    dependency_error_mode: DependencyErrorMode,
) -> Result<Option<String>, axum::response::Response> {
    use axum::response::IntoResponse;
    let reject = || {
        crate::token::err(
            axum::http::StatusCode::BAD_REQUEST,
            "invalid_dpop_proof",
            "DPoP proof 校验失败",
        )
        .into_response()
    };
    // 多个 DPoP 头 MUST 拒(RFC 9449 §4.3:proof 恰一个;评审 L1)。
    let mut it = headers.get_all("dpop").iter();
    let Some(hv) = it.next() else {
        // 无 DPoP 头:require_dpop=true 的 client MUST 拒(防中间件丢头/漏配静默降级 bearer);否则 bearer(opt-in)。
        if require_dpop {
            return Err(reject());
        }
        return Ok(None);
    };
    if it.next().is_some() {
        return Err(reject()); // > 1 个 DPoP 头
    }
    let proof = hv.to_str().map_err(|_| reject())?;
    let now = crate::token::current_unix_secs_pub();
    let htu = format!("{issuer}/token");
    let verified =
        verify_as_proof(proof, &htu, "POST", now, DPOP_IAT_WINDOW_SECS).map_err(|_| reject())?;
    if !state.region.accepts_external_issued_at(verified.iat) {
        return Err(reject());
    }
    // jti 重放去重(B2):(issuer, jkt, jti) 条件插入;重复 → 拒。key 含 issuer + jkt 防跨租户/跨 key 串扰。
    // **TTL 锚到 `iat + 窗`(评审 H1),非 `now + 窗`**:iat 接受窗含未来容偏(|now-iat|≤窗),future-dated
    // proof 的 replay 项若按 now 计会先于其 iat 有效窗过期 → 过期后同 jti 又过 iat 校验 → 重放缺口。用 iat 锚
    // 使 replay 项存活覆盖整个 iat 有效窗(`iat+窗`≥`now+窗` 当 iat≥now)。store 未配 → fail-closed 拒。
    if let Some(rl) = state.replay_store.as_ref() {
        use crate::ports::ReplayStore;
        let key = format!("dpop\x1f{issuer}\x1f{}\x1f{}", verified.jkt, verified.jti);
        let ttl = verified
            .iat
            .checked_add(DPOP_IAT_WINDOW_SECS)
            .ok_or_else(|| {
                crate::token::err(
                    axum::http::StatusCode::BAD_REQUEST,
                    "invalid_dpop_proof",
                    "DPoP proof 校验失败",
                )
                .into_response()
            })?;
        match rl.check_and_set(tenant, &key, ttl).await {
            Ok(true) => {}                     // 首现 → 接受
            Ok(false) => return Err(reject()), // 窗内重放 → 拒
            Err(crate::ports::StoreError::Transient(_)) => {
                return Err(match dependency_error_mode {
                    DependencyErrorMode::InvalidProof => reject(),
                    DependencyErrorMode::OAuthDependency => crate::token::err_retry_after(
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "temporarily_unavailable",
                        "DPoP replay store unavailable",
                        1,
                    )
                    .into_response(),
                })
            }
            Err(crate::ports::StoreError::Permanent(_)) => {
                return Err(match dependency_error_mode {
                    DependencyErrorMode::InvalidProof => reject(),
                    DependencyErrorMode::OAuthDependency => crate::token::err(
                        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                        "server_error",
                        "DPoP replay store unavailable",
                    )
                    .into_response(),
                })
            }
        }
    } else {
        // replay_store 未配:DPoP 绑定无法防重放 → fail-closed 拒(不签一个防不了重放的 sender-constrained token)。
        return Err(match dependency_error_mode {
            DependencyErrorMode::InvalidProof => reject(),
            DependencyErrorMode::OAuthDependency => crate::token::err(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "DPoP replay store is not configured",
            )
            .into_response(),
        });
    }
    Ok(Some(verified.jkt))
}

/// 从 EC P-256 JWK 的 x/y(base64url)重建验签 key(复用 verify.rs 同款 SEC1 逻辑)。
fn verifying_key_from_xy(x_b64: &str, y_b64: &str) -> Option<VerifyingKey> {
    let x = URL_SAFE_NO_PAD.decode(x_b64).ok()?;
    let y = URL_SAFE_NO_PAD.decode(y_b64).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, SigningKey};

    const HTU: &str = "https://auth.example.com/token";

    // 造一个 EC P-256 keypair + 其 public jwk(x/y base64url)。
    fn keypair() -> (SigningKey, String, String) {
        // 固定种子(测试确定性;非密钥用途)。
        let sk = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = sk.verifying_key();
        let ep = vk.to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(ep.x().unwrap());
        let y = URL_SAFE_NO_PAD.encode(ep.y().unwrap());
        (sk, x, y)
    }

    // 组装并签一个 DPoP proof(header/claims 可注入以测各失败模式)。
    fn make_proof(sk: &SigningKey, header: serde_json::Value, claims: serde_json::Value) -> String {
        let h = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let c = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let si = format!("{h}.{c}");
        let sig: Signature = sk.sign(si.as_bytes());
        format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn valid_header(x: &str, y: &str) -> serde_json::Value {
        serde_json::json!({
            "typ": "dpop+jwt", "alg": "ES256",
            "jwk": { "kty": "EC", "crv": "P-256", "x": x, "y": y }
        })
    }
    fn valid_claims() -> serde_json::Value {
        serde_json::json!({ "htu": HTU, "htm": "POST", "iat": 1000, "jti": "jti-abc" })
    }

    #[test]
    fn accepts_valid_proof_and_computes_jkt() {
        let (sk, x, y) = keypair();
        let proof = make_proof(&sk, valid_header(&x, &y), valid_claims());
        let v = verify_as_proof(&proof, HTU, "POST", 1010, 300).unwrap();
        // jkt == ec_thumbprint(P-256, x, y) 的 base64url(与 RS SDK compute_jkt 等价)。
        assert_eq!(
            v.jkt,
            URL_SAFE_NO_PAD.encode(ec_thumbprint("P-256", &x, &y))
        );
        assert_eq!(v.jti, "jti-abc");
    }

    #[test]
    fn rejects_wrong_typ() {
        let (sk, x, y) = keypair();
        let mut h = valid_header(&x, &y);
        h["typ"] = serde_json::json!("jwt");
        let proof = make_proof(&sk, h, valid_claims());
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 1010, 300),
            Err(DpopError::BadTyp)
        );
    }

    #[test]
    fn rejects_alg_none_and_non_es256() {
        let (sk, x, y) = keypair();
        for bad in ["none", "RS256", "HS256"] {
            let mut h = valid_header(&x, &y);
            h["alg"] = serde_json::json!(bad);
            let proof = make_proof(&sk, h, valid_claims());
            assert_eq!(
                verify_as_proof(&proof, HTU, "POST", 1010, 300),
                Err(DpopError::BadAlg),
                "alg={bad} 应拒"
            );
        }
    }

    #[test]
    fn rejects_jwk_with_private_key_field() {
        let (sk, x, y) = keypair();
        let mut h = valid_header(&x, &y);
        h["jwk"]["d"] = serde_json::json!("cHJpdmF0ZQ"); // 私钥字段
        let proof = make_proof(&sk, h, valid_claims());
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 1010, 300),
            Err(DpopError::BadJwk)
        );
    }

    #[test]
    fn rejects_bad_signature() {
        // 用 keypair A 的 jwk,但用 keypair B 签 → 自验签失败。
        let (_ska, x, y) = keypair();
        let skb = SigningKey::from_bytes(&[9u8; 32].into()).unwrap();
        let proof = make_proof(&skb, valid_header(&x, &y), valid_claims());
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 1010, 300),
            Err(DpopError::BadSignature)
        );
    }

    #[test]
    fn rejects_htu_htm_mismatch() {
        let (sk, x, y) = keypair();
        // htu 不匹配。
        let mut c = valid_claims();
        c["htu"] = serde_json::json!("https://evil.example.com/token");
        let proof = make_proof(&sk, valid_header(&x, &y), c);
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 1010, 300),
            Err(DpopError::HtuMismatch)
        );
        // htm 不匹配(proof htm=GET,期望 POST)。
        let mut c2 = valid_claims();
        c2["htm"] = serde_json::json!("GET");
        let proof2 = make_proof(&sk, valid_header(&x, &y), c2);
        assert_eq!(
            verify_as_proof(&proof2, HTU, "POST", 1010, 300),
            Err(DpopError::HtmMismatch)
        );
    }

    #[test]
    fn htu_normalization_ignores_query_fragment() {
        let (sk, x, y) = keypair();
        let mut c = valid_claims();
        c["htu"] = serde_json::json!("https://auth.example.com/token?foo=bar#frag");
        let proof = make_proof(&sk, valid_header(&x, &y), c);
        // 规范化后 == HTU,应通过。
        assert!(verify_as_proof(&proof, HTU, "POST", 1010, 300).is_ok());
    }

    #[test]
    fn rejects_stale_and_future_iat() {
        let (sk, x, y) = keypair();
        let proof = make_proof(&sk, valid_header(&x, &y), valid_claims()); // iat=1000
                                                                           // now=2000,窗 300 → 陈旧拒。
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 2000, 300),
            Err(DpopError::BadIat)
        );
        // now=500,iat=1000(未来 500s > 窗)→ 拒。
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 500, 300),
            Err(DpopError::BadIat)
        );

        for extreme in [i64::MIN, i64::MAX] {
            let mut claims = valid_claims();
            claims["iat"] = serde_json::json!(extreme);
            let proof = make_proof(&sk, valid_header(&x, &y), claims);
            assert_eq!(
                verify_as_proof(&proof, HTU, "POST", 1_000, 300),
                Err(DpopError::BadIat)
            );
        }
    }

    #[test]
    fn rejects_missing_jti() {
        let (sk, x, y) = keypair();
        let mut c = valid_claims();
        c.as_object_mut().unwrap().remove("jti");
        let proof = make_proof(&sk, valid_header(&x, &y), c);
        assert_eq!(
            verify_as_proof(&proof, HTU, "POST", 1010, 300),
            Err(DpopError::MissingJti)
        );
    }

    #[tokio::test]
    async fn ema_dependency_errors_do_not_change_existing_grant_responses() {
        let (sk, x, y) = keypair();
        let now = crate::token::current_unix_secs_pub();
        let proof = make_proof(
            &sk,
            valid_header(&x, &y),
            serde_json::json!({
                "htu": HTU,
                "htm": "POST",
                "iat": now,
                "jti": "dependency-contract"
            }),
        );
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("dpop", proof.parse().unwrap());
        let mut state = crate::state::AppState::dev("auth.example.com");
        state.replay_store = None;

        let existing = resolve_dpop_binding(
            &state,
            &headers,
            "default",
            "https://auth.example.com",
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(existing.status(), axum::http::StatusCode::BAD_REQUEST);

        let ema = resolve_dpop_binding_for_ema(
            &state,
            &headers,
            "default",
            "https://auth.example.com",
            false,
        )
        .await
        .unwrap_err();
        assert_eq!(ema.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
