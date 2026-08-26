//! access token 验签 + 时间/aud 校验(供 `/userinfo` C2.11、未来 introspect 等复用)。
//!
//! 用本 AS 自己发布的 JWKS 公钥验 ES256 签名(按 `kid` 选 key,双活支持),再校 exp/nbf/iat
//! (留时钟偏移余量 C10.6)。纯验证逻辑;JWK→验签 key 的密码学用 p256。
//! 决策真相源:docs/DESIGN §2·§2.1;docs/CONFORMANCE C2.11·C10.6·C10.11a。

use agent_auth_infra_core::lifecycle::{check_time_claims, DEFAULT_CLOCK_SKEW_SECS};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::jwks::Jwk;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    Malformed,
    UnknownKid,
    BadSignature,
    Expired,
    NotYetValid,
    IssuedInFuture,
}

/// 验签结果:验证通过的 claims(JSON)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    pub claims: serde_json::Value,
}

/// 从 JWK(x/y)重建 P-256 验签 key。
fn verifying_key_from_jwk(jwk: &Jwk) -> Option<VerifyingKey> {
    // 仅 EC(access token 恒 ES256);RSA JWK 无 x/y → None(不参与 access 验签)。
    let x = URL_SAFE_NO_PAD.decode(jwk.x.as_deref()?).ok()?;
    let y = URL_SAFE_NO_PAD.decode(jwk.y.as_deref()?).ok()?;
    if x.len() != 32 || y.len() != 32 {
        return None;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1).ok()
}

/// 验证一枚 ES256 JWT:按 header.kid 从 jwks 选 key 验签 + 校 exp/nbf/iat(留 skew)。
/// `now` 由上层注入(HTTP 边界取系统时钟)。不校 aud——aud 隔离由调用方按端点判(C2.11)。
pub fn verify_es256(token: &str, jwks: &[Jwk], now: i64) -> Result<Verified, VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Malformed);
    }
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    let claims: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| VerifyError::Malformed)?;

    // header.alg 必须 ES256(本 AS access token 恒 ES256,C10.15a)。
    if header.get("alg").and_then(|a| a.as_str()) != Some("ES256") {
        return Err(VerifyError::BadSignature);
    }
    let kid = header
        .get("kid")
        .and_then(|k| k.as_str())
        .ok_or(VerifyError::Malformed)?;

    // 按 kid 选 key(双活;未知 kid fail-closed)。
    let jwk = jwks
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(VerifyError::UnknownKid)?;
    let vk = verifying_key_from_jwk(jwk).ok_or(VerifyError::UnknownKid)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| VerifyError::BadSignature)?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    vk.verify(signing_input.as_bytes(), &sig)
        .map_err(|_| VerifyError::BadSignature)?;

    // 时间校验(留 skew,C10.6)。
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(VerifyError::Malformed)?;
    let nbf = claims.get("nbf").and_then(|v| v.as_i64());
    let iat = claims.get("iat").and_then(|v| v.as_i64());
    match check_time_claims(now, exp, nbf, iat, DEFAULT_CLOCK_SKEW_SECS) {
        Ok(()) => {}
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::Expired) => {
            return Err(VerifyError::Expired)
        }
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::NotYetValid) => {
            return Err(VerifyError::NotYetValid)
        }
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::IssuedInFuture) => {
            return Err(VerifyError::IssuedInFuture)
        }
    }

    Ok(Verified { claims })
}

/// 取 token 的单值 aud(本系统 aud 恒单元素数组,C2.5a)。
///
/// ⚠️ 宽松版:兼容裸字符串 aud(历史/互操作)。**introspection/RS SDK 侧 MUST 用严格版**
/// `single_aud_strict`(拒裸字符串,C2.5a),见 spec 010 SDK-VALID-1。
pub fn single_aud(claims: &serde_json::Value) -> Option<String> {
    match claims.get("aud")? {
        serde_json::Value::Array(a) if a.len() == 1 => a[0].as_str().map(String::from),
        serde_json::Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// 严格版单值 aud(C2.5a):**只**接受单元素 JSON 数组,裸字符串/多元素/缺失 → None。
/// introspection 与 RS SDK 侧用此版(评审 codex:裸字符串 aud MUST 拒)。
pub fn single_aud_strict(claims: &serde_json::Value) -> Option<String> {
    match claims.get("aud")? {
        serde_json::Value::Array(a) if a.len() == 1 => a[0].as_str().map(String::from),
        _ => None,
    }
}

/// 严格 access token 基线校验(RFC 9068,spec 010 SDK-VALID-1 的 AS/introspection 侧对应):
/// verify_es256 之外,再强制 header `typ == "at+jwt"` + 顶层 `client_id` 存在。
/// 通过返回 Verified,否则 Err。不校 aud(隔离由调用方按端点判)。
pub fn verify_access_token(token: &str, jwks: &[Jwk], now: i64) -> Result<Verified, VerifyError> {
    let verified = verify_es256(token, jwks, now)?;
    // header.typ 必须 at+jwt(拒非 access token,如 ID token / 任意同 signer JWT)。
    let parts: Vec<&str> = token.split('.').collect();
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    if header.get("typ").and_then(|t| t.as_str()) != Some("at+jwt") {
        return Err(VerifyError::Malformed);
    }
    // 顶层 client_id 必在(C2.1)。
    if verified
        .claims
        .get("client_id")
        .and_then(|v| v.as_str())
        .is_none()
    {
        return Err(VerifyError::Malformed);
    }
    Ok(verified)
}

/// **grant-ref 验签(ES256,spec 011 §4,C7.7)**——专用 verifier,强制 header `typ == "grant-ref+jwt"`
/// (与 access token 的 `typ=at+jwt` **严格隔离**防混淆:虽同 signer kid,typ 不同则互不接受)。
/// 通过返回 Verified(含 claims{grant_id,bound_agent,iss,iat,exp});否则 Err。iss/时效由调用方/verify_es256 校。
pub fn verify_grant_ref(token: &str, jwks: &[Jwk], now: i64) -> Result<Verified, VerifyError> {
    let verified = verify_es256(token, jwks, now)?; // 签名 + exp/nbf 时效
    let parts: Vec<&str> = token.split('.').collect();
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    // typ MUST == grant-ref+jwt(拒把 access token / id_token / 任意同 signer JWT 当 grant-ref)。
    if header.get("typ").and_then(|t| t.as_str()) != Some("grant-ref+jwt") {
        return Err(VerifyError::Malformed);
    }
    Ok(verified)
}

/// **id_token 验签(RS256)**——供 token-exchange 以 id_token 作 subject_token 时用(spec 011 C7.8a)。
///
/// 与 `verify_access_token`(ES256 + typ=at+jwt)**严格分离**,防 alg/typ 混淆:
/// - **RS256**:按 header.kid 从 jwks 选 **RSA** key(有 n/e),`verify_rs256` 内强制 header.alg==RS256
///   (拒 alg 混淆:EC key + alg=RS256 会因该 key 无 n/e 选不中 → UnknownKid;alg!=RS256 → 拒);
/// - **typ MUST NOT == at+jwt**(id_token 的 typ 是 JWT 或缺省;拒把 access token 当 id_token);
/// - **iss == 本 AS**;
/// - **aud 单值 == expected_client_id**(id_token 的 aud 是单个 client_id 字符串,C2.6;
///   纵深防御:防 agent-A 拿 agent-B 的 id_token 发起委托——校 aud 与其 Grant 归属 client 一致);
/// - **exp/nbf/iat**(留 skew);
/// - **jti MUST 存在**(C7.8a:id_token 作 subject_token 须带 jti 以经映射还原 user_id;MUST NOT 解 sub)。
///
/// 返回验证通过的 claims(调用方从中取 jti)。`expected_client_id` 传 None 时不校 aud 归属
/// (仅当调用方稍后自行比对 grant.client_id==aud;推荐传入以在验签阶段即挡)。
pub fn verify_id_token(
    token: &str,
    jwks: &[Jwk],
    as_issuer: &str,
    expected_client_id: Option<&str>,
    now: i64,
) -> Result<Verified, VerifyError> {
    let verified = verify_id_token_identity(token, jwks, as_issuer, expected_client_id)?;
    validate_id_token_time(&verified, now)?;
    Ok(verified)
}

/// Verify an ID Token supplied as an authorization request `id_token_hint`.
///
/// Unlike token exchange, authorization hints may use either registered ID
/// token signing algorithm. The hint is still an identity assertion from this
/// issuer, so signature, type, issuer, audience, time, and subject are all
/// required before `/authorize` may use it for account selection.
pub fn verify_authorization_id_token_hint(
    token: &str,
    jwks: &[Jwk],
    as_issuer: &str,
    expected_client_id: &str,
    now: i64,
) -> Result<Verified, VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Malformed);
    }
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    if header.get("typ").and_then(|value| value.as_str()) == Some("at+jwt") {
        return Err(VerifyError::Malformed);
    }

    let verified = match header.get("alg").and_then(|value| value.as_str()) {
        Some("RS256") => verify_id_token(token, jwks, as_issuer, Some(expected_client_id), now)?,
        Some("ES256") => {
            let verified = verify_es256(token, jwks, now)?;
            if verified.claims.get("iss").and_then(|value| value.as_str()) != Some(as_issuer) {
                return Err(VerifyError::Malformed);
            }
            let audience_matches = match verified.claims.get("aud") {
                Some(serde_json::Value::String(value)) => value == expected_client_id,
                Some(serde_json::Value::Array(values)) => {
                    values.len() == 1 && values[0].as_str() == Some(expected_client_id)
                }
                _ => false,
            };
            if !audience_matches {
                return Err(VerifyError::Malformed);
            }
            verified
        }
        _ => return Err(VerifyError::BadSignature),
    };
    if verified
        .claims
        .get("sub")
        .and_then(|value| value.as_str())
        .is_none_or(str::is_empty)
    {
        return Err(VerifyError::Malformed);
    }
    Ok(verified)
}

/// Verify the signed ID-token identity claims without applying temporal claims.
///
/// CIBA uses this in order to reject a cryptographically valid JTI owned by a
/// previous regional activation before expiry can hide the ownership failure.
pub(crate) fn verify_id_token_identity(
    token: &str,
    jwks: &[Jwk],
    as_issuer: &str,
    expected_client_id: Option<&str>,
) -> Result<Verified, VerifyError> {
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(VerifyError::Malformed);
    }
    let header: serde_json::Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .map_err(|_| VerifyError::Malformed)?,
    )
    .map_err(|_| VerifyError::Malformed)?;
    // typ 隔离:id_token MUST NOT 是 at+jwt(那是 access token 专属,防类型混淆)。
    if header.get("typ").and_then(|t| t.as_str()) == Some("at+jwt") {
        return Err(VerifyError::Malformed);
    }
    let kid = header
        .get("kid")
        .and_then(|k| k.as_str())
        .ok_or(VerifyError::Malformed)?;
    // 按 kid 选 **RSA** key(id_token 默认 RS256;EC key 无 n/e,选不中 RSA 分支 → 视为 UnknownKid)。
    let jwk = jwks
        .iter()
        .find(|k| k.kid == kid)
        .ok_or(VerifyError::UnknownKid)?;
    let (Some(n), Some(e)) = (jwk.n.as_deref(), jwk.e.as_deref()) else {
        // 命中的 kid 不是 RSA key(无 n/e)→ 拒(防 alg 混淆:不拿 EC key 走 RS256)。
        return Err(VerifyError::UnknownKid);
    };
    // RS256 验签(workload::verify_rs256 内强制 header.alg==RS256 + kid 比对)。
    let verified =
        agent_auth_workload::verify_rs256(token, n, e, Some(kid)).map_err(|err| match err {
            agent_auth_workload::Rs256Error::BadSignature => VerifyError::BadSignature,
            agent_auth_workload::Rs256Error::NotRs256 => VerifyError::BadSignature,
            agent_auth_workload::Rs256Error::KidMismatch => VerifyError::UnknownKid,
            agent_auth_workload::Rs256Error::BadKey => VerifyError::UnknownKid,
            agent_auth_workload::Rs256Error::Malformed => VerifyError::Malformed,
        })?;
    let claims = verified.claims;

    // iss == 本 AS。
    if claims.get("iss").and_then(|v| v.as_str()) != Some(as_issuer) {
        return Err(VerifyError::Malformed);
    }
    // aud 单值 == expected_client_id(id_token aud 是单个 client_id 字符串,C2.6)。
    if let Some(cid) = expected_client_id {
        let aud_ok = match claims.get("aud") {
            Some(serde_json::Value::String(s)) => s == cid,
            // 兼容单元素数组(宽松);多元素/其它 → 不匹配。
            Some(serde_json::Value::Array(a)) => a.len() == 1 && a[0].as_str() == Some(cid),
            _ => false,
        };
        if !aud_ok {
            return Err(VerifyError::Malformed);
        }
    }
    // jti MUST exist(C7.8a:经 jti→user_id 映射还原主体,不解 sub)。
    if claims.get("jti").and_then(|v| v.as_str()).is_none() {
        return Err(VerifyError::Malformed);
    }

    Ok(Verified { claims })
}

pub(crate) fn validate_id_token_time(verified: &Verified, now: i64) -> Result<(), VerifyError> {
    let claims = &verified.claims;
    // 时间校验(留 skew,C10.6)。
    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(VerifyError::Malformed)?;
    let nbf = claims.get("nbf").and_then(|v| v.as_i64());
    let iat = claims.get("iat").and_then(|v| v.as_i64());
    match check_time_claims(now, exp, nbf, iat, DEFAULT_CLOCK_SKEW_SECS) {
        Ok(()) => {}
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::Expired) => {
            return Err(VerifyError::Expired)
        }
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::NotYetValid) => {
            return Err(VerifyError::NotYetValid)
        }
        Err(agent_auth_infra_core::lifecycle::TimeClaimError::IssuedInFuture) => {
            return Err(VerifyError::IssuedInFuture)
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::memory::MemorySigner;
    use crate::ports::Signer;

    // 用 MemorySigner 签一个 ES256 JWT,返回 (jwt, jwks)。
    async fn signed_token(exp: i64, aud: &str) -> (String, Vec<Jwk>) {
        let signer = MemorySigner::from_seed([5u8; 32]);
        let kid = signer.active_kid().await.unwrap();
        let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
        let claims = serde_json::json!({ "sub": "u1", "aud": [aud], "iat": 1000, "exp": exp });
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = signer.sign_es256(si.as_bytes()).await.unwrap();
        let jwt = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig));
        let jwks = signer
            .public_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::to_jwk)
            .collect();
        (jwt, jwks)
    }

    async fn signed_token_with_time_claims(
        exp: i64,
        nbf: Option<i64>,
        iat: Option<i64>,
    ) -> (String, Vec<Jwk>) {
        let signer = MemorySigner::from_seed([5u8; 32]);
        let kid = signer.active_kid().await.unwrap();
        let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
        let mut claims =
            serde_json::json!({ "sub": "u1", "aud": ["https://rs.example.com"], "exp": exp });
        if let Some(nbf) = nbf {
            claims["nbf"] = serde_json::json!(nbf);
        }
        if let Some(iat) = iat {
            claims["iat"] = serde_json::json!(iat);
        }
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = signer.sign_es256(si.as_bytes()).await.unwrap();
        let jwt = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig));
        let jwks = signer
            .public_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::to_jwk)
            .collect();
        (jwt, jwks)
    }

    #[tokio::test]
    async fn verifies_valid_token() {
        let (jwt, jwks) = signed_token(9999, "https://rs.example.com").await;
        let v = verify_es256(&jwt, &jwks, 2000).unwrap();
        assert_eq!(v.claims["sub"], "u1");
        assert_eq!(
            single_aud(&v.claims).as_deref(),
            Some("https://rs.example.com")
        );
    }

    #[tokio::test]
    async fn rejects_expired() {
        let (jwt, jwks) = signed_token(1000, "https://rs.example.com").await;
        // now=2000 远超 exp=1000(+skew)→ Expired。
        assert_eq!(verify_es256(&jwt, &jwks, 2000), Err(VerifyError::Expired));
    }

    #[tokio::test]
    async fn verify_es256_applies_the_same_clock_skew_to_exp_nbf_and_iat() {
        assert_eq!(DEFAULT_CLOCK_SKEW_SECS, 30);

        let (exp_token, exp_jwks) = signed_token_with_time_claims(1000, None, Some(900)).await;
        assert!(
            verify_es256(&exp_token, &exp_jwks, 1029).is_ok(),
            "exp remains valid until the last second inside the 30-second skew"
        );
        assert_eq!(
            verify_es256(&exp_token, &exp_jwks, 1030),
            Err(VerifyError::Expired),
            "exp is rejected exactly at exp plus the configured skew"
        );

        let (nbf_boundary, nbf_jwks) =
            signed_token_with_time_claims(2000, Some(1030), Some(1000)).await;
        assert!(
            verify_es256(&nbf_boundary, &nbf_jwks, 1000).is_ok(),
            "nbf exactly 30 seconds ahead is inside the shared skew"
        );
        let (nbf_outside, nbf_outside_jwks) =
            signed_token_with_time_claims(2000, Some(1031), Some(1000)).await;
        assert_eq!(
            verify_es256(&nbf_outside, &nbf_outside_jwks, 1000),
            Err(VerifyError::NotYetValid),
            "nbf 31 seconds ahead is outside the shared skew"
        );

        let (iat_boundary, iat_jwks) = signed_token_with_time_claims(2000, None, Some(1030)).await;
        assert!(
            verify_es256(&iat_boundary, &iat_jwks, 1000).is_ok(),
            "iat exactly 30 seconds ahead is inside the shared skew"
        );
        let (iat_outside, iat_outside_jwks) =
            signed_token_with_time_claims(2000, None, Some(1031)).await;
        assert_eq!(
            verify_es256(&iat_outside, &iat_outside_jwks, 1000),
            Err(VerifyError::IssuedInFuture),
            "iat 31 seconds ahead is outside the shared skew"
        );
    }

    #[tokio::test]
    async fn rejects_unknown_kid() {
        let (jwt, _) = signed_token(9999, "https://rs.example.com").await;
        // 用一把不同 key 的 jwks(kid 对不上)→ UnknownKid。
        let (_, other_jwks) = signed_token_seed(9999, [9u8; 32]).await;
        assert_eq!(
            verify_es256(&jwt, &other_jwks, 2000),
            Err(VerifyError::UnknownKid)
        );
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let (jwt, jwks) = signed_token(9999, "https://rs.example.com").await;
        let parts: Vec<&str> = jwt.split('.').collect();
        // 解码签名、翻转中间一字节(保持 64 字节长度,确保走到验签失败而非长度错)。
        let mut sig = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        sig[10] ^= 0xFF;
        let tampered = format!("{}.{}.{}", parts[0], parts[1], URL_SAFE_NO_PAD.encode(&sig));
        assert_eq!(
            verify_es256(&tampered, &jwks, 2000),
            Err(VerifyError::BadSignature),
            "篡改签名字节应 BadSignature(长度不变、验签失败)"
        );
    }

    #[tokio::test]
    async fn rejects_malformed() {
        let (_, jwks) = signed_token(9999, "x").await;
        assert_eq!(
            verify_es256("not.a.jwt.x", &jwks, 2000),
            Err(VerifyError::Malformed)
        );
        assert_eq!(
            verify_es256("onlyonepart", &jwks, 2000),
            Err(VerifyError::Malformed)
        );
    }

    // single_aud:多值/空 → None(本系统 aud 恒单元素)。
    #[test]
    fn single_aud_only_single() {
        assert_eq!(
            single_aud(&serde_json::json!({"aud": ["a"]})).as_deref(),
            Some("a")
        );
        assert_eq!(single_aud(&serde_json::json!({"aud": ["a", "b"]})), None);
        assert_eq!(single_aud(&serde_json::json!({})), None);
    }

    // 严格版:裸字符串 aud → None(C2.5a);只认单元素数组(评审 codex)。
    #[test]
    fn single_aud_strict_rejects_bare_string() {
        assert_eq!(
            single_aud_strict(&serde_json::json!({"aud": ["a"]})).as_deref(),
            Some("a")
        );
        assert_eq!(
            single_aud_strict(&serde_json::json!({"aud": "a"})),
            None,
            "裸字符串 MUST 拒"
        );
        assert_eq!(
            single_aud_strict(&serde_json::json!({"aud": ["a", "b"]})),
            None
        );
    }

    // verify_access_token:typ != at+jwt → Malformed(拒非 access token,评审 codex)。
    #[tokio::test]
    async fn access_token_requires_typ_and_client_id() {
        // 正常 at+jwt + client_id → 通过。
        let (jwt, jwks) = signed_access_token(9999, "at+jwt", true).await;
        assert!(verify_access_token(&jwt, &jwks, 2000).is_ok());
        // typ=JWT(非 at+jwt)→ 拒。
        let (jwt2, jwks2) = signed_access_token(9999, "JWT", true).await;
        assert_eq!(
            verify_access_token(&jwt2, &jwks2, 2000),
            Err(VerifyError::Malformed)
        );
        // 缺 client_id → 拒。
        let (jwt3, jwks3) = signed_access_token(9999, "at+jwt", false).await;
        assert_eq!(
            verify_access_token(&jwt3, &jwks3, 2000),
            Err(VerifyError::Malformed)
        );
    }

    async fn signed_access_token(exp: i64, typ: &str, with_client_id: bool) -> (String, Vec<Jwk>) {
        let signer = MemorySigner::from_seed([6u8; 32]);
        let kid = signer.active_kid().await.unwrap();
        let header = serde_json::json!({ "alg": "ES256", "typ": typ, "kid": kid });
        let mut claims = serde_json::json!({ "sub": "u1", "aud": ["r"], "iat": 1000, "exp": exp });
        if with_client_id {
            claims["client_id"] = serde_json::json!("c1");
        }
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = signer.sign_es256(si.as_bytes()).await.unwrap();
        let jwt = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig));
        let jwks = signer
            .public_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::to_jwk)
            .collect();
        (jwt, jwks)
    }

    // 用 MemorySigner 签一个 RS256 id_token,返回 (jwt, jwks[RSA])。
    // typ/aud/iss/jti 可控以测形态闸。
    async fn signed_id_token(
        exp: i64,
        typ: &str,
        iss: &str,
        aud: serde_json::Value,
        with_jti: bool,
    ) -> (String, Vec<Jwk>) {
        let signer = MemorySigner::from_seed([7u8; 32]);
        let (rsa_kid, _) = signer.sign_rs256(b"probe").await.unwrap();
        let header = serde_json::json!({ "alg": "RS256", "typ": typ, "kid": rsa_kid });
        let mut claims = serde_json::json!({
            "sub": "u1", "aud": aud, "iss": iss, "iat": 1000, "exp": exp
        });
        if with_jti {
            claims["jti"] = serde_json::json!("jti-xyz");
        }
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let (_, sig) = signer.sign_rs256(si.as_bytes()).await.unwrap();
        let jwt = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig));
        let jwks = signer
            .public_rsa_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::rsa_to_jwk)
            .collect();
        (jwt, jwks)
    }

    const AS_ISS: &str = "https://auth.example.com";
    const CID: &str = "agt_client_1";

    // C7.8a:合法 id_token(RS256/typ=JWT/aud=client_id/iss/jti)→ 验签通过。
    #[tokio::test]
    async fn verify_id_token_accepts_valid() {
        let (jwt, jwks) = signed_id_token(9999, "JWT", AS_ISS, serde_json::json!(CID), true).await;
        let v = verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 2000).unwrap();
        assert_eq!(v.claims["jti"], "jti-xyz");
    }

    // 红线:typ=at+jwt(access token 专属)→ 拒(防类型混淆)。
    #[tokio::test]
    async fn verify_id_token_rejects_at_jwt_typ() {
        let (jwt, jwks) =
            signed_id_token(9999, "at+jwt", AS_ISS, serde_json::json!(CID), true).await;
        assert_eq!(
            verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 2000),
            Err(VerifyError::Malformed),
            "typ=at+jwt 的 id_token MUST 拒"
        );
    }

    // 红线:缺 jti → 拒(C7.8a:无 jti 无法经映射还原主体)。
    #[tokio::test]
    async fn verify_id_token_rejects_missing_jti() {
        let (jwt, jwks) = signed_id_token(9999, "JWT", AS_ISS, serde_json::json!(CID), false).await;
        assert_eq!(
            verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 2000),
            Err(VerifyError::Malformed),
            "缺 jti 的 id_token MUST 拒"
        );
    }

    // 红线:iss != 本 AS → 拒。
    #[tokio::test]
    async fn verify_id_token_rejects_wrong_iss() {
        let (jwt, jwks) = signed_id_token(
            9999,
            "JWT",
            "https://evil.example.com",
            serde_json::json!(CID),
            true,
        )
        .await;
        assert_eq!(
            verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 2000),
            Err(VerifyError::Malformed),
            "iss 非本 AS 的 id_token MUST 拒"
        );
    }

    // aud != expected_client_id → 拒(纵深:防跨 client 转用)。
    #[tokio::test]
    async fn verify_id_token_rejects_aud_mismatch() {
        let (jwt, jwks) =
            signed_id_token(9999, "JWT", AS_ISS, serde_json::json!("agt_other"), true).await;
        assert_eq!(
            verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 2000),
            Err(VerifyError::Malformed),
            "aud 与 expected_client_id 不符 MUST 拒"
        );
        // expected_client_id=None 时不校 aud 归属(上层稍后校)→ 通过。
        assert!(verify_id_token(&jwt, &jwks, AS_ISS, None, 2000).is_ok());
    }

    // 红线:过期 → Expired。
    #[tokio::test]
    async fn verify_id_token_rejects_expired() {
        let (jwt, jwks) = signed_id_token(1000, "JWT", AS_ISS, serde_json::json!(CID), true).await;
        assert_eq!(
            verify_id_token(&jwt, &jwks, AS_ISS, Some(CID), 5000),
            Err(VerifyError::Expired)
        );
    }

    #[tokio::test]
    async fn id_token_identity_can_be_checked_before_expiry() {
        let (jwt, jwks) = signed_id_token(1000, "JWT", AS_ISS, serde_json::json!(CID), true).await;
        let verified = verify_id_token_identity(&jwt, &jwks, AS_ISS, Some(CID)).unwrap();
        assert_eq!(verified.claims["jti"], "jti-xyz");
        assert_eq!(
            validate_id_token_time(&verified, 5000),
            Err(VerifyError::Expired)
        );
    }

    // 红线:alg 混淆——用 ES256 access token(EC key)走 id_token 验签器 → 拒
    //(header.kid 命中 EC key、无 n/e → UnknownKid;绝不拿 EC key 走 RS256)。
    #[tokio::test]
    async fn verify_id_token_rejects_es256_token() {
        // 一个 ES256 at+jwt token + 其 EC jwks。
        let (es_jwt, ec_jwks) = signed_token(9999, "https://rs.example.com").await;
        assert!(
            matches!(
                verify_id_token(&es_jwt, &ec_jwks, AS_ISS, None, 2000),
                Err(VerifyError::Malformed) | Err(VerifyError::UnknownKid)
            ),
            "ES256 token 走 id_token(RS256)验签器 MUST 拒(alg/typ 混淆防御)"
        );
    }

    async fn signed_token_seed(exp: i64, seed: [u8; 32]) -> (String, Vec<Jwk>) {
        let signer = MemorySigner::from_seed(seed);
        let kid = signer.active_kid().await.unwrap();
        let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
        let claims = serde_json::json!({ "sub": "u1", "aud": ["x"], "iat": 1000, "exp": exp });
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = signer.sign_es256(si.as_bytes()).await.unwrap();
        let jwt = format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig));
        let jwks = signer
            .public_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::to_jwk)
            .collect();
        (jwt, jwks)
    }

    // ===== 跨租户 token 伪造隔离(spec 020 §2.2 / C10.13)=====
    // 密码学不变量:租户 A 的 signing key 签的 token,对租户 B 的 JWKS **必验签失败**。
    // 该属性只取决于 key 材料是否不同——单进程两个种子与逐租户 CMK 等价,故纯逻辑可锁定。
    // 两条签名路径都覆盖:ES256(access token)+ RS256(id_token)。

    // 用 sign_seed 的 EC key 签 ES256 token,但 header.kid 用给定 kid(伪造场景传他人 kid)。
    async fn es256_token_forge_kid(exp: i64, sign_seed: [u8; 32], kid: &str) -> String {
        let signer = MemorySigner::from_seed(sign_seed);
        let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": kid });
        let claims = serde_json::json!({ "sub": "u1", "aud": ["x"], "iat": 1000, "exp": exp });
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let sig = signer.sign_es256(si.as_bytes()).await.unwrap();
        format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    // 取某 seed 的 EC(ES256)active kid。
    async fn es256_kid_of(seed: [u8; 32]) -> String {
        MemorySigner::from_seed(seed).active_kid().await.unwrap()
    }

    // 用 sign_seed 的 RSA key 签 RS256 id_token,header.kid 用给定 kid(伪造场景传他人 kid)。
    async fn rs256_token_forge_kid(exp: i64, sign_seed: [u8; 32], kid: &str) -> String {
        let signer = MemorySigner::from_seed(sign_seed);
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": kid });
        let claims = serde_json::json!({
            "sub": "u1", "aud": CID, "iss": AS_ISS, "iat": 1000, "exp": exp, "jti": "jti-x"
        });
        let si = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap())
        );
        let (_, sig) = signer.sign_rs256(si.as_bytes()).await.unwrap();
        format!("{si}.{}", URL_SAFE_NO_PAD.encode(sig))
    }

    // 取某 seed 的 RSA JWKS + rsa kid。
    async fn rsa_jwks_and_kid(seed: [u8; 32]) -> (Vec<Jwk>, String) {
        let signer = MemorySigner::from_seed(seed);
        let (kid, _) = signer.sign_rs256(b"probe").await.unwrap();
        let jwks = signer
            .public_rsa_jwks()
            .await
            .unwrap()
            .iter()
            .map(crate::jwks::rsa_to_jwk)
            .collect();
        (jwks, kid)
    }

    // C10.13:租户 A 的 EC/ES256 key 冒签,对租户 B 的 EC JWKS **验签失败**(access token 路径)。
    #[tokio::test]
    async fn cross_tenant_es256_forgery_rejected() {
        let seed_a = [0x11u8; 32];
        let seed_b = [0x22u8; 32];
        // (a) 自然场景:A 的 token 带 A 的 kid,B 的 JWKS 只含 B 的 kid → UnknownKid。
        let (jwt_a, _jwks_a) = signed_token_seed(9999, seed_a).await;
        let (_jwt_b, jwks_b) = signed_token_seed(9999, seed_b).await;
        assert_eq!(
            verify_es256(&jwt_a, &jwks_b, 2000),
            Err(VerifyError::UnknownKid),
            "A 签的 access token 对 B 的 JWKS:A 的 kid 不在 B 的 JWKS → UnknownKid"
        );
        // (b) 伪造 kid 场景(更强):攻击者把 header.kid 改成 B 的 kid,仍用 A 的 key 签 →
        //     B 的 JWKS 选中 B 的 key、密码学验签失败 → BadSignature(即便 kid 被冒充也拦下)。
        let kid_b = es256_kid_of(seed_b).await;
        let forged = es256_token_forge_kid(9999, seed_a, &kid_b).await;
        assert_eq!(
            verify_es256(&forged, &jwks_b, 2000),
            Err(VerifyError::BadSignature),
            "A 的 key 签 + 冒充 B 的 kid,对 B 的 JWKS 密码学验签必失败 → BadSignature"
        );
    }

    // C10.15a alg 混淆对称补白(评审 Kiro LOW-2):**反向** RS256 id_token 喂给 access token
    // 验签器(verify_es256/verify_access_token)→ alg 闸拒(header.alg=RS256 != ES256 → BadSignature)。
    // 与既有 `verify_id_token_rejects_es256_token`(正向:ES256 token 喂 id_token 验签器)对称,
    // 两个方向都锁死 alg 混淆:access 验签器恒 ES256、id_token 验签器恒 RS256,互不接受对方 token。
    #[tokio::test]
    async fn rs256_token_rejected_by_es256_verifier() {
        // 造一枚合法 RS256 id_token(除算法外形态齐全)+ 其 RSA JWKS。
        let (rs_jwt, rsa_jwks) =
            signed_id_token(9999, "JWT", AS_ISS, serde_json::json!(CID), true).await;
        // 喂给 access token 的 ES256 验签器:alg=RS256 != ES256,alg 闸即拒(不进签名/kid 选取)。
        assert_eq!(
            verify_es256(&rs_jwt, &rsa_jwks, 2000),
            Err(VerifyError::BadSignature),
            "RS256 id_token 喂 ES256 access 验签器 MUST 因 alg 闸拒(C10.15a alg 混淆防御)"
        );
        // verify_access_token(叠加 typ=at+jwt 闸)同样拒。
        assert_eq!(
            verify_access_token(&rs_jwt, &rsa_jwks, 2000),
            Err(VerifyError::BadSignature),
            "RS256 id_token 喂 verify_access_token MUST 拒(alg 闸先于 typ 闸)"
        );
    }

    // C10.13:租户 A 的 RSA/RS256 key 冒签,对租户 B 的 RSA JWKS **验签失败**(id_token 路径)。
    #[tokio::test]
    async fn cross_tenant_rs256_forgery_rejected() {
        let seed_a = [0x33u8; 32];
        let seed_b = [0x44u8; 32];
        let (jwks_b, kid_b) = rsa_jwks_and_kid(seed_b).await;
        let (_jwks_a, kid_a) = rsa_jwks_and_kid(seed_a).await;
        // (a) 自然场景:A 的 id_token 带 A 的 rsa kid,B 的 JWKS 只含 B 的 → UnknownKid。
        let jwt_a = rs256_token_forge_kid(9999, seed_a, &kid_a).await;
        assert_eq!(
            verify_id_token(&jwt_a, &jwks_b, AS_ISS, Some(CID), 2000),
            Err(VerifyError::UnknownKid),
            "A 签的 id_token 对 B 的 RSA JWKS:A 的 kid 不在 → UnknownKid"
        );
        // (b) 伪造 kid 场景(更强):A 的 RSA key 签 + header.kid=B 的 kid →
        //     B 的 JWKS 选中 B 的 RSA key、验签失败 → BadSignature(密码学隔离,kid 冒充也拦)。
        let forged = rs256_token_forge_kid(9999, seed_a, &kid_b).await;
        assert_eq!(
            verify_id_token(&forged, &jwks_b, AS_ISS, Some(CID), 2000),
            Err(VerifyError::BadSignature),
            "A 的 RSA key 签 + 冒充 B 的 kid,对 B 的 RSA JWKS 验签必失败 → BadSignature"
        );
    }
}
