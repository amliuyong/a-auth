//! WebAuthn passkey 纯逻辑(spec 003 C9.4,P1b 后端契约)。零 IO、零 AWS。
//!
//! **关注点**:rp_id 逐租户派生 + assertion 验证(rpIdHash 匹配 → **跨租户拒**、ES256 签名、
//! counter 单调、UP flag)。浏览器 `navigator.credentials` 注册/认证仪式属前端(frontend-gated),
//! 不在此;本模块只做后端**验证**契约 + credential schema。
//!
//! **跨租户核心**(C9.4):authenticatorData 前 32 字节 = `rpIdHash = SHA256(rp_id)`。验证时用
//! **本租户期望的 rp_id**(逐租户子域,如 `t1.saas.example.com`)算 SHA256 比对——t1 注册的 passkey
//! 其 rpIdHash=SHA256("t1…"),拿到 t2(期望 rp_id="t2…")验证时 rpIdHash 不匹配 → 拒。
//!
//! 决策真相源:docs/DESIGN §7(rp_id 逐租户)/ §8;CONFORMANCE C9.4。

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Verifier, DerSignature, VerifyingKey};
use sha2::{Digest, Sha256};

/// 从 issuer host 派生 WebAuthn rp_id(C9.4):非 BYOD 直接用 issuer host(逐租户子域)。
/// 例:issuer host `t1.saas.example.com` → rp_id `t1.saas.example.com`。**绝不用父域**(那会跨租户越界)。
pub fn rp_id_from_issuer_host(issuer_host: &str) -> String {
    // P1:rp_id = issuer host 本身(逐租户子域已隔离)。BYOD 自带域名策略 post-freeze(P3)。
    issuer_host.trim().to_lowercase()
}

/// 存储的 passkey 凭证(持久身份记录;生命周期见 C10.5,不挂裸 TTL)。
/// serde:Dynamo adapter 存 JSON(公钥非 secret;凭证是公开验证材料,私钥在用户 authenticator 里)。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PasskeyCredential {
    /// 凭证 id(WebAuthn credentialId,base64url)。
    pub credential_id: String,
    /// 用户内部 id(该 passkey 归属)。
    pub user_id: String,
    /// 该凭证注册时绑定的 rp_id(逐租户;验证时须与本租户期望 rp_id 一致)。
    pub rp_id: String,
    /// COSE/SEC1 公钥(P-256 未压缩点 65 字节:0x04‖X‖Y)。
    pub public_key_sec1: Vec<u8>,
    /// 签名计数器(防克隆:每次认证 MUST 严格递增)。
    pub sign_count: u32,
    /// User-managed presentation name. It is not credential material.
    #[serde(default = "default_passkey_name")]
    pub name: String,
    /// Registration time (Unix seconds). Legacy records default to unknown.
    #[serde(default)]
    pub created_at: i64,
}

fn default_passkey_name() -> String {
    "Passkey".to_string()
}

/// assertion 验证的输入(浏览器 navigator.credentials.get 的产物,已 base64url 解码为字节)。
pub struct AssertionInput<'a> {
    /// authenticatorData(前 32 字节 rpIdHash + 1 字节 flags + 4 字节 signCount + …)。
    pub authenticator_data: &'a [u8],
    /// clientDataJSON 原始字节。
    pub client_data_json: &'a [u8],
    /// 签名(ASN.1 DER,ES256)。
    pub signature: &'a [u8],
}

/// 本次 assertion 的服务端期望(防重放/防跨源;WebAuthn §7.2 client data 校验)。
pub struct AssertionExpectations<'a> {
    /// 本租户期望 rp_id(逐租户;t1 的 passkey 到 t2 在此拒,C9.4)。
    pub rp_id: &'a str,
    /// 服务端下发并记住的 challenge(base64url;clientDataJSON.challenge MUST 逐字节等,防重放)。
    pub challenge_b64url: &'a str,
    /// 期望 origin(= 本租户 issuer origin,如 `https://t1.saas.example.com`;clientDataJSON.origin MUST 等,防跨源)。
    pub origin: &'a str,
    /// 是否要求 User Verified(UV,评审 Kiro High):passkey 作**无密码主认证因子**签发全会话
    /// (amr 含 webauthn/hwk),MUST 要求 UV(bit2)——仅 UP(present)不足以支撑主因子保证。
    /// 注册时 `authenticatorSelection.userVerification="required"`,认证时校 UV flag。
    pub require_uv: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssertionError {
    /// authenticatorData 太短(< 37 字节)。
    Malformed,
    /// rpIdHash 与期望 rp_id 不符(**跨租户/错 RP**,C9.4 核心拒因)。
    RpIdMismatch,
    /// User Present(UP)flag 未置位。
    UserNotPresent,
    /// require_uv 但 User Verified(UV)flag 未置位(评审 Kiro:无密码主因子 MUST UV)。
    UserNotVerified,
    /// 签名验证失败。
    BadSignature,
    /// counter 未严格递增(可能凭证克隆)。
    CounterNotIncreasing,
    /// 公钥非法。
    BadPublicKey,
    /// clientDataJSON 非法(非 JSON / 缺字段)。
    BadClientData,
    /// clientDataJSON.type != "webauthn.get"(防把注册/其它仪式的 clientData 当认证用)。
    WrongType,
    /// clientDataJSON.challenge 与服务端下发的不符(**防重放**)。
    ChallengeMismatch,
    /// clientDataJSON.origin 与期望不符(**防跨源**)。
    OriginMismatch,
}

/// 从 authenticatorData 取 (rpIdHash[0..32], flags, signCount)。
fn parse_auth_data(ad: &[u8]) -> Option<(&[u8], u8, u32)> {
    if ad.len() < 37 {
        return None;
    }
    let rp_id_hash = &ad[0..32];
    let flags = ad[32];
    let sign_count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    Some((rp_id_hash, flags, sign_count))
}

/// 校验 clientDataJSON(WebAuthn §7.2 步骤 3-5,防重放/防跨源):
/// `type == "webauthn.get"` + `challenge` 逐字节等服务端下发 + `origin` 等期望。
fn verify_client_data(
    client_data_json: &[u8],
    challenge_b64url: &str,
    expected_origin: &str,
) -> Result<(), AssertionError> {
    let v: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| AssertionError::BadClientData)?;
    // type MUST == webauthn.get(拒把注册 webauthn.create / 其它仪式的 clientData 当认证用)。
    if v.get("type").and_then(|t| t.as_str()) != Some("webauthn.get") {
        return Err(AssertionError::WrongType);
    }
    // challenge MUST 逐字节等服务端记住的(base64url;防重放)。
    if v.get("challenge").and_then(|c| c.as_str()) != Some(challenge_b64url) {
        return Err(AssertionError::ChallengeMismatch);
    }
    // origin MUST == 期望(本租户 issuer origin;防跨源钓鱼)。
    if v.get("origin").and_then(|o| o.as_str()) != Some(expected_origin) {
        return Err(AssertionError::OriginMismatch);
    }
    Ok(())
}

/// 验证一次 WebAuthn assertion(C9.4,完整含 clientDataJSON 校验)。成功返回新 signCount。
///
/// 步骤(WebAuthn §7.2):①clientDataJSON:type=webauthn.get + challenge 逐字节等(防重放)+
/// origin 等期望(防跨源);②rpIdHash == SHA256(expected rp_id)(跨租户拒,C9.4);③UP flag 置位;
/// ④ES256 验签 over `authenticatorData ‖ SHA256(clientDataJSON)`;⑤signCount 严格递增。
pub fn verify_assertion(
    cred: &PasskeyCredential,
    expect: &AssertionExpectations<'_>,
    input: &AssertionInput<'_>,
) -> Result<u32, AssertionError> {
    // The stored credential is itself RP-bound. Checking only authenticatorData would let a
    // caller with the private key sign a fresh assertion for another RP and reuse a credential
    // record that was accidentally exposed across a tenant boundary.
    if cred.rp_id != expect.rp_id {
        return Err(AssertionError::RpIdMismatch);
    }

    // ① clientDataJSON 校验(防重放 + 防跨源;先于验签做形态闸,验签仍覆盖 clientDataJSON 完整性)。
    verify_client_data(
        input.client_data_json,
        expect.challenge_b64url,
        expect.origin,
    )?;

    let (rp_id_hash, flags, sign_count) =
        parse_auth_data(input.authenticator_data).ok_or(AssertionError::Malformed)?;

    // ② rpIdHash 必须 == SHA256(本租户期望 rp_id)。t1 的 passkey 到 t2 验证在此拒(C9.4)。
    let expected_hash = Sha256::digest(expect.rp_id.as_bytes());
    if rp_id_hash != expected_hash.as_slice() {
        return Err(AssertionError::RpIdMismatch);
    }

    // ③ User Present(bit 0)MUST 置位。
    if flags & 0x01 == 0 {
        return Err(AssertionError::UserNotPresent);
    }
    // ③b User Verified(bit 2)MUST 置位(当 require_uv:无密码主因子保证,评审 Kiro High)。
    if expect.require_uv && flags & 0x04 == 0 {
        return Err(AssertionError::UserNotVerified);
    }

    // ④ 验签:signed data = authenticatorData ‖ SHA256(clientDataJSON)。
    let vk = VerifyingKey::from_sec1_bytes(&cred.public_key_sec1)
        .map_err(|_| AssertionError::BadPublicKey)?;
    let client_data_hash = Sha256::digest(input.client_data_json);
    let mut signed = Vec::with_capacity(input.authenticator_data.len() + 32);
    signed.extend_from_slice(input.authenticator_data);
    signed.extend_from_slice(&client_data_hash);
    let sig =
        DerSignature::from_bytes(input.signature).map_err(|_| AssertionError::BadSignature)?;
    vk.verify(&signed, &sig)
        .map_err(|_| AssertionError::BadSignature)?;

    // ⑤ signCount 严格递增(防克隆)。两边都为 0 是"认证器不支持计数",放行(WebAuthn 允许)。
    if (sign_count != 0 || cred.sign_count != 0) && sign_count <= cred.sign_count {
        return Err(AssertionError::CounterNotIncreasing);
    }
    Ok(sign_count)
}

// ============ 注册(attestation)——评审 Kiro:仿 verify_assertion,放 authn crate,结构性 fail-closed ============

/// 注册仪式的服务端期望(begin 下发,finish 校验)。
pub struct RegistrationExpectations<'a> {
    /// 本租户期望 rp_id(逐租户;credential 绑此 rp_id)。
    pub rp_id: &'a str,
    /// begin 下发并绑当前登录会话 user_id 的 challenge(base64url;clientDataJSON.challenge 逐字节等,防重放)。
    pub challenge_b64url: &'a str,
    /// 期望 origin(本租户 issuer origin;防跨源)。
    pub origin: &'a str,
    /// MUST 要求 UV(无密码主因子;与 assertion 侧对称,评审 Kiro High)。
    pub require_uv: bool,
}

/// 注册验证成功产出:要存进 `PasskeyCredential` 的凭证 id + SEC1 公钥。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredCredential {
    /// credentialId(base64url;PasskeyStore 主键,MUST 全局唯一——存储层条件写保证)。
    pub credential_id: String,
    /// P-256 SEC1 未压缩点(0x04‖X‖Y,65 字节;存 PasskeyCredential.public_key_sec1)。
    pub public_key_sec1: Vec<u8>,
    /// 初始 signCount(注册时 authData 的计数;后续认证严格递增)。
    pub sign_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    /// clientDataJSON 非法(非 JSON / 缺字段)。
    BadClientData,
    /// clientDataJSON.type != "webauthn.create"(防把认证/其它仪式的 clientData 当注册用)。
    WrongType,
    /// challenge 不符(防重放)。
    ChallengeMismatch,
    /// origin 不符(防跨源)。
    OriginMismatch,
    /// attestationObject CBOR 畸形 / 非 map / 缺 fmt|authData。
    BadAttestation,
    /// fmt != "none"(P1 仅 fmt=none;企业 attestation packed/tpm 留后)。
    UnsupportedFmt,
    /// authData 太短(< 37 + attestedCredentialData 头)或结构非法。
    Malformed,
    /// rpIdHash != SHA256(rp_id)(跨租户 / 错 RP)。
    RpIdMismatch,
    /// UP flag 未置位。
    UserNotPresent,
    /// require_uv 但 UV flag 未置位(无密码主因子 MUST UV)。
    UserNotVerified,
    /// authData 未置 AT(Attested credential data included)flag,或无 attestedCredentialData。
    NoAttestedCredential,
    /// COSE 公钥非 EC2/P-256/ES256,或坐标非法(防 alg 混淆)。
    BadCoseKey,
}

/// **验证 WebAuthn 注册(fmt=none)**(C9.4,评审 Kiro:仿 verify_assertion 放 authn crate)。给定
/// clientDataJSON + attestationObject(CBOR)+ 服务端期望 → 校验后产出要存的凭证。全 fail-closed。
///
/// 步骤(WebAuthn §7.1 registration,fmt=none 子集):
/// ①clientDataJSON:type==webauthn.create + challenge 逐字节等 + origin 等期望;
/// ②CBOR 解 attestationObject{fmt,attStmt,authData};fmt MUST=="none"(P1);
/// ③authData:rpIdHash==SHA256(rp_id)[跨租户拒] + UP + (require_uv→UV) + AT flag;
/// ④解 attestedCredentialData 取 credentialId + COSE 公钥;COSE MUST EC2/P-256/ES256 → SEC1(0x04‖X‖Y);
/// ⑤返 RegisteredCredential(credentialId/SEC1/初始 signCount)。
pub fn verify_attestation_none(
    client_data_json: &[u8],
    attestation_object: &[u8],
    expect: &RegistrationExpectations<'_>,
) -> Result<RegisteredCredential, RegistrationError> {
    // ① clientDataJSON(type=webauthn.create + challenge + origin)。
    let v: serde_json::Value =
        serde_json::from_slice(client_data_json).map_err(|_| RegistrationError::BadClientData)?;
    if v.get("type").and_then(|t| t.as_str()) != Some("webauthn.create") {
        return Err(RegistrationError::WrongType);
    }
    if v.get("challenge").and_then(|c| c.as_str()) != Some(expect.challenge_b64url) {
        return Err(RegistrationError::ChallengeMismatch);
    }
    if v.get("origin").and_then(|o| o.as_str()) != Some(expect.origin) {
        return Err(RegistrationError::OriginMismatch);
    }

    // ② CBOR 解 attestationObject → {fmt, authData}。
    let att: ciborium::value::Value = ciborium::de::from_reader(attestation_object)
        .map_err(|_| RegistrationError::BadAttestation)?;
    let map = att.as_map().ok_or(RegistrationError::BadAttestation)?;
    let mut fmt: Option<&str> = None;
    let mut auth_data: Option<&[u8]> = None;
    for (k, val) in map {
        match k.as_text() {
            Some("fmt") => fmt = val.as_text(),
            Some("authData") => auth_data = val.as_bytes().map(|b| b.as_slice()),
            _ => {}
        }
    }
    if fmt != Some("none") {
        return Err(RegistrationError::UnsupportedFmt);
    }
    let ad = auth_data.ok_or(RegistrationError::BadAttestation)?;

    // ③ authData 头:rpIdHash(32) + flags(1) + signCount(4)。
    if ad.len() < 37 {
        return Err(RegistrationError::Malformed);
    }
    let rp_id_hash = &ad[0..32];
    let flags = ad[32];
    let sign_count = u32::from_be_bytes([ad[33], ad[34], ad[35], ad[36]]);
    let expected_hash = Sha256::digest(expect.rp_id.as_bytes());
    if rp_id_hash != expected_hash.as_slice() {
        return Err(RegistrationError::RpIdMismatch);
    }
    if flags & 0x01 == 0 {
        return Err(RegistrationError::UserNotPresent);
    }
    if expect.require_uv && flags & 0x04 == 0 {
        return Err(RegistrationError::UserNotVerified);
    }
    // AT flag(bit 6,0x40):MUST 置位(注册须带 attestedCredentialData)。
    if flags & 0x40 == 0 {
        return Err(RegistrationError::NoAttestedCredential);
    }

    // ④ attestedCredentialData:AAGUID(16) + credIdLen(2 BE) + credId + COSE 公钥(剩余)。
    let acd = &ad[37..];
    if acd.len() < 18 {
        return Err(RegistrationError::Malformed);
    }
    let cred_id_len = u16::from_be_bytes([acd[16], acd[17]]) as usize;
    let cred_id_start = 18;
    let cred_id_end = cred_id_start + cred_id_len;
    if acd.len() < cred_id_end {
        return Err(RegistrationError::Malformed);
    }
    let credential_id = &acd[cred_id_start..cred_id_end];
    let cose_bytes = &acd[cred_id_end..];
    let public_key_sec1 = cose_ec2_p256_to_sec1(cose_bytes)?;

    Ok(RegisteredCredential {
        credential_id: URL_SAFE_NO_PAD.encode(credential_id),
        public_key_sec1,
        sign_count,
    })
}

/// COSE_Key(EC2/P-256/ES256)→ SEC1 未压缩点(0x04‖X‖Y)。fail-closed:非 EC2(kty≠2)/非 P-256(crv≠1)/
/// 非 ES256(alg≠-7)/坐标长度≠32 → BadCoseKey(防 alg 混淆 / 曲线混淆)。
/// COSE key label:1=kty, 3=alg, -1=crv, -2=x, -3=y(RFC 8152 / 9053)。
fn cose_ec2_p256_to_sec1(cose: &[u8]) -> Result<Vec<u8>, RegistrationError> {
    let v: ciborium::value::Value =
        ciborium::de::from_reader(cose).map_err(|_| RegistrationError::BadCoseKey)?;
    let map = v.as_map().ok_or(RegistrationError::BadCoseKey)?;
    let int = |val: &ciborium::value::Value| -> Option<i64> {
        val.as_integer().and_then(|i| i64::try_from(i).ok())
    };
    let (mut kty, mut alg, mut crv): (Option<i64>, Option<i64>, Option<i64>) = (None, None, None);
    let (mut x, mut y): (Option<Vec<u8>>, Option<Vec<u8>>) = (None, None);
    for (k, val) in map {
        match k.as_integer().and_then(|i| i64::try_from(i).ok()) {
            Some(1i64) => kty = int(val),
            Some(3i64) => alg = int(val),
            Some(-1i64) => crv = int(val),
            Some(-2i64) => x = val.as_bytes().cloned(),
            Some(-3i64) => y = val.as_bytes().cloned(),
            _ => {}
        }
    }
    // kty=2(EC2)、alg=-7(ES256)、crv=1(P-256);坐标各 32 字节。
    if kty != Some(2) || alg != Some(-7) || crv != Some(1) {
        return Err(RegistrationError::BadCoseKey);
    }
    let (x, y) = (
        x.ok_or(RegistrationError::BadCoseKey)?,
        y.ok_or(RegistrationError::BadCoseKey)?,
    );
    if x.len() != 32 || y.len() != 32 {
        return Err(RegistrationError::BadCoseKey);
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    // 纵深:确认是曲线上合法点(拒无效点,防后续验签 panic/异常)。
    VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| RegistrationError::BadCoseKey)?;
    Ok(sec1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    // rp_id 逐租户派生:issuer host 即 rp_id(小写),不取父域。
    #[test]
    fn rp_id_is_per_tenant_host() {
        assert_eq!(
            rp_id_from_issuer_host("T1.saas.example.com"),
            "t1.saas.example.com"
        );
        assert_ne!(
            rp_id_from_issuer_host("t1.saas.example.com"),
            "saas.example.com"
        );
    }

    // 造一次合法 assertion(用 signing key 签),返回 (cred, input bytes 持有者)。
    struct Fixture {
        key: SigningKey,
        pubkey: Vec<u8>,
    }
    fn fixture() -> Fixture {
        let key = SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let vk = key.verifying_key();
        let pubkey = vk.to_encoded_point(false).as_bytes().to_vec();
        Fixture { key, pubkey }
    }

    fn auth_data(rp_id: &str, flags: u8, count: u32) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        ad.push(flags);
        ad.extend_from_slice(&count.to_be_bytes());
        ad
    }

    fn sign(key: &SigningKey, ad: &[u8], cdj: &[u8]) -> Vec<u8> {
        let mut signed = ad.to_vec();
        signed.extend_from_slice(&Sha256::digest(cdj));
        let sig: Signature = key.sign(&signed);
        sig.to_der().as_bytes().to_vec()
    }

    const CHAL: &str = "Y2hhbGxlbmdl"; // "challenge" base64url(测试固定值)
    const ORIGIN: &str = "https://t1.saas.example.com";

    // 合法 clientDataJSON(webauthn.get + 固定 challenge + origin)。
    fn cdj_ok() -> Vec<u8> {
        format!(r#"{{"type":"webauthn.get","challenge":"{CHAL}","origin":"{ORIGIN}"}}"#)
            .into_bytes()
    }

    fn expect(rp: &str) -> AssertionExpectations<'static> {
        // rp 借用有生命周期问题——测试里 rp 都是 'static 字面量,直接构造。
        AssertionExpectations {
            rp_id: Box::leak(rp.to_string().into_boxed_str()),
            challenge_b64url: CHAL,
            origin: ORIGIN,
            require_uv: false, // 多数既有用例只校 UP;UV required 由 uv_required_* 用例专测
        }
    }

    #[test]
    fn valid_assertion_ok_and_returns_new_count() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 5);
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c1".into(),
            user_id: "u1".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 3,
            name: "Passkey".into(),
            created_at: 0,
        };
        let out = verify_assertion(
            &cred,
            &expect(rp),
            &AssertionInput {
                authenticator_data: &ad,
                client_data_json: &cdj,
                signature: &sig,
            },
        );
        assert_eq!(out, Ok(5));
    }

    // C9.4 核心:t1 注册的 passkey(rpIdHash=SHA256 t1)拿到 t2 验证(期望 rp_id=t2)→ RpIdMismatch。
    #[test]
    fn t1_passkey_rejected_at_t2() {
        let f = fixture();
        let ad = auth_data("t1.saas.example.com", 0x01, 5); // rpIdHash 绑 t1
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c1".into(),
            user_id: "u1".into(),
            rp_id: "t1.saas.example.com".into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        // 在 t2 验证(expected rp_id = t2)→ 拒(challenge/origin 相同,只 rp_id 变)。
        let exp = AssertionExpectations {
            rp_id: "t2.saas.example.com",
            challenge_b64url: CHAL,
            origin: ORIGIN,
            require_uv: false,
        };
        let out = verify_assertion(
            &cred,
            &exp,
            &AssertionInput {
                authenticator_data: &ad,
                client_data_json: &cdj,
                signature: &sig,
            },
        );
        assert_eq!(out, Err(AssertionError::RpIdMismatch));
    }

    #[test]
    fn stored_t1_credential_rejected_even_when_assertion_is_forged_for_t2() {
        let f = fixture();
        let ad = auth_data("t2.saas.example.com", 0x01, 5);
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c1".into(),
            user_id: "u1".into(),
            rp_id: "t1.saas.example.com".into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        let exp = AssertionExpectations {
            rp_id: "t2.saas.example.com",
            challenge_b64url: CHAL,
            origin: ORIGIN,
            require_uv: false,
        };

        assert_eq!(
            verify_assertion(
                &cred,
                &exp,
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig,
                },
            ),
            Err(AssertionError::RpIdMismatch)
        );
    }

    #[test]
    fn up_flag_required() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x00, 1); // UP 未置位
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::UserNotPresent)
        );
    }

    // require_uv=true + UV(bit2)置位(flags=0x05=UP|UV)→ 通过(无密码主因子)。
    #[test]
    fn uv_required_and_present_ok() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x05, 5); // UP|UV
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        let mut exp = expect(rp);
        exp.require_uv = true;
        assert!(verify_assertion(
            &cred,
            &exp,
            &AssertionInput {
                authenticator_data: &ad,
                client_data_json: &cdj,
                signature: &sig
            }
        )
        .is_ok());
    }

    // require_uv=true + 仅 UP(flags=0x01,UV 未置位)→ UserNotVerified(评审 Kiro High:主因子 MUST UV)。
    #[test]
    fn uv_required_but_absent_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 5); // 仅 UP
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        let mut exp = expect(rp);
        exp.require_uv = true;
        assert_eq!(
            verify_assertion(
                &cred,
                &exp,
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::UserNotVerified)
        );
    }

    #[test]
    fn counter_must_increase() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 5); // count=5
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 5, // 已是 5,新的 5 不 > 5
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::CounterNotIncreasing)
        );
    }

    #[test]
    fn bad_signature_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 9);
        let cdj = cdj_ok();
        let mut sig = sign(&f.key, &ad, &cdj);
        // 篡改签名末字节。
        *sig.last_mut().unwrap() ^= 0xFF;
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::BadSignature)
        );
    }

    #[test]
    fn malformed_auth_data_rejected() {
        let f = fixture();
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: "t1".into(),
            public_key_sec1: f.pubkey,
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        // clientData 合法(过 clientData 闸)但 authenticatorData 太短 → Malformed。
        let cdj = cdj_ok();
        let exp = AssertionExpectations {
            rp_id: "t1",
            challenge_b64url: CHAL,
            origin: ORIGIN,
            require_uv: false,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &exp,
                &AssertionInput {
                    authenticator_data: &[0u8; 10],
                    client_data_json: &cdj,
                    signature: b"x"
                }
            ),
            Err(AssertionError::Malformed)
        );
    }

    // counter 双 0(认证器不支持计数)→ 放行(WebAuthn 允许)。
    #[test]
    fn zero_counters_allowed() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 0);
        let cdj = cdj_ok();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Ok(0)
        );
    }

    // 防重放:challenge 不符 → ChallengeMismatch(即便签名/rpId 都对)。
    #[test]
    fn challenge_mismatch_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 1);
        // clientData 带**别的** challenge(重放旧 assertion 场景)。
        let cdj = format!(r#"{{"type":"webauthn.get","challenge":"b3RoZXI","origin":"{ORIGIN}"}}"#)
            .into_bytes();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::ChallengeMismatch)
        );
    }

    // 防跨源:origin 不符 → OriginMismatch。
    #[test]
    fn origin_mismatch_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 1);
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{CHAL}","origin":"https://evil.example.com"}}"#
        )
        .into_bytes();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::OriginMismatch)
        );
    }

    // type != webauthn.get(如把注册的 webauthn.create clientData 拿来认证)→ WrongType。
    #[test]
    fn wrong_type_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let ad = auth_data(rp, 0x01, 1);
        let cdj =
            format!(r#"{{"type":"webauthn.create","challenge":"{CHAL}","origin":"{ORIGIN}"}}"#)
                .into_bytes();
        let sig = sign(&f.key, &ad, &cdj);
        let cred = PasskeyCredential {
            credential_id: "c".into(),
            user_id: "u".into(),
            rp_id: rp.into(),
            public_key_sec1: f.pubkey.clone(),
            sign_count: 0,
            name: "Passkey".into(),
            created_at: 0,
        };
        assert_eq!(
            verify_assertion(
                &cred,
                &expect(rp),
                &AssertionInput {
                    authenticator_data: &ad,
                    client_data_json: &cdj,
                    signature: &sig
                }
            ),
            Err(AssertionError::WrongType)
        );
    }

    // ---- verify_attestation_none(注册,fmt=none;进程内 CBOR encode 造 attestation)----
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;

    // 把 P-256 SEC1 公钥(0x04‖X‖Y)编成 COSE_Key CBOR(EC2/P-256/ES256)。
    fn cose_from_sec1(sec1: &[u8]) -> Vec<u8> {
        let x = &sec1[1..33];
        let y = &sec1[33..65];
        // COSE map:{1:2(EC2), 3:-7(ES256), -1:1(P-256), -2:X, -3:Y}。
        let val = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            (
                ciborium::value::Value::Integer(3.into()),
                ciborium::value::Value::Integer((-7).into()),
            ),
            (
                ciborium::value::Value::Integer((-1).into()),
                ciborium::value::Value::Integer(1.into()),
            ),
            (
                ciborium::value::Value::Integer((-2).into()),
                ciborium::value::Value::Bytes(x.to_vec()),
            ),
            (
                ciborium::value::Value::Integer((-3).into()),
                ciborium::value::Value::Bytes(y.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&val, &mut out).unwrap();
        out
    }

    // 造 authData:rpIdHash(32)+flags(1)+signCount(4)+AAGUID(16)+credIdLen(2)+credId+COSE。
    fn auth_data_reg(rp_id: &str, flags: u8, count: u32, cred_id: &[u8], cose: &[u8]) -> Vec<u8> {
        let mut ad = Vec::new();
        ad.extend_from_slice(&Sha256::digest(rp_id.as_bytes()));
        ad.push(flags);
        ad.extend_from_slice(&count.to_be_bytes());
        ad.extend_from_slice(&[0u8; 16]); // AAGUID
        ad.extend_from_slice(&(cred_id.len() as u16).to_be_bytes());
        ad.extend_from_slice(cred_id);
        ad.extend_from_slice(cose);
        ad
    }

    // 造 attestationObject CBOR:{fmt:"none", attStmt:{}, authData:bytes}。
    fn attestation_none(auth_data: &[u8]) -> Vec<u8> {
        let val = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".into()),
                ciborium::value::Value::Text("none".into()),
            ),
            (
                ciborium::value::Value::Text("attStmt".into()),
                ciborium::value::Value::Map(vec![]),
            ),
            (
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(auth_data.to_vec()),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::ser::into_writer(&val, &mut out).unwrap();
        out
    }

    fn cdj_create() -> Vec<u8> {
        format!(r#"{{"type":"webauthn.create","challenge":"{CHAL}","origin":"{ORIGIN}"}}"#)
            .into_bytes()
    }

    fn reg_expect(rp: &str) -> RegistrationExpectations<'static> {
        RegistrationExpectations {
            rp_id: Box::leak(rp.to_string().into_boxed_str()),
            challenge_b64url: CHAL,
            origin: ORIGIN,
            require_uv: true,
        }
    }

    // 快乐路径:合法 fmt=none attestation(UP|UV|AT flags)→ 产出 credentialId + SEC1 公钥。
    #[test]
    fn attestation_none_valid_extracts_credential() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let cose = cose_from_sec1(&f.pubkey);
        let cred_id = b"cred-abc-123";
        let ad = auth_data_reg(rp, 0x45, 7, cred_id, &cose); // 0x45 = UP|UV|AT
        let att = attestation_none(&ad);
        let out = verify_attestation_none(&cdj_create(), &att, &reg_expect(rp)).unwrap();
        assert_eq!(out.credential_id, B64.encode(cred_id));
        assert_eq!(out.public_key_sec1, f.pubkey, "COSE→SEC1 还原 == 原公钥");
        assert_eq!(out.sign_count, 7);
    }

    // 跨租户拒:t1 注册的 rpIdHash 用 t2 期望验 → RpIdMismatch(C9.4)。
    #[test]
    fn attestation_rp_id_cross_tenant_rejected() {
        let f = fixture();
        let cose = cose_from_sec1(&f.pubkey);
        let ad = auth_data_reg("t1.saas.example.com", 0x45, 1, b"c", &cose);
        let att = attestation_none(&ad);
        assert_eq!(
            verify_attestation_none(&cdj_create(), &att, &reg_expect("t2.saas.example.com")),
            Err(RegistrationError::RpIdMismatch)
        );
    }

    // UV required 但仅 UP|AT(0x41,无 UV)→ UserNotVerified。
    #[test]
    fn attestation_uv_required_but_absent_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let cose = cose_from_sec1(&f.pubkey);
        let ad = auth_data_reg(rp, 0x41, 1, b"c", &cose); // UP|AT,无 UV
        let att = attestation_none(&ad);
        assert_eq!(
            verify_attestation_none(&cdj_create(), &att, &reg_expect(rp)),
            Err(RegistrationError::UserNotVerified)
        );
    }

    // 非 fmt=none(如 packed)→ UnsupportedFmt(P1 仅 none)。
    #[test]
    fn attestation_non_none_fmt_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let cose = cose_from_sec1(&f.pubkey);
        let ad = auth_data_reg(rp, 0x45, 1, b"c", &cose);
        let val = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Text("fmt".into()),
                ciborium::value::Value::Text("packed".into()),
            ),
            (
                ciborium::value::Value::Text("authData".into()),
                ciborium::value::Value::Bytes(ad),
            ),
        ]);
        let mut att = Vec::new();
        ciborium::ser::into_writer(&val, &mut att).unwrap();
        assert_eq!(
            verify_attestation_none(&cdj_create(), &att, &reg_expect(rp)),
            Err(RegistrationError::UnsupportedFmt)
        );
    }

    // 畸形 CBOR → BadAttestation(fail-closed)。
    #[test]
    fn attestation_malformed_cbor_rejected() {
        let rp = "t1.saas.example.com";
        assert_eq!(
            verify_attestation_none(&cdj_create(), &[0xff, 0x00, 0x13, 0x37], &reg_expect(rp)),
            Err(RegistrationError::BadAttestation)
        );
    }

    // wrong type(把 webauthn.get 的 clientData 拿来注册)→ WrongType。
    #[test]
    fn attestation_wrong_client_data_type_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let cose = cose_from_sec1(&f.pubkey);
        let ad = auth_data_reg(rp, 0x45, 1, b"c", &cose);
        let att = attestation_none(&ad);
        let cdj_get =
            format!(r#"{{"type":"webauthn.get","challenge":"{CHAL}","origin":"{ORIGIN}"}}"#)
                .into_bytes();
        assert_eq!(
            verify_attestation_none(&cdj_get, &att, &reg_expect(rp)),
            Err(RegistrationError::WrongType)
        );
    }

    // COSE 非 P-256(crv 错)→ BadCoseKey(防曲线混淆)。
    #[test]
    fn attestation_non_p256_cose_rejected() {
        let f = fixture();
        let rp = "t1.saas.example.com";
        let x = &f.pubkey[1..33];
        let y = &f.pubkey[33..65];
        // crv=2(P-384)而非 1 → 拒。
        let bad = ciborium::value::Value::Map(vec![
            (
                ciborium::value::Value::Integer(1.into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            (
                ciborium::value::Value::Integer(3.into()),
                ciborium::value::Value::Integer((-7).into()),
            ),
            (
                ciborium::value::Value::Integer((-1).into()),
                ciborium::value::Value::Integer(2.into()),
            ),
            (
                ciborium::value::Value::Integer((-2).into()),
                ciborium::value::Value::Bytes(x.to_vec()),
            ),
            (
                ciborium::value::Value::Integer((-3).into()),
                ciborium::value::Value::Bytes(y.to_vec()),
            ),
        ]);
        let mut cose = Vec::new();
        ciborium::ser::into_writer(&bad, &mut cose).unwrap();
        let ad = auth_data_reg(rp, 0x45, 1, b"c", &cose);
        let att = attestation_none(&ad);
        assert_eq!(
            verify_attestation_none(&cdj_create(), &att, &reg_expect(rp)),
            Err(RegistrationError::BadCoseKey)
        );
    }
}
