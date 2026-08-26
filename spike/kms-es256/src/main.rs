//! P-1 薄纵切 spike(DESIGN §10,P0 开工 gate)——KMS ES256 Sign 密码学链 + 延迟实测。
//!
//! 验证最薄端到端签名链的**正确性**与**性能输入**:
//!   JWT signing input → 真实 KMS ECDSA_SHA_256 Sign(得 DER 签名)
//!   → `infra_core::signature::der_to_jose`(DER→裸 r‖s)→ 组装完整 JWT
//!   → 导出公钥(GetPublicKey,SPKI DER)→ 交独立验签器(PyJWT)验签。
//! 同时实测 KMS Sign 延迟(P50/P95/P99),作为语言选型 / provisioned concurrency /
//! 跨区分片阈值 / P0 工期重估的输入(DESIGN §10 line 776/783)。
//!
//! ⚠️ 这是 spike,不是生产代码:创建的 CMK 用后可 `--cleanup` 计划删除。账号号等敏感值走 .env、不进 repo。
//!
//! 用法:
//!   cargo run                      # 创建临时 EC_NIST_P256 CMK,跑签名链 + 延迟实测
//!   cargo run -- --reuse-key <id>  # 复用已有 CMK(避免重复创建)
//!   cargo run -- --cleanup <id>    # 计划删除该 CMK(7 天等待期)

use anyhow::{anyhow, Context, Result};
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, KeyUsageType, MessageType, SigningAlgorithmSpec};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use std::time::Instant;

use agent_auth_infra_core::signature::der_to_jose;

const REGION: &str = "us-east-1";
const LATENCY_SAMPLES: usize = 30;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let conf = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_kms::config::Region::new(REGION))
        .load()
        .await;
    let kms = aws_sdk_kms::Client::new(&conf);

    // --cleanup <id>:计划删除 spike CMK(KMS 最短 7 天等待期,无法立即硬删)。
    if args.get(1).map(String::as_str) == Some("--cleanup") {
        let key_id = args.get(2).ok_or_else(|| anyhow!("--cleanup 需 key id"))?;
        let out = kms
            .schedule_key_deletion()
            .key_id(key_id)
            .pending_window_in_days(7)
            .send()
            .await
            .context("schedule_key_deletion 失败")?;
        println!("已计划删除 CMK {key_id};删除时间 ≈ {:?}", out.deletion_date());
        return Ok(());
    }

    // 复用或创建 EC_NIST_P256(ES256)signing CMK。
    let key_id = if args.get(1).map(String::as_str) == Some("--reuse-key") {
        args.get(2).ok_or_else(|| anyhow!("--reuse-key 需 key id"))?.clone()
    } else {
        println!("创建 EC_NIST_P256(ES256)signing CMK …");
        let out = kms
            .create_key()
            .key_spec(KeySpec::EccNistP256)
            .key_usage(KeyUsageType::SignVerify)
            .description("agent-auth P-1 spike ES256 (DELETE ME)")
            .send()
            .await
            .context("create_key 失败")?;
        let id = out
            .key_metadata()
            .and_then(|m| Some(m.key_id().to_string()))
            .ok_or_else(|| anyhow!("create_key 无 key_id"))?;
        println!("已创建 CMK: {id}");
        println!("⚠️ 用后清理: cargo run -- --cleanup {id}");
        id
    };

    // ---- 1. 组装 JWT header + payload,算 signing input ----
    let header = serde_json::json!({ "alg": "ES256", "typ": "at+jwt", "kid": "spike" });
    let now = 1_700_000_000i64; // spike 固定时间戳(不读墙上时钟)
    let payload = serde_json::json!({
        "iss": "https://spike.example.com",
        "sub": "spike-subject",
        "aud": ["https://mcp.rs.example.com"],
        "iat": now,
        "exp": now + 300,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    );

    // ---- 2. KMS Sign(ECDSA_SHA_256,RAW message)→ DER 签名 ----
    // MessageType::Raw:KMS 内部对 message 做 SHA-256 再签(与 JOSE ES256 = ES256(SHA-256(input)) 一致)。
    let sign_out = kms
        .sign()
        .key_id(&key_id)
        .message(Blob::new(signing_input.clone().into_bytes()))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .send()
        .await
        .context("KMS Sign 失败")?;
    let der_sig = sign_out
        .signature()
        .ok_or_else(|| anyhow!("Sign 无 signature"))?
        .as_ref()
        .to_vec();
    println!("KMS 返回 DER 签名 {} 字节", der_sig.len());

    // ---- 3. DER → JOSE(用我们的 infra-core 转换)----
    let jose_sig = der_to_jose(&der_sig).map_err(|e| anyhow!("der_to_jose 失败: {e:?}"))?;
    println!("DER→JOSE 转换后 {} 字节(应为 64)", jose_sig.len());

    // ---- 4. 组装完整 JWT ----
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(jose_sig));

    // ---- 5. 导出公钥(SPKI DER)供独立验签 ----
    let pk_out = kms.get_public_key().key_id(&key_id).send().await.context("GetPublicKey 失败")?;
    let spki_der = pk_out
        .public_key()
        .ok_or_else(|| anyhow!("GetPublicKey 无 public_key"))?
        .as_ref()
        .to_vec();

    // ---- 6. 写出 artifact 供 PyJWT 独立验签 ----
    std::fs::write("/tmp/spike_jwt.txt", &jwt)?;
    std::fs::write("/tmp/spike_pubkey.der", &spki_der)?;
    println!("JWT 写入 /tmp/spike_jwt.txt;公钥(SPKI DER)写入 /tmp/spike_pubkey.der");

    // ---- 7. KMS Sign 延迟实测(P50/P95/P99)----
    println!("\n实测 KMS Sign 延迟({LATENCY_SAMPLES} 次)…");
    let mut lat_ms: Vec<f64> = Vec::with_capacity(LATENCY_SAMPLES);
    for _ in 0..LATENCY_SAMPLES {
        let t0 = Instant::now();
        let _ = kms
            .sign()
            .key_id(&key_id)
            .message(Blob::new(signing_input.clone().into_bytes()))
            .message_type(MessageType::Raw)
            .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
            .send()
            .await?;
        lat_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    lat_ms.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| lat_ms[((p * (lat_ms.len() as f64 - 1.0)).round() as usize).min(lat_ms.len() - 1)];
    println!(
        "KMS Sign 延迟 ms: min={:.1} P50={:.1} P95={:.1} P99={:.1} max={:.1}",
        lat_ms[0],
        pct(0.50),
        pct(0.95),
        pct(0.99),
        lat_ms[lat_ms.len() - 1]
    );

    println!("\n下一步:python3 spike/kms-es256/verify.py 用 PyJWT 独立验签 /tmp/spike_jwt.txt");
    println!("复用此 key 重跑: cargo run -- --reuse-key {key_id}");
    println!("清理: cargo run -- --cleanup {key_id}");
    Ok(())
}
