//! P-1 spike:Rust Lambda 冷启动实测 handler(DESIGN §10 语言选型 gate)。
//!
//! handler 做**真实签发路径的核心**:KMS ES256 Sign → `infra_core::signature::der_to_jose`
//! → 返回组装的 JWT。据此测 Rust Lambda 的冷启动(Init Duration)+ 签发延迟,
//! 与 Node 几百 ms 冷启动对比,拍板语言 / 是否需 provisioned concurrency(DESIGN §8/§10)。
//!
//! KMS key id 由环境变量 `SPIKE_ES256_KEY_ID` 注入(不硬编码、不进 repo)。

use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{MessageType, SigningAlgorithmSpec};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use lambda_runtime::{service_fn, Error, LambdaEvent};
use serde_json::{json, Value};

use agent_auth_infra_core::signature::der_to_jose;

async fn handler(kms: &aws_sdk_kms::Client, key_id: &str, _e: LambdaEvent<Value>) -> Result<Value, Error> {
    let header = json!({ "alg": "ES256", "typ": "at+jwt", "kid": "spike" });
    let payload = json!({
        "iss": "https://spike.example.com",
        "sub": "spike-lambda",
        "aud": ["https://mcp.rs.example.com"],
        "iat": 1_700_000_000,
        "exp": 1_700_000_300,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header)?),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload)?)
    );

    let out = kms
        .sign()
        .key_id(key_id)
        .message(Blob::new(signing_input.clone().into_bytes()))
        .message_type(MessageType::Raw)
        .signing_algorithm(SigningAlgorithmSpec::EcdsaSha256)
        .send()
        .await?;
    let der = out.signature().ok_or("no signature")?.as_ref().to_vec();
    let jose = der_to_jose(&der).map_err(|e| format!("der_to_jose: {e:?}"))?;
    let jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(jose));

    Ok(json!({ "jwt": jwt, "der_len": der.len() }))
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // 冷启动期:load AWS config + 建 KMS client(这些计入 Init Duration,是真实场景)。
    let conf = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let kms = aws_sdk_kms::Client::new(&conf);
    let key_id = std::env::var("SPIKE_ES256_KEY_ID").expect("SPIKE_ES256_KEY_ID env required");

    lambda_runtime::run(service_fn(|e| handler(&kms, &key_id, e))).await
}
