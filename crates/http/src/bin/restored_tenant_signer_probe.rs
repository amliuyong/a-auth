//! Read-only disaster-recovery probe for a restored tenant-key registry.

#[cfg(feature = "aws")]
use agent_auth_http::ports::Signer;
#[cfg(feature = "aws")]
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

#[cfg(feature = "aws")]
struct ProbeArgs {
    table: String,
    tenant: String,
    issuer: String,
}

#[cfg(feature = "aws")]
fn parse_args(mut args: impl Iterator<Item = String>) -> Result<ProbeArgs, String> {
    let table = args
        .next()
        .ok_or_else(|| "restored tenant-key table is required".to_string())?;
    let tenant = args
        .next()
        .ok_or_else(|| "tenant id is required".to_string())?;
    let issuer = args
        .next()
        .ok_or_else(|| "issuer is required".to_string())?;
    if args.next().is_some() {
        return Err("unexpected extra argument".to_string());
    }
    if table.is_empty()
        || tenant.is_empty()
        || !tenant
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("invalid restored table or tenant id".to_string());
    }
    let issuer_url =
        reqwest::Url::parse(&issuer).map_err(|_| "issuer must be an HTTPS origin".to_string())?;
    if issuer_url.scheme() != "https"
        || issuer_url.host_str().is_none()
        || issuer_url.username() != ""
        || issuer_url.password().is_some()
        || issuer_url.path() != "/"
        || issuer_url.query().is_some()
        || issuer_url.fragment().is_some()
        || issuer.ends_with('/')
    {
        return Err("issuer must be an HTTPS origin without a trailing slash".to_string());
    }
    Ok(ProbeArgs {
        table,
        tenant,
        issuer,
    })
}

#[cfg(feature = "aws")]
fn signing_input(
    algorithm: &str,
    token_type: &str,
    kid: &str,
    issuer: &str,
    tenant: &str,
    now: i64,
) -> Result<String, String> {
    let header = serde_json::json!({
        "alg": algorithm,
        "typ": token_type,
        "kid": kid,
    });
    let claims = serde_json::json!({
        "iss": issuer,
        "sub": format!("dr-probe:{tenant}"),
        "aud": format!("{issuer}/dr-probe"),
        "iat": now,
        "exp": now + 300,
        "jti": format!("dr-probe-{tenant}-{now}"),
    });
    let header = serde_json::to_vec(&header).map_err(|error| error.to_string())?;
    let claims = serde_json::to_vec(&claims).map_err(|error| error.to_string())?;
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(claims)
    ))
}

#[cfg(feature = "aws")]
async fn run() -> Result<(), String> {
    let ProbeArgs {
        table,
        tenant,
        issuer,
    } = parse_args(std::env::args().skip(1))?;

    let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let registry = agent_auth_http::adapters::aws::DynamoTenantKeyRegistry::new(
        aws_sdk_dynamodb::Client::new(&config),
        table,
    );
    let service = agent_auth_http::tenant_keys::TenantKeyService::dynamo_readonly(
        registry,
        aws_sdk_kms::Client::new(&config),
    );
    let signer = service
        .resolve(&tenant)
        .await
        .map_err(|error| format!("restored tenant signer resolution failed: {error:?}"))?;

    let ec_kid = signer
        .active_kid()
        .await
        .map_err(|error| format!("active EC key resolution failed: {error:?}"))?;
    let ec_keys = signer
        .public_jwks()
        .await
        .map_err(|error| format!("restored EC JWKS resolution failed: {error:?}"))?;
    let ec_jwk = ec_keys
        .iter()
        .find(|key| key.kid == ec_kid)
        .ok_or_else(|| "active EC key is absent from restored published JWKS".to_string())?;

    let rsa_kid = signer
        .active_rsa_kid()
        .await
        .map_err(|error| format!("active RSA key resolution failed: {error:?}"))?;
    let rsa_keys = signer
        .public_rsa_jwks()
        .await
        .map_err(|error| format!("restored RSA JWKS resolution failed: {error:?}"))?;
    let rsa_jwk = rsa_keys
        .iter()
        .find(|key| key.kid == rsa_kid)
        .ok_or_else(|| "active RSA key is absent from restored published JWKS".to_string())?;

    let now = agent_auth_http::current_unix_secs();
    let ec_input = signing_input("ES256", "at+jwt", &ec_kid, &issuer, &tenant, now)?;
    let ec_signature = signer
        .sign_es256(ec_input.as_bytes())
        .await
        .map_err(|error| format!("restored ES256 signing failed: {error:?}"))?;
    let rsa_input = signing_input("RS256", "JWT", &rsa_kid, &issuer, &tenant, now)?;
    let (signed_rsa_kid, rsa_signature) = signer
        .sign_rs256(rsa_input.as_bytes())
        .await
        .map_err(|error| format!("restored RS256 signing failed: {error:?}"))?;
    if signed_rsa_kid != rsa_kid {
        return Err("restored RSA signer used a key other than active_rsa_kid".to_string());
    }

    let output = serde_json::json!({
        "tenant": tenant,
        "issuer": issuer,
        "ec": {
            "signing_input": ec_input,
            "signature": URL_SAFE_NO_PAD.encode(ec_signature),
            "jwk": {
                "kty": ec_jwk.kty,
                "crv": ec_jwk.crv,
                "x": ec_jwk.x,
                "y": ec_jwk.y,
                "kid": ec_jwk.kid,
                "alg": ec_jwk.alg,
                "use": ec_jwk.r#use,
            },
        },
        "rsa": {
            "signing_input": rsa_input,
            "signature": URL_SAFE_NO_PAD.encode(rsa_signature),
            "jwk": {
                "kty": rsa_jwk.kty,
                "n": rsa_jwk.n,
                "e": rsa_jwk.e,
                "kid": rsa_jwk.kid,
                "alg": rsa_jwk.alg,
                "use": rsa_jwk.r#use,
            },
        },
    });
    println!(
        "{}",
        serde_json::to_string(&output).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(all(test, feature = "aws"))]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> std::vec::IntoIter<String> {
        values
            .iter()
            .map(|value| (*value).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn arguments_require_a_table_safe_tenant_and_https_origin() {
        let parsed = parse_args(args(&[
            "RestoredTenantKeys",
            "tenant_1.example",
            "https://tenant.example.com",
        ]))
        .unwrap();
        assert_eq!(parsed.table, "RestoredTenantKeys");
        assert_eq!(parsed.tenant, "tenant_1.example");
        assert_eq!(parsed.issuer, "https://tenant.example.com");

        for invalid in [
            vec!["", "t1", "https://t1.example.com"],
            vec!["RestoredTenantKeys", "bad tenant", "https://t1.example.com"],
            vec!["RestoredTenantKeys", "t1", "http://t1.example.com"],
            vec!["RestoredTenantKeys", "t1", "https://t1.example.com/"],
            vec!["RestoredTenantKeys", "t1", "https://t1.example.com/path"],
            vec![
                "RestoredTenantKeys",
                "t1",
                "https://t1.example.com",
                "extra",
            ],
        ] {
            assert!(parse_args(args(&invalid)).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn signing_input_binds_key_tenant_and_issuer_claims() {
        let input = signing_input(
            "ES256",
            "at+jwt",
            "kid-1",
            "https://t1.example.com",
            "t1",
            1_700_000_000,
        )
        .unwrap();
        let parts: Vec<_> = input.split('.').collect();
        assert_eq!(parts.len(), 2);
        let header: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        let claims: serde_json::Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(
            header,
            serde_json::json!({"alg":"ES256","typ":"at+jwt","kid":"kid-1"})
        );
        assert_eq!(claims["iss"], "https://t1.example.com");
        assert_eq!(claims["sub"], "dr-probe:t1");
        assert_eq!(claims["aud"], "https://t1.example.com/dr-probe");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(claims["exp"], 1_700_000_300);
        assert_eq!(claims["jti"], "dr-probe-t1-1700000000");
    }
}

#[cfg(feature = "aws")]
#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("RESTORED_TENANT_SIGNER_PROBE_FAILED: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "aws"))]
fn main() {
    eprintln!("agent-auth-restored-tenant-signer-probe requires --features aws");
    std::process::exit(1);
}
