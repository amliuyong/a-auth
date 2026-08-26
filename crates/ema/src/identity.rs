use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

pub fn derive_replay_key(
    server_secret: &[u8],
    agent_auth_tenant: &str,
    trusted_issuer: &str,
    issuer_tenant: Option<&str>,
    jwt_id: &str,
) -> String {
    let digest = derive(
        server_secret,
        b"ema-replay:v1",
        agent_auth_tenant,
        trusted_issuer,
        issuer_tenant,
        jwt_id,
    );
    format!("ema-replay:v1:{}", URL_SAFE_NO_PAD.encode(digest))
}

pub fn derive_enterprise_user_id(
    server_secret: &[u8],
    agent_auth_tenant: &str,
    trusted_issuer: &str,
    issuer_tenant: Option<&str>,
    subject: &str,
) -> String {
    let digest = derive(
        server_secret,
        b"ema-user-id:v1",
        agent_auth_tenant,
        trusted_issuer,
        issuer_tenant,
        subject,
    );
    format!("user:ema:v1:{}", URL_SAFE_NO_PAD.encode(digest))
}

fn derive(
    server_secret: &[u8],
    domain: &[u8],
    agent_auth_tenant: &str,
    trusted_issuer: &str,
    issuer_tenant: Option<&str>,
    final_component: &str,
) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(domain);
    update_framed(&mut mac, agent_auth_tenant.as_bytes());
    update_framed(&mut mac, trusted_issuer.as_bytes());
    match issuer_tenant {
        Some(issuer_tenant) => {
            mac.update(&[1]);
            update_framed(&mut mac, issuer_tenant.as_bytes());
        }
        None => mac.update(&[0]),
    }
    update_framed(&mut mac, final_component.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn update_framed(mac: &mut HmacSha256, value: &[u8]) {
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
}
