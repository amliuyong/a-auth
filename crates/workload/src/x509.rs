//! X.509-SVID(SPIFFE)证书主体提取 —— spec 012 §1.4 X.509-mTLS(C5.7,P3)。
//!
//! **职责边界(评审关键)**:mTLS 握手时 **API Gateway 已对客户端证书验链到 truststore 的 CA**——
//! 只有验链通过的连接才到 Lambda。本模块**不做链验证**(信任根是 truststore),只从**已验链的叶子证书**
//! 里**确定性提取唯一 SPIFFE ID**(SAN 的 URI 项)供信任绑定匹配。fail-closed:任何歧义(0/多 URI SAN、
//! 非 spiffe://、畸形 trust domain)一律拒——SAN 多 URI 是冒充入口(评审 H2)。
//!
//! **主体在 SAN URI、不在 subject DN**:X.509-SVID 规范(SPIFFE)——SPIFFE ID 编码在
//! Subject Alternative Name 的 `uniformResourceIdentifier` 项;SVID 的 subject DN 常空/无意义,不参与信任判定。

use x509_cert::der::DecodePem;
use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};
use x509_cert::Certificate;

/// 从叶子证书提取的 SPIFFE 主体 + 证书有效期(供 HTTP 层纵深复核 validity)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509SvidSubject {
    /// 唯一 SPIFFE ID(`spiffe://<trust-domain>/<path>`,来自 SAN 的唯一 URI 项)。
    pub spiffe_id: String,
    /// 证书 notBefore(Unix 秒;纵深 validity 复核用)。
    pub not_before: i64,
    /// 证书 notAfter(Unix 秒)。
    pub not_after: i64,
}

/// 提取失败原因(全部 fail-closed;无一放行歧义证书)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X509Error {
    /// PEM 解析失败 / 非法证书 DER。
    ParseFailed,
    /// 证书无 SubjectAltName 扩展。
    NoSan,
    /// SAN 里 URI 项数 != 1(0 = 无 SPIFFE 主体;>1 = 冒充歧义,评审 H2)。
    UriSanCount(usize),
    /// 唯一 URI 不是 `spiffe://` scheme。
    NotSpiffeUri,
}

/// 从**已验链的叶子证书 PEM** 提取唯一 SPIFFE ID + validity(spec 012 §1.4 / C5.7)。
///
/// 规则(fail-closed):
/// - PEM 解析为单张 X.509 证书(API Gateway 传的是叶子 clientCertPem)。
/// - 取 SubjectAltName 扩展;无 → `NoSan`。
/// - **统计 URI 项**(`uniformResourceIdentifier`):恰好 1 个否则拒(0=`UriSanCount(0)`;>1=`UriSanCount(n)`
///   即便其中只有一个是 spiffe://——多 URI 有冒充歧义)。DNS/IP/rfc822 等**非 URI** GeneralName 可共存、不计数。
/// - 唯一 URI MUST `spiffe://` 前缀,否则 `NotSpiffeUri`。
/// - **不做链验证**(API Gateway 已验);trust domain 合法性由调用方 `spiffe_trust_domain` 再校(畸形拒)。
pub fn spiffe_id_from_leaf_pem(pem: &str) -> Result<X509SvidSubject, X509Error> {
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| X509Error::ParseFailed)?;
    let tbs = &cert.tbs_certificate;

    // SubjectAltName 扩展(OID 2.5.29.17)。get 对同 OID 出现多次会 Err → 视作解析失败(fail-closed)。
    let san = match tbs.get::<SubjectAltName>() {
        Ok(Some((_critical, san))) => san,
        Ok(None) => return Err(X509Error::NoSan),
        Err(_) => return Err(X509Error::ParseFailed),
    };

    // 只统计 URI 项(uniformResourceIdentifier);其余 GeneralName 变体(DNS/IP/rfc822/...)不参与。
    let uris: Vec<String> = san
        .0
        .iter()
        .filter_map(|gn| match gn {
            GeneralName::UniformResourceIdentifier(ia5) => Some(ia5.as_str().to_string()),
            _ => None,
        })
        .collect();

    // 恰好一个 URI SAN(0=无主体;>1=冒充歧义,评审 H2)。
    if uris.len() != 1 {
        return Err(X509Error::UriSanCount(uris.len()));
    }
    let uri = uris.into_iter().next().unwrap();
    if !uri.starts_with("spiffe://") {
        return Err(X509Error::NotSpiffeUri);
    }

    Ok(X509SvidSubject {
        spiffe_id: uri,
        not_before: time_to_unix(&tbs.validity.not_before),
        not_after: time_to_unix(&tbs.validity.not_after),
    })
}

/// x509_cert Time → Unix 秒(UTCTime/GeneralizedTime 皆有 `to_unix_duration`)。
fn time_to_unix(t: &x509_cert::time::Time) -> i64 {
    t.to_unix_duration().as_secs() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_cert::builder::{Builder, CertificateBuilder, Profile};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Validity;

    use p256::ecdsa::{DerSignature, SigningKey};
    use std::str::FromStr;
    use std::time::Duration;
    use x509_cert::der::asn1::Ia5String;
    use x509_cert::der::{pem::LineEnding, EncodePem};
    use x509_cert::ext::pkix::name::GeneralName;
    use x509_cert::ext::pkix::SubjectAltName;

    // 用 p256(既有依赖同族)自签一张带指定 SAN 的叶子证书 PEM(测试造样本;不做链)。
    fn make_cert_pem(sans: &[GeneralName]) -> String {
        let signer = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = signer.verifying_key();
        let spki = SubjectPublicKeyInfoOwned::from_key(*vk).unwrap();
        let profile = Profile::Leaf {
            issuer: Name::from_str("CN=test-ca").unwrap(),
            enable_key_agreement: false,
            enable_key_encipherment: false,
        };
        let mut builder = CertificateBuilder::new(
            profile,
            SerialNumber::from(1u32),
            Validity::from_now(Duration::from_secs(3600)).unwrap(),
            Name::from_str("CN=svid").unwrap(),
            spki,
            &signer,
        )
        .unwrap();
        if !sans.is_empty() {
            builder
                .add_extension(&SubjectAltName(sans.to_vec()))
                .unwrap();
        }
        let cert: x509_cert::Certificate =
            <CertificateBuilder<_> as Builder>::build::<DerSignature>(builder).unwrap();
        cert.to_pem(LineEnding::LF).unwrap()
    }

    fn uri(u: &str) -> GeneralName {
        GeneralName::UniformResourceIdentifier(Ia5String::new(u).unwrap())
    }
    fn dns(d: &str) -> GeneralName {
        GeneralName::DnsName(Ia5String::new(d).unwrap())
    }

    #[test]
    fn single_spiffe_uri_san_happy() {
        let pem = make_cert_pem(&[uri("spiffe://acme.example/agent/kb")]);
        let s = spiffe_id_from_leaf_pem(&pem).unwrap();
        assert_eq!(s.spiffe_id, "spiffe://acme.example/agent/kb");
        assert!(s.not_after > s.not_before);
    }

    #[test]
    fn dns_san_coexists_but_not_counted() {
        // 一个 spiffe URI + 一个 DNS SAN → 仍合法(DNS 不计入 URI 计数)。
        let pem = make_cert_pem(&[uri("spiffe://acme.example/agent/x"), dns("host.example")]);
        assert_eq!(
            spiffe_id_from_leaf_pem(&pem).unwrap().spiffe_id,
            "spiffe://acme.example/agent/x"
        );
    }

    #[test]
    fn no_san_rejected() {
        let pem = make_cert_pem(&[]);
        assert_eq!(spiffe_id_from_leaf_pem(&pem), Err(X509Error::NoSan));
    }

    #[test]
    fn zero_uri_san_rejected() {
        // 只有 DNS SAN,无 URI → UriSanCount(0)。
        let pem = make_cert_pem(&[dns("host.example")]);
        assert_eq!(
            spiffe_id_from_leaf_pem(&pem),
            Err(X509Error::UriSanCount(0))
        );
    }

    #[test]
    fn two_uri_san_rejected_even_if_one_spiffe() {
        // 一个 spiffe + 一个 http URI → 冒充歧义,拒(评审 H2)。
        let pem = make_cert_pem(&[
            uri("spiffe://acme.example/agent/kb"),
            uri("https://evil.example/"),
        ]);
        assert_eq!(
            spiffe_id_from_leaf_pem(&pem),
            Err(X509Error::UriSanCount(2))
        );
    }

    #[test]
    fn non_spiffe_uri_rejected() {
        let pem = make_cert_pem(&[uri("https://acme.example/agent")]);
        assert_eq!(spiffe_id_from_leaf_pem(&pem), Err(X509Error::NotSpiffeUri));
    }

    #[test]
    fn malformed_pem_rejected() {
        assert_eq!(
            spiffe_id_from_leaf_pem("not a pem"),
            Err(X509Error::ParseFailed)
        );
    }
}
