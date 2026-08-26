//! C10.3 — KMS ECDSA 签名 DER ↔ JOSE 格式转换。
//!
//! AWS KMS `Sign`(ECDSA_SHA_256)返回 **ASN.1 DER** 编码的 `SEQUENCE { INTEGER r, INTEGER s }`,
//! 而 JOSE ES256(RFC 7518 §3.4)要求**定长裸拼接** `r‖s`,各 32 字节、大端、左侧补零。
//! DER 的 INTEGER 是**变长**且对最高位为 1 的正数会**前置 0x00** 防被读成负数,
//! 也可能因高位字节为 0 而**短于** 32 字节——两侧都要归一化到恰好 32 字节。
//! 该转换漏了或写反是接第三方 RS 时"签名忽好忽坏"的经典坑(见 DESIGN §8 DER↔JOSE 陷阱)。
//!
//! 本模块纯字节解析、零 AWS 依赖:上层把 KMS 返回的 DER 签名喂进来,得到 JOSE 的 64 字节。
//! 决策真相源:docs/DESIGN §8;docs/CONFORMANCE C10.3。

/// P-256 的每个标量(r/s)在 JOSE 中的定长字节数。ES256 = 2 × 32 = 64 字节签名。
pub const P256_COORD_LEN: usize = 32;
/// JOSE ES256 签名总长度(`r‖s`)。
pub const ES256_JOSE_SIG_LEN: usize = P256_COORD_LEN * 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DerError {
    /// 顶层不是 DER SEQUENCE(tag 0x30)。
    NotSequence,
    /// 长度字段非法 / 与实际内容不符 / 使用了不支持的长格式。
    BadLength,
    /// 成员不是 INTEGER(tag 0x02)。
    NotInteger,
    /// r 或 s 规范化后仍超过 32 字节(非 P-256 签名 / 损坏)。
    IntegerTooLong,
    /// 尾部有多余字节(SEQUENCE 声明长度之外还有数据)。
    TrailingData,
    /// 数据过短、在预期位置耗尽。
    Truncated,
    /// INTEGER 编码非法(空内容,或多余前导 0x00 / 负数)。
    MalformedInteger,
}

/// 读一个 DER 长度字节(仅支持短格式 0x00–0x7F,ES256 的 r/s ≤ 33 字节足够)。
/// 返回 (长度值, 消耗的字节数)。长格式(0x80|n)对 P-256 签名不会出现,视为 BadLength。
fn read_short_len(bytes: &[u8], pos: usize) -> Result<(usize, usize), DerError> {
    let b = *bytes.get(pos).ok_or(DerError::Truncated)?;
    if b & 0x80 == 0 {
        Ok((b as usize, 1))
    } else {
        // 长格式不该出现在 P-256 ECDSA 签名里(总长 < 128)。
        Err(DerError::BadLength)
    }
}

/// 解析一个 DER INTEGER,返回其**去掉合法前导 0x00 后**的大端字节切片(即数值本身的最小编码)。
/// 校验 DER INTEGER 规范:非空;不得有多余前导 0x00(除非紧跟高位为 1 的字节);不得为负(最高位为 1)。
fn parse_der_integer(bytes: &[u8], pos: usize) -> Result<(&[u8], usize), DerError> {
    let tag = *bytes.get(pos).ok_or(DerError::Truncated)?;
    if tag != 0x02 {
        return Err(DerError::NotInteger);
    }
    let (len, len_bytes) = read_short_len(bytes, pos + 1)?;
    if len == 0 {
        return Err(DerError::MalformedInteger); // INTEGER 至少 1 字节
    }
    let content_start = pos + 1 + len_bytes;
    let content_end = content_start.checked_add(len).ok_or(DerError::BadLength)?;
    let content = bytes
        .get(content_start..content_end)
        .ok_or(DerError::Truncated)?;

    // DER INTEGER 规范校验:
    // - 负数(最高位为 1 且未前置 0x00)不该出现在 ECDSA r/s(它们是正整数)。
    // - 多余前导 0x00:仅当去掉后下一字节最高位仍为 0 才算多余(否则 0x00 是防负号的必要前导)。
    if content[0] & 0x80 != 0 {
        return Err(DerError::MalformedInteger); // 负整数
    }
    if content.len() > 1 && content[0] == 0x00 && content[1] & 0x80 == 0 {
        return Err(DerError::MalformedInteger); // 非最小编码(多余前导 0)
    }

    // 去掉唯一的合法前导 0x00(用于防负号的那一个),得到数值最小表示。
    let magnitude = if content[0] == 0x00 {
        &content[1..]
    } else {
        content
    };
    Ok((magnitude, content_end))
}

/// 把一个大端标量(去零后的最小表示)左侧补零到定长 32 字节。超长即错。
fn left_pad_fixed(magnitude: &[u8]) -> Result<[u8; P256_COORD_LEN], DerError> {
    if magnitude.len() > P256_COORD_LEN {
        return Err(DerError::IntegerTooLong);
    }
    let mut out = [0u8; P256_COORD_LEN];
    out[P256_COORD_LEN - magnitude.len()..].copy_from_slice(magnitude);
    Ok(out)
}

/// **DER → JOSE**:把 KMS 返回的 DER ECDSA 签名转成 JOSE ES256 的 64 字节 `r‖s`。
pub fn der_to_jose(der: &[u8]) -> Result<[u8; ES256_JOSE_SIG_LEN], DerError> {
    // 顶层 SEQUENCE。
    if der.first().copied() != Some(0x30) {
        return Err(DerError::NotSequence);
    }
    let (seq_len, seq_len_bytes) = read_short_len(der, 1)?;
    let body_start = 1 + seq_len_bytes;
    let body_end = body_start.checked_add(seq_len).ok_or(DerError::BadLength)?;
    if body_end != der.len() {
        // SEQUENCE 声明长度必须正好覆盖余下全部字节。
        return Err(if body_end < der.len() {
            DerError::TrailingData
        } else {
            DerError::Truncated
        });
    }

    let (r, after_r) = parse_der_integer(der, body_start)?;
    let (s, after_s) = parse_der_integer(der, after_r)?;
    if after_s != body_end {
        return Err(DerError::TrailingData); // r、s 之外还有内容
    }

    let r_fixed = left_pad_fixed(r)?;
    let s_fixed = left_pad_fixed(s)?;

    let mut jose = [0u8; ES256_JOSE_SIG_LEN];
    jose[..P256_COORD_LEN].copy_from_slice(&r_fixed);
    jose[P256_COORD_LEN..].copy_from_slice(&s_fixed);
    Ok(jose)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoseError {
    /// 输入不是 64 字节(不是合法 ES256 JOSE 签名)。
    BadLength,
}

/// 把一个标量的定长 32 字节编码为 DER INTEGER 内容(去前导 0、必要时前置 0x00 防负号)。
fn scalar_to_der_integer_content(coord: &[u8; P256_COORD_LEN]) -> Vec<u8> {
    // 去掉前导 0(但至少保留 1 字节)。
    let mut start = 0;
    while start < P256_COORD_LEN - 1 && coord[start] == 0x00 {
        start += 1;
    }
    let trimmed = &coord[start..];
    // 若最高位为 1,前置 0x00 防被读成负数。
    if trimmed[0] & 0x80 != 0 {
        let mut v = Vec::with_capacity(trimmed.len() + 1);
        v.push(0x00);
        v.extend_from_slice(trimmed);
        v
    } else {
        trimmed.to_vec()
    }
}

/// **JOSE → DER**:把 JOSE ES256 的 64 字节 `r‖s` 转回 DER(对称转换,便于测试往返 / 少数需 DER 的路径)。
pub fn jose_to_der(jose: &[u8]) -> Result<Vec<u8>, JoseError> {
    if jose.len() != ES256_JOSE_SIG_LEN {
        return Err(JoseError::BadLength);
    }
    let mut r = [0u8; P256_COORD_LEN];
    let mut s = [0u8; P256_COORD_LEN];
    r.copy_from_slice(&jose[..P256_COORD_LEN]);
    s.copy_from_slice(&jose[P256_COORD_LEN..]);

    let r_int = scalar_to_der_integer_content(&r);
    let s_int = scalar_to_der_integer_content(&s);

    // 组装:SEQUENCE { INTEGER r, INTEGER s }。r/s 内容长度均 < 128,用短格式长度。
    let mut body = Vec::with_capacity(r_int.len() + s_int.len() + 4);
    body.push(0x02);
    body.push(r_int.len() as u8);
    body.extend_from_slice(&r_int);
    body.push(0x02);
    body.push(s_int.len() as u8);
    body.extend_from_slice(&s_int);

    let mut der = Vec::with_capacity(body.len() + 2);
    der.push(0x30);
    der.push(body.len() as u8); // body 长度 < 128(2×(2+33)=70),短格式安全
    der.extend_from_slice(&body);
    Ok(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    // 构造一个 DER SEQUENCE{INTEGER r, INTEGER s},r/s 为给定的最小编码内容(含防负号 0x00)。
    fn der(r_content: &[u8], s_content: &[u8]) -> Vec<u8> {
        let mut body = vec![0x02, r_content.len() as u8];
        body.extend_from_slice(r_content);
        body.push(0x02);
        body.push(s_content.len() as u8);
        body.extend_from_slice(s_content);
        let mut out = vec![0x30, body.len() as u8];
        out.extend_from_slice(&body);
        out
    }

    // C10.3:标准 32 字节 r/s(无前导 0)→ 直接拼成 64 字节。
    #[test]
    fn der_to_jose_full_width() {
        let r = [0x11u8; 32];
        let s = [0x22u8; 32];
        let out = der_to_jose(&der(&r, &s)).unwrap();
        assert_eq!(&out[..32], &r);
        assert_eq!(&out[32..], &s);
    }

    // C10.3:r 高位为 1 → DER 前置 0x00(33 字节),转换须剥掉 0x00 回到 32 字节。
    #[test]
    fn der_to_jose_strips_sign_padding() {
        let mut r33 = vec![0x00u8];
        r33.extend_from_slice(&[0x80u8; 32]); // 高位 1,DER 必带前导 0x00
        let s = [0x01u8; 32];
        let out = der_to_jose(&der(&r33, &s)).unwrap();
        assert_eq!(&out[..32], &[0x80u8; 32]); // 0x00 被剥掉
        assert_eq!(&out[32..], &s);
    }

    // C10.3:r 短于 32 字节(高位字节为 0)→ JOSE 须左侧补零到 32。
    #[test]
    fn der_to_jose_left_pads_short_integer() {
        let r_short = [0x07u8]; // 数值 7,DER 里 1 字节
        let s = [0x02u8; 32];
        let out = der_to_jose(&der(&r_short, &s)).unwrap();
        let mut expect_r = [0u8; 32];
        expect_r[31] = 0x07;
        assert_eq!(&out[..32], &expect_r);
        assert_eq!(&out[32..], &s);
    }

    // 往返:JOSE → DER → JOSE 稳定(含高位为 1 的补零场景)。
    #[test]
    fn jose_der_roundtrip() {
        let mut jose = [0u8; 64];
        jose[..32].copy_from_slice(&[0x80u8; 32]); // r 高位 1
        jose[32..].copy_from_slice(&[0x03u8; 32]);
        let der = jose_to_der(&jose).unwrap();
        // DER 里 r 应带前置 0x00(高位 1)。
        assert_eq!(der[0], 0x30);
        let back = der_to_jose(&der).unwrap();
        assert_eq!(back, jose);
    }

    // 往返:短标量(前导 0)也能稳定往返。
    #[test]
    fn jose_der_roundtrip_short_scalar() {
        let mut jose = [0u8; 64];
        jose[31] = 0x09; // r = 9
        jose[63] = 0x01; // s = 1
        let der = jose_to_der(&jose).unwrap();
        let back = der_to_jose(&der).unwrap();
        assert_eq!(back, jose);
    }

    // 顶层不是 SEQUENCE → 拒。
    #[test]
    fn rejects_non_sequence() {
        assert_eq!(der_to_jose(&[0x02, 0x01, 0x00]), Err(DerError::NotSequence));
    }

    // 成员不是 INTEGER → 拒。
    #[test]
    fn rejects_non_integer_member() {
        // SEQUENCE { OCTET STRING ... } 而非 INTEGER
        let bad = vec![0x30, 0x03, 0x04, 0x01, 0x00];
        assert_eq!(der_to_jose(&bad), Err(DerError::NotInteger));
    }

    // SEQUENCE 尾部多余字节 → TrailingData。
    #[test]
    fn rejects_trailing_data() {
        let mut ok = der(&[0x01u8; 32], &[0x02u8; 32]);
        ok.push(0xFF); // 多一个字节
        assert_eq!(der_to_jose(&ok), Err(DerError::TrailingData));
    }

    // 负数 INTEGER(最高位 1 未前置 0x00)→ MalformedInteger。
    #[test]
    fn rejects_negative_integer() {
        let neg = der(&[0x80u8, 0x01], &[0x02u8; 32]); // 0x80.. 高位 1、无前导 0
        assert_eq!(der_to_jose(&neg), Err(DerError::MalformedInteger));
    }

    // 非最小编码(多余前导 0x00)→ MalformedInteger。
    #[test]
    fn rejects_non_minimal_integer() {
        let nonmin = der(&[0x00u8, 0x00, 0x01], &[0x02u8; 32]); // 多一个 0x00
        assert_eq!(der_to_jose(&nonmin), Err(DerError::MalformedInteger));
    }

    // r/s 超过 32 字节(非 P-256)→ IntegerTooLong。
    #[test]
    fn rejects_oversized_integer() {
        let big = [0x01u8; 33]; // 33 字节且高位为 0 → 合法 DER 但对 P-256 过长
        assert_eq!(
            der_to_jose(&der(&big, &[0x02u8; 32])),
            Err(DerError::IntegerTooLong)
        );
    }

    // 截断输入 → 不 panic、返回错误。
    #[test]
    fn truncated_no_panic() {
        assert!(der_to_jose(&[0x30, 0x40, 0x02, 0x20]).is_err());
        assert!(der_to_jose(&[0x30]).is_err());
        assert!(der_to_jose(&[]).is_err());
    }

    // JOSE 长度非 64 → 拒。
    #[test]
    fn jose_bad_length_rejected() {
        assert_eq!(jose_to_der(&[0u8; 63]), Err(JoseError::BadLength));
        assert_eq!(jose_to_der(&[0u8; 65]), Err(JoseError::BadLength));
    }
}
