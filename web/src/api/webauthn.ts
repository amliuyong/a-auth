// WebAuthn base64url ↔ ArrayBuffer marshaling(spec 003 §3.9,C9.4)。
//
// 后端(passkey_flow.rs)全用 **base64url 无填充**(Rust `URL_SAFE_NO_PAD`)交换二进制字段:
// challenge / credentialId(rawId)/ clientDataJSON / attestationObject / authenticatorData / signature。
// 浏览器 `navigator.credentials` 收发 ArrayBuffer,故须在此逐字节对齐转换。
//
// ⚠️ 仅做字节↔字符串转换,**不解释内容**:clientDataJSON 是 UTF-8 JSON、attestationObject 是 CBOR、
// authenticatorData/signature 是原始字节——前端一律当**不透明字节**从 ArrayBuffer 直接编码回后端,
// 由后端(authn::passkey)解析验证。前端不解 CBOR、不改字节(评审 codex M2:勿对 clientDataJSON 先
// TextDecoder 再 base64,会破坏字节一致性)。
//
// ⚠️⚠️ **只用于 base64url ↔ ArrayBuffer(二进制字段)**:输入 MUST 是合法 base64url([A-Za-z0-9_-])
// 或 ArrayBuffer。**不可**用于任意 UTF-8 文本编码——`atob`/`btoa` 是 Latin-1,遇多字节字符乱码。
// 尤其:WebAuthn `user.id` 的来源(后端 `user_id` 明文串如 `user:alice@example.com`)MUST 走
// `new TextEncoder().encode(user_id)`,**不走** `b64urlToBuf`(评审 codex Blocker1:文本非 base64url)。
// rp_id 亦是明文串,直接作 `rp.id` 字符串(不编码)。

/** ArrayBuffer / TypedArray → base64url(无填充)。 */
export function bufToB64url(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  // 按字节码点构 binary string(不经 UTF-8;btoa 只接受 Latin-1 码点 0–255)。
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  // 标准 base64 → base64url:+/→-_,去尾部 =。
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url(无填充,亦容忍带填充/标准 b64)→ ArrayBuffer。 */
export function b64urlToBuf(s: string): ArrayBuffer {
  // base64url → 标准 base64:-_→+/,补齐 = 到 4 的倍数(atob 要求填充)。
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/** 浏览器是否支持 WebAuthn(安全上下文 + PublicKeyCredential 存在)。不支持时前端应隐藏 passkey 入口。 */
export function webauthnSupported(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.isSecureContext === true &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator.credentials?.create === 'function' &&
    typeof navigator.credentials?.get === 'function'
  );
}
