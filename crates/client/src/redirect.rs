//! C4.4a / C4.5 — redirect_uri 受控匹配(P0:exact + loopback,无通配)。
//!
//! 安全关键:授权码注入/劫持、开放重定向都在这层堵。canonicalize 规则的**权威定义在
//! DESIGN §3.3**,本模块按其实现:parse 成组件 → path 段解码一次(检查 `..`/`//`/`?`/`#`、
//! 解码后仍含 `%` 即拒、不递归)→ query 独立精确匹配 → userinfo 禁止 → host 小写化 →
//! 尾斜杠区分 → 逐组件精确相等。loopback 只认 IP 字面量(127.0.0.1 / [::1]),拒 localhost。
//!
//! 决策真相源:docs/DESIGN §3.3、docs/CONFORMANCE C4.4a/C4.5。

/// redirect 匹配模式(P0:exact + loopback;P1:prefix)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RedirectMode {
    /// 精确匹配:canonicalize 后逐组件严格相等。
    Exact,
    /// RFC 8252 loopback:仅 IP 字面量、端口任意、拒 localhost。
    Loopback,
    /// 受控前缀(C4.4b,P1):host 精确 + scheme **必须 https** + path 前缀固定 + **尾部单层通配**。
    /// 注册值 path MUST 以 `/*` 结尾;入站 path MUST = 前缀 + **单层**段(通配段禁 `/`、不吞 query)。
    /// ⚠️ **仅授 confidential + host allowlist** 属**调用层**门控(C4.6,handler 判 client_type/allowlist),
    /// 本纯匹配逻辑不做该门控——只实现"prefix 匹配是否成立"。
    Prefix,
}

/// 匹配结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MatchResult {
    Allow,
    /// 拒绝 + 原因(便于审计/测试断言)。
    Reject(&'static str),
}

/// URI 的关键组件(canonicalize 后)。本系统不接受 fragment(`#`)。
#[derive(Debug, Clone, PartialEq, Eq)]
struct Components {
    scheme: String, // 小写
    host: String,   // 小写(loopback 为 IP 字面量原样)
    port: Option<u16>,
    path: String,          // 解码校验后的 path(保留尾斜杠差异)
    query: Option<String>, // 规范化原始 query(不参与 path 解码);None = 无 query
}

/// 入口长度上限(DoS 硬化 + 合理边界)。redirect_uri 远小于此。
const MAX_URI_LEN: usize = 2048;

/// canonicalize + parse。返回 Err(原因) 表示该 URI 本身非法(穿越/双重编码/userinfo 等)。
fn canonicalize(uri: &str) -> Result<Components, &'static str> {
    // 长度上限(DoS 硬化)。
    if uri.len() > MAX_URI_LEN {
        return Err("redirect_uri 过长");
    }
    // 结构性拒绝(纵深防御,不只依赖"exact 不等即拒"):
    // 控制字符(< 0x20 或 = 0x7f,含 \0 空字节 / CR / LF)与反斜杠 `\` 一律拒——
    // 防下游把 canonicalized 值用于日志/落库/再重定向时的 CRLF 注入 / 路径混淆。
    if uri.bytes().any(|b| b < 0x20 || b == 0x7f || b == b'\\') {
        return Err("redirect_uri 含控制字符或反斜杠");
    }
    // 禁止 fragment。
    if uri.contains('#') {
        return Err("redirect_uri 不得含 fragment(#)");
    }
    let (scheme, rest, has_authority) = if let Some((scheme, rest)) = uri.split_once("://") {
        (scheme, rest, true)
    } else {
        let (scheme, rest) = uri.split_once(':').ok_or("缺 URI scheme")?;
        // RFC 8252 private-use redirects commonly use `com.example.app:/callback`.
        // HTTP(S) redirects still require an authority and host.
        if matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
            return Err("http/https redirect_uri 缺 authority");
        }
        if !rest.starts_with('/') {
            return Err("private-use redirect_uri path 必须以 / 开头");
        }
        (scheme, rest, false)
    };
    if scheme.is_empty()
        || !scheme.as_bytes()[0].is_ascii_alphabetic()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
    {
        return Err("scheme 非法");
    }
    let scheme = scheme.to_ascii_lowercase();

    // rest = authority[/path][?query], or /path[?query] for a private-use scheme.
    // query 采用**最严的原始字节相等**(不做 hex 大小写归一/参数排序等规范化);
    // 差异即不匹配→拒,fail-closed。§3.3 "规范化后精确匹配" 在本实现取最严解读。
    let (authority_path, query) = match rest.split_once('?') {
        Some((ap, q)) => (ap, Some(q.to_string())),
        None => (rest, None),
    };
    let (authority, path) = if has_authority {
        match authority_path.split_once('/') {
            Some((a, p)) => (a, format!("/{p}")),
            None => (authority_path, String::new()),
        }
    } else {
        ("", authority_path.to_string())
    };

    // userinfo 一律禁止(§3.3:防 user:pass@host 混淆)。
    if has_authority && authority.contains('@') {
        return Err("redirect_uri 禁止 userinfo(user:pass@host)");
    }

    // host[:port] —— 兼容 IPv6 字面量 [::1]:port。
    let (host, port) = if has_authority {
        let (host_raw, port) = split_host_port(authority)?;
        let host = host_raw.to_ascii_lowercase();
        if host.is_empty() {
            return Err("host 为空");
        }
        (host, port)
    } else {
        (String::new(), None)
    };

    // path 解码一次并检查穿越(§3.3)。
    let path = canonicalize_path(&path)?;

    Ok(Components {
        scheme,
        host,
        port,
        path,
        query,
    })
}

/// 拆 host 与 port,兼容 `[::1]:8080` / `127.0.0.1:8080` / `host`(无端口)。
fn split_host_port(authority: &str) -> Result<(String, Option<u16>), &'static str> {
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 字面量:`[addr]` 或 `[addr]:port`。
        let (addr, after) = rest.split_once(']').ok_or("IPv6 字面量缺 ]")?;
        let port = if after.is_empty() {
            None
        } else {
            let p = after.strip_prefix(':').ok_or("IPv6 端口格式错")?;
            Some(p.parse::<u16>().map_err(|_| "端口非法")?)
        };
        Ok((format!("[{addr}]"), port))
    } else {
        match authority.split_once(':') {
            Some((h, p)) => Ok((
                h.to_string(),
                Some(p.parse::<u16>().map_err(|_| "端口非法")?),
            )),
            None => Ok((authority.to_string(), None)),
        }
    }
}

/// path 解码一次 + 穿越检查(§3.3):解码一次后含 `..`/`//`/`?`/`#` 或仍含 `%` 即拒(不递归)。
fn canonicalize_path(path: &str) -> Result<String, &'static str> {
    if path.is_empty() {
        return Ok(String::new());
    }
    let decoded = percent_decode_once(path)?;
    // 解码后仍含 % = 双重编码,拒(不递归解码到不动点)。
    if decoded.contains('%') {
        return Err("path 双重编码(解码一次后仍含 %)");
    }
    if decoded.contains("..") {
        return Err("path 含 .. 穿越");
    }
    if decoded.contains("//") {
        return Err("path 含 // ");
    }
    if decoded.contains('?') || decoded.contains('#') {
        return Err("path 段含 ? 或 #");
    }
    Ok(decoded)
}

/// 百分号解码一次(遇非法 `%XX` 即报错,不静默保留——redirect 场景从严)。
fn percent_decode_once(s: &str) -> Result<String, &'static str> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            if i + 2 >= b.len() {
                return Err("path 含不完整百分号转义");
            }
            let h = hex(b[i + 1]).ok_or("path 百分号转义非法")?;
            let l = hex(b[i + 2]).ok_or("path 百分号转义非法")?;
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| "path 解码后非 UTF-8")
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn contains_encoded_prefix_structure(path: &str) -> bool {
    let bytes = path.as_bytes();
    let mut index = 0;
    while index + 2 < bytes.len() {
        if bytes[index] == b'%' {
            if let (Some(high), Some(low)) = (hex(bytes[index + 1]), hex(bytes[index + 2])) {
                if matches!(high * 16 + low, b'/' | b'*') {
                    return true;
                }
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    false
}

fn raw_authority_path(uri: &str) -> Option<&str> {
    let (_, rest) = uri.split_once("://")?;
    let authority_path = rest
        .split_once('?')
        .map_or(rest, |(without_query, _)| without_query);
    Some(
        authority_path
            .find('/')
            .map_or("", |path_start| &authority_path[path_start..]),
    )
}

fn is_ip_literal(host: &str) -> bool {
    host == "127.0.0.1" || host == "[::1]"
}

/// 匹配入站 `redirect_uri` 与注册值(C4.4a/C4.5)。
/// - `mode`:该注册项的匹配模式。
/// - `registered`:注册的 redirect_uri。
/// - `inbound`:入站 redirect_uri。
pub fn match_redirect(mode: &RedirectMode, registered: &str, inbound: &str) -> MatchResult {
    if matches!(mode, RedirectMode::Prefix) {
        let raw_path = match raw_authority_path(registered) {
            Some(path) => path,
            None => return MatchResult::Reject("注册值本身非法"),
        };
        if raw_path.ends_with('*') && !raw_path.ends_with("/*") {
            return MatchResult::Reject("prefix 通配只在末段(前缀须以 / 结尾,如 /path/*)");
        }
        if !raw_path.ends_with("/*") {
            return MatchResult::Reject("prefix 注册 path 必须以 /* 结尾(尾部单层通配)");
        }
        if contains_encoded_prefix_structure(raw_path) {
            return MatchResult::Reject("prefix 注册 path 不得编码 / 或 * 结构字符");
        }
    }
    let reg = match canonicalize(registered) {
        Ok(c) => c,
        Err(_) => return MatchResult::Reject("注册值本身非法"),
    };
    let inb = match canonicalize(inbound) {
        Ok(c) => c,
        Err(e) => return MatchResult::Reject(e),
    };

    match mode {
        RedirectMode::Exact => {
            // 逐组件精确相等(scheme/host 已小写;path 大小写敏感;query 精确)。
            if reg == inb {
                MatchResult::Allow
            } else {
                MatchResult::Reject("exact 不逐组件相等")
            }
        }
        RedirectMode::Loopback => {
            // 只认 IP 字面量、拒 localhost;端口任意;其余组件精确。
            if !is_ip_literal(&inb.host) {
                return MatchResult::Reject("loopback 只认 127.0.0.1/[::1],拒 localhost");
            }
            if inb.scheme == reg.scheme
                && is_ip_literal(&reg.host)
                && inb.host == reg.host
                && inb.path == reg.path
                && inb.query == reg.query
            {
                // 端口任意:不比较 port。
                MatchResult::Allow
            } else {
                MatchResult::Reject("loopback 非端口维度不匹配")
            }
        }
        RedirectMode::Prefix => {
            // C4.4b:host 精确 + scheme **必须 https**(§3.3:prefix 模式强制 https,防降级)+
            // path 前缀固定 + **尾部单层通配**(注册 path 末段为 `*`)。
            // scheme 强制 https(注册与入站都必须——防 http 降级到共享 host)。
            if reg.scheme != "https" {
                return MatchResult::Reject("prefix 模式注册 scheme 必须 https");
            }
            if inb.scheme != "https" {
                return MatchResult::Reject("prefix 模式入站 scheme 必须 https");
            }
            // host 精确(已小写)+ port 精确(共享 host 上不放宽端口)。
            if inb.host != reg.host || inb.port != reg.port {
                return MatchResult::Reject("prefix host/port 不精确匹配");
            }
            // 注册 path MUST 以 `/*` 结尾(尾部单层通配声明);否则注册值非法(prefix 语义要求通配)。
            let Some(prefix) = reg.path.strip_suffix('*') else {
                return MatchResult::Reject("prefix 注册 path 必须以 /* 结尾(尾部单层通配)");
            };
            // 前缀部分 MUST 以 `/` 结尾(通配只在**末段**:`/a/b/` + 单层,不允许 `/a/b*` 这类段内通配)。
            if !prefix.ends_with('/') {
                return MatchResult::Reject("prefix 通配只在末段(前缀须以 / 结尾,如 /path/*)");
            }
            // 入站 path MUST 以前缀开头。
            let Some(tail) = inb.path.strip_prefix(prefix) else {
                return MatchResult::Reject("prefix 入站 path 不以注册前缀开头");
            };
            // **单层**:通配段(tail)MUST NOT 含 `/`(不越段,§3.3:禁二级路径)。
            // canonicalize 已拒 path 里的 `..`/`//`/`?`/`#`/`%`(双重编码);tail 只需再禁 `/`。
            if tail.contains('/') {
                return MatchResult::Reject("prefix 通配单层,不得越段(含 /)");
            }
            // 通配段非空(`/path/*` 要求 `*` 处至少匹配一段;空 tail = 入站正好是前缀,无 callback 段→拒)。
            if tail.is_empty() {
                return MatchResult::Reject("prefix 通配段为空(入站须在前缀下有一层)");
            }
            // query:**通配绝不吞 query**——注册 prefix 值本身不应带 query;入站 query MUST 为空。
            // (prefix 用例是 UUID callback,不带固定 query;要固定 query 用 exact。)
            if reg.query.is_some() {
                return MatchResult::Reject("prefix 注册值不应带 query(通配不吞 query)");
            }
            if inb.query.is_some() {
                return MatchResult::Reject("prefix 入站不得带 query(通配不吞 query)");
            }
            MatchResult::Allow
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APP: &str = "https://app.example.com/callback";

    // C4.4a:exact 精确相等放行。
    #[test]
    fn exact_identical_allows() {
        assert_eq!(
            match_redirect(&RedirectMode::Exact, APP, APP),
            MatchResult::Allow
        );
    }

    #[test]
    fn exact_private_use_scheme_without_authority_allows() {
        const PRIVATE_USE: &str = "com.example.app:/oauth2/callback";
        assert_eq!(
            match_redirect(&RedirectMode::Exact, PRIVATE_USE, PRIVATE_USE),
            MatchResult::Allow
        );
    }

    #[test]
    fn http_redirect_without_authority_is_rejected() {
        assert!(matches!(
            match_redirect(
                &RedirectMode::Exact,
                "https:/app.example.com/callback",
                "https:/app.example.com/callback"
            ),
            MatchResult::Reject(_)
        ));
    }

    // C4.4a:host 大小写不敏感(小写化后相等)。
    #[test]
    fn host_case_insensitive() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://APP.example.com/callback"
            ),
            MatchResult::Allow
        );
    }

    // C4.4a:scheme 大小写不敏感(小写化后相等)。
    #[test]
    fn scheme_case_insensitive() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "HTTPS://app.example.com/callback"
            ),
            MatchResult::Allow
        );
    }

    // C4.4a 模糊测试:编码穿越/双重编码/双斜杠/尾斜杠/多 query/userinfo/path 大小写全拒。
    #[test]
    fn exact_fuzz_all_rejected() {
        let bad = [
            "https://app.example.com/callback%2e%2e",      // 编码 ..
            "https://app.example.com/%252e%252e/callback", // 双重编码
            "https://app.example.com/callback//",          // 双斜杠
            "https://app.example.com/callback/",           // 尾斜杠差异
            "https://app.example.com/callback?x=1",        // 多 query
            "https://user:pass@app.example.com/callback",  // userinfo 混淆
            "https://app.example.com/CallBack",            // path 大小写
            "https://app.example.com/callback#frag",       // fragment
        ];
        for b in bad {
            assert!(
                matches!(
                    match_redirect(&RedirectMode::Exact, APP, b),
                    MatchResult::Reject(_)
                ),
                "{b} 应被拒(具体拒因见各专项测试)"
            );
        }
    }

    // path 大小写敏感:注册小写 callback,入站 CallBack 拒。
    #[test]
    fn path_case_sensitive() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://app.example.com/CallBack"
            ),
            MatchResult::Reject("exact 不逐组件相等")
        );
    }

    // userinfo 拒。
    #[test]
    fn userinfo_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://user:pass@app.example.com/callback"
            ),
            MatchResult::Reject("redirect_uri 禁止 userinfo(user:pass@host)")
        );
    }

    // 双重编码拒。
    #[test]
    fn double_encoding_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://app.example.com/%252e%252e/callback"
            ),
            MatchResult::Reject("path 双重编码(解码一次后仍含 %)")
        );
    }

    // 编码 .. 穿越:%2e%2e 解码为 .. 被拒。
    #[test]
    fn encoded_dotdot_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://app.example.com/%2e%2e/callback"
            ),
            MatchResult::Reject("path 含 .. 穿越")
        );
    }

    // C4.4a:path 解码后产生结构分隔符必须在比较前拒绝。
    #[test]
    fn encoded_path_delimiters_rejected() {
        for (uri, reason) in [
            ("https://app.example.com/callback%2F%2Fevil", "path 含 // "),
            (
                "https://app.example.com/callback%3Fadmin",
                "path 段含 ? 或 #",
            ),
            (
                "https://app.example.com/callback%23fragment",
                "path 段含 ? 或 #",
            ),
        ] {
            assert_eq!(
                match_redirect(&RedirectMode::Exact, APP, uri),
                MatchResult::Reject(reason),
                "{uri} 解码后产生的结构分隔符必须被拒"
            );
        }
    }

    // C4.5:loopback 覆盖 127.0.0.1 与 [::1]、各自端口任意但 host 不互换。
    #[test]
    fn loopback_both_ip_literals_any_port() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://127.0.0.1/callback",
                "http://127.0.0.1:54321/callback"
            ),
            MatchResult::Allow
        );
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://[::1]/callback",
                "http://[::1]:8080/callback"
            ),
            MatchResult::Allow
        );
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://127.0.0.1/callback",
                "http://[::1]:8080/callback"
            ),
            MatchResult::Reject("loopback 非端口维度不匹配")
        );
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://[::1]/callback",
                "http://127.0.0.1:54321/callback"
            ),
            MatchResult::Reject("loopback 非端口维度不匹配")
        );
    }

    // C4.5:loopback 拒 localhost。
    #[test]
    fn loopback_rejects_localhost() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://127.0.0.1/callback",
                "http://localhost:8080/callback"
            ),
            MatchResult::Reject("loopback 只认 127.0.0.1/[::1],拒 localhost")
        );
    }

    // loopback path 不符仍拒(端口任意但 path 要匹配)。
    #[test]
    fn loopback_path_must_match() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Loopback,
                "http://127.0.0.1/callback",
                "http://127.0.0.1:9/other"
            ),
            MatchResult::Reject("loopback 非端口维度不匹配")
        );
    }

    // 无 query 注册 + 无 query 入站 → 精确相等放行(query None==None)。
    #[test]
    fn no_query_both_sides_ok() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://app.example.com/callback"
            ),
            MatchResult::Allow
        );
    }

    // 注册带 query,入站 query 精确相等才放行。
    #[test]
    fn query_exact_match() {
        let reg = "https://app.example.com/cb?state=fixed";
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                reg,
                "https://app.example.com/cb?state=fixed"
            ),
            MatchResult::Allow
        );
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                reg,
                "https://app.example.com/cb?state=other"
            ),
            MatchResult::Reject("exact 不逐组件相等")
        );
    }

    // 安全回归护栏(Kiro 评审):loopback 绕过变体全部拒。
    #[test]
    fn loopback_bypass_variants_rejected() {
        let reg = "http://127.0.0.1/callback";
        for evil in [
            "http://127.0.0.1.evil.com/callback", // 后缀混淆
            "http://127.1/callback",              // 短写
            "http://0x7f.0.0.1/callback",         // 十六进制
            "http://2130706433/callback",         // 十进制整数 IP
            "http://[0:0:0:0:0:0:0:1]/callback",  // 未压缩 IPv6(非 [::1] 字面量)
        ] {
            assert!(
                matches!(
                    match_redirect(&RedirectMode::Loopback, reg, evil),
                    MatchResult::Reject(_)
                ),
                "{evil} 应被拒(只认 127.0.0.1/[::1] 字面量)"
            );
        }
    }

    // 安全回归护栏:控制字符 / 空字节 / 反斜杠 / CRLF 一律拒。
    #[test]
    fn control_chars_backslash_rejected() {
        for evil in [
            "https://app.example.com/call\\back",   // 反斜杠
            "https://app.example.com/callback\x00", // 空字节
            "https://app.example.com/call\rback",   // CR
            "https://app.example.com/call\nback",   // LF
            "https://app.example.com/call\x7fback", // DEL
        ] {
            assert_eq!(
                match_redirect(&RedirectMode::Exact, APP, evil),
                MatchResult::Reject("redirect_uri 含控制字符或反斜杠"),
                "{evil:?} 应被拒"
            );
        }
    }

    // 错误路径:非法端口 / 缺 :// / 空 host / 不完整或非 hex 百分号 / 缺 IPv6 ]。
    #[test]
    fn malformed_uris_rejected() {
        let bad = [
            "https://app.example.com:abc/callback", // 端口非数字
            "app.example.com/callback",             // 缺 ://
            "https:///callback",                    // 空 host
            "https://app.example.com/%2",           // 不完整转义
            "https://app.example.com/%GG",          // 非 hex
            "https://[::1/callback",                // 缺 ]
        ];
        for b in bad {
            assert!(
                matches!(
                    match_redirect(&RedirectMode::Exact, APP, b),
                    MatchResult::Reject(_)
                ),
                "{b} 应被拒"
            );
        }
    }

    // exact:显式端口参与比较(:443 vs 无端口 不等)。
    #[test]
    fn exact_port_participates() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Exact,
                APP,
                "https://app.example.com:443/callback"
            ),
            MatchResult::Reject("exact 不逐组件相等")
        );
    }

    // 超长 URI 拒(DoS 硬化)。
    #[test]
    fn overlong_uri_rejected() {
        let long = format!("https://app.example.com/{}", "a".repeat(3000));
        assert!(matches!(
            match_redirect(&RedirectMode::Exact, APP, &long),
            MatchResult::Reject(_)
        ));
    }

    // ---- C4.4b prefix 模式(P1)----
    const PFX: &str = "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/*";

    // prefix:前缀下单层 callback 放行(AgentCore UUID callback 用例)。
    #[test]
    fn prefix_single_segment_allows() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/abc-uuid-123"
            ),
            MatchResult::Allow
        );
    }

    // prefix:通配**单层**——越段(含 /)拒。
    #[test]
    fn prefix_no_multi_segment() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/a/b"
            ),
            MatchResult::Reject("prefix 通配单层,不得越段(含 /)")
        );
    }

    // prefix:通配**绝不吞 query**——入站带 query 拒。
    #[test]
    fn prefix_wildcard_not_swallow_query() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid?code=x"
            ),
            MatchResult::Reject("prefix 入站不得带 query(通配不吞 query)")
        );
    }

    // prefix:注册 URI 本身也不得带 query,避免把 query 固化到通配模板。
    #[test]
    fn prefix_registered_query_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "https://app.example.com/identities/*?fixed=1",
                "https://app.example.com/identities/uuid"
            ),
            MatchResult::Reject("prefix 注册值不应带 query(通配不吞 query)")
        );
    }

    // prefix:scheme 必须 https——http 入站降级拒(共享 host 防降级)。
    #[test]
    fn prefix_rejects_http_downgrade() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "http://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid"
            ),
            MatchResult::Reject("prefix 模式入站 scheme 必须 https")
        );
    }

    // prefix:注册值自身也必须是 HTTPS,不能只约束入站 URI。
    #[test]
    fn prefix_rejects_http_registration() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "http://app.example.com/identities/*",
                "https://app.example.com/identities/uuid"
            ),
            MatchResult::Reject("prefix 模式注册 scheme 必须 https")
        );
    }

    // prefix:host 精确——不同 host(即便前缀路径同)拒(防跨 host)。
    #[test]
    fn prefix_host_exact() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://evil.example.com/identities/uuid"
            ),
            MatchResult::Reject("prefix host/port 不精确匹配")
        );
    }

    // prefix:port 参与 authority 精确匹配,不得把注册端口视为可变通配。
    #[test]
    fn prefix_port_exact() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "https://app.example.com:8443/identities/*",
                "https://app.example.com:8443/identities/uuid"
            ),
            MatchResult::Allow
        );
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "https://app.example.com:8443/identities/*",
                "https://app.example.com:9443/identities/uuid"
            ),
            MatchResult::Reject("prefix host/port 不精确匹配")
        );
    }

    // prefix:入站 path 不以前缀开头 → 拒(旁路前缀)。
    #[test]
    fn prefix_path_must_start_with_prefix() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/other/uuid"
            ),
            MatchResult::Reject("prefix 入站 path 不以注册前缀开头")
        );
    }

    // prefix:入站正好是前缀(通配段为空)→ 拒(须在前缀下有一层 callback)。
    #[test]
    fn prefix_empty_wildcard_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/"
            ),
            MatchResult::Reject("prefix 通配段为空(入站须在前缀下有一层)")
        );
    }

    // prefix:注册 path 不以 /* 结尾 → 拒(prefix 语义要求尾部通配声明)。
    #[test]
    fn prefix_registered_must_end_star() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "https://app.example.com/callback", // 无 /*
                "https://app.example.com/callback/x"
            ),
            MatchResult::Reject("prefix 注册 path 必须以 /* 结尾(尾部单层通配)")
        );
    }

    // prefix:段内通配(/cb*)非法——通配只在末段(前缀须以 / 结尾)。
    #[test]
    fn prefix_no_intra_segment_wildcard() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                "https://app.example.com/cb*", // 段内通配
                "https://app.example.com/cbXYZ"
            ),
            MatchResult::Reject("prefix 通配只在末段(前缀须以 / 结尾,如 /path/*)")
        );
    }

    // prefix 模糊:编码越段(%2f 解码为 / 后形成第二层 path segment)。
    #[test]
    fn prefix_encoded_slash_rejected() {
        assert_eq!(
            match_redirect(
                &RedirectMode::Prefix,
                PFX,
                "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/a%2fb"
            ),
            MatchResult::Reject("prefix 通配单层,不得越段(含 /)")
        );
    }

    // prefix 仍必须经过共享 canonicalizer,不能为通配分支绕过 traversal/delimiter 防线。
    #[test]
    fn prefix_canonicalization_hazards_rejected() {
        for inbound in [
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/../evil",
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/%2e%2e",
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid%3fextra",
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid%23frag",
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid%252fextra",
            "https://bedrock-agentcore.us-east-1.amazonaws.com/identities/uuid#fragment",
        ] {
            assert!(
                matches!(
                    match_redirect(&RedirectMode::Prefix, PFX, inbound),
                    MatchResult::Reject(_)
                ),
                "prefix canonicalization hazard 必须拒绝: {inbound}"
            );
        }
    }

    // 注册模板不得靠 percent-decoding 合成 path separator 或通配符;其它 canonicalizer
    // hazard 同样须在读取历史/seeded client 时 fail closed,不能只依赖 DCR admission。
    #[test]
    fn prefix_registered_canonicalization_hazards_rejected() {
        for registered in [
            "https://app.example.com/identities/%2A",
            "https://app.example.com/iden%2Ftities/*",
            "https://app.example.com/identities/%2e%2e/*",
            "https://app.example.com/identities/uuid%3ffixed/*",
            "https://app.example.com/identities/uuid%252f/*",
        ] {
            assert!(
                matches!(
                    match_redirect(
                        &RedirectMode::Prefix,
                        registered,
                        "https://app.example.com/identities/uuid"
                    ),
                    MatchResult::Reject(_)
                ),
                "prefix 注册 canonicalization hazard 必须拒绝: {registered}"
            );
        }
    }
}
