//! Protected Resource Metadata(PRM,RFC 9728)生成 —— spec 010 C8.1(P1a 生成侧)。
//!
//! **决策真相源:docs/DESIGN §6。** PRM 按"受保护资源自身标识"派生,`resource` 字段 =
//! 该 RS 的资源标识、`authorization_servers` 指向 AS issuer。P1 默认投放方式 a:AS 只
//! **生成** JSON,交 RS 自挂在其自身 origin 的 `/.well-known/oauth-protected-resource`——
//! **绝不发布在 AS issuer origin 上**(AS origin 上不存在代表任意 RS 的全局 PRM)。
//!
//! 本模块纯逻辑、零 IO:给定 (resource_id, issuer, 可选 bearer methods/scopes) 产出 PRM JSON。
//! 最小字段 `resource` + `authorization_servers`(MUST),`bearer_methods_supported` +
//! `scopes_supported`(SHOULD,零配置客户端需完整 PRM,评审 M-2)。

use serde_json::{Map, Value};

/// 构造一份 PRM 的输入(资源标识 + 该 RS 声明的 AS issuer + 可选宣告字段)。
#[derive(Debug, Clone)]
pub struct PrmConfig {
    /// RS 资源标识(= 签发 token 的单元素 `aud`);PRM 的 `resource` 字段。
    pub resource_id: String,
    /// 该 RS 的 PRM 应声明的 AS issuer(P1 = 本 AS issuer)。
    pub authorization_server: String,
    /// 支持的 bearer 出示方式(RFC 9728;缺省 `["header"]`)。
    pub bearer_methods_supported: Vec<String>,
    /// 该 RS 支持的 scope 名(可空;SHOULD 宣告便于客户端零配置)。
    pub scopes_supported: Vec<String>,
}

impl PrmConfig {
    /// 最小构造:只给 resource_id + issuer,bearer 方式默认 `header`、scope 留空。
    pub fn new(resource_id: impl Into<String>, authorization_server: impl Into<String>) -> Self {
        PrmConfig {
            resource_id: resource_id.into(),
            authorization_server: authorization_server.into(),
            bearer_methods_supported: vec!["header".to_string()],
            scopes_supported: vec![],
        }
    }
}

/// 生成的 PRM 文档(不可变;`to_json` 取 JSON 值)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prm(Map<String, Value>);

impl Prm {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.get(key)
    }
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.clone())
    }
}

fn str_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|s| Value::String(s.clone())).collect())
}

/// 从配置生成 PRM(RFC 9728)。`resource` = resource_id;`authorization_servers` = [issuer]。
pub fn build(cfg: &PrmConfig) -> Prm {
    let mut m = Map::new();
    // MUST:资源标识 + 授权服务器。
    m.insert("resource".into(), Value::String(cfg.resource_id.clone()));
    m.insert(
        "authorization_servers".into(),
        str_array(std::slice::from_ref(&cfg.authorization_server)),
    );
    // SHOULD:bearer 出示方式(至少 header)。
    let methods = if cfg.bearer_methods_supported.is_empty() {
        vec!["header".to_string()]
    } else {
        cfg.bearer_methods_supported.clone()
    };
    m.insert("bearer_methods_supported".into(), str_array(&methods));
    // SHOULD:scope 宣告(非空才放)。
    if !cfg.scopes_supported.is_empty() {
        m.insert("scopes_supported".into(), str_array(&cfg.scopes_supported));
    }
    Prm(m)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prm_has_required_fields() {
        let cfg = PrmConfig::new("https://mcp.kb.example.com", "https://auth.example.com");
        let prm = build(&cfg);
        // resource = 资源标识。
        assert_eq!(prm.get("resource").unwrap(), "https://mcp.kb.example.com");
        // authorization_servers = 单元素数组含 issuer。
        assert_eq!(
            prm.get("authorization_servers").unwrap(),
            &serde_json::json!(["https://auth.example.com"])
        );
        // bearer_methods_supported 缺省含 header。
        assert_eq!(
            prm.get("bearer_methods_supported").unwrap(),
            &serde_json::json!(["header"])
        );
    }

    #[test]
    fn scopes_only_when_present() {
        let cfg = PrmConfig::new("https://mcp.rs.example.com", "https://auth.example.com");
        assert!(
            build(&cfg).get("scopes_supported").is_none(),
            "空 scope 不放该键"
        );

        let mut cfg2 = cfg;
        cfg2.scopes_supported = vec!["kb:read".into(), "kb:write".into()];
        assert_eq!(
            build(&cfg2).get("scopes_supported").unwrap(),
            &serde_json::json!(["kb:read", "kb:write"])
        );
    }

    // resource 与 authorization_server 不同(PRM 描述 RS、指向 AS)——不能混同。
    #[test]
    fn resource_distinct_from_issuer() {
        let cfg = PrmConfig::new("https://mcp.rs.example.com", "https://auth.example.com");
        let prm = build(&cfg);
        assert_ne!(
            prm.get("resource").unwrap(),
            &prm.get("authorization_servers").unwrap()[0]
        );
    }
}
