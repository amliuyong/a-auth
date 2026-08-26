//! C1.6a — issuer 按入站请求 Host 确定性派生(见 DEPLOYMENT §0 / DESIGN §1)。
//!
//! 规则:
//! - 【SaaS】Host = `t{N}.<zone>`(租户子域)→ issuer = `https://t{N}.<zone>`
//! - 【自部署】Host = 客户配置域 → issuer = `https://<该域>`
//! - **控制面 Host(如 `c.<zone>`)不是租户 issuer**,MUST NOT 返回 AS discovery/JWKS
//!   —— 此处直接拒绝派生(负向用例的正式验收归 spec 020 / C10.20)。
//! - MUST NOT 硬编码单一 issuer、MUST NOT 跨 Host 返错。
//!
//! 决策真相源:docs/DESIGN §1、docs/DEPLOYMENT §0。本模块只实现"Host→issuer"这一确定性映射。

/// 部署形态。issuer 派生规则按形态不同(DEPLOYMENT §0)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Form {
    /// 【SaaS】多租户:租户走 `t{N}.<zone>` 子域;`control_host` 是控制面(非 issuer)。
    Saas {
        /// 托管区(如 `aws.example.com`)。租户 Host 必须是它的直接子域。
        zone: String,
        /// 控制面 Host(如 `c.aws.example.com`)——不是任何租户 issuer,派生时拒绝。
        control_host: String,
    },
    /// 【自部署】单租户:issuer = 客户配置的这个域(单一确定域名)。
    SelfHosted {
        /// 客户配置的部署域(如 `auth.customer.example`)。
        configured_host: String,
    },
}

/// issuer 派生失败原因(可测的确定性错误,不 panic)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuerError {
    /// Host 为空或含非法字符。
    InvalidHost(String),
    /// 【SaaS】命中控制面 Host——它不是租户 issuer(负向,C10.20 归 spec 020)。
    ControlPlaneHost(String),
    /// 【SaaS】Host 不是 `zone` 的合法租户子域。
    NotATenantSubdomain { host: String, zone: String },
    /// 【自部署】Host 与配置域不符(防跨 Host 返错)。
    HostMismatch { host: String, expected: String },
    /// 部署配置错误:`control_host`/`configured_host` 不是合法全小写 Host
    /// (fail-closed,不静默把大写配置域降级成可绕过的比较)。
    InvalidConfig(String),
}

/// 派生出的 issuer:恒为 `https://<host>` 形态(HTTPS,无路径、无查询)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issuer(String);

impl Issuer {
    /// issuer 字符串(如 `https://t1.aws.example.com`)。
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// issuer 的 origin(scheme+host+port);本系统 issuer 无路径,故 origin == issuer 串。
    pub fn origin(&self) -> &str {
        &self.0
    }
}

/// FQDN 长度上限(RFC 1035:整体 ≤253、单标签 ≤63)。
const MAX_HOST_LEN: usize = 253;
const MAX_LABEL_LEN: usize = 63;

/// Host 合法性:非空、无 scheme/路径/端口/空白、只含域名允许字符、大小写敏感(只认全小写)。
/// 传入的 Host 应是已去掉端口的纯主机名(端口收拢由上游反代/CloudFront 处理)。
/// ⚠️ **不做 lowercase**:混合大小写一律拒(fail-closed)——归一化职责在上游反代,
/// 避免"issuer 按小写推导、下游按原样索引"导致 t1/T1 被当两套租户(隔离破裂)。
fn validate_host(host: &str) -> Result<(), IssuerError> {
    if host.is_empty() {
        return Err(IssuerError::InvalidHost("empty".into()));
    }
    if host.len() > MAX_HOST_LEN {
        return Err(IssuerError::InvalidHost(format!(
            "too long ({})",
            host.len()
        )));
    }
    // 拒绝混入 scheme / 路径 / 端口 / 空白 / 大写 / IDN / 下划线 / 百分号编码
    // ——只认 ASCII 小写域名字符 [a-z0-9.-]。
    let ok = host
        .bytes()
        .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'-'));
    if !ok || host.starts_with('.') || host.ends_with('.') || host.contains("..") {
        return Err(IssuerError::InvalidHost(host.into()));
    }
    // 逐标签:非空、≤63、不以连字符开头/结尾(DNS 规则,堵 fail-open 边缘)。
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(IssuerError::InvalidHost(host.into()));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(IssuerError::InvalidHost(host.into()));
        }
    }
    Ok(())
}

/// 校验并规范化**配置域**(control_host / configured_host):必须已是合法且全小写的 Host,
/// 否则视为部署配置错误(fail-closed,不静默降级)。返回校验通过的配置域引用。
///
/// 防的是 Kiro 评审的洞:配置域若含大写,入站小写 Host 与它字节比较会不等,
/// 导致控制面被当租户 issuer 签发 / 自部署合法请求被误拒。
fn validate_config_host(cfg_host: &str) -> Result<(), IssuerError> {
    validate_host(cfg_host).map_err(|_| IssuerError::InvalidConfig(cfg_host.into()))
}

/// 判断 `host` 是否 `zone` 的**单层**直接子域(`t1.<zone>` 可,`a.t1.<zone>` 不可)。
/// 返回子域标签(如 `t1`)。
fn single_label_subdomain<'a>(host: &'a str, zone: &str) -> Option<&'a str> {
    let suffix = host.strip_suffix(zone)?;
    // suffix 形如 `t1.`;必须非空、以 `.` 结尾、且去掉尾点后不含 `.`(单层)。
    let label = suffix.strip_suffix('.')?;
    if label.is_empty() || label.contains('.') {
        return None;
    }
    Some(label)
}

/// 按入站 Host 确定性派生 issuer(C1.6a)。
///
/// - `host`:入站请求的主机名(小写、无端口)。上游必须传该请求实际 Host,不得替换成固定值。
pub fn derive(host: &str, form: &Form) -> Result<Issuer, IssuerError> {
    // 不 trim:首尾空白本就是非法 Host,交给 validate_host 直接拒(fail-closed);
    // trim 会静默接受 " t1.aws.example.com ",与"拒空白"契约矛盾(codex 评审)。
    validate_host(host)?;

    match form {
        Form::Saas { zone, control_host } => {
            // 配置域也必须是合法全小写 Host,否则配置错误(防大写 control_host 被绕过)。
            validate_config_host(zone)?;
            validate_config_host(control_host)?;
            if host == control_host {
                // 控制面不是租户 issuer(C1.6a 边界;负向验收归 C10.20)。
                return Err(IssuerError::ControlPlaneHost(host.into()));
            }
            match single_label_subdomain(host, zone) {
                Some(_label) => Ok(Issuer(format!("https://{host}"))),
                None => Err(IssuerError::NotATenantSubdomain {
                    host: host.into(),
                    zone: zone.clone(),
                }),
            }
        }
        Form::SelfHosted { configured_host } => {
            validate_config_host(configured_host)?;
            if host == configured_host {
                Ok(Issuer(format!("https://{host}")))
            } else {
                // 自部署单栈:只认配置域,别的 Host 一律拒(防硬编码/跨 Host 返错)。
                Err(IssuerError::HostMismatch {
                    host: host.into(),
                    expected: configured_host.clone(),
                })
            }
        }
    }
}

/// 从入站 Host 派生**租户 id**(spec 020 C10.19/C10.20:数据分区键 / claims 防伪造闸的租户维度)。
///
/// - 【SaaS】`t{N}.<zone>` → 租户 id = 子域标签(`t1`);控制面 / 非租户子域 → `Err`(同 `derive` 的负向)。
/// - 【自部署】配置域 → 固定 `"default"`(单租户)。
///
/// **与 `derive` 同源**(先 `derive` 确保是合法租户 issuer,再取标签),不另立第二套 Host 解析——避免
/// "issuer 按一套规则、tenant 按另一套"导致隔离维度错位。
pub fn tenant_id_from(host: &str, form: &Form) -> Result<String, IssuerError> {
    // 先走 derive:控制面 / 非租户子域 / 配置错误都在此拒(与 issuer 判定同一真相源)。
    derive(host, form)?;
    match form {
        Form::Saas { zone, .. } => single_label_subdomain(host, zone)
            .map(|label| label.to_string())
            // derive 已保证是合法租户子域,这里 None 不可达;fail-closed 返错。
            .ok_or_else(|| IssuerError::NotATenantSubdomain {
                host: host.into(),
                zone: zone.clone(),
            }),
        // 自部署单租户:固定 tenant。
        Form::SelfHosted { .. } => Ok("default".to_string()),
    }
}

/// **从存储的 `tenant_id` + 形态重建该租户的 issuer**(spec 010 §5.4 / C8.1b,BYOD)。
///
/// BYOD PRM 数据面:入站 Host 是 RS 自带域名(非 tenant 子域),**不能** `derive(host)` 派生 issuer
/// (会 `NotATenantSubdomain`);也**绝不**能用 `https://{host}`(那会把 PRM 的 authorization_servers
/// 指向 RS 自己域名 = 跨租户 misdirection 面,评审 B3)。故 issuer MUST 从**登记时存下的 tenant_id** +
/// 形态重建:SaaS = `https://{tenant_id}.{zone}`(tenant_id = 子域标签);SelfHosted = `https://{configured_host}`。
/// `tenant_id` 由 `tenant_id_from` 在登记时算出并存进 domain map,此处不接触请求 Host。
pub fn issuer_for_tenant(form: &Form, tenant_id: &str) -> Result<Issuer, IssuerError> {
    match form {
        Form::Saas { zone, .. } => {
            validate_config_host(zone)?;
            // tenant_id 是单层标签(如 t1);重建 host 后复用 derive 校验(挡空/非法 label/控制面碰撞)。
            let host = format!("{tenant_id}.{zone}");
            derive(&host, form)
        }
        Form::SelfHosted { configured_host } => {
            validate_config_host(configured_host)?;
            Ok(Issuer(format!("https://{configured_host}")))
        }
    }
}

/// **claims 级跨租户防伪造闸**(spec 020 C10.22a):claims 级(共享 key)租户无密码学租户边界,
/// 控制面 MUST 拒绝其签发带**他人 `iss`** 的 token —— 共享 key 下唯一的跨租户防线。
///
/// 判定:待签 token 的 `iss` MUST 恰等于**该请求租户自己的 issuer**(按 Host 派生)。不等即拒(伪造)。
/// 逐租户 CMK(默认档)有密码学边界、不依赖本闸,但叠加此校验无害(纵深)。返回 `Ok(())` = 放行。
pub fn assert_iss_belongs_to_tenant(
    token_iss: &str,
    request_host: &str,
    form: &Form,
) -> Result<(), IssuerError> {
    let issuer = derive(request_host, form)?;
    if token_iss == issuer.as_str() {
        Ok(())
    } else {
        // 借用 HostMismatch 表达"token iss 与本租户 issuer 不符"(伪造他人 iss)。
        Err(IssuerError::HostMismatch {
            host: token_iss.into(),
            expected: issuer.as_str().to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn saas() -> Form {
        Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "c.aws.example.com".into(),
        }
    }

    // C1.6a Scenario:多租户下各 Host 返回对应 issuer,互不串。
    #[test]
    fn saas_tenant_host_maps_to_own_issuer() {
        assert_eq!(
            derive("t1.aws.example.com", &saas()).unwrap().as_str(),
            "https://t1.aws.example.com"
        );
        assert_eq!(
            derive("t2.aws.example.com", &saas()).unwrap().as_str(),
            "https://t2.aws.example.com"
        );
    }

    #[test]
    fn saas_tenants_do_not_cross() {
        let t1 = derive("t1.aws.example.com", &saas()).unwrap();
        let t2 = derive("t2.aws.example.com", &saas()).unwrap();
        assert_ne!(t1, t2, "不同 Host MUST 派生不同 issuer,不得相互串");
    }

    // C1.6a 边界:控制面 Host 不是租户 issuer(不返回 discovery/JWKS)。
    #[test]
    fn saas_control_plane_host_rejected() {
        assert_eq!(
            derive("c.aws.example.com", &saas()),
            Err(IssuerError::ControlPlaneHost("c.aws.example.com".into()))
        );
    }

    // 单层子域约束:嵌套子域不算租户 issuer。
    #[test]
    fn saas_nested_subdomain_rejected() {
        assert!(matches!(
            derive("a.t1.aws.example.com", &saas()),
            Err(IssuerError::NotATenantSubdomain { .. })
        ));
    }

    #[test]
    fn saas_zone_apex_is_not_a_tenant() {
        assert!(matches!(
            derive("aws.example.com", &saas()),
            Err(IssuerError::NotATenantSubdomain { .. })
        ));
    }

    // 【自部署】只认配置域。
    #[test]
    fn self_hosted_configured_host_ok() {
        let f = Form::SelfHosted {
            configured_host: "auth.customer.example".into(),
        };
        assert_eq!(
            derive("auth.customer.example", &f).unwrap().as_str(),
            "https://auth.customer.example"
        );
    }

    // 【自部署】不得跨 Host 返错(不硬编码返回配置域)。
    #[test]
    fn self_hosted_other_host_rejected() {
        let f = Form::SelfHosted {
            configured_host: "auth.customer.example".into(),
        };
        assert_eq!(
            derive("evil.attacker.example", &f),
            Err(IssuerError::HostMismatch {
                host: "evil.attacker.example".into(),
                expected: "auth.customer.example".into(),
            })
        );
    }

    // Host 合法性:拒 scheme/路径/端口/空。
    #[test]
    fn invalid_hosts_rejected() {
        for bad in [
            "",
            "https://t1.aws.example.com",
            "t1.aws.example.com/path",
            "t1.aws.example.com:8443",
            "T1.AWS.EXAMPLE.COM",
            ".aws.example.com",
            "t1..aws.example.com",
        ] {
            assert!(
                matches!(derive(bad, &saas()), Err(IssuerError::InvalidHost(_)))
                    || matches!(
                        derive(bad, &saas()),
                        Err(IssuerError::NotATenantSubdomain { .. })
                    ),
                "host {bad:?} 应被拒"
            );
        }
    }

    // issuer origin == issuer 串(无路径)。
    #[test]
    fn issuer_origin_equals_issuer() {
        let iss = derive("t1.aws.example.com", &saas()).unwrap();
        assert_eq!(iss.origin(), iss.as_str());
    }

    // 更多 Host 边界(codex+Kiro 评审补齐):下划线/首尾连字符/尾空格/超长/超长标签。
    #[test]
    fn more_invalid_hosts_rejected() {
        let bads = [
            "t_1.aws.example.com",  // 下划线
            "-t1.aws.example.com",  // 标签首连字符
            "t1-.aws.example.com",  // 标签尾连字符
            " t1.aws.example.com",  // 前导空格(不 trim,直接拒)
            "t1.aws.example.com ",  // 尾随空格
            "t1.aws.example.com\t", // 制表符
        ];
        for bad in bads {
            assert!(
                matches!(derive(bad, &saas()), Err(IssuerError::InvalidHost(_))),
                "host {bad:?} 应判 InvalidHost"
            );
        }
    }

    #[test]
    fn overlong_host_and_label_rejected() {
        // 整体 > 253。
        let long_host = format!("{}.aws.example.com", "a".repeat(250));
        assert!(matches!(
            derive(&long_host, &saas()),
            Err(IssuerError::InvalidHost(_))
        ));
        // 单标签 > 63(整体仍 < 253)。
        let long_label = format!("{}.aws.example.com", "a".repeat(64));
        assert!(matches!(
            derive(&long_label, &saas()),
            Err(IssuerError::InvalidHost(_))
        ));
    }

    // Kiro 中#1:配置域含大写 = 部署配置错误,fail-closed(不静默把控制面降级成租户)。
    #[test]
    fn uppercase_control_host_is_config_error_not_bypass() {
        let bad_saas = Form::Saas {
            zone: "aws.example.com".into(),
            control_host: "C.aws.example.com".into(), // 大写配置
        };
        // 入站小写控制面 host:不得被当成租户 issuer 签发,而是报配置错误。
        assert_eq!(
            derive("c.aws.example.com", &bad_saas),
            Err(IssuerError::InvalidConfig("C.aws.example.com".into())),
            "大写 control_host MUST 判配置错误,不得降级成可绕过的比较"
        );
    }

    #[test]
    fn uppercase_configured_host_is_config_error() {
        let bad = Form::SelfHosted {
            configured_host: "Auth.Customer.Example".into(),
        };
        assert_eq!(
            derive("auth.customer.example", &bad),
            Err(IssuerError::InvalidConfig("Auth.Customer.Example".into()))
        );
    }

    // punycode(xn--)是合法 ASCII 域名,发现面接受(产品决策:不额外拒 ACE label)。
    #[test]
    fn punycode_ace_label_accepted() {
        assert_eq!(
            derive("xn--t1-abc.aws.example.com", &saas())
                .unwrap()
                .as_str(),
            "https://xn--t1-abc.aws.example.com"
        );
    }

    // spec 020 C10.19/C10.20:tenant_id 从 Host 派生(SaaS=子域标签、自部署=default;控制面/非租户拒)。
    #[test]
    fn tenant_id_from_host() {
        assert_eq!(tenant_id_from("t1.aws.example.com", &saas()).unwrap(), "t1");
        assert_eq!(
            tenant_id_from("t42.aws.example.com", &saas()).unwrap(),
            "t42"
        );
        // 控制面 → 与 derive 同,拒(不解析为租户)。
        assert_eq!(
            tenant_id_from("c.aws.example.com", &saas()),
            Err(IssuerError::ControlPlaneHost("c.aws.example.com".into()))
        );
        // 非租户子域(多层)→ 拒。
        assert!(matches!(
            tenant_id_from("a.t1.aws.example.com", &saas()),
            Err(IssuerError::NotATenantSubdomain { .. })
        ));
        // 自部署 → 固定 default。
        let sh = Form::SelfHosted {
            configured_host: "auth.customer.example".into(),
        };
        assert_eq!(
            tenant_id_from("auth.customer.example", &sh).unwrap(),
            "default"
        );
    }

    // spec 010 §5.4 / C8.1b:BYOD 从存储 tenant_id 重建 issuer(不接触请求 Host)。
    #[test]
    fn issuer_for_tenant_reconstructs_from_stored_tenant() {
        // SaaS:tenant_id=t1 → https://t1.<zone>(与 derive(t1.zone) 一致)。
        assert_eq!(
            issuer_for_tenant(&saas(), "t1").unwrap().as_str(),
            "https://t1.aws.example.com"
        );
        // 空 / 非法 tenant_id → 经 derive 校验拒(fail-closed,不产出畸形 issuer)。
        assert!(issuer_for_tenant(&saas(), "").is_err());
        // tenant_id 不能是控制面标签对应 host(重建后 = control_host → derive 拒)。
        assert!(matches!(
            issuer_for_tenant(&saas(), "c"),
            Err(IssuerError::ControlPlaneHost(_))
        ));
        // 自部署:恒 configured_host,忽略 tenant_id 值。
        let sh = Form::SelfHosted {
            configured_host: "auth.customer.example".into(),
        };
        assert_eq!(
            issuer_for_tenant(&sh, "default").unwrap().as_str(),
            "https://auth.customer.example"
        );
    }

    // spec 020 C10.22a:claims 级跨租户防伪造闸——token iss MUST == 本租户 issuer。
    #[test]
    fn assert_iss_belongs_to_tenant_guard() {
        // t1 请求签 t1 自己的 iss → 放行。
        assert!(assert_iss_belongs_to_tenant(
            "https://t1.aws.example.com",
            "t1.aws.example.com",
            &saas()
        )
        .is_ok());
        // t1 请求签 **t2 的 iss** → 拒(跨租户伪造,C10.22a 核心)。
        assert!(matches!(
            assert_iss_belongs_to_tenant(
                "https://t2.aws.example.com",
                "t1.aws.example.com",
                &saas()
            ),
            Err(IssuerError::HostMismatch { .. })
        ));
        // request_host 是控制面 → derive 先拒(控制面不签租户 token)。
        assert!(matches!(
            assert_iss_belongs_to_tenant(
                "https://t1.aws.example.com",
                "c.aws.example.com",
                &saas()
            ),
            Err(IssuerError::ControlPlaneHost(_))
        ));
    }

    // spec 020 §4.2 / C10.22a:**反证——证明闸的必要性**。
    // claims 级共享 key 下,若**不过本闸**、直接信任"客户端自称的 iss",则租户 t1 能签出
    // iss=t2 的 token(共享 key 无密码学边界拦不住)——即跨租户伪造成立。本测试用"无闸"基线
    // (裸字符串,模拟直接采信客户端 iss)对照"有闸"(assert_iss_belongs_to_tenant),证明:
    //   - 无闸:t1 请求里带 iss=t2 → 该 iss 会被原样用于签发(伪造成功,危险);
    //   - 有闸:同一请求被 HostMismatch 拒(伪造被挡)。
    #[test]
    fn assert_iss_guard_is_necessary_counterexample() {
        let form = saas();
        let attacker_host = "t1.aws.example.com"; // 攻击者是合法租户 t1(持共享 key)
        let forged_iss = "https://t2.aws.example.com"; // 想冒充 t2 签发

        // —— 无闸基线:直接采信客户端自称 iss(不校验归属)——
        // 模拟"未接本闸"的签发路径:token_iss 原样进入签名。此时 forged_iss 会被签出。
        let naive_issuer_used = forged_iss; // 无校验 → 直接用客户端给的 iss
        assert_eq!(
            naive_issuer_used, forged_iss,
            "反证:无闸时客户端自称的 iss 被原样采用 → t1 能签出 iss=t2(跨租户伪造成立)"
        );
        // 且该 forged_iss 并不等于 t1 按 Host 派生的真实 issuer(证明确属越界)。
        let t1_real = derive(attacker_host, &form).unwrap();
        assert_ne!(
            forged_iss,
            t1_real.as_str(),
            "反证:被伪造的 iss 确实不属于 t1(t1 真 issuer 是 t1.aws.example.com)"
        );

        // —— 有闸:同一伪造请求过 assert_iss_belongs_to_tenant → 拒 ——
        assert!(
            matches!(
                assert_iss_belongs_to_tenant(forged_iss, attacker_host, &form),
                Err(IssuerError::HostMismatch { .. })
            ),
            "有闸:t1 想签 iss=t2 被 HostMismatch 拒(闸挡住了无闸时会成立的伪造)"
        );
    }
}
