//! DESIGN §1 — 协议面端点清单 / grant 矩阵 × 阶段归属(公理 1)。
//!
//! 每个端点/grant 只在其所属发布阶段落地;未到阶段 MUST NOT 可达、MUST NOT 进 discovery。
//! 复用 `agent-auth-discovery::Phase` 作为阶段真相源,避免两处各定义阶段枚举。
//! grant_types 的阶段清单已在 discovery::phase 钉死(P0=code+refresh,P2=cc/exchange/device/ciba);
//! 本模块补端点清单 × 阶段 + "某阶段某端点/grant 是否应可达"的判定。
//!
//! 决策真相源:docs/DESIGN §1、§10;docs/CONFORMANCE C1.2。

use agent_auth_discovery::Phase;

/// AS 协议面端点(不含 PRM——PRM 属 RS origin,不是 AS 端点)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Endpoint {
    pub name: &'static str,
    pub min_phase: Phase,
}

/// 端点清单 × 阶段归属(DESIGN §1)。PRM 不在此列(RS origin / RS CNAME vhost)。
pub fn endpoints() -> &'static [Endpoint] {
    use Phase::*;
    &[
        // P0
        Endpoint {
            name: "/.well-known/openid-configuration",
            min_phase: P0,
        },
        Endpoint {
            name: "/.well-known/oauth-authorization-server",
            min_phase: P0,
        },
        Endpoint {
            name: "/jwks.json",
            min_phase: P0,
        },
        Endpoint {
            name: "/register",
            min_phase: P0,
        },
        Endpoint {
            name: "/authorize",
            min_phase: P0,
        },
        Endpoint {
            name: "/token",
            min_phase: P0,
        },
        Endpoint {
            name: "/userinfo",
            min_phase: P0,
        }, // 与 /token 同阶段(§1)
        // P1
        Endpoint {
            name: "/introspect",
            min_phase: P1,
        },
        Endpoint {
            name: "/revoke",
            min_phase: P1,
        },
        Endpoint {
            name: "/sessions",
            min_phase: P1,
        },
        Endpoint {
            name: "/end-session",
            min_phase: P1,
        },
        // P2
        Endpoint {
            name: "/device_authorization",
            min_phase: P2,
        },
        Endpoint {
            name: "/bc-authorize",
            min_phase: P2,
        },
        Endpoint {
            name: "/grants",
            min_phase: P2,
        },
        // P3
        Endpoint {
            name: "/par",
            min_phase: P3,
        },
    ]
}

/// grant 矩阵 × 阶段(DESIGN §1)。implicit/hybrid 永久不存在,故不在清单。
pub fn grants() -> &'static [(&'static str, Phase)] {
    use Phase::*;
    &[
        ("authorization_code", P0),
        ("refresh_token", P0),
        ("client_credentials", P2),
        ("urn:ietf:params:oauth:grant-type:token-exchange", P2),
        ("urn:ietf:params:oauth:grant-type:device_code", P2),
        ("urn:openid:params:grant-type:ciba", P2),
    ]
}

fn rank(p: Phase) -> u8 {
    match p {
        Phase::P0 => 0,
        Phase::P0_5 => 1,
        Phase::P1 => 2,
        Phase::P2 => 3,
        Phase::P3 => 4,
    }
}

fn reached(current: Phase, min: Phase) -> bool {
    rank(current) >= rank(min)
}

/// 某端点在给定阶段是否应可达(C1.2:未到阶段不可达)。
pub fn endpoint_available(current: Phase, name: &str) -> bool {
    endpoints()
        .iter()
        .find(|e| e.name == name)
        .map(|e| reached(current, e.min_phase))
        .unwrap_or(false) // 未知端点一律不可达(fail-closed)
}

/// 某 grant_type 在给定阶段是否应被 `/token` 受理。
/// implicit/hybrid/ROPC(不在清单)一律拒(永久非目标)。
pub fn grant_accepted(current: Phase, grant_type: &str) -> bool {
    grants()
        .iter()
        .find(|(g, _)| *g == grant_type)
        .map(|(_, min)| reached(current, *min))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    // C1.2:P0 可达 P0 端点、不可达 P1+ 端点。
    #[test]
    fn p0_endpoints_gate() {
        assert!(endpoint_available(Phase::P0, "/authorize"));
        assert!(endpoint_available(Phase::P0, "/token"));
        assert!(endpoint_available(Phase::P0, "/userinfo")); // 与 /token 同阶段
        assert!(!endpoint_available(Phase::P0, "/introspect")); // P1
        assert!(!endpoint_available(Phase::P0, "/device_authorization")); // P2
        assert!(!endpoint_available(Phase::P0, "/par")); // P3
    }

    #[test]
    fn p1_reaches_p1_not_p2() {
        assert!(endpoint_available(Phase::P1, "/introspect"));
        assert!(endpoint_available(Phase::P1, "/end-session"));
        assert!(!endpoint_available(Phase::P1, "/device_authorization"));
    }

    // 未知端点 fail-closed。
    #[test]
    fn unknown_endpoint_unavailable() {
        assert!(!endpoint_available(Phase::P3, "/evil"));
    }

    // grant 矩阵:P0 只受理 code + refresh。
    #[test]
    fn p0_grants() {
        assert!(grant_accepted(Phase::P0, "authorization_code"));
        assert!(grant_accepted(Phase::P0, "refresh_token"));
        assert!(!grant_accepted(Phase::P0, "client_credentials")); // P2
        assert!(!grant_accepted(
            Phase::P0,
            "urn:ietf:params:oauth:grant-type:token-exchange"
        ));
    }

    #[test]
    fn p2_grants() {
        assert!(grant_accepted(Phase::P2, "client_credentials"));
        assert!(grant_accepted(
            Phase::P2,
            "urn:openid:params:grant-type:ciba"
        ));
    }

    // implicit/hybrid/ROPC 永久拒(不在清单)。
    #[test]
    fn implicit_hybrid_ropc_never_accepted() {
        for banned in [
            "token",
            "id_token",
            "token id_token",
            "password",
            "implicit",
        ] {
            assert!(
                !grant_accepted(Phase::P3, banned),
                "{banned} 永久非目标,任何阶段都不受理"
            );
        }
    }

    // PRM 不在端点清单(属 RS origin)。
    #[test]
    fn prm_not_an_as_endpoint() {
        assert!(endpoints()
            .iter()
            .all(|e| !e.name.contains("prm") && !e.name.contains("protected-resource")));
    }
}
