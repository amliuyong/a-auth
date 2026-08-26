"""C8.5b 参考策略评估器样例(非规范性,spec 010 §5.1 H2)。

演示 RS 如何通过 `RsSdk.authenticate(..., RoutePolicy.rar)` 注册策略评估器，把**词汇表外**的复杂
RAR 在验签、aud、scope 全部通过后交给策略判定。**Python 侧刻意用手写策略**
(不引原生 Cedar 依赖——纯 Python SDK 现仅 pyjwt+cryptography,加原生 wheel = 打包退化,评审 H2)。
真实部署可换成 `cedarpy`(optional-extra)或调 AVP;hook 签名不变(同步返 PolicyDecision)。

关键示范:
- evaluator **启动时预实例化**策略引擎(此处 = 编译好的规则集),注册的闭包**同步**求值(评审 H1)。
- evaluator 只据**冻结 claims 投影 {sub, scope}** + detail + AccessRequest 判,返回 ALLOW/DENY;
  **绝不**扩权(RAR 是收窄闸,aud/scope 授权在 verify 阶段已过)。
"""

from agent_auth_rs import (
    AccessRequest,
    PolicyDecision,
    RarPolicy,
    RoutePolicy,
    RsSdk,
    RsSdkConfig,
)

from .helpers import KeyMaterial, jwks_of, sign_token

ISS = "https://auth.example.com"
RS = "https://mcp.docs.example.com"


# ── 参考:一个"策略引擎"(手写规则集;真实可换 cedarpy / AVP)──


class SamplePolicyEngine:
    """启动时构造(预实例化,H1);evaluate 同步。规则:type=`doc_policy` 的 detail 要求
    principal(sub)在 detail.allowed_subjects 白名单、且请求 scope ⊆ detail.max_scope。"""

    def __init__(self, ruleset_version: str):
        self.version = ruleset_version  # 模拟"编译好的策略集"

    def evaluate(self, detail, req, claims) -> PolicyDecision:
        if detail.get("type") != "doc_policy":
            return PolicyDecision.DENY  # 本引擎只认 doc_policy;其余拒(fail-closed)
        allowed_subjects = detail.get("allowed_subjects") or []
        if claims.get("sub") not in allowed_subjects:
            return PolicyDecision.DENY
        # scope 收窄:token 的 scope 必须 ⊆ detail 允许的 max_scope(RAR 只收窄)。
        max_scope = set(detail.get("max_scope") or [])
        token_scope = set((claims.get("scope") or "").split())
        if not token_scope.issubset(max_scope):
            return PolicyDecision.DENY
        return PolicyDecision.ALLOW


def authenticate(detail, evaluator, *, scope="doc:read"):
    key = KeyMaterial()
    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            jwks_fetcher=lambda: jwks_of(key),
        )
    )
    sdk.seed_jwks(jwks_of(key))
    token = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        sub="user:alice",
        scope=scope,
        authorization_details=[detail],
    )
    return sdk.authenticate(
        f"Bearer {token}",
        RoutePolicy(
            require_scopes=["doc:read"],
            rar=RarPolicy(
                request=AccessRequest(resource=RS),
                evaluator=evaluator,
            ),
        ),
    )


def test_sample_cedar_style_evaluator_allows_in_policy():
    engine = SamplePolicyEngine("v1")  # 预实例化(H1)
    evaluator = lambda d, q, c: engine.evaluate(d, q, c)  # noqa: E731 — 同步闭包
    detail = {
        "type": "doc_policy",
        "allowed_subjects": ["user:alice"],
        "max_scope": ["doc:read", "doc:list"],
        "locations": [RS],
    }
    assert authenticate(detail, evaluator).ok


def test_sample_evaluator_denies_out_of_policy_subject():
    engine = SamplePolicyEngine("v1")
    detail = {
        "type": "doc_policy",
        "allowed_subjects": ["user:bob"],  # alice 不在白名单
        "max_scope": ["doc:read"],
        "locations": [RS],
    }
    assert not authenticate(detail, engine.evaluate).ok


def test_sample_evaluator_denies_scope_escalation():
    # token scope 超出 detail.max_scope → 拒(RAR 只收窄,evaluator 不放行超授权)。
    engine = SamplePolicyEngine("v1")
    detail = {
        "type": "doc_policy",
        "allowed_subjects": ["user:alice"],
        "max_scope": ["doc:read"],
        "locations": [RS],
    }
    assert not authenticate(detail, engine.evaluate, scope="doc:read doc:write").ok
