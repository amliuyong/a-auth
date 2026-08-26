"""RS SDK 校验测试(spec 010 C8.2/C8.3/C8.4/C8.8)。fixture token 离线,不依赖 AS。"""

from __future__ import annotations

import base64
import json
import time

import pytest
from agent_auth_rs import (
    AccessRequest,
    PolicyDecision,
    RarPolicy,
    RsSdk,
    RsSdkConfig,
    RoutePolicy,
    create_scope_resolver,
    derive_resource_metadata_url,
)

from .helpers import KeyMaterial, jwks_of, sign_token

ISS = "https://auth.example.com"
RS = "https://mcp.kb.example.com"


def _b64u(o) -> str:
    return base64.urlsafe_b64encode(json.dumps(o).encode()).rstrip(b"=").decode()


def make_sdk(key: KeyMaterial, **overrides) -> RsSdk:
    cfg = RsSdkConfig(
        resource_id=RS,
        issuer=ISS,
        jwks_fetcher=lambda: jwks_of(key),
        **overrides,
    )
    sdk = RsSdk(cfg)
    sdk.seed_jwks(jwks_of(key))
    return sdk


# ---- C8.2 aud + sub_type ----


def test_valid_token_ok():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS])
    r = sdk.authenticate(f"Bearer {t}")
    assert r.ok
    assert r.token.aud == RS
    assert r.token.sub_type == "user"
    assert r.token.client_id == "app-1"


def test_c2_2b_offline_sdk_preserves_actor_types():
    key = KeyMaterial()
    sdk = make_sdk(key)
    actor_types = {"agent-current": "agent", "service-earlier": "service"}
    token = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        actor_types=actor_types,
    )
    result = sdk.authenticate(f"Bearer {token}")
    assert result.ok
    assert result.token.sub_type == "user"
    assert result.token.auth_grant == "grant-1"
    assert result.token.actor_types == actor_types


def test_actor_types_null_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    token = sign_token(key, iss=ISS, aud=[RS], actor_types=None)
    result = sdk.authenticate(f"Bearer {token}")
    assert not result.ok
    assert result.status == 401


def test_aud_mismatch_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=["https://mcp.other.example.com"])
    r = sdk.authenticate(f"Bearer {t}")
    assert not r.ok and r.status == 401
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


def test_bare_string_aud_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=RS)  # 裸字符串
    r = sdk.authenticate(f"Bearer {t}")
    assert not r.ok


def test_require_sub_type_user_rejects_agent():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], sub_type="agent")
    r = sdk.authenticate(f"Bearer {t}", RoutePolicy(require_sub_type="user"))
    assert not r.ok and r.status == 403
    assert 'error="insufficient_scope"' in r.headers["WWW-Authenticate"]


def test_require_sub_type_user_allows_user():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], sub_type="user")
    r = sdk.authenticate(f"Bearer {t}", RoutePolicy(require_sub_type="user"))
    assert r.ok


def test_require_scopes_missing_403():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], scope="openid")
    r = sdk.authenticate(f"Bearer {t}", RoutePolicy(require_scopes=["kb:write"]))
    assert not r.ok and r.status == 403
    assert 'scope="kb:write"' in r.headers["WWW-Authenticate"]


def test_c8_2_audience_subject_and_scope_policy():
    key = KeyMaterial()
    sdk = make_sdk(key)
    valid = sign_token(key, iss=ISS, aud=[RS], scope="kb:read", sub_type="user")
    assert sdk.authenticate(
        f"Bearer {valid}",
        RoutePolicy(require_sub_type="user", require_scopes=["kb:read"]),
    ).ok

    for sub_type in ("agent", "service", "unknown", None):
        m2m_or_missing = sign_token(
            key, iss=ISS, aud=[RS], scope="kb:read", sub_type=sub_type
        )
        result = sdk.authenticate(
            f"Bearer {m2m_or_missing}", RoutePolicy(require_sub_type="user")
        )
        assert result.status == 403

    for undeclared_scope in ("kb:admin", "kb:read:all", "kb"):
        broader_name_only = sign_token(
            key, iss=ISS, aud=[RS], scope=undeclared_scope, sub_type="user"
        )
        result = sdk.authenticate(
            f"Bearer {broader_name_only}",
            RoutePolicy(require_scopes=["kb:read"]),
        )
        assert result.status == 403

    declared = make_sdk(
        key,
        scope_implications={
            "kb:admin": ["kb:write"],
            "kb:write": ["kb:read"],
        },
    )
    broader_name_only = sign_token(
        key, iss=ISS, aud=[RS], scope="kb:admin", sub_type="user"
    )
    assert declared.authenticate(
        f"Bearer {broader_name_only}",
        RoutePolicy(require_scopes=["kb:read", "kb:write"]),
    ).ok

    with pytest.raises(ValueError, match="cycle"):
        make_sdk(
            key,
            scope_implications={
                "kb:admin": ["kb:write"],
                "kb:write": ["kb:admin"],
            },
        )

    resolver_calls = {"n": 0}

    def permissive_resolver(_granted: str, _required: str) -> bool:
        resolver_calls["n"] += 1
        return True

    permissive_policy = make_sdk(key, scope_resolver=permissive_resolver)
    signed = sign_token(key, iss=ISS, aud=[RS], scope="kb:admin")
    header, body, signature = signed.split(".")
    corrupted_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    baseline_invalid = [
        sign_token(
            key, iss=ISS, aud=["https://mcp.other.example.com"], scope="kb:read"
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS, "https://mcp.other.example.com"],
            scope="kb:read",
        ),
        sign_token(key, iss=ISS, aud=RS, scope="kb:read"),
        sign_token(
            key,
            iss="https://evil.example.com",
            aud=[RS],
            scope="kb:read",
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            include_client_id=False,
        ),
        sign_token(key, iss=ISS, aud=[RS], scope="kb:read", typ="JWT"),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            now=1,
            exp_offset=1,
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            nbf_offset=5000,
            exp_offset=10000,
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            now=int(time.time()) + 5000,
            exp_offset=10000,
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            include_exp=False,
        ),
        sign_token(
            key,
            iss=ISS,
            aud=[RS],
            scope="kb:read",
            include_iat=False,
        ),
        f"{header}.{body}.{corrupted_signature}",
    ]
    for token in baseline_invalid:
        result = permissive_policy.authenticate(
            f"Bearer {token}", RoutePolicy(require_scopes=["kb:read"])
        )
        assert result.status == 401
    assert resolver_calls["n"] == 0, (
        "policy resolver must run only after baseline verification"
    )

    assert permissive_policy.authenticate(
        f"Bearer {signed}", RoutePolicy(require_scopes=["kb:read"])
    ).ok
    assert resolver_calls["n"] > 0


def test_resource_id_trailing_slash_normalized():
    key = KeyMaterial()
    cfg = RsSdkConfig(
        resource_id=RS + "/", issuer=ISS, jwks_fetcher=lambda: jwks_of(key)
    )
    sdk = RsSdk(cfg)
    sdk.seed_jwks(jwks_of(key))
    t = sign_token(key, iss=ISS, aud=[RS])  # aud 无尾斜杠
    assert sdk.authenticate(f"Bearer {t}").ok


# ---- C8.3 kid 强制 alg + 拒 alg:none ----


def test_alg_confusion_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    # 真实 ES256 签,再把 header.alg 改成 RS256(kid 仍指向 EC 公钥)。
    t = sign_token(key, iss=ISS, aud=[RS])
    h, body, sig = t.split(".")
    confused = f"{_b64u({'alg': 'RS256', 'typ': 'at+jwt', 'kid': key.public_jwk['kid']})}.{body}.{sig}"
    r = sdk.authenticate(f"Bearer {confused}")
    assert not r.ok and r.status == 401


def test_alg_none_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    import time

    t = f"{_b64u({'alg': 'none', 'typ': 'at+jwt', 'kid': key.public_jwk['kid']})}.{_b64u({'iss': ISS, 'aud': [RS], 'exp': int(time.time()) + 100, 'client_id': 'c'})}."
    r = sdk.authenticate(f"Bearer {t}")
    assert not r.ok


def test_c8_3_alg_key_pinning_and_none_rejection():
    ec_key = KeyMaterial("ES256")
    rsa_key = KeyMaterial("RS256")
    keys = jwks_of(ec_key, rsa_key)
    sdk = RsSdk(
        RsSdkConfig(
            resource_id=RS,
            issuer=ISS,
            jwks_fetcher=lambda: keys,
        )
    )
    sdk.seed_jwks(keys)

    es_token = sign_token(ec_key, iss=ISS, aud=[RS])
    rs_token = sign_token(rsa_key, iss=ISS, aud=[RS])
    assert sdk.authenticate(f"Bearer {es_token}").ok
    assert sdk.authenticate(f"Bearer {rs_token}").ok

    rsa_signed_for_ec_kid = sign_token(
        rsa_key,
        iss=ISS,
        aud=[RS],
        kid_override=ec_key.public_jwk["kid"],
    )
    ec_signed_for_rsa_kid = sign_token(
        ec_key,
        iss=ISS,
        aud=[RS],
        kid_override=rsa_key.public_jwk["kid"],
    )
    assert not sdk.authenticate(f"Bearer {rsa_signed_for_ec_kid}").ok
    assert not sdk.authenticate(f"Bearer {ec_signed_for_rsa_kid}").ok

    rsa384_token = sign_token(
        rsa_key,
        iss=ISS,
        aud=[RS],
        alg_override="RS384",
    )
    assert not sdk.authenticate(f"Bearer {rsa384_token}").ok

    none_token = (
        f"{_b64u({'alg': 'none', 'typ': 'at+jwt', 'kid': ec_key.public_jwk['kid']})}."
        f"{_b64u({'iss': ISS, 'aud': [RS], 'exp': int(time.time()) + 100, 'client_id': 'c'})}."
    )
    assert not sdk.authenticate(f"Bearer {none_token}").ok


# ---- RFC 9068 基线 ----


def test_typ_not_at_jwt_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], typ="JWT")
    assert not sdk.authenticate(f"Bearer {t}").ok


def test_iss_mismatch_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss="https://evil.example.com", aud=[RS])
    assert not sdk.authenticate(f"Bearer {t}").ok


def test_missing_client_id_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], include_client_id=False)
    assert not sdk.authenticate(f"Bearer {t}").ok


def test_expired_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    t = sign_token(key, iss=ISS, aud=[RS], now=1_000_000, exp_offset=100)  # 1970,早过期
    r = sdk.authenticate(f"Bearer {t}")
    assert not r.ok and r.status == 401


def test_future_iat_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    import time

    # iat 在未来 5000s(超默认 60s skew);exp 更远,只因 iat 未来被拒(评审 codex)。
    t = sign_token(
        key, iss=ISS, aud=[RS], now=int(time.time()) + 5000, exp_offset=10000
    )
    r = sdk.authenticate(f"Bearer {t}")
    assert not r.ok


# ---- C8.8 WWW-Authenticate ----


def test_no_token_pure_discovery_header():
    key = KeyMaterial()
    sdk = make_sdk(key)
    r = sdk.authenticate(None)
    assert not r.ok and r.status == 401
    h = r.headers["WWW-Authenticate"]
    assert f'resource_metadata="{RS}/.well-known/oauth-protected-resource"' in h
    assert "invalid_token" not in h


def test_invalid_token_has_error_code():
    key = KeyMaterial()
    sdk = make_sdk(key)
    r = sdk.authenticate("Bearer garbage.token.here")
    assert not r.ok
    assert 'error="invalid_token"' in r.headers["WWW-Authenticate"]


# ---- RFC 9728 URL + MCP 2026-07-28 challenge behavior ----


@pytest.mark.parametrize(
    ("resource", "expected"),
    [
        (
            "https://mcp.example.com",
            "https://mcp.example.com/.well-known/oauth-protected-resource",
        ),
        (
            "https://mcp.example.com/mcp",
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
        ),
        (
            "https://mcp.example.com:8443/mcp/v1/tools/",
            "https://mcp.example.com:8443/.well-known/oauth-protected-resource/mcp/v1/tools",
        ),
        (
            "https://mcp.example.com:443/mcp/v1",
            "https://mcp.example.com:443/.well-known/oauth-protected-resource/mcp/v1",
        ),
        (
            "https://[0:0:0:0:0:0:0:1]:8443/mcp",
            "https://[::1]:8443/.well-known/oauth-protected-resource/mcp",
        ),
        (
            "https://mcp.example.com/a%3Cb",
            "https://mcp.example.com/.well-known/oauth-protected-resource/a%3Cb",
        ),
    ],
)
def test_resource_metadata_url_derivation(resource, expected):
    assert derive_resource_metadata_url(resource) == expected


def test_explicit_resource_metadata_url_is_used_exactly():
    explicit = "https://metadata.example.com/custom/prm?tenant=t1"
    sdk = RsSdk(
        RsSdkConfig(
            resource_id="https://mcp.example.com/mcp",
            issuer=ISS,
            resource_metadata_url=explicit,
        )
    )
    result = sdk.authenticate(None)
    assert not result.ok
    assert result.headers["WWW-Authenticate"] == (
        f'Bearer resource_metadata="{explicit}"'
    )


@pytest.mark.parametrize(
    "resource_id",
    [
        "http://mcp.example.com/mcp",
        "https://user@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?tenant=t1",
        "https://mcp.example.com/mcp#fragment",
        "https://mcp.example.com\\evil",
        "https://%65xample.com/mcp",
        "https://127.1/mcp",
        "https://1.2.3.4./mcp",
        "https://mcp.example.com/a/../mcp",
        "https://mcp.example.com/%2e%2e/mcp",
        "https://mcp.example.com/a<b",
        "https://mcp.example.com/a[b",
        "https://mcp.example.com/%zz",
        "not-a-url",
    ],
)
def test_invalid_resource_id_rejected(resource_id):
    with pytest.raises(ValueError):
        RsSdk(RsSdkConfig(resource_id=resource_id, issuer=ISS))


@pytest.mark.parametrize(
    "resource_metadata_url",
    [
        "http://metadata.example.com/prm",
        "https://user@metadata.example.com/prm",
        "https://metadata.example.com/prm#fragment",
        'https://metadata.example.com/prm"x',
        "https://metadata.example.com/prm\\x",
        "https://metadata.example.com/prm\r\nX-Injected: yes",
        "https://exa<mple.example/prm",
        "https://metadata.example.com/a<b",
        "https://metadata.example.com/a[b",
        "https://metadata.example.com/%zz",
        "",
    ],
)
def test_unsafe_explicit_resource_metadata_url_rejected(resource_metadata_url):
    with pytest.raises(ValueError):
        RsSdk(
            RsSdkConfig(
                resource_id=RS,
                issuer=ISS,
                resource_metadata_url=resource_metadata_url,
            )
        )


def test_c8_8_prm_challenge_is_safe_exact_and_redacted():
    resource = "https://mcp.example.com/mcp/v1"
    metadata = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/v1"
    sdk = RsSdk(RsSdkConfig(resource_id=resource, issuer=ISS))

    missing = sdk.authenticate(None)
    assert not missing.ok and missing.status == 401
    assert missing.headers["WWW-Authenticate"] == (
        f'Bearer resource_metadata="{metadata}"'
    )

    private_detail = "Bearer private-validation-detail"
    invalid = sdk.authenticate(
        private_detail,
        RoutePolicy(require_scopes=["mcp:read"]),
    )
    assert not invalid.ok and invalid.status == 401
    assert invalid.headers["WWW-Authenticate"] == (
        f'Bearer error="invalid_token", resource_metadata="{metadata}"'
    )
    assert "private-validation-detail" not in invalid.headers["WWW-Authenticate"]
    assert "mcp:read" not in invalid.headers["WWW-Authenticate"]

    key = KeyMaterial()
    validating_sdk = make_sdk(key)
    expired_token = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        now=1_000_000,
        exp_offset=100,
    )
    expired = validating_sdk.authenticate(f"Bearer {expired_token}")
    assert not expired.ok and expired.status == 401
    assert expired.headers["WWW-Authenticate"] == (
        f'Bearer error="invalid_token", '
        f'resource_metadata="{RS}/.well-known/oauth-protected-resource"'
    )
    assert expired_token not in expired.headers["WWW-Authenticate"]

    derivations = {
        "https://mcp.example.com": (
            "https://mcp.example.com/.well-known/oauth-protected-resource"
        ),
        "https://mcp.example.com/mcp": (
            "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
        ),
        "https://mcp.example.com:8443/mcp/v1/tools/": (
            "https://mcp.example.com:8443/"
            ".well-known/oauth-protected-resource/mcp/v1/tools"
        ),
    }
    for source, expected in derivations.items():
        assert derive_resource_metadata_url(source) == expected

    explicit = "https://metadata.example.com/custom/prm?tenant=t1"
    explicit_sdk = RsSdk(
        RsSdkConfig(
            resource_id=resource,
            issuer=ISS,
            resource_metadata_url=explicit,
        )
    )
    explicit_result = explicit_sdk.authenticate(None)
    assert explicit_result.headers["WWW-Authenticate"] == (
        f'Bearer resource_metadata="{explicit}"'
    )

    unsafe_resources = [
        "http://mcp.example.com/mcp",
        "https://user@mcp.example.com/mcp",
        "https://mcp.example.com/mcp?tenant=t1",
        "https://mcp.example.com/mcp#fragment",
        "https://mcp.example.com\\evil",
        "https://%65xample.com/mcp",
        "https://mcp.example.com/a/../mcp",
        "https://mcp.example.com/%2e%2e/mcp",
        "https://mcp.example.com/%zz",
    ]
    for unsafe in unsafe_resources:
        with pytest.raises(ValueError):
            RsSdk(RsSdkConfig(resource_id=unsafe, issuer=ISS))

    unsafe_metadata_urls = [
        "http://metadata.example.com/prm",
        "https://user@metadata.example.com/prm",
        "https://metadata.example.com/prm#fragment",
        'https://metadata.example.com/prm"x',
        "https://metadata.example.com/prm\\x",
        "https://metadata.example.com/prm\r\nX-Injected: yes",
        "https://metadata.example.com/%zz",
    ]
    for unsafe in unsafe_metadata_urls:
        with pytest.raises(ValueError):
            RsSdk(
                RsSdkConfig(
                    resource_id=resource,
                    issuer=ISS,
                    resource_metadata_url=unsafe,
                )
            )


def test_missing_token_challenge_has_complete_operation_scope():
    sdk = RsSdk(RsSdkConfig(resource_id=RS, issuer=ISS))
    result = sdk.authenticate(None, RoutePolicy(require_scopes=["kb:read", "kb:write"]))
    assert not result.ok
    assert result.headers["WWW-Authenticate"] == (
        'Bearer scope="kb:read kb:write", '
        f'resource_metadata="{RS}/.well-known/oauth-protected-resource"'
    )


def test_invalid_token_challenge_does_not_expose_details_or_scope():
    sdk = RsSdk(RsSdkConfig(resource_id=RS, issuer=ISS))
    result = sdk.authenticate(
        "Bearer private-validation-detail",
        RoutePolicy(require_scopes=["kb:read"]),
    )
    assert not result.ok
    assert result.headers["WWW-Authenticate"] == (
        'Bearer error="invalid_token", '
        f'resource_metadata="{RS}/.well-known/oauth-protected-resource"'
    )
    assert "private-validation-detail" not in result.headers["WWW-Authenticate"]


def test_insufficient_scope_challenge_is_complete():
    key = KeyMaterial()
    sdk = make_sdk(key)
    token = sign_token(key, iss=ISS, aud=[RS], scope="kb:read")
    result = sdk.authenticate(
        f"Bearer {token}",
        RoutePolicy(require_scopes=["kb:read", "kb:write"]),
    )
    assert not result.ok
    assert result.headers["WWW-Authenticate"] == (
        'Bearer error="insufficient_scope", scope="kb:read kb:write", '
        f'resource_metadata="{RS}/.well-known/oauth-protected-resource"'
    )


@pytest.mark.parametrize(
    "scope",
    ["kb read", 'kb"read', "kb\\read", "kb\r\nX-Injected:", "", "读"],
)
def test_unsafe_challenge_scope_rejected(scope):
    sdk = RsSdk(RsSdkConfig(resource_id=RS, issuer=ISS))
    with pytest.raises(ValueError):
        sdk.authenticate(None, RoutePolicy(require_scopes=[scope]))


def test_c8_8a_operation_scope_challenges_are_complete():
    metadata = f"{RS}/.well-known/oauth-protected-resource"
    required_scopes = ["kb:read", "kb:write"]
    sdk = RsSdk(RsSdkConfig(resource_id=RS, issuer=ISS))

    missing = sdk.authenticate(
        None,
        RoutePolicy(require_scopes=required_scopes),
    )
    assert not missing.ok and missing.status == 401
    missing_challenge = missing.headers["WWW-Authenticate"]
    assert missing_challenge == (
        f'Bearer scope="kb:read kb:write", resource_metadata="{metadata}"'
    )
    assert missing_challenge.count("Bearer") == 1

    key = KeyMaterial()
    validating_sdk = make_sdk(key)
    token = sign_token(key, iss=ISS, aud=[RS], scope="kb:read")
    insufficient = validating_sdk.authenticate(
        f"Bearer {token}",
        RoutePolicy(require_scopes=required_scopes),
    )
    assert not insufficient.ok and insufficient.status == 403
    insufficient_challenge = insufficient.headers["WWW-Authenticate"]
    assert insufficient_challenge == (
        'Bearer error="insufficient_scope", scope="kb:read kb:write", '
        f'resource_metadata="{metadata}"'
    )
    assert insufficient_challenge.count("Bearer") == 1

    for unsafe_scope in [
        "kb read",
        'kb"read',
        "kb\\read",
        "kb\r\nX-Injected:",
        "",
        "读",
    ]:
        with pytest.raises(ValueError):
            sdk.authenticate(
                None,
                RoutePolicy(require_scopes=[unsafe_scope]),
            )
        with pytest.raises(ValueError):
            validating_sdk.authenticate(
                f"Bearer {token}",
                RoutePolicy(require_scopes=[unsafe_scope]),
            )


# ---- Explicit scope implication hierarchy ----


def test_default_scope_resolver_uses_exact_equality_only():
    resolver = create_scope_resolver()
    assert resolver("kb:read", "kb:read")
    assert not resolver("kb", "kb:read")
    assert not resolver("kb:admin", "kb:read")


def test_declared_scope_implications_are_transitive():
    key = KeyMaterial()
    sdk = make_sdk(
        key,
        scope_implications={
            "kb:admin": ["kb:write"],
            "kb:write": ["kb:read"],
        },
    )
    token = sign_token(key, iss=ISS, aud=[RS], scope="kb:admin")
    result = sdk.authenticate(
        f"Bearer {token}",
        RoutePolicy(require_scopes=["kb:read", "kb:write"]),
    )
    assert result.ok


def test_undeclared_scope_implication_is_rejected():
    key = KeyMaterial()
    sdk = make_sdk(key)
    token = sign_token(key, iss=ISS, aud=[RS], scope="kb:admin")
    result = sdk.authenticate(
        f"Bearer {token}", RoutePolicy(require_scopes=["kb:read"])
    )
    assert not result.ok and result.status == 403


def test_cyclic_hierarchy_and_dual_resolver_configuration_rejected():
    with pytest.raises(ValueError, match="cycle"):
        create_scope_resolver(
            {
                "kb:admin": ["kb:write"],
                "kb:write": ["kb:admin"],
            }
        )
    with pytest.raises(ValueError, match="mutually exclusive"):
        RsSdk(
            RsSdkConfig(
                resource_id=RS,
                issuer=ISS,
                scope_implications={"kb:admin": ["kb:read"]},
                scope_resolver=lambda _granted, _required: True,
            )
        )


def test_custom_scope_resolver_requires_boolean_true():
    key = KeyMaterial()
    sdk = make_sdk(
        key,
        scope_resolver=lambda _granted, _required: "truthy but not boolean",
    )
    token = sign_token(key, iss=ISS, aud=[RS], scope="kb:admin")
    result = sdk.authenticate(
        f"Bearer {token}", RoutePolicy(require_scopes=["kb:read"])
    )
    assert not result.ok and result.status == 403


def test_c8_10b_offline_sdk_rejects_grant_backed_rar_summary():
    key = KeyMaterial()
    sdk = make_sdk(key)
    summary = {
        "type": "agent_auth_grant_summary_v1",
        "locations": [RS],
        "authorization_details_count": 4,
        "authorization_details_sha256": "A" * 43,
        "introspection_required": True,
    }
    token = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details=[summary],
    )

    result = sdk.authenticate(
        f"Bearer {token}",
        RoutePolicy(require_scopes=["kb:read"]),
    )

    assert not result.ok
    assert result.status == 403
    assert result.token is None
    assert result.error is not None
    assert result.error.kind == "insufficient_scope"
    assert "authenticated introspection" in result.error.detail


def test_c8_5b_offline_evaluator_runs_only_after_signature_audience_and_scope():
    key = KeyMaterial()
    sdk = make_sdk(key)
    complex_detail = {
        "type": "cedar_policy",
        "policy_ref": "doc-read",
        "locations": [RS],
    }
    calls = []

    def evaluator(detail, request, claims):
        calls.append((detail, request, claims))
        return PolicyDecision.ALLOW

    policy = RoutePolicy(
        require_sub_type="user",
        require_scopes=["kb:read"],
        rar=RarPolicy(
            request=AccessRequest(resource=RS),
            evaluator=evaluator,
        ),
    )

    valid = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details=[complex_detail],
    )
    header, payload, signature = valid.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"
    wrong_audience = sign_token(
        key,
        iss=ISS,
        aud=["https://mcp.other.example.com"],
        scope="kb:read",
        authorization_details=[complex_detail],
    )
    multiple_audiences = sign_token(
        key,
        iss=ISS,
        aud=[RS, "https://mcp.other.example.com"],
        scope="kb:read",
        authorization_details=[complex_detail],
    )
    wrong_sub_type = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        sub_type="agent",
        authorization_details=[complex_detail],
    )
    missing_scope = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="openid",
        authorization_details=[complex_detail],
    )
    malformed_rar = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details={"type": "cedar_policy"},
    )
    empty_rar = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details={},
    )
    malformed_detail = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details=[42, complex_detail],
    )
    missing_type = sign_token(
        key,
        iss=ISS,
        aud=[RS],
        scope="kb:read",
        authorization_details=[{"policy_ref": "missing-type"}, complex_detail],
    )

    for rejected in (
        tampered,
        wrong_audience,
        multiple_audiences,
        wrong_sub_type,
        missing_scope,
        malformed_rar,
        empty_rar,
        malformed_detail,
        missing_type,
    ):
        result = sdk.authenticate(f"Bearer {rejected}", policy)
        assert not result.ok
        assert calls == []

    allowed = sdk.authenticate(f"Bearer {valid}", policy)
    assert allowed.ok
    assert allowed.token is not None
    assert len(calls) == 1
    detail, request, claims = calls[0]
    assert detail["policy_ref"] == "doc-read"
    assert request.resource == RS
    assert dict(claims) == {"sub": "user-1", "scope": "kb:read"}

    denied = sdk.authenticate(
        f"Bearer {valid}",
        RoutePolicy(
            require_sub_type="user",
            require_scopes=["kb:read"],
            rar=RarPolicy(
                request=AccessRequest(resource=RS),
                evaluator=lambda _detail, _request, _claims: PolicyDecision.DENY,
            ),
        ),
    )
    assert not denied.ok
    assert denied.status == 403
    assert denied.token is None
