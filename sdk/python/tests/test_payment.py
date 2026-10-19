"""Issue #77 C14: `agent_auth_payment_v1` single-transaction payment authorization.

Checks the canonical terms encoding against the cross-language vectors, the strict
exactly-one-detail execution check, and that the generic `enforce_rar` semantics are unchanged.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agent_auth_rs import (
    PAYMENT_EXECUTE_SCOPE,
    PAYMENT_RAR_TYPE_V1,
    PAYMENT_TERMS_DIGEST_DOMAIN,
    RAR_TYPE_V1,
    AccessRequest,
    PaymentAuthorizationError,
    VerifiedPaymentAuthorization,
    enforce_rar,
    payment_terms_canonical_bytes,
    payment_terms_digest,
    validate_payment_terms,
    verify_payment_authorization,
)

# tests -> python -> sdk -> repository root (works with --import-mode=importlib from any cwd).
VECTORS_PATH = (
    Path(__file__).resolve().parents[3] / "specs" / "fixtures" / "agent_auth_payment_v1.json"
)


def _vectors() -> dict:
    return json.loads(VECTORS_PATH.read_text(encoding="utf-8"))


def _baseline() -> tuple[str, dict]:
    case = _vectors()["valid"][0]
    return case["intent_id"], case["terms"]


def _detail(intent_id: str, terms: dict) -> dict:
    return {
        "type": PAYMENT_RAR_TYPE_V1,
        "locations": [terms["resource"]],
        "actions": ["execute"],
        "intent_id": intent_id,
        "terms_digest": payment_terms_digest(intent_id, terms),
        "terms": copy.deepcopy(terms),
    }


def _claims(terms: dict, details: object) -> dict:
    return {
        "active": True,
        "aud": [terms["resource"]],
        "scope": PAYMENT_EXECUTE_SCOPE,
        "act": {"sub": terms["actor"]},
        "sub": terms["payer"],
        "authorization_details": details,
    }


def _code(fn, *args, **kwargs) -> str:
    with pytest.raises(PaymentAuthorizationError) as raised:
        fn(*args, **kwargs)
    return raised.value.code


def test_c14_1_payment_terms_vectors_match_canonical_encoding():
    doc = _vectors()
    assert doc["profile"] == PAYMENT_RAR_TYPE_V1
    assert doc["digest_domain_hex"] == PAYMENT_TERMS_DIGEST_DOMAIN.hex()
    assert doc["field_order"][0] == "profile" and len(doc["field_order"]) == 18

    assert len(doc["valid"]) >= 3
    for case in doc["valid"]:
        name, intent_id, terms = case["name"], case["intent_id"], case["terms"]
        validated = validate_payment_terms(terms)
        assert validated == terms, name
        assert validated is not terms and validated["payee"] is not terms["payee"], name
        assert payment_terms_canonical_bytes(intent_id, terms).hex() == case["canonical_hex"], name
        digest = payment_terms_digest(intent_id, terms)
        assert digest == case["terms_digest"], name
        assert len(digest) == 43 and "=" not in digest, name
        # Key order is irrelevant: the digest never hashes a JSON serialization.
        reordered = dict(reversed(list(terms.items())))
        assert payment_terms_digest(intent_id, reordered) == digest, name

    assert len(doc["invalid_terms"]) >= 20
    for case in doc["invalid_terms"]:
        assert _code(validate_payment_terms, case["terms"]) == "invalid_terms", case["name"]
        assert (
            _code(payment_terms_digest, case["intent_id"], case["terms"]) == "invalid_terms"
        ), case["name"]

    intent_id, terms = _baseline()
    # Amount rules are exact ASCII decimal strings (no `\d` / float leniency).
    for bad_amount in ["", "0", "00", "01", "-1", "+1", "1.0", "1e3", " 1", "1 ", "1\n",
                       "\uff11", "\u0661\u0662", "1000000000000000000", 1, 19.99, None]:
        bad = copy.deepcopy(terms)
        bad["amount_minor"] = bad_amount
        assert _code(validate_payment_terms, bad) == "invalid_terms", repr(bad_amount)
    longest = copy.deepcopy(terms)
    longest["amount_minor"] = "999999999999999999"
    assert validate_payment_terms(longest)["amount_minor"] == "999999999999999999"
    # bool / float / out-of-range integers, padded or surrogate labels, and bad intent ids.
    for path, value in [
        (("funding_source", "version"), True),
        (("payee", "version"), 2.0),
        (("payee", "version"), 2**64),
        (("currency_exponent",), False),
        (("currency_exponent",), 5),
        (("execute_before",), 2**63),
        (("execute_before",), True),
        (("payee", "name"), "Example Books Ltd\u3000"),
        (("payee", "name"), "\u00a0Example"),
        (("payee", "name"), "Example\u0085Books"),
        (("payee", "name"), "Example \ud800"),
        (("payee", "name"), "x" * 129),
        (("currency",), "\uff35SD"),
        (("resource",), "https://"),
        (("resource",), "https://payments.example/" + "a" * 2048),
        (("tenant",), "t" * 257),
        (("payer",), "p\u00e9"),
    ]:
        bad = copy.deepcopy(terms)
        target = bad
        for key in path[:-1]:
            target = target[key]
        target[path[-1]] = value
        assert _code(validate_payment_terms, bad) == "invalid_terms", (path, value)
    assert _code(validate_payment_terms, [terms]) == "invalid_terms"
    assert _code(payment_terms_digest, "pi one", terms) == "invalid_terms"
    assert _code(payment_terms_canonical_bytes, "", terms) == "invalid_terms"
    labelled = copy.deepcopy(terms)
    labelled["payee"]["name"] = "y" * 128
    assert validate_payment_terms(labelled)["payee"]["name"] == "y" * 128
    # Length framing: moving bytes between adjacent fields changes the digest.
    a, b = copy.deepcopy(terms), copy.deepcopy(terms)
    a["client_id"], a["actor"] = "ab", "c"
    b["client_id"], b["actor"] = "a", "bc"
    assert payment_terms_digest(intent_id, a) != payment_terms_digest(intent_id, b)


def test_c14_4_payment_authorization_requires_exactly_the_approved_detail():
    intent_id, terms = _baseline()
    resource, actor = terms["resource"], terms["actor"]
    detail = _detail(intent_id, terms)
    claims = _claims(terms, [detail])
    digest = payment_terms_digest(intent_id, terms)

    def verify(c: dict, **overrides):
        kwargs = {"resource": resource, "intent_id": intent_id, "actor": actor}
        kwargs.update(overrides)
        return verify_payment_authorization(c, **kwargs)

    def rejected(c: dict, **overrides) -> str:
        return _code(verify, c, **overrides)

    def with_claim(**changes) -> dict:
        changed = copy.deepcopy(claims)
        changed.update(changes)
        return changed

    def without_claim(key: str) -> dict:
        changed = copy.deepcopy(claims)
        del changed[key]
        return changed

    result = verify(claims, terms=terms, terms_digest=digest)
    assert isinstance(result, VerifiedPaymentAuthorization)
    assert result.intent_id == intent_id
    assert result.terms == terms
    assert result.terms_digest == digest
    assert result.actor == actor
    assert result.subject == terms["payer"]
    with pytest.raises(TypeError):
        result.terms["amount_minor"] = "1"  # type: ignore[index]
    with pytest.raises(TypeError):
        result.terms["payee"]["name"] = "Mallory"  # type: ignore[index]
    aliased = _claims(terms, [copy.deepcopy(detail)])
    aliased_result = verify(aliased)
    aliased["authorization_details"][0]["terms"]["amount_minor"] = "1"
    assert aliased_result.terms["amount_minor"] == terms["amount_minor"], "result is a copy"
    # JWT claims (no `active`) and a single scope among many are accepted.
    assert verify(without_claim("active")).intent_id == intent_id
    assert verify(with_claim(scope=f"openid {PAYMENT_EXECUTE_SCOPE} payments:prepare")).actor == actor

    # Token state, audience, scope and actor.
    assert rejected(with_claim(active=False)) == "inactive"
    assert rejected(with_claim(active="true")) == "inactive"
    assert rejected([claims]) == "inactive"
    with pytest.raises(TypeError):
        verify(claims, actor=None)
    assert rejected(with_claim(aud=["https://other-payments.example"])) == "audience_mismatch"
    assert rejected(with_claim(aud=resource)) == "audience_mismatch"
    assert rejected(with_claim(aud=[resource, resource])) == "audience_mismatch"
    assert rejected(with_claim(aud=[resource, "https://other.example"])) == "audience_mismatch"
    assert rejected(without_claim("aud")) == "audience_mismatch"
    assert rejected(with_claim(scope="payments:prepare")) == "insufficient_scope"
    assert rejected(with_claim(scope=[PAYMENT_EXECUTE_SCOPE])) == "insufficient_scope"
    assert rejected(without_claim("scope")) == "insufficient_scope"
    assert rejected(without_claim("act")) == "actor_mismatch"
    assert rejected(with_claim(act={"sub": "other-runtime"})) == "actor_mismatch"
    assert rejected(with_claim(act={"sub": actor, "act": {"sub": "hop-1"}})) == "actor_mismatch"
    assert rejected(with_claim(act=actor)) == "actor_mismatch"
    assert rejected(without_claim("sub")) == "payer_mismatch"
    assert rejected(with_claim(sub="another-payer")) == "payer_mismatch"

    # The authorization_details array must be exactly the one canonical payment detail.
    generic = {"type": RAR_TYPE_V1, "locations": [resource]}
    assert rejected(without_claim("authorization_details")) == "missing_payment_authorization"
    assert rejected(with_claim(authorization_details=[])) == "missing_payment_authorization"
    assert rejected(with_claim(authorization_details=[generic])) == "missing_payment_authorization"
    assert rejected(with_claim(authorization_details=detail)) == "malformed_payment_authorization"
    assert rejected(with_claim(authorization_details=None)) == "malformed_payment_authorization"
    assert (
        rejected(with_claim(authorization_details=[detail, generic]))
        == "malformed_payment_authorization"
    )
    assert (
        rejected(with_claim(authorization_details=[generic, detail]))
        == "malformed_payment_authorization"
    )
    assert (
        rejected(with_claim(authorization_details=[detail, copy.deepcopy(detail)]))
        == "malformed_payment_authorization"
    )

    def tampered(mutate) -> dict:
        changed = copy.deepcopy(detail)
        mutate(changed)
        return with_claim(authorization_details=[changed])

    malformed = {
        "extra detail key": lambda d: d.update(max_amount="1"),
        "missing terms_digest": lambda d: d.pop("terms_digest"),
        "extra terms key": lambda d: d["terms"].update(fee_minor="10"),
        "extra funding key": lambda d: d["terms"]["funding_source"].update(
            account_number="4242424242424242"
        ),
        "actions with refund": lambda d: d.update(actions=["execute", "refund"]),
        "transfer action": lambda d: d.update(actions=["transfer"]),
        "other location": lambda d: d.update(locations=["https://other-payments.example"]),
        "two locations": lambda d: d.update(locations=[resource, resource]),
        "string location": lambda d: d.update(locations=resource),
        "bad intent id": lambda d: d.update(intent_id="pi one"),
        "bool version": lambda d: d["terms"]["funding_source"].update(version=True),
        "float amount": lambda d: d["terms"].update(amount_minor=19.99),
    }
    for name, mutate in malformed.items():
        assert rejected(tampered(mutate)) == "malformed_payment_authorization", name
    # Another profile version is not a payment entry of this profile at all.
    next_version = tampered(lambda d: d.update(type="agent_auth_payment_v2"))
    assert rejected(next_version) == "missing_payment_authorization"

    # Tampered amount with the stale digest, and a non-string digest.
    assert rejected(tampered(lambda d: d["terms"].update(amount_minor="1"))) == "digest_mismatch"
    assert rejected(tampered(lambda d: d.update(terms_digest=None))) == "digest_mismatch"

    # Another intent / resource / actor, each with a self-consistent digest.
    other_intent = with_claim(authorization_details=[_detail("pi_other", terms)])
    assert rejected(other_intent) == "intent_mismatch"
    other_resource_terms = dict(copy.deepcopy(terms), resource="https://other-payments.example")
    other_resource = with_claim(authorization_details=[_detail(intent_id, other_resource_terms)])
    assert rejected(other_resource) == "audience_mismatch"
    other_actor_terms = dict(copy.deepcopy(terms), actor="other-runtime")
    other_actor = with_claim(authorization_details=[_detail(intent_id, other_actor_terms)])
    assert rejected(other_actor) == "actor_mismatch"

    # Binding to the stored intent: terms and digest supplied by the resource server.
    changed_terms = dict(copy.deepcopy(terms), amount_minor="2000")
    assert rejected(claims, terms=changed_terms) == "terms_mismatch"
    changed_payee = copy.deepcopy(terms)
    changed_payee["payee"]["version"] += 1
    assert rejected(claims, terms=changed_payee) == "terms_mismatch"
    assert rejected(claims, terms_digest="stale-digest") == "digest_mismatch"
    assert rejected(claims, terms_digest=payment_terms_digest("pi_other", terms)) == "digest_mismatch"
    reissued = with_claim(authorization_details=[_detail(intent_id, changed_terms)])
    assert rejected(reissued, terms=terms) == "terms_mismatch"
    assert rejected(reissued, terms_digest=digest) == "digest_mismatch"
    bool_version = copy.deepcopy(terms)
    bool_version["payee"]["version"] = True
    assert rejected(claims, terms=bool_version) == "terms_mismatch"
    assert rejected(claims, terms={"amount_minor": terms["amount_minor"]}) == "terms_mismatch"


def test_c14_4_generic_rar_enforcement_still_denies_payment_entries():
    intent_id, terms = _baseline()
    resource = terms["resource"]
    detail = _detail(intent_id, terms)
    request = AccessRequest(resource=resource)

    # A payment detail is an unknown type for the generic vocabulary: fail-closed, as before.
    assert not enforce_rar([detail], request).allowed
    # OR semantics: a permissive generic entry next to it still allows on the generic path.
    assert enforce_rar([detail, {"type": RAR_TYPE_V1}], request).allowed
    # Generic semantics are unchanged: a permissive v1 entry and a missing RAR still allow.
    allowed = enforce_rar([{"type": RAR_TYPE_V1}], request)
    assert allowed.allowed and allowed.matched
    missing = enforce_rar(None, request)
    assert missing.allowed and not missing.matched
    # ...which is exactly why payment execution uses its own strict path.
    claims = _claims(terms, [{"type": RAR_TYPE_V1}])
    assert (
        _code(
            verify_payment_authorization,
            claims,
            resource=resource,
            intent_id=intent_id,
            actor=terms["actor"],
        )
        == "missing_payment_authorization"
    )
