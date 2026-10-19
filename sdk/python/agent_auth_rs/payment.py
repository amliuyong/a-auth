"""Agent Auth RS SDK — `agent_auth_payment_v1` single-transaction payment authorization (issue #77).

Normative source: the Rust reference implementation in `crates/payment` (`terms.rs`, `profile.rs`);
`specs/fixtures/agent_auth_payment_v1.json` pins the canonical byte layout for every SDK.

- **Terms digest**: never hashes a JSON serialization. The digest domain is followed by each field in a
  fixed order as `u32_be(len(utf8)) || utf8`; integers use canonical decimal ASCII.
  `terms_digest = base64url_nopad(SHA-256(canonical_bytes))` (43 characters).
- **Execution check**: a dedicated strict path, separate from the generic `enforce_rar`. The whole
  `authorization_details` array must be exactly one canonical payment detail; a missing array, an extra
  generic (`agent_auth_rar_v1`) entry or a second payment entry is rejected. A bare `payments:execute`
  scope never authorizes a payment. Amounts stay decimal strings: no float arithmetic anywhere.

`verify_payment_authorization` consumes claims that the caller has already authenticated (verified JWT
signature/issuer/expiry, or an authenticated online RFC 7662 introspection response, which issue #77
requires before accepting an execution).
"""

from __future__ import annotations

import base64
import hashlib
import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Optional

from .rar import RAR_TYPE_V1

# RFC 9396 `type` of the payment authorization profile.
PAYMENT_RAR_TYPE_V1 = "agent_auth_payment_v1"
# Scope required, together with the payment detail, to execute one intent.
PAYMENT_EXECUTE_SCOPE = "payments:execute"
# Domain separator prepended to the canonical encoding.
PAYMENT_TERMS_DIGEST_DOMAIN = b"agent-auth:payment-terms:v1\x00"

PaymentAuthorizationErrorCode = Literal[
    "inactive",
    "audience_mismatch",
    "insufficient_scope",
    "insufficient_assurance",
    "actor_mismatch",
    "missing_payment_authorization",
    "malformed_payment_authorization",
    "invalid_terms",
    "intent_mismatch",
    "payer_mismatch",
    "terms_mismatch",
    "digest_mismatch",
]

_EXECUTE_ACTION = "execute"
# The payment profile always requires the strong Agent Auth assurance class.
_STRONG_ACR = "urn:agent-auth:assurance:strong"

_MAX_IDENTIFIER_BYTES = 256
_MAX_RESOURCE_BYTES = 2048
_MAX_LABEL_CHARS = 128
_MAX_CURRENCY_EXPONENT = 4
_MAX_U64 = 2**64 - 1
_MAX_I64 = 2**63 - 1
_HTTPS_PREFIX = "https://"

_TERMS_KEYS = frozenset(
    {
        "tenant",
        "payer",
        "client_id",
        "actor",
        "resource",
        "order_id",
        "funding_source",
        "payee",
        "amount_minor",
        "currency",
        "currency_exponent",
        "execute_before",
    }
)
_FUNDING_SOURCE_KEYS = frozenset({"id", "version", "label"})
_PAYEE_KEYS = frozenset({"id", "version", "name"})
_DETAIL_KEYS = frozenset(
    {"type", "locations", "actions", "intent_id", "terms_digest", "terms"}
)

# `^[1-9][0-9]{0,17}$` with ASCII digits only (`\d` would admit non-ASCII digits).
_AMOUNT_MINOR = re.compile(r"[1-9][0-9]{0,17}")
_CURRENCY = re.compile(r"[A-Z]{3}")
# Unicode `White_Space`, i.e. what Rust `str::trim` strips (independent of the Python version).
_UNICODE_WHITE_SPACE = frozenset(
    "\u0009\u000a\u000b\u000c\u000d\u0020\u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


class PaymentAuthorizationError(Exception):
    """A payment execution is not authorized; `code` is one of `PaymentAuthorizationErrorCode`."""

    def __init__(
        self, code: PaymentAuthorizationErrorCode, detail: Optional[str] = None
    ) -> None:
        super().__init__(detail or code)
        self.code: PaymentAuthorizationErrorCode = code
        self.detail = detail or code


@dataclass(frozen=True)
class VerifiedPaymentAuthorization:
    """The exact approved payment the presented authorization covers."""

    intent_id: str
    terms: Mapping[str, Any]  # read-only validated copy (nested objects are read-only too)
    terms_digest: str
    actor: str
    subject: str  # always equal to terms["payer"]


def _invalid(field: str) -> PaymentAuthorizationError:
    return PaymentAuthorizationError("invalid_terms", f"invalid payment terms field: {field}")


def _is_visible_ascii(value: str) -> bool:
    return all("\x21" <= ch <= "\x7e" for ch in value)


def _identifier(value: Any, field: str) -> str:
    # Visible ASCII only, so the code-point count equals the UTF-8 byte count.
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= _MAX_IDENTIFIER_BYTES
        or not _is_visible_ascii(value)
    ):
        raise _invalid(field)
    return str(value)


def _resource(value: Any) -> str:
    if (
        not isinstance(value, str)
        or len(value) > _MAX_RESOURCE_BYTES
        or not value.startswith(_HTTPS_PREFIX)
        or len(value) == len(_HTTPS_PREFIX)
        or not _is_visible_ascii(value)
    ):
        raise _invalid("resource")
    return str(value)


def _label(value: Any, field: str) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= _MAX_LABEL_CHARS:
        raise _invalid(field)
    try:
        value.encode("utf-8")  # rejects lone surrogates, which Rust strings cannot hold
    except UnicodeEncodeError:
        raise _invalid(field) from None
    if value[0] in _UNICODE_WHITE_SPACE or value[-1] in _UNICODE_WHITE_SPACE:
        raise _invalid(field)
    # Rust `char::is_control` == general category Cc: U+0000..U+001F and U+007F..U+009F.
    if any(ord(ch) < 0x20 or 0x7F <= ord(ch) <= 0x9F for ch in value):
        raise _invalid(field)
    return str(value)


def _integer(value: Any, field: str, minimum: int, maximum: int) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not minimum <= value <= maximum
    ):
        raise _invalid(field)
    return int(value)


def _exact_object(value: Any, keys: frozenset, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value.keys()) != keys:
        raise _invalid(field)
    return value


def validate_payment_terms(value: object) -> dict:
    """Validate `value` against the v1 terms rules and return a validated plain-dict copy.

    Raises `PaymentAuthorizationError("invalid_terms")` on any unknown/missing member or bad value.
    """
    terms = _exact_object(value, _TERMS_KEYS, "terms")
    funding = _exact_object(terms["funding_source"], _FUNDING_SOURCE_KEYS, "funding_source")
    payee = _exact_object(terms["payee"], _PAYEE_KEYS, "payee")
    amount = terms["amount_minor"]
    if not isinstance(amount, str) or _AMOUNT_MINOR.fullmatch(amount) is None:
        raise _invalid("amount_minor")
    currency = terms["currency"]
    if not isinstance(currency, str) or _CURRENCY.fullmatch(currency) is None:
        raise _invalid("currency")
    return {
        "tenant": _identifier(terms["tenant"], "tenant"),
        "payer": _identifier(terms["payer"], "payer"),
        "client_id": _identifier(terms["client_id"], "client_id"),
        "actor": _identifier(terms["actor"], "actor"),
        "resource": _resource(terms["resource"]),
        "order_id": _identifier(terms["order_id"], "order_id"),
        "funding_source": {
            "id": _identifier(funding["id"], "funding_source.id"),
            "version": _integer(funding["version"], "funding_source.version", 1, _MAX_U64),
            "label": _label(funding["label"], "funding_source.label"),
        },
        "payee": {
            "id": _identifier(payee["id"], "payee.id"),
            "version": _integer(payee["version"], "payee.version", 1, _MAX_U64),
            "name": _label(payee["name"], "payee.name"),
        },
        "amount_minor": str(amount),
        "currency": str(currency),
        "currency_exponent": _integer(
            terms["currency_exponent"], "currency_exponent", 0, _MAX_CURRENCY_EXPONENT
        ),
        "execute_before": _integer(terms["execute_before"], "execute_before", 1, _MAX_I64),
    }


def _canonical_bytes(intent_id: str, terms: Mapping[str, Any]) -> bytes:
    """Encode already-validated terms (see `validate_payment_terms`)."""
    funding = terms["funding_source"]
    payee = terms["payee"]
    fields = (
        PAYMENT_RAR_TYPE_V1,
        intent_id,
        terms["tenant"],
        terms["payer"],
        terms["client_id"],
        terms["actor"],
        terms["resource"],
        terms["order_id"],
        funding["id"],
        str(funding["version"]),
        funding["label"],
        payee["id"],
        str(payee["version"]),
        payee["name"],
        terms["amount_minor"],
        terms["currency"],
        str(terms["currency_exponent"]),
        str(terms["execute_before"]),
    )
    out = bytearray(PAYMENT_TERMS_DIGEST_DOMAIN)
    for field in fields:
        encoded = field.encode("utf-8")
        out += struct.pack(">I", len(encoded))
        out += encoded
    return bytes(out)


def _digest(intent_id: str, terms: Mapping[str, Any]) -> str:
    raw = hashlib.sha256(_canonical_bytes(intent_id, terms)).digest()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def payment_terms_canonical_bytes(intent_id: str, terms: Mapping) -> bytes:
    """Canonical v1 bytes for `intent_id` and `terms` (both validated first; `invalid_terms` on failure)."""
    validated = validate_payment_terms(terms)
    return _canonical_bytes(_identifier(intent_id, "intent_id"), validated)


def payment_terms_digest(intent_id: str, terms: Mapping) -> str:
    """`base64url_nopad(SHA-256(canonical_bytes))`, 43 characters."""
    validated = validate_payment_terms(terms)
    return _digest(_identifier(intent_id, "intent_id"), validated)


def _freeze_terms(terms: Mapping[str, Any]) -> Mapping[str, Any]:
    frozen = dict(terms)
    frozen["funding_source"] = MappingProxyType(dict(terms["funding_source"]))
    frozen["payee"] = MappingProxyType(dict(terms["payee"]))
    return MappingProxyType(frozen)


def _is_json_array(value: Any) -> bool:
    return isinstance(value, (list, tuple))


def _is_exact_string_list(value: Any, expected: str) -> bool:
    return (
        _is_json_array(value)
        and len(value) == 1
        and isinstance(value[0], str)
        and value[0] == expected
    )


def _is_payment_detail(detail: Any) -> bool:
    return isinstance(detail, Mapping) and detail.get("type") == PAYMENT_RAR_TYPE_V1


def _malformed(reason: str) -> PaymentAuthorizationError:
    return PaymentAuthorizationError(
        "malformed_payment_authorization", f"malformed payment authorization: {reason}"
    )


def _parse_canonical_detail(detail: Any) -> tuple[str, dict, str]:
    """Strictly parse the one canonical detail; returns (intent_id, validated terms, digest)."""
    if not isinstance(detail, Mapping):
        raise _malformed("entry is not an object")
    if set(detail.keys()) != _DETAIL_KEYS:
        raise _malformed("detail members are not exactly the canonical set")
    if not isinstance(detail["type"], str) or detail["type"] != PAYMENT_RAR_TYPE_V1:
        raise _malformed("bad type")
    try:
        intent_id = _identifier(detail["intent_id"], "intent_id")
        terms = validate_payment_terms(detail["terms"])
    except PaymentAuthorizationError:
        raise _malformed("bad intent_id or terms") from None
    if not _is_exact_string_list(detail["locations"], terms["resource"]):
        raise _malformed("locations must be exactly [terms.resource]")
    if not _is_exact_string_list(detail["actions"], _EXECUTE_ACTION):
        raise _malformed('actions must be exactly ["execute"]')
    digest = _digest(intent_id, terms)
    claimed = detail["terms_digest"]
    if not isinstance(claimed, str) or claimed != digest:
        raise PaymentAuthorizationError(
            "digest_mismatch", "terms_digest does not match the recomputed digest"
        )
    return intent_id, terms, digest


def _same_terms(actual: dict, expected: Any) -> bool:
    """Expected terms that are not valid v1 terms can never match (no lenient 2 == 2.0 / True == 1)."""
    try:
        return validate_payment_terms(expected) == actual
    except PaymentAuthorizationError:
        return False


def verify_payment_authorization(
    claims: Mapping,
    *,
    resource: str,
    intent_id: str,
    actor: str,
    terms: Optional[Mapping] = None,
    terms_digest: Optional[str] = None,
) -> VerifiedPaymentAuthorization:
    """Payment-specific authorization check performed before accepting one execution.

    `claims` must be an authenticated online RFC 7662 introspection response (no result cache);
    offline JWT claims are rejected. `resource` is this payment resource server's audience,
    `intent_id` the intent being executed, `actor` the workload that must execute it. The stored
    intent's `terms` and/or `terms_digest` are required to bind the token to the frozen intent.
    Raises `PaymentAuthorizationError` on any mismatch; never fall back to `enforce_rar`.
    """
    if not all(isinstance(value, str) for value in (resource, intent_id, actor)):
        raise TypeError("resource, intent_id and actor must be strings")
    if terms is None and terms_digest is None:
        raise TypeError("pass the persisted intent's terms or terms_digest")
    # Only an online introspection result that says exactly `active: true` is accepted.
    if not isinstance(claims, Mapping) or claims.get("active") is not True:
        raise PaymentAuthorizationError(
            "inactive", "an active online introspection result is required"
        )

    audience = claims.get("aud")
    if not _is_exact_string_list(audience, resource):
        raise PaymentAuthorizationError(
            "audience_mismatch", "aud must be exactly [resource]"
        )

    scope = claims.get("scope")
    if not isinstance(scope, str) or PAYMENT_EXECUTE_SCOPE not in scope.split(" "):
        raise PaymentAuthorizationError(
            "insufficient_scope", f"scope {PAYMENT_EXECUTE_SCOPE} is required"
        )

    if claims.get("acr") != _STRONG_ACR:
        raise PaymentAuthorizationError(
            "insufficient_assurance", "payment authorization requires strong assurance"
        )

    act = claims.get("act")
    if (
        not isinstance(act, Mapping)
        or not isinstance(act.get("sub"), str)
        or act.get("sub") != actor
        or "act" in act
    ):
        raise PaymentAuthorizationError(
            "actor_mismatch", "act.sub must be the designated actor (single delegation hop)"
        )

    # Absent → missing; present but not an array (including JSON null) → malformed (as in Rust).
    if "authorization_details" not in claims:
        raise PaymentAuthorizationError(
            "missing_payment_authorization", "no authorization_details"
        )
    details = claims["authorization_details"]
    if not _is_json_array(details):
        raise _malformed("authorization_details is not an array")
    if not any(_is_payment_detail(entry) for entry in details):
        raise PaymentAuthorizationError(
            "missing_payment_authorization",
            f"no {PAYMENT_RAR_TYPE_V1} entry (a generic {RAR_TYPE_V1} entry never authorizes payment)",
        )
    if len(details) != 1:
        raise _malformed("authorization_details must contain exactly one entry")
    detail_intent, detail_terms, digest = _parse_canonical_detail(details[0])

    if detail_intent != intent_id:
        raise PaymentAuthorizationError("intent_mismatch", "authorization is for another intent")
    if detail_terms["resource"] != resource:
        raise PaymentAuthorizationError(
            "audience_mismatch", "terms.resource is not this resource"
        )
    if detail_terms["actor"] != actor:
        raise PaymentAuthorizationError("actor_mismatch", "terms.actor is not the executing actor")
    subject = claims.get("sub")
    if not isinstance(subject, str) or subject != detail_terms["payer"]:
        raise PaymentAuthorizationError(
            "payer_mismatch", "token subject is not the payer of these terms"
        )
    if terms is not None and not _same_terms(detail_terms, terms):
        raise PaymentAuthorizationError(
            "terms_mismatch", "authorized terms differ from the frozen intent"
        )
    if terms_digest is not None and terms_digest != digest:
        raise PaymentAuthorizationError(
            "digest_mismatch", "terms_digest differs from the frozen intent"
        )

    return VerifiedPaymentAuthorization(
        intent_id=detail_intent,
        terms=_freeze_terms(detail_terms),
        terms_digest=digest,
        actor=detail_terms["actor"],
        subject=subject,
    )
