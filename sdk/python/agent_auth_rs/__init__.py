"""Agent Auth RS 校验 SDK(spec 010 P1b)—— MCP 资源服务器侧 access token 校验。

决策真相源:docs/DESIGN §6/§2 / CONFORMANCE C8.2/C8.3/C8.4/C8.8。RS 侧只消费/校验,不派生 sub。
"""

from .types import (
    NAMESPACE,
    AuthResult,
    Jwk,
    RarPolicy,
    RoutePolicy,
    RsSdkConfig,
    ScopeImplications,
    ScopeResolver,
    VerifiedToken,
    VerifyError,
)
from .sdk import RsSdk
from .authorization import (
    create_scope_resolver,
    derive_resource_metadata_url,
    normalize_resource_id,
    validate_resource_metadata_url,
    validate_scope_token,
)
from .introspection import (
    IntrospectionClient,
    IntrospectionConfig,
    IntrospectionResult,
)
from .rar import (
    AccessRequest,
    RarResult,
    RAR_TYPE_V1,
    PolicyDecision,
    PolicyEvaluator,
    enforce_rar,
    extract_authorization_details,
)
from .dpop import (
    DPoPResult,
    verify_dpop_proof,
    compute_jkt,
    compute_ath,
    normalize_htu,
)

__all__ = [
    "NAMESPACE",
    "AuthResult",
    "Jwk",
    "RarPolicy",
    "RoutePolicy",
    "RsSdkConfig",
    "ScopeImplications",
    "ScopeResolver",
    "VerifiedToken",
    "VerifyError",
    "RsSdk",
    "create_scope_resolver",
    "derive_resource_metadata_url",
    "normalize_resource_id",
    "validate_resource_metadata_url",
    "validate_scope_token",
    "IntrospectionClient",
    "IntrospectionConfig",
    "IntrospectionResult",
    "AccessRequest",
    "RarResult",
    "RAR_TYPE_V1",
    "PolicyDecision",
    "PolicyEvaluator",
    "enforce_rar",
    "extract_authorization_details",
    "DPoPResult",
    "verify_dpop_proof",
    "compute_jkt",
    "compute_ath",
    "normalize_htu",
]
