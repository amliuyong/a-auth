// Issue #77 / CONFORMANCE C14: strict agent_auth_payment_v1 verification in the TS RS SDK.
// Source of truth: crates/payment/src/{terms.rs,profile.rs}; vectors: specs/fixtures/agent_auth_payment_v1.json.

import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  PAYMENT_EXECUTE_SCOPE,
  PAYMENT_RAR_TYPE_V1,
  PAYMENT_TERMS_DIGEST_DOMAIN,
  PaymentAuthorizationError,
  RAR_TYPE_V1,
  enforceRar,
  paymentTermsCanonicalBytes,
  paymentTermsDigest,
  validatePaymentTerms,
  verifyPaymentAuthorization,
  type PaymentExpectation,
  type PaymentTerms,
} from "../src/index.js";

interface VectorCase {
  name: string;
  intent_id: string;
  terms: PaymentTerms;
  canonical_hex: string;
  terms_digest: string;
}

interface VectorFile {
  profile: string;
  digest_domain_hex: string;
  valid: VectorCase[];
  invalid_terms: { name: string; intent_id: string; terms: unknown }[];
}

const vectors = JSON.parse(
  readFileSync(
    new URL("../../../specs/fixtures/agent_auth_payment_v1.json", import.meta.url),
    "utf8",
  ),
) as VectorFile;

const hex = (bytes: Uint8Array): string => Buffer.from(bytes).toString("hex");

function errorCode(fn: () => unknown): string {
  try {
    fn();
  } catch (err) {
    if (err instanceof PaymentAuthorizationError) return err.code;
    throw err;
  }
  return "accepted";
}

const baseline = vectors.valid[0] as VectorCase;
const terms = baseline.terms;
const resource = terms.resource;
const intentId = baseline.intent_id;

type Detail = Record<string, unknown>;

function canonicalDetail(id: string, t: PaymentTerms): Detail {
  return {
    type: PAYMENT_RAR_TYPE_V1,
    locations: [t.resource],
    actions: ["execute"],
    intent_id: id,
    terms_digest: paymentTermsDigest(id, t),
    terms: structuredClone(t),
  };
}

const detail: Detail = {
  type: PAYMENT_RAR_TYPE_V1,
  locations: [resource],
  actions: ["execute"],
  intent_id: intentId,
  terms_digest: baseline.terms_digest,
  terms: structuredClone(terms),
};

function claimsWith(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const claims: Record<string, unknown> = {
    active: true,
    aud: [resource],
    scope: PAYMENT_EXECUTE_SCOPE,
    act: { sub: terms.actor },
    sub: terms.payer,
    authorization_details: [structuredClone(detail)],
    ...overrides,
  };
  for (const [key, value] of Object.entries(overrides)) {
    if (value === undefined) delete claims[key];
  }
  return claims;
}

const expected: PaymentExpectation = { resource, intentId, actor: terms.actor };

describe("agent_auth_payment_v1 terms", () => {
  it("c14_1_payment_terms_vectors_match_canonical_encoding", () => {
    expect(vectors.profile).toBe(PAYMENT_RAR_TYPE_V1);
    expect(hex(PAYMENT_TERMS_DIGEST_DOMAIN)).toBe(vectors.digest_domain_hex);
    expect(vectors.valid.length).toBeGreaterThanOrEqual(3);
    for (const vector of vectors.valid) {
      const validated = validatePaymentTerms(vector.terms);
      expect(validated, vector.name).toEqual(vector.terms);
      expect(Object.isFrozen(validated)).toBe(true);
      expect(Object.isFrozen(validated.funding_source)).toBe(true);
      expect(Object.isFrozen(validated.payee)).toBe(true);
      expect(hex(paymentTermsCanonicalBytes(vector.intent_id, vector.terms)), vector.name).toBe(
        vector.canonical_hex,
      );
      const digest = paymentTermsDigest(vector.intent_id, vector.terms);
      expect(digest, vector.name).toBe(vector.terms_digest);
      expect(digest).toHaveLength(43);
    }

    expect(vectors.invalid_terms.length).toBeGreaterThan(0);
    for (const vector of vectors.invalid_terms) {
      expect(errorCode(() => validatePaymentTerms(vector.terms)), vector.name).toBe(
        "invalid_terms",
      );
      expect(
        errorCode(() => paymentTermsDigest(vector.intent_id, vector.terms as PaymentTerms)),
        vector.name,
      ).toBe("invalid_terms");
    }

    // JSON member order never changes the digest; the intent id is bound.
    const reordered = JSON.parse(
      JSON.stringify({
        execute_before: terms.execute_before,
        currency_exponent: terms.currency_exponent,
        currency: terms.currency,
        amount_minor: terms.amount_minor,
        payee: { name: terms.payee.name, version: terms.payee.version, id: terms.payee.id },
        funding_source: {
          label: terms.funding_source.label,
          version: terms.funding_source.version,
          id: terms.funding_source.id,
        },
        order_id: terms.order_id,
        resource: terms.resource,
        actor: terms.actor,
        client_id: terms.client_id,
        payer: terms.payer,
        tenant: terms.tenant,
      }),
    ) as PaymentTerms;
    expect(paymentTermsDigest(intentId, reordered)).toBe(baseline.terms_digest);
    expect(paymentTermsDigest("pi_other", terms)).not.toBe(baseline.terms_digest);
    expect(errorCode(() => paymentTermsDigest("pi one", terms))).toBe("invalid_terms");

    // Mutating the exported domain constant cannot change digests.
    const exported = PAYMENT_TERMS_DIGEST_DOMAIN[0] as number;
    PAYMENT_TERMS_DIGEST_DOMAIN[0] = 0;
    try {
      expect(paymentTermsDigest(intentId, terms)).toBe(baseline.terms_digest);
    } finally {
      PAYMENT_TERMS_DIGEST_DOMAIN[0] = exported;
    }

    // Label rules follow Rust char::is_control / str::trim (Unicode White_Space), not JS trim().
    const withPayeeName = (name: string) => ({ ...terms, payee: { ...terms.payee, name } });
    expect(errorCode(() => validatePaymentTerms(withPayeeName("\uFEFFExample")))).toBe("accepted");
    expect(errorCode(() => validatePaymentTerms(withPayeeName("\u200BExample")))).toBe("accepted");
    expect(errorCode(() => validatePaymentTerms(withPayeeName("\u00A0Example")))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms(withPayeeName("Example\u3000")))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms(withPayeeName("Ex\u007Fample")))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms(withPayeeName("Example \uD800")))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms(withPayeeName("\u{1F600}".repeat(128))))).toBe(
      "accepted",
    );
    expect(errorCode(() => validatePaymentTerms(withPayeeName("a".repeat(129))))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms({ ...terms, execute_before: true }))).toBe(
      "invalid_terms",
    );
    expect(errorCode(() => validatePaymentTerms({ ...terms, currency_exponent: -0 }))).toBe(
      "invalid_terms",
    );
  });
});

describe("verifyPaymentAuthorization", () => {
  it("c14_4_payment_authorization_requires_exactly_the_approved_detail", () => {
    const verified = verifyPaymentAuthorization(claimsWith(), {
      ...expected,
      terms,
      termsDigest: baseline.terms_digest,
    });
    expect(verified).toEqual({
      intentId,
      terms,
      termsDigest: baseline.terms_digest,
      actor: terms.actor,
      subject: terms.payer,
    });
    expect(Object.isFrozen(verified)).toBe(true);
    expect(Object.isFrozen(verified.terms)).toBe(true);
    // Verified JWT claims carry no `active`; scope may hold other tokens.
    const jwtLike = verifyPaymentAuthorization(
      claimsWith({ active: undefined, scope: `payments:prepare ${PAYMENT_EXECUTE_SCOPE}` }),
      expected,
    );
    expect(jwtLike.subject).toBe(terms.payer);

    const verify = (claims: Record<string, unknown>, exp: PaymentExpectation = expected) =>
      errorCode(() => verifyPaymentAuthorization(claims, exp));
    const withDetail = (entry: unknown) => claimsWith({ authorization_details: [entry] });

    // 1. active
    expect(verify(claimsWith({ active: false }))).toBe("inactive");
    expect(verify(claimsWith({ active: "true" }))).toBe("inactive");

    // 2. audience
    expect(verify(claimsWith({ aud: ["https://other-payments.example"] }))).toBe(
      "audience_mismatch",
    );
    expect(verify(claimsWith({ aud: resource }))).toBe("audience_mismatch");
    expect(verify(claimsWith({ aud: [resource, "https://other-payments.example"] }))).toBe(
      "audience_mismatch",
    );
    expect(verify(claimsWith({ aud: undefined }))).toBe("audience_mismatch");

    // 3. scope
    expect(verify(claimsWith({ scope: "payments:prepare" }))).toBe("insufficient_scope");
    expect(verify(claimsWith({ scope: undefined }))).toBe("insufficient_scope");
    expect(verify(claimsWith({ scope: "payments:executeX" }))).toBe("insufficient_scope");
    expect(verify(claimsWith({ scope: [PAYMENT_EXECUTE_SCOPE] }))).toBe("insufficient_scope");

    // 4. single-hop actor
    expect(verify(claimsWith({ act: undefined }))).toBe("actor_mismatch");
    expect(verify(claimsWith({ act: { sub: "other-runtime" } }))).toBe("actor_mismatch");
    expect(
      verify(claimsWith({ act: { sub: terms.actor, act: { sub: "upstream-runtime" } } })),
    ).toBe("actor_mismatch");

    // The token subject must be the payer frozen into the terms.
    expect(verify(claimsWith({ sub: undefined }))).toBe("payer_mismatch");
    expect(verify(claimsWith({ sub: "another-payer" }))).toBe("payer_mismatch");

    // 5. exactly one canonical payment detail in the whole array
    expect(verify(claimsWith({ authorization_details: undefined }))).toBe(
      "missing_payment_authorization",
    );
    expect(verify(claimsWith({ authorization_details: [] }))).toBe(
      "missing_payment_authorization",
    );
    expect(verify(withDetail({ type: RAR_TYPE_V1, locations: [resource] }))).toBe(
      "missing_payment_authorization",
    );
    expect(
      verify(
        claimsWith({
          authorization_details: [structuredClone(detail), { type: RAR_TYPE_V1, locations: [resource] }],
        }),
      ),
    ).toBe("malformed_payment_authorization");
    expect(
      verify(claimsWith({ authorization_details: [structuredClone(detail), structuredClone(detail)] })),
    ).toBe("malformed_payment_authorization");
    expect(verify(claimsWith({ authorization_details: structuredClone(detail) }))).toBe(
      "malformed_payment_authorization",
    );
    expect(verify(withDetail({ ...structuredClone(detail), max_amount: "1" }))).toBe(
      "malformed_payment_authorization",
    );
    const { terms_digest: _omitted, ...withoutDigest } = structuredClone(detail);
    expect(verify(withDetail(withoutDigest))).toBe("malformed_payment_authorization");
    expect(
      verify(withDetail({ ...structuredClone(detail), terms: { ...terms, fee_minor: "10" } })),
    ).toBe("malformed_payment_authorization");
    expect(verify(withDetail({ ...structuredClone(detail), actions: ["execute", "refund"] }))).toBe(
      "malformed_payment_authorization",
    );
    expect(
      verify(withDetail({ ...structuredClone(detail), locations: ["https://other-payments.example"] })),
    ).toBe("malformed_payment_authorization");
    expect(verify(withDetail({ ...structuredClone(detail), type: "agent_auth_payment_v2" }))).toBe(
      "missing_payment_authorization",
    );
    expect(
      verify(withDetail({ ...structuredClone(detail), terms: { ...terms, amount_minor: "1" } })),
    ).toBe("digest_mismatch");

    // 6. bound to this execution
    expect(verify(withDetail(canonicalDetail("pi_other_intent", terms)))).toBe("intent_mismatch");
    expect(
      verify(withDetail(canonicalDetail(intentId, { ...terms, resource: "https://other-payments.example" }))),
    ).toBe("audience_mismatch");
    expect(verify(withDetail(canonicalDetail(intentId, { ...terms, actor: "other-runtime" })))).toBe(
      "actor_mismatch",
    );
    expect(verify(claimsWith(), { ...expected, terms: { ...terms, amount_minor: "2000" } })).toBe(
      "terms_mismatch",
    );
    expect(
      verify(claimsWith(), {
        ...expected,
        terms: { ...terms, payee: { ...terms.payee, version: terms.payee.version + 1 } },
      }),
    ).toBe("terms_mismatch");
    expect(
      verify(claimsWith(), { ...expected, terms: { ...terms, fee_minor: "10" } as PaymentTerms }),
    ).toBe("terms_mismatch");
    expect(verify(claimsWith(), { ...expected, termsDigest: "stale-digest" })).toBe(
      "digest_mismatch",
    );
  });

  it("c14_4_generic_rar_enforcement_still_denies_payment_entries", () => {
    // The generic path treats a payment entry as an unknown type and fails closed ...
    const generic = enforceRar([structuredClone(detail)], { resource });
    expect(generic.allowed).toBe(false);
    expect(generic.matched).toBe(true);
    // ... while its own semantics are unchanged: a permissive generic entry still allows.
    expect(enforceRar([{ type: RAR_TYPE_V1 }], { resource }).allowed).toBe(true);
    // That permissive generic entry is never a payment authorization on the strict path.
    expect(
      errorCode(() =>
        verifyPaymentAuthorization(
          claimsWith({ authorization_details: [{ type: RAR_TYPE_V1 }] }),
          expected,
        ),
      ),
    ).toBe("missing_payment_authorization");
  });
});
