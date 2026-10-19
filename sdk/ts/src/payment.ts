// Agent Auth RS SDK — strict `agent_auth_payment_v1` execution check (issue #77).
//
// Source of truth: crates/payment/src/{terms.rs,profile.rs}. Cross-language vectors:
// specs/fixtures/agent_auth_payment_v1.json.
//
// Payment execution does NOT reuse the generic RAR semantics of `enforceRar` (missing RAR falls
// back to scope, any applicable entry may allow, unknown types are evaluator-delegated). For the
// generic path a payment entry is just an unknown type and is always denied without an evaluator.
// A payment resource server instead calls `verifyPaymentAuthorization`, which requires:
//
// - the token to be active, for exactly this audience, with the `payments:execute` scope;
// - a single delegation hop whose `act.sub` is the one actor frozen into the terms;
// - the WHOLE `authorization_details` array to be exactly one canonical payment detail with exact
//   member sets, `locations == [terms.resource]`, `actions == ["execute"]` and a recomputed digest.
//
// Callers MUST obtain `claims` from online introspection (`IntrospectionClient` with
// `cacheTtlSecs: 0`) so revocation is honoured at execution time, and MUST NOT fall back to
// `enforceRar` when this function throws.
//
// The terms digest never hashes JSON: every field is written in a fixed order as
// `u32_be(len(utf8)) || utf8` after a domain separator, integers as canonical decimal ASCII.
// Amounts stay decimal strings end to end; no floating-point arithmetic touches them.

import { createHash } from "node:crypto";

/** RFC 9396 `type` of the payment authorization profile. */
export const PAYMENT_RAR_TYPE_V1 = "agent_auth_payment_v1";
/** Scope required, together with the payment detail, to execute one intent. */
export const PAYMENT_EXECUTE_SCOPE = "payments:execute";

const PAYMENT_EXECUTE_ACTION = "execute";
const DOMAIN_TEXT = "agent-auth:payment-terms:v1\0";

/**
 * Domain separator prepended to the canonical encoding (`agent-auth:payment-terms:v1\0`).
 * Typed arrays cannot be frozen, so the encoder uses a private copy: mutating this export never
 * changes a digest.
 */
export const PAYMENT_TERMS_DIGEST_DOMAIN: Uint8Array = new TextEncoder().encode(DOMAIN_TEXT);
const DOMAIN_BYTES: Uint8Array = new TextEncoder().encode(DOMAIN_TEXT);

const MAX_IDENTIFIER_BYTES = 256;
const MAX_RESOURCE_BYTES = 2048;
const MAX_LABEL_CHARS = 128;
const MAX_CURRENCY_EXPONENT = 4;
const HTTPS_PREFIX = "https://";
const AMOUNT_MINOR = /^[1-9][0-9]{0,17}$/;
const CURRENCY_CODE = /^[A-Z]{3}$/;

const TERMS_KEYS = [
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
] as const;
const FUNDING_SOURCE_KEYS = ["id", "version", "label"] as const;
const PAYEE_KEYS = ["id", "version", "name"] as const;
const DETAIL_KEYS = [
  "type",
  "locations",
  "actions",
  "intent_id",
  "terms_digest",
  "terms",
] as const;

/** Trusted funding-source reference frozen into the intent. */
export interface PaymentFundingSourceRef {
  id: string;
  version: number;
  /** Registry display label (for example a masked account); never a full account number. */
  label: string;
}

/** Trusted payee reference frozen into the intent. */
export interface PaymentPayeeRef {
  id: string;
  version: number;
  /** Registry display name; never taken from the agent request. */
  name: string;
}

/** The complete set of facts a user approves for one payment. */
export interface PaymentTerms {
  tenant: string;
  /** Payer subject as seen by the payment resource (`sub` for that audience). */
  payer: string;
  /** Initiating 3LO client. */
  client_id: string;
  /** The only workload allowed to execute. */
  actor: string;
  /** Payment resource server audience. */
  resource: string;
  order_id: string;
  funding_source: PaymentFundingSourceRef;
  payee: PaymentPayeeRef;
  /** Total amount in minor units as a canonical positive decimal string (`^[1-9][0-9]{0,17}$`). */
  amount_minor: string;
  currency: string;
  currency_exponent: number;
  /** Latest first-acceptance instant (Unix seconds, exclusive). */
  execute_before: number;
}

export type PaymentAuthorizationErrorCode =
  | "inactive"
  | "audience_mismatch"
  | "insufficient_scope"
  | "actor_mismatch"
  | "missing_payment_authorization"
  | "malformed_payment_authorization"
  | "invalid_terms"
  | "intent_mismatch"
  | "payer_mismatch"
  | "terms_mismatch"
  | "digest_mismatch";

/** Fail-closed rejection. Messages name fields only and never echo payment values. */
export class PaymentAuthorizationError extends Error {
  readonly code: PaymentAuthorizationErrorCode;

  constructor(code: PaymentAuthorizationErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = "PaymentAuthorizationError";
    this.code = code;
  }
}

/** What the payment resource expects for one execution. */
export interface PaymentExpectation {
  /** This payment resource server's audience. */
  resource: string;
  /** The intent being executed (from the request path). */
  intentId: string;
  /** The workload executing (must equal `act.sub` and `terms.actor`). */
  actor: string;
  /** The persisted frozen terms; when given every field must be equal. */
  terms?: PaymentTerms;
  /** The persisted terms digest; when given it must be equal. */
  termsDigest?: string;
}

/** The exact approved authorization carried by the token (frozen). */
export interface VerifiedPaymentAuthorization {
  intentId: string;
  terms: PaymentTerms;
  termsDigest: string;
  actor: string;
  /** Token subject; always equal to `terms.payer`. */
  subject: string;
}

type JsonObject = Record<string, unknown>;

function isPlainRecord(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasOwn(value: object, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

/** Own property only (never inherited / prototype-polluted values). */
function own(value: JsonObject, key: string): unknown {
  return hasOwn(value, key) ? value[key] : undefined;
}

/** `value` as an object with exactly `keys` as own members, else null. */
function exactObject(value: unknown, keys: readonly string[]): JsonObject | null {
  if (!isPlainRecord(value)) return null;
  const present = Object.keys(value);
  if (present.length !== keys.length) return null;
  for (const key of present) {
    if (!keys.includes(key)) return null;
  }
  return value;
}

function invalidTerms(field: string): never {
  throw new PaymentAuthorizationError("invalid_terms", `invalid payment terms field: ${field}`);
}

function isPrintableAscii(value: string): boolean {
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code < 0x21 || code > 0x7e) return false;
  }
  return true;
}

/** 1..=256 bytes, every byte in 0x21..=0x7E (ASCII only, so UTF-16 length == byte length). */
function isIdentifier(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= MAX_IDENTIFIER_BYTES &&
    isPrintableAscii(value)
  );
}

function identifier(value: unknown, field: string): string {
  if (!isIdentifier(value)) invalidTerms(field);
  return value;
}

function resource(value: unknown): string {
  if (
    typeof value !== "string" ||
    value.length > MAX_RESOURCE_BYTES ||
    !value.startsWith(HTTPS_PREFIX) ||
    value.length === HTTPS_PREFIX.length ||
    !isPrintableAscii(value)
  ) {
    invalidTerms("resource");
  }
  return value;
}

/** Unicode general category Cc (Rust `char::is_control`). */
function isControl(codePoint: number): boolean {
  return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
}

/**
 * Unicode `White_Space` (Rust `char::is_whitespace`, used by `str::trim`). Deliberately not JS
 * `String.prototype.trim`, which also strips U+FEFF and would reject labels Rust accepts.
 */
function isWhiteSpace(codePoint: number): boolean {
  return (
    (codePoint >= 0x09 && codePoint <= 0x0d) ||
    codePoint === 0x20 ||
    codePoint === 0x85 ||
    codePoint === 0xa0 ||
    codePoint === 0x1680 ||
    (codePoint >= 0x2000 && codePoint <= 0x200a) ||
    codePoint === 0x2028 ||
    codePoint === 0x2029 ||
    codePoint === 0x202f ||
    codePoint === 0x205f ||
    codePoint === 0x3000
  );
}

/** 1..=128 Unicode scalar values, no Cc, no leading/trailing White_Space, no lone surrogate. */
function label(value: unknown, field: string): string {
  if (typeof value !== "string" || value.length === 0) invalidTerms(field);
  let count = 0;
  let first = -1;
  let last = -1;
  for (const char of value) {
    const codePoint = char.codePointAt(0) as number;
    // for..of yields well-formed pairs as one code point, so any surrogate here is unpaired and
    // would not survive UTF-8 encoding unchanged.
    if ((codePoint >= 0xd800 && codePoint <= 0xdfff) || isControl(codePoint)) {
      invalidTerms(field);
    }
    if (first === -1) first = codePoint;
    last = codePoint;
    count += 1;
    if (count > MAX_LABEL_CHARS) invalidTerms(field);
  }
  if (isWhiteSpace(first) || isWhiteSpace(last)) invalidTerms(field);
  return value;
}

function version(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) {
    invalidTerms(field);
  }
  return value;
}

function freezeTerms(terms: PaymentTerms): PaymentTerms {
  Object.freeze(terms.funding_source);
  Object.freeze(terms.payee);
  return Object.freeze(terms);
}

/**
 * Validate a terms object against the v1 value rules and return a frozen copy.
 *
 * Exactly the 12 members (and the exact nested member sets) are accepted; numbers must be JSON
 * numbers and strings JSON strings. Throws `PaymentAuthorizationError("invalid_terms")`.
 */
export function validatePaymentTerms(value: unknown): PaymentTerms {
  const terms = exactObject(value, TERMS_KEYS);
  if (terms === null) invalidTerms("terms");
  const fundingSource = exactObject(terms.funding_source, FUNDING_SOURCE_KEYS);
  if (fundingSource === null) invalidTerms("funding_source");
  const payee = exactObject(terms.payee, PAYEE_KEYS);
  if (payee === null) invalidTerms("payee");

  const validated: PaymentTerms = {
    tenant: identifier(terms.tenant, "tenant"),
    payer: identifier(terms.payer, "payer"),
    client_id: identifier(terms.client_id, "client_id"),
    actor: identifier(terms.actor, "actor"),
    resource: resource(terms.resource),
    order_id: identifier(terms.order_id, "order_id"),
    funding_source: {
      id: identifier(fundingSource.id, "funding_source.id"),
      version: version(fundingSource.version, "funding_source.version"),
      label: label(fundingSource.label, "funding_source.label"),
    },
    payee: {
      id: identifier(payee.id, "payee.id"),
      version: version(payee.version, "payee.version"),
      name: label(payee.name, "payee.name"),
    },
    amount_minor: "",
    currency: "",
    currency_exponent: 0,
    execute_before: 0,
  };

  const amount = terms.amount_minor;
  if (typeof amount !== "string" || !AMOUNT_MINOR.test(amount)) invalidTerms("amount_minor");
  validated.amount_minor = amount;

  const currency = terms.currency;
  if (typeof currency !== "string" || !CURRENCY_CODE.test(currency)) invalidTerms("currency");
  validated.currency = currency;

  const exponent = terms.currency_exponent;
  if (
    typeof exponent !== "number" ||
    !Number.isInteger(exponent) ||
    Object.is(exponent, -0) ||
    exponent < 0 ||
    exponent > MAX_CURRENCY_EXPONENT
  ) {
    invalidTerms("currency_exponent");
  }
  validated.currency_exponent = exponent;

  const executeBefore = terms.execute_before;
  if (
    typeof executeBefore !== "number" ||
    !Number.isSafeInteger(executeBefore) ||
    executeBefore <= 0
  ) {
    invalidTerms("execute_before");
  }
  validated.execute_before = executeBefore;

  return freezeTerms(validated);
}

/** Canonical bytes of already validated inputs. */
function encodeCanonical(intentId: string, terms: PaymentTerms): Uint8Array {
  const fields = [
    PAYMENT_RAR_TYPE_V1,
    intentId,
    terms.tenant,
    terms.payer,
    terms.client_id,
    terms.actor,
    terms.resource,
    terms.order_id,
    terms.funding_source.id,
    String(terms.funding_source.version),
    terms.funding_source.label,
    terms.payee.id,
    String(terms.payee.version),
    terms.payee.name,
    terms.amount_minor,
    terms.currency,
    String(terms.currency_exponent),
    String(terms.execute_before),
  ];
  const encoder = new TextEncoder();
  const encoded = fields.map((field) => encoder.encode(field));
  const total = encoded.reduce((sum, bytes) => sum + 4 + bytes.length, DOMAIN_BYTES.length);
  const out = new Uint8Array(total);
  const view = new DataView(out.buffer);
  out.set(DOMAIN_BYTES, 0);
  let offset = DOMAIN_BYTES.length;
  for (const bytes of encoded) {
    view.setUint32(offset, bytes.length, false);
    offset += 4;
    out.set(bytes, offset);
    offset += bytes.length;
  }
  return out;
}

function digestCanonical(intentId: string, terms: PaymentTerms): string {
  return createHash("sha256").update(encodeCanonical(intentId, terms)).digest("base64url");
}

function validIntentId(intentId: unknown): string {
  return identifier(intentId, "intent_id");
}

/**
 * Canonical v1 bytes for `intentId` and `terms`. Both are validated first (throws
 * `PaymentAuthorizationError("invalid_terms")`), so a digest is never computed over
 * inadmissible values.
 */
export function paymentTermsCanonicalBytes(intentId: string, terms: PaymentTerms): Uint8Array {
  const id = validIntentId(intentId);
  return encodeCanonical(id, validatePaymentTerms(terms));
}

/** `base64url_nopad(SHA-256(canonical_bytes))`, 43 characters. Validates like the bytes. */
export function paymentTermsDigest(intentId: string, terms: PaymentTerms): string {
  const id = validIntentId(intentId);
  return digestCanonical(id, validatePaymentTerms(terms));
}

function fail(code: PaymentAuthorizationErrorCode, message: string, cause?: unknown): never {
  throw new PaymentAuthorizationError(
    code,
    message,
    cause === undefined ? undefined : { cause },
  );
}

function malformed(message: string, cause?: unknown): never {
  return fail("malformed_payment_authorization", message, cause);
}

function isExactStringList(value: unknown, expected: string): boolean {
  return Array.isArray(value) && value.length === 1 && value[0] === expected;
}

function isPaymentTyped(detail: unknown): boolean {
  return isPlainRecord(detail) && own(detail, "type") === PAYMENT_RAR_TYPE_V1;
}

interface ParsedDetail {
  intentId: string;
  terms: PaymentTerms;
  termsDigest: string;
}

/** Strictly parse the one canonical detail and recompute its digest (Rust `parse_canonical_detail`). */
function parseCanonicalDetail(entry: unknown): ParsedDetail {
  const detail = exactObject(entry, DETAIL_KEYS);
  if (detail === null) {
    malformed("payment detail must have exactly the canonical members");
  }
  if (detail.type !== PAYMENT_RAR_TYPE_V1) malformed("payment detail type mismatch");
  const intentId = detail.intent_id;
  if (!isIdentifier(intentId)) malformed("payment detail intent_id is invalid");
  let terms: PaymentTerms;
  try {
    terms = validatePaymentTerms(detail.terms);
  } catch (err) {
    malformed("payment detail terms are invalid", err);
  }
  if (!isExactStringList(detail.locations, terms.resource)) {
    malformed("payment detail locations must be exactly [terms.resource]");
  }
  if (!isExactStringList(detail.actions, PAYMENT_EXECUTE_ACTION)) {
    malformed('payment detail actions must be exactly ["execute"]');
  }
  const termsDigest = digestCanonical(intentId, terms);
  if (detail.terms_digest !== termsDigest) {
    fail("digest_mismatch", "payment detail terms_digest does not match the terms");
  }
  return { intentId, terms, termsDigest };
}

function sameTerms(actual: PaymentTerms, expected: unknown): boolean {
  const terms = exactObject(expected, TERMS_KEYS);
  if (terms === null) return false;
  const fundingSource = exactObject(terms.funding_source, FUNDING_SOURCE_KEYS);
  const payee = exactObject(terms.payee, PAYEE_KEYS);
  if (fundingSource === null || payee === null) return false;
  return (
    terms.tenant === actual.tenant &&
    terms.payer === actual.payer &&
    terms.client_id === actual.client_id &&
    terms.actor === actual.actor &&
    terms.resource === actual.resource &&
    terms.order_id === actual.order_id &&
    fundingSource.id === actual.funding_source.id &&
    fundingSource.version === actual.funding_source.version &&
    fundingSource.label === actual.funding_source.label &&
    payee.id === actual.payee.id &&
    payee.version === actual.payee.version &&
    payee.name === actual.payee.name &&
    terms.amount_minor === actual.amount_minor &&
    terms.currency === actual.currency &&
    terms.currency_exponent === actual.currency_exponent &&
    terms.execute_before === actual.execute_before
  );
}

/**
 * Strict payment execution check over verified token claims or an RFC 7662 introspection body.
 *
 * The caller has already verified signature/issuer or performed online introspection (required
 * for payments: use `IntrospectionClient` with `cacheTtlSecs: 0`). Checks, in order: active,
 * single-element `aud == expected.resource`, `payments:execute` scope, single-hop
 * `act.sub == expected.actor`, exactly one canonical payment detail in the whole
 * `authorization_details` array (exact members, `locations`, `actions`, recomputed digest), then
 * intent id, terms resource/actor, `sub == terms.payer` and the optional persisted terms /
 * digest.
 *
 * Throws `PaymentAuthorizationError`; never fall back to `enforceRar` on failure. Returns a
 * frozen view of the approved authorization.
 */
export function verifyPaymentAuthorization(
  claims: Record<string, unknown>,
  expected: PaymentExpectation,
): VerifiedPaymentAuthorization {
  if (
    !isPlainRecord(expected) ||
    typeof expected.resource !== "string" ||
    typeof expected.intentId !== "string" ||
    typeof expected.actor !== "string"
  ) {
    throw new TypeError(
      "verifyPaymentAuthorization: expected.resource, intentId and actor must be strings",
    );
  }

  // 1. An introspection body must say active:true; verified JWT claims carry no `active`.
  if (!isPlainRecord(claims) || (hasOwn(claims, "active") && claims.active !== true)) {
    fail("inactive", "token is not active");
  }

  // 2. Single-element audience equal to this payment resource (bare string rejected, C2.5a).
  const aud = own(claims, "aud");
  if (
    !Array.isArray(aud) ||
    aud.length !== 1 ||
    typeof aud[0] !== "string" ||
    aud[0] !== expected.resource
  ) {
    fail("audience_mismatch", "token audience is not exactly this payment resource");
  }

  // 3. RFC 6749 space-delimited scope must include payments:execute.
  const scope = own(claims, "scope");
  if (typeof scope !== "string" || !scope.split(" ").includes(PAYMENT_EXECUTE_SCOPE)) {
    fail("insufficient_scope", `token lacks scope ${PAYMENT_EXECUTE_SCOPE}`);
  }

  // 4. Exactly one delegation hop to the expected actor.
  const act = own(claims, "act");
  if (
    !isPlainRecord(act) ||
    typeof own(act, "sub") !== "string" ||
    own(act, "sub") !== expected.actor ||
    hasOwn(act, "act")
  ) {
    fail("actor_mismatch", "token act is not a single hop to the expected actor");
  }

  // 5. The whole array is exactly one canonical payment detail.
  const details = own(claims, "authorization_details");
  if (details === undefined) {
    fail("missing_payment_authorization", "token has no authorization_details");
  }
  if (!Array.isArray(details)) {
    malformed("authorization_details is not an array");
  }
  if (!details.some(isPaymentTyped)) {
    fail(
      "missing_payment_authorization",
      `token has no ${PAYMENT_RAR_TYPE_V1} authorization detail`,
    );
  }
  if (details.length !== 1) {
    malformed("authorization_details must contain exactly one payment detail and nothing else");
  }
  const parsed = parseCanonicalDetail(details[0]);

  // 6. Bind to this execution.
  if (parsed.intentId !== expected.intentId) {
    fail("intent_mismatch", "payment detail is for another intent");
  }
  if (parsed.terms.resource !== expected.resource) {
    fail("audience_mismatch", "payment terms are for another resource");
  }
  if (parsed.terms.actor !== expected.actor) {
    fail("actor_mismatch", "payment terms name another actor");
  }
  const subject = own(claims, "sub");
  if (typeof subject !== "string" || subject !== parsed.terms.payer) {
    fail("payer_mismatch", "token subject is not the payer of these terms");
  }
  if (expected.terms !== undefined && !sameTerms(parsed.terms, expected.terms)) {
    fail("terms_mismatch", "payment terms differ from the persisted intent");
  }
  if (expected.termsDigest !== undefined && parsed.termsDigest !== expected.termsDigest) {
    fail("digest_mismatch", "payment terms digest differs from the persisted intent");
  }

  return Object.freeze({
    intentId: parsed.intentId,
    terms: parsed.terms,
    termsDigest: parsed.termsDigest,
    actor: expected.actor,
    subject,
  });
}
