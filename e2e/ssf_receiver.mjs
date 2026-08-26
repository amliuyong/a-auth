import crypto from "node:crypto";
import {
  DynamoDBClient,
  GetItemCommand,
  PutItemCommand,
  UpdateItemCommand,
} from "@aws-sdk/client-dynamodb";

const db = new DynamoDBClient({});
const table = process.env.TABLE_NAME;
const jwksCache = new Map();
const configKey = { jti: { S: "__config__" } };

function response(statusCode, body = "") {
  return {
    statusCode,
    headers: { "content-type": "text/plain; charset=utf-8" },
    body,
  };
}

function decodeJson(part) {
  return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
}

function canonicalJson(value) {
  if (Array.isArray(value)) {
    return value.map(canonicalJson);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonicalJson(value[key])]),
    );
  }
  return value;
}

function sameJson(left, right) {
  return (
    JSON.stringify(canonicalJson(left)) === JSON.stringify(canonicalJson(right))
  );
}

function validSubject(subject, expected) {
  if (!subject || !expected || !sameJson(subject, expected)) {
    return false;
  }
  if (expected.format === "iss_sub") {
    return (
      Object.keys(subject).sort().join(",") === "format,iss,sub" &&
      subject.iss === expected.iss &&
      subject.sub === expected.sub
    );
  }
  return (
    expected.format === "complex" &&
    Object.keys(subject).sort().join(",") === "format,session,tenant,user" &&
    subject.session?.format === "opaque" &&
    typeof subject.session.id === "string" &&
    /^[A-Za-z0-9_-]{43}$/.test(subject.session.id) &&
    subject.user?.format === "iss_sub" &&
    subject.tenant?.format === "opaque"
  );
}

async function configuredTargets() {
  const result = await db.send(
    new GetItemCommand({
      TableName: table,
      Key: configKey,
      ConsistentRead: true,
    }),
  );
  const encoded = result.Item?.expected_targets?.S;
  if (typeof encoded !== "string" || encoded.length === 0) {
    throw new Error("receiver_config");
  }
  const configured = JSON.parse(encoded);
  if (!configured || Array.isArray(configured) || typeof configured !== "object") {
    throw new Error("receiver_config");
  }
  return configured;
}

async function jwksFor(issuer) {
  const cached = jwksCache.get(issuer);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.keys;
  }
  const result = await fetch(`${issuer}/jwks.json`, {
    signal: AbortSignal.timeout(3000),
  });
  if (!result.ok) {
    throw new Error("jwks_fetch");
  }
  const document = await result.json();
  if (!Array.isArray(document.keys) || document.keys.length > 16) {
    throw new Error("jwks_shape");
  }
  jwksCache.set(issuer, {
    keys: document.keys,
    expiresAt: Date.now() + 60_000,
  });
  return document.keys;
}

async function verifySet(compactSet, target) {
  const parts = compactSet.split(".");
  if (parts.length !== 3) {
    throw new Error("compact_shape");
  }
  const header = decodeJson(parts[0]);
  const claims = decodeJson(parts[1]);
  const headerNames = Object.keys(header).sort();
  if (
    JSON.stringify(headerNames) !== JSON.stringify(["alg", "kid", "typ"]) ||
    header.alg !== "ES256" ||
    header.typ !== "secevent+jwt" ||
    typeof header.kid !== "string" ||
    header.kid.length === 0
  ) {
    throw new Error("protected_header");
  }
  const jwk = (await jwksFor(target.issuer)).find(
    (candidate) =>
      candidate.kid === header.kid &&
      candidate.kty === "EC" &&
      candidate.crv === "P-256",
  );
  if (!jwk) {
    throw new Error("unknown_kid");
  }
  const validSignature = crypto.verify(
    "sha256",
    Buffer.from(`${parts[0]}.${parts[1]}`),
    {
      key: crypto.createPublicKey({ key: jwk, format: "jwk" }),
      dsaEncoding: "ieee-p1363",
    },
    Buffer.from(parts[2], "base64url"),
  );
  if (!validSignature) {
    throw new Error("signature");
  }

  const now = Math.floor(Date.now() / 1000);
  const eventNames =
    claims.events && typeof claims.events === "object"
      ? Object.keys(claims.events)
      : [];
  const subject = claims.sub_id;
  const payload = claims.events?.[target.eventUri];
  const claimNames = Object.keys(claims).sort();
  const payloadNames =
    payload && typeof payload === "object" ? Object.keys(payload).sort() : [];
  const acceptedTransactions = Array.isArray(target.txns)
    ? target.txns
    : [target.txn];
  if (
    JSON.stringify(claimNames) !==
      JSON.stringify(["aud", "events", "iat", "iss", "jti", "sub_id", "txn"]) ||
    claims.iss !== target.issuer ||
    claims.aud !== target.audience ||
    !Number.isInteger(claims.iat) ||
    claims.iat > now + 60 ||
    now - claims.iat > 86_400 ||
    typeof claims.jti !== "string" ||
    !claims.jti.startsWith("set_") ||
    !acceptedTransactions.includes(claims.txn) ||
    eventNames.length !== 1 ||
    eventNames[0] !== target.eventUri ||
    !validSubject(subject, target.subject) ||
    !Number.isInteger(payload?.event_timestamp) ||
    payload.event_timestamp > now + 60 ||
    now - payload.event_timestamp > 86_400 ||
    JSON.stringify(payloadNames) !==
      JSON.stringify(Object.keys(target.payload).sort()) ||
    Object.entries(target.payload).some(
      ([name, value]) => name !== "event_timestamp" && payload[name] !== value,
    )
  ) {
    throw new Error("claims");
  }
  return { header, claims };
}

async function recordAccepted(targetName, compactSet, verified) {
  const now = Math.floor(Date.now() / 1000);
  const digest = `sha256:${crypto
    .createHash("sha256")
    .update(compactSet)
    .digest("base64url")}`;
  const item = {
    jti: { S: verified.claims.jti },
    target: { S: targetName },
    issuer: { S: verified.claims.iss },
    audience: { S: verified.claims.aud },
    txn: { S: verified.claims.txn },
    event_uri: { S: Object.keys(verified.claims.events)[0] },
    signing_kid: { S: verified.header.kid },
    set_sha256: { S: digest },
    compact_set: { S: compactSet },
    claims_json: { S: JSON.stringify(verified.claims) },
    receive_count: { N: "1" },
    dedupe_count: { N: "0" },
    first_seen_at: { N: String(now) },
    last_seen_at: { N: String(now) },
    expires_at: { N: String(now + 86_400) },
  };
  try {
    await db.send(
      new PutItemCommand({
        TableName: table,
        Item: item,
        ConditionExpression: "attribute_not_exists(jti)",
      }),
    );
    return false;
  } catch (error) {
    if (error.name !== "ConditionalCheckFailedException") {
      throw error;
    }
  }

  const current = await db.send(
    new GetItemCommand({
      TableName: table,
      Key: { jti: { S: verified.claims.jti } },
      ConsistentRead: true,
    }),
  );
  if (
    current.Item?.set_sha256?.S !== digest ||
    current.Item?.target?.S !== targetName
  ) {
    throw new Error("replay_mismatch");
  }
  await db.send(
    new UpdateItemCommand({
      TableName: table,
      Key: { jti: { S: verified.claims.jti } },
      UpdateExpression:
        "SET last_seen_at = :now, expires_at = :expires ADD receive_count :one, dedupe_count :one",
      ExpressionAttributeValues: {
        ":now": { N: String(now) },
        ":expires": { N: String(now + 86_400) },
        ":one": { N: "1" },
      },
    }),
  );
  return true;
}

export async function handler(event) {
  try {
    const contentType = event.headers?.["content-type"] ?? "";
    const compactSet = event.isBase64Encoded
      ? Buffer.from(event.body ?? "", "base64").toString("utf8")
      : event.body ?? "";
    if (
      !contentType.toLowerCase().startsWith("application/secevent+jwt") ||
      compactSet.length === 0 ||
      compactSet.length > 256 * 1024
    ) {
      return response(401);
    }
    const match = /^\/receive\/([a-z0-9-]+)\/(success|timeout-once)$/.exec(
      event.rawPath ?? "",
    );
    const targets = await configuredTargets();
    const target = match && targets[match[1]];
    if (!target) {
      return response(401);
    }
    const verified = await verifySet(compactSet, target);
    const duplicate = await recordAccepted(match[1], compactSet, verified);
    if (match[2] === "timeout-once" && !duplicate) {
      await new Promise((resolve) => setTimeout(resolve, 12_000));
    }
    return response(202);
  } catch (error) {
    console.error("SSF_RECEIVER_REJECT", error?.message ?? "unknown");
    return response(401);
  }
}
