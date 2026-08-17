"use client";

import {
  PRIVATE_RESPONSE_HASH_BYTES,
  PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN,
  PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_SIGNATURE_BYTES,
  base64UrlToBytes,
  bytesToBase64Url,
  canonicalPrivateResponseLogEntryCore,
  canonicalPrivateResponseLogHeadPayload,
  canonicalPrivateResponseReceiptPayload,
  domainSeparatedUtf8,
  normalizeEvaluatorPublicKey,
  publicRuntimeValue,
  type PrivateResponsePolicyV1,
  type PrivateResponseReceiptV1,
} from "./protocol";

export type P256TrustPin = {
  keyId: string;
  publicKey: string;
};

export class PrivateResponseTrustError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PrivateResponseTrustError";
  }
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle) {
    throw new PrivateResponseTrustError("This device cannot verify Herd trust proofs.");
  }
  return globalThis.crypto;
}

function canonicalBase64Url(value: unknown, bytes: number, field: string): string {
  if (typeof value !== "string") {
    throw new PrivateResponseTrustError(`${field} is missing.`);
  }
  let decoded: Uint8Array;
  try {
    decoded = base64UrlToBytes(value);
  } catch {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  if (decoded.length !== bytes || bytesToBase64Url(decoded) !== value) {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  return value;
}

function canonicalTimestamp(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  return value;
}

async function sha256(value: Uint8Array): Promise<string> {
  return bytesToBase64Url(
    new Uint8Array(
      await cryptoApi().subtle.digest("SHA-256", ownedArrayBuffer(value)),
    ),
  );
}

async function verifyP256(
  pin: P256TrustPin,
  domain: string,
  canonicalPayload: string,
  signature: string,
): Promise<boolean> {
  let publicKey: string;
  try {
    publicKey = normalizeEvaluatorPublicKey(pin.publicKey);
  } catch {
    throw new PrivateResponseTrustError("This Herd release has an invalid trust key.");
  }
  const signatureValue = canonicalBase64Url(
    signature,
    PRIVATE_RESPONSE_SIGNATURE_BYTES,
    "Trust signature",
  );
  try {
    const key = await cryptoApi().subtle.importKey(
      "raw",
      ownedArrayBuffer(base64UrlToBytes(publicKey)),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return cryptoApi().subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      ownedArrayBuffer(base64UrlToBytes(signatureValue)),
      ownedArrayBuffer(domainSeparatedUtf8(domain, canonicalPayload)),
    );
  } catch (error) {
    if (error instanceof PrivateResponseTrustError) throw error;
    return false;
  }
}

export function configuredPolicySigningPin(): P256TrustPin | null {
  const keyId = publicRuntimeValue("HERD_EVALUATOR_POLICY_SIGNING_KEY_ID");
  const publicKey = publicRuntimeValue("HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY");
  return keyId && publicKey ? { keyId, publicKey } : null;
}

export function configuredTransparencySigningPin(): P256TrustPin | null {
  const keyId = publicRuntimeValue("HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID");
  const publicKey = publicRuntimeValue("HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY");
  return keyId && publicKey ? { keyId, publicKey } : null;
}

export async function verifyEventPolicyCertification(
  policy: PrivateResponsePolicyV1,
  pin: P256TrustPin,
): Promise<void> {
  if (
    !policy.policySigningKeyId ||
    policy.policySigningKeyId !== pin.keyId ||
    !policy.policySignature ||
    !(await verifyP256(
      pin,
      PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
      policy.canonicalDocument,
      policy.policySignature,
    ))
  ) {
    throw new PrivateResponseTrustError(
      "The event policy is not certified by this Herd release.",
    );
  }
}

export async function verifyPrivateResponseReceiptTransparency(
  receipt: PrivateResponseReceiptV1,
  pin: P256TrustPin,
): Promise<void> {
  const proof = receipt.transparency;
  if (!proof) {
    throw new PrivateResponseTrustError(
      "Herd did not return a verifiable response inclusion proof.",
    );
  }
  if (
    proof.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    proof.signingKeyId !== pin.keyId ||
    proof.logHead.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    proof.logHead.signingKeyId !== pin.keyId ||
    proof.logHead.logId !== proof.logId ||
    proof.logHead.treeSize !== proof.logIndex ||
    proof.logHead.headEntryHash !== proof.entryHash ||
    !Number.isInteger(proof.logIndex) ||
    proof.logIndex < 1 ||
    proof.logIndex > 2_147_483_647 ||
    typeof proof.logId !== "string" ||
    proof.logId.length < 1 ||
    proof.logId.length > 120
  ) {
    throw new PrivateResponseTrustError("The response inclusion proof is invalid.");
  }
  canonicalBase64Url(
    proof.previousEntryHash,
    PRIVATE_RESPONSE_HASH_BYTES,
    "Previous response entry hash",
  );
  canonicalBase64Url(
    proof.entryHash,
    PRIVATE_RESPONSE_HASH_BYTES,
    "Response entry hash",
  );
  canonicalBase64Url(
    receipt.ciphertextHash,
    PRIVATE_RESPONSE_HASH_BYTES,
    "Response ciphertext hash",
  );
  canonicalBase64Url(
    receipt.policyHash,
    PRIVATE_RESPONSE_HASH_BYTES,
    "Response policy hash",
  );
  canonicalBase64Url(
    receipt.responseSigningPublicKey,
    32,
    "Response-signing public key",
  );
  canonicalBase64Url(
    receipt.responseSignature,
    PRIVATE_RESPONSE_SIGNATURE_BYTES,
    "Response authorization",
  );
  canonicalTimestamp(receipt.committedAt, "Response commit time");
  canonicalTimestamp(proof.logHead.generatedAt, "Response log-head time");

  const core = {
    envelopeId: receipt.envelopeId,
    eventId: receipt.eventId,
    inviteeId: receipt.inviteeId,
    policyHash: receipt.policyHash,
    accountKeyEpochId: receipt.accountKeyEpochId,
    revision: receipt.revision,
    ciphertextHash: receipt.ciphertextHash,
    responseSigningPublicKey: receipt.responseSigningPublicKey,
    responseSignature: receipt.responseSignature,
    committedAt: receipt.committedAt,
  };
  const entryCore = canonicalPrivateResponseLogEntryCore(core, proof);
  const expectedEntryHash = await sha256(
    domainSeparatedUtf8(PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN, entryCore),
  );
  if (expectedEntryHash !== proof.entryHash) {
    throw new PrivateResponseTrustError("The response log entry hash is invalid.");
  }
  const receiptPayload = canonicalPrivateResponseReceiptPayload(core, proof);
  if (
    !(await verifyP256(
      pin,
      PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
      receiptPayload,
      proof.receiptSignature,
    ))
  ) {
    throw new PrivateResponseTrustError("The response receipt signature is invalid.");
  }
  const { signature: _signature, ...unsignedHead } = proof.logHead;
  void _signature;
  if (
    !(await verifyP256(
      pin,
      PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
      canonicalPrivateResponseLogHeadPayload(unsignedHead),
      proof.logHead.signature,
    ))
  ) {
    throw new PrivateResponseTrustError("The response log-head signature is invalid.");
  }
}

function exactObject(
  value: unknown,
  keys: readonly string[],
  field: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new PrivateResponseTrustError(`${field} is invalid.`);
  }
  return record;
}

/**
 * Confirms that the signed head returned with a receipt is already visible on
 * the public, hash-only log. Independent witnesses can poll the same endpoint;
 * a private receipt that was never published is therefore not accepted as a
 * successful submission by the client.
 */
export async function verifyPrivateResponseReceiptPublication(
  receipt: PrivateResponseReceiptV1,
  pin: P256TrustPin,
  fetchImpl: typeof fetch = fetch,
): Promise<void> {
  await verifyPrivateResponseReceiptTransparency(receipt, pin);
  const proof = receipt.transparency!;
  let response: Response;
  try {
    response = await fetchImpl(
      `/api/transparency/responses?after=${proof.logIndex - 1}&limit=1`,
      {
        method: "GET",
        credentials: "omit",
        redirect: "manual",
        cache: "no-store",
        headers: { accept: "application/json" },
      },
    );
  } catch {
    throw new PrivateResponseTrustError(
      "The public response log could not be reached.",
    );
  }
  if (
    !response.ok ||
    response.type === "opaqueredirect" ||
    response.headers.get("content-type")?.split(";", 1)[0]?.trim() !==
      "application/json"
  ) {
    throw new PrivateResponseTrustError(
      "The public response log did not confirm this receipt.",
    );
  }
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) ||
      Number(declaredLength) > 32_768)
  ) {
    throw new PrivateResponseTrustError("The public response log is invalid.");
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > 32_768) {
    throw new PrivateResponseTrustError("The public response log is invalid.");
  }
  let payload: unknown;
  try {
    payload = JSON.parse(text);
  } catch {
    throw new PrivateResponseTrustError("The public response log is invalid.");
  }
  const log = exactObject(payload, ["protocolVersion", "logId", "entries"], "Public response log");
  if (
    log.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    log.logId !== proof.logId ||
    !Array.isArray(log.entries) ||
    log.entries.length !== 1
  ) {
    throw new PrivateResponseTrustError(
      "The public response log did not confirm this receipt.",
    );
  }
  const entry = exactObject(
    log.entries[0],
    ["logIndex", "previousEntryHash", "entryHash", "head"],
    "Public response log entry",
  );
  const head = exactObject(
    entry.head,
    [
      "protocolVersion",
      "logId",
      "treeSize",
      "headEntryHash",
      "generatedAt",
      "signingKeyId",
      "signature",
    ],
    "Public response log head",
  );
  if (
    entry.logIndex !== proof.logIndex ||
    entry.previousEntryHash !== proof.previousEntryHash ||
    entry.entryHash !== proof.entryHash ||
    JSON.stringify(head) !== JSON.stringify(proof.logHead)
  ) {
    throw new PrivateResponseTrustError(
      "The public response log did not confirm this receipt.",
    );
  }
}
