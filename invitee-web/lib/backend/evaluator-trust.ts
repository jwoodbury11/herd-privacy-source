import type { HerdBindings } from "@/db";
import {
  PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
  PRIVATE_RESPONSE_HASH_BYTES,
  PRIVATE_RESPONSE_LOG_ID,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  PRIVATE_RESPONSE_SIGNATURE_BYTES,
  base64UrlToBytes,
  bytesToBase64Url,
  domainSeparatedUtf8,
  type PrivateResponsePolicyV1,
} from "@/lib/privacy/protocol";

import {
  getDeploymentProfile,
  getEvaluatorTrustSigningConfig,
  type EvaluatorTrustSigningConfig,
} from "./config";
import { ApiError } from "./http";

export type EvaluatorSignature = {
  signingKeyId: string;
  payloadHash: string;
  signature: string;
};

export type EvaluatorTransparencyAppendCertification = {
  signingKeyId: string;
  receipt: {
    payloadHash: string;
    signature: string;
  };
  logHead: {
    canonicalPayload: string;
    payloadHash: string;
    signature: string;
  };
};

export type EvaluatorTransparencyReconciliationProof = {
  protocolVersion: typeof PRIVATE_RESPONSE_PROTOCOL_VERSION;
  logId: typeof PRIVATE_RESPONSE_LOG_ID;
  rejectedLogIndex: number;
  rejectedEntryHash: string;
  authorityTreeSize: number;
  authorityHeadEntryHash: string;
  generatedAt: string;
  signingKeyId: string;
  canonicalPayload: string;
  signature: string;
};

export class TransparencyLateMissingEntryError extends ApiError {
  readonly proof: EvaluatorTransparencyReconciliationProof;

  constructor(proof: EvaluatorTransparencyReconciliationProof) {
    super(
      409,
      "response_transparency_late_missing_entry",
      "The encrypted response reached the independent log after its authority deadline.",
    );
    this.name = "TransparencyLateMissingEntryError";
    this.proof = proof;
  }
}

const MAXIMUM_SIGNER_RESPONSE_BYTES = 16 * 1024;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/u;

type LocalQaSigningKey = {
  keyId: string;
  publicKey: string;
  privateKey: CryptoKey;
};

type LocalQaTrustSigner = {
  policy: LocalQaSigningKey;
  transparency: LocalQaSigningKey;
};

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function exactRecord(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("The evaluator signer returned an invalid object.");
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError("The evaluator signer returned unsupported fields.");
  }
  return record;
}

function canonicalHash(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("The evaluator reconciliation hash is invalid.");
  }
  const decoded = base64UrlToBytes(value);
  if (
    decoded.length !== PRIVATE_RESPONSE_HASH_BYTES ||
    bytesToBase64Url(decoded) !== value
  ) {
    throw new TypeError("The evaluator reconciliation hash is invalid.");
  }
  return value;
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") {
    throw new TypeError("The evaluator reconciliation time is invalid.");
  }
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    throw new TypeError("The evaluator reconciliation time is invalid.");
  }
  return value;
}

async function lateMissingEntryProof(
  value: unknown,
  config: EvaluatorTrustSigningConfig,
): Promise<EvaluatorTransparencyReconciliationProof> {
  const outer = exactRecord(value, ["error"]);
  const error = exactRecord(outer.error, ["code", "proof"]);
  if (error.code !== "transparency_late_missing_entry") {
    throw new TypeError("The evaluator reconciliation code is invalid.");
  }
  const proof = exactRecord(error.proof, [
    "canonicalPayload",
    "domain",
    "payloadHash",
    "signature",
    "signingKeyId",
  ]);
  if (
    proof.domain !== PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN ||
    proof.signingKeyId !== config.transparencySigningKeyId ||
    typeof proof.canonicalPayload !== "string" ||
    proof.canonicalPayload.length < 2 ||
    proof.canonicalPayload.length > MAXIMUM_SIGNER_RESPONSE_BYTES ||
    typeof proof.signature !== "string"
  ) {
    throw new TypeError("The evaluator reconciliation proof is invalid.");
  }
  const payload = exactRecord(JSON.parse(proof.canonicalPayload), [
    "protocolVersion",
    "logId",
    "rejectedLogIndex",
    "rejectedEntryHash",
    "authorityTreeSize",
    "authorityHeadEntryHash",
    "generatedAt",
    "signingKeyId",
  ]);
  if (
    payload.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    payload.logId !== PRIVATE_RESPONSE_LOG_ID ||
    !Number.isSafeInteger(payload.rejectedLogIndex) ||
    (payload.rejectedLogIndex as number) < 1 ||
    !Number.isSafeInteger(payload.authorityTreeSize) ||
    (payload.authorityTreeSize as number) < 0 ||
    (payload.authorityTreeSize as number) + 1 !== payload.rejectedLogIndex ||
    payload.signingKeyId !== config.transparencySigningKeyId
  ) {
    throw new TypeError("The evaluator reconciliation payload is invalid.");
  }
  const normalized = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: PRIVATE_RESPONSE_LOG_ID,
    rejectedLogIndex: payload.rejectedLogIndex as number,
    rejectedEntryHash: canonicalHash(payload.rejectedEntryHash),
    authorityTreeSize: payload.authorityTreeSize as number,
    authorityHeadEntryHash: canonicalHash(payload.authorityHeadEntryHash),
    generatedAt: canonicalTimestamp(payload.generatedAt),
    signingKeyId: config.transparencySigningKeyId,
  };
  const payloadHash = await sha256Base64Url(proof.canonicalPayload);
  if (
    JSON.stringify(normalized) !== proof.canonicalPayload ||
    proof.payloadHash !== payloadHash ||
    !(await verifyP256Signature(
      config.transparencySigningPublicKey,
      PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN,
      proof.canonicalPayload,
      proof.signature,
    ))
  ) {
    throw new TypeError("The evaluator reconciliation signature is invalid.");
  }
  return {
    ...normalized,
    canonicalPayload: proof.canonicalPayload,
    signature: proof.signature,
  };
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return bytesToBase64Url(new Uint8Array(digest));
}

async function importLocalQaSigningKey(
  keyId: string,
  publicKey: string,
  privateJwk: string | undefined,
): Promise<LocalQaSigningKey> {
  let parsed: JsonWebKey;
  try {
    parsed = JSON.parse(privateJwk ?? "") as JsonWebKey;
  } catch {
    throw new ApiError(500, "server_misconfigured", "The QA trust signer key is invalid.");
  }
  if (
    parsed.kty !== "EC" ||
    parsed.crv !== "P-256" ||
    typeof parsed.x !== "string" ||
    typeof parsed.y !== "string" ||
    typeof parsed.d !== "string"
  ) {
    throw new ApiError(500, "server_misconfigured", "The QA trust signer key is invalid.");
  }
  const derivedPublicKey = bytesToBase64Url(
    Uint8Array.from([
      0x04,
      ...base64UrlToBytes(parsed.x),
      ...base64UrlToBytes(parsed.y),
    ]),
  );
  if (derivedPublicKey !== publicKey) {
    throw new ApiError(500, "server_misconfigured", "The QA trust signer key does not match its release pin.");
  }
  try {
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      { ...parsed, ext: false, key_ops: ["sign"] },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    return { keyId, publicKey, privateKey };
  } catch {
    throw new ApiError(500, "server_misconfigured", "The QA trust signer key is invalid.");
  }
}

async function localQaTrustSigner(
  bindings: HerdBindings,
): Promise<LocalQaTrustSigner | null> {
  const enabled =
    bindings.HERD_SOFTWARE_QA_LOCAL_TRUST_SIGNER_ENABLED?.trim().toLowerCase() ===
    "true";
  if (!enabled) return null;
  if (getDeploymentProfile(bindings) !== "test") {
    throw new ApiError(500, "server_misconfigured", "The local QA trust signer is forbidden in production.");
  }
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) {
    throw new ApiError(500, "server_misconfigured", "The local QA trust signer pins are missing.");
  }
  const [policy, transparency] = await Promise.all([
    importLocalQaSigningKey(
      config.policySigningKeyId,
      config.policySigningPublicKey,
      bindings.HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK,
    ),
    importLocalQaSigningKey(
      config.transparencySigningKeyId,
      config.transparencySigningPublicKey,
      bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK,
    ),
  ]);
  return { policy, transparency };
}

async function localSignature(
  key: LocalQaSigningKey,
  domain: string,
  canonicalPayload: string,
): Promise<string> {
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      key.privateKey,
      ownedArrayBuffer(domainSeparatedUtf8(domain, canonicalPayload)),
    ),
  );
  if (signature.length !== PRIVATE_RESPONSE_SIGNATURE_BYTES) {
    throw new ApiError(500, "server_misconfigured", "The QA trust signer returned an invalid signature.");
  }
  return bytesToBase64Url(signature);
}

async function locallySignPolicy(
  signer: LocalQaTrustSigner,
  canonicalDocument: string,
): Promise<EvaluatorSignature> {
  return {
    signingKeyId: signer.policy.keyId,
    payloadHash: await sha256Base64Url(canonicalDocument),
    signature: await localSignature(
      signer.policy,
      PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
      canonicalDocument,
    ),
  };
}

async function locallyAppendTransparency(
  signer: LocalQaTrustSigner,
  canonicalReceiptPayload: string,
): Promise<EvaluatorTransparencyAppendCertification> {
  let receipt: Record<string, unknown>;
  try {
    receipt = JSON.parse(canonicalReceiptPayload) as Record<string, unknown>;
  } catch {
    throw new ApiError(500, "server_misconfigured", "The QA transparency receipt is invalid.");
  }
  if (
    !receipt ||
    typeof receipt !== "object" ||
    Array.isArray(receipt) ||
    JSON.stringify(receipt) !== canonicalReceiptPayload ||
    !Number.isSafeInteger(receipt.logIndex) ||
    (receipt.logIndex as number) < 1 ||
    typeof receipt.entryHash !== "string"
  ) {
    throw new ApiError(500, "server_misconfigured", "The QA transparency receipt is invalid.");
  }
  const generatedAt = new Date().toISOString();
  const canonicalHead = JSON.stringify({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: PRIVATE_RESPONSE_LOG_ID,
    treeSize: receipt.logIndex,
    headEntryHash: canonicalHash(receipt.entryHash),
    generatedAt,
    signingKeyId: signer.transparency.keyId,
  });
  return {
    signingKeyId: signer.transparency.keyId,
    receipt: {
      payloadHash: await sha256Base64Url(canonicalReceiptPayload),
      signature: await localSignature(
        signer.transparency,
        PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
        canonicalReceiptPayload,
      ),
    },
    logHead: {
      canonicalPayload: canonicalHead,
      payloadHash: await sha256Base64Url(canonicalHead),
      signature: await localSignature(
        signer.transparency,
        PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
        canonicalHead,
      ),
    },
  };
}

async function verifyP256Signature(
  publicKey: string,
  domain: string,
  canonicalPayload: string,
  signature: string,
): Promise<boolean> {
  const publicKeyBytes = base64UrlToBytes(publicKey);
  const signatureBytes = base64UrlToBytes(signature);
  if (
    publicKeyBytes.length !== 65 ||
    publicKeyBytes[0] !== 0x04 ||
    signatureBytes.length !== PRIVATE_RESPONSE_SIGNATURE_BYTES ||
    bytesToBase64Url(signatureBytes) !== signature
  ) {
    return false;
  }
  const key = await crypto.subtle.importKey(
    "raw",
    ownedArrayBuffer(publicKeyBytes),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
  return crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key,
    ownedArrayBuffer(signatureBytes),
    ownedArrayBuffer(domainSeparatedUtf8(domain, canonicalPayload)),
  );
}

function signerHeaders(config: EvaluatorTrustSigningConfig): Headers {
  const headers = new Headers({
    authorization: `Bearer ${config.token}`,
    "content-type": "application/json",
  });
  if (config.sitesBypassToken) {
    headers.set("OAI-Sites-Authorization", `Bearer ${config.sitesBypassToken}`);
  }
  return headers;
}

async function signerJson(response: Response): Promise<unknown> {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAXIMUM_SIGNER_RESPONSE_BYTES) {
    throw new TypeError("The evaluator signer response is too large.");
  }
  const text = await response.text();
  if (text.length > MAXIMUM_SIGNER_RESPONSE_BYTES) {
    throw new TypeError("The evaluator signer response is too large.");
  }
  return JSON.parse(text) as unknown;
}

async function callPolicySigner(
  config: EvaluatorTrustSigningConfig,
  canonicalPayload: string,
): Promise<EvaluatorSignature> {
  let response: Response;
  try {
    response = await fetch(new URL("/api/v1/sign/policy", config.url), {
      method: "POST",
      headers: signerHeaders(config),
      body: JSON.stringify({
        protocolVersion: 1,
        canonicalDocument: canonicalPayload,
      }),
      redirect: "manual",
    });
  } catch {
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation.",
    );
  }
  if (!response.ok) {
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation.",
    );
  }

  try {
    const value = exactRecord(
      await signerJson(response),
      [
        "protocolVersion",
        "domain",
        "signingKeyId",
        "payloadHash",
        "signature",
      ],
    );
    const payloadHash = await sha256Base64Url(canonicalPayload);
    if (
      value.protocolVersion !== 1 ||
      value.domain !== PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN ||
      value.signingKeyId !== config.policySigningKeyId ||
      value.payloadHash !== payloadHash ||
      typeof value.signingKeyId !== "string" ||
      !IDENTIFIER_PATTERN.test(value.signingKeyId) ||
      typeof value.signature !== "string" ||
      !(await verifyP256Signature(
        config.policySigningPublicKey,
        PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
        canonicalPayload,
        value.signature,
      ))
    ) {
      throw new TypeError("The evaluator signer proof is invalid.");
    }
    return {
      signingKeyId: value.signingKeyId,
      payloadHash,
      signature: value.signature,
    };
  } catch {
    throw new ApiError(
      502,
      "invalid_evaluator_trust_proof",
      "The confidential evaluator returned an invalid certification.",
    );
  }
}

async function callTransparencyAuthority(
  config: EvaluatorTrustSigningConfig,
  canonicalReceiptPayload: string,
): Promise<EvaluatorTransparencyAppendCertification> {
  let response: Response;
  try {
    response = await fetch(new URL("/api/v1/sign/transparency", config.url), {
      method: "POST",
      headers: signerHeaders(config),
      body: JSON.stringify({
        protocolVersion: 1,
        kind: "append",
        canonicalReceiptPayload,
      }),
      redirect: "manual",
    });
  } catch {
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation.",
    );
  }
  if (!response.ok) {
    if (response.status === 409) {
      let value: unknown;
      try {
        value = await signerJson(response);
        const error = exactRecord(value, ["error"]);
        if (
          !error.error ||
          typeof error.error !== "object" ||
          Array.isArray(error.error)
        ) {
          throw new TypeError("The evaluator conflict response is invalid.");
        }
        const errorCode = (error.error as Record<string, unknown>).code;
        if (errorCode === "transparency_late_missing_entry") {
          throw new TransparencyLateMissingEntryError(
            await lateMissingEntryProof(value, config),
          );
        }
        const details = exactRecord(error.error, ["code"]);
        if (details.code !== "transparency_conflict") {
          throw new TypeError("The evaluator conflict response is invalid.");
        }
      } catch (error) {
        if (error instanceof TransparencyLateMissingEntryError) throw error;
        throw new ApiError(
          502,
          "invalid_evaluator_trust_proof",
          "The confidential evaluator returned an invalid reconciliation proof.",
        );
      }
      throw new ApiError(
        409,
        "response_transparency_conflict",
        "The encrypted response conflicts with the independently committed response log.",
      );
    }
    throw new ApiError(
      503,
      "evaluator_trust_unavailable",
      "The confidential evaluator could not certify this operation.",
    );
  }

  try {
    const value = exactRecord(await signerJson(response), [
      "protocolVersion",
      "kind",
      "signingKeyId",
      "receipt",
      "logHead",
    ]);
    const receipt = exactRecord(value.receipt, [
      "domain",
      "payloadHash",
      "signature",
    ]);
    const logHead = exactRecord(value.logHead, [
      "canonicalPayload",
      "domain",
      "payloadHash",
      "signature",
    ]);
    const receiptPayloadHash = await sha256Base64Url(canonicalReceiptPayload);
    if (
      value.protocolVersion !== 1 ||
      value.kind !== "append" ||
      value.signingKeyId !== config.transparencySigningKeyId ||
      typeof value.signingKeyId !== "string" ||
      !IDENTIFIER_PATTERN.test(value.signingKeyId) ||
      receipt.domain !== PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN ||
      receipt.payloadHash !== receiptPayloadHash ||
      typeof receipt.signature !== "string" ||
      typeof logHead.canonicalPayload !== "string" ||
      logHead.canonicalPayload.length < 2 ||
      logHead.canonicalPayload.length > MAXIMUM_SIGNER_RESPONSE_BYTES ||
      logHead.domain !== PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN ||
      typeof logHead.signature !== "string"
    ) {
      throw new TypeError("The evaluator transparency proof is invalid.");
    }
    const headPayloadHash = await sha256Base64Url(logHead.canonicalPayload);
    if (
      logHead.payloadHash !== headPayloadHash ||
      !(await verifyP256Signature(
        config.transparencySigningPublicKey,
        PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
        canonicalReceiptPayload,
        receipt.signature,
      )) ||
      !(await verifyP256Signature(
        config.transparencySigningPublicKey,
        PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
        logHead.canonicalPayload,
        logHead.signature,
      ))
    ) {
      throw new TypeError("The evaluator transparency signature is invalid.");
    }
    return {
      signingKeyId: value.signingKeyId,
      receipt: {
        payloadHash: receiptPayloadHash,
        signature: receipt.signature,
      },
      logHead: {
        canonicalPayload: logHead.canonicalPayload,
        payloadHash: headPayloadHash,
        signature: logHead.signature,
      },
    };
  } catch {
    throw new ApiError(
      502,
      "invalid_evaluator_trust_proof",
      "The confidential evaluator returned an invalid certification.",
    );
  }
}

export async function signEventPolicy(
  bindings: HerdBindings,
  canonicalDocument: string,
): Promise<EvaluatorSignature | null> {
  const localSigner = await localQaTrustSigner(bindings);
  if (localSigner) return locallySignPolicy(localSigner, canonicalDocument);
  const config = getEvaluatorTrustSigningConfig(bindings);
  return config ? callPolicySigner(config, canonicalDocument) : null;
}

export async function appendTransparencyEntry(
  bindings: HerdBindings,
  canonicalReceiptPayload: string,
): Promise<EvaluatorTransparencyAppendCertification | null> {
  const localSigner = await localQaTrustSigner(bindings);
  if (localSigner) {
    return locallyAppendTransparency(localSigner, canonicalReceiptPayload);
  }
  const config = getEvaluatorTrustSigningConfig(bindings);
  return config
    ? callTransparencyAuthority(config, canonicalReceiptPayload)
    : null;
}

export async function verifyStoredEventPolicyCertification(
  bindings: HerdBindings,
  policy: PrivateResponsePolicyV1,
): Promise<boolean> {
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) return true;
  return Boolean(
    policy.policySigningKeyId === config.policySigningKeyId &&
      policy.policySignature &&
      (await verifyP256Signature(
        config.policySigningPublicKey,
        PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
        policy.canonicalDocument,
        policy.policySignature,
      )),
  );
}
