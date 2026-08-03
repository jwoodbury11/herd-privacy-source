import {
  loadConfig as loadEvaluatorConfig,
  validateCanonicalPolicyDocumentForSigning,
  type EvaluatorBindings,
  type EvaluatorConfig,
} from "./evaluate";

const POLICY_DOMAIN = "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
const RECEIPT_DOMAIN = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
const LOG_HEAD_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const LOG_ENTRY_HASH_DOMAIN = "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1";
const RESPONSE_AUTHORIZATION_DOMAIN = "HERD-RESPONSE-AUTHORIZATION-V1";
const LOG_ID = "herd-response-log-v1";
const MAXIMUM_REQUEST_BYTES = 64 * 1024;
const MAXIMUM_LOG_INDEX = 2_147_483_647;
const MAXIMUM_RESPONSE_REVISION = 1_000_000;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const HASH_PATTERN = /^[A-Za-z0-9_-]{43}$/u;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const encoder = new TextEncoder();

type Purpose = "policy" | "transparency";

type SignerConfig = {
  token: string;
  evaluator: Pick<
    EvaluatorConfig,
    "keyId" | "publicKey" | "measurement" | "releaseId"
  >;
  policy: { keyId: string; privateKey: CryptoKey; publicIdentity: string };
  transparency: { keyId: string; privateKey: CryptoKey; publicIdentity: string };
};

type SignerGate = { token: string };

class SignerError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
  }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function failure(error: unknown): Response {
  if (error instanceof SignerError) {
    return json({ error: { code: error.code } }, error.status);
  }
  return json({ error: { code: "service_unavailable" } }, 503);
}

function invalidRequest(): never {
  throw new SignerError(400, "invalid_request");
}

function exactRecord(
  value: unknown,
  keys: readonly string[],
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest();
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    invalidRequest();
  }
  return record;
}

function requiredIdentifier(value: string | undefined): string {
  const result = value?.trim() ?? "";
  if (!IDENTIFIER_PATTERN.test(result)) {
    throw new SignerError(503, "service_unavailable");
  }
  return result;
}

function canonicalHash(value: unknown): string {
  if (typeof value !== "string" || !HASH_PATTERN.test(value)) invalidRequest();
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64Url(value);
  } catch {
    invalidRequest();
  }
  if (bytes.length !== 32 || encodeBase64Url(bytes) !== value) invalidRequest();
  return value;
}

function canonicalBytes(value: unknown, length: number): string {
  if (typeof value !== "string") invalidRequest();
  let bytes: Uint8Array;
  try {
    bytes = decodeBase64Url(value);
  } catch {
    invalidRequest();
  }
  if (bytes.length !== length || encodeBase64Url(bytes) !== value) invalidRequest();
  return value;
}

function canonicalUuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) invalidRequest();
  return value;
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") invalidRequest();
  const instant = Date.parse(value);
  if (!Number.isFinite(instant) || new Date(instant).toISOString() !== value) {
    invalidRequest();
  }
  return value;
}

function canonicalPositiveInteger(
  value: unknown,
  maximum = Number.MAX_SAFE_INTEGER,
): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 1 ||
    (value as number) > maximum
  ) {
    invalidRequest();
  }
  return value as number;
}

function decodeBase64Url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/u.test(value)) throw new TypeError("invalid base64url");
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function encodeBase64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

async function importPrivateKey(value: string | undefined): Promise<{
  privateKey: CryptoKey;
  publicIdentity: string;
}> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value ?? "");
  } catch {
    throw new SignerError(503, "service_unavailable");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new SignerError(503, "service_unavailable");
  }
  const jwk = parsed as JsonWebKey;
  if (
    jwk.kty !== "EC" ||
    jwk.crv !== "P-256" ||
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    typeof jwk.d !== "string"
  ) {
    throw new SignerError(503, "service_unavailable");
  }
  try {
    const [x, y, d] = [jwk.x, jwk.y, jwk.d].map(decodeBase64Url);
    if (x.length !== 32 || y.length !== 32 || d.length !== 32) {
      throw new TypeError("invalid key size");
    }
    const privateKey = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x: jwk.x,
        y: jwk.y,
        d: jwk.d,
        ext: false,
        key_ops: ["sign"],
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
    return {
      privateKey,
      publicIdentity: encodeBase64Url(
        Uint8Array.from([0x04, ...x, ...y]),
      ),
    };
  } catch (error) {
    if (error instanceof SignerError) throw error;
    throw new SignerError(503, "service_unavailable");
  }
}

function loadGate(bindings: EvaluatorBindings): SignerGate {
  if (
    bindings.HERD_DEPLOYMENT_PROFILE?.trim().toLowerCase() !== "test" ||
    bindings.HERD_SOFTWARE_QA_TRUST_SIGNER_ENABLED?.trim().toLowerCase() !== "true"
  ) {
    throw new SignerError(404, "not_found");
  }
  const token = bindings.HERD_EVALUATOR_TOKEN?.trim() ?? "";
  if (token.length < 32 || !/^[A-Za-z0-9_-]+$/u.test(token)) {
    throw new SignerError(503, "service_unavailable");
  }
  return { token };
}

async function loadConfig(
  bindings: EvaluatorBindings,
  gate: SignerGate,
): Promise<SignerConfig> {
  const [evaluator, resultKey, policyKey, transparencyKey] = await Promise.all([
    loadEvaluatorConfig(bindings),
    importPrivateKey(bindings.HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK),
    importPrivateKey(bindings.HERD_EVALUATOR_POLICY_SIGNING_PRIVATE_KEY_JWK),
    importPrivateKey(bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PRIVATE_KEY_JWK),
  ]);
  if (evaluator.token !== gate.token) {
    throw new SignerError(503, "service_unavailable");
  }
  const resultKeyId = requiredIdentifier(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
  );
  const policy = {
    keyId: requiredIdentifier(bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID),
    ...policyKey,
  };
  const transparency = {
    keyId: requiredIdentifier(
      bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    ),
    ...transparencyKey,
  };
  const keyIds = [evaluator.keyId, resultKeyId, policy.keyId, transparency.keyId];
  const publicIdentities = [
    evaluator.publicKey,
    resultKey.publicIdentity,
    policy.publicIdentity,
    transparency.publicIdentity,
  ];
  if (new Set(keyIds).size !== keyIds.length || new Set(publicIdentities).size !== 4) {
    throw new SignerError(503, "service_unavailable");
  }
  return {
    token: gate.token,
    evaluator: {
      keyId: evaluator.keyId,
      publicKey: evaluator.publicKey,
      measurement: evaluator.measurement,
      releaseId: evaluator.releaseId,
    },
    policy,
    transparency,
  };
}

async function constantTimeEqual(left: string, right: string): Promise<boolean> {
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

async function authorize(request: Request, config: SignerGate): Promise<void> {
  const authorization = request.headers.get("authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (!supplied || !(await constantTimeEqual(supplied, config.token))) {
    throw new SignerError(401, "unauthorized");
  }
}

function requireBackendOnly(request: Request): void {
  if (request.headers.has("origin")) {
    throw new SignerError(403, "forbidden");
  }
}

async function readBody(request: Request): Promise<Record<string, unknown>> {
  const mediaType = (request.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    throw new SignerError(415, "unsupported_media_type");
  }
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > MAXIMUM_REQUEST_BYTES) {
      throw new SignerError(413, "payload_too_large");
    }
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length === 0) throw new SignerError(400, "invalid_json");
  if (bytes.length > MAXIMUM_REQUEST_BYTES) {
    throw new SignerError(413, "payload_too_large");
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new SignerError(400, "invalid_json");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest();
  }
  return value as Record<string, unknown>;
}

async function sha256(value: string): Promise<string> {
  return encodeBase64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(value))),
  );
}

async function sign(
  privateKey: CryptoKey,
  domain: string,
  canonicalPayload: string,
): Promise<string> {
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      ownedArrayBuffer(encoder.encode(`${domain}\0${canonicalPayload}`)),
    ),
  );
  if (signature.length !== 64) {
    throw new SignerError(503, "service_unavailable");
  }
  return encodeBase64Url(signature);
}

function canonicalPolicyPayload(value: unknown): string {
  if (typeof value !== "string" || value.length < 2 || value.length > 60 * 1024) {
    invalidRequest();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    invalidRequest();
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    invalidRequest();
  }
  if (JSON.stringify(parsed) !== value) invalidRequest();
  return value;
}

function canonicalReceipt(value: unknown, signingKeyId: string): {
  canonicalPayload: string;
  logIndex: number;
  entryHash: string;
  generatedAt: string;
} {
  if (typeof value !== "string" || value.length < 2 || value.length > 60 * 1024) {
    invalidRequest();
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    invalidRequest();
  }
  const receipt = exactRecord(parsed, [
    "protocolVersion",
    "logId",
    "logIndex",
    "previousEntryHash",
    "entryHash",
    "envelopeId",
    "eventId",
    "inviteeId",
    "policyHash",
    "accountKeyEpochId",
    "revision",
    "ciphertextHash",
    "responseSigningPublicKey",
    "responseSignature",
    "committedAt",
    "signingKeyId",
  ]);
  const logIndex = canonicalPositiveInteger(receipt.logIndex);
  const normalized = {
    protocolVersion: 1,
    logId: LOG_ID,
    logIndex,
    previousEntryHash: canonicalHash(receipt.previousEntryHash),
    entryHash: canonicalHash(receipt.entryHash),
    envelopeId: canonicalUuid(receipt.envelopeId),
    eventId: canonicalUuid(receipt.eventId),
    inviteeId: canonicalUuid(receipt.inviteeId),
    policyHash: canonicalHash(receipt.policyHash),
    accountKeyEpochId: canonicalUuid(receipt.accountKeyEpochId),
    revision: canonicalPositiveInteger(receipt.revision),
    ciphertextHash: canonicalHash(receipt.ciphertextHash),
    responseSigningPublicKey: canonicalBytes(receipt.responseSigningPublicKey, 32),
    responseSignature: canonicalBytes(receipt.responseSignature, 64),
    committedAt: canonicalTimestamp(receipt.committedAt),
    signingKeyId,
  };
  if (
    receipt.protocolVersion !== 1 ||
    receipt.logId !== LOG_ID ||
    receipt.signingKeyId !== signingKeyId ||
    JSON.stringify(normalized) !== value
  ) {
    invalidRequest();
  }
  return {
    canonicalPayload: value,
    logIndex,
    entryHash: normalized.entryHash,
    generatedAt: new Date().toISOString(),
  };
}

export async function handleQaPolicySigningRequest(
  request: Request,
  bindings: EvaluatorBindings,
): Promise<Response> {
  try {
    const gate = loadGate(bindings);
    requireBackendOnly(request);
    await authorize(request, gate);
    const config = await loadConfig(bindings, gate);
    const body = exactRecord(await readBody(request), [
      "protocolVersion",
      "canonicalDocument",
    ]);
    if (body.protocolVersion !== 1) invalidRequest();
    const canonicalDocument = canonicalPolicyPayload(body.canonicalDocument);
    return json({
      protocolVersion: 1,
      domain: POLICY_DOMAIN,
      signingKeyId: config.policy.keyId,
      payloadHash: await sha256(canonicalDocument),
      signature: await sign(config.policy.privateKey, POLICY_DOMAIN, canonicalDocument),
    });
  } catch (error) {
    return failure(error);
  }
}

export async function handleQaTransparencySigningRequest(
  request: Request,
  bindings: EvaluatorBindings,
): Promise<Response> {
  try {
    const gate = loadGate(bindings);
    requireBackendOnly(request);
    await authorize(request, gate);
    const config = await loadConfig(bindings, gate);
    const body = exactRecord(await readBody(request), [
      "protocolVersion",
      "kind",
      "canonicalReceiptPayload",
    ]);
    if (body.protocolVersion !== 1 || body.kind !== "append") invalidRequest();
    const receipt = canonicalReceipt(
      body.canonicalReceiptPayload,
      config.transparency.keyId,
    );
    const canonicalHead = JSON.stringify({
      protocolVersion: 1,
      logId: LOG_ID,
      treeSize: receipt.logIndex,
      headEntryHash: receipt.entryHash,
      generatedAt: receipt.generatedAt,
      signingKeyId: config.transparency.keyId,
    });
    return json({
      protocolVersion: 1,
      kind: "append",
      signingKeyId: config.transparency.keyId,
      receipt: {
        domain: RECEIPT_DOMAIN,
        payloadHash: await sha256(receipt.canonicalPayload),
        signature: await sign(
          config.transparency.privateKey,
          RECEIPT_DOMAIN,
          receipt.canonicalPayload,
        ),
      },
      logHead: {
        canonicalPayload: canonicalHead,
        domain: LOG_HEAD_DOMAIN,
        payloadHash: await sha256(canonicalHead),
        signature: await sign(
          config.transparency.privateKey,
          LOG_HEAD_DOMAIN,
          canonicalHead,
        ),
      },
    });
  } catch (error) {
    return failure(error);
  }
}
