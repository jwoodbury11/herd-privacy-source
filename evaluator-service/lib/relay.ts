import {
  EvaluatorHttpError,
  errorResponse,
  evaluate,
  evaluationAuthorityClaim,
  jsonResponse,
  loadConfig,
  type EvaluationAuthorityClaim,
  type EvaluationResult,
  type EvaluatorBindings,
} from "./evaluate";

const PROTOCOL_VERSION = 1 as const;
const CIPHER_SUITE = "P256_HKDF_SHA256_AES256_GCM" as const;
const RELAY_PLAINTEXT_BYTES = 320 * 1024;
const AES_GCM_IV_BYTES = 12;
const AES_GCM_TAG_BYTES = 16;
const RELAY_CIPHERTEXT_BYTES =
  AES_GCM_IV_BYTES + RELAY_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES;
const MAXIMUM_INNER_REQUEST_BYTES = 256 * 1024;
const MAXIMUM_RELAY_REQUEST_BYTES = 437_391;
const MAXIMUM_CAPABILITY_LIFETIME_MS = 120_000;
const MAXIMUM_ISSUED_AT_AGE_MS = 300_000;
const MAXIMUM_FUTURE_CLOCK_SKEW_MS = 30_000;
const RELAY_KEY_LABEL = "HERD-EVALUATOR-RELAY-KEY-V1\0";
const RELAY_AAD_LABEL = "HERD-EVALUATOR-RELAY-AAD-V1\0";
const RELAY_CAPABILITY_LABEL = "HERD-EVALUATOR-RELAY-CAPABILITY-V1\0";
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/;
const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder("utf-8", { fatal: true });

const OUTER_KEYS = [
  "protocolVersion",
  "cipherSuite",
  "evaluatorKeyId",
  "ephemeralPublicKey",
  "salt",
  "ciphertext",
  "capabilityMac",
] as const;

const INNER_KEYS = [
  "protocolVersion",
  "relayRequestId",
  "leaseId",
  "issuedAt",
  "expiresAt",
  "evaluationRequest",
] as const;

type RelayRequest = {
  protocolVersion: typeof PROTOCOL_VERSION;
  cipherSuite: typeof CIPHER_SUITE;
  evaluatorKeyId: string;
  ephemeralPublicKey: string;
  salt: string;
  ciphertext: string;
  capabilityMac: string;
};

type InnerRelayRequest = {
  protocolVersion: typeof PROTOCOL_VERSION;
  relayRequestId: string;
  leaseId: string;
  issuedAt: string;
  expiresAt: string;
  evaluationRequest: Record<string, unknown>;
};

type ResultAttestation = {
  protocolVersion: typeof PROTOCOL_VERSION;
  signingKeyId: string;
  evaluatedAt: string;
  canonicalDocument: string;
  signature: string;
};

export type RelayEvaluationResponse = {
  protocolVersion: typeof PROTOCOL_VERSION;
  relayRequestHash: string;
  relayRequestId: string;
  leaseId: string;
  result: EvaluationResult;
  attestation: ResultAttestation;
};

export type EvaluationAuthorizer = (
  claim: EvaluationAuthorityClaim,
) => Promise<unknown>;

export const relayProtocolConstants = Object.freeze({
  protocolVersion: PROTOCOL_VERSION,
  cipherSuite: CIPHER_SUITE,
  plaintextBytes: RELAY_PLAINTEXT_BYTES,
  ciphertextBytes: RELAY_CIPHERTEXT_BYTES,
  maximumInnerRequestBytes: MAXIMUM_INNER_REQUEST_BYTES,
  maximumRelayRequestBytes: MAXIMUM_RELAY_REQUEST_BYTES,
  maximumCapabilityLifetimeMs: MAXIMUM_CAPABILITY_LIFETIME_MS,
  maximumIssuedAtAgeMs: MAXIMUM_ISSUED_AT_AGE_MS,
  maximumFutureClockSkewMs: MAXIMUM_FUTURE_CLOCK_SKEW_MS,
  keyLabel: RELAY_KEY_LABEL,
  aadLabel: RELAY_AAD_LABEL,
  capabilityLabel: RELAY_CAPABILITY_LABEL,
});

function invalidRequest(): never {
  throw new EvaluatorHttpError(400, "invalid_request");
}

function unauthorized(): never {
  throw new EvaluatorHttpError(401, "unauthorized");
}

function forbidden(): never {
  throw new EvaluatorHttpError(403, "forbidden");
}

function serviceUnavailable(): never {
  throw new EvaluatorHttpError(503, "service_unavailable");
}

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    invalidRequest();
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    invalidRequest();
  }
}

function configuredText(
  bindings: EvaluatorBindings,
  name: keyof EvaluatorBindings,
  minimum: number,
  maximum: number,
): string {
  const value = bindings[name];
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    serviceUnavailable();
  }
  return value;
}

function identifier(value: unknown): string {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) {
    invalidRequest();
  }
  return value;
}

function uuid(value: unknown): string {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) {
    invalidRequest();
  }
  return value;
}

function canonicalIsoTimestamp(value: unknown): string {
  if (typeof value !== "string") invalidRequest();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest();
  }
  return value;
}

function encodeBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function decodeBase64Url(value: unknown, expectedBytes: number): Uint8Array {
  if (
    typeof value !== "string" ||
    !value ||
    !BASE64URL_PATTERN.test(value) ||
    value.length % 4 === 1
  ) {
    invalidRequest();
  }
  let binary: string;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    invalidRequest();
  }
  const bytes = Uint8Array.from(binary!, (character) => character.charCodeAt(0));
  if (bytes.length !== expectedBytes || encodeBase64Url(bytes) !== value) {
    invalidRequest();
  }
  return bytes;
}

function decodeConfiguredBase64Url(
  value: unknown,
  expectedBytes: number,
): Uint8Array {
  try {
    return decodeBase64Url(value, expectedBytes);
  } catch {
    serviceUnavailable();
  }
}

function concatenate(...values: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(
    values.reduce((total, value) => total + value.length, 0),
  );
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  const maximumLength = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximumLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(value));
  return encodeBase64Url(new Uint8Array(digest));
}

function relayContext(request: RelayRequest): string {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
  });
}

function capabilityDocument(request: RelayRequest): string {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext,
  });
}

function normalizedRelayJson(request: RelayRequest): string {
  return JSON.stringify({
    protocolVersion: request.protocolVersion,
    cipherSuite: request.cipherSuite,
    evaluatorKeyId: request.evaluatorKeyId,
    ephemeralPublicKey: request.ephemeralPublicKey,
    salt: request.salt,
    ciphertext: request.ciphertext,
    capabilityMac: request.capabilityMac,
  });
}

function normalizeRelayRequest(value: unknown): RelayRequest {
  const input = record(value);
  exactKeys(input, OUTER_KEYS);
  if (
    input.protocolVersion !== PROTOCOL_VERSION ||
    input.cipherSuite !== CIPHER_SUITE
  ) {
    invalidRequest();
  }
  const ephemeralPublicKeyBytes = decodeBase64Url(input.ephemeralPublicKey, 65);
  if (ephemeralPublicKeyBytes[0] !== 0x04) invalidRequest();
  return {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    evaluatorKeyId: identifier(input.evaluatorKeyId),
    ephemeralPublicKey: encodeBase64Url(ephemeralPublicKeyBytes),
    salt: encodeBase64Url(decodeBase64Url(input.salt, 32)),
    ciphertext: encodeBase64Url(
      decodeBase64Url(input.ciphertext, RELAY_CIPHERTEXT_BYTES),
    ),
    capabilityMac: encodeBase64Url(decodeBase64Url(input.capabilityMac, 32)),
  };
}

async function verifyCapability(
  request: RelayRequest,
  configuredToken: string,
): Promise<void> {
  let key: CryptoKey;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      encoder.encode(configuredToken),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
  } catch {
    serviceUnavailable();
  }
  const input = concatenate(
    encoder.encode(RELAY_CAPABILITY_LABEL),
    encoder.encode(capabilityDocument(request)),
  );
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", key!, arrayBuffer(input)),
  );
  const supplied = decodeBase64Url(request.capabilityMac, 32);
  if (!constantTimeEqual(expected, supplied)) unauthorized();
}

async function decryptRelayFrame(
  request: RelayRequest,
  evaluatorPrivateKey: CryptoKey,
): Promise<Uint8Array> {
  const ephemeralPublicKeyBytes = decodeBase64Url(
    request.ephemeralPublicKey,
    65,
  );
  let ephemeralPublicKey: CryptoKey;
  let sharedSecret: ArrayBuffer;
  try {
    ephemeralPublicKey = await crypto.subtle.importKey(
      "raw",
      arrayBuffer(ephemeralPublicKeyBytes),
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    sharedSecret = await crypto.subtle.deriveBits(
      { name: "ECDH", public: ephemeralPublicKey },
      evaluatorPrivateKey,
      256,
    );
  } catch {
    invalidRequest();
  }

  let baseKey: CryptoKey;
  let aesKey: CryptoKey;
  const context = encoder.encode(relayContext(request));
  try {
    baseKey = await crypto.subtle.importKey(
      "raw",
      sharedSecret!,
      "HKDF",
      false,
      ["deriveKey"],
    );
    aesKey = await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: arrayBuffer(decodeBase64Url(request.salt, 32)),
        info: arrayBuffer(
          concatenate(encoder.encode(RELAY_KEY_LABEL), context),
        ),
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  } catch {
    serviceUnavailable();
  }

  const sealed = decodeBase64Url(request.ciphertext, RELAY_CIPHERTEXT_BYTES);
  const iv = sealed.subarray(0, AES_GCM_IV_BYTES);
  const ciphertextAndTag = sealed.subarray(AES_GCM_IV_BYTES);
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: arrayBuffer(iv),
        additionalData: arrayBuffer(
          concatenate(encoder.encode(RELAY_AAD_LABEL), context),
        ),
        tagLength: 128,
      },
      aesKey!,
      arrayBuffer(ciphertextAndTag),
    );
    const bytes = new Uint8Array(plaintext);
    if (bytes.length !== RELAY_PLAINTEXT_BYTES) invalidRequest();
    return bytes;
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    invalidRequest();
  }
}

function normalizeInnerRelayRequest(
  frame: Uint8Array,
  now: Date,
): InnerRelayRequest {
  if (frame.length !== RELAY_PLAINTEXT_BYTES || !Number.isFinite(now.getTime())) {
    serviceUnavailable();
  }
  const length = new DataView(
    frame.buffer,
    frame.byteOffset,
    frame.byteLength,
  ).getUint32(0, false);
  if (
    length < 2 ||
    length > MAXIMUM_INNER_REQUEST_BYTES ||
    length > frame.length - 4
  ) {
    invalidRequest();
  }
  for (let index = 4 + length; index < frame.length; index += 1) {
    if (frame[index] !== 0) invalidRequest();
  }
  let canonicalDocument: string;
  let parsed: unknown;
  try {
    canonicalDocument = fatalDecoder.decode(frame.subarray(4, 4 + length));
    parsed = JSON.parse(canonicalDocument);
  } catch {
    invalidRequest();
  }
  if (JSON.stringify(parsed!) !== canonicalDocument!) invalidRequest();
  const input = record(parsed!);
  exactKeys(input, INNER_KEYS);
  if (input.protocolVersion !== PROTOCOL_VERSION) invalidRequest();
  const evaluationRequest = record(input.evaluationRequest);
  const issuedAt = canonicalIsoTimestamp(input.issuedAt);
  const expiresAt = canonicalIsoTimestamp(input.expiresAt);
  const issuedAtMs = Date.parse(issuedAt);
  const expiresAtMs = Date.parse(expiresAt);
  const nowMs = now.getTime();
  if (
    expiresAtMs <= issuedAtMs ||
    expiresAtMs - issuedAtMs > MAXIMUM_CAPABILITY_LIFETIME_MS ||
    issuedAtMs > nowMs + MAXIMUM_FUTURE_CLOCK_SKEW_MS ||
    nowMs - issuedAtMs > MAXIMUM_ISSUED_AT_AGE_MS ||
    nowMs >= expiresAtMs
  ) {
    unauthorized();
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    relayRequestId: uuid(input.relayRequestId),
    leaseId: uuid(input.leaseId),
    issuedAt,
    expiresAt,
    evaluationRequest,
  };
}

type SigningConfig = {
  keyId: string;
  privateKey: CryptoKey;
};

async function loadSigningConfig(
  bindings: EvaluatorBindings,
): Promise<SigningConfig> {
  const keyId = configuredText(
    bindings,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID",
    1,
    120,
  );
  if (!IDENTIFIER_PATTERN.test(keyId)) serviceUnavailable();
  const encodedJwk = configuredText(
    bindings,
    "HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK",
    50,
    4_000,
  );
  let input: Record<string, unknown>;
  try {
    input = record(JSON.parse(encodedJwk));
  } catch {
    serviceUnavailable();
  }
  if (input!.kty !== "EC" || input!.crv !== "P-256") serviceUnavailable();
  const x = encodeBase64Url(decodeConfiguredBase64Url(input!.x, 32));
  const y = encodeBase64Url(decodeConfiguredBase64Url(input!.y, 32));
  const d = encodeBase64Url(decodeConfiguredBase64Url(input!.d, 32));
  let privateKey: CryptoKey;
  try {
    privateKey = await crypto.subtle.importKey(
      "jwk",
      {
        kty: "EC",
        crv: "P-256",
        x,
        y,
        d,
        ext: false,
        key_ops: ["sign"],
      },
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"],
    );
  } catch {
    serviceUnavailable();
  }
  return { keyId, privateKey };
}

function readDerLength(bytes: Uint8Array, state: { offset: number }): number {
  if (state.offset >= bytes.length) serviceUnavailable();
  const first = bytes[state.offset++];
  if ((first & 0x80) === 0) return first;
  const width = first & 0x7f;
  if (width < 1 || width > 2 || state.offset + width > bytes.length) {
    serviceUnavailable();
  }
  let length = 0;
  for (let index = 0; index < width; index += 1) {
    length = length * 256 + bytes[state.offset++];
  }
  if (length < 128 || (width === 2 && length < 256)) serviceUnavailable();
  return length;
}

function readDerInteger(
  bytes: Uint8Array,
  state: { offset: number },
): Uint8Array {
  if (state.offset >= bytes.length || bytes[state.offset++] !== 0x02) {
    serviceUnavailable();
  }
  const length = readDerLength(bytes, state);
  if (length < 1 || length > 33 || state.offset + length > bytes.length) {
    serviceUnavailable();
  }
  let value = bytes.subarray(state.offset, state.offset + length);
  state.offset += length;
  if ((value[0] & 0x80) !== 0) serviceUnavailable();
  if (value.length === 33) {
    if (value[0] !== 0 || (value[1] & 0x80) === 0) serviceUnavailable();
    value = value.subarray(1);
  } else if (value.length > 1 && value[0] === 0 && (value[1] & 0x80) === 0) {
    serviceUnavailable();
  }
  const result = new Uint8Array(32);
  result.set(value, 32 - value.length);
  return result;
}

export function normalizeEcdsaSignature(signature: Uint8Array): Uint8Array {
  if (signature.length === 64) return Uint8Array.from(signature);
  const state = { offset: 0 };
  if (signature[state.offset++] !== 0x30) serviceUnavailable();
  const sequenceLength = readDerLength(signature, state);
  if (state.offset + sequenceLength !== signature.length) serviceUnavailable();
  const sequenceEnd = state.offset + sequenceLength;
  const r = readDerInteger(signature, state);
  const s = readDerInteger(signature, state);
  if (state.offset !== sequenceEnd) serviceUnavailable();
  return concatenate(r, s);
}

async function signResultAttestation(
  signingConfig: SigningConfig,
  relayRequestHash: string,
  inner: InnerRelayRequest,
  result: EvaluationResult,
  evaluatedAt: string,
): Promise<ResultAttestation> {
  const canonicalDocument = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    signingKeyId: signingConfig.keyId,
    relayRequestHash,
    relayRequestId: inner.relayRequestId,
    leaseId: inner.leaseId,
    evaluatedAt,
    result,
  });
  let signature: Uint8Array;
  try {
    signature = normalizeEcdsaSignature(
      new Uint8Array(
        await crypto.subtle.sign(
          { name: "ECDSA", hash: "SHA-256" },
          signingConfig.privateKey,
          encoder.encode(canonicalDocument),
        ),
      ),
    );
  } catch (error) {
    if (error instanceof EvaluatorHttpError) throw error;
    serviceUnavailable();
  }
  if (signature!.length !== 64) serviceUnavailable();
  return {
    protocolVersion: PROTOCOL_VERSION,
    signingKeyId: signingConfig.keyId,
    evaluatedAt,
    canonicalDocument,
    signature: encodeBase64Url(signature!),
  };
}

async function readBoundedBody(
  request: Request,
  maximumBytes: number,
): Promise<Uint8Array> {
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const parsed = Number(contentLength);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > maximumBytes) {
      throw new EvaluatorHttpError(413, "request_too_large");
    }
  }
  if (!request.body) invalidRequest();
  const reader = request.body!.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maximumBytes) {
        await reader.cancel();
        throw new EvaluatorHttpError(413, "request_too_large");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  if (total === 0) invalidRequest();
  return concatenate(...chunks);
}

function configuredAllowedOrigin(bindings: EvaluatorBindings): string {
  const value = configuredText(
    bindings,
    "HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN",
    8,
    300,
  );
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    serviceUnavailable();
  }
  const localHttp =
    parsed!.protocol === "http:" &&
    (parsed!.hostname === "localhost" || parsed!.hostname === "127.0.0.1");
  if (
    (parsed!.protocol !== "https:" && !localHttp) ||
    parsed!.origin !== value ||
    parsed!.pathname !== "/" ||
    parsed!.search ||
    parsed!.hash ||
    parsed!.username ||
    parsed!.password
  ) {
    serviceUnavailable();
  }
  return value;
}

function requestOrigin(
  request: Request,
  allowedOrigin: string,
  required: boolean,
): string | null {
  const origin = request.headers.get("origin");
  if (origin === null) {
    if (required) forbidden();
    return null;
  }
  if (origin !== allowedOrigin) forbidden();
  return origin;
}

function withCors(response: Response, origin: string | null): Response {
  if (origin !== null) {
    response.headers.set("access-control-allow-origin", origin);
    response.headers.set("vary", "Origin");
  }
  return response;
}

export async function handleRelayOptionsRequest(
  request: Request,
  bindings: EvaluatorBindings,
): Promise<Response> {
  let origin: string | null = null;
  try {
    if (request.method !== "OPTIONS") invalidRequest();
    const allowedOrigin = configuredAllowedOrigin(bindings);
    origin = requestOrigin(request, allowedOrigin, true);
    if (request.headers.get("access-control-request-method") !== "POST") {
      forbidden();
    }
    const requestedHeaders = (request.headers.get(
      "access-control-request-headers",
    ) ?? "")
      .split(",")
      .map((value) => value.trim().toLowerCase())
      .filter(Boolean)
      .sort();
    const allowedHeaders = new Set([
      "cache-control",
      "content-type",
      "pragma",
    ]);
    if (
      !requestedHeaders.includes("content-type") ||
      new Set(requestedHeaders).size !== requestedHeaders.length ||
      requestedHeaders.some((header) => !allowedHeaders.has(header)) ||
      request.headers.has("access-control-request-private-network")
    ) {
      forbidden();
    }
    return withCors(
      new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-methods": "POST",
          "access-control-allow-headers":
            "content-type, cache-control, pragma",
          "access-control-max-age": "600",
          "cache-control": "no-store",
          "x-content-type-options": "nosniff",
        },
      }),
      origin,
    );
  } catch (error) {
    const response =
      error instanceof EvaluatorHttpError
        ? errorResponse(error)
        : errorResponse(new EvaluatorHttpError(503, "service_unavailable"));
    return withCors(response, origin);
  }
}

export async function handleRelayRequest(
  request: Request,
  bindings: EvaluatorBindings,
  now = new Date(),
  evaluationAuthorizer?: EvaluationAuthorizer,
): Promise<Response> {
  let origin: string | null = null;
  try {
    if (request.method !== "POST") invalidRequest();
    const allowedOrigin = configuredAllowedOrigin(bindings);
    origin = requestOrigin(request, allowedOrigin, false);
    const mediaType = (request.headers.get("content-type") ?? "")
      .split(";", 1)[0]
      .trim()
      .toLowerCase();
    if (mediaType !== "application/json") invalidRequest();
    const bytes = await readBoundedBody(request, MAXIMUM_RELAY_REQUEST_BYTES);
    let parsed: unknown;
    try {
      parsed = JSON.parse(fatalDecoder.decode(bytes));
    } catch {
      invalidRequest();
    }
    const relayRequest = normalizeRelayRequest(parsed!);
    const normalizedJson = normalizedRelayJson(relayRequest);

    const config = await loadConfig(bindings);
    if (relayRequest.evaluatorKeyId !== config.keyId) invalidRequest();
    await verifyCapability(relayRequest, config.token);
    const relayRequestHash = await sha256Base64Url(normalizedJson);
    const frame = await decryptRelayFrame(relayRequest, config.privateKey);
    const inner = normalizeInnerRelayRequest(frame, now);
    if (evaluationAuthorizer) {
      const claim = await evaluationAuthorityClaim(
        inner.evaluationRequest,
        config,
        now,
      );
      await evaluationAuthorizer(claim);
    }
    const result = await evaluate(inner.evaluationRequest, config, now);
    const evaluatedAt = now.toISOString();
    const signingConfig = await loadSigningConfig(bindings);
    const attestation = await signResultAttestation(
      signingConfig,
      relayRequestHash,
      inner,
      result,
      evaluatedAt,
    );
    return withCors(
      jsonResponse(
        {
          protocolVersion: PROTOCOL_VERSION,
          relayRequestHash,
          relayRequestId: inner.relayRequestId,
          leaseId: inner.leaseId,
          result,
          attestation,
        } satisfies RelayEvaluationResponse,
        200,
      ),
      origin,
    );
  } catch (error) {
    const response =
      error instanceof EvaluatorHttpError
        ? errorResponse(error)
        : errorResponse(new EvaluatorHttpError(503, "service_unavailable"));
    return withCors(response, origin);
  }
}
