// Copyright 2026 Herd contributors. Licensed under Apache-2.0.
import "reflect-metadata";

import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509Certificate,
  X509ChainBuilder,
  cryptoProvider,
} from "@peculiar/x509";

const GOOGLE_ATTESTATION_ISSUER =
  "https://confidentialcomputing.googleapis.com";
const KEY_BINDING_DOMAIN = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
const MAXIMUM_ATTESTATION_BYTES = 128 * 1024;
const MAXIMUM_CERTIFICATE_BYTES = 32 * 1024;
const CLOCK_SKEW_SECONDS = 30;
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export class LiveEvaluatorAttestationError extends Error {
  constructor(message) {
    super(message);
    this.name = "LiveEvaluatorAttestationError";
  }
}

function fail(message) {
  throw new LiveEvaluatorAttestationError(message);
}

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactRecord(value, expectedKeys, label) {
  if (!isObject(value)) fail(`${label} is invalid.`);
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    fail(`${label} contains unsupported or missing fields.`);
  }
  return value;
}

function record(value, label) {
  if (!isObject(value)) fail(`${label} is invalid.`);
  return value;
}

function stringArray(value, label) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    fail(`${label} is invalid.`);
  }
  return value;
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replace(/=+$/u, "");
}

function strictBase64Url(value, label, { expectedLength = null, maximum = MAXIMUM_ATTESTATION_BYTES } = {}) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > Math.ceil((maximum * 4) / 3) + 4 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    fail(`${label} is invalid.`);
  }
  let bytes;
  try {
    const standard = value.replaceAll("-", "+").replaceAll("_", "/");
    const binary = atob(standard.padEnd(Math.ceil(standard.length / 4) * 4, "="));
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    fail(`${label} is invalid.`);
  }
  if (
    bytes.byteLength > maximum ||
    (expectedLength !== null && bytes.byteLength !== expectedLength) ||
    base64Url(bytes) !== value
  ) {
    fail(`${label} is invalid.`);
  }
  return bytes;
}

function strictBase64(value, label, maximum = MAXIMUM_CERTIFICATE_BYTES) {
  if (
    typeof value !== "string" ||
    value.length < 4 ||
    value.length > Math.ceil((maximum * 4) / 3) + 4 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    fail(`${label} is invalid.`);
  }
  let bytes;
  try {
    const binary = atob(value);
    bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    fail(`${label} is invalid.`);
  }
  if (bytes.byteLength < 1 || bytes.byteLength > maximum || btoa(String.fromCharCode(...bytes)) !== value) {
    fail(`${label} is invalid.`);
  }
  return bytes;
}

function decodeJsonSegment(segment, label) {
  const bytes = strictBase64Url(segment, label);
  if (bytes.byteLength < 2) fail(`${label} is invalid.`);
  try {
    const value = JSON.parse(decoder.decode(bytes));
    if (!isObject(value)) throw new TypeError();
    return value;
  } catch {
    fail(`${label} is invalid.`);
  }
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(bytes)));
}

async function sha256Hex(bytes) {
  return [...(await sha256(bytes))]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function sha256Base64Url(bytes) {
  return base64Url(await sha256(bytes));
}

async function sameCertificate(left, right) {
  return (await sha256Hex(new Uint8Array(left.rawData))) ===
    (await sha256Hex(new Uint8Array(right.rawData)));
}

async function verifyCertificateChain(encodedChain, rootBytes, expectedFingerprint, currentTime) {
  if (
    !Array.isArray(encodedChain) ||
    encodedChain.length < 1 ||
    encodedChain.length > 6 ||
    encodedChain.some((value) => typeof value !== "string" || value.length > 48 * 1024)
  ) {
    fail("The live evaluator attestation certificate chain is invalid.");
  }
  cryptoProvider.set(globalThis.crypto);
  let certificates;
  let root;
  try {
    certificates = encodedChain.map((value) => new X509Certificate(value));
    root = new X509Certificate(Uint8Array.from(rootBytes).buffer);
  } catch {
    fail("The live evaluator attestation certificate chain is invalid.");
  }
  if ((await sha256Hex(new Uint8Array(root.rawData))) !== expectedFingerprint) {
    fail("The independently configured attestation root differs from the signed release pin.");
  }
  const chain = await new X509ChainBuilder({
    certificates: [...certificates.slice(1), root],
  }).build(certificates[0]);
  if (chain.length < 2 || !(await sameCertificate(chain.at(-1), root))) {
    fail("The live evaluator attestation certificate chain is untrusted.");
  }
  const suppliedFingerprints = new Set(
    await Promise.all(
      certificates.map((certificate) =>
        sha256Hex(new Uint8Array(certificate.rawData)),
      ),
    ),
  );
  const chainFingerprints = new Set(
    await Promise.all(
      chain.map((certificate) => sha256Hex(new Uint8Array(certificate.rawData))),
    ),
  );
  if ([...suppliedFingerprints].some((value) => !chainFingerprints.has(value))) {
    fail("The live evaluator attestation certificate chain is invalid.");
  }
  for (let index = 0; index < chain.length; index += 1) {
    const certificate = chain[index];
    const unknownCriticalExtension = certificate.extensions.some(
      (extension) =>
        extension.critical &&
        ![
          "2.5.29.14",
          "2.5.29.15",
          "2.5.29.19",
          "2.5.29.32",
          "2.5.29.35",
          "2.5.29.37",
          "2.5.29.31",
          "1.3.6.1.5.5.7.1.1",
        ].includes(extension.type),
    );
    if (
      unknownCriticalExtension ||
      !(certificate.notBefore < currentTime && currentTime < certificate.notAfter)
    ) {
      fail("The live evaluator attestation certificate chain is invalid.");
    }
    if (index < chain.length - 1) {
      const issuer = chain[index + 1];
      const basicConstraints = issuer.getExtension(BasicConstraintsExtension);
      const keyUsage = issuer.getExtension(KeyUsagesExtension);
      if (
        !basicConstraints?.ca ||
        !keyUsage ||
        (keyUsage.usages & KeyUsageFlags.keyCertSign) === 0 ||
        !(await certificate.verify({ publicKey: issuer.publicKey, date: currentTime }))
      ) {
        fail("The live evaluator attestation certificate chain is invalid.");
      }
    }
  }
  if (!(await root.isSelfSigned())) {
    fail("The independently configured attestation root is not self-signed.");
  }
  const leafUsage = chain[0].getExtension(KeyUsagesExtension);
  if (leafUsage && (leafUsage.usages & KeyUsageFlags.digitalSignature) === 0) {
    fail("The live evaluator attestation signing certificate is invalid.");
  }
  return chain[0];
}

function expectedKeyBinding(manifest) {
  return {
    protocolVersion: 1,
    releaseId: manifest.evaluatorKeyEpochId,
    keys: {
      responseDecryption: {
        keyId: manifest.trust.evaluatorEncryption.keyId,
        algorithm: "ECDH_P256",
        publicKey: manifest.trust.evaluatorEncryption.publicKey,
      },
      evaluationResultSigning: {
        keyId: manifest.trust.resultSigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: manifest.trust.resultSigning.publicKey,
      },
      policySigning: {
        keyId: manifest.trust.policySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: manifest.trust.policySigning.publicKey,
      },
      transparencySigning: {
        keyId: manifest.trust.receiptTransparencySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: manifest.trust.receiptTransparencySigning.publicKey,
      },
    },
  };
}

function normalizeKeyMetadata(value, expectedAlgorithm, label) {
  const input = exactRecord(value, ["keyId", "algorithm", "publicKey"], label);
  if (
    typeof input.keyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(input.keyId) ||
    input.algorithm !== expectedAlgorithm ||
    typeof input.publicKey !== "string"
  ) {
    fail(`${label} is invalid.`);
  }
  const publicKey = strictBase64Url(input.publicKey, `${label} public key`, {
    expectedLength: 65,
    maximum: 65,
  });
  if (publicKey[0] !== 0x04) fail(`${label} is invalid.`);
  return {
    keyId: input.keyId,
    algorithm: expectedAlgorithm,
    publicKey: input.publicKey,
  };
}

function normalizeKeyBinding(value) {
  const input = exactRecord(
    value,
    ["protocolVersion", "releaseId", "keys"],
    "Live evaluator key binding",
  );
  const keys = exactRecord(
    input.keys,
    [
      "responseDecryption",
      "evaluationResultSigning",
      "policySigning",
      "transparencySigning",
    ],
    "Live evaluator key binding keys",
  );
  if (
    input.protocolVersion !== 1 ||
    typeof input.releaseId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(input.releaseId)
  ) {
    fail("Live evaluator key binding is invalid.");
  }
  return {
    protocolVersion: 1,
    releaseId: input.releaseId,
    keys: {
      responseDecryption: normalizeKeyMetadata(
        keys.responseDecryption,
        "ECDH_P256",
        "Live response-decryption key",
      ),
      evaluationResultSigning: normalizeKeyMetadata(
        keys.evaluationResultSigning,
        "ECDSA_P256_SHA256",
        "Live evaluation-result signing key",
      ),
      policySigning: normalizeKeyMetadata(
        keys.policySigning,
        "ECDSA_P256_SHA256",
        "Live policy-signing key",
      ),
      transparencySigning: normalizeKeyMetadata(
        keys.transparencySigning,
        "ECDSA_P256_SHA256",
        "Live transparency-signing key",
      ),
    },
  };
}

function normalizeResponse(value) {
  const input = exactRecord(
    value,
    [
      "protocolVersion",
      "tokenType",
      "audience",
      "nonce",
      "keyBinding",
      "keyBindingHash",
      "attestationToken",
    ],
    "Live evaluator attestation response",
  );
  if (
    input.protocolVersion !== 1 ||
    input.tokenType !== "google-pki" ||
    typeof input.audience !== "string" ||
    typeof input.nonce !== "string" ||
    typeof input.keyBindingHash !== "string" ||
    typeof input.attestationToken !== "string"
  ) {
    fail("Live evaluator attestation response is invalid.");
  }
  strictBase64Url(input.nonce, "Live evaluator nonce", {
    expectedLength: 32,
    maximum: 32,
  });
  strictBase64Url(input.keyBindingHash, "Live evaluator key-binding hash", {
    expectedLength: 32,
    maximum: 32,
  });
  return {
    protocolVersion: 1,
    tokenType: "google-pki",
    audience: input.audience,
    nonce: input.nonce,
    keyBinding: normalizeKeyBinding(input.keyBinding),
    keyBindingHash: input.keyBindingHash,
    attestationToken: input.attestationToken,
  };
}

async function readBounded(response, maximumBytes) {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) ||
      Number(declaredLength) > maximumBytes)
  ) {
    fail("Live evaluator attestation response is oversized.");
  }
  if (!response.body) return new Uint8Array();
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maximumBytes) {
      await reader.cancel();
      fail("Live evaluator attestation response is oversized.");
    }
    chunks.push(value);
  }
  const result = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return result;
}

function parseResponseBytes(bytes) {
  try {
    const value = JSON.parse(decoder.decode(bytes));
    return normalizeResponse(value);
  } catch (error) {
    if (error instanceof LiveEvaluatorAttestationError) throw error;
    fail("Live evaluator attestation response is not valid UTF-8 JSON.");
  }
}

async function verifyToken(response, expectedNonce, configuration, currentTime) {
  if (
    response.attestationToken.length > MAXIMUM_ATTESTATION_BYTES ||
    response.attestationToken.split(".").length !== 3
  ) {
    fail("The live evaluator attestation token is invalid.");
  }
  const segments = response.attestationToken.split(".");
  const header = decodeJsonSegment(segments[0], "Live evaluator attestation header");
  if (
    header.alg !== "RS256" ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    !Array.isArray(header.x5c) ||
    header.x5c.some((value) => typeof value !== "string") ||
    "crit" in header ||
    "jku" in header ||
    "jwk" in header ||
    "x5u" in header
  ) {
    fail("The live evaluator attestation header is invalid.");
  }
  const rootBytes = strictBase64(
    configuration.rootCertificateDerBase64,
    "Independent attestation root certificate",
  );
  const expectedRootFingerprint =
    configuration.manifest.trust.workload.attestationRootFingerprint.value;
  const leaf = await verifyCertificateChain(
    header.x5c,
    rootBytes,
    expectedRootFingerprint,
    currentTime,
  );
  const signature = strictBase64Url(
    segments[2],
    "Live evaluator attestation signature",
  );
  let signingKey;
  try {
    signingKey = await leaf.publicKey.export(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      ["verify"],
    );
  } catch {
    fail("The live evaluator attestation signing key is invalid.");
  }
  if (
    !(await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      signingKey,
      Uint8Array.from(signature),
      encoder.encode(`${segments[0]}.${segments[1]}`),
    ))
  ) {
    fail("The live evaluator attestation signature is invalid.");
  }

  const claims = decodeJsonSegment(segments[1], "Live evaluator attestation claims");
  const policy = configuration.manifest.trust.workload.attestationClaimPolicy;
  const currentSeconds = Math.floor(currentTime.getTime() / 1000);
  const { iat, nbf, exp } = claims;
  if (
    !Number.isSafeInteger(iat) ||
    !Number.isSafeInteger(nbf) ||
    !Number.isSafeInteger(exp) ||
    iat > currentSeconds + CLOCK_SKEW_SECONDS ||
    currentSeconds - iat > policy.maxAgeSeconds ||
    nbf > currentSeconds + CLOCK_SKEW_SECONDS ||
    exp <= currentSeconds - CLOCK_SKEW_SECONDS ||
    exp <= iat ||
    exp <= nbf ||
    exp - iat > 7_200
  ) {
    fail("The live evaluator attestation token is stale or not yet valid.");
  }
  const nonces = stringArray(claims.eat_nonce, "Live evaluator attestation nonces");
  const serviceAccounts = stringArray(
    claims.google_service_accounts,
    "Live evaluator service accounts",
  );
  const swVersions = stringArray(claims.swversion, "Live evaluator OS version");
  const attesterTcb = stringArray(claims.attester_tcb, "Live evaluator attester TCB");
  const submods = record(claims.submods, "Live evaluator submodules");
  const gce = record(submods.gce, "Live evaluator VM identity");
  const container = record(submods.container, "Live evaluator container identity");
  const confidentialSpace = record(
    submods.confidential_space,
    "Live evaluator Confidential Space claims",
  );
  const supportAttributes = stringArray(
    confidentialSpace.support_attributes,
    "Live evaluator support attributes",
  );
  const monitoring = exactRecord(
    confidentialSpace.monitoring_enabled,
    ["memory"],
    "Live evaluator monitoring claims",
  );
  // Confidential Space omits these claims when no override was requested. An
  // explicitly empty value is equivalent, but any supplied override remains a
  // hard policy failure.
  const environmentOverride = container.env_override === undefined
    ? {}
    : exactRecord(
        container.env_override,
        [],
        "Live evaluator environment override",
      );
  const commandOverride = container.cmd_override === undefined
    ? []
    : container.cmd_override;
  const allowedImageDigests = new Set(
    policy.allowedImageDigests.map(({ algorithm, value }) => `${algorithm}:${value}`),
  );
  if (
    claims.iss !== GOOGLE_ATTESTATION_ISSUER ||
    claims.aud !== policy.audience ||
    response.audience !== policy.audience ||
    response.nonce !== expectedNonce ||
    nonces.length !== 2 ||
    nonces[0] !== expectedNonce ||
    nonces[1] !== response.keyBindingHash ||
    claims.secboot !== true ||
    claims.dbgstat !== "disabled-since-boot" ||
    claims.hwmodel !== "GCP_INTEL_TDX" ||
    claims.swname !== "CONFIDENTIAL_SPACE" ||
    claims.oemid !== 11129 ||
    attesterTcb.length !== 1 ||
    attesterTcb[0] !== "INTEL" ||
    swVersions.length !== 1 ||
    !policy.allowedSwversions.includes(swVersions[0]) ||
    gce.project_id !== policy.projectId ||
    serviceAccounts.length !== 1 ||
    serviceAccounts[0] !== policy.serviceAccount ||
    !allowedImageDigests.has(container.image_digest) ||
    container.restart_policy !== "Always" ||
    Object.keys(environmentOverride).length !== 0 ||
    !Array.isArray(commandOverride) ||
    commandOverride.length !== 0 ||
    !supportAttributes.includes("USABLE") ||
    !supportAttributes.includes("STABLE") ||
    monitoring.memory !== false
  ) {
    fail("The live evaluator does not match the signed confidential-compute policy.");
  }
  return container.image_digest;
}

function attestationUrl(origin) {
  let url;
  try {
    url = new URL("/api/v1/attestation", origin);
  } catch {
    fail("The independently configured evaluator origin is invalid.");
  }
  if (
    url.protocol !== "https:" ||
    url.origin !== origin ||
    url.pathname !== "/api/v1/attestation" ||
    url.search ||
    url.hash
  ) {
    fail("The independently configured evaluator origin is invalid.");
  }
  return url.toString();
}

export async function verifyLiveEvaluatorAttestation(
  configuration,
  {
    fetchImpl = fetch,
    now = () => new Date(),
    randomBytes = (length) => crypto.getRandomValues(new Uint8Array(length)),
  } = {},
) {
  const currentTime = now();
  if (!(currentTime instanceof Date) || !Number.isFinite(currentTime.getTime())) {
    fail("The monitor clock is invalid.");
  }
  const audience = new URL(
    configuration.manifest.trust.workload.attestationClaimPolicy.audience,
  );
  if (audience.origin !== configuration.origin) {
    fail("The attestation audience is outside the independently configured evaluator origin.");
  }
  const nonceBytes = randomBytes(32);
  if (!(nonceBytes instanceof Uint8Array) || nonceBytes.byteLength !== 32) {
    fail("The monitor nonce source is invalid.");
  }
  const nonce = base64Url(nonceBytes);
  const expectedBinding = expectedKeyBinding(configuration.manifest);
  const expectedBindingHash = await sha256Base64Url(
    encoder.encode(`${KEY_BINDING_DOMAIN}\0${JSON.stringify(expectedBinding)}`),
  );
  if (
    expectedBindingHash !==
    configuration.manifest.trust.workload.attestationClaimPolicy.keyBindingHash
  ) {
    fail("The signed release attestation key binding is inconsistent.");
  }
  let response;
  try {
    response = await fetchImpl(attestationUrl(configuration.origin), {
      method: "POST",
      redirect: "manual",
      cache: "no-store",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: JSON.stringify({ protocolVersion: 1, nonce }),
    });
  } catch (error) {
    if (error instanceof LiveEvaluatorAttestationError) throw error;
    fail("The live evaluator attestation endpoint could not be reached.");
  }
  if (response.status >= 300 && response.status < 400) {
    fail("The live evaluator attestation endpoint redirected.");
  }
  if (response.status !== 200) {
    fail(`The live evaluator attestation endpoint returned HTTP ${response.status}.`);
  }
  const contentType =
    response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  if (contentType !== "application/json") {
    fail("The live evaluator attestation endpoint returned a non-JSON response.");
  }
  const attestation = parseResponseBytes(
    await readBounded(response, MAXIMUM_ATTESTATION_BYTES),
  );
  if (
    attestation.nonce !== nonce ||
    attestation.audience !==
      configuration.manifest.trust.workload.attestationClaimPolicy.audience ||
    attestation.keyBindingHash !== expectedBindingHash ||
    JSON.stringify(attestation.keyBinding) !== JSON.stringify(expectedBinding)
  ) {
    fail("The live evaluator attestation is not bound to the signed release keys.");
  }
  const imageDigest = await verifyToken(attestation, nonce, configuration, currentTime);
  return {
    verifiedAt: currentTime.toISOString(),
    origin: configuration.origin,
    audience: attestation.audience,
    imageDigest,
    keyBindingHash: expectedBindingHash,
    rootFingerprint:
      configuration.manifest.trust.workload.attestationRootFingerprint.value,
  };
}
