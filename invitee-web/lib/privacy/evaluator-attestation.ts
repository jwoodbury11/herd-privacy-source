"use client";

import type { X509Certificate } from "@peculiar/x509";

import {
  base64UrlToBytes,
  bytesToBase64Url,
  normalizeEvaluatorPublicKey,
  type PrivateResponsePolicyV1,
} from "./protocol";

const GOOGLE_ATTESTATION_ISSUER =
  "https://confidentialcomputing.googleapis.com";
const KEY_BINDING_DOMAIN = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
const MAXIMUM_ATTESTATION_BYTES = 128 * 1024;
const CLOCK_SKEW_SECONDS = 30;
const encoder = new TextEncoder();

type EvaluatorKeyMetadata = {
  keyId: string;
  algorithm: "ECDH_P256" | "ECDSA_P256_SHA256";
  publicKey: string;
};

type EvaluatorKeyBinding = {
  protocolVersion: 1;
  releaseId: string;
  keys: {
    responseDecryption: EvaluatorKeyMetadata;
    evaluationResultSigning: EvaluatorKeyMetadata;
    policySigning: EvaluatorKeyMetadata;
    transparencySigning: EvaluatorKeyMetadata;
  };
};

type AttestationResponse = {
  protocolVersion: 1;
  tokenType: "google-pki";
  audience: string;
  nonce: string;
  keyBinding: EvaluatorKeyBinding;
  keyBindingHash: string;
  attestationToken: string;
};

type AttestationConfig = {
  audience: string;
  projectId: string;
  serviceAccount: string;
  imageDigest: string;
  rootCertificate: string;
  rootFingerprint: string;
  releaseId: string;
  allowedSwVersions: string[];
  maxAgeSeconds: number;
  keyBinding: EvaluatorKeyBinding;
};

export class EvaluatorAttestationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvaluatorAttestationError";
  }
}

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

function exactRecord(
  value: unknown,
  expected: readonly string[],
  field: string,
): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new EvaluatorAttestationError(`${field} contains unsupported fields.`);
  }
  return record;
}

function requiredBuildValue(value: string | undefined, field: string): string {
  if (!value || !value.trim()) {
    throw new EvaluatorAttestationError(
      `This Herd release is missing its ${field} trust pin.`,
    );
  }
  return value.trim();
}

function releaseIdentifier(value: string | undefined, field: string): string {
  const result = requiredBuildValue(value, field);
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(result)) {
    throw new EvaluatorAttestationError(`This Herd release has an invalid ${field}.`);
  }
  return result;
}

function httpsAudience(value: string | undefined): string {
  const result = requiredBuildValue(value, "attestation audience");
  let url: URL;
  try {
    url = new URL(result);
  } catch {
    throw new EvaluatorAttestationError("This Herd release has an invalid attestation audience.");
  }
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new EvaluatorAttestationError("This Herd release has an invalid attestation audience.");
  }
  return result;
}

function p256Key(
  keyId: string | undefined,
  publicKey: string | undefined,
  algorithm: EvaluatorKeyMetadata["algorithm"],
  field: string,
): EvaluatorKeyMetadata {
  const normalizedKeyId = releaseIdentifier(keyId, `${field} key ID`);
  let normalizedPublicKey: string;
  try {
    normalizedPublicKey = normalizeEvaluatorPublicKey(
      requiredBuildValue(publicKey, `${field} public key`),
    );
  } catch {
    throw new EvaluatorAttestationError(
      `This Herd release has an invalid ${field} public key.`,
    );
  }
  return { keyId: normalizedKeyId, algorithm, publicKey: normalizedPublicKey };
}

function loadAttestationConfig(): AttestationConfig {
  const maxAgeSeconds = Number(
    process.env.NEXT_PUBLIC_HERD_ATTESTATION_MAX_AGE_SECONDS ?? "300",
  );
  if (!Number.isInteger(maxAgeSeconds) || maxAgeSeconds < 30 || maxAgeSeconds > 900) {
    throw new EvaluatorAttestationError(
      "This Herd release has an invalid attestation freshness policy.",
    );
  }
  const allowedSwVersions = requiredBuildValue(
    process.env.NEXT_PUBLIC_HERD_ATTESTATION_SWVERSIONS,
    "Confidential Space OS version",
  )
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (
    allowedSwVersions.length < 1 ||
    new Set(allowedSwVersions).size !== allowedSwVersions.length ||
    allowedSwVersions.some((value) => !/^[0-9]{6}$/u.test(value))
  ) {
    throw new EvaluatorAttestationError(
      "This Herd release has an invalid Confidential Space OS allowlist.",
    );
  }
  const releaseId = releaseIdentifier(
    process.env.NEXT_PUBLIC_HERD_RELEASE_ID,
    "release ID",
  );
  const keyBinding: EvaluatorKeyBinding = {
    protocolVersion: 1,
    releaseId,
    keys: {
      responseDecryption: p256Key(
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID,
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY,
        "ECDH_P256",
        "response-decryption",
      ),
      evaluationResultSigning: p256Key(
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
        "ECDSA_P256_SHA256",
        "evaluation-result signing",
      ),
      policySigning: p256Key(
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
        "ECDSA_P256_SHA256",
        "policy signing",
      ),
      transparencySigning: p256Key(
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
        process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
        "ECDSA_P256_SHA256",
        "transparency signing",
      ),
    },
  };
  const ids = Object.values(keyBinding.keys).map((key) => key.keyId);
  const publicKeys = Object.values(keyBinding.keys).map((key) => key.publicKey);
  if (new Set(ids).size !== ids.length || new Set(publicKeys).size !== publicKeys.length) {
    throw new EvaluatorAttestationError(
      "This Herd release reuses an evaluator key across trust purposes.",
    );
  }
  const imageDigest = requiredBuildValue(
    process.env.NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGEST,
    "evaluator image digest",
  );
  if (!/^sha256:[0-9a-f]{64}$/u.test(imageDigest)) {
    throw new EvaluatorAttestationError(
      "This Herd release has an invalid evaluator image digest.",
    );
  }
  const rootFingerprint = requiredBuildValue(
    process.env.NEXT_PUBLIC_HERD_ATTESTATION_ROOT_FINGERPRINT,
    "attestation root fingerprint",
  );
  if (!/^[0-9a-f]{64}$/u.test(rootFingerprint)) {
    throw new EvaluatorAttestationError(
      "This Herd release has an invalid attestation root fingerprint.",
    );
  }
  return {
    audience: httpsAudience(process.env.NEXT_PUBLIC_HERD_ATTESTATION_AUDIENCE),
    projectId: requiredBuildValue(
      process.env.NEXT_PUBLIC_HERD_ATTESTATION_PROJECT_ID,
      "evaluator project ID",
    ),
    serviceAccount: requiredBuildValue(
      process.env.NEXT_PUBLIC_HERD_ATTESTATION_SERVICE_ACCOUNT,
      "evaluator service account",
    ),
    imageDigest,
    rootCertificate: requiredBuildValue(
      process.env.NEXT_PUBLIC_HERD_ATTESTATION_ROOT_CERTIFICATE,
      "attestation root certificate",
    ).replaceAll("\\n", "\n"),
    rootFingerprint,
    releaseId,
    allowedSwVersions,
    maxAgeSeconds,
    keyBinding,
  };
}

function softwareQaEvaluatorAccepted(policy: PrivateResponsePolicyV1): boolean {
  const enabled = process.env.NEXT_PUBLIC_HERD_ALLOW_SOFTWARE_QA_EVALUATOR;
  if (enabled !== "true") {
    if (enabled && enabled !== "false") {
      throw new EvaluatorAttestationError(
        "This Herd release has an invalid software-QA evaluator setting.",
      );
    }
    return false;
  }
  if (process.env.NEXT_PUBLIC_HERD_DEPLOYMENT_PROFILE !== "test") {
    throw new EvaluatorAttestationError(
      "Software evaluator verification is permitted only in an isolated test release.",
    );
  }
  const releaseId = releaseIdentifier(
    process.env.NEXT_PUBLIC_HERD_RELEASE_ID,
    "release ID",
  );
  const evaluator = p256Key(
    process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID,
    process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY,
    "ECDH_P256",
    "response-decryption",
  );
  const measurement = requiredBuildValue(
    process.env.NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT,
    "software-QA evaluator measurement",
  );
  if (
    policy.releaseId !== releaseId ||
    policy.evaluatorKeyId !== evaluator.keyId ||
    policy.evaluatorPublicKey !== evaluator.publicKey ||
    policy.evaluatorMeasurement !== measurement
  ) {
    throw new EvaluatorAttestationError(
      "The software-QA evaluator does not match this test release's trust pins.",
    );
  }
  return true;
}

function strictBase64Url(value: unknown, field: string): Uint8Array {
  if (typeof value !== "string") {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  try {
    const bytes = base64UrlToBytes(value);
    if (bytesToBase64Url(bytes) !== value) throw new TypeError();
    return bytes;
  } catch {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
}

function decodeJsonSegment(segment: string, field: string): Record<string, unknown> {
  const bytes = strictBase64Url(segment, field);
  if (bytes.length < 2 || bytes.length > MAXIMUM_ATTESTATION_BYTES) {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  try {
    const parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new TypeError();
    return parsed as Record<string, unknown>;
  } catch {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
}

async function sha256Base64Url(value: Uint8Array): Promise<string> {
  return bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", ownedArrayBuffer(value)),
    ),
  );
}

async function sha256Hex(value: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", value));
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sameCertificate(
  left: X509Certificate,
  right: X509Certificate,
): Promise<boolean> {
  return (await sha256Hex(left.rawData)) === (await sha256Hex(right.rawData));
}

async function verifyCertificateChain(
  encodedChain: string[],
  config: AttestationConfig,
): Promise<X509Certificate> {
  // Certificate parsing is needed only at the point of submission. Loading it
  // here keeps the decorator runtime and X.509 implementation out of the SSR
  // graph for ordinary event and invitation pages.
  await import("reflect-metadata");
  const {
    BasicConstraintsExtension,
    KeyUsageFlags,
    KeyUsagesExtension,
    X509Certificate,
    X509ChainBuilder,
  } = await import("@peculiar/x509");
  if (encodedChain.length < 1 || encodedChain.length > 6) {
    throw new EvaluatorAttestationError("The attestation certificate chain is invalid.");
  }
  let certificates: X509Certificate[];
  let root: X509Certificate;
  try {
    certificates = encodedChain.map((value) => new X509Certificate(value));
    root = new X509Certificate(config.rootCertificate);
  } catch {
    throw new EvaluatorAttestationError("The attestation certificate chain is invalid.");
  }
  if ((await sha256Hex(root.rawData)) !== config.rootFingerprint) {
    throw new EvaluatorAttestationError("The attestation root does not match this Herd release.");
  }
  const candidates = [...certificates.slice(1), root];
  const chain = await new X509ChainBuilder({ certificates: candidates }).build(
    certificates[0],
  );
  if (chain.length < 2 || !(await sameCertificate(chain[chain.length - 1], root))) {
    throw new EvaluatorAttestationError("The attestation certificate chain is untrusted.");
  }
  const suppliedFingerprints = new Set(
    await Promise.all(certificates.map((certificate) => sha256Hex(certificate.rawData))),
  );
  const chainFingerprints = new Set(
    await Promise.all(chain.map((certificate) => sha256Hex(certificate.rawData))),
  );
  if ([...suppliedFingerprints].some((fingerprint) => !chainFingerprints.has(fingerprint))) {
    throw new EvaluatorAttestationError("The attestation certificate chain is invalid.");
  }

  const now = new Date();
  for (let index = 0; index < chain.length; index += 1) {
    const certificate = chain[index];
    const unknownCritical = certificate.extensions.some(
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
    if (unknownCritical || !(certificate.notBefore < now && now < certificate.notAfter)) {
      throw new EvaluatorAttestationError("The attestation certificate chain is invalid.");
    }
    if (index < chain.length - 1) {
      const issuer = chain[index + 1];
      const basicConstraints = issuer.getExtension(BasicConstraintsExtension);
      const keyUsage = issuer.getExtension(KeyUsagesExtension);
      if (
        !basicConstraints?.ca ||
        !keyUsage ||
        (keyUsage.usages & KeyUsageFlags.keyCertSign) === 0 ||
        !(await certificate.verify({ publicKey: issuer.publicKey, date: now }))
      ) {
        throw new EvaluatorAttestationError("The attestation certificate chain is invalid.");
      }
    }
  }
  if (!(await root.isSelfSigned())) {
    throw new EvaluatorAttestationError("The attestation root certificate is invalid.");
  }
  const leafUsage = chain[0].getExtension(KeyUsagesExtension);
  if (leafUsage && (leafUsage.usages & KeyUsageFlags.digitalSignature) === 0) {
    throw new EvaluatorAttestationError("The attestation signing certificate is invalid.");
  }
  return chain[0];
}

function keyMetadata(value: unknown, field: string): EvaluatorKeyMetadata {
  const record = exactRecord(value, ["keyId", "algorithm", "publicKey"], field);
  if (
    typeof record.keyId !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(record.keyId) ||
    (record.algorithm !== "ECDH_P256" && record.algorithm !== "ECDSA_P256_SHA256") ||
    typeof record.publicKey !== "string"
  ) {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  let publicKey: string;
  try {
    publicKey = normalizeEvaluatorPublicKey(record.publicKey);
  } catch {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  return {
    keyId: record.keyId,
    algorithm: record.algorithm,
    publicKey,
  };
}

function normalizeKeyBinding(value: unknown): EvaluatorKeyBinding {
  const binding = exactRecord(value, ["protocolVersion", "releaseId", "keys"], "Key binding");
  const keys = exactRecord(
    binding.keys,
    [
      "responseDecryption",
      "evaluationResultSigning",
      "policySigning",
      "transparencySigning",
    ],
    "Key binding keys",
  );
  if (binding.protocolVersion !== 1 || typeof binding.releaseId !== "string") {
    throw new EvaluatorAttestationError("Key binding is invalid.");
  }
  return {
    protocolVersion: 1,
    releaseId: binding.releaseId,
    keys: {
      responseDecryption: keyMetadata(keys.responseDecryption, "Response-decryption key"),
      evaluationResultSigning: keyMetadata(
        keys.evaluationResultSigning,
        "Evaluation-result signing key",
      ),
      policySigning: keyMetadata(keys.policySigning, "Policy-signing key"),
      transparencySigning: keyMetadata(
        keys.transparencySigning,
        "Transparency-signing key",
      ),
    },
  };
}

function parseAttestationResponse(value: unknown): AttestationResponse {
  const record = exactRecord(
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
    "Evaluator attestation",
  );
  if (
    record.protocolVersion !== 1 ||
    record.tokenType !== "google-pki" ||
    typeof record.audience !== "string" ||
    typeof record.nonce !== "string" ||
    typeof record.keyBindingHash !== "string" ||
    typeof record.attestationToken !== "string"
  ) {
    throw new EvaluatorAttestationError("Evaluator attestation is invalid.");
  }
  return {
    protocolVersion: 1,
    tokenType: "google-pki",
    audience: record.audience,
    nonce: record.nonce,
    keyBinding: normalizeKeyBinding(record.keyBinding),
    keyBindingHash: record.keyBindingHash,
    attestationToken: record.attestationToken,
  };
}

function record(value: unknown, field: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  return value as Record<string, unknown>;
}

function stringArray(value: unknown, field: string): string[] {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string")) {
    throw new EvaluatorAttestationError(`${field} is invalid.`);
  }
  return value as string[];
}

function emptyCommandOverride(value: unknown): boolean {
  return Array.isArray(value) && value.length === 0;
}

function emptyEnvironmentOverride(value: unknown): boolean {
  return (
    (value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      Object.keys(value as Record<string, unknown>).length === 0)
  );
}

async function verifyAttestationToken(
  response: AttestationResponse,
  nonce: string,
  config: AttestationConfig,
): Promise<void> {
  const segments = response.attestationToken.split(".");
  if (segments.length !== 3 || response.attestationToken.length > MAXIMUM_ATTESTATION_BYTES) {
    throw new EvaluatorAttestationError("The evaluator attestation token is invalid.");
  }
  const header = decodeJsonSegment(segments[0], "Attestation header");
  if (
    header.alg !== "RS256" ||
    (header.typ !== undefined && header.typ !== "JWT") ||
    !Array.isArray(header.x5c) ||
    header.x5c.some((value) => typeof value !== "string") ||
    "jku" in header ||
    "jwk" in header ||
    "x5u" in header ||
    "crit" in header
  ) {
    throw new EvaluatorAttestationError("The evaluator attestation header is invalid.");
  }
  const leaf = await verifyCertificateChain(header.x5c as string[], config);
  const signature = strictBase64Url(segments[2], "Attestation signature");
  let signingKey: CryptoKey;
  try {
    signingKey = await leaf.publicKey.export(
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      ["verify"],
    );
  } catch {
    throw new EvaluatorAttestationError("The evaluator attestation signing key is invalid.");
  }
  if (
    !(await crypto.subtle.verify(
      { name: "RSASSA-PKCS1-v1_5" },
      signingKey,
      ownedArrayBuffer(signature),
      ownedArrayBuffer(encoder.encode(`${segments[0]}.${segments[1]}`)),
    ))
  ) {
    throw new EvaluatorAttestationError("The evaluator attestation signature is invalid.");
  }

  const claims = decodeJsonSegment(segments[1], "Attestation claims");
  const now = Math.floor(Date.now() / 1000);
  const iat = claims.iat;
  const nbf = claims.nbf;
  const exp = claims.exp;
  if (
    !Number.isInteger(iat) ||
    !Number.isInteger(nbf) ||
    !Number.isInteger(exp) ||
    (iat as number) > now + CLOCK_SKEW_SECONDS ||
    now - (iat as number) > config.maxAgeSeconds ||
    (nbf as number) > now + CLOCK_SKEW_SECONDS ||
    (exp as number) <= now - CLOCK_SKEW_SECONDS ||
    (exp as number) <= (iat as number) ||
    (exp as number) <= (nbf as number) ||
    (exp as number) - (iat as number) > 7_200
  ) {
    throw new EvaluatorAttestationError("The evaluator attestation is stale or not yet valid.");
  }
  const nonces = typeof claims.eat_nonce === "string"
    ? [claims.eat_nonce]
    : stringArray(claims.eat_nonce, "Attestation nonces");
  const submods = record(claims.submods, "Attestation submodules");
  const gce = record(submods.gce, "Attestation VM identity");
  const container = record(submods.container, "Attestation container identity");
  const confidentialSpace = record(
    submods.confidential_space,
    "Confidential Space claims",
  );
  const supportAttributes = stringArray(
    confidentialSpace.support_attributes,
    "Confidential Space support attributes",
  );
  const monitoring = exactRecord(
    confidentialSpace.monitoring_enabled,
    ["memory"],
    "Confidential Space monitoring claims",
  );
  const serviceAccounts = stringArray(
    claims.google_service_accounts,
    "Attested service accounts",
  );
  const swVersions = stringArray(claims.swversion, "Attested OS version");
  const attesterTcb = stringArray(claims.attester_tcb, "Attester TCB");
  if (
    claims.iss !== GOOGLE_ATTESTATION_ISSUER ||
    claims.aud !== config.audience ||
    response.audience !== config.audience ||
    response.nonce !== nonce ||
    nonces.length !== 2 ||
    nonces[0] !== nonce ||
    nonces[1] !== response.keyBindingHash ||
    claims.secboot !== true ||
    claims.dbgstat !== "disabled-since-boot" ||
    claims.hwmodel !== "GCP_INTEL_TDX" ||
    claims.swname !== "CONFIDENTIAL_SPACE" ||
    claims.oemid !== 11129 ||
    attesterTcb.length !== 1 ||
    attesterTcb[0] !== "INTEL" ||
    swVersions.length !== 1 ||
    !config.allowedSwVersions.includes(swVersions[0]) ||
    gce.project_id !== config.projectId ||
    serviceAccounts.length !== 1 ||
    serviceAccounts[0] !== config.serviceAccount ||
    container.image_digest !== config.imageDigest ||
    container.restart_policy !== "Always" ||
    !emptyEnvironmentOverride(container.env_override) ||
    !emptyCommandOverride(container.cmd_override) ||
    !supportAttributes.includes("USABLE") ||
    !supportAttributes.includes("STABLE") ||
    monitoring.memory !== false
  ) {
    throw new EvaluatorAttestationError(
      "The evaluator does not match this Herd release's confidential-compute policy.",
    );
  }
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function verifyResponse(
  response: AttestationResponse,
  nonce: string,
  policy: PrivateResponsePolicyV1,
  config: AttestationConfig,
): Promise<void> {
  const computedKeyBindingHash = await sha256Base64Url(
    encoder.encode(`${KEY_BINDING_DOMAIN}\0${JSON.stringify(response.keyBinding)}`),
  );
  if (
    response.nonce !== nonce ||
    response.keyBindingHash !== computedKeyBindingHash ||
    !sameJson(response.keyBinding, config.keyBinding) ||
    response.keyBinding.releaseId !== policy.releaseId ||
    response.keyBinding.keys.responseDecryption.keyId !== policy.evaluatorKeyId ||
    response.keyBinding.keys.responseDecryption.publicKey !== policy.evaluatorPublicKey ||
    policy.releaseId !== config.releaseId ||
    policy.evaluatorMeasurement !== config.imageDigest
  ) {
    throw new EvaluatorAttestationError(
      "The evaluator attestation is not bound to this event and Herd release.",
    );
  }
  await verifyAttestationToken(response, nonce, config);
}

export async function attestEvaluatorForPolicy(
  policy: PrivateResponsePolicyV1,
): Promise<void> {
  if (softwareQaEvaluatorAccepted(policy)) return;
  const config = loadAttestationConfig();
  const nonce = bytesToBase64Url(crypto.getRandomValues(new Uint8Array(32)));
  let response: Response;
  try {
    response = await fetch("/api/trust/evaluator-attestation", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "include",
      cache: "no-store",
      body: JSON.stringify({ nonce }),
    });
  } catch {
    throw new EvaluatorAttestationError(
      "The confidential evaluator could not be reached for verification.",
    );
  }
  if (!response.ok) {
    throw new EvaluatorAttestationError(
      "The confidential evaluator could not be verified.",
    );
  }
  const text = await response.text();
  if (text.length > MAXIMUM_ATTESTATION_BYTES) {
    throw new EvaluatorAttestationError("The evaluator attestation response is invalid.");
  }
  let value: unknown;
  try {
    value = JSON.parse(text) as unknown;
  } catch {
    throw new EvaluatorAttestationError("The evaluator attestation response is invalid.");
  }
  await verifyResponse(parseAttestationResponse(value), nonce, policy, config);
}
