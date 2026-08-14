import { createHash } from "node:crypto";

import {
  canonicalJson,
  compareStrings,
  exactKeys,
  isPlainObject,
  requireCanonicalTimestamp,
  requireInteger,
  requireSha256,
  requireString,
  timestampFromEpoch,
} from "./canonical.mjs";

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const KEY_ID = RELEASE_ID;
const REVISION = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u;
const GOOGLE_ATTESTATION_ISSUER = "https://confidentialcomputing.googleapis.com";
const SLSA_PROVENANCE_V1 = "https://slsa.dev/provenance/v1";
const GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com/";
const SIGSTORE_REKOR_ORIGIN = "https://rekor.sigstore.dev";
const SIGSTORE_REKOR_RECORD_PATH = "/api/v1/log/entries";
const CONFIDENTIAL_SPACE_PLATFORM = "gcp-confidential-space";
const GOOGLE_PKI_ATTESTATION_PROVIDER = "google-pki-attestation-token";
const CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
const GCP_PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
const SERVICE_ACCOUNT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/u;
const IOS_BUNDLE_IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9-]*(?:\.[A-Za-z0-9][A-Za-z0-9-]*)+$/u;
const IOS_VERSION = /^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){0,2}$/u;

function decodeBase64Url(value, expectedBytes, label) {
  requireString(value, label, {
    minimum: Math.ceil((expectedBytes * 4) / 3),
    maximum: Math.ceil((expectedBytes * 4) / 3),
    pattern: /^[A-Za-z0-9_-]+$/u,
  });
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== expectedBytes || bytes.toString("base64url") !== value) {
    throw new TypeError(`${label} must be canonical unpadded base64url.`);
  }
  return bytes;
}

function normalizeHttpsUrl(value, label, { nullable = false, originOnly = false } = {}) {
  if (nullable && value === null) return null;
  requireString(value, label, { maximum: 2048 });
  let url;
  try {
    url = new URL(value);
  } catch {
    throw new TypeError(`${label} must be an HTTPS URL.`);
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    (originOnly && (url.pathname !== "/" || url.search))
  ) {
    throw new TypeError(`${label} must be a safe HTTPS ${originOnly ? "origin" : "URL"}.`);
  }
  return originOnly ? url.origin : url.toString();
}

export function normalizeArtifact(value, label) {
  exactKeys(value, ["name", "mediaType", "sha256", "size", "url"], label);
  return {
    name: requireString(value.name, `${label}.name`, {
      maximum: 160,
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
    }),
    mediaType: requireString(value.mediaType, `${label}.mediaType`, {
      minimum: 3,
      maximum: 160,
      pattern: /^[A-Za-z0-9!#$&^_.+\-/]+$/u,
    }),
    sha256: requireSha256(value.sha256, `${label}.sha256`),
    size: requireInteger(value.size, `${label}.size`),
    url: normalizeHttpsUrl(value.url, `${label}.url`, { nullable: true }),
  };
}

function normalizeDigest(value, label, { sha256Only = false } = {}) {
  exactKeys(value, ["algorithm", "value"], label);
  const algorithm = requireString(value.algorithm, `${label}.algorithm`);
  if ((sha256Only && algorithm !== "sha256") || !["sha256", "sha384"].includes(algorithm)) {
    throw new TypeError(`${label}.algorithm is unsupported.`);
  }
  const length = algorithm === "sha256" ? 64 : 96;
  return {
    algorithm,
    value: requireString(value.value, `${label}.value`, {
      minimum: length,
      maximum: length,
      pattern: /^[0-9a-f]+$/u,
    }),
  };
}

function normalizeKey(value, label, expectedAlgorithm) {
  exactKeys(
    value,
    ["keyId", "algorithm", "publicKeyFormat", "publicKey", "publicKeySha256"],
    label,
  );
  const publicKey = decodeBase64Url(value.publicKey, 65, `${label}.publicKey`);
  if (publicKey[0] !== 0x04) throw new TypeError(`${label}.publicKey is not an uncompressed P-256 point.`);
  const digest = createHash("sha256").update(publicKey).digest("hex");
  if (value.publicKeySha256 !== digest) {
    throw new TypeError(`${label}.publicKeySha256 does not match its public key.`);
  }
  if (value.algorithm !== expectedAlgorithm || value.publicKeyFormat !== "P256_X963_BASE64URL") {
    throw new TypeError(`${label} uses an unsupported algorithm or encoding.`);
  }
  return {
    keyId: requireString(value.keyId, `${label}.keyId`, { maximum: 120, pattern: KEY_ID }),
    algorithm: expectedAlgorithm,
    publicKeyFormat: "P256_X963_BASE64URL",
    publicKey: value.publicKey,
    publicKeySha256: requireSha256(value.publicKeySha256, `${label}.publicKeySha256`),
  };
}

export function workloadKeyBindingPayload({
  evaluatorKeyEpochId,
  evaluatorEncryption,
  resultSigning,
  policySigning,
  receiptTransparencySigning,
}) {
  return {
    protocolVersion: 1,
    // The confidential evaluator protocol calls this field releaseId. Its
    // value is the evaluator key epoch, deliberately independent from the
    // artifact release manifest that happens to publish it.
    // `releaseId` is the protocol-v1 wire name. Its value is the evaluator
    // key epoch, not the signed artifact release identifier.
    releaseId: evaluatorKeyEpochId,
    keys: {
      responseDecryption: {
        keyId: evaluatorEncryption.keyId,
        algorithm: "ECDH_P256",
        publicKey: evaluatorEncryption.publicKey,
      },
      evaluationResultSigning: {
        keyId: resultSigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: resultSigning.publicKey,
      },
      policySigning: {
        keyId: policySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: policySigning.publicKey,
      },
      transparencySigning: {
        keyId: receiptTransparencySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: receiptTransparencySigning.publicKey,
      },
    },
  };
}

export function computeWorkloadKeyBindingHash(binding) {
  return createHash("sha256")
    .update(
      `${CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN}\0${JSON.stringify(workloadKeyBindingPayload(binding))}`,
      "utf8",
    )
    .digest("base64url");
}

function normalizeClaimPolicy(value, { binding, imageDigest }) {
  const label = "trust.workload.attestationClaimPolicy";
  exactKeys(
    value,
    [
      "policyId",
      "issuer",
      "audience",
      "maxAgeSeconds",
      "challengeNonceRequired",
      "keyBindingDomain",
      "keyBindingHashAlgorithm",
      "keyBindingHashEncoding",
      "keyBindingHash",
      "imageDigest",
      "allowedImageDigests",
      "projectId",
      "serviceAccount",
      "hwmodel",
      "secboot",
      "dbgstat",
      "swname",
      "allowedSwversions",
      "oemid",
      "attesterTcb",
      "envOverrideAllowed",
      "cmdOverrideAllowed",
    ],
    label,
  );
  if (
    value.issuer !== GOOGLE_ATTESTATION_ISSUER ||
    value.challengeNonceRequired !== true ||
    value.keyBindingDomain !== CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN ||
    value.keyBindingHashAlgorithm !== "sha256" ||
    value.keyBindingHashEncoding !== "base64url" ||
    value.hwmodel !== "GCP_INTEL_TDX" ||
    value.secboot !== true ||
    value.dbgstat !== "disabled-since-boot" ||
    value.swname !== "CONFIDENTIAL_SPACE" ||
    value.oemid !== 11129 ||
    value.attesterTcb !== "INTEL" ||
    value.envOverrideAllowed !== false ||
    value.cmdOverrideAllowed !== false
  ) {
    throw new TypeError(`${label} does not enforce the required Google Confidential Space claims.`);
  }
  const normalizedImageDigest = normalizeDigest(value.imageDigest, `${label}.imageDigest`, {
    sha256Only: true,
  });
  if (
    normalizedImageDigest.algorithm !== imageDigest.algorithm ||
    normalizedImageDigest.value !== imageDigest.value
  ) {
    throw new TypeError(`${label}.imageDigest must exactly match trust.workload.imageDigest.`);
  }
  if (
    !Array.isArray(value.allowedImageDigests) ||
    value.allowedImageDigests.length === 0 ||
    value.allowedImageDigests.length > 2
  ) {
    throw new TypeError(`${label}.allowedImageDigests must contain one or two exact digests.`);
  }
  const allowedImageDigests = value.allowedImageDigests.map((digest, index) =>
    normalizeDigest(digest, `${label}.allowedImageDigests[${index}]`, { sha256Only: true }),
  );
  const allowedImageDigestValues = allowedImageDigests.map(
    (digest) => `${digest.algorithm}:${digest.value}`,
  );
  if (new Set(allowedImageDigestValues).size !== allowedImageDigestValues.length) {
    throw new TypeError(`${label}.allowedImageDigests contains duplicates.`);
  }
  if (allowedImageDigestValues[0] !== `${imageDigest.algorithm}:${imageDigest.value}`) {
    throw new TypeError(
      `${label}.allowedImageDigests must begin with trust.workload.imageDigest.`,
    );
  }
  const expectedKeyBindingHash = computeWorkloadKeyBindingHash(binding);
  if (value.keyBindingHash !== expectedKeyBindingHash) {
    throw new TypeError(
      `${label}.keyBindingHash must bind releaseId and all four operational key descriptors.`,
    );
  }
  if (!Array.isArray(value.allowedSwversions) || value.allowedSwversions.length === 0) {
    throw new TypeError(`${label}.allowedSwversions must not be empty.`);
  }
  const allowedSwversions = value.allowedSwversions.map((version, index) =>
    requireString(version, `${label}.allowedSwversions[${index}]`, {
      minimum: 6,
      maximum: 6,
      pattern: /^[0-9]{6}$/u,
    }),
  );
  if (new Set(allowedSwversions).size !== allowedSwversions.length) {
    throw new TypeError(`${label}.allowedSwversions contains duplicates.`);
  }
  return {
    policyId: requireString(value.policyId, `${label}.policyId`, { maximum: 120, pattern: RELEASE_ID }),
    issuer: GOOGLE_ATTESTATION_ISSUER,
    audience: normalizeHttpsUrl(value.audience, `${label}.audience`),
    maxAgeSeconds: requireInteger(value.maxAgeSeconds, `${label}.maxAgeSeconds`, {
      minimum: 30,
      maximum: 900,
    }),
    challengeNonceRequired: true,
    keyBindingDomain: CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN,
    keyBindingHashAlgorithm: "sha256",
    keyBindingHashEncoding: "base64url",
    keyBindingHash: requireString(value.keyBindingHash, `${label}.keyBindingHash`, {
      minimum: 43,
      maximum: 43,
      pattern: /^[A-Za-z0-9_-]{43}$/u,
    }),
    imageDigest: normalizedImageDigest,
    allowedImageDigests,
    projectId: requireString(value.projectId, `${label}.projectId`, {
      maximum: 30,
      pattern: GCP_PROJECT_ID,
    }),
    serviceAccount: requireString(value.serviceAccount, `${label}.serviceAccount`, {
      maximum: 253,
      pattern: SERVICE_ACCOUNT,
    }),
    hwmodel: "GCP_INTEL_TDX",
    secboot: true,
    dbgstat: "disabled-since-boot",
    swname: "CONFIDENTIAL_SPACE",
    allowedSwversions: [...allowedSwversions].sort(),
    oemid: 11129,
    attesterTcb: "INTEL",
    envOverrideAllowed: false,
    cmdOverrideAllowed: false,
  };
}

function normalizeWorkload(value, binding) {
  exactKeys(
    value,
    [
      "platform",
      "imageDigest",
      "policyMeasurement",
      "measurements",
      "attestationProvider",
      "attestationClaimPolicy",
      "attestationRootFingerprint",
    ],
    "trust.workload",
  );
  if (!Array.isArray(value.measurements) || value.measurements.length === 0) {
    throw new TypeError("trust.workload.measurements must not be empty.");
  }
  const measurements = value.measurements.map((measurement, index) =>
    normalizeDigest(measurement, `trust.workload.measurements[${index}]`),
  );
  const measurementKeys = measurements.map(({ algorithm, value: digest }) => `${algorithm}:${digest}`);
  if (new Set(measurementKeys).size !== measurementKeys.length) {
    throw new TypeError("trust.workload.measurements contains duplicates.");
  }
  if (
    value.platform !== CONFIDENTIAL_SPACE_PLATFORM ||
    value.attestationProvider !== GOOGLE_PKI_ATTESTATION_PROVIDER
  ) {
    throw new TypeError(
      "trust.workload must use Google PKI attestation tokens for GCP Confidential Space.",
    );
  }
  const imageDigest = normalizeDigest(value.imageDigest, "trust.workload.imageDigest", {
      sha256Only: true,
    });
  const policyMeasurement = normalizeDigest(
    value.policyMeasurement,
    "trust.workload.policyMeasurement",
    { sha256Only: true },
  );
  return {
    platform: CONFIDENTIAL_SPACE_PLATFORM,
    imageDigest,
    policyMeasurement,
    measurements: measurements.sort((left, right) =>
      compareStrings(`${left.algorithm}:${left.value}`, `${right.algorithm}:${right.value}`),
    ),
    attestationProvider: GOOGLE_PKI_ATTESTATION_PROVIDER,
    attestationClaimPolicy: normalizeClaimPolicy(value.attestationClaimPolicy, {
      binding,
      imageDigest,
    }),
    attestationRootFingerprint: normalizeDigest(
      value.attestationRootFingerprint,
      "trust.workload.attestationRootFingerprint",
      { sha256Only: true },
    ),
  };
}

function normalizeProvenance(value, index) {
  const label = `evidence.provenance[${index}]`;
  exactKeys(
    value,
    ["subjects", "predicateType", "issuer", "workflowIdentity", "statement", "bundle"],
    label,
  );
  if (!Array.isArray(value.subjects) || value.subjects.length === 0) {
    throw new TypeError(`${label}.subjects must not be empty.`);
  }
  const subjects = value.subjects.map((subject, subjectIndex) => {
    const subjectLabel = `${label}.subjects[${subjectIndex}]`;
    exactKeys(subject, ["name", "sha256"], subjectLabel);
    return {
      name: requireString(subject.name, `${subjectLabel}.name`, {
        maximum: 160,
        pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
      }),
      sha256: requireSha256(subject.sha256, `${subjectLabel}.sha256`),
    };
  });
  if (new Set(subjects.map(({ name }) => name)).size !== subjects.length) {
    throw new TypeError(`${label}.subjects contains duplicate names.`);
  }
  const predicateType = normalizeHttpsUrl(value.predicateType, `${label}.predicateType`);
  const issuer = normalizeHttpsUrl(value.issuer, `${label}.issuer`);
  if (predicateType !== SLSA_PROVENANCE_V1 || issuer !== GITHUB_ACTIONS_OIDC_ISSUER) {
    throw new TypeError(`${label} must use SLSA v1 and the GitHub Actions OIDC issuer.`);
  }
  return {
    subjects: subjects.sort((left, right) => compareStrings(left.name, right.name)),
    predicateType: SLSA_PROVENANCE_V1,
    issuer: GITHUB_ACTIONS_OIDC_ISSUER,
    workflowIdentity: requireString(value.workflowIdentity, `${label}.workflowIdentity`, {
      maximum: 500,
    }),
    statement: normalizeArtifact(value.statement, `${label}.statement`),
    bundle: normalizeArtifact(value.bundle, `${label}.bundle`),
  };
}

function normalizeTransparency(value, index) {
  const label = `evidence.transparency[${index}]`;
  exactKeys(
    value,
    ["provider", "logId", "entryId", "integratedTime", "bundleSha256", "url"],
    label,
  );
  if (value.provider !== "sigstore-rekor") {
    throw new TypeError(`${label}.provider must be sigstore-rekor.`);
  }
  const logId = requireString(value.logId, `${label}.logId`, { maximum: 256 });
  const entryId = requireString(value.entryId, `${label}.entryId`, { maximum: 512 });
  const separator = entryId.lastIndexOf(":");
  if (
    separator <= 0 ||
    entryId.slice(0, separator) !== logId ||
    !/^(?:0|[1-9][0-9]*)$/u.test(entryId.slice(separator + 1))
  ) {
    throw new TypeError(`${label}.entryId must exactly bind its log ID and numeric index.`);
  }
  const logIndex = Number(entryId.slice(separator + 1));
  if (!Number.isSafeInteger(logIndex)) throw new TypeError(`${label}.entryId index is too large.`);
  const recordUrl = new URL(normalizeHttpsUrl(value.url, `${label}.url`));
  const query = [...recordUrl.searchParams.entries()];
  if (
    recordUrl.origin !== SIGSTORE_REKOR_ORIGIN ||
    recordUrl.pathname !== SIGSTORE_REKOR_RECORD_PATH ||
    query.length !== 1 ||
    query[0][0] !== "logIndex" ||
    query[0][1] !== String(logIndex)
  ) {
    throw new TypeError(`${label}.url must identify the exact public Rekor log index.`);
  }
  return {
    provider: "sigstore-rekor",
    logId,
    entryId,
    integratedTime: requireInteger(value.integratedTime, `${label}.integratedTime`, { minimum: 1 }),
    bundleSha256: requireSha256(value.bundleSha256, `${label}.bundleSha256`),
    url: recordUrl.toString(),
  };
}

function sortedArtifacts(value, label, { minimum = 0 } = {}) {
  if (!Array.isArray(value) || value.length < minimum) {
    throw new TypeError(`${label} must contain at least ${minimum} item(s).`);
  }
  const artifacts = value.map((artifact, index) => normalizeArtifact(artifact, `${label}[${index}]`));
  if (new Set(artifacts.map(({ name }) => name)).size !== artifacts.length) {
    throw new TypeError(`${label} contains duplicate artifact names.`);
  }
  return artifacts.sort((left, right) => compareStrings(left.name, right.name));
}

function normalizePreviousRelease(value, currentReleaseId) {
  if (value === null) return null;
  exactKeys(value, ["releaseId", "manifestSha256"], "previousRelease");
  const releaseId = requireString(value.releaseId, "previousRelease.releaseId", {
    maximum: 120,
    pattern: RELEASE_ID,
  });
  if (releaseId === currentReleaseId) {
    throw new TypeError("previousRelease.releaseId must differ from releaseId.");
  }
  return {
    releaseId,
    manifestSha256: requireSha256(
      value.manifestSha256,
      "previousRelease.manifestSha256",
    ),
  };
}

export function normalizeReleaseManifest(value, { requireProduction = false } = {}) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "releaseId",
      "evaluatorKeyEpochId",
      "previousRelease",
      "releaseStage",
      "createdAt",
      "sourceDateEpoch",
      "source",
      "protocol",
      "trust",
      "artifacts",
      "database",
      "productionPolicy",
      "evidence",
    ],
    "release manifest",
  );
  if (value.schemaVersion !== 1) throw new TypeError("release manifest schemaVersion is unsupported.");
  if (!['candidate', 'production'].includes(value.releaseStage)) {
    throw new TypeError("release manifest releaseStage is unsupported.");
  }
  if (requireProduction && value.releaseStage !== "production") {
    throw new TypeError("A production release manifest is required.");
  }
  const releaseId = requireString(value.releaseId, "releaseId", { maximum: 120, pattern: RELEASE_ID });
  const evaluatorKeyEpochId = requireString(
    value.evaluatorKeyEpochId,
    "evaluatorKeyEpochId",
    { maximum: 120, pattern: RELEASE_ID },
  );
  const previousRelease = normalizePreviousRelease(value.previousRelease, releaseId);
  const sourceDateEpoch = requireInteger(value.sourceDateEpoch, "sourceDateEpoch");
  const createdAt = requireCanonicalTimestamp(value.createdAt, "createdAt");
  if (createdAt !== timestampFromEpoch(sourceDateEpoch)) {
    throw new TypeError("createdAt must be derived exactly from sourceDateEpoch.");
  }

  exactKeys(value.source, ["repository", "revision", "license", "exportArchive", "exportManifest"], "source");
  if (value.source.license !== "Apache-2.0") throw new TypeError("source.license must be Apache-2.0.");

  exactKeys(
    value.protocol,
    [
      "version",
      "cipherSuite",
      "paddedPlaintextBytes",
      "payloadFrameBytes",
      "userWrapBytes",
      "evaluatorWrapBytes",
    ],
    "protocol",
  );
  const protocol = {
    version: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    paddedPlaintextBytes: 4096,
    payloadFrameBytes: 4124,
    userWrapBytes: 60,
    evaluatorWrapBytes: 157,
  };
  if (Object.entries(protocol).some(([key, expected]) => value.protocol[key] !== expected)) {
    throw new TypeError("protocol does not match the reviewed private-response protocol v1.");
  }

  exactKeys(
    value.trust,
    [
      "evaluatorEncryption",
      "resultSigning",
      "policySigning",
      "receiptTransparencySigning",
      "releaseManifestSigning",
      "workload",
    ],
    "trust",
  );
  const evaluatorEncryption = normalizeKey(
      value.trust.evaluatorEncryption,
      "trust.evaluatorEncryption",
      "P256_ECDH_HKDF_SHA256_AES256_GCM",
    );
  const resultSigning = normalizeKey(
    value.trust.resultSigning,
    "trust.resultSigning",
    "ECDSA_P256_SHA256",
  );
  const policySigning = normalizeKey(
    value.trust.policySigning,
    "trust.policySigning",
    "ECDSA_P256_SHA256",
  );
  const receiptTransparencySigning = normalizeKey(
      value.trust.receiptTransparencySigning,
      "trust.receiptTransparencySigning",
      "ECDSA_P256_SHA256",
    );
  const releaseManifestSigning = normalizeKey(
    value.trust.releaseManifestSigning,
    "trust.releaseManifestSigning",
    "ECDSA_P256_SHA256",
  );
  const operationalKeyBinding = {
    evaluatorKeyEpochId,
    evaluatorEncryption,
    resultSigning,
    policySigning,
    receiptTransparencySigning,
  };
  const trust = {
    evaluatorEncryption,
    resultSigning,
    policySigning,
    receiptTransparencySigning,
    releaseManifestSigning,
    workload: normalizeWorkload(value.trust.workload, operationalKeyBinding),
  };
  const trustKeys = [
    trust.evaluatorEncryption,
    trust.resultSigning,
    trust.policySigning,
    trust.receiptTransparencySigning,
    trust.releaseManifestSigning,
  ];
  if (
    new Set(trustKeys.map(({ keyId }) => keyId)).size !== trustKeys.length ||
    new Set(trustKeys.map(({ publicKeySha256 }) => publicKeySha256)).size !== trustKeys.length
  ) {
    throw new TypeError("Every release trust purpose must use a distinct key ID and public key.");
  }

  exactKeys(value.artifacts, ["web", "ios", "ordinaryApi", "evaluator", "scheduler"], "artifacts");
  exactKeys(
    value.artifacts.web,
    ["publicOrigin", "deploymentArchive", "assetManifestSha256", "entryDocumentSha256"],
    "artifacts.web",
  );
  exactKeys(
    value.artifacts.ios,
    ["bundleIdentifier", "version", "build", "submissionArchive", "normalizedBinarySha256"],
    "artifacts.ios",
  );

  exactKeys(value.database, ["migrationSetSha256", "schemaSha256"], "database");
  exactKeys(
    value.productionPolicy,
    ["configurationSha256", "testAuthenticationEnabled", "debugEnabled", "requestBodyLoggingEnabled"],
    "productionPolicy",
  );
  if (
    value.productionPolicy.testAuthenticationEnabled !== false ||
    value.productionPolicy.debugEnabled !== false ||
    value.productionPolicy.requestBodyLoggingEnabled !== false
  ) {
    throw new TypeError("Production policy must disable test authentication, debug mode, and request-body logging.");
  }

  exactKeys(
    value.evidence,
    ["sboms", "provenance", "transparency", "transitions", "deployments", "audits"],
    "evidence",
  );
  if (!Array.isArray(value.evidence.provenance) || !Array.isArray(value.evidence.transparency)) {
    throw new TypeError("evidence provenance and transparency fields must be arrays.");
  }
  const provenance = value.evidence.provenance
    .map(normalizeProvenance)
    .sort((left, right) => compareStrings(left.statement.name, right.statement.name));
  const transparency = value.evidence.transparency
    .map(normalizeTransparency)
    .sort((left, right) => compareStrings(`${left.provider}:${left.logId}:${left.entryId}`, `${right.provider}:${right.logId}:${right.entryId}`));

  if (
    value.releaseStage === "production" &&
    (provenance.length === 0 || transparency.length === 0 || value.evidence.audits.length === 0)
  ) {
    throw new TypeError("A production manifest requires provenance, transparency, and audit evidence.");
  }

  const normalized = {
    schemaVersion: 1,
    releaseId,
    evaluatorKeyEpochId,
    previousRelease,
    releaseStage: value.releaseStage,
    createdAt,
    sourceDateEpoch,
    source: {
      repository: normalizeHttpsUrl(value.source.repository, "source.repository"),
      revision: requireString(value.source.revision, "source.revision", {
        minimum: 40,
        maximum: 64,
        pattern: REVISION,
      }),
      license: "Apache-2.0",
      exportArchive: normalizeArtifact(value.source.exportArchive, "source.exportArchive"),
      exportManifest: normalizeArtifact(value.source.exportManifest, "source.exportManifest"),
    },
    protocol,
    trust,
    artifacts: {
      web: {
        publicOrigin: normalizeHttpsUrl(value.artifacts.web.publicOrigin, "artifacts.web.publicOrigin", {
          originOnly: true,
        }),
        deploymentArchive: normalizeArtifact(
          value.artifacts.web.deploymentArchive,
          "artifacts.web.deploymentArchive",
        ),
        assetManifestSha256: requireSha256(
          value.artifacts.web.assetManifestSha256,
          "artifacts.web.assetManifestSha256",
        ),
        entryDocumentSha256: requireSha256(
          value.artifacts.web.entryDocumentSha256,
          "artifacts.web.entryDocumentSha256",
        ),
      },
      ios: {
        bundleIdentifier: requireString(value.artifacts.ios.bundleIdentifier, "artifacts.ios.bundleIdentifier", {
          minimum: 3,
          maximum: 255,
          pattern: IOS_BUNDLE_IDENTIFIER,
        }),
        version: requireString(value.artifacts.ios.version, "artifacts.ios.version", {
          maximum: 40,
          pattern: IOS_VERSION,
        }),
        build: requireString(value.artifacts.ios.build, "artifacts.ios.build", {
          maximum: 40,
          pattern: IOS_VERSION,
        }),
        submissionArchive: normalizeArtifact(
          value.artifacts.ios.submissionArchive,
          "artifacts.ios.submissionArchive",
        ),
        normalizedBinarySha256: requireSha256(
          value.artifacts.ios.normalizedBinarySha256,
          "artifacts.ios.normalizedBinarySha256",
        ),
      },
      ordinaryApi: normalizeArtifact(value.artifacts.ordinaryApi, "artifacts.ordinaryApi"),
      evaluator: normalizeArtifact(value.artifacts.evaluator, "artifacts.evaluator"),
      scheduler: normalizeArtifact(value.artifacts.scheduler, "artifacts.scheduler"),
    },
    database: {
      migrationSetSha256: requireSha256(value.database.migrationSetSha256, "database.migrationSetSha256"),
      schemaSha256: requireSha256(value.database.schemaSha256, "database.schemaSha256"),
    },
    productionPolicy: {
      configurationSha256: requireSha256(
        value.productionPolicy.configurationSha256,
        "productionPolicy.configurationSha256",
      ),
      testAuthenticationEnabled: false,
      debugEnabled: false,
      requestBodyLoggingEnabled: false,
    },
    evidence: {
      sboms: sortedArtifacts(value.evidence.sboms, "evidence.sboms", { minimum: 1 }),
      provenance,
      transparency,
      transitions: sortedArtifacts(value.evidence.transitions, "evidence.transitions"),
      deployments: sortedArtifacts(value.evidence.deployments, "evidence.deployments"),
      audits: sortedArtifacts(value.evidence.audits, "evidence.audits"),
    },
  };
  const artifactReferences = [
    normalized.source.exportArchive,
    normalized.source.exportManifest,
    normalized.artifacts.web.deploymentArchive,
    normalized.artifacts.ios.submissionArchive,
    normalized.artifacts.ordinaryApi,
    normalized.artifacts.evaluator,
    normalized.artifacts.scheduler,
    ...normalized.evidence.sboms,
    ...normalized.evidence.transitions,
    ...normalized.evidence.provenance.flatMap(({ statement, bundle }) => [statement, bundle]),
    ...normalized.evidence.deployments,
    ...normalized.evidence.audits,
  ];
  if (new Set(artifactReferences.map(({ name }) => name)).size !== artifactReferences.length) {
    throw new TypeError("Every release artifact must have a globally unique name.");
  }
  if (normalized.releaseStage === "production") {
    if (artifactReferences.some(({ url }) => url === null)) {
      throw new TypeError("Every production artifact and evidence object must have a durable HTTPS URL.");
    }
    if (normalized.evidence.sboms.some(({ mediaType }) => mediaType !== "application/spdx+json")) {
      throw new TypeError("Production SBOM evidence must use application/spdx+json.");
    }
    if (
      normalized.evidence.provenance.some(
        ({ statement, bundle }) =>
          statement.mediaType !== "application/vnd.in-toto+json" ||
          !/^application\/vnd\.dev\.sigstore\.bundle(?:\.v[0-9]+(?:\.[0-9]+)*)?\+json$/u.test(
            bundle.mediaType,
          ),
      )
    ) {
      throw new TypeError(
        "Production provenance evidence must use in-toto statement and Sigstore bundle media types.",
      );
    }
    if (normalized.evidence.audits.some(({ mediaType }) => mediaType !== "application/pdf")) {
      throw new TypeError("Production audit evidence must use application/pdf.");
    }
    const evaluatorTransitions = normalized.evidence.transitions.filter(
      ({ name, mediaType }) =>
        name === "evaluator-epoch-transition.json" &&
        mediaType === "application/vnd.herd.evaluator-epoch-transition.v2+json",
    );
    const releaseContinuity = normalized.evidence.transitions.filter(
      ({ name, mediaType }) =>
        name === "release-continuity.json" &&
        mediaType === "application/vnd.herd.release-continuity.v1+json",
    );
    if (
      evaluatorTransitions.length !== 1 ||
      releaseContinuity.length !== (normalized.previousRelease === null ? 0 : 1) ||
      normalized.evidence.transitions.length !==
        evaluatorTransitions.length + releaseContinuity.length
    ) {
      throw new TypeError(
        "Production transition evidence does not exactly match bootstrap or successor requirements.",
      );
    }
    const requiredSubjects = new Map(
      [
        normalized.source.exportArchive,
        normalized.source.exportManifest,
        normalized.artifacts.web.deploymentArchive,
        normalized.artifacts.ios.submissionArchive,
        normalized.artifacts.ordinaryApi,
        normalized.artifacts.evaluator,
        normalized.artifacts.scheduler,
        ...normalized.evidence.sboms,
        ...normalized.evidence.transitions,
      ].map(({ name, sha256 }) => [name, sha256]),
    );
    const coveredSubjects = new Map();
    for (const provenanceRecord of normalized.evidence.provenance) {
      for (const subject of provenanceRecord.subjects) {
        if (coveredSubjects.has(subject.name)) {
          throw new TypeError("Production provenance covers a subject name more than once.");
        }
        coveredSubjects.set(subject.name, subject.sha256);
      }
    }
    if (
      coveredSubjects.size !== requiredSubjects.size ||
      [...requiredSubjects].some(
        ([name, sha256]) => coveredSubjects.get(name) !== sha256,
      )
    ) {
      throw new TypeError(
        "Production provenance must exactly cover every source, client, service, and SBOM artifact.",
      );
    }
    const provenanceBundles = new Set(
      normalized.evidence.provenance.map(({ bundle }) => bundle.sha256),
    );
    const transparentBundles = new Set(
      normalized.evidence.transparency.map(({ bundleSha256 }) => bundleSha256),
    );
    if (
      transparentBundles.size !== provenanceBundles.size ||
      [...provenanceBundles].some((sha256) => !transparentBundles.has(sha256)) ||
      normalized.evidence.transparency.some(
        ({ integratedTime }) => integratedTime < normalized.sourceDateEpoch,
      )
    ) {
      throw new TypeError(
        "Every production transparency record must bind a provenance bundle at or after the source epoch.",
      );
    }
  }
  return normalized;
}

export function canonicalReleaseManifest(value, options) {
  return canonicalJson(normalizeReleaseManifest(value, options));
}

export function manifestArtifactReferences(manifest) {
  const normalized = normalizeReleaseManifest(manifest);
  return [
    normalized.source.exportArchive,
    normalized.source.exportManifest,
    normalized.artifacts.web.deploymentArchive,
    normalized.artifacts.ios.submissionArchive,
    normalized.artifacts.ordinaryApi,
    normalized.artifacts.evaluator,
    normalized.artifacts.scheduler,
    ...normalized.evidence.sboms,
    ...normalized.evidence.transitions,
    ...normalized.evidence.provenance.flatMap(({ statement, bundle }) => [statement, bundle]),
    ...normalized.evidence.deployments,
    ...normalized.evidence.audits,
  ];
}

export function assertManifestObject(value) {
  if (!isPlainObject(value)) throw new TypeError("Release manifest must be an object.");
  return value;
}
