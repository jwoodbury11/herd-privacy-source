import { canonicalStringify, sha256Hex } from "./canonical.mjs";
import {
  evaluatorKeyEpochDescriptor,
  evaluatorKeyEpochSha256,
  RESPONSE_TRANSPARENCY_LOG_ID,
} from "./evaluator-key-epoch.mjs";

const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const P256_PUBLIC_KEY = /^[A-Za-z0-9_-]{87}$/u;
const IMAGE_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const MAXIMUM_STATUS_AGE_MS = 5 * 60 * 1000;

function exactRecord(value, keys, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError(`${label} is not an object.`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index])
  ) {
    throw new TypeError(`${label} has unsupported fields.`);
  }
  return value;
}

function timestamp(value, label) {
  const instant = Date.parse(value);
  if (
    typeof value !== "string" ||
    !Number.isFinite(instant) ||
    new Date(instant).toISOString() !== value
  ) {
    throw new TypeError(`${label} is not a canonical UTC timestamp.`);
  }
  return value;
}

function count(value, label) {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} is not a nonnegative safe integer.`);
  }
  return value;
}

function generation(value, label) {
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new TypeError(`${label} is not a positive safe integer.`);
  }
  return value;
}

function identifier(value, label) {
  if (typeof value !== "string" || !IDENTIFIER.test(value)) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function digest(value, label) {
  if (typeof value !== "string" || !SHA256.test(value)) {
    throw new TypeError(`${label} is not a lowercase SHA-256 digest.`);
  }
  return value;
}

function runtimeKey(value, label) {
  const key = exactRecord(value, ["keyId", "publicKey"], label);
  if (!P256_PUBLIC_KEY.test(key.publicKey)) {
    throw new TypeError(`${label}.publicKey is not a raw P-256 key.`);
  }
  return {
    keyId: identifier(key.keyId, `${label}.keyId`),
    publicKey: key.publicKey,
  };
}

function same(left, right) {
  return left.keyId === right.keyId && left.publicKey === right.publicKey;
}

function transparencyIdentitySha256(key) {
  return sha256Hex(
    Buffer.from(
      canonicalStringify({
        schemaVersion: 1,
        logId: RESPONSE_TRANSPARENCY_LOG_ID,
        keyId: key.keyId,
        publicKey: key.publicKey,
      }),
      "utf8",
    ),
  );
}

function epochDescriptorFromStatus(status, keys) {
  return {
    schemaVersion: 1,
    evaluatorKeyEpochId: status.evaluatorKeyEpochId,
    workloadImageDigest: status.workloadImageDigest,
    responseDecryption: keys.responseDecryption,
    evaluationResultSigning: keys.evaluationResultSigning,
    policySigning: keys.policySigning,
    responseTransparency: {
      logId: RESPONSE_TRANSPARENCY_LOG_ID,
      ...keys.responseTransparencySigning,
    },
  };
}

function normalizeDrainCounts(value, label) {
  exactRecord(
    value,
    [
      "unresolvedPolicyCount",
      "activeEvaluationLeaseCount",
      "activeEvaluationJobCount",
      "uncertifiedTransparencyCount",
    ],
    label,
  );
  return {
    unresolvedPolicyCount: count(
      value.unresolvedPolicyCount,
      `${label}.unresolvedPolicyCount`,
    ),
    activeEvaluationLeaseCount: count(
      value.activeEvaluationLeaseCount,
      `${label}.activeEvaluationLeaseCount`,
    ),
    activeEvaluationJobCount: count(
      value.activeEvaluationJobCount,
      `${label}.activeEvaluationJobCount`,
    ),
    uncertifiedTransparencyCount: count(
      value.uncertifiedTransparencyCount,
      `${label}.uncertifiedTransparencyCount`,
    ),
  };
}

function normalizeTransition(value) {
  if (value === null) return null;
  exactRecord(
    value,
    [
      "transitionId",
      "fromGeneration",
      "fromEvaluatorKeyEpochId",
      "fromEpochDescriptorSha256",
      "transparencyIdentitySha256",
      "drainStartedAt",
      "drainCounts",
      "toGeneration",
      "toEvaluatorKeyEpochId",
      "toEpochDescriptorSha256",
      "activatedAt",
      "canonicalActivationEvidence",
      "activationEvidenceSha256",
    ],
    "evaluator epoch transition",
  );
  const transition = {
    transitionId: identifier(value.transitionId, "transitionId"),
    fromGeneration: generation(value.fromGeneration, "fromGeneration"),
    fromEvaluatorKeyEpochId: identifier(
      value.fromEvaluatorKeyEpochId,
      "fromEvaluatorKeyEpochId",
    ),
    fromEpochDescriptorSha256: digest(
      value.fromEpochDescriptorSha256,
      "fromEpochDescriptorSha256",
    ),
    transparencyIdentitySha256: digest(
      value.transparencyIdentitySha256,
      "transition transparencyIdentitySha256",
    ),
    drainStartedAt: timestamp(value.drainStartedAt, "transition drainStartedAt"),
    drainCounts: normalizeDrainCounts(value.drainCounts, "transition drainCounts"),
    toGeneration: value.toGeneration,
    toEvaluatorKeyEpochId: value.toEvaluatorKeyEpochId,
    toEpochDescriptorSha256: value.toEpochDescriptorSha256,
    activatedAt: value.activatedAt,
    canonicalActivationEvidence: value.canonicalActivationEvidence,
    activationEvidenceSha256: value.activationEvidenceSha256,
  };
  const activationFields = [
    transition.toGeneration,
    transition.toEvaluatorKeyEpochId,
    transition.toEpochDescriptorSha256,
    transition.activatedAt,
    transition.canonicalActivationEvidence,
    transition.activationEvidenceSha256,
  ];
  const activated = activationFields.every((item) => item !== null);
  if (!activated && activationFields.some((item) => item !== null)) {
    throw new TypeError("Evaluator epoch activation evidence is incomplete.");
  }
  if (!activated) return transition;

  transition.toGeneration = generation(transition.toGeneration, "toGeneration");
  if (transition.toGeneration !== transition.fromGeneration + 1) {
    throw new TypeError("Evaluator epoch transition generations are not consecutive.");
  }
  transition.toEvaluatorKeyEpochId = identifier(
    transition.toEvaluatorKeyEpochId,
    "toEvaluatorKeyEpochId",
  );
  transition.toEpochDescriptorSha256 = digest(
    transition.toEpochDescriptorSha256,
    "toEpochDescriptorSha256",
  );
  transition.activatedAt = timestamp(transition.activatedAt, "transition activatedAt");
  if (typeof transition.canonicalActivationEvidence !== "string") {
    throw new TypeError("Evaluator epoch canonical activation evidence is invalid.");
  }
  transition.activationEvidenceSha256 = digest(
    transition.activationEvidenceSha256,
    "activationEvidenceSha256",
  );
  const expectedEvidence = canonicalStringify({
    schemaVersion: 1,
    transitionId: transition.transitionId,
    from: {
      generation: transition.fromGeneration,
      evaluatorKeyEpochId: transition.fromEvaluatorKeyEpochId,
      epochDescriptorSha256: transition.fromEpochDescriptorSha256,
    },
    to: {
      generation: transition.toGeneration,
      evaluatorKeyEpochId: transition.toEvaluatorKeyEpochId,
      epochDescriptorSha256: transition.toEpochDescriptorSha256,
    },
    transparencyIdentitySha256: transition.transparencyIdentitySha256,
    drainStartedAt: transition.drainStartedAt,
    activatedAt: transition.activatedAt,
    finalDrainCounts: {
      unresolvedPolicyCount: 0,
      activeEvaluationLeaseCount: 0,
      activeEvaluationJobCount: 0,
      uncertifiedTransparencyCount: 0,
    },
  });
  if (
    transition.canonicalActivationEvidence !== expectedEvidence ||
    transition.activationEvidenceSha256 !==
      sha256Hex(Buffer.from(expectedEvidence, "utf8"))
  ) {
    throw new TypeError("Evaluator epoch activation evidence is not canonical or authentic.");
  }
  return transition;
}

export function normalizeEvaluatorEpochStatus(value, { now = Date.now } = {}) {
  const status = exactRecord(
    value,
    [
      "schemaVersion",
      "artifactReleaseId",
      "evaluatorKeyEpochId",
      "workloadImageDigest",
      "epochDescriptorSha256",
      "transparencyIdentitySha256",
      "keys",
      "state",
      "runtimeMatchesState",
      "unresolvedPolicyCount",
      "activeEvaluationLeaseCount",
      "activeEvaluationJobCount",
      "uncertifiedTransparencyCount",
      "minimumDrainReached",
      "drained",
      "transition",
      "observedAt",
    ],
    "evaluator epoch status",
  );
  if (status.schemaVersion !== 2 || !IMAGE_DIGEST.test(status.workloadImageDigest)) {
    throw new TypeError("Evaluator epoch status schema or image digest is invalid.");
  }
  const artifactReleaseId =
    status.artifactReleaseId === null
      ? null
      : identifier(status.artifactReleaseId, "artifactReleaseId");
  const evaluatorKeyEpochId = identifier(
    status.evaluatorKeyEpochId,
    "evaluatorKeyEpochId",
  );
  const keysValue = exactRecord(
    status.keys,
    [
      "responseDecryption",
      "evaluationResultSigning",
      "policySigning",
      "responseTransparencySigning",
    ],
    "evaluator epoch status keys",
  );
  const keys = {
    responseDecryption: runtimeKey(
      keysValue.responseDecryption,
      "response-decryption key",
    ),
    evaluationResultSigning: runtimeKey(
      keysValue.evaluationResultSigning,
      "result-signing key",
    ),
    policySigning: runtimeKey(keysValue.policySigning, "policy-signing key"),
    responseTransparencySigning: runtimeKey(
      keysValue.responseTransparencySigning,
      "response-transparency key",
    ),
  };
  const expectedEpochDescriptorSha256 = sha256Hex(
    Buffer.from(canonicalStringify(epochDescriptorFromStatus(status, keys)), "utf8"),
  );
  const epochDescriptorSha256 = digest(
    status.epochDescriptorSha256,
    "epochDescriptorSha256",
  );
  const expectedTransparencyIdentitySha256 = transparencyIdentitySha256(
    keys.responseTransparencySigning,
  );
  const transparencyIdentity = digest(
    status.transparencyIdentitySha256,
    "transparencyIdentitySha256",
  );
  if (
    epochDescriptorSha256 !== expectedEpochDescriptorSha256 ||
    transparencyIdentity !== expectedTransparencyIdentitySha256
  ) {
    throw new TypeError("Evaluator epoch status digests do not match its runtime tuple.");
  }

  const stateValue = exactRecord(
    status.state,
    [
      "generation",
      "mode",
      "evaluatorKeyEpochId",
      "epochDescriptorSha256",
      "transparencyIdentitySha256",
      "activatedAt",
      "drainStartedAt",
      "updatedAt",
    ],
    "evaluator epoch state",
  );
  if (!['active', 'draining'].includes(stateValue.mode)) {
    throw new TypeError("Evaluator epoch state mode is invalid.");
  }
  const state = {
    generation: generation(stateValue.generation, "state.generation"),
    mode: stateValue.mode,
    evaluatorKeyEpochId: identifier(
      stateValue.evaluatorKeyEpochId,
      "state.evaluatorKeyEpochId",
    ),
    epochDescriptorSha256: digest(
      stateValue.epochDescriptorSha256,
      "state.epochDescriptorSha256",
    ),
    transparencyIdentitySha256: digest(
      stateValue.transparencyIdentitySha256,
      "state.transparencyIdentitySha256",
    ),
    activatedAt: timestamp(stateValue.activatedAt, "state.activatedAt"),
    drainStartedAt:
      stateValue.drainStartedAt === null
        ? null
        : timestamp(stateValue.drainStartedAt, "state.drainStartedAt"),
    updatedAt: timestamp(stateValue.updatedAt, "state.updatedAt"),
  };
  if (
    state.evaluatorKeyEpochId !== evaluatorKeyEpochId ||
    state.epochDescriptorSha256 !== epochDescriptorSha256 ||
    state.transparencyIdentitySha256 !== transparencyIdentity ||
    state.updatedAt < state.activatedAt ||
    (state.mode === "active" && state.drainStartedAt !== null) ||
    (state.mode === "draining" &&
      (state.drainStartedAt === null || state.drainStartedAt > state.updatedAt))
  ) {
    throw new TypeError("Evaluator epoch state conflicts with its runtime tuple.");
  }
  if (typeof status.runtimeMatchesState !== "boolean") {
    throw new TypeError("runtimeMatchesState is not boolean.");
  }
  const counts = normalizeDrainCounts(
    {
      unresolvedPolicyCount: status.unresolvedPolicyCount,
      activeEvaluationLeaseCount: status.activeEvaluationLeaseCount,
      activeEvaluationJobCount: status.activeEvaluationJobCount,
      uncertifiedTransparencyCount: status.uncertifiedTransparencyCount,
    },
    "current drain counts",
  );
  if (
    typeof status.minimumDrainReached !== "boolean" ||
    typeof status.drained !== "boolean"
  ) {
    throw new TypeError("Evaluator epoch drain flags are not boolean.");
  }
  const expectedDrained =
    state.mode === "draining" &&
    status.minimumDrainReached &&
    Object.values(counts).every((item) => item === 0);
  if (
    status.drained !== expectedDrained ||
    (state.mode === "active" && status.minimumDrainReached)
  ) {
    throw new TypeError("Evaluator epoch drained status is internally inconsistent.");
  }

  const transition = normalizeTransition(status.transition);
  if (state.mode === "draining") {
    if (
      transition === null ||
      transition.fromGeneration !== state.generation ||
      transition.fromEvaluatorKeyEpochId !== state.evaluatorKeyEpochId ||
      transition.fromEpochDescriptorSha256 !== state.epochDescriptorSha256 ||
      transition.transparencyIdentitySha256 !== state.transparencyIdentitySha256 ||
      transition.drainStartedAt !== state.drainStartedAt ||
      transition.toGeneration !== null
    ) {
      throw new TypeError("Draining evaluator epoch lacks its pending transition record.");
    }
  } else if (state.generation === 1) {
    if (transition !== null) {
      throw new TypeError("Initial active evaluator epoch has unexpected transition evidence.");
    }
  } else if (
    transition === null ||
    transition.toGeneration !== state.generation ||
    transition.toEvaluatorKeyEpochId !== state.evaluatorKeyEpochId ||
    transition.toEpochDescriptorSha256 !== state.epochDescriptorSha256 ||
    transition.transparencyIdentitySha256 !== state.transparencyIdentitySha256
  ) {
    throw new TypeError("Active evaluator epoch lacks matching activation evidence.");
  }

  const observedAt = timestamp(status.observedAt, "observedAt");
  const age = now() - Date.parse(observedAt);
  if (age < -30_000 || age > MAXIMUM_STATUS_AGE_MS || observedAt < state.updatedAt) {
    throw new TypeError("Evaluator epoch status is stale or predates its state.");
  }
  return {
    schemaVersion: 2,
    artifactReleaseId,
    evaluatorKeyEpochId,
    workloadImageDigest: status.workloadImageDigest,
    epochDescriptorSha256,
    transparencyIdentitySha256: transparencyIdentity,
    keys,
    state,
    runtimeMatchesState: status.runtimeMatchesState,
    ...counts,
    minimumDrainReached: status.minimumDrainReached,
    drained: status.drained,
    transition,
    observedAt,
  };
}

export function verifyEvaluatorEpochTransition(nextManifest, statusInput, options = {}) {
  const status = normalizeEvaluatorEpochStatus(statusInput, options);
  const expectedCurrentArtifactReleaseId =
    nextManifest.previousRelease?.releaseId ?? nextManifest.releaseId;
  if (status.artifactReleaseId !== expectedCurrentArtifactReleaseId) {
    throw new TypeError(
      "Live artifact release ID does not match the signed current/predecessor release.",
    );
  }
  const nextDescriptor = evaluatorKeyEpochDescriptor(nextManifest);
  const nextEpochSha256 = evaluatorKeyEpochSha256(nextManifest);
  const next = {
    evaluatorKeyEpochId: nextManifest.evaluatorKeyEpochId,
    epochDescriptorSha256: nextEpochSha256,
    workloadImageDigest: nextDescriptor.workloadImageDigest,
    transparencyIdentitySha256: transparencyIdentitySha256(
      nextDescriptor.responseTransparency,
    ),
    keys: {
      responseDecryption: nextDescriptor.responseDecryption,
      evaluationResultSigning: nextDescriptor.evaluationResultSigning,
      policySigning: nextDescriptor.policySigning,
      responseTransparencySigning: {
        keyId: nextDescriptor.responseTransparency.keyId,
        publicKey: nextDescriptor.responseTransparency.publicKey,
      },
    },
  };
  if (!status.runtimeMatchesState) {
    throw new TypeError("Live evaluator runtime does not match the D1 epoch state.");
  }
  if (
    next.transparencyIdentitySha256 !== status.transparencyIdentitySha256 ||
    !same(
      next.keys.responseTransparencySigning,
      status.keys.responseTransparencySigning,
    )
  ) {
    throw new TypeError(
      "The lifetime-global response-transparency signing identity changed.",
    );
  }
  if (next.evaluatorKeyEpochId === status.evaluatorKeyEpochId) {
    if (
      status.state.mode !== "active" ||
      next.epochDescriptorSha256 !== status.epochDescriptorSha256
    ) {
      throw new TypeError(
        "An existing evaluator epoch must be active and retain its exact image and evaluator key tuple.",
      );
    }
    return {
      schemaVersion: 2,
      mode: "reuse-active-generation",
      previousArtifactReleaseId: status.artifactReleaseId,
      nextArtifactReleaseId: nextManifest.releaseId,
      generation: status.state.generation,
      previousEvaluatorKeyEpochId: status.evaluatorKeyEpochId,
      nextEvaluatorKeyEpochId: next.evaluatorKeyEpochId,
      nextEvaluatorKeyEpochSha256: next.epochDescriptorSha256,
      transparencyIdentitySha256: next.transparencyIdentitySha256,
      observedAt: status.observedAt,
      activationEvidenceSha256:
        status.transition?.activationEvidenceSha256 ?? null,
    };
  }
  if (
    status.state.mode !== "draining" ||
    !status.minimumDrainReached ||
    !status.drained ||
    status.transition === null
  ) {
    throw new TypeError(
      "Evaluator epoch rotation requires a persisted D1 draining generation, the minimum drain interval, and zero policies, leases, jobs, and uncertified transparency records.",
    );
  }
  for (const purpose of [
    "responseDecryption",
    "evaluationResultSigning",
    "policySigning",
  ]) {
    if (
      next.keys[purpose].keyId === status.keys[purpose].keyId ||
      next.keys[purpose].publicKey === status.keys[purpose].publicKey
    ) {
      throw new TypeError(
        `Evaluator epoch rotation must replace the complete ${purpose} key identity.`,
      );
    }
  }
  return {
    schemaVersion: 2,
    mode: "rotate-from-drained-generation",
    transitionId: status.transition.transitionId,
    previousArtifactReleaseId: status.artifactReleaseId,
    nextArtifactReleaseId: nextManifest.releaseId,
    expectedGeneration: status.state.generation,
    previousEvaluatorKeyEpochId: status.evaluatorKeyEpochId,
    previousEvaluatorKeyEpochSha256: status.epochDescriptorSha256,
    nextEvaluatorKeyEpochId: next.evaluatorKeyEpochId,
    nextEvaluatorKeyEpochSha256: next.epochDescriptorSha256,
    transparencyIdentitySha256: next.transparencyIdentitySha256,
    drainStartedAt: status.state.drainStartedAt,
    drainCounts: {
      unresolvedPolicyCount: status.unresolvedPolicyCount,
      activeEvaluationLeaseCount: status.activeEvaluationLeaseCount,
      activeEvaluationJobCount: status.activeEvaluationJobCount,
      uncertifiedTransparencyCount: status.uncertifiedTransparencyCount,
    },
    observedAt: status.observedAt,
  };
}

export function initialEvaluatorEpochRecord(nextManifest, observedAt) {
  if (nextManifest.previousRelease !== null) {
    throw new TypeError(
      "An initial evaluator epoch requires previousRelease to be null.",
    );
  }
  timestamp(observedAt, "Initial evaluator epoch observation time");
  const descriptor = evaluatorKeyEpochDescriptor(nextManifest);
  return {
    schemaVersion: 2,
    mode: "initial-generation",
    generation: 1,
    previousArtifactReleaseId: null,
    nextArtifactReleaseId: nextManifest.releaseId,
    previousEvaluatorKeyEpochId: null,
    nextEvaluatorKeyEpochId: nextManifest.evaluatorKeyEpochId,
    nextEvaluatorKeyEpochSha256: evaluatorKeyEpochSha256(nextManifest),
    transparencyIdentitySha256: transparencyIdentitySha256(
      descriptor.responseTransparency,
    ),
    observedAt,
  };
}
