const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const IMAGE_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/u;

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} is missing.`);
  }
  return value;
}

export function verifyLiveReadinessSample(value, expected = {}) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Live readiness response is not an object.");
  }
  if (value.schemaVersion !== 2) {
    throw new TypeError("Live readiness schema version is unsupported.");
  }
  if (value.readyForPrivateEventCreation !== true) {
    throw new TypeError("Production is not ready for private event creation.");
  }
  if (value.runtimeMatchesState !== true || value.state?.mode !== "active") {
    throw new TypeError("Live evaluator runtime does not match the active D1 epoch.");
  }
  const artifactReleaseId = requiredString(
    value.artifactReleaseId,
    "artifactReleaseId",
  );
  const evaluatorKeyEpochId = requiredString(
    value.evaluatorKeyEpochId,
    "evaluatorKeyEpochId",
  );
  const epochDescriptorSha256 = requiredString(
    value.epochDescriptorSha256,
    "epochDescriptorSha256",
  );
  const workloadImageDigest = requiredString(
    value.workloadImageDigest,
    "workloadImageDigest",
  );
  if (!SHA256_PATTERN.test(epochDescriptorSha256)) {
    throw new TypeError("epochDescriptorSha256 is invalid.");
  }
  if (!IMAGE_DIGEST_PATTERN.test(workloadImageDigest)) {
    throw new TypeError("workloadImageDigest is invalid.");
  }
  if (
    expected.artifactReleaseId &&
    artifactReleaseId !== expected.artifactReleaseId
  ) {
    throw new TypeError("Live artifact release ID does not match the expected release.");
  }
  if (
    expected.workloadImageDigest &&
    workloadImageDigest !== expected.workloadImageDigest
  ) {
    throw new TypeError("Live evaluator image does not match the expected digest.");
  }
  return {
    artifactReleaseId,
    evaluatorKeyEpochId,
    epochDescriptorSha256,
    workloadImageDigest,
    stateGeneration: value.state.generation,
  };
}

export function verifyStableLiveReadiness(samples, expected = {}) {
  if (!Array.isArray(samples) || samples.length < 2) {
    throw new TypeError("At least two live readiness samples are required.");
  }
  const normalized = samples.map((sample) =>
    verifyLiveReadinessSample(sample, expected),
  );
  const baseline = JSON.stringify(normalized[0]);
  if (normalized.some((sample) => JSON.stringify(sample) !== baseline)) {
    throw new TypeError("Production readiness samples disagree across deployed isolates.");
  }
  return normalized[0];
}
