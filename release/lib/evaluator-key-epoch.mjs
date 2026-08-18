import { canonicalStringify, sha256Hex } from "./canonical.mjs";

export const RESPONSE_TRANSPARENCY_LOG_ID = "herd-response-log-v1";

function keyIdentity(value) {
  return { keyId: value.keyId, publicKey: value.publicKey };
}

export function evaluatorKeyEpochDescriptor(manifest) {
  return {
    schemaVersion: 1,
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    workloadImageDigest:
      `${manifest.trust.workload.policyMeasurement.algorithm}:` +
      manifest.trust.workload.policyMeasurement.value,
    responseDecryption: keyIdentity(manifest.trust.evaluatorEncryption),
    evaluationResultSigning: keyIdentity(manifest.trust.resultSigning),
    policySigning: keyIdentity(manifest.trust.policySigning),
    responseTransparency: {
      logId: RESPONSE_TRANSPARENCY_LOG_ID,
      ...keyIdentity(manifest.trust.receiptTransparencySigning),
    },
  };
}

// This digest deliberately excludes artifact release identity. Artifact-only
// releases may reuse an evaluator epoch only when this exact tuple is stable.
// The legacy workloadImageDigest wire name carries the stable policy
// measurement, not the independently attested artifact image digest.
export function evaluatorKeyEpochSha256(manifest) {
  return sha256Hex(
    Buffer.from(canonicalStringify(evaluatorKeyEpochDescriptor(manifest)), "utf8"),
  );
}
