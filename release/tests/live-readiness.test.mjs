import assert from "node:assert/strict";
import test from "node:test";

import {
  verifyLiveReadinessSample,
  verifyStableLiveReadiness,
} from "../lib/live-readiness.mjs";

const digest = `sha256:${"1".repeat(64)}`;
const descriptor = "2".repeat(64);

function sample(overrides = {}) {
  return {
    schemaVersion: 2,
    readyForPrivateEventCreation: true,
    artifactReleaseId: "2026.08.04.1",
    evaluatorKeyEpochId: "herd-evaluator-epoch-2026-08-04-v1",
    workloadImageDigest: digest,
    epochDescriptorSha256: descriptor,
    runtimeMatchesState: true,
    evaluatorCompatibility: {
      protocolVersion: 1,
      policyDescriptorCapability: "policy_descriptor_evaluator_measurement_v1",
    },
    state: { mode: "active", generation: 2 },
    ...overrides,
  };
}

test("live readiness requires the exact private-event creation fence", () => {
  assert.deepEqual(verifyLiveReadinessSample(sample()), {
    artifactReleaseId: "2026.08.04.1",
    evaluatorKeyEpochId: "herd-evaluator-epoch-2026-08-04-v1",
    workloadImageDigest: digest,
    evaluatorPolicyDescriptorCapability:
      "policy_descriptor_evaluator_measurement_v1",
    epochDescriptorSha256: descriptor,
    stateGeneration: 2,
  });
  assert.throws(
    () => verifyLiveReadinessSample(sample({ runtimeMatchesState: false })),
    /does not match the active D1 epoch/u,
  );
  assert.throws(
    () => verifyLiveReadinessSample(sample({ evaluatorCompatibility: undefined })),
    /does not support the deployed policy descriptor format/u,
  );
  assert.throws(
    () => verifyLiveReadinessSample(sample({ readyForPrivateEventCreation: false })),
    /not ready for private event creation/u,
  );
});

test("live readiness fails if deployment isolates disagree", () => {
  assert.deepEqual(verifyStableLiveReadiness([sample(), sample(), sample()]), {
    artifactReleaseId: "2026.08.04.1",
    evaluatorKeyEpochId: "herd-evaluator-epoch-2026-08-04-v1",
    workloadImageDigest: digest,
    evaluatorPolicyDescriptorCapability:
      "policy_descriptor_evaluator_measurement_v1",
    epochDescriptorSha256: descriptor,
    stateGeneration: 2,
  });
  assert.throws(
    () =>
      verifyStableLiveReadiness([
        sample(),
        sample({ workloadImageDigest: `sha256:${"3".repeat(64)}` }),
      ]),
    /samples disagree/u,
  );
});

test("live readiness pins the signed release and evaluator image", () => {
  assert.doesNotThrow(() =>
    verifyStableLiveReadiness([sample(), sample()], {
      artifactReleaseId: "2026.08.04.1",
      workloadImageDigest: digest,
    }),
  );
  assert.throws(
    () =>
      verifyStableLiveReadiness([sample(), sample()], {
        artifactReleaseId: "2026.08.04.2",
      }),
    /artifact release ID/u,
  );
});
