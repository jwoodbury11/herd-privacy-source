import { canonicalJson, canonicalStringify, sha256Hex } from "./canonical.mjs";
import { evaluatorKeyEpochSha256 } from "./evaluator-key-epoch.mjs";

function same(left, right) {
  return canonicalStringify(left) === canonicalStringify(right);
}

function keyIdentity(value) {
  return {
    keyId: value.keyId,
    publicKey: value.publicKey,
    publicKeySha256: value.publicKeySha256,
  };
}

export function verifyReleaseContinuity(
  previousManifest,
  nextManifest,
  {
    previousManifestSha256 = sha256Hex(
      Buffer.from(canonicalJson(previousManifest), "utf8"),
    ),
  } = {},
) {
  if (previousManifest.releaseId === nextManifest.releaseId) {
    throw new TypeError("A successor release must use a new artifact release ID.");
  }
  if (
    nextManifest.previousRelease?.releaseId !== previousManifest.releaseId ||
    nextManifest.previousRelease?.manifestSha256 !== previousManifestSha256
  ) {
    throw new TypeError(
      "The successor manifest does not name the exact preceding signed release manifest.",
    );
  }
  if (nextManifest.createdAt <= previousManifest.createdAt) {
    throw new TypeError("A successor release must have a later creation timestamp.");
  }
  if (
    !same(
      nextManifest.trust.releaseManifestSigning,
      previousManifest.trust.releaseManifestSigning,
    )
  ) {
    throw new TypeError("The release-manifest signing identity changed.");
  }
  if (
    !same(
      nextManifest.trust.receiptTransparencySigning,
      previousManifest.trust.receiptTransparencySigning,
    )
  ) {
    throw new TypeError(
      "The lifetime-global response-transparency signing identity changed.",
    );
  }

  const previousEpochSha256 = evaluatorKeyEpochSha256(previousManifest);
  const nextEpochSha256 = evaluatorKeyEpochSha256(nextManifest);
  if (nextManifest.evaluatorKeyEpochId === previousManifest.evaluatorKeyEpochId) {
    if (nextEpochSha256 !== previousEpochSha256) {
      throw new TypeError(
        "An existing evaluator epoch must retain its exact image and evaluator key tuple.",
      );
    }
    return {
      schemaVersion: 1,
      mode: "artifact-release",
      previousReleaseId: previousManifest.releaseId,
      nextReleaseId: nextManifest.releaseId,
      evaluatorKeyEpochId: nextManifest.evaluatorKeyEpochId,
      evaluatorKeyEpochSha256: nextEpochSha256,
    };
  }

  for (const [purpose, field] of [
    ["response-decryption", "evaluatorEncryption"],
    ["evaluation-result signing", "resultSigning"],
    ["policy signing", "policySigning"],
  ]) {
    const previousKey = keyIdentity(previousManifest.trust[field]);
    const nextKey = keyIdentity(nextManifest.trust[field]);
    if (
      previousKey.keyId === nextKey.keyId ||
      previousKey.publicKey === nextKey.publicKey ||
      previousKey.publicKeySha256 === nextKey.publicKeySha256
    ) {
      throw new TypeError(
        `A new evaluator epoch must replace the complete ${purpose} key identity.`,
      );
    }
  }
  return {
    schemaVersion: 1,
    mode: "evaluator-epoch-rotation",
    previousReleaseId: previousManifest.releaseId,
    nextReleaseId: nextManifest.releaseId,
    previousEvaluatorKeyEpochId: previousManifest.evaluatorKeyEpochId,
    nextEvaluatorKeyEpochId: nextManifest.evaluatorKeyEpochId,
    evaluatorKeyEpochSha256: nextEpochSha256,
  };
}
