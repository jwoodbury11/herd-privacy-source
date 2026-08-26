import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { chmod, mkdtemp, mkdir, readFile, symlink, unlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalJson, canonicalStringify, sha256Hex } from "../lib/canonical.mjs";
import { verifyLocalArtifacts } from "../lib/artifacts.mjs";
import {
  iosApplicationIdentifier,
  normalizeDeploymentStatement,
  verifyAppleAppSiteAssociation,
} from "../lib/deployment.mjs";
import {
  initialEvaluatorEpochRecord,
  normalizeEvaluatorEpochStatus,
  verifyEvaluatorEpochTransition,
} from "../lib/evaluator-epoch.mjs";
import {
  evaluatorKeyEpochDescriptor,
  evaluatorKeyEpochSha256,
} from "../lib/evaluator-key-epoch.mjs";
import { buildProductionConfig } from "../lib/production-config.mjs";
import {
  preflightProductionArtifacts,
  verifyWebArchive,
} from "../lib/production-preflight.mjs";
import {
  normalizeProductionReleaseTemplate,
  productionProvenanceArtifacts,
} from "../lib/production-template.mjs";
import {
  computeWorkloadKeyBindingHash,
  normalizeReleaseManifest,
} from "../lib/release-manifest.mjs";
import { verifyReleaseContinuity } from "../lib/release-continuity.mjs";
import { signCanonicalArtifact, verifyCanonicalArtifact } from "../lib/signature.mjs";
import { tarEntry } from "../../public-source/lib/export-core.mjs";
import { makeReleaseFixture } from "./fixture.mjs";

const run = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, "../..");
const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";

function transparencyIdentitySha256(descriptor) {
  return sha256Hex(Buffer.from(canonicalStringify({
    schemaVersion: 1,
    logId: "herd-response-log-v1",
    keyId: descriptor.responseTransparency.keyId,
    publicKey: descriptor.responseTransparency.publicKey,
  })));
}

function evaluatorEpochStatus(
  manifest,
  {
    mode = "active",
    generation = 1,
    counts = {
      unresolvedPolicyCount: 0,
      activeEvaluationLeaseCount: 0,
      activeEvaluationJobCount: 0,
      uncertifiedTransparencyCount: 0,
    },
  } = {},
) {
  const descriptor = evaluatorKeyEpochDescriptor(manifest);
  const epochDescriptorSha256 = evaluatorKeyEpochSha256(manifest);
  const transparencySha256 = transparencyIdentitySha256(descriptor);
  const draining = mode === "draining";
  const transition = draining
    ? {
        transitionId: "transition-2026-08",
        fromGeneration: generation,
        fromEvaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
        fromEpochDescriptorSha256: epochDescriptorSha256,
        transparencyIdentitySha256: transparencySha256,
        drainStartedAt: manifest.createdAt,
        drainCounts: counts,
        toGeneration: null,
        toEvaluatorKeyEpochId: null,
        toEpochDescriptorSha256: null,
        activatedAt: null,
        canonicalActivationEvidence: null,
        activationEvidenceSha256: null,
      }
    : null;
  return {
    schemaVersion: 2,
    artifactReleaseId: manifest.releaseId,
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    workloadImageDigest: descriptor.workloadImageDigest,
    epochDescriptorSha256,
    transparencyIdentitySha256: transparencySha256,
    keys: {
      responseDecryption: descriptor.responseDecryption,
      evaluationResultSigning: descriptor.evaluationResultSigning,
      policySigning: descriptor.policySigning,
      responseTransparencySigning: {
        keyId: descriptor.responseTransparency.keyId,
        publicKey: descriptor.responseTransparency.publicKey,
      },
    },
    state: {
      generation,
      mode,
      evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
      epochDescriptorSha256,
      transparencyIdentitySha256: transparencySha256,
      activatedAt: manifest.createdAt,
      drainStartedAt: draining ? manifest.createdAt : null,
      updatedAt: manifest.createdAt,
    },
    runtimeMatchesState: true,
    ...counts,
    minimumDrainReached: draining,
    drained: draining && Object.values(counts).every((value) => value === 0),
    transition,
    observedAt: manifest.createdAt,
  };
}

test("evaluator epoch identity uses the stable policy measurement across image rollouts", () => {
  const { manifest } = makeReleaseFixture();
  const descriptor = evaluatorKeyEpochDescriptor(manifest);
  assert.equal(
    descriptor.workloadImageDigest,
    `${manifest.trust.workload.policyMeasurement.algorithm}:${manifest.trust.workload.policyMeasurement.value}`,
  );
  assert.notEqual(
    descriptor.workloadImageDigest,
    `${manifest.trust.workload.imageDigest.algorithm}:${manifest.trust.workload.imageDigest.value}`,
  );
});

test("signed predecessor manifests map the legacy workload policy without relaxing new manifests", () => {
  const legacy = structuredClone(makeReleaseFixture().manifest);
  legacy.trust.workload.imageDigest = legacy.trust.workload.policyMeasurement;
  legacy.trust.workload.attestationClaimPolicy.imageDigest = legacy.trust.workload.policyMeasurement;
  delete legacy.trust.workload.policyMeasurement;
  delete legacy.trust.workload.attestationClaimPolicy.allowedImageDigests;

  assert.throws(() => normalizeReleaseManifest(legacy, { requireProduction: true }));
  const normalized = normalizeReleaseManifest(legacy, {
    requireProduction: true,
    allowLegacyWorkloadPolicy: true,
  });
  assert.deepEqual(normalized.trust.workload.policyMeasurement, legacy.trust.workload.imageDigest);
  assert.deepEqual(normalized.trust.workload.attestationClaimPolicy.allowedImageDigests, [
    legacy.trust.workload.imageDigest,
  ]);
});
const TEST_ROOT_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBwDCCAWWgAwIBAgIUSNN9w5LfurZ0bwlrvV4ZGA9EyaIwCgYIKoZIzj0EAwIw
NTEfMB0GA1UEAwwWSGVyZCBSZWxlYXNlIFRlc3QgUm9vdDESMBAGA1UECgwJSGVy
ZCBUZXN0MB4XDTI2MDgwMzAzMzE1NloXDTM2MDczMTAzMzE1NlowNTEfMB0GA1UE
AwwWSGVyZCBSZWxlYXNlIFRlc3QgUm9vdDESMBAGA1UECgwJSGVyZCBUZXN0MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEBq48qwScHWDC2otIOc0gyNjqFh7Va7HF
ZaHz/tT8gskchd7VtyjmKqRVRLFrOa9eSYAaYCjouBEmmstBh2Qr5qNTMFEwHQYD
VR0OBBYEFGTpn1g0PJqshN7FuTtf9H/MhFt1MB8GA1UdIwQYMBaAFGTpn1g0PJqs
hN7FuTtf9H/MhFt1MA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIh
AMCr+WD2w+JOmJiRl9J2hh2FqEXPmYlr/Ygwqv//MMECAiEAmBV94wKe/QLxU+Ul
niFfO1flUN9tLtyKP0krpTB9yD4=
-----END CERTIFICATE-----
`;

async function command(arguments_, options = {}) {
  return run(process.execPath, arguments_, {
    cwd: repositoryRoot,
    maxBuffer: 4 * 1024 * 1024,
    ...options,
  });
}

async function writeFixture(root, fixture) {
  const paths = {
    manifest: path.join(root, "release-manifest.json"),
    signature: path.join(root, "release-manifest.sig.json"),
    deployment: path.join(root, "deployment.json"),
    deploymentSignature: path.join(root, "deployment.sig.json"),
    publicKey: path.join(root, "release-public.pem"),
    privateKey: path.join(root, "release-private.pem"),
  };
  await Promise.all([
    writeFile(paths.manifest, fixture.manifestBytes),
    writeFile(paths.signature, fixture.manifestSignatureBytes),
    writeFile(paths.deployment, fixture.deploymentBytes),
    writeFile(paths.deploymentSignature, fixture.deploymentSignatureBytes),
    writeFile(paths.publicKey, fixture.keys.releaseSigning.publicPem),
    writeFile(paths.privateKey, fixture.keys.releaseSigning.privatePem),
  ]);
  return paths;
}

async function writeCosignStub(root) {
  const stubPath = path.join(root, "cosign-test-stub.mjs");
  await writeFile(
    stubPath,
    `#!/usr/bin/env node
import { accessSync } from "node:fs";
const args = process.argv.slice(2);
if (args[0] !== "verify-blob") throw new Error("expected verify-blob");
const bundleIndex = args.indexOf("--bundle");
const identityIndex = args.indexOf("--certificate-identity");
const issuerIndex = args.indexOf("--certificate-oidc-issuer");
if (bundleIndex < 0 || identityIndex < 0 || issuerIndex < 0) throw new Error("missing identity flags");
if (args[issuerIndex + 1] !== "https://token.actions.githubusercontent.com") throw new Error("wrong issuer");
accessSync(args[bundleIndex + 1]);
accessSync(args.at(-1));
`,
    { mode: 0o700 },
  );
  await chmod(stubPath, 0o700);
  return stubPath;
}

test("canonical manifest binds distinct operational keys to exact Confidential Space claims", () => {
  const fixture = makeReleaseFixture();
  const normalized = normalizeReleaseManifest(fixture.manifest, { requireProduction: true });
  assert.equal(canonicalJson(normalized), fixture.manifestBytes.toString("utf8"));
  const policy = normalized.trust.workload.attestationClaimPolicy;
  assert.equal(policy.issuer, "https://confidentialcomputing.googleapis.com");
  assert.equal(policy.hwmodel, "GCP_INTEL_TDX");
  assert.equal(policy.secboot, true);
  assert.equal(policy.dbgstat, "disabled-since-boot");
  assert.equal(policy.swname, "CONFIDENTIAL_SPACE");
  assert.deepEqual(policy.allowedImageDigests, [fixture.manifest.trust.workload.imageDigest]);
  assert.deepEqual(policy.allowedSwversions, ["260500", "260600"]);
  assert.equal(policy.oemid, 11129);
  assert.equal(policy.attesterTcb, "INTEL");
  assert.equal(policy.envOverrideAllowed, false);
  assert.equal(policy.cmdOverrideAllowed, false);
  verifyCanonicalArtifact({
    bytes: fixture.manifestBytes,
    envelope: fixture.manifestSignature,
    publicKey: fixture.keys.releaseSigning.publicPem,
    artifactType: MANIFEST_TYPE,
    expectedKey: normalized.trust.releaseManifestSigning,
  });
});

test("manifest rejects an incorrect four-key binding and reused trust keys", () => {
  const fixture = makeReleaseFixture();
  const staleSwversionFormat = structuredClone(fixture.manifest);
  staleSwversionFormat.trust.workload.attestationClaimPolicy.allowedSwversions = ["20260801"];
  assert.throws(
    () => normalizeReleaseManifest(staleSwversionFormat),
    /allowedSwversions\[0\] is invalid/u,
  );

  const duplicateImageDigest = structuredClone(fixture.manifest);
  duplicateImageDigest.trust.workload.attestationClaimPolicy.allowedImageDigests.push(
    structuredClone(duplicateImageDigest.trust.workload.imageDigest),
  );
  assert.throws(
    () => normalizeReleaseManifest(duplicateImageDigest),
    /allowedImageDigests contains duplicates/u,
  );

  const wrongPrimaryImageDigest = structuredClone(fixture.manifest);
  wrongPrimaryImageDigest.trust.workload.attestationClaimPolicy.allowedImageDigests = [
    { algorithm: "sha256", value: "44".repeat(32) },
    structuredClone(wrongPrimaryImageDigest.trust.workload.imageDigest),
  ];
  assert.throws(
    () => normalizeReleaseManifest(wrongPrimaryImageDigest),
    /allowedImageDigests must begin with trust\.workload\.imageDigest/u,
  );

  const excessiveImageDigests = structuredClone(fixture.manifest);
  excessiveImageDigests.trust.workload.attestationClaimPolicy.allowedImageDigests = [
    structuredClone(excessiveImageDigests.trust.workload.imageDigest),
    { algorithm: "sha256", value: "44".repeat(32) },
    { algorithm: "sha256", value: "55".repeat(32) },
  ];
  assert.throws(
    () => normalizeReleaseManifest(excessiveImageDigests),
    /allowedImageDigests must contain one or two exact digests/u,
  );

  const badBinding = structuredClone(fixture.manifest);
  badBinding.trust.workload.attestationClaimPolicy.keyBindingHash = "00".repeat(32);
  assert.throws(() => normalizeReleaseManifest(badBinding), /all four operational key descriptors/u);

  const reused = structuredClone(fixture.manifest);
  reused.trust.policySigning = reused.trust.resultSigning;
  reused.trust.workload.attestationClaimPolicy.keyBindingHash = computeWorkloadKeyBindingHash({
    evaluatorKeyEpochId: reused.evaluatorKeyEpochId,
    evaluatorEncryption: reused.trust.evaluatorEncryption,
    resultSigning: reused.trust.resultSigning,
    policySigning: reused.trust.policySigning,
    receiptTransparencySigning: reused.trust.receiptTransparencySigning,
  });
  assert.throws(() => normalizeReleaseManifest(reused), /distinct key ID and public key/u);

  const duplicateArtifact = structuredClone(fixture.manifest);
  duplicateArtifact.artifacts.scheduler.name = duplicateArtifact.artifacts.evaluator.name;
  assert.throws(() => normalizeReleaseManifest(duplicateArtifact), /globally unique name/u);

  for (const [field, value] of [
    ["bundleIdentifier", "HerdPrototype"],
    ["version", "1.0-beta"],
    ["build", "100a"],
  ]) {
    const invalidIosIdentity = structuredClone(fixture.manifest);
    invalidIosIdentity.artifacts.ios[field] = value;
    assert.throws(
      () => normalizeReleaseManifest(invalidIosIdentity),
      new RegExp(`artifacts\\.ios\\.${field} is invalid`, "u"),
    );
  }
});

test("signed release continuity separates artifact releases from evaluator epochs", () => {
  const fixture = makeReleaseFixture();
  const previous = fixture.manifest;
  const next = structuredClone(previous);
  next.releaseId = "2026.08.02.2";
  next.previousRelease = {
    releaseId: previous.releaseId,
    manifestSha256: sha256Hex(Buffer.from(canonicalJson(previous))),
  };
  next.sourceDateEpoch += 1;
  next.createdAt = new Date(next.sourceDateEpoch * 1000).toISOString();

  assert.throws(
    () => initialEvaluatorEpochRecord(next, next.createdAt),
    /initial evaluator epoch requires previousRelease to be null/u,
  );

  const artifactRelease = verifyReleaseContinuity(previous, next);
  assert.equal(artifactRelease.mode, "artifact-release");
  assert.equal(
    artifactRelease.evaluatorKeyEpochSha256,
    evaluatorKeyEpochSha256(previous),
  );

  const wrongPredecessor = structuredClone(next);
  wrongPredecessor.previousRelease.manifestSha256 = "ff".repeat(32);
  assert.throws(
    () => verifyReleaseContinuity(previous, wrongPredecessor),
    /exact preceding signed release manifest/u,
  );

  const sameEpochDrift = structuredClone(next);
  sameEpochDrift.trust.policySigning.keyId = "policy-signing-drift";
  assert.throws(
    () => verifyReleaseContinuity(previous, sameEpochDrift),
    /existing evaluator epoch must retain its exact image and evaluator key tuple/iu,
  );

  const transparencyRotation = structuredClone(next);
  transparencyRotation.trust.receiptTransparencySigning.keyId =
    "receipt-signing-rotated";
  assert.throws(
    () => verifyReleaseContinuity(previous, transparencyRotation),
    /lifetime-global response-transparency signing identity changed/iu,
  );

  const incompleteEpochRotation = structuredClone(next);
  incompleteEpochRotation.evaluatorKeyEpochId =
    "herd-evaluator-epoch-2026.09";
  for (const field of ["evaluatorEncryption", "resultSigning", "policySigning"]) {
    incompleteEpochRotation.trust[field].keyId += "-rotated";
  }
  assert.throws(
    () => verifyReleaseContinuity(previous, incompleteEpochRotation),
    /must replace the complete response-decryption key identity/u,
  );
});

test("evaluator epoch release gate requires an active reuse or persisted fully drained generation", () => {
  const current = makeReleaseFixture().manifest;
  const now = () => Date.parse(current.createdAt);
  const active = evaluatorEpochStatus(current);
  assert.equal(normalizeEvaluatorEpochStatus(active, { now }).schemaVersion, 2);
  assert.equal(
    verifyEvaluatorEpochTransition(current, active, { now }).mode,
    "reuse-active-generation",
  );

  const nextFixture = makeReleaseFixture();
  const rotated = structuredClone(current);
  rotated.evaluatorKeyEpochId = "herd-evaluator-epoch-2026.09";
  rotated.trust.evaluatorEncryption = nextFixture.manifest.trust.evaluatorEncryption;
  rotated.trust.resultSigning = nextFixture.manifest.trust.resultSigning;
  rotated.trust.policySigning = nextFixture.manifest.trust.policySigning;
  rotated.trust.evaluatorEncryption.keyId = "evaluator-encryption-202609";
  rotated.trust.resultSigning.keyId = "result-signing-202609";
  rotated.trust.policySigning.keyId = "policy-signing-202609";
  const drained = evaluatorEpochStatus(current, { mode: "draining" });
  const rotation = verifyEvaluatorEpochTransition(rotated, drained, { now });
  assert.equal(rotation.mode, "rotate-from-drained-generation");
  assert.equal(rotation.expectedGeneration, 1);
  assert.equal(rotation.drainCounts.activeEvaluationJobCount, 0);

  const snapshotOnly = structuredClone(drained);
  snapshotOnly.state.mode = "active";
  snapshotOnly.state.drainStartedAt = null;
  snapshotOnly.minimumDrainReached = false;
  snapshotOnly.drained = false;
  snapshotOnly.transition = null;
  assert.throws(
    () => verifyEvaluatorEpochTransition(rotated, snapshotOnly, { now }),
    /persisted D1 draining generation/u,
  );

  const outstandingJob = evaluatorEpochStatus(current, {
    mode: "draining",
    counts: {
      unresolvedPolicyCount: 0,
      activeEvaluationLeaseCount: 0,
      activeEvaluationJobCount: 1,
      uncertifiedTransparencyCount: 0,
    },
  });
  assert.throws(
    () => verifyEvaluatorEpochTransition(rotated, outstandingJob, { now }),
    /zero policies, leases, jobs, and uncertified transparency records/u,
  );

  const driftedDigest = structuredClone(active);
  driftedDigest.epochDescriptorSha256 = "ff".repeat(32);
  driftedDigest.state.epochDescriptorSha256 = driftedDigest.epochDescriptorSha256;
  assert.throws(
    () => normalizeEvaluatorEpochStatus(driftedDigest, { now }),
    /digests do not match its runtime tuple/u,
  );
});

test("iOS Release identity is delegated to the fail-closed generated xcconfig", async () => {
  const [project, wrapper] = await Promise.all([
    readFile(path.join(repositoryRoot, "HerdHost.xcodeproj", "project.pbxproj"), "utf8"),
    readFile(path.join(repositoryRoot, "release", "HerdRelease.xcconfig"), "utf8"),
  ]);
  const debugBlock = project.match(
    /A00000000000000000000018 \/\* Debug \*\/[\s\S]*?name = Debug;/u,
  )?.[0];
  const releaseBlock = project.match(
    /A00000000000000000000019 \/\* Release \*\/[\s\S]*?name = Release;/u,
  )?.[0];
  assert.ok(debugBlock);
  assert.ok(releaseBlock);
  assert.match(debugBlock, /CURRENT_PROJECT_VERSION = 4;/u);
  assert.match(debugBlock, /MARKETING_VERSION = 1\.0;/u);
  assert.match(debugBlock, /PRODUCT_BUNDLE_IDENTIFIER = com\.jameswoodbury\.HerdPrototype;/u);
  assert.match(releaseBlock, /baseConfigurationReference = .*HerdRelease\.xcconfig/u);
  assert.doesNotMatch(releaseBlock, /CURRENT_PROJECT_VERSION\s*=/u);
  assert.doesNotMatch(releaseBlock, /MARKETING_VERSION\s*=/u);
  assert.doesNotMatch(releaseBlock, /PRODUCT_BUNDLE_IDENTIFIER\s*=/u);
  assert.match(wrapper, /^CURRENT_PROJECT_VERSION = 0$/mu);
  assert.match(wrapper, /^MARKETING_VERSION = 0\.0\.0$/mu);
  assert.match(wrapper, /^PRODUCT_BUNDLE_IDENTIFIER = configuration\.invalid\.Herd$/mu);
  assert.match(wrapper, /^#include\? "generated\/HerdRelease\.generated\.xcconfig"$/mu);
});

test("release and deployment CLI signatures verify and generate the public well-known record", async () => {
  const fixture = makeReleaseFixture();
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-release-sign-test-"));
  const paths = await writeFixture(root, fixture);
  await Promise.all(
    fixture.publishedArtifacts.map(([descriptor, bytes]) =>
      writeFile(path.join(root, descriptor.name), bytes),
    ),
  );
  const cosignStub = await writeCosignStub(root);
  const generatedSignature = path.join(root, "generated-manifest.sig.json");
  await command([
    "release/sign-release-manifest.mjs",
    "--manifest", paths.manifest,
    "--private-key", paths.privateKey,
    "--public-key", paths.publicKey,
    "--output", generatedSignature,
  ]);
  await assert.rejects(
    command([
      "release/verify-release-manifest.mjs",
      "--manifest", paths.manifest,
      "--signature", generatedSignature,
      "--public-key", paths.publicKey,
      "--require-production",
    ]),
    /--artifact-root is required/u,
  );
  await command([
    "release/verify-release-manifest.mjs",
    "--manifest", paths.manifest,
    "--signature", generatedSignature,
    "--public-key", paths.publicKey,
    "--require-production",
    "--artifact-root", root,
    "--cosign", cosignStub,
  ]);
  const generatedDeploymentSignature = path.join(root, "generated-deployment.sig.json");
  const appleAppSiteAssociationPath = path.join(root, "apple-app-site-association");
  await writeFile(appleAppSiteAssociationPath, fixture.appleAppSiteAssociationBytes);
  await command([
    "release/sign-deployment-statement.mjs",
    "--statement", paths.deployment,
    "--manifest", paths.manifest,
    "--private-key", paths.privateKey,
    "--public-key", paths.publicKey,
    "--apple-app-site-association", appleAppSiteAssociationPath,
    "--output", generatedDeploymentSignature,
  ]);
  const wellKnownPath = path.join(root, "well-known.json");
  await command([
    "release/generate-well-known.mjs",
    "--manifest", paths.manifest,
    "--manifest-signature", paths.signature,
    "--deployment", paths.deployment,
    "--deployment-signature", paths.deploymentSignature,
    "--public-key", paths.publicKey,
    "--apple-app-site-association", appleAppSiteAssociationPath,
    "--deployment-url", fixture.wellKnown.deploymentStatement.url,
    "--deployment-signature-url", fixture.wellKnown.deploymentStatement.signature.url,
    "--verifier-source-url", fixture.wellKnown.verifier.sourceUrl,
    "--output", wellKnownPath,
  ]);
  const wellKnown = JSON.parse(await readFile(wellKnownPath, "utf8"));
  assert.equal(wellKnown.releaseId, fixture.releaseId);
  assert.deepEqual(wellKnown.evaluator.attestationClaimPolicy, fixture.manifest.trust.workload.attestationClaimPolicy);
  assert.equal(wellKnown.releaseSigningKey.publicKeySha256, fixture.keys.releaseSigning.descriptor.publicKeySha256);
});

test("directory packaging and SPDX generation are deterministic", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-release-determinism-test-"));
  const input = path.join(root, "artifact");
  await mkdir(path.join(input, "nested"), { recursive: true });
  await writeFile(path.join(input, "a.txt"), "alpha\n");
  await writeFile(path.join(input, "nested", "b.txt"), "beta\n");
  const archiveOne = path.join(root, "one.tar");
  const archiveTwo = path.join(root, "two.tar");
  await command(["release/package-directory.mjs", "--input", input, "--output", archiveOne, "--manifest", path.join(root, "one.json"), "--name", "sample", "--source-date-epoch", "1785657600"]);
  await command(["release/package-directory.mjs", "--input", input, "--output", archiveTwo, "--manifest", path.join(root, "two.json"), "--name", "sample", "--source-date-epoch", "1785657600"]);
  assert.deepEqual(await readFile(archiveOne), await readFile(archiveTwo));
  assert.deepEqual(await readFile(path.join(root, "one.json")), await readFile(path.join(root, "two.json")));

  const sourceRoot = path.join(root, "source");
  await mkdir(sourceRoot);
  const sourceBytes = Buffer.from("licensed source\n");
  await writeFile(path.join(sourceRoot, "source.mjs"), sourceBytes);
  const sourceManifest = {
    sourceDateEpoch: 1785657600,
    sourceRevision: "ef".repeat(20),
    files: [{ path: "source.mjs", size: sourceBytes.byteLength, sha256: sha256Hex(sourceBytes) }],
  };
  const sourceManifestPath = path.join(root, "source-manifest.json");
  const lockPath = path.join(root, "package-lock.json");
  await writeFile(sourceManifestPath, canonicalJson(sourceManifest));
  await writeFile(lockPath, canonicalJson({ name: "fixture", version: "1.0.0", lockfileVersion: 3, requires: true, packages: { "": { name: "fixture", version: "1.0.0", license: "Apache-2.0" } } }));
  const sbomOne = path.join(root, "one.spdx.json");
  const sbomTwo = path.join(root, "two.spdx.json");
  for (const output of [sbomOne, sbomTwo]) {
    await command(["release/generate-sbom.mjs", "--source-manifest", sourceManifestPath, "--source-root", sourceRoot, "--output", output, "--name", "fixture-sbom", lockPath]);
  }
  assert.deepEqual(await readFile(sbomOne), await readFile(sbomTwo));
  const sbom = JSON.parse(await readFile(sbomOne, "utf8"));
  const sourcePackage = sbom.packages.find(({ SPDXID }) => SPDXID === "SPDXRef-Package-Herd-Privacy-Source");
  assert.match(sourcePackage.verificationCode.packageVerificationCodeValue, /^[0-9a-f]{40}$/u);
  assert.deepEqual(sbom.files[0].checksums.map(({ algorithm }) => algorithm), ["SHA1", "SHA256"]);
});

test("pinned toolchain facts, SLSA provenance, and Rekor bundle extraction are fail-closed", async () => {
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-release-evidence-test-"));
  const factsPath = path.join(root, "facts.json");
  await writeFile(factsPath, canonicalJson({
    node: "22.13.0",
    npm: "10.9.2",
    timezone: "UTC",
    locale: "C.UTF-8",
    sourceDateEpoch: "1785657600",
  }));
  await command(["release/verify-toolchains.mjs", "--spec", "release/toolchains.json", "--facts", factsPath]);
  const wrongFactsPath = path.join(root, "wrong-facts.json");
  await writeFile(wrongFactsPath, canonicalJson({
    node: "22.12.0",
    npm: "10.9.2",
    timezone: "UTC",
    locale: "C.UTF-8",
    sourceDateEpoch: "1785657600",
  }));
  await assert.rejects(command(["release/verify-toolchains.mjs", "--spec", "release/toolchains.json", "--facts", wrongFactsPath]));

  const artifactRoot = path.join(root, "artifacts");
  await mkdir(artifactRoot);
  await writeFile(path.join(artifactRoot, "artifact.bin"), "artifact\n");
  const provenancePath = path.join(artifactRoot, "provenance.json");
  await command([
    "release/generate-provenance.mjs",
    "--artifact-root", artifactRoot,
    "--output", provenancePath,
    "--started-at", "2026-08-02T00:00:00.000Z",
    "--finished-at", "2026-08-02T00:01:00.000Z",
    "--source-repository", "https://github.com/jwoodbury11/Herd",
    "--source-revision", "ab".repeat(20),
    "--release-id", "2026.08.02-test.1",
    "--toolchain-spec", "release/toolchains.json",
    "--builder-id", "https://github.com/jwoodbury11/Herd/.github/workflows/release-evidence.yml",
    "--invocation-id", "test-invocation",
  ]);
  const provenance = JSON.parse(await readFile(provenancePath, "utf8"));
  assert.equal(provenance.predicateType, "https://slsa.dev/provenance/v1");
  assert.equal(provenance.predicate.buildDefinition.buildType, "urn:herd:build-type:privacy-release-evidence:v1");

  const bundlePath = path.join(root, "bundle.json");
  const transparencyPath = path.join(root, "transparency.json");
  await writeFile(bundlePath, canonicalJson({
    verificationMaterial: {
      tlogEntries: [{ logId: { keyId: "rekor-log-key" }, logIndex: "42", integratedTime: "1785657600" }],
    },
  }));
  await command(["release/record-transparency.mjs", "--bundle", bundlePath, "--rekor-record-base-url", "https://rekor.sigstore.dev/api/v1/log/entries", "--output", transparencyPath]);
  const transparency = JSON.parse(await readFile(transparencyPath, "utf8"));
  assert.equal(transparency.provider, "sigstore-rekor");
  assert.equal(transparency.entryId, "rekor-log-key:42");
});

test("production config CLI verifies a prepared template without accepting it as a final manifest", async () => {
  const fixture = makeReleaseFixture();
  const template = structuredClone(fixture.manifest);
  template.artifacts.web.publicOrigin = "https://app.herdprivacy.com";
  template.trust.workload.attestationClaimPolicy.audience =
    "https://evaluator.herdprivacy.com/attestation";
  template.trust.workload.attestationRootFingerprint.value = sha256Hex(
    new X509Certificate(TEST_ROOT_CERTIFICATE).raw,
  );
  template.evidence.provenance = [];
  template.evidence.transparency = [];
  template.evidence.transitions = [];
  template.evidence.deployments = [];
  normalizeProductionReleaseTemplate(template);

  const root = await mkdtemp(path.join(os.tmpdir(), "herd-template-config-test-"));
  const templatePath = path.join(root, "release-template.json");
  const rootCertificatePath = path.join(root, "attestation-root.pem");
  const outputDirectory = path.join(root, "generated");
  await Promise.all([
    writeFile(templatePath, canonicalJson(template)),
    writeFile(rootCertificatePath, TEST_ROOT_CERTIFICATE),
  ]);
  const baseArguments = [
    "release/generate-production-config.mjs",
    "--manifest", templatePath,
    "--evaluator-url", "https://evaluator.herdprivacy.com/api/v1/relay/",
    "--attestation-root-certificate", rootCertificatePath,
    "--output-directory", outputDirectory,
  ];

  const prepared = JSON.parse((await command([...baseArguments, "--prepare"])).stdout);
  assert.equal(prepared.verified, false);
  assert.match(prepared.configurationSha256, /^[0-9a-f]{64}$/u);

  template.productionPolicy.configurationSha256 = prepared.configurationSha256;
  await writeFile(templatePath, canonicalJson(template));
  const verified = JSON.parse(
    (await command([...baseArguments, "--verify-template"])).stdout,
  );
  assert.equal(verified.verified, true);
  assert.equal(verified.configurationSha256, prepared.configurationSha256);

  await assert.rejects(
    command(baseArguments),
    /production manifest requires provenance/u,
  );
  const wrongDigest = structuredClone(template);
  wrongDigest.productionPolicy.configurationSha256 = "00".repeat(32);
  await writeFile(templatePath, canonicalJson(wrongDigest));
  await assert.rejects(
    command([...baseArguments, "--verify-template"]),
    /configurationSha256/u,
  );
  await assert.rejects(
    command([...baseArguments, "--prepare", "--verify-template"]),
    /mutually exclusive/u,
  );
});

test("production config generation and artifact preflight bind web and iOS builds to the signed manifest", async () => {
  const fixture = makeReleaseFixture();
  assert.throws(
    () => buildProductionConfig(fixture.manifest, {
      evaluatorUrl: "https://evaluator.herdprivacy.com/api/v1/relay/",
      rootCertificate: TEST_ROOT_CERTIFICATE,
    }),
    /non-production host name/u,
  );
  const manifestInput = structuredClone(fixture.manifest);
  manifestInput.artifacts.web.publicOrigin = "https://app.herdprivacy.com";
  manifestInput.trust.workload.attestationClaimPolicy.audience =
    "https://evaluator.herdprivacy.com/attestation";
  const rootCertificate = new X509Certificate(TEST_ROOT_CERTIFICATE);
  manifestInput.trust.workload.attestationRootFingerprint.value = sha256Hex(rootCertificate.raw);
  assert.throws(
    () => buildProductionConfig(manifestInput, {
      evaluatorUrl: "https://evaluator.herdprivacy.com/api/v1/evaluate",
      rootCertificate: TEST_ROOT_CERTIFICATE,
    }),
    /exact production \/api\/v1\/relay\//u,
  );
  const evaluatorUrl = "https://evaluator.herdprivacy.com/api/v1/relay/";
  const nonstandardUniversalLinkOrigin = structuredClone(manifestInput);
  nonstandardUniversalLinkOrigin.artifacts.web.publicOrigin =
    "https://app.herdprivacy.com:8443";
  assert.throws(
    () => buildProductionConfig(nonstandardUniversalLinkOrigin, {
      evaluatorUrl,
      rootCertificate: TEST_ROOT_CERTIFICATE,
    }),
    /standard HTTPS port for universal links/u,
  );
  let generated = buildProductionConfig(manifestInput, {
    evaluatorUrl,
    rootCertificate: TEST_ROOT_CERTIFICATE,
  });
  manifestInput.productionPolicy.configurationSha256 = generated.configurationSha256;
  generated = buildProductionConfig(manifestInput, {
    evaluatorUrl,
    rootCertificate: TEST_ROOT_CERTIFICATE,
  });
  const changedIosIdentity = structuredClone(manifestInput);
  changedIosIdentity.artifacts.ios.bundleIdentifier = "com.herd.host.changed";
  assert.notEqual(
    buildProductionConfig(changedIosIdentity, {
      evaluatorUrl,
      rootCertificate: TEST_ROOT_CERTIFICATE,
    }).configurationSha256,
    generated.configurationSha256,
  );
  assert.equal(generated.webRuntimeVariables.HERD_EVALUATOR_MEASUREMENT, `sha256:${"33".repeat(32)}`);
  assert.equal(
    generated.webPublicEnvironment.NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT,
    `sha256:${"33".repeat(32)}`,
  );
  assert.equal(
    generated.webPublicEnvironment.NEXT_PUBLIC_HERD_ALLOW_SOFTWARE_QA_EVALUATOR,
    undefined,
  );
  assert.equal(
    generated.webPublicEnvironment.NEXT_PUBLIC_HERD_ARTIFACT_RELEASE_ID,
    manifestInput.releaseId,
  );
  assert.equal(
    generated.webRuntimeVariables.HERD_ARTIFACT_RELEASE_ID,
    manifestInput.releaseId,
  );
  assert.equal(
    generated.webRuntimeVariables.HERD_EVALUATOR_KEY_EPOCH_SHA256,
    evaluatorKeyEpochSha256(manifestInput),
  );
  assert.equal(
    generated.schedulerRuntimeVariables.HERD_ARTIFACT_RELEASE_ID,
    manifestInput.releaseId,
  );
  assert.equal(
    generated.iosBuildSettings.HERD_ARTIFACT_RELEASE_ID,
    manifestInput.releaseId,
  );
  assert.equal(generated.iosBuildSettings.HERD_ALLOW_SOFTWARE_QA_EVALUATOR, undefined);
  assert.equal(generated.webRuntimeVariables.HERD_TEST_ACCOUNT_ACCESS_ENABLED, "true");
  assert.equal(generated.webRuntimeVariables.HERD_ATTESTATION_ROOT_CERTIFICATE, TEST_ROOT_CERTIFICATE);
  assert.equal(
    generated.iosBuildSettings.HERD_EVALUATOR_MEASUREMENT,
    `sha256:${"33".repeat(32)}`,
  );
  assert.equal(
    generated.webRuntimeVariables.HERD_RELEASE_ID,
    manifestInput.evaluatorKeyEpochId,
  );
  assert.equal(
    generated.webRuntimeVariables.HERD_IOS_APP_ID,
    `R4UPN8ZDV8.${manifestInput.artifacts.ios.bundleIdentifier}`,
  );
  assert.deepEqual(generated.contract.ios, {
    bundleIdentifier: manifestInput.artifacts.ios.bundleIdentifier,
    version: manifestInput.artifacts.ios.version,
    build: manifestInput.artifacts.ios.build,
    developmentTeam: "R4UPN8ZDV8",
    appIdentifier: `R4UPN8ZDV8.${manifestInput.artifacts.ios.bundleIdentifier}`,
    appClipBundleIdentifier: `${manifestInput.artifacts.ios.bundleIdentifier}.Clip`,
    appClipIdentifier: `R4UPN8ZDV8.${manifestInput.artifacts.ios.bundleIdentifier}.Clip`,
    associatedDomain: "app.herdprivacy.com",
  });
  assert.equal(
    generated.iosBuildSettings.PRODUCT_BUNDLE_IDENTIFIER,
    manifestInput.artifacts.ios.bundleIdentifier,
  );
  assert.equal(
    generated.iosBuildSettings.HERD_ASSOCIATED_DOMAIN,
    "app.herdprivacy.com",
  );
  assert.equal(
    generated.iosBuildSettings.HERD_APP_CLIP_BUNDLE_IDENTIFIER,
    `${manifestInput.artifacts.ios.bundleIdentifier}.Clip`,
  );
  assert.equal(generated.iosBuildSettings.DEVELOPMENT_TEAM, "R4UPN8ZDV8");
  assert.equal(generated.iosBuildSettings.MARKETING_VERSION, manifestInput.artifacts.ios.version);
  assert.equal(generated.iosBuildSettings.CURRENT_PROJECT_VERSION, manifestInput.artifacts.ios.build);
  assert.equal(
    generated.iosInfoValues.CFBundleIdentifier,
    manifestInput.artifacts.ios.bundleIdentifier,
  );
  assert.equal(
    generated.iosInfoValues.CFBundleShortVersionString,
    manifestInput.artifacts.ios.version,
  );
  assert.equal(generated.iosInfoValues.CFBundleVersion, manifestInput.artifacts.ios.build);
  assert.doesNotMatch(generated.files["HerdRelease.generated.xcconfig"], /\/\//u);
  assert.match(generated.files["HerdRelease.generated.xcconfig"], /\$\(\)/u);
  assert.match(
    generated.files["HerdRelease.generated.xcconfig"],
    /^PRODUCT_BUNDLE_IDENTIFIER=com\.herd\.host$/mu,
  );

  const webBundle = Buffer.from(JSON.stringify(generated.webPublicEnvironment));
  const webArchive = Buffer.concat([
    tarEntry(
      "web-deployment/client/assets/page-production.js",
      webBundle,
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/url-parser.js",
      Buffer.from('const relativeUrlBase = "https://localhost";\n'),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/HERD-RELEASE-CONFIG-SHA256",
      Buffer.from(`${generated.configurationSha256}\n`),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/HERD-ARTIFACT-RELEASE-ID",
      Buffer.from(`${manifestInput.releaseId}\n`),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    Buffer.alloc(1024),
  ]);
  const serverOnlyConfigurationArchive = Buffer.concat([
    tarEntry(
      "web-deployment/config.js",
      webBundle,
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/client/assets/page-production.js",
      Buffer.from("const publicEnvironment = {};\n"),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/HERD-RELEASE-CONFIG-SHA256",
      Buffer.from(`${generated.configurationSha256}\n`),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    tarEntry(
      "web-deployment/HERD-ARTIFACT-RELEASE-ID",
      Buffer.from(`${manifestInput.releaseId}\n`),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    Buffer.alloc(1024),
  ]);
  assert.throws(
    () => verifyWebArchive(serverOnlyConfigurationArchive, generated),
    /browser JavaScript does not contain every public value/u,
  );
  const schedulerArchive = Buffer.concat([
    tarEntry(
      "scheduler/scheduler-runtime-vars.json",
      Buffer.from(generated.files["scheduler-runtime-vars.json"]),
      0o644,
      manifestInput.sourceDateEpoch,
    ),
    Buffer.alloc(1024),
  ]);
  const iosArchive = Buffer.from("signed iOS archive fixture\n");
  const normalizedIosBinary = Buffer.from("normalized iOS executable fixture\n");
  Object.assign(manifestInput.artifacts.web.deploymentArchive, {
    sha256: sha256Hex(webArchive),
    size: webArchive.byteLength,
  });
  Object.assign(manifestInput.artifacts.ios.submissionArchive, {
    sha256: sha256Hex(iosArchive),
    size: iosArchive.byteLength,
  });
  Object.assign(manifestInput.artifacts.scheduler, {
    sha256: sha256Hex(schedulerArchive),
    size: schedulerArchive.byteLength,
  });
  manifestInput.evidence.provenance[0].subjects.find(
    ({ name }) => name === manifestInput.artifacts.web.deploymentArchive.name,
  ).sha256 = sha256Hex(webArchive);
  manifestInput.evidence.provenance[0].subjects.find(
    ({ name }) => name === manifestInput.artifacts.ios.submissionArchive.name,
  ).sha256 = sha256Hex(iosArchive);
  manifestInput.evidence.provenance[0].subjects.find(
    ({ name }) => name === manifestInput.artifacts.scheduler.name,
  ).sha256 = sha256Hex(schedulerArchive);
  const originalStatementBytes = fixture.publishedArtifacts.find(
    ([descriptor]) => descriptor.name === manifestInput.evidence.provenance[0].statement.name,
  )[1];
  const statement = JSON.parse(originalStatementBytes);
  statement.subject.find(
    ({ name }) => name === manifestInput.artifacts.web.deploymentArchive.name,
  ).digest.sha256 = sha256Hex(webArchive);
  statement.subject.find(
    ({ name }) => name === manifestInput.artifacts.ios.submissionArchive.name,
  ).digest.sha256 = sha256Hex(iosArchive);
  statement.subject.find(
    ({ name }) => name === manifestInput.artifacts.scheduler.name,
  ).digest.sha256 = sha256Hex(schedulerArchive);
  const statementBytes = Buffer.from(canonicalJson(statement));
  Object.assign(manifestInput.evidence.provenance[0].statement, {
    sha256: sha256Hex(statementBytes),
    size: statementBytes.byteLength,
  });
  const originalBundleBytes = fixture.publishedArtifacts.find(
    ([descriptor]) => descriptor.name === manifestInput.evidence.provenance[0].bundle.name,
  )[1];
  const bundle = JSON.parse(originalBundleBytes);
  bundle.messageSignature.messageDigest.digest = Buffer.from(
    sha256Hex(statementBytes),
    "hex",
  ).toString("base64");
  bundle.verificationMaterial.tlogEntries[0].canonicalizedBody = Buffer.from(
    JSON.stringify({ statementSha256: sha256Hex(statementBytes) }),
  ).toString("base64");
  const bundleBytes = Buffer.from(canonicalJson(bundle));
  Object.assign(manifestInput.evidence.provenance[0].bundle, {
    sha256: sha256Hex(bundleBytes),
    size: bundleBytes.byteLength,
  });
  manifestInput.evidence.transparency[0].bundleSha256 = sha256Hex(bundleBytes);
  manifestInput.artifacts.ios.normalizedBinarySha256 = sha256Hex(normalizedIosBinary);
  const manifest = normalizeReleaseManifest(manifestInput, { requireProduction: true });
  generated = buildProductionConfig(manifest, {
    evaluatorUrl,
    rootCertificate: TEST_ROOT_CERTIFICATE,
  });
  const iosEntitlements = {
    "application-identifier": generated.contract.ios.appIdentifier,
    "com.apple.developer.team-identifier": generated.contract.ios.developmentTeam,
    "com.apple.developer.associated-domains": [
      `applinks:${generated.contract.ios.associatedDomain}`,
    ],
    "com.apple.developer.associated-appclip-app-identifiers": [
      generated.contract.ios.appClipIdentifier,
    ],
    "get-task-allow": false,
  };
  const appClipInfo = {
    ...generated.iosInfoValues,
    CFBundleIdentifier: generated.contract.ios.appClipBundleIdentifier,
    CFBundleExecutable: "HerdClip",
    NSAppClip: {
      NSAppClipRequestEphemeralUserNotification: false,
      NSAppClipRequestLocationConfirmation: false,
    },
  };
  const appClipEntitlements = {
    "application-identifier": generated.contract.ios.appClipIdentifier,
    "com.apple.developer.team-identifier": generated.contract.ios.developmentTeam,
    "com.apple.developer.associated-domains": [
      `appclips:${generated.contract.ios.associatedDomain}`,
    ],
    "com.apple.developer.parent-application-identifiers": [
      generated.contract.ios.appIdentifier,
    ],
    "com.apple.developer.on-demand-install-capable": true,
    "get-task-allow": false,
  };

  const root = await mkdtemp(path.join(os.tmpdir(), "herd-production-preflight-test-"));
  const cosignStub = await writeCosignStub(root);
  const configDirectory = path.join(root, "config");
  await mkdir(configDirectory);
  for (const [name, contents] of Object.entries(generated.files)) {
    await writeFile(path.join(configDirectory, name), contents);
  }
  const webArchivePath = path.join(root, manifest.artifacts.web.deploymentArchive.name);
  const iosArchivePath = path.join(root, manifest.artifacts.ios.submissionArchive.name);
  const normalizedIosBinaryPath = path.join(root, "HerdHost.normalized-executable");
  await Promise.all([
    writeFile(webArchivePath, webArchive),
    writeFile(iosArchivePath, iosArchive),
    writeFile(path.join(root, manifest.artifacts.scheduler.name), schedulerArchive),
    writeFile(normalizedIosBinaryPath, normalizedIosBinary),
  ]);
  const replacedArtifacts = new Set([
    manifest.artifacts.web.deploymentArchive.name,
    manifest.artifacts.ios.submissionArchive.name,
    manifest.artifacts.scheduler.name,
    manifest.evidence.provenance[0].statement.name,
    manifest.evidence.provenance[0].bundle.name,
  ]);
  await Promise.all(
    fixture.publishedArtifacts
      .filter(([descriptor]) => !replacedArtifacts.has(descriptor.name))
      .map(([descriptor, bytes]) => writeFile(path.join(root, descriptor.name), bytes)),
  );
  await Promise.all([
    writeFile(path.join(root, manifest.evidence.provenance[0].statement.name), statementBytes),
    writeFile(path.join(root, manifest.evidence.provenance[0].bundle.name), bundleBytes),
  ]);
  const result = await preflightProductionArtifacts({
    manifest,
    evaluatorUrl,
    rootCertificate: TEST_ROOT_CERTIFICATE,
    configDirectory,
    artifactRoot: root,
    webArchivePath,
    iosArchivePath,
    normalizedIosBinaryPath,
    iosInfo: { ...generated.iosInfoValues, CFBundleExecutable: "HerdHost" },
    iosEntitlements,
    appClipInfo,
    appClipEntitlements,
    cosign: cosignStub,
  });
  assert.equal(result.configurationSha256, manifest.productionPolicy.configurationSha256);
  assert.equal(result.iosBundleIdentifier, manifest.artifacts.ios.bundleIdentifier);
  assert.equal(result.iosVersion, manifest.artifacts.ios.version);
  assert.equal(result.iosBuild, manifest.artifacts.ios.build);

  const wrongInfo = { ...generated.iosInfoValues, CFBundleExecutable: "HerdHost" };
  wrongInfo.HERD_API_BASE_URL = "https://preview.example";
  await assert.rejects(
    preflightProductionArtifacts({
      manifest,
      evaluatorUrl,
      rootCertificate: TEST_ROOT_CERTIFICATE,
      configDirectory,
      artifactRoot: root,
      webArchivePath,
      iosArchivePath,
      normalizedIosBinaryPath,
      iosInfo: wrongInfo,
      iosEntitlements,
      appClipInfo,
      appClipEntitlements,
      cosign: cosignStub,
    }),
    /HERD_API_BASE_URL does not match/u,
  );

  for (const [key, value] of [
    ["CFBundleIdentifier", "com.jameswoodbury.HerdPrototype"],
    ["CFBundleShortVersionString", "9.9.9"],
    ["CFBundleVersion", "999"],
  ]) {
    const wrongIdentity = {
      ...generated.iosInfoValues,
      CFBundleExecutable: "HerdHost",
      [key]: value,
    };
    await assert.rejects(
      preflightProductionArtifacts({
        manifest,
        evaluatorUrl,
        rootCertificate: TEST_ROOT_CERTIFICATE,
        configDirectory,
        artifactRoot: root,
        webArchivePath,
        iosArchivePath,
        normalizedIosBinaryPath,
        iosInfo: wrongIdentity,
        iosEntitlements,
        appClipInfo,
        appClipEntitlements,
        cosign: cosignStub,
      }),
      new RegExp(`${key} does not match`, "u"),
    );
  }

  for (const [mutate, expected] of [
    [
      (value) => { value["application-identifier"] = "R4UPN8ZDV8.com.herd.wrong"; },
      /application-identifier/u,
    ],
    [
      (value) => { value["com.apple.developer.team-identifier"] = "WRONGTEAM1"; },
      /team identifier/u,
    ],
    [
      (value) => { value["com.apple.developer.associated-domains"] = ["applinks:preview.example"]; },
      /associated domains/u,
    ],
    [
      (value) => { value["com.apple.developer.associated-appclip-app-identifiers"] = ["R4UPN8ZDV8.com.herd.wrong.Clip"]; },
      /embedded App Clip/u,
    ],
    [
      (value) => { value["keychain-access-groups"] = ["R4UPN8ZDV8.com.herd.other"]; },
      /unexpected capability/u,
    ],
    [
      (value) => { value["get-task-allow"] = true; },
      /get-task-allow/u,
    ],
    [
      (value) => { value["com.apple.developer.networking.wifi-info"] = true; },
      /unexpected capability/u,
    ],
  ]) {
    const changedEntitlements = structuredClone(iosEntitlements);
    mutate(changedEntitlements);
    await assert.rejects(
      preflightProductionArtifacts({
        manifest,
        evaluatorUrl,
        rootCertificate: TEST_ROOT_CERTIFICATE,
        configDirectory,
        artifactRoot: root,
        webArchivePath,
        iosArchivePath,
        normalizedIosBinaryPath,
        iosInfo: { ...generated.iosInfoValues, CFBundleExecutable: "HerdHost" },
        iosEntitlements: changedEntitlements,
        appClipInfo,
        appClipEntitlements,
        cosign: cosignStub,
      }),
      expected,
    );
  }

  const missingOnDemandCapability = structuredClone(appClipEntitlements);
  delete missingOnDemandCapability["com.apple.developer.on-demand-install-capable"];
  await assert.rejects(
    preflightProductionArtifacts({
      manifest,
      evaluatorUrl,
      rootCertificate: TEST_ROOT_CERTIFICATE,
      configDirectory,
      artifactRoot: root,
      webArchivePath,
      iosArchivePath,
      normalizedIosBinaryPath,
      iosInfo: { ...generated.iosInfoValues, CFBundleExecutable: "HerdHost" },
      iosEntitlements,
      appClipInfo,
      appClipEntitlements: missingOnDemandCapability,
      cosign: cosignStub,
    }),
    /on-demand install capability/u,
  );

  const manifestBytes = Buffer.from(canonicalJson(manifest));
  const signature = signCanonicalArtifact({
    bytes: manifestBytes,
    privateKey: fixture.keys.releaseSigning.privatePem,
    publicKey: fixture.keys.releaseSigning.publicPem,
    keyId: fixture.keys.releaseSigning.descriptor.keyId,
    signedAt: manifest.createdAt,
    artifactType: MANIFEST_TYPE,
  });
  const paths = {
    manifest: path.join(root, "release-manifest.json"),
    signature: path.join(root, "release-manifest.sig.json"),
    publicKey: path.join(root, "release-public.pem"),
    rootCertificate: path.join(root, "attestation-root.pem"),
    iosInfo: path.join(root, "Info.plist.json"),
    iosEntitlements: path.join(root, "Entitlements.plist.json"),
    appClipInfo: path.join(root, "AppClip.Info.plist.json"),
    appClipEntitlements: path.join(root, "AppClip.Entitlements.plist.json"),
  };
  await Promise.all([
    writeFile(paths.manifest, manifestBytes),
    writeFile(paths.signature, canonicalJson(signature)),
    writeFile(paths.publicKey, fixture.keys.releaseSigning.publicPem),
    writeFile(paths.rootCertificate, TEST_ROOT_CERTIFICATE),
    writeFile(paths.iosInfo, canonicalJson({ ...generated.iosInfoValues, CFBundleExecutable: "HerdHost" })),
    writeFile(paths.iosEntitlements, canonicalJson(iosEntitlements)),
    writeFile(paths.appClipInfo, canonicalJson(appClipInfo)),
    writeFile(paths.appClipEntitlements, canonicalJson(appClipEntitlements)),
  ]);
  await command([
    "release/preflight-production-artifacts.mjs",
    "--manifest", paths.manifest,
    "--signature", paths.signature,
    "--public-key", paths.publicKey,
    "--evaluator-url", evaluatorUrl,
    "--attestation-root-certificate", paths.rootCertificate,
    "--config-directory", configDirectory,
    "--artifact-root", root,
    "--web-archive", webArchivePath,
    "--ios-archive", iosArchivePath,
    "--normalized-ios-binary", normalizedIosBinaryPath,
    "--ios-info-json", paths.iosInfo,
    "--ios-entitlements-json", paths.iosEntitlements,
    "--app-clip-info-json", paths.appClipInfo,
    "--app-clip-entitlements-json", paths.appClipEntitlements,
    "--cosign", cosignStub,
  ]);
});

test("deployment normalization binds the four production components", () => {
  const fixture = makeReleaseFixture();
  const normalized = normalizeDeploymentStatement(fixture.deployment);
  assert.deepEqual(normalized.platformDeployments.map(({ component }) => component), ["evaluator", "ordinary-api", "scheduler", "web"]);
  assert.equal(
    normalized.monitoredResources.find(({ name }) => name === "apple-app-site-association")?.url,
    "https://app.herd.example/.well-known/apple-app-site-association",
  );
  assert.deepEqual(
    verifyAppleAppSiteAssociation(
      fixture.appleAppSiteAssociationBytes,
      iosApplicationIdentifier(fixture.manifest.artifacts.ios.bundleIdentifier),
    ).applinks.details[0].paths,
    ["/invite/*"],
  );

  const missing = structuredClone(fixture.deployment);
  missing.monitoredResources = missing.monitoredResources.filter(
    ({ name }) => name !== "apple-app-site-association",
  );
  assert.throws(() => normalizeDeploymentStatement(missing), /Apple app-site association/u);

  for (const [field, value] of [
    ["url", "https://app.herd.example/apple-app-site-association"],
    ["mediaType", "text/plain"],
  ]) {
    const changed = structuredClone(fixture.deployment);
    changed.monitoredResources.find(
      ({ name }) => name === "apple-app-site-association",
    )[field] = value;
    assert.throws(
      () => normalizeDeploymentStatement(changed),
      /exact production well-known JSON resource/u,
    );
  }
});

test("bottom-up manifest assembly rejects preexisting, missing, and unrelated provenance", async () => {
  const fixture = makeReleaseFixture();
  assert.throws(
    () => normalizeProductionReleaseTemplate(fixture.manifest),
    /must not contain preexisting provenance/u,
  );
  const template = structuredClone(fixture.manifest);
  template.evidence.provenance = [];
  template.evidence.transparency = [];
  template.evidence.transitions = [];
  template.evidence.deployments = [];
  normalizeProductionReleaseTemplate(template);

  const root = await mkdtemp(path.join(os.tmpdir(), "herd-evidence-assembly-test-"));
  const templatePath = path.join(root, "release-template.json");
  const statementPath = path.join(root, "build-provenance.intoto.json");
  const bundlePath = path.join(root, "build-provenance.sigstore.json");
  const transparencyPath = path.join(root, "build-provenance.rekor.json");
  const evaluatorTransitionPath = path.join(root, "evaluator-epoch-transition.json");
  const outputPath = path.join(root, "release-manifest.json");
  const statementBytes = fixture.publishedArtifacts.find(
    ([descriptor]) => descriptor.name === fixture.manifest.evidence.provenance[0].statement.name,
  )[1];
  const bundleBytes = fixture.publishedArtifacts.find(
    ([descriptor]) => descriptor.name === fixture.manifest.evidence.provenance[0].bundle.name,
  )[1];
  const evaluatorTransitionBytes = fixture.publishedArtifacts.find(
    ([descriptor]) => descriptor.name === "evaluator-epoch-transition.json",
  )[1];
  await Promise.all([
    writeFile(templatePath, canonicalJson(template)),
    writeFile(statementPath, statementBytes),
    writeFile(bundlePath, bundleBytes),
    writeFile(transparencyPath, canonicalJson(fixture.manifest.evidence.transparency[0])),
    writeFile(evaluatorTransitionPath, evaluatorTransitionBytes),
  ]);
  const assemblyArguments = [
    "release/assemble-release-manifest.mjs",
    "--template", templatePath,
    "--evaluator-epoch-transition", evaluatorTransitionPath,
    "--provenance-statement", statementPath,
    "--sigstore-bundle", bundlePath,
    "--transparency-record", transparencyPath,
    "--evidence-base-url", "https://evidence.example/releases/2026.08.02.1/",
    "--issuer", "https://token.actions.githubusercontent.com",
    "--workflow-identity", fixture.manifest.evidence.provenance[0].workflowIdentity,
    "--output", outputPath,
  ];
  await command(assemblyArguments);
  const assembled = normalizeReleaseManifest(JSON.parse(await readFile(outputPath, "utf8")), {
    requireProduction: true,
  });
  assert.equal(assembled.evidence.provenance[0].subjects.length, 9);

  const missingCore = structuredClone(assembled);
  missingCore.evidence.provenance[0].subjects = missingCore.evidence.provenance[0].subjects.filter(
    ({ name }) => name !== missingCore.artifacts.scheduler.name,
  );
  assert.throws(
    () => normalizeReleaseManifest(missingCore, { requireProduction: true }),
    /must exactly cover every source, client, service, and SBOM artifact/u,
  );

  const unrelated = structuredClone(assembled);
  unrelated.evidence.provenance[0].subjects[0] = {
    name: "unrelated-preexisting-artifact.tar",
    sha256: "ef".repeat(32),
  };
  assert.throws(
    () => normalizeReleaseManifest(unrelated, { requireProduction: true }),
    /must exactly cover every source, client, service, and SBOM artifact/u,
  );

  for (const [mutate, expected] of [
    [
      (record) => {
        record.entryId = `wrong-prefix:${record.entryId.split(":").at(-1)}`;
      },
      /do not identify the same inclusion/u,
    ],
    [
      (record) => {
        record.url = "https://evidence.example/unrelated?logIndex=1234";
      },
      /do not identify the same inclusion/u,
    ],
  ]) {
    const record = structuredClone(fixture.manifest.evidence.transparency[0]);
    mutate(record);
    await writeFile(transparencyPath, canonicalJson(record));
    await assert.rejects(command(assemblyArguments), expected);
  }

  const noncanonicalDigestBundle = JSON.parse(bundleBytes);
  noncanonicalDigestBundle.messageSignature.messageDigest.digest =
    noncanonicalDigestBundle.messageSignature.messageDigest.digest.slice(0, -1);
  await Promise.all([
    writeFile(bundlePath, canonicalJson(noncanonicalDigestBundle)),
    writeFile(transparencyPath, canonicalJson(fixture.manifest.evidence.transparency[0])),
  ]);
  await assert.rejects(command(assemblyArguments), /not canonical base64/u);
});

test("workflow-shaped production graph generates, assembles, signs, and verifies exact evidence", async () => {
  const fixture = makeReleaseFixture();
  const templateInput = structuredClone(fixture.manifest);
  templateInput.previousRelease = {
    releaseId: "2026.08.01.1",
    manifestSha256: "aa".repeat(32),
  };
  templateInput.evidence.provenance = [];
  templateInput.evidence.transparency = [];
  templateInput.evidence.transitions = [];
  templateInput.evidence.deployments = [];
  const template = normalizeProductionReleaseTemplate(templateInput);
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-workflow-shaped-release-test-"));
  const stage = path.join(root, "stage");
  await mkdir(stage);
  const bytesByName = new Map(
    fixture.publishedArtifacts.map(([descriptor, bytes]) => [descriptor.name, bytes]),
  );
  await Promise.all(
    [...productionProvenanceArtifacts(template), ...template.evidence.audits].map((descriptor) =>
      writeFile(path.join(stage, descriptor.name), bytesByName.get(descriptor.name)),
    ),
  );
  const templatePath = path.join(root, "release-template.json");
  const statementPath = path.join(stage, "build-provenance.intoto.json");
  const bundlePath = path.join(stage, "build-provenance.sigstore.json");
  const transparencyPath = path.join(stage, "build-provenance.rekor.json");
  const evaluatorTransitionPath = path.join(stage, "evaluator-epoch-transition.json");
  const releaseContinuityPath = path.join(stage, "release-continuity.json");
  const manifestPath = path.join(stage, "release-manifest.json");
  const signaturePath = path.join(stage, "release-manifest.sig.json");
  const publicKeyPath = path.join(root, "release-public.pem");
  const privateKeyPath = path.join(root, "release-private.pem");
  await Promise.all([
    writeFile(templatePath, canonicalJson(templateInput)),
    writeFile(publicKeyPath, fixture.keys.releaseSigning.publicPem),
    writeFile(privateKeyPath, fixture.keys.releaseSigning.privatePem),
    writeFile(
      evaluatorTransitionPath,
      bytesByName.get("evaluator-epoch-transition.json"),
    ),
    writeFile(
      releaseContinuityPath,
      canonicalJson({
        schemaVersion: 1,
        observedAt: template.createdAt,
        currentReleasePointer: {
          url: "https://app.herd.example/.well-known/herd-release.json",
          sha256: "ab".repeat(32),
        },
        previousManifest: {
          releaseId: template.previousRelease.releaseId,
          url: "https://evidence.example/previous-release-manifest.json",
          sha256: template.previousRelease.manifestSha256,
          signatureUrl: "https://evidence.example/previous-release-manifest.sig.json",
          signatureSha256: "ac".repeat(32),
        },
        continuity: {
          schemaVersion: 1,
          mode: "artifact-release",
          previousReleaseId: template.previousRelease.releaseId,
          nextReleaseId: template.releaseId,
          evaluatorKeyEpochId: template.evaluatorKeyEpochId,
          evaluatorKeyEpochSha256: evaluatorKeyEpochSha256(template),
        },
      }),
    ),
  ]);
  await command([
    "release/generate-provenance.mjs",
    "--artifact-root", stage,
    "--release-template", templatePath,
    "--evaluator-epoch-transition", evaluatorTransitionPath,
    "--release-continuity", releaseContinuityPath,
    "--output", statementPath,
    "--started-at", template.createdAt,
    "--finished-at", template.createdAt,
    "--source-repository", template.source.repository,
    "--source-revision", template.source.revision,
    "--release-id", template.releaseId,
    "--toolchain-spec", "release/toolchains.json",
    "--builder-id", "https://github.com/jwoodbury11/Herd/.github/workflows/release-evidence.yml",
    "--invocation-id", "workflow-shaped-test",
  ]);
  const statementBytes = await readFile(statementPath);
  const generatedSubjects = JSON.parse(statementBytes).subject.map(({ name }) => name);
  assert.ok(generatedSubjects.includes("evaluator-epoch-transition.json"));
  assert.ok(generatedSubjects.includes("release-continuity.json"));
  const statementSha256 = sha256Hex(statementBytes);
  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      certificate: { rawBytes: Buffer.alloc(96, 5).toString("base64") },
      tlogEntries: [
        {
          logId: { keyId: "rekor-production" },
          logIndex: "1234",
          integratedTime: String(template.sourceDateEpoch),
          inclusionPromise: { signedEntryTimestamp: Buffer.alloc(64, 6).toString("base64") },
          canonicalizedBody: Buffer.from(JSON.stringify({ statementSha256 })).toString("base64"),
        },
      ],
    },
    messageSignature: {
      messageDigest: {
        algorithm: "SHA2_256",
        digest: Buffer.from(statementSha256, "hex").toString("base64"),
      },
      signature: Buffer.alloc(64, 7).toString("base64"),
    },
  };
  await writeFile(bundlePath, canonicalJson(bundle));
  await command([
    "release/record-transparency.mjs",
    "--bundle", bundlePath,
    "--rekor-record-base-url", "https://rekor.sigstore.dev/api/v1/log/entries",
    "--output", transparencyPath,
  ]);
  const workflowIdentity =
    "https://github.com/jwoodbury11/Herd/.github/workflows/release-evidence.yml@refs/heads/main";
  await command([
    "release/assemble-release-manifest.mjs",
    "--template", templatePath,
    "--evaluator-epoch-transition", evaluatorTransitionPath,
    "--release-continuity", releaseContinuityPath,
    "--provenance-statement", statementPath,
    "--sigstore-bundle", bundlePath,
    "--transparency-record", transparencyPath,
    "--evidence-base-url", `https://evidence.example/releases/${template.releaseId}/`,
    "--issuer", "https://token.actions.githubusercontent.com",
    "--workflow-identity", workflowIdentity,
    "--output", manifestPath,
  ]);
  await command([
    "release/sign-release-manifest.mjs",
    "--manifest", manifestPath,
    "--private-key", privateKeyPath,
    "--public-key", publicKeyPath,
    "--output", signaturePath,
  ]);
  const cosignStub = await writeCosignStub(root);
  const { stdout } = await command([
    "release/verify-release-manifest.mjs",
    "--manifest", manifestPath,
    "--signature", signaturePath,
    "--public-key", publicKeyPath,
    "--require-production",
    "--artifact-root", stage,
    "--cosign", cosignStub,
  ]);
  const verification = JSON.parse(stdout);
  assert.equal(verification.provenanceBundles, 1);
  assert.equal(verification.artifactCount, 13);
});

test("local release-artifact verification rejects a bytes-identical symbolic link", async () => {
  const fixture = makeReleaseFixture();
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-release-symlink-test-"));
  await Promise.all(
    fixture.publishedArtifacts.map(([descriptor, bytes]) =>
      writeFile(path.join(root, descriptor.name), bytes),
    ),
  );
  const descriptor = fixture.manifest.source.exportArchive;
  const expectedPath = path.join(root, descriptor.name);
  const targetPath = path.join(root, "bytes-identical-target.bin");
  await writeFile(targetPath, bytesByDescriptor(fixture, descriptor));
  await unlink(expectedPath);
  await symlink(targetPath, expectedPath);
  await assert.rejects(
    verifyLocalArtifacts(fixture.manifest, root),
    /non-symbolic-link file/u,
  );
});

function bytesByDescriptor(fixture, descriptor) {
  return fixture.publishedArtifacts.find(([candidate]) => candidate.name === descriptor.name)[1];
}
