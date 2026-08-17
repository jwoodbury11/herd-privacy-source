import { generateKeyPairSync } from "node:crypto";

import { canonicalJson, sha256Hex, timestampFromEpoch } from "../lib/canonical.mjs";
import { computeWorkloadKeyBindingHash, normalizeReleaseManifest } from "../lib/release-manifest.mjs";
import { releaseSigningKeyDescriptor, signCanonicalArtifact } from "../lib/signature.mjs";

const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";
const DEPLOYMENT_TYPE = "application/vnd.herd.deployment-statement.v1+json";
const REKOR_LOG_ID_BYTES = Buffer.alloc(32, 9);
const REKOR_LOG_ID = REKOR_LOG_ID_BYTES.toString("base64");

function artifact(
  name,
  bytes = Buffer.from(name),
  url = `https://evidence.example/${name}`,
  mediaType = "application/octet-stream",
) {
  return {
    name,
    mediaType,
    sha256: sha256Hex(bytes),
    size: bytes.byteLength,
    url,
  };
}

function keyPair(keyId, algorithm = "ECDSA_P256_SHA256") {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const publicPem = publicKey.export({ format: "pem", type: "spki" }).toString();
  const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return {
    publicPem,
    privatePem,
    descriptor: { ...releaseSigningKeyDescriptor(publicPem, keyId), algorithm },
  };
}

function reference(bytes, url) {
  return { url, sha256: sha256Hex(bytes), size: bytes.byteLength };
}

export function makeReleaseFixture({
  releaseStage = "production",
  previousRelease = null,
  evaluatorUrl = "https://evaluator.herd.example/api/v1/relay/",
  evaluatorAttestationOrigin = "https://evaluator.herd.example",
  appleAppSiteAssociationValue = null,
} = {}) {
  const releaseId = "2026.08.02.1";
  const evaluatorKeyEpochId = "herd-evaluator-epoch-2026.08";
  const sourceDateEpoch = 1785657600;
  const createdAt = timestampFromEpoch(sourceDateEpoch);
  const evaluatorEncryption = keyPair("evaluator-encryption-2026", "P256_ECDH_HKDF_SHA256_AES256_GCM");
  const resultSigning = keyPair("result-signing-2026");
  const policySigning = keyPair("policy-signing-2026");
  const receiptTransparencySigning = keyPair("receipt-signing-2026");
  const releaseSigning = keyPair("release-signing-2026");
  const imageDigest = { algorithm: "sha256", value: "11".repeat(32) };
  const policyMeasurement = { algorithm: "sha256", value: "33".repeat(32) };
  const sourceArchiveBytes = Buffer.from("herd-privacy-source.tar");
  const sourceArchive = artifact("herd-privacy-source.tar", sourceArchiveBytes);
  const sourceManifestBytes = Buffer.from(canonicalJson({
    schemaVersion: 1,
    archiveFormat: "ustar",
    archivePrefix: "herd-privacy-source",
    createdAt,
    sourceDateEpoch,
    sourceRevision: "ab".repeat(20),
    license: "Apache-2.0",
    policy: { path: "public-source/export-policy.json", sha256: "10".repeat(32) },
    files: [
      {
        path: "LICENSE",
        mode: "0644",
        size: 11_358,
        sha256: "12".repeat(32),
      },
    ],
  }));
  const sourceManifest = artifact(
    "herd-privacy-source.manifest.json",
    sourceManifestBytes,
    "https://evidence.example/herd-privacy-source.manifest.json",
    "application/json",
  );
  const webDeploymentBytes = Buffer.from("web-deployment.tar");
  const webDeploymentArchive = artifact("web-deployment.tar", webDeploymentBytes);
  const iosArchiveBytes = Buffer.from("HerdHost.ipa");
  const iosArchive = artifact("HerdHost.ipa", iosArchiveBytes);
  const ordinaryApiBytes = Buffer.from("ordinary-api.tar");
  const ordinaryApi = artifact("ordinary-api.tar", ordinaryApiBytes);
  const evaluatorBytes = Buffer.from("evaluator.tar");
  const evaluator = artifact("evaluator.tar", evaluatorBytes);
  const schedulerBytes = Buffer.from("scheduler.tar");
  const scheduler = artifact("scheduler.tar", schedulerBytes);
  const sbomBytes = Buffer.from(canonicalJson({
    SPDXID: "SPDXRef-DOCUMENT",
    creationInfo: { created: createdAt, creators: ["Tool: Herd release fixture"] },
    dataLicense: "CC0-1.0",
    documentNamespace: `https://evidence.example/spdx/${releaseId}`,
    name: `Herd ${releaseId}`,
    packages: [{ SPDXID: "SPDXRef-Package-Herd", name: "Herd privacy source" }],
    files: [],
    relationships: [],
    spdxVersion: "SPDX-2.3",
  }));
  const sbom = artifact(
    "herd.spdx.json",
    sbomBytes,
    "https://evidence.example/herd.spdx.json",
    "application/spdx+json",
  );
  const evaluatorEpochTransitionBytes = Buffer.from(canonicalJson({
    schemaVersion: 2,
    mode: "initial-generation",
    generation: 1,
    previousArtifactReleaseId: null,
    nextArtifactReleaseId: releaseId,
    previousEvaluatorKeyEpochId: null,
    nextEvaluatorKeyEpochId: evaluatorKeyEpochId,
    nextEvaluatorKeyEpochSha256: "10".repeat(32),
    transparencyIdentitySha256: "12".repeat(32),
    observedAt: createdAt,
  }));
  const evaluatorEpochTransition = artifact(
    "evaluator-epoch-transition.json",
    evaluatorEpochTransitionBytes,
    "https://evidence.example/evaluator-epoch-transition.json",
    "application/vnd.herd.evaluator-epoch-transition.v2+json",
  );
  const provenanceSubjects = [
    sourceArchive,
    sourceManifest,
    webDeploymentArchive,
    iosArchive,
    ordinaryApi,
    evaluator,
    scheduler,
    sbom,
    ...(releaseStage === "production" ? [evaluatorEpochTransition] : []),
  ]
    .map(({ name, sha256 }) => ({ name, sha256 }))
    .sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
  const provenanceStatement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: provenanceSubjects.map(({ name, sha256 }) => ({ name, digest: { sha256 } })),
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "urn:herd:build-type:privacy-release-evidence:v1",
        externalParameters: {
          releaseId,
          source: {
            repository: "https://github.com/jwoodbury11/Herd",
            revision: "ab".repeat(20),
          },
        },
        internalParameters: {},
        resolvedDependencies: [],
      },
      runDetails: {
        builder: {
          id: "https://github.com/jwoodbury11/Herd/.github/workflows/release-evidence.yml",
        },
        metadata: {
          invocationId: "fixture-invocation",
          startedOn: createdAt,
          finishedOn: createdAt,
        },
        byproducts: [],
      },
    },
  };
  const provenanceStatementBytes = Buffer.from(canonicalJson(provenanceStatement));
  const provenanceStatementArtifact = artifact(
    "build-provenance.intoto.json",
    provenanceStatementBytes,
    "https://evidence.example/build-provenance.intoto.json",
    "application/vnd.in-toto+json",
  );
  const provenanceBundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json";
  const provenanceBundleBytes = Buffer.from(canonicalJson({
    mediaType: provenanceBundleMediaType,
    verificationMaterial: {
      certificate: { rawBytes: Buffer.alloc(96, 5).toString("base64") },
      tlogEntries: [
        {
          logId: { keyId: REKOR_LOG_ID },
          logIndex: "1234",
          integratedTime: String(sourceDateEpoch),
          inclusionPromise: { signedEntryTimestamp: Buffer.alloc(64, 6).toString("base64") },
          inclusionProof: {
            logIndex: "34",
            treeSize: "35",
            rootHash: Buffer.alloc(32, 7).toString("base64"),
            hashes: [Buffer.alloc(32, 8).toString("base64")],
            checkpoint: { envelope: "rekor.example - 1\n35\ncheckpoint\n" },
          },
          canonicalizedBody: Buffer.from(
            JSON.stringify({ statementSha256: provenanceStatementArtifact.sha256 }),
          ).toString("base64"),
        },
      ],
    },
    messageSignature: {
      messageDigest: {
        algorithm: "SHA2_256",
        digest: Buffer.from(provenanceStatementArtifact.sha256, "hex").toString("base64"),
      },
      signature: Buffer.alloc(64, 7).toString("base64"),
    },
  }));
  const provenanceBundle = artifact(
    "provenance.sigstore.json",
    provenanceBundleBytes,
    "https://evidence.example/provenance.sigstore.json",
    provenanceBundleMediaType,
  );
  const auditBytes = Buffer.from("%PDF-1.7\n% Herd independent audit fixture\n%%EOF\n");
  const audit = artifact(
    "independent-audit.pdf",
    auditBytes,
    "https://evidence.example/independent-audit.pdf",
    "application/pdf",
  );
  const trust = {
    evaluatorEncryption: evaluatorEncryption.descriptor,
    resultSigning: resultSigning.descriptor,
    policySigning: policySigning.descriptor,
    receiptTransparencySigning: receiptTransparencySigning.descriptor,
    releaseManifestSigning: releaseSigning.descriptor,
  };
  const binding = {
    evaluatorKeyEpochId,
    evaluatorEncryption: trust.evaluatorEncryption,
    resultSigning: trust.resultSigning,
    policySigning: trust.policySigning,
    receiptTransparencySigning: trust.receiptTransparencySigning,
  };
  const manifest = normalizeReleaseManifest({
    schemaVersion: 1,
    releaseId,
    evaluatorKeyEpochId,
    previousRelease,
    releaseStage,
    createdAt,
    sourceDateEpoch,
    source: {
      repository: "https://github.com/jwoodbury11/Herd",
      revision: "ab".repeat(20),
      license: "Apache-2.0",
      exportArchive: sourceArchive,
      exportManifest: sourceManifest,
    },
    protocol: {
      version: 1,
      cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
      paddedPlaintextBytes: 4096,
      payloadFrameBytes: 4124,
      userWrapBytes: 60,
      evaluatorWrapBytes: 157,
    },
    trust: {
      ...trust,
      workload: {
        platform: "gcp-confidential-space",
        imageDigest,
        policyMeasurement,
        measurements: [{ algorithm: "sha384", value: "22".repeat(48) }],
        attestationProvider: "google-pki-attestation-token",
        attestationClaimPolicy: {
          policyId: "herd-confidential-space-v1",
          issuer: "https://confidentialcomputing.googleapis.com",
          audience: "https://evaluator.herd.example/attestation",
          maxAgeSeconds: 300,
          challengeNonceRequired: true,
          keyBindingDomain: "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1",
          keyBindingHashAlgorithm: "sha256",
          keyBindingHashEncoding: "base64url",
          keyBindingHash: computeWorkloadKeyBindingHash(binding),
          imageDigest,
          allowedImageDigests: [imageDigest],
          projectId: "herd-prod",
          serviceAccount: "herd-evaluator@herd-prod.iam.gserviceaccount.com",
          hwmodel: "GCP_INTEL_TDX",
          secboot: true,
          dbgstat: "disabled-since-boot",
          swname: "CONFIDENTIAL_SPACE",
          allowedSwversions: ["260500", "260600"],
          oemid: 11129,
          attesterTcb: "INTEL",
          envOverrideAllowed: false,
          cmdOverrideAllowed: false,
        },
        attestationRootFingerprint: { algorithm: "sha256", value: "33".repeat(32) },
      },
    },
    artifacts: {
      web: {
        publicOrigin: "https://app.herd.example",
        deploymentArchive: webDeploymentArchive,
        assetManifestSha256: "44".repeat(32),
        entryDocumentSha256: "55".repeat(32),
      },
      ios: {
        bundleIdentifier: "com.herd.host",
        version: "1.0.0",
        build: "100",
        submissionArchive: iosArchive,
        normalizedBinarySha256: "66".repeat(32),
      },
      ordinaryApi,
      evaluator,
      scheduler,
    },
    database: { migrationSetSha256: "77".repeat(32), schemaSha256: "88".repeat(32) },
    productionPolicy: {
      configurationSha256: "99".repeat(32),
      testAuthenticationEnabled: false,
      debugEnabled: false,
      requestBodyLoggingEnabled: false,
    },
    evidence: {
      sboms: [sbom],
      provenance:
        releaseStage === "production"
          ? [
              {
                subjects: provenanceSubjects,
                predicateType: "https://slsa.dev/provenance/v1",
                issuer: "https://token.actions.githubusercontent.com",
                workflowIdentity: "jwoodbury11/Herd/.github/workflows/release-evidence.yml@refs/heads/main",
                statement: provenanceStatementArtifact,
                bundle: provenanceBundle,
              },
            ]
          : [],
      transparency:
        releaseStage === "production"
          ? [
              {
                provider: "sigstore-rekor",
                logId: REKOR_LOG_ID,
                entryId: `${REKOR_LOG_ID}:1234`,
                integratedTime: sourceDateEpoch,
                bundleSha256: provenanceBundle.sha256,
                url: "https://rekor.sigstore.dev/api/v1/log/entries?logIndex=1234",
              },
            ]
          : [],
      transitions:
        releaseStage === "production" ? [evaluatorEpochTransition] : [],
      deployments: [],
      audits: releaseStage === "production" ? [audit] : [],
    },
  });
  const entryBytes = Buffer.from("<!doctype html><title>Herd</title>\n");
  const assetBytes = Buffer.from('{"app.js":"app.01234567.js"}\n');
  const appleAppSiteAssociationBytes = Buffer.from(JSON.stringify(
    appleAppSiteAssociationValue ?? {
      applinks: {
        apps: [],
        details: [{
          appID: `R4UPN8ZDV8.${manifest.artifacts.ios.bundleIdentifier}`,
          paths: ["/invite/*"],
        }],
      },
    },
  ));
  manifest.artifacts.web.entryDocumentSha256 = sha256Hex(entryBytes);
  manifest.artifacts.web.assetManifestSha256 = sha256Hex(assetBytes);
  const correctedManifestBytes = Buffer.from(canonicalJson(manifest));
  const correctedManifestSignature = signCanonicalArtifact({
    bytes: correctedManifestBytes,
    privateKey: releaseSigning.privatePem,
    publicKey: releaseSigning.publicPem,
    keyId: releaseSigning.descriptor.keyId,
    signedAt: createdAt,
    artifactType: MANIFEST_TYPE,
  });
  const correctedManifestSignatureBytes = Buffer.from(canonicalJson(correctedManifestSignature));
  const manifestUrl = "https://evidence.example/releases/test/release-manifest.json";
  const manifestSignatureUrl = "https://evidence.example/releases/test/release-manifest.sig.json";
  const resources = [
    {
      name: "apple-app-site-association",
      url: "https://app.herd.example/.well-known/apple-app-site-association",
      sha256: sha256Hex(appleAppSiteAssociationBytes),
      size: appleAppSiteAssociationBytes.byteLength,
      mediaType: "application/json",
    },
    {
      name: "asset-manifest",
      url: "https://app.herd.example/assets/manifest.json",
      sha256: sha256Hex(assetBytes),
      size: assetBytes.byteLength,
      mediaType: "application/json",
    },
    {
      name: "entry-document",
      url: "https://app.herd.example/",
      sha256: sha256Hex(entryBytes),
      size: entryBytes.byteLength,
      mediaType: "text/html",
    },
  ];
  const deployment = {
    schemaVersion: 1,
    releaseId,
    environment: releaseStage === "production" ? "production" : "staging",
    deployedAt: createdAt,
    manifest: {
      name: "release-manifest.json",
      mediaType: MANIFEST_TYPE,
      ...reference(correctedManifestBytes, manifestUrl),
    },
    manifestSignature: {
      name: "release-manifest.sig.json",
      mediaType: "application/vnd.herd.signature.v1+json",
      ...reference(correctedManifestSignatureBytes, manifestSignatureUrl),
    },
    endpoints: {
      webOrigin: "https://app.herd.example",
      apiBaseUrl: "https://app.herd.example/api/",
      evaluatorUrl,
      schedulerIdentity: "cloudflare-worker:herd-scheduler",
    },
    platformDeployments: [
      { component: "evaluator", provider: "gcp", deploymentId: "eval-1", artifactSha256: manifest.artifacts.evaluator.sha256 },
      { component: "ordinary-api", provider: "cloudflare", deploymentId: "api-1", artifactSha256: manifest.artifacts.ordinaryApi.sha256 },
      { component: "scheduler", provider: "cloudflare", deploymentId: "scheduler-1", artifactSha256: manifest.artifacts.scheduler.sha256 },
      { component: "web", provider: "cloudflare", deploymentId: "web-1", artifactSha256: manifest.artifacts.web.deploymentArchive.sha256 },
    ],
    monitoredResources: resources,
  };
  const deploymentBytes = Buffer.from(canonicalJson(deployment));
  const deploymentSignature = signCanonicalArtifact({
    bytes: deploymentBytes,
    privateKey: releaseSigning.privatePem,
    publicKey: releaseSigning.publicPem,
    keyId: releaseSigning.descriptor.keyId,
    signedAt: createdAt,
    artifactType: DEPLOYMENT_TYPE,
  });
  const deploymentSignatureBytes = Buffer.from(canonicalJson(deploymentSignature));
  const deploymentUrl = "https://evidence.example/releases/test/deployment.json";
  const deploymentSignatureUrl = "https://evidence.example/releases/test/deployment.sig.json";
  const wellKnown = {
    schemaVersion: 1,
    releaseId,
    previousRelease: manifest.previousRelease,
    protocol: manifest.protocol,
    releaseSigningKey: releaseSigning.descriptor,
    manifest: {
      ...reference(correctedManifestBytes, manifestUrl),
      signature: reference(correctedManifestSignatureBytes, manifestSignatureUrl),
    },
    deploymentStatement: {
      ...reference(deploymentBytes, deploymentUrl),
      signature: reference(deploymentSignatureBytes, deploymentSignatureUrl),
      environment: deployment.environment,
      deployedAt: deployment.deployedAt,
    },
    web: {
      publicOrigin: manifest.artifacts.web.publicOrigin,
      entryDocumentSha256: manifest.artifacts.web.entryDocumentSha256,
      assetManifestSha256: manifest.artifacts.web.assetManifestSha256,
    },
    evaluator: {
      evaluatorKeyEpochId,
      encryptionKeyId: manifest.trust.evaluatorEncryption.keyId,
      resultSigningKeyId: manifest.trust.resultSigning.keyId,
      policySigningKeyId: manifest.trust.policySigning.keyId,
      receiptTransparencySigningKeyId: manifest.trust.receiptTransparencySigning.keyId,
      workloadImageDigest: manifest.trust.workload.imageDigest,
      policyMeasurement: manifest.trust.workload.policyMeasurement,
      measurements: manifest.trust.workload.measurements,
      attestationProvider: manifest.trust.workload.attestationProvider,
      attestationClaimPolicy: manifest.trust.workload.attestationClaimPolicy,
      attestationRootFingerprint: manifest.trust.workload.attestationRootFingerprint,
    },
    responseTransparency: {
      protocolVersion: 1,
      logId: "herd-response-log-v1",
      url: "https://app.herd.example/api/transparency/responses",
      signingKey: manifest.trust.receiptTransparencySigning,
      dataPolicy: "hash-chain-heads-only-v1",
      entryFields: ["entryHash", "head", "logIndex", "previousEntryHash"],
    },
    monitoredResources: resources,
    verifier: {
      sourceUrl: "https://github.com/jwoodbury11/Herd/tree/main/monitor",
      command: "node release/verify-release-manifest.mjs",
    },
  };
  const wellKnownBytes = Buffer.from(canonicalJson(wellKnown));
  const wellKnownUrl = "https://app.herd.example/.well-known/herd-release.json";
  const publishedArtifacts = [
    [sourceArchive, sourceArchiveBytes],
    [sourceManifest, sourceManifestBytes],
    [webDeploymentArchive, webDeploymentBytes],
    [iosArchive, iosArchiveBytes],
    [ordinaryApi, ordinaryApiBytes],
    [evaluator, evaluatorBytes],
    [scheduler, schedulerBytes],
    [sbom, sbomBytes],
    ...(releaseStage === "production"
      ? [[evaluatorEpochTransition, evaluatorEpochTransitionBytes]]
      : []),
    [provenanceStatementArtifact, provenanceStatementBytes],
    [provenanceBundle, provenanceBundleBytes],
    [audit, auditBytes],
  ];
  const rekorResponseBytes = Buffer.from(canonicalJson({
    logID: REKOR_LOG_ID_BYTES.toString("hex"),
    logIndex: 1234,
    integratedTime: sourceDateEpoch,
  }));
  const responses = new Map([
    [wellKnownUrl, { bytes: wellKnownBytes, mediaType: "application/json" }],
    [manifestUrl, { bytes: correctedManifestBytes, mediaType: MANIFEST_TYPE }],
    [manifestSignatureUrl, { bytes: correctedManifestSignatureBytes, mediaType: "application/vnd.herd.signature.v1+json" }],
    [deploymentUrl, { bytes: deploymentBytes, mediaType: DEPLOYMENT_TYPE }],
    [deploymentSignatureUrl, { bytes: deploymentSignatureBytes, mediaType: "application/vnd.herd.signature.v1+json" }],
    [resources[0].url, { bytes: appleAppSiteAssociationBytes, mediaType: resources[0].mediaType }],
    [resources[1].url, { bytes: assetBytes, mediaType: resources[1].mediaType }],
    [resources[2].url, { bytes: entryBytes, mediaType: resources[2].mediaType }],
    ...(manifest.evidence.transparency[0]
      ? [[manifest.evidence.transparency[0].url, {
          bytes: rekorResponseBytes,
          mediaType: "application/json",
        }]]
      : []),
    ...publishedArtifacts.map(([descriptor, bytes]) => [
      descriptor.url,
      { bytes, mediaType: descriptor.mediaType },
    ]),
  ]);
  return {
    releaseId,
    evaluatorKeyEpochId,
    createdAt,
    keys: { evaluatorEncryption, resultSigning, policySigning, receiptTransparencySigning, releaseSigning },
    manifest,
    manifestBytes: correctedManifestBytes,
    manifestSignature: correctedManifestSignature,
    manifestSignatureBytes: correctedManifestSignatureBytes,
    deployment,
    deploymentBytes,
    deploymentSignature,
    deploymentSignatureBytes,
    wellKnown,
    wellKnownBytes,
    wellKnownUrl,
    resources,
    appleAppSiteAssociationBytes,
    publishedArtifacts,
    responses,
    target: {
      name: "herd-production",
      wellKnownUrl,
      expectedWebOrigin: "https://app.herd.example",
      allowedEvidenceOrigins: ["https://evidence.example", "https://rekor.sigstore.dev"],
      requireProduction: releaseStage === "production",
      releaseSigningKey: releaseSigning.descriptor,
      ...(releaseStage === "production"
        ? {
            evaluatorAttestation: {
              origin: evaluatorAttestationOrigin,
              rootCertificateDerBase64: Buffer.from(
                "fixture-independent-attestation-root",
              ).toString("base64"),
            },
          }
        : {}),
    },
  };
}
