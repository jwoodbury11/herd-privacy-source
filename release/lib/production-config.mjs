import { X509Certificate } from "node:crypto";

import { canonicalJson, sha256Hex } from "./canonical.mjs";
import { evaluatorKeyEpochSha256 } from "./evaluator-key-epoch.mjs";
import { IOS_DEVELOPMENT_TEAM, iosApplicationIdentifier } from "./deployment.mjs";
import { normalizeReleaseManifest } from "./release-manifest.mjs";
import { normalizeProductionReleaseTemplate } from "./production-template.mjs";

export const PRODUCTION_CONFIG_SCHEMA = "herd-production-config-v1";
export const IOS_XCCONFIG_NAME = "HerdRelease.generated.xcconfig";

const FORBIDDEN_PRODUCTION_TOKEN =
  /(?:^|[._-])(?:dev|development|local|localhost|preview|qa|sandbox|stage|staging|test|testing)(?:[._-]|$)/iu;

function productionUrl(value, label, { originOnly = false } = {}) {
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
    url.origin === "null" ||
    (originOnly && (url.pathname !== "/" || url.search))
  ) {
    throw new TypeError(`${label} must be a safe HTTPS ${originOnly ? "origin" : "URL"}.`);
  }
  const hostLabels = url.hostname.split(".");
  const reservedExampleDomain =
    ["example.com", "example.net", "example.org"].some(
      (domain) => url.hostname === domain || url.hostname.endsWith(`.${domain}`),
    ) || url.hostname.endsWith(".example") || url.hostname.endsWith(".invalid");
  if (
    url.hostname === "localhost" ||
    url.hostname.endsWith(".localhost") ||
    url.hostname.endsWith(".test") ||
    reservedExampleDomain ||
    hostLabels.some((labelPart) => FORBIDDEN_PRODUCTION_TOKEN.test(labelPart))
  ) {
    throw new TypeError(`${label} contains a non-production host name.`);
  }
  return originOnly ? url.origin : url.toString();
}

function productionIdentifier(value, label) {
  if (FORBIDDEN_PRODUCTION_TOKEN.test(value) || /(?:^|[-_.])live-v1(?:$|[-_.])/iu.test(value)) {
    throw new TypeError(`${label} contains a preview, test, or legacy live-v1 identifier.`);
  }
  return value;
}

function productionEvaluatorRelayUrl(value) {
  const normalized = productionUrl(value, "evaluator URL");
  const url = new URL(normalized);
  if (url.pathname !== "/api/v1/relay/" || url.search) {
    throw new TypeError(
      "evaluator URL must be the exact production /api/v1/relay/ endpoint without a query.",
    );
  }
  return url.toString();
}

function runtimeKey(value, label) {
  return {
    keyId: productionIdentifier(value.keyId, `${label}.keyId`),
    algorithm: value.algorithm,
    publicKeyFormat: value.publicKeyFormat,
    publicKey: value.publicKey,
    publicKeySha256: value.publicKeySha256,
  };
}

function rootCertificateRecord(rootCertificate, expectedFingerprint) {
  let certificate;
  try {
    certificate = new X509Certificate(rootCertificate);
  } catch {
    throw new TypeError("The attestation root certificate is not a valid X.509 certificate.");
  }
  if (!certificate.checkIssued(certificate) || !certificate.verify(certificate.publicKey)) {
    throw new TypeError("The attestation root certificate must be self-issued and self-signed.");
  }
  const der = Buffer.from(certificate.raw);
  const fingerprint = sha256Hex(der);
  if (fingerprint !== expectedFingerprint) {
    throw new TypeError("The attestation root certificate does not match the signed manifest fingerprint.");
  }
  return {
    format: "X509_DER_BASE64",
    derBase64: der.toString("base64"),
    sha256: fingerprint,
    pem: certificate.toString().replaceAll("\r\n", "\n"),
  };
}

function xcconfigValue(value) {
  if (/[$\r\n]/u.test(value)) throw new TypeError("An xcconfig value contains unsupported characters.");
  return value.replaceAll("//", "/$()/");
}

function dotenvValue(value) {
  return JSON.stringify(value.replaceAll("\n", "\\n"));
}

function renderAssignments(values, renderValue) {
  return `${Object.entries(values)
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .map(([name, value]) => `${name}=${renderValue(String(value))}`)
    .join("\n")}\n`;
}

export function buildProductionConfig(
  manifestInput,
  { evaluatorUrl, rootCertificate, releaseTemplate = false },
) {
  const manifest = releaseTemplate
    ? normalizeProductionReleaseTemplate(manifestInput)
    : normalizeReleaseManifest(manifestInput, { requireProduction: true });
  productionIdentifier(manifest.releaseId, "releaseId");
  productionIdentifier(manifest.evaluatorKeyEpochId, "evaluatorKeyEpochId");
  const iosBundleIdentifier = productionIdentifier(
    manifest.artifacts.ios.bundleIdentifier,
    "iOS bundle identifier",
  );
  const iosVersion = manifest.artifacts.ios.version;
  const iosBuild = manifest.artifacts.ios.build;
  const publicOrigin = productionUrl(manifest.artifacts.web.publicOrigin, "web public origin", {
    originOnly: true,
  });
  const publicOriginUrl = new URL(publicOrigin);
  if (publicOriginUrl.port && publicOriginUrl.port !== "443") {
    throw new TypeError("web public origin must use the standard HTTPS port for universal links.");
  }
  const iosAssociatedDomain = publicOriginUrl.hostname;
  const iosAppIdentifier = iosApplicationIdentifier(iosBundleIdentifier);
  const normalizedEvaluatorUrl = productionEvaluatorRelayUrl(evaluatorUrl);
  const claimPolicy = manifest.trust.workload.attestationClaimPolicy;
  productionUrl(claimPolicy.audience, "attestation audience");
  const root = rootCertificateRecord(
    rootCertificate,
    manifest.trust.workload.attestationRootFingerprint.value,
  );
  const imageDigest = `${manifest.trust.workload.imageDigest.algorithm}:${manifest.trust.workload.imageDigest.value}`;
  const evaluatorEpochSha256 = evaluatorKeyEpochSha256(manifest);
  const keys = {
    evaluatorEncryption: runtimeKey(manifest.trust.evaluatorEncryption, "evaluator encryption key"),
    resultSigning: runtimeKey(manifest.trust.resultSigning, "result signing key"),
    policySigning: runtimeKey(manifest.trust.policySigning, "policy signing key"),
    receiptTransparencySigning: runtimeKey(
      manifest.trust.receiptTransparencySigning,
      "receipt/transparency signing key",
    ),
  };
  const contract = {
    schema: PRODUCTION_CONFIG_SCHEMA,
    releaseId: manifest.releaseId,
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    evaluatorKeyEpochSha256: evaluatorEpochSha256,
    releaseStage: "production",
    web: { publicOrigin },
    ios: {
      bundleIdentifier: iosBundleIdentifier,
      version: iosVersion,
      build: iosBuild,
      developmentTeam: IOS_DEVELOPMENT_TEAM,
      appIdentifier: iosAppIdentifier,
      associatedDomain: iosAssociatedDomain,
      keychainAccessGroup: iosAppIdentifier,
    },
    evaluator: {
      url: normalizedEvaluatorUrl,
      transport: "client_relay",
      measurement: imageDigest,
    },
    scheduler: {
      deploymentProfile: "production",
      publicAppUrl: publicOrigin,
      evaluatorUrl: normalizedEvaluatorUrl,
      evaluatorKeyId: keys.evaluatorEncryption.keyId,
      artifactReleaseId: manifest.releaseId,
      releaseId: manifest.evaluatorKeyEpochId,
    },
    protocol: manifest.protocol,
    trust: {
      ...keys,
      workload: {
        platform: manifest.trust.workload.platform,
        imageDigest,
        measurements: manifest.trust.workload.measurements,
        attestationProvider: manifest.trust.workload.attestationProvider,
        attestationClaimPolicy: claimPolicy,
        attestationRootCertificate: {
          format: root.format,
          derBase64: root.derBase64,
          sha256: root.sha256,
        },
      },
    },
    productionSafety: {
      testAuthenticationEnabled: false,
      debugEnabled: false,
      requestBodyLoggingEnabled: false,
    },
  };
  const configurationSha256 = sha256Hex(Buffer.from(canonicalJson(contract)));

  const webPublicEnvironment = {
    NEXT_PUBLIC_HERD_ALLOW_SOFTWARE_QA_EVALUATOR: "false",
    NEXT_PUBLIC_HERD_ARTIFACT_RELEASE_ID: manifest.releaseId,
    NEXT_PUBLIC_HERD_ATTESTATION_AUDIENCE: claimPolicy.audience,
    NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGEST: imageDigest,
    NEXT_PUBLIC_HERD_ATTESTATION_MAX_AGE_SECONDS: String(claimPolicy.maxAgeSeconds),
    NEXT_PUBLIC_HERD_ATTESTATION_PROJECT_ID: claimPolicy.projectId,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_CERTIFICATE: root.pem,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_FINGERPRINT: root.sha256,
    NEXT_PUBLIC_HERD_ATTESTATION_SERVICE_ACCOUNT: claimPolicy.serviceAccount,
    NEXT_PUBLIC_HERD_ATTESTATION_SWVERSIONS: claimPolicy.allowedSwversions.join(","),
    NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID: keys.evaluatorEncryption.keyId,
    NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT: imageDigest,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: keys.policySigning.keyId,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: keys.policySigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY: keys.evaluatorEncryption.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: keys.resultSigning.keyId,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: keys.resultSigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID:
      keys.receiptTransparencySigning.keyId,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      keys.receiptTransparencySigning.publicKey,
    NEXT_PUBLIC_HERD_RELEASE_CONFIGURATION_SHA256: configurationSha256,
    NEXT_PUBLIC_HERD_RELEASE_ID: manifest.evaluatorKeyEpochId,
    NEXT_PUBLIC_HERD_DEPLOYMENT_PROFILE: "production",
  };
  const webRuntimeVariables = {
    HERD_ARTIFACT_RELEASE_ID: manifest.releaseId,
    HERD_ATTESTATION_AUDIENCE: claimPolicy.audience,
    HERD_ATTESTATION_IMAGE_DIGEST: imageDigest,
    HERD_ATTESTATION_MAX_AGE_SECONDS: String(claimPolicy.maxAgeSeconds),
    HERD_ATTESTATION_PROJECT_ID: claimPolicy.projectId,
    HERD_ATTESTATION_ROOT_FINGERPRINT: root.sha256,
    HERD_ATTESTATION_SERVICE_ACCOUNT: claimPolicy.serviceAccount,
    HERD_ATTESTATION_SWVERSIONS: claimPolicy.allowedSwversions.join(","),
    HERD_ATTESTATION_URL: `${new URL(normalizedEvaluatorUrl).origin}/api/v1/attestation`,
    HERD_DEPLOYMENT_PROFILE: "production",
    HERD_EVALUATOR_KEY_ID: keys.evaluatorEncryption.keyId,
    HERD_EVALUATOR_KEY_EPOCH_SHA256: evaluatorEpochSha256,
    HERD_EVALUATOR_MEASUREMENT: imageDigest,
    HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: keys.policySigning.keyId,
    HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: keys.policySigning.publicKey,
    HERD_EVALUATOR_PUBLIC_KEY: keys.evaluatorEncryption.publicKey,
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: keys.resultSigning.keyId,
    HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: keys.resultSigning.publicKey,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: keys.receiptTransparencySigning.keyId,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      keys.receiptTransparencySigning.publicKey,
    HERD_EVALUATOR_TRANSPORT: "client_relay",
    HERD_EVALUATOR_URL: normalizedEvaluatorUrl,
    HERD_PUBLIC_APP_URL: publicOrigin,
    HERD_IOS_APP_ID: iosAppIdentifier,
    HERD_RELEASE_CONFIGURATION_SHA256: configurationSha256,
    HERD_RELEASE_ID: manifest.evaluatorKeyEpochId,
    HERD_TEST_BYPASS_ENABLED: "false",
  };
  const iosBuildSettings = {
    CURRENT_PROJECT_VERSION: iosBuild,
    DEVELOPMENT_TEAM: IOS_DEVELOPMENT_TEAM,
    HERD_API_BASE_URL: publicOrigin,
    HERD_ASSOCIATED_DOMAIN: iosAssociatedDomain,
    HERD_ARTIFACT_RELEASE_ID: manifest.releaseId,
    HERD_ALLOW_SOFTWARE_QA_EVALUATOR: "false",
    HERD_ATTESTATION_AUDIENCE: claimPolicy.audience,
    HERD_ATTESTATION_IMAGE_DIGEST: imageDigest,
    HERD_ATTESTATION_MAX_AGE_SECONDS: String(claimPolicy.maxAgeSeconds),
    HERD_ATTESTATION_PROJECT_ID: claimPolicy.projectId,
    HERD_ATTESTATION_ROOT_CERTIFICATE_BASE64: root.derBase64,
    HERD_ATTESTATION_ROOT_FINGERPRINT: root.sha256,
    HERD_ATTESTATION_SERVICE_ACCOUNT: claimPolicy.serviceAccount,
    HERD_ATTESTATION_SWVERSIONS: claimPolicy.allowedSwversions.join(","),
    HERD_EVALUATOR_KEY_ID: keys.evaluatorEncryption.keyId,
    HERD_EVALUATOR_MEASUREMENT: imageDigest,
    HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: keys.policySigning.keyId,
    HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: keys.policySigning.publicKey,
    HERD_EVALUATOR_PUBLIC_KEY: keys.evaluatorEncryption.publicKey,
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: keys.resultSigning.keyId,
    HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: keys.resultSigning.publicKey,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: keys.receiptTransparencySigning.keyId,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      keys.receiptTransparencySigning.publicKey,
    HERD_RELEASE_CONFIGURATION_SHA256: configurationSha256,
    HERD_RELEASE_ID: manifest.evaluatorKeyEpochId,
    HERD_DEPLOYMENT_PROFILE: "production",
    MARKETING_VERSION: iosVersion,
    PRODUCT_BUNDLE_IDENTIFIER: iosBundleIdentifier,
  };
  const iosInfoValues = {
    CFBundleIdentifier: iosBundleIdentifier,
    CFBundleShortVersionString: iosVersion,
    CFBundleVersion: iosBuild,
    ...Object.fromEntries(
      Object.entries(iosBuildSettings).filter(
        ([name]) => name.startsWith("HERD_") && name !== "HERD_ASSOCIATED_DOMAIN",
      ),
    ),
  };
  const schedulerRuntimeVariables = {
    HERD_ARTIFACT_RELEASE_ID: manifest.releaseId,
    HERD_DEPLOYMENT_PROFILE: "production",
    HERD_EVALUATOR_KEY_ID: keys.evaluatorEncryption.keyId,
    HERD_EVALUATOR_URL: normalizedEvaluatorUrl,
    HERD_PUBLIC_APP_URL: publicOrigin,
    HERD_RELEASE_CONFIGURATION_SHA256: configurationSha256,
    HERD_RELEASE_ID: manifest.evaluatorKeyEpochId,
  };
  const files = {
    "release-config.json": canonicalJson({ configurationSha256, contract }),
    "scheduler-runtime-vars.json": canonicalJson(schedulerRuntimeVariables),
    "web-public.env": renderAssignments(webPublicEnvironment, dotenvValue),
    "web-runtime-vars.json": canonicalJson(webRuntimeVariables),
    [IOS_XCCONFIG_NAME]: renderAssignments(iosBuildSettings, xcconfigValue),
  };
  return {
    manifest,
    configurationSha256,
    contract,
    files,
    webPublicEnvironment,
    webRuntimeVariables,
    schedulerRuntimeVariables,
    iosBuildSettings,
    iosInfoValues,
  };
}

export function assertProductionConfigurationDigest(result, { prepare = false } = {}) {
  const expected = result.manifest.productionPolicy.configurationSha256;
  if (!prepare && result.configurationSha256 !== expected) {
    throw new TypeError(
      `Signed productionPolicy.configurationSha256 is ${expected}, but generated production configuration is ${result.configurationSha256}.`,
    );
  }
  return result.configurationSha256;
}
