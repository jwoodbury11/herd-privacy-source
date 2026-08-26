import {
  compareStrings,
  exactKeys,
  requireCanonicalTimestamp,
  requireInteger,
  requireSha256,
  requireString,
} from "./canonical.mjs";
import { normalizeArtifact } from "./release-manifest.mjs";

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const COMPONENTS = ["evaluator", "ordinary-api", "scheduler", "web"];
export const IOS_DEVELOPMENT_TEAM = "R4UPN8ZDV8";
export const APPLE_APP_SITE_ASSOCIATION_NAME = "apple-app-site-association";

export function iosApplicationIdentifier(bundleIdentifier) {
  return `${IOS_DEVELOPMENT_TEAM}.${requireString(bundleIdentifier, "iOS bundle identifier", {
    minimum: 3,
    maximum: 255,
    pattern: /^[A-Za-z0-9][A-Za-z0-9.-]+$/u,
  })}`;
}

export function verifyAppleAppSiteAssociation(bytes, appIdentifier) {
  if (!Buffer.isBuffer(bytes) || bytes.byteLength === 0 || bytes.byteLength > 64 * 1024) {
    throw new TypeError("Apple app-site association bytes are missing or oversized.");
  }
  let value;
  try {
    value = JSON.parse(bytes.toString("utf8"));
  } catch {
    throw new TypeError("Apple app-site association is not valid JSON.");
  }
  exactKeys(value, ["applinks", "appclips"], "Apple app-site association");
  exactKeys(value.applinks, ["apps", "details"], "Apple app-site association applinks");
  if (!Array.isArray(value.applinks.apps) || value.applinks.apps.length !== 0) {
    throw new TypeError("Apple app-site association applinks.apps must be empty.");
  }
  if (!Array.isArray(value.applinks.details) || value.applinks.details.length !== 1) {
    throw new TypeError("Apple app-site association must contain exactly one app detail.");
  }
  const detail = value.applinks.details[0];
  exactKeys(detail, ["appID", "paths"], "Apple app-site association detail");
  if (
    detail.appID !== appIdentifier ||
    !Array.isArray(detail.paths) ||
    detail.paths.length !== 1 ||
    detail.paths[0] !== "/invite/*"
  ) {
    throw new TypeError("Apple app-site association does not bind the exact production app and invitation path.");
  }
  exactKeys(value.appclips, ["apps"], "Apple app-site association appclips");
  if (
    !Array.isArray(value.appclips.apps) ||
    value.appclips.apps.length !== 1 ||
    value.appclips.apps[0] !== `${appIdentifier}.Clip`
  ) {
    throw new TypeError("Apple app-site association does not bind the exact production App Clip.");
  }
  return value;
}

function httpsUrl(value, label, { originOnly = false } = {}) {
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

function normalizeDeployment(value, index) {
  const label = `platformDeployments[${index}]`;
  exactKeys(value, ["component", "provider", "deploymentId", "artifactSha256"], label);
  if (!COMPONENTS.includes(value.component)) throw new TypeError(`${label}.component is unsupported.`);
  return {
    component: value.component,
    provider: requireString(value.provider, `${label}.provider`, { maximum: 120 }),
    deploymentId: requireString(value.deploymentId, `${label}.deploymentId`, { maximum: 300 }),
    artifactSha256: requireSha256(value.artifactSha256, `${label}.artifactSha256`),
  };
}

export function normalizeMonitoredResource(value, index) {
  const label = `monitoredResources[${index}]`;
  exactKeys(value, ["name", "url", "sha256", "size", "mediaType"], label);
  return {
    name: requireString(value.name, `${label}.name`, {
      maximum: 160,
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
    }),
    url: httpsUrl(value.url, `${label}.url`),
    sha256: requireSha256(value.sha256, `${label}.sha256`),
    size: requireInteger(value.size, `${label}.size`, { maximum: 64 * 1024 * 1024 }),
    mediaType: requireString(value.mediaType, `${label}.mediaType`, {
      minimum: 3,
      maximum: 160,
      pattern: /^[A-Za-z0-9!#$&^_.+\-/]+$/u,
    }),
  };
}

export function normalizeDeploymentStatement(value) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "releaseId",
      "environment",
      "deployedAt",
      "manifest",
      "manifestSignature",
      "endpoints",
      "platformDeployments",
      "monitoredResources",
    ],
    "deployment statement",
  );
  if (value.schemaVersion !== 1) throw new TypeError("Deployment statement schemaVersion is unsupported.");
  if (!['staging', 'production'].includes(value.environment)) {
    throw new TypeError("Deployment environment is unsupported.");
  }
  exactKeys(value.endpoints, ["webOrigin", "apiBaseUrl", "evaluatorUrl", "schedulerIdentity"], "endpoints");
  if (!Array.isArray(value.platformDeployments) || value.platformDeployments.length !== 4) {
    throw new TypeError("Deployment statement requires exactly four platform deployments.");
  }
  const platformDeployments = value.platformDeployments.map(normalizeDeployment).sort((left, right) =>
    compareStrings(left.component, right.component),
  );
  if (platformDeployments.some(({ component }, index) => component !== COMPONENTS[index])) {
    throw new TypeError("Deployment statement must identify web, ordinary API, evaluator, and scheduler exactly once.");
  }
  const webOrigin = httpsUrl(value.endpoints.webOrigin, "endpoints.webOrigin", { originOnly: true });
  if (!Array.isArray(value.monitoredResources) || value.monitoredResources.length < 3) {
    throw new TypeError("Deployment statement requires entry-document, asset-manifest, and Apple app-site association resources.");
  }
  const monitoredResources = value.monitoredResources.map(normalizeMonitoredResource).sort((left, right) =>
    compareStrings(left.name, right.name),
  );
  if (
    new Set(monitoredResources.map(({ name }) => name)).size !== monitoredResources.length ||
    new Set(monitoredResources.map(({ url }) => url)).size !== monitoredResources.length ||
    !monitoredResources.some(({ name }) => name === "entry-document") ||
    !monitoredResources.some(({ name }) => name === "asset-manifest") ||
    monitoredResources.filter(({ name }) => name === APPLE_APP_SITE_ASSOCIATION_NAME).length !== 1
  ) {
    throw new TypeError("Monitored resources must be unique and include entry-document, asset-manifest, and Apple app-site association.");
  }
  const appleAssociation = monitoredResources.find(
    ({ name }) => name === APPLE_APP_SITE_ASSOCIATION_NAME,
  );
  if (
    appleAssociation.url !== new URL("/.well-known/apple-app-site-association", webOrigin).toString() ||
    appleAssociation.mediaType.toLowerCase() !== "application/json"
  ) {
    throw new TypeError("Apple app-site association monitoring must use the exact production well-known JSON resource.");
  }
  const manifest = normalizeArtifact(value.manifest, "manifest");
  const manifestSignature = normalizeArtifact(value.manifestSignature, "manifestSignature");
  if (!manifest.url || !manifestSignature.url) {
    throw new TypeError("Deployment statement must publish manifest and signature HTTPS URLs.");
  }
  return {
    schemaVersion: 1,
    releaseId: requireString(value.releaseId, "releaseId", { maximum: 120, pattern: RELEASE_ID }),
    environment: value.environment,
    deployedAt: requireCanonicalTimestamp(value.deployedAt, "deployedAt"),
    manifest,
    manifestSignature,
    endpoints: {
      webOrigin,
      apiBaseUrl: httpsUrl(value.endpoints.apiBaseUrl, "endpoints.apiBaseUrl"),
      evaluatorUrl: httpsUrl(value.endpoints.evaluatorUrl, "endpoints.evaluatorUrl"),
      schedulerIdentity: requireString(value.endpoints.schedulerIdentity, "endpoints.schedulerIdentity", {
        maximum: 300,
      }),
    },
    platformDeployments,
    monitoredResources,
  };
}
