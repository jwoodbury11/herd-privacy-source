// Copyright 2026 Herd contributors. Licensed under Apache-2.0.
import { verifyLiveEvaluatorAttestation } from "./attestation.mjs";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const IOS_DEVELOPMENT_TEAM = "R4UPN8ZDV8";
const APPLE_APP_SITE_ASSOCIATION_NAME = "apple-app-site-association";

const RELEASE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const KEY_ID = RELEASE_ID;
const GCP_PROJECT_ID = /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/u;
const SERVICE_ACCOUNT = /^[a-z][a-z0-9-]{4,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$/u;
const MANIFEST_TYPE = "application/vnd.herd.release-manifest.v1+json";
const DEPLOYMENT_TYPE = "application/vnd.herd.deployment-statement.v1+json";
const RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const RESPONSE_LOG_ID = "herd-response-log-v1";
const CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
const GOOGLE_ISSUER = "https://confidentialcomputing.googleapis.com";
const MAX_WELL_KNOWN_BYTES = 256 * 1024;
const MAX_EVIDENCE_BYTES = 4 * 1024 * 1024;
const MAX_RESOURCE_BYTES = 64 * 1024 * 1024;
const MAX_RESPONSE_LOG_PAGE_BYTES = 1024 * 1024;
const MAX_RELEASE_ARTIFACT_BYTES = 2_147_483_647;
const MAX_EVIDENCE_ARTIFACT_BYTES = 64 * 1024 * 1024;
const RESPONSE_LOG_PAGE_SIZE = 500;
const MAX_RESPONSE_LOG_PAGES = 100;
const GENESIS_RESPONSE_ENTRY_HASH = base64Url(new Uint8Array(32));

function isObject(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function exactKeys(value, keys, label) {
  if (!isObject(value)) throw new TypeError(`${label} must be an object.`);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new TypeError(`${label} contains unsupported or missing fields.`);
  }
}

function string(value, label, { pattern, minimum = 1, maximum = 4096 } = {}) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    (pattern && !pattern.test(value))
  ) {
    throw new TypeError(`${label} is invalid.`);
  }
  return value;
}

function integer(value, label, { minimum = 0, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${label} is outside its allowed range.`);
  }
  return value;
}

function sha256String(value, label) {
  return string(value, label, { minimum: 64, maximum: 64, pattern: SHA256 });
}

function timestamp(value, label) {
  string(value, label, { maximum: 40 });
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    throw new TypeError(`${label} must be a canonical UTC timestamp.`);
  }
  return value;
}

function normalizePreviousRelease(value, label, currentReleaseId) {
  if (value === null) return null;
  exactKeys(value, ["releaseId", "manifestSha256"], label);
  const releaseId = string(value.releaseId, `${label}.releaseId`, {
    maximum: 120,
    pattern: RELEASE_ID,
  });
  if (releaseId === currentReleaseId) {
    throw new TypeError(`${label}.releaseId must differ from the current release ID.`);
  }
  return {
    releaseId,
    manifestSha256: sha256String(
      value.manifestSha256,
      `${label}.manifestSha256`,
    ),
  };
}

function safeHttpsUrl(value, label, { originOnly = false } = {}) {
  string(value, label, { maximum: 2048 });
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

export function canonicalStringify(value) {
  return serialize(value, new Set());
}

function serialize(value, seen) {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Canonical JSON cannot contain a non-finite number.");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (!isObject(value) && !Array.isArray(value)) {
    throw new TypeError("Canonical JSON contains an unsupported value.");
  }
  if (seen.has(value)) throw new TypeError("Canonical JSON cannot contain a cycle.");
  seen.add(value);
  try {
    if (Array.isArray(value)) return `[${value.map((item) => serialize(item, seen)).join(",")}]`;
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${serialize(value[key], seen)}`)
      .join(",")}}`;
  } finally {
    seen.delete(value);
  }
}

export function canonicalJson(value) {
  return `${canonicalStringify(value)}\n`;
}

function bytesToHex(bytes) {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export async function sha256Hex(bytes) {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

async function sha256Base64Url(bytes) {
  return base64Url(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

function base64UrlBytes(value, expectedLength, label) {
  string(value, label, { pattern: /^[A-Za-z0-9_-]+$/u });
  if (value.includes("=")) throw new TypeError(`${label} is not unpadded base64url.`);
  let binary;
  try {
    const base64 = value.replaceAll("-", "+").replaceAll("_", "/");
    binary = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  } catch {
    throw new TypeError(`${label} is not base64url.`);
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength !== expectedLength || base64Url(bytes) !== value) {
    throw new TypeError(`${label} is not canonical base64url.`);
  }
  return bytes;
}

function base64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function canonicalBase64(value, label, maximumBytes = 32 * 1024) {
  string(value, label, { maximum: Math.ceil((maximumBytes * 4) / 3) + 4 });
  if (
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    throw new TypeError(`${label} is not canonical base64.`);
  }
  let binary;
  try {
    binary = atob(value);
  } catch {
    throw new TypeError(`${label} is not canonical base64.`);
  }
  if (binary.length < 1 || binary.length > maximumBytes || btoa(binary) !== value) {
    throw new TypeError(`${label} is not canonical base64.`);
  }
  return value;
}

function parseCanonicalJson(bytes, label) {
  let text;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw new TypeError(`${label} is not valid UTF-8.`);
  }
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError(`${label} is not valid JSON.`);
  }
  if (text !== canonicalJson(parsed)) throw new TypeError(`${label} is not canonical JSON.`);
  return parsed;
}

function sameJson(left, right) {
  return canonicalStringify(left) === canonicalStringify(right);
}

function compareStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizeDigest(value, label, { sha256Only = false } = {}) {
  exactKeys(value, ["algorithm", "value"], label);
  if (!['sha256', 'sha384'].includes(value.algorithm) || (sha256Only && value.algorithm !== "sha256")) {
    throw new TypeError(`${label}.algorithm is unsupported.`);
  }
  const length = value.algorithm === "sha256" ? 64 : 96;
  return {
    algorithm: value.algorithm,
    value: string(value.value, `${label}.value`, {
      minimum: length,
      maximum: length,
      pattern: /^[0-9a-f]+$/u,
    }),
  };
}

async function normalizeKey(value, label, algorithm) {
  exactKeys(value, ["keyId", "algorithm", "publicKeyFormat", "publicKey", "publicKeySha256"], label);
  if (value.algorithm !== algorithm || value.publicKeyFormat !== "P256_X963_BASE64URL") {
    throw new TypeError(`${label} uses an unsupported key format.`);
  }
  const raw = base64UrlBytes(value.publicKey, 65, `${label}.publicKey`);
  if (raw[0] !== 0x04) throw new TypeError(`${label}.publicKey is not an uncompressed P-256 point.`);
  const fingerprint = await sha256Hex(raw);
  if (fingerprint !== value.publicKeySha256) throw new TypeError(`${label}.publicKeySha256 is incorrect.`);
  return {
    keyId: string(value.keyId, `${label}.keyId`, { maximum: 120, pattern: KEY_ID }),
    algorithm,
    publicKeyFormat: "P256_X963_BASE64URL",
    publicKey: value.publicKey,
    publicKeySha256: sha256String(value.publicKeySha256, `${label}.publicKeySha256`),
  };
}

function normalizeReference(value, label, { signature = false } = {}) {
  exactKeys(value, signature ? ["url", "sha256", "size", "signature"] : ["url", "sha256", "size"], label);
  return {
    url: safeHttpsUrl(value.url, `${label}.url`),
    sha256: sha256String(value.sha256, `${label}.sha256`),
    size: integer(value.size, `${label}.size`, { maximum: MAX_EVIDENCE_BYTES }),
    ...(signature ? { signature: normalizeReference(value.signature, `${label}.signature`) } : {}),
  };
}

function normalizeResource(value, label) {
  exactKeys(value, ["name", "url", "sha256", "size", "mediaType"], label);
  return {
    name: string(value.name, `${label}.name`, {
      maximum: 160,
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
    }),
    url: safeHttpsUrl(value.url, `${label}.url`),
    sha256: sha256String(value.sha256, `${label}.sha256`),
    size: integer(value.size, `${label}.size`, { maximum: MAX_RESOURCE_BYTES }),
    mediaType: string(value.mediaType, `${label}.mediaType`, {
      maximum: 160,
      pattern: /^[A-Za-z0-9!#$&^_.+\-/]+$/u,
    }),
  };
}

function assertAppleAppSiteAssociation(bytes, bundleIdentifier) {
  const value = jsonEvidence(bytes, "Apple app-site association");
  exactKeys(value, ["applinks"], "Apple app-site association");
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
    detail.appID !== `${IOS_DEVELOPMENT_TEAM}.${bundleIdentifier}` ||
    !Array.isArray(detail.paths) ||
    detail.paths.length !== 1 ||
    detail.paths[0] !== "/invite/*"
  ) {
    throw new TypeError("Apple app-site association does not bind the exact production app and invitation path.");
  }
}

function normalizeArtifact(value, label, { maximum = MAX_RELEASE_ARTIFACT_BYTES } = {}) {
  exactKeys(value, ["name", "mediaType", "sha256", "size", "url"], label);
  return {
    name: string(value.name, `${label}.name`, {
      maximum: 160,
      pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
    }),
    mediaType: string(value.mediaType, `${label}.mediaType`, {
      minimum: 3,
      maximum: 160,
      pattern: /^[A-Za-z0-9!#$&^_.+\-/]+$/u,
    }).toLowerCase(),
    sha256: sha256String(value.sha256, `${label}.sha256`),
    size: integer(value.size, `${label}.size`, { maximum }),
    url: safeHttpsUrl(value.url, `${label}.url`),
  };
}

function uniqueArtifacts(values, label) {
  if (new Set(values.map(({ name }) => name)).size !== values.length) {
    throw new TypeError(`${label} contains duplicate artifact names.`);
  }
  return values;
}

function normalizeProvenance(value, index) {
  const label = `release manifest evidence.provenance[${index}]`;
  exactKeys(value, ["subjects", "predicateType", "issuer", "workflowIdentity", "statement", "bundle"], label);
  if (!Array.isArray(value.subjects) || value.subjects.length === 0) {
    throw new TypeError(`${label}.subjects must not be empty.`);
  }
  const subjects = value.subjects.map((subject, subjectIndex) => {
    exactKeys(subject, ["name", "sha256"], `${label}.subjects[${subjectIndex}]`);
    return {
      name: string(subject.name, `${label}.subjects[${subjectIndex}].name`, {
        maximum: 160,
        pattern: /^[A-Za-z0-9][A-Za-z0-9._-]*$/u,
      }),
      sha256: sha256String(subject.sha256, `${label}.subjects[${subjectIndex}].sha256`),
    };
  });
  subjects.sort((left, right) => compareStrings(left.name, right.name));
  if (new Set(subjects.map(({ name }) => name)).size !== subjects.length) {
    throw new TypeError(`${label}.subjects contains duplicate names.`);
  }
  const statement = normalizeArtifact(value.statement, `${label}.statement`, {
    maximum: MAX_EVIDENCE_ARTIFACT_BYTES,
  });
  const bundle = normalizeArtifact(value.bundle, `${label}.bundle`, {
    maximum: MAX_EVIDENCE_ARTIFACT_BYTES,
  });
  if (
    value.predicateType !== "https://slsa.dev/provenance/v1" ||
    value.issuer !== "https://token.actions.githubusercontent.com/"
  ) {
    throw new TypeError(`${label} does not use the required SLSA predicate and GitHub OIDC issuer.`);
  }
  if (!bundle.mediaType.includes("sigstore") || !bundle.mediaType.endsWith("+json")) {
    throw new TypeError(`${label}.bundle is not declared as a Sigstore JSON bundle.`);
  }
  if (statement.mediaType !== "application/vnd.in-toto+json") {
    throw new TypeError(`${label}.statement is not declared as an in-toto statement.`);
  }
  return {
    subjects,
    predicateType: value.predicateType,
    issuer: value.issuer,
    workflowIdentity: string(value.workflowIdentity, `${label}.workflowIdentity`, { maximum: 500 }),
    statement,
    bundle,
  };
}

function normalizeTransparency(value, index) {
  const label = `release manifest evidence.transparency[${index}]`;
  exactKeys(value, ["provider", "logId", "entryId", "integratedTime", "bundleSha256", "url"], label);
  if (value.provider !== "sigstore-rekor") {
    throw new TypeError(`${label}.provider is not Sigstore Rekor.`);
  }
  const logId = string(value.logId, `${label}.logId`, { maximum: 256 });
  const entryId = string(value.entryId, `${label}.entryId`, { maximum: 512 });
  const separator = entryId.lastIndexOf(":");
  if (separator <= 0 || entryId.slice(0, separator) !== logId || !/^(?:0|[1-9][0-9]*)$/u.test(entryId.slice(separator + 1))) {
    throw new TypeError(`${label}.entryId does not bind its log ID and numeric index.`);
  }
  const logIndex = Number(entryId.slice(separator + 1));
  if (!Number.isSafeInteger(logIndex)) throw new TypeError(`${label}.entryId index is too large.`);
  const url = new URL(safeHttpsUrl(value.url, `${label}.url`));
  const query = [...url.searchParams.entries()];
  if (
    url.origin !== "https://rekor.sigstore.dev" ||
    url.pathname !== "/api/v1/log/entries" ||
    query.length !== 1 ||
    query[0][0] !== "logIndex" ||
    query[0][1] !== String(logIndex)
  ) {
    throw new TypeError(`${label}.url does not identify its exact public Rekor log index.`);
  }
  return {
    provider: "sigstore-rekor",
    logId,
    entryId,
    logIndex,
    integratedTime: integer(value.integratedTime, `${label}.integratedTime`, { minimum: 1 }),
    bundleSha256: sha256String(value.bundleSha256, `${label}.bundleSha256`),
    url: url.toString(),
  };
}

async function normalizeTarget(value) {
  const hasResponseTransparency = isObject(value) && Object.hasOwn(value, "responseTransparency");
  const hasEvaluatorAttestation = isObject(value) && Object.hasOwn(value, "evaluatorAttestation");
  exactKeys(
    value,
    [
      "name",
      "wellKnownUrl",
      "expectedWebOrigin",
      "allowedEvidenceOrigins",
      "requireProduction",
      "releaseSigningKey",
      ...(hasResponseTransparency ? ["responseTransparency"] : []),
      ...(hasEvaluatorAttestation ? ["evaluatorAttestation"] : []),
    ],
    "monitor target",
  );
  const wellKnownUrl = safeHttpsUrl(value.wellKnownUrl, "monitor target wellKnownUrl");
  const expectedWebOrigin = safeHttpsUrl(value.expectedWebOrigin, "monitor target expectedWebOrigin", {
    originOnly: true,
  });
  if (!Array.isArray(value.allowedEvidenceOrigins) || value.allowedEvidenceOrigins.length === 0) {
    throw new TypeError("monitor target allowedEvidenceOrigins must not be empty.");
  }
  const allowedEvidenceOrigins = value.allowedEvidenceOrigins.map((origin, index) =>
    safeHttpsUrl(origin, `monitor target allowedEvidenceOrigins[${index}]`, { originOnly: true }),
  );
  if (new Set(allowedEvidenceOrigins).size !== allowedEvidenceOrigins.length) {
    throw new TypeError("monitor target allowedEvidenceOrigins contains duplicates.");
  }
  if (typeof value.requireProduction !== "boolean") {
    throw new TypeError("monitor target requireProduction must be boolean.");
  }
  let responseTransparency = null;
  if (hasResponseTransparency) {
    exactKeys(
      value.responseTransparency,
      ["url", "logId", "signingKey"],
      "monitor target responseTransparency",
    );
    const url = safeHttpsUrl(value.responseTransparency.url, "monitor target responseTransparency.url");
    if (new URL(url).search) {
      throw new TypeError("monitor target responseTransparency.url must not contain a query.");
    }
    responseTransparency = {
      url,
      logId: string(value.responseTransparency.logId, "monitor target responseTransparency.logId", {
        maximum: 120,
        pattern: RELEASE_ID,
      }),
      signingKey: await normalizeKey(
        value.responseTransparency.signingKey,
        "monitor target responseTransparency.signingKey",
        "ECDSA_P256_SHA256",
      ),
    };
  }
  if (value.requireProduction && responseTransparency === null) {
    throw new TypeError("production monitor target requires an independently pinned responseTransparency witness.");
  }
  let evaluatorAttestation = null;
  if (hasEvaluatorAttestation) {
    exactKeys(
      value.evaluatorAttestation,
      ["origin", "rootCertificateDerBase64"],
      "monitor target evaluatorAttestation",
    );
    evaluatorAttestation = {
      origin: safeHttpsUrl(
        value.evaluatorAttestation.origin,
        "monitor target evaluatorAttestation.origin",
        { originOnly: true },
      ),
      rootCertificateDerBase64: canonicalBase64(
        value.evaluatorAttestation.rootCertificateDerBase64,
        "monitor target evaluatorAttestation.rootCertificateDerBase64",
      ),
    };
  }
  if (value.requireProduction && evaluatorAttestation === null) {
    throw new TypeError("production monitor target requires an independently pinned evaluatorAttestation root and origin.");
  }
  return {
    name: string(value.name, "monitor target name", { maximum: 120, pattern: RELEASE_ID }),
    wellKnownUrl,
    expectedWebOrigin,
    allowedEvidenceOrigins: [...allowedEvidenceOrigins].sort(),
    requireProduction: value.requireProduction,
    releaseSigningKey: await normalizeKey(
      value.releaseSigningKey,
      "monitor target releaseSigningKey",
      "ECDSA_P256_SHA256",
    ),
    responseTransparency,
    evaluatorAttestation,
  };
}

async function fetchBounded(fetchImpl, url, maximumBytes, label) {
  const response = await fetchImpl(url, {
    method: "GET",
    redirect: "manual",
    cache: "no-store",
    headers: { accept: "application/json, application/*+json, */*;q=0.1" },
  });
  if (response.status >= 300 && response.status < 400) throw new TypeError(`${label} redirected.`);
  if (response.status !== 200) throw new TypeError(`${label} returned HTTP ${response.status}.`);
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) > maximumBytes) {
      throw new TypeError(`${label} declared an invalid or excessive content length.`);
    }
  }
  const chunks = [];
  let length = 0;
  if (response.body?.getReader) {
    const reader = response.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > maximumBytes) {
        await reader.cancel();
        throw new TypeError(`${label} exceeded its byte limit.`);
      }
      chunks.push(value);
    }
  } else {
    const value = new Uint8Array(await response.arrayBuffer());
    length = value.byteLength;
    if (length > maximumBytes) throw new TypeError(`${label} exceeded its byte limit.`);
    chunks.push(value);
  }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { bytes, contentType: response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ?? "" };
}

async function fetchReference(fetchImpl, reference, label, allowedOrigins) {
  if (!allowedOrigins.includes(new URL(reference.url).origin)) {
    throw new TypeError(`${label} uses an unapproved evidence origin.`);
  }
  const result = await fetchBounded(fetchImpl, reference.url, Math.min(reference.size + 1, MAX_EVIDENCE_BYTES), label);
  if (result.bytes.byteLength !== reference.size || (await sha256Hex(result.bytes)) !== reference.sha256) {
    throw new TypeError(`${label} does not match its pinned size and SHA-256 digest.`);
  }
  return result;
}

async function fetchArtifact(fetchImpl, artifact, label, allowedOrigins, { retainBytes = false } = {}) {
  if (!allowedOrigins.includes(new URL(artifact.url).origin)) {
    throw new TypeError(`${label} uses an unapproved evidence origin.`);
  }
  const response = await fetchImpl(artifact.url, {
    method: "GET",
    redirect: "manual",
    cache: "no-store",
    headers: { accept: artifact.mediaType },
  });
  if (response.status >= 300 && response.status < 400) throw new TypeError(`${label} redirected.`);
  if (response.status !== 200) throw new TypeError(`${label} returned HTTP ${response.status}.`);
  const contentType = response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ?? "";
  if (contentType !== artifact.mediaType) {
    throw new TypeError(`${label} has media type ${contentType || "<missing>"}, not ${artifact.mediaType}.`);
  }
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null && (!/^(?:0|[1-9][0-9]*)$/u.test(declaredLength) || Number(declaredLength) !== artifact.size)) {
    throw new TypeError(`${label} does not match its pinned size.`);
  }
  if (retainBytes || typeof crypto.DigestStream !== "function") {
    if (artifact.size > MAX_EVIDENCE_ARTIFACT_BYTES && typeof crypto.DigestStream !== "function") {
      throw new TypeError(`${label} requires streaming SHA-256 support on this runtime.`);
    }
    const chunks = [];
    let size = 0;
    const reader = response.body?.getReader();
    if (reader) {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > artifact.size) {
          await reader.cancel();
          throw new TypeError(`${label} exceeds its pinned size.`);
        }
        chunks.push(value);
      }
    } else {
      const value = new Uint8Array(await response.arrayBuffer());
      size = value.byteLength;
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    if (size !== artifact.size || (await sha256Hex(bytes)) !== artifact.sha256) {
      throw new TypeError(`${label} does not match its pinned size and SHA-256 digest.`);
    }
    return { bytes };
  }
  if (!response.body) throw new TypeError(`${label} has no response body.`);
  let size = 0;
  const digest = new crypto.DigestStream("SHA-256");
  const counter = new TransformStream({
    transform(chunk, controller) {
      size += chunk.byteLength;
      if (size > artifact.size) throw new TypeError(`${label} exceeds its pinned size.`);
      controller.enqueue(chunk);
    },
  });
  await response.body.pipeThrough(counter).pipeTo(digest);
  const digestHex = bytesToHex(new Uint8Array(await digest.digest));
  if (size !== artifact.size || digestHex !== artifact.sha256) {
    throw new TypeError(`${label} does not match its pinned size and SHA-256 digest.`);
  }
  return { bytes: null };
}

function jsonEvidence(bytes, label) {
  let value;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new TypeError(`${label} is not valid UTF-8 JSON.`);
  }
  if (!isObject(value)) throw new TypeError(`${label} JSON root is not an object.`);
  return value;
}

function assertSourceExportManifest(bytes, manifest) {
  const value = jsonEvidence(bytes, "public-source export manifest");
  exactKeys(value, ["schemaVersion", "archiveFormat", "archivePrefix", "createdAt", "sourceDateEpoch", "sourceRevision", "license", "policy", "files"], "public-source export manifest");
  if (
    value.schemaVersion !== 1 ||
    value.archiveFormat !== "ustar" ||
    value.license !== "Apache-2.0" ||
    value.sourceRevision !== manifest.source.revision ||
    value.sourceDateEpoch !== manifest.sourceDateEpoch ||
    value.createdAt !== manifest.createdAt ||
    !Array.isArray(value.files) ||
    value.files.length === 0
  ) {
    throw new TypeError("public-source export manifest does not identify this release source.");
  }
  exactKeys(value.policy, ["path", "sha256"], "public-source export manifest policy");
  sha256String(value.policy.sha256, "public-source export manifest policy SHA-256");
  let previousPath = "";
  for (const [index, file] of value.files.entries()) {
    exactKeys(file, ["path", "mode", "size", "sha256"], `public-source export manifest files[${index}]`);
    const filePath = string(file.path, `public-source export manifest files[${index}].path`, { maximum: 500 });
    if (filePath <= previousPath || filePath.startsWith("/") || filePath.split("/").some((part) => !part || part === "." || part === "..")) {
      throw new TypeError("public-source export manifest paths are not strictly sorted safe paths.");
    }
    previousPath = filePath;
    if (!['0644', '0755'].includes(file.mode)) throw new TypeError("public-source export manifest contains an unsafe mode.");
    integer(file.size, `public-source export manifest files[${index}].size`, { maximum: 64 * 1024 * 1024 });
    sha256String(file.sha256, `public-source export manifest files[${index}].sha256`);
  }
}

function assertSpdx(bytes, label) {
  const value = jsonEvidence(bytes, label);
  if (
    value.spdxVersion !== "SPDX-2.3" ||
    value.dataLicense !== "CC0-1.0" ||
    value.SPDXID !== "SPDXRef-DOCUMENT" ||
    typeof value.name !== "string" ||
    typeof value.documentNamespace !== "string" ||
    !Array.isArray(value.packages) ||
    value.packages.length === 0
  ) {
    throw new TypeError(`${label} is not an identified SPDX 2.3 document.`);
  }
  safeHttpsUrl(value.documentNamespace, `${label}.documentNamespace`);
  if (!value.packages.some((pkg) => isObject(pkg) && typeof pkg.SPDXID === "string" && typeof pkg.name === "string")) {
    throw new TypeError(`${label} has no identified package.`);
  }
}

function integerLike(value, label) {
  const normalized = typeof value === "string" && /^(?:0|[1-9][0-9]*)$/u.test(value) ? Number(value) : value;
  return integer(normalized, label);
}

function assertInTotoStatement(bytes, provenance, manifest) {
  const statement = jsonEvidence(bytes, `provenance statement ${provenance.statement.name}`);
  if (
    statement._type !== "https://in-toto.io/Statement/v1" ||
    statement.predicateType !== provenance.predicateType ||
    !Array.isArray(statement.subject) ||
    !isObject(statement.predicate)
  ) {
    throw new TypeError("provenance statement is not a SLSA in-toto v1 statement.");
  }
  const subjects = statement.subject.map((subject, index) => {
    if (!isObject(subject) || !isObject(subject.digest)) throw new TypeError(`provenance statement subject ${index} is malformed.`);
    exactKeys(subject, ["name", "digest"], `provenance statement subject ${index}`);
    exactKeys(subject.digest, ["sha256"], `provenance statement subject ${index}.digest`);
    return {
      name: string(subject.name, `provenance statement subject ${index}.name`, { maximum: 160 }),
      sha256: sha256String(subject.digest.sha256, `provenance statement subject ${index}.sha256`),
    };
  }).sort((left, right) => compareStrings(left.name, right.name));
  if (!sameJson(subjects, provenance.subjects)) {
    throw new TypeError("provenance statement subjects differ from the signed release manifest.");
  }
  const parameters = statement.predicate?.buildDefinition?.externalParameters;
  if (
    parameters?.releaseId !== manifest.releaseId ||
    parameters?.source?.repository !== manifest.source.repository ||
    parameters?.source?.revision !== manifest.source.revision
  ) {
    throw new TypeError("provenance statement build parameters are unrelated to this release.");
  }
}

function assertSigstoreBundle(bytes, provenance, transparency) {
  const bundle = jsonEvidence(bytes, `Sigstore bundle ${provenance.bundle.name}`);
  if (bundle.mediaType !== provenance.bundle.mediaType) {
    throw new TypeError("Sigstore bundle mediaType does not match its descriptor.");
  }
  const tlogEntries = bundle.verificationMaterial?.tlogEntries;
  const certificate = bundle.verificationMaterial?.certificate;
  const messageSignature = bundle.messageSignature;
  if (
    !Array.isArray(tlogEntries) ||
    tlogEntries.length !== 1 ||
    typeof certificate?.rawBytes !== "string" ||
    certificate.rawBytes.length < 64 ||
    typeof messageSignature?.signature !== "string" ||
    typeof messageSignature?.messageDigest?.digest !== "string"
  ) {
    throw new TypeError("Sigstore bundle lacks one tlog entry, signing certificate, or message signature.");
  }
  const algorithm = messageSignature.messageDigest.algorithm;
  if (algorithm !== "SHA2_256" && algorithm !== "sha256") {
    throw new TypeError("Sigstore bundle message digest algorithm is not SHA-256.");
  }
  let subjectDigest;
  try {
    subjectDigest = bytesToHex(Uint8Array.from(atob(messageSignature.messageDigest.digest), (character) => character.charCodeAt(0)));
  } catch {
    throw new TypeError("Sigstore bundle message digest is not base64.");
  }
  if (subjectDigest !== provenance.statement.sha256) {
    throw new TypeError("Sigstore bundle message digest does not bind its provenance statement.");
  }
  const entry = tlogEntries[0];
  const logId = entry?.logId?.keyId ?? entry?.logId;
  const logIndex = integerLike(entry?.logIndex, "Sigstore tlog logIndex");
  const integratedTime = integerLike(entry?.integratedTime, "Sigstore tlog integratedTime");
  if (
    logId !== transparency.logId ||
    logIndex !== transparency.logIndex ||
    integratedTime !== transparency.integratedTime ||
    (!entry.inclusionPromise?.signedEntryTimestamp && !entry.inclusionProof) ||
    typeof entry.canonicalizedBody !== "string"
  ) {
    throw new TypeError("Sigstore tlog entry does not bind the inline Rekor record or inclusion material.");
  }
  let body;
  try {
    body = atob(entry.canonicalizedBody);
  } catch {
    throw new TypeError("Sigstore tlog canonicalizedBody is not base64.");
  }
  if (!body.includes(provenance.statement.sha256)) {
    throw new TypeError("Sigstore tlog body does not bind the provenance statement digest.");
  }
}

function assertPdf(bytes, label) {
  const text = new TextDecoder("latin1").decode(bytes);
  if (!text.startsWith("%PDF-") || !text.trimEnd().endsWith("%%EOF")) {
    throw new TypeError(`${label} is not a complete PDF document.`);
  }
}

function matchingRekorLogId(candidate, expected) {
  if (candidate === expected) return true;
  if (typeof candidate !== "string" || !/^[0-9a-f]{64}$/u.test(candidate)) return false;
  try {
    const binary = atob(expected);
    return binary.length === 32 && bytesToHex(
      Uint8Array.from(binary, (character) => character.charCodeAt(0)),
    ) === candidate;
  } catch {
    return false;
  }
}

function matchingRekorRecord(value, transparency) {
  if (Array.isArray(value)) return value.some((item) => matchingRekorRecord(item, transparency));
  if (!isObject(value)) return false;
  const rawLogId = value.logID ?? value.logId;
  const candidateLogId = isObject(rawLogId) ? rawLogId.keyId : rawLogId;
  if (
    matchingRekorLogId(candidateLogId, transparency.logId) &&
    integerLike(value.logIndex, "Rekor response logIndex") === transparency.logIndex &&
    integerLike(value.integratedTime, "Rekor response integratedTime") === transparency.integratedTime
  ) return true;
  return Object.values(value).some((item) => isObject(item) || Array.isArray(item) ? matchingRekorRecord(item, transparency) : false);
}

async function verifyPublishedReleaseEvidence(fetchImpl, manifest, target) {
  const results = [];
  for (const artifact of [
    manifest.source.exportArchive,
    manifest.artifacts.web.deploymentArchive,
    manifest.artifacts.ios.submissionArchive,
    manifest.artifacts.ordinaryApi,
    manifest.artifacts.evaluator,
    manifest.artifacts.scheduler,
  ]) {
    await fetchArtifact(fetchImpl, artifact, `release artifact ${artifact.name}`, target.allowedEvidenceOrigins);
    results.push({ name: artifact.name, sha256: artifact.sha256, size: artifact.size });
  }
  const exportManifestFetch = await fetchArtifact(fetchImpl, manifest.source.exportManifest, "public-source export manifest", target.allowedEvidenceOrigins, { retainBytes: true });
  assertSourceExportManifest(exportManifestFetch.bytes, manifest);
  results.push({ name: manifest.source.exportManifest.name, sha256: manifest.source.exportManifest.sha256, size: manifest.source.exportManifest.size });
  for (const artifact of manifest.evidence.sboms) {
    if (!['application/spdx+json', 'application/json'].includes(artifact.mediaType)) {
      throw new TypeError(`SBOM ${artifact.name} is not declared as SPDX JSON.`);
    }
    const fetched = await fetchArtifact(fetchImpl, artifact, `SBOM ${artifact.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    assertSpdx(fetched.bytes, `SBOM ${artifact.name}`);
    results.push({ name: artifact.name, sha256: artifact.sha256, size: artifact.size });
  }
  for (const provenance of manifest.evidence.provenance) {
    const transparency = manifest.evidence.transparency.find(({ bundleSha256 }) => bundleSha256 === provenance.bundle.sha256);
    const statementFetch = await fetchArtifact(fetchImpl, provenance.statement, `provenance statement ${provenance.statement.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    assertInTotoStatement(statementFetch.bytes, provenance, manifest);
    results.push({ name: provenance.statement.name, sha256: provenance.statement.sha256, size: provenance.statement.size });
    const fetched = await fetchArtifact(fetchImpl, provenance.bundle, `Sigstore bundle ${provenance.bundle.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    assertSigstoreBundle(fetched.bytes, provenance, transparency);
    results.push({ name: provenance.bundle.name, sha256: provenance.bundle.sha256, size: provenance.bundle.size });
  }
  for (const artifact of manifest.evidence.deployments) {
    if (!artifact.mediaType.endsWith("+json") && artifact.mediaType !== "application/json") {
      throw new TypeError(`deployment evidence ${artifact.name} is not declared as JSON.`);
    }
    const fetched = await fetchArtifact(fetchImpl, artifact, `deployment evidence ${artifact.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    const deployment = jsonEvidence(fetched.bytes, `deployment evidence ${artifact.name}`);
    if (deployment.releaseId !== manifest.releaseId) throw new TypeError(`deployment evidence ${artifact.name} is unrelated to this release.`);
    results.push({ name: artifact.name, sha256: artifact.sha256, size: artifact.size });
  }
  for (const artifact of manifest.evidence.transitions) {
    if (!artifact.mediaType.endsWith("+json")) {
      throw new TypeError(`transition evidence ${artifact.name} is not declared as JSON.`);
    }
    const fetched = await fetchArtifact(fetchImpl, artifact, `transition evidence ${artifact.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    const transition = jsonEvidence(fetched.bytes, `transition evidence ${artifact.name}`);
    const expectedSchemaVersion = artifact.name === "evaluator-epoch-transition.json" ? 2 : 1;
    if (transition.schemaVersion !== expectedSchemaVersion) {
      throw new TypeError(`transition evidence ${artifact.name} has an unsupported schema.`);
    }
    results.push({ name: artifact.name, sha256: artifact.sha256, size: artifact.size });
  }
  for (const artifact of manifest.evidence.audits) {
    if (artifact.mediaType !== "application/pdf") throw new TypeError(`audit ${artifact.name} is not declared as PDF.`);
    const fetched = await fetchArtifact(fetchImpl, artifact, `audit ${artifact.name}`, target.allowedEvidenceOrigins, { retainBytes: true });
    assertPdf(fetched.bytes, `audit ${artifact.name}`);
    results.push({ name: artifact.name, sha256: artifact.sha256, size: artifact.size });
  }
  for (const transparency of manifest.evidence.transparency) {
    if (!target.allowedEvidenceOrigins.includes(new URL(transparency.url).origin)) {
      throw new TypeError("Rekor record uses an unapproved evidence origin.");
    }
    const fetched = await fetchBounded(fetchImpl, transparency.url, MAX_EVIDENCE_BYTES, "Rekor record");
    if (fetched.contentType !== "application/json") throw new TypeError("Rekor record is not JSON.");
    const record = jsonEvidence(fetched.bytes, "Rekor record");
    if (!matchingRekorRecord(record, transparency)) throw new TypeError("Rekor response is unrelated to the pinned transparency entry.");
  }
  results.sort((left, right) => compareStrings(left.name, right.name));
  return results;
}

async function normalizeWellKnown(value) {
  exactKeys(
    value,
    ["schemaVersion", "releaseId", "previousRelease", "protocol", "releaseSigningKey", "manifest", "deploymentStatement", "web", "evaluator", "responseTransparency", "monitoredResources", "verifier"],
    "well-known release record",
  );
  if (value.schemaVersion !== 1) throw new TypeError("well-known release schema is unsupported.");
  exactKeys(value.protocol, ["version", "cipherSuite", "paddedPlaintextBytes", "payloadFrameBytes", "userWrapBytes", "evaluatorWrapBytes"], "well-known protocol");
  exactKeys(value.web, ["publicOrigin", "entryDocumentSha256", "assetManifestSha256"], "well-known web");
  exactKeys(value.evaluator, ["evaluatorKeyEpochId", "encryptionKeyId", "resultSigningKeyId", "policySigningKeyId", "receiptTransparencySigningKeyId", "workloadImageDigest", "measurements", "attestationProvider", "attestationClaimPolicy", "attestationRootFingerprint"], "well-known evaluator");
  exactKeys(value.responseTransparency, ["protocolVersion", "logId", "url", "signingKey", "dataPolicy", "entryFields"], "well-known responseTransparency");
  if (
    value.responseTransparency.protocolVersion !== 1 ||
    value.responseTransparency.logId !== RESPONSE_LOG_ID ||
    value.responseTransparency.dataPolicy !== "hash-chain-heads-only-v1" ||
    !sameJson(value.responseTransparency.entryFields, ["entryHash", "head", "logIndex", "previousEntryHash"])
  ) {
    throw new TypeError("well-known responseTransparency does not enforce the hash-only v1 format.");
  }
  exactKeys(value.verifier, ["sourceUrl", "command"], "well-known verifier");
  if (!Array.isArray(value.monitoredResources) || value.monitoredResources.length < 3) {
    throw new TypeError("well-known monitoredResources must include entry, asset-manifest, and Apple association resources.");
  }
  const releaseId = string(value.releaseId, "well-known releaseId", {
    maximum: 120,
    pattern: RELEASE_ID,
  });
  return {
    schemaVersion: 1,
    releaseId,
    previousRelease: normalizePreviousRelease(
      value.previousRelease,
      "well-known previousRelease",
      releaseId,
    ),
    protocol: value.protocol,
    releaseSigningKey: await normalizeKey(value.releaseSigningKey, "well-known releaseSigningKey", "ECDSA_P256_SHA256"),
    manifest: normalizeReference(value.manifest, "well-known manifest", { signature: true }),
    deploymentStatement: {
      ...normalizeReference(
        {
          url: value.deploymentStatement.url,
          sha256: value.deploymentStatement.sha256,
          size: value.deploymentStatement.size,
          signature: value.deploymentStatement.signature,
        },
        "well-known deploymentStatement",
        { signature: true },
      ),
      environment: (() => {
        exactKeys(value.deploymentStatement, ["url", "sha256", "size", "signature", "environment", "deployedAt"], "well-known deploymentStatement");
        if (!['staging', 'production'].includes(value.deploymentStatement.environment)) throw new TypeError("well-known deployment environment is unsupported.");
        return value.deploymentStatement.environment;
      })(),
      deployedAt: timestamp(value.deploymentStatement.deployedAt, "well-known deploymentStatement.deployedAt"),
    },
    web: {
      publicOrigin: safeHttpsUrl(value.web.publicOrigin, "well-known web.publicOrigin", { originOnly: true }),
      entryDocumentSha256: sha256String(value.web.entryDocumentSha256, "well-known web.entryDocumentSha256"),
      assetManifestSha256: sha256String(value.web.assetManifestSha256, "well-known web.assetManifestSha256"),
    },
    evaluator: value.evaluator,
    responseTransparency: {
      protocolVersion: 1,
      logId: string(value.responseTransparency.logId, "well-known responseTransparency.logId", {
        maximum: 120,
        pattern: RELEASE_ID,
      }),
      url: safeHttpsUrl(value.responseTransparency.url, "well-known responseTransparency.url"),
      signingKey: await normalizeKey(
        value.responseTransparency.signingKey,
        "well-known responseTransparency.signingKey",
        "ECDSA_P256_SHA256",
      ),
      dataPolicy: "hash-chain-heads-only-v1",
      entryFields: ["entryHash", "head", "logIndex", "previousEntryHash"],
    },
    monitoredResources: value.monitoredResources.map((resource, index) => normalizeResource(resource, `well-known monitoredResources[${index}]`)),
    verifier: {
      sourceUrl: safeHttpsUrl(value.verifier.sourceUrl, "well-known verifier.sourceUrl"),
      command: string(value.verifier.command, "well-known verifier.command", { maximum: 300 }),
    },
  };
}

function assertProtocol(protocol, label) {
  exactKeys(protocol, ["version", "cipherSuite", "paddedPlaintextBytes", "payloadFrameBytes", "userWrapBytes", "evaluatorWrapBytes"], label);
  const expected = {
    version: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    paddedPlaintextBytes: 4096,
    payloadFrameBytes: 4124,
    userWrapBytes: 60,
    evaluatorWrapBytes: 157,
  };
  if (!sameJson(protocol, expected)) throw new TypeError(`${label} is not private-response protocol v1.`);
  return expected;
}

async function normalizeCriticalManifest(value, requireProduction) {
  exactKeys(value, ["schemaVersion", "releaseId", "evaluatorKeyEpochId", "previousRelease", "releaseStage", "createdAt", "sourceDateEpoch", "source", "protocol", "trust", "artifacts", "database", "productionPolicy", "evidence"], "release manifest");
  if (value.schemaVersion !== 1 || !['candidate', 'production'].includes(value.releaseStage)) {
    throw new TypeError("release manifest schema or stage is unsupported.");
  }
  if (requireProduction && value.releaseStage !== "production") throw new TypeError("production manifest required.");
  const releaseId = string(value.releaseId, "release manifest releaseId", { maximum: 120, pattern: RELEASE_ID });
  const evaluatorKeyEpochId = string(value.evaluatorKeyEpochId, "release manifest evaluatorKeyEpochId", { maximum: 120, pattern: RELEASE_ID });
  const previousRelease = normalizePreviousRelease(
    value.previousRelease,
    "release manifest previousRelease",
    releaseId,
  );
  const createdAt = timestamp(value.createdAt, "release manifest createdAt");
  const sourceDateEpoch = integer(value.sourceDateEpoch, "release manifest sourceDateEpoch", { maximum: 253402300799 });
  if (new Date(sourceDateEpoch * 1000).toISOString() !== createdAt) {
    throw new TypeError("release manifest createdAt is not derived from sourceDateEpoch.");
  }
  exactKeys(value.source, ["repository", "revision", "license", "exportArchive", "exportManifest"], "release manifest source");
  if (value.source.license !== "Apache-2.0") throw new TypeError("release manifest source license is not Apache-2.0.");
  const source = {
    repository: safeHttpsUrl(value.source.repository, "release manifest source.repository"),
    revision: string(value.source.revision, "release manifest source.revision", {
      minimum: 40,
      maximum: 64,
      pattern: /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u,
    }),
    license: "Apache-2.0",
    exportArchive: normalizeArtifact(value.source.exportArchive, "release manifest source.exportArchive"),
    exportManifest: normalizeArtifact(value.source.exportManifest, "release manifest source.exportManifest", {
      maximum: MAX_EVIDENCE_ARTIFACT_BYTES,
    }),
  };
  if (source.exportManifest.mediaType !== "application/json" && !source.exportManifest.mediaType.endsWith("+json")) {
    throw new TypeError("release manifest source.exportManifest is not declared as JSON evidence.");
  }
  const protocol = assertProtocol(value.protocol, "release manifest protocol");
  exactKeys(value.trust, ["evaluatorEncryption", "resultSigning", "policySigning", "receiptTransparencySigning", "releaseManifestSigning", "workload"], "release manifest trust");
  const evaluatorEncryption = await normalizeKey(value.trust.evaluatorEncryption, "release manifest evaluatorEncryption", "P256_ECDH_HKDF_SHA256_AES256_GCM");
  const resultSigning = await normalizeKey(value.trust.resultSigning, "release manifest resultSigning", "ECDSA_P256_SHA256");
  const policySigning = await normalizeKey(value.trust.policySigning, "release manifest policySigning", "ECDSA_P256_SHA256");
  const receiptTransparencySigning = await normalizeKey(value.trust.receiptTransparencySigning, "release manifest receiptTransparencySigning", "ECDSA_P256_SHA256");
  const releaseManifestSigning = await normalizeKey(value.trust.releaseManifestSigning, "release manifest releaseManifestSigning", "ECDSA_P256_SHA256");
  const keys = [evaluatorEncryption, resultSigning, policySigning, receiptTransparencySigning, releaseManifestSigning];
  if (new Set(keys.map(({ keyId }) => keyId)).size !== 5 || new Set(keys.map(({ publicKeySha256 }) => publicKeySha256)).size !== 5) {
    throw new TypeError("release manifest trust purposes do not use distinct keys.");
  }
  const workload = value.trust.workload;
  exactKeys(workload, ["platform", "imageDigest", "measurements", "attestationProvider", "attestationClaimPolicy", "attestationRootFingerprint"], "release manifest workload");
  if (workload.platform !== "gcp-confidential-space" || workload.attestationProvider !== "google-pki-attestation-token") {
    throw new TypeError("release manifest workload is not Google Confidential Space.");
  }
  const imageDigest = normalizeDigest(workload.imageDigest, "release manifest workload.imageDigest", { sha256Only: true });
  if (!Array.isArray(workload.measurements) || workload.measurements.length === 0) throw new TypeError("release manifest workload measurements are empty.");
  const measurements = workload.measurements.map((item, index) => normalizeDigest(item, `release manifest workload.measurements[${index}]`));
  normalizeDigest(workload.attestationRootFingerprint, "release manifest workload.attestationRootFingerprint", { sha256Only: true });
  const claim = workload.attestationClaimPolicy;
  exactKeys(claim, ["policyId", "issuer", "audience", "maxAgeSeconds", "challengeNonceRequired", "keyBindingDomain", "keyBindingHashAlgorithm", "keyBindingHashEncoding", "keyBindingHash", "imageDigest", "projectId", "serviceAccount", "hwmodel", "secboot", "dbgstat", "swname", "allowedSwversions", "oemid", "attesterTcb", "envOverrideAllowed", "cmdOverrideAllowed"], "release manifest attestationClaimPolicy");
  if (
    claim.issuer !== GOOGLE_ISSUER ||
    claim.challengeNonceRequired !== true ||
    claim.keyBindingDomain !== CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN ||
    claim.keyBindingHashAlgorithm !== "sha256" ||
    claim.keyBindingHashEncoding !== "base64url" ||
    claim.hwmodel !== "GCP_INTEL_TDX" ||
    claim.secboot !== true ||
    claim.dbgstat !== "disabled-since-boot" ||
    claim.swname !== "CONFIDENTIAL_SPACE" ||
    claim.oemid !== 11129 ||
    claim.attesterTcb !== "INTEL" ||
    claim.envOverrideAllowed !== false ||
    claim.cmdOverrideAllowed !== false
  ) throw new TypeError("release manifest attestation claim constants are not fail-closed.");
  string(claim.policyId, "release manifest attestation policyId", { maximum: 120, pattern: RELEASE_ID });
  safeHttpsUrl(claim.audience, "release manifest attestation audience");
  integer(claim.maxAgeSeconds, "release manifest attestation maxAgeSeconds", { minimum: 30, maximum: 900 });
  string(claim.projectId, "release manifest attestation projectId", { maximum: 30, pattern: GCP_PROJECT_ID });
  string(claim.serviceAccount, "release manifest attestation serviceAccount", { maximum: 253, pattern: SERVICE_ACCOUNT });
  if (!Array.isArray(claim.allowedSwversions) || claim.allowedSwversions.length === 0 || new Set(claim.allowedSwversions).size !== claim.allowedSwversions.length) {
    throw new TypeError("release manifest attestation swversion allowlist is invalid.");
  }
  claim.allowedSwversions.forEach((version, index) => string(version, `release manifest allowedSwversions[${index}]`, { minimum: 6, maximum: 6, pattern: /^[0-9]{6}$/u }));
  if (!sameJson(normalizeDigest(claim.imageDigest, "release manifest attestation imageDigest", { sha256Only: true }), imageDigest)) {
    throw new TypeError("release manifest attestation image digest is inconsistent.");
  }
  const bindingPayload = {
    protocolVersion: 1,
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
  const bindingHash = await sha256Base64Url(
    encoder.encode(`${CONFIDENTIAL_SPACE_KEY_BINDING_DOMAIN}\0${JSON.stringify(bindingPayload)}`),
  );
  if (
    string(claim.keyBindingHash, "release manifest attestation keyBindingHash", {
      minimum: 43,
      maximum: 43,
      pattern: /^[A-Za-z0-9_-]{43}$/u,
    }) !== bindingHash
  ) {
    throw new TypeError("release manifest attestation key binding is incorrect.");
  }
  exactKeys(value.productionPolicy, ["configurationSha256", "testAuthenticationEnabled", "debugEnabled", "requestBodyLoggingEnabled"], "release manifest productionPolicy");
  sha256String(value.productionPolicy.configurationSha256, "release manifest productionPolicy.configurationSha256");
  if (value.productionPolicy.testAuthenticationEnabled !== false || value.productionPolicy.debugEnabled !== false || value.productionPolicy.requestBodyLoggingEnabled !== false) {
    throw new TypeError("release manifest production safety flags are enabled.");
  }
  exactKeys(value.artifacts, ["web", "ios", "ordinaryApi", "evaluator", "scheduler"], "release manifest artifacts");
  exactKeys(value.artifacts.web, ["publicOrigin", "deploymentArchive", "assetManifestSha256", "entryDocumentSha256"], "release manifest web artifact");
  exactKeys(value.artifacts.ios, ["bundleIdentifier", "version", "build", "submissionArchive", "normalizedBinarySha256"], "release manifest iOS artifact");
  const artifacts = {
    web: {
      publicOrigin: safeHttpsUrl(value.artifacts.web.publicOrigin, "release manifest web publicOrigin", { originOnly: true }),
      deploymentArchive: normalizeArtifact(value.artifacts.web.deploymentArchive, "release manifest web deploymentArchive"),
      assetManifestSha256: sha256String(value.artifacts.web.assetManifestSha256, "release manifest web assetManifestSha256"),
      entryDocumentSha256: sha256String(value.artifacts.web.entryDocumentSha256, "release manifest web entryDocumentSha256"),
    },
    ios: {
      bundleIdentifier: string(value.artifacts.ios.bundleIdentifier, "release manifest iOS bundleIdentifier", {
        minimum: 3,
        maximum: 255,
        pattern: /^[A-Za-z0-9][A-Za-z0-9.-]+$/u,
      }),
      version: string(value.artifacts.ios.version, "release manifest iOS version", { maximum: 40 }),
      build: string(value.artifacts.ios.build, "release manifest iOS build", { maximum: 40 }),
      submissionArchive: normalizeArtifact(value.artifacts.ios.submissionArchive, "release manifest iOS submissionArchive"),
      normalizedBinarySha256: sha256String(value.artifacts.ios.normalizedBinarySha256, "release manifest iOS normalizedBinarySha256"),
    },
    ordinaryApi: normalizeArtifact(value.artifacts.ordinaryApi, "release manifest ordinaryApi"),
    evaluator: normalizeArtifact(value.artifacts.evaluator, "release manifest evaluator"),
    scheduler: normalizeArtifact(value.artifacts.scheduler, "release manifest scheduler"),
  };
  exactKeys(value.evidence, ["sboms", "provenance", "transparency", "transitions", "deployments", "audits"], "release manifest evidence");
  for (const field of ["sboms", "provenance", "transparency", "transitions", "deployments", "audits"]) {
    if (!Array.isArray(value.evidence[field])) throw new TypeError(`release manifest evidence.${field} must be an array.`);
  }
  const evidence = {
    sboms: value.evidence.sboms.map((artifact, index) =>
      normalizeArtifact(artifact, `release manifest evidence.sboms[${index}]`, { maximum: MAX_EVIDENCE_ARTIFACT_BYTES })),
    provenance: value.evidence.provenance.map(normalizeProvenance),
    transparency: value.evidence.transparency.map(normalizeTransparency),
    transitions: value.evidence.transitions.map((artifact, index) =>
      normalizeArtifact(artifact, `release manifest evidence.transitions[${index}]`, { maximum: MAX_EVIDENCE_ARTIFACT_BYTES })),
    deployments: value.evidence.deployments.map((artifact, index) =>
      normalizeArtifact(artifact, `release manifest evidence.deployments[${index}]`, { maximum: MAX_EVIDENCE_ARTIFACT_BYTES })),
    audits: value.evidence.audits.map((artifact, index) =>
      normalizeArtifact(artifact, `release manifest evidence.audits[${index}]`, { maximum: MAX_EVIDENCE_ARTIFACT_BYTES })),
  };
  if (evidence.sboms.length === 0 || (requireProduction && (evidence.provenance.length === 0 || evidence.transparency.length === 0 || evidence.transitions.length === 0 || evidence.audits.length === 0))) {
    throw new TypeError("release manifest lacks required release evidence.");
  }
  if (requireProduction) {
    const evaluatorTransitions = evidence.transitions.filter(
      ({ name, mediaType }) =>
        name === "evaluator-epoch-transition.json" &&
        mediaType === "application/vnd.herd.evaluator-epoch-transition.v2+json",
    );
    const releaseContinuity = evidence.transitions.filter(
      ({ name, mediaType }) =>
        name === "release-continuity.json" &&
        mediaType === "application/vnd.herd.release-continuity.v1+json",
    );
    if (
      evaluatorTransitions.length !== 1 ||
      releaseContinuity.length !== (previousRelease === null ? 0 : 1) ||
      evidence.transitions.length !==
        evaluatorTransitions.length + releaseContinuity.length
    ) {
      throw new TypeError(
        "release manifest transition evidence does not match bootstrap or successor requirements.",
      );
    }
  }
  const referenced = uniqueArtifacts([
    source.exportArchive,
    source.exportManifest,
    artifacts.web.deploymentArchive,
    artifacts.ios.submissionArchive,
    artifacts.ordinaryApi,
    artifacts.evaluator,
    artifacts.scheduler,
    ...evidence.sboms,
    ...evidence.transitions,
    ...evidence.provenance.map(({ statement }) => statement),
    ...evidence.provenance.map(({ bundle }) => bundle),
    ...evidence.deployments,
    ...evidence.audits,
  ], "release manifest");
  const expectedProvenanceSubjects = new Map([
    source.exportArchive,
    source.exportManifest,
    artifacts.web.deploymentArchive,
    artifacts.ios.submissionArchive,
    artifacts.ordinaryApi,
    artifacts.evaluator,
    artifacts.scheduler,
    ...evidence.sboms,
    ...evidence.transitions,
  ].map(({ name, sha256 }) => [name, sha256]));
  const actualProvenanceSubjects = new Map();
  for (const provenance of evidence.provenance) {
    for (const subject of provenance.subjects) {
      if (actualProvenanceSubjects.has(subject.name)) throw new TypeError("release manifest provenance subjects overlap.");
      actualProvenanceSubjects.set(subject.name, subject.sha256);
    }
    const matchingTransparency = evidence.transparency.filter(({ bundleSha256 }) => bundleSha256 === provenance.bundle.sha256);
    if (matchingTransparency.length !== 1) {
      throw new TypeError("release manifest provenance bundle does not have one matching Rekor record.");
    }
  }
  if (
    evidence.provenance.length > 0 &&
    (
      actualProvenanceSubjects.size !== expectedProvenanceSubjects.size ||
      [...expectedProvenanceSubjects].some(([name, digest]) => actualProvenanceSubjects.get(name) !== digest) ||
      new Set(evidence.transparency.map(({ bundleSha256 }) => bundleSha256)).size !== evidence.provenance.length
    )
  ) {
    throw new TypeError("release manifest provenance does not exactly cover every required release subject.");
  }
  return {
    releaseId,
    evaluatorKeyEpochId,
    previousRelease,
    releaseStage: value.releaseStage,
    createdAt,
    sourceDateEpoch,
    protocol,
    trust: { evaluatorEncryption, resultSigning, policySigning, receiptTransparencySigning, releaseManifestSigning, workload: { ...workload, imageDigest, measurements } },
    source,
    artifacts,
    evidence,
    referencedArtifacts: referenced,
  };
}

function keyWitness(value) {
  return { keyId: value.keyId, publicKeySha256: value.publicKeySha256 };
}

async function evaluatorKeyEpochWitness(manifest) {
  const workloadImageDigest =
    `${manifest.trust.workload.imageDigest.algorithm}:` +
    manifest.trust.workload.imageDigest.value;
  const descriptor = {
    schemaVersion: 1,
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    workloadImageDigest,
    responseDecryption: {
      keyId: manifest.trust.evaluatorEncryption.keyId,
      publicKey: manifest.trust.evaluatorEncryption.publicKey,
    },
    evaluationResultSigning: {
      keyId: manifest.trust.resultSigning.keyId,
      publicKey: manifest.trust.resultSigning.publicKey,
    },
    policySigning: {
      keyId: manifest.trust.policySigning.keyId,
      publicKey: manifest.trust.policySigning.publicKey,
    },
    responseTransparency: {
      logId: RESPONSE_LOG_ID,
      keyId: manifest.trust.receiptTransparencySigning.keyId,
      publicKey: manifest.trust.receiptTransparencySigning.publicKey,
    },
  };
  return {
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    sha256: await sha256Hex(encoder.encode(canonicalStringify(descriptor))),
    workloadImageDigest,
    responseDecryption: keyWitness(manifest.trust.evaluatorEncryption),
    evaluationResultSigning: keyWitness(manifest.trust.resultSigning),
    policySigning: keyWitness(manifest.trust.policySigning),
    responseTransparency: {
      logId: RESPONSE_LOG_ID,
      ...keyWitness(manifest.trust.receiptTransparencySigning),
    },
  };
}

async function verifySignature(bytes, envelopeValue, expectedKey, artifactType) {
  exactKeys(envelopeValue, ["schemaVersion", "artifactType", "algorithm", "keyId", "publicKeySha256", "signedDigest", "signatureFormat", "signature", "signedAt"], "signature envelope");
  exactKeys(envelopeValue.signedDigest, ["algorithm", "value"], "signature envelope signedDigest");
  if (
    envelopeValue.schemaVersion !== 1 ||
    envelopeValue.artifactType !== artifactType ||
    envelopeValue.algorithm !== "ECDSA_P256_SHA256" ||
    envelopeValue.signatureFormat !== "P1363_BASE64URL" ||
    envelopeValue.signedDigest.algorithm !== "sha256" ||
    envelopeValue.keyId !== expectedKey.keyId ||
    envelopeValue.publicKeySha256 !== expectedKey.publicKeySha256 ||
    envelopeValue.signedDigest.value !== (await sha256Hex(bytes))
  ) throw new TypeError("signature envelope does not bind the artifact and trusted release key.");
  timestamp(envelopeValue.signedAt, "signature envelope signedAt");
  const signature = base64UrlBytes(envelopeValue.signature, 64, "signature envelope signature");
  const publicKeyBytes = base64UrlBytes(expectedKey.publicKey, 65, "trusted release public key");
  let key;
  try {
    key = await crypto.subtle.importKey("raw", publicKeyBytes, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    throw new TypeError("trusted release public key is not a valid P-256 point.");
  }
  if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, bytes))) {
    throw new TypeError("release signature verification failed.");
  }
}

async function verifyDomainSignature(publicKey, domain, canonicalPayload, signatureValue) {
  const signature = base64UrlBytes(signatureValue, 64, "response log-head signature");
  const publicKeyBytes = base64UrlBytes(publicKey.publicKey, 65, "response transparency public key");
  let key;
  try {
    key = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new TypeError("response transparency public key is not a valid P-256 point.");
  }
  const signedBytes = encoder.encode(`${domain}\0${canonicalPayload}`);
  if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signedBytes))) {
    throw new TypeError("response log-head signature is invalid.");
  }
}

function normalizePreviousResponseWitness(value, configuration) {
  if (value === null || value === undefined) {
    return {
      logId: configuration.logId,
      url: configuration.url,
      signingKeyId: configuration.signingKey.keyId,
      publicKeySha256: configuration.signingKey.publicKeySha256,
      witnessedIndex: 0,
      witnessedPreviousEntryHash: null,
      witnessedEntryHash: GENESIS_RESPONSE_ENTRY_HASH,
      witnessedAt: null,
    };
  }
  exactKeys(
    value,
    [
      "logId",
      "url",
      "signingKeyId",
      "publicKeySha256",
      "witnessedIndex",
      "witnessedPreviousEntryHash",
      "witnessedEntryHash",
      "witnessedAt",
    ],
    "previous response-transparency witness",
  );
  if (
    value.logId !== configuration.logId ||
    value.url !== configuration.url ||
    value.signingKeyId !== configuration.signingKey.keyId ||
    value.publicKeySha256 !== configuration.signingKey.publicKeySha256
  ) {
    throw new TypeError("response-transparency URL, log ID, or signing key changed from witnessed state.");
  }
  const witnessedIndex = integer(value.witnessedIndex, "previous witnessedIndex", {
    maximum: 2_147_483_647,
  });
  const witnessedEntryHash = base64UrlBytes(
    value.witnessedEntryHash,
    32,
    "previous witnessedEntryHash",
  );
  if (witnessedIndex === 0 && value.witnessedPreviousEntryHash !== null) {
    throw new TypeError("empty response-transparency witness has a previous entry hash.");
  }
  if (witnessedIndex > 0) {
    base64UrlBytes(
      value.witnessedPreviousEntryHash,
      32,
      "previous witnessedPreviousEntryHash",
    );
  }
  if (witnessedIndex === 0 && base64Url(witnessedEntryHash) !== GENESIS_RESPONSE_ENTRY_HASH) {
    throw new TypeError("empty response-transparency witness does not use the genesis hash.");
  }
  if (value.witnessedAt !== null) timestamp(value.witnessedAt, "previous witnessedAt");
  return {
    logId: value.logId,
    url: value.url,
    signingKeyId: value.signingKeyId,
    publicKeySha256: value.publicKeySha256,
    witnessedIndex,
    witnessedPreviousEntryHash: value.witnessedPreviousEntryHash,
    witnessedEntryHash: value.witnessedEntryHash,
    witnessedAt: value.witnessedAt,
  };
}

function parseResponseLogPage(bytes) {
  let value;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new TypeError("response-transparency page is not valid UTF-8 JSON.");
  }
  exactKeys(value, ["protocolVersion", "logId", "entries"], "response-transparency page");
  if (value.protocolVersion !== 1 || !Array.isArray(value.entries) || value.entries.length > RESPONSE_LOG_PAGE_SIZE) {
    throw new TypeError("response-transparency page has an unsupported protocol or entry count.");
  }
  return value;
}

async function fetchResponseLogPage(fetchImpl, configuration, after) {
  const url = new URL(configuration.url);
  url.searchParams.set("after", String(after));
  url.searchParams.set("limit", String(RESPONSE_LOG_PAGE_SIZE));
  const fetched = await fetchBounded(
    fetchImpl,
    url.toString(),
    MAX_RESPONSE_LOG_PAGE_BYTES,
    "response-transparency page",
  );
  if (fetched.contentType !== "application/json") {
    throw new TypeError("response-transparency page has a non-JSON content type.");
  }
  const page = parseResponseLogPage(fetched.bytes);
  if (page.logId !== configuration.logId) {
    throw new TypeError("response-transparency log ID changed.");
  }
  return page.entries;
}

async function normalizeAndVerifyResponseLogEntry(value, configuration, expectedIndex, previousHash) {
  exactKeys(
    value,
    ["logIndex", "previousEntryHash", "entryHash", "head"],
    `response-transparency entry ${expectedIndex}`,
  );
  exactKeys(
    value.head,
    [
      "protocolVersion",
      "logId",
      "treeSize",
      "headEntryHash",
      "generatedAt",
      "signingKeyId",
      "signature",
    ],
    `response-transparency entry ${expectedIndex} head`,
  );
  if (
    value.logIndex !== expectedIndex ||
    value.previousEntryHash !== previousHash ||
    value.head.protocolVersion !== 1 ||
    value.head.logId !== configuration.logId ||
    value.head.treeSize !== expectedIndex ||
    value.head.headEntryHash !== value.entryHash ||
    value.head.signingKeyId !== configuration.signingKey.keyId
  ) {
    throw new TypeError(`response-transparency entry ${expectedIndex} creates a gap, fork, or key change.`);
  }
  base64UrlBytes(value.previousEntryHash, 32, `response-transparency entry ${expectedIndex} previousEntryHash`);
  base64UrlBytes(value.entryHash, 32, `response-transparency entry ${expectedIndex} entryHash`);
  timestamp(value.head.generatedAt, `response-transparency entry ${expectedIndex} generatedAt`);
  const canonicalHead = JSON.stringify({
    protocolVersion: 1,
    logId: configuration.logId,
    treeSize: expectedIndex,
    headEntryHash: value.entryHash,
    generatedAt: value.head.generatedAt,
    signingKeyId: configuration.signingKey.keyId,
  });
  await verifyDomainSignature(
    configuration.signingKey,
    RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
    canonicalHead,
    value.head.signature,
  );
  return { index: expectedIndex, hash: value.entryHash };
}

export async function witnessResponseTransparency(
  configuration,
  { fetchImpl = fetch, previous = null, now = () => new Date() } = {},
) {
  const state = normalizePreviousResponseWitness(previous, configuration);
  let latestIndex = state.witnessedIndex;
  let latestHash = state.witnessedEntryHash;
  let latestPreviousHash = state.witnessedPreviousEntryHash;
  let after = latestIndex > 0 ? latestIndex - 1 : 0;
  let expectAnchor = latestIndex > 0;
  let pages = 0;
  for (; pages < MAX_RESPONSE_LOG_PAGES; pages += 1) {
    const entries = await fetchResponseLogPage(fetchImpl, configuration, after);
    if (expectAnchor && entries.length === 0) {
      throw new TypeError("response-transparency log rewound below the last witnessed entry.");
    }
    let expectedIndex = after + 1;
    let chainHash = expectAnchor
      ? null
      : after === 0
        ? GENESIS_RESPONSE_ENTRY_HASH
        : latestHash;
    for (const entry of entries) {
      if (expectAnchor) {
        if (entry.logIndex !== latestIndex || entry.entryHash !== latestHash) {
          throw new TypeError("response-transparency log forked at the last witnessed entry.");
        }
        const anchor = await normalizeAndVerifyResponseLogEntry(
          entry,
          configuration,
          latestIndex,
          latestPreviousHash,
        );
        latestIndex = anchor.index;
        latestHash = anchor.hash;
        latestPreviousHash = entry.previousEntryHash;
        chainHash = latestHash;
        expectedIndex = latestIndex + 1;
        expectAnchor = false;
        continue;
      }
      const normalized = await normalizeAndVerifyResponseLogEntry(
        entry,
        configuration,
        expectedIndex,
        chainHash,
      );
      latestIndex = normalized.index;
      latestPreviousHash = entry.previousEntryHash;
      latestHash = normalized.hash;
      chainHash = latestHash;
      expectedIndex += 1;
    }
    if (entries.length < RESPONSE_LOG_PAGE_SIZE) break;
    if (expectAnchor) throw new TypeError("response-transparency anchor was not returned.");
    after = latestIndex;
  }
  if (pages === MAX_RESPONSE_LOG_PAGES) {
    throw new TypeError("response-transparency backlog exceeds one monitor run.");
  }
  const witnessedAt = now().toISOString();
  timestamp(witnessedAt, "response-transparency witnessedAt");
  return {
    logId: configuration.logId,
    url: configuration.url,
    signingKeyId: configuration.signingKey.keyId,
    publicKeySha256: configuration.signingKey.publicKeySha256,
    witnessedIndex: latestIndex,
    witnessedPreviousEntryHash: latestPreviousHash,
    witnessedEntryHash: latestHash,
    witnessedAt,
  };
}

function normalizeDeployment(value) {
  exactKeys(value, ["schemaVersion", "releaseId", "environment", "deployedAt", "manifest", "manifestSignature", "endpoints", "platformDeployments", "monitoredResources"], "deployment statement");
  if (value.schemaVersion !== 1 || !['staging', 'production'].includes(value.environment)) throw new TypeError("deployment statement schema or environment is unsupported.");
  exactKeys(value.endpoints, ["webOrigin", "apiBaseUrl", "evaluatorUrl", "schedulerIdentity"], "deployment endpoints");
  if (!Array.isArray(value.platformDeployments) || value.platformDeployments.length !== 4) throw new TypeError("deployment statement must bind four components.");
  const platformDeployments = value.platformDeployments.map((deployment, index) => {
    exactKeys(deployment, ["component", "provider", "deploymentId", "artifactSha256"], `platformDeployments[${index}]`);
    if (!['web', 'ordinary-api', 'evaluator', 'scheduler'].includes(deployment.component)) throw new TypeError("deployment component is unsupported.");
    return { ...deployment, artifactSha256: sha256String(deployment.artifactSha256, `platformDeployments[${index}].artifactSha256`) };
  });
  if (new Set(platformDeployments.map(({ component }) => component)).size !== 4) throw new TypeError("deployment components are duplicated.");
  const webOrigin = safeHttpsUrl(value.endpoints.webOrigin, "deployment webOrigin", { originOnly: true });
  if (!Array.isArray(value.monitoredResources) || value.monitoredResources.length < 3) throw new TypeError("deployment monitored resources are incomplete.");
  const monitoredResources = value.monitoredResources.map((resource, index) => normalizeResource(resource, `deployment monitoredResources[${index}]`));
  const appleAssociation = monitoredResources.filter(
    ({ name }) => name === APPLE_APP_SITE_ASSOCIATION_NAME,
  );
  if (
    appleAssociation.length !== 1 ||
    appleAssociation[0].url !== new URL("/.well-known/apple-app-site-association", webOrigin).toString() ||
    appleAssociation[0].mediaType.toLowerCase() !== "application/json"
  ) {
    throw new TypeError("deployment must monitor the exact production Apple app-site association JSON resource.");
  }
  return {
    ...value,
    releaseId: string(value.releaseId, "deployment releaseId", { maximum: 120, pattern: RELEASE_ID }),
    deployedAt: timestamp(value.deployedAt, "deployment deployedAt"),
    manifest: value.manifest,
    manifestSignature: value.manifestSignature,
    endpoints: {
      webOrigin,
      apiBaseUrl: safeHttpsUrl(value.endpoints.apiBaseUrl, "deployment apiBaseUrl"),
      evaluatorUrl: safeHttpsUrl(value.endpoints.evaluatorUrl, "deployment evaluatorUrl"),
      schedulerIdentity: string(value.endpoints.schedulerIdentity, "deployment schedulerIdentity", { maximum: 300 }),
    },
    platformDeployments,
    monitoredResources,
  };
}

function artifactBinding(artifact, reference, label) {
  if (!isObject(artifact) || artifact.url !== reference.url || artifact.sha256 !== reference.sha256 || artifact.size !== reference.size) {
    throw new TypeError(`${label} does not bind its published artifact.`);
  }
}

export async function verifyTarget(
  targetValue,
  {
    fetchImpl = fetch,
    now = () => new Date(),
    previousResponseTransparency = null,
    liveAttestationVerifier = verifyLiveEvaluatorAttestation,
  } = {},
) {
  const target = await normalizeTarget(targetValue);
  const wellKnownOrigin = new URL(target.wellKnownUrl).origin;
  if (
    wellKnownOrigin !== target.expectedWebOrigin &&
    !target.allowedEvidenceOrigins.includes(wellKnownOrigin)
  ) {
    throw new TypeError("well-known release record is outside the configured web or evidence origins.");
  }
  const wellKnownFetch = await fetchBounded(fetchImpl, target.wellKnownUrl, MAX_WELL_KNOWN_BYTES, "well-known release record");
  if (wellKnownFetch.contentType && wellKnownFetch.contentType !== "application/json" && !wellKnownFetch.contentType.endsWith("+json")) {
    throw new TypeError("well-known release record has a non-JSON content type.");
  }
  const wellKnown = await normalizeWellKnown(parseCanonicalJson(wellKnownFetch.bytes, "well-known release record"));
  const trustedKey = target.releaseSigningKey;
  if (!sameJson(trustedKey, wellKnown.releaseSigningKey)) throw new TypeError("well-known release key differs from the independently configured key.");
  if (wellKnown.web.publicOrigin !== target.expectedWebOrigin) throw new TypeError("well-known web origin differs from configured origin.");
  if (target.requireProduction && wellKnown.deploymentStatement.environment !== "production") throw new TypeError("well-known record is not production.");

  const [manifestFetch, manifestSignatureFetch, deploymentFetch, deploymentSignatureFetch] = await Promise.all([
    fetchReference(fetchImpl, wellKnown.manifest, "release manifest", target.allowedEvidenceOrigins),
    fetchReference(fetchImpl, wellKnown.manifest.signature, "release manifest signature", target.allowedEvidenceOrigins),
    fetchReference(fetchImpl, wellKnown.deploymentStatement, "deployment statement", target.allowedEvidenceOrigins),
    fetchReference(fetchImpl, wellKnown.deploymentStatement.signature, "deployment statement signature", target.allowedEvidenceOrigins),
  ]);
  const manifestValue = parseCanonicalJson(manifestFetch.bytes, "release manifest");
  const manifest = await normalizeCriticalManifest(manifestValue, target.requireProduction);
  if (manifest.releaseId !== wellKnown.releaseId) throw new TypeError("well-known and manifest release IDs differ.");
  if (!sameJson(manifest.previousRelease, wellKnown.previousRelease)) {
    throw new TypeError("well-known predecessor differs from the signed release manifest.");
  }
  if (!sameJson(manifest.trust.releaseManifestSigning, trustedKey)) throw new TypeError("manifest release key differs from independently configured key.");
  await verifySignature(manifestFetch.bytes, parseCanonicalJson(manifestSignatureFetch.bytes, "release manifest signature"), trustedKey, MANIFEST_TYPE);

  const deploymentValue = parseCanonicalJson(deploymentFetch.bytes, "deployment statement");
  const deployment = normalizeDeployment(deploymentValue);
  if (deployment.releaseId !== manifest.releaseId || deployment.environment !== wellKnown.deploymentStatement.environment || deployment.deployedAt !== wellKnown.deploymentStatement.deployedAt) {
    throw new TypeError("deployment statement conflicts with the release pointer or manifest.");
  }
  if (target.requireProduction && deployment.environment !== "production") throw new TypeError("deployment statement is not production.");
  await verifySignature(deploymentFetch.bytes, parseCanonicalJson(deploymentSignatureFetch.bytes, "deployment signature"), trustedKey, DEPLOYMENT_TYPE);
  artifactBinding(deployment.manifest, wellKnown.manifest, "deployment manifest reference");
  artifactBinding(deployment.manifestSignature, wellKnown.manifest.signature, "deployment manifest-signature reference");
  if (deployment.endpoints.webOrigin !== target.expectedWebOrigin || manifest.artifacts.web.publicOrigin !== target.expectedWebOrigin) {
    throw new TypeError("deployment web origin conflicts with the configured origin.");
  }
  const evaluatorRelayUrl = new URL(deployment.endpoints.evaluatorUrl);
  if (evaluatorRelayUrl.pathname !== "/api/v1/relay/" || evaluatorRelayUrl.search) {
    throw new TypeError("deployment evaluator URL is not the exact /api/v1/relay/ endpoint.");
  }
  if (target.evaluatorAttestation) {
    const attestationAudience = new URL(
      manifest.trust.workload.attestationClaimPolicy.audience,
    );
    if (
      evaluatorRelayUrl.origin !== target.evaluatorAttestation.origin ||
      attestationAudience.origin !== target.evaluatorAttestation.origin
    ) {
      throw new TypeError(
        "signed evaluator endpoint and attestation audience differ from the independently configured evaluator origin.",
      );
    }
  }
  if (!sameJson(deployment.monitoredResources, wellKnown.monitoredResources)) throw new TypeError("well-known and deployment monitored resources differ.");
  if (!sameJson(wellKnown.protocol, manifest.protocol)) throw new TypeError("well-known protocol differs from manifest.");
  const expectedEvaluator = {
    evaluatorKeyEpochId: manifest.evaluatorKeyEpochId,
    encryptionKeyId: manifest.trust.evaluatorEncryption.keyId,
    resultSigningKeyId: manifest.trust.resultSigning.keyId,
    policySigningKeyId: manifest.trust.policySigning.keyId,
    receiptTransparencySigningKeyId: manifest.trust.receiptTransparencySigning.keyId,
    workloadImageDigest: manifest.trust.workload.imageDigest,
    measurements: manifest.trust.workload.measurements,
    attestationProvider: manifest.trust.workload.attestationProvider,
    attestationClaimPolicy: manifest.trust.workload.attestationClaimPolicy,
    attestationRootFingerprint: manifest.trust.workload.attestationRootFingerprint,
  };
  if (!sameJson(wellKnown.evaluator, expectedEvaluator)) throw new TypeError("well-known evaluator trust pins differ from manifest.");
  if (!sameJson(wellKnown.responseTransparency.signingKey, manifest.trust.receiptTransparencySigning)) {
    throw new TypeError("well-known response-transparency pin differs from manifest.");
  }
  if (new URL(wellKnown.responseTransparency.url).origin !== target.expectedWebOrigin) {
    throw new TypeError("well-known response-transparency log is outside the configured web origin.");
  }
  if (target.responseTransparency) {
    if (new URL(target.responseTransparency.url).origin !== target.expectedWebOrigin) {
      throw new TypeError("response-transparency log is outside the configured web origin.");
    }
    if (!sameJson(target.responseTransparency.signingKey, manifest.trust.receiptTransparencySigning)) {
      throw new TypeError("response-transparency signing pin differs from the signed release manifest.");
    }
    if (
      target.responseTransparency.url !== wellKnown.responseTransparency.url ||
      target.responseTransparency.logId !== wellKnown.responseTransparency.logId ||
      !sameJson(target.responseTransparency.signingKey, wellKnown.responseTransparency.signingKey)
    ) {
      throw new TypeError("configured response-transparency witness differs from the public release record.");
    }
  }
  const deployments = new Map(deployment.platformDeployments.map((item) => [item.component, item.artifactSha256]));
  if (
    deployments.get("web") !== manifest.artifacts.web.deploymentArchive.sha256 ||
    deployments.get("ordinary-api") !== manifest.artifacts.ordinaryApi.sha256 ||
    deployments.get("evaluator") !== manifest.artifacts.evaluator.sha256 ||
    deployments.get("scheduler") !== manifest.artifacts.scheduler.sha256
  ) throw new TypeError("deployment IDs are not bound to released artifact hashes.");
  const resources = new Map(deployment.monitoredResources.map((resource) => [resource.name, resource]));
  const appleAssociation = resources.get(APPLE_APP_SITE_ASSOCIATION_NAME);
  if (
    resources.size !== deployment.monitoredResources.length ||
    resources.get("entry-document")?.sha256 !== manifest.artifacts.web.entryDocumentSha256 ||
    resources.get("asset-manifest")?.sha256 !== manifest.artifacts.web.assetManifestSha256 ||
    appleAssociation?.url !== new URL("/.well-known/apple-app-site-association", target.expectedWebOrigin).toString() ||
    appleAssociation?.mediaType.toLowerCase() !== "application/json" ||
    wellKnown.web.entryDocumentSha256 !== manifest.artifacts.web.entryDocumentSha256 ||
    wellKnown.web.assetManifestSha256 !== manifest.artifacts.web.assetManifestSha256
  ) throw new TypeError("monitored web hashes differ from the release manifest.");

  const [resourceResults, publishedArtifacts] = await Promise.all([
    Promise.all(deployment.monitoredResources.map(async (resource) => {
      if (new URL(resource.url).origin !== target.expectedWebOrigin) throw new TypeError(`${resource.name} is outside the configured web origin.`);
      const fetched = await fetchBounded(fetchImpl, resource.url, Math.min(resource.size + 1, MAX_RESOURCE_BYTES), `monitored resource ${resource.name}`);
      if (fetched.bytes.byteLength !== resource.size || (await sha256Hex(fetched.bytes)) !== resource.sha256) {
        throw new TypeError(`monitored resource ${resource.name} differs from its release hash.`);
      }
      if (fetched.contentType !== resource.mediaType.toLowerCase()) {
        throw new TypeError(`monitored resource ${resource.name} has an unexpected content type.`);
      }
      if (resource.name === APPLE_APP_SITE_ASSOCIATION_NAME) {
        assertAppleAppSiteAssociation(fetched.bytes, manifest.artifacts.ios.bundleIdentifier);
      }
      return { name: resource.name, sha256: resource.sha256, size: resource.size };
    })),
    verifyPublishedReleaseEvidence(fetchImpl, manifest, target),
  ]);
  const responseTransparency = target.responseTransparency
    ? await witnessResponseTransparency(target.responseTransparency, {
        fetchImpl,
        previous: previousResponseTransparency,
        now,
      })
    : null;
  const evaluatorAttestation = target.evaluatorAttestation
    ? await liveAttestationVerifier(
        {
          ...target.evaluatorAttestation,
          manifest,
        },
        { fetchImpl, now },
      )
    : null;
  const checkedAt = now().toISOString();
  timestamp(checkedAt, "monitor checkedAt");
  const evaluatorKeyEpoch = await evaluatorKeyEpochWitness(manifest);
  return {
    schemaVersion: 1,
    target: target.name,
    ok: true,
    checkedAt,
    releaseId: manifest.releaseId,
    previousRelease: manifest.previousRelease,
    evaluatorKeyEpoch,
    releaseStage: manifest.releaseStage,
    releaseCreatedAt: manifest.createdAt,
    environment: deployment.environment,
    deployedAt: deployment.deployedAt,
    wellKnownSha256: await sha256Hex(wellKnownFetch.bytes),
    manifestSha256: wellKnown.manifest.sha256,
    deploymentSha256: wellKnown.deploymentStatement.sha256,
    resources: resourceResults.sort((left, right) => compareStrings(left.name, right.name)),
    releaseArtifacts: publishedArtifacts,
    ...(responseTransparency ? { responseTransparency } : {}),
    ...(evaluatorAttestation ? { evaluatorAttestation } : {}),
  };
}
