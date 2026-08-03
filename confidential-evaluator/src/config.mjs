import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";

import {
  DEFAULT_ATTESTATION_SOCKET,
  DEFAULT_CONFIG_FILE,
  GOOGLE_STS_AUDIENCE,
  GOOGLE_PROJECT_ID_PATTERN,
  FIRESTORE_COLLECTION_ID_PATTERN,
  FIRESTORE_DATABASE_ID_PATTERN,
  IDENTIFIER_PATTERN,
  IMAGE_DIGEST_PATTERN,
  KMS_KEY_RESOURCE_PATTERN,
  PRIVATE_KEY_ENVIRONMENT_NAMES,
  PROTOCOL_VERSION,
  WIP_PROVIDER_RESOURCE_PATTERN,
} from "./constants.mjs";
import { exactKeys } from "./encoding.mjs";
import { ConfigurationError } from "./errors.mjs";

const CONFIG_KEYS = Object.freeze([
  "protocolVersion",
  "releaseId",
  "keyBundleCiphertextFile",
  "kmsKeyResource",
  "transparencyKeyCiphertextFile",
  "transparencyKmsKeyResource",
  "workloadIdentityProvider",
  "transparencyStateProjectId",
  "transparencyStateDatabaseId",
  "transparencyStateCollection",
  "attestationAudience",
  "allowedOrigin",
  "port",
  "attestationSocket",
]);

function configurationError() {
  throw new ConfigurationError();
}

function boundedText(value, minimum, maximum) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    configurationError();
  }
  return value;
}

function absoluteFile(value) {
  const path = boundedText(value, 1, 1024);
  if (!isAbsolute(path)) configurationError();
  return path;
}

function httpsAudience(value) {
  const audience = boundedText(value, 8, 512);
  let parsed;
  try {
    parsed = new URL(audience);
  } catch {
    configurationError();
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username ||
    parsed.password ||
    parsed.hash
  ) {
    configurationError();
  }
  if (audience === GOOGLE_STS_AUDIENCE) configurationError();
  return audience;
}

function allowedOrigin(value) {
  if (value === null) return null;
  const origin = httpsAudience(value);
  const parsed = new URL(origin);
  if (parsed.origin !== origin || parsed.pathname !== "/" || parsed.search) {
    configurationError();
  }
  return origin;
}

function rejectSecretEnvironment(runtimeEnvironment) {
  for (const name of PRIVATE_KEY_ENVIRONMENT_NAMES) {
    if (runtimeEnvironment[name] !== undefined) configurationError();
  }
  for (const name of Object.keys(runtimeEnvironment)) {
    if (
      name.startsWith("HERD_") &&
      /(?:PRIVATE|SECRET|TOKEN|PASSWORD|CREDENTIAL)/u.test(name) &&
      name !== "HERD_DEPLOYMENT_CONFIG_FILE"
    ) {
      configurationError();
    }
  }
}

export function normalizeDeploymentConfig(value) {
  const input = exactKeys(value, CONFIG_KEYS, configurationError);
  if (input.protocolVersion !== PROTOCOL_VERSION) configurationError();
  const releaseId = boundedText(input.releaseId, 1, 200);
  if (!IDENTIFIER_PATTERN.test(releaseId)) configurationError();
  const keyBundleCiphertextFile = absoluteFile(input.keyBundleCiphertextFile);
  const kmsKeyResource = boundedText(input.kmsKeyResource, 1, 512);
  if (!KMS_KEY_RESOURCE_PATTERN.test(kmsKeyResource)) configurationError();
  const transparencyKeyCiphertextFile = absoluteFile(
    input.transparencyKeyCiphertextFile,
  );
  const transparencyKmsKeyResource = boundedText(
    input.transparencyKmsKeyResource,
    1,
    512,
  );
  if (!KMS_KEY_RESOURCE_PATTERN.test(transparencyKmsKeyResource)) {
    configurationError();
  }
  if (
    transparencyKeyCiphertextFile === keyBundleCiphertextFile ||
    transparencyKmsKeyResource === kmsKeyResource
  ) {
    configurationError();
  }
  const workloadIdentityProvider = boundedText(
    input.workloadIdentityProvider,
    1,
    512,
  );
  if (!WIP_PROVIDER_RESOURCE_PATTERN.test(workloadIdentityProvider)) {
    configurationError();
  }
  const transparencyStateProjectId = boundedText(
    input.transparencyStateProjectId,
    6,
    30,
  );
  if (!GOOGLE_PROJECT_ID_PATTERN.test(transparencyStateProjectId)) {
    configurationError();
  }
  const transparencyStateDatabaseId = boundedText(
    input.transparencyStateDatabaseId,
    4,
    63,
  );
  if (!FIRESTORE_DATABASE_ID_PATTERN.test(transparencyStateDatabaseId)) {
    configurationError();
  }
  const transparencyStateCollection = boundedText(
    input.transparencyStateCollection,
    3,
    63,
  );
  if (!FIRESTORE_COLLECTION_ID_PATTERN.test(transparencyStateCollection)) {
    configurationError();
  }
  const attestationAudience = httpsAudience(input.attestationAudience);
  const port = input.port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) configurationError();
  const attestationSocket =
    input.attestationSocket === null
      ? DEFAULT_ATTESTATION_SOCKET
      : absoluteFile(input.attestationSocket);
  return Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    releaseId,
    keyBundleCiphertextFile,
    kmsKeyResource,
    transparencyKeyCiphertextFile,
    transparencyKmsKeyResource,
    workloadIdentityProvider,
    transparencyStateProjectId,
    transparencyStateDatabaseId,
    transparencyStateCollection,
    attestationAudience,
    allowedOrigin: allowedOrigin(input.allowedOrigin),
    port,
    attestationSocket,
  });
}

export function normalizeImageDigest(value) {
  if (typeof value !== "string" || !IMAGE_DIGEST_PATTERN.test(value)) {
    configurationError();
  }
  return value;
}

export function bindAttestedImageDigest(config, value) {
  exactKeys(config, CONFIG_KEYS, configurationError);
  return Object.freeze({
    ...config,
    evaluatorMeasurement: normalizeImageDigest(value),
  });
}

export async function loadDeploymentConfig({
  runtimeEnvironment = process.env,
  filePath = runtimeEnvironment.HERD_DEPLOYMENT_CONFIG_FILE ?? DEFAULT_CONFIG_FILE,
  read = readFile,
} = {}) {
  rejectSecretEnvironment(runtimeEnvironment);
  if (typeof filePath !== "string" || !isAbsolute(filePath)) {
    configurationError();
  }
  let bytes;
  try {
    bytes = await read(filePath);
  } catch {
    configurationError();
  }
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  if (bytes.length === 0 || bytes.length > 32 * 1024) configurationError();
  let input;
  try {
    input = JSON.parse(bytes.toString("utf8"));
  } catch {
    configurationError();
  } finally {
    bytes.fill(0);
  }
  return normalizeDeploymentConfig(input);
}
