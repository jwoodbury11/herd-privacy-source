import http from "node:http";

import {
  GOOGLE_KMS_ENDPOINT,
  GOOGLE_STS_AUDIENCE,
  GOOGLE_STS_ENDPOINT,
  IMAGE_DIGEST_PATTERN,
} from "./constants.mjs";
import { crc32c } from "./crc32c.mjs";
import { ConfigurationError } from "./errors.mjs";

const MAXIMUM_TOKEN_BYTES = 64 * 1024;
const MAXIMUM_BUNDLE_BYTES = 64 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;
const JWT_PATTERN = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u;

function fail() {
  throw new ConfigurationError("confidential provider request failed");
}

function canonicalBase64(value, maximumBytes) {
  if (typeof value !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) {
    fail();
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64");
  } catch {
    fail();
  }
  if (
    bytes.length === 0 ||
    bytes.length > maximumBytes ||
    bytes.toString("base64") !== value
  ) {
    bytes.fill(0);
    fail();
  }
  return bytes;
}

function assertJwt(value) {
  const token = value.trim();
  if (token.length > MAXIMUM_TOKEN_BYTES || !JWT_PATTERN.test(token)) fail();
  return token;
}

function record(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail();
  return value;
}

export function attestedImageDigestFromOidcToken(token) {
  const normalized = assertJwt(token);
  const payloadSegment = normalized.split(".")[1];
  let bytes;
  let payload;
  try {
    bytes = Buffer.from(payloadSegment, "base64url");
    if (
      bytes.length === 0 ||
      bytes.length > MAXIMUM_TOKEN_BYTES ||
      bytes.toString("base64url") !== payloadSegment
    ) {
      fail();
    }
    payload = JSON.parse(
      new TextDecoder("utf-8", { fatal: true }).decode(bytes),
    );
  } catch (error) {
    if (error instanceof ConfigurationError) throw error;
    fail();
  } finally {
    bytes?.fill(0);
  }
  const claims = record(payload);
  const submods = record(claims.submods);
  const container = record(submods.container);
  const confidentialSpace = record(submods.confidential_space);
  const monitoring = record(confidentialSpace.monitoring_enabled);
  const digest = container.image_digest;
  if (typeof digest !== "string" || !IMAGE_DIGEST_PATTERN.test(digest)) fail();
  if (
    claims.aud !== GOOGLE_STS_AUDIENCE ||
    claims.iss !== "https://confidentialcomputing.googleapis.com" ||
    claims.swname !== "CONFIDENTIAL_SPACE" ||
    claims.dbgstat !== "disabled-since-boot" ||
    claims.secboot !== true ||
    claims.hwmodel !== "GCP_INTEL_TDX" ||
    !Array.isArray(claims.attester_tcb) ||
    claims.attester_tcb.length !== 1 ||
    claims.attester_tcb[0] !== "INTEL" ||
    !Array.isArray(confidentialSpace.support_attributes) ||
    !confidentialSpace.support_attributes.includes("STABLE") ||
    !Array.isArray(container.cmd_override) ||
    container.cmd_override.length !== 0 ||
    Object.keys(record(container.env_override)).length !== 0 ||
    container.restart_policy !== "Always" ||
    monitoring.memory !== false ||
    Object.keys(monitoring).length !== 1
  ) {
    fail();
  }
  return digest;
}

export function postLauncherToken({
  socketPath,
  audience,
  tokenType,
  nonces,
  request = http.request,
}) {
  const body = Buffer.from(
    JSON.stringify({
      audience,
      token_type: tokenType,
      ...(nonces === undefined ? {} : { nonces }),
    }),
    "utf8",
  );
  return new Promise((resolve, reject) => {
    const operation = request(
      {
        socketPath,
        path: "/v1/token",
        method: "POST",
        headers: {
          host: "localhost",
          "content-type": "application/json",
          "content-length": String(body.length),
        },
        timeout: REQUEST_TIMEOUT_MS,
      },
      (response) => {
        const chunks = [];
        let length = 0;
        response.on("data", (chunk) => {
          length += chunk.length;
          if (length > MAXIMUM_TOKEN_BYTES) {
            response.destroy();
            return;
          }
          chunks.push(chunk);
        });
        response.on("end", () => {
          if (response.statusCode !== 200 || length === 0) {
            reject(new ConfigurationError("attestation launcher rejected request"));
            return;
          }
          try {
            resolve(assertJwt(Buffer.concat(chunks).toString("utf8")));
          } catch (error) {
            reject(error);
          }
        });
        response.on("error", reject);
      },
    );
    operation.on("timeout", () => operation.destroy(new Error("timeout")));
    operation.on("error", () => reject(new ConfigurationError("attestation launcher unavailable")));
    operation.end(body);
  });
}

async function checkedJsonResponse(response, maximumBytes = 64 * 1024) {
  if (!response || response.status !== 200) fail();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > maximumBytes) fail();
  let parsed;
  try {
    parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    fail();
  } finally {
    bytes.fill(0);
  }
  return parsed;
}

async function exchangeAttestedAccessToken({
  socketPath,
  workloadIdentityProvider,
  expectedImageDigest = null,
  fetchImplementation,
  launcherRequest,
}) {
  let subjectToken = await postLauncherToken({
    socketPath,
    audience: GOOGLE_STS_AUDIENCE,
    tokenType: "OIDC",
    request: launcherRequest,
  });
  const imageDigest = attestedImageDigestFromOidcToken(subjectToken);
  if (expectedImageDigest !== null && imageDigest !== expectedImageDigest) fail();
  const form = new URLSearchParams({
    audience: `//iam.googleapis.com/${workloadIdentityProvider}`,
    grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
    requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
    scope: "https://www.googleapis.com/auth/cloud-platform",
    subject_token_type: "urn:ietf:params:oauth:token-type:jwt",
    subject_token: subjectToken,
  });
  let response;
  try {
    response = await fetchImplementation(GOOGLE_STS_ENDPOINT, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: form,
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch {
    fail();
  } finally {
    subjectToken = "";
    form.set("subject_token", "");
  }
  const value = await checkedJsonResponse(response);
  if (
    !value ||
    typeof value !== "object" ||
    typeof value.access_token !== "string" ||
    value.access_token.length < 20 ||
    value.access_token.length > MAXIMUM_TOKEN_BYTES ||
    value.token_type !== "Bearer" ||
    !Number.isInteger(value.expires_in) ||
    value.expires_in < 60 ||
    value.expires_in > 3600
  ) {
    fail();
  }
  return {
    accessToken: value.access_token,
    expiresIn: value.expires_in,
    imageDigest,
  };
}

export class GoogleKmsBundleDecryptor {
  #attestedImageDigest = null;

  constructor({
    socketPath,
    workloadIdentityProvider,
    kmsKeyResource,
    fetchImplementation = globalThis.fetch,
    launcherRequest = http.request,
  }) {
    this.socketPath = socketPath;
    this.workloadIdentityProvider = workloadIdentityProvider;
    this.kmsKeyResource = kmsKeyResource;
    this.fetch = fetchImplementation;
    this.launcherRequest = launcherRequest;
  }

  async decrypt(ciphertext) {
    if (!(ciphertext instanceof Uint8Array) || ciphertext.length === 0) fail();
    if (ciphertext.length > MAXIMUM_BUNDLE_BYTES) fail();
    if (this.#attestedImageDigest !== null) fail();
    const federated = await exchangeAttestedAccessToken({
      socketPath: this.socketPath,
      workloadIdentityProvider: this.workloadIdentityProvider,
      fetchImplementation: this.fetch,
      launcherRequest: this.launcherRequest,
    });
    const ciphertextBytes = Buffer.from(ciphertext);
    let kmsResponse;
    try {
      kmsResponse = await this.fetch(
        `${GOOGLE_KMS_ENDPOINT}/${this.kmsKeyResource}:decrypt`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${federated.accessToken}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            ciphertext: ciphertextBytes.toString("base64"),
            ciphertextCrc32c: String(crc32c(ciphertextBytes)),
          }),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        },
      );
    } catch {
      fail();
    } finally {
      ciphertextBytes.fill(0);
      federated.accessToken = "";
    }
    const kms = await checkedJsonResponse(kmsResponse, MAXIMUM_BUNDLE_BYTES * 2);
    if (
      !kms ||
      typeof kms !== "object" ||
      typeof kms.plaintext !== "string" ||
      typeof kms.plaintextCrc32c !== "string" ||
      !/^[0-9]{1,10}$/u.test(kms.plaintextCrc32c)
    ) {
      fail();
    }
    const plaintext = canonicalBase64(kms.plaintext, MAXIMUM_BUNDLE_BYTES);
    if (String(crc32c(plaintext)) !== kms.plaintextCrc32c) {
      plaintext.fill(0);
      fail();
    }
    const result = Uint8Array.from(plaintext);
    plaintext.fill(0);
    kms.plaintext = "";
    // This is the exact claim from the subject token that Google STS accepted
    // and that authorized the successful KMS decrypt. Do not expose it before
    // both operations have completed.
    this.#attestedImageDigest = federated.imageDigest;
    return result;
  }

  getAttestedImageDigest() {
    if (
      typeof this.#attestedImageDigest !== "string" ||
      !IMAGE_DIGEST_PATTERN.test(this.#attestedImageDigest)
    ) {
      fail();
    }
    return this.#attestedImageDigest;
  }
}

export class ConfidentialSpaceFederatedAccessTokenProvider {
  #cached = null;
  #refresh = null;

  constructor({
    socketPath,
    workloadIdentityProvider,
    expectedImageDigest,
    fetchImplementation = globalThis.fetch,
    launcherRequest = http.request,
    clock = () => Date.now(),
  }) {
    if (
      typeof expectedImageDigest !== "string" ||
      !IMAGE_DIGEST_PATTERN.test(expectedImageDigest)
    ) {
      fail();
    }
    this.socketPath = socketPath;
    this.workloadIdentityProvider = workloadIdentityProvider;
    this.expectedImageDigest = expectedImageDigest;
    this.fetch = fetchImplementation;
    this.launcherRequest = launcherRequest;
    this.clock = clock;
  }

  async #renew() {
    const value = await exchangeAttestedAccessToken({
      socketPath: this.socketPath,
      workloadIdentityProvider: this.workloadIdentityProvider,
      expectedImageDigest: this.expectedImageDigest,
      fetchImplementation: this.fetch,
      launcherRequest: this.launcherRequest,
    });
    const cached = {
      accessToken: value.accessToken,
      // Refresh at least sixty seconds before STS expiry. Short-lived tokens
      // are rejected by exchangeAttestedAccessToken, so this remains positive.
      refreshAt: this.clock() + (value.expiresIn - 60) * 1000,
    };
    this.#cached = cached;
    return cached.accessToken;
  }

  async getAccessToken() {
    if (this.#cached && this.clock() < this.#cached.refreshAt) {
      return this.#cached.accessToken;
    }
    if (!this.#refresh) this.#refresh = this.#renew();
    try {
      return await this.#refresh;
    } finally {
      this.#refresh = null;
    }
  }
}

export class ConfidentialSpaceAttestationProvider {
  constructor({ socketPath, launcherRequest = http.request }) {
    this.socketPath = socketPath;
    this.launcherRequest = launcherRequest;
  }

  async attest({ audience, nonces }) {
    return postLauncherToken({
      socketPath: this.socketPath,
      audience,
      tokenType: "PKI",
      nonces,
      request: this.launcherRequest,
    });
  }
}
