import {
  generateKeyPairSync,
  sign as nodeSign,
  webcrypto,
} from "node:crypto";

import {
  bindAttestedImageDigest,
  normalizeDeploymentConfig,
} from "../src/config.mjs";
import { crc32c } from "../src/crc32c.mjs";
import { parseKeyBundles } from "../src/key-bundle.mjs";

export const TOKEN = "test-confidential-evaluator-token-0000000000000001";
export const TEST_IMAGE_DIGEST =
  "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
export const EVENT_ID = "10000000-0000-4000-8000-000000000001";
export const INVITEE_ID = "20000000-0000-4000-8000-000000000001";

export function makeTestResponseSigningIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicDer = publicKey.export({ type: "spki", format: "der" });
  return {
    privateKey,
    publicKey: Buffer.from(publicDer.subarray(publicDer.length - 32)).toString(
      "base64url",
    ),
  };
}

export const TEST_RESPONSE_SIGNING_IDENTITY =
  makeTestResponseSigningIdentity();

export function responseAuthorization(
  value,
  identity = TEST_RESPONSE_SIGNING_IDENTITY,
) {
  const canonicalDocument = JSON.stringify({
    protocolVersion: value.protocolVersion,
    eventId: value.eventId,
    inviteeId: value.inviteeId,
    policyHash: value.policyHash,
    accountKeyEpochId: value.accountKeyEpochId,
    revision: value.revision,
    envelopeId: value.envelopeId,
    ciphertextHash: value.ciphertextHash,
    responseSigningPublicKey: identity.publicKey,
  });
  return {
    responseSigningPublicKey: identity.publicKey,
    responseSignature: nodeSign(
      null,
      Buffer.from(`HERD-RESPONSE-AUTHORIZATION-V1\0${canonicalDocument}`, "utf8"),
      identity.privateKey,
    ).toString("base64url"),
  };
}

export class InMemoryTransparencyStore {
  #entries = new Map();
  #state = null;
  #policies = new Map();
  #members = new Map();
  #version = 0;
  #lock = Promise.resolve();

  async #exclusive(operation) {
    const previous = this.#lock;
    let release;
    this.#lock = new Promise((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      return operation();
    } finally {
      release();
    }
  }

  #versionToken() {
    this.#version += 1;
    return `memory-version-${this.#version}`;
  }

  #memberKey(eventId, inviteeId) {
    return `${eventId}\0${inviteeId}`;
  }

  async readEntry(logIndex) {
    const entry = this.#entries.get(logIndex);
    return entry ? structuredClone(entry) : null;
  }

  async checkAvailable() {
    return true;
  }

  async readState() {
    return this.#state ? structuredClone(this.#state) : null;
  }

  async readPolicy(eventId) {
    const policy = this.#policies.get(eventId);
    return policy ? structuredClone(policy) : null;
  }

  async readMember(eventId, inviteeId) {
    const member = this.#members.get(this.#memberKey(eventId, inviteeId));
    return member ? structuredClone(member) : null;
  }

  async createPolicy(policy) {
    return this.#exclusive(() => {
      if (this.#policies.has(policy.eventId)) return false;
      this.#policies.set(policy.eventId, {
        ...structuredClone(policy),
        versionToken: this.#versionToken(),
      });
      return true;
    });
  }

  async commitTransition({ expectedStateVersion, entry, state }) {
    return this.#exclusive(() => {
      const actualVersion = this.#state?.versionToken ?? null;
      if (
        actualVersion !== expectedStateVersion ||
        this.#entries.has(entry.logIndex)
      ) {
        return false;
      }
      const versionToken = this.#versionToken();
      this.#entries.set(entry.logIndex, structuredClone(entry));
      this.#state = {
        ...structuredClone(state),
        versionToken,
      };
      return true;
    });
  }

  async commitResponseTransition({
    expectedStateVersion,
    expectedPolicyVersion,
    expectedMemberVersion,
    entry,
    state,
    policy,
    member,
  }) {
    return this.#exclusive(() => {
      const policyValue = this.#policies.get(policy.eventId);
      const memberKey = this.#memberKey(policy.eventId, member.inviteeId);
      const memberValue = this.#members.get(memberKey);
      if (
        (this.#state?.versionToken ?? null) !== expectedStateVersion ||
        policyValue?.versionToken !== expectedPolicyVersion ||
        (memberValue?.versionToken ?? null) !== expectedMemberVersion ||
        this.#entries.has(entry.logIndex)
      ) {
        return false;
      }
      const versionToken = this.#versionToken();
      this.#entries.set(entry.logIndex, structuredClone(entry));
      this.#state = { ...structuredClone(state), versionToken };
      this.#policies.set(policy.eventId, {
        ...structuredClone(policy),
        versionToken,
      });
      this.#members.set(memberKey, {
        ...structuredClone(member),
        versionToken,
      });
      return true;
    });
  }

  async commitEvaluation({ expectedPolicyVersion, policy }) {
    return this.#exclusive(() => {
      const existing = this.#policies.get(policy.eventId);
      if (existing?.versionToken !== expectedPolicyVersion) return false;
      this.#policies.set(policy.eventId, {
        ...structuredClone(policy),
        versionToken: this.#versionToken(),
      });
      return true;
    });
  }

  snapshot() {
    return {
      state: this.#state ? structuredClone(this.#state) : null,
      entries: [...this.#entries.values()].map((entry) => structuredClone(entry)),
      policies: [...this.#policies.values()].map((policy) => structuredClone(policy)),
      members: [...this.#members.values()].map((member) => structuredClone(member)),
    };
  }
}

export function testDeploymentConfig(overrides = {}) {
  return normalizeDeploymentConfig({
    protocolVersion: 1,
    releaseId: "herd-confidential-test-v1",
    keyBundleCiphertextFile: "/test/key-bundle.ciphertext",
    kmsKeyResource:
      "projects/herd-key-test/locations/us-central1/keyRings/herd-evaluator/cryptoKeys/key-bundle",
    transparencyKeyCiphertextFile: "/test/transparency-key.ciphertext",
    transparencyKmsKeyResource:
      "projects/herd-key-test/locations/us-central1/keyRings/herd-evaluator/cryptoKeys/response-transparency-identity",
    workloadIdentityProvider:
      "projects/123456789012/locations/global/workloadIdentityPools/herd-evaluator/providers/google-attestation",
    transparencyStateProjectId: "herd-key-test",
    transparencyStateDatabaseId: "herd-transparency",
    transparencyStateCollection: "herd_response_log_v1",
    attestationAudience: "https://herd.example/evaluator-attestation/v1",
    allowedOrigin: "https://app.herd.example",
    port: 8080,
    attestationSocket: "/test/teeserver.sock",
    ...overrides,
  });
}

export function testConfig(overrides = {}) {
  return bindAttestedImageDigest(
    testDeploymentConfig(overrides),
    TEST_IMAGE_DIGEST,
  );
}

async function privateJwk(algorithm, usages) {
  const pair = await webcrypto.subtle.generateKey(
    { name: algorithm, namedCurve: "P-256" },
    true,
    usages,
  );
  const exported = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  return {
    kty: "EC",
    crv: "P-256",
    x: exported.x,
    y: exported.y,
    d: exported.d,
  };
}

export async function makeBundle(overrides = {}) {
  const responseDecryptionKey = {
    keyId: "response-decryption-test-v1",
    privateKeyJwk: await privateJwk("ECDH", ["deriveBits"]),
  };
  const evaluationResultSigningKey = {
    keyId: "evaluation-signing-test-v1",
    privateKeyJwk: await privateJwk("ECDSA", ["sign", "verify"]),
  };
  const policySigningKey = {
    keyId: "policy-signing-test-v1",
    privateKeyJwk: await privateJwk("ECDSA", ["sign", "verify"]),
  };
  return {
    protocolVersion: 1,
    releaseId: "herd-confidential-test-v1",
    requestAuthenticationToken: TOKEN,
    responseDecryptionKey,
    evaluationResultSigningKey,
    policySigningKey,
    ...overrides,
  };
}

export async function makeTransparencyBundle(overrides = {}) {
  return {
    protocolVersion: 1,
    logId: "herd-response-log-v1",
    transparencySigningKey: {
      keyId: "transparency-signing-test-v1",
      privateKeyJwk: await privateJwk("ECDSA", ["sign", "verify"]),
    },
    ...overrides,
  };
}

export async function makeKeyStore(config = testConfig(), overrides = {}) {
  const bundle = await makeBundle(overrides);
  const transparencyBundle = await makeTransparencyBundle();
  return parseKeyBundles(
    Uint8Array.from(Buffer.from(JSON.stringify(bundle), "utf8")),
    Uint8Array.from(
      Buffer.from(JSON.stringify(transparencyBundle), "utf8"),
    ),
    config,
    config.evaluatorMeasurement,
  );
}

export function authHeaders(extra = {}) {
  return {
    authorization: `Bearer ${TOKEN}`,
    "content-type": "application/json",
    ...extra,
  };
}

export function publicKeyFromMetadata(metadata) {
  return webcrypto.subtle.importKey(
    "raw",
    Buffer.from(metadata.publicKey, "base64url"),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"],
  );
}

export function canonicalPolicyDocument(config, keyStore) {
  return JSON.stringify({
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    event: {
      id: EVENT_ID,
      title: "Confidential test",
      eventDate: "2026-12-01T18:00:00.000Z",
      endDate: null,
      hostName: "Host",
      locationName: "",
      locationAddress: "",
      eventDescription: "",
    },
    members: [{ id: INVITEE_ID }],
    hostRules: { minimumParticipants: 2, requiredGroups: [] },
    rsvpDeadline: "2026-01-01T00:00:00.000Z",
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits: {
      maximumParticipants: 2,
      maximumConditionGroups: 1,
      maximumMembersPerGroup: 1,
      paddedPlaintextBytes: 4096,
    },
    evaluator: {
      keyId: keyStore.metadata.keys.responseDecryption.keyId,
      publicKey: keyStore.metadata.keys.responseDecryption.publicKey,
      measurement: config.evaluatorMeasurement,
    },
    releaseId: config.releaseId,
  });
}

export async function evaluationRequest(config, keyStore) {
  const canonicalDocument = canonicalPolicyDocument(config, keyStore);
  const policyHash = Buffer.from(
    await webcrypto.subtle.digest("SHA-256", Buffer.from(canonicalDocument)),
  ).toString("base64url");
  const slots = [{ inviteeId: INVITEE_ID, envelopeHash: null, envelope: null }];
  const batchCommitment = JSON.stringify({
    protocolVersion: 1,
    eventId: EVENT_ID,
    policyHash,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({ inviteeId, envelopeHash })),
  });
  const batchHash = Buffer.from(
    await webcrypto.subtle.digest("SHA-256", Buffer.from(batchCommitment)),
  ).toString("base64url");
  return {
    protocolVersion: 1,
    eventId: EVENT_ID,
    policy: {
      protocolVersion: 1,
      cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
      policyHash,
      canonicalDocument,
      evaluatorKeyId: keyStore.metadata.keys.responseDecryption.keyId,
      evaluatorPublicKey: keyStore.metadata.keys.responseDecryption.publicKey,
      evaluatorMeasurement: config.evaluatorMeasurement,
      releaseId: config.releaseId,
      paddedPlaintextBytes: 4096,
      frozenAt: "2025-11-01T18:00:00.000Z",
    },
    batchHash,
    slots,
  };
}

export function kmsPlaintextResponse(bytes) {
  return {
    plaintext: Buffer.from(bytes).toString("base64"),
    plaintextCrc32c: String(crc32c(bytes)),
  };
}
