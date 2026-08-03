import assert from "node:assert/strict";
import test from "node:test";

import {
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_ID,
} from "../src/constants.mjs";
import { domainSeparatedBytes, sha256Base64Url } from "../src/encoding.mjs";
import { StatefulTransparencyAuthority } from "../src/transparency-authority.mjs";
import { FirestoreTransparencyStore } from "../src/transparency-store.mjs";
import { makeKeyStore, responseAuthorization } from "./helpers.mjs";

const PROJECT = "herd-key-test";
const DATABASE = "herd-transparency";
const COLLECTION = "herd_response_log_v1";
const TOKEN = "federated-firestore-test-token-with-safe-length";

function canonicalReceipt(keyStore, discriminator = 1) {
  const suffix = String(discriminator).padStart(12, "0");
  const envelopeId = `40000000-0000-4000-8000-${suffix}`;
  const eventId = `10000000-0000-4000-8000-${suffix}`;
  const inviteeId = `20000000-0000-4000-8000-${suffix}`;
  const policyHash = sha256Base64Url(Buffer.from(eventId, "utf8"));
  const accountKeyEpochId = `30000000-0000-4000-8000-${suffix}`;
  const ciphertextHash = Buffer.alloc(32, discriminator).toString("base64url");
  const authorization = responseAuthorization({
    protocolVersion: 1,
    eventId,
    inviteeId,
    policyHash,
    accountKeyEpochId,
    revision: 1,
    envelopeId,
    ciphertextHash,
  });
  const core = {
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    logIndex: 1,
    previousEntryHash: Buffer.alloc(32).toString("base64url"),
    envelopeId,
    eventId,
    inviteeId,
    policyHash,
    accountKeyEpochId,
    revision: 1,
    ciphertextHash,
    ...authorization,
    committedAt: `2026-01-01T00:00:${String(discriminator).padStart(2, "0")}.000Z`,
  };
  const entryHash = sha256Base64Url(
      domainSeparatedBytes(
        TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
        JSON.stringify(core),
      ),
    );
  return JSON.stringify({
    protocolVersion: core.protocolVersion,
    logId: core.logId,
    logIndex: core.logIndex,
    previousEntryHash: core.previousEntryHash,
    entryHash,
    envelopeId: core.envelopeId,
    eventId: core.eventId,
    inviteeId: core.inviteeId,
    policyHash: core.policyHash,
    accountKeyEpochId: core.accountKeyEpochId,
    revision: core.revision,
    ciphertextHash: core.ciphertextHash,
    responseSigningPublicKey: core.responseSigningPublicKey,
    responseSignature: core.responseSignature,
    committedAt: core.committedAt,
    signingKeyId: keyStore.metadata.keys.transparencySigning.keyId,
  });
}

class FakeFirestore {
  constructor() {
    this.documents = new Map();
    this.version = 0;
    this.requests = [];
    this.loseNextCommitResponse = false;
    this.deleteProtectionState = "DELETE_PROTECTION_ENABLED";
    this.pointInTimeRecoveryEnablement = "POINT_IN_TIME_RECOVERY_ENABLED";
  }

  #response(body, status = 200) {
    return new Response(body === null ? null : JSON.stringify(body), {
      status,
      headers: body === null ? {} : { "content-type": "application/json" },
    });
  }

  fetch = async (rawUrl, options) => {
    const url = new URL(rawUrl);
    this.requests.push({ url: url.href, options: structuredClone(options) });
    assert.equal(options.headers.authorization, `Bearer ${TOKEN}`);
    const resource = decodeURIComponent(url.pathname.slice("/v1/".length));
    if (options.method === "GET") {
      if (resource === `projects/${PROJECT}/databases/${DATABASE}`) {
        return this.#response({
          name: resource,
          type: "FIRESTORE_NATIVE",
          deleteProtectionState: this.deleteProtectionState,
          pointInTimeRecoveryEnablement: this.pointInTimeRecoveryEnablement,
        });
      }
      const document = this.documents.get(resource);
      return document ? this.#response(document) : this.#response(null, 404);
    }
    assert.equal(
      resource,
      `projects/${PROJECT}/databases/${DATABASE}/documents:commit`,
    );
    const body = JSON.parse(options.body);
    assert.ok(body.writes.length >= 1 && body.writes.length <= 4);

    for (const write of body.writes) {
      const current = this.documents.get(write.update.name);
      if (write.currentDocument.exists === false && current) {
        return this.#response({ error: { status: "ALREADY_EXISTS" } }, 409);
      }
      if (
        write.currentDocument.updateTime !== undefined &&
        current?.updateTime !== write.currentDocument.updateTime
      ) {
        return this.#response({ error: { status: "FAILED_PRECONDITION" } }, 412);
      }
    }

    this.version += 1;
    const updateTime = `2026-01-01T00:00:${String(this.version).padStart(2, "0")}.000000Z`;
    for (const write of body.writes) {
      const current = this.documents.get(write.update.name);
      this.documents.set(write.update.name, {
        name: write.update.name,
        fields: structuredClone(write.update.fields),
        createTime: current?.createTime ?? updateTime,
        updateTime,
      });
    }
    if (this.loseNextCommitResponse) {
      this.loseNextCommitResponse = false;
      throw new TypeError("response lost after commit");
    }
    return this.#response({ writeResults: [], commitTime: updateTime });
  };
}

function store(service) {
  return new FirestoreTransparencyStore({
    projectId: PROJECT,
    databaseId: DATABASE,
    collectionId: COLLECTION,
    accessTokenProvider: { async getAccessToken() { return TOKEN; } },
    fetchImplementation: service.fetch,
  });
}

function authority(service, keyStore) {
  return new StatefulTransparencyAuthority({
    store: store(service),
    keyStore,
    clock: () => new Date("2026-01-01T00:00:10.000Z"),
  });
}

async function registerPolicy(signer, keyStore, payload) {
  const receipt = JSON.parse(payload);
  await signer.freezePolicy({
    protocolVersion: 1,
    eventId: receipt.eventId,
    policyHash: sha256Base64Url(Buffer.from(receipt.eventId, "utf8")),
    rsvpDeadline: "2026-12-01T00:00:00.000Z",
    memberIds: [receipt.inviteeId],
    releaseId: keyStore.metadata.releaseId,
    evaluatorKeyId: keyStore.metadata.keys.responseDecryption.keyId,
  });
}

test("Firestore commits tail, entry, policy sequence, and authenticated member in one CAS", async () => {
  const service = new FakeFirestore();
  const keyStore = await makeKeyStore();
  const signer = authority(service, keyStore);
  assert.equal(await signer.checkReady(), true);
  const payload = canonicalReceipt(keyStore);
  await registerPolicy(signer, keyStore, payload);
  const result = await signer.append(payload);
  const commit = service.requests.find(
    ({ options }) =>
      options.method === "POST" && JSON.parse(options.body).writes.length === 4,
  );
  const writes = JSON.parse(commit.options.body).writes;

  assert.equal(result.kind, "append");
  assert.equal(writes.length, 4);
  assert.equal(service.documents.size, 4);
  assert.deepEqual(writes.map((write) => write.currentDocument), [
    { exists: false },
    { exists: false },
    { updateTime: writes[2].currentDocument.updateTime },
    { exists: false },
  ]);
  assert.ok(
    writes.every((write) =>
      write.update.name.startsWith(
        `projects/${PROJECT}/databases/${DATABASE}/documents/`,
      )),
  );
  const serialized = JSON.stringify(writes);
  assert.equal(serialized.includes("Confidential test"), false);
  assert.equal(serialized.includes("locationAddress"), false);
  assert.deepEqual(Object.keys(writes[2].update.fields).sort(), [
    "evaluatedAt",
    "evaluationBatchHash",
    "evaluatorKeyId",
    "eventId",
    "memberIdsJson",
    "policyHash",
    "protocolVersion",
    "releaseId",
    "responseSequence",
    "rsvpDeadline",
  ]);
  assert.deepEqual(Object.keys(writes[3].update.fields).sort(), [
    "accountKeyEpochId",
    "ciphertextHash",
    "committedAt",
    "entryHash",
    "envelopeId",
    "eventId",
    "inviteeId",
    "logIndex",
    "protocolVersion",
    "responseSigningPublicKey",
    "revision",
  ]);
  assert.ok(
    service.requests.some(
      ({ url, options }) =>
        options.method === "GET" &&
        decodeURIComponent(new URL(url).pathname).endsWith(
          `projects/${PROJECT}/databases/${DATABASE}`,
        ),
    ),
  );
});

test("a response lost after Firestore commit returns the stored signatures", async () => {
  const service = new FakeFirestore();
  const keyStore = await makeKeyStore();
  const payload = canonicalReceipt(keyStore);
  await registerPolicy(authority(service, keyStore), keyStore, payload);
  service.loseNextCommitResponse = true;
  const first = await authority(service, keyStore).append(payload);
  const restarted = await authority(service, keyStore).append(payload);

  assert.equal(JSON.stringify(restarted), JSON.stringify(first));
  assert.equal(service.documents.size, 4);
  assert.equal(
    service.requests.filter(
      ({ options }) =>
        options.method === "POST" && JSON.parse(options.body).writes.length === 4,
    ).length,
    1,
  );
});

test("replicas racing different same-size heads can commit only one", async () => {
  const service = new FakeFirestore();
  const keyStore = await makeKeyStore();
  const replicas = Array.from({ length: 20 }, () => authority(service, keyStore));
  const payloads = replicas.map((_, index) =>
    canonicalReceipt(keyStore, index + 1),
  );
  await Promise.all(
    payloads.map((payload, index) =>
      registerPolicy(replicas[index], keyStore, payload),
    ),
  );
  const results = await Promise.allSettled(
    replicas.map((replica, index) => replica.append(payloads[index])),
  );

  assert.equal(results.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(results.filter((result) => result.status === "rejected").length, 19);
  assert.equal(service.documents.size, 23);
  const successfulCommits = service.requests.filter(
    ({ options }) =>
      options.method === "POST" && JSON.parse(options.body).writes.length === 4,
  );
  assert.ok(successfulCommits.length >= 1);
});

test("readiness fails if the custodian database loses delete protection or PITR", async () => {
  const keyStore = await makeKeyStore();
  for (const mutation of [
    (service) => { service.deleteProtectionState = "DELETE_PROTECTION_DISABLED"; },
    (service) => { service.pointInTimeRecoveryEnablement = "POINT_IN_TIME_RECOVERY_DISABLED"; },
  ]) {
    const service = new FakeFirestore();
    mutation(service);
    await assert.rejects(
      authority(service, keyStore).checkReady(),
      (error) => error?.status === 503 && error?.code === "service_unavailable",
    );
  }
});
