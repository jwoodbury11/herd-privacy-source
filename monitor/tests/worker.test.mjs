import assert from "node:assert/strict";
import { sign as cryptoSign } from "node:crypto";
import test from "node:test";

import { makeReleaseFixture } from "../../release/tests/fixture.mjs";
import {
  assertReleaseContinuity,
  ReleaseMonitorCoordinator,
  runChecks,
} from "../src/worker.mjs";

const LOG_ID = "herd-response-log-v1";
const LOG_HEAD_DOMAIN = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const GENESIS_HASH = Buffer.alloc(32).toString("base64url");

function logEntry(index, previousEntryHash, entryHash, keyPair) {
  const unsignedHead = {
    protocolVersion: 1,
    logId: LOG_ID,
    treeSize: index,
    headEntryHash: entryHash,
    generatedAt: `2026-08-02T00:00:0${index}.000Z`,
    signingKeyId: keyPair.descriptor.keyId,
  };
  const signature = cryptoSign(
    "sha256",
    Buffer.from(`${LOG_HEAD_DOMAIN}\0${JSON.stringify(unsignedHead)}`),
    { key: keyPair.privatePem, dsaEncoding: "ieee-p1363" },
  ).toString("base64url");
  return {
    logIndex: index,
    previousEntryHash,
    entryHash,
    head: { ...unsignedHead, signature },
  };
}

function fixtureWithLog() {
  // Worker concurrency/witness tests exercise the staging path. Production
  // live-attestation cryptography is covered independently in attestation.test.
  const fixture = makeReleaseFixture({ releaseStage: "candidate" });
  const hashes = [1, 2, 3].map((value) => Buffer.alloc(32, value).toString("base64url"));
  const entries = [
    logEntry(1, GENESIS_HASH, hashes[0], fixture.keys.receiptTransparencySigning),
    logEntry(2, hashes[0], hashes[1], fixture.keys.receiptTransparencySigning),
    logEntry(3, hashes[1], hashes[2], fixture.keys.receiptTransparencySigning),
  ];
  const url = "https://app.herd.example/api/transparency/responses";
  fixture.target.responseTransparency = {
    url,
    logId: LOG_ID,
    signingKey: fixture.keys.receiptTransparencySigning.descriptor,
  };
  const page = (items) => {
    const bytes = Buffer.from(JSON.stringify({ protocolVersion: 1, logId: LOG_ID, entries: items }));
    return { bytes, mediaType: "application/json" };
  };
  fixture.responses.set(`${url}?after=0&limit=500`, page(entries));
  fixture.responses.set(`${url}?after=2&limit=500`, page([entries[2]]));
  return { fixture, url, hashes, entries, page };
}

function response(record, status = 200) {
  if (status !== 200) return new Response("unavailable", { status });
  return new Response(record.bytes, {
    status,
    headers: {
      "content-type": record.mediaType,
      "content-length": String(record.bytes.byteLength),
    },
  });
}

class MemoryStorage {
  constructor() {
    this.values = new Map();
  }

  async get(key) {
    return this.values.get(key);
  }

  async transaction(callback) {
    return callback({
      put: async (key, value) => {
        this.values.set(key, structuredClone(value));
      },
    });
  }
}

class MemoryStore {
  constructor() {
    this.status = null;
    this.witnesses = new Map();
  }

  async getStatus() {
    return this.status;
  }

  async getWitness(name) {
    return this.witnesses.get(name) ?? null;
  }

  async commit(status, witnesses) {
    this.status = structuredClone(status);
    for (const witness of witnesses) this.witnesses.set(witness.target, structuredClone(witness));
  }
}

function memoryKv() {
  const values = new Map();
  return {
    values,
    async put(key, value) {
      values.set(key, value);
    },
  };
}

function environment(fixture) {
  return {
    TARGETS_JSON: JSON.stringify([fixture.target]),
    STATUS_KV: memoryKv(),
  };
}

function epochWitness(overrides = {}) {
  return {
    evaluatorKeyEpochId: "herd-evaluator-epoch-2026.08",
    sha256: "10".repeat(32),
    workloadImageDigest: `sha256:${"11".repeat(32)}`,
    responseDecryption: {
      keyId: "response-decryption-2026",
      publicKeySha256: "12".repeat(32),
    },
    evaluationResultSigning: {
      keyId: "result-signing-2026",
      publicKeySha256: "13".repeat(32),
    },
    policySigning: {
      keyId: "policy-signing-2026",
      publicKeySha256: "14".repeat(32),
    },
    responseTransparency: {
      logId: LOG_ID,
      keyId: "receipt-signing-lifetime",
      publicKeySha256: "15".repeat(32),
    },
    ...overrides,
  };
}

test("release witness rejects predecessor, epoch tuple, and global transparency drift", () => {
  const previous = {
    releaseId: "2026.08.02.1",
    manifestSha256: "20".repeat(32),
    evaluatorKeyEpoch: epochWitness(),
  };
  const next = {
    releaseId: "2026.08.02.2",
    manifestSha256: "21".repeat(32),
    previousRelease: {
      releaseId: previous.releaseId,
      manifestSha256: previous.manifestSha256,
    },
    evaluatorKeyEpoch: epochWitness(),
  };
  assert.doesNotThrow(() => assertReleaseContinuity(previous, next));

  const wrongPredecessor = structuredClone(next);
  wrongPredecessor.previousRelease.manifestSha256 = "22".repeat(32);
  assert.throws(
    () => assertReleaseContinuity(previous, wrongPredecessor),
    /exact last witnessed release manifest/u,
  );

  const sameEpochDrift = structuredClone(next);
  sameEpochDrift.evaluatorKeyEpoch.sha256 = "23".repeat(32);
  assert.throws(
    () => assertReleaseContinuity(previous, sameEpochDrift),
    /existing evaluator epoch changed/u,
  );

  const transparencyDrift = structuredClone(next);
  transparencyDrift.evaluatorKeyEpoch.responseTransparency.keyId =
    "receipt-signing-rotated";
  assert.throws(
    () => assertReleaseContinuity(previous, transparencyDrift),
    /lifetime-global response-transparency signing identity changed/u,
  );
});

test("production configuration requires STATUS_KV and response transparency", async () => {
  const fixture = makeReleaseFixture();
  const store = new MemoryStore();
  let result = await runChecks({ TARGETS_JSON: JSON.stringify([fixture.target]) }, store);
  assert.equal(result.ok, false);
  assert.match(result.configurationError, /STATUS_KV is required/u);

  result = await runChecks({ TARGETS_JSON: JSON.stringify([fixture.target]), STATUS_KV: memoryKv() }, store);
  assert.equal(result.ok, false);
  assert.match(result.configurationError, /requires responseTransparency/u);

  fixture.target.responseTransparency = {
    url: "https://app.herd.example/api/transparency/responses",
    logId: LOG_ID,
    signingKey: fixture.keys.receiptTransparencySigning.descriptor,
  };
  delete fixture.target.evaluatorAttestation;
  result = await runChecks(
    { TARGETS_JSON: JSON.stringify([fixture.target]), STATUS_KV: memoryKv() },
    store,
  );
  assert.equal(result.ok, false);
  assert.match(result.configurationError, /requires evaluatorAttestation/u);
});

test("last-good response/deployment witness survives 503 and rejects the following signed fork", async () => {
  const { fixture, url, hashes, entries, page } = fixtureWithLog();
  const storage = new MemoryStorage();
  const env = environment(fixture);
  const coordinator = new ReleaseMonitorCoordinator({ storage }, env);
  const originalFetch = globalThis.fetch;
  let mode = "good";
  const forkHash = Buffer.alloc(32, 9).toString("base64url");
  const fork = logEntry(3, hashes[1], forkHash, fixture.keys.receiptTransparencySigning);
  globalThis.fetch = async (input) => {
    const requestUrl = String(input);
    if (requestUrl === `${url}?after=2&limit=500`) {
      if (mode === "down") return response(null, 503);
      if (mode === "fork") return response(page([fork]));
    }
    const record = fixture.responses.get(requestUrl);
    return record ? response(record) : new Response("not found", { status: 404 });
  };
  try {
    const first = await coordinator.fetch(new Request("https://coordinator/check", { method: "POST" }));
    assert.equal(first.status, 200);
    const witnessEntry = [...storage.values.entries()].find(([key]) => key.includes("last-good"));
    assert.ok(witnessEntry);
    assert.equal(witnessEntry[1].responseTransparency.witnessedEntryHash, entries[2].entryHash);

    mode = "down";
    const unavailable = await coordinator.fetch(new Request("https://coordinator/check", { method: "POST" }));
    assert.equal(unavailable.status, 503);
    assert.match((await unavailable.json()).targets[0].error, /returned HTTP 503/u);
    assert.equal(storage.values.get(witnessEntry[0]).responseTransparency.witnessedEntryHash, entries[2].entryHash);

    mode = "fork";
    const forked = await coordinator.fetch(new Request("https://coordinator/check", { method: "POST" }));
    assert.equal(forked.status, 503);
    assert.match((await forked.json()).targets[0].error, /forked at the last witnessed entry/u);
    assert.equal(storage.values.get(witnessEntry[0]).responseTransparency.witnessedEntryHash, entries[2].entryHash);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Durable Object serializes overlapping manual checks before advancing a witness", async () => {
  const { fixture, url } = fixtureWithLog();
  const storage = new MemoryStorage();
  const env = environment(fixture);
  const coordinator = new ReleaseMonitorCoordinator({ storage }, env);
  const originalFetch = globalThis.fetch;
  let activeWellKnown = 0;
  let maximumActiveWellKnown = 0;
  let initialLogFetches = 0;
  let resumedLogFetches = 0;
  globalThis.fetch = async (input) => {
    const requestUrl = String(input);
    if (requestUrl === fixture.wellKnownUrl) {
      activeWellKnown += 1;
      maximumActiveWellKnown = Math.max(maximumActiveWellKnown, activeWellKnown);
      await new Promise((resolve) => setTimeout(resolve, 20));
      activeWellKnown -= 1;
    }
    if (requestUrl === `${url}?after=0&limit=500`) initialLogFetches += 1;
    if (requestUrl === `${url}?after=2&limit=500`) resumedLogFetches += 1;
    const record = fixture.responses.get(requestUrl);
    return record ? response(record) : new Response("not found", { status: 404 });
  };
  try {
    const [first, second] = await Promise.all([
      coordinator.fetch(new Request("https://coordinator/check", { method: "POST" })),
      coordinator.fetch(new Request("https://coordinator/check", { method: "POST" })),
    ]);
    assert.equal(first.status, 200);
    assert.equal(second.status, 200);
    assert.equal(maximumActiveWellKnown, 1);
    assert.equal(initialLogFetches, 1);
    assert.equal(resumedLogFetches, 1);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
