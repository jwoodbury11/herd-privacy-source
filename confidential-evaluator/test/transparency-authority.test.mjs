import assert from "node:assert/strict";
import test from "node:test";

import {
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_ID,
} from "../src/constants.mjs";
import { domainSeparatedBytes, sha256Base64Url } from "../src/encoding.mjs";
import { parseKeyBundles } from "../src/key-bundle.mjs";
import { StatefulTransparencyAuthority } from "../src/transparency-authority.mjs";
import {
  InMemoryTransparencyStore,
  makeBundle,
  makeKeyStore,
  makeTransparencyBundle,
  responseAuthorization,
  testConfig,
} from "./helpers.mjs";

const GENESIS_HASH = Buffer.alloc(32).toString("base64url");

function canonicalReceipt(
  keyStore,
  {
    logIndex = 1,
    previousEntryHash = GENESIS_HASH,
    discriminator = 1,
    revision = 1,
    committedAt,
  } = {},
) {
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
    revision,
    envelopeId,
    ciphertextHash,
  });
  const core = {
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    logIndex,
    previousEntryHash,
    envelopeId,
    eventId,
    inviteeId,
    policyHash,
    accountKeyEpochId,
    revision,
    ciphertextHash,
    ...authorization,
    committedAt:
      committedAt ?? new Date(Date.UTC(2026, 0, 1, 0, 0, discriminator)).toISOString(),
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

function authority(store, keyStore, instant = "2026-01-01T00:00:10.000Z") {
  const signer = new StatefulTransparencyAuthority({
    store,
    keyStore,
    clock: () => new Date(instant),
  });
  const rawAppend = signer.append.bind(signer);
  signer.append = async (payload) => {
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
    return rawAppend(payload);
  };
  return signer;
}

function policyStoreDelegates(store) {
  return {
    readPolicy: (...input) => store.readPolicy(...input),
    readMember: (...input) => store.readMember(...input),
    createPolicy: (...input) => store.createPolicy(...input),
    replacePendingPolicy: (...input) => store.replacePendingPolicy(...input),
    commitResponseTransition: (...input) =>
      store.commitResponseTransition(...input),
    commitEvaluation: (...input) => store.commitEvaluation(...input),
  };
}

test("one append atomically commits a receipt and its derived head", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const signer = authority(store, keyStore);
  const payload = canonicalReceipt(keyStore);
  const result = await signer.append(payload);
  const snapshot = store.snapshot();

  assert.deepEqual(Object.keys(result), [
    "protocolVersion",
    "kind",
    "signingKeyId",
    "receipt",
    "logHead",
  ]);
  assert.deepEqual(Object.keys(result.receipt), [
    "domain",
    "payloadHash",
    "signature",
  ]);
  assert.deepEqual(Object.keys(result.logHead), [
    "canonicalPayload",
    "domain",
    "payloadHash",
    "signature",
  ]);
  assert.equal(result.kind, "append");
  assert.equal(result.logHead.canonicalPayload, snapshot.entries[0].canonicalHeadPayload);
  assert.equal(result.receipt.signature, snapshot.entries[0].receiptSignature);
  assert.equal(result.logHead.signature, snapshot.entries[0].headSignature);
  assert.equal(snapshot.entries.length, 1);
  assert.equal(snapshot.state.treeSize, 1);
  assert.equal(snapshot.state.headEntryHash, snapshot.entries[0].entryHash);
  const head = JSON.parse(result.logHead.canonicalPayload);
  assert.equal(head.treeSize, 1);
  assert.equal(head.headEntryHash, JSON.parse(payload).entryHash);
});

test("exact retries across restarts return byte-identical stored certifications", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const payload = canonicalReceipt(keyStore);
  const first = await authority(store, keyStore).append(payload);
  const restarted = authority(store, keyStore, "2026-01-01T00:10:00.000Z");
  const retry = await restarted.append(payload);

  assert.equal(JSON.stringify(retry), JSON.stringify(first));
  assert.equal(store.snapshot().entries.length, 1);
});

test("a new evaluator epoch continues the existing log under the same global identity", async () => {
  const firstConfig = testConfig();
  const secondConfig = testConfig({ releaseId: "herd-confidential-test-v2" });
  const transparencyPlaintext = JSON.stringify(await makeTransparencyBundle());
  const firstKeyStore = await parseKeyBundles(
    Uint8Array.from(Buffer.from(JSON.stringify(await makeBundle()))),
    Uint8Array.from(Buffer.from(transparencyPlaintext)),
    firstConfig,
    firstConfig.attestedImageDigest,
  );
  const secondKeyStore = await parseKeyBundles(
    Uint8Array.from(
      Buffer.from(
        JSON.stringify(await makeBundle({ releaseId: secondConfig.releaseId })),
      ),
    ),
    Uint8Array.from(Buffer.from(transparencyPlaintext)),
    secondConfig,
    secondConfig.attestedImageDigest,
  );
  const store = new InMemoryTransparencyStore();
  const first = await authority(store, firstKeyStore).append(
    canonicalReceipt(firstKeyStore),
  );
  const firstHead = JSON.parse(first.logHead.canonicalPayload);
  const successor = authority(store, secondKeyStore);

  await successor.checkReady();
  await successor.append(
    canonicalReceipt(secondKeyStore, {
      logIndex: 2,
      previousEntryHash: firstHead.headEntryHash,
      discriminator: 2,
    }),
  );
  assert.equal(store.snapshot().state.treeSize, 2);
  assert.equal(
    firstKeyStore.metadata.keys.transparencySigning.publicKey,
    secondKeyStore.metadata.keys.transparencySigning.publicKey,
  );
  assert.notEqual(
    firstKeyStore.metadata.keys.responseDecryption.publicKey,
    secondKeyStore.metadata.keys.responseDecryption.publicKey,
  );
});

test("a lost commit response is recovered by re-reading the durable record", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  let first = true;
  const indeterminateStore = {
    ...policyStoreDelegates(durable),
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readEntry: (...input) => durable.readEntry(...input),
    readState: (...input) => durable.readState(...input),
    async commitResponseTransition(input) {
      const committed = await durable.commitResponseTransition(input);
      if (first && committed) {
        first = false;
        return null;
      }
      return committed;
    },
  };
  const payload = canonicalReceipt(keyStore);
  const result = await authority(indeterminateStore, keyStore).append(payload);
  const stored = durable.snapshot().entries[0];

  assert.equal(result.receipt.signature, stored.receiptSignature);
  assert.equal(result.logHead.signature, stored.headSignature);
  assert.equal(durable.snapshot().entries.length, 1);
});

test("concurrent exact retries converge on one durable certification", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const signer = authority(store, keyStore);
  const payload = canonicalReceipt(keyStore);
  const results = await Promise.all(
    Array.from({ length: 32 }, () => signer.append(payload)),
  );

  assert.equal(store.snapshot().entries.length, 1);
  assert.equal(new Set(results.map((value) => JSON.stringify(value))).size, 1);
});

test("concurrent conflicting entries cannot obtain signatures for one tree size", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const signer = authority(store, keyStore);
  const attempts = await Promise.allSettled(
    Array.from({ length: 24 }, (_, index) =>
      signer.append(canonicalReceipt(keyStore, { discriminator: index + 1 })),
    ),
  );
  const fulfilled = attempts.filter((result) => result.status === "fulfilled");
  const rejected = attempts.filter((result) => result.status === "rejected");

  assert.equal(fulfilled.length, 1);
  assert.equal(rejected.length, 23);
  assert.ok(rejected.every((result) => result.reason?.status === 409));
  assert.ok(rejected.every((result) => result.reason?.code === "transparency_conflict"));
  assert.equal(store.snapshot().entries.length, 1);
});

test("gaps, stale successors, and wrong previous hashes fail before commit", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const signer = authority(store, keyStore);
  const firstPayload = canonicalReceipt(keyStore);
  const first = await signer.append(firstPayload);
  const head = JSON.parse(first.logHead.canonicalPayload);

  for (const payload of [
    canonicalReceipt(keyStore, {
      logIndex: 3,
      previousEntryHash: head.headEntryHash,
      discriminator: 3,
    }),
    canonicalReceipt(keyStore, {
      logIndex: 2,
      previousEntryHash: Buffer.alloc(32, 9).toString("base64url"),
      discriminator: 2,
    }),
  ]) {
    await assert.rejects(
      signer.append(payload),
      (error) => error?.status === 409 && error?.code === "transparency_conflict",
    );
  }
  assert.equal(store.snapshot().entries.length, 1);
});

test("head timestamps remain monotonic when a restarted replica clock moves backward", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const firstPayload = canonicalReceipt(keyStore);
  const first = await authority(
    store,
    keyStore,
    "2026-01-01T00:00:10.000Z",
  ).append(firstPayload);
  const firstHead = JSON.parse(first.logHead.canonicalPayload);
  const secondPayload = canonicalReceipt(keyStore, {
    logIndex: 2,
    previousEntryHash: firstHead.headEntryHash,
    discriminator: 2,
    committedAt: "2025-12-31T00:00:00.000Z",
  });
  const second = await authority(
    store,
    keyStore,
    "2025-12-31T00:00:00.000Z",
  ).append(secondPayload);
  const secondHead = JSON.parse(second.logHead.canonicalPayload);

  assert.equal(
    Date.parse(secondHead.generatedAt),
    Date.parse(firstHead.generatedAt) + 1,
  );
  assert.equal(store.snapshot().state.treeSize, 2);
});

test("readiness rejects a corrupt durable tail instead of enabling a stateless fallback", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  await authority(durable, keyStore).append(canonicalReceipt(keyStore));
  const corruptStore = {
    ...policyStoreDelegates(durable),
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readState: (...input) => durable.readState(...input),
    async readEntry(...input) {
      const entry = await durable.readEntry(...input);
      return entry ? { ...entry, receiptSignature: Buffer.alloc(64, 3).toString("base64url") } : null;
    },
    commitTransition: (...input) => durable.commitTransition(...input),
  };
  await assert.rejects(
    authority(corruptStore, keyStore).checkReady(),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});

test("readiness rejects a stored tail signed under any other log identity", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  await authority(durable, keyStore).append(canonicalReceipt(keyStore));
  const wrongKeyStore = await makeKeyStore();
  await assert.rejects(
    authority(durable, wrongKeyStore).checkReady(),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});

test("readiness rejects an instance that cannot use its transparency signing key", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  await authority(durable, keyStore).append(canonicalReceipt(keyStore));
  const unusableKeyStore = {
    ...keyStore,
    keys: {
      ...keyStore.keys,
      transparencySigning: {
        ...keyStore.keys.transparencySigning,
        privateKey: null,
      },
    },
  };
  await assert.rejects(
    authority(durable, unusableKeyStore).checkReady(),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});

test("a stored entry without its durable tail is corruption, not an idempotent success", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  const payload = canonicalReceipt(keyStore);
  await authority(durable, keyStore).append(payload);
  const missingTailStore = {
    ...policyStoreDelegates(durable),
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readEntry: (...input) => durable.readEntry(...input),
    async readState() { return null; },
    commitTransition: (...input) => durable.commitTransition(...input),
  };
  await assert.rejects(
    authority(missingTailStore, keyStore).append(payload),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});

test("readiness rejects an orphaned genesis entry when the durable tail is absent", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  await authority(durable, keyStore).append(canonicalReceipt(keyStore));
  const orphanedGenesisStore = {
    ...policyStoreDelegates(durable),
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readEntry: (...input) => durable.readEntry(...input),
    async readState() { return null; },
    commitTransition: (...input) => durable.commitTransition(...input),
  };
  await assert.rejects(
    authority(orphanedGenesisStore, keyStore).checkReady(),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});

test("readiness detects a tail rewound behind an existing successor entry", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  await authority(durable, keyStore).append(canonicalReceipt(keyStore));
  const first = await durable.readEntry(1);
  const rewoundStore = {
    ...policyStoreDelegates(durable),
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readState: (...input) => durable.readState(...input),
    async readEntry(logIndex) {
      if (logIndex === 2) return { ...first, logIndex: 2 };
      return durable.readEntry(logIndex);
    },
    commitTransition: (...input) => durable.commitTransition(...input),
  };
  await assert.rejects(
    authority(rewoundStore, keyStore).checkReady(),
    (error) => error?.status === 503 && error?.code === "service_unavailable",
  );
});
