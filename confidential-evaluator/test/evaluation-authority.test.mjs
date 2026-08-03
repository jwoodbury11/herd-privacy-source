import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_ID,
  TRANSPARENCY_RECONCILIATION_DOMAIN,
} from "../src/constants.mjs";
import { domainSeparatedBytes, sha256Base64Url } from "../src/encoding.mjs";
import { StatefulTransparencyAuthority } from "../src/transparency-authority.mjs";
import {
  InMemoryTransparencyStore,
  makeKeyStore,
  makeTestResponseSigningIdentity,
  publicKeyFromMetadata,
  responseAuthorization,
} from "./helpers.mjs";

const GENESIS_HASH = Buffer.alloc(32).toString("base64url");
const DEADLINE = "2026-02-01T00:00:00.000Z";
const BEFORE_DEADLINE = "2026-01-01T00:00:00.000Z";
const AFTER_DEADLINE = "2026-03-01T00:00:00.000Z";
const EVENT_ID = "10000000-0000-4000-8000-000000000001";
const MEMBER_A = "20000000-0000-4000-8000-000000000001";
const MEMBER_B = "20000000-0000-4000-8000-000000000002";

function policy(keyStore, { eventId = EVENT_ID, memberIds = [MEMBER_A] } = {}) {
  return {
    protocolVersion: 1,
    eventId,
    policyHash: sha256Base64Url(Buffer.from(`policy:${eventId}`, "utf8")),
    rsvpDeadline: DEADLINE,
    memberIds,
    releaseId: keyStore.metadata.releaseId,
    evaluatorKeyId: keyStore.metadata.keys.responseDecryption.keyId,
  };
}

function receipt(
  keyStore,
  {
    eventId = EVENT_ID,
    inviteeId = MEMBER_A,
    revision = 1,
    discriminator = 1,
    logIndex = 1,
    previousEntryHash = GENESIS_HASH,
    committedAt = BEFORE_DEADLINE,
    responseSigningIdentity,
    accountKeyEpochId = "30000000-0000-4000-8000-000000000001",
  } = {},
) {
  const suffix = String(discriminator).padStart(12, "0");
  const envelopeId = `40000000-0000-4000-8000-${suffix}`;
  const policyHash = sha256Base64Url(
    Buffer.from(`policy:${eventId}`, "utf8"),
  );
  const ciphertextHash = Buffer.alloc(32, discriminator).toString("base64url");
  const authorization = responseAuthorization(
    {
      protocolVersion: 1,
      eventId,
      inviteeId,
      policyHash,
      accountKeyEpochId,
      revision,
      envelopeId,
      ciphertextHash,
    },
    responseSigningIdentity,
  );
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
    committedAt,
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

function claim(policyCommitments, slots, batchHashOverride) {
  const batchHash =
    batchHashOverride ??
    sha256Base64Url(
      Buffer.from(
        JSON.stringify({
          protocolVersion: 1,
          eventId: policyCommitments.eventId,
          policyHash: policyCommitments.policyHash,
          slots: slots.map(({ inviteeId, envelopeHash }) => ({
            inviteeId,
            envelopeHash,
          })),
        }),
        "utf8",
      ),
    );
  return {
    ...policyCommitments,
    batchHash,
    slots,
  };
}

function authority(store, keyStore, now) {
  return new StatefulTransparencyAuthority({
    store,
    keyStore,
    clock: () => new Date(now.value),
  });
}

function delegateStore(durable, overrides = {}) {
  return {
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readEntry: (...input) => durable.readEntry(...input),
    readState: (...input) => durable.readState(...input),
    readPolicy: (...input) => durable.readPolicy(...input),
    readMember: (...input) => durable.readMember(...input),
    createPolicy: (...input) => durable.createPolicy(...input),
    commitResponseTransition: (...input) =>
      durable.commitResponseTransition(...input),
    commitEvaluation: (...input) => durable.commitEvaluation(...input),
    ...overrides,
  };
}

function headHash(certification) {
  return JSON.parse(certification.logHead.canonicalPayload).headEntryHash;
}

function slotFromReceipt(payload) {
  const value = JSON.parse(payload);
  return {
    inviteeId: value.inviteeId,
    envelopeHash: value.ciphertextHash,
    revision: value.revision,
    responseSigningPublicKey: value.responseSigningPublicKey,
  };
}

function tamperResponseSignature(payload) {
  const receiptValue = JSON.parse(payload);
  const signature = Buffer.from(receiptValue.responseSignature, "base64url");
  signature[0] ^= 1;
  receiptValue.responseSignature = signature.toString("base64url");
  const entryCore = {
    protocolVersion: receiptValue.protocolVersion,
    logId: receiptValue.logId,
    logIndex: receiptValue.logIndex,
    previousEntryHash: receiptValue.previousEntryHash,
    envelopeId: receiptValue.envelopeId,
    eventId: receiptValue.eventId,
    inviteeId: receiptValue.inviteeId,
    policyHash: receiptValue.policyHash,
    accountKeyEpochId: receiptValue.accountKeyEpochId,
    revision: receiptValue.revision,
    ciphertextHash: receiptValue.ciphertextHash,
    responseSigningPublicKey: receiptValue.responseSigningPublicKey,
    responseSignature: receiptValue.responseSignature,
    committedAt: receiptValue.committedAt,
  };
  receiptValue.entryHash = sha256Base64Url(
    domainSeparatedBytes(
      TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
      JSON.stringify(entryCore),
    ),
  );
  return JSON.stringify({
    protocolVersion: receiptValue.protocolVersion,
    logId: receiptValue.logId,
    logIndex: receiptValue.logIndex,
    previousEntryHash: receiptValue.previousEntryHash,
    entryHash: receiptValue.entryHash,
    envelopeId: receiptValue.envelopeId,
    eventId: receiptValue.eventId,
    inviteeId: receiptValue.inviteeId,
    policyHash: receiptValue.policyHash,
    accountKeyEpochId: receiptValue.accountKeyEpochId,
    revision: receiptValue.revision,
    ciphertextHash: receiptValue.ciphertextHash,
    responseSigningPublicKey: receiptValue.responseSigningPublicKey,
    responseSignature: receiptValue.responseSignature,
    committedAt: receiptValue.committedAt,
    signingKeyId: receiptValue.signingKeyId,
  });
}

async function assertLateMissingProof(error, keyStore, payload, expectedHead) {
  assert.equal(error?.status, 409);
  assert.equal(error?.code, "transparency_late_missing_entry");
  assert.deepEqual(Object.keys(error.details), ["proof"]);
  const proof = error.details.proof;
  assert.deepEqual(Object.keys(proof), [
    "canonicalPayload",
    "domain",
    "payloadHash",
    "signature",
    "signingKeyId",
  ]);
  assert.equal(proof.domain, TRANSPARENCY_RECONCILIATION_DOMAIN);
  assert.equal(
    proof.signingKeyId,
    keyStore.metadata.keys.transparencySigning.keyId,
  );
  assert.equal(
    proof.payloadHash,
    sha256Base64Url(Buffer.from(proof.canonicalPayload, "utf8")),
  );
  const receiptValue = JSON.parse(payload);
  assert.deepEqual(JSON.parse(proof.canonicalPayload), {
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    rejectedLogIndex: receiptValue.logIndex,
    rejectedEntryHash: receiptValue.entryHash,
    authorityTreeSize: expectedHead.treeSize,
    authorityHeadEntryHash: expectedHead.entryHash,
    generatedAt: AFTER_DEADLINE,
    signingKeyId: keyStore.metadata.keys.transparencySigning.keyId,
  });
  const publicKey = await publicKeyFromMetadata(
    keyStore.metadata.keys.transparencySigning,
  );
  assert.equal(
    await webcrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      Buffer.from(proof.signature, "base64url"),
      domainSeparatedBytes(proof.domain, proof.canonicalPayload),
    ),
    true,
  );
}

test("policy authority freezes only opaque commitments and rejects replacement", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore);

  await evaluator.freezePolicy(commitments);
  await evaluator.freezePolicy(commitments);
  const snapshot = store.snapshot();
  assert.equal(snapshot.policies.length, 1);
  assert.deepEqual(Object.keys(snapshot.policies[0]).sort(), [
    "evaluatedAt",
    "evaluationBatchHash",
    "evaluatorKeyId",
    "eventId",
    "memberIds",
    "policyHash",
    "protocolVersion",
    "releaseId",
    "responseSequence",
    "rsvpDeadline",
    "versionToken",
  ]);
  assert.equal(
    JSON.stringify(snapshot.policies).includes("Confidential test"),
    false,
  );
  assert.equal(JSON.stringify(snapshot.policies).includes("location"), false);

  await assert.rejects(
    evaluator.freezePolicy({
      ...commitments,
      policyHash: Buffer.alloc(32, 9).toString("base64url"),
    }),
    (error) => error?.status === 409,
  );
});

test("member revisions begin at one and advance by exactly one", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));

  await assert.rejects(
    evaluator.append(receipt(keyStore, { revision: 2 })),
    (error) => error?.status === 409,
  );
  const firstPayload = receipt(keyStore);
  const first = await evaluator.append(firstPayload);
  const previousEntryHash = headHash(first);
  await assert.rejects(
    evaluator.append(
      receipt(keyStore, {
        logIndex: 2,
        previousEntryHash,
        revision: 3,
        discriminator: 3,
      }),
    ),
    (error) => error?.status === 409,
  );
  await evaluator.append(
    receipt(keyStore, {
      logIndex: 2,
      previousEntryHash,
      revision: 2,
      discriminator: 2,
    }),
  );
  assert.equal(store.snapshot().members[0].revision, 2);
});

test("the first response key is pinned and a new account root cannot replace it", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));
  const firstPayload = receipt(keyStore);
  const first = await evaluator.append(firstPayload);
  const replacementIdentity = makeTestResponseSigningIdentity();
  await assert.rejects(
    evaluator.append(
      receipt(keyStore, {
        logIndex: 2,
        previousEntryHash: headHash(first),
        revision: 2,
        discriminator: 2,
        responseSigningIdentity: replacementIdentity,
      }),
    ),
    (error) => error?.status === 409,
  );
  const exactRetry = await evaluator.append(firstPayload);
  assert.equal(JSON.stringify(exactRetry), JSON.stringify(first));
});

test("the enrolled account-key epoch cannot change under the same valid response key", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));
  const first = await evaluator.append(receipt(keyStore));

  await assert.rejects(
    evaluator.append(
      receipt(keyStore, {
        logIndex: 2,
        previousEntryHash: headHash(first),
        revision: 2,
        discriminator: 2,
        accountKeyEpochId: "30000000-0000-4000-8000-000000000002",
      }),
    ),
    (error) => error?.status === 409,
  );
  assert.equal(
    store.snapshot().members[0].accountKeyEpochId,
    "30000000-0000-4000-8000-000000000001",
  );
  assert.equal(store.snapshot().members[0].revision, 1);
});

test("a corrupted latest-member index cannot authorize an append or evaluation", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const trustedAuthority = authority(durable, keyStore, now);
  const commitments = policy(keyStore);
  await trustedAuthority.freezePolicy(commitments);
  const firstPayload = receipt(keyStore);
  const first = await trustedAuthority.append(firstPayload);
  const corruptedStore = delegateStore(durable, {
    async readMember(...input) {
      const member = await durable.readMember(...input);
      return member
        ? {
            ...member,
            ciphertextHash: Buffer.alloc(32, 99).toString("base64url"),
          }
        : null;
    },
  });
  const corruptedAuthority = authority(corruptedStore, keyStore, now);

  await assert.rejects(
    corruptedAuthority.append(
      receipt(keyStore, {
        logIndex: 2,
        previousEntryHash: headHash(first),
        revision: 2,
        discriminator: 2,
      }),
    ),
    (error) => error?.status === 503,
  );

  now.value = AFTER_DEADLINE;
  await assert.rejects(
    corruptedAuthority.consumeCanonicalBatch(
      claim(commitments, [slotFromReceipt(firstPayload)]),
    ),
    (error) => error?.status === 503,
  );
  assert.equal(durable.snapshot().entries.length, 1);
  assert.equal(durable.snapshot().members[0].revision, 1);
  assert.equal(durable.snapshot().policies[0].evaluationBatchHash, "");
});

test("a receipt with a forged response authorization never enrolls a key", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));
  await assert.rejects(
    evaluator.append(tamperResponseSignature(receipt(keyStore))),
    (error) => error?.status === 409,
  );
  assert.equal(store.snapshot().members.length, 0);
  assert.equal(store.snapshot().entries.length, 0);
});

test("late appends fail while an exact certified retry survives deadline and consumption", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore);
  await evaluator.freezePolicy(commitments);
  const firstPayload = receipt(keyStore);
  const first = await evaluator.append(firstPayload);
  const expectedSlot = slotFromReceipt(firstPayload);

  now.value = AFTER_DEADLINE;
  await assert.rejects(
    evaluator.append(
      receipt(keyStore, {
        logIndex: 2,
        previousEntryHash: headHash(first),
        revision: 2,
        discriminator: 2,
      }),
    ),
    (error) => error?.status === 409,
  );
  await evaluator.consumeCanonicalBatch(claim(commitments, [expectedSlot]));
  const retry = await evaluator.append(firstPayload);
  assert.equal(JSON.stringify(retry), JSON.stringify(first));
});

test("a fully valid late missing entry receives a signed authority-head reconciliation proof", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));
  const payload = receipt(keyStore);

  now.value = AFTER_DEADLINE;
  let rejection;
  try {
    await evaluator.append(payload);
    assert.fail("the late missing append unexpectedly succeeded");
  } catch (error) {
    rejection = error;
  }
  await assertLateMissingProof(rejection, keyStore, payload, {
    treeSize: 0,
    entryHash: GENESIS_HASH,
  });
  assert.equal(store.snapshot().entries.length, 0);
  assert.equal(store.snapshot().members.length, 0);
  assert.equal(store.snapshot().policies[0].responseSequence, 0);
});

test("a consumed policy signs the exact next missing entry without changing authority state", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore);
  await evaluator.freezePolicy(commitments);
  const firstPayload = receipt(keyStore);
  const first = await evaluator.append(firstPayload);
  const previousEntryHash = headHash(first);

  now.value = AFTER_DEADLINE;
  await evaluator.consumeCanonicalBatch(
    claim(commitments, [slotFromReceipt(firstPayload)]),
  );
  const missingPayload = receipt(keyStore, {
    logIndex: 2,
    previousEntryHash,
    revision: 2,
    discriminator: 2,
  });
  let rejection;
  try {
    await evaluator.append(missingPayload);
    assert.fail("the consumed-policy append unexpectedly succeeded");
  } catch (error) {
    rejection = error;
  }
  await assertLateMissingProof(rejection, keyStore, missingPayload, {
    treeSize: 1,
    entryHash: previousEntryHash,
  });
  const snapshot = store.snapshot();
  assert.equal(snapshot.entries.length, 1);
  assert.equal(snapshot.members[0].revision, 1);
  assert.notEqual(snapshot.policies[0].evaluationBatchHash, "");
});

test("invalid authorization, revision, hash, timestamp, key, or tail never receives reconciliation disposition", async () => {
  const keyStore = await makeKeyStore();

  async function rejectGenesis(candidate) {
    const store = new InMemoryTransparencyStore();
    const now = { value: BEFORE_DEADLINE };
    const evaluator = authority(store, keyStore, now);
    await evaluator.freezePolicy(policy(keyStore));
    now.value = AFTER_DEADLINE;
    await assert.rejects(
      evaluator.append(candidate),
      (error) =>
        error?.code !== "transparency_late_missing_entry" &&
        error?.details?.proof === undefined,
    );
    assert.equal(store.snapshot().entries.length, 0);
    assert.equal(store.snapshot().members.length, 0);
  }

  await rejectGenesis(tamperResponseSignature(receipt(keyStore)));
  await rejectGenesis(receipt(keyStore, { revision: 2 }));
  await rejectGenesis(
    receipt(keyStore, {
      committedAt: "2026-02-01T00:00:00.001Z",
    }),
  );
  const malformedHash = JSON.parse(receipt(keyStore));
  malformedHash.entryHash = Buffer.alloc(32, 88).toString("base64url");
  await rejectGenesis(JSON.stringify(malformedHash));

  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  await evaluator.freezePolicy(policy(keyStore));
  const first = await evaluator.append(receipt(keyStore));
  now.value = AFTER_DEADLINE;
  const wrongIdentity = makeTestResponseSigningIdentity();
  const candidates = [
    receipt(keyStore, {
      logIndex: 2,
      previousEntryHash: headHash(first),
      revision: 2,
      discriminator: 2,
      responseSigningIdentity: wrongIdentity,
    }),
    receipt(keyStore, {
      logIndex: 2,
      previousEntryHash: Buffer.alloc(32, 77).toString("base64url"),
      revision: 2,
      discriminator: 3,
    }),
  ];
  for (const candidate of candidates) {
    await assert.rejects(
      evaluator.append(candidate),
      (error) =>
        error?.code !== "transparency_late_missing_entry" &&
        error?.details?.proof === undefined,
    );
  }
  assert.equal(store.snapshot().entries.length, 1);
  assert.equal(store.snapshot().members[0].revision, 1);
});

test("omitted, null, and stale member snapshots cannot be used as evaluation oracles", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore, { memberIds: [MEMBER_A, MEMBER_B] });
  await evaluator.freezePolicy(commitments);

  const a1 = receipt(keyStore, { discriminator: 1 });
  const a1Certification = await evaluator.append(a1);
  const b1 = receipt(keyStore, {
    inviteeId: MEMBER_B,
    discriminator: 2,
    logIndex: 2,
    previousEntryHash: headHash(a1Certification),
  });
  const b1Certification = await evaluator.append(b1);
  const a2 = receipt(keyStore, {
    discriminator: 3,
    revision: 2,
    logIndex: 3,
    previousEntryHash: headHash(b1Certification),
  });
  await evaluator.append(a2);
  now.value = AFTER_DEADLINE;

  const latest = [slotFromReceipt(a2), slotFromReceipt(b1)];
  await assert.rejects(
    evaluator.consumeCanonicalBatch(claim(commitments, latest.slice(0, 1))),
    (error) => error?.status === 400,
  );
  await assert.rejects(
    evaluator.consumeCanonicalBatch(
      claim(commitments, [
        {
          inviteeId: MEMBER_A,
          envelopeHash: null,
          revision: null,
          responseSigningPublicKey: null,
        },
        latest[1],
      ]),
    ),
    (error) => error?.status === 409,
  );
  await assert.rejects(
    evaluator.consumeCanonicalBatch(
      claim(commitments, [slotFromReceipt(a1), latest[1]]),
    ),
    (error) => error?.status === 409,
  );

  const acceptedClaim = claim(commitments, latest);
  const first = await evaluator.consumeCanonicalBatch(acceptedClaim);
  const retry = await evaluator.consumeCanonicalBatch(acceptedClaim);
  assert.deepEqual(retry, first);
  await assert.rejects(
    evaluator.consumeCanonicalBatch(
      claim(commitments, latest, Buffer.alloc(32, 7).toString("base64url")),
    ),
    (error) => error?.status === 409,
  );
});

test("a last receipt and evaluation consumption have exactly one CAS winner", async () => {
  const keyStore = await makeKeyStore();
  const store = new InMemoryTransparencyStore();
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore);
  await evaluator.freezePolicy(commitments);
  const finalReceipt = receipt(keyStore, { committedAt: DEADLINE });
  const beforeClaim = claim(commitments, [
    {
      inviteeId: MEMBER_A,
      envelopeHash: null,
      revision: null,
      responseSigningPublicKey: null,
    },
  ]);
  const afterClaim = claim(commitments, [slotFromReceipt(finalReceipt)]);
  now.value = DEADLINE;

  const [appendResult, consumeResult] = await Promise.allSettled([
    evaluator.append(finalReceipt),
    evaluator.consumeCanonicalBatch(beforeClaim),
  ]);
  assert.equal(
    [appendResult, consumeResult].filter(({ status }) => status === "fulfilled")
      .length,
    1,
  );

  if (appendResult.status === "fulfilled") {
    await assert.rejects(evaluator.consumeCanonicalBatch(beforeClaim));
    await evaluator.consumeCanonicalBatch(afterClaim);
  } else {
    await evaluator.consumeCanonicalBatch(beforeClaim);
    await assert.rejects(evaluator.append(finalReceipt));
    await assert.rejects(evaluator.consumeCanonicalBatch(afterClaim));
  }
});

test("an evaluation commit response lost after durable consumption is an exact retry", async () => {
  const keyStore = await makeKeyStore();
  const durable = new InMemoryTransparencyStore();
  let loseResponse = true;
  const store = {
    checkAvailable: (...input) => durable.checkAvailable(...input),
    readEntry: (...input) => durable.readEntry(...input),
    readState: (...input) => durable.readState(...input),
    readPolicy: (...input) => durable.readPolicy(...input),
    readMember: (...input) => durable.readMember(...input),
    createPolicy: (...input) => durable.createPolicy(...input),
    commitResponseTransition: (...input) =>
      durable.commitResponseTransition(...input),
    async commitEvaluation(input) {
      const committed = await durable.commitEvaluation(input);
      if (committed && loseResponse) {
        loseResponse = false;
        return null;
      }
      return committed;
    },
  };
  const now = { value: BEFORE_DEADLINE };
  const evaluator = authority(store, keyStore, now);
  const commitments = policy(keyStore);
  await evaluator.freezePolicy(commitments);
  now.value = AFTER_DEADLINE;
  const emptyClaim = claim(commitments, [
    {
      inviteeId: MEMBER_A,
      envelopeHash: null,
      revision: null,
      responseSigningPublicKey: null,
    },
  ]);
  const result = await evaluator.consumeCanonicalBatch(emptyClaim);
  assert.equal(result.batchHash, emptyClaim.batchHash);
  assert.equal(durable.snapshot().policies[0].evaluationBatchHash, emptyClaim.batchHash);
});
