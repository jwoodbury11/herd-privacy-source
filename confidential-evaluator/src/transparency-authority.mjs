import { webcrypto } from "node:crypto";

import {
  MAXIMUM_CANONICAL_PAYLOAD_BYTES,
  PROTOCOL_VERSION,
  RESPONSE_AUTHORIZATION_DOMAIN,
  TRANSPARENCY_LOG_HEAD_DOMAIN,
  TRANSPARENCY_LOG_ID,
  TRANSPARENCY_RECEIPT_DOMAIN,
} from "./constants.mjs";
import {
  decodeBase64Url,
  domainSeparatedBytes,
  exactKeys,
  parseCompactCanonicalJson,
  sha256Base64Url,
} from "./encoding.mjs";
import { HttpError, invalidRequest, serviceUnavailable } from "./errors.mjs";
import {
  signTransparencyReconciliation,
  signTransparencyPayload,
  validateReceiptPayload,
} from "./signing.mjs";

const MAXIMUM_COMMIT_ATTEMPTS = 16;
const MAXIMUM_INVITEES = 19;
const MAXIMUM_RESPONSE_REVISION = 1_000_000;
const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/u;

function conflict() {
  throw new HttpError(409, "transparency_conflict");
}

async function lateMissingEntry(receipt, state, generatedAt, keyStore) {
  const proof = await signTransparencyReconciliation({
    rejectedLogIndex: receipt.logIndex,
    rejectedEntryHash: receipt.entryHash,
    authorityTreeSize: state?.treeSize ?? 0,
    authorityHeadEntryHash:
      state?.headEntryHash ?? Buffer.alloc(32).toString("base64url"),
    generatedAt,
    keyStore,
  });
  throw new HttpError(409, "transparency_late_missing_entry", { proof });
}

function unavailable() {
  serviceUnavailable();
}

function clockInstant(clock) {
  const value = clock();
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) unavailable();
  return value;
}

function requestTimestamp(value) {
  if (typeof value !== "string") invalidRequest();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest();
  }
  return timestamp;
}

function requestUuid(value) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) invalidRequest();
  return value;
}

function requestIdentifier(value, maximum = 120) {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(value)
  ) {
    invalidRequest();
  }
  return value;
}

function policyCommitments(value, keyStore) {
  const input = exactKeys(value, [
    "protocolVersion",
    "eventId",
    "policyHash",
    "rsvpDeadline",
    "memberIds",
    "releaseId",
    "evaluatorKeyId",
  ]);
  if (
    input.protocolVersion !== PROTOCOL_VERSION ||
    !Array.isArray(input.memberIds) ||
    input.memberIds.length < 1 ||
    input.memberIds.length > MAXIMUM_INVITEES
  ) {
    invalidRequest();
  }
  const memberIds = input.memberIds.map(requestUuid);
  if (
    memberIds.some(
      (memberId, index) =>
        index > 0 && memberId.localeCompare(memberIds[index - 1]) <= 0,
    )
  ) {
    invalidRequest();
  }
  const policyHash = Buffer.from(decodeBase64Url(input.policyHash, 32)).toString(
    "base64url",
  );
  const releaseId = requestIdentifier(input.releaseId, 200);
  const evaluatorKeyId = requestIdentifier(input.evaluatorKeyId);
  if (
    releaseId !== keyStore.metadata.releaseId ||
    evaluatorKeyId !== keyStore.metadata.keys.responseDecryption.keyId
  ) {
    invalidRequest();
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    eventId: requestUuid(input.eventId),
    policyHash,
    rsvpDeadline: new Date(requestTimestamp(input.rsvpDeadline)).toISOString(),
    memberIds,
    releaseId,
    evaluatorKeyId,
  };
}

function storedPolicy(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
  const expected = [
    "protocolVersion",
    "eventId",
    "policyHash",
    "rsvpDeadline",
    "memberIds",
    "releaseId",
    "evaluatorKeyId",
    "responseSequence",
    "evaluationBatchHash",
    "evaluatedAt",
    "versionToken",
  ];
  const actual = Object.keys(value).sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== [...expected].sort()[index]) ||
    value.protocolVersion !== PROTOCOL_VERSION ||
    !UUID_PATTERN.test(value.eventId) ||
    !Array.isArray(value.memberIds) ||
    value.memberIds.length < 1 ||
    value.memberIds.length > MAXIMUM_INVITEES ||
    value.memberIds.some(
      (memberId, index) =>
        typeof memberId !== "string" ||
        !UUID_PATTERN.test(memberId) ||
        (index > 0 && memberId.localeCompare(value.memberIds[index - 1]) <= 0),
    ) ||
    typeof value.responseSequence !== "number" ||
    !Number.isSafeInteger(value.responseSequence) ||
    value.responseSequence < 0 ||
    typeof value.versionToken !== "string" ||
    value.versionToken.length < 1 ||
    !IDENTIFIER_PATTERN.test(value.evaluatorKeyId) ||
    typeof value.releaseId !== "string" ||
    value.releaseId.length < 1 ||
    value.releaseId.length > 200
  ) {
    unavailable();
  }
  canonicalHash(value.policyHash);
  canonicalTimestamp(value.rsvpDeadline);
  const unevaluated =
    value.evaluationBatchHash === "" && value.evaluatedAt === "";
  const evaluated =
    typeof value.evaluationBatchHash === "string" &&
    value.evaluationBatchHash !== "" &&
    canonicalHash(value.evaluationBatchHash) === value.evaluationBatchHash &&
    typeof value.evaluatedAt === "string" &&
    value.evaluatedAt !== "" &&
    Number.isFinite(canonicalTimestamp(value.evaluatedAt));
  if (!unevaluated && !evaluated) unavailable();
  return value;
}

function storedMember(value, eventId, inviteeId) {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
  const expected = [
    "protocolVersion",
    "eventId",
    "inviteeId",
    "revision",
    "envelopeId",
    "ciphertextHash",
    "committedAt",
    "logIndex",
    "entryHash",
    "accountKeyEpochId",
    "responseSigningPublicKey",
    "versionToken",
  ];
  const wanted = [...expected].sort();
  const actual = Object.keys(value).sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index]) ||
    value.protocolVersion !== PROTOCOL_VERSION ||
    value.eventId !== eventId ||
    value.inviteeId !== inviteeId ||
    !UUID_PATTERN.test(value.envelopeId) ||
    !UUID_PATTERN.test(value.accountKeyEpochId) ||
    !Number.isInteger(value.revision) ||
    value.revision < 1 ||
    value.revision > MAXIMUM_RESPONSE_REVISION ||
    !Number.isInteger(value.logIndex) ||
    value.logIndex < 1 ||
    typeof value.versionToken !== "string" ||
    value.versionToken.length < 1
  ) {
    unavailable();
  }
  canonicalHash(value.entryHash);
  canonicalHash(value.ciphertextHash);
  try {
    decodeBase64Url(value.responseSigningPublicKey, 32);
  } catch {
    unavailable();
  }
  canonicalTimestamp(value.committedAt);
  return value;
}

function sameCommitments(policy, commitments) {
  return (
    policy.protocolVersion === commitments.protocolVersion &&
    policy.eventId === commitments.eventId &&
    policy.policyHash === commitments.policyHash &&
    policy.rsvpDeadline === commitments.rsvpDeadline &&
    policy.releaseId === commitments.releaseId &&
    policy.evaluatorKeyId === commitments.evaluatorKeyId &&
    JSON.stringify(policy.memberIds) === JSON.stringify(commitments.memberIds)
  );
}

function normalizeEvaluationClaim(value, keyStore) {
  const input = exactKeys(value, [
    "protocolVersion",
    "eventId",
    "policyHash",
    "releaseId",
    "evaluatorKeyId",
    "rsvpDeadline",
    "memberIds",
    "batchHash",
    "revealAttendance",
    "slots",
  ]);
  const commitments = policyCommitments(
    {
      protocolVersion: input.protocolVersion,
      eventId: input.eventId,
      policyHash: input.policyHash,
      rsvpDeadline: input.rsvpDeadline,
      memberIds: input.memberIds,
      releaseId: input.releaseId,
      evaluatorKeyId: input.evaluatorKeyId,
    },
    keyStore,
  );
  if (!Array.isArray(input.slots) || input.slots.length !== commitments.memberIds.length) {
    invalidRequest();
  }
  if (typeof input.revealAttendance !== "boolean") invalidRequest();
  const slots = input.slots.map((rawSlot, index) => {
    const slot = exactKeys(rawSlot, [
      "inviteeId",
      "envelopeHash",
      "revision",
      "responseSigningPublicKey",
    ]);
    const inviteeId = requestUuid(slot.inviteeId);
    if (inviteeId !== commitments.memberIds[index]) invalidRequest();
    if (
      slot.envelopeHash === null ||
      slot.revision === null ||
      slot.responseSigningPublicKey === null
    ) {
      if (
        slot.envelopeHash !== null ||
        slot.revision !== null ||
        slot.responseSigningPublicKey !== null
      ) {
        invalidRequest();
      }
      return {
        inviteeId,
        envelopeHash: null,
        revision: null,
        responseSigningPublicKey: null,
      };
    }
    const envelopeHash = Buffer.from(
      decodeBase64Url(slot.envelopeHash, 32),
    ).toString("base64url");
    if (
      !Number.isInteger(slot.revision) ||
      slot.revision < 1 ||
      slot.revision > MAXIMUM_RESPONSE_REVISION
    ) {
      invalidRequest();
    }
    return {
      inviteeId,
      envelopeHash,
      revision: slot.revision,
      responseSigningPublicKey: Buffer.from(
        decodeBase64Url(slot.responseSigningPublicKey, 32),
      ).toString("base64url"),
    };
  });
  const batchHash = Buffer.from(decodeBase64Url(input.batchHash, 32)).toString(
    "base64url",
  );
  const expectedBatchHash = sha256Base64Url(Buffer.from(JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    eventId: commitments.eventId,
    policyHash: commitments.policyHash,
    revealAttendance: input.revealAttendance,
    slots: slots.map(({ inviteeId, envelopeHash }) => ({ inviteeId, envelopeHash })),
  }), "utf8"));
  if (batchHash !== expectedBatchHash) invalidRequest();
  return {
    ...commitments,
    batchHash,
    revealAttendance: input.revealAttendance,
    slots,
  };
}

async function verifyResponseAuthorization(receipt) {
  const canonicalDocument = JSON.stringify({
    protocolVersion: receipt.protocolVersion,
    eventId: receipt.eventId,
    inviteeId: receipt.inviteeId,
    policyHash: receipt.policyHash,
    accountKeyEpochId: receipt.accountKeyEpochId,
    revision: receipt.revision,
    envelopeId: receipt.envelopeId,
    ciphertextHash: receipt.ciphertextHash,
    responseSigningPublicKey: receipt.responseSigningPublicKey,
  });
  try {
    const key = await webcrypto.subtle.importKey(
      "raw",
      decodeBase64Url(receipt.responseSigningPublicKey, 32),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return webcrypto.subtle.verify(
      { name: "Ed25519" },
      key,
      decodeBase64Url(receipt.responseSignature, 64),
      domainSeparatedBytes(RESPONSE_AUTHORIZATION_DOMAIN, canonicalDocument),
    );
  } catch {
    return false;
  }
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") unavailable();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    unavailable();
  }
  return timestamp;
}

function canonicalHash(value) {
  try {
    return Buffer.from(decodeBase64Url(value, 32)).toString("base64url");
  } catch {
    unavailable();
  }
}

function exactStoredHead(canonicalPayload) {
  let head;
  try {
    head = parseCompactCanonicalJson(
      canonicalPayload,
      MAXIMUM_CANONICAL_PAYLOAD_BYTES,
    );
    exactKeys(head, [
      "protocolVersion",
      "logId",
      "treeSize",
      "headEntryHash",
      "generatedAt",
      "signingKeyId",
    ]);
  } catch {
    unavailable();
  }
  if (
    head.protocolVersion !== PROTOCOL_VERSION ||
    head.logId !== TRANSPARENCY_LOG_ID ||
    !Number.isInteger(head.treeSize) ||
    head.treeSize < 1 ||
    typeof head.signingKeyId !== "string" ||
    head.signingKeyId.length < 1 ||
    head.signingKeyId.length > 120
  ) {
    unavailable();
  }
  canonicalHash(head.headEntryHash);
  canonicalTimestamp(head.generatedAt);
  return head;
}

async function verifySignature(keyStore, domain, payload, signature) {
  let key;
  try {
    const bytes = decodeBase64Url(
      keyStore.metadata.keys.transparencySigning.publicKey,
      65,
    );
    const encodedSignature = decodeBase64Url(signature, 64);
    key = await webcrypto.subtle.importKey(
      "raw",
      bytes,
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
    return webcrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      key,
      encodedSignature,
      domainSeparatedBytes(domain, payload),
    );
  } catch {
    return false;
  }
}

function responseFromEntry(entry) {
  return {
    protocolVersion: PROTOCOL_VERSION,
    kind: "append",
    signingKeyId: entry.signingKeyId,
    receipt: {
      domain: TRANSPARENCY_RECEIPT_DOMAIN,
      payloadHash: entry.receiptPayloadHash,
      signature: entry.receiptSignature,
    },
    logHead: {
      canonicalPayload: entry.canonicalHeadPayload,
      domain: TRANSPARENCY_LOG_HEAD_DOMAIN,
      payloadHash: entry.headPayloadHash,
      signature: entry.headSignature,
    },
  };
}

async function validateExistingEntry(entry, receipt, canonicalReceiptPayload, keyStore) {
  if (entry.canonicalReceiptPayload !== canonicalReceiptPayload) conflict();
  const head = exactStoredHead(entry.canonicalHeadPayload);
  const expectedReceiptHash = sha256Base64Url(
    Buffer.from(canonicalReceiptPayload, "utf8"),
  );
  const expectedHeadHash = sha256Base64Url(
    Buffer.from(entry.canonicalHeadPayload, "utf8"),
  );
  if (
    entry.protocolVersion !== PROTOCOL_VERSION ||
    entry.logId !== receipt.logId ||
    entry.logIndex !== receipt.logIndex ||
    entry.previousEntryHash !== receipt.previousEntryHash ||
    entry.entryHash !== receipt.entryHash ||
    entry.signingKeyId !== receipt.signingKeyId ||
    entry.receiptPayloadHash !== expectedReceiptHash ||
    entry.headPayloadHash !== expectedHeadHash ||
    entry.generatedAt !== head.generatedAt ||
    head.treeSize !== receipt.logIndex ||
    head.headEntryHash !== receipt.entryHash ||
    head.signingKeyId !== receipt.signingKeyId ||
    !(await verifySignature(
      keyStore,
      TRANSPARENCY_RECEIPT_DOMAIN,
      canonicalReceiptPayload,
      entry.receiptSignature,
    )) ||
    !(await verifySignature(
      keyStore,
      TRANSPARENCY_LOG_HEAD_DOMAIN,
      entry.canonicalHeadPayload,
      entry.headSignature,
    ))
  ) {
    unavailable();
  }
  return responseFromEntry(entry);
}

async function validateMemberCertification(
  store,
  member,
  policyHash,
  keyStore,
) {
  const entry = await store.readEntry(member.logIndex);
  if (!entry) unavailable();
  let receipt;
  try {
    receipt = validateReceiptPayload(
      parseCompactCanonicalJson(
        entry.canonicalReceiptPayload,
        MAXIMUM_CANONICAL_PAYLOAD_BYTES,
      ),
      entry.canonicalReceiptPayload,
      keyStore,
    );
    await validateExistingEntry(
      entry,
      receipt,
      entry.canonicalReceiptPayload,
      keyStore,
    );
  } catch {
    unavailable();
  }
  if (
    receipt.protocolVersion !== member.protocolVersion ||
    receipt.eventId !== member.eventId ||
    receipt.inviteeId !== member.inviteeId ||
    receipt.policyHash !== policyHash ||
    receipt.accountKeyEpochId !== member.accountKeyEpochId ||
    receipt.revision !== member.revision ||
    receipt.envelopeId !== member.envelopeId ||
    receipt.ciphertextHash !== member.ciphertextHash ||
    receipt.responseSigningPublicKey !== member.responseSigningPublicKey ||
    receipt.committedAt !== member.committedAt ||
    receipt.logIndex !== member.logIndex ||
    receipt.entryHash !== member.entryHash
  ) {
    unavailable();
  }
}

async function validateTail(state, tail, keyStore) {
  if (!state || !tail) unavailable();
  const head = exactStoredHead(state.canonicalHeadPayload);
  if (
    state.protocolVersion !== PROTOCOL_VERSION ||
    state.logId !== TRANSPARENCY_LOG_ID ||
    !Number.isInteger(state.treeSize) ||
    state.treeSize < 1 ||
    state.headEntryHash !== canonicalHash(state.headEntryHash) ||
    state.signingKeyId !== keyStore.metadata.keys.transparencySigning.keyId ||
    state.treeSize !== head.treeSize ||
    state.headEntryHash !== head.headEntryHash ||
    state.signingKeyId !== head.signingKeyId ||
    state.generatedAt !== head.generatedAt ||
    state.headSignature !== tail.headSignature ||
    state.canonicalHeadPayload !== tail.canonicalHeadPayload ||
    tail.protocolVersion !== PROTOCOL_VERSION ||
    tail.logId !== state.logId ||
    tail.logIndex !== state.treeSize ||
    tail.entryHash !== state.headEntryHash ||
    tail.signingKeyId !== state.signingKeyId ||
    tail.generatedAt !== state.generatedAt
  ) {
    unavailable();
  }
  canonicalTimestamp(state.generatedAt);
  let receipt;
  try {
    receipt = validateReceiptPayload(
      parseCompactCanonicalJson(
        tail.canonicalReceiptPayload,
        MAXIMUM_CANONICAL_PAYLOAD_BYTES,
      ),
      tail.canonicalReceiptPayload,
      keyStore,
    );
  } catch {
    unavailable();
  }
  if (
    receipt.logIndex !== tail.logIndex ||
    receipt.previousEntryHash !== tail.previousEntryHash ||
    receipt.entryHash !== tail.entryHash ||
    tail.receiptPayloadHash !==
      sha256Base64Url(Buffer.from(tail.canonicalReceiptPayload, "utf8")) ||
    tail.headPayloadHash !==
      sha256Base64Url(Buffer.from(tail.canonicalHeadPayload, "utf8")) ||
    !(await verifySignature(
      keyStore,
      TRANSPARENCY_RECEIPT_DOMAIN,
      tail.canonicalReceiptPayload,
      tail.receiptSignature,
    )) ||
    !(await verifySignature(
      keyStore,
      TRANSPARENCY_LOG_HEAD_DOMAIN,
      state.canonicalHeadPayload,
      state.headSignature,
    ))
  ) {
    unavailable();
  }
}

function nextGeneratedAt(value, state) {
  if (!(value instanceof Date) || !Number.isFinite(value.getTime())) unavailable();
  const minimum = state ? canonicalTimestamp(state.generatedAt) + 1 : 0;
  return new Date(Math.max(value.getTime(), minimum)).toISOString();
}

export class StatefulTransparencyAuthority {
  constructor({ store, keyStore, clock = () => new Date() }) {
    if (
      !store ||
      typeof store.readEntry !== "function" ||
      typeof store.readState !== "function" ||
      typeof store.readPolicy !== "function" ||
      typeof store.readMember !== "function" ||
      typeof store.checkAvailable !== "function" ||
      typeof store.createPolicy !== "function" ||
      typeof store.commitResponseTransition !== "function" ||
      typeof store.commitEvaluation !== "function" ||
      !keyStore
    ) {
      throw new TypeError("transparency authority dependencies are required");
    }
    this.store = store;
    this.keyStore = keyStore;
    this.clock = clock;
  }

  async checkReady() {
    await this.store.checkAvailable();
    const state = await this.store.readState();
    if (!state) {
      // A missing tail is a pristine log only when the first immutable entry is
      // also absent. Treat an orphaned genesis entry as corruption at startup
      // instead of reporting ready and discovering it on the first append.
      if (await this.store.readEntry(1)) unavailable();
      return true;
    }
    const tail = await this.store.readEntry(state.treeSize);
    await validateTail(state, tail, this.keyStore);
    // Reading and verifying the durable tail proves Firestore availability and
    // public-key continuity, but it does not prove the process can still use
    // its in-memory transparency private key. Exercise that exact signing
    // primitive so a key-use failure removes this instance from service before
    // an RSVP discovers it.
    await signTransparencyPayload({
      kind: "log_head",
      canonicalPayload: state.canonicalHeadPayload,
      keyStore: this.keyStore,
    });
    if (state.treeSize < 2_147_483_647) {
      const impossibleSuccessor = await this.store.readEntry(state.treeSize + 1);
      if (impossibleSuccessor) unavailable();
    }
    return true;
  }

  async freezePolicy(value) {
    await this.store.checkAvailable();
    const commitments = policyCommitments(value, this.keyStore);
    for (let attempt = 0; attempt < MAXIMUM_COMMIT_ATTEMPTS; attempt += 1) {
      const existing = await this.store.readPolicy(commitments.eventId);
      if (existing) {
        const policy = storedPolicy(existing);
        if (!sameCommitments(policy, commitments)) conflict();
        return {
          protocolVersion: PROTOCOL_VERSION,
          eventId: policy.eventId,
          policyHash: policy.policyHash,
          rsvpDeadline: policy.rsvpDeadline,
        };
      }
      if (clockInstant(this.clock).getTime() > Date.parse(commitments.rsvpDeadline)) {
        conflict();
      }
      const committed = await this.store.createPolicy({
        ...commitments,
        responseSequence: 0,
        evaluationBatchHash: "",
        evaluatedAt: "",
      });
      if (committed === true) {
        return {
          protocolVersion: PROTOCOL_VERSION,
          eventId: commitments.eventId,
          policyHash: commitments.policyHash,
          rsvpDeadline: commitments.rsvpDeadline,
        };
      }
      // CAS loss and an indeterminate response both require an exact read.
    }
    unavailable();
  }

  async append(canonicalReceiptPayload) {
    await this.checkReady();
    const parsed = parseCompactCanonicalJson(
      canonicalReceiptPayload,
      MAXIMUM_CANONICAL_PAYLOAD_BYTES,
    );
    const receipt = validateReceiptPayload(
      parsed,
      canonicalReceiptPayload,
      this.keyStore,
    );

    for (let attempt = 0; attempt < MAXIMUM_COMMIT_ATTEMPTS; attempt += 1) {
      const existing = await this.store.readEntry(receipt.logIndex);
      if (existing) {
        const currentState = await this.store.readState();
        if (!currentState || currentState.treeSize < receipt.logIndex) {
          unavailable();
        }
        const currentTail = await this.store.readEntry(currentState.treeSize);
        await validateTail(currentState, currentTail, this.keyStore);
        return validateExistingEntry(
          existing,
          receipt,
          canonicalReceiptPayload,
          this.keyStore,
        );
      }

      const policyValue = await this.store.readPolicy(receipt.eventId);
      if (!policyValue) conflict();
      const policy = storedPolicy(policyValue);
      if (
        !policy.memberIds.includes(receipt.inviteeId) ||
        receipt.policyHash !== policy.policyHash
      ) {
        conflict();
      }
      const memberValue = await this.store.readMember(
        receipt.eventId,
        receipt.inviteeId,
      );
      const member = memberValue
        ? storedMember(memberValue, receipt.eventId, receipt.inviteeId)
        : null;
      if (member) {
        await validateMemberCertification(
          this.store,
          member,
          policy.policyHash,
          this.keyStore,
        );
      }
      const expectedRevision = (member?.revision ?? 0) + 1;
      const accountEpochChanged = Boolean(
        member && member.accountKeyEpochId !== receipt.accountKeyEpochId,
      );
      const responseSignerChanged = Boolean(
        member &&
          member.responseSigningPublicKey !== receipt.responseSigningPublicKey,
      );
      if (
        receipt.revision !== expectedRevision ||
        // A freshly phone-verified device switch rotates the account epoch and
        // response signer together. Either identity changing alone is an
        // unauthorized relabel or key substitution.
        accountEpochChanged !== responseSignerChanged ||
        !(await verifyResponseAuthorization(receipt))
      ) {
        conflict();
      }

      const state = await this.store.readState();
      if (state) {
        const tail = await this.store.readEntry(state.treeSize);
        await validateTail(state, tail, this.keyStore);
      }
      const expectedTreeSize = (state?.treeSize ?? 0) + 1;
      const expectedPreviousHash = state?.headEntryHash ?? Buffer.alloc(32).toString("base64url");
      if (
        receipt.logIndex !== expectedTreeSize ||
        receipt.previousEntryHash !== expectedPreviousHash
      ) {
        conflict();
      }

      const appendInstant = clockInstant(this.clock);
      if (Date.parse(receipt.committedAt) > appendInstant.getTime() + 30_000) {
        conflict();
      }
      const generatedAt = nextGeneratedAt(appendInstant, state);
      const canonicalHeadPayload = JSON.stringify({
        protocolVersion: PROTOCOL_VERSION,
        logId: TRANSPARENCY_LOG_ID,
        treeSize: receipt.logIndex,
        headEntryHash: receipt.entryHash,
        generatedAt,
        signingKeyId: receipt.signingKeyId,
      });
      const receiptCertification = await signTransparencyPayload({
        kind: "receipt",
        canonicalPayload: canonicalReceiptPayload,
        keyStore: this.keyStore,
      });
      const headCertification = await signTransparencyPayload({
        kind: "log_head",
        canonicalPayload: canonicalHeadPayload,
        keyStore: this.keyStore,
      });
      const entry = {
        protocolVersion: PROTOCOL_VERSION,
        logId: receipt.logId,
        logIndex: receipt.logIndex,
        previousEntryHash: receipt.previousEntryHash,
        entryHash: receipt.entryHash,
        canonicalReceiptPayload,
        signingKeyId: receipt.signingKeyId,
        receiptPayloadHash: receiptCertification.payloadHash,
        receiptSignature: receiptCertification.signature,
        canonicalHeadPayload,
        headPayloadHash: headCertification.payloadHash,
        headSignature: headCertification.signature,
        generatedAt,
      };
      const nextState = {
        protocolVersion: PROTOCOL_VERSION,
        logId: receipt.logId,
        treeSize: receipt.logIndex,
        headEntryHash: receipt.entryHash,
        canonicalHeadPayload,
        signingKeyId: receipt.signingKeyId,
        headSignature: headCertification.signature,
        generatedAt,
      };
      const nextPolicy = {
        protocolVersion: PROTOCOL_VERSION,
        eventId: policy.eventId,
        policyHash: policy.policyHash,
        rsvpDeadline: policy.rsvpDeadline,
        memberIds: policy.memberIds,
        releaseId: policy.releaseId,
        evaluatorKeyId: policy.evaluatorKeyId,
        responseSequence: policy.responseSequence + 1,
        evaluationBatchHash: "",
        evaluatedAt: "",
      };
      const nextMember = {
        protocolVersion: PROTOCOL_VERSION,
        eventId: receipt.eventId,
        inviteeId: receipt.inviteeId,
        revision: receipt.revision,
        envelopeId: receipt.envelopeId,
        ciphertextHash: receipt.ciphertextHash,
        committedAt: receipt.committedAt,
        logIndex: receipt.logIndex,
        entryHash: receipt.entryHash,
        accountKeyEpochId: receipt.accountKeyEpochId,
        responseSigningPublicKey: receipt.responseSigningPublicKey,
      };
      const committed = await this.store.commitResponseTransition({
        expectedStateVersion: state?.versionToken ?? null,
        expectedPolicyVersion: policy.versionToken,
        expectedMemberVersion: member?.versionToken ?? null,
        entry,
        state: nextState,
        policy: nextPolicy,
        member: nextMember,
      });
      if (committed === true) return responseFromEntry(entry);
      // CAS loss and an indeterminate network response both require a fresh
      // read. A successful but unacknowledged commit is returned byte-for-byte.
    }
    unavailable();
  }

  async consumeCanonicalBatch(value) {
    await this.checkReady();
    const claim = normalizeEvaluationClaim(value, this.keyStore);
    for (let attempt = 0; attempt < MAXIMUM_COMMIT_ATTEMPTS; attempt += 1) {
      const policyValue = await this.store.readPolicy(claim.eventId);
      if (!policyValue) conflict();
      const policy = storedPolicy(policyValue);
      if (!sameCommitments(policy, claim)) conflict();
      const evaluatedAt = clockInstant(this.clock);

      // These are deliberately exact per-member reads from the independently
      // administered authority. A backend-supplied subset is never sufficient.
      const members = await Promise.all(
        policy.memberIds.map(async (inviteeId) => {
          const member = await this.store.readMember(policy.eventId, inviteeId);
          if (!member) return null;
          const normalized = storedMember(member, policy.eventId, inviteeId);
          await validateMemberCertification(
            this.store,
            normalized,
            policy.policyHash,
            this.keyStore,
          );
          return normalized;
        }),
      );
      for (let index = 0; index < policy.memberIds.length; index += 1) {
        const member = members[index];
        const slot = claim.slots[index];
        if (
          slot.inviteeId !== policy.memberIds[index] ||
          (member === null &&
            (slot.envelopeHash !== null || slot.revision !== null)) ||
          (member !== null &&
            (slot.envelopeHash !== member.ciphertextHash ||
              slot.revision !== member.revision ||
              slot.responseSigningPublicKey !==
                member.responseSigningPublicKey))
        ) {
          conflict();
        }
      }

      if (policy.evaluationBatchHash !== "") {
        if (policy.evaluationBatchHash === claim.batchHash) {
          return {
            protocolVersion: PROTOCOL_VERSION,
            eventId: policy.eventId,
            batchHash: policy.evaluationBatchHash,
            evaluatedAt: policy.evaluatedAt,
          };
        }
      }

      const nextPolicy = {
        protocolVersion: PROTOCOL_VERSION,
        eventId: policy.eventId,
        policyHash: policy.policyHash,
        rsvpDeadline: policy.rsvpDeadline,
        memberIds: policy.memberIds,
        releaseId: policy.releaseId,
        evaluatorKeyId: policy.evaluatorKeyId,
        responseSequence: policy.responseSequence,
        evaluationBatchHash: claim.batchHash,
        evaluatedAt: evaluatedAt.toISOString(),
      };
      const committed = await this.store.commitEvaluation({
        expectedPolicyVersion: policy.versionToken,
        policy: nextPolicy,
      });
      if (committed === true) {
        return {
          protocolVersion: PROTOCOL_VERSION,
          eventId: policy.eventId,
          batchHash: claim.batchHash,
          evaluatedAt: nextPolicy.evaluatedAt,
        };
      }
      // An append or another evaluation won the policy CAS. Re-read all
      // members and the policy before accepting any result.
    }
    unavailable();
  }
}
