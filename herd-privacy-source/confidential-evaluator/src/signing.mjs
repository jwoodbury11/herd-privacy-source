import { webcrypto } from "node:crypto";

import {
  CIPHER_SUITE,
  EVALUATION_RESULT_DOMAIN,
  MAXIMUM_CANONICAL_PAYLOAD_BYTES,
  POLICY_SIGNATURE_DOMAIN,
  PROTOCOL_VERSION,
  TRANSPARENCY_LOG_HEAD_DOMAIN,
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_ID,
  TRANSPARENCY_RECONCILIATION_DOMAIN,
  TRANSPARENCY_RECEIPT_DOMAIN,
} from "./constants.mjs";
import {
  decodeBase64Url,
  domainSeparatedBytes,
  encodeBase64Url,
  exactKeys,
  parseCompactCanonicalJson,
  sha256Base64Url,
} from "./encoding.mjs";
import { invalidRequest, serviceUnavailable } from "./errors.mjs";

const UUID_PATTERN =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9._-]{1,120}$/u;
const PADDED_PLAINTEXT_BYTES = 4096;
const MAXIMUM_INVITEES = 19;
const MAXIMUM_LOG_INDEX = 2_147_483_647;
const MAXIMUM_RESPONSE_REVISION = 1_000_000;
const GENESIS_ENTRY_HASH = Buffer.alloc(32).toString("base64url");

function boundedString(value, minimum, maximum) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    invalidRequest();
  }
  return value;
}

function uuid(value) {
  if (typeof value !== "string" || !UUID_PATTERN.test(value)) invalidRequest();
  return value;
}

function integer(value, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    invalidRequest();
  }
  return value;
}

function canonicalTimestamp(value) {
  if (typeof value !== "string") invalidRequest();
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp) || new Date(timestamp).toISOString() !== value) {
    invalidRequest();
  }
  return value;
}

function requiredGroups(value, memberIds) {
  if (!Array.isArray(value) || value.length > memberIds.length) invalidRequest();
  const allowed = new Set(memberIds);
  const seenGroupIds = new Set();
  const seenMemberIds = new Set();
  let previousGroupId = "";
  return value.map((rawGroup) => {
    const group = exactKeys(rawGroup, ["id", "memberIDs"]);
    const id = uuid(group.id);
    if (
      seenGroupIds.has(id) ||
      (previousGroupId && id.localeCompare(previousGroupId) <= 0)
    ) {
      invalidRequest();
    }
    previousGroupId = id;
    seenGroupIds.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      invalidRequest();
    }
    let previousMemberId = "";
    const memberIDs = group.memberIDs.map((rawMemberId) => {
      const memberId = uuid(rawMemberId);
      if (
        !allowed.has(memberId) ||
        seenMemberIds.has(memberId) ||
        (previousMemberId && memberId.localeCompare(previousMemberId) <= 0)
      ) {
        invalidRequest();
      }
      previousMemberId = memberId;
      seenMemberIds.add(memberId);
      return memberId;
    });
    return { id, memberIDs };
  });
}

async function signature(privateKey, domain, payload) {
  let bytes;
  try {
    bytes = new Uint8Array(
      await webcrypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        domainSeparatedBytes(domain, payload),
      ),
    );
  } catch {
    serviceUnavailable();
  }
  if (bytes.length !== 64) serviceUnavailable();
  return encodeBase64Url(bytes);
}

function validatePolicyDescriptor(parsed, canonicalDocument, config, keyStore) {
  exactKeys(parsed, [
    "protocolVersion",
    "cipherSuite",
    "event",
    "members",
    "hostRules",
    "rsvpDeadline",
    "revealPolicy",
    "limits",
    "evaluator",
    "releaseId",
  ]);
  if (
    parsed.protocolVersion !== PROTOCOL_VERSION ||
    parsed.cipherSuite !== CIPHER_SUITE
  ) {
    invalidRequest();
  }

  const rawEvent = exactKeys(parsed.event, [
    "id",
    "title",
    "eventDate",
    "endDate",
    "hostName",
    "locationName",
    "locationAddress",
    "eventDescription",
  ]);
  const eventDate = canonicalTimestamp(rawEvent.eventDate);
  const endDate =
    rawEvent.endDate === null ? null : canonicalTimestamp(rawEvent.endDate);
  if (endDate !== null && endDate <= eventDate) invalidRequest();
  const event = {
    id: uuid(rawEvent.id),
    title: boundedString(rawEvent.title, 1, 120),
    eventDate,
    endDate,
    hostName: boundedString(rawEvent.hostName, 1, 80),
    locationName: boundedString(rawEvent.locationName, 0, 160),
    locationAddress: boundedString(rawEvent.locationAddress, 0, 300),
    eventDescription: boundedString(rawEvent.eventDescription, 0, 2000),
  };

  if (
    !Array.isArray(parsed.members) ||
    parsed.members.length === 0 ||
    parsed.members.length > MAXIMUM_INVITEES
  ) {
    invalidRequest();
  }
  const seenMembers = new Set();
  let previousMemberId = "";
  const members = parsed.members.map((rawMember) => {
    const member = exactKeys(rawMember, ["id"]);
    const id = uuid(member.id);
    if (
      seenMembers.has(id) ||
      (previousMemberId && id.localeCompare(previousMemberId) <= 0)
    ) {
      invalidRequest();
    }
    previousMemberId = id;
    seenMembers.add(id);
    return { id };
  });
  const memberIds = members.map(({ id }) => id);

  const rawHostRules = exactKeys(parsed.hostRules, [
    "minimumParticipants",
    "requiredGroups",
  ]);
  const hostRules = {
    minimumParticipants: integer(
      rawHostRules.minimumParticipants,
      2,
      members.length + 1,
    ),
    requiredGroups: requiredGroups(rawHostRules.requiredGroups, memberIds),
  };

  const rsvpDeadline = canonicalTimestamp(parsed.rsvpDeadline);
  if (rsvpDeadline >= eventDate) invalidRequest();
  if (parsed.revealPolicy !== "not_confirmed_or_confirmed_attendance") {
    invalidRequest();
  }

  const rawLimits = exactKeys(parsed.limits, [
    "maximumParticipants",
    "maximumConditionGroups",
    "maximumMembersPerGroup",
    "paddedPlaintextBytes",
  ]);
  const limits = {
    maximumParticipants: integer(
      rawLimits.maximumParticipants,
      members.length + 1,
      members.length + 1,
    ),
    maximumConditionGroups: integer(
      rawLimits.maximumConditionGroups,
      members.length,
      members.length,
    ),
    maximumMembersPerGroup: integer(
      rawLimits.maximumMembersPerGroup,
      members.length,
      members.length,
    ),
    paddedPlaintextBytes: integer(
      rawLimits.paddedPlaintextBytes,
      PADDED_PLAINTEXT_BYTES,
      PADDED_PLAINTEXT_BYTES,
    ),
  };

  const rawEvaluator = exactKeys(parsed.evaluator, [
    "keyId",
    "publicKey",
    "measurement",
  ]);
  const expected = keyStore.metadata.keys.responseDecryption;
  const evaluatorPublicKey = encodeBase64Url(
    decodeBase64Url(rawEvaluator.publicKey, 65),
  );
  if (
    !IDENTIFIER_PATTERN.test(rawEvaluator.keyId) ||
    Buffer.from(evaluatorPublicKey, "base64url")[0] !== 0x04 ||
    rawEvaluator.keyId !== expected.keyId ||
    evaluatorPublicKey !== expected.publicKey ||
    rawEvaluator.measurement !== config.evaluatorMeasurement
  ) {
    invalidRequest();
  }
  const evaluator = {
    keyId: rawEvaluator.keyId,
    publicKey: evaluatorPublicKey,
    measurement: boundedString(rawEvaluator.measurement, 1, 500),
  };
  const releaseId = boundedString(parsed.releaseId, 1, 200);
  if (releaseId !== config.releaseId) invalidRequest();

  const normalized = {
    protocolVersion: PROTOCOL_VERSION,
    cipherSuite: CIPHER_SUITE,
    event,
    members,
    hostRules,
    rsvpDeadline,
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits,
    evaluator,
    releaseId,
  };
  if (
    JSON.stringify(normalized) !== canonicalDocument ||
    Buffer.byteLength(canonicalDocument, "utf8") > MAXIMUM_CANONICAL_PAYLOAD_BYTES
  ) {
    invalidRequest();
  }
  return normalized;
}

export function policyAuthorityRecord({ canonicalDocument, config, keyStore }) {
  const parsed = parseCompactCanonicalJson(
    canonicalDocument,
    MAXIMUM_CANONICAL_PAYLOAD_BYTES,
  );
  const normalized = validatePolicyDescriptor(
    parsed,
    canonicalDocument,
    config,
    keyStore,
  );
  return {
    protocolVersion: PROTOCOL_VERSION,
    eventId: normalized.event.id,
    policyHash: sha256Base64Url(Buffer.from(canonicalDocument, "utf8")),
    rsvpDeadline: normalized.rsvpDeadline,
    memberIds: normalized.members.map(({ id }) => id),
    releaseId: normalized.releaseId,
    evaluatorKeyId: normalized.evaluator.keyId,
  };
}

export async function signPolicyDescriptor({ canonicalDocument, config, keyStore }) {
  policyAuthorityRecord({ canonicalDocument, config, keyStore });
  return {
    protocolVersion: PROTOCOL_VERSION,
    domain: POLICY_SIGNATURE_DOMAIN,
    signingKeyId: keyStore.keys.policySigning.keyId,
    payloadHash: sha256Base64Url(Buffer.from(canonicalDocument, "utf8")),
    signature: await signature(
      keyStore.keys.policySigning.privateKey,
      POLICY_SIGNATURE_DOMAIN,
      canonicalDocument,
    ),
  };
}

function canonicalHash(value) {
  return encodeBase64Url(decodeBase64Url(value, 32));
}

export function validateReceiptPayload(parsed, canonicalPayload, keyStore) {
  exactKeys(parsed, [
    "protocolVersion",
    "logId",
    "logIndex",
    "previousEntryHash",
    "entryHash",
    "envelopeId",
    "eventId",
    "inviteeId",
    "policyHash",
    "accountKeyEpochId",
    "revision",
    "ciphertextHash",
    "responseSigningPublicKey",
    "responseSignature",
    "committedAt",
    "signingKeyId",
  ]);
  const logIndex = integer(parsed.logIndex, 1, MAXIMUM_LOG_INDEX);
  const previousEntryHash = canonicalHash(parsed.previousEntryHash);
  const entryHash = canonicalHash(parsed.entryHash);
  const normalized = {
    protocolVersion: PROTOCOL_VERSION,
    logId: TRANSPARENCY_LOG_ID,
    logIndex,
    previousEntryHash,
    entryHash,
    envelopeId: uuid(parsed.envelopeId),
    eventId: uuid(parsed.eventId),
    inviteeId: uuid(parsed.inviteeId),
    policyHash: canonicalHash(parsed.policyHash),
    accountKeyEpochId: uuid(parsed.accountKeyEpochId),
    revision: integer(parsed.revision, 1, MAXIMUM_RESPONSE_REVISION),
    ciphertextHash: canonicalHash(parsed.ciphertextHash),
    responseSigningPublicKey: encodeBase64Url(
      decodeBase64Url(parsed.responseSigningPublicKey, 32),
    ),
    responseSignature: encodeBase64Url(
      decodeBase64Url(parsed.responseSignature, 64),
    ),
    committedAt: canonicalTimestamp(parsed.committedAt),
    signingKeyId: keyStore.keys.transparencySigning.keyId,
  };
  if (
    parsed.protocolVersion !== PROTOCOL_VERSION ||
    parsed.logId !== TRANSPARENCY_LOG_ID ||
    parsed.signingKeyId !== normalized.signingKeyId ||
    (logIndex === 1) !== (previousEntryHash === GENESIS_ENTRY_HASH)
  ) {
    invalidRequest();
  }
  const canonicalEntryCore = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    logId: TRANSPARENCY_LOG_ID,
    logIndex,
    previousEntryHash,
    envelopeId: normalized.envelopeId,
    eventId: normalized.eventId,
    inviteeId: normalized.inviteeId,
    policyHash: normalized.policyHash,
    accountKeyEpochId: normalized.accountKeyEpochId,
    revision: normalized.revision,
    ciphertextHash: normalized.ciphertextHash,
    responseSigningPublicKey: normalized.responseSigningPublicKey,
    responseSignature: normalized.responseSignature,
    committedAt: normalized.committedAt,
  });
  const expectedEntryHash = sha256Base64Url(
    domainSeparatedBytes(
      TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
      canonicalEntryCore,
    ),
  );
  if (
    entryHash !== expectedEntryHash ||
    JSON.stringify(normalized) !== canonicalPayload
  ) {
    invalidRequest();
  }
  return normalized;
}

export function validateLogHeadPayload(parsed, canonicalPayload, keyStore) {
  exactKeys(parsed, [
    "protocolVersion",
    "logId",
    "treeSize",
    "headEntryHash",
    "generatedAt",
    "signingKeyId",
  ]);
  const headEntryHash = canonicalHash(parsed.headEntryHash);
  const normalized = {
    protocolVersion: PROTOCOL_VERSION,
    logId: TRANSPARENCY_LOG_ID,
    treeSize: integer(parsed.treeSize, 1, MAXIMUM_LOG_INDEX),
    headEntryHash,
    generatedAt: canonicalTimestamp(parsed.generatedAt),
    signingKeyId: keyStore.keys.transparencySigning.keyId,
  };
  if (
    parsed.protocolVersion !== PROTOCOL_VERSION ||
    parsed.logId !== TRANSPARENCY_LOG_ID ||
    parsed.signingKeyId !== normalized.signingKeyId ||
    headEntryHash === GENESIS_ENTRY_HASH ||
    JSON.stringify(normalized) !== canonicalPayload
  ) {
    invalidRequest();
  }
  return normalized;
}

export async function signTransparencyPayload({ kind, canonicalPayload, keyStore }) {
  const parsed = parseCompactCanonicalJson(
    canonicalPayload,
    MAXIMUM_CANONICAL_PAYLOAD_BYTES,
  );
  const domain =
    kind === "receipt"
      ? TRANSPARENCY_RECEIPT_DOMAIN
      : kind === "log_head"
        ? TRANSPARENCY_LOG_HEAD_DOMAIN
        : invalidRequest();
  if (kind === "receipt") {
    validateReceiptPayload(parsed, canonicalPayload, keyStore);
  } else {
    validateLogHeadPayload(parsed, canonicalPayload, keyStore);
  }
  return {
    protocolVersion: PROTOCOL_VERSION,
    kind,
    domain,
    signingKeyId: keyStore.keys.transparencySigning.keyId,
    payloadHash: sha256Base64Url(Buffer.from(canonicalPayload, "utf8")),
    signature: await signature(
      keyStore.keys.transparencySigning.privateKey,
      domain,
      canonicalPayload,
    ),
  };
}

export async function signTransparencyReconciliation({
  rejectedLogIndex,
  rejectedEntryHash,
  authorityTreeSize,
  authorityHeadEntryHash,
  generatedAt,
  keyStore,
}) {
  const normalizedRejectedLogIndex = integer(
    rejectedLogIndex,
    1,
    MAXIMUM_LOG_INDEX,
  );
  const normalizedAuthorityTreeSize = integer(
    authorityTreeSize,
    0,
    MAXIMUM_LOG_INDEX - 1,
  );
  const normalizedRejectedEntryHash = canonicalHash(rejectedEntryHash);
  const normalizedAuthorityHeadEntryHash = canonicalHash(
    authorityHeadEntryHash,
  );
  if (
    normalizedRejectedLogIndex !== normalizedAuthorityTreeSize + 1 ||
    (normalizedAuthorityTreeSize === 0) !==
      (normalizedAuthorityHeadEntryHash === GENESIS_ENTRY_HASH)
  ) {
    invalidRequest();
  }
  const canonicalPayload = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    logId: TRANSPARENCY_LOG_ID,
    rejectedLogIndex: normalizedRejectedLogIndex,
    rejectedEntryHash: normalizedRejectedEntryHash,
    authorityTreeSize: normalizedAuthorityTreeSize,
    authorityHeadEntryHash: normalizedAuthorityHeadEntryHash,
    generatedAt: canonicalTimestamp(generatedAt),
    signingKeyId: keyStore.keys.transparencySigning.keyId,
  });
  return {
    canonicalPayload,
    domain: TRANSPARENCY_RECONCILIATION_DOMAIN,
    payloadHash: sha256Base64Url(Buffer.from(canonicalPayload, "utf8")),
    signature: await signature(
      keyStore.keys.transparencySigning.privateKey,
      TRANSPARENCY_RECONCILIATION_DOMAIN,
      canonicalPayload,
    ),
    signingKeyId: keyStore.keys.transparencySigning.keyId,
  };
}

export async function signEvaluationResult({ result, evaluatedAt, keyStore }) {
  const canonicalDocument = JSON.stringify({
    protocolVersion: PROTOCOL_VERSION,
    signingKeyId: keyStore.keys.evaluationResultSigning.keyId,
    evaluatedAt,
    result,
  });
  return {
    protocolVersion: PROTOCOL_VERSION,
    domain: EVALUATION_RESULT_DOMAIN,
    signingKeyId: keyStore.keys.evaluationResultSigning.keyId,
    evaluatedAt,
    payloadHash: sha256Base64Url(Buffer.from(canonicalDocument, "utf8")),
    signature: await signature(
      keyStore.keys.evaluationResultSigning.privateKey,
      EVALUATION_RESULT_DOMAIN,
      canonicalDocument,
    ),
  };
}
