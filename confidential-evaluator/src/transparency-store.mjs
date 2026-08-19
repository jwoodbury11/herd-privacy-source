import { GOOGLE_FIRESTORE_ENDPOINT, PROTOCOL_VERSION } from "./constants.mjs";
import { serviceUnavailable } from "./errors.mjs";

const MAXIMUM_FIRESTORE_RESPONSE_BYTES = 128 * 1024;
const REQUEST_TIMEOUT_MS = 20_000;

function unavailable() {
  serviceUnavailable();
}

function record(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) unavailable();
  return value;
}

function exactRecord(value, expected) {
  const input = record(value);
  const actual = Object.keys(input).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    unavailable();
  }
  return input;
}

function boundedString(value, maximum = 64 * 1024, minimum = 1) {
  if (
    typeof value !== "string" ||
    value.length < minimum ||
    value.length > maximum ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    unavailable();
  }
  return value;
}

function firestoreString(field, maximum = 64 * 1024, minimum = 1) {
  const value = exactRecord(field, ["stringValue"]);
  return boundedString(value.stringValue, maximum, minimum);
}

function firestoreInteger(field, minimum = 1) {
  const value = exactRecord(field, ["integerValue"]);
  if (
    typeof value.integerValue !== "string" ||
    !/^(?:0|[1-9][0-9]*)$/u.test(value.integerValue)
  ) {
    unavailable();
  }
  const parsed = Number(value.integerValue);
  if (!Number.isSafeInteger(parsed) || parsed < minimum) unavailable();
  return parsed;
}

function stringValue(value) {
  return { stringValue: value };
}

function integerValue(value) {
  return { integerValue: String(value) };
}

async function boundedJson(response) {
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (declared > MAXIMUM_FIRESTORE_RESPONSE_BYTES) unavailable();
  const bytes = new Uint8Array(await response.arrayBuffer());
  if (bytes.length === 0 || bytes.length > MAXIMUM_FIRESTORE_RESPONSE_BYTES) {
    unavailable();
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    unavailable();
  } finally {
    bytes.fill(0);
  }
}

function entryFields(value) {
  const fields = exactRecord(value, [
    "protocolVersion",
    "logId",
    "logIndex",
    "previousEntryHash",
    "entryHash",
    "canonicalReceiptPayload",
    "signingKeyId",
    "receiptPayloadHash",
    "receiptSignature",
    "canonicalHeadPayload",
    "headPayloadHash",
    "headSignature",
    "generatedAt",
  ]);
  if (firestoreInteger(fields.protocolVersion) !== PROTOCOL_VERSION) unavailable();
  return {
    protocolVersion: PROTOCOL_VERSION,
    logId: firestoreString(fields.logId),
    logIndex: firestoreInteger(fields.logIndex),
    previousEntryHash: firestoreString(fields.previousEntryHash),
    entryHash: firestoreString(fields.entryHash),
    canonicalReceiptPayload: firestoreString(fields.canonicalReceiptPayload),
    signingKeyId: firestoreString(fields.signingKeyId),
    receiptPayloadHash: firestoreString(fields.receiptPayloadHash),
    receiptSignature: firestoreString(fields.receiptSignature),
    canonicalHeadPayload: firestoreString(fields.canonicalHeadPayload),
    headPayloadHash: firestoreString(fields.headPayloadHash),
    headSignature: firestoreString(fields.headSignature),
    generatedAt: firestoreString(fields.generatedAt),
  };
}

function stateFields(value) {
  const fields = exactRecord(value, [
    "protocolVersion",
    "logId",
    "treeSize",
    "headEntryHash",
    "canonicalHeadPayload",
    "signingKeyId",
    "headSignature",
    "generatedAt",
  ]);
  if (firestoreInteger(fields.protocolVersion) !== PROTOCOL_VERSION) unavailable();
  return {
    protocolVersion: PROTOCOL_VERSION,
    logId: firestoreString(fields.logId),
    treeSize: firestoreInteger(fields.treeSize),
    headEntryHash: firestoreString(fields.headEntryHash),
    canonicalHeadPayload: firestoreString(fields.canonicalHeadPayload),
    signingKeyId: firestoreString(fields.signingKeyId),
    headSignature: firestoreString(fields.headSignature),
    generatedAt: firestoreString(fields.generatedAt),
  };
}

function memberIds(value) {
  const canonical = firestoreString(value, 4 * 1024);
  let parsed;
  try {
    parsed = JSON.parse(canonical);
  } catch {
    unavailable();
  }
  if (
    !Array.isArray(parsed) ||
    parsed.length < 1 ||
    parsed.length > 19 ||
    parsed.some(
      (memberId, index) =>
        typeof memberId !== "string" ||
        memberId.length > 120 ||
        (index > 0 && memberId.localeCompare(parsed[index - 1]) <= 0),
    ) ||
    JSON.stringify(parsed) !== canonical
  ) {
    unavailable();
  }
  return parsed;
}

function policyFields(value) {
  const fields = exactRecord(value, [
    "protocolVersion",
    "eventId",
    "policyHash",
    "rsvpDeadline",
    "memberIdsJson",
    "releaseId",
    "evaluatorKeyId",
    "responseSequence",
    "evaluationBatchHash",
    "evaluatedAt",
  ]);
  if (firestoreInteger(fields.protocolVersion) !== PROTOCOL_VERSION) unavailable();
  return {
    protocolVersion: PROTOCOL_VERSION,
    eventId: firestoreString(fields.eventId, 120),
    policyHash: firestoreString(fields.policyHash, 64),
    rsvpDeadline: firestoreString(fields.rsvpDeadline, 128),
    memberIds: memberIds(fields.memberIdsJson),
    releaseId: firestoreString(fields.releaseId, 200),
    evaluatorKeyId: firestoreString(fields.evaluatorKeyId, 120),
    responseSequence: firestoreInteger(fields.responseSequence, 0),
    evaluationBatchHash: firestoreString(fields.evaluationBatchHash, 64, 0),
    evaluatedAt: firestoreString(fields.evaluatedAt, 128, 0),
  };
}

function memberFields(value) {
  const fields = exactRecord(value, [
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
  ]);
  if (firestoreInteger(fields.protocolVersion) !== PROTOCOL_VERSION) unavailable();
  return {
    protocolVersion: PROTOCOL_VERSION,
    eventId: firestoreString(fields.eventId, 120),
    inviteeId: firestoreString(fields.inviteeId, 120),
    revision: firestoreInteger(fields.revision),
    envelopeId: firestoreString(fields.envelopeId, 120),
    ciphertextHash: firestoreString(fields.ciphertextHash, 64),
    committedAt: firestoreString(fields.committedAt, 128),
    logIndex: firestoreInteger(fields.logIndex),
    entryHash: firestoreString(fields.entryHash, 64),
    accountKeyEpochId: firestoreString(fields.accountKeyEpochId, 120),
    responseSigningPublicKey: firestoreString(
      fields.responseSigningPublicKey,
      64,
    ),
  };
}

function entryDocument(name, entry) {
  return {
    name,
    fields: {
      protocolVersion: integerValue(PROTOCOL_VERSION),
      logId: stringValue(entry.logId),
      logIndex: integerValue(entry.logIndex),
      previousEntryHash: stringValue(entry.previousEntryHash),
      entryHash: stringValue(entry.entryHash),
      canonicalReceiptPayload: stringValue(entry.canonicalReceiptPayload),
      signingKeyId: stringValue(entry.signingKeyId),
      receiptPayloadHash: stringValue(entry.receiptPayloadHash),
      receiptSignature: stringValue(entry.receiptSignature),
      canonicalHeadPayload: stringValue(entry.canonicalHeadPayload),
      headPayloadHash: stringValue(entry.headPayloadHash),
      headSignature: stringValue(entry.headSignature),
      generatedAt: stringValue(entry.generatedAt),
    },
  };
}

function stateDocument(name, state) {
  return {
    name,
    fields: {
      protocolVersion: integerValue(PROTOCOL_VERSION),
      logId: stringValue(state.logId),
      treeSize: integerValue(state.treeSize),
      headEntryHash: stringValue(state.headEntryHash),
      canonicalHeadPayload: stringValue(state.canonicalHeadPayload),
      signingKeyId: stringValue(state.signingKeyId),
      headSignature: stringValue(state.headSignature),
      generatedAt: stringValue(state.generatedAt),
    },
  };
}

function policyDocument(name, policy) {
  return {
    name,
    fields: {
      protocolVersion: integerValue(PROTOCOL_VERSION),
      eventId: stringValue(policy.eventId),
      policyHash: stringValue(policy.policyHash),
      rsvpDeadline: stringValue(policy.rsvpDeadline),
      memberIdsJson: stringValue(JSON.stringify(policy.memberIds)),
      releaseId: stringValue(policy.releaseId),
      evaluatorKeyId: stringValue(policy.evaluatorKeyId),
      responseSequence: integerValue(policy.responseSequence),
      evaluationBatchHash: stringValue(policy.evaluationBatchHash),
      evaluatedAt: stringValue(policy.evaluatedAt),
    },
  };
}

function memberDocument(name, member) {
  return {
    name,
    fields: {
      protocolVersion: integerValue(PROTOCOL_VERSION),
      eventId: stringValue(member.eventId),
      inviteeId: stringValue(member.inviteeId),
      revision: integerValue(member.revision),
      envelopeId: stringValue(member.envelopeId),
      ciphertextHash: stringValue(member.ciphertextHash),
      committedAt: stringValue(member.committedAt),
      logIndex: integerValue(member.logIndex),
      entryHash: stringValue(member.entryHash),
      accountKeyEpochId: stringValue(member.accountKeyEpochId),
      responseSigningPublicKey: stringValue(member.responseSigningPublicKey),
    },
  };
}

export class FirestoreTransparencyStore {
  #availabilityCheck = null;
  #availabilityVerifiedUntil = 0;

  constructor({
    projectId,
    databaseId,
    collectionId,
    accessTokenProvider,
    fetchImplementation = globalThis.fetch,
    clock = () => Date.now(),
  }) {
    if (!accessTokenProvider || typeof accessTokenProvider.getAccessToken !== "function") {
      throw new TypeError("a federated access-token provider is required");
    }
    this.accessTokenProvider = accessTokenProvider;
    this.fetch = fetchImplementation;
    this.clock = clock;
    this.databaseName = `projects/${projectId}/databases/${databaseId}`;
    this.databaseUrl = `${GOOGLE_FIRESTORE_ENDPOINT}/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(databaseId)}`;
    this.documentsRoot = `${GOOGLE_FIRESTORE_ENDPOINT}/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(databaseId)}/documents`;
    this.stateName = `projects/${projectId}/databases/${databaseId}/documents/${collectionId}/tail`;
    this.stateUrl = `${this.documentsRoot}/${encodeURIComponent(collectionId)}/tail`;
    this.entriesRootName = `${this.stateName}/entries`;
    this.entriesRootUrl = `${this.stateUrl}/entries`;
    this.policiesRootName = `${this.stateName}/policies`;
    this.policiesRootUrl = `${this.stateUrl}/policies`;
    this.commitUrl = `${GOOGLE_FIRESTORE_ENDPOINT}/projects/${encodeURIComponent(projectId)}/databases/${encodeURIComponent(databaseId)}/documents:commit`;
  }

  #entryId(logIndex) {
    return String(logIndex).padStart(10, "0");
  }

  async #headers() {
    const token = await this.accessTokenProvider.getAccessToken();
    if (typeof token !== "string" || token.length < 20 || token.length > 64 * 1024) {
      unavailable();
    }
    return {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    };
  }

  async #read(url, expectedName, parseFields) {
    let response;
    try {
      response = await this.fetch(url, {
        method: "GET",
        headers: await this.#headers(),
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      unavailable();
    }
    if (response.status === 404) return null;
    if (response.status !== 200) unavailable();
    const document = exactRecord(await boundedJson(response), [
      "name",
      "fields",
      "createTime",
      "updateTime",
    ]);
    if (document.name !== expectedName) unavailable();
    return {
      ...parseFields(document.fields),
      versionToken: boundedString(document.updateTime, 128),
    };
  }

  async #commit(writes) {
    let response;
    try {
      response = await this.fetch(this.commitUrl, {
        method: "POST",
        headers: await this.#headers(),
        body: JSON.stringify({ writes }),
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      // A commit can have succeeded even when its response was lost. Callers
      // always resolve this state by re-reading the exact documents.
      return null;
    }
    if (response.status === 200) return true;
    if (response.status === 409 || response.status === 412) return false;
    if (response.status === 429 || response.status >= 500) return null;
    unavailable();
  }

  async readEntry(logIndex) {
    const id = this.#entryId(logIndex);
    return this.#read(
      `${this.entriesRootUrl}/${id}`,
      `${this.entriesRootName}/${id}`,
      entryFields,
    );
  }

  async checkAvailable() {
    if (this.clock() < this.#availabilityVerifiedUntil) return true;
    if (this.#availabilityCheck) return this.#availabilityCheck;
    this.#availabilityCheck = this.#checkAvailable();
    try {
      return await this.#availabilityCheck;
    } finally {
      this.#availabilityCheck = null;
    }
  }

  async #checkAvailable() {
    let response;
    try {
      response = await this.fetch(this.databaseUrl, {
        method: "GET",
        headers: await this.#headers(),
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      unavailable();
    }
    if (response.status !== 200) unavailable();
    const database = record(await boundedJson(response));
    if (
      database.name !== this.databaseName ||
      database.type !== "FIRESTORE_NATIVE" ||
      database.deleteProtectionState !== "DELETE_PROTECTION_ENABLED" ||
      database.pointInTimeRecoveryEnablement !== "POINT_IN_TIME_RECOVERY_ENABLED"
    ) {
      unavailable();
    }
    // The database-administration metadata endpoint has a substantially lower
    // operational budget than document reads. Reconfirm the immutable safety
    // flags once per minute per replica while every readiness check continues
    // to read and validate the durable log tail below this store layer.
    this.#availabilityVerifiedUntil = this.clock() + 60_000;
    return true;
  }

  async readState() {
    return this.#read(this.stateUrl, this.stateName, stateFields);
  }

  async readPolicy(eventId) {
    const encoded = encodeURIComponent(eventId);
    return this.#read(
      `${this.policiesRootUrl}/${encoded}`,
      `${this.policiesRootName}/${eventId}`,
      policyFields,
    );
  }

  async readMember(eventId, inviteeId) {
    const policyName = `${this.policiesRootName}/${eventId}`;
    return this.#read(
      `${this.policiesRootUrl}/${encodeURIComponent(eventId)}/members/${encodeURIComponent(inviteeId)}`,
      `${policyName}/members/${inviteeId}`,
      memberFields,
    );
  }

  async createPolicy(policy) {
    const name = `${this.policiesRootName}/${policy.eventId}`;
    return this.#commit([
      {
        update: policyDocument(name, policy),
        currentDocument: { exists: false },
      },
    ]);
  }

  async replacePendingPolicy({ expectedPolicyVersion, policy }) {
    const name = `${this.policiesRootName}/${policy.eventId}`;
    return this.#commit([
      {
        update: policyDocument(name, policy),
        currentDocument: { updateTime: expectedPolicyVersion },
      },
    ]);
  }

  async commitTransition({ expectedStateVersion, entry, state }) {
    const id = this.#entryId(entry.logIndex);
    return this.#commit([
      {
        update: stateDocument(this.stateName, state),
        currentDocument:
          expectedStateVersion === null
            ? { exists: false }
            : { updateTime: expectedStateVersion },
      },
      {
        update: entryDocument(`${this.entriesRootName}/${id}`, entry),
        currentDocument: { exists: false },
      },
    ]);
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
    const entryId = this.#entryId(entry.logIndex);
    const policyName = `${this.policiesRootName}/${policy.eventId}`;
    const memberName = `${policyName}/members/${member.inviteeId}`;
    return this.#commit([
      {
        update: stateDocument(this.stateName, state),
        currentDocument:
          expectedStateVersion === null
            ? { exists: false }
            : { updateTime: expectedStateVersion },
      },
      {
        update: entryDocument(`${this.entriesRootName}/${entryId}`, entry),
        currentDocument: { exists: false },
      },
      {
        update: policyDocument(policyName, policy),
        currentDocument: { updateTime: expectedPolicyVersion },
      },
      {
        update: memberDocument(memberName, member),
        currentDocument:
          expectedMemberVersion === null
            ? { exists: false }
            : { updateTime: expectedMemberVersion },
      },
    ]);
  }

  async commitEvaluation({ expectedPolicyVersion, policy }) {
    const name = `${this.policiesRootName}/${policy.eventId}`;
    return this.#commit([
      {
        update: policyDocument(name, policy),
        currentDocument: { updateTime: expectedPolicyVersion },
      },
    ]);
  }
}
