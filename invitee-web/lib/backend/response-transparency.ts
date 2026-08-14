import type { HerdBindings } from "@/db";
import {
  PRIVATE_RESPONSE_HASH_BYTES,
  PRIVATE_RESPONSE_LOG_ID,
  PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN,
  PRIVATE_RESPONSE_PROTOCOL_VERSION,
  bytesToBase64Url,
  canonicalPrivateResponseLogEntryCore,
  canonicalPrivateResponseLogHeadPayload,
  canonicalPrivateResponseReceiptPayload,
  domainSeparatedUtf8,
  type PrivateResponseLogHeadV1,
  type PrivateResponseReceiptCoreV1,
  type PrivateResponseReceiptV1,
  type PrivateResponseTransparencyProofV1,
  type StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";

import { getEvaluatorTrustSigningConfig } from "./config";
import {
  TransparencyLateMissingEntryError,
  appendTransparencyEntry,
  type EvaluatorTransparencyReconciliationProof,
} from "./evaluator-trust";
import { ApiError } from "./http";

const RESPONSE_LOG_ID = PRIVATE_RESPONSE_LOG_ID;
const GENESIS_HASH = bytesToBase64Url(
  new Uint8Array(PRIVATE_RESPONSE_HASH_BYTES),
);
const MAXIMUM_APPEND_ATTEMPTS = 16;
const MAXIMUM_PREFIX_CERTIFICATIONS = 64;

function ownedArrayBuffer(value: Uint8Array): ArrayBuffer {
  return Uint8Array.from(value).buffer;
}

type TransparencyEntryRow = {
  logIndex: number;
  logId: string;
  previousEntryHash: string;
  entryHash: string;
  envelopeId: string;
  canonicalReceiptPayload: string;
  signingKeyId: string;
  receiptSignature: string | null;
  createdAt: string;
  signedAt: string | null;
};

type TransparencyHeadRow = {
  logIndex: number;
  logId: string;
  headEntryHash: string;
  canonicalPayload: string;
  signingKeyId: string;
  signature: string;
  generatedAt: string;
};

const ENTRY_SELECT = `SELECT
  log_index AS logIndex,
  log_id AS logId,
  previous_entry_hash AS previousEntryHash,
  entry_hash AS entryHash,
  envelope_id AS envelopeId,
  canonical_receipt_payload AS canonicalReceiptPayload,
  signing_key_id AS signingKeyId,
  receipt_signature AS receiptSignature,
  created_at AS createdAt,
  signed_at AS signedAt
FROM response_transparency_entries`;

const HEAD_SELECT = `SELECT
  log_index AS logIndex,
  log_id AS logId,
  head_entry_hash AS headEntryHash,
  canonical_payload AS canonicalPayload,
  signing_key_id AS signingKeyId,
  signature,
  generated_at AS generatedAt
FROM response_transparency_heads`;

function receiptCore(
  envelope: StoredPrivateResponseEnvelopeV1,
): PrivateResponseReceiptCoreV1 {
  return {
    envelopeId: envelope.envelopeId,
    eventId: envelope.eventId,
    inviteeId: envelope.inviteeId,
    policyHash: envelope.policyHash,
    accountKeyEpochId: envelope.accountKeyEpochId,
    revision: envelope.revision,
    ciphertextHash: envelope.ciphertextHash,
    responseSigningPublicKey: envelope.responseSigningPublicKey,
    responseSignature: envelope.responseSignature,
    committedAt: envelope.createdAt,
  };
}

async function entryHash(
  receipt: PrivateResponseReceiptCoreV1,
  proof: Pick<
    PrivateResponseTransparencyProofV1,
    "protocolVersion" | "logId" | "logIndex" | "previousEntryHash"
  >,
): Promise<string> {
  const canonicalCore = canonicalPrivateResponseLogEntryCore(receipt, proof);
  const digest = await crypto.subtle.digest(
    "SHA-256",
    ownedArrayBuffer(
      domainSeparatedUtf8(PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN, canonicalCore),
    ),
  );
  return bytesToBase64Url(new Uint8Array(digest));
}

function corruptLog(): never {
  throw new ApiError(
    500,
    "response_transparency_corrupt",
    "The encrypted-response transparency log could not be verified.",
  );
}

function authorityHead(
  canonicalPayload: string,
  signature: string,
): PrivateResponseLogHeadV1 {
  let input: unknown;
  try {
    input = JSON.parse(canonicalPayload);
  } catch {
    corruptLog();
  }
  if (!input || typeof input !== "object" || Array.isArray(input)) corruptLog();
  const value = input as Record<string, unknown>;
  const actual = Object.keys(value).sort();
  const expected = [
    "protocolVersion",
    "logId",
    "treeSize",
    "headEntryHash",
    "generatedAt",
    "signingKeyId",
  ].sort();
  if (
    actual.length !== expected.length ||
    actual.some((key, index) => key !== expected[index]) ||
    value.protocolVersion !== PRIVATE_RESPONSE_PROTOCOL_VERSION ||
    typeof value.logId !== "string" ||
    !Number.isInteger(value.treeSize) ||
    typeof value.headEntryHash !== "string" ||
    typeof value.generatedAt !== "string" ||
    typeof value.signingKeyId !== "string"
  ) {
    corruptLog();
  }
  const head: PrivateResponseLogHeadV1 = {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: value.logId,
    treeSize: value.treeSize as number,
    headEntryHash: value.headEntryHash,
    generatedAt: value.generatedAt,
    signingKeyId: value.signingKeyId,
    signature,
  };
  const { signature: _signature, ...unsigned } = head;
  void _signature;
  if (canonicalPrivateResponseLogHeadPayload(unsigned) !== canonicalPayload) {
    corruptLog();
  }
  return head;
}

async function loadEntryForEnvelope(
  db: D1Database,
  envelopeId: string,
): Promise<TransparencyEntryRow | null> {
  return db
    .prepare(`${ENTRY_SELECT} WHERE envelope_id = ?`)
    .bind(envelopeId)
    .first<TransparencyEntryRow>();
}

async function appendEntry(
  db: D1Database,
  envelope: StoredPrivateResponseEnvelopeV1,
  signingKeyId: string,
): Promise<TransparencyEntryRow> {
  const receipt = receiptCore(envelope);
  for (let attempt = 0; attempt < MAXIMUM_APPEND_ATTEMPTS; attempt += 1) {
    const existing = await loadEntryForEnvelope(db, envelope.envelopeId);
    if (existing) return existing;

    const tail = await db
      .prepare(`${ENTRY_SELECT} ORDER BY log_index DESC LIMIT 1`)
      .first<TransparencyEntryRow>();
    if (tail && tail.logId !== RESPONSE_LOG_ID) corruptLog();
    const logIndex = (tail?.logIndex ?? 0) + 1;
    const previousEntryHash = tail?.entryHash ?? GENESIS_HASH;
    const proofCore = {
      protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
      logId: RESPONSE_LOG_ID,
      logIndex,
      previousEntryHash,
    } as const;
    const computedEntryHash = await entryHash(receipt, proofCore);
    const canonicalReceiptPayload = canonicalPrivateResponseReceiptPayload(
      receipt,
      {
        ...proofCore,
        entryHash: computedEntryHash,
        signingKeyId,
      },
    );
    const createdAt = new Date().toISOString();
    try {
      const inserted = await db
        .prepare(
          `INSERT OR IGNORE INTO response_transparency_entries
            (log_index, log_id, previous_entry_hash, entry_hash, envelope_id,
             canonical_receipt_payload, signing_key_id, receipt_signature,
             created_at, signed_at)
           SELECT ?, ?, ?, ?, ?, ?, ?, NULL, ?, NULL
           WHERE NOT EXISTS (
             SELECT 1 FROM response_transparency_entries AS newer_entries
             WHERE newer_entries.log_index >= ?
           )
             AND (
               (? = 1 AND ? = ?) OR
               (? > 1 AND EXISTS (
                 SELECT 1 FROM response_transparency_entries AS predecessor
                 WHERE predecessor.log_index = ? - 1
                   AND predecessor.entry_hash = ?
               ))
             )`,
        )
        .bind(
          logIndex,
          RESPONSE_LOG_ID,
          previousEntryHash,
          computedEntryHash,
          envelope.envelopeId,
          canonicalReceiptPayload,
          signingKeyId,
          createdAt,
          logIndex,
          logIndex,
          previousEntryHash,
          GENESIS_HASH,
          logIndex,
          logIndex,
          previousEntryHash,
        )
        .run();
      if ((inserted.meta.changes ?? 0) === 1) {
        const row = await loadEntryForEnvelope(db, envelope.envelopeId);
        if (row) return row;
      }
    } catch {
      // A concurrent append can win either uniqueness constraint. Reload and
      // retry from the new tail; no fork is accepted into the log.
    }
  }
  throw new ApiError(
    503,
    "response_transparency_busy",
    "The encrypted response was saved, but its inclusion proof is still being finalized.",
  );
}

async function validateEntry(
  entry: TransparencyEntryRow,
  envelope: StoredPrivateResponseEnvelopeV1,
  signingKeyId: string,
): Promise<void> {
  const receipt = receiptCore(envelope);
  const computedEntryHash = await entryHash(receipt, {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: entry.logId,
    logIndex: entry.logIndex,
    previousEntryHash: entry.previousEntryHash,
  });
  const expected = canonicalPrivateResponseReceiptPayload(receiptCore(envelope), {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: entry.logId,
    logIndex: entry.logIndex,
    previousEntryHash: entry.previousEntryHash,
    entryHash: entry.entryHash,
    signingKeyId,
  });
  if (
    entry.logId !== RESPONSE_LOG_ID ||
    entry.envelopeId !== envelope.envelopeId ||
    entry.signingKeyId !== signingKeyId ||
    entry.entryHash !== computedEntryHash ||
    entry.canonicalReceiptPayload !== expected
  ) {
    corruptLog();
  }
}

async function certifyStoredEntry(
  db: D1Database,
  bindings: HerdBindings,
  entry: TransparencyEntryRow,
): Promise<{ receiptSignature: string; head: TransparencyHeadRow }> {
  let head = await db
    .prepare(`${HEAD_SELECT} WHERE log_index = ?`)
    .bind(entry.logIndex)
    .first<TransparencyHeadRow>();
  const certification =
    entry.receiptSignature && entry.signedAt && head
      ? null
      : await appendTransparencyEntry(bindings, entry.canonicalReceiptPayload);
  if ((!entry.receiptSignature || !head) && !certification) corruptLog();
  if (certification && certification.signingKeyId !== entry.signingKeyId) {
    corruptLog();
  }
  const receiptSignature = entry.receiptSignature ?? certification!.receipt.signature;
  if (
    certification &&
    entry.receiptSignature &&
    entry.receiptSignature !== certification.receipt.signature
  ) {
    corruptLog();
  }
  const certifiedHead = certification
    ? authorityHead(
        certification.logHead.canonicalPayload,
        certification.logHead.signature,
      )
    : null;
  if (
    certifiedHead &&
    (certifiedHead.logId !== entry.logId ||
      certifiedHead.treeSize !== entry.logIndex ||
      certifiedHead.headEntryHash !== entry.entryHash ||
      certifiedHead.signingKeyId !== entry.signingKeyId)
  ) {
    corruptLog();
  }

  if (!head) {
    if (!certifiedHead || !certification) {
      corruptLog();
    }
    await db.batch([
      db
        .prepare(
          `UPDATE response_transparency_entries
           SET receipt_signature = COALESCE(receipt_signature, ?),
               signed_at = COALESCE(signed_at, ?)
           WHERE log_index = ? AND canonical_receipt_payload = ?`,
        )
        .bind(
          receiptSignature,
          new Date().toISOString(),
          entry.logIndex,
          entry.canonicalReceiptPayload,
        ),
      db
        .prepare(
          `INSERT OR IGNORE INTO response_transparency_heads
            (log_index, log_id, head_entry_hash, canonical_payload,
             signing_key_id, signature, generated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          entry.logIndex,
          entry.logId,
          entry.entryHash,
          certification.logHead.canonicalPayload,
          entry.signingKeyId,
          certification.logHead.signature,
          certifiedHead.generatedAt,
        ),
    ]);
    head = await db
      .prepare(`${HEAD_SELECT} WHERE log_index = ?`)
      .bind(entry.logIndex)
      .first<TransparencyHeadRow>();
  } else if (!entry.receiptSignature || !entry.signedAt) {
    await db
      .prepare(
        `UPDATE response_transparency_entries
         SET receipt_signature = COALESCE(receipt_signature, ?),
             signed_at = COALESCE(signed_at, ?)
         WHERE log_index = ?
           AND (receipt_signature IS NULL OR signed_at IS NULL)`,
      )
      .bind(receiptSignature, new Date().toISOString(), entry.logIndex)
      .run();
  }
  if (!head) corruptLog();

  if (
    certification &&
    (head.canonicalPayload !== certification.logHead.canonicalPayload ||
      head.signature !== certification.logHead.signature)
  ) {
    corruptLog();
  }

  const canonicalHead = canonicalPrivateResponseLogHeadPayload({
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: head.logId,
    treeSize: head.logIndex,
    headEntryHash: head.headEntryHash,
    generatedAt: head.generatedAt,
    signingKeyId: head.signingKeyId,
  });
  if (
    head.logId !== entry.logId ||
    head.headEntryHash !== entry.entryHash ||
    head.signingKeyId !== entry.signingKeyId ||
    head.canonicalPayload !== canonicalHead
  ) {
    corruptLog();
  }

  return { receiptSignature, head };
}

async function abandonUncertifiedSuffix(
  db: D1Database,
  entry: TransparencyEntryRow,
  proof: EvaluatorTransparencyReconciliationProof,
): Promise<void> {
  if (
    proof.logId !== entry.logId ||
    proof.rejectedLogIndex !== entry.logIndex ||
    proof.rejectedEntryHash !== entry.entryHash ||
    proof.authorityTreeSize + 1 !== entry.logIndex ||
    proof.authorityHeadEntryHash !== entry.previousEntryHash ||
    proof.signingKeyId !== entry.signingKeyId
  ) {
    corruptLog();
  }

  if (proof.authorityTreeSize === 0) {
    if (entry.logIndex !== 1 || entry.previousEntryHash !== GENESIS_HASH) {
      corruptLog();
    }
  } else {
    const prefix = await db
      .prepare(
        `SELECT
           entries.entry_hash AS entryHash,
           entries.receipt_signature AS receiptSignature,
           entries.signed_at AS signedAt,
           heads.head_entry_hash AS headEntryHash,
           heads.log_id AS headLogId,
           heads.signing_key_id AS headSigningKeyId
         FROM response_transparency_entries AS entries
         LEFT JOIN response_transparency_heads AS heads
           ON heads.log_index = entries.log_index
         WHERE entries.log_index = ?`,
      )
      .bind(proof.authorityTreeSize)
      .first<{
        entryHash: string;
        receiptSignature: string | null;
        signedAt: string | null;
        headEntryHash: string | null;
        headLogId: string | null;
        headSigningKeyId: string | null;
      }>();
    if (
      !prefix?.receiptSignature ||
      !prefix.signedAt ||
      prefix.entryHash !== proof.authorityHeadEntryHash ||
      prefix.headEntryHash !== proof.authorityHeadEntryHash ||
      prefix.headLogId !== entry.logId ||
      prefix.headSigningKeyId !== entry.signingKeyId
    ) {
      corruptLog();
    }
  }

  const deleted = await db
    .prepare(
      `WITH reconciliation_guard AS MATERIALIZED (
         SELECT 1 AS allowed
         WHERE EXISTS (
           SELECT 1 FROM response_transparency_entries AS rejected_entry
           WHERE rejected_entry.log_index = ?
             AND rejected_entry.entry_hash = ?
             AND rejected_entry.previous_entry_hash = ?
         )
           AND NOT EXISTS (
           SELECT 1
           FROM response_transparency_entries AS protected_entries
           LEFT JOIN response_transparency_heads AS protected_heads
             ON protected_heads.log_index = protected_entries.log_index
           WHERE protected_entries.log_index >= ?
             AND (
               protected_entries.receipt_signature IS NOT NULL OR
               protected_entries.signed_at IS NOT NULL OR
               protected_heads.log_index IS NOT NULL
             )
           )
       )
       DELETE FROM response_transparency_entries
       WHERE log_index >= ?
         AND EXISTS (SELECT 1 FROM reconciliation_guard WHERE allowed = 1)`,
    )
    .bind(
      entry.logIndex,
      entry.entryHash,
      entry.previousEntryHash,
      entry.logIndex,
      entry.logIndex,
    )
    .run();
  const remaining = await db
    .prepare(
      `SELECT log_index AS logIndex
       FROM response_transparency_entries
       WHERE log_index >= ?
       ORDER BY log_index ASC
       LIMIT 1`,
    )
    .bind(entry.logIndex)
    .first<{ logIndex: number }>();
  if ((deleted.meta.changes ?? 0) < 1) corruptLog();
  if (remaining) {
    throw new ApiError(
      503,
      "response_transparency_busy",
      "A new encrypted-response receipt was queued while recovery completed. Evaluation will retry.",
    );
  }
}

async function certifyOrAbandonLateSuffix(
  db: D1Database,
  bindings: HerdBindings,
  entry: TransparencyEntryRow,
): Promise<{ receiptSignature: string; head: TransparencyHeadRow } | null> {
  try {
    return await certifyStoredEntry(db, bindings, entry);
  } catch (error) {
    if (!(error instanceof TransparencyLateMissingEntryError)) throw error;
    await abandonUncertifiedSuffix(db, entry, error.proof);
    return null;
  }
}

/**
 * Finishes authority commits whose HTTP response was lost after the ordinary
 * database had already durably queued the exact receipt. Evaluation calls this
 * before selecting envelopes, including after the RSVP deadline: the authority
 * permits only byte-identical retries of entries it already committed.
 *
 * Work is deliberately bounded. If more entries remain, the caller fails
 * closed and a later scheduler/read pass resumes at the next oldest index.
 */
export async function recoverPendingResponseTransparency(
  db: D1Database,
  bindings: HerdBindings,
): Promise<void> {
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) return;

  const pending = await db
    .prepare(
      `${ENTRY_SELECT}
       WHERE receipt_signature IS NULL OR signed_at IS NULL OR
         NOT EXISTS (
           SELECT 1 FROM response_transparency_heads AS pending_heads
           WHERE pending_heads.log_index = response_transparency_entries.log_index
         )
       ORDER BY log_index ASC
       LIMIT ?`,
    )
    .bind(MAXIMUM_PREFIX_CERTIFICATIONS)
    .all<TransparencyEntryRow>();
  for (const entry of pending.results) {
    if (!(await certifyOrAbandonLateSuffix(db, bindings, entry))) break;
  }

  const remaining = await db
    .prepare(
      `SELECT log_index AS logIndex
       FROM response_transparency_entries
       WHERE receipt_signature IS NULL OR signed_at IS NULL OR
         NOT EXISTS (
           SELECT 1 FROM response_transparency_heads AS pending_heads
           WHERE pending_heads.log_index = response_transparency_entries.log_index
         )
       ORDER BY log_index ASC
       LIMIT 1`,
    )
    .first<{ logIndex: number }>();
  if (remaining) {
    throw new ApiError(
      503,
      "response_transparency_busy",
      "Encrypted-response receipts are still being finalized. Evaluation will retry.",
    );
  }
}

async function certifyEntry(
  db: D1Database,
  bindings: HerdBindings,
  envelope: StoredPrivateResponseEnvelopeV1,
  entry: TransparencyEntryRow,
): Promise<PrivateResponseReceiptV1> {
  // D1 can commit index N+1 before the request responsible for index N reaches
  // the remote authority. Finalize the bounded missing prefix in log order so
  // a disconnected earlier caller cannot permanently block every successor.
  const pending = await db
    .prepare(
      `${ENTRY_SELECT}
       WHERE log_index <= ?
         AND (
           receipt_signature IS NULL OR signed_at IS NULL OR
           NOT EXISTS (
             SELECT 1 FROM response_transparency_heads AS pending_heads
             WHERE pending_heads.log_index = response_transparency_entries.log_index
           )
         )
       ORDER BY log_index ASC
       LIMIT ?`,
    )
    .bind(entry.logIndex, MAXIMUM_PREFIX_CERTIFICATIONS)
    .all<TransparencyEntryRow>();
  let targetCertification: {
    receiptSignature: string;
    head: TransparencyHeadRow;
  } | null = null;
  for (const pendingEntry of pending.results) {
    const certification = await certifyOrAbandonLateSuffix(
      db,
      bindings,
      pendingEntry,
    );
    if (!certification) {
      throw new ApiError(
        409,
        "response_deadline_passed",
        "The reply deadline passed before this encrypted response reached the independent log.",
      );
    }
    if (pendingEntry.logIndex === entry.logIndex) targetCertification = certification;
  }
  if (!targetCertification) {
    const stillPendingBeforeTarget = await db
      .prepare(
        `SELECT log_index AS logIndex
         FROM response_transparency_entries
         WHERE log_index < ?
           AND (
             receipt_signature IS NULL OR signed_at IS NULL OR
             NOT EXISTS (
               SELECT 1 FROM response_transparency_heads AS pending_heads
               WHERE pending_heads.log_index = response_transparency_entries.log_index
             )
           )
         ORDER BY log_index ASC
         LIMIT 1`,
      )
      .bind(entry.logIndex)
      .first<{ logIndex: number }>();
    if (stillPendingBeforeTarget) {
      throw new ApiError(
        503,
        "response_transparency_busy",
        "The encrypted response was saved, but earlier transparency entries are still being finalized.",
      );
    }
    targetCertification = await certifyOrAbandonLateSuffix(db, bindings, entry);
    if (!targetCertification) {
      throw new ApiError(
        409,
        "response_deadline_passed",
        "The reply deadline passed before this encrypted response reached the independent log.",
      );
    }
  }

  const head = targetCertification.head;
  return {
    ...receiptCore(envelope),
    transparency: {
      protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
      logId: entry.logId,
      logIndex: entry.logIndex,
      previousEntryHash: entry.previousEntryHash,
      entryHash: entry.entryHash,
      signingKeyId: entry.signingKeyId,
      receiptSignature: targetCertification.receiptSignature,
      logHead: {
        protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
        logId: head.logId,
        treeSize: head.logIndex,
        headEntryHash: head.headEntryHash,
        generatedAt: head.generatedAt,
        signingKeyId: head.signingKeyId,
        signature: head.signature,
      },
    },
  };
}

export async function ensurePrivateResponseReceipt(
  db: D1Database,
  bindings: HerdBindings,
  envelope: StoredPrivateResponseEnvelopeV1,
): Promise<PrivateResponseReceiptV1> {
  const config = getEvaluatorTrustSigningConfig(bindings);
  if (!config) return { ...receiptCore(envelope), transparency: null };
  const entry = await appendEntry(db, envelope, config.transparencySigningKeyId);
  await validateEntry(entry, envelope, config.transparencySigningKeyId);
  return certifyEntry(db, bindings, envelope, entry);
}

export async function getPublicResponseTransparencyLog(
  db: D1Database,
  afterIndex: number,
  limit: number,
): Promise<{
  protocolVersion: 1;
  logId: string;
  entries: Array<{
    logIndex: number;
    previousEntryHash: string;
    entryHash: string;
    head: PrivateResponseLogHeadV1;
  }>;
}> {
  const result = await db
    .prepare(
      `SELECT
         entries.log_index AS logIndex,
         entries.previous_entry_hash AS previousEntryHash,
         entries.entry_hash AS entryHash,
         heads.log_id AS logId,
         heads.canonical_payload AS canonicalPayload,
         heads.signing_key_id AS signingKeyId,
         heads.signature AS signature,
         heads.generated_at AS generatedAt
       FROM response_transparency_entries AS entries
       JOIN response_transparency_heads AS heads
         ON heads.log_index = entries.log_index
       WHERE entries.log_index > ?
       ORDER BY entries.log_index ASC
       LIMIT ?`,
    )
    .bind(afterIndex, limit)
    .all<{
      logIndex: number;
      previousEntryHash: string;
      entryHash: string;
      logId: string;
      canonicalPayload: string;
      signingKeyId: string;
      signature: string;
      generatedAt: string;
    }>();
  return {
    protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
    logId: RESPONSE_LOG_ID,
    entries: result.results.map((row) => {
      const head: PrivateResponseLogHeadV1 = {
        protocolVersion: PRIVATE_RESPONSE_PROTOCOL_VERSION,
        logId: row.logId,
        treeSize: row.logIndex,
        headEntryHash: row.entryHash,
        generatedAt: row.generatedAt,
        signingKeyId: row.signingKeyId,
        signature: row.signature,
      };
      const { signature: _signature, ...unsignedHead } = head;
      void _signature;
      if (canonicalPrivateResponseLogHeadPayload(unsignedHead) !== row.canonicalPayload) {
        corruptLog();
      }
      return {
        logIndex: row.logIndex,
        previousEntryHash: row.previousEntryHash,
        entryHash: row.entryHash,
        head,
      };
    }),
  };
}
