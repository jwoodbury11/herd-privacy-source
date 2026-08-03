import {
  base64UrlToBytes,
  bytesToBase64Url,
} from "@/lib/privacy/protocol";

import { randomUuid } from "./crypto";
import { ApiError } from "./http";
import type { AccountKeyEpoch, AuthenticatedSession } from "./types";

const FRESH_SMS_SECONDS = 10 * 60;

type AccountKeyEpochRow = {
  id: string;
  userId: string;
  epochNumber: number;
  keyCommitment: string | null;
  createdAt: string;
  supersededAt: string | null;
};

const ACCOUNT_KEY_EPOCH_SELECT = `SELECT
  id,
  user_id AS userId,
  epoch_number AS epochNumber,
  key_commitment AS keyCommitment,
  created_at AS createdAt,
  superseded_at AS supersededAt
FROM account_key_epochs`;

export async function getActiveAccountKeyEpoch(
  db: D1Database,
  userId: string,
): Promise<AccountKeyEpoch | null> {
  return db
    .prepare(
      `${ACCOUNT_KEY_EPOCH_SELECT}
       WHERE user_id = ? AND superseded_at IS NULL
       ORDER BY epoch_number DESC
       LIMIT 1`,
    )
    .bind(userId)
    .first<AccountKeyEpochRow>();
}

export async function ensureActiveAccountKeyEpoch(
  db: D1Database,
  userId: string,
  nowIso = new Date().toISOString(),
): Promise<AccountKeyEpoch> {
  const existing = await getActiveAccountKeyEpoch(db, userId);
  if (existing) return existing;

  const epochId = randomUuid();
  await db
    .prepare(
      `INSERT OR IGNORE INTO account_key_epochs
        (id, user_id, epoch_number, created_at, superseded_at)
       SELECT
         ?, ?,
         COALESCE(
           (SELECT MAX(epoch_number) FROM account_key_epochs WHERE user_id = ?),
           0
         ) + 1,
         ?, NULL
       WHERE NOT EXISTS (
         SELECT 1 FROM account_key_epochs
         WHERE user_id = ? AND superseded_at IS NULL
       )`,
    )
    .bind(epochId, userId, userId, nowIso, userId)
    .run();

  const created = await getActiveAccountKeyEpoch(db, userId);
  if (!created) {
    throw new ApiError(
      500,
      "account_key_epoch_unavailable",
      "The account encryption key could not be initialized.",
    );
  }
  return created;
}

export async function resetAccountKeyEpoch(
  db: D1Database,
  session: AuthenticatedSession,
  expectedAccountKeyEpochId: string,
) {
  const now = Date.now();
  const authenticatedAt = Date.parse(session.createdAt);
  if (
    !Number.isFinite(authenticatedAt) ||
    authenticatedAt < now - FRESH_SMS_SECONDS * 1_000
  ) {
    throw new ApiError(
      403,
      "fresh_sms_required",
      "Confirm this phone number again before starting over.",
    );
  }

  const active = await getActiveAccountKeyEpoch(db, session.user.id);
  if (!active || active.id !== expectedAccountKeyEpochId) {
    throw new ApiError(
      409,
      "account_key_epoch_changed",
      "The account encryption key changed. Refresh before starting over.",
      { accountKeyEpochId: active?.id ?? null },
    );
  }

  const resetAt = new Date(now).toISOString();
  const nextId = randomUuid();
  try {
    const results = await db.batch([
      db
        .prepare(
          `INSERT INTO account_key_epochs
            (id, user_id, epoch_number, created_at, superseded_at)
           SELECT ?, user_id, epoch_number + 1, ?, NULL
           FROM account_key_epochs
           WHERE id = ? AND user_id = ? AND superseded_at IS NULL`,
        )
        .bind(nextId, resetAt, active.id, session.user.id),
      db
        .prepare(
          `UPDATE account_key_epochs
           SET superseded_at = ?
           WHERE id = ? AND user_id = ? AND superseded_at IS NULL
             AND EXISTS (SELECT 1 FROM account_key_epochs WHERE id = ?)`,
        )
        .bind(resetAt, active.id, session.user.id, nextId),
      db
        .prepare(
          `UPDATE sessions
           SET revoked_at = ?
           WHERE user_id = ? AND id <> ? AND revoked_at IS NULL
             AND EXISTS (SELECT 1 FROM account_key_epochs WHERE id = ?)`,
        )
        .bind(resetAt, session.user.id, session.sessionId, nextId),
    ]);
    if ((results[0].meta.changes ?? 0) !== 1 || (results[1].meta.changes ?? 0) !== 1) {
      throw new ApiError(
        409,
        "account_key_epoch_changed",
        "The account encryption key changed. Refresh before starting over.",
      );
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      409,
      "account_key_epoch_changed",
      "The account encryption key changed. Refresh before starting over.",
    );
  }

  return { accountKeyEpochId: nextId, resetAt };
}

export function normalizeAccountKeyCommitment(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApiError(
      400,
      "invalid_account_key_commitment",
      "keyCommitment must be an unpadded base64url SHA-256 value.",
    );
  }
  try {
    const bytes = base64UrlToBytes(value);
    if (bytes.length !== 32 || bytesToBase64Url(bytes) !== value) throw new TypeError();
    return value;
  } catch {
    throw new ApiError(
      400,
      "invalid_account_key_commitment",
      "keyCommitment must be an unpadded base64url SHA-256 value.",
    );
  }
}

export async function initializeAccountKeyEpoch(
  db: D1Database,
  session: AuthenticatedSession,
  expectedAccountKeyEpochId: string,
  keyCommitment: string,
) {
  const active = await getActiveAccountKeyEpoch(db, session.user.id);
  if (!active || active.id !== expectedAccountKeyEpochId) {
    throw new ApiError(
      409,
      "account_key_epoch_changed",
      "The account encryption key changed. Refresh and try again.",
      { accountKeyEpochId: active?.id ?? null },
    );
  }
  if (active.keyCommitment && active.keyCommitment !== keyCommitment) {
    throw new ApiError(
      409,
      "account_key_commitment_conflict",
      "This account key was already initialized on another device.",
    );
  }
  const result = await db
    .prepare(
      `UPDATE account_key_epochs
       SET key_commitment = ?
       WHERE id = ? AND user_id = ? AND superseded_at IS NULL
         AND (key_commitment IS NULL OR key_commitment = ?)`,
    )
    .bind(keyCommitment, active.id, session.user.id, keyCommitment)
    .run();
  if ((result.meta.changes ?? 0) !== 1) {
    throw new ApiError(
      409,
      "account_key_commitment_conflict",
      "This account key was already initialized on another device.",
    );
  }
  return {
    accountKeyEpochId: active.id,
    keyCommitment,
  };
}
