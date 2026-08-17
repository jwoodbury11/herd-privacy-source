import type { HerdBindings } from "@/db";

import { getAuthConfig } from "./config";
import { pepperedHash, randomId } from "./crypto";
import { ApiError } from "./http";
import type { AuthenticatedSession } from "./types";

export const ACCOUNT_DELETION_SESSION_MAX_AGE_SECONDS = 5 * 60;

function requireRecentlyAuthenticated(session: AuthenticatedSession, now: Date): void {
  const createdAt = Date.parse(session.createdAt);
  const ageMilliseconds = now.getTime() - createdAt;
  if (
    !Number.isFinite(createdAt) ||
    ageMilliseconds < -5_000 ||
    ageMilliseconds > ACCOUNT_DELETION_SESSION_MAX_AGE_SECONDS * 1_000
  ) {
    throw new ApiError(
      403,
      "recent_authentication_required",
      "Confirm your phone number again before deleting your account.",
      { maximumAgeSeconds: ACCOUNT_DELETION_SESSION_MAX_AGE_SECONDS },
    );
  }
}

/**
 * Permanently removes an authenticated account while preserving only the
 * anonymous event-member placeholders and append-only cryptographic
 * commitments needed to keep other people's frozen event policies auditable.
 */
export async function deleteAuthenticatedAccount(
  db: D1Database,
  bindings: HerdBindings,
  session: AuthenticatedSession,
  now = new Date(),
): Promise<void> {
  requireRecentlyAuthenticated(session, now);

  const config = getAuthConfig(bindings);
  const phoneHash = await pepperedHash(
    config.pepper,
    "phone",
    session.user.phoneNumber,
  );
  const deletionNonce = randomId("erased");
  const nowIso = now.toISOString();

  // D1 executes a batch as one transaction. Tokens and delivery diagnostics
  // are removed before the user row cascades through hosted events, sessions,
  // account-key epochs, and encrypted response envelopes.
  await db.batch([
    db
      .prepare(
        `DELETE FROM invitation_deliveries
         WHERE invitee_id IN (
           SELECT id FROM invitees
           WHERE user_id = ? OR phone_hash = ?
         )`,
      )
      .bind(session.user.id, phoneHash),
    db
      .prepare(
        `UPDATE invitees
         SET user_id = NULL,
             display_name = 'Deleted account',
             phone_number = '',
             phone_hash = 'erased-phone:' || id || ':' || ?,
             token_hash = 'erased-token:' || id || ':' || ?,
             token_ciphertext = NULL,
             token_nonce = NULL,
             token_storage_version = NULL,
             updated_at = ?
         WHERE user_id = ? OR phone_hash = ?`,
      )
      .bind(
        deletionNonce,
        deletionNonce,
        nowIso,
        session.user.id,
        phoneHash,
      ),
    db
      .prepare("DELETE FROM challenges WHERE phone_hash = ? OR phone_number = ?")
      .bind(phoneHash, session.user.phoneNumber),
    db
      .prepare("DELETE FROM auth_phone_rate_limits WHERE phone_hash = ?")
      .bind(phoneHash),
    db
      .prepare("DELETE FROM users WHERE id = ?")
      .bind(session.user.id),
  ]);
}
