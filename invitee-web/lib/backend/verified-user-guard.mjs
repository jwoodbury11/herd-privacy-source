/**
 * Creates or refreshes a user only while the exact SMS challenge that
 * authorized the operation still exists in its verified state. Returning the
 * row from the same statement avoids a delete/recreate race between an UPSERT
 * and a later lookup by phone number.
 */
export async function upsertUserForVerifiedChallenge(
  db,
  {
    challengeId,
    verifiedAt,
    phoneNumber,
    phoneHash,
    userId,
    suggestedName,
    nowIso,
  },
) {
  return db
    .prepare(
      `INSERT INTO users
        (id, phone_number, phone_hash, name, address, created_at, updated_at)
       SELECT ?, ?, ?, ?, '', ?, ?
       FROM challenges
       WHERE id = ?
         AND phone_number = ?
         AND phone_hash = ?
         AND status = 'verified'
         AND verified_at = ?
       ON CONFLICT(phone_number) DO UPDATE SET
         phone_hash = excluded.phone_hash,
         updated_at = excluded.updated_at
       RETURNING id, phone_number AS phoneNumber, name, address`,
    )
    .bind(
      userId,
      phoneNumber,
      phoneHash,
      suggestedName,
      nowIso,
      nowIso,
      challengeId,
      phoneNumber,
      phoneHash,
      verifiedAt,
    )
    .first();
}
