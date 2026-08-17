const HOUR_MS = 60 * 60 * 1_000;
const DAY_MS = 24 * HOUR_MS;

export const HERD_DATA_RETENTION = Object.freeze({
  expiredChallengeMilliseconds: DAY_MS,
  staleRateLimitMilliseconds: DAY_MS,
  expiredSessionMilliseconds: 30 * DAY_MS,
  deliveryDiagnosticMilliseconds: 30 * DAY_MS,
  resolvedResponseMilliseconds: 90 * DAY_MS,
  unconfirmedEventMilliseconds: 5 * DAY_MS,
});

export type DataRetentionSweepSummary = {
  deletedChallenges: number;
  deletedSessions: number;
  deletedPhoneRateLimits: number;
  deletedIpRateLimits: number;
  scrubbedDeliveryDiagnostics: number;
  deletedEncryptedResponses: number;
  deletedUnconfirmedEvents: number;
};

function canonicalInstant(value: string): number {
  const milliseconds = Date.parse(value);
  if (
    !Number.isFinite(milliseconds) ||
    new Date(milliseconds).toISOString() !== value
  ) {
    throw new TypeError("The retention sweep requires a canonical UTC instant.");
  }
  return milliseconds;
}

function cutoff(now: number, age: number): string {
  return new Date(now - age).toISOString();
}

function changes(result: D1Result<unknown>): number {
  return result.meta.changes ?? 0;
}

/**
 * Applies Herd's data-minimization schedule. The public response-transparency
 * chain and final event result are deliberately retained; expired encrypted
 * response payloads are erased without rewriting either commitment.
 */
export async function runDataRetentionSweep(
  db: D1Database,
  nowIso: string,
): Promise<DataRetentionSweepSummary> {
  const now = canonicalInstant(nowIso);
  const challengeCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.expiredChallengeMilliseconds,
  );
  const rateLimitCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.staleRateLimitMilliseconds,
  );
  const sessionCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.expiredSessionMilliseconds,
  );
  const deliveryCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.deliveryDiagnosticMilliseconds,
  );
  const responseCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.resolvedResponseMilliseconds,
  );
  const unconfirmedEventCutoff = cutoff(
    now,
    HERD_DATA_RETENTION.unconfirmedEventMilliseconds,
  );

  const results = await db.batch([
    db
      .prepare("DELETE FROM challenges WHERE expires_at < ?")
      .bind(challengeCutoff),
    db
      .prepare(
        `DELETE FROM sessions
         WHERE (expires_at < ? OR (revoked_at IS NOT NULL AND revoked_at < ?))`,
      )
      .bind(sessionCutoff, sessionCutoff),
    db
      .prepare("DELETE FROM auth_phone_rate_limits WHERE last_requested_at < ?")
      .bind(rateLimitCutoff),
    db
      .prepare("DELETE FROM auth_ip_rate_limits WHERE last_requested_at < ?")
      .bind(rateLimitCutoff),
    db
      .prepare(
        `UPDATE invitation_deliveries
         SET provider_message_sid = NULL,
             provider_status = NULL,
             last_error_code = NULL,
             last_error_message = NULL,
             dispatch_started_at = NULL
         WHERE updated_at < ?
           AND status IN ('sent', 'failed', 'unknown', 'suppressed')
           AND (
             provider_message_sid IS NOT NULL
             OR provider_status IS NOT NULL
             OR last_error_code IS NOT NULL
             OR last_error_message IS NOT NULL
             OR dispatch_started_at IS NOT NULL
           )`,
      )
      .bind(deliveryCutoff),
    db
      .prepare(
        `DELETE FROM response_envelopes
         WHERE event_id IN (
           SELECT event_id
           FROM event_resolutions
           WHERE status IN ('confirmed', 'not_confirmed')
             AND resolved_at IS NOT NULL
             AND resolved_at < ?
         )`,
      )
      .bind(responseCutoff),
    db
      .prepare(
        `DELETE FROM events
         WHERE invitations_sent = 1
           AND rsvp_deadline IS NOT NULL
           AND rsvp_deadline < ?
           AND NOT EXISTS (
             SELECT 1
             FROM event_resolutions
             WHERE event_resolutions.event_id = events.id
               AND event_resolutions.status = 'confirmed'
           )`,
      )
      .bind(unconfirmedEventCutoff),
  ]);

  return {
    deletedChallenges: changes(results[0]),
    deletedSessions: changes(results[1]),
    deletedPhoneRateLimits: changes(results[2]),
    deletedIpRateLimits: changes(results[3]),
    scrubbedDeliveryDiagnostics: changes(results[4]),
    deletedEncryptedResponses: changes(results[5]),
    deletedUnconfirmedEvents: changes(results[6]),
  };
}
