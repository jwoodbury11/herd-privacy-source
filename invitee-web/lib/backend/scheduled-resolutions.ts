import type { HerdBindings } from "@/db";

import { getEventById } from "./events";
import { ApiError } from "./http";
import { getEvaluatorRelayConfig } from "./config";
import { getPrivateResponsePolicies } from "./policy";
import { getSimpleEventResolution } from "./simple-resolutions";
import {
  completeClientRelayEvaluation,
  prepareInsertPendingEventResolution,
  releaseClientRelayEvaluationLease,
  startClientRelayEvaluation,
  type EvaluationRelayJob,
  type ResolutionReadableEvent,
} from "./resolutions";

const SCHEDULED_BATCH_LIMIT = 12;
const SCHEDULED_CONCURRENCY = 3;
const EVALUATOR_REQUEST_LIMIT_BYTES = 600 * 1_024;
const EVALUATOR_RESPONSE_LIMIT_BYTES = 64 * 1_024;
const EVALUATOR_REQUEST_TIMEOUT_MILLISECONDS = 12_000;

type DueEventRow = {
  eventId: string;
  policyHash: string;
  rsvpDeadline: string;
};

type ScheduledEvent = {
  event: ResolutionReadableEvent;
  policyHash: string;
};

type ScheduledAttemptCounts = {
  relayCount: number;
  resolvedCount: number;
  pendingCount: number;
  failedCount: number;
  releasedLeaseCount: number;
};

export type ScheduledResolutionSweepSummary = ScheduledAttemptCounts & {
  selectedCount: number;
};

const EMPTY_ATTEMPT_COUNTS: ScheduledAttemptCounts = {
  relayCount: 0,
  resolvedCount: 0,
  pendingCount: 0,
  failedCount: 0,
  releasedLeaseCount: 0,
};

async function dueEvents(
  db: D1Database,
  nowIso: string,
): Promise<DueEventRow[]> {
  const result = await db
    .prepare(
      `SELECT events.id AS eventId,
              event_policies.policy_hash AS policyHash,
              events.rsvp_deadline AS rsvpDeadline
       FROM events
       INNER JOIN event_policies
         ON event_policies.event_id = events.id
       LEFT JOIN event_resolutions
         ON event_resolutions.event_id = events.id
       WHERE events.invitations_sent = 1
         AND events.rsvp_deadline IS NOT NULL
         AND (
           events.rsvp_deadline <= ?
           OR event_resolutions.status IN ('confirmed', 'not_confirmed')
           OR EXISTS (
             SELECT 1
             FROM response_envelopes AS scheduled_responses
             JOIN response_transparency_entries AS scheduled_entries
               ON scheduled_entries.envelope_id = scheduled_responses.id
              AND scheduled_entries.receipt_signature IS NOT NULL
              AND scheduled_entries.signed_at IS NOT NULL
             JOIN response_transparency_heads AS scheduled_heads
               ON scheduled_heads.log_index = scheduled_entries.log_index
              AND scheduled_heads.log_id = scheduled_entries.log_id
              AND scheduled_heads.head_entry_hash = scheduled_entries.entry_hash
              AND scheduled_heads.signing_key_id = scheduled_entries.signing_key_id
             WHERE scheduled_responses.event_id = events.id
           )
         )
         AND (
           event_resolutions.event_id IS NULL
           OR event_resolutions.status = 'pending'
           OR (
             event_resolutions.status = 'evaluating'
             AND event_resolutions.evaluation_lease_expires_at IS NOT NULL
             AND event_resolutions.evaluation_lease_expires_at <= ?
           )
           OR (
             event_resolutions.status IN ('confirmed', 'not_confirmed')
             AND event_resolutions.resolved_at < events.rsvp_deadline
             AND events.rsvp_deadline <= ?
           )
         )
       ORDER BY CASE WHEN events.rsvp_deadline <= ? THEN 0 ELSE 1 END ASC,
                COALESCE(
                  event_resolutions.updated_at,
                  event_policies.frozen_at
                ) ASC,
                events.rsvp_deadline ASC,
                events.id ASC
       LIMIT ?`,
    )
    .bind(nowIso, nowIso, nowIso, nowIso, SCHEDULED_BATCH_LIMIT)
    .all<DueEventRow>();
  return result.results;
}

async function markScheduledAttempt(
  db: D1Database,
  eventId: string,
  policyHash: string,
  nowIso: string,
): Promise<void> {
  await prepareInsertPendingEventResolution(
    db,
    eventId,
    policyHash,
    nowIso,
  ).run();
  await db
    .prepare(
      `UPDATE event_resolutions
       SET status = 'pending',
           batch_hash = NULL,
           attending_member_ids = NULL,
           resolved_at = NULL,
           evaluation_request_hash = NULL,
           result_attestation_protocol_version = NULL,
           result_attestation_signing_key_id = NULL,
           result_attestation_evaluated_at = NULL,
           result_attestation_canonical_document = NULL,
           result_attestation_signature = NULL,
           updated_at = ?
       WHERE event_id = ?
         AND policy_hash = ?
         AND status IN ('confirmed', 'not_confirmed')
         AND resolved_at < (SELECT rsvp_deadline FROM events WHERE id = ?)
         AND (SELECT rsvp_deadline FROM events WHERE id = ?) <= ?`,
    )
    .bind(nowIso, eventId, policyHash, eventId, eventId, nowIso)
    .run();
  await db
    .prepare(
      `UPDATE event_resolutions
       SET updated_at = ?
       WHERE event_id = ?
         AND (
           status = 'pending'
           OR (
             status = 'evaluating'
             AND evaluation_lease_expires_at IS NOT NULL
             AND evaluation_lease_expires_at <= ?
           )
         )`,
    )
    .bind(nowIso, eventId, nowIso)
    .run();
}

async function responseTextWithinLimit(
  response: Response,
  maximumBytes: number,
): Promise<string> {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (
      !Number.isInteger(parsedLength) ||
      parsedLength < 0 ||
      parsedLength > maximumBytes
    ) {
      try {
        await response.body?.cancel();
      } catch {
        // The invalid declared length remains authoritative.
      }
      throw new Error("The evaluator response was invalid.");
    }
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The size violation remains authoritative even if cancellation fails.
        }
        throw new Error("The evaluator response was invalid.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("The evaluator response was invalid.");
  }
}

async function relayEvaluationJob(
  bindings: HerdBindings,
  job: EvaluationRelayJob,
): Promise<unknown> {
  const relay = getEvaluatorRelayConfig(bindings);
  if (
    job.evaluatorUrl !== relay.url ||
    job.evaluatorHost !== relay.evaluatorHost
  ) {
    throw new Error("The evaluator destination was invalid.");
  }

  const requestBody = JSON.stringify(job.relayRequest);
  if (
    new TextEncoder().encode(requestBody).byteLength >
    EVALUATOR_REQUEST_LIMIT_BYTES
  ) {
    throw new Error("The evaluator request was invalid.");
  }

  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    EVALUATOR_REQUEST_TIMEOUT_MILLISECONDS,
  );
  try {
    const response = await fetch(relay.url, {
      method: "POST",
      credentials: "omit",
      redirect: "manual",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
        "cache-control": "no-store",
        ...(relay.sitesBypassToken
          ? {
              "OAI-Sites-Authorization": `Bearer ${relay.sitesBypassToken}`,
            }
          : {}),
      },
      body: requestBody,
      signal: controller.signal,
    });
    if (!response.ok || response.type === "opaqueredirect") {
      try {
        await response.body?.cancel();
      } catch {
        // The unsuccessful response remains authoritative.
      }
      throw new Error("The evaluator was unavailable.");
    }
    const mediaType = (response.headers.get("content-type") ?? "")
      .split(";", 1)[0]
      .trim()
      .toLowerCase();
    if (mediaType !== "application/json") {
      try {
        await response.body?.cancel();
      } catch {
        // The invalid media type remains authoritative.
      }
      throw new Error("The evaluator response was invalid.");
    }

    const responseText = await responseTextWithinLimit(
      response,
      EVALUATOR_RESPONSE_LIMIT_BYTES,
    );
    let value: unknown;
    try {
      value = JSON.parse(responseText);
    } catch {
      throw new Error("The evaluator response was invalid.");
    }
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("The evaluator response was invalid.");
    }
    return value;
  } finally {
    clearTimeout(timeout);
  }
}

async function attemptDueEvent(
  db: D1Database,
  bindings: HerdBindings,
  event: ResolutionReadableEvent,
  policyHash: string,
): Promise<ScheduledAttemptCounts> {
  try {
    const attemptedAt = new Date().toISOString();
    await markScheduledAttempt(
      db,
      event.id,
      policyHash,
      attemptedAt,
    );
    const started = await startClientRelayEvaluation(
      db,
      bindings,
      event,
      attemptedAt,
    );
    if (started.kind === "resolved") {
      return { ...EMPTY_ATTEMPT_COUNTS, resolvedCount: 1 };
    }
    if (started.kind === "pending") {
      return { ...EMPTY_ATTEMPT_COUNTS, pendingCount: 1 };
    }

    let releasedLeaseCount = 0;
    try {
      const evaluatorResponse = await relayEvaluationJob(bindings, started.job);
      const resolution = await completeClientRelayEvaluation(
        db,
        bindings,
        event,
        evaluatorResponse,
      );
      return resolution.status === "pending"
        ? { ...EMPTY_ATTEMPT_COUNTS, relayCount: 1, pendingCount: 1 }
        : { ...EMPTY_ATTEMPT_COUNTS, relayCount: 1, resolvedCount: 1 };
    } catch {
      try {
        releasedLeaseCount = (await releaseClientRelayEvaluationLease(
          db,
          event.id,
          policyHash,
          started.job.leaseId,
        ))
          ? 1
          : 0;
      } catch {
        releasedLeaseCount = 0;
      }
      return {
        ...EMPTY_ATTEMPT_COUNTS,
        relayCount: 1,
        failedCount: 1,
        releasedLeaseCount,
      };
    }
  } catch {
    return { ...EMPTY_ATTEMPT_COUNTS, failedCount: 1 };
  }
}

async function boundedAttempts(
  db: D1Database,
  bindings: HerdBindings,
  events: ScheduledEvent[],
): Promise<ScheduledAttemptCounts[]> {
  const results = new Array<ScheduledAttemptCounts>(events.length);
  let nextIndex = 0;
  const workers = Array.from(
    { length: Math.min(SCHEDULED_CONCURRENCY, events.length) },
    async () => {
      while (nextIndex < events.length) {
        const index = nextIndex;
        nextIndex += 1;
        results[index] = await attemptDueEvent(
          db,
          bindings,
          events[index].event,
          events[index].policyHash,
        );
      }
    },
  );
  await Promise.all(workers);
  return results;
}

/**
 * Claims at most one due event for an authenticated opaque courier. The
 * ordered, bounded candidate scan keeps an event with a transiently busy or
 * invalid lease from blocking every event behind it. Lease acquisition in
 * startClientRelayEvaluation is the final concurrency guard.
 */
export async function claimScheduledResolutionJob(
  db: D1Database,
  bindings: HerdBindings,
  claimedAt = new Date().toISOString(),
): Promise<EvaluationRelayJob | null> {
  const candidates = await dueEvents(db, claimedAt);
  if (candidates.length === 0) return null;

  const policies = await getPrivateResponsePolicies(
    db,
    candidates.map(({ eventId }) => eventId),
  );
  let hadFailure = false;
  for (const candidate of candidates) {
    try {
      await markScheduledAttempt(
        db,
        candidate.eventId,
        candidate.policyHash,
        claimedAt,
      );
      const started = await startClientRelayEvaluation(
        db,
        bindings,
        {
          id: candidate.eventId,
          invitationsSent: true,
          rsvpDeadline: candidate.rsvpDeadline,
          privateResponsePolicy: policies.get(candidate.eventId) ?? null,
        },
        claimedAt,
      );
      if (started.kind === "relay") return started.job;
    } catch {
      hadFailure = true;
      // Moving the attempted row's timestamp prevents one malformed or
      // transiently unavailable event from starving the rest of the queue.
    }
  }
  if (hadFailure) {
    throw new ApiError(
      503,
      "scheduled_claim_unavailable",
      "A due event could not be prepared for the scheduler.",
    );
  }
  return null;
}

/** Persists one evaluator response without returning the private resolution. */
export async function completeScheduledResolutionJob(
  db: D1Database,
  bindings: HerdBindings,
  eventId: string,
  evaluationResponse: unknown,
): Promise<void> {
  const storedEvent = await getEventById(db, eventId);
  if (!storedEvent) {
    throw new ApiError(
      404,
      "scheduled_event_not_found",
      "The scheduled event was not found.",
    );
  }
  const { hostUserId: _hostUserId, ...event } = storedEvent;
  void _hostUserId;
  await completeClientRelayEvaluation(
    db,
    bindings,
    event,
    evaluationResponse,
  );
}

/** Releases only the matching lease; stale courier failures are harmless. */
export async function releaseScheduledResolutionJob(
  db: D1Database,
  eventId: string,
  leaseId: string,
): Promise<boolean> {
  const storedEvent = await getEventById(db, eventId);
  if (!storedEvent?.privateResponsePolicy) return false;
  return releaseClientRelayEvaluationLease(
    db,
    eventId,
    storedEvent.privateResponsePolicy.policyHash,
    leaseId,
  );
}

export async function runScheduledResolutionSweep(
  db: D1Database,
  bindings: HerdBindings,
  scheduledAt = new Date().toISOString(),
): Promise<ScheduledResolutionSweepSummary> {
  const simpleRows = await db
    .prepare(
      `SELECT events.id AS eventId
       FROM events
       LEFT JOIN event_policies ON event_policies.event_id = events.id
       LEFT JOIN event_resolutions ON event_resolutions.event_id = events.id
       WHERE events.invitations_sent = 1
         AND event_policies.event_id IS NULL
         AND events.rsvp_deadline IS NOT NULL
         AND events.rsvp_deadline <= ?
         AND (
           event_resolutions.event_id IS NULL
           OR event_resolutions.status NOT IN ('confirmed', 'not_confirmed')
         )
       ORDER BY events.rsvp_deadline ASC, events.id ASC
       LIMIT ?`,
    )
    .bind(scheduledAt, SCHEDULED_BATCH_LIMIT)
    .all<{ eventId: string }>();
  let simpleResolvedCount = 0;
  let simplePendingCount = 0;
  let simpleFailedCount = 0;
  for (const { eventId } of simpleRows.results) {
    try {
      const event = await getEventById(db, eventId);
      if (!event) continue;
      const resolution = await getSimpleEventResolution(db, bindings, event, scheduledAt);
      if (resolution?.status === "pending") simplePendingCount += 1;
      else if (resolution) simpleResolvedCount += 1;
    } catch {
      simpleFailedCount += 1;
    }
  }
  const candidates = await dueEvents(db, scheduledAt);
  if (candidates.length === 0) {
    return {
      selectedCount: simpleRows.results.length,
      ...EMPTY_ATTEMPT_COUNTS,
      resolvedCount: simpleResolvedCount,
      pendingCount: simplePendingCount,
      failedCount: simpleFailedCount,
    };
  }

  const policies = await getPrivateResponsePolicies(
    db,
    candidates.map(({ eventId }) => eventId),
  );
  const events: ScheduledEvent[] = candidates.map((candidate) => ({
    policyHash: candidate.policyHash,
    event: {
      id: candidate.eventId,
      invitationsSent: true,
      rsvpDeadline: candidate.rsvpDeadline,
      privateResponsePolicy: policies.get(candidate.eventId) ?? null,
    },
  }));
  const results = await boundedAttempts(db, bindings, events);
  return results.reduce<ScheduledResolutionSweepSummary>(
    (summary, result) => ({
      selectedCount: summary.selectedCount,
      relayCount: summary.relayCount + result.relayCount,
      resolvedCount: summary.resolvedCount + result.resolvedCount,
      pendingCount: summary.pendingCount + result.pendingCount,
      failedCount: summary.failedCount + result.failedCount,
      releasedLeaseCount:
        summary.releasedLeaseCount + result.releasedLeaseCount,
    }),
    {
      selectedCount: candidates.length + simpleRows.results.length,
      ...EMPTY_ATTEMPT_COUNTS,
      resolvedCount: simpleResolvedCount,
      pendingCount: simplePendingCount,
      failedCount: simpleFailedCount,
    },
  );
}
