/** Cloudflare Worker entry point for the Herd invitee app. */
import type { HerdBindings } from "@/db";
import { appleAppSiteAssociationResponse } from "@/lib/backend/apple-app-site-association";
import { runDataRetentionSweep } from "@/lib/backend/data-retention";
import { ApiError, jsonResponse } from "@/lib/backend/http";
import { releasePointerResponse } from "@/lib/backend/release-pointer";
import { runScheduledResolutionSweep } from "@/lib/backend/scheduled-resolutions";
import {
  aggregateOperationalSignal,
  clientPlatform,
  correlationId,
  logOperationalSignal,
  operationName,
  purgeOperationalMetrics,
  releaseId,
} from "@/lib/backend/observability";
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

type Env = HerdBindings & {
  ASSETS: Fetcher;
  DB: D1Database;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
};

interface ScheduledController {
  scheduledTime: number;
  cron: string;
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

const TELEMETRY_BODY_LIMIT = 2_048;
const ALERT_BODY_LIMIT = 8_192;
const SAFE_VALUE = /^[a-z0-9][a-z0-9._:-]{0,79}$/u;
const CLIENT_SIGNALS = new Set([
  "client_api_request",
  "client_decode",
  "client_runtime_error",
  "client_session",
]);
const CLIENT_OPERATIONS = new Set([
  "app.loaded",
  "app.promise",
  "app.runtime",
  "delete.auth.session",
  "delete.events.event",
  "delete.me",
  "get.events",
  "get.invites.invite",
  "get.me",
  "get.transparency.responses",
  "patch.me",
  "post.account.key-epoch.initialize",
  "post.account.key-epoch.reset",
  "post.auth.request-code",
  "post.auth.verify-code",
  "post.events.event.attendees",
  "post.events.event.evaluation",
  "post.trust.evaluator-attestation",
  "post.v1.relay",
  "reply.saved.open",
  "put.events.event",
  "put.events.event.evaluation",
  "put.invites.invite.rsvp",
]);

function exactObject(value: unknown, keys: string[]): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function safeBearer(request: Request, expected: string | undefined): boolean {
  if (!expected || expected.length < 32 || expected.length > 512) return false;
  const supplied = request.headers.get("authorization") ?? "";
  const wanted = `Bearer ${expected}`;
  if (supplied.length !== wanted.length) return false;
  let difference = 0;
  for (let index = 0; index < wanted.length; index += 1) {
    difference |= supplied.charCodeAt(index) ^ wanted.charCodeAt(index);
  }
  return difference === 0;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function validAlertSignature(bytes: Uint8Array, signature: string | null, secret: string | undefined): Promise<boolean> {
  if (!secret || secret.length < 32 || secret.length > 512 || !signature?.startsWith("sha256=")) return false;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const body = bytes.slice().buffer as ArrayBuffer;
  const expected = `sha256=${hex(new Uint8Array(await crypto.subtle.sign("HMAC", key, body)))}`;
  if (expected.length !== signature.length) return false;
  let difference = 0;
  for (let index = 0; index < expected.length; index += 1) {
    difference |= expected.charCodeAt(index) ^ signature.charCodeAt(index);
  }
  return difference === 0;
}

async function monitorAlert(request: Request, env: Env): Promise<Response> {
  const declared = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(declared) || declared > ALERT_BODY_LIMIT) {
    return jsonResponse({ error: { code: "payload_too_large" } }, { status: 413 });
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length === 0 || bytes.length > ALERT_BODY_LIMIT) {
    return jsonResponse({ error: { code: "invalid_alert" } }, { status: 400 });
  }
  if (!(await validAlertSignature(bytes, request.headers.get("x-herd-signature"), env.HERD_MONITOR_ALERT_HMAC_SECRET))) {
    return jsonResponse({ error: { code: "unauthorized" } }, { status: 401 });
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    return jsonResponse({ error: { code: "invalid_alert" } }, { status: 400 });
  }
  if (
    !exactObject(value, ["schemaVersion", "ok", "checkedAt", "configurationFailureClass", "storageFailureClass", "targets"]) ||
    value.schemaVersion !== 1 || typeof value.ok !== "boolean" ||
    typeof value.checkedAt !== "string" || !Number.isFinite(Date.parse(value.checkedAt)) ||
    !Array.isArray(value.targets) || value.targets.length > 20
  ) {
    return jsonResponse({ error: { code: "invalid_alert" } }, { status: 400 });
  }
  const allowedFailures = new Set([
    "availability", "configuration", "evaluator_attestation", "monitor_storage",
    "release_integrity", "response_transparency", "unknown",
  ]);
  const records: Array<{ target: string; recovered: boolean; failureClass: string; releaseId: string; durationMs: number | null }> = [];
  for (const target of value.targets) {
    if (
      !exactObject(target, ["target", "ok", "durationMs", "failureClass", "releaseId"]) ||
      !SAFE_VALUE.test(String(target.target)) || typeof target.ok !== "boolean" ||
      (target.durationMs !== null && (!Number.isInteger(target.durationMs) || Number(target.durationMs) < 0 || Number(target.durationMs) > 120_000)) ||
      (target.failureClass !== null && !allowedFailures.has(String(target.failureClass))) ||
      (target.releaseId !== null && !SAFE_VALUE.test(String(target.releaseId)))
    ) {
      return jsonResponse({ error: { code: "invalid_alert" } }, { status: 400 });
    }
    records.push({
      target: String(target.target),
      recovered: target.ok,
      failureClass: target.failureClass === null ? "none" : String(target.failureClass),
      releaseId: target.releaseId === null ? "unknown" : String(target.releaseId),
      durationMs: target.durationMs === null ? null : Number(target.durationMs),
    });
  }
  for (const [target, failure] of [
    ["monitor-configuration", value.configurationFailureClass],
    ["monitor-storage", value.storageFailureClass],
  ] as const) {
    if (failure !== null) {
      if (!allowedFailures.has(String(failure))) return jsonResponse({ error: { code: "invalid_alert" } }, { status: 400 });
      records.push({ target, recovered: false, failureClass: String(failure), releaseId: "monitor", durationMs: null });
    }
  }
  if (records.length === 0) records.push({ target: "monitor", recovered: value.ok, failureClass: value.ok ? "none" : "unknown", releaseId: "monitor", durationMs: null });
  const recordedAt = new Date(Date.parse(value.checkedAt)).toISOString();
  await env.DB.batch(records.map((record) => env.DB.prepare(`
    INSERT INTO operational_alerts
      (id, recorded_at, recovered, target, failure_class, release_id, duration_ms)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).bind(
    crypto.randomUUID(), recordedAt, record.recovered ? 1 : 0, record.target,
    record.failureClass, record.releaseId, record.durationMs,
  )));
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function clientTelemetry(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const origin = request.headers.get("origin");
  if (origin && origin !== new URL(request.url).origin) {
    return jsonResponse({ error: { code: "cross_origin_request" } }, { status: 403 });
  }
  const contentLength = Number(request.headers.get("content-length") ?? "0");
  if (!Number.isFinite(contentLength) || contentLength > TELEMETRY_BODY_LIMIT) {
    return jsonResponse({ error: { code: "payload_too_large" } }, { status: 413 });
  }
  let value: unknown;
  try {
    const text = await request.text();
    if (text.length > TELEMETRY_BODY_LIMIT) throw new TypeError();
    value = JSON.parse(text);
  } catch {
    return jsonResponse({ error: { code: "invalid_telemetry" } }, { status: 400 });
  }
  const keys = [
    "schemaVersion", "platform", "signal", "operation", "outcome",
    "statusCode", "errorCode", "durationMs", "correlationId",
  ];
  if (
    !exactObject(value, keys) ||
    value.schemaVersion !== 1 ||
    !["web", "ios"].includes(String(value.platform)) ||
    !CLIENT_SIGNALS.has(String(value.signal)) ||
    !CLIENT_OPERATIONS.has(String(value.operation)) ||
    !["success", "failure", "cancelled"].includes(String(value.outcome)) ||
    !Number.isInteger(value.statusCode) || Number(value.statusCode) < 0 || Number(value.statusCode) > 599 ||
    !SAFE_VALUE.test(String(value.errorCode)) ||
    !Number.isFinite(value.durationMs) || Number(value.durationMs) < 0 || Number(value.durationMs) > 120_000 ||
    typeof value.correlationId !== "string"
  ) {
    return jsonResponse({ error: { code: "invalid_telemetry" } }, { status: 400 });
  }
  const signal = logOperationalSignal({
    component: value.platform as "web" | "ios",
    signal: String(value.signal),
    operation: String(value.operation),
    outcome: value.outcome as "success" | "failure" | "cancelled",
    statusCode: Number(value.statusCode),
    errorCode: String(value.errorCode),
    durationMs: Number(value.durationMs),
    correlationId: String(value.correlationId),
    releaseId: releaseId(env),
  });
  ctx.waitUntil(aggregateOperationalSignal(env.DB, signal));
  return new Response(null, { status: 204, headers: { "cache-control": "no-store" } });
}

async function observabilitySummary(request: Request, env: Env): Promise<Response> {
  if (!safeBearer(request, env.HERD_OBSERVABILITY_TOKEN)) {
    return jsonResponse({ error: { code: "unauthorized" } }, { status: 401 });
  }
  const hoursValue = Number(new URL(request.url).searchParams.get("hours") ?? "24");
  const hours = Number.isInteger(hoursValue) && hoursValue >= 1 && hoursValue <= 720 ? hoursValue : 24;
  const since = new Date(Date.now() - hours * 3_600_000).toISOString();
  const rows = await env.DB.prepare(`
    SELECT component, signal, operation, outcome, status_class AS statusClass,
      error_code AS errorCode, latency_bucket AS latencyBucket,
      release_id AS releaseId, SUM(count) AS count,
      SUM(latency_total_ms) AS latencyTotalMs, MAX(latency_max_ms) AS latencyMaxMs,
      MIN(bucket_started_at) AS firstBucket, MAX(bucket_started_at) AS lastBucket
    FROM operational_metrics
    WHERE bucket_started_at >= ?
    GROUP BY component, signal, operation, outcome, status_class, error_code,
      latency_bucket, release_id
    ORDER BY component, signal, operation, outcome, status_class, error_code,
      latency_bucket, release_id
    LIMIT 5000
  `).bind(since).all();
  const now = new Date().toISOString();
  const [resolutionHealth, deliveryHealth, transparencyHealth, alertHealth] = await env.DB.batch([
    env.DB.prepare(`
      SELECT
        COUNT(*) AS dueUnresolvedCount,
        CASE
          WHEN MIN(e.rsvp_deadline) IS NULL THEN 'none'
          WHEN unixepoch(?) - unixepoch(MIN(e.rsvp_deadline)) < 300 THEN 'lt5m'
          WHEN unixepoch(?) - unixepoch(MIN(e.rsvp_deadline)) < 900 THEN '5to14m'
          WHEN unixepoch(?) - unixepoch(MIN(e.rsvp_deadline)) < 3600 THEN '15to59m'
          ELSE 'gte1h'
        END AS oldestDueBucket
      FROM events e
      LEFT JOIN event_resolutions r ON r.event_id = e.id
      WHERE e.invitations_sent = 1 AND e.rsvp_deadline IS NOT NULL
        AND e.rsvp_deadline <= ? AND COALESCE(r.status, 'pending') IN ('pending', 'evaluating')
    `).bind(now, now, now, now),
    env.DB.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN status IN ('failed', 'unknown') THEN 1 ELSE 0 END), 0) AS invitationFailureCount,
        COALESCE(SUM(CASE WHEN status IN ('pending', 'dispatching') THEN 1 ELSE 0 END), 0) AS invitationPendingCount
      FROM invitation_deliveries
    `),
    env.DB.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN receipt_signature IS NULL OR signed_at IS NULL THEN 1 ELSE 0 END), 0) AS uncertifiedEntryCount,
        COUNT(*) AS transparencyEntryCount
      FROM response_transparency_entries
    `),
    env.DB.prepare(`
      SELECT
        COALESCE(SUM(CASE WHEN recovered = 0 THEN 1 ELSE 0 END), 0) AS alertFailureCount,
        COALESCE(SUM(CASE WHEN recovered = 1 THEN 1 ELSE 0 END), 0) AS alertRecoveryCount,
        MAX(recorded_at) AS latestAlertAt,
        COALESCE((
          SELECT SUM(CASE WHEN ranked.recovered = 0 THEN 1 ELSE 0 END)
          FROM (
            SELECT recovered,
              ROW_NUMBER() OVER (PARTITION BY target ORDER BY recorded_at DESC, id DESC) AS rank
            FROM operational_alerts
          ) ranked
          WHERE ranked.rank = 1
        ), 0) AS activeAlertCount
      FROM operational_alerts
      WHERE recorded_at >= ?
    `).bind(new Date(Date.now() - 30 * 86_400_000).toISOString()),
  ]);
  const first = (result: D1Result) => result.results[0] ?? {};
  return jsonResponse({
    schemaVersion: 1,
    generatedAt: now,
    hours,
    rows: rows.results,
    health: {
      ...first(resolutionHealth),
      ...first(deliveryHealth),
      ...first(transparencyHealth),
      ...first(alertHealth),
    },
  });
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/api/telemetry" && request.method === "POST") {
      return clientTelemetry(request, env, ctx);
    }
    if (url.pathname === "/api/internal/observability/alerts" && request.method === "POST") {
      return monitorAlert(request, env);
    }
    if (url.pathname === "/api/internal/observability/summary" && request.method === "GET") {
      return observabilitySummary(request, env);
    }

    if (url.pathname === "/.well-known/apple-app-site-association") {
      try {
        return appleAppSiteAssociationResponse(env);
      } catch (error) {
        if (error instanceof ApiError) {
          return jsonResponse(
            { error: { code: error.code, message: error.message } },
            { status: error.status },
          );
        }
        throw error;
      }
    }

    if (url.pathname === "/.well-known/herd-release.json") {
      try {
        return await releasePointerResponse(env);
      } catch (error) {
        if (error instanceof ApiError) {
          return jsonResponse(
            { error: { code: error.code, message: error.message } },
            { status: error.status },
          );
        }
        throw error;
      }
    }

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    if (!url.pathname.startsWith("/api/")) return handler.fetch(request, env, ctx);

    const requestId = correlationId(request);
    const headers = new Headers(request.headers);
    headers.set("x-herd-request-id", requestId);
    const observedRequest = new Request(request, { headers });
    const startedAt = Date.now();
    let response: Response;
    try {
      response = await handler.fetch(observedRequest, env, ctx);
    } catch (error) {
      const signal = logOperationalSignal({
        component: "api",
        signal: "api_request",
        operation: operationName(request),
        outcome: "failure",
        statusCode: 500,
        errorCode: "uncaught_exception",
        durationMs: Date.now() - startedAt,
        correlationId: requestId,
        releaseId: releaseId(env),
      });
      ctx.waitUntil(aggregateOperationalSignal(env.DB, signal));
      throw error;
    }
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set("x-herd-request-id", requestId);
    responseHeaders.set("server-timing", `app;dur=${Math.max(0, Date.now() - startedAt)}`);
    const observedResponse = new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
    const signal = logOperationalSignal({
      component: "api",
      signal: "api_request",
      operation: operationName(request),
      outcome: response.ok ? "success" : "failure",
      statusCode: response.status,
      errorCode: response.headers.get("x-herd-error-code") ?? "none",
      durationMs: Date.now() - startedAt,
      correlationId: requestId,
      releaseId: releaseId(env),
    });
    ctx.waitUntil(aggregateOperationalSignal(env.DB, signal));
    const platformSignal = { ...signal, component: clientPlatform(request), signal: "service_boundary" } as const;
    ctx.waitUntil(aggregateOperationalSignal(env.DB, platformSignal));
    return observedResponse;
  },

  scheduled(
    controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): void {
    const invokedAt = new Date(controller.scheduledTime).toISOString();
    ctx.waitUntil(
      runScheduledResolutionSweep(env.DB, env, invokedAt)
        .then((summary) => {
          if (summary.failedCount > 0) {
            console.error("Herd scheduled resolution sweep incomplete", summary);
          } else {
            console.info("Herd scheduled resolution sweep", summary);
          }
          return aggregateOperationalSignal(env.DB, logOperationalSignal({
            component: "scheduler",
            signal: "resolution_sweep",
            operation: "scheduled_resolution",
            outcome: summary.failedCount > 0 ? "failure" : "success",
            statusCode: summary.failedCount > 0 ? 500 : 200,
            errorCode: summary.failedCount > 0 ? "resolution_sweep_incomplete" : "none",
            durationMs: 0,
            releaseId: releaseId(env),
          }));
        })
        .catch(() => {
          console.error("Herd scheduled resolution sweep failed", {
            selectedCount: 0,
            relayCount: 0,
            resolvedCount: 0,
            pendingCount: 0,
            failedCount: 1,
            releasedLeaseCount: 0,
          });
          return aggregateOperationalSignal(env.DB, logOperationalSignal({
            component: "scheduler",
            signal: "resolution_sweep",
            operation: "scheduled_resolution",
            outcome: "failure",
            statusCode: 500,
            errorCode: "resolution_sweep_failed",
            durationMs: 0,
            releaseId: releaseId(env),
          }));
        }),
    );
    ctx.waitUntil(
      runDataRetentionSweep(env.DB, invokedAt)
        .then((summary) => {
          console.info("Herd data-retention sweep", summary);
          return aggregateOperationalSignal(env.DB, logOperationalSignal({
            component: "api",
            signal: "retention_sweep",
            operation: "data_retention",
            outcome: "success",
            statusCode: 200,
            errorCode: "none",
            durationMs: 0,
            releaseId: releaseId(env),
          }));
        })
        .catch(() => {
          console.error("Herd data-retention sweep failed");
          return aggregateOperationalSignal(env.DB, logOperationalSignal({
            component: "api",
            signal: "retention_sweep",
            operation: "data_retention",
            outcome: "failure",
            statusCode: 500,
            errorCode: "retention_sweep_failed",
            durationMs: 0,
            releaseId: releaseId(env),
          }));
        }),
    );
    ctx.waitUntil(purgeOperationalMetrics(env.DB, new Date(controller.scheduledTime)));
  },
};

export default worker;
