import type { HerdBindings } from "@/db";

const SAFE_VALUE = /^[a-z0-9][a-z0-9._:-]{0,79}$/u;
const CORRELATION_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const MAX_DURATION_MS = 120_000;

export const OBSERVABILITY_RETENTION_DAYS = 30;

export type OperationalSignal = {
  component: "web" | "ios" | "api" | "scheduler" | "monitor" | "evaluator";
  signal: string;
  operation: string;
  outcome: "success" | "failure" | "cancelled";
  statusCode?: number;
  errorCode?: string;
  durationMs?: number;
  correlationId?: string;
  releaseId?: string;
};

function safeValue(value: unknown, fallback: string): string {
  return typeof value === "string" && SAFE_VALUE.test(value) ? value : fallback;
}

export function validCorrelationId(value: unknown): value is string {
  return typeof value === "string" && CORRELATION_ID.test(value);
}

export function correlationId(request: Request): string {
  const supplied = request.headers.get("x-herd-request-id")?.toLowerCase();
  return validCorrelationId(supplied) ? supplied : crypto.randomUUID();
}

export function routeTemplate(request: Request): string {
  const path = new URL(request.url).pathname;
  const segments = path.split("/").filter(Boolean);
  if (segments[0] !== "api") return "non_api";
  const normalized = segments.map((segment, index) => {
    const prior = segments[index - 1];
    if (prior === "events") return ":event";
    if (prior === "invites") return ":invite";
    return SAFE_VALUE.test(segment) ? segment : ":value";
  });
  return `/${normalized.join("/")}`.slice(0, 80);
}

export function operationName(request: Request): string {
  const method = request.method.toLowerCase();
  const route = routeTemplate(request)
    .replace(/^\/api\//u, "")
    .replaceAll("/", ".")
    .replaceAll(":", "");
  return safeValue(`${method}.${route}`, "unknown");
}

export function latencyBucket(durationMs: number): string {
  if (durationMs < 100) return "lt100ms";
  if (durationMs < 300) return "100to299ms";
  if (durationMs < 1_000) return "300to999ms";
  if (durationMs < 3_000) return "1to2s";
  if (durationMs < 10_000) return "3to9s";
  return "gte10s";
}

function hourBucket(date = new Date()): string {
  const value = new Date(date);
  value.setUTCMinutes(0, 0, 0);
  return value.toISOString();
}

function statusClass(statusCode?: number): string {
  return Number.isInteger(statusCode) && statusCode! >= 100 && statusCode! <= 599
    ? `${Math.floor(statusCode! / 100)}xx`
    : "none";
}

export function boundedSignal(input: OperationalSignal): Required<OperationalSignal> {
  const durationMs = Number.isFinite(input.durationMs)
    ? Math.max(0, Math.min(MAX_DURATION_MS, Math.round(input.durationMs!)))
    : 0;
  return {
    component: input.component,
    signal: safeValue(input.signal, "unknown"),
    operation: safeValue(input.operation, "unknown"),
    outcome: input.outcome,
    statusCode: Number.isInteger(input.statusCode) ? input.statusCode! : 0,
    errorCode: safeValue(input.errorCode, "none"),
    durationMs,
    correlationId: validCorrelationId(input.correlationId) ? input.correlationId : crypto.randomUUID(),
    releaseId: safeValue(input.releaseId, "unknown"),
  };
}

export function logOperationalSignal(input: OperationalSignal): Required<OperationalSignal> {
  const signal = boundedSignal(input);
  // Keep this object exact and bounded. Cloud logs are the short-lived trace
  // surface; they must never receive free-form errors, URLs, or payloads.
  console.info(JSON.stringify({
    schemaVersion: 1,
    kind: "herd.operational",
    recordedAt: new Date().toISOString(),
    ...signal,
    statusClass: statusClass(signal.statusCode),
    latencyBucket: latencyBucket(signal.durationMs),
  }));
  return signal;
}

export async function aggregateOperationalSignal(
  db: D1Database | undefined,
  input: OperationalSignal,
  now = new Date(),
): Promise<void> {
  if (!db) return;
  const signal = boundedSignal(input);
  const bucket = hourBucket(now);
  const updatedAt = now.toISOString();
  await db.prepare(`
    INSERT INTO operational_metrics (
      bucket_started_at, component, signal, operation, outcome, status_class,
      error_code, latency_bucket, release_id, count, latency_total_ms,
      latency_max_ms, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
    ON CONFLICT (
      bucket_started_at, component, signal, operation, outcome, status_class,
      error_code, latency_bucket, release_id
    ) DO UPDATE SET
      count = count + 1,
      latency_total_ms = latency_total_ms + excluded.latency_total_ms,
      latency_max_ms = MAX(latency_max_ms, excluded.latency_max_ms),
      updated_at = excluded.updated_at
  `).bind(
    bucket,
    signal.component,
    signal.signal,
    signal.operation,
    signal.outcome,
    statusClass(signal.statusCode),
    signal.errorCode,
    latencyBucket(signal.durationMs),
    signal.releaseId,
    signal.durationMs,
    signal.durationMs,
    updatedAt,
  ).run();
}

export async function purgeOperationalMetrics(
  db: D1Database | undefined,
  now = new Date(),
): Promise<void> {
  if (!db) return;
  const cutoff = new Date(now.getTime() - OBSERVABILITY_RETENTION_DAYS * 86_400_000).toISOString();
  await db.batch([
    db.prepare("DELETE FROM operational_metrics WHERE bucket_started_at < ?").bind(cutoff),
    db.prepare("DELETE FROM operational_alerts WHERE recorded_at < ?").bind(cutoff),
  ]);
}

export function releaseId(env: HerdBindings): string {
  return safeValue(env.HERD_ARTIFACT_RELEASE_ID ?? env.HERD_RELEASE_ID, "unknown");
}

export function clientPlatform(request: Request): "web" | "ios" | "scheduler" | "monitor" {
  const value = request.headers.get("x-herd-client-platform");
  return value === "ios" || value === "scheduler" || value === "monitor" ? value : "web";
}
