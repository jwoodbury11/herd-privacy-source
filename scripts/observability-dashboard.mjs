#!/usr/bin/env node

function fail(message) {
  throw new TypeError(message);
}

function safeOrigin(value) {
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") fail();
    return url.origin;
  } catch {
    fail("--origin must be a safe HTTPS origin.");
  }
}

function integer(value, fallback, minimum, maximum, label) {
  const parsed = value === undefined ? fallback : Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) fail(`${label} is invalid.`);
  return parsed;
}

function args(values) {
  const result = {};
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    if (key === "--json" || key === "--check") result[key.slice(2)] = true;
    else if (key?.startsWith("--")) result[key.slice(2)] = values[++index];
    else fail(`Unexpected argument ${String(key)}.`);
  }
  return result;
}

export function summarizeOperationalRows(rows) {
  if (!Array.isArray(rows)) fail("Observability summary rows are invalid.");
  let requests = 0;
  let failures = 0;
  let serverFailures = 0;
  let latencyTotalMs = 0;
  let latencyMaximumMs = 0;
  let slowRequests = 0;
  const byComponent = new Map();
  const errors = new Map();
  for (const row of rows) {
    if (!row || typeof row !== "object") fail("Observability summary row is invalid.");
    const count = Number(row.count);
    const total = Number(row.latencyTotalMs);
    const maximum = Number(row.latencyMaxMs);
    if (![count, total, maximum].every(Number.isSafeInteger) || count < 0 || total < 0 || maximum < 0) {
      fail("Observability summary contains invalid counters.");
    }
    if (row.signal === "api_request") {
      requests += count;
      latencyTotalMs += total;
      latencyMaximumMs = Math.max(latencyMaximumMs, maximum);
      if (row.outcome !== "success") failures += count;
      if (row.statusClass === "5xx") serverFailures += count;
      if (["3to9s", "gte10s"].includes(row.latencyBucket)) slowRequests += count;
    }
    byComponent.set(row.component, (byComponent.get(row.component) ?? 0) + count);
    if (row.errorCode !== "none") {
      const key = `${row.component}:${row.operation}:${row.errorCode}`;
      errors.set(key, (errors.get(key) ?? 0) + count);
    }
  }
  return {
    requests,
    failures,
    serverFailures,
    failureRate: requests === 0 ? 0 : failures / requests,
    serverFailureRate: requests === 0 ? 0 : serverFailures / requests,
    averageLatencyMs: requests === 0 ? 0 : Math.round(latencyTotalMs / requests),
    latencyMaximumMs,
    slowRequests,
    byComponent: Object.fromEntries([...byComponent].sort()),
    topErrors: [...errors].sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0])).slice(0, 20),
  };
}

export function checkOperationalSummary(summary, options = {}, health = {}) {
  const minimumRequests = options.minimumRequests ?? 1;
  const maximumServerFailureRate = options.maximumServerFailureRate ?? 0.01;
  const failures = [];
  if (summary.requests < minimumRequests) failures.push("no_recent_api_telemetry");
  if (summary.serverFailureRate > maximumServerFailureRate) failures.push("server_error_budget_burn");
  if (summary.latencyMaximumMs >= 10_000) failures.push("extreme_latency_observed");
  if (Number(health.uncertifiedEntryCount) > 0) failures.push("uncertified_transparency_entries");
  if (Number(health.activeAlertCount) > 0) failures.push("active_monitor_alert");
  if (Number(health.dueUnresolvedCount) > 0 && ["15to59m", "gte1h"].includes(health.oldestDueBucket)) {
    failures.push("scheduled_resolution_stale");
  }
  return failures;
}

function markdown(result, summary, checks) {
  const percent = (value) => `${(value * 100).toFixed(2)}%`;
  const lines = [
    "# Herd operational dashboard",
    "",
    `Generated: ${result.generatedAt}`,
    `Window: last ${result.hours} hour(s)`,
    "",
    `- API requests: ${summary.requests}`,
    `- Failures: ${summary.failures} (${percent(summary.failureRate)})`,
    `- Server failures: ${summary.serverFailures} (${percent(summary.serverFailureRate)})`,
    `- Average latency: ${summary.averageLatencyMs} ms`,
    `- Maximum latency: ${summary.latencyMaximumMs} ms`,
    `- Slow requests (3s+): ${summary.slowRequests}`,
    `- Automated check: ${checks.length === 0 ? "PASS" : `FAIL — ${checks.join(", ")}`}`,
    `- Due unresolved events: ${Number(result.health?.dueUnresolvedCount ?? 0)} (oldest: ${result.health?.oldestDueBucket ?? "unknown"})`,
    `- Uncertified transparency entries: ${Number(result.health?.uncertifiedEntryCount ?? 0)}`,
    `- Invitation failures/pending: ${Number(result.health?.invitationFailureCount ?? 0)} / ${Number(result.health?.invitationPendingCount ?? 0)}`,
    `- Active monitor alerts: ${Number(result.health?.activeAlertCount ?? 0)} (failures/recoveries in retention: ${Number(result.health?.alertFailureCount ?? 0)} / ${Number(result.health?.alertRecoveryCount ?? 0)})`,
    "",
    "## Component volume",
    "",
    "| Component | Signals |",
    "| --- | ---: |",
    ...Object.entries(summary.byComponent).map(([component, count]) => `| ${component} | ${count} |`),
    "",
    "## Top bounded errors",
    "",
    ...(summary.topErrors.length === 0
      ? ["No bounded errors in this window."]
      : ["| Boundary | Count |", "| --- | ---: |", ...summary.topErrors.map(([key, count]) => `| ${key} | ${count} |`)]),
  ];
  return `${lines.join("\n")}\n`;
}

async function main() {
  const options = args(process.argv.slice(2));
  const origin = safeOrigin(options.origin ?? "https://app.herdprivacy.com");
  const hours = integer(options.hours, 24, 1, 720, "--hours");
  const token = process.env.HERD_OBSERVABILITY_TOKEN;
  if (typeof token !== "string" || token.length < 32 || token.length > 512) {
    fail("HERD_OBSERVABILITY_TOKEN is missing or invalid.");
  }
  const url = new URL("/api/internal/observability/summary", origin);
  url.searchParams.set("hours", String(hours));
  const response = await fetch(url, {
    headers: { authorization: `Bearer ${token}`, accept: "application/json" },
    redirect: "manual",
    signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) fail(`Observability summary returned HTTP ${response.status}.`);
  const result = await response.json();
  const summary = summarizeOperationalRows(result.rows);
  const checks = checkOperationalSummary(summary, {}, result.health);
  process.stdout.write(options.json
    ? `${JSON.stringify({ ...result, summary, checks })}\n`
    : markdown(result, summary, checks));
  if (options.check && checks.length > 0) process.exitCode = 1;
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
    process.exitCode = 1;
  });
}
