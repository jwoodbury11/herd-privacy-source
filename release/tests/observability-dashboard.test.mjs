import assert from "node:assert/strict";
import test from "node:test";

import {
  checkOperationalSummary,
  summarizeOperationalRows,
} from "../../scripts/observability-dashboard.mjs";

test("operational dashboard reconciles counts, rates, and latency", () => {
  const summary = summarizeOperationalRows([
    {
      component: "api", signal: "api_request", operation: "get.events",
      outcome: "success", statusClass: "2xx", errorCode: "none",
      latencyBucket: "lt100ms", count: 90, latencyTotalMs: 4_500, latencyMaxMs: 90,
    },
    {
      component: "api", signal: "api_request", operation: "get.events",
      outcome: "failure", statusClass: "5xx", errorCode: "internal_error",
      latencyBucket: "gte10s", count: 10, latencyTotalMs: 100_000, latencyMaxMs: 12_000,
    },
    {
      component: "web", signal: "client_api_request", operation: "get.events",
      outcome: "failure", statusClass: "5xx", errorCode: "internal_error",
      latencyBucket: "gte10s", count: 10, latencyTotalMs: 100_000, latencyMaxMs: 12_000,
    },
  ]);
  assert.equal(summary.requests, 100);
  assert.equal(summary.failures, 10);
  assert.equal(summary.serverFailures, 10);
  assert.equal(summary.averageLatencyMs, 1_045);
  assert.equal(summary.latencyMaximumMs, 12_000);
  assert.equal(summary.slowRequests, 10);
  assert.deepEqual(summary.byComponent, { api: 100, web: 10 });
  assert.deepEqual(checkOperationalSummary(summary), [
    "server_error_budget_burn",
    "extreme_latency_observed",
  ]);
  assert.deepEqual(checkOperationalSummary(summary, {}, {
    activeAlertCount: 1,
    uncertifiedEntryCount: 1,
    dueUnresolvedCount: 1,
    oldestDueBucket: "15to59m",
  }), [
    "server_error_budget_burn",
    "extreme_latency_observed",
    "uncertified_transparency_entries",
    "active_monitor_alert",
    "scheduled_resolution_stale",
  ]);
});

test("operational dashboard flags a missing telemetry window", () => {
  const summary = summarizeOperationalRows([]);
  assert.deepEqual(checkOperationalSummary(summary), ["no_recent_api_telemetry"]);
});
