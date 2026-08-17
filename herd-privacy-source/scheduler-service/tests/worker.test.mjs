import assert from "node:assert/strict";
import test from "node:test";

import worker, { runCourier } from "../src/worker.mjs";

const TOKEN = "a".repeat(64);
const EVENT_ID = "00000000-0000-4000-8000-000000000001";
const LEASE_ID = "00000000-0000-4000-8000-000000000002";
const EVALUATOR_URL =
  "https://evaluator.example.com/api/v1/relay/";
const RELEASE_ID = "herd-production-2026-08-02";
const EVALUATOR_KEY_ID = "herd-evaluator-production-2026-08-02";
const ENV = Object.freeze({
  HERD_ARTIFACT_RELEASE_ID: "herd-artifact-production-2026-08-02",
  HERD_DEPLOYMENT_PROFILE: "production",
  HERD_PUBLIC_APP_URL: "https://app.example.com",
  HERD_EVALUATOR_URL: EVALUATOR_URL,
  HERD_EVALUATOR_KEY_ID: EVALUATOR_KEY_ID,
  HERD_RELEASE_ID: RELEASE_ID,
  HERD_RELEASE_CONFIGURATION_SHA256: "b".repeat(64),
  HERD_SCHEDULER_TOKEN: TOKEN,
});

function base64Url(bytes) {
  return Buffer.alloc(bytes, 7).toString("base64url");
}

function claim() {
  return {
    eventId: EVENT_ID,
    evaluatorHost: "https://evaluator.example.com",
    evaluatorUrl: EVALUATOR_URL,
    expiresAt: "2030-01-01T00:00:00.000Z",
    leaseId: LEASE_ID,
    releaseId: RELEASE_ID,
    relayRequest: {
      protocolVersion: 1,
      cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
      evaluatorKeyId: EVALUATOR_KEY_ID,
      ephemeralPublicKey: base64Url(65),
      salt: base64Url(32),
      ciphertext: base64Url(327_708),
      capabilityMac: base64Url(32),
    },
  };
}

function json(value, init = {}) {
  return new Response(JSON.stringify(value), {
    status: init.status ?? 200,
    headers: { "content-type": "application/json", ...init.headers },
  });
}

function streamedResponse(byteLength, contentType = "application/json") {
  return new Response(
    new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array(byteLength));
        controller.close();
      },
    }),
    { headers: { "content-type": contentType } },
  );
}

test("an empty queue completes without calling the evaluator", async () => {
  const calls = [];
  const completed = await runCourier(
    ENV,
    {
      now: () => 0,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return new Response(null, { status: 204 });
      },
    },
  );
  assert.equal(completed, 0);
  assert.equal(calls.length, 1);
  assert.match(calls[0].url, /\/claim$/u);
  assert.equal(calls[0].init.headers.authorization, `Bearer ${TOKEN}`);
});

test("a job is relayed without the scheduler credential and then completed", async () => {
  const calls = [];
  const replies = [
    json(claim()),
    json({ signed: "aggregate" }),
    new Response(null, { status: 204 }),
    new Response(null, { status: 204 }),
  ];
  const completed = await runCourier(
    ENV,
    {
      now: () => 0,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return replies.shift();
      },
    },
  );
  assert.equal(completed, 1);
  assert.equal(calls[1].url, EVALUATOR_URL);
  assert.equal(calls[1].init.headers.authorization, undefined);
  assert.equal(calls[1].init.headers.origin, undefined);
  assert.match(calls[2].url, /\/complete$/u);
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    eventId: EVENT_ID,
    evaluationResponse: { signed: "aggregate" },
  });
});

test("an evaluator failure releases only the matching lease", async () => {
  const calls = [];
  const replies = [
    json(claim()),
    new Response(null, { status: 503 }),
    new Response(null, { status: 204 }),
  ];
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async (url, init) => {
          calls.push({ url: String(url), init });
          return replies.shift();
        },
      },
    ),
    /could not be completed safely/u,
  );
  assert.match(calls[2].url, /\/release$/u);
  assert.deepEqual(JSON.parse(calls[2].init.body), {
    eventId: EVENT_ID,
    leaseId: LEASE_ID,
  });
});

test("an invalid or missing secret fails before any network request", async () => {
  let calls = 0;
  await assert.rejects(
    runCourier(
      { ...ENV, HERD_SCHEDULER_TOKEN: undefined },
      { fetchImpl: async () => { calls += 1; } },
    ),
    /credential is missing or invalid/u,
  );
  assert.equal(calls, 0);
});

test("missing, preview, legacy, and malformed production bindings fail before networking", async () => {
  const invalidEnvironments = [
    { ...ENV, HERD_PUBLIC_APP_URL: undefined },
    { ...ENV, HERD_EVALUATOR_URL: undefined },
    { ...ENV, HERD_EVALUATOR_KEY_ID: undefined },
    { ...ENV, HERD_ARTIFACT_RELEASE_ID: undefined },
    { ...ENV, HERD_RELEASE_ID: undefined },
    { ...ENV, HERD_RELEASE_CONFIGURATION_SHA256: undefined },
    { ...ENV, HERD_PUBLIC_APP_URL: "https://herd-preview.example.com" },
    { ...ENV, HERD_EVALUATOR_URL: "https://evaluator-staging.example.com/api/v1/relay/" },
    { ...ENV, HERD_EVALUATOR_KEY_ID: "herd-evaluator-live-v1" },
    { ...ENV, HERD_ARTIFACT_RELEASE_ID: "herd-preview-artifact" },
    { ...ENV, HERD_EVALUATOR_URL: "https://evaluator.example.com/other" },
    { ...ENV, HERD_EVALUATOR_URL: `${ENV.HERD_PUBLIC_APP_URL}/api/v1/relay/` },
    { ...ENV, HERD_RELEASE_CONFIGURATION_SHA256: "B".repeat(64) },
  ];
  for (const environment of invalidEnvironments) {
    let calls = 0;
    await assert.rejects(
      runCourier(environment, { fetchImpl: async () => { calls += 1; } }),
    );
    assert.equal(calls, 0);
  }
});

test("a claim from another signed release is rejected and its lease is released", async () => {
  const changed = claim();
  changed.releaseId = "another-production-release";
  const calls = [];
  await assert.rejects(
    runCourier(ENV, {
      now: () => 0,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        return calls.length === 1
          ? json(changed)
          : new Response(null, { status: 204 });
      },
    }),
    /invalid opaque courier job/u,
  );
  assert.match(calls[1].url, /\/release$/u);
});

test("a claim with an unpinned evaluator is rejected", async () => {
  const changed = claim();
  changed.evaluatorUrl = "https://example.com/api/v1/relay/";
  const calls = [];
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async (url, init) => {
          calls.push({ url: String(url), init });
          return calls.length === 1
            ? json(changed)
            : new Response(null, { status: 204 });
        },
      },
    ),
    /invalid opaque courier job/u,
  );
  assert.match(calls[1].url, /\/release$/u);
});

test("a non-canonical base64url field is rejected without decoding the payload", async () => {
  const changed = claim();
  changed.relayRequest.capabilityMac = `${changed.relayRequest.capabilityMac.slice(0, -1)}x`;
  await assert.rejects(
    runCourier(
      ENV,
      { now: () => 0, fetchImpl: async () => json(changed) },
    ),
    /invalid opaque courier job/u,
  );
});

test("oversized claim responses are rejected", async () => {
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async () =>
          json({}, { headers: { "content-length": String(700 * 1_024) } }),
      },
    ),
    /exceeded its safe size/u,
  );
});

test("streamed oversized claim responses are rejected without buffering past the limit", async () => {
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async () => streamedResponse(600 * 1_024 + 1),
      },
    ),
    /exceeded its safe size/u,
  );
});

test("scheduler redirects are never followed with the bearer credential", async () => {
  const calls = [];
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async (url, init) => {
          calls.push({ url: String(url), init });
          return new Response(null, {
            status: 302,
            headers: { location: EVALUATOR_URL },
          });
        },
      },
    ),
    /Herd rejected a courier request/u,
  );
  assert.equal(calls.length, 1);
  assert.equal(calls[0].init.redirect, "manual");
});

test("a streamed oversized evaluator result releases the claimed lease", async () => {
  const calls = [];
  const replies = [
    json(claim()),
    streamedResponse(60 * 1_024 + 1),
    new Response(null, { status: 204 }),
  ];
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async (url, init) => {
          calls.push({ url: String(url), init });
          return replies.shift();
        },
      },
    ),
    /could not be completed safely/u,
  );
  assert.match(calls[2].url, /\/release$/u);
});

test("the scheduled handler attaches the courier to the event lifetime", async () => {
  let promise;
  worker.scheduled(
    {},
    {},
    { waitUntil(value) { promise = value; } },
  );
  assert.ok(promise instanceof Promise);
  await assert.rejects(promise);
});

test("one invocation is capped below the free-plan subrequest limit", async () => {
  let calls = 0;
  const completed = await runCourier(
    ENV,
    {
      now: () => 0,
      fetchImpl: async (url) => {
        calls += 1;
        if (String(url).endsWith("/claim")) return json(claim());
        if (String(url) === EVALUATOR_URL) return json({ signed: "aggregate" });
        return new Response(null, { status: 204 });
      },
    },
  );
  assert.equal(completed, 12);
  assert.equal(calls, 36);
  assert.ok(calls < 40);
});

test("a completion failure after eleven successes uses at most 37 subrequests", async () => {
  let calls = 0;
  let completions = 0;
  await assert.rejects(
    runCourier(
      ENV,
      {
        now: () => 0,
        fetchImpl: async (url) => {
          calls += 1;
          const target = String(url);
          if (target.endsWith("/claim")) return json(claim());
          if (target === EVALUATOR_URL) return json({ signed: "aggregate" });
          if (target.endsWith("/complete")) {
            completions += 1;
            return new Response(null, { status: completions === 12 ? 503 : 204 });
          }
          return new Response(null, { status: 204 });
        },
      },
    ),
    /could not be completed safely/u,
  );
  assert.equal(completions, 12);
  assert.equal(calls, 37);
});

test("the invocation budget stops new claims before the next job can overrun", async () => {
  let clock = 0;
  let calls = 0;
  const completed = await runCourier(
    ENV,
    {
      now: () => clock,
      fetchImpl: async (url) => {
        calls += 1;
        const target = String(url);
        if (target.endsWith("/claim")) return json(claim());
        if (target === EVALUATOR_URL) return json({ signed: "aggregate" });
        clock = 5_001;
        return new Response(null, { status: 204 });
      },
    },
  );
  assert.equal(completed, 1);
  assert.equal(calls, 3);
});

test("the HTTP surface never exposes a manual trigger", async () => {
  const response = await worker.fetch();
  assert.equal(response.status, 404);
  assert.equal(await response.text(), "Not found");
});
