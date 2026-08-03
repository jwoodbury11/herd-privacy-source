import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare, NoOpLog } from "miniflare";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const schedulerToken = "epoch-fence-scheduler-token-0123456789abcdefghijklmnopqrstuvwxyz";
const authPepper = "epoch-fence-auth-pepper-0123456789abcdefghijklmnopqrstuvwxyz";
const evaluatorToken = "epoch-fence-evaluator-token-0123456789abcdefghijklmnopqrstuvwxyz";
const logId = "herd-response-log-v1";

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  return `{${Object.entries(value)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, item]) => `${JSON.stringify(key)}:${canonicalJson(item)}`)
    .join(",")}}`;
}

async function sha256Hex(value) {
  return Buffer.from(
    await webcrypto.subtle.digest("SHA-256", Buffer.from(value, "utf8")),
  ).toString("hex");
}

async function publicKey() {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return Buffer.from(await webcrypto.subtle.exportKey("raw", pair.publicKey)).toString(
    "base64url",
  );
}

async function epochBindings({
  epochId,
  measurement,
  responseDecryption,
  evaluationResultSigning,
  policySigning,
  responseTransparency,
}) {
  const descriptor = {
    schemaVersion: 1,
    evaluatorKeyEpochId: epochId,
    workloadImageDigest: measurement,
    responseDecryption,
    evaluationResultSigning,
    policySigning,
    responseTransparency: {
      logId,
      ...responseTransparency,
    },
  };
  return {
    HERD_DEPLOYMENT_PROFILE: "test",
    HERD_AUTH_PEPPER: authPepper,
    HERD_TEST_BYPASS_ENABLED: "false",
    HERD_EVALUATOR_KEY_ID: responseDecryption.keyId,
    HERD_EVALUATOR_PUBLIC_KEY: responseDecryption.publicKey,
    HERD_EVALUATOR_MEASUREMENT: measurement,
    HERD_ARTIFACT_RELEASE_ID: `invitee-web-${epochId}`,
    HERD_RELEASE_ID: epochId,
    HERD_EVALUATOR_URL: "https://evaluator.test/api/v1/relay/",
    HERD_EVALUATOR_TOKEN: evaluatorToken,
    HERD_EVALUATOR_TRANSPORT: "client_relay",
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: evaluationResultSigning.keyId,
    HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluationResultSigning.publicKey,
    HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: policySigning.keyId,
    HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: policySigning.publicKey,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: responseTransparency.keyId,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      responseTransparency.publicKey,
    HERD_EVALUATOR_KEY_EPOCH_SHA256: await sha256Hex(canonicalJson(descriptor)),
    HERD_EVALUATOR_EPOCH_DRAIN_MINIMUM_SECONDS: "0",
    HERD_SCHEDULER_TOKEN: schedulerToken,
  };
}

async function javascriptModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await javascriptModules(entryPath)));
    else if (entry.name.endsWith(".js")) files.push(entryPath);
  }
  return files;
}

async function createHarness(bindings) {
  await access(path.join(serverRoot, "index.js"));
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const options = {
    modules: modulePaths.map((modulePath) => ({ type: "ESModule", path: modulePath })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    log: new NoOpLog(),
    d1Databases: { DB: `herd-evaluator-epoch-${process.pid}-${Date.now()}` },
    bindings,
  };
  const miniflare = new Miniflare(options);
  let database = await miniflare.getD1Database("DB");
  const migrations = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  for (const name of migrations) {
    const sql = await readFile(path.join(migrationDirectory, name), "utf8");
    for (const chunk of sql.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return {
    miniflare,
    get database() {
      return database;
    },
    async updateBindings(next) {
      options.bindings = next;
      await miniflare.setOptions(options);
      database = await miniflare.getD1Database("DB");
    },
  };
}

function request(pathname, { body, token = schedulerToken } = {}) {
  return {
    url: `https://herd.test${pathname}`,
    init: {
      method: "POST",
      headers: {
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    },
  };
}

async function dispatch(miniflare, pathname, options) {
  const prepared = request(pathname, options);
  return miniflare.dispatchFetch(prepared.url, prepared.init);
}

async function insertEvent(database, suffix) {
  const userId = `user-${suffix}`;
  const eventId = `90000000-0000-4000-8000-${String(suffix).padStart(12, "0")}`;
  await database
    .prepare(
      `INSERT OR IGNORE INTO users
        (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES (?, ?, ?, '', '', ?, ?)`,
    )
    .bind(
      userId,
      `+1415555${String(suffix).padStart(4, "0")}`,
      `phone-hash-${suffix}`,
      "2026-08-02T00:00:00.000Z",
      "2026-08-02T00:00:00.000Z",
    )
    .run();
  await database
    .prepare(
      `INSERT INTO events
        (id, host_user_id, title, event_date, end_date, host_name,
         location_name, location_address, minimum_participants, rsvp_deadline,
         event_description, invitations_sent, created_at, updated_at)
       VALUES (?, ?, 'Epoch test', '2026-08-10T00:00:00.000Z', NULL, 'Host',
               '', '', 2, '2026-08-09T00:00:00.000Z', '', 1, ?, ?)`,
    )
    .bind(
      eventId,
      userId,
      "2026-08-02T00:00:00.000Z",
      "2026-08-02T00:00:00.000Z",
    )
    .run();
  return eventId;
}

async function insertPolicy(database, {
  eventId,
  epochId,
  descriptorSha256,
  keyId,
  publicKey,
  measurement,
  suffix,
}) {
  await database
    .prepare(
      `INSERT INTO event_policies
        (event_id, protocol_version, cipher_suite, policy_hash, canonical_document,
         evaluator_key_id, evaluator_public_key, evaluator_measurement, release_id,
         evaluator_epoch_descriptor_sha256, padded_plaintext_bytes, frozen_at,
         policy_signing_key_id, policy_signature)
       VALUES (?, 1, 'P256_HKDF_SHA256_AES256_GCM', ?, '{}', ?, ?, ?, ?, ?,
               4096, '2026-08-02T00:00:00.000Z', ?, 'signature')`,
    )
    .bind(
      eventId,
      `policy-hash-${suffix}`,
      keyId,
      publicKey,
      measurement,
      epochId,
      descriptorSha256,
      `policy-key-${suffix}`,
    )
    .run();
}

test("D1 enforces a single drained evaluator epoch and preserves transition evidence", async (t) => {
  const transparencyKey = {
    keyId: "global-response-transparency-v1",
    publicKey: await publicKey(),
  };
  const oldEpoch = {
    epochId: "evaluator-key-epoch-1",
    measurement: `sha256:${"1".repeat(64)}`,
    responseDecryption: { keyId: "response-decryption-1", publicKey: await publicKey() },
    evaluationResultSigning: { keyId: "result-signing-1", publicKey: await publicKey() },
    policySigning: { keyId: "policy-signing-1", publicKey: await publicKey() },
    responseTransparency: transparencyKey,
  };
  const newEpoch = {
    epochId: "evaluator-key-epoch-2",
    measurement: `sha256:${"2".repeat(64)}`,
    responseDecryption: { keyId: "response-decryption-2", publicKey: await publicKey() },
    evaluationResultSigning: { keyId: "result-signing-2", publicKey: await publicKey() },
    policySigning: { keyId: "policy-signing-2", publicKey: await publicKey() },
    responseTransparency: transparencyKey,
  };
  const oldBindings = await epochBindings(oldEpoch);
  const harness = await createHarness(oldBindings);
  t.after(() => harness.miniflare.dispose());

  const unauthorized = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-status",
    { token: "wrong-token-that-is-still-long-enough-0123456789" },
  );
  assert.equal(unauthorized.status, 401);

  let response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-status",
  );
  assert.equal(response.status, 200);
  let status = await response.json();
  assert.equal(status.schemaVersion, 2);
  assert.equal(status.artifactReleaseId, `invitee-web-${oldEpoch.epochId}`);
  assert.equal(status.state.mode, "active");
  assert.equal(status.state.generation, 1);
  assert.equal(status.runtimeMatchesState, true);
  assert.equal(status.epochDescriptorSha256, oldBindings.HERD_EVALUATOR_KEY_EPOCH_SHA256);

  const firstEventId = await insertEvent(harness.database, 1);
  await insertPolicy(harness.database, {
    eventId: firstEventId,
    epochId: oldEpoch.epochId,
    descriptorSha256: oldBindings.HERD_EVALUATOR_KEY_EPOCH_SHA256,
    keyId: oldEpoch.responseDecryption.keyId,
    publicKey: oldEpoch.responseDecryption.publicKey,
    measurement: oldEpoch.measurement,
    suffix: 1,
  });
  await harness.database
    .prepare(
      `INSERT INTO event_resolutions
        (event_id, policy_hash, status, created_at, updated_at)
       VALUES (?, 'policy-hash-1', 'pending', ?, ?)`,
    )
    .bind(
      firstEventId,
      "2026-08-02T00:00:00.000Z",
      "2026-08-02T00:00:00.000Z",
    )
    .run();

  const transitionRequest = {
    schemaVersion: 1,
    expectedGeneration: 1,
    expectedEvaluatorKeyEpochId: oldEpoch.epochId,
  };
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-drain",
    { body: transitionRequest },
  );
  assert.equal(response.status, 200);
  status = await response.json();
  assert.equal(status.state.mode, "draining");
  assert.equal(status.unresolvedPolicyCount, 1);
  assert.equal(status.transition.drainCounts.unresolvedPolicyCount, 1);
  assert.equal(
    status.transition.fromEvaluatorKeyEpochId,
    status.state.evaluatorKeyEpochId,
  );
  assert.equal(
    status.transition.fromEpochDescriptorSha256,
    status.state.epochDescriptorSha256,
  );
  assert.equal(
    status.transition.transparencyIdentitySha256,
    status.state.transparencyIdentitySha256,
  );
  assert.equal(status.transition.drainStartedAt, status.state.drainStartedAt);

  const secondEventId = await insertEvent(harness.database, 2);
  await assert.rejects(
    insertPolicy(harness.database, {
      eventId: secondEventId,
      epochId: oldEpoch.epochId,
      descriptorSha256: oldBindings.HERD_EVALUATOR_KEY_EPOCH_SHA256,
      keyId: oldEpoch.responseDecryption.keyId,
      publicKey: oldEpoch.responseDecryption.publicKey,
      measurement: oldEpoch.measurement,
      suffix: 2,
    }),
    /evaluator_epoch_policy_freeze_blocked/u,
  );

  const newBindings = await epochBindings(newEpoch);
  await harness.updateBindings(newBindings);
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error.code, "evaluator_epoch_not_drained");

  await harness.database
    .prepare(
      `UPDATE event_resolutions
          SET status = 'not_confirmed', batch_hash = 'batch-hash',
              evaluation_request_hash = 'committed-evaluation-request-hash',
              resolved_at = ?, updated_at = ?
        WHERE event_id = ?`,
    )
    .bind(
      "2026-08-02T00:01:00.000Z",
      "2026-08-02T00:01:00.000Z",
      firstEventId,
    )
    .run();
  await harness.database
    .prepare(
      `INSERT INTO response_transparency_entries
        (log_index, log_id, previous_entry_hash, entry_hash, envelope_id,
         canonical_receipt_payload, signing_key_id, receipt_signature,
         created_at, signed_at)
       VALUES (1, ?, 'genesis', 'entry-1', 'envelope-1', '{}', ?, NULL, ?, NULL)`,
    )
    .bind(
      logId,
      transparencyKey.keyId,
      "2026-08-02T00:01:00.000Z",
    )
    .run();
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(response.status, 409);
  const uncertifiedError = await response.json();
  assert.equal(
    uncertifiedError.error.details.uncertifiedTransparencyCount,
    1,
  );
  assert.equal(uncertifiedError.error.details.activeEvaluationJobCount, 0);

  await harness.database
    .prepare(
      `UPDATE response_transparency_entries
          SET receipt_signature = 'receipt-signature', signed_at = ?
        WHERE log_index = 1`,
    )
    .bind("2026-08-02T00:02:00.000Z")
    .run();
  await harness.database
    .prepare(
      `INSERT INTO response_transparency_heads
        (log_index, log_id, head_entry_hash, canonical_payload,
         signing_key_id, signature, generated_at)
       VALUES (1, ?, 'entry-1', ?, ?, 'head-signature', ?)`,
    )
    .bind(
      logId,
      JSON.stringify({
        protocolVersion: 1,
        logId,
        treeSize: 1,
        headEntryHash: "entry-1",
        generatedAt: "2026-08-02T00:02:00.000Z",
        signingKeyId: transparencyKey.keyId,
      }),
      transparencyKey.keyId,
      "2026-08-02T00:02:00.000Z",
    )
    .run();

  const publicLogResponse = await harness.miniflare.dispatchFetch(
    "https://herd.test/api/transparency/responses?after=0&limit=1",
    { headers: { accept: "application/json" } },
  );
  assert.equal(publicLogResponse.status, 200);
  assert.deepEqual(await publicLogResponse.json(), {
    protocolVersion: 1,
    logId,
    entries: [{
      logIndex: 1,
      previousEntryHash: "genesis",
      entryHash: "entry-1",
      head: {
        protocolVersion: 1,
        logId,
        treeSize: 1,
        headEntryHash: "entry-1",
        generatedAt: "2026-08-02T00:02:00.000Z",
        signingKeyId: transparencyKey.keyId,
        signature: "head-signature",
      },
    }],
  });

  await harness.database
    .prepare(
      `UPDATE response_transparency_entries
          SET log_id = 'not-the-herd-response-log'
        WHERE log_index = 1`,
    )
    .run();
  await harness.database
    .prepare(
      `UPDATE response_transparency_heads
          SET log_id = 'not-the-herd-response-log'
        WHERE log_index = 1`,
    )
    .run();
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(response.status, 409);
  assert.ok(
    (await response.json()).error.details.uncertifiedTransparencyCount >= 1,
  );

  await harness.database
    .prepare(
      `UPDATE response_transparency_entries SET log_id = ? WHERE log_index = 1`,
    )
    .bind(logId)
    .run();
  await harness.database
    .prepare(
      `UPDATE response_transparency_heads SET log_id = ? WHERE log_index = 1`,
    )
    .bind(logId)
    .run();
  await harness.database
    .prepare(
      `UPDATE response_transparency_entries
          SET signing_key_id = 'mutually-consistent-but-untrusted-key'
        WHERE log_index = 1`,
    )
    .run();
  await harness.database
    .prepare(
      `UPDATE response_transparency_heads
          SET signing_key_id = 'mutually-consistent-but-untrusted-key'
        WHERE log_index = 1`,
    )
    .run();
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(response.status, 409);
  assert.ok(
    (await response.json()).error.details.uncertifiedTransparencyCount >= 1,
  );

  await harness.database
    .prepare(
      `UPDATE response_transparency_entries SET signing_key_id = ?
        WHERE log_index = 1`,
    )
    .bind(transparencyKey.keyId)
    .run();
  await harness.database
    .prepare(
      `UPDATE response_transparency_heads SET signing_key_id = ?
        WHERE log_index = 1`,
    )
    .bind(transparencyKey.keyId)
    .run();

  const rotatedTransparencyBindings = await epochBindings({
    ...newEpoch,
    responseTransparency: {
      keyId: "forbidden-rotated-transparency-key",
      publicKey: await publicKey(),
    },
  });
  await harness.updateBindings(rotatedTransparencyBindings);
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(response.status, 409);
  assert.equal(
    (await response.json()).error.code,
    "evaluator_epoch_transition_conflict",
  );
  await harness.updateBindings(newBindings);

  await harness.database.exec(
    `CREATE TRIGGER sabotage_epoch_transition_activation
       BEFORE UPDATE ON evaluator_epoch_transitions
       WHEN NEW.activated_at IS NOT NULL
       BEGIN
         SELECT RAISE(IGNORE);
       END;`.replace(/\s+/gu, " "),
  );
  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.notEqual(response.status, 200);
  assert.equal(
    await harness.database
      .prepare(
        "SELECT mode FROM evaluator_epoch_state WHERE singleton_id = 1",
      )
      .first("mode"),
    "draining",
  );
  assert.equal(
    await harness.database
      .prepare(
        `SELECT activated_at AS activatedAt
           FROM evaluator_epoch_transitions WHERE from_generation = 1`,
      )
      .first("activatedAt"),
    null,
  );
  await harness.database.exec("DROP TRIGGER sabotage_epoch_transition_activation");

  const activationResponses = await Promise.all([
    dispatch(
      harness.miniflare,
      "/api/internal/evaluator-epoch-activate",
      { body: transitionRequest },
    ),
    dispatch(
      harness.miniflare,
      "/api/internal/evaluator-epoch-activate",
      { body: transitionRequest },
    ),
  ]);
  assert.deepEqual(
    activationResponses.map((item) => item.status),
    [200, 200],
  );
  const activationStatuses = await Promise.all(
    activationResponses.map((item) => item.json()),
  );
  status = activationStatuses[0];
  assert.equal(
    activationStatuses[1].transition.activationEvidenceSha256,
    status.transition.activationEvidenceSha256,
  );
  assert.equal(status.state.mode, "active");
  assert.equal(status.state.generation, 2);
  assert.equal(status.state.evaluatorKeyEpochId, newEpoch.epochId);
  assert.equal(status.runtimeMatchesState, true);
  assert.equal(status.artifactReleaseId, `invitee-web-${newEpoch.epochId}`);
  assert.equal(status.transition.toEvaluatorKeyEpochId, newEpoch.epochId);
  assert.equal(
    await sha256Hex(status.transition.canonicalActivationEvidence),
    status.transition.activationEvidenceSha256,
  );
  const evidence = JSON.parse(status.transition.canonicalActivationEvidence);
  assert.deepEqual(evidence.finalDrainCounts, {
    activeEvaluationJobCount: 0,
    activeEvaluationLeaseCount: 0,
    uncertifiedTransparencyCount: 0,
    unresolvedPolicyCount: 0,
  });

  const exactRetry = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-activate",
    { body: transitionRequest },
  );
  assert.equal(exactRetry.status, 200);
  assert.equal(
    (await exactRetry.json()).transition.activationEvidenceSha256,
    status.transition.activationEvidenceSha256,
  );

  await assert.rejects(
    harness.database
      .prepare("DELETE FROM evaluator_epoch_transitions WHERE from_generation = 1")
      .run(),
    /evaluator_epoch_transition_is_immutable/u,
  );
  const thirdEventId = await insertEvent(harness.database, 3);
  await insertPolicy(harness.database, {
    eventId: thirdEventId,
    epochId: newEpoch.epochId,
    descriptorSha256: newBindings.HERD_EVALUATOR_KEY_EPOCH_SHA256,
    keyId: newEpoch.responseDecryption.keyId,
    publicKey: newEpoch.responseDecryption.publicKey,
    measurement: newEpoch.measurement,
    suffix: 3,
  });
  assert.equal(
    await harness.database
      .prepare("SELECT COUNT(*) AS count FROM event_policies")
      .first("count"),
    2,
  );
});

test("a conflicting drain record cannot strand the singleton in draining mode", async (t) => {
  const transparencyKey = {
    keyId: "global-response-transparency-batch-assertion-v1",
    publicKey: await publicKey(),
  };
  const epoch = {
    epochId: "evaluator-key-epoch-batch-assertion-1",
    measurement: `sha256:${"a".repeat(64)}`,
    responseDecryption: {
      keyId: "response-decryption-batch-assertion-1",
      publicKey: await publicKey(),
    },
    evaluationResultSigning: {
      keyId: "result-signing-batch-assertion-1",
      publicKey: await publicKey(),
    },
    policySigning: {
      keyId: "policy-signing-batch-assertion-1",
      publicKey: await publicKey(),
    },
    responseTransparency: transparencyKey,
  };
  const bindings = await epochBindings(epoch);
  const harness = await createHarness(bindings);
  t.after(() => harness.miniflare.dispose());

  let response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-status",
  );
  assert.equal(response.status, 200);
  const bootstrapped = await response.json();

  await harness.database
    .prepare(
      `INSERT INTO evaluator_epoch_transitions
        (transition_id, from_generation, from_evaluator_key_epoch_id,
         from_epoch_descriptor_sha256, transparency_identity_sha256,
         drain_started_at, unresolved_policy_count_at_drain,
         active_evaluation_lease_count_at_drain,
         active_evaluation_job_count_at_drain,
         uncertified_transparency_count_at_drain)
       VALUES ('malformed-preexisting-transition', 1, 'wrong-epoch', ?, ?, ?,
               0, 0, 0, 0)`,
    )
    .bind(
      "0".repeat(64),
      bootstrapped.state.transparencyIdentitySha256,
      "2026-08-02T00:00:00.000Z",
    )
    .run();

  response = await dispatch(
    harness.miniflare,
    "/api/internal/evaluator-epoch-drain",
    {
      body: {
        schemaVersion: 1,
        expectedGeneration: 1,
        expectedEvaluatorKeyEpochId: epoch.epochId,
      },
    },
  );
  assert.notEqual(response.status, 200);
  assert.deepEqual(
    await harness.database
      .prepare(
        `SELECT mode, drain_started_at AS drainStartedAt
           FROM evaluator_epoch_state WHERE singleton_id = 1`,
      )
      .first(),
    { mode: "active", drainStartedAt: null },
  );
});
