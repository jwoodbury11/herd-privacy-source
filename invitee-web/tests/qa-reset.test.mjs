import assert from "node:assert/strict";
import { readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const SCHEDULER_TOKEN =
  "qa-reset-scheduler-token-0123456789abcdefghijklmnopqrstuvwxyz";
const CONFIRMATION = "RESET HERD QA DATA";

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

async function createHarness(bindingOverrides = {}) {
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: { DB: `herd-qa-reset-${process.pid}-${Date.now()}` },
    bindings: {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_TEST_BYPASS_ENABLED: "true",
      HERD_ALLOW_INSECURE_QA_BYPASS: "true",
      HERD_QA_RESET_ENABLED: "true",
      HERD_SCHEDULER_TOKEN: SCHEDULER_TOKEN,
      ...bindingOverrides,
    },
  });
  const database = await miniflare.getD1Database("DB");
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(
      path.join(migrationDirectory, migrationFile),
      "utf8",
    );
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return { miniflare, database };
}

async function resetRequest(miniflare, {
  token = SCHEDULER_TOKEN,
  confirmation = CONFIRMATION,
} = {}) {
  return miniflare.dispatchFetch("https://herd.test/api/internal/qa-reset", {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ confirmation }),
  });
}

async function seedAllQaTables(database) {
  const now = "2026-08-02T12:00:00.000Z";
  const later = "2026-08-03T12:00:00.000Z";
  const zeroHash = Buffer.alloc(32).toString("base64url");
  const oneHash = Buffer.alloc(32, 1).toString("base64url");
  const userId = "10000000-0000-4000-8000-000000000001";
  const eventId = "20000000-0000-4000-8000-000000000001";
  const inviteeId = "30000000-0000-4000-8000-000000000001";
  const groupId = "40000000-0000-4000-8000-000000000001";
  const accountEpochId = "50000000-0000-4000-8000-000000000001";
  const envelopeId = "60000000-0000-4000-8000-000000000001";
  const epochHash = "a".repeat(64);
  const transparencyHash = "b".repeat(64);
  const statements = [
    database.prepare(
      `INSERT INTO evaluator_epoch_state
       (singleton_id, generation, mode, evaluator_key_epoch_id,
        epoch_descriptor_sha256, transparency_identity_sha256,
        workload_image_digest, response_decryption_key_id,
        evaluation_result_signing_key_id, policy_signing_key_id,
        response_transparency_signing_key_id, activated_at,
        drain_started_at, updated_at)
       VALUES (1, 1, 'active', 'herd-test-release-v1', ?, ?,
        'qa-measurement', 'qa-decryption', 'qa-result', 'qa-policy',
        'qa-transparency', ?, NULL, ?)`,
    ).bind(epochHash, transparencyHash, now, now),
    database.prepare(
      `INSERT INTO evaluator_epoch_transitions
       (transition_id, from_generation, from_evaluator_key_epoch_id,
        from_epoch_descriptor_sha256, transparency_identity_sha256,
        drain_started_at, unresolved_policy_count_at_drain,
        active_evaluation_lease_count_at_drain,
        active_evaluation_job_count_at_drain,
        uncertified_transparency_count_at_drain)
       VALUES ('70000000-0000-4000-8000-000000000001', 1,
        'herd-test-release-v1', ?, ?, ?, 0, 0, 0, 0)`,
    ).bind(epochHash, transparencyHash, now),
    database.prepare(
      `INSERT INTO users
       (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES (?, '+14155550187', 'phone-hash', 'QA user', '', ?, ?)`,
    ).bind(userId, now, now),
    database.prepare(
      `INSERT INTO account_key_epochs
       (id, user_id, epoch_number, key_commitment, created_at, superseded_at)
       VALUES (?, ?, 1, NULL, ?, NULL)`,
    ).bind(accountEpochId, userId, now),
    database.prepare(
      `INSERT INTO sessions
       (id, user_id, token_hash, auth_mode, qa_bypass_generation,
        created_at, expires_at, last_seen_at, revoked_at)
       VALUES ('80000000-0000-4000-8000-000000000001', ?, 'token-hash',
        'test', 'qa-generation', ?, ?, ?, NULL)`,
    ).bind(userId, now, later, now),
    database.prepare(
      `INSERT INTO challenges
       (id, phone_number, phone_hash, code_hash, provider_sid, delivery,
        status, request_ip_hash, attempt_count, max_attempts, created_at,
        expires_at, resend_at, verified_at)
       VALUES ('90000000-0000-4000-8000-000000000001', '+14155550187',
        'phone-hash', NULL, NULL, 'test', 'pending', 'ip-hash', 0, 5,
        ?, ?, ?, NULL)`,
    ).bind(now, later, later),
    database.prepare(
      `INSERT INTO auth_phone_rate_limits
       (phone_hash, window_started_at, request_count, last_requested_at)
       VALUES ('phone-hash', ?, 1, ?)`,
    ).bind(now, now),
    database.prepare(
      `INSERT INTO auth_ip_rate_limits
       (ip_hash, window_started_at, request_count, last_requested_at)
       VALUES ('ip-hash', ?, 1, ?)`,
    ).bind(now, now),
    database.prepare(
      `INSERT INTO events
       (id, host_user_id, title, event_date, end_date, host_name,
        location_name, location_address, minimum_participants,
        rsvp_deadline, event_description, invitations_sent, created_at, updated_at)
       VALUES (?, ?, 'QA event', ?, NULL, 'QA host', '', '', 1, ?, '', 1, ?, ?)`,
    ).bind(eventId, userId, later, later, now, now),
    database.prepare(
      `INSERT INTO invitees
       (id, event_id, user_id, display_name, phone_number, phone_hash,
        token_hash, token_ciphertext, token_nonce, token_storage_version,
        created_at, updated_at)
       VALUES (?, ?, ?, 'QA user', '+14155550187', 'phone-hash',
        'invite-token-hash', NULL, NULL, NULL, ?, ?)`,
    ).bind(inviteeId, eventId, userId, now, now),
    database.prepare(
      "INSERT INTO groups (id, event_id, position) VALUES (?, ?, 0)",
    ).bind(groupId, eventId),
    database.prepare(
      `INSERT INTO group_members (group_id, invitee_id, position)
       VALUES (?, ?, 0)`,
    ).bind(groupId, inviteeId),
    database.prepare(
      `INSERT INTO event_policies
       (event_id, protocol_version, cipher_suite, policy_hash,
        canonical_document, evaluator_key_id, evaluator_public_key,
        evaluator_measurement, release_id, evaluator_epoch_descriptor_sha256,
        padded_plaintext_bytes, frozen_at, policy_signing_key_id,
        policy_signature)
       VALUES (?, 1, 'P256_HKDF_SHA256_AES256_GCM', ?, '{}',
        'qa-decryption', 'qa-public-key', 'qa-measurement',
        'herd-test-release-v1', ?, 4096, ?, 'qa-policy', 'qa-signature')`,
    ).bind(eventId, oneHash, epochHash, now),
    database.prepare(
      `INSERT INTO event_resolutions
       (event_id, policy_hash, status, batch_hash, attending_member_ids,
        resolved_at, created_at, updated_at)
       VALUES (?, ?, 'pending', NULL, NULL, NULL, ?, ?)`,
    ).bind(eventId, oneHash, now, now),
    database.prepare(
      `INSERT INTO response_envelopes
       (id, event_id, invitee_id, account_key_epoch_id, policy_hash,
        protocol_version, cipher_suite, evaluator_key_id, revision,
        payload_ciphertext, user_key_wrap, evaluator_key_wrap,
        response_signing_public_key, response_signature, ciphertext_hash,
        created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, 1, 'P256_HKDF_SHA256_AES256_GCM',
        'qa-decryption', 1, 'payload', 'user-wrap', 'evaluator-wrap',
        'response-key', 'response-signature', 'ciphertext-hash', ?, ?)`,
    ).bind(envelopeId, eventId, inviteeId, accountEpochId, oneHash, now, now),
    database.prepare(
      `INSERT INTO invitation_deliveries
       (id, event_id, invitee_id, status, attempt_count, created_at, updated_at)
       VALUES ('a0000000-0000-4000-8000-000000000001', ?, ?, 'suppressed', 0, ?, ?)`,
    ).bind(eventId, inviteeId, now, now),
    database.prepare(
      `INSERT INTO response_transparency_entries
       (log_id, previous_entry_hash, entry_hash, envelope_id,
        canonical_receipt_payload, signing_key_id, receipt_signature,
        created_at, signed_at)
       VALUES ('herd-response-log-v1', ?, ?, ?, '{}', 'qa-transparency',
        'receipt-signature', ?, ?)`,
    ).bind(zeroHash, oneHash, envelopeId, now, now),
  ];
  await database.batch(statements);
  await database
    .prepare(
      `INSERT INTO response_transparency_heads
       (log_index, log_id, head_entry_hash, canonical_payload,
        signing_key_id, signature, generated_at)
       VALUES (1, 'herd-response-log-v1', ?, '{}', 'qa-transparency',
        'head-signature', ?)`,
    )
    .bind(oneHash, now)
    .run();
}

const QA_TABLES = [
  "users",
  "account_key_epochs",
  "sessions",
  "challenges",
  "auth_phone_rate_limits",
  "auth_ip_rate_limits",
  "events",
  "event_policies",
  "evaluator_epoch_state",
  "evaluator_epoch_transitions",
  "invitees",
  "groups",
  "group_members",
  "response_envelopes",
  "response_transparency_entries",
  "response_transparency_heads",
  "event_resolutions",
  "invitation_deliveries",
];

async function assertQaTablesEmpty(database) {
  for (const table of QA_TABLES) {
    const row = await database
      .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
      .first();
    assert.equal(row.count, 0, `${table} should be empty`);
  }
}

async function insertEpochState(database) {
  const now = "2026-08-02T12:00:00.000Z";
  await database
    .prepare(
      `INSERT INTO evaluator_epoch_state
       (singleton_id, generation, mode, evaluator_key_epoch_id,
        epoch_descriptor_sha256, transparency_identity_sha256,
        workload_image_digest, response_decryption_key_id,
        evaluation_result_signing_key_id, policy_signing_key_id,
        response_transparency_signing_key_id, activated_at,
        drain_started_at, updated_at)
       VALUES (1, 1, 'active', 'herd-test-release-v1', ?, ?,
        'qa-measurement', 'qa-decryption', 'qa-result', 'qa-policy',
        'qa-transparency', ?, NULL, ?)`,
    )
    .bind("a".repeat(64), "b".repeat(64), now, now)
    .run();
}

test("authenticated test-only QA reset is atomic, exhaustive, repeatable, and restores guards", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  await seedAllQaTables(database);

  const unauthorized = await resetRequest(miniflare, {
    token: "wrong-reset-token-0123456789abcdefghijklmnopqrstuvwxyz",
  });
  assert.equal(unauthorized.status, 401);
  assert.equal((await unauthorized.json()).error.code, "scheduler_unauthorized");

  const unconfirmed = await resetRequest(miniflare, { confirmation: "RESET" });
  assert.equal(unconfirmed.status, 400);
  assert.equal((await unconfirmed.json()).error.code, "qa_reset_not_confirmed");
  assert.equal(
    (await database.prepare("SELECT COUNT(*) AS count FROM users").first()).count,
    1,
  );

  await database.prepare(
    `CREATE TRIGGER qa_reset_forced_failure
     BEFORE DELETE ON challenges
     BEGIN
       SELECT RAISE(ABORT, 'qa_reset_forced_failure');
     END`,
  ).run();
  const failed = await resetRequest(miniflare);
  assert.equal(failed.status, 500);
  assert.equal((await failed.json()).error.code, "internal_error");
  for (const table of QA_TABLES) {
    const row = await database
      .prepare(`SELECT COUNT(*) AS count FROM ${table}`)
      .first();
    assert.equal(row.count, 1, `${table} deletion must roll back`);
  }
  await assert.rejects(
    database.prepare("DELETE FROM evaluator_epoch_state").run(),
    /evaluator_epoch_state_is_immutable/u,
  );
  await assert.rejects(
    database.prepare("DELETE FROM evaluator_epoch_transitions").run(),
    /evaluator_epoch_transition_is_immutable/u,
  );
  await database.exec("DROP TRIGGER qa_reset_forced_failure");

  const response = await resetRequest(miniflare);
  assert.equal(response.status, 204);
  await assertQaTablesEmpty(database);

  await insertEpochState(database);
  await assert.rejects(
    database.prepare("DELETE FROM evaluator_epoch_state").run(),
    /evaluator_epoch_state_is_immutable/u,
  );
  const appended = await database
    .prepare(
      `INSERT INTO response_transparency_entries
       (log_id, previous_entry_hash, entry_hash, envelope_id,
        canonical_receipt_payload, signing_key_id, receipt_signature,
        created_at, signed_at)
       VALUES ('herd-response-log-v1', ?, ?,
        '60000000-0000-4000-8000-000000000002', '{}', 'qa-transparency',
        'receipt-signature', '2026-08-02T12:00:00.000Z',
        '2026-08-02T12:00:00.000Z')
       RETURNING log_index AS logIndex`,
    )
    .bind(Buffer.alloc(32).toString("base64url"), Buffer.alloc(32, 2).toString("base64url"))
    .first();
  assert.equal(appended.logIndex, 1);

  const repeated = await resetRequest(miniflare);
  assert.equal(repeated.status, 204);
  await assertQaTablesEmpty(database);
  await insertEpochState(database);
  await assert.rejects(
    database.prepare("DELETE FROM evaluator_epoch_state").run(),
    /evaluator_epoch_state_is_immutable/u,
  );
});

test("QA reset endpoint is absent outside the exact test safety profile", async (t) => {
  for (const deploymentProfile of ["production", ""]) {
    const { miniflare, database } = await createHarness({
      HERD_DEPLOYMENT_PROFILE: deploymentProfile,
      HERD_SCHEDULER_TOKEN: "",
    });
    t.after(() => miniflare.dispose());
    await seedAllQaTables(database);
    const response = await resetRequest(miniflare);
    assert.equal(response.status, 404);
    assert.equal((await response.json()).error.code, "not_found");
    assert.equal(
      (await database.prepare("SELECT COUNT(*) AS count FROM users").first()).count,
      1,
    );
  }
});
