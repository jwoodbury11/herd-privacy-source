import assert from "node:assert/strict";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");

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

async function harness() {
  await access(path.join(serverRoot, "index.js"));
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
    unsafeTriggerHandlers: true,
    d1Databases: {
      DB: `herd-retention-${process.pid}-${Date.now()}`,
    },
    bindings: {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_AUTH_PEPPER:
        "herd-retention-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz",
      HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
      HERD_TEST_ACCOUNT_ACCESS_GENERATION: "herd-retention-generation-v1",
    },
  });
  const database = await miniflare.getD1Database("DB");
  const migrations = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  for (const migration of migrations) {
    const sql = await readFile(path.join(migrationDirectory, migration), "utf8");
    for (const chunk of sql.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return { miniflare, database };
}

async function scalar(database, sql) {
  return database.prepare(sql).first("value");
}

test("the scheduled sweep enforces retention without rewriting transparency", async (t) => {
  const { miniflare, database } = await harness();
  t.after(() => miniflare.dispose());

  const now = "2026-08-02T12:00:00.000Z";
  const recent = "2026-08-02T11:00:00.000Z";
  const oldAuth = "2026-06-01T00:00:00.000Z";
  const oldResponse = "2026-04-01T00:00:00.000Z";
  const userID = "10000000-0000-4000-8000-000000000001";
  const epochID = "20000000-0000-4000-8000-000000000001";

  await database.batch([
    database.prepare(
      `INSERT INTO users
       (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES (?, '+14155550101', 'phone-hash', 'Retention user', '', ?, ?)`,
    ).bind(userID, recent, recent),
    database.prepare(
      `INSERT INTO account_key_epochs
       (id, user_id, epoch_number, key_commitment, created_at, superseded_at)
       VALUES (?, ?, 1, 'commitment', ?, NULL)`,
    ).bind(epochID, userID, recent),
  ]);

  for (const [suffix, resolvedAt] of [["1", oldResponse], ["2", recent]]) {
    const eventID = `30000000-0000-4000-8000-00000000000${suffix}`;
    const inviteeID = `40000000-0000-4000-8000-00000000000${suffix}`;
    const envelopeID = `50000000-0000-4000-8000-00000000000${suffix}`;
    await database.batch([
      database.prepare(
        `INSERT INTO events
         (id, host_user_id, title, event_date, end_date, host_name,
          location_name, location_address, minimum_participants, rsvp_deadline,
          event_description, invitations_sent, created_at, updated_at)
         VALUES (?, ?, 'Retention event', ?, ?, 'Host', '', '', 1, ?, '', 0, ?, ?)`,
      ).bind(eventID, userID, recent, recent, recent, recent, recent),
      database.prepare(
        `INSERT INTO invitees
         (id, event_id, user_id, display_name, phone_number, phone_hash,
          token_hash, token_ciphertext, token_nonce, token_storage_version,
          created_at, updated_at)
         VALUES (?, ?, ?, 'Guest', '+14155550101', ?, ?, NULL, NULL, NULL, ?, ?)`,
      ).bind(inviteeID, eventID, userID, `invite-phone-${suffix}`, `token-${suffix}`, recent, recent),
      database.prepare(
        `INSERT INTO response_envelopes
         (id, event_id, invitee_id, account_key_epoch_id, policy_hash,
          protocol_version, cipher_suite, evaluator_key_id, revision,
          payload_ciphertext, user_key_wrap, evaluator_key_wrap, ciphertext_hash,
          created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, 1, 'P256_HKDF_SHA256_AES256_GCM',
          'evaluator', 1, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        envelopeID,
        eventID,
        inviteeID,
        epochID,
        `policy-${suffix}`,
        `ciphertext-${suffix}`,
        `user-wrap-${suffix}`,
        `evaluator-wrap-${suffix}`,
        `ciphertext-hash-${suffix}`,
        recent,
        recent,
      ),
      database.prepare(
        `INSERT INTO event_resolutions
         (event_id, policy_hash, status, batch_hash, attending_member_ids,
          resolved_at, evaluation_lease_id, evaluation_lease_expires_at,
          evaluation_request_hash, created_at, updated_at)
         VALUES (?, ?, 'confirmed', ?, '[]', ?, NULL, NULL, NULL, ?, ?)`,
      ).bind(eventID, `policy-${suffix}`, `batch-${suffix}`, resolvedAt, resolvedAt, resolvedAt),
    ]);
  }

  const expiredUnconfirmedID = "60000000-0000-4000-8000-000000000001";
  const recentUnconfirmedID = "60000000-0000-4000-8000-000000000002";
  const expiredConfirmedID = "60000000-0000-4000-8000-000000000003";
  await database.batch([
    database.prepare(
      `INSERT INTO events
       (id, host_user_id, title, event_date, end_date, host_name,
        location_name, location_address, minimum_participants, rsvp_deadline,
        event_description, invitations_sent, created_at, updated_at)
       VALUES
       (?, ?, 'Expired unconfirmed', ?, NULL, 'Host', '', '', 1, ?, '', 1, ?, ?),
       (?, ?, 'Recent unconfirmed', ?, NULL, 'Host', '', '', 1, ?, '', 1, ?, ?),
       (?, ?, 'Expired confirmed', ?, NULL, 'Host', '', '', 1, ?, '', 1, ?, ?)`,
    ).bind(
      expiredUnconfirmedID, userID, oldResponse, oldResponse, oldResponse, oldResponse,
      recentUnconfirmedID, userID, recent, recent, recent, recent,
      expiredConfirmedID, userID, oldResponse, oldResponse, oldResponse, oldResponse,
    ),
    database.prepare(
      `INSERT INTO event_resolutions
       (event_id, policy_hash, status, batch_hash, attending_member_ids,
        resolved_at, evaluation_lease_id, evaluation_lease_expires_at,
        evaluation_request_hash, created_at, updated_at)
       VALUES (?, 'confirmed-policy', 'confirmed', 'confirmed-batch', '[]',
        ?, NULL, NULL, NULL, ?, ?)`,
    ).bind(expiredConfirmedID, oldResponse, oldResponse, oldResponse),
  ]);

  await database.batch([
    database.prepare(
      `INSERT INTO challenges
       (id, phone_number, phone_hash, code_hash, provider_sid, delivery, status,
        request_ip_hash, attempt_count, max_attempts, created_at, expires_at,
        resend_at, verified_at)
       VALUES ('old-challenge', '+14155550101', 'old-phone', NULL, NULL, 'sms',
        'expired', 'old-ip', 0, 5, ?, ?, ?, NULL),
       ('new-challenge', '+14155550102', 'new-phone', NULL, NULL, 'sms',
        'pending', 'new-ip', 0, 5, ?, ?, ?, NULL)`,
    ).bind(oldAuth, oldAuth, oldAuth, recent, recent, recent),
    database.prepare(
      `INSERT INTO sessions
       (id, user_id, token_hash, auth_mode, test_access_generation, created_at,
        expires_at, last_seen_at, revoked_at)
       VALUES ('old-session', ?, 'old-token', 'twilio', NULL, ?, ?, ?, NULL),
       ('new-session', ?, 'new-token', 'twilio', NULL, ?, ?, ?, NULL)`,
    ).bind(userID, oldAuth, oldAuth, oldAuth, userID, recent, recent, recent),
    database.prepare(
      `INSERT INTO auth_phone_rate_limits
       (phone_hash, window_started_at, request_count, last_requested_at)
       VALUES ('old-rate-phone', ?, 1, ?), ('new-rate-phone', ?, 1, ?)`,
    ).bind(oldAuth, oldAuth, recent, recent),
    database.prepare(
      `INSERT INTO auth_ip_rate_limits
       (ip_hash, window_started_at, request_count, last_requested_at)
       VALUES ('old-rate-ip', ?, 1, ?), ('new-rate-ip', ?, 1, ?)`,
    ).bind(oldAuth, oldAuth, recent, recent),
    database.prepare(
      `INSERT INTO invitation_deliveries
       (id, event_id, invitee_id, status, provider_message_sid, provider_status,
        attempt_count, dispatch_started_at, sent_at, failed_at, last_error_code,
        last_error_message, suppressed_reason, created_at, updated_at)
       VALUES ('old-delivery', '30000000-0000-4000-8000-000000000001',
        '40000000-0000-4000-8000-000000000001', 'sent',
        'SM0123456789abcdef0123456789abcdef', 'queued', 1, ?, ?, NULL,
        'diagnostic-code', 'diagnostic message', NULL, ?, ?)`,
    ).bind(oldAuth, oldAuth, oldAuth, oldAuth),
    database.prepare(
      `INSERT INTO response_transparency_entries
       (log_index, log_id, previous_entry_hash, entry_hash, envelope_id,
        canonical_receipt_payload, signing_key_id, receipt_signature,
        created_at, signed_at)
       VALUES (1, 'herd-response-v1', 'previous', 'entry',
        '50000000-0000-4000-8000-000000000001', '{}', 'key', 'signature', ?, ?)`,
    ).bind(oldResponse, oldResponse),
  ]);

  const scheduled = await miniflare.dispatchFetch(
    `http://localhost/cdn-cgi/handler/scheduled?time=${Date.parse(now)}&cron=${encodeURIComponent("* * * * *")}`,
  );
  assert.equal(scheduled.status, 200);
  assert.equal(await scheduled.text(), "ok");

  assert.equal(await scalar(database, "SELECT COUNT(*) AS value FROM challenges"), 1);
  assert.equal(await scalar(database, "SELECT COUNT(*) AS value FROM sessions"), 1);
  assert.equal(await scalar(database, "SELECT COUNT(*) AS value FROM auth_phone_rate_limits"), 1);
  assert.equal(await scalar(database, "SELECT COUNT(*) AS value FROM auth_ip_rate_limits"), 1);
  assert.equal(await scalar(database, "SELECT COUNT(*) AS value FROM response_envelopes"), 1);
  assert.equal(
    await scalar(database, `SELECT COUNT(*) AS value FROM events WHERE id = '${expiredUnconfirmedID}'`),
    0,
  );
  assert.equal(
    await scalar(database, `SELECT COUNT(*) AS value FROM events WHERE id = '${recentUnconfirmedID}'`),
    1,
  );
  assert.equal(
    await scalar(database, `SELECT COUNT(*) AS value FROM events WHERE id = '${expiredConfirmedID}'`),
    1,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM response_transparency_entries"),
    1,
  );
  assert.deepEqual(
    await database.prepare(
      `SELECT provider_message_sid AS sid, provider_status AS status,
              last_error_code AS errorCode, last_error_message AS errorMessage,
              dispatch_started_at AS dispatchStartedAt
       FROM invitation_deliveries WHERE id = 'old-delivery'`,
    ).first(),
    {
      sid: null,
      status: null,
      errorCode: null,
      errorMessage: null,
      dispatchStartedAt: null,
    },
  );
});
