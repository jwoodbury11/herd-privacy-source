import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { Miniflare } from "miniflare";

import { upsertUserForVerifiedChallenge } from "../lib/backend/verified-user-guard.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const testPepper = "herd-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const testAccessGeneration = "herd-test-generation-v1";
const evaluatorPublicKey = Buffer.from(
  `04${
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  }${"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}`,
  "hex",
).toString("base64url");

function pepperedTestHash(purpose, value) {
  return createHmac("sha256", testPepper)
    .update(`${purpose}\0${value}`)
    .digest("base64url");
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

async function createHarness() {
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
    d1Databases: { DB: `herd-account-deletion-${process.pid}-${Date.now()}` },
    bindings: {
      HERD_AUTH_PEPPER: testPepper,
      HERD_BALLOT_PSEUDONYM_KEY: "test-only-high-entropy-ballot-key",
      HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
      HERD_TEST_ACCOUNT_ACCESS_GENERATION: testAccessGeneration,
      HERD_TEST_HOST_PHONE_E164: "+14155550111",
      HERD_EVALUATOR_KEY_ID: "test-evaluator-v1",
      HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
      HERD_EVALUATOR_MEASUREMENT: "test-software-evaluator-sha384",
      HERD_RELEASE_ID: "herd-test-release-v1",
    },
  });
  const database = await miniflare.getD1Database("DB");
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(
      path.join(migrationDirectory, migrationFile),
      "utf8",
    );
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/g, " "));
    }
  }
  return { miniflare, database };
}

function api(miniflare, pathname, init = {}) {
  return miniflare.dispatchFetch(`https://herd.test${pathname}`, init);
}

function jsonRequest(method, body, accessToken, extraHeaders = {}) {
  return {
    method,
    headers: {
      "content-type": "application/json",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
      ...extraHeaders,
    },
    body: JSON.stringify(body),
  };
}

async function testSession(miniflare, phoneInput) {
  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: phoneInput }),
  );
  assert.equal(response.status, 200);
  return response.json();
}

async function scalar(database, query, ...bindings) {
  return database.prepare(query).bind(...bindings).first("value");
}

test("account deletion requires recent phone authentication and erases all recoverable account data", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const host = await testSession(miniflare, "1");
  const deletee = await testSession(miniflare, "2");
  const deleteePhone = "+14155550102";
  const deleteePhoneHash = pepperedTestHash("phone", deleteePhone);
  const originalInviteToken = "account-deletion-test-invite-token";
  const originalInviteTokenHash = pepperedTestHash(
    "invite-token",
    originalInviteToken,
  );
  const hostEventID = "10000000-0000-4000-8000-000000000001";
  const guestEventID = "10000000-0000-4000-8000-000000000002";
  const guestInviteeID = "20000000-0000-4000-8000-000000000002";
  const envelopeID = "30000000-0000-4000-8000-000000000002";
  const nowIso = new Date().toISOString();
  const frozenMembershipDocument = JSON.stringify({
    members: [{ id: guestInviteeID }],
  });
  const evaluatorEpochDescriptorSha256 = "a".repeat(64);

  await database.batch([
    database
      .prepare(
        `INSERT INTO evaluator_epoch_state
          (singleton_id, generation, mode, evaluator_key_epoch_id,
           epoch_descriptor_sha256, transparency_identity_sha256,
           workload_image_digest, response_decryption_key_id,
           evaluation_result_signing_key_id, policy_signing_key_id,
           response_transparency_signing_key_id, activated_at,
           drain_started_at, updated_at)
         VALUES (1, 1, 'active', 'herd-test-release-v1', ?, ?,
          'test-software-evaluator-sha384', 'test-evaluator-v1',
          'test-result-signing-v1', 'test-policy-signing-v1', 'proof-key',
          ?, NULL, ?)`,
      )
      .bind(
        evaluatorEpochDescriptorSha256,
        "b".repeat(64),
        nowIso,
        nowIso,
      ),
    database
      .prepare(
        `INSERT INTO events
          (id, host_user_id, title, event_date, end_date, host_name,
           location_name, location_address, minimum_participants,
           rsvp_deadline, event_description, invitations_sent, created_at,
           updated_at)
         VALUES (?, ?, 'Deletee hosted event', NULL, NULL, 'Deletee', '', '',
          1, NULL, '', 0, ?, ?)`,
      )
      .bind(hostEventID, deletee.user.id, nowIso, nowIso),
    database
      .prepare(
        `INSERT INTO events
          (id, host_user_id, title, event_date, end_date, host_name,
           location_name, location_address, minimum_participants,
           rsvp_deadline, event_description, invitations_sent, created_at,
           updated_at)
         VALUES (?, ?, 'Host event', NULL, NULL, 'Host', '', '', 2, NULL, '',
          1, ?, ?)`,
      )
      .bind(guestEventID, host.user.id, nowIso, nowIso),
    database
      .prepare(
        `INSERT INTO invitees
          (id, event_id, user_id, display_name, phone_number, phone_hash,
           token_hash, token_ciphertext, token_nonce, token_storage_version,
           created_at, updated_at)
         VALUES (?, ?, ?, 'Delete Me', ?, ?, ?, 'sealed-token', 'sealed-nonce',
          1, ?, ?)`,
      )
      .bind(
        guestInviteeID,
        guestEventID,
        deletee.user.id,
        deleteePhone,
        deleteePhoneHash,
        originalInviteTokenHash,
        nowIso,
        nowIso,
      ),
    database
      .prepare(
        `INSERT INTO event_policies
          (event_id, protocol_version, cipher_suite, policy_hash,
           canonical_document, evaluator_key_id, evaluator_public_key,
           evaluator_measurement, release_id, padded_plaintext_bytes,
           frozen_at, evaluator_epoch_descriptor_sha256)
         VALUES (?, 1, 'P256_HKDF_SHA256_AES256_GCM',
          'account-deletion-minimized-policy', ?, 'test-evaluator-v1', ?,
          'test-software-evaluator-sha384', 'herd-test-release-v1', 4096, ?, ?)`,
      )
      .bind(
        guestEventID,
        frozenMembershipDocument,
        evaluatorPublicKey,
        nowIso,
        evaluatorEpochDescriptorSha256,
      ),
    database
      .prepare(
        `INSERT INTO groups (id, event_id, position)
         VALUES ('40000000-0000-4000-8000-000000000002', ?, 0)`,
      )
      .bind(guestEventID),
    database.prepare(
      `INSERT INTO group_members (group_id, invitee_id, position)
       VALUES ('40000000-0000-4000-8000-000000000002', ?, 0)`,
    ).bind(guestInviteeID),
    database
      .prepare(
        `INSERT INTO invitation_deliveries
          (id, event_id, invitee_id, status, provider_message_sid,
           provider_status, attempt_count, dispatch_started_at, sent_at,
           failed_at, last_error_code, last_error_message, suppressed_reason,
           created_at, updated_at)
         VALUES ('50000000-0000-4000-8000-000000000002', ?, ?, 'sent',
          'SMprivate', 'delivered', 1, ?, ?, NULL, NULL, NULL, NULL, ?, ?)`,
      )
      .bind(guestEventID, guestInviteeID, nowIso, nowIso, nowIso, nowIso),
    database
      .prepare(
        `INSERT INTO response_envelopes
          (id, event_id, invitee_id, account_key_epoch_id, policy_hash,
           protocol_version, cipher_suite, evaluator_key_id, revision,
           payload_ciphertext, user_key_wrap, evaluator_key_wrap,
           ciphertext_hash, created_at, updated_at)
         VALUES (?, ?, ?, ?, 'policy-hash', 1,
          'P256_HKDF_SHA256_AES256_GCM', 'test-evaluator-v1', 1,
          'sealed-payload', 'sealed-user-wrap', 'sealed-evaluator-wrap',
          'ciphertext-hash', ?, ?)`,
      )
      .bind(
        envelopeID,
        guestEventID,
        guestInviteeID,
        deletee.accountKeyEpochId,
        nowIso,
        nowIso,
      ),
    database
      .prepare(
        `INSERT INTO response_transparency_entries
          (log_index, log_id, previous_entry_hash, entry_hash, envelope_id,
           canonical_receipt_payload, signing_key_id, receipt_signature,
           created_at, signed_at)
         VALUES (1, 'herd-response-v1', 'genesis', 'entry-hash', ?,
          '{"ciphertextHash":"ciphertext-hash"}', 'proof-key', 'signature', ?, ?)`,
      )
      .bind(envelopeID, nowIso, nowIso),
  ]);

  assert.equal(
    await scalar(
      database,
      "SELECT COUNT(*) AS value FROM invitees WHERE token_hash = ?",
      originalInviteTokenHash,
    ),
    1,
  );

  const deleteeSessionHash = pepperedTestHash(
    "session-token",
    deletee.accessToken,
  );
  await database
    .prepare("UPDATE sessions SET created_at = ? WHERE token_hash = ?")
    .bind(
      new Date(Date.now() - 10 * 60 * 1_000).toISOString(),
      deleteeSessionHash,
    )
    .run();

  const staleDeletion = await api(
    miniflare,
    "/api/me",
    jsonRequest("DELETE", { confirmation: "DELETE" }, deletee.accessToken),
  );
  assert.equal(staleDeletion.status, 403);
  assert.equal(
    (await staleDeletion.json()).error.code,
    "recent_authentication_required",
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM users WHERE id = ?", deletee.user.id),
    1,
  );

  // The stale-session scenario represents a login older than the resend
  // window; align the independently stored abuse-control clock accordingly.
  await database
    .prepare(
      `UPDATE auth_phone_rate_limits
       SET last_requested_at = '2000-01-01T00:00:00.000Z'
       WHERE phone_hash = ?`,
    )
    .bind(deleteePhoneHash)
    .run();

  // Only the explicit one-digit alias bypasses SMS. It still resolves to the
  // same durable account for reauthentication.
  const freshDeletee = await testSession(miniflare, "2");
  assert.equal(freshDeletee.user.id, deletee.user.id);

  const missingConfirmation = await api(
    miniflare,
    "/api/me",
    jsonRequest("DELETE", { confirmation: "delete" }, freshDeletee.accessToken),
  );
  assert.equal(missingConfirmation.status, 400);
  assert.equal(
    (await missingConfirmation.json()).error.code,
    "account_deletion_not_confirmed",
  );

  const crossOriginDeletion = await api(
    miniflare,
    "/api/me",
    jsonRequest(
      "DELETE",
      { confirmation: "DELETE" },
      freshDeletee.accessToken,
      { origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    ),
  );
  assert.equal(crossOriginDeletion.status, 403);
  assert.equal((await crossOriginDeletion.json()).error.code, "cross_origin_request");

  const deletion = await api(
    miniflare,
    "/api/me",
    jsonRequest("DELETE", { confirmation: "DELETE" }, freshDeletee.accessToken),
  );
  assert.equal(deletion.status, 204);
  assert.equal(await deletion.text(), "");
  assert.match(deletion.headers.get("set-cookie") ?? "", /Max-Age=0/i);

  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM users WHERE id = ?", deletee.user.id),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM sessions WHERE user_id = ?", deletee.user.id),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM account_key_epochs WHERE user_id = ?", deletee.user.id),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM events WHERE id = ?", hostEventID),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM events WHERE id = ?", guestEventID),
    1,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM response_envelopes WHERE id = ?", envelopeID),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM response_transparency_entries WHERE envelope_id = ?", envelopeID),
    1,
  );
  const survivingPolicyDocument = await database
    .prepare(
      "SELECT canonical_document AS canonicalDocument FROM event_policies WHERE event_id = ?",
    )
    .bind(guestEventID)
    .first("canonicalDocument");
  assert.deepEqual(JSON.parse(survivingPolicyDocument).members, [
    { id: guestInviteeID },
  ]);
  assert.equal(survivingPolicyDocument.includes("Delete Me"), false);
  assert.equal(survivingPolicyDocument.includes(deleteePhone), false);
  assert.equal(survivingPolicyDocument.includes("phoneAssignment"), false);
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM invitation_deliveries WHERE invitee_id = ?", guestInviteeID),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM group_members WHERE invitee_id = ?", guestInviteeID),
    1,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM challenges WHERE phone_hash = ?", deleteePhoneHash),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM auth_phone_rate_limits WHERE phone_hash = ?", deleteePhoneHash),
    0,
  );

  const tombstone = await database
    .prepare(
      `SELECT user_id AS userId, display_name AS displayName,
              phone_number AS phoneNumber, phone_hash AS phoneHash,
              token_hash AS tokenHash, token_ciphertext AS tokenCiphertext,
              token_nonce AS tokenNonce,
              token_storage_version AS tokenStorageVersion
       FROM invitees WHERE id = ?`,
    )
    .bind(guestInviteeID)
    .first();
  assert.deepEqual(
    {
      userId: tombstone.userId,
      displayName: tombstone.displayName,
      phoneNumber: tombstone.phoneNumber,
      tokenCiphertext: tombstone.tokenCiphertext,
      tokenNonce: tombstone.tokenNonce,
      tokenStorageVersion: tombstone.tokenStorageVersion,
    },
    {
      userId: null,
      displayName: "Deleted account",
      phoneNumber: "",
      tokenCiphertext: null,
      tokenNonce: null,
      tokenStorageVersion: null,
    },
  );
  assert.notEqual(tombstone.phoneHash, deleteePhoneHash);
  assert.notEqual(tombstone.tokenHash, originalInviteTokenHash);
  assert.match(tombstone.phoneHash, /^erased-phone:/);
  assert.match(tombstone.tokenHash, /^erased-token:/);

  for (const accessToken of [deletee.accessToken, freshDeletee.accessToken]) {
    const deletedSession = await api(miniflare, "/api/me", {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    assert.equal(deletedSession.status, 401);
  }

  const recreated = await testSession(miniflare, "2");
  assert.notEqual(recreated.user.id, deletee.user.id);
  const oldInviteAfterDeletion = await api(
    miniflare,
    `/api/invites/${originalInviteToken}`,
    { headers: { authorization: `Bearer ${recreated.accessToken}` } },
  );
  assert.equal(oldInviteAfterDeletion.status, 404);
  const preservedTombstone = await database
    .prepare("SELECT user_id AS userId FROM invitees WHERE id = ?")
    .bind(guestInviteeID)
    .first();
  assert.equal(preservedTombstone.userId, null);
});

test("an in-flight SMS verification cannot recreate an account after deletion", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const account = await testSession(miniflare, "3");
  const phoneNumber = "+14155550103";
  const phoneHash = pepperedTestHash("phone", phoneNumber);
  const challengeId = "challenge_deletion_race_regression";
  const verifiedAt = new Date().toISOString();
  await database
    .prepare(
      `INSERT INTO challenges
        (id, phone_number, phone_hash, code_hash, provider_sid, delivery,
         status, request_ip_hash, attempt_count, max_attempts, created_at,
         expires_at, resend_at, verified_at)
       VALUES (?, ?, ?, NULL, 'VE-test', 'sms', 'verified', 'ip-test', 1, 5,
        ?, ?, ?, ?)`,
    )
    .bind(
      challengeId,
      phoneNumber,
      phoneHash,
      verifiedAt,
      new Date(Date.now() + 300_000).toISOString(),
      verifiedAt,
      verifiedAt,
    )
    .run();

  // Model the exact pause point in verifyAuthCode: Twilio approved and the
  // challenge was marked verified, then the already-authenticated user deleted
  // the account before user/session creation resumed.
  const deletion = await api(
    miniflare,
    "/api/me",
    jsonRequest("DELETE", { confirmation: "DELETE" }, account.accessToken),
  );
  assert.equal(deletion.status, 204);
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM challenges WHERE id = ?", challengeId),
    0,
  );

  const resumed = await upsertUserForVerifiedChallenge(database, {
    challengeId,
    verifiedAt,
    phoneNumber,
    phoneHash,
    userId: "user_should_never_be_created",
    suggestedName: "Deleted person",
    nowIso: new Date().toISOString(),
  });
  assert.equal(resumed, null);
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM users WHERE phone_number = ?", phoneNumber),
    0,
  );
  assert.equal(
    await scalar(database, "SELECT COUNT(*) AS value FROM sessions WHERE user_id = ?", account.user.id),
    0,
  );
});
