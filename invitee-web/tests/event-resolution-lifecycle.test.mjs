import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { createFetchMock, Miniflare } from "miniflare";

import { loadPrivateResponseTestModules } from "./helpers/private-response-test-modules.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const testPhone = "+14155550187";
const testPepper = "herd-resolution-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const evaluatorKeyId = "test-evaluator-v1";
const evaluatorUrl = "https://evaluator.example.com/v1/evaluations";
const evaluatorToken = "test-evaluator-token-0123456789-abcdefghijklmnopqrstuvwxyz";
const evaluatorSitesBypassToken =
  "test-sites-bypass-token-0123456789-abcdefghijklmnopqrstuvwxyz";
const policySigningKeyId = "test-policy-signing-v1";
const transparencySigningKeyId = "test-transparency-signing-v1";
const resultSigningKeyId = "test-result-signing-v1";
const evaluatorPublicKey = Buffer.from(
  `04${
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  }${"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}`,
  "hex",
).toString("base64url");
const twilioApiKeySid = `SK${"7".repeat(32)}`;
const twilioVerifyServiceSid = `VA${"8".repeat(32)}`;
const twilioAccountSid = `AC${"6".repeat(32)}`;
const twilioMessagingServiceSid = `MG${"5".repeat(32)}`;

let harnessNumber = 0;

const { protocol, cleanup: cleanupPrivateResponseModules } =
  await loadPrivateResponseTestModules(projectRoot);
after(cleanupPrivateResponseModules);

async function signingFixture(keyId) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    keyId,
    keyPair,
    publicKey: protocol.bytesToBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
    ),
  };
}

const policySigning = await signingFixture(policySigningKeyId);
const transparencySigning = await signingFixture(transparencySigningKeyId);
const resultSigning = await signingFixture(resultSigningKeyId);

function encodedBytes(length, fill = 7) {
  return Buffer.alloc(length, fill % 256).toString("base64url");
}

function sha256Base64Url(value) {
  return createHash("sha256").update(value).digest("base64url");
}

const responseSigningKeyPair = generateKeyPairSync("ed25519");
const responseSigningPublicKey = responseSigningKeyPair.publicKey.export({
  format: "jwk",
}).x;

function responseAuthorizationSignature(unsignedEnvelope) {
  const ciphertextHash = sha256Base64Url(JSON.stringify(unsignedEnvelope));
  const authorizationPayload = JSON.stringify({
    protocolVersion: unsignedEnvelope.protocolVersion,
    eventId: unsignedEnvelope.eventId,
    inviteeId: unsignedEnvelope.inviteeId,
    policyHash: unsignedEnvelope.policyHash,
    accountKeyEpochId: unsignedEnvelope.accountKeyEpochId,
    revision: unsignedEnvelope.revision,
    envelopeId: unsignedEnvelope.envelopeId,
    ciphertextHash,
    responseSigningPublicKey: unsignedEnvelope.responseSigningPublicKey,
  });
  return sign(
    null,
    Buffer.from(`HERD-RESPONSE-AUTHORIZATION-V1\0${authorizationPayload}`),
    responseSigningKeyPair.privateKey,
  ).toString("base64url");
}

function jsonRequest(method, body, accessToken) {
  return {
    method,
    headers: {
      "content-type": "application/json",
      origin: "https://herd.test",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify(body),
  };
}

function authorizedRequest(accessToken) {
  return { headers: { authorization: `Bearer ${accessToken}` } };
}

function api(miniflare, pathname, init = {}) {
  return miniflare.dispatchFetch(`https://herd.test${pathname}`, init);
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

async function createHarness(options = {}) {
  await access(path.join(serverRoot, "index.js"));
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  harnessNumber += 1;
  const evaluatorBindings = options.omitEvaluatorService
    ? {}
    : {
        HERD_EVALUATOR_URL: evaluatorUrl,
        HERD_EVALUATOR_TOKEN: evaluatorToken,
        HERD_EVALUATOR_SITES_BYPASS_TOKEN: evaluatorSitesBypassToken,
      };
  const fetchMock = options.fetchMock ?? createFetchMock();
  const messageBodies = [];
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://verify.twilio.com")
    .intercept({ method: "POST", path: `/v2/Services/${twilioVerifyServiceSid}/Verifications` })
    .reply(201, { sid: `VE${"9".repeat(32)}`, status: "pending" })
    .persist();
  fetchMock
    .get("https://verify.twilio.com")
    .intercept({ method: "POST", path: `/v2/Services/${twilioVerifyServiceSid}/VerificationCheck` })
    .reply(200, { sid: `VE${"9".repeat(32)}`, status: "approved", valid: true })
    .persist();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: `/2010-04-01/Accounts/${twilioAccountSid}/Messages.json` })
    .reply(201, async (request) => {
      const body = new URLSearchParams(await new Response(request.body).text());
      messageBodies.push(body.get("Body"));
      return { sid: `SM${"4".repeat(32)}`, status: "accepted" };
    })
    .persist();
  const trustSigningBindings = options.fetchMock
    ? {
        HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: policySigning.keyId,
        HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: policySigning.publicKey,
        HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: transparencySigning.keyId,
        HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
          transparencySigning.publicKey,
        HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: resultSigning.keyId,
        HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: resultSigning.publicKey,
      }
    : {};
  const miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({ type: "ESModule", path: modulePath })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: {
      DB: `herd-resolution-${process.pid}-${Date.now()}-${harnessNumber}`,
    },
    fetchMock,
    bindings: {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_AUTH_PEPPER: testPepper,
      HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
      HERD_TEST_ACCOUNT_ACCESS_GENERATION: "herd-test-generation-v1",
      HERD_TEST_HOST_PHONE_E164: "+14155550111",
      HERD_EVALUATOR_KEY_ID: evaluatorKeyId,
      HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
      HERD_EVALUATOR_MEASUREMENT: "test-software-evaluator-sha384",
      HERD_RELEASE_ID: "herd-test-release-v1",
      HERD_ARTIFACT_RELEASE_ID: "2026.08.12.resolution-test",
      HERD_PUBLIC_APP_URL: "https://app.herdprivacy.com",
      TWILIO_API_KEY_SID: twilioApiKeySid,
      TWILIO_API_KEY_SECRET: "resolution-twilio-secret",
      TWILIO_VERIFY_SERVICE_SID: twilioVerifyServiceSid,
      TWILIO_ACCOUNT_SID: twilioAccountSid,
      TWILIO_MESSAGING_SERVICE_SID: twilioMessagingServiceSid,
      ...evaluatorBindings,
      ...trustSigningBindings,
      ...options.bindings,
    },
  });
  const database = await miniflare.getD1Database("DB");
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/.test(name))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(path.join(migrationDirectory, migrationFile), "utf8");
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/g, " "));
    }
  }
  return { miniflare, database, messageBodies };
}

async function trustSignature(keyPair, domain, canonicalPayload) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        protocol.domainSeparatedUtf8(domain, canonicalPayload),
      ),
    ),
  );
}

async function trustPayloadHash(canonicalPayload) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonicalPayload),
      ),
    ),
  );
}

function installTrustSigningTransport(fetchMock, options = {}) {
  const evaluatorOrigin = fetchMock.get("https://evaluator.example.com");
  const appendResponses = new Map();
  let lastLogIndex = 0;
  let lastEntryHash = protocol.bytesToBase64Url(new Uint8Array(32));

  evaluatorOrigin
    .intercept({ method: "POST", path: /^\/api\/v1\/sign\/policy\/?$/u })
    .reply(
      200,
      async (request) => {
        const body = JSON.parse(await new Response(request.body).text());
        assert.deepEqual(Object.keys(body).sort(), [
          "canonicalDocument",
          "protocolVersion",
        ]);
        return JSON.stringify({
          protocolVersion: 1,
          domain: protocol.PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
          signingKeyId: policySigning.keyId,
          payloadHash: await trustPayloadHash(body.canonicalDocument),
          signature: await trustSignature(
            policySigning.keyPair,
            protocol.PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
            body.canonicalDocument,
          ),
        });
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();

  if (options.lateMissingFirstEntry) {
    evaluatorOrigin
      .intercept({
        method: "POST",
        path: /^\/api\/v1\/sign\/transparency\/?$/u,
      })
      .reply(
        503,
        JSON.stringify({ error: { code: "service_unavailable" } }),
        { headers: { "content-type": "application/json" } },
      );

    const lateMissingReply = (tamperSignature) => async (request) => {
      const body = JSON.parse(await new Response(request.body).text());
      const receipt = JSON.parse(body.canonicalReceiptPayload);
      assert.equal(receipt.logIndex, 1);
      assert.equal(receipt.previousEntryHash, lastEntryHash);
      const canonicalPayload = JSON.stringify({
        protocolVersion: 1,
        logId: protocol.PRIVATE_RESPONSE_LOG_ID,
        rejectedLogIndex: receipt.logIndex,
        rejectedEntryHash: receipt.entryHash,
        authorityTreeSize: 0,
        authorityHeadEntryHash: lastEntryHash,
        generatedAt: new Date().toISOString(),
        signingKeyId: transparencySigning.keyId,
      });
      let signature = await trustSignature(
        transparencySigning.keyPair,
        protocol.PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN,
        canonicalPayload,
      );
      if (tamperSignature) {
        const bytes = Buffer.from(signature, "base64url");
        bytes[0] ^= 1;
        signature = bytes.toString("base64url");
      }
      return JSON.stringify({
        error: {
          code: "transparency_late_missing_entry",
          proof: {
            canonicalPayload,
            domain: protocol.PRIVATE_RESPONSE_RECONCILIATION_SIGNATURE_DOMAIN,
            payloadHash: await trustPayloadHash(canonicalPayload),
            signature,
            signingKeyId: transparencySigning.keyId,
          },
        },
      });
    };

    if (options.tamperFirstLateMissingProof) {
      evaluatorOrigin
        .intercept({
          method: "POST",
          path: /^\/api\/v1\/sign\/transparency\/?$/u,
        })
        .reply(409, lateMissingReply(true), {
          headers: { "content-type": "application/json" },
        });
    }
    const validLateMissingScope = evaluatorOrigin
      .intercept({
        method: "POST",
        path: /^\/api\/v1\/sign\/transparency\/?$/u,
      })
      .reply(409, lateMissingReply(false), {
        headers: { "content-type": "application/json" },
      });
    validLateMissingScope.times(options.validLateMissingProofCount ?? 1);
  }

  evaluatorOrigin
    .intercept({
      method: "POST",
      path: /^\/api\/v1\/sign\/transparency\/?$/u,
    })
    .reply(
      200,
      async (request) => {
        const body = JSON.parse(await new Response(request.body).text());
        assert.equal(body.protocolVersion, 1);
        assert.equal(body.kind, "append");
        const existing = appendResponses.get(body.canonicalReceiptPayload);
        if (existing) return existing;
        const certification = (async () => {
          const receipt = JSON.parse(body.canonicalReceiptPayload);
          assert.equal(JSON.stringify(receipt), body.canonicalReceiptPayload);
          assert.equal(receipt.logIndex, lastLogIndex + 1);
          assert.equal(receipt.previousEntryHash, lastEntryHash);
          assert.equal(receipt.signingKeyId, transparencySigning.keyId);
          lastLogIndex = receipt.logIndex;
          lastEntryHash = receipt.entryHash;
          const canonicalHeadPayload =
            protocol.canonicalPrivateResponseLogHeadPayload({
              protocolVersion: 1,
              logId: receipt.logId,
              treeSize: receipt.logIndex,
              headEntryHash: receipt.entryHash,
              generatedAt: new Date().toISOString(),
              signingKeyId: transparencySigning.keyId,
            });
          return JSON.stringify({
            protocolVersion: 1,
            kind: "append",
            signingKeyId: transparencySigning.keyId,
            receipt: {
              domain: protocol.PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
              payloadHash: await trustPayloadHash(body.canonicalReceiptPayload),
              signature: await trustSignature(
                transparencySigning.keyPair,
                protocol.PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
                body.canonicalReceiptPayload,
              ),
            },
            logHead: {
              canonicalPayload: canonicalHeadPayload,
              domain: protocol.PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
              payloadHash: await trustPayloadHash(canonicalHeadPayload),
              signature: await trustSignature(
                transparencySigning.keyPair,
                protocol.PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
                canonicalHeadPayload,
              ),
            },
          });
        })();
        appendResponses.set(body.canonicalReceiptPayload, certification);
        return certification;
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
}

function evaluatorMock(options = {}) {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  installTrustSigningTransport(fetchMock, options);
  return fetchMock;
}

function queueEvaluatorResult(fetchMock, result, requestLog = [], options = {}) {
  const scope = fetchMock
    .get("https://evaluator.example.com")
    .intercept({
      method: "POST",
      path: "/v1/evaluations",
      headers: {
        authorization: `Bearer ${evaluatorToken}`,
        "OAI-Sites-Authorization": `Bearer ${evaluatorSitesBypassToken}`,
      },
    })
    .reply((request) => {
      requestLog.push(request);
      return {
        statusCode: result.statusCode ?? 200,
        data: JSON.stringify(result.body ?? result),
        responseOptions: { headers: { "content-type": "application/json" } },
      };
    });
  if (options.persist) scope.persist();
  else scope.times(options.times ?? 1);
  if (options.delayMilliseconds) scope.delay(options.delayMilliseconds);
}

async function expectedBatch(
  database,
  eventId,
  policyHash,
  inviteeIds,
  revealAttendance = true,
) {
  const rows = await database
    .prepare(
      `SELECT invitees.id,
              response_envelopes.ciphertext_hash AS envelopeHash
       FROM invitees
       LEFT JOIN response_envelopes
         ON response_envelopes.id = (
           SELECT latest.id
           FROM response_envelopes AS latest
           WHERE latest.invitee_id = invitees.id
           ORDER BY latest.revision DESC, latest.created_at DESC
           LIMIT 1
         )
       WHERE invitees.event_id = ?
       ORDER BY invitees.id ASC`,
    )
    .bind(eventId)
    .all();
  assert.deepEqual(rows.results.map(({ id }) => id), [...inviteeIds].sort());
  const slots = rows.results.map(({ id: inviteeId, envelopeHash }) => ({
    inviteeId,
    envelopeHash: envelopeHash ?? null,
  }));
  return {
    slots,
    batchHash: sha256Base64Url(
      JSON.stringify({ protocolVersion: 1, eventId, policyHash, revealAttendance, slots }),
    ),
  };
}

async function authenticate(miniflare, phoneNumber) {
  const fixedAccount = /^\+1415555010([1-9])$/u.exec(phoneNumber);
  const alias = /^[1-9]$/u.test(phoneNumber) ? phoneNumber : fixedAccount?.[1];
  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: alias ?? phoneNumber }),
  );
  if (alias) {
    assert.equal(response.status, 200);
    return response.json();
  }
  assert.equal(response.status, 201);
  const challenge = await response.json();
  const verified = await api(
    miniflare,
    "/api/auth/verify-code",
    jsonRequest("POST", { challengeId: challenge.challengeId, code: "1234" }),
  );
  assert.equal(verified.status, 200);
  return verified.json();
}

function eventPayload({ id, invitees, deadline, title = "Resolution lifecycle", ...overrides }) {
  const eventDate = new Date(Date.now() + 60_000).toISOString();
  return {
    id,
    title,
    eventDate,
    endDate: new Date(Date.parse(eventDate) + 3_600_000).toISOString(),
    hostName: "Test host",
    locationName: "Herd test",
    locationAddress: "San Francisco, CA",
    invitees,
    minimumParticipants: 2,
    requiredGroups: [],
    rsvpDeadline: deadline,
    eventDescription: "Exercises durable private event resolution.",
    createdAt: new Date().toISOString(),
    invitationsSent: true,
    ...overrides,
  };
}

function encryptedEnvelope({ event, inviteeId, accountKeyEpochId, revision, number }) {
  const evaluatorFrame = Buffer.alloc(157, (number + revision) % 256);
  evaluatorFrame[0] = 0x04;
  const unsignedEnvelope = {
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    envelopeId: `81000000-0000-4000-8000-${String(number * 100 + revision).padStart(12, "0")}`,
    eventId: event.id,
    inviteeId,
    policyHash: event.privateResponsePolicy.policyHash,
    revision,
    accountKeyEpochId,
    evaluatorKeyId,
    payloadCiphertext: encodedBytes(4_124, number + revision),
    userKeyWrap: encodedBytes(60, number + revision + 40),
    evaluatorKeyWrap: evaluatorFrame.toString("base64url"),
    responseSigningPublicKey,
  };
  return {
    ...unsignedEnvelope,
    responseSignature: responseAuthorizationSignature(unsignedEnvelope),
  };
}

async function initializeKey(miniflare, session, fill) {
  const response = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    jsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: session.accountKeyEpochId,
        keyCommitment: encodedBytes(32, fill),
      },
      session.accessToken,
    ),
  );
  assert.equal(response.status, 200);
}

async function waitPast(iso) {
  const milliseconds = Math.max(0, Date.parse(iso) - Date.now() + 35);
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitUntil(predicate, message) {
  const timeoutAt = Date.now() + 2_000;
  while (!predicate()) {
    if (Date.now() >= timeoutAt) throw new Error(message);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

function exactEvaluatorResult(request, status, attendingMemberIds) {
  return {
    protocolVersion: 1,
    eventId: request.eventId,
    policyHash: request.policy.policyHash,
    batchHash: request.batchHash,
    evaluatorKeyId,
    status,
    revealAttendance: request.revealAttendance ?? true,
    ...(status === "confirmed" && (request.revealAttendance ?? true)
      ? { attendingMemberIds }
      : {}),
  };
}

async function createSingleInviteeEvent(
  miniflare,
  host,
  invitee,
  eventId,
  deadline,
  overrides = {},
) {
  const inviteeId = eventId.replace(/^82/, "83");
  const event = eventPayload({
    id: eventId,
    deadline,
    invitees: [
      {
        id: inviteeId,
        displayName: "Test account 1",
        phoneNumber: "+14155550101",
      },
    ],
    ...overrides,
  });
  const response = await api(
    miniflare,
    `/api/events/${eventId}`,
    jsonRequest("PUT", event, host.accessToken),
  );
  assert.equal(response.status, 200);
  const saved = (await response.json()).event;
  const listing = await api(miniflare, "/api/events", authorizedRequest(invitee.accessToken));
  assert.equal(listing.status, 200);
  const invited = (await listing.json()).events.find((candidate) => candidate.id === eventId);
  assert.ok(invited);
  return { event: saved, invited, inviteeId };
}

test("a stale empty result self-heals and a corrupt result cannot hide the event list", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const epochActivatedAt = new Date().toISOString();
  await database
    .prepare(
      `INSERT INTO evaluator_epoch_state
        (singleton_id, generation, mode, evaluator_key_epoch_id,
         epoch_descriptor_sha256, transparency_identity_sha256,
         workload_image_digest, response_decryption_key_id,
         evaluation_result_signing_key_id, policy_signing_key_id,
         response_transparency_signing_key_id, activated_at, drain_started_at,
         updated_at)
       VALUES (1, 1, 'active', 'test-release', ?, ?, 'test-image',
        'test-response-key', 'test-result-key', 'test-policy-key',
        'test-transparency-key', ?, NULL, ?)`,
    )
    .bind("a".repeat(64), "b".repeat(64), epochActivatedAt, epochActivatedAt)
    .run();

  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  const deadline = new Date(Date.now() + 30_000).toISOString();
  const recoverableEventId = "82000000-0000-4000-8000-000000000081";
  const corruptEventId = "82000000-0000-4000-8000-000000000082";
  await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    recoverableEventId,
    deadline,
  );
  await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    corruptEventId,
    deadline,
  );

  const nowIso = new Date().toISOString();
  const insertPolicy = (eventId, policyHash) =>
    database
      .prepare(
        `INSERT INTO event_policies
          (event_id, protocol_version, cipher_suite, policy_hash,
           canonical_document, evaluator_key_id, evaluator_public_key,
           evaluator_measurement, release_id, padded_plaintext_bytes, frozen_at,
           evaluator_epoch_descriptor_sha256)
         SELECT ?, 1, 'P256_HKDF_SHA256_AES256_GCM', ?, '{}',
          'test-evaluator-v1', 'test-public-key', 'test-measurement',
          evaluator_key_epoch_id, 4096, ?, epoch_descriptor_sha256
         FROM evaluator_epoch_state WHERE singleton_id = 1`,
      )
      .bind(eventId, policyHash, nowIso);
  const insertResolution = (eventId, policyHash, status) =>
    database
      .prepare(
        `UPDATE event_resolutions
         SET policy_hash = ?, status = ?, batch_hash = ?,
             attending_member_ids = NULL, resolved_at = ?, updated_at = ?
         WHERE event_id = ?`,
      )
      .bind(
        policyHash,
        status,
        status === "pending" ? null : "historical-result",
        status === "pending" ? null : nowIso,
        nowIso,
        eventId,
      );
  await database.batch([
    insertPolicy(recoverableEventId, "current-policy-recoverable"),
    insertResolution(recoverableEventId, "stale-policy-recoverable", "pending"),
    insertPolicy(corruptEventId, "current-policy-corrupt"),
    insertResolution(corruptEventId, "stale-policy-corrupt", "confirmed"),
  ]);

  const listing = await api(
    miniflare,
    "/api/events",
    authorizedRequest(invitee.accessToken),
  );
  assert.equal(listing.status, 200);
  const events = (await listing.json()).events;
  assert.deepEqual(
    events.find(({ id }) => id === recoverableEventId).resolution,
    { status: "pending" },
  );
  assert.deepEqual(
    events.find(({ id }) => id === corruptEventId).resolution,
    { status: "verification_unavailable" },
  );

  const recovered = await database
    .prepare("SELECT policy_hash AS policyHash FROM event_resolutions WHERE event_id = ?")
    .bind(recoverableEventId)
    .first();
  assert.equal(recovered.policyHash, "current-policy-recoverable");
  const preserved = await database
    .prepare("SELECT policy_hash AS policyHash FROM event_resolutions WHERE event_id = ?")
    .bind(corruptEventId)
    .first();
  assert.equal(preserved.policyHash, "stale-policy-corrupt");
});

test("ten accounts share one durable confirmed/failure outcome without leaking failed RSVP details", async (t) => {
  const requests = [];
  const fetchMock = evaluatorMock();
  const { miniflare, database, messageBodies } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());

  const host = await authenticate(miniflare, testPhone);
  const inviteeSessions = [];
  for (let number = 1; number <= 9; number += 1) {
    inviteeSessions.push(await authenticate(miniflare, String(number)));
  }

  const eventId = "82000000-0000-4000-8000-000000000001";
  const invitees = inviteeSessions.map((_, index) => ({
    id: `83000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    displayName: `Test account ${index + 1}`,
    phoneNumber: `+1415555010${index + 1}`,
  }));
  const deadline = new Date(Date.now() + 2_500).toISOString();
  const attendance = ["host", ...invitees.slice(0, 5).map(({ id }) => id)];
  const payload = eventPayload({
    id: eventId,
    invitees,
    deadline,
    minimumParticipants: 5,
    requiredGroups: [
      {
        id: "84000000-0000-4000-8000-000000000001",
        memberIDs: [invitees[0].id, invitees[1].id],
      },
    ],
  });
  const sentResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    jsonRequest("PUT", payload, host.accessToken),
  );
  assert.equal(sentResponse.status, 200);

  const inviteViews = [];
  for (const [index, session] of inviteeSessions.entries()) {
    const response = await api(miniflare, "/api/events", authorizedRequest(session.accessToken));
    assert.equal(response.status, 200);
    const event = (await response.json()).events.find((candidate) => candidate.id === eventId);
    assert.deepEqual(event.resolution, { status: "pending" });
    await initializeKey(miniflare, session, index + 1);
    inviteViews.push(event);
  }

  const firstEnvelope = encryptedEnvelope({
    event: inviteViews[0],
    inviteeId: invitees[0].id,
    accountKeyEpochId: inviteeSessions[0].accountKeyEpochId,
    revision: 1,
    number: 1,
  });
  const firstResponse = await api(
    miniflare,
    `/api/invites/${inviteViews[0].inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: firstEnvelope }, inviteeSessions[0].accessToken),
  );
  assert.equal(firstResponse.status, 200);
  const firstResponseBody = await firstResponse.json();
  const exactRetry = await api(
    miniflare,
    `/api/invites/${inviteViews[0].inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: firstEnvelope }, inviteeSessions[0].accessToken),
  );
  assert.equal(exactRetry.status, 200);
  assert.deepEqual(await exactRetry.json(), firstResponseBody);

  const skippedRevision = encryptedEnvelope({
    event: inviteViews[0],
    inviteeId: invitees[0].id,
    accountKeyEpochId: inviteeSessions[0].accountKeyEpochId,
    revision: 3,
    number: 3,
  });
  const skippedResponse = await api(
    miniflare,
    `/api/invites/${inviteViews[0].inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: skippedRevision }, inviteeSessions[0].accessToken),
  );
  assert.equal(skippedResponse.status, 409);
  assert.equal((await skippedResponse.json()).error.details.expectedRevision, 2);

  const competing = [11, 12].map((number) =>
    encryptedEnvelope({
      event: inviteViews[0],
      inviteeId: invitees[0].id,
      accountKeyEpochId: inviteeSessions[0].accountKeyEpochId,
      revision: 2,
      number,
    }),
  );
  const competingResponses = await Promise.all(
    competing.map((envelope) =>
      api(
        miniflare,
        `/api/invites/${inviteViews[0].inviteToken}/rsvp`,
        jsonRequest("PUT", { envelope }, inviteeSessions[0].accessToken),
      ),
    ),
  );
  assert.deepEqual(competingResponses.map(({ status }) => status).sort(), [200, 409]);
  const winningIndex = competingResponses.findIndex(({ status }) => status === 200);
  const winningRetry = await api(
    miniflare,
    `/api/invites/${inviteViews[0].inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: competing[winningIndex] }, inviteeSessions[0].accessToken),
  );
  assert.equal(winningRetry.status, 200);

  const wrongEpoch = encryptedEnvelope({
    event: inviteViews[1],
    inviteeId: invitees[1].id,
    accountKeyEpochId: "85000000-0000-4000-8000-000000000099",
    revision: 1,
    number: 20,
  });
  const wrongEpochResponse = await api(
    miniflare,
    `/api/invites/${inviteViews[1].inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: wrongEpoch }, inviteeSessions[1].accessToken),
  );
  assert.equal(wrongEpochResponse.status, 409);
  assert.equal((await wrongEpochResponse.json()).error.code, "account_key_epoch_changed");

  for (let index = 1; index < inviteeSessions.length; index += 1) {
    const envelope = encryptedEnvelope({
      event: inviteViews[index],
      inviteeId: invitees[index].id,
      accountKeyEpochId: inviteeSessions[index].accountKeyEpochId,
      revision: 1,
      number: index + 1,
    });
    const response = await api(
      miniflare,
      `/api/invites/${inviteViews[index].inviteToken}/rsvp`,
      jsonRequest("PUT", { envelope }, inviteeSessions[index].accessToken),
    );
    assert.equal(response.status, 200);
  }
  const revisionCount = await database
    .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
    .bind(eventId)
    .first();
  assert.equal(revisionCount.count, 10);

  // Recreate the durable state left when the independent authority commits but
  // its HTTP response (or the following D1 persistence) is lost: the exact
  // canonical entry remains queued while its local receipt/head are absent.
  // Deadline evaluation must retry that exact entry before selecting a batch.
  const lostCertification = await database
    .prepare(
      `SELECT transparency.log_index AS logIndex
       FROM response_transparency_entries AS transparency
       JOIN response_envelopes AS envelopes
         ON envelopes.id = transparency.envelope_id
       WHERE envelopes.invitee_id = ?
       ORDER BY envelopes.revision DESC
       LIMIT 1`,
    )
    .bind(invitees[0].id)
    .first();
  assert.ok(lostCertification?.logIndex);
  await database.batch([
    database
      .prepare("DELETE FROM response_transparency_heads WHERE log_index = ?")
      .bind(lostCertification.logIndex),
    database
      .prepare(
        `UPDATE response_transparency_entries
         SET receipt_signature = NULL, signed_at = NULL
         WHERE log_index = ?`,
      )
      .bind(lostCertification.logIndex),
  ]);
  const lostSignedAt = await database
    .prepare(
      `SELECT transparency.log_index AS logIndex
       FROM response_transparency_entries AS transparency
       JOIN response_envelopes AS envelopes
         ON envelopes.id = transparency.envelope_id
       WHERE envelopes.invitee_id = ?
       ORDER BY envelopes.revision DESC
       LIMIT 1`,
    )
    .bind(invitees[1].id)
    .first();
  assert.ok(lostSignedAt?.logIndex);
  await database
    .prepare(
      `UPDATE response_transparency_entries
       SET signed_at = NULL
       WHERE log_index = ?`,
    )
    .bind(lostSignedAt.logIndex)
    .run();

  for (const index of [0, 1]) {
    const pendingRead = await api(
      miniflare,
      `/api/invites/${inviteViews[index].inviteToken}`,
      authorizedRequest(inviteeSessions[index].accessToken),
    );
    assert.equal(pendingRead.status, 200);
    const pendingBody = await pendingRead.json();
    // The independent authority can complete the exact durable retry before
    // this read on a fast hosted runner. Both states are safe here: pending
    // proves the evaluation path must recover it, while certified proves the
    // background self-heal already did. The final assertions below still
    // require a complete receipt and signed head.
    assert.ok(
      ["pending", "certified"].includes(
        pendingBody.event.responseCertificationStatus,
      ),
    );
    assert.equal(
      pendingBody.inviteMetadata.responseCertificationStatus,
      pendingBody.event.responseCertificationStatus,
    );
    assert.equal(
      pendingBody.inviteMetadata.responseEnvelope.envelopeId,
      index === 0
        ? (await database
            .prepare(
              `SELECT envelope_id AS envelopeId
               FROM response_transparency_entries
               WHERE log_index = ?`,
            )
            .bind(lostCertification.logIndex)
            .first()).envelopeId
        : (await database
            .prepare(
              `SELECT envelope_id AS envelopeId
               FROM response_transparency_entries
               WHERE log_index = ?`,
            )
            .bind(lostSignedAt.logIndex)
            .first()).envelopeId,
    );
  }

  const confirmedBatch = await expectedBatch(
    database,
    eventId,
    inviteViews[0].privateResponsePolicy.policyHash,
    invitees.map(({ id }) => id),
  );
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      {
        eventId,
        policy: inviteViews[0].privateResponsePolicy,
        batchHash: confirmedBatch.batchHash,
      },
      "confirmed",
      attendance,
    ),
    requests,
  );

  await waitPast(deadline);
  const hostRead = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
  assert.equal(
    hostRead.status,
    200,
    JSON.stringify({ body: await hostRead.clone().json(), evaluatorRequests: requests.length }),
  );
  const resolved = (await hostRead.json()).events.find((event) => event.id === eventId);
  assert.equal(resolved.resolution.status, "confirmed");
  assert.equal(resolved.resolution.attendanceRevealed, true);
  assert.deepEqual(resolved.resolution.attendingMemberIds, attendance);
  assert.ok(resolved.invitees.every(({ responseHistory }) =>
    responseHistory?.missedConfirmedEvents === 0
      && responseHistory?.totalConfirmedEvents === 1
  ));
  assert.deepEqual(
    resolved.resolution.guestStates.map(({ memberId, status, missedDeadline }) => ({
      memberId,
      status,
      missedDeadline,
    })),
    invitees.map(({ id }, index) => ({
      memberId: id,
      status: index < 5 ? "going" : "cant_commit",
      missedDeadline: false,
    })),
  );
  assert.match(resolved.resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.equal(requests.length, 1);
  assert.deepEqual(
    await database
      .prepare(
        `SELECT COUNT(*) AS count, COUNT(DISTINCT phone_number) AS recipients,
                MIN(delivery_status) AS minimumStatus,
                MAX(delivery_status) AS maximumStatus
         FROM resolution_notifications
         WHERE event_id = ? AND status = 'confirmed'`,
      )
      .bind(eventId)
      .first(),
    {
      count: 10,
      recipients: 10,
      minimumStatus: "sent",
      maximumStatus: "sent",
    },
  );
  const eventDate = `${new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "UTC",
  }).format(new Date(payload.eventDate))} UTC`;
  const confirmedMessages = messageBodies.filter((body) =>
    body?.startsWith('The event "Resolution lifecycle" is now confirmed')
  );
  assert.equal(confirmedMessages.length, 10);
  assert.ok(confirmedMessages.includes(
    `The event "Resolution lifecycle" is now confirmed and will happen on ${eventDate}. View event information: https://app.herdprivacy.com`,
  ));
  assert.ok(confirmedMessages.some((body) =>
    body?.startsWith(
      `The event "Resolution lifecycle" is now confirmed and will happen on ${eventDate}. View event information: https://app.herdprivacy.com/invite/`,
    )
  ));
  assert.equal(confirmedBatch.slots.length, 9);
  assert.ok(confirmedBatch.slots.every(({ envelopeHash }) => envelopeHash));
  assert.equal(confirmedBatch.batchHash.length, 43);
  const recoveredCertification = await database
    .prepare(
      `SELECT entries.receipt_signature AS receiptSignature,
              heads.signature AS headSignature
       FROM response_transparency_entries AS entries
       LEFT JOIN response_transparency_heads AS heads
         ON heads.log_index = entries.log_index
       WHERE entries.log_index = ?`,
    )
    .bind(lostCertification.logIndex)
    .first();
  assert.equal(typeof recoveredCertification?.receiptSignature, "string");
  assert.equal(typeof recoveredCertification?.headSignature, "string");
  const recoveredSignedAt = await database
    .prepare(
      `SELECT signed_at AS signedAt
       FROM response_transparency_entries
       WHERE log_index = ?`,
    )
    .bind(lostSignedAt.logIndex)
    .first();
  assert.match(recoveredSignedAt?.signedAt ?? "", /^\d{4}-\d{2}-\d{2}T/u);

  for (const session of inviteeSessions) {
    const response = await api(miniflare, "/api/events", authorizedRequest(session.accessToken));
    assert.equal(response.status, 200);
    const event = (await response.json()).events.find((candidate) => candidate.id === eventId);
    assert.deepEqual(event.resolution, resolved.resolution);
    assert.equal(Object.hasOwn(event.resolution, "batchHash"), false);
  }
  assert.equal(requests.length, 1);
  const tokenRead = await api(
    miniflare,
    `/api/invites/${inviteViews[0].inviteToken}`,
    authorizedRequest(inviteeSessions[0].accessToken),
  );
  assert.equal(tokenRead.status, 200);
  const tokenBody = await tokenRead.json();
  assert.deepEqual(tokenBody.event.resolution, resolved.resolution);
  assert.equal(tokenBody.event.responseCertificationStatus, "certified");
  assert.equal(tokenBody.inviteMetadata.responseCertificationStatus, "certified");
  assert.equal(requests.length, 1);

  const failureEventId = "82000000-0000-4000-8000-000000000002";
  const failureInvitees = invitees.map((invitee, index) => ({
    ...invitee,
    id: `86000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
  }));
  const failureDeadline = new Date(Date.now() + 180).toISOString();
  const failureResponse = await api(
    miniflare,
    `/api/events/${failureEventId}`,
    jsonRequest(
      "PUT",
      eventPayload({
        id: failureEventId,
        invitees: failureInvitees,
        deadline: failureDeadline,
        title: "Privacy-preserving failure",
        minimumParticipants: 10,
      }),
      host.accessToken,
    ),
  );
  assert.equal(failureResponse.status, 200);
  const failureEvent = (await failureResponse.json()).event;
  const failureBatch = await expectedBatch(
    database,
    failureEventId,
    failureEvent.privateResponsePolicy.policyHash,
    failureInvitees.map(({ id }) => id),
  );
  assert.ok(failureBatch.slots.every(({ envelopeHash }) => envelopeHash === null));
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      {
        eventId: failureEventId,
        policy: failureEvent.privateResponsePolicy,
        batchHash: failureBatch.batchHash,
      },
      "not_confirmed",
    ),
    requests,
  );
  await waitPast(failureDeadline);
  const failedRead = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
  assert.equal(failedRead.status, 200);
  const failed = (await failedRead.json()).events.find((event) => event.id === failureEventId);
  assert.deepEqual(Object.keys(failed.resolution).sort(), ["resolvedAt", "status"]);
  assert.equal(failed.resolution.status, "not_confirmed");
  for (const session of inviteeSessions) {
    const response = await api(miniflare, "/api/events", authorizedRequest(session.accessToken));
    const event = (await response.json()).events.find(
      (candidate) => candidate.id === failureEventId,
    );
    assert.deepEqual(event.resolution, failed.resolution);
  }
  assert.equal(requests.length, 2);
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM resolution_notifications WHERE event_id = ?")
      .bind(failureEventId)
      .first("count"),
    0,
  );
});

test("a signed late-missing proof abandons only an uncertified suffix and unwedges the global log", async (t) => {
  const requests = [];
  const fetchMock = evaluatorMock({
    lateMissingFirstEntry: true,
    tamperFirstLateMissingProof: true,
    validLateMissingProofCount: 2,
  });
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  const deadline = new Date(Date.now() + 900).toISOString();
  const eventId = "82000000-0000-4000-8000-000000000040";
  const created = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    eventId,
    deadline,
  );
  await initializeKey(miniflare, invitee, 40);
  const envelope = encryptedEnvelope({
    event: created.invited,
    inviteeId: created.inviteeId,
    accountKeyEpochId: invitee.accountKeyEpochId,
    revision: 1,
    number: 40,
  });
  const interrupted = await api(
    miniflare,
    `/api/invites/${created.invited.inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope }, invitee.accessToken),
  );
  assert.equal(interrupted.status, 503);
  assert.equal(
    (
      await database
        .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
        .first()
    ).count,
    1,
  );
  const queuedHead = await database
    .prepare(
      `SELECT entry_hash AS entryHash
       FROM response_transparency_entries
       WHERE log_index = 1`,
    )
    .first();
  assert.equal(typeof queuedHead?.entryHash, "string");
  await database
    .prepare(
      `INSERT INTO response_transparency_entries
        (log_index, log_id, previous_entry_hash, entry_hash, envelope_id,
         canonical_receipt_payload, signing_key_id, receipt_signature,
         created_at, signed_at)
       VALUES (2, ?, ?, ?, ?, '{}', ?, NULL, ?, NULL)`,
    )
    .bind(
      protocol.PRIVATE_RESPONSE_LOG_ID,
      queuedHead.entryHash,
      encodedBytes(32, 88),
      "81000000-0000-4000-8000-000000009999",
      transparencySigning.keyId,
      new Date().toISOString(),
    )
    .run();

  const slots = [{ inviteeId: created.inviteeId, envelopeHash: null }];
  const batchHash = sha256Base64Url(
    JSON.stringify({
      protocolVersion: 1,
      eventId,
      policyHash: created.event.privateResponsePolicy.policyHash,
      revealAttendance: true,
      slots,
    }),
  );
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      {
        eventId,
        policy: created.event.privateResponsePolicy,
        batchHash,
      },
      "not_confirmed",
    ),
    requests,
  );
  await waitPast(deadline);

  const rejectedProofRead = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(rejectedProofRead.status, 200);
  const stillPending = (await rejectedProofRead.json()).events.find(
    (event) => event.id === eventId,
  );
  assert.deepEqual(stillPending.resolution, { status: "pending", retrying: true });
  assert.equal(requests.length, 0);
  assert.equal(
    (
      await database
        .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
        .first()
    ).count,
    2,
  );

  await database
    .prepare(
      `UPDATE response_transparency_entries
       SET receipt_signature = ?
       WHERE log_index = 2`,
    )
    .bind(encodedBytes(64, 90))
    .run();
  const protectedSuffixRead = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(protectedSuffixRead.status, 200);
  const protectedPending = (await protectedSuffixRead.json()).events.find(
    (event) => event.id === eventId,
  );
  assert.deepEqual(protectedPending.resolution, {
    status: "pending",
    retrying: true,
  });
  assert.equal(requests.length, 0);
  assert.equal(
    (
      await database
        .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
        .first()
    ).count,
    2,
  );
  await database
    .prepare(
      `UPDATE response_transparency_entries
       SET receipt_signature = NULL
       WHERE log_index = 2`,
    )
    .run();

  const recoveredRead = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(recoveredRead.status, 200);
  const recovered = (await recoveredRead.json()).events.find(
    (event) => event.id === eventId,
  );
  assert.equal(recovered.resolution.status, "not_confirmed");
  assert.equal(requests.length, 1);
  assert.equal(
    (
      await database
        .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
        .first()
    ).count,
    0,
  );
  assert.equal(
    (
      await database
        .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
        .bind(eventId)
        .first()
    ).count,
    1,
  );

  const successorId = "82000000-0000-4000-8000-000000000041";
  const successor = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    successorId,
    new Date(Date.now() + 5_000).toISOString(),
  );
  const successorEnvelope = encryptedEnvelope({
    event: successor.invited,
    inviteeId: successor.inviteeId,
    accountKeyEpochId: invitee.accountKeyEpochId,
    revision: 1,
    number: 41,
  });
  const successorResponse = await api(
    miniflare,
    `/api/invites/${successor.invited.inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: successorEnvelope }, invitee.accessToken),
  );
  assert.equal(successorResponse.status, 200);
  const resumed = await database
    .prepare(
      `SELECT log_index AS logIndex, envelope_id AS envelopeId
       FROM response_transparency_entries`,
    )
    .first();
  assert.deepEqual(resumed, {
    logIndex: 1,
    envelopeId: successorEnvelope.envelopeId,
  });
});

test("post-deadline reads are idempotent under concurrency and persist exactly one result", async (t) => {
  const requests = [];
  const fetchMock = evaluatorMock();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  const deadline = new Date(Date.now() + 160).toISOString();
  const eventId = "82000000-0000-4000-8000-000000000010";
  const created = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    eventId,
    deadline,
  );
  const batch = await expectedBatch(
    database,
    eventId,
    created.event.privateResponsePolicy.policyHash,
    [created.inviteeId],
  );
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      {
        eventId,
        policy: created.event.privateResponsePolicy,
        batchHash: batch.batchHash,
      },
      "confirmed",
      ["host", created.inviteeId],
    ),
    requests,
    { persist: true, delayMilliseconds: 300 },
  );
  await waitPast(deadline);

  const evaluatorOwner = api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  await waitUntil(
    () => requests.length === 1,
    "The evaluator owner did not reach the external service.",
  );
  const leased = await database
    .prepare(
      `SELECT status, evaluation_lease_id AS leaseId,
              evaluation_lease_expires_at AS leaseExpiresAt
       FROM event_resolutions WHERE event_id = ?`,
    )
    .bind(eventId)
    .first();
  assert.equal(leased.status, "evaluating");
  assert.match(leased.leaseId, /^[0-9a-f-]{36}$/u);
  assert.ok(Date.parse(leased.leaseExpiresAt) > Date.now());

  const followers = await Promise.all(
    Array.from({ length: 4 }, () =>
      api(miniflare, "/api/events", authorizedRequest(host.accessToken)),
    ),
  );
  assert.ok(followers.every(({ status }) => status === 200));
  for (const follower of followers) {
    assert.deepEqual((await follower.json()).events[0].resolution, {
      status: "pending",
    });
  }

  const ownerResponse = await evaluatorOwner;
  assert.equal(ownerResponse.status, 200);
  const ownerResolution = (await ownerResponse.json()).events[0].resolution;
  assert.equal(ownerResolution.status, "confirmed");
  assert.equal(requests.length, 1);

  const repeat = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
  assert.equal(repeat.status, 200);
  assert.equal(requests.length, 1);
  assert.deepEqual((await repeat.clone().json()).events[0].resolution, ownerResolution);
  const rows = await database
    .prepare(
      `SELECT COUNT(*) AS count, status,
              evaluation_lease_id AS leaseId,
              evaluation_lease_expires_at AS leaseExpiresAt
       FROM event_resolutions WHERE event_id = ?`,
    )
    .bind(eventId)
    .first();
  assert.equal(rows.count, 1);
  assert.equal(rows.status, "confirmed");
  assert.equal(rows.leaseId, null);
  assert.equal(rows.leaseExpiresAt, null);
});

test("an active evaluation lease stays private and an expired lease is taken over", async (t) => {
  const requests = [];
  const fetchMock = evaluatorMock();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  const deadline = new Date(Date.now() + 140).toISOString();
  const eventId = "82000000-0000-4000-8000-000000000011";
  const created = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    eventId,
    deadline,
  );
  const batch = await expectedBatch(
    database,
    eventId,
    created.event.privateResponsePolicy.policyHash,
    [created.inviteeId],
  );
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      {
        eventId,
        policy: created.event.privateResponsePolicy,
        batchHash: batch.batchHash,
      },
      "confirmed",
      ["host", created.inviteeId],
    ),
    requests,
  );
  await waitPast(deadline);

  const activeExpiry = new Date(Date.now() + 60_000).toISOString();
  await database
    .prepare(
      `UPDATE event_resolutions
       SET status = 'evaluating', evaluation_lease_id = ?,
           evaluation_lease_expires_at = ?, updated_at = ?
       WHERE event_id = ?`,
    )
    .bind("active-test-lease", activeExpiry, new Date().toISOString(), eventId)
    .run();
  const activeRead = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(activeRead.status, 200);
  assert.deepEqual((await activeRead.json()).events[0].resolution, {
    status: "pending",
  });
  assert.equal(requests.length, 0);

  await database
    .prepare(
      `UPDATE event_resolutions
       SET evaluation_lease_expires_at = ?
       WHERE event_id = ? AND status = 'evaluating'`,
    )
    .bind(new Date(Date.now() - 1_000).toISOString(), eventId)
    .run();
  const takeover = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(takeover.status, 200);
  assert.equal((await takeover.json()).events[0].resolution.status, "confirmed");
  assert.equal(requests.length, 1);
  const resolved = await database
    .prepare(
      `SELECT status, evaluation_lease_id AS leaseId,
              evaluation_lease_expires_at AS leaseExpiresAt
       FROM event_resolutions WHERE event_id = ?`,
    )
    .bind(eventId)
    .first();
  assert.deepEqual(resolved, {
    status: "confirmed",
    leaseId: null,
    leaseExpiresAt: null,
  });
});

test("a late stale evaluator cannot overwrite the replacement lease result", async (t) => {
  const requests = [];
  const fetchMock = evaluatorMock();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  const deadline = new Date(Date.now() + 140).toISOString();
  const eventId = "82000000-0000-4000-8000-000000000012";
  const created = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    eventId,
    deadline,
  );
  const batch = await expectedBatch(
    database,
    eventId,
    created.event.privateResponsePolicy.policyHash,
    [created.inviteeId],
  );
  const evaluatorRequest = {
    eventId,
    policy: created.event.privateResponsePolicy,
    batchHash: batch.batchHash,
  };
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(evaluatorRequest, "not_confirmed"),
    requests,
    { delayMilliseconds: 350 },
  );
  queueEvaluatorResult(
    fetchMock,
    exactEvaluatorResult(
      evaluatorRequest,
      "confirmed",
      ["host", created.inviteeId],
    ),
    requests,
  );
  await waitPast(deadline);

  const staleOwner = api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  await waitUntil(
    () => requests.length === 1,
    "The first evaluator lease did not start.",
  );
  await database
    .prepare(
      `UPDATE event_resolutions
       SET evaluation_lease_expires_at = ?
       WHERE event_id = ? AND status = 'evaluating'`,
    )
    .bind(new Date(Date.now() - 1_000).toISOString(), eventId)
    .run();

  const replacement = await api(
    miniflare,
    "/api/events",
    authorizedRequest(host.accessToken),
  );
  assert.equal(replacement.status, 200);
  const replacementResolution = (await replacement.json()).events[0].resolution;
  assert.equal(replacementResolution.status, "confirmed");
  assert.equal(requests.length, 2);

  const staleResponse = await staleOwner;
  assert.equal(staleResponse.status, 200);
  assert.deepEqual(
    (await staleResponse.json()).events[0].resolution,
    replacementResolution,
  );
  const durable = await database
    .prepare(
      `SELECT status, attending_member_ids AS attendingMemberIds,
              evaluation_lease_id AS leaseId,
              evaluation_lease_expires_at AS leaseExpiresAt
       FROM event_resolutions WHERE event_id = ?`,
    )
    .bind(eventId)
    .first();
  assert.deepEqual(durable, {
    status: "confirmed",
    attendingMemberIds: JSON.stringify(["host", created.inviteeId]),
    leaseId: null,
    leaseExpiresAt: null,
  });
});

test("late replies remain editable and policy freeze races cannot mutate the winner", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  const host = await authenticate(miniflare, testPhone);
  const invitee = await authenticate(miniflare, "1");
  await initializeKey(miniflare, invitee, 1);

  const cutoffDeadline = new Date(Date.now() + 170).toISOString();
  const cutoffId = "82000000-0000-4000-8000-000000000020";
  const cutoff = await createSingleInviteeEvent(
    miniflare,
    host,
    invitee,
    cutoffId,
    cutoffDeadline,
  );
  await waitPast(cutoffDeadline);
  const lateEnvelope = encryptedEnvelope({
    event: cutoff.invited,
    inviteeId: cutoff.inviteeId,
    accountKeyEpochId: invitee.accountKeyEpochId,
    revision: 1,
    number: 1,
  });
  const late = await api(
    miniflare,
    `/api/invites/${cutoff.invited.inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: lateEnvelope }, invitee.accessToken),
  );
  assert.equal(late.status, 200);
  assert.equal((await late.json()).responseEnvelope.envelopeId, lateEnvelope.envelopeId);
  const lateRows = await database
    .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
    .bind(cutoffId)
    .first();
  assert.equal(lateRows.count, 1);

  const raceId = "82000000-0000-4000-8000-000000000021";
  const raceInviteeId = "83000000-0000-4000-8000-000000000021";
  const draft = eventPayload({
    id: raceId,
    deadline: new Date(Date.now() + 20_000).toISOString(),
    invitees: [
      {
        id: raceInviteeId,
        displayName: "Before race",
        phoneNumber: "+14155550101",
      },
    ],
    invitationsSent: false,
  });
  const draftResponse = await api(
    miniflare,
    `/api/events/${raceId}`,
    jsonRequest("PUT", draft, host.accessToken),
  );
  assert.equal(draftResponse.status, 200);
  const candidates = ["Race winner A", "Race winner B"].map((title, index) => ({
    ...draft,
    title,
    invitees: [{ ...draft.invitees[0], displayName: `Candidate ${index + 1}` }],
    invitationsSent: true,
  }));
  const raceResponses = await Promise.all(
    candidates.map((candidate) =>
      api(
        miniflare,
        `/api/events/${raceId}`,
        jsonRequest("PUT", candidate, host.accessToken),
      ),
    ),
  );
  assert.deepEqual(raceResponses.map(({ status }) => status).sort(), [200, 409]);
  const winnerIndex = raceResponses.findIndex(({ status }) => status === 200);
  const stored = await database
    .prepare(
      `SELECT events.title, invitees.display_name AS displayName,
              event_policies.canonical_document AS canonicalDocument
       FROM events
       JOIN invitees ON invitees.event_id = events.id
       JOIN event_policies ON event_policies.event_id = events.id
       WHERE events.id = ?`,
    )
    .bind(raceId)
    .first();
  assert.equal(stored.title, candidates[winnerIndex].title);
  assert.equal(stored.displayName, candidates[winnerIndex].invitees[0].displayName);
  assert.equal(JSON.parse(stored.canonicalDocument).event.title, candidates[winnerIndex].title);
  const durable = await database
    .prepare("SELECT COUNT(*) AS count FROM event_resolutions WHERE event_id = ?")
    .bind(raceId)
    .first();
  assert.equal(durable.count, 1);
});

test("missing evaluator configuration and invalid evaluator results stay pending", async (t) => {
  await t.test("missing secret token fails before any result is persisted", async (st) => {
    const { miniflare, database } = await createHarness({
      omitEvaluatorService: true,
      bindings: { HERD_EVALUATOR_URL: evaluatorUrl },
    });
    st.after(() => miniflare.dispose());
    const host = await authenticate(miniflare, testPhone);
    const invitee = await authenticate(miniflare, "1");
    const deadline = new Date(Date.now() + 120).toISOString();
    const eventId = "82000000-0000-4000-8000-000000000030";
    await createSingleInviteeEvent(miniflare, host, invitee, eventId, deadline);
    await waitPast(deadline);
    const response = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
    assert.equal(response.status, 200);
    const event = (await response.json()).events.find((candidate) => candidate.id === eventId);
    assert.deepEqual(event.resolution, { status: "pending", retrying: true });
    const row = await database
      .prepare(
        `SELECT status, batch_hash AS batchHash,
                evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(row, {
      status: "pending",
      batchHash: null,
      leaseId: null,
      leaseExpiresAt: null,
    });
  });

  await t.test("a short Sites bypass secret is rejected", async (st) => {
    const { miniflare, database } = await createHarness({
      bindings: { HERD_EVALUATOR_SITES_BYPASS_TOKEN: "too-short" },
    });
    st.after(() => miniflare.dispose());
    const host = await authenticate(miniflare, testPhone);
    const invitee = await authenticate(miniflare, "1");
    const deadline = new Date(Date.now() + 120).toISOString();
    const eventId = "82000000-0000-4000-8000-000000000031";
    await createSingleInviteeEvent(miniflare, host, invitee, eventId, deadline);
    await waitPast(deadline);
    const response = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
    assert.equal(response.status, 200);
    const event = (await response.json()).events.find((candidate) => candidate.id === eventId);
    assert.deepEqual(event.resolution, { status: "pending", retrying: true });
    const row = await database
      .prepare(
        `SELECT status, evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(row, {
      status: "pending",
      leaseId: null,
      leaseExpiresAt: null,
    });
  });

  await t.test("a failed evaluator call releases its lease and retries cleanly", async (st) => {
    const requests = [];
    const fetchMock = evaluatorMock();
    const { miniflare, database } = await createHarness({ fetchMock });
    st.after(() => miniflare.dispose());
    const host = await authenticate(miniflare, testPhone);
    const invitee = await authenticate(miniflare, "1");
    const deadline = new Date(Date.now() + 120).toISOString();
    const eventId = "82000000-0000-4000-8000-000000000032";
    const created = await createSingleInviteeEvent(
      miniflare,
      host,
      invitee,
      eventId,
      deadline,
    );
    const batch = await expectedBatch(
      database,
      eventId,
      created.event.privateResponsePolicy.policyHash,
      [created.inviteeId],
    );
    const evaluatorRequest = {
      eventId,
      policy: created.event.privateResponsePolicy,
      batchHash: batch.batchHash,
    };
    queueEvaluatorResult(
      fetchMock,
      {
        statusCode: 503,
        body: { error: { code: "temporarily_unavailable" } },
      },
      requests,
    );
    await waitPast(deadline);
    const telemetry = [];
    const originalConsoleError = console.error;
    console.error = (...fields) => telemetry.push(fields);
    let failedRead;
    try {
      failedRead = await api(
        miniflare,
        "/api/events",
        authorizedRequest(host.accessToken),
      );
    } finally {
      console.error = originalConsoleError;
    }
    assert.equal(failedRead.status, 200);
    const failedProjection = (await failedRead.json()).events[0].resolution;
    assert.deepEqual(failedProjection, { status: "pending", retrying: true });
    assert.equal(JSON.stringify(failedProjection).includes("temporarily_unavailable"), false);
    assert.equal(requests.length, 1);
    assert.equal(
      telemetry.flat().join("\n"),
      "Herd event evaluation failed { code: 'evaluator_http_503' }",
    );
    const released = await database
      .prepare(
        `SELECT status, evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(released, {
      status: "pending",
      leaseId: null,
      leaseExpiresAt: null,
    });

    queueEvaluatorResult(
      fetchMock,
      exactEvaluatorResult(
        evaluatorRequest,
        "confirmed",
        ["host", created.inviteeId],
      ),
      requests,
    );
    const retry = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(retry.status, 200);
    assert.equal((await retry.json()).events[0].resolution.status, "confirmed");
    assert.equal(requests.length, 2);
  });

  for (const scenario of [
    {
      name: "a mismatched batch commitment",
      result(request) {
        return { ...exactEvaluatorResult(request, "not_confirmed"), batchHash: encodedBytes(32, 2) };
      },
    },
    {
      name: "unknown confirmed membership",
      result(request) {
        return exactEvaluatorResult(request, "confirmed", [
          "host",
          "ffffffff-ffff-4fff-8fff-ffffffffffff",
        ]);
      },
    },
    {
      name: "guest-level fields on failure",
      result(request) {
        return {
          ...exactEvaluatorResult(request, "not_confirmed"),
          attendingMemberIds: ["host"],
        };
      },
    },
  ]) {
    await t.test(scenario.name, async (st) => {
      const requests = [];
      const fetchMock = evaluatorMock();
      const { miniflare, database } = await createHarness({ fetchMock });
      st.after(() => miniflare.dispose());
      const host = await authenticate(miniflare, testPhone);
      const invitee = await authenticate(miniflare, "1");
      const suffix = String(requests.length + harnessNumber).padStart(12, "0");
      const eventId = `82000000-0000-4000-8000-${suffix}`;
      const deadline = new Date(Date.now() + 120).toISOString();
      const created = await createSingleInviteeEvent(
        miniflare,
        host,
        invitee,
        eventId,
        deadline,
      );
      const batch = await expectedBatch(
        database,
        eventId,
        created.event.privateResponsePolicy.policyHash,
        [created.inviteeId],
      );
      const evaluatorRequest = {
        eventId,
        policy: created.event.privateResponsePolicy,
        batchHash: batch.batchHash,
      };
      queueEvaluatorResult(fetchMock, scenario.result(evaluatorRequest), requests);
      await waitPast(deadline);
      const response = await api(miniflare, "/api/events", authorizedRequest(host.accessToken));
      assert.equal(response.status, 200);
      const event = (await response.json()).events.find(
        (candidate) => candidate.id === eventId,
      );
      assert.deepEqual(event.resolution, { status: "pending", retrying: true });
      assert.equal(requests.length, 1);
      const row = await database
        .prepare(
          `SELECT status, resolved_at AS resolvedAt,
                  evaluation_lease_id AS leaseId,
                  evaluation_lease_expires_at AS leaseExpiresAt
           FROM event_resolutions WHERE event_id = ?`,
        )
        .bind(eventId)
        .first();
      assert.deepEqual(row, {
        status: "pending",
        resolvedAt: null,
        leaseId: null,
        leaseExpiresAt: null,
      });
    });
  }
});
