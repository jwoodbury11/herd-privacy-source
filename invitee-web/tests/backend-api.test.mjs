import assert from "node:assert/strict";
import {
  createHash,
  createHmac,
  generateKeyPairSync,
  sign,
} from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createFetchMock, Miniflare } from "miniflare";

import { stagingScenario } from "./fixtures/staging-scenarios.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const testPhone = "+14155550187";
const testPepper = "herd-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const qaBypassGeneration = "herd-test-generation-v1";
const evaluatorKeyId = "test-evaluator-v1";
const evaluatorPublicKey = Buffer.from(
  `04${
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  }${"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}`,
  "hex",
).toString("base64url");

function encodedBytes(length, fill = 7) {
  return Buffer.alloc(length, fill).toString("base64url");
}

function pepperedTestHash(purpose, value) {
  return createHmac("sha256", testPepper)
    .update(`${purpose}\0${value}`)
    .digest("base64url");
}

function responseSigningIdentity() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicJwk = publicKey.export({ format: "jwk" });
  return { privateKey, publicKey: publicJwk.x };
}

const defaultResponseSigningIdentity = responseSigningIdentity();
const replacementResponseSigningIdentity = responseSigningIdentity();

function authorizeEnvelope(unsignedEnvelope, identity) {
  const ciphertextHash = createHash("sha256")
    .update(JSON.stringify(unsignedEnvelope))
    .digest("base64url");
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
    identity.privateKey,
  ).toString("base64url");
}

function encryptedEnvelope({
  event,
  inviteeId,
  accountKeyEpochId,
  revision = 1,
  responseSigningIdentity: identity = defaultResponseSigningIdentity,
  responseSignature,
  ...overrides
}) {
  const evaluatorFrame = Buffer.alloc(157, 9);
  evaluatorFrame[0] = 0x04;
  const unsignedEnvelope = {
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    envelopeId: `80000000-0000-4000-8000-${String(revision).padStart(12, "0")}`,
    eventId: event.id,
    inviteeId,
    policyHash: event.privateResponsePolicy.policyHash,
    revision,
    accountKeyEpochId,
    evaluatorKeyId,
    payloadCiphertext: encodedBytes(4_124, revision),
    userKeyWrap: encodedBytes(60, revision + 20),
    evaluatorKeyWrap: evaluatorFrame.toString("base64url"),
    responseSigningPublicKey: identity.publicKey,
    ...overrides,
  };
  return {
    ...unsignedEnvelope,
    responseSignature:
      responseSignature ?? authorizeEnvelope(unsignedEnvelope, identity),
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

async function createHarness(options = {}) {
  await access(path.join(serverRoot, "index.js"));
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const harnessBindings = {
    HERD_AUTH_PEPPER: testPepper,
    HERD_TEST_BYPASS_ENABLED: "true",
    HERD_ALLOW_INSECURE_QA_BYPASS: "true",
    HERD_QA_BYPASS_GENERATION: qaBypassGeneration,
    HERD_TEST_PHONE_E164: testPhone,
    HERD_TEST_HOST_PHONE_E164: "+14155550111",
    HERD_EVALUATOR_KEY_ID: evaluatorKeyId,
    HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
    HERD_EVALUATOR_MEASUREMENT: "test-software-evaluator-sha384",
    HERD_RELEASE_ID: "herd-test-release-v1",
    ...options.bindings,
  };
  const miniflareOptions = {
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: { DB: `herd-backend-${process.pid}-${Date.now()}` },
    ...(options.fetchMock ? { fetchMock: options.fetchMock } : {}),
    bindings: { ...harnessBindings },
  };
  const miniflare = new Miniflare(miniflareOptions);
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
  return {
    miniflare,
    database,
    async updateBindings(overrides) {
      Object.assign(harnessBindings, overrides);
      await miniflare.setOptions({
        ...miniflareOptions,
        bindings: { ...harnessBindings },
      });
    },
  };
}

test("QA authentication fails closed without the second safety acknowledgement", async (t) => {
  const { miniflare, database } = await createHarness({
    bindings: { HERD_ALLOW_INSECURE_QA_BYPASS: "false" },
  });
  t.after(() => miniflare.dispose());

  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(response.status, 500);
  const body = await response.json();
  assert.equal(body.error?.code, "server_misconfigured");
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    0,
  );
});

test("authentication accepts only canonical pending invitation tokens", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1", inviteToken: "bad/token" }),
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error?.code, "invalid_invite_token");
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    0,
  );
});

test("invitation authentication sends no code or session unless token and phone are bound", async (t) => {
  const apiKeySid = `SK${"4".repeat(32)}`;
  const verifyServiceSid = `VA${"5".repeat(32)}`;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const { miniflare, database } = await createHarness({
    fetchMock,
    bindings: {
      TWILIO_API_KEY_SID: apiKeySid,
      TWILIO_API_KEY_SECRET: "twilio-unused-for-mismatch",
      TWILIO_VERIFY_SERVICE_SID: verifyServiceSid,
    },
  });
  t.after(() => miniflare.dispose());

  // Start from a fresh database: native can carry this link directly into
  // authentication without making an anonymous preview request first.
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM invitees").first("count"),
    0,
  );
  const wrongPhone = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", {
      phoneNumber: "+14155550998",
      inviteToken: "poker-party",
    }),
  );
  assert.equal(wrongPhone.status, 400);
  const wrongPhoneError = (await wrongPhone.json()).error;
  assert.equal(wrongPhoneError.code, "invitation_auth_mismatch");

  const missingToken = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", {
      phoneNumber: testPhone,
      inviteToken: "missing_invite_token",
    }),
  );
  assert.equal(missingToken.status, 400);
  assert.deepEqual((await missingToken.json()).error, wrongPhoneError);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM challenges").first("count"),
    0,
  );
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    0,
  );

  const correctPhone = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", {
      phoneNumber: testPhone,
      inviteToken: "poker-party",
    }),
  );
  assert.equal(correctPhone.status, 200);
  assert.equal((await correctPhone.json()).user.phoneNumber, testPhone);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    1,
  );
});

test("a matching non-QA invitation starts exactly one Twilio challenge", async (t) => {
  const apiKeySid = `SK${"6".repeat(32)}`;
  const verifyServiceSid = `VA${"7".repeat(32)}`;
  const providerSid = `VE${"8".repeat(32)}`;
  const realPhone = "+14155550995";
  const wrongPhone = "+14155550996";
  const inviteToken = "Real_invite-token-123";
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://verify.twilio.com")
    .intercept({
      method: "POST",
      path: `/v2/Services/${verifyServiceSid}/Verifications`,
    })
    .reply(201, { sid: providerSid, status: "pending" });
  const { miniflare, database } = await createHarness({
    fetchMock,
    bindings: {
      TWILIO_API_KEY_SID: apiKeySid,
      TWILIO_API_KEY_SECRET: "twilio-invitation-binding-secret",
      TWILIO_VERIFY_SERVICE_SID: verifyServiceSid,
    },
  });
  t.after(() => miniflare.dispose());

  const nowIso = new Date().toISOString();
  await database.batch([
    database
      .prepare(
        `INSERT INTO users
          (id, phone_number, phone_hash, name, address, created_at, updated_at)
         VALUES (?, ?, ?, '', '', ?, ?)`,
      )
      .bind(
        "invite-auth-host",
        "+14155550994",
        pepperedTestHash("phone", "+14155550994"),
        nowIso,
        nowIso,
      ),
    database
      .prepare(
        `INSERT INTO events
          (id, host_user_id, title, event_date, end_date, host_name,
           location_name, location_address, minimum_participants,
           rsvp_deadline, event_description, invitations_sent, created_at, updated_at)
         VALUES (?, ?, 'Bound auth', NULL, NULL, 'Host', '', '', 2,
                 NULL, '', 1, ?, ?)`,
      )
      .bind(
        "76000000-0000-4000-8000-000000000001",
        "invite-auth-host",
        nowIso,
        nowIso,
      ),
    database
      .prepare(
        `INSERT INTO invitees
          (id, event_id, user_id, display_name, phone_number, phone_hash,
           token_hash, created_at, updated_at)
         VALUES (?, ?, NULL, 'Real invitee', ?, ?, ?, ?, ?)`,
      )
      .bind(
        "76100000-0000-4000-8000-000000000001",
        "76000000-0000-4000-8000-000000000001",
        realPhone,
        pepperedTestHash("phone", realPhone),
        pepperedTestHash("invite-token", inviteToken),
        nowIso,
        nowIso,
      ),
  ]);

  const mismatch = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: wrongPhone, inviteToken }),
  );
  assert.equal(mismatch.status, 400);
  const mismatchError = (await mismatch.json()).error;
  assert.equal(mismatchError.code, "invitation_auth_mismatch");
  const missing = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", {
      phoneNumber: realPhone,
      inviteToken: "Missing_invite-token-456",
    }),
  );
  assert.equal(missing.status, 400);
  assert.deepEqual((await missing.json()).error, mismatchError);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM challenges").first("count"),
    0,
  );

  const accepted = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: realPhone, inviteToken }),
  );
  assert.equal(accepted.status, 201);
  const challenge = await accepted.json();
  assert.equal(challenge.phoneNumber, realPhone);
  assert.equal(challenge.delivery, "sms");
  const stored = await database
    .prepare(
      `SELECT provider_sid AS providerSid, status
       FROM challenges`,
    )
    .all();
  assert.deepEqual(stored.results, [{ providerSid, status: "pending" }]);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    0,
  );
});

test("QA authentication requires a unique bypass generation", async (t) => {
  const { miniflare, database } = await createHarness({
    bindings: { HERD_QA_BYPASS_GENERATION: "" },
  });
  t.after(() => miniflare.dispose());

  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(response.status, 500);
  assert.equal((await response.json()).error?.code, "server_misconfigured");
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    0,
  );
});

test("a QA generation mismatch permanently revokes the observed session", async (t) => {
  const { miniflare, database, updateBindings } = await createHarness();
  t.after(() => miniflare.dispose());

  const sessionResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  const storedBeforeRotation = await database
    .prepare(
      `SELECT qa_bypass_generation AS qaBypassGeneration,
              revoked_at AS revokedAt
       FROM sessions
       WHERE id = (SELECT id FROM sessions LIMIT 1)`,
    )
    .first();
  assert.equal(storedBeforeRotation.qaBypassGeneration, qaBypassGeneration);
  assert.equal(storedBeforeRotation.revokedAt, null);

  await updateBindings({
    HERD_QA_BYPASS_GENERATION: "herd-test-generation-v2",
  });
  const rotatedResponse = await api(miniflare, "/api/me", {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  assert.equal(rotatedResponse.status, 401);
  assert.equal((await rotatedResponse.json()).error?.code, "invalid_session");

  let currentDatabase = await miniflare.getD1Database("DB");
  const revoked = await currentDatabase
    .prepare(
      `SELECT revoked_at AS revokedAt
       FROM sessions
       WHERE qa_bypass_generation = ?`,
    )
    .bind(qaBypassGeneration)
    .first();
  assert.ok(revoked?.revokedAt);

  await updateBindings({ HERD_QA_BYPASS_GENERATION: qaBypassGeneration });
  const switchedBackResponse = await api(miniflare, "/api/me", {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  assert.equal(switchedBackResponse.status, 401);
  assert.equal((await switchedBackResponse.json()).error?.code, "invalid_session");

  currentDatabase = await miniflare.getD1Database("DB");
  assert.equal(
    await currentDatabase
      .prepare("SELECT COUNT(*) AS count FROM sessions WHERE revoked_at IS NOT NULL")
      .first("count"),
    1,
  );
});

test("real phone numbers use Twilio Verify before a session is created", async (t) => {
  const apiKeySid = `SK${"1".repeat(32)}`;
  const verifyServiceSid = `VA${"2".repeat(32)}`;
  const realPhone = "+14155550999";
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const twilio = fetchMock.get("https://verify.twilio.com");
  twilio
    .intercept({
      method: "POST",
      path: `/v2/Services/${verifyServiceSid}/Verifications`,
    })
    .reply(201, { sid: `VE${"3".repeat(32)}`, status: "pending" });
  twilio
    .intercept({
      method: "POST",
      path: `/v2/Services/${verifyServiceSid}/VerificationCheck`,
    })
    .reply(200, { sid: `VE${"3".repeat(32)}`, status: "approved", valid: true });

  const { miniflare, database } = await createHarness({
    fetchMock,
    bindings: {
      TWILIO_API_KEY_SID: apiKeySid,
      TWILIO_API_KEY_SECRET: "twilio-api-key-secret",
      TWILIO_VERIFY_SERVICE_SID: verifyServiceSid,
    },
  });
  t.after(() => miniflare.dispose());

  const requestResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: realPhone }),
  );
  assert.equal(requestResponse.status, 201);
  const challenge = await requestResponse.json();
  assert.equal(challenge.phoneNumber, realPhone);
  assert.equal(challenge.delivery, "sms");
  assert.equal(Object.hasOwn(challenge, "testCode"), false);

  const verifyResponse = await api(
    miniflare,
    "/api/auth/verify-code",
    jsonRequest("POST", {
      challengeId: challenge.challengeId,
      code: "1234",
    }),
  );
  assert.equal(verifyResponse.status, 200);
  const session = await verifyResponse.json();
  assert.equal(session.user.phoneNumber, realPhone);
  assert.ok(session.accessToken.length >= 40);
  assert.match(verifyResponse.headers.get("set-cookie") ?? "", /herd_session=/);

  const authSession = await database
    .prepare("SELECT auth_mode AS authMode FROM sessions LIMIT 1")
    .first();
  assert.equal(authSession.authMode, "twilio");
  const storedChallenge = await database
    .prepare("SELECT status, code_hash AS codeHash FROM challenges WHERE id = ?")
    .bind(challenge.challengeId)
    .first();
  assert.equal(storedChallenge.status, "verified");
  assert.equal(storedChallenge.codeHash, null);
});

test("a host event appears for every invited QA account after invitations are sent", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const accountIds = new Set();
  const sessions = new Map();
  const sessionRecords = new Map();
  for (const digit of ["1", "2", "3", "4", "5", "6", "7", "8", "9"]) {
    const response = await api(
      miniflare,
      "/api/auth/request-code",
      jsonRequest("POST", { phoneNumber: digit }),
    );
    assert.equal(response.status, 200);
    const session = await response.json();
    assert.equal(session.user.phoneNumber, `+1415555010${digit}`);
    assert.equal(session.user.name, "");
    assert.equal(session.user.address, "");
    accountIds.add(session.user.id);
    sessions.set(digit, session.accessToken);
    sessionRecords.set(digit, session);

    const eventsResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
    assert.equal(eventsResponse.status, 200);
    assert.deepEqual((await eventsResponse.json()).events, []);
  }
  assert.equal(accountIds.size, 9);

  const eventId = "71000000-0000-4000-8000-000000000001";
  const invitees = ["2", "3", "4", "5", "6", "7", "8", "9"].map((digit) => ({
    id: `72000000-0000-4000-8000-${digit.padStart(12, "0")}`,
    displayName: `Test account ${digit}`,
    phoneNumber: `+1415555010${digit}`,
  }));
  const event = {
    id: eventId,
    title: "All-account visibility check",
    eventDate: new Date(Date.now() + 14 * 86_400_000).toISOString(),
    endDate: new Date(Date.now() + 14 * 86_400_000 + 7_200_000).toISOString(),
    hostName: "Test account 1",
    locationName: "Herd QA",
    locationAddress: "San Francisco, CA",
    invitees,
    minimumParticipants: 2,
    requiredGroups: [],
    rsvpDeadline: new Date(Date.now() + 12 * 86_400_000).toISOString(),
    eventDescription: "Verifies host-to-invitee backend synchronization.",
    createdAt: new Date().toISOString(),
    invitationsSent: false,
  };

  const draftResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest("PUT", event, sessions.get("1")),
  );
  assert.equal(draftResponse.status, 200);

  const hostDraftEvents = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("1")}` },
  });
  assert.equal((await hostDraftEvents.json()).events[0].role, "host");
  for (const digit of ["2", "3", "4", "5", "6", "7", "8", "9"]) {
    const hiddenDraftResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${sessions.get(digit)}` },
    });
    assert.deepEqual((await hiddenDraftResponse.json()).events, []);
  }

  const sentResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest(
      "PUT",
      { ...event, invitationsSent: true },
      sessions.get("1"),
    ),
  );
  assert.equal(sentResponse.status, 200);
  assert.equal((await sentResponse.json()).event.privateResponsePolicy.evaluatorKeyId, evaluatorKeyId);

  const invitedEventsByDigit = new Map();
  const envelopesByDigit = new Map();
  for (const digit of ["2", "3", "4", "5", "6", "7", "8", "9"]) {
    const invitedEventsResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${sessions.get(digit)}` },
    });
    assert.equal(invitedEventsResponse.status, 200);
    const invitedEvents = (await invitedEventsResponse.json()).events;
    const invitedEvent = invitedEvents.find((candidate) => candidate.id === eventId);
    assert.equal(invitedEvent.role, "invitee");
    assert.equal(invitedEvent.invitees.filter((invitee) => invitee.isCurrentUser).length, 1);
    assert.ok(invitedEvent.inviteToken);
    invitedEventsByDigit.set(digit, invitedEvent);
  }

  for (const digit of ["2", "3", "4", "5", "6", "7", "8", "9"]) {
    const invitedEvent = invitedEventsByDigit.get(digit);
    const session = sessionRecords.get(digit);
    const initializeResponse = await api(
      miniflare,
      "/api/account/key-epoch/initialize",
      authorizedJsonRequest(
        "POST",
        {
          expectedAccountKeyEpochId: invitedEvent.accountKeyEpochId,
          keyCommitment: encodedBytes(32, Number(digit) + 40),
        },
        session.accessToken,
      ),
    );
    assert.equal(initializeResponse.status, 200);

    const currentInvitee = invitedEvent.invitees.find(
      (invitee) => invitee.isCurrentUser,
    );
    const envelope = encryptedEnvelope({
      event: invitedEvent,
      inviteeId: currentInvitee.id,
      accountKeyEpochId: invitedEvent.accountKeyEpochId,
      envelopeId: `73000000-0000-4000-8000-${digit.padStart(12, "0")}`,
      responseSigningIdentity: responseSigningIdentity(),
    });
    envelopesByDigit.set(digit, envelope);
    const rsvpResponse = await api(
      miniflare,
      `/api/invites/${invitedEvent.inviteToken}/rsvp`,
      authorizedJsonRequest(
        "PUT",
        { envelope },
        session.accessToken,
      ),
    );
    assert.equal(rsvpResponse.status, 200);
    assert.equal((await rsvpResponse.json()).responseEnvelope.revision, 1);

    const refreshedEventsResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
    const refreshedEvent = (await refreshedEventsResponse.json()).events.find(
      (candidate) => candidate.id === eventId,
    );
    assert.equal(refreshedEvent.hasResponse, true);
    assert.equal(refreshedEvent.responseRevision, 1);
  }

  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    8,
  );

  const secondEventId = "71000000-0000-4000-8000-000000000002";
  const secondInviteeId = "72000000-0000-4000-8000-000000000102";
  const secondEvent = {
    ...event,
    id: secondEventId,
    title: "Post-reset unanswered event",
    invitees: [
      {
        id: secondInviteeId,
        displayName: "Test account 2",
        phoneNumber: "+14155550102",
      },
    ],
    invitationsSent: true,
  };
  const secondEventResponse = await api(
    miniflare,
    `/api/events/${secondEventId}`,
    authorizedJsonRequest("PUT", secondEvent, sessions.get("1")),
  );
  assert.equal(secondEventResponse.status, 200);

  const accountTwoSession = sessionRecords.get("2");
  const accountTwoFirstEvent = invitedEventsByDigit.get("2");
  const resetResponse = await api(
    miniflare,
    "/api/account/key-epoch/reset",
    authorizedJsonRequest(
      "POST",
      { expectedAccountKeyEpochId: accountTwoFirstEvent.accountKeyEpochId },
      accountTwoSession.accessToken,
    ),
  );
  assert.equal(resetResponse.status, 200);
  const reset = await resetResponse.json();
  assert.notEqual(reset.accountKeyEpochId, accountTwoFirstEvent.accountKeyEpochId);

  const exactRetryAfterReset = await api(
    miniflare,
    `/api/invites/${accountTwoFirstEvent.inviteToken}/rsvp`,
    authorizedJsonRequest(
      "PUT",
      { envelope: envelopesByDigit.get("2") },
      accountTwoSession.accessToken,
    ),
  );
  assert.equal(exactRetryAfterReset.status, 200);
  assert.equal((await exactRetryAfterReset.json()).responseEnvelope.revision, 1);

  const initializeReplacement = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    authorizedJsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: reset.accountKeyEpochId,
        keyCommitment: encodedBytes(32, 92),
      },
      accountTwoSession.accessToken,
    ),
  );
  assert.equal(initializeReplacement.status, 200);

  const replacedAnsweredEnvelope = encryptedEnvelope({
    event: accountTwoFirstEvent,
    inviteeId: accountTwoFirstEvent.invitees.find(
      (invitee) => invitee.isCurrentUser,
    ).id,
    accountKeyEpochId: reset.accountKeyEpochId,
    revision: 2,
    envelopeId: "73000000-0000-4000-8000-000000000102",
    responseSigningIdentity: replacementResponseSigningIdentity,
  });
  const replaceAnsweredResponse = await api(
    miniflare,
    `/api/invites/${accountTwoFirstEvent.inviteToken}/rsvp`,
    authorizedJsonRequest(
      "PUT",
      { envelope: replacedAnsweredEnvelope },
      accountTwoSession.accessToken,
    ),
  );
  assert.equal(replaceAnsweredResponse.status, 409);
  assert.equal(
    (await replaceAnsweredResponse.json()).error.code,
    "response_authorization_locked",
  );

  const accountTwoEventsResponse = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${accountTwoSession.accessToken}` },
  });
  const accountTwoSecondEvent = (await accountTwoEventsResponse.json()).events.find(
    (candidate) => candidate.id === secondEventId,
  );
  assert.equal(accountTwoSecondEvent.hasResponse, false);
  assert.equal(accountTwoSecondEvent.accountKeyEpochId, reset.accountKeyEpochId);
  const newEventEnvelope = encryptedEnvelope({
    event: accountTwoSecondEvent,
    inviteeId: secondInviteeId,
    accountKeyEpochId: reset.accountKeyEpochId,
    envelopeId: "73000000-0000-4000-8000-000000000202",
    responseSigningIdentity: replacementResponseSigningIdentity,
  });
  const newEventResponse = await api(
    miniflare,
    `/api/invites/${accountTwoSecondEvent.inviteToken}/rsvp`,
    authorizedJsonRequest(
      "PUT",
      { envelope: newEventEnvelope },
      accountTwoSession.accessToken,
    ),
  );
  assert.equal(newEventResponse.status, 200);
  assert.equal((await newEventResponse.json()).responseEnvelope.revision, 1);

  const accounts = await database
    .prepare(
      `SELECT phone_number AS phoneNumber, name, address
       FROM users
       WHERE phone_number LIKE '+1415555010_'
       ORDER BY phone_number`,
    )
    .all();
  assert.equal(accounts.results.length, 9);
  assert.ok(accounts.results.every((account) => account.name === "" && account.address === ""));

  const challenges = await database
    .prepare("SELECT COUNT(*) AS count FROM challenges")
    .first();
  assert.equal(challenges.count, 0);

  const zeroResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "0" }),
  );
  assert.equal(zeroResponse.status, 400);
});

test("event PUT rejects the authenticated host's normalized phone number", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  const sessionResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();
  assert.equal(session.user.phoneNumber, "+14155550101");

  const eventId = "74000000-0000-4000-8000-000000000001";
  const response = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest(
      "PUT",
      {
        id: eventId,
        title: "Self-invite rejection",
        eventDate: null,
        endDate: null,
        hostName: "Test account 1",
        locationName: "",
        locationAddress: "",
        invitees: [
          {
            id: "74100000-0000-4000-8000-000000000001",
            displayName: "Host entered as guest",
            phoneNumber: "(415) 555-0101",
          },
        ],
        minimumParticipants: 2,
        requiredGroups: [],
        rsvpDeadline: null,
        eventDescription: "",
        createdAt: new Date().toISOString(),
        invitationsSent: false,
      },
      session.accessToken,
    ),
  );
  assert.equal(response.status, 400);
  assert.equal((await response.json()).error.code, "host_cannot_be_invited");
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM events WHERE id = ?")
      .bind(eventId)
      .first("count"),
    0,
  );
});

test("legacy self-invites project as host-only and reject RSVP writes", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  const sessionResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(sessionResponse.status, 200);
  const session = await sessionResponse.json();

  const eventId = "75000000-0000-4000-8000-000000000001";
  const inviteeId = "75100000-0000-4000-8000-000000000001";
  const event = {
    id: eventId,
    title: "Legacy self-invite",
    eventDate: null,
    endDate: null,
    hostName: "Test account 1",
    locationName: "",
    locationAddress: "",
    invitees: [],
    minimumParticipants: 2,
    requiredGroups: [],
    rsvpDeadline: null,
    eventDescription: "",
    createdAt: new Date().toISOString(),
    invitationsSent: false,
  };
  const createResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest("PUT", event, session.accessToken),
  );
  assert.equal(createResponse.status, 200);

  const user = await database
    .prepare("SELECT phone_hash AS phoneHash FROM users WHERE id = ?")
    .bind(session.user.id)
    .first();
  assert.ok(user?.phoneHash);
  const rawToken = "legacy-self-invite-token";
  const nowIso = new Date().toISOString();
  await database
    .prepare(
      `INSERT INTO invitees
        (id, event_id, user_id, display_name, phone_number, phone_hash, token_hash,
         created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      inviteeId,
      eventId,
      session.user.id,
      "Legacy host invitee row",
      session.user.phoneNumber,
      user.phoneHash,
      pepperedTestHash("invite-token", rawToken),
      nowIso,
      nowIso,
    )
    .run();

  const inviteResponse = await api(miniflare, `/api/invites/${rawToken}`, {
    headers: { authorization: `Bearer ${session.accessToken}` },
  });
  assert.equal(inviteResponse.status, 200);
  const projection = await inviteResponse.json();
  assert.equal(projection.event.role, "host");
  assert.equal(Object.hasOwn(projection.event, "inviteToken"), false);
  assert.equal(Object.hasOwn(projection.event.invitees[0], "isCurrentUser"), false);
  assert.equal(projection.inviteMetadata.authenticated, true);
  assert.equal(projection.inviteMetadata.canRespond, false);
  assert.equal(projection.inviteMetadata.requiresAuthentication, false);
  for (const field of [
    "accountKeyEpochId",
    "accountKeyCommitment",
    "hasResponse",
    "responseRevision",
    "responseEnvelope",
  ]) {
    assert.equal(Object.hasOwn(projection.event, field), false);
    assert.equal(Object.hasOwn(projection.inviteMetadata, field), false);
  }

  const envelope = encryptedEnvelope({
    event: {
      id: eventId,
      privateResponsePolicy: { policyHash: encodedBytes(32, 29) },
    },
    inviteeId,
    accountKeyEpochId: session.accountKeyEpochId,
  });
  const rsvpResponse = await api(
    miniflare,
    `/api/invites/${rawToken}/rsvp`,
    authorizedJsonRequest("PUT", { envelope }, session.accessToken),
  );
  assert.equal(rsvpResponse.status, 403);
  assert.equal((await rsvpResponse.json()).error.code, "host_cannot_respond");
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE invitee_id = ?")
      .bind(inviteeId)
      .first("count"),
    0,
  );
});

test("event date fields accept optional values and enforce their ordering", async (t) => {
  const { miniflare } = await createHarness();
  t.after(() => miniflare.dispose());

  const sessionResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(sessionResponse.status, 200);
  const { accessToken } = await sessionResponse.json();

  const eventDate = "2026-08-20T19:00:00.000Z";
  const endDate = "2026-08-20T21:00:00.000Z";
  const rsvpDeadline = "2026-08-18T19:00:00.000Z";
  const cases = [
    {
      name: "omitted optional dates become null",
      dates: {},
      expectedDates: { eventDate: null, endDate: null, rsvpDeadline: null },
    },
    {
      name: "explicit null optional dates remain null",
      dates: { eventDate: null, endDate: null, rsvpDeadline: null },
      expectedDates: { eventDate: null, endDate: null, rsvpDeadline: null },
    },
    {
      name: "valid dates preserve an end after the start and a deadline before it",
      dates: { eventDate, endDate, rsvpDeadline },
      expectedDates: { eventDate, endDate, rsvpDeadline },
    },
    {
      name: "a malformed event date is rejected",
      dates: { eventDate: "not-an-iso-timestamp" },
      errorField: "event.eventDate",
    },
    {
      name: "a malformed end date is rejected",
      dates: { endDate: 42 },
      errorField: "event.endDate",
    },
    {
      name: "a malformed RSVP deadline is rejected",
      dates: { rsvpDeadline: {} },
      errorField: "event.rsvpDeadline",
    },
    {
      name: "an end equal to the start is rejected",
      dates: { eventDate, endDate: eventDate },
      expectedMessage: "event.endDate must be after event.eventDate.",
    },
    {
      name: "an end before the start is rejected",
      dates: { eventDate, endDate: rsvpDeadline },
      expectedMessage: "event.endDate must be after event.eventDate.",
    },
    {
      name: "a deadline equal to the start is rejected",
      dates: { eventDate, rsvpDeadline: eventDate },
      expectedMessage: "event.rsvpDeadline must be before event.eventDate.",
    },
  ];

  for (const [index, scenario] of cases.entries()) {
    await t.test(scenario.name, async () => {
      const id = `73000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`;
      const response = await api(
        miniflare,
        `/api/events/${id}`,
        authorizedJsonRequest(
          "PUT",
          {
            id,
            title: `Date contract ${index + 1}`,
            hostName: "Test account 1",
            locationName: "",
            locationAddress: "",
            invitees: [],
            minimumParticipants: 2,
            requiredGroups: [],
            eventDescription: "",
            createdAt: "2026-07-31T12:00:00.000Z",
            invitationsSent: false,
            ...scenario.dates,
          },
          accessToken,
        ),
      );

      if (scenario.expectedDates) {
        assert.equal(response.status, 200);
        const event = (await response.json()).event;
        for (const [field, expected] of Object.entries(scenario.expectedDates)) {
          assert.equal(event[field], expected);
        }
        return;
      }

      assert.equal(response.status, 400);
      const error = (await response.json()).error;
      assert.equal(error.code, "invalid_event");
      if (scenario.errorField) assert.match(error.message, new RegExp(scenario.errorField));
      if (scenario.expectedMessage) assert.equal(error.message, scenario.expectedMessage);
    });
  }
});

function api(miniflare, pathname, init = {}) {
  return miniflare.dispatchFetch(`https://herd.test${pathname}`, init);
}

function jsonRequest(method, body, cookie) {
  return {
    method,
    headers: {
      "content-type": "application/json",
      ...(cookie ? { cookie } : {}),
    },
    body: JSON.stringify(body),
  };
}

function authorizedJsonRequest(method, body, accessToken) {
  return {
    method,
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(body),
  };
}

test("account key mutations authenticate before parsing request bodies", async (t) => {
  const { miniflare } = await createHarness();
  t.after(() => miniflare.dispose());

  for (const pathname of [
    "/api/account/key-epoch/initialize",
    "/api/account/key-epoch/reset",
  ]) {
    const response = await api(miniflare, pathname, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "not JSON",
    });
    assert.equal(response.status, 401);
    assert.equal((await response.json()).error?.code, "authentication_required");
  }
});

test("the authentication cutover revokes every legacy session", async () => {
  const migration = await readFile(
    path.join(migrationDirectory, "0002_revoke_legacy_sessions.sql"),
    "utf8",
  );
  assert.match(migration, /UPDATE `sessions`/);
  assert.match(migration, /WHERE `revoked_at` IS NULL/);
});

test("phone auth, shared events, invite projection, and RSVP work through D1", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const nonJsonResponse = await api(miniflare, "/api/auth/request-code", {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: JSON.stringify({ phoneNumber: testPhone }),
  });
  assert.equal(nonJsonResponse.status, 415);
  assert.equal((await nonJsonResponse.json()).error.code, "unsupported_media_type");

  const crossOriginResponse = await api(
    miniflare,
    "/api/auth/request-code",
    {
      ...jsonRequest("POST", { phoneNumber: testPhone }),
      headers: {
        ...jsonRequest("POST", {}).headers,
        origin: "https://attacker.example",
      },
    },
  );
  assert.equal(crossOriginResponse.status, 403);
  assert.equal((await crossOriginResponse.json()).error.code, "cross_origin_request");

  const blockedPhoneResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "+14155550999" }),
  );
  assert.equal(blockedPhoneResponse.status, 503);
  assert.equal((await blockedPhoneResponse.json()).error.code, "sms_unavailable");

  const publicInviteResponse = await api(miniflare, "/api/invites/poker-party");
  assert.equal(publicInviteResponse.status, 200);
  const publicInvite = await publicInviteResponse.json();
  assert.equal(Object.hasOwn(publicInvite, "event"), false);
  assert.equal(publicInvite.invitationPreview.title, "Poker night");
  assert.equal(
    Object.hasOwn(publicInvite.invitationPreview, "locationAddress"),
    false,
  );
  assert.match(
    publicInvite.invitationPreview.eventId,
    /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i,
  );
  assert.ok(Date.parse(publicInvite.invitationPreview.eventDate) > Date.now());

  const requestResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "(415) 555-0187" }),
  );
  assert.equal(requestResponse.status, 200);
  const verified = await requestResponse.json();
  assert.equal(verified.user.phoneNumber, testPhone);
  assert.match(verified.accountKeyEpochId, /^[0-9a-f-]{36}$/i);
  assert.equal(verified.accountKeyCommitment, null);
  assert.ok(verified.accessToken.length >= 40);
  assert.ok(Date.parse(verified.expiresAt) > Date.now());
  const setCookie = requestResponse.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /herd_session=[A-Za-z0-9_-]+/);
  assert.match(setCookie, /HttpOnly/i);
  assert.match(setCookie, /Secure/i);
  assert.match(setCookie, /SameSite=Lax/i);
  const cookie = setCookie.split(";")[0];

  const throttledResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: testPhone }),
  );
  assert.equal(throttledResponse.status, 429);
  assert.equal((await throttledResponse.json()).error.code, "code_request_throttled");

  const sessionMode = await database
    .prepare("SELECT auth_mode AS authMode FROM sessions LIMIT 1")
    .first();
  assert.equal(sessionMode.authMode, "test");
  await database
    .prepare("UPDATE users SET phone_number = '+14155550999' WHERE id = ?")
    .bind(verified.user.id)
    .run();
  const mismatchedModeResponse = await api(miniflare, "/api/me", {
    headers: { cookie },
  });
  assert.equal(mismatchedModeResponse.status, 401);
  await database
    .prepare("UPDATE users SET phone_number = ? WHERE id = ?")
    .bind(testPhone, verified.user.id)
    .run();

  const challengeCount = await database
    .prepare("SELECT COUNT(*) AS count FROM challenges")
    .first();
  assert.equal(challengeCount.count, 0);
  const sessionRecord = await database
    .prepare("SELECT token_hash AS tokenHash FROM sessions LIMIT 1")
    .first();
  assert.notEqual(sessionRecord.tokenHash, verified.accessToken);
  const inviteRecord = await database
    .prepare(
      "SELECT token_hash AS tokenHash FROM invitees WHERE event_id = ? AND display_name = 'Jeff Wilson'",
    )
    .bind(publicInvite.invitationPreview.eventId)
    .first();
  assert.notEqual(inviteRecord.tokenHash, "poker-party");

  const meResponse = await api(miniflare, "/api/me", {
    headers: { authorization: `Bearer ${verified.accessToken}` },
  });
  assert.equal(meResponse.status, 200);
  assert.equal((await meResponse.json()).user.id, verified.user.id);

  const profileResponse = await api(
    miniflare,
    "/api/me",
    jsonRequest(
      "PATCH",
      { name: "Jeff Wilson", address: "219 Cumberland St" },
      cookie,
    ),
  );
  assert.equal(profileResponse.status, 200);
  assert.equal((await profileResponse.json()).user.name, "Jeff Wilson");

  const eventsResponse = await api(miniflare, "/api/events", {
    headers: { cookie },
  });
  assert.equal(eventsResponse.status, 200);
  const initialEvents = (await eventsResponse.json()).events;
  const poker = initialEvents.find(
    (event) => event.id === publicInvite.invitationPreview.eventId,
  );
  assert.equal(poker.role, "invitee");
  assert.equal(poker.inviteToken, "poker-party");
  assert.equal(poker.hasResponse, false);
  assert.equal(Object.hasOwn(poker, "myRsvp"), false);
  assert.ok(
    poker.invitees.every((invitee) => !Object.hasOwn(invitee, "phoneNumber")),
  );
  assert.equal(
    poker.invitees.filter((invitee) => invitee.isCurrentUser).length,
    1,
  );

  const authenticatedInviteResponse = await api(
    miniflare,
    "/api/invites/poker-party",
    { headers: { cookie } },
  );
  assert.equal(authenticatedInviteResponse.status, 200);
  const authenticatedInvite = await authenticatedInviteResponse.json();
  assert.equal(authenticatedInvite.event.id, poker.id);
  assert.equal(
    authenticatedInvite.inviteMetadata.accountKeyEpochId,
    verified.accountKeyEpochId,
  );
  assert.equal(authenticatedInvite.inviteMetadata.accountKeyCommitment, null);
  assert.equal(authenticatedInvite.event.privateResponsePolicy.evaluatorKeyId, evaluatorKeyId);
  assert.ok(
    authenticatedInvite.event.invitees.every(
      (invitee) => !Object.hasOwn(invitee, "phoneNumber"),
    ),
  );

  const legacyRsvpResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest(
      "PUT",
      {
        response: "going",
        minimumParticipants: 4,
        requiredGroups: [],
      },
      cookie,
    ),
  );
  assert.equal(legacyRsvpResponse.status, 400);
  assert.equal(
    (await legacyRsvpResponse.json()).error.code,
    "plaintext_response_rejected",
  );

  const keyCommitment = encodedBytes(32, 31);
  const initializeKeyResponse = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    jsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: verified.accountKeyEpochId,
        keyCommitment,
      },
      cookie,
    ),
  );
  assert.equal(initializeKeyResponse.status, 200);
  assert.equal((await initializeKeyResponse.json()).keyCommitment, keyCommitment);
  const conflictingCommitment = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    jsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: verified.accountKeyEpochId,
        keyCommitment: encodedBytes(32, 30),
      },
      cookie,
    ),
  );
  assert.equal(conflictingCommitment.status, 409);
  assert.equal(
    (await conflictingCommitment.json()).error.code,
    "account_key_commitment_conflict",
  );

  const currentInvitee = poker.invitees.find((invitee) => invitee.isCurrentUser);
  const envelope = encryptedEnvelope({
    event: authenticatedInvite.event,
    inviteeId: currentInvitee.id,
    accountKeyEpochId: verified.accountKeyEpochId,
  });
  const forgedResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest(
      "PUT",
      {
        envelope: {
          ...envelope,
          responseSignature: encodedBytes(64, 1),
        },
      },
      cookie,
    ),
  );
  assert.equal(forgedResponse.status, 400);
  assert.equal(
    (await forgedResponse.json()).error.code,
    "invalid_response_authorization",
  );
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_envelopes")
      .first("count"),
    0,
  );
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
      .first("count"),
    0,
  );
  const rsvpResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest(
      "PUT",
      { envelope },
      cookie,
    ),
  );
  assert.equal(rsvpResponse.status, 200);
  const encryptedResult = await rsvpResponse.json();
  assert.equal(encryptedResult.responseEnvelope.revision, 1);
  assert.equal(encryptedResult.responseEnvelope.payloadCiphertext, envelope.payloadCiphertext);
  assert.equal(encryptedResult.receipt.ciphertextHash.length, 43);

  const secondEnvelope = encryptedEnvelope({
    event: authenticatedInvite.event,
    inviteeId: currentInvitee.id,
    accountKeyEpochId: verified.accountKeyEpochId,
    revision: 2,
  });
  const secondResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest("PUT", { envelope: secondEnvelope }, cookie),
  );
  assert.equal(secondResponse.status, 200);
  assert.equal((await secondResponse.json()).responseEnvelope.revision, 2);

  const changedSignerEnvelope = encryptedEnvelope({
    event: authenticatedInvite.event,
    inviteeId: currentInvitee.id,
    accountKeyEpochId: verified.accountKeyEpochId,
    revision: 3,
    responseSigningIdentity: replacementResponseSigningIdentity,
  });
  const changedSignerResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest("PUT", { envelope: changedSignerEnvelope }, cookie),
  );
  assert.equal(changedSignerResponse.status, 409);
  assert.equal(
    (await changedSignerResponse.json()).error.code,
    "response_authorization_locked",
  );

  const responseColumns = await database
    .prepare("PRAGMA table_info(response_envelopes)")
    .all();
  const responseColumnNames = responseColumns.results.map((column) => column.name);
  for (const forbidden of ["reply", "minimum_participants", "condition_groups", "user_id"]) {
    assert.equal(responseColumnNames.includes(forbidden), false);
  }
  const legacyTable = await database
    .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'rsvps'")
    .first();
  assert.equal(legacyTable, null);

  const eventId = "40000000-0000-4000-8000-000000000001";
  const inviteeId = "50000000-0000-4000-8000-000000000001";
  const groupId = "60000000-0000-4000-8000-000000000001";
  const eventDate = new Date(Date.now() + 10 * 86_400_000).toISOString();
  const endDate = new Date(Date.now() + 10 * 86_400_000 + 7_200_000).toISOString();
  const deadline = new Date(Date.now() + 8 * 86_400_000).toISOString();
  const createEventResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    jsonRequest(
      "PUT",
      {
        id: eventId,
        title: "Backyard dinner",
        eventDate,
        endDate,
        hostName: "Jeff Wilson",
        locationName: "Home",
        locationAddress: "San Francisco, CA",
        invitees: [
          {
            id: inviteeId,
            sourceContactIdentifier: "must-not-cross-api",
            displayName: "Avery Johnson",
            phoneNumber: "+14155550137",
          },
        ],
        minimumParticipants: 2,
        requiredGroups: [{ id: groupId, memberIDs: [inviteeId] }],
        rsvpDeadline: deadline,
        eventDescription: "Dinner outside.",
        createdAt: new Date().toISOString(),
        invitationsSent: true,
      },
      cookie,
    ),
  );
  assert.equal(createEventResponse.status, 200);
  const hostedEvent = (await createEventResponse.json()).event;
  assert.equal(hostedEvent.id, eventId);
  assert.equal(hostedEvent.invitees[0].phoneNumber, "+14155550137");
  assert.equal(
    Object.hasOwn(hostedEvent.invitees[0], "sourceContactIdentifier"),
    false,
  );
  assert.ok(hostedEvent.privateResponsePolicy?.policyHash);
  const minimizedPolicyDocument = JSON.parse(
    hostedEvent.privateResponsePolicy.canonicalDocument,
  );
  assert.deepEqual(minimizedPolicyDocument.members, [{ id: inviteeId }]);
  assert.equal(
    hostedEvent.privateResponsePolicy.canonicalDocument.includes("Avery Johnson"),
    false,
  );
  assert.equal(
    hostedEvent.privateResponsePolicy.canonicalDocument.includes("+14155550137"),
    false,
  );
  assert.equal(
    hostedEvent.privateResponsePolicy.canonicalDocument.includes("phoneAssignment"),
    false,
  );

  const mutateFrozenEventResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    jsonRequest(
      "PUT",
      {
        ...hostedEvent,
        title: "Changed after sending",
      },
      cookie,
    ),
  );
  assert.equal(mutateFrozenEventResponse.status, 409);
  assert.equal(
    (await mutateFrozenEventResponse.json()).error.code,
    "event_policy_frozen",
  );

  for (const participantCount of [5, 10, 20]) {
    const scenario = stagingScenario(participantCount);
    const scenarioResponse = await api(
      miniflare,
      `/api/events/${scenario.event.id}`,
      jsonRequest("PUT", scenario.event, cookie),
    );
    assert.equal(scenarioResponse.status, 200);
    const scenarioEvent = (await scenarioResponse.json()).event;
    assert.equal(scenarioEvent.invitees.length + 1, participantCount);
    const frozenPolicy = JSON.parse(
      scenarioEvent.privateResponsePolicy.canonicalDocument,
    );
    assert.equal(frozenPolicy.limits.maximumParticipants, participantCount);
    assert.equal(
      frozenPolicy.limits.maximumConditionGroups,
      participantCount - 1,
    );
    const scenarioDeleteResponse = await api(
      miniflare,
      `/api/events/${scenario.event.id}`,
      { method: "DELETE", headers: { cookie } },
    );
    assert.equal(scenarioDeleteResponse.status, 200);
  }

  const refreshedEventsResponse = await api(miniflare, "/api/events", {
    headers: { cookie },
  });
  const refreshedEvents = (await refreshedEventsResponse.json()).events;
  assert.equal(
    refreshedEvents.find(
      (event) => event.id === publicInvite.invitationPreview.eventId,
    ).hasResponse,
    true,
  );
  assert.equal(
    refreshedEvents.find((event) => event.id === eventId).role,
    "host",
  );

  const resetResponse = await api(
    miniflare,
    "/api/account/key-epoch/reset",
    jsonRequest(
      "POST",
      { expectedAccountKeyEpochId: verified.accountKeyEpochId },
      cookie,
    ),
  );
  assert.equal(resetResponse.status, 200);
  const reset = await resetResponse.json();
  assert.notEqual(reset.accountKeyEpochId, verified.accountKeyEpochId);

  const reclaimedInviteResponse = await api(
    miniflare,
    "/api/invites/poker-party",
    { headers: { cookie } },
  );
  assert.equal(reclaimedInviteResponse.status, 200);
  const reclaimedInvite = await reclaimedInviteResponse.json();
  assert.equal(
    reclaimedInvite.inviteMetadata.accountKeyEpochId,
    reset.accountKeyEpochId,
  );
  assert.equal(reclaimedInvite.inviteMetadata.accountKeyCommitment, null);
  assert.equal(reclaimedInvite.inviteMetadata.responseEnvelope.revision, 2);

  const retryAfterReset = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest("PUT", { envelope }, cookie),
  );
  assert.equal(retryAfterReset.status, 200);
  assert.deepEqual(await retryAfterReset.json(), encryptedResult);

  const replacementEnvelope = encryptedEnvelope({
    event: reclaimedInvite.event,
    inviteeId: currentInvitee.id,
    accountKeyEpochId: reset.accountKeyEpochId,
    revision: 3,
    responseSigningIdentity: replacementResponseSigningIdentity,
  });
  const uninitializedReplacement = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest("PUT", { envelope: replacementEnvelope }, cookie),
  );
  assert.equal(uninitializedReplacement.status, 409);
  assert.equal(
    (await uninitializedReplacement.json()).error.code,
    "account_key_not_initialized",
  );

  const replacementCommitment = encodedBytes(32, 32);
  const initializeReplacement = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    jsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: reset.accountKeyEpochId,
        keyCommitment: replacementCommitment,
      },
      cookie,
    ),
  );
  assert.equal(initializeReplacement.status, 200);
  const replacementResponse = await api(
    miniflare,
    "/api/invites/poker-party/rsvp",
    jsonRequest("PUT", { envelope: replacementEnvelope }, cookie),
  );
  assert.equal(replacementResponse.status, 409);
  assert.equal(
    (await replacementResponse.json()).error.code,
    "response_authorization_locked",
  );
  const durableRevisionCount = await database
    .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE invitee_id = ?")
    .bind(currentInvitee.id)
    .first();
  assert.equal(durableRevisionCount.count, 2);

  const deleteEventResponse = await api(miniflare, `/api/events/${eventId}`, {
    method: "DELETE",
    headers: { cookie },
  });
  assert.equal(deleteEventResponse.status, 200);

  const nowIso = new Date().toISOString();
  await database
    .prepare(
      `UPDATE auth_phone_rate_limits
       SET request_count = 0,
           last_requested_at = '2000-01-01T00:00:00.000Z',
           window_started_at = ?`,
    )
    .bind(nowIso)
    .run();
  await database
    .prepare(
      `UPDATE auth_ip_rate_limits
       SET request_count = 30, window_started_at = ?, last_requested_at = ?`,
    )
    .bind(nowIso, nowIso)
    .run();
  const ipThrottledResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: testPhone }),
  );
  assert.equal(ipThrottledResponse.status, 429);
  assert.equal(
    (await ipThrottledResponse.json()).error.code,
    "ip_request_throttled",
  );

  const logoutResponse = await api(miniflare, "/api/auth/session", {
    method: "DELETE",
    headers: { cookie },
  });
  assert.equal(logoutResponse.status, 200);
  assert.match(logoutResponse.headers.get("set-cookie") ?? "", /Max-Age=0/i);
  const expiredSessionResponse = await api(miniflare, "/api/me", {
    headers: { cookie },
  });
  assert.equal(expiredSessionResponse.status, 401);
});
