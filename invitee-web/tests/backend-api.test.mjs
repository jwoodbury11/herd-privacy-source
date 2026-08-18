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

import { testAccountNameForAlias } from "../lib/backend/test-accounts.mjs";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const testPepper = "herd-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const testAccessGeneration = "herd-test-generation-v1";
const messagingAccountSid = `AC${"1".repeat(32)}`;
const messagingApiKeySid = `SK${"2".repeat(32)}`;
const messagingServiceSid = `MG${"3".repeat(32)}`;
const verifyServiceSid = `VA${"4".repeat(32)}`;
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
  const fetchMock = options.fetchMock ?? createFetchMock();
  if (!options.fetchMock) {
    fetchMock.disableNetConnect();
    fetchMock
      .get("https://api.twilio.com")
      .intercept({
        method: "POST",
        path: `/2010-04-01/Accounts/${messagingAccountSid}/Messages.json`,
      })
      .reply(201, () => ({ sid: `SM${"9".repeat(32)}`, status: "accepted" }))
      .persist();
  }
  const defaultDeliveryBindings = options.fetchMock
    ? {}
    : {
        HERD_PUBLIC_APP_URL: "https://app.herdprivacy.com",
        TWILIO_ACCOUNT_SID: messagingAccountSid,
        TWILIO_API_KEY_SID: messagingApiKeySid,
        TWILIO_API_KEY_SECRET: "test-messaging-secret",
        TWILIO_VERIFY_SERVICE_SID: verifyServiceSid,
        TWILIO_MESSAGING_SERVICE_SID: messagingServiceSid,
      };
  const harnessBindings = {
    HERD_DEPLOYMENT_PROFILE: "test",
    HERD_AUTH_PEPPER: testPepper,
    HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
    HERD_TEST_ACCOUNT_ACCESS_GENERATION: testAccessGeneration,
    HERD_TEST_HOST_PHONE_E164: "+14155550111",
    HERD_EVALUATOR_KEY_ID: evaluatorKeyId,
    HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
    HERD_EVALUATOR_MEASUREMENT: "test-software-evaluator-sha384",
    HERD_RELEASE_ID: "herd-test-release-v1",
    HERD_ARTIFACT_RELEASE_ID: "2026.08.12.1",
    ...defaultDeliveryBindings,
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
    fetchMock,
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

test("a full test-account phone number still starts a real Twilio challenge", async (t) => {
  const apiKeySid = `SK${"6".repeat(32)}`;
  const verifyServiceSid = `VA${"7".repeat(32)}`;
  const providerSid = `VE${"8".repeat(32)}`;
  const realPhone = "+14155550101";
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

test("an authenticated test account can reverify its own canonical number", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const initialResponse = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }),
  );
  assert.equal(initialResponse.status, 200);
  const initialSession = await initialResponse.json();
  assert.equal(initialSession.user.phoneNumber, "+14155550101");

  const refreshedResponse = await api(
    miniflare,
    "/api/auth/request-code",
    {
      method: "POST",
      headers: {
        authorization: `Bearer ${initialSession.accessToken}`,
        "content-type": "application/json",
      },
      body: JSON.stringify({ phoneNumber: initialSession.user.phoneNumber }),
    },
  );
  assert.equal(refreshedResponse.status, 200);
  const refreshedSession = await refreshedResponse.json();
  assert.equal(refreshedSession.user.id, initialSession.user.id);
  assert.notEqual(refreshedSession.accessToken, initialSession.accessToken);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM challenges").first("count"),
    0,
  );
  assert.equal(
    await database
      .prepare("SELECT request_count AS count FROM auth_phone_rate_limits")
      .first("count"),
    1,
  );
  assert.equal(
    await database
      .prepare("SELECT request_count AS count FROM auth_ip_rate_limits")
      .first("count"),
    1,
  );
});

test("test-account access requires a unique generation", async (t) => {
  const { miniflare, database } = await createHarness({
    bindings: { HERD_TEST_ACCOUNT_ACCESS_GENERATION: "" },
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

test("a test-access generation mismatch permanently revokes the observed session", async (t) => {
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
      `SELECT test_access_generation AS testAccessGeneration,
              revoked_at AS revokedAt
       FROM sessions
       WHERE id = (SELECT id FROM sessions LIMIT 1)`,
    )
    .first();
  assert.equal(storedBeforeRotation.testAccessGeneration, testAccessGeneration);
  assert.equal(storedBeforeRotation.revokedAt, null);

  await updateBindings({
    HERD_TEST_ACCOUNT_ACCESS_GENERATION: "herd-test-generation-v2",
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
       WHERE test_access_generation = ?`,
    )
    .bind(testAccessGeneration)
    .first();
  assert.ok(revoked?.revokedAt);

  await updateBindings({ HERD_TEST_ACCOUNT_ACCESS_GENERATION: testAccessGeneration });
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

test("a host event appears for every invited test account after invitations are sent", async (t) => {
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
    assert.equal(session.user.name, testAccountNameForAlias(digit));
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
    displayName: testAccountNameForAlias(digit),
    phoneNumber: `+1415555010${digit}`,
  }));
  const event = {
    id: eventId,
    title: "All-account visibility check",
    eventDate: new Date(Date.now() + 14 * 86_400_000).toISOString(),
    endDate: new Date(Date.now() + 14 * 86_400_000 + 7_200_000).toISOString(),
    hostName: testAccountNameForAlias("1"),
    locationName: "Herd test",
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
  assert.equal(sentResponse.status, 200, await sentResponse.clone().text());
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
  const replaceAnsweredBody = await replaceAnsweredResponse.json();
  assert.equal(replaceAnsweredResponse.status, 200, JSON.stringify(replaceAnsweredBody));
  assert.equal(
    replaceAnsweredBody.responseEnvelope.revision,
    2,
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
  assert.deepEqual(
    accounts.results.map((account) => account.name),
    ["1", "2", "3", "4", "5", "6", "7", "8", "9"].map(testAccountNameForAlias),
  );
  assert.ok(accounts.results.every((account) => account.address === ""));

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

test("hosts and permitted attendees can add guests before and after private replies begin", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const sessions = new Map();
  for (const digit of ["1", "2", "3", "4"]) {
    const response = await api(
      miniflare,
      "/api/auth/request-code",
      jsonRequest("POST", { phoneNumber: digit }),
    );
    assert.equal(response.status, 200);
    sessions.set(digit, (await response.json()).accessToken);
  }

  const eventId = "74000000-0000-4000-8000-000000000001";
  const futureDate = new Date(Date.now() + 14 * 86_400_000).toISOString();
  const event = {
    id: eventId,
    title: "Shared guest additions",
    eventDate: futureDate,
    endDate: null,
    hostName: testAccountNameForAlias("1"),
    locationName: "",
    locationAddress: "",
    invitees: [{
      id: "74000000-0000-4000-8000-000000000002",
      displayName: testAccountNameForAlias("2"),
      phoneNumber: "+14155550102",
    }],
    minimumParticipants: 2,
    allowsAttendeesToAddGuests: true,
    requiredGroups: [],
    rsvpDeadline: new Date(Date.now() + 12 * 86_400_000).toISOString(),
    eventDescription: "",
    createdAt: new Date().toISOString(),
    invitationsSent: true,
  };
  const createResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest("PUT", event, sessions.get("1")),
  );
  assert.equal(createResponse.status, 200);

  const attendeeAddition = await api(
    miniflare,
    `/api/events/${eventId}/attendees`,
    authorizedJsonRequest("POST", {
      invitees: [{
        id: "74000000-0000-4000-8000-000000000003",
        displayName: testAccountNameForAlias("3"),
        phoneNumber: "+14155550103",
      }],
    }, sessions.get("2")),
  );
  assert.equal(attendeeAddition.status, 200);
  const attendeeEvent = (await attendeeAddition.json()).event;
  assert.equal(attendeeEvent.role, "invitee");
  assert.equal(attendeeEvent.invitees.length, 2);

  const initializeAccountTwo = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    authorizedJsonRequest("POST", {
      expectedAccountKeyEpochId: attendeeEvent.accountKeyEpochId,
      keyCommitment: encodedBytes(32, 72),
    }, sessions.get("2")),
  );
  assert.equal(initializeAccountTwo.status, 200);
  const accountTwoInvitee = attendeeEvent.invitees.find((invitee) => invitee.isCurrentUser);
  assert.ok(accountTwoInvitee);
  const firstPolicyHash = attendeeEvent.privateResponsePolicy.policyHash;
  const firstResponse = await api(
    miniflare,
    `/api/invites/${attendeeEvent.inviteToken}/rsvp`,
    authorizedJsonRequest("PUT", {
      envelope: encryptedEnvelope({
        event: attendeeEvent,
        inviteeId: accountTwoInvitee.id,
        accountKeyEpochId: attendeeEvent.accountKeyEpochId,
        envelopeId: "74000000-0000-4000-8000-000000000102",
      }),
    }, sessions.get("2")),
  );
  assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    1,
  );
  await database
    .prepare(
      `INSERT INTO response_transparency_entries
        (log_id, previous_entry_hash, entry_hash, envelope_id,
         canonical_receipt_payload, signing_key_id, receipt_signature,
         created_at, signed_at)
       VALUES (?, ?, ?, ?, ?, ?, NULL, ?, NULL)`,
    )
    .bind(
      "roster-expansion-test-log",
      "roster-expansion-genesis",
      "roster-expansion-entry",
      "74000000-0000-4000-8000-000000000102",
      "{}",
      "test-signing-key",
      new Date().toISOString(),
    )
    .run();
  // An early resolution is still mutable while the reply window is open.
  // Adding a guest must replace it along with the roster-bound policy.
  await database
    .prepare("UPDATE event_resolutions SET status = 'confirmed' WHERE event_id = ?")
    .bind(eventId)
    .run();

  const postReplyAddition = await api(
    miniflare,
    `/api/events/${eventId}/attendees`,
    authorizedJsonRequest("POST", {
      invitees: [{
        id: "74000000-0000-4000-8000-000000000004",
        displayName: testAccountNameForAlias("4"),
        phoneNumber: "+14155550104",
      }],
    }, sessions.get("1")),
  );
  assert.equal(postReplyAddition.status, 200, await postReplyAddition.clone().text());
  const expandedEvent = (await postReplyAddition.json()).event;
  assert.equal(expandedEvent.invitees.length, 3);
  assert.notEqual(expandedEvent.privateResponsePolicy.policyHash, firstPolicyHash);
  assert.equal(expandedEvent.resolution.status, "pending");
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_envelopes WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    0,
  );
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM response_transparency_entries")
      .first("count"),
    1,
  );
  assert.equal(
    await database
      .prepare(
        `SELECT attempt_count AS attemptCount
         FROM invitation_deliveries
         WHERE event_id = ? AND invitee_id = ?`,
      )
      .bind(eventId, accountTwoInvitee.id)
      .first("attemptCount"),
    2,
  );
  const refreshedAccountTwo = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("2")}` },
  });
  const refreshedAccountTwoEvent = (await refreshedAccountTwo.json()).events.find(
    (candidate) => candidate.id === eventId,
  );
  assert.equal(refreshedAccountTwoEvent.hasResponse, false);
  assert.equal(refreshedAccountTwoEvent.responseRevision, null);
  const replacementResponse = await api(
    miniflare,
    `/api/invites/${refreshedAccountTwoEvent.inviteToken}/rsvp`,
    authorizedJsonRequest("PUT", {
      envelope: encryptedEnvelope({
        event: refreshedAccountTwoEvent,
        inviteeId: accountTwoInvitee.id,
        accountKeyEpochId: refreshedAccountTwoEvent.accountKeyEpochId,
        envelopeId: "74000000-0000-4000-8000-000000000202",
      }),
    }, sessions.get("2")),
  );
  assert.equal(replacementResponse.status, 200, await replacementResponse.clone().text());
  assert.equal((await replacementResponse.json()).responseEnvelope.revision, 1);
  const disabledEventId = "74000000-0000-4000-8000-000000000011";
  const disabledEvent = {
    ...event,
    id: disabledEventId,
    title: "Host-only guest additions",
    invitees: [{
      id: "74000000-0000-4000-8000-000000000012",
      displayName: testAccountNameForAlias("2"),
      phoneNumber: "+14155550102",
    }],
    allowsAttendeesToAddGuests: false,
  };
  const createDisabledResponse = await api(
    miniflare,
    `/api/events/${disabledEventId}`,
    authorizedJsonRequest("PUT", disabledEvent, sessions.get("1")),
  );
  assert.equal(createDisabledResponse.status, 200);

  const deniedAddition = await api(
    miniflare,
    `/api/events/${disabledEventId}/attendees`,
    authorizedJsonRequest("POST", {
      invitees: [{
        id: "74000000-0000-4000-8000-000000000014",
        displayName: testAccountNameForAlias("4"),
        phoneNumber: "+14155550104",
      }],
    }, sessions.get("2")),
  );
  assert.equal(deniedAddition.status, 403);
  assert.equal((await deniedAddition.json()).error?.code, "attendee_additions_disabled");

  const hostAddition = await api(
    miniflare,
    `/api/events/${disabledEventId}/attendees`,
    authorizedJsonRequest("POST", {
      invitees: [{
        id: "74000000-0000-4000-8000-000000000014",
        displayName: testAccountNameForAlias("4"),
        phoneNumber: "+14155550104",
      }],
    }, sessions.get("1")),
  );
  assert.equal(hostAddition.status, 200);
  assert.equal((await hostAddition.json()).event.invitees.length, 2);
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

test("operational telemetry correlates API boundaries and stores aggregates only", async (t) => {
  const observabilityToken = "observability-test-token-0123456789-abcdef";
  const alertSecret = "monitor-alert-test-secret-0123456789-abcdef";
  const { miniflare, database } = await createHarness({
    bindings: {
      HERD_OBSERVABILITY_TOKEN: observabilityToken,
      HERD_MONITOR_ALERT_HMAC_SECRET: alertSecret,
    },
  });
  t.after(() => miniflare.dispose());

  const requestId = "90000000-0000-4000-8000-000000000001";
  const failed = await api(miniflare, "/api/events", {
    headers: {
      "x-herd-request-id": requestId,
      "x-herd-client-platform": "ios",
    },
  });
  assert.equal(failed.status, 401);
  assert.equal(failed.headers.get("x-herd-request-id"), requestId);
  assert.equal(failed.headers.get("x-herd-error-code"), "authentication_required");

  const clientSignal = await api(miniflare, "/api/telemetry", jsonRequest("POST", {
    schemaVersion: 1,
    platform: "web",
    signal: "client_api_request",
    operation: "get.events",
    outcome: "failure",
    statusCode: 401,
    errorCode: "authentication_required",
    durationMs: 12,
    correlationId: requestId,
  }));
  assert.equal(clientSignal.status, 204);

  const localDecodeSignal = await api(miniflare, "/api/telemetry", jsonRequest("POST", {
    schemaVersion: 1,
    platform: "web",
    signal: "client_decode",
    operation: "reply.saved.open",
    outcome: "failure",
    statusCode: 0,
    errorCode: "saved_reply_invalid_envelope",
    durationMs: 8,
    correlationId: "90000000-0000-4000-8000-000000000003",
  }));
  assert.equal(localDecodeSignal.status, 204);

  const rows = await database.prepare(`
    SELECT component, signal, operation, outcome, status_class AS statusClass,
      error_code AS errorCode, count
    FROM operational_metrics
    ORDER BY component, signal
  `).all();
  assert.deepEqual(rows.results.map((row) => ({ ...row })), [
    {
      component: "api",
      signal: "api_request",
      operation: "get.events",
      outcome: "failure",
      statusClass: "4xx",
      errorCode: "authentication_required",
      count: 1,
    },
    {
      component: "ios",
      signal: "service_boundary",
      operation: "get.events",
      outcome: "failure",
      statusClass: "4xx",
      errorCode: "authentication_required",
      count: 1,
    },
    {
      component: "web",
      signal: "client_api_request",
      operation: "get.events",
      outcome: "failure",
      statusClass: "4xx",
      errorCode: "authentication_required",
      count: 1,
    },
    {
      component: "web",
      signal: "client_decode",
      operation: "reply.saved.open",
      outcome: "failure",
      statusClass: "none",
      errorCode: "saved_reply_invalid_envelope",
      count: 1,
    },
  ]);

  const alertBody = JSON.stringify({
    schemaVersion: 1,
    ok: false,
    checkedAt: new Date().toISOString(),
    configurationFailureClass: null,
    storageFailureClass: null,
    targets: [{
      target: "herd-production",
      ok: false,
      durationMs: 250,
      failureClass: "availability",
      releaseId: "2026.08.12.1",
    }],
  });
  const alertSignature = createHmac("sha256", alertSecret).update(alertBody).digest("hex");
  const alert = await api(miniflare, "/api/internal/observability/alerts", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-herd-signature": `sha256=${alertSignature}`,
    },
    body: alertBody,
  });
  assert.equal(alert.status, 204);

  const unauthorized = await api(miniflare, "/api/internal/observability/summary?hours=24");
  assert.equal(unauthorized.status, 401);
  const summary = await api(miniflare, "/api/internal/observability/summary?hours=24", {
    headers: { authorization: `Bearer ${observabilityToken}` },
  });
  assert.equal(summary.status, 200);
  const summaryBody = await summary.json();
  assert.equal(summaryBody.schemaVersion, 1);
  assert.equal(summaryBody.rows.length, 4);
  assert.equal(summaryBody.health.alertFailureCount, 1);
  assert.equal(summaryBody.health.alertRecoveryCount, 0);
  assert.equal(summaryBody.health.activeAlertCount, 1);

  const badAlert = await api(miniflare, "/api/internal/observability/alerts", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "x-herd-signature": "sha256=deadbeef",
    },
    body: alertBody,
  });
  assert.equal(badAlert.status, 401);

  const recoveryBody = JSON.stringify({
    ...JSON.parse(alertBody),
    ok: true,
    checkedAt: new Date(Date.now() + 1_000).toISOString(),
    targets: [{
      ...JSON.parse(alertBody).targets[0],
      ok: true,
      failureClass: null,
    }],
  });
  const recoverySignature = createHmac("sha256", alertSecret).update(recoveryBody).digest("hex");
  const recovery = await api(miniflare, "/api/internal/observability/alerts", {
    method: "POST",
    headers: { "x-herd-signature": `sha256=${recoverySignature}` },
    body: recoveryBody,
  });
  assert.equal(recovery.status, 204);
  const recoveredSummary = await api(miniflare, "/api/internal/observability/summary?hours=24", {
    headers: { authorization: `Bearer ${observabilityToken}` },
  });
  assert.equal(recoveredSummary.status, 200);
  assert.equal((await recoveredSummary.json()).health.activeAlertCount, 0);
});

test("telemetry rejects identifiers, payload fields, and malformed dimensions", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  const base = {
    schemaVersion: 1,
    platform: "web",
    signal: "client_api_request",
    operation: "put.invites.invite.rsvp",
    outcome: "success",
    statusCode: 200,
    errorCode: "none",
    durationMs: 20,
    correlationId: "90000000-0000-4000-8000-000000000002",
  };
  for (const body of [
    { ...base, eventId: "private-event" },
    { ...base, phoneNumber: "+14155550100" },
    { ...base, operation: "/api/invites/secret-token/rsvp" },
  ]) {
    const response = await api(miniflare, "/api/telemetry", jsonRequest("POST", body));
    assert.equal(response.status, 400);
  }

  const baseRequest = jsonRequest("POST", base);
  const crossOrigin = await api(miniflare, "/api/telemetry", {
    ...baseRequest,
    headers: { ...baseRequest.headers, origin: "https://attacker.example" },
  });
  assert.equal(crossOrigin.status, 403);
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM operational_metrics").first("count"),
    0,
  );
  const unsignedAlert = await api(miniflare, "/api/internal/observability/alerts", jsonRequest("POST", {}));
  assert.equal(unsignedAlert.status, 401);
});

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

test("removed demo invitation fixtures are not exposed by the production API", async (t) => {
  const { miniflare } = await createHarness();
  t.after(() => miniflare.dispose());
  const response = await api(miniflare, "/api/invites/poker-party");
  assert.equal(response.status, 404);
});
