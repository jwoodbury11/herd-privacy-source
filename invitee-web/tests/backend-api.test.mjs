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
  const sentMessages = [];
  if (!options.fetchMock) {
    let messageSequence = 0;
    fetchMock.disableNetConnect();
    fetchMock
      .get("https://api.twilio.com")
      .intercept({
        method: "POST",
        path: `/2010-04-01/Accounts/${messagingAccountSid}/Messages.json`,
      })
      .reply(201, (request) => {
        sentMessages.push(new Response(request.body).text()
          .then((body) => new URLSearchParams(body)));
        return { sid: `${options.messageSidPrefix ?? "SM"}${(++messageSequence).toString(16).padStart(32, "0")}`, status: "accepted" };
      })
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
        TWILIO_AUTH_TOKEN: "sms-webhook-auth-token",
        HERD_SMS_FROM_NUMBER: "+14155550999",
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
    sentMessages,
    async updateBindings(overrides) {
      Object.assign(harnessBindings, overrides);
      await miniflare.setOptions({
        ...miniflareOptions,
        bindings: { ...harnessBindings },
      });
    },
  };
}

test("authentication ignores invitation-link presentation data", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());

  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1", inviteToken: "bad/token" }),
  );
  assert.equal(response.status, 200);
  assert.equal((await response.json()).user.phoneNumber, "+14155550101");
  assert.equal(
    await database.prepare("SELECT COUNT(*) AS count FROM sessions").first("count"),
    1,
  );
});

test("a full test-account phone number still starts a real Twilio challenge", async (t) => {
  const apiKeySid = `SK${"6".repeat(32)}`;
  const verifyServiceSid = `VA${"7".repeat(32)}`;
  const providerSid = `VE${"8".repeat(32)}`;
  const realPhone = "+14155550101";
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

test("automatic invitations attach the selected artwork and are sent only once", async (t) => {
  const { miniflare, database, sentMessages } = await createHarness({ messageSidPrefix: "MM" });
  t.after(() => miniflare.dispose());
  const signIn = await api(miniflare, "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: "1" }));
  const { accessToken } = await signIn.json();

  for (const [index, imageID] of ["fishing", "beach", "lan", "arcade"].entries()) {
    const event = {
      id: `71000000-0000-4000-8000-${String(index + 10).padStart(12, "0")}`,
      title: "Picture invitation test", hostName: testAccountNameForAlias("1"),
      eventDate: new Date(Date.now() + 14 * 86_400_000).toISOString(),
      endDate: new Date(Date.now() + 14 * 86_400_000 + 7_200_000).toISOString(),
      rsvpDeadline: new Date(Date.now() + 12 * 86_400_000).toISOString(),
      eventTimeZone: "America/Los_Angeles",
      locationName: "Test", locationAddress: "", minimumParticipants: 2,
      invitees: [{
        id: `72000000-0000-4000-8000-${String(index + 10).padStart(12, "0")}`,
        displayName: testAccountNameForAlias("2"), phoneNumber: "+14155550102",
      }],
      requiredGroups: [], eventDescription: "", eventImageID: imageID,
      createdAt: new Date().toISOString(), invitationsSent: true,
    };
    const response = await api(miniflare, `/api/events/${event.id}`,
      authorizedJsonRequest("PUT", event, accessToken));
    assert.equal(response.status, 200, await response.clone().text());
    const sentEvent = (await response.json()).event;
    assert.equal(sentMessages.length, index + 1);
    const message = await sentMessages[index];
    assert.equal(message.get("To"), "+14155550102");
    assert.equal(message.get("MessagingServiceSid"), messagingServiceSid);
    assert.equal(message.get("MediaUrl"), `https://app.herdprivacy.com/event-images/${imageID}.png`);
    assert.match(message.get("Body"), /Open the invitation and reply privately\./u);
    assert.match(message.get("Body"), /Reply STOP to opt out; HELP for help\./u);
    assert.match(message.get("Body"), /\nhttps:\/\/app\.herdprivacy\.com\/invite\/[A-Za-z0-9_-]+$/u);
    const image = await readFile(path.join(projectRoot, "public", "event-images", `${imageID}.png`));
    assert.ok(image.length < 5_000_000, "MMS artwork must fit Twilio's media limit");
    assert.equal(await database.prepare("SELECT status FROM invitation_deliveries WHERE event_id = ?")
      .bind(event.id).first("status"), "sent");
    assert.match(await database.prepare("SELECT provider_message_sid FROM invitation_deliveries WHERE event_id = ?")
      .bind(event.id).first("provider_message_sid"), /^MM[0-9a-f]{32}$/u);

    const savedAgain = await api(miniflare, `/api/events/${event.id}`,
      authorizedJsonRequest("PUT", sentEvent, accessToken));
    assert.equal(savedAgain.status, 200, await savedAgain.clone().text());
    assert.equal(sentMessages.length, index + 1, "Saving again must not resend the MMS");
  }
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
    eventImageID: "beach",
    createdAt: new Date().toISOString(),
    invitationsSent: false,
  };

  const draftResponse = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest("PUT", event, sessions.get("1")),
  );
  assert.equal(draftResponse.status, 200);
  assert.equal((await draftResponse.json()).event.eventImageID, "beach");
  assert.equal(
    await database
      .prepare("SELECT event_image_id AS eventImageID FROM events WHERE id = ?")
      .bind(eventId)
      .first("eventImageID"),
    "beach",
  );

  const hostDraftEvents = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("1")}` },
  });
  const hostDraftEvent = (await hostDraftEvents.json()).events[0];
  assert.equal(hostDraftEvent.role, "host");
  assert.equal(hostDraftEvent.eventImageID, "beach");
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
  assert.equal((await sentResponse.json()).event.privateResponsePolicy, null);

  const invitedEventsByDigit = new Map();
  for (const digit of ["2", "3", "4", "5", "6", "7", "8", "9"]) {
    const invitedEventsResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${sessions.get(digit)}` },
    });
    assert.equal(invitedEventsResponse.status, 200);
    const invitedEvents = (await invitedEventsResponse.json()).events;
    const invitedEvent = invitedEvents.find((candidate) => candidate.id === eventId);
    assert.equal(invitedEvent.role, "invitee");
    assert.equal(invitedEvent.eventImageID, "beach");
    assert.equal(invitedEvent.invitees.filter((invitee) => invitee.isCurrentUser).length, 1);
    assert.ok(invitedEvent.inviteToken);
    invitedEventsByDigit.set(digit, invitedEvent);
  }

  for (const digit of ["2", "3", "4", "5", "6", "7", "8", "9"]) {
    const invitedEvent = invitedEventsByDigit.get(digit);
    const session = sessionRecords.get(digit);
    const ballotResponse = await api(
      miniflare,
      `/api/invites/${invitedEvent.inviteToken}/ballot`,
      authorizedJsonRequest("PUT", {
        response: "cant_commit",
        minimumParticipants: null,
        requiredGroups: [],
      }, session.accessToken),
    );
    assert.equal(ballotResponse.status, 200, await ballotResponse.clone().text());
    assert.equal((await ballotResponse.json()).ballot.revision, 1);

    const refreshedEventsResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${session.accessToken}` },
    });
    const refreshedEvent = (await refreshedEventsResponse.json()).events.find(
      (candidate) => candidate.id === eventId,
    );
    assert.equal(refreshedEvent.hasBallot, true);
    assert.equal(refreshedEvent.responseRevision, 1);
  }

  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM ballot_revisions WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    8,
  );

  for (const viewerDigit of ["1", "2"]) {
    const viewerResponse = await api(miniflare, "/api/events", {
      headers: { authorization: `Bearer ${sessions.get(viewerDigit)}` },
    });
    assert.equal(viewerResponse.status, 200);
    const viewerEvent = (await viewerResponse.json()).events.find(
      (candidate) => candidate.id === eventId,
    );
    assert.ok(viewerEvent);
    assert.equal(
      viewerEvent.invitees.filter((invitee) => invitee.hasResponded === true).length,
      8,
      `test account ${viewerDigit} must receive every other account's response marker`,
    );
  }

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

test("hosts and permitted attendees can expand a sent roster while host rules lock at confirmation", async (t) => {
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

  const accountTwoInvitee = attendeeEvent.invitees.find((invitee) => invitee.isCurrentUser);
  assert.ok(accountTwoInvitee);
  const firstResponse = await api(
    miniflare,
    `/api/invites/${attendeeEvent.inviteToken}/ballot`,
    authorizedJsonRequest("PUT", {
      response: "cant_commit",
      minimumParticipants: null,
      requiredGroups: [],
    }, sessions.get("2")),
  );
  assert.equal(firstResponse.status, 200, await firstResponse.clone().text());
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM ballot_revisions WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    1,
  );
  // A protocol-v2 roster can expand after replies begin. The existing
  // pseudonymous ballot stays intact and the cached result is recalculated.
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
  assert.equal(
    await database
      .prepare("SELECT COUNT(*) AS count FROM ballot_revisions WHERE event_id = ?")
      .bind(eventId)
      .first("count"),
    1,
  );
  const refreshedAccountTwo = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("2")}` },
  });
  const refreshedAccountTwoEvent = (await refreshedAccountTwo.json()).events.find(
    (candidate) => candidate.id === eventId,
  );
  assert.equal(refreshedAccountTwoEvent.hasBallot, true);
  assert.equal(refreshedAccountTwoEvent.responseRevision, 1);
  assert.equal(refreshedAccountTwoEvent.privateResponsePolicy, null);
  const confirmingBallot = await api(
    miniflare,
    `/api/invites/${attendeeEvent.inviteToken}/ballot`,
    authorizedJsonRequest("PUT", {
      response: "going",
      minimumParticipants: 2,
      requiredGroups: [],
    }, sessions.get("2")),
  );
  assert.equal(confirmingBallot.status, 200, await confirmingBallot.clone().text());
  const resolvedEvents = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("2")}` },
  });
  const resolvedEvent = (await resolvedEvents.json()).events.find(
    (candidate) => candidate.id === eventId,
  );
  assert.equal(resolvedEvent.resolution.status, "confirmed");
  assert.deepEqual(resolvedEvent.resolution.attendingMemberIds, [
    "host",
    accountTwoInvitee.id,
  ]);
  assert.equal(resolvedEvent.privateResponsePolicy, null);
  const confirmedHostEvents = await api(miniflare, "/api/events", {
    headers: { authorization: `Bearer ${sessions.get("1")}` },
  });
  assert.equal(confirmedHostEvents.status, 200);
  const confirmedHostEvent = (await confirmedHostEvents.json()).events.find(
    (candidate) => candidate.id === eventId,
  );
  assert.ok(confirmedHostEvent);

  const confirmedMetadataEdit = await api(
    miniflare,
    `/api/events/${eventId}`,
    authorizedJsonRequest("PUT", {
      ...confirmedHostEvent,
      title: "Edited after confirmation",
      locationName: "Updated location",
      eventDescription: "Ordinary event details remain editable.",
    }, sessions.get("1")),
  );
  assert.equal(confirmedMetadataEdit.status, 200, await confirmedMetadataEdit.clone().text());
  const editedConfirmedEvent = (await confirmedMetadataEdit.json()).event;
  assert.equal(editedConfirmedEvent.title, "Edited after confirmation");
  assert.equal(editedConfirmedEvent.locationName, "Updated location");
  assert.equal(
    await database
      .prepare("SELECT status FROM event_resolutions WHERE event_id = ?")
      .bind(eventId)
      .first("status"),
    "confirmed",
  );

  const lockedConfirmedChanges = [
    {
      ...editedConfirmedEvent,
      minimumParticipants: editedConfirmedEvent.minimumParticipants + 1,
    },
    {
      ...editedConfirmedEvent,
      rsvpDeadline: new Date(Date.parse(editedConfirmedEvent.rsvpDeadline) - 60_000).toISOString(),
    },
    {
      ...editedConfirmedEvent,
      requiredGroups: [{
        id: "75000000-0000-4000-8000-000000000005",
        memberIDs: [editedConfirmedEvent.invitees[0].id],
      }],
    },
  ];
  for (const lockedChange of lockedConfirmedChanges) {
    const response = await api(
      miniflare,
      `/api/events/${eventId}`,
      authorizedJsonRequest("PUT", lockedChange, sessions.get("1")),
    );
    assert.equal(response.status, 409);
    assert.equal(
      (await response.json()).error.code,
      "confirmed_event_attendance_locked",
    );
  }

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

test("operator ballot diagnostics stay deidentified and corrections are append-only audited", async (t) => {
  const operatorToken = "herd-operator-test-token-0123456789-abcdefghijklmnopqrstuvwxyz";
  const { miniflare, database } = await createHarness({
    bindings: {
      HERD_OPERATOR_TOKEN: operatorToken,
      HERD_BALLOT_PSEUDONYM_KEY:
        "herd-ballot-test-key-0123456789-abcdefghijklmnopqrstuvwxyz",
    },
  });
  t.after(() => miniflare.dispose());

  const eventId = "7b000000-0000-4000-8000-000000000001";
  const hostId = "7b000000-0000-4000-8000-000000000002";
  const inviteeId = "7b000000-0000-4000-8000-000000000003";
  const ballotId = "A".repeat(43);
  const now = "2026-08-18T20:00:00.000Z";
  await database.batch([
    database.prepare(
      `INSERT INTO users (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES (?, ?, ?, ?, '', ?, ?)`,
    ).bind(hostId, "+14155550991", "operator-host-phone-hash", "Host", now, now),
    database.prepare(
      `INSERT INTO events (
         id, host_user_id, title, event_date, end_date, host_name,
         location_name, location_address, minimum_participants, rsvp_deadline,
         event_description, invitations_sent, created_at, updated_at
       ) VALUES (?, ?, 'Operator fixture', NULL, NULL, 'Host', '', '', 2, NULL, '', 1, ?, ?)`,
    ).bind(eventId, hostId, now, now),
    database.prepare(
      `INSERT INTO invitees (
         id, event_id, user_id, display_name, phone_number, phone_hash,
         token_hash, created_at, updated_at
       ) VALUES (?, ?, NULL, 'Invitee', '+14155550992', 'operator-invitee-phone-hash', ?, ?, ?)`,
    ).bind(inviteeId, eventId, "operator-invite-token-hash", now, now),
    database.prepare(
      `INSERT INTO ballot_revisions (
         ballot_id, revision, protocol_version, key_version, event_id, response,
         minimum_participants, required_groups, source, correction_reason,
         content_digest, created_at
       ) VALUES (?, 1, 2, 1, ?, 'going', 2, '[]', 'user', NULL, ?, ?)`,
    ).bind(ballotId, eventId, "operator-original-digest", now),
  ]);

  const unauthorized = await api(
    miniflare,
    `/api/internal/ballots?eventId=${eventId}`,
  );
  assert.equal(unauthorized.status, 401);

  const authorization = { authorization: `Bearer ${operatorToken}` };
  const diagnostic = await api(
    miniflare,
    `/api/internal/ballots?eventId=${eventId}`,
    { headers: authorization },
  );
  assert.equal(diagnostic.status, 200, await diagnostic.clone().text());
  const diagnosticBody = await diagnostic.json();
  assert.equal(diagnosticBody.ballots.length, 1);
  assert.equal(diagnosticBody.ballots[0].ballotId, ballotId);
  const serializedDiagnostic = JSON.stringify(diagnosticBody);
  assert.doesNotMatch(
    serializedDiagnostic,
    /phone|displayName|inviteeId|userId|accountId/iu,
  );

  const correction = await api(
    miniflare,
    "/api/internal/ballots",
    {
      method: "POST",
      headers: { ...authorization, "content-type": "application/json" },
      body: JSON.stringify({
        action: "append_correction",
        eventId,
        ballotId,
        actor: "launch-support",
        reason: "Correct the recorded minimum after reviewing the reported mismatch.",
        correlationId: "support-case-2026-08-18-001",
        response: "cant_commit",
        minimumParticipants: null,
        requiredGroups: [],
      }),
    },
  );
  assert.equal(correction.status, 201, await correction.clone().text());
  assert.equal((await correction.json()).revision, 2);
  assert.equal(
    await database.prepare(
      "SELECT COUNT(*) AS count FROM ballot_revisions WHERE ballot_id = ?",
    ).bind(ballotId).first("count"),
    2,
  );
  const action = await database.prepare(
    `SELECT actor, reason, previous_digest AS previousDigest,
            next_digest AS nextDigest, correlation_id AS correlationId
     FROM ballot_operator_actions WHERE ballot_id = ?`,
  ).bind(ballotId).first();
  assert.equal(action.actor, "launch-support");
  assert.equal(action.previousDigest, "operator-original-digest");
  assert.notEqual(action.nextDigest, action.previousDigest);
  assert.equal(action.correlationId, "support-case-2026-08-18-001");

  await database.prepare(
    `INSERT INTO event_resolutions (
       event_id, policy_hash, status, batch_hash, attending_member_ids,
       resolved_at, created_at, updated_at
     ) VALUES (?, 'operator-policy', 'confirmed', NULL, '[]', ?, ?, ?)`,
  ).bind(eventId, now, now, now).run();
  const afterConfirmation = await api(
    miniflare,
    "/api/internal/ballots",
    {
      method: "POST",
      headers: { ...authorization, "content-type": "application/json" },
      body: JSON.stringify({
        action: "append_correction",
        eventId,
        ballotId,
        actor: "launch-support",
        reason: "This correction must be rejected after confirmation.",
        correlationId: "support-case-2026-08-18-002",
        response: "going",
        minimumParticipants: 2,
        requiredGroups: [],
      }),
    },
  );
  assert.equal(afterConfirmation.status, 409);
});

test("internal event viewer is operator-only and returns bounded public event health", async (t) => {
  const operatorToken = "herd-viewer-test-token-0123456789-abcdefghijklmnopqrstuvwxyz";
  const { miniflare, database } = await createHarness({
    bindings: { HERD_OPERATOR_TOKEN: operatorToken },
  });
  t.after(() => miniflare.dispose());

  const eventId = "7c000000-0000-4000-8000-000000000001";
  const hostId = "7c000000-0000-4000-8000-000000000002";
  const inviteeId = "7c000000-0000-4000-8000-000000000003";
  const groupId = "7c000000-0000-4000-8000-000000000004";
  const now = "2026-08-18T21:00:00.000Z";
  await database.batch([
    database.prepare(
      `INSERT INTO users (id, phone_number, phone_hash, name, address, created_at, updated_at)
       VALUES (?, '+14155550881', 'viewer-host-phone-hash', 'Viewer Host', '', ?, ?)`,
    ).bind(hostId, now, now),
    database.prepare(
      `INSERT INTO events (
         id, host_user_id, title, event_date, end_date, host_name,
         location_name, location_address, minimum_participants, rsvp_deadline,
         event_description, invitations_sent, created_at, updated_at
       ) VALUES (?, ?, 'Viewer fixture', ?, NULL, 'Viewer Host', 'The Park',
                 '1 Main St', 2, ?, 'A visible event description.', 1, ?, ?)`,
    ).bind(eventId, hostId, now, now, now, now),
    database.prepare(
      `INSERT INTO invitees (
         id, event_id, user_id, display_name, phone_number, phone_hash,
         token_hash, created_at, updated_at
       ) VALUES (?, ?, NULL, 'Private Invitee', '+14155550882',
                 'viewer-invitee-phone-hash', 'viewer-private-token-hash', ?, ?)`,
    ).bind(inviteeId, eventId, now, now),
    database.prepare(
      `INSERT INTO ballot_revisions (
         ballot_id, revision, protocol_version, key_version, event_id, response,
         minimum_participants, required_groups, source, correction_reason,
         content_digest, created_at
       ) VALUES (?, 1, 2, 1, ?, 'going', 2, '[]', 'user', NULL, ?, ?)`,
    ).bind("B".repeat(43), eventId, "viewer-ballot-digest", now),
    database.prepare(
      `INSERT INTO groups (id, event_id, position) VALUES (?, ?, 0)`,
    ).bind(groupId, eventId),
    database.prepare(
      `INSERT INTO group_members (group_id, invitee_id, position) VALUES (?, ?, 0)`,
    ).bind(groupId, inviteeId),
  ]);

  const unauthorized = await api(miniflare, "/api/internal/events");
  assert.equal(unauthorized.status, 401);

  const response = await api(miniflare, "/api/internal/events?q=Viewer", {
    headers: { authorization: `Bearer ${operatorToken}` },
  });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(response.headers.get("x-robots-tag"), "noindex, nofollow, noarchive");
  const body = await response.json();
  assert.equal(body.events.length, 1);
  assert.equal(body.events[0].id, eventId);
  assert.equal(body.events[0].participantCount, 2);
  assert.equal(body.events[0].hostConditionGroupCount, 1);
  assert.equal(body.events[0].hostConditionOptionCount, 1);
  assert.equal(body.events[0].ballotCount, 1);
  assert.equal(body.events[0].hostName, "Viewer Host");
  assert.equal(body.events[0].locationAddress, "1 Main St");
  assert.equal(body.nextCursor, null);
  assert.doesNotMatch(
    JSON.stringify(body),
    /Private Invitee|141555508|phoneHash|phoneNumber|token|ballotId|requiredGroups|contentDigest|session/iu,
  );
});

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

test("signed-out callers cannot probe removed invitation fixtures", async (t) => {
  const { miniflare } = await createHarness();
  t.after(() => miniflare.dispose());
  const response = await api(miniflare, "/api/invites/poker-party");
  assert.equal(response.status, 401);
});

test("confirmed events grow until the next day and reconsider saved conditional replies", async (t) => {
  const { miniflare, database } = await createHarness();
  t.after(() => miniflare.dispose());
  const sessions = new Map();
  for (const digit of ["1", "2", "3", "4", "5", "6", "7", "8", "9"]) {
    const response = await api(miniflare, "/api/auth/request-code", jsonRequest("POST", { phoneNumber: digit }));
    assert.equal(response.status, 200);
    sessions.set(digit, (await response.json()).accessToken);
  }
  const eventId = "74000000-0000-4000-8000-000000000101";
  const guest = (digit) => ({
    id: `74000000-0000-4000-8000-00000000010${digit}`,
    displayName: testAccountNameForAlias(digit),
    phoneNumber: `+1415555010${digit}`,
  });
  const event = {
    id: eventId, title: "Growing confirmed volleyball", hostName: testAccountNameForAlias("1"),
    eventDate: new Date(Date.now() + 2 * 86_400_000).toISOString(), endDate: null,
    rsvpDeadline: new Date(Date.now() + 86_400_000).toISOString(),
    locationName: "", locationAddress: "", eventDescription: "", minimumParticipants: 4,
    requiredGroups: [], allowsAttendeesToAddGuests: true, invitationsSent: true,
    invitees: ["2", "3", "4", "5", "6"].map(guest), createdAt: new Date().toISOString(),
  };
  const created = await api(miniflare, `/api/events/${eventId}`, authorizedJsonRequest("PUT", event, sessions.get("1")));
  assert.equal(created.status, 200, await created.clone().text());
  const read = async (digit = "1") => {
    const response = await api(miniflare, "/api/events", { headers: { authorization: `Bearer ${sessions.get(digit)}` } });
    assert.equal(response.status, 200, await response.clone().text());
    return (await response.json()).events.find((item) => item.id === eventId);
  };
  const reply = async (digit, minimum = 2, requiredGroups = [], response = "going") => {
    const ownEvent = await read(digit);
    return api(miniflare, `/api/invites/${ownEvent.inviteToken}/ballot`, authorizedJsonRequest("PUT", {
      response, minimumParticipants: response === "going" ? minimum : null, requiredGroups,
    }, sessions.get(digit)));
  };
  assert.equal((await reply("2", 6)).status, 200);
  for (const digit of ["3", "4", "5"]) assert.equal((await reply(digit)).status, 200);
  const initiallyConfirmed = await read();
  assert.equal(initiallyConfirmed.resolution.status, "confirmed");
  assert.equal(initiallyConfirmed.resolution.attendingMemberIds.length, 4);
  assert.equal(initiallyConfirmed.resolution.guestStates.find((state) => state.memberId === guest("2").id).status, "cant_commit");
  const confirmedAt = initiallyConfirmed.resolution.resolvedAt;
  const notificationCount = await database.prepare("SELECT COUNT(*) AS count FROM resolution_notifications WHERE event_id = ?").bind(eventId).first("count");
  const originalBallots = await database.prepare("SELECT * FROM ballot_revisions WHERE event_id = ? ORDER BY ballot_id, revision").bind(eventId).all();

  // The original RSVP deadline and event start have passed; joining is still open.
  await database.prepare("UPDATE events SET event_date = ?, rsvp_deadline = ? WHERE id = ?")
    .bind(new Date(Date.now() - 60 * 60_000).toISOString(), new Date(Date.now() - 2 * 60 * 60_000).toISOString(), eventId).run();
  const added = await api(miniflare, `/api/events/${eventId}/attendees`, authorizedJsonRequest("POST", {
    invitees: ["7", "8", "9"].map(guest),
  }, sessions.get("3")));
  assert.equal(added.status, 200, await added.clone().text());
  assert.equal((await added.json()).event.resolution.status, "confirmed");
  const newDeliveries = await database.prepare("SELECT status, last_error_code FROM invitation_deliveries WHERE event_id = ? AND invitee_id IN (?, ?, ?)")
    .bind(eventId, guest("7").id, guest("8").id, guest("9").id).all();
  assert.equal(newDeliveries.results.length, 3);
  assert.ok(newDeliveries.results.every((row) => row.status === "sent"), JSON.stringify(newDeliveries.results));
  assert.equal((await reply("6")).status, 200);
  const grown = await read();
  assert.equal(grown.resolution.attendingMemberIds.length, 6);
  assert.equal(grown.resolution.guestStates.find((state) => state.memberId === guest("2").id).status, "going");
  assert.equal(grown.resolution.resolvedAt, confirmedAt);
  const originalAfter = await database.prepare("SELECT * FROM ballot_revisions WHERE event_id = ? AND ballot_id IN (SELECT ballot_id FROM ballot_revisions WHERE event_id = ? ORDER BY created_at LIMIT 4) ORDER BY ballot_id, revision").bind(eventId, eventId).all();
  assert.deepEqual(originalAfter.results, originalBallots.results, "automatic eligibility must not rewrite anyone’s saved reply");

  // New conditional guests, including named-person dependencies, are reconsidered too.
  const group = [{ id: "75000000-0000-4000-8000-000000000101", memberIDs: [guest("8").id] }];
  assert.equal((await reply("7", 2, group)).status, 200);
  assert.equal((await read()).resolution.attendingMemberIds.length, 6);
  const [eighthReply, ninthReply] = await Promise.all([
    reply("8"), reply("9", 2, [], "cant_commit"), read(),
  ]);
  assert.equal(eighthReply.status, 200);
  assert.equal(ninthReply.status, 200);
  assert.equal((await read()).resolution.attendingMemberIds.length, 8);
  assert.equal(await database.prepare("SELECT COUNT(*) AS count FROM resolution_notifications WHERE event_id = ?").bind(eventId).first("count"), notificationCount);
  const withdrawal = await reply("3", 2, [], "cant_commit");
  assert.equal(withdrawal.status, 409);
  assert.equal((await withdrawal.json()).error.code, "attendance_already_committed");
  assert.equal((await reply("2", 6)).status, 200, "exact retries stay idempotent after automatic promotion");

  // One minute inside the next-day window remains open; beyond it rejects all new writes.
  await database.prepare("UPDATE events SET event_date = ?, rsvp_deadline = ? WHERE id = ?")
    .bind(new Date(Date.now() - 86_400_000 + 60_000).toISOString(), new Date(Date.now() - 2 * 86_400_000).toISOString(), eventId).run();
  assert.equal((await reply("9", 9)).status, 200);
  await database.prepare("UPDATE events SET event_date = ? WHERE id = ?")
    .bind(new Date(Date.now() - 86_400_000 - 60_000).toISOString(), eventId).run();
  const tooLate = await reply("9");
  assert.equal(tooLate.status, 409);
  assert.equal((await tooLate.json()).error.code, "rsvp_closed");
  const lateAddition = await api(miniflare, `/api/events/${eventId}/attendees`, authorizedJsonRequest("POST", {
    invitees: [{ id: "74000000-0000-4000-8000-000000000110", displayName: "Late guest", phoneNumber: "+14155550110" }],
  }, sessions.get("1")));
  assert.equal(lateAddition.status, 409);
  assert.equal((await lateAddition.json()).error.code, "rsvp_closed");
  assert.equal((await read()).resolution.resolvedAt, confirmedAt);
  assert.equal((await read()).resolution.attendingMemberIds.length, 9);
});

test("SMS follow-ups target only unanswered guests, allow no to yes, and keep confirmed yes final", async (t) => {
  const operator = "sms-operator-0123456789-abcdefghijklmnopqrstuvwxyz";
  const { miniflare, updateBindings } = await createHarness({ bindings: { HERD_OPERATOR_TOKEN: operator } });
  let database = await miniflare.getD1Database("DB");
  t.after(() => miniflare.dispose());
  const sessions = new Map();
  for (const digit of ["1", "2", "3", "4", "5"]) {
    const auth = await api(miniflare, "/api/auth/request-code", jsonRequest("POST", { phoneNumber: digit }));
    sessions.set(digit, (await auth.json()).accessToken);
  }
  const eventId = "78000000-0000-4000-8000-000000000101";
  const guest = (digit) => ({ id: `78000000-0000-4000-8000-00000000010${digit}`, displayName: testAccountNameForAlias(digit), phoneNumber: `+1415555010${digit}` });
  const event = {
    id: eventId, title: "SMS volleyball", hostName: testAccountNameForAlias("1"),
    eventDate: new Date(Date.now() + 86_400_000).toISOString(), eventTimeZone: "America/Los_Angeles", endDate: null,
    rsvpDeadline: new Date(Date.now() + 3_600_000).toISOString(), locationName: "Test park", locationAddress: "", eventDescription: "",
    minimumParticipants: 2, requiredGroups: [], invitationsSent: true, invitees: ["2", "3", "4"].map(guest), createdAt: new Date().toISOString(),
  };
  const created = await api(miniflare, `/api/events/${eventId}`, authorizedJsonRequest("PUT", event, sessions.get("1")));
  assert.equal(created.status, 200, await created.clone().text());
  const read = async (digit = "1") => {
    const r = await api(miniflare, "/api/events", { headers: { authorization: `Bearer ${sessions.get(digit)}` } });
    assert.equal(r.status, 200, await r.clone().text());
    return (await r.json()).events.find((e) => e.id === eventId);
  };
  const ordinaryReply = async (digit, response) => api(miniflare, `/api/invites/${(await read(digit)).inviteToken}/ballot`, authorizedJsonRequest("PUT", { response, minimumParticipants: response === "going" ? 2 : null, requiredGroups: [] }, sessions.get(digit)));
  assert.equal((await ordinaryReply("2", "going")).status, 200);
  assert.equal((await ordinaryReply("4", "cant_commit")).status, 200);
  assert.equal((await read()).resolution.status, "confirmed");
  const notificationCount = await database.prepare("SELECT COUNT(*) AS n FROM resolution_notifications WHERE event_id = ?").bind(eventId).first("n");
  const operatorRequest = (body, key = operator) => api(miniflare, "/api/internal/sms-rsvp", authorizedJsonRequest("POST", body, key));
  const batchId = "78000000-0000-4000-8000-000000000201";
  const request = { action: "send", eventId, audience: "unanswered", batchId };
  assert.equal((await operatorRequest(request, "incorrect-operator-token-01234567890")).status, 401);
  for (const audience of ["all", "going", "cant_commit"]) {
    assert.equal((await operatorRequest({ ...request, audience })).status, 400);
  }
  const preview = await operatorRequest({ ...request, action: "preview" });
  assert.equal(preview.status, 200, await preview.clone().text());
  const previewBody = await preview.json();
  assert.equal(previewBody.recipientCount, 1, "neither existing yes nor existing no receives the follow-up");
  assert.match(previewBody.message, /1: I’m down\n2: Can’t come/);
  assert.match(previewBody.message, /Herd is thoughtfully designed to remove all the downsides to answering honestly/);
  assert.match(previewBody.message, /tomorrow,/);
  assert.doesNotMatch(JSON.stringify(previewBody), /phoneNumber|inviteToken|ballotId/);
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM sms_rsvp_prompts").first("n"), 0);
  const disabled = await operatorRequest(request);
  assert.equal(disabled.status, 409);
  assert.equal((await disabled.json()).error.code, "sms_rsvp_disabled");
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM sms_rsvp_prompts").first("n"), 0);
  await updateBindings({ HERD_SMS_RSVP_ENABLED: "true" });
  database = await miniflare.getD1Database("DB");
  const sent = await operatorRequest(request);
  assert.equal(sent.status, 200, await sent.clone().text());
  assert.deepEqual((await sent.json()).counts, { sent: 1 });
  assert.equal((await operatorRequest(request)).status, 200);
  const prompts = await database.prepare("SELECT invitee_id FROM sms_rsvp_prompts").all();
  assert.deepEqual(prompts.results, [{ invitee_id: guest("3").id }]);
  const incoming = (digit, body, id, overrides = {}, badSignature = false) => {
    const params = new URLSearchParams({ AccountSid: messagingAccountSid, MessageSid: `SM${id.toString(16).padStart(32, "0")}`, From: `+1415555010${digit}`, To: "+14155550999", Body: body, ...overrides });
    const canonical = "https://app.herdprivacy.com/api/webhooks/twilio/sms" + [...params.keys()].sort().map((k) => k + params.get(k)).join("");
    const signature = createHmac("sha1", badSignature ? "wrong" : "sms-webhook-auth-token").update(canonical).digest("base64");
    return api(miniflare, "/api/webhooks/twilio/sms", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-twilio-signature": signature }, body: params.toString() });
  };
  const ballotCount = () => database.prepare("SELECT COUNT(*) AS n FROM ballot_revisions WHERE event_id=?").bind(eventId).first("n");
  const before = await ballotCount();
  assert.equal((await incoming("3", "1", 1, {}, true)).status, 403);
  assert.equal((await incoming("3", "1", 2, { To: "+14155550888" })).status, 403);
  assert.equal((await incoming("3", "1", 3, { AccountSid: `AC${"9".repeat(32)}` })).status, 403);
  assert.doesNotMatch(await (await incoming("5", "1", 4)).text(), /<Message>/); // Not invited.
  assert.doesNotMatch(await (await incoming("2", "2", 5)).text(), /<Message>/); // Not prompted.
  assert.doesNotMatch(await (await incoming("3", "STOP", 6)).text(), /<Message>/);
  assert.doesNotMatch(await (await incoming("3", "1", 7, { OptOutType: "STOP" })).text(), /<Message>/);
  assert.match(await (await incoming("3", "yes", 8)).text(), /reply 1 to attend or 2/);
  assert.equal(await ballotCount(), before);
  const no = await incoming("3", "2", 9);
  assert.equal(no.status, 200, await no.clone().text());
  assert.match(await no.text(), /won&apos;t count as attending/);
  assert.equal((await read()).resolution.attendingMemberIds.length, 2);
  assert.equal((await read()).resolution.guestStates.find((g) => g.memberId === guest("3").id).status, "cant_commit");
  const yes = await incoming("3", " 1 ", 10);
  assert.equal(yes.status, 200, await yes.clone().text());
  assert.match(await yes.text(), /confirmed Going/);
  const afterYes = await read();
  assert.equal(afterYes.resolution.attendingMemberIds.length, 3);
  assert.equal(afterYes.resolution.guestStates.find((g) => g.memberId === guest("3").id).status, "going");
  const ownBallot = await api(miniflare, `/api/invites/${(await read("3")).inviteToken}/ballot`, { headers: { authorization: `Bearer ${sessions.get("3")}` } });
  assert.equal((await ownBallot.json()).ballot.response, "going", "existing web and native clients read the same saved RSVP");
  const savedCount = await ballotCount();
  // Simulate a worker stopping after saving yes but before publishing attendance.
  await database.prepare("UPDATE event_resolutions SET attending_member_ids = ? WHERE event_id = ?")
    .bind(JSON.stringify(afterYes.resolution.attendingMemberIds.filter((id) => id !== guest("3").id)), eventId).run();
  assert.match(await (await incoming("3", "2", 11)).text(), /cannot be changed to no/);
  assert.equal((await ordinaryReply("3", "cant_commit")).status, 409);
  assert.equal((await incoming("3", "2", 9)).status, 200); // An old NO cannot overwrite the newer YES.
  const concurrentRetries = await Promise.all([incoming("3", "1", 10), incoming("3", "1", 10)]);
  assert.ok(concurrentRetries.every((reply) => reply.status === 200));
  assert.equal(await ballotCount(), savedCount);
  assert.equal((await read()).resolution.attendingMemberIds.length, 3);
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM sms_rsvp_receipts").first("n"), 2);
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM resolution_notifications WHERE event_id = ?").bind(eventId).first("n"), notificationCount, "SMS replies must not broadcast another event confirmation");
  assert.equal((await ordinaryReply("4", "going")).status, 200, "earlier no remains changeable to yes in the app without another reminder");
  assert.equal((await (await operatorRequest({ ...request, action: "preview" })).json()).recipientCount, 0);
  // Another event accepting the same bare digits makes the reply ambiguous.
  const secondId = "78000000-0000-4000-8000-000000000301";
  const secondGuestId = "78000000-0000-4000-8000-000000000302";
  const second = { ...event, id: secondId, title: "Different event", invitees: [
    { ...guest("3"), id: secondGuestId },
    { ...guest("4"), id: "78000000-0000-4000-8000-000000000304" },
  ] };
  assert.equal((await api(miniflare, `/api/events/${secondId}`, authorizedJsonRequest("PUT", second, sessions.get("1")))).status, 200);
  const replyToSecond = async (digit, response) => {
    const allEvents = await api(miniflare, "/api/events", { headers: { authorization: `Bearer ${sessions.get(digit)}` } });
    const token = (await allEvents.json()).events.find((e) => e.id === secondId).inviteToken;
    return api(miniflare, `/api/invites/${token}/ballot`, authorizedJsonRequest("PUT", { response, minimumParticipants: response === "going" ? 2 : null, requiredGroups: [] }, sessions.get(digit)));
  };
  assert.equal((await replyToSecond("3", "going")).status, 200);
  const secondRequest = { ...request, eventId: secondId, batchId: "78000000-0000-4000-8000-000000000401" };
  const secondPreview = await operatorRequest({ ...secondRequest, action: "preview" });
  assert.equal((await secondPreview.json()).recipientCount, 1);
  assert.equal((await replyToSecond("4", "cant_commit")).status, 200);
  const changedSincePreview = await operatorRequest(secondRequest);
  assert.equal(changedSincePreview.status, 200);
  assert.equal((await changedSincePreview.json()).total, 0, "someone who answered after preview is excluded at send time");
  await database.prepare("INSERT INTO sms_rsvp_prompts (id,batch_id,event_id,invitee_id,status,created_at,expires_at) VALUES (?,?,?,?, 'sent',?,?)")
    .bind("ambiguous-prompt", "other-batch", secondId, secondGuestId, new Date().toISOString(), new Date(Date.now() + 3_600_000).toISOString()).run();
  assert.match(await (await incoming("3", "1", 12)).text(), /more than one event/);
  assert.equal(await ballotCount(), savedCount + 1);
  await updateBindings({ HERD_SMS_RSVP_ENABLED: "false" });
  database = await miniflare.getD1Database("DB");
  assert.doesNotMatch(await (await incoming("3", "1", 13)).text(), /<Message>/, "disabled means no automated outbound reply either");
  await updateBindings({ HERD_SMS_RSVP_ENABLED: "true" });
  database = await miniflare.getD1Database("DB");
  await database.prepare("UPDATE sms_rsvp_prompts SET expires_at=?").bind(new Date(Date.now() - 1_000).toISOString()).run();
  assert.doesNotMatch(await (await incoming("3", "1", 14)).text(), /<Message>/);
  assert.equal(await ballotCount(), savedCount + 1);
  const receipts = await database.prepare("SELECT * FROM sms_rsvp_receipts").all();
  assert.doesNotMatch(JSON.stringify(receipts.results), /phone|invitee|body|response|ballot|1415555/iu);
});

test("SMS canary sends approved copy only to the allowlisted number and creates no other notifications", async (t) => {
  const operator = "sms-canary-operator-0123456789-abcdefghijklmnopqrstuvwxyz";
  const { miniflare, sentMessages, updateBindings } = await createHarness({ bindings: { HERD_OPERATOR_TOKEN: operator } });
  t.after(() => miniflare.dispose());
  let database = await miniflare.getD1Database("DB");
  const sessions = new Map();
  for (const digit of ["1", "2", "5"]) {
    const auth = await api(miniflare, "/api/auth/request-code", jsonRequest("POST", { phoneNumber: digit }));
    sessions.set(digit, (await auth.json()).accessToken);
  }
  const sourceId = "79000000-0000-4000-8000-000000000101";
  const testId = "79000000-0000-4000-8000-000000000201";
  const source = {
    id: sourceId, title: "Volleyball", hostName: "James Woodbury",
    eventDate: new Date(Date.now() + 86_400_000).toISOString(), eventTimeZone: "America/Los_Angeles", endDate: null,
    rsvpDeadline: new Date(Date.now() + 3_600_000).toISOString(), locationName: "Dolores Park", locationAddress: "", eventDescription: "",
    minimumParticipants: 2, requiredGroups: [], invitationsSent: true, invitees: ["2", "3"].map((digit) => ({
      id: `79000000-0000-4000-8000-00000000010${digit}`, displayName: `Guest ${digit}`, phoneNumber: `+1415555010${digit}`,
    })), createdAt: new Date().toISOString(),
  };
  const created = await api(miniflare, `/api/events/${sourceId}`, authorizedJsonRequest("PUT", source, sessions.get("1")));
  assert.equal(created.status, 200, await created.clone().text());
  const read = async (digit, id) => {
    const response = await api(miniflare, "/api/events", { headers: { authorization: `Bearer ${sessions.get(digit)}` } });
    return (await response.json()).events.find((e) => e.id === id);
  };
  const second = await read("2", sourceId);
  assert.equal((await api(miniflare, `/api/invites/${second.inviteToken}/ballot`, authorizedJsonRequest("PUT", { response: "going", minimumParticipants: 2, requiredGroups: [] }, sessions.get("2")))).status, 200);
  await Promise.all(sentMessages);
  sentMessages.length = 0;
  const op = (body) => api(miniflare, "/api/internal/sms-rsvp", authorizedJsonRequest("POST", body, operator));
  const prepare = { action: "prepare_test", eventId: sourceId, testEventId: testId };
  assert.equal((await op(prepare)).status, 409, "a canary requires an explicit single-number restriction");
  await updateBindings({ HERD_SMS_RSVP_TEST_PHONE: "+14155550105" });
  database = await miniflare.getD1Database("DB");
  assert.equal((await op({ ...prepare, testEventId: sourceId })).status, 400);
  const prepared = await op(prepare);
  assert.equal(prepared.status, 200, await prepared.clone().text());
  const preview = await prepared.json();
  assert.equal(preview.recipientCount, 1);
  assert.match(preview.message, /^Thanks for trying out the eng prototype test of Herd!/);
  assert.match(preview.message, /James Woodbury’s event “Volleyball” is tomorrow,/);
  assert.match(preview.message, /1: I’m down\n2: Can’t come$/);
  assert.doesNotMatch(preview.message, /STOP|confirmed yes|SMS test/);
  assert.equal((await op(prepare)).status, 200, "canary preparation is idempotent");
  const before = await read("5", testId);
  assert.equal(before.hasBallot, false);
  assert.equal(before.invitees.length, 1);
  assert.equal(before.resolution.status, "confirmed");
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM invitation_deliveries WHERE event_id = ?").bind(testId).first("n"), 0);
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM resolution_notifications WHERE event_id = ?").bind(testId).first("n"), 0);
  assert.deepEqual(sentMessages, [], "preparing or reading a canary never sends a text");
  await updateBindings({ HERD_SMS_RSVP_ENABLED: "true" });
  database = await miniflare.getD1Database("DB");
  const sourceBatch = await op({ action: "send", eventId: sourceId, audience: "unanswered", batchId: "79000000-0000-4000-8000-000000000301" });
  assert.equal((await sourceBatch.json()).total, 0, "the restriction blocks every other unanswered guest");
  const send = { action: "send", eventId: testId, audience: "unanswered", batchId: "79000000-0000-4000-8000-000000000302", message: preview.message };
  const result = await op(send);
  assert.equal(result.status, 200, await result.clone().text());
  assert.deepEqual((await result.json()).counts, { sent: 1 });
  assert.equal((await op(send)).status, 200);
  assert.deepEqual((await Promise.all(sentMessages)).map((fields) => ({ to: fields.get("To"), body: fields.get("Body") })), [{ to: "+14155550105", body: preview.message }]);
  const incoming = (digit, sequence) => {
    const params = new URLSearchParams({ AccountSid: messagingAccountSid, MessageSid: `SM${sequence.toString(16).padStart(32, "0")}`, From: `+1415555010${digit}`, To: "+14155550999", Body: "1" });
    const canonical = "https://app.herdprivacy.com/api/webhooks/twilio/sms" + [...params.keys()].sort().map((k) => k + params.get(k)).join("");
    const signature = createHmac("sha1", "sms-webhook-auth-token").update(canonical).digest("base64");
    return api(miniflare, "/api/webhooks/twilio/sms", { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", "x-twilio-signature": signature }, body: params.toString() });
  };
  assert.doesNotMatch(await (await incoming("3", 31)).text(), /<Message>/);
  const reply = await incoming("5", 32);
  assert.equal(reply.status, 200, await reply.clone().text());
  assert.match(await reply.text(), /confirmed Going/);
  const after = await read("5", testId);
  assert.equal(after.hasBallot, true);
  assert.equal(after.resolution.attendingMemberIds.length, 2);
  assert.equal(await database.prepare("SELECT COUNT(*) AS n FROM resolution_notifications WHERE event_id = ?").bind(testId).first("n"), 0);
  assert.equal(sentMessages.length, 1, "no host or guest broadcasts are produced by the canary reply");
  assert.equal((await read("1", sourceId)).resolution.attendingMemberIds.length, 2, "the source event is unchanged");
});
