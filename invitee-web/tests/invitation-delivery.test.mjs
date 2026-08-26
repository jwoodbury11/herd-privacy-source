import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { createFetchMock, Miniflare } from "miniflare";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const testPepper = "herd-delivery-test-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const accountSid = `AC${"1".repeat(32)}`;
const apiKeySid = `SK${"2".repeat(32)}`;
const verifyServiceSid = `VA${"3".repeat(32)}`;
const messagingServiceSid = `MG${"4".repeat(32)}`;
const twilioMessagesPath = `/2010-04-01/Accounts/${accountSid}/Messages.json`;
const evaluatorPublicKey = Buffer.from(
  `04${
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
  }${"4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"}`,
  "hex",
).toString("base64url");

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

async function createHarness({ fetchMock, deliveryConfigured = true } = {}) {
  await access(path.join(serverRoot, "index.js"));
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const deliveryBindings = deliveryConfigured
    ? {
        HERD_PUBLIC_APP_URL: "https://herd.example.test",
        TWILIO_ACCOUNT_SID: accountSid,
        TWILIO_API_KEY_SID: apiKeySid,
        TWILIO_API_KEY_SECRET: "twilio-delivery-test-secret",
        TWILIO_VERIFY_SERVICE_SID: verifyServiceSid,
        TWILIO_MESSAGING_SERVICE_SID: messagingServiceSid,
      }
    : {};
  const bindings = {
    HERD_DEPLOYMENT_PROFILE: "test",
    HERD_AUTH_PEPPER: testPepper,
    HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
    HERD_TEST_ACCOUNT_ACCESS_GENERATION: "herd-test-generation-v1",
    HERD_TEST_HOST_PHONE_E164: "+14155550111",
    HERD_EVALUATOR_KEY_ID: "delivery-test-evaluator-v1",
    HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
    HERD_EVALUATOR_MEASUREMENT: "delivery-test-evaluator-measurement",
    HERD_RELEASE_ID: "delivery-test-release-v1",
    HERD_ARTIFACT_RELEASE_ID: "2026.08.12.delivery-test",
    ...deliveryBindings,
  };
  const miniflareOptions = {
    modules: modulePaths.map((modulePath) => ({ type: "ESModule", path: modulePath })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: { DB: `herd-delivery-${process.pid}-${Date.now()}-${Math.random()}` },
    ...(fetchMock ? { fetchMock } : {}),
    bindings,
  };
  const miniflare = new Miniflare(miniflareOptions);
  const database = await miniflare.getD1Database("DB");
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(path.join(migrationDirectory, migrationFile), "utf8");
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return {
    miniflare,
    database,
    async disableDelivery() {
      const nextBindings = { ...bindings };
      for (const key of Object.keys(deliveryBindings)) delete nextBindings[key];
      await miniflare.setOptions({ ...miniflareOptions, bindings: nextBindings });
    },
  };
}

function api(miniflare, pathname, init = {}) {
  return miniflare.dispatchFetch(`https://herd.test${pathname}`, init);
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

async function signIn(miniflare, alias = "1") {
  const response = await api(miniflare, "/api/auth/request-code", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ phoneNumber: alias }),
  });
  assert.equal(response.status, 200);
  return (await response.json()).accessToken;
}

function eventFixture({ eventId, invitees, invitationsSent = false }) {
  const now = Date.now();
  const eventDate = new Date(now + 14 * 86_400_000);
  return {
    id: eventId,
    title: "Delivery reliability dinner",
    eventDate: eventDate.toISOString(),
    endDate: new Date(eventDate.getTime() + 7_200_000).toISOString(),
    hostName: "Herd test Host",
    locationName: "Test kitchen",
    locationAddress: "San Francisco, CA",
    invitees,
    minimumParticipants: 2,
    requiredGroups: [],
    rsvpDeadline: new Date(now + 12 * 86_400_000).toISOString(),
    eventDescription: "Transactional invitation delivery test.",
    createdAt: new Date(now).toISOString(),
    invitationsSent,
  };
}

async function readProviderBody(body) {
  if (typeof body === "string") return body;
  if (!body || typeof body.getReader !== "function") return String(body ?? "");
  const reader = body.getReader();
  const chunks = [];
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function saveEvent(miniflare, token, event) {
  return api(
    miniflare,
    `/api/events/${event.id}`,
    authorizedJsonRequest("PUT", event, token),
  );
}

test("first Send stores an encrypted private link and returns provider-accepted delivery", async (t) => {
  const providerRequests = [];
  const providerBodyPromises = [];
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, (options) => {
      providerRequests.push(options);
      providerBodyPromises.push(readProviderBody(options.body));
      return {
        sid: `SM${"5".repeat(32)}`,
        status: "queued",
      };
    });
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare);
  const event = eventFixture({
    eventId: "91000000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "91100000-0000-4000-8000-000000000001",
        displayName: "Real delivery guest",
        phoneNumber: "+16505559001",
      },
    ],
  });
  event.eventImageID = "camping";

  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  const sentResponse = await saveEvent(miniflare, hostToken, {
    ...event,
    invitationsSent: true,
  });
  assert.equal(sentResponse.status, 200);
  const sentEvent = (await sentResponse.json()).event;
  assert.deepEqual(sentEvent.invitationDelivery, {
    status: "complete",
    total: 1,
    counts: {
      pending: 0,
      dispatching: 0,
      sent: 1,
      failed: 0,
      unknown: 0,
      suppressed: 0,
    },
    guests: [
      {
        inviteeId: event.invitees[0].id,
        displayName: event.invitees[0].displayName,
        status: "sent",
      },
    ],
  });
  assert.equal(providerRequests.length, 1);
  assert.equal(providerBodyPromises.length, 1);
  const providerHeaders = new Headers(providerRequests[0].headers);
  assert.equal(
    providerHeaders.get("authorization"),
    `Basic ${Buffer.from(`${apiKeySid}:twilio-delivery-test-secret`).toString("base64")}`,
  );
  assert.match(
    providerHeaders.get("content-type") ?? "",
    /^application\/x-www-form-urlencoded/u,
  );
  const providerBody = new URLSearchParams(await providerBodyPromises[0]);
  assert.equal(providerBody.get("To"), event.invitees[0].phoneNumber);
  assert.equal(providerBody.get("MessagingServiceSid"), messagingServiceSid);
  const message = providerBody.get("Body") ?? "";
  assert.match(message, /^A plan is taking shape on Herd: Delivery reliability dinner — /u);
  assert.match(
    message,
    /\. Herd test Host included you\. Open the invitation and reply privately\. One-time message sent at the host’s request\. Reply STOP to opt out; HELP for help\. Msg & data rates may apply\.\nhttps:\/\/herd\.example\.test\/invite\/[A-Za-z0-9_-]{43}$/u,
  );
  const invitationToken = message.match(/\/invite\/([A-Za-z0-9_-]{43})\./u)?.[1];
  assert.ok(invitationToken);

  const tokenRow = await database
    .prepare(
      `SELECT token_hash AS tokenHash, token_ciphertext AS tokenCiphertext,
              token_nonce AS tokenNonce, token_storage_version AS tokenStorageVersion
       FROM invitees WHERE id = ?`,
    )
    .bind(event.invitees[0].id)
    .first();
  assert.equal(tokenRow.tokenStorageVersion, 1);
  assert.notEqual(tokenRow.tokenHash, invitationToken);
  assert.notEqual(tokenRow.tokenCiphertext, invitationToken);
  assert.equal(tokenRow.tokenNonce.length, 16);
  const privatePreview = await api(
    miniflare,
    `/api/invites/${encodeURIComponent(invitationToken)}`,
  );
  assert.equal(privatePreview.status, 401);
  const richPreview = await api(
    miniflare,
    `/invite/${encodeURIComponent(invitationToken)}`,
  );
  assert.equal(richPreview.status, 200);
  const richPreviewHTML = await richPreview.text();
  assert.match(richPreviewHTML, /Delivery reliability dinner/u);
  assert.match(richPreviewHTML, /Reply privately\. Plan honestly\./u);
  assert.match(
    richPreviewHTML,
    /https:\/\/herd\.example\.test\/link-previews\/camping\.png/u,
  );
  assert.doesNotMatch(richPreviewHTML, /Real delivery guest/u);
  assert.doesNotMatch(richPreviewHTML, /\+16505559001/u);
  assert.doesNotMatch(richPreviewHTML, /Transactional invitation delivery test/u);
  assert.doesNotMatch(richPreviewHTML, /91100000-0000-4000-8000-000000000001/u);
  assert.equal(JSON.stringify(sentEvent.invitationDelivery).includes(invitationToken), false);
  assert.equal(JSON.stringify(sentEvent.invitationDelivery).includes(accountSid), false);
});

test("definitive rejection is failed and an exact PUT retry never sends twice", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(400, () => {
      providerCalls += 1;
      return { code: 21_610, message: "Recipient opted out" };
    });
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare);
  const event = eventFixture({
    eventId: "92000000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "92100000-0000-4000-8000-000000000001",
        displayName: "Opted-out guest",
        phoneNumber: "+16505559002",
      },
    ],
  });
  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  const sentPayload = { ...event, invitationsSent: true };
  const firstSend = await saveEvent(miniflare, hostToken, sentPayload);
  assert.equal(firstSend.status, 200);
  assert.equal((await firstSend.json()).event.invitationDelivery.status, "attention_needed");
  const exactRetry = await saveEvent(miniflare, hostToken, sentPayload);
  assert.equal(exactRetry.status, 200);
  const retryEvent = (await exactRetry.json()).event;
  assert.equal(retryEvent.invitationDelivery.guests[0].status, "failed");
  assert.equal(providerCalls, 1);
  const stored = await database
    .prepare(
      `SELECT COUNT(*) AS count, MAX(attempt_count) AS attempts,
              MAX(status) AS status, MAX(provider_message_sid) AS providerMessageSid
       FROM invitation_deliveries WHERE event_id = ?`,
    )
    .bind(event.id)
    .first();
  assert.equal(stored.count, 1);
  assert.equal(stored.attempts, 1);
  assert.equal(stored.status, "failed");
  assert.equal(stored.providerMessageSid, null);
});

test("ambiguous provider failure becomes unknown and is not automatically retried", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(503, () => {
      providerCalls += 1;
      return { code: 30_000, message: "Temporary provider failure" };
    });
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare);
  const event = eventFixture({
    eventId: "93000000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "93100000-0000-4000-8000-000000000001",
        displayName: "Ambiguous guest",
        phoneNumber: "+16505559003",
      },
    ],
  });
  const sentPayload = { ...event, invitationsSent: true };
  const response = await saveEvent(miniflare, hostToken, sentPayload);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).event.invitationDelivery.guests[0].status, "unknown");
  assert.equal((await saveEvent(miniflare, hostToken, sentPayload)).status, 200);
  assert.equal(providerCalls, 1);
  const delivery = await database
    .prepare(
      `SELECT status, attempt_count AS attempts, last_error_code AS errorCode
       FROM invitation_deliveries WHERE event_id = ?`,
    )
    .bind(event.id)
    .first();
  assert.equal(delivery.status, "unknown");
  assert.equal(delivery.attempts, 1);
  assert.equal(delivery.errorCode, "30000");
});

test("simultaneous Send transitions create one outbox row and one provider request", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, () => {
      providerCalls += 1;
      return { sid: `SM${"6".repeat(32)}`, status: "queued" };
    })
    .delay(40);
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare);
  const event = eventFixture({
    eventId: "94000000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "94100000-0000-4000-8000-000000000001",
        displayName: "Race guest",
        phoneNumber: "+16505559004",
      },
    ],
  });
  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  const sentPayload = { ...event, invitationsSent: true };
  const [left, right] = await Promise.all([
    saveEvent(miniflare, hostToken, sentPayload),
    saveEvent(miniflare, hostToken, sentPayload),
  ]);
  assert.deepEqual([left.status, right.status].sort(), [200, 200]);
  assert.equal(providerCalls, 1);
  const outbox = await database
    .prepare(
      `SELECT COUNT(*) AS count, SUM(attempt_count) AS attempts,
              MAX(status) AS status
       FROM invitation_deliveries WHERE event_id = ?`,
    )
    .bind(event.id)
    .first();
  assert.equal(outbox.count, 1);
  assert.equal(outbox.attempts, 1);
  assert.equal(outbox.status, "sent");
});

test("concurrent exact retries drain an interrupted pending delivery exactly once", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, () => {
      providerCalls += 1;
      return { sid: `SM${"7".repeat(32)}`, status: "queued" };
    })
    .delay(40)
    .persist();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare, "1");
  const event = eventFixture({
    eventId: "94500000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "94600000-0000-4000-8000-000000000001",
        displayName: "Interrupted delivery guest",
        phoneNumber: "+14155550102",
      },
    ],
    invitationsSent: true,
  });

  const firstSend = await saveEvent(miniflare, hostToken, event);
  assert.equal(firstSend.status, 200);
  assert.equal((await firstSend.json()).event.invitationDelivery.status, "complete");
  assert.equal(providerCalls, 1);

  // Model a worker interruption after the event, policy, and durable outbox commit,
  // but before the pending delivery was claimed for dispatch.
  const interrupted = await database
    .prepare(
      `UPDATE invitation_deliveries
       SET status = 'pending', attempt_count = 0, provider_message_sid = NULL,
           dispatch_started_at = NULL, updated_at = ?
       WHERE event_id = ? AND invitee_id = ? AND status = 'sent'`,
    )
    .bind(new Date().toISOString(), event.id, event.invitees[0].id)
    .run();
  assert.equal(interrupted.meta.changes, 1);
  providerCalls = 0;

  const [left, right] = await Promise.all([
    saveEvent(miniflare, hostToken, event),
    saveEvent(miniflare, hostToken, event),
  ]);
  assert.deepEqual([left.status, right.status], [200, 200]);

  const settledRetry = await saveEvent(miniflare, hostToken, event);
  assert.equal(settledRetry.status, 200);
  const settledEvent = (await settledRetry.json()).event;
  assert.equal(settledEvent.invitationDelivery.status, "complete");
  assert.equal(settledEvent.invitationDelivery.guests[0].status, "sent");
  assert.equal(providerCalls, 1);

  const outbox = await database
    .prepare(
      `SELECT status, attempt_count AS attempts, provider_message_sid AS providerMessageSid
       FROM invitation_deliveries WHERE event_id = ? AND invitee_id = ?`,
    )
    .bind(event.id, event.invitees[0].id)
    .first();
  assert.equal(outbox.status, "sent");
  assert.equal(outbox.attempts, 1);
  assert.equal(outbox.providerMessageSid, `SM${"7".repeat(32)}`);
});

test("an exact retry drains pending delivery using the stored frozen release", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, () => {
      providerCalls += 1;
      return { sid: `SM${"8".repeat(32)}`, status: "queued" };
    })
    .persist();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare, "1");
  const event = eventFixture({
    eventId: "94200000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "94300000-0000-4000-8000-000000000001",
        displayName: "Cross-release recovery guest",
        phoneNumber: "+14155550102",
      },
    ],
    invitationsSent: true,
  });
  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  providerCalls = 0;

  const storedPolicy = await database
    .prepare(
      `SELECT canonical_document AS canonicalDocument
       FROM event_policies WHERE event_id = ?`,
    )
    .bind(event.id)
    .first();
  const frozenDocument = JSON.parse(storedPolicy.canonicalDocument);
  frozenDocument.evaluator.keyId = "delivery-test-evaluator-previous-release";
  frozenDocument.evaluator.measurement = "delivery-test-previous-measurement";
  frozenDocument.releaseId = "delivery-test-previous-release";
  const canonicalDocument = JSON.stringify(frozenDocument);
  const policyHash = createHash("sha256")
    .update(canonicalDocument)
    .digest("base64url");
  await database.batch([
    database
      .prepare(
        `UPDATE event_policies
         SET canonical_document = ?, policy_hash = ?, evaluator_key_id = ?,
             evaluator_measurement = ?, release_id = ?
         WHERE event_id = ?`,
      )
      .bind(
        canonicalDocument,
        policyHash,
        frozenDocument.evaluator.keyId,
        frozenDocument.evaluator.measurement,
        frozenDocument.releaseId,
        event.id,
      ),
    database
      .prepare("UPDATE event_resolutions SET policy_hash = ? WHERE event_id = ?")
      .bind(policyHash, event.id),
    database
      .prepare(
        `UPDATE invitation_deliveries
         SET status = 'pending', attempt_count = 0, provider_message_sid = NULL,
             dispatch_started_at = NULL, updated_at = ?
         WHERE event_id = ? AND invitee_id = ? AND status = 'sent'`,
      )
      .bind(new Date().toISOString(), event.id, event.invitees[0].id),
  ]);

  const retry = await saveEvent(miniflare, hostToken, event);
  assert.equal(retry.status, 200);
  const recoveredEvent = (await retry.json()).event;
  assert.equal(
    recoveredEvent.privateResponsePolicy.evaluatorKeyId,
    frozenDocument.evaluator.keyId,
  );
  assert.equal(recoveredEvent.invitationDelivery.guests[0].status, "sent");
  assert.equal(providerCalls, 1);
});

test("missing messaging configuration leaves interrupted delivery pending", async (t) => {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, { sid: `SM${"6".repeat(32)}`, status: "queued" });
  const { miniflare, database: initialDatabase, disableDelivery } = await createHarness({ fetchMock });
  let database = initialDatabase;
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare, "1");
  const event = eventFixture({
    eventId: "94900000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "94910000-0000-4000-8000-000000000001",
        displayName: "Configuration recovery guest",
        phoneNumber: "+14155550102",
      },
    ],
    invitationsSent: true,
  });
  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  await disableDelivery();
  database = await miniflare.getD1Database("DB");
  await database
    .prepare(
      `UPDATE invitation_deliveries
       SET status = 'pending', attempt_count = 0, provider_message_sid = NULL,
           dispatch_started_at = NULL, updated_at = ?
       WHERE event_id = ? AND invitee_id = ? AND status = 'sent'`,
    )
    .bind(new Date().toISOString(), event.id, event.invitees[0].id)
    .run();

  for (let attempt = 0; attempt < 2; attempt += 1) {
    const retry = await saveEvent(miniflare, hostToken, event);
    assert.equal(retry.status, 503);
    assert.equal(
      (await retry.json()).error.code,
      "invitation_delivery_unavailable",
    );
  }
  const delivery = await database
    .prepare(
      `SELECT status, attempt_count AS attempts, dispatch_started_at AS dispatchStartedAt,
              last_error_code AS errorCode
       FROM invitation_deliveries WHERE event_id = ? AND invitee_id = ?`,
    )
    .bind(event.id, event.invitees[0].id)
    .first();
  assert.equal(delivery.status, "pending");
  assert.equal(delivery.attempts, 0);
  assert.equal(delivery.dispatchStartedAt, null);
  assert.equal(delivery.errorCode, null);
});

test("an interrupted delivery is not sent after its reply deadline", async (t) => {
  let providerCalls = 0;
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({ method: "POST", path: twilioMessagesPath })
    .reply(201, () => {
      providerCalls += 1;
      return { sid: `SM${"3".repeat(32)}`, status: "queued" };
    })
    .persist();
  const { miniflare, database } = await createHarness({ fetchMock });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare, "1");
  const rsvpDeadline = new Date(Date.now() + 2_000).toISOString();
  const event = {
    ...eventFixture({
      eventId: "94700000-0000-4000-8000-000000000001",
      invitees: [
        {
          id: "94800000-0000-4000-8000-000000000001",
          displayName: "Late interrupted guest",
          phoneNumber: "+14155550102",
        },
      ],
      invitationsSent: true,
    }),
    rsvpDeadline,
  };

  const firstSend = await saveEvent(miniflare, hostToken, event);
  assert.equal(firstSend.status, 200);
  assert.equal(providerCalls, 1);
  await database
    .prepare(
      `UPDATE invitation_deliveries
       SET status = 'pending', attempt_count = 0, provider_message_sid = NULL,
           dispatch_started_at = NULL, last_error_code = NULL, updated_at = ?
       WHERE event_id = ? AND invitee_id = ? AND status = 'sent'`,
    )
    .bind(new Date().toISOString(), event.id, event.invitees[0].id)
    .run();

  await new Promise((resolve) =>
    setTimeout(resolve, Math.max(0, Date.parse(rsvpDeadline) - Date.now() + 25)),
  );
  const retry = await saveEvent(miniflare, hostToken, event);
  assert.equal(retry.status, 200);
  const retryEvent = (await retry.json()).event;
  assert.equal(retryEvent.invitationDelivery.status, "attention_needed");
  assert.equal(retryEvent.invitationDelivery.guests[0].status, "failed");
  assert.equal(providerCalls, 1);

  const delivery = await database
    .prepare(
      `SELECT status, attempt_count AS attempts, provider_message_sid AS providerMessageSid,
              last_error_code AS errorCode
       FROM invitation_deliveries WHERE event_id = ? AND invitee_id = ?`,
    )
    .bind(event.id, event.invitees[0].id)
    .first();
  assert.equal(delivery.status, "failed");
  assert.equal(delivery.attempts, 1);
  assert.equal(delivery.providerMessageSid, null);
  assert.equal(delivery.errorCode, "rsvp_closed_before_delivery");
});

test("a real-recipient Send fails closed before freezing when messaging is not configured", async (t) => {
  const { miniflare, database } = await createHarness({ deliveryConfigured: false });
  t.after(() => miniflare.dispose());
  const hostToken = await signIn(miniflare);
  const event = eventFixture({
    eventId: "96000000-0000-4000-8000-000000000001",
    invitees: [
      {
        id: "96100000-0000-4000-8000-000000000001",
        displayName: "Configuration check guest",
        phoneNumber: "+16505559006",
      },
    ],
  });
  assert.equal((await saveEvent(miniflare, hostToken, event)).status, 200);
  const response = await saveEvent(miniflare, hostToken, {
    ...event,
    invitationsSent: true,
  });
  assert.equal(response.status, 503);
  assert.equal((await response.json()).error.code, "invitation_delivery_unavailable");
  const persisted = await database
    .prepare(
      `SELECT invitations_sent AS invitationsSent,
              (SELECT COUNT(*) FROM event_policies WHERE event_id = events.id) AS policies,
              (SELECT COUNT(*) FROM invitation_deliveries WHERE event_id = events.id) AS deliveries
       FROM events WHERE id = ?`,
    )
    .bind(event.id)
    .first();
  assert.equal(persisted.invitationsSent, 0);
  assert.equal(persisted.policies, 0);
  assert.equal(persisted.deliveries, 0);
});
