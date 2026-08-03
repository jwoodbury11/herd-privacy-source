import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import ts from "typescript";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const confirmationPhrase = "RESET_NINE_QA_KEYS_AND_CREATE_TWO_LIVE_EVENTS";
const maximumResponseBytes = 2 * 1024 * 1024;
const requestTimeoutMilliseconds = 15_000;
const pollingIntervalMilliseconds = 5_000;
const submissionSafetyMarginMilliseconds = 15_000;
const qaInviteePhones = Array.from(
  { length: 9 },
  (_, index) => `+1415555010${index + 1}`,
);

class SmokeFailure extends Error {
  constructor(message) {
    super(message);
    this.name = "SmokeFailure";
  }
}

function ensure(condition, message) {
  if (!condition) throw new SmokeFailure(message);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function requiredEnvironmentValue(name, failureMessage) {
  const value = process.env[name]?.trim();
  ensure(Boolean(value), failureMessage);
  return value;
}

function boundedEnvironmentInteger(name, fallback, minimum, maximum) {
  const raw = process.env[name]?.trim();
  if (!raw) return fallback;
  ensure(/^\d+$/u.test(raw), `${name} must be a whole number.`);
  const value = Number(raw);
  ensure(
    Number.isSafeInteger(value) && value >= minimum && value <= maximum,
    `${name} must be between ${minimum} and ${maximum}.`,
  );
  return value;
}

function canonicalBase64UrlBytes(value, expectedLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/u.test(value)) return null;
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length !== expectedLength || bytes.toString("base64url") !== value) {
      return null;
    }
    return bytes;
  } catch {
    return null;
  }
}

function isUuid(value) {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    )
  );
}

function isCanonicalIsoTimestamp(value) {
  if (typeof value !== "string") return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function exactKeys(value, expectedKeys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function arraysEqual(left, right) {
  return (
    Array.isArray(left) &&
    Array.isArray(right) &&
    left.length === right.length &&
    left.every((value, index) => value === right[index])
  );
}

function assertNoPrivateResponseLeak(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new SmokeFailure("An event projection could not be inspected safely.");
  }
  for (const forbidden of [
    '"payloadCiphertext"',
    '"userKeyWrap"',
    '"evaluatorKeyWrap"',
    '"ciphertextHash"',
    '"envelopeHash"',
    '"batchHash"',
    '"evaluationRequestHash"',
    '"responseEnvelope"',
    '"response":"going"',
    '"response":"cant_commit"',
  ]) {
    ensure(
      !serialized.includes(forbidden),
      "A private response field leaked into an event projection.",
    );
  }
}

function assertInviteePhonePrivacy(value) {
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new SmokeFailure("An invitee projection could not be inspected safely.");
  }
  ensure(
    !serialized.includes('"phoneNumber"') &&
      qaInviteePhones.every((phoneNumber) => !serialized.includes(phoneNumber)),
    "An invitee projection exposed a guest phone number.",
  );
}

function validateNodeVersion() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  ensure(
    major > 22 || (major === 22 && minor >= 13),
    "This smoke test requires Node.js 22.13 or newer.",
  );
}

function loadConfiguration() {
  validateNodeVersion();
  ensure(
    process.env.HERD_LIVE_CONFIRMED_TRANSPORT?.trim() === "client_relay",
    "Independently verify the deployed HERD_EVALUATOR_TRANSPORT, then set HERD_LIVE_CONFIRMED_TRANSPORT=client_relay.",
  );

  const rawOrigin = requiredEnvironmentValue(
    "HERD_LIVE_ORIGIN",
    "HERD_LIVE_ORIGIN is required.",
  );
  let parsedOrigin;
  try {
    parsedOrigin = new URL(rawOrigin);
  } catch {
    throw new SmokeFailure("HERD_LIVE_ORIGIN must be a valid HTTPS origin.");
  }
  ensure(
    parsedOrigin.protocol === "https:" &&
      !parsedOrigin.username &&
      !parsedOrigin.password &&
      !parsedOrigin.search &&
      !parsedOrigin.hash &&
      (parsedOrigin.pathname === "/" || parsedOrigin.pathname === ""),
    "HERD_LIVE_ORIGIN must be a bare HTTPS origin with no credentials, path, query, or hash.",
  );
  const runNonce = requiredEnvironmentValue(
    "HERD_LIVE_RUN_NONCE",
    "HERD_LIVE_RUN_NONCE is required.",
  );
  ensure(isUuid(runNonce), "HERD_LIVE_RUN_NONCE must be a UUID.");
  const expectedConfirmation = `${confirmationPhrase}:${parsedOrigin.hostname}:${runNonce}`;
  ensure(
    process.env.HERD_LIVE_SCHEDULER_SMOKE_CONFIRM === expectedConfirmation,
    `Set HERD_LIVE_SCHEDULER_SMOKE_CONFIRM=${expectedConfirmation} to authorize this host-bound run, nine shared-QA key resets, and two live QA events.`,
  );

  const hostPhone = requiredEnvironmentValue(
    "HERD_LIVE_QA_HOST_PHONE",
    "HERD_LIVE_QA_HOST_PHONE is required.",
  );
  ensure(
    /^\+1\d{3}55501\d{2}$/u.test(hostPhone) && !qaInviteePhones.includes(hostPhone),
    "HERD_LIVE_QA_HOST_PHONE must be a distinct fictional +1 NXX-555-01XX QA number.",
  );

  const evaluatorKeyId = requiredEnvironmentValue(
    "HERD_LIVE_EVALUATOR_KEY_ID",
    "HERD_LIVE_EVALUATOR_KEY_ID is required.",
  );
  ensure(
    /^[A-Za-z0-9._:-]{1,160}$/u.test(evaluatorKeyId),
    "HERD_LIVE_EVALUATOR_KEY_ID is invalid.",
  );
  const evaluatorPublicKey = requiredEnvironmentValue(
    "HERD_LIVE_EVALUATOR_PUBLIC_KEY",
    "HERD_LIVE_EVALUATOR_PUBLIC_KEY is required.",
  );
  const evaluatorPublicKeyBytes = canonicalBase64UrlBytes(evaluatorPublicKey, 65);
  ensure(
    evaluatorPublicKeyBytes?.[0] === 0x04,
    "HERD_LIVE_EVALUATOR_PUBLIC_KEY must be a canonical uncompressed P-256 public key.",
  );
  const evaluatorMeasurement = requiredEnvironmentValue(
    "HERD_LIVE_EVALUATOR_MEASUREMENT",
    "HERD_LIVE_EVALUATOR_MEASUREMENT is required.",
  );
  ensure(
    /^[A-Za-z0-9._:-]{1,500}$/u.test(evaluatorMeasurement),
    "HERD_LIVE_EVALUATOR_MEASUREMENT is invalid.",
  );
  const policySigningKeyId = requiredEnvironmentValue(
    "HERD_LIVE_POLICY_SIGNING_KEY_ID",
    "HERD_LIVE_POLICY_SIGNING_KEY_ID is required.",
  );
  ensure(
    /^[A-Za-z0-9._:-]{1,160}$/u.test(policySigningKeyId),
    "HERD_LIVE_POLICY_SIGNING_KEY_ID is invalid.",
  );
  const policySigningPublicKey = requiredEnvironmentValue(
    "HERD_LIVE_POLICY_SIGNING_PUBLIC_KEY",
    "HERD_LIVE_POLICY_SIGNING_PUBLIC_KEY is required.",
  );
  const policySigningPublicKeyBytes = canonicalBase64UrlBytes(
    policySigningPublicKey,
    65,
  );
  ensure(
    policySigningPublicKeyBytes?.[0] === 0x04,
    "HERD_LIVE_POLICY_SIGNING_PUBLIC_KEY must be a canonical uncompressed P-256 public key.",
  );
  const releaseId = requiredEnvironmentValue(
    "HERD_LIVE_RELEASE_ID",
    "HERD_LIVE_RELEASE_ID is required.",
  );
  ensure(
    /^[A-Za-z0-9._:-]{1,200}$/u.test(releaseId),
    "HERD_LIVE_RELEASE_ID is invalid.",
  );
  const resultSigningKeyId = requiredEnvironmentValue(
    "HERD_LIVE_RESULT_SIGNING_KEY_ID",
    "HERD_LIVE_RESULT_SIGNING_KEY_ID is required.",
  );
  ensure(
    /^[A-Za-z0-9._:-]{1,160}$/u.test(resultSigningKeyId),
    "HERD_LIVE_RESULT_SIGNING_KEY_ID is invalid.",
  );
  const resultSigningPublicKey = requiredEnvironmentValue(
    "HERD_LIVE_RESULT_SIGNING_PUBLIC_KEY",
    "HERD_LIVE_RESULT_SIGNING_PUBLIC_KEY is required.",
  );
  ensure(
    canonicalBase64UrlBytes(resultSigningPublicKey, 65)?.[0] === 0x04,
    "HERD_LIVE_RESULT_SIGNING_PUBLIC_KEY must be a canonical uncompressed P-256 public key.",
  );

  return {
    origin: parsedOrigin.origin,
    hostPhone,
    evaluatorKeyId,
    evaluatorPublicKey,
    evaluatorMeasurement,
    policySigningKeyId,
    policySigningPublicKey,
    releaseId,
    resultSigningKeyId,
    resultSigningPublicKey,
    deadlineSeconds: boundedEnvironmentInteger(
      "HERD_LIVE_DEADLINE_SECONDS",
      150,
      90,
      600,
    ),
    resolutionTimeoutSeconds: boundedEnvironmentInteger(
      "HERD_LIVE_RESOLUTION_TIMEOUT_SECONDS",
      480,
      60,
      600,
    ),
  };
}

async function readBoundedJson(response, label) {
  const contentType = response.headers.get("content-type")?.toLowerCase() ?? "";
  ensure(
    /^application\/json(?:\s*;|$)/u.test(contentType),
    `${label} returned a non-JSON response.`,
  );
  const contentLength = response.headers.get("content-length");
  if (contentLength && /^\d+$/u.test(contentLength)) {
    ensure(
      Number(contentLength) <= maximumResponseBytes,
      `${label} returned an oversized response.`,
    );
  }
  ensure(Boolean(response.body), `${label} returned an empty response.`);

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let size = 0;
  let text = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumResponseBytes) {
        await reader.cancel();
        throw new SmokeFailure(`${label} returned an oversized response.`);
      }
      text += decoder.decode(value, { stream: true });
    }
    text += decoder.decode();
  } catch (error) {
    if (error instanceof SmokeFailure) throw error;
    throw new SmokeFailure(`${label} returned unreadable JSON.`);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new SmokeFailure(`${label} returned malformed JSON.`);
  }
}

function createLiveApi(origin) {
  let mutationsClosed = false;

  function requestIsAllowed(pathname, method) {
    if (method === "GET" && pathname === "/api/events") return true;
    if (
      method === "GET" &&
      /^\/api\/invites\/[A-Za-z0-9_-]{8,200}$/u.test(pathname)
    ) {
      return true;
    }
    if (method === "POST" && pathname === "/api/auth/request-code") return true;
    if (
      method === "POST" &&
      [
        "/api/account/key-epoch/reset",
        "/api/account/key-epoch/initialize",
      ].includes(pathname)
    ) {
      return true;
    }
    if (method === "PUT" && /^\/api\/events\/[0-9a-f-]{36}$/u.test(pathname)) {
      return true;
    }
    return (
      method === "PUT" &&
      /^\/api\/invites\/[A-Za-z0-9_-]{8,200}\/rsvp$/u.test(pathname)
    );
  }

  return {
    closeMutations() {
      mutationsClosed = true;
    },

    async request(
      pathname,
      { method = "GET", token, body, label, expectedError = null },
    ) {
      ensure(typeof label === "string" && label.length > 0, "A request label is missing.");
      ensure(
        expectedError === null ||
          (isRecord(expectedError) &&
            Number.isInteger(expectedError.status) &&
            expectedError.status >= 400 &&
            expectedError.status <= 599 &&
            typeof expectedError.code === "string" &&
            /^[a-z0-9_]{1,80}$/u.test(expectedError.code)),
        "An expected live error contract is invalid.",
      );
      ensure(
        requestIsAllowed(pathname, method),
        "The live smoke test blocked an endpoint outside its allowlist.",
      );
      if (mutationsClosed) {
        ensure(
          method === "GET" && pathname === "/api/events" && body === undefined,
          "The live smoke test blocked a mutation after clients went offline.",
        );
      }

      const target = new URL(pathname, `${origin}/`);
      ensure(
        target.origin === origin && !target.search && !target.hash,
        "The live smoke test blocked a cross-origin request.",
      );
      const headers = new Headers({ accept: "application/json" });
      if (token) headers.set("authorization", `Bearer ${token}`);
      const isMutation = method !== "GET";
      if (isMutation) {
        headers.set("content-type", "application/json");
        headers.set("origin", origin);
      }

      let response;
      try {
        response = await fetch(target, {
          method,
          headers,
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
          cache: "no-store",
          credentials: "omit",
          redirect: "manual",
          signal: AbortSignal.timeout(requestTimeoutMilliseconds),
        });
      } catch {
        throw new SmokeFailure(`${label} could not reach the live QA service.`);
      }

      let payload;
      try {
        payload = await readBoundedJson(response, label);
      } catch (error) {
        if (!response.ok) {
          throw new SmokeFailure(`${label} failed (HTTP ${response.status}).`);
        }
        throw error;
      }
      const code =
        isRecord(payload) &&
        isRecord(payload.error) &&
        typeof payload.error.code === "string" &&
        /^[a-z0-9_]{1,80}$/u.test(payload.error.code)
          ? payload.error.code
          : null;
      if (expectedError !== null) {
        ensure(
          response.status === expectedError.status && code === expectedError.code,
          `${label} did not return the exact expected failure.`,
        );
        return payload;
      }
      if (!response.ok) {
        throw new SmokeFailure(
          `${label} failed (HTTP ${response.status}${code ? `, ${code}` : ""}).`,
        );
      }
      ensure(isRecord(payload), `${label} returned an invalid JSON object.`);
      return payload;
    },
  };
}

async function transpilePrivacyModule(
  temporaryDirectory,
  sourceName,
  outputName,
  replacements = [],
) {
  let source = await readFile(path.join(projectRoot, sourceName), "utf8");
  for (const [pattern, replacement] of replacements) {
    ensure(pattern.test(source), "A local privacy module import could not be prepared.");
    source = source.replace(pattern, replacement);
  }
  const result = ts.transpileModule(source, {
    compilerOptions: {
      isolatedModules: true,
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
    fileName: sourceName,
    reportDiagnostics: true,
  });
  ensure(
    !(result.diagnostics ?? []).some(
      ({ category }) => category === ts.DiagnosticCategory.Error,
    ),
    "A local privacy module could not be compiled.",
  );
  await writeFile(path.join(temporaryDirectory, outputName), result.outputText, {
    mode: 0o600,
  });
}

async function loadPrivacyModules(config, temporaryDirectory) {
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID = config.evaluatorKeyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY = config.evaluatorPublicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID =
    config.policySigningKeyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
    config.policySigningPublicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID =
    config.resultSigningKeyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY =
    config.resultSigningPublicKey;

  await transpilePrivacyModule(
    temporaryDirectory,
    "lib/privacy/protocol.ts",
    "protocol.mjs",
  );
  const protocolImportReplacement = [
    [/from "\.\/protocol";/u, 'from "./protocol.mjs";'],
  ];
  await transpilePrivacyModule(
    temporaryDirectory,
    "lib/privacy/private-response-crypto.ts",
    "private-response-crypto.mjs",
    [
      ...protocolImportReplacement,
      [/from "\.\/trust-verification";/u, 'from "./trust-verification.mjs";'],
    ],
  );
  await transpilePrivacyModule(
    temporaryDirectory,
    "lib/privacy/trust-verification.ts",
    "trust-verification.mjs",
    protocolImportReplacement,
  );
  await transpilePrivacyModule(
    temporaryDirectory,
    "lib/privacy/device-vault.ts",
    "device-vault.mjs",
    protocolImportReplacement,
  );
  await transpilePrivacyModule(
    temporaryDirectory,
    "lib/privacy/event-resolution-proof.ts",
    "event-resolution-proof.mjs",
    protocolImportReplacement,
  );

  const cacheKey = `live-smoke-${Date.now()}`;
  const vault = await import(
    `${pathToFileURL(path.join(temporaryDirectory, "device-vault.mjs")).href}?${cacheKey}`
  );
  const responseCrypto = await import(
    `${pathToFileURL(path.join(temporaryDirectory, "private-response-crypto.mjs")).href}?${cacheKey}`
  );
  const eventResolutionProof = await import(
    `${pathToFileURL(path.join(temporaryDirectory, "event-resolution-proof.mjs")).href}?${cacheKey}`
  );
  ensure(
    typeof vault.accountRootSecretCommitment === "function" &&
      typeof responseCrypto.sealPrivateResponse === "function",
    "The local privacy modules are missing required functions.",
  );
  return { vault, responseCrypto, eventResolutionProof };
}

function validateAuthenticatedSession(payload, expectedPhone) {
  ensure(
    typeof payload.accessToken === "string" &&
      canonicalBase64UrlBytes(payload.accessToken, 32) !== null,
    "QA bypass did not return a direct authenticated session.",
  );
  ensure(isUuid(payload.accountKeyEpochId), "A QA account returned an invalid key epoch.");
  ensure(
    payload.accountKeyCommitment === null ||
      canonicalBase64UrlBytes(payload.accountKeyCommitment, 32) !== null,
    "A QA account returned an invalid key commitment.",
  );
  ensure(
    isRecord(payload.user) &&
      typeof payload.user.id === "string" &&
      payload.user.id.length > 0 &&
      payload.user.phoneNumber === expectedPhone,
    "QA bypass authenticated an unexpected account.",
  );
  return {
    accessToken: payload.accessToken,
    userId: payload.user.id,
    accountKeyEpochId: payload.accountKeyEpochId,
    accountKeyCommitment: payload.accountKeyCommitment,
  };
}

async function authenticateQaAccount(api, phoneInput, expectedPhone, label) {
  const payload = await api.request("/api/auth/request-code", {
    method: "POST",
    body: { phoneNumber: phoneInput },
    label,
  });
  return validateAuthenticatedSession(payload, expectedPhone);
}

async function prepareFreshInviteeKey(api, vault, session, rootSecrets) {
  const rootSecret = globalThis.crypto.getRandomValues(new Uint8Array(32));
  rootSecrets.push(rootSecret);
  let accountKeyEpochId = session.accountKeyEpochId;

  if (session.accountKeyCommitment !== null) {
    const reset = await api.request("/api/account/key-epoch/reset", {
      method: "POST",
      token: session.accessToken,
      body: { expectedAccountKeyEpochId: accountKeyEpochId },
      label: "QA key reset",
    });
    ensure(
      isUuid(reset.accountKeyEpochId) && reset.accountKeyEpochId !== accountKeyEpochId,
      "A QA key reset returned an invalid epoch.",
    );
    accountKeyEpochId = reset.accountKeyEpochId;
  }

  let keyCommitment;
  try {
    keyCommitment = await vault.accountRootSecretCommitment(rootSecret);
  } catch {
    throw new SmokeFailure("A fresh local QA key could not be committed.");
  }
  ensure(
    canonicalBase64UrlBytes(keyCommitment, 32) !== null,
    "A fresh local QA key produced an invalid commitment.",
  );
  const initialized = await api.request("/api/account/key-epoch/initialize", {
    method: "POST",
    token: session.accessToken,
    body: {
      expectedAccountKeyEpochId: accountKeyEpochId,
      keyCommitment,
    },
    label: "QA key initialization",
  });
  ensure(
    initialized.accountKeyEpochId === accountKeyEpochId &&
      initialized.keyCommitment === keyCommitment,
    "A QA key initialization returned an unexpected result.",
  );
  session.accountKeyEpochId = accountKeyEpochId;
  session.accountKeyCommitment = keyCommitment;
  return rootSecret;
}

function createInvitees() {
  return qaInviteePhones.map((phoneNumber, index) => ({
    id: randomUUID(),
    displayName: `QA account ${index + 1}`,
    phoneNumber,
  }));
}

function buildEventPayload({
  id,
  title,
  invitees,
  minimumParticipants,
  requiredGroups,
  deadline,
  eventDate,
}) {
  return {
    id,
    title,
    eventDate,
    endDate: null,
    hostName: "Scheduler smoke QA host",
    locationName: "Herd QA",
    locationAddress: "",
    invitees,
    minimumParticipants,
    requiredGroups,
    rsvpDeadline: deadline,
    eventDescription: "Automated live scheduler and encrypted RSVP smoke test.",
    createdAt: new Date().toISOString(),
    invitationsSent: true,
  };
}

function verifyPolicyPins(event, config) {
  const policy = event.privateResponsePolicy;
  ensure(isRecord(policy), "A sent QA event is missing its private response policy.");
  ensure(
    policy.protocolVersion === 1 &&
      policy.cipherSuite === "P256_HKDF_SHA256_AES256_GCM" &&
      policy.paddedPlaintextBytes === 4_096 &&
      policy.evaluatorKeyId === config.evaluatorKeyId &&
      policy.evaluatorPublicKey === config.evaluatorPublicKey &&
      policy.evaluatorMeasurement === config.evaluatorMeasurement &&
      policy.releaseId === config.releaseId &&
      canonicalBase64UrlBytes(policy.policyHash, 32) !== null &&
      typeof policy.canonicalDocument === "string" &&
      policy.canonicalDocument.length > 0,
    "A sent QA event does not match the expected live evaluator pins.",
  );
}

function findEvent(eventsPayload, eventId) {
  ensure(Array.isArray(eventsPayload.events), "An event listing is invalid.");
  const event = eventsPayload.events.find((candidate) => candidate?.id === eventId);
  ensure(isRecord(event), "A newly created QA event is missing from an event listing.");
  return event;
}

async function createLiveEvent(api, host, payload, config) {
  const result = await api.request(`/api/events/${payload.id}`, {
    method: "PUT",
    token: host.accessToken,
    body: payload,
    label: "Live QA event creation",
  });
  ensure(isRecord(result.event) && result.event.id === payload.id, "A live QA event was not saved.");
  ensure(result.event.endDate === null, "A live QA event did not preserve its empty end time.");
  ensure(
    isRecord(result.event.resolution) && result.event.resolution.status === "pending",
    "A new live QA event did not start pending.",
  );
  const delivery = result.event.invitationDelivery;
  ensure(
    isRecord(delivery) &&
      delivery.status === "suppressed" &&
      delivery.total === 9 &&
      isRecord(delivery.counts) &&
      delivery.counts.suppressed === 9 &&
      delivery.counts.pending === 0 &&
      delivery.counts.dispatching === 0 &&
      delivery.counts.sent === 0 &&
      delivery.counts.failed === 0 &&
      delivery.counts.unknown === 0 &&
      Array.isArray(delivery.guests) &&
      delivery.guests.length === 9 &&
      delivery.guests.every((guest) => guest?.status === "suppressed"),
    "A live QA invitation was not safely suppressed before delivery.",
  );
  verifyPolicyPins(result.event, config);
  assertNoPrivateResponseLeak(result.event);
  return result.event;
}

async function loadInviteeViews(api, sessions, scenarios, config) {
  return Promise.all(
    sessions.map(async (session, accountIndex) => {
      const listing = await api.request("/api/events", {
        token: session.accessToken,
        label: "QA invitee event listing",
      });
      return scenarios.map((scenario) => {
        const event = findEvent(listing, scenario.id);
        ensure(event.role === "invitee", "A QA account received the wrong event role.");
        ensure(
          typeof event.inviteToken === "string" &&
            /^[A-Za-z0-9_-]{8,200}$/u.test(event.inviteToken),
          "A QA invitee is missing a valid invitation token.",
        );
        ensure(
          event.accountKeyEpochId === session.accountKeyEpochId &&
            event.accountKeyCommitment === session.accountKeyCommitment,
          "A QA invitee event used the wrong account key epoch.",
        );
        ensure(
          isRecord(event.resolution) && event.resolution.status === "pending",
          "A QA invitee event was not pending before its deadline.",
        );
        ensure(Array.isArray(event.invitees) && event.invitees.length === 9, "A QA invitee list is incomplete.");
        const currentUsers = event.invitees.filter((invitee) => invitee?.isCurrentUser === true);
        ensure(
          currentUsers.length === 1 &&
            currentUsers[0].id === scenario.invitees[accountIndex].id,
          "A QA invitee projection marked the wrong current user.",
        );
        verifyPolicyPins(event, config);
        assertNoPrivateResponseLeak(event);
        assertInviteePhonePrivacy(event);
        return event;
      });
    }),
  );
}

async function verifyInvitationAccountMatrix(
  api,
  sessions,
  inviteeViews,
  scenarios,
) {
  let correctPairs = 0;
  let rejectedPairs = 0;
  for (let scenarioIndex = 0; scenarioIndex < scenarios.length; scenarioIndex += 1) {
    for (let inviteeIndex = 0; inviteeIndex < sessions.length; inviteeIndex += 1) {
      const eventView = inviteeViews[inviteeIndex][scenarioIndex];
      const path = `/api/invites/${eventView.inviteToken}`;
      const correct = await api.request(path, {
        token: sessions[inviteeIndex].accessToken,
        label: "Correct-account live invitation open",
      });
      ensure(
        isRecord(correct.event) &&
          correct.event.id === scenarios[scenarioIndex].id &&
          correct.event.role === "invitee" &&
          correct.inviteMetadata?.canRespond === true,
        "A correct QA account could not open its live invitation.",
      );
      correctPairs += 1;

      const wrongAccountTasks = sessions.flatMap((session, accountIndex) =>
        accountIndex === inviteeIndex
          ? []
          : [
              api.request(path, {
                token: session.accessToken,
                label: "Wrong-account live invitation denial",
                expectedError: {
                  status: 403,
                  code: "invite_for_different_account",
                },
              }),
            ],
      );
      await Promise.all(wrongAccountTasks);
      rejectedPairs += wrongAccountTasks.length;
    }
  }
  ensure(correctPairs === 18, "The live correct-account invitation matrix is incomplete.");
  ensure(rejectedPairs === 144, "The live wrong-account invitation matrix is incomplete.");
}

function confirmedResponseSpecs(invitees) {
  return [
    { response: "going", minimumParticipants: 6, requiredGroups: [] },
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    {
      response: "going",
      minimumParticipants: 6,
      requiredGroups: [{ id: randomUUID(), memberIDs: [invitees[3].id] }],
    },
    { response: "going", minimumParticipants: 6, requiredGroups: [] },
    {
      response: "going",
      minimumParticipants: 6,
      requiredGroups: [
        { id: randomUUID(), memberIDs: [invitees[5].id, invitees[6].id] },
      ],
    },
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    { response: "going", minimumParticipants: 6, requiredGroups: [] },
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    {
      response: "going",
      minimumParticipants: 6,
      requiredGroups: [{ id: randomUUID(), memberIDs: [invitees[7].id] }],
    },
  ];
}

function notConfirmedResponseSpecs(invitees) {
  return [
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    {
      response: "going",
      minimumParticipants: 8,
      requiredGroups: [{ id: randomUUID(), memberIDs: [invitees[3].id] }],
    },
    { response: "going", minimumParticipants: 8, requiredGroups: [] },
    { response: "going", minimumParticipants: 10, requiredGroups: [] },
    {
      response: "going",
      minimumParticipants: 8,
      requiredGroups: [{ id: randomUUID(), memberIDs: [invitees[7].id] }],
    },
    { response: "going", minimumParticipants: 8, requiredGroups: [] },
    { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    { response: "going", minimumParticipants: 8, requiredGroups: [] },
  ];
}

async function submitEncryptedReply({
  api,
  responseCrypto,
  session,
  rootSecret,
  eventView,
  inviteeId,
  allowedInviteeIds,
  spec,
  revision,
}) {
  let envelope;
  try {
    ({ envelope } = await responseCrypto.sealPrivateResponse({
      eventId: eventView.id,
      inviteeId,
      accountKeyEpochId: session.accountKeyEpochId,
      revision,
      response: spec.response,
      minimumParticipants: spec.minimumParticipants,
      requiredGroups: spec.requiredGroups,
      allowedInviteeIds,
      accountRootSecret: rootSecret,
      policy: eventView.privateResponsePolicy,
    }));
  } catch (error) {
    if (process.env.HERD_LIVE_DEBUG === "1") console.error(error);
    throw new SmokeFailure("A QA private response could not be encrypted.");
  }

  const result = await api.request(`/api/invites/${eventView.inviteToken}/rsvp`, {
    method: "PUT",
    token: session.accessToken,
    body: { envelope },
    label: "Encrypted QA reply submission",
  });
  ensure(
    isRecord(result.receipt) &&
      result.receipt.eventId === eventView.id &&
      result.receipt.inviteeId === inviteeId &&
      result.receipt.revision === revision &&
      isCanonicalIsoTimestamp(result.receipt.committedAt),
    "An encrypted QA reply returned an invalid receipt.",
  );
}

async function submitAllReplies({
  api,
  responseCrypto,
  sessions,
  rootSecrets,
  inviteeViews,
  scenarios,
  revision,
}) {
  const accountTasks = sessions.map(async (session, accountIndex) => {
    for (let scenarioIndex = 0; scenarioIndex < scenarios.length; scenarioIndex += 1) {
      const scenario = scenarios[scenarioIndex];
      await submitEncryptedReply({
        api,
        responseCrypto,
        session,
        rootSecret: rootSecrets[accountIndex],
        eventView: inviteeViews[accountIndex][scenarioIndex],
        inviteeId: scenario.invitees[accountIndex].id,
        allowedInviteeIds: scenario.invitees.map(({ id }) => id),
        spec: scenario.responseSpecs[accountIndex],
        revision,
      });
    }
    return 2;
  });
  const results = await Promise.allSettled(accountTasks);
  const failed = results.find(({ status }) => status === "rejected");
  if (failed) {
    if (failed.reason instanceof SmokeFailure) throw failed.reason;
    throw new SmokeFailure("One or more encrypted QA replies failed safely.");
  }
  return results.reduce((count, result) => count + result.value, 0);
}

function zeroRootSecrets(rootSecrets) {
  for (const rootSecret of rootSecrets) rootSecret.fill(0);
}

async function waitUntil(timestamp) {
  while (Date.now() < timestamp) {
    await new Promise((resolve) =>
      setTimeout(resolve, Math.min(pollingIntervalMilliseconds, timestamp - Date.now())),
    );
  }
}

function verifyConfirmedResolution(resolution, expectedAttendingMemberIds) {
  ensure(
    exactKeys(resolution, ["status", "attendingMemberIds", "resolvedAt", "attestation"]) &&
      resolution.status === "confirmed" &&
      arraysEqual(resolution.attendingMemberIds, expectedAttendingMemberIds) &&
      isCanonicalIsoTimestamp(resolution.resolvedAt),
    "The confirmed QA event returned an incorrect final resolution.",
  );
}

function verifyNotConfirmedResolution(resolution) {
  ensure(
    exactKeys(resolution, ["status", "resolvedAt", "attestation"]) &&
      resolution.status === "not_confirmed" &&
      isCanonicalIsoTimestamp(resolution.resolvedAt),
    "The non-confirmed QA event returned an incorrect final resolution.",
  );
}

async function verifyScenarioResolution(event, scenario, eventResolutionProof) {
  let verified;
  try {
    verified = await eventResolutionProof.verifyEventResolutionProof(
      {
        eventId: event.id,
        rsvpDeadline: event.rsvpDeadline,
        privateResponsePolicy: event.privateResponsePolicy,
      },
      event.resolution,
      eventResolutionProof.configuredEvaluationResultSigningPin(),
    );
  } catch {
    throw new SmokeFailure("A QA event returned an invalid signed final resolution.");
  }
  if (scenario.expectedStatus === "confirmed") {
    verifyConfirmedResolution(verified, scenario.expectedAttendingMemberIds);
  } else {
    verifyNotConfirmedResolution(verified);
  }
  const resolvedAt = Date.parse(event.resolution.resolvedAt);
  ensure(
    resolvedAt >= Date.parse(scenario.deadline) &&
      resolvedAt <= Date.parse(scenario.latestResolutionAt),
    "A QA event resolved outside its permitted deadline window.",
  );
}

async function pollForExternalResolution(
  api,
  token,
  scenarios,
  deadline,
  timeoutSeconds,
  eventResolutionProof,
) {
  await waitUntil(Date.parse(deadline) + 500);
  const expiresAt = Date.parse(deadline) + timeoutSeconds * 1_000;

  while (Date.now() <= expiresAt) {
    const listing = await api.request("/api/events", {
      token,
      label: "Read-only scheduler resolution poll",
    });
    const events = scenarios.map((scenario) => findEvent(listing, scenario.id));
    for (const event of events) {
      ensure(
        event.role === "invitee" && event.resolution?.relayNeeded !== true,
        "The read-only scheduler poll received a host relay instruction.",
      );
      assertNoPrivateResponseLeak(event);
      assertInviteePhonePrivacy(event);
      ensure(
        ["pending", "confirmed", "not_confirmed"].includes(event.resolution?.status),
        "A scheduled QA event returned an invalid resolution state.",
      );
    }
    if (events.every(({ resolution }) => resolution.status !== "pending")) {
      await Promise.all(
        events.map((event, index) =>
          verifyScenarioResolution(event, scenarios[index], eventResolutionProof),
        ),
      );
      return;
    }
    await waitUntil(Math.min(Date.now() + pollingIntervalMilliseconds, expiresAt + 1));
  }
  throw new SmokeFailure("The external scheduler did not resolve both QA events in time.");
}

async function verifyHostProjection(event, scenario, config, eventResolutionProof) {
  ensure(event.role === "host", "The QA host received the wrong event role.");
  ensure(event.endDate === null, "A resolved QA event changed its empty end time.");
  ensure(event.rsvpDeadline === scenario.deadline, "A resolved QA event changed its deadline.");
  ensure(Array.isArray(event.invitees) && event.invitees.length === 9, "The QA host invitee list is incomplete.");
  ensure(
    scenario.invitees.every(
      (expectedInvitee) =>
        event.invitees.find((invitee) => invitee?.id === expectedInvitee.id)
          ?.phoneNumber === expectedInvitee.phoneNumber,
    ),
    "The QA host invitee projection is incorrect.",
  );
  verifyPolicyPins(event, config);
  await verifyScenarioResolution(event, scenario, eventResolutionProof);
  assertNoPrivateResponseLeak(event);
}

async function verifyInviteeProjection(
  event,
  scenario,
  accountIndex,
  config,
  eventResolutionProof,
) {
  ensure(event.role === "invitee", "A resolved QA invitee received the wrong role.");
  ensure(event.endDate === null, "A resolved invitee event changed its empty end time.");
  ensure(event.rsvpDeadline === scenario.deadline, "A resolved invitee event changed its deadline.");
  ensure(event.hasResponse === true && event.responseRevision === 2, "A QA reply revision is missing from its invitee projection.");
  ensure(Array.isArray(event.invitees) && event.invitees.length === 9, "A resolved QA invitee list is incomplete.");
  const currentUsers = event.invitees.filter((invitee) => invitee?.isCurrentUser === true);
  ensure(
    currentUsers.length === 1 &&
      currentUsers[0].id === scenario.invitees[accountIndex].id,
    "A resolved QA event marked the wrong current invitee.",
  );
  verifyPolicyPins(event, config);
  await verifyScenarioResolution(event, scenario, eventResolutionProof);
  assertNoPrivateResponseLeak(event);
  assertInviteePhonePrivacy(event);
}

async function verifyAllFinalProjections(
  api,
  host,
  sessions,
  scenarios,
  config,
  eventResolutionProof,
) {
  const [hostListing, ...inviteeListings] = await Promise.all([
    api.request("/api/events", {
      token: host.accessToken,
      label: "Final QA host event listing",
    }),
    ...sessions.map((session) =>
      api.request("/api/events", {
        token: session.accessToken,
        label: "Final QA invitee event listing",
      }),
    ),
  ]);

  for (const scenario of scenarios) {
    await verifyHostProjection(
      findEvent(hostListing, scenario.id),
      scenario,
      config,
      eventResolutionProof,
    );
  }
  for (let accountIndex = 0; accountIndex < inviteeListings.length; accountIndex += 1) {
    const listing = inviteeListings[accountIndex];
    for (const scenario of scenarios) {
      await verifyInviteeProjection(
        findEvent(listing, scenario.id),
        scenario,
        accountIndex,
        config,
        eventResolutionProof,
      );
    }
  }
}

async function main() {
  const config = loadConfiguration();
  const api = createLiveApi(config.origin);
  const rootSecrets = [];
  let temporaryDirectory;

  try {
    temporaryDirectory = await mkdtemp(
      path.join(tmpdir(), "herd-live-scheduler-smoke-"),
    );
    const { vault, responseCrypto, eventResolutionProof } = await loadPrivacyModules(
      config,
      temporaryDirectory,
    );

    const firstInvitee = await authenticateQaAccount(
      api,
      "1",
      qaInviteePhones[0],
      "QA bypass proof",
    );
    const sessions = [firstInvitee];
    for (let number = 2; number <= 9; number += 1) {
      sessions.push(
        await authenticateQaAccount(
          api,
          String(number),
          qaInviteePhones[number - 1],
          "QA invitee authentication",
        ),
      );
    }
    const host = await authenticateQaAccount(
      api,
      config.hostPhone,
      config.hostPhone,
      "QA host authentication",
    );
    ensure(
      new Set([...sessions, host].map(({ userId }) => userId)).size === 10,
      "QA authentication did not return ten distinct accounts.",
    );
    console.log("Authenticated 10 QA accounts.");

    for (const session of sessions) {
      await prepareFreshInviteeKey(api, vault, session, rootSecrets);
    }
    console.log("Prepared 9 fresh invitee key epochs.");

    const createdAt = Date.now();
    const deadline = new Date(
      createdAt + config.deadlineSeconds * 1_000,
    ).toISOString();
    const latestResolutionAt = new Date(
      Date.parse(deadline) + config.resolutionTimeoutSeconds * 1_000,
    ).toISOString();
    const runLabel = new Date(createdAt).toISOString();
    const confirmedInvitees = createInvitees();
    const notConfirmedInvitees = createInvitees();
    const scenarios = [
      {
        id: randomUUID(),
        title: `Scheduler smoke: confirm (${runLabel})`,
        invitees: confirmedInvitees,
        minimumParticipants: 6,
        requiredGroups: [
          {
            id: randomUUID(),
            memberIDs: [confirmedInvitees[0].id, confirmedInvitees[1].id],
          },
          { id: randomUUID(), memberIDs: [confirmedInvitees[4].id] },
        ],
        responseSpecs: confirmedResponseSpecs(confirmedInvitees),
        expectedStatus: "confirmed",
        deadline,
        latestResolutionAt,
        expectedAttendingMemberIds: [
          "host",
          ...[
            confirmedInvitees[0].id,
            confirmedInvitees[2].id,
            confirmedInvitees[3].id,
            confirmedInvitees[4].id,
            confirmedInvitees[6].id,
          ].sort(),
        ],
        eventDate: new Date(Date.parse(deadline) + 10 * 60_000).toISOString(),
      },
      {
        id: randomUUID(),
        title: `Scheduler smoke: do not confirm (${runLabel})`,
        invitees: notConfirmedInvitees,
        minimumParticipants: 8,
        requiredGroups: [
          {
            id: randomUUID(),
            memberIDs: [notConfirmedInvitees[0].id, notConfirmedInvitees[1].id],
          },
        ],
        responseSpecs: notConfirmedResponseSpecs(notConfirmedInvitees),
        expectedStatus: "not_confirmed",
        deadline,
        latestResolutionAt,
        eventDate: new Date(Date.parse(deadline) + 15 * 60_000).toISOString(),
      },
    ];

    for (const scenario of scenarios) {
      const payload = buildEventPayload({ ...scenario, deadline });
      await createLiveEvent(api, host, payload, config);
    }
    console.log("Created 2 live QA events.");

    const inviteeViews = await loadInviteeViews(api, sessions, scenarios, config);
    await verifyInvitationAccountMatrix(api, sessions, inviteeViews, scenarios);
    console.log("Verified 18 correct and 144 wrong live invitation/account pairs.");
    const submitted = await submitAllReplies({
      api,
      responseCrypto,
      sessions,
      rootSecrets,
      inviteeViews,
      scenarios,
      revision: 1,
    });
    const revised = await submitAllReplies({
      api,
      responseCrypto,
      sessions,
      rootSecrets,
      inviteeViews,
      scenarios,
      revision: 2,
    });
    api.closeMutations();
    zeroRootSecrets(rootSecrets);
    ensure(submitted === 18, "The smoke test did not submit all 18 encrypted replies.");
    ensure(revised === 18, "The smoke test did not submit all 18 encrypted revisions.");
    ensure(
      Date.now() <= Date.parse(deadline) - submissionSafetyMarginMilliseconds,
      "The encrypted QA replies finished too close to the deadline for a valid smoke test.",
    );
    console.log("Submitted and revised all 18 encrypted QA replies.");
    console.log(
      "Waiting for the external deadline scheduler; polling read-only event listings.",
    );

    await pollForExternalResolution(
      api,
      sessions[8].accessToken,
      scenarios,
      deadline,
      config.resolutionTimeoutSeconds,
      eventResolutionProof,
    );
    await verifyAllFinalProjections(
      api,
      host,
      sessions,
      scenarios,
      config,
      eventResolutionProof,
    );
    console.log("Live scheduler smoke passed: 1 confirmed and 1 not confirmed.");
    console.log(
      "The two timestamped QA events remain as audit evidence; the nine shared QA key resets were intentional.",
    );
  } finally {
    api.closeMutations();
    zeroRootSecrets(rootSecrets);
    if (temporaryDirectory) {
      await rm(temporaryDirectory, { recursive: true, force: true });
    }
  }
}

try {
  await main();
} catch (error) {
  if (process.env.HERD_LIVE_DEBUG === "1") {
    console.error(error);
  }
  console.error(
    error instanceof SmokeFailure
      ? error.message
      : "Live scheduler smoke failed safely.",
  );
  process.exitCode = 1;
}
