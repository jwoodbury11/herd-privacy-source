const SCHEDULER_BASE_PATH = "/api/internal/scheduled-resolutions";
const MAXIMUM_JOBS = 12;
const MAXIMUM_CLAIM_BYTES = 600 * 1_024;
const MAXIMUM_RESULT_BYTES = 60 * 1_024;
const SCHEDULER_REQUEST_TIMEOUT_MS = 10_000;
const EVALUATOR_REQUEST_TIMEOUT_MS = 25_000;
const INVOCATION_BUDGET_MS = 50_000;
const MINIMUM_NEW_JOB_BUDGET_MS = 45_000;
const MINIMUM_LEASE_REMAINING_MS = 40_000;
const FORBIDDEN_PRODUCTION_TOKEN =
  /(?:^|[._-])(?:dev|development|local|localhost|preview|qa|sandbox|stage|staging|test|testing)(?:[._-]|$)/iu;

export const SCHEDULER_RUNTIME_VARIABLE_NAMES = Object.freeze([
  "HERD_ARTIFACT_RELEASE_ID",
  "HERD_DEPLOYMENT_PROFILE",
  "HERD_EVALUATOR_KEY_ID",
  "HERD_EVALUATOR_URL",
  "HERD_PUBLIC_APP_URL",
  "HERD_RELEASE_CONFIGURATION_SHA256",
  "HERD_RELEASE_ID",
]);

class SchedulerError extends Error {
  constructor(message, code = "scheduler_failure") {
    super(message);
    this.name = "SchedulerError";
    this.code = code;
  }
}

function fail(message, code) {
  throw new SchedulerError(message, code);
}

function isRecord(value) {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function hasExactKeys(value, keys) {
  if (!isRecord(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function isUuid(value) {
  return (
    typeof value === "string" &&
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value,
    )
  );
}

function canonicalBase64UrlBytes(value, expectedLength) {
  if (
    typeof value !== "string" ||
    value.length !== Math.ceil((expectedLength * 4) / 3) ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    return false;
  }

  const remainder = expectedLength % 3;
  if (remainder === 0) return true;
  const finalCharacter = value.at(-1);
  return remainder === 1
    ? /^[AQgw]$/u.test(finalCharacter)
    : /^[AEIMQUYcgkosw048]$/u.test(finalCharacter);
}

async function readBoundedText(response, maximumBytes) {
  const declared = response.headers.get("content-length");
  if (declared !== null) {
    const parsed = Number(declared);
    if (!Number.isInteger(parsed) || parsed < 0 || parsed > maximumBytes) {
      try {
        await response.body?.cancel();
      } catch {
        // The invalid declared length remains authoritative.
      }
      fail("A service response exceeded its safe size.");
    }
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The measured size violation remains authoritative.
        }
        fail("A service response exceeded its safe size.");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    fail("A service returned unreadable data.");
  }
}

async function readJson(response, maximumBytes) {
  const mediaType = (response.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    try {
      await response.body?.cancel();
    } catch {
      // The invalid media type remains authoritative.
    }
    fail("A service returned non-JSON data.");
  }
  const text = await readBoundedText(response, maximumBytes);
  try {
    return JSON.parse(text);
  } catch {
    fail("A service returned malformed JSON.");
  }
}

function validateSchedulerToken(value) {
  const token = typeof value === "string" ? value.trim() : "";
  if (
    token.length < 32 ||
    token.length > 512 ||
    !/^[A-Za-z0-9_-]+$/u.test(token)
  ) {
    fail("The scheduler credential is missing or invalid.");
  }
  return token;
}

function requiredRuntimeValue(value, name, maximum = 2_048) {
  const result = typeof value === "string" ? value.trim() : "";
  if (
    !result ||
    result.length > maximum ||
    /[\u0000-\u001f\u007f]/u.test(result)
  ) {
    fail(`${name} is missing or invalid.`);
  }
  return result;
}

function runtimeUrl(value, name, { originOnly = false, relay = false } = {}) {
  let url;
  try {
    url = new URL(requiredRuntimeValue(value, name));
  } catch {
    fail(`${name} must be a safe HTTPS ${originOnly ? "origin" : "URL"}.`);
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.origin === "null" ||
    (originOnly && (url.pathname !== "/" || url.search)) ||
    (relay && (url.pathname !== "/api/v1/relay/" || url.search))
  ) {
    fail(`${name} must be a safe HTTPS ${originOnly ? "origin" : "URL"}.`);
  }
  return originOnly ? url.origin : url.toString();
}

function validateRuntimeConfig(env) {
  const profile = requiredRuntimeValue(
    env?.HERD_DEPLOYMENT_PROFILE,
    "HERD_DEPLOYMENT_PROFILE",
    20,
  ).toLowerCase();
  if (profile !== "production" && profile !== "test") {
    fail("HERD_DEPLOYMENT_PROFILE must be production or test.");
  }
  const herdOrigin = runtimeUrl(
    env?.HERD_PUBLIC_APP_URL,
    "HERD_PUBLIC_APP_URL",
    { originOnly: true },
  );
  const evaluatorUrl = runtimeUrl(
    env?.HERD_EVALUATOR_URL,
    "HERD_EVALUATOR_URL",
    { relay: true },
  );
  const evaluatorOrigin = new URL(evaluatorUrl).origin;
  if (evaluatorOrigin === herdOrigin) {
    fail("The evaluator must use a separate HTTPS origin.");
  }
  const evaluatorKeyId = requiredRuntimeValue(
    env?.HERD_EVALUATOR_KEY_ID,
    "HERD_EVALUATOR_KEY_ID",
    120,
  );
  const artifactReleaseId = requiredRuntimeValue(
    env?.HERD_ARTIFACT_RELEASE_ID,
    "HERD_ARTIFACT_RELEASE_ID",
    200,
  );
  const releaseId = requiredRuntimeValue(
    env?.HERD_RELEASE_ID,
    "HERD_RELEASE_ID",
    200,
  );
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(evaluatorKeyId) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(artifactReleaseId) ||
    !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(releaseId)
  ) {
    fail("Scheduler release identifiers are invalid.");
  }
  const configurationSha256 = requiredRuntimeValue(
    env?.HERD_RELEASE_CONFIGURATION_SHA256,
    "HERD_RELEASE_CONFIGURATION_SHA256",
    64,
  );
  if (!/^[0-9a-f]{64}$/u.test(configurationSha256)) {
    fail("HERD_RELEASE_CONFIGURATION_SHA256 must be a lowercase SHA-256 digest.");
  }
  if (profile === "production") {
    const identifiers = [
      new URL(herdOrigin).hostname,
      new URL(evaluatorUrl).hostname,
      evaluatorKeyId,
      artifactReleaseId,
      releaseId,
    ];
    if (
      identifiers.some((value) => FORBIDDEN_PRODUCTION_TOKEN.test(value)) ||
      /(?:^|[-_.])live-v1(?:$|[-_.])/iu.test(evaluatorKeyId)
    ) {
      fail("Production scheduler configuration contains a test, preview, or legacy identifier.");
    }
  }
  return {
    profile,
    herdOrigin,
    evaluatorUrl,
    evaluatorOrigin,
    evaluatorKeyId,
    artifactReleaseId,
    releaseId,
    configurationSha256,
    schedulerToken: validateSchedulerToken(env?.HERD_SCHEDULER_TOKEN),
  };
}

function validateClaim(value, now, config) {
  if (
    !hasExactKeys(value, [
      "eventId",
      "evaluatorHost",
      "evaluatorUrl",
      "expiresAt",
      "leaseId",
      "releaseId",
      "relayRequest",
    ]) ||
    !isUuid(value.eventId) ||
    !isUuid(value.leaseId) ||
    value.evaluatorUrl !== config.evaluatorUrl ||
    value.evaluatorHost !== config.evaluatorOrigin ||
    value.releaseId !== config.releaseId ||
    typeof value.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(value.expiresAt)) ||
    new Date(Date.parse(value.expiresAt)).toISOString() !== value.expiresAt ||
    Date.parse(value.expiresAt) - now < MINIMUM_LEASE_REMAINING_MS ||
    !hasExactKeys(value.relayRequest, [
      "protocolVersion",
      "cipherSuite",
      "evaluatorKeyId",
      "ephemeralPublicKey",
      "salt",
      "ciphertext",
      "capabilityMac",
    ]) ||
    value.relayRequest.protocolVersion !== 1 ||
    value.relayRequest.cipherSuite !== "P256_HKDF_SHA256_AES256_GCM" ||
    value.relayRequest.evaluatorKeyId !== config.evaluatorKeyId ||
    !canonicalBase64UrlBytes(value.relayRequest.ephemeralPublicKey, 65) ||
    !canonicalBase64UrlBytes(value.relayRequest.salt, 32) ||
    !canonicalBase64UrlBytes(value.relayRequest.ciphertext, 327_708) ||
    !canonicalBase64UrlBytes(value.relayRequest.capabilityMac, 32)
  ) {
    fail("Herd returned an invalid opaque courier job.");
  }
  return value;
}

function timeoutSignal(maximumMilliseconds, deadline, now) {
  const remaining = deadline === undefined ? maximumMilliseconds : deadline - now();
  if (remaining <= 0) fail("The courier invocation exhausted its safe time budget.");
  return AbortSignal.timeout(
    Math.max(1, Math.min(maximumMilliseconds, Math.floor(remaining))),
  );
}

async function schedulerRequest(fetchImpl, config, path, options) {
  const { body, acceptedStatuses, deadline, now = Date.now } = options;
  const requestId = crypto.randomUUID();
  const response = await fetchImpl(new URL(path, config.herdOrigin), {
    method: "POST",
    redirect: "manual",
    headers: {
      authorization: `Bearer ${config.schedulerToken}`,
      accept: "application/json",
      "x-herd-client-platform": "scheduler",
      "x-herd-request-id": requestId,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    signal: timeoutSignal(SCHEDULER_REQUEST_TIMEOUT_MS, deadline, now),
  });
  if (!acceptedStatuses.includes(response.status)) {
    try {
      await response.body?.cancel();
    } catch {
      // The status remains authoritative.
    }
    fail(`Herd rejected a courier request (HTTP ${response.status}).`, `herd_http_${response.status}`);
  }
  return response;
}

async function claimJob(fetchImpl, config, now, deadline) {
  const response = await schedulerRequest(
    fetchImpl,
    config,
    `${SCHEDULER_BASE_PATH}/claim`,
    { acceptedStatuses: [200, 204], deadline, now },
  );
  if (response.status === 204) {
    await response.body?.cancel();
    return null;
  }
  const value = await readJson(response, MAXIMUM_CLAIM_BYTES);
  try {
    return validateClaim(value, now(), config);
  } catch (error) {
    if (isRecord(value) && isUuid(value.eventId) && isUuid(value.leaseId)) {
      try {
        await releaseJob(fetchImpl, config, value);
      } catch {
        // An unreadable claim still expires safely if its lease cannot be released.
      }
    }
    throw error;
  }
}

async function relayJob(fetchImpl, config, job, now, deadline) {
  const requestId = crypto.randomUUID();
  const response = await fetchImpl(config.evaluatorUrl, {
    method: "POST",
    redirect: "manual",
    headers: {
      accept: "application/json",
      "content-type": "application/json",
      "cache-control": "no-store",
      "x-herd-client-platform": "scheduler",
      "x-herd-request-id": requestId,
    },
    body: JSON.stringify(job.relayRequest),
    signal: timeoutSignal(EVALUATOR_REQUEST_TIMEOUT_MS, deadline, now),
  });
  if (!response.ok || response.type === "opaqueredirect") {
    try {
      await response.body?.cancel();
    } catch {
      // The unsuccessful status remains authoritative.
    }
    fail(`The evaluator rejected an opaque job (HTTP ${response.status}).`, `evaluator_http_${response.status}`);
  }
  const result = await readJson(response, MAXIMUM_RESULT_BYTES);
  if (!isRecord(result)) fail("The evaluator returned an invalid signed result.");
  return result;
}

async function completeJob(
  fetchImpl,
  config,
  job,
  evaluationResponse,
  now,
  deadline,
) {
  const response = await schedulerRequest(
    fetchImpl,
    config,
    `${SCHEDULER_BASE_PATH}/complete`,
    {
      body: { eventId: job.eventId, evaluationResponse },
      acceptedStatuses: [204],
      deadline,
      now,
    },
  );
  await response.body?.cancel();
}

async function releaseJob(fetchImpl, config, job) {
  const response = await schedulerRequest(
    fetchImpl,
    config,
    `${SCHEDULER_BASE_PATH}/release`,
    {
      body: { eventId: job.eventId, leaseId: job.leaseId },
      acceptedStatuses: [204],
    },
  );
  await response.body?.cancel();
}

export async function runCourier(env, options = {}) {
  const invocationId = crypto.randomUUID();
  const startedAt = Date.now();
  const config = validateRuntimeConfig(env);
  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const invocationDeadline = now() + INVOCATION_BUDGET_MS;

  let completed = 0;
  for (; completed < MAXIMUM_JOBS; completed += 1) {
    if (invocationDeadline - now() < MINIMUM_NEW_JOB_BUDGET_MS) break;
    const job = await claimJob(
      fetchImpl,
      config,
      now,
      invocationDeadline,
    );
    if (!job) break;
    try {
      const evaluationResponse = await relayJob(
        fetchImpl,
        config,
        job,
        now,
        invocationDeadline,
      );
      await completeJob(
        fetchImpl,
        config,
        job,
        evaluationResponse,
        now,
        invocationDeadline,
      );
    } catch (error) {
      try {
        await releaseJob(fetchImpl, config, job);
      } catch {
        // The short lease still makes the job safely retryable.
      }
      fail(
        "An opaque evaluation could not be completed safely.",
        error instanceof SchedulerError ? error.code : "evaluation_boundary_failed",
      );
    }
  }
  console.info(JSON.stringify({
    schemaVersion: 1,
    kind: "herd.operational",
    recordedAt: new Date().toISOString(),
    component: "scheduler",
    signal: "scheduler_run",
    operation: "scheduled_resolution",
    outcome: "success",
    statusCode: 200,
    errorCode: "none",
    durationMs: Math.max(0, Date.now() - startedAt),
    correlationId: invocationId,
    releaseId: config.artifactReleaseId,
    completedCount: completed,
  }));
  return completed;
}

export default {
  scheduled(_controller, env, context) {
    context.waitUntil(runCourier(env).catch((error) => {
      console.error(JSON.stringify({
        schemaVersion: 1,
        kind: "herd.operational",
        recordedAt: new Date().toISOString(),
        component: "scheduler",
        signal: "scheduler_run",
        operation: "scheduled_resolution",
        outcome: "failure",
        statusCode: 500,
        errorCode: error instanceof SchedulerError ? error.code : "scheduler_run_failed",
        durationMs: 0,
        correlationId: crypto.randomUUID(),
        releaseId: "unknown",
      }));
      throw error;
    }));
  },

  fetch() {
    return new Response("Not found", {
      status: 404,
      headers: { "cache-control": "no-store" },
    });
  },
};
