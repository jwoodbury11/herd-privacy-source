// Copyright 2026 Herd contributors. Licensed under Apache-2.0.
import { canonicalJson, verifyTarget } from "./core.mjs";

const STATUS_KEY = "herd-release-monitor:status:v2";
const WITNESS_KEY_PREFIX = "herd-release-monitor:last-good:v2:";

function witnessKey(targetName) {
  return `${WITNESS_KEY_PREFIX}${encodeURIComponent(targetName)}`;
}

function targets(env) {
  if (!env.TARGETS_JSON) throw new TypeError("TARGETS_JSON is not configured.");
  const value = JSON.parse(env.TARGETS_JSON);
  if (!Array.isArray(value) || value.length === 0 || value.length > 20) {
    throw new TypeError("TARGETS_JSON must contain one through twenty monitor targets.");
  }
  const names = value.map((target) => target?.name);
  if (names.some((name) => typeof name !== "string") || new Set(names).size !== names.length) {
    throw new TypeError("TARGETS_JSON target names must be present and unique.");
  }
  if (value.some((target) => target?.requireProduction === true)) {
    if (!env.STATUS_KV) throw new TypeError("STATUS_KV is required for every production monitor target.");
    for (const target of value) {
      if (target?.requireProduction === true && !target?.responseTransparency) {
        throw new TypeError(`Production target ${String(target?.name ?? "<unnamed>")} requires responseTransparency.`);
      }
      if (target?.requireProduction === true && !target?.evaluatorAttestation) {
        throw new TypeError(`Production target ${String(target?.name ?? "<unnamed>")} requires evaluatorAttestation.`);
      }
    }
  }
  return value;
}

function authorized(request, env) {
  const expected = env.MONITOR_BEARER_TOKEN;
  if (typeof expected !== "string" || expected.length < 32) return false;
  const supplied = request.headers.get("authorization") ?? "";
  const wanted = `Bearer ${expected}`;
  if (supplied.length !== wanted.length) return false;
  let difference = 0;
  for (let index = 0; index < wanted.length; index += 1) {
    difference |= supplied.charCodeAt(index) ^ wanted.charCodeAt(index);
  }
  return difference === 0;
}

export function sitesAuthorizedFetch(env, target, fetchImpl = fetch) {
  // A production client must be able to reach the published origin without a
  // browser-only Sites session. Deliberately ignore the operator bypass here so
  // the monitor catches an accidental owner-only access policy before users do.
  if (target.requireProduction === true) return fetchImpl;
  const token = env.SITES_BYPASS_BEARER_TOKEN;
  if (token === undefined || token === "") return fetchImpl;
  if (typeof token !== "string" || token.length < 32) {
    throw new TypeError("SITES_BYPASS_BEARER_TOKEN must be at least 32 characters when configured.");
  }
  const authorizedOrigin = new URL(target.expectedWebOrigin).origin;
  return (input, init = {}) => {
    const requestUrl = new URL(typeof input === "string" || input instanceof URL ? input : input.url);
    if (requestUrl.origin !== authorizedOrigin) return fetchImpl(input, init);
    const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
    if (headers.has("OAI-Sites-Authorization")) {
      throw new TypeError("OAI-Sites-Authorization is reserved for the monitor's origin-scoped Sites credential.");
    }
    headers.set("OAI-Sites-Authorization", `Bearer ${token}`);
    return fetchImpl(input, { ...init, headers });
  };
}

function json(value, status = 200) {
  return new Response(canonicalJson(value), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}

export function operationalFailureClass(error) {
  const message = (error instanceof Error ? error.message : String(error)).toLowerCase();
  if (/(storage|durable|kv mirror)/u.test(message)) {
    return "monitor_storage";
  }
  if (/(target|configured|configuration|status_kv|required)/u.test(message)) {
    return "configuration";
  }
  if (/(attestation|certificate|confidential|nonce|workload|image digest)/u.test(message)) {
    return "evaluator_attestation";
  }
  if (/(http [45][0-9]{2}|fetch|timeout|unavailable|network|redirect)/u.test(message)) {
    return "availability";
  }
  if (/(transparency|witness|log index|entry hash|signed head|fork|rewind)/u.test(message)) {
    return "response_transparency";
  }
  if (/(release|manifest|deployment|predecessor|rollback|artifact|resource hash)/u.test(message)) {
    return "release_integrity";
  }
  return "unknown";
}

async function hmacHex(secret, bytes) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes));
  return [...signature].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

export function operationalAlert(status) {
  return {
    schemaVersion: 1,
    ok: status?.ok === true,
    checkedAt: typeof status?.checkedAt === "string" ? status.checkedAt : null,
    configurationFailureClass: status?.configurationError
      ? operationalFailureClass(status.configurationError)
      : null,
    storageFailureClass: status?.storageError
      ? operationalFailureClass(status.storageError)
      : null,
    targets: Array.isArray(status?.targets)
      ? status.targets.map((target) => ({
          target: typeof target?.target === "string" ? target.target : "invalid-target",
          ok: target?.ok === true,
          durationMs: Number.isSafeInteger(target?.durationMs) ? target.durationMs : null,
          failureClass: target?.ok === true
            ? null
            : (typeof target?.failureClass === "string" ? target.failureClass : "unknown"),
          releaseId: typeof target?.releaseId === "string" ? target.releaseId : null,
        }))
      : [],
  };
}

async function sendAlert(env, status) {
  if (!env.ALERT_WEBHOOK_URL) return;
  if (!env.ALERT_HMAC_SECRET || env.ALERT_HMAC_SECRET.length < 32) {
    throw new TypeError("ALERT_HMAC_SECRET must be at least 32 characters when alerts are configured.");
  }
  const url = new URL(env.ALERT_WEBHOOK_URL);
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new TypeError("ALERT_WEBHOOK_URL must be a safe HTTPS URL.");
  }
  const bytes = new TextEncoder().encode(canonicalJson(operationalAlert(status)));
  const response = await fetch(url, {
    method: "POST",
    redirect: "manual",
    headers: {
      "content-type": "application/json",
      "x-herd-signature": `sha256=${await hmacHex(env.ALERT_HMAC_SECRET, bytes)}`,
    },
    body: bytes,
  });
  if (response.status < 200 || response.status >= 300) throw new TypeError(`Alert webhook returned HTTP ${response.status}.`);
}

function lastGoodWitness(result) {
  return {
    schemaVersion: 1,
    target: result.target,
    releaseId: result.releaseId,
    previousRelease: result.previousRelease,
    evaluatorKeyEpoch: result.evaluatorKeyEpoch,
    releaseCreatedAt: result.releaseCreatedAt,
    environment: result.environment,
    deployedAt: result.deployedAt,
    manifestSha256: result.manifestSha256,
    deploymentSha256: result.deploymentSha256,
    responseTransparency: result.responseTransparency ?? null,
    witnessedAt: result.checkedAt,
  };
}

function exactRecord(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return (
    actual.length === expected.length &&
    actual.every((key, index) => key === expected[index])
  );
}

function validIdentifier(value) {
  return (
    typeof value === "string" &&
    /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(value)
  );
}

function validSha256(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/u.test(value);
}

function validKeyWitness(value) {
  return (
    exactRecord(value, ["keyId", "publicKeySha256"]) &&
    validIdentifier(value.keyId) &&
    validSha256(value.publicKeySha256)
  );
}

function validEvaluatorKeyEpoch(value) {
  return (
    exactRecord(value, [
      "evaluatorKeyEpochId",
      "sha256",
      "workloadImageDigest",
      "responseDecryption",
      "evaluationResultSigning",
      "policySigning",
      "responseTransparency",
    ]) &&
    validIdentifier(value.evaluatorKeyEpochId) &&
    validSha256(value.sha256) &&
    typeof value.workloadImageDigest === "string" &&
    /^sha256:[0-9a-f]{64}$/u.test(value.workloadImageDigest) &&
    validKeyWitness(value.responseDecryption) &&
    validKeyWitness(value.evaluationResultSigning) &&
    validKeyWitness(value.policySigning) &&
    exactRecord(value.responseTransparency, [
      "logId",
      "keyId",
      "publicKeySha256",
    ]) &&
    value.responseTransparency.logId === "herd-response-log-v1" &&
    validIdentifier(value.responseTransparency.keyId) &&
    validSha256(value.responseTransparency.publicKeySha256)
  );
}

function validPreviousRelease(value) {
  return (
    value === null ||
    (exactRecord(value, ["releaseId", "manifestSha256"]) &&
      validIdentifier(value.releaseId) &&
      validSha256(value.manifestSha256))
  );
}

export function assertReleaseContinuity(previous, result) {
  if (result.manifestSha256 !== previous.manifestSha256) {
    if (
      result.previousRelease?.releaseId !== previous.releaseId ||
      result.previousRelease?.manifestSha256 !== previous.manifestSha256
    ) {
      throw new TypeError(
        "new release does not name the exact last witnessed release manifest as its predecessor.",
      );
    }
  } else if (result.releaseId !== previous.releaseId) {
    throw new TypeError("artifact release ID changed without a new signed manifest.");
  }

  const priorEpoch = previous.evaluatorKeyEpoch;
  const nextEpoch = result.evaluatorKeyEpoch;
  if (
    nextEpoch.responseTransparency.logId !== priorEpoch.responseTransparency.logId ||
    nextEpoch.responseTransparency.keyId !== priorEpoch.responseTransparency.keyId ||
    nextEpoch.responseTransparency.publicKeySha256 !==
      priorEpoch.responseTransparency.publicKeySha256
  ) {
    throw new TypeError(
      "lifetime-global response-transparency signing identity changed.",
    );
  }
  if (nextEpoch.evaluatorKeyEpochId === priorEpoch.evaluatorKeyEpochId) {
    if (nextEpoch.sha256 !== priorEpoch.sha256) {
      throw new TypeError(
        "existing evaluator epoch changed its image or evaluator key tuple.",
      );
    }
    return;
  }
  for (const purpose of [
    "responseDecryption",
    "evaluationResultSigning",
    "policySigning",
  ]) {
    if (
      nextEpoch[purpose].keyId === priorEpoch[purpose].keyId ||
      nextEpoch[purpose].publicKeySha256 === priorEpoch[purpose].publicKeySha256
    ) {
      throw new TypeError(
        `new evaluator epoch did not replace its complete ${purpose} key identity.`,
      );
    }
  }
}

function validatePriorWitness(value, targetName) {
  if (value === null || value === undefined) return null;
  if (
    typeof value !== "object" ||
    value.schemaVersion !== 1 ||
    value.target !== targetName ||
    !validIdentifier(value.releaseId) ||
    !validPreviousRelease(value.previousRelease) ||
    !validEvaluatorKeyEpoch(value.evaluatorKeyEpoch) ||
    typeof value.releaseCreatedAt !== "string" ||
    !['staging', 'production'].includes(value.environment) ||
    typeof value.deployedAt !== "string" ||
    !validSha256(value.manifestSha256) ||
    !validSha256(value.deploymentSha256) ||
    (value.responseTransparency !== null && typeof value.responseTransparency !== "object")
  ) {
    throw new TypeError(`Durable last-good witness for ${targetName} is corrupt.`);
  }
  return value;
}

export async function runChecks(env, store) {
  if (!store || typeof store.getStatus !== "function" || typeof store.getWitness !== "function" || typeof store.commit !== "function") {
    throw new TypeError("A serial durable witness store is required.");
  }
  const checkedAt = new Date().toISOString();
  const previous = await store.getStatus();
  let configuredTargets;
  try {
    configuredTargets = targets(env);
  } catch (error) {
    const status = {
      schemaVersion: 2,
      ok: false,
      checkedAt,
      targets: [],
      configurationError: error instanceof Error ? error.message : String(error),
    };
    await store.commit(status, []);
    if (env.STATUS_KV) await env.STATUS_KV.put(STATUS_KEY, canonicalJson(status));
    await sendAlert(env, status);
    return status;
  }
  const results = await Promise.all(
    configuredTargets.map(async (target) => {
      const targetName = typeof target?.name === "string" ? target.name : "invalid-target";
      const startedAt = Date.now();
      try {
        const prior = validatePriorWitness(await store.getWitness(targetName), targetName);
        const result = await verifyTarget(target, {
          fetchImpl: sitesAuthorizedFetch(env, target),
          previousResponseTransparency: prior?.responseTransparency ?? null,
        });
        if (prior) {
          assertReleaseContinuity(prior, result);
          if (result.releaseCreatedAt < prior.releaseCreatedAt) {
            throw new TypeError("release creation timestamp moved backwards; possible release rollback detected.");
          }
          if (result.releaseCreatedAt === prior.releaseCreatedAt && result.manifestSha256 !== prior.manifestSha256) {
            throw new TypeError("release manifest changed at an already witnessed release timestamp.");
          }
          if (result.deployedAt < prior.deployedAt) {
            throw new TypeError("deployment timestamp moved backwards; possible rollback detected.");
          }
          if (result.deployedAt === prior.deployedAt && result.deploymentSha256 !== prior.deploymentSha256) {
            throw new TypeError("deployment changed at an already witnessed deployment timestamp.");
          }
        }
        return {
          ...result,
          durationMs: Math.max(0, Date.now() - startedAt),
        };
      } catch (error) {
        return {
          schemaVersion: 1,
          target: targetName,
          ok: false,
          checkedAt: new Date().toISOString(),
          durationMs: Math.max(0, Date.now() - startedAt),
          failureClass: operationalFailureClass(error),
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }),
  );
  results.sort((left, right) => (left.target < right.target ? -1 : left.target > right.target ? 1 : 0));
  const status = { schemaVersion: 2, ok: results.every(({ ok }) => ok), checkedAt, targets: results };
  const successfulWitnesses = results.filter(({ ok }) => ok).map(lastGoodWitness);
  await store.commit(status, successfulWitnesses);
  try {
    if (!env.STATUS_KV) throw new TypeError("STATUS_KV is not configured.");
    await Promise.all([
      env.STATUS_KV.put(STATUS_KEY, canonicalJson(status)),
      ...successfulWitnesses.map((witness) => env.STATUS_KV.put(witnessKey(witness.target), canonicalJson(witness))),
    ]);
  } catch (error) {
    const storageFailure = {
      ...status,
      ok: false,
      storageError: `STATUS_KV mirror failed: ${error instanceof Error ? error.message : String(error)}`,
    };
    await store.commit(storageFailure, []);
    await sendAlert(env, storageFailure);
    return storageFailure;
  }
  const wasOk = previous?.ok === true;
  if (!status.ok || (!wasOk && status.ok)) await sendAlert(env, status);
  return status;
}

class DurableWitnessStore {
  constructor(storage) {
    this.storage = storage;
  }

  async getStatus() {
    return (await this.storage.get(STATUS_KEY)) ?? null;
  }

  async getWitness(targetName) {
    return (await this.storage.get(witnessKey(targetName))) ?? null;
  }

  async commit(status, witnesses) {
    await this.storage.transaction(async (transaction) => {
      await transaction.put(STATUS_KEY, status);
      for (const witness of witnesses) await transaction.put(witnessKey(witness.target), witness);
    });
  }
}

export class ReleaseMonitorCoordinator {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this.serial = Promise.resolve();
  }

  async fetch(request) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/status") {
      const status = await this.state.storage.get(STATUS_KEY);
      return status ? json(status, status.ok ? 200 : 503) : json({ ok: false, error: "No check has completed." }, 503);
    }
    if (request.method !== "POST" || url.pathname !== "/check") return json({ ok: false, error: "Not found" }, 404);
    const execute = () => runChecks(this.env, new DurableWitnessStore(this.state.storage));
    const resultPromise = this.serial.then(execute, execute);
    this.serial = resultPromise.then(() => undefined, () => undefined);
    try {
      const status = await resultPromise;
      return json(status, status.ok ? 200 : 503);
    } catch (error) {
      return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 503);
    }
  }
}

function coordinator(env) {
  if (!env.MONITOR_COORDINATOR) throw new TypeError("MONITOR_COORDINATOR Durable Object binding is not configured.");
  return env.MONITOR_COORDINATOR.get(env.MONITOR_COORDINATOR.idFromName("herd-release-monitor-global-v1"));
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!authorized(request, env)) return json({ ok: false, error: "Unauthorized" }, env.MONITOR_BEARER_TOKEN ? 401 : 503);
    if ((request.method === "POST" && url.pathname === "/check") || (request.method === "GET" && url.pathname === "/status")) {
      try {
        return await coordinator(env).fetch(new Request(`https://coordinator${url.pathname}`, { method: request.method }));
      } catch (error) {
        return json({ ok: false, error: error instanceof Error ? error.message : String(error) }, 503);
      }
    }
    return json({ ok: false, error: "Not found" }, 404);
  },

  async scheduled(_controller, env, context) {
    context.waitUntil(coordinator(env).fetch(new Request("https://coordinator/check", { method: "POST" })));
  },
};
