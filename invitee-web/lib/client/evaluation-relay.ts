const MAIN_RESPONSE_LIMIT_BYTES = 600 * 1024;
const EVALUATOR_RESPONSE_LIMIT_BYTES = 512 * 1024;
const EVALUATOR_REQUEST_LIMIT_BYTES = 600 * 1024;
const MAIN_REQUEST_TIMEOUT_MS = 12_000;
const EVALUATOR_REQUEST_TIMEOUT_MS = 12_000;

type JsonObject = Record<string, unknown>;

export type EvaluationRelayOutcome = "completed" | "pending";

function isObject(value: unknown): value is JsonObject {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function responseTextWithinLimit(response: Response, limit: number) {
  const declaredLength = response.headers.get("content-length");
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (Number.isFinite(parsedLength) && parsedLength > limit) {
      throw new Error("The evaluation response was too large.");
    }
  }

  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > limit) {
        await reader.cancel();
        throw new Error("The evaluation response was too large.");
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
    throw new Error("The evaluation response was not valid UTF-8.");
  }
}

function parseJsonObject(text: string, message: string): JsonObject {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error(message);
  }
  if (!isObject(value)) throw new Error(message);
  return value;
}

async function fetchWithTimeout(
  input: RequestInfo | URL,
  init: RequestInit,
  timeoutMs: number,
) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(input, { ...init, signal: controller.signal });
  } finally {
    window.clearTimeout(timeout);
  }
}

function pinnedEvaluatorURL(rawURL: unknown, rawPin: unknown) {
  if (typeof rawURL !== "string" || typeof rawPin !== "string") {
    throw new Error("The evaluation relay destination was invalid.");
  }

  let endpoint: URL;
  try {
    endpoint = new URL(rawURL);
  } catch {
    throw new Error("The evaluation relay destination was invalid.");
  }
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username !== "" ||
    endpoint.password !== "" ||
    endpoint.pathname !== "/api/v1/relay/" ||
    endpoint.search !== "" ||
    endpoint.hash !== ""
  ) {
    throw new Error("The evaluation relay destination was invalid.");
  }

  const pin = rawPin.trim();
  let pinnedOrigin: string;
  try {
    const parsedPin = new URL(pin);
    if (
      parsedPin.protocol !== "https:" ||
      parsedPin.username !== "" ||
      parsedPin.password !== "" ||
      (parsedPin.pathname !== "" && parsedPin.pathname !== "/") ||
      parsedPin.search !== "" ||
      parsedPin.hash !== "" ||
      parsedPin.origin !== pin.replace(/\/$/u, "")
    ) {
      throw new Error("invalid pin");
    }
    pinnedOrigin = parsedPin.origin;
  } catch {
    throw new Error("The evaluation relay destination was invalid.");
  }

  if (endpoint.origin !== pinnedOrigin) {
    throw new Error("The evaluation relay destination did not match its pin.");
  }
  return endpoint;
}

/**
 * Acquires one host-only evaluation lease, relays the opaque request without
 * credentials, and returns the evaluator's opaque signed response to Herd.
 * Transient failures intentionally throw so the caller can leave the event
 * pending and try again during the next normal refresh.
 */
export async function relayHostEventEvaluation(
  eventId: string,
): Promise<EvaluationRelayOutcome> {
  const encodedEventId = encodeURIComponent(eventId);
  const mainEndpoint = `/api/events/${encodedEventId}/evaluation`;
  const leaseResponse = await fetchWithTimeout(
    mainEndpoint,
    {
      method: "POST",
      credentials: "include",
      redirect: "manual",
      cache: "no-store",
      headers: { accept: "application/json" },
    },
    MAIN_REQUEST_TIMEOUT_MS,
  );
  if (leaseResponse.status === 202 || leaseResponse.status === 409) return "pending";
  if (!leaseResponse.ok || leaseResponse.type === "opaqueredirect") {
    throw new Error("The evaluation relay is temporarily unavailable.");
  }

  const leaseText = await responseTextWithinLimit(leaseResponse, MAIN_RESPONSE_LIMIT_BYTES);
  const lease = parseJsonObject(leaseText, "The evaluation relay returned an invalid lease.");
  if (lease.eventId !== eventId) {
    throw new Error("The evaluation relay returned the wrong event.");
  }

  // A repeated request may race with a successful completion. In that case the
  // main service returns the already-final resolution and there is nothing to relay.
  if (isObject(lease.resolution) && lease.relayRequest === undefined) return "completed";
  if (
    !isObject(lease.relayRequest) ||
    typeof lease.leaseId !== "string" ||
    lease.leaseId.length === 0 ||
    lease.leaseId.length > 128 ||
    typeof lease.expiresAt !== "string" ||
    !Number.isFinite(Date.parse(lease.expiresAt))
  ) {
    throw new Error("The evaluation relay returned an invalid lease.");
  }

  const evaluatorURL = pinnedEvaluatorURL(lease.evaluatorUrl, lease.evaluatorHost);
  const relayBody = JSON.stringify(lease.relayRequest);
  if (new TextEncoder().encode(relayBody).byteLength > EVALUATOR_REQUEST_LIMIT_BYTES) {
    throw new Error("The evaluation relay request was too large.");
  }

  const evaluatorResponse = await fetchWithTimeout(
    evaluatorURL,
    {
      method: "POST",
      credentials: "omit",
      redirect: "manual",
      cache: "no-store",
      referrerPolicy: "no-referrer",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: relayBody,
    },
    EVALUATOR_REQUEST_TIMEOUT_MS,
  );
  if (!evaluatorResponse.ok || evaluatorResponse.type === "opaqueredirect") {
    throw new Error("The evaluator is temporarily unavailable.");
  }

  const evaluationText = await responseTextWithinLimit(
    evaluatorResponse,
    EVALUATOR_RESPONSE_LIMIT_BYTES,
  );
  parseJsonObject(evaluationText, "The evaluator returned an invalid response.");

  // Preserve the evaluator's JSON object byte-for-byte inside the required
  // completion wrapper instead of parsing and reserializing its signed payload.
  const completionBody = `{"evaluationResponse":${evaluationText}}`;
  if (new TextEncoder().encode(completionBody).byteLength > MAIN_RESPONSE_LIMIT_BYTES) {
    throw new Error("The evaluator response was too large.");
  }

  const completionResponse = await fetchWithTimeout(
    mainEndpoint,
    {
      method: "PUT",
      credentials: "include",
      redirect: "manual",
      cache: "no-store",
      headers: {
        accept: "application/json",
        "content-type": "application/json",
      },
      body: completionBody,
    },
    MAIN_REQUEST_TIMEOUT_MS,
  );
  if (completionResponse.status === 202 || completionResponse.status === 409) return "pending";
  if (!completionResponse.ok || completionResponse.type === "opaqueredirect") {
    throw new Error("Herd could not record the evaluation yet.");
  }
  return "completed";
}
