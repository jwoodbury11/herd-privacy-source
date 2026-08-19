"use client";

const API_PATH = /^\/api\//u;
const API_REQUEST_TIMEOUT_MS = 15_000;

function template(pathname: string): string {
  const segments = pathname.split("/").filter(Boolean);
  return `/${segments.map((segment, index) => {
    const prior = segments[index - 1];
    return prior === "events" || prior === "invites" ? `:${prior === "events" ? "event" : "invite"}` : segment;
  }).join("/")}`;
}

function operation(input: RequestInfo | URL, method: string): string {
  try {
    const raw = input instanceof Request ? input.url : String(input);
    const url = new URL(raw, window.location.origin);
    return `${method.toLowerCase()}.${template(url.pathname).replace(/^\/api\//u, "").replaceAll("/", ".").replaceAll(":", "")}`.slice(0, 80);
  } catch {
    return "unknown";
  }
}

function validRequestId(value: string | null): value is string {
  return value !== null && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value);
}

export async function trackedFetch(input: RequestInfo | URL, init: RequestInit = {}): Promise<Response> {
  const raw = input instanceof Request ? input.url : String(input);
  let pathname = "";
  let isSameOrigin = false;
  try {
    const url = new URL(raw, window.location.origin);
    pathname = url.pathname;
    isSameOrigin = url.origin === window.location.origin;
  } catch {
    return fetch(input, init);
  }
  if (!API_PATH.test(pathname) || pathname === "/api/telemetry") return fetch(input, init);

  const requestId = crypto.randomUUID();
  const headers = new Headers(init.headers ?? (input instanceof Request ? input.headers : undefined));
  // Keep direct evaluator calls credential-free and free of custom request headers so
  // observability can never introduce a new browser preflight dependency.
  if (isSameOrigin) {
    headers.set("x-herd-request-id", requestId);
    headers.set("x-herd-client-platform", "web");
  }
  const method = (init.method ?? (input instanceof Request ? input.method : "GET")).toUpperCase();
  const startedAt = performance.now();
  const requestController = new AbortController();
  const upstreamSignal = init.signal ?? (input instanceof Request ? input.signal : undefined);
  const forwardAbort = () => requestController.abort(upstreamSignal?.reason);
  if (upstreamSignal?.aborted) forwardAbort();
  else upstreamSignal?.addEventListener("abort", forwardAbort, { once: true });
  let timedOut = false;
  const timeout = window.setTimeout(() => {
    timedOut = true;
    requestController.abort();
  }, API_REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(input, { ...init, headers, signal: requestController.signal });
    void reportClientSignal({
      signal: "client_api_request",
      operation: operation(input, method),
      outcome: response.ok ? "success" : "failure",
      statusCode: response.status,
      errorCode: response.headers.get("x-herd-error-code") ?? "none",
      durationMs: performance.now() - startedAt,
      correlationId: validRequestId(response.headers.get("x-herd-request-id"))
        ? response.headers.get("x-herd-request-id")!
        : requestId,
    });
    return response;
  } catch (error) {
    void reportClientSignal({
      signal: "client_api_request",
      operation: operation(input, method),
      outcome: timedOut ? "failure" : error instanceof DOMException && error.name === "AbortError" ? "cancelled" : "failure",
      errorCode: timedOut ? "request_timeout" : error instanceof DOMException && error.name === "AbortError" ? "aborted" : "network_error",
      durationMs: performance.now() - startedAt,
      correlationId: requestId,
    });
    if (timedOut) throw new Error("Herd took too long to respond. Try again.");
    throw error;
  } finally {
    window.clearTimeout(timeout);
    upstreamSignal?.removeEventListener("abort", forwardAbort);
  }
}

export async function reportClientSignal(signal: Record<string, unknown>): Promise<void> {
  try {
    await fetch("/api/telemetry", {
      method: "POST",
      credentials: "omit",
      keepalive: true,
      headers: { "content-type": "application/json", "x-herd-client-platform": "web" },
      body: JSON.stringify({
        schemaVersion: 1,
        platform: "web",
        signal: signal.signal ?? "client_runtime",
        operation: signal.operation ?? "unknown",
        outcome: signal.outcome ?? "failure",
        statusCode: signal.statusCode ?? 0,
        errorCode: signal.errorCode ?? "none",
        durationMs: signal.durationMs ?? 0,
        correlationId: signal.correlationId ?? crypto.randomUUID(),
      }),
    });
  } catch {
    // Telemetry is deliberately best-effort and must never alter product behavior.
  }
}
