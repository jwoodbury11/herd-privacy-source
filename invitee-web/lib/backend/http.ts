const DEFAULT_HEADERS = {
  "Cache-Control": "no-store",
  "Content-Type": "application/json; charset=utf-8",
  "X-Content-Type-Options": "nosniff",
};

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly details?: Record<string, unknown>;

  constructor(
    status: number,
    code: string,
    message: string,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function jsonResponse(
  body: unknown,
  init: ResponseInit & { headers?: HeadersInit } = {},
): Response {
  const headers = new Headers(DEFAULT_HEADERS);
  if (init.headers) {
    new Headers(init.headers).forEach((value, key) => headers.set(key, value));
  }
  return new Response(JSON.stringify(body), { ...init, headers });
}

export async function readJsonObject(request: Request): Promise<Record<string, unknown>> {
  requireSameOrigin(request);
  const contentType = (request.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (contentType !== "application/json") {
    throw new ApiError(
      415,
      "unsupported_media_type",
      "The request Content-Type must be application/json.",
    );
  }
  const maximumBytes = 64 * 1024;
  const contentLengthValue = request.headers.get("content-length");
  if (contentLengthValue !== null) {
    const contentLength = Number(contentLengthValue);
    if (!Number.isInteger(contentLength) || contentLength < 0) {
      throw new ApiError(400, "invalid_request", "Content-Length is invalid.");
    }
    if (contentLength > maximumBytes) {
      throw new ApiError(413, "payload_too_large", "The request body is too large.");
    }
  }

  if (!request.body) {
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON.");
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // The size violation remains authoritative even if the underlying
          // request stream cannot be cancelled cleanly.
        }
        throw new ApiError(413, "payload_too_large", "The request body is too large.");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON.");
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON.");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(400, "invalid_request", "The request body must be a JSON object.");
  }
  return value as Record<string, unknown>;
}

export function requireSameOrigin(request: Request): void {
  const fetchSite = request.headers.get("sec-fetch-site")?.toLowerCase();
  if (fetchSite === "cross-site") {
    throw new ApiError(403, "cross_origin_request", "Cross-origin writes are not allowed.");
  }
  const origin = request.headers.get("origin");
  if (!origin) return;
  let originValue: string;
  try {
    originValue = new URL(origin).origin;
  } catch {
    throw new ApiError(403, "cross_origin_request", "Cross-origin writes are not allowed.");
  }
  if (originValue !== new URL(request.url).origin) {
    throw new ApiError(403, "cross_origin_request", "Cross-origin writes are not allowed.");
  }
}

export async function withApiErrors(
  action: () => Promise<Response>,
): Promise<Response> {
  try {
    return await action();
  } catch (error) {
    if (error instanceof ApiError) {
      return jsonResponse(
        {
          error: {
            code: error.code,
            message: error.message,
            ...(error.details ? { details: error.details } : {}),
          },
        },
        { status: error.status },
      );
    }

    console.error("Unhandled Herd API error", error);
    return jsonResponse(
      {
        error: {
          code: "internal_error",
          message: "The service could not complete the request.",
        },
      },
      { status: 500 },
    );
  }
}

export function requireString(
  value: unknown,
  field: string,
  options: { min?: number; max?: number; allowEmpty?: boolean } = {},
): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_request", `${field} must be a string.`);
  }
  const result = value.trim();
  const minimum = options.min ?? (options.allowEmpty ? 0 : 1);
  if (result.length < minimum || result.length > (options.max ?? 500)) {
    throw new ApiError(
      400,
      "invalid_request",
      `${field} must be between ${minimum} and ${options.max ?? 500} characters.`,
    );
  }
  return result;
}

export function requireIdentifier(value: unknown, field: string): string {
  const identifier = requireString(value, field, { min: 1, max: 120 });
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(identifier)) {
    throw new ApiError(
      400,
      "invalid_request",
      `${field} contains unsupported characters.`,
    );
  }
  return identifier;
}

export function requireUuid(value: unknown, field: string): string {
  if (
    typeof value !== "string" ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(
      value.trim(),
    )
  ) {
    throw new ApiError(400, "invalid_request", `${field} must be a UUID string.`);
  }
  return value.trim().toLowerCase();
}
