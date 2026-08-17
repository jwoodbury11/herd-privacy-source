import type { HerdBindings } from "@/db";

import { getSchedulerConfig } from "./config";
import { ApiError } from "./http";

async function constantTimeEqual(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

export async function requireSchedulerAuthorization(
  request: Request,
  bindings: HerdBindings,
): Promise<void> {
  const expected = getSchedulerConfig(bindings).token;
  const authorization = request.headers.get("authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (!supplied || !(await constantTimeEqual(supplied, expected))) {
    throw new ApiError(
      401,
      "scheduler_unauthorized",
      "Scheduler authorization failed.",
    );
  }
}

export async function requireEmptySchedulerBody(request: Request): Promise<void> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/u.test(declaredLength)) {
      throw new ApiError(400, "invalid_request", "Content-Length is invalid.");
    }
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength)) {
      throw new ApiError(400, "invalid_request", "Content-Length is invalid.");
    }
    if (parsedLength > 0) {
      throw new ApiError(400, "invalid_request", "The scheduler request body must be empty.");
    }
  }
  if (!request.body) return;

  const reader = request.body.getReader();
  try {
    const first = await reader.read();
    if (!first.done) {
      try {
        await reader.cancel();
      } catch {
        // The non-empty-body rejection remains authoritative.
      }
      throw new ApiError(
        400,
        "invalid_request",
        "The scheduler request body must be empty.",
      );
    }
  } finally {
    reader.releaseLock();
  }
}

const MAXIMUM_SCHEDULER_JSON_BYTES = 64 * 1024;

/**
 * Reads an authenticated scheduler request without applying browser Origin
 * checks. Callers must authorize the request before invoking this function.
 */
export async function readSchedulerJsonObject(
  request: Request,
): Promise<Record<string, unknown>> {
  const mediaType = (request.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    throw new ApiError(
      415,
      "unsupported_media_type",
      "The scheduler request Content-Type must be application/json.",
    );
  }

  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    if (!/^\d+$/u.test(declaredLength)) {
      throw new ApiError(400, "invalid_request", "Content-Length is invalid.");
    }
    const parsedLength = Number(declaredLength);
    if (!Number.isSafeInteger(parsedLength)) {
      throw new ApiError(400, "invalid_request", "Content-Length is invalid.");
    }
    if (parsedLength > MAXIMUM_SCHEDULER_JSON_BYTES) {
      throw new ApiError(
        413,
        "payload_too_large",
        "The scheduler request body is too large.",
      );
    }
  }

  if (!request.body) {
    throw new ApiError(
      400,
      "invalid_json",
      "The scheduler request body must be valid JSON.",
    );
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAXIMUM_SCHEDULER_JSON_BYTES) {
        try {
          await reader.cancel();
        } catch {
          // The size violation remains authoritative.
        }
        throw new ApiError(
          413,
          "payload_too_large",
          "The scheduler request body is too large.",
        );
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      400,
      "invalid_json",
      "The scheduler request body must be valid JSON.",
    );
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
    throw new ApiError(
      400,
      "invalid_json",
      "The scheduler request body must be valid JSON.",
    );
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(
      400,
      "invalid_request",
      "The scheduler request body must be a JSON object.",
    );
  }
  return value as Record<string, unknown>;
}
