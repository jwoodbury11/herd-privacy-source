import type { HerdBindings } from "@/db";

import { ApiError } from "./http";

export async function requireOperatorAuthorization(
  request: Request,
  bindings: HerdBindings,
): Promise<void> {
  const expected = bindings.HERD_OPERATOR_TOKEN?.trim() ?? "";
  const authorization = request.headers.get("authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (expected.length < 32 || supplied.length < 32) {
    throw new ApiError(401, "operator_unauthorized", "Operator authorization failed.");
  }
  const encoder = new TextEncoder();
  const [left, right] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
    crypto.subtle.digest("SHA-256", encoder.encode(supplied)),
  ]);
  let difference = 0;
  const leftBytes = new Uint8Array(left);
  const rightBytes = new Uint8Array(right);
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  if (difference !== 0) {
    throw new ApiError(401, "operator_unauthorized", "Operator authorization failed.");
  }
}
