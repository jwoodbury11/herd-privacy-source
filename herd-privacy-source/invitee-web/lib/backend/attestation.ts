import type { HerdBindings } from "@/db";
import {
  base64UrlToBytes,
  bytesToBase64Url,
} from "@/lib/privacy/protocol";

import { getEvaluatorAttestationProxyConfig } from "./config";
import { ApiError } from "./http";

const MAXIMUM_ATTESTATION_RESPONSE_BYTES = 128 * 1024;

function exactRecord(value: unknown, expected: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new TypeError("Invalid evaluator attestation response.");
  }
  const record = value as Record<string, unknown>;
  const actual = Object.keys(record).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    throw new TypeError("Invalid evaluator attestation response.");
  }
  return record;
}

export function normalizeAttestationNonce(value: unknown): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_request", "nonce must be canonical base64url.");
  }
  try {
    const bytes = base64UrlToBytes(value);
    if (bytes.length !== 32 || bytesToBase64Url(bytes) !== value) throw new TypeError();
  } catch {
    throw new ApiError(400, "invalid_request", "nonce must encode exactly 32 bytes.");
  }
  return value;
}

export async function fetchEvaluatorAttestation(
  bindings: HerdBindings,
  nonce: string,
): Promise<unknown> {
  const config = getEvaluatorAttestationProxyConfig(bindings);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  let response: Response;
  try {
    response = await fetch(config.attestationUrl, {
      method: "POST",
      headers: {
        authorization: `Bearer ${config.token}`,
        "content-type": "application/json",
        accept: "application/json",
        ...(config.sitesBypassToken
          ? { "OAI-Sites-Authorization": `Bearer ${config.sitesBypassToken}` }
          : {}),
      },
      body: JSON.stringify({ protocolVersion: 1, nonce }),
      redirect: "manual",
      signal: controller.signal,
    });
  } catch {
    throw new ApiError(
      503,
      "evaluator_attestation_unavailable",
      "The confidential evaluator could not be attested.",
    );
  } finally {
    clearTimeout(timeout);
  }
  if (!response.ok) {
    throw new ApiError(
      503,
      "evaluator_attestation_unavailable",
      "The confidential evaluator could not be attested.",
    );
  }
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAXIMUM_ATTESTATION_RESPONSE_BYTES) {
    throw new ApiError(502, "invalid_evaluator_attestation", "The evaluator attestation is invalid.");
  }
  const text = await response.text();
  if (text.length > MAXIMUM_ATTESTATION_RESPONSE_BYTES) {
    throw new ApiError(502, "invalid_evaluator_attestation", "The evaluator attestation is invalid.");
  }
  try {
    const result = exactRecord(JSON.parse(text) as unknown, [
      "protocolVersion",
      "tokenType",
      "audience",
      "nonce",
      "keyBinding",
      "keyBindingHash",
      "attestationToken",
    ]);
    if (
      result.protocolVersion !== 1 ||
      result.tokenType !== "google-pki" ||
      result.nonce !== nonce ||
      typeof result.audience !== "string" ||
      typeof result.keyBindingHash !== "string" ||
      typeof result.attestationToken !== "string" ||
      result.attestationToken.length < 64 ||
      result.attestationToken.length > 96 * 1024 ||
      !result.keyBinding ||
      typeof result.keyBinding !== "object" ||
      Array.isArray(result.keyBinding)
    ) {
      throw new TypeError();
    }
    return result;
  } catch {
    throw new ApiError(
      502,
      "invalid_evaluator_attestation",
      "The evaluator attestation is invalid.",
    );
  }
}
