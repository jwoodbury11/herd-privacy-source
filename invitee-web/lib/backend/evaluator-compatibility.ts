import type { HerdBindings } from "@/db";

import { getAuthConfig, getEvaluatorServiceConfig } from "./config";
import { signEventPolicy } from "./evaluator-trust";
import { ApiError } from "./http";

const MAXIMUM_READINESS_BYTES = 32 * 1024;
export const REQUIRED_EVALUATOR_POLICY_CAPABILITY =
  "policy_descriptor_evaluator_measurement_v1";

export type EvaluatorCompatibility = {
  protocolVersion: 1;
  policyDescriptorCapability: typeof REQUIRED_EVALUATOR_POLICY_CAPABILITY;
};

function compatibilityPolicyDocument(bindings: HerdBindings): string {
  const privateResponse = getAuthConfig(bindings).privateResponse;
  if (!privateResponse) {
    throw new ApiError(
      503,
      "evaluator_incompatible",
      "Private-response policy configuration is unavailable.",
    );
  }
  return JSON.stringify({
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    event: {
      id: "00000000-0000-4000-8000-000000000001",
      title: "Release compatibility check",
      eventDate: "2099-12-31T23:59:59.000Z",
      endDate: null,
      hostName: "Herd",
      locationName: "",
      locationAddress: "",
      eventDescription: "",
    },
    members: [{ id: "00000000-0000-4000-8000-000000000002" }],
    hostRules: { minimumParticipants: 2, requiredGroups: [] },
    rsvpDeadline: "2099-12-30T23:59:59.000Z",
    revealPolicy: "not_confirmed_or_confirmed_attendance",
    limits: {
      maximumParticipants: 2,
      maximumConditionGroups: 1,
      maximumMembersPerGroup: 1,
      paddedPlaintextBytes: 4096,
    },
    evaluator: {
      keyId: privateResponse.evaluatorKeyId,
      publicKey: privateResponse.evaluatorPublicKey,
      measurement: privateResponse.evaluatorMeasurement,
    },
    releaseId: privateResponse.releaseId,
  });
}

export async function requireEvaluatorCompatibility(
  bindings: HerdBindings,
): Promise<EvaluatorCompatibility> {
  const service = getEvaluatorServiceConfig(bindings);
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  let response: Response;
  try {
    response = await fetch(new URL("/readyz", service.url), {
      method: "GET",
      headers: {
        accept: "application/json",
        ...(service.sitesBypassToken
          ? { "OAI-Sites-Authorization": `Bearer ${service.sitesBypassToken}` }
          : {}),
      },
      redirect: "manual",
      signal: controller.signal,
    });
  } catch {
    throw new ApiError(
      503,
      "evaluator_compatibility_unavailable",
      "The confidential evaluator compatibility check is unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
  if (response.status !== 200) {
    throw new ApiError(
      503,
      "evaluator_compatibility_unavailable",
      "The confidential evaluator compatibility check is unavailable.",
    );
  }
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > MAXIMUM_READINESS_BYTES) {
    throw new ApiError(
      502,
      "invalid_evaluator_compatibility",
      "The confidential evaluator compatibility response is invalid.",
    );
  }
  const text = await response.text();
  if (text.length === 0 || text.length > MAXIMUM_READINESS_BYTES) {
    throw new ApiError(
      502,
      "invalid_evaluator_compatibility",
      "The confidential evaluator compatibility response is invalid.",
    );
  }
  let body: unknown;
  try {
    body = JSON.parse(text) as unknown;
  } catch {
    throw new ApiError(
      502,
      "invalid_evaluator_compatibility",
      "The confidential evaluator compatibility response is invalid.",
    );
  }
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new ApiError(
      502,
      "invalid_evaluator_compatibility",
      "The confidential evaluator compatibility response is invalid.",
    );
  }
  const record = body as Record<string, unknown>;
  if (record.status !== "ok" || record.protocolVersion !== 1) {
    throw new ApiError(
      502,
      "invalid_evaluator_compatibility",
      "The confidential evaluator compatibility response is invalid.",
    );
  }
  const capabilities = record.capabilities;
  if (
    Array.isArray(capabilities) &&
    !capabilities.includes(REQUIRED_EVALUATOR_POLICY_CAPABILITY)
  ) {
    throw new ApiError(
      503,
      "evaluator_incompatible",
      "The confidential evaluator does not support the deployed policy format.",
    );
  }
  if (!Array.isArray(capabilities)) {
    try {
      const certification = await signEventPolicy(
        bindings,
        compatibilityPolicyDocument(bindings),
      );
      if (!certification) throw new TypeError("Missing evaluator certification.");
    } catch {
      throw new ApiError(
        503,
        "evaluator_incompatible",
        "The confidential evaluator does not support the deployed policy format.",
      );
    }
  }
  return {
    protocolVersion: 1,
    policyDescriptorCapability: REQUIRED_EVALUATOR_POLICY_CAPABILITY,
  };
}
