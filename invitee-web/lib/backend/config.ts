import type { HerdBindings } from "@/db";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  normalizeEvaluatorPublicKey,
} from "@/lib/privacy/protocol";

import { ApiError } from "./http";
import { normalizePhoneNumber } from "./phone";

export type AuthConfig = {
  pepper: string;
  testBypassEnabled: boolean;
  qaBypassGeneration: string | null;
  testPhoneNumber: string | null;
  challengeTtlSeconds: number;
  resendSeconds: number;
  maxCodeAttempts: number;
  phoneRequestsPerHour: number;
  ipRequestsPerHour: number;
  sessionTtlSeconds: number;
  privateResponse: {
    evaluatorKeyId: string;
    evaluatorPublicKey: string;
    evaluatorMeasurement: string;
    releaseId: string;
  } | null;
  twilio: {
    apiKeySid: string;
    apiKeySecret: string;
    verifyServiceSid: string;
  } | null;
};

export type EvaluatorServiceConfig = {
  url: string;
  token: string;
  sitesBypassToken: string | null;
};

export type DeploymentProfile = "production" | "test";

export type EvaluatorTransport = "direct" | "client_relay";

export type EvaluatorRelayConfig = EvaluatorServiceConfig & {
  transport: "client_relay";
  evaluatorHost: string;
  evaluatorKeyId: string;
  evaluatorPublicKey: string;
  resultSigningKeyId: string;
  resultSigningPublicKey: string;
};

export type EvaluatorResultSigningConfig = {
  resultSigningKeyId: string;
  resultSigningPublicKey: string;
};

export type EvaluatorTrustSigningConfig = EvaluatorServiceConfig & {
  policySigningKeyId: string;
  policySigningPublicKey: string;
  transparencySigningKeyId: string;
  transparencySigningPublicKey: string;
};

export type EvaluatorAttestationProxyConfig = EvaluatorServiceConfig & {
  attestationUrl: string;
};

export type SchedulerConfig = {
  token: string;
};

export type InvitationDeliveryConfig = {
  publicAppUrl: string;
  twilio: {
    accountSid: string;
    apiKeySid: string;
    apiKeySecret: string;
    messagingServiceSid: string;
  };
};

function boundedInteger(
  value: string | undefined,
  fallback: number,
  minimum: number,
  maximum: number,
): number {
  if (value === undefined || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ApiError(500, "server_misconfigured", "Authentication timing is misconfigured.");
  }
  return parsed;
}

function required(value: string | undefined, name: string): string {
  if (!value) {
    throw new ApiError(500, "server_misconfigured", `${name} is not configured.`);
  }
  return value;
}

function requiredBounded(value: string | undefined, name: string, maximum: number): string {
  const result = required(value, name).trim();
  if (!result || result.length > maximum || /[\u0000-\u001f\u007f]/u.test(result)) {
    throw new ApiError(500, "server_misconfigured", `${name} is invalid.`);
  }
  return result;
}

function evaluatorKeyId(value: string | undefined): string {
  const result = requiredBounded(value, "HERD_EVALUATOR_KEY_ID", 120);
  if (!/^[A-Za-z0-9._-]+$/u.test(result)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_KEY_ID must be a release-scoped identifier.",
    );
  }
  return result;
}

function evaluatorPublicKey(value: string | undefined): string {
  try {
    const normalized = normalizeEvaluatorPublicKey(
      requiredBounded(value, "HERD_EVALUATOR_PUBLIC_KEY", 200),
    );
    const bytes = base64UrlToBytes(normalized);
    if (bytes[0] !== 0x04 || bytesToBase64Url(bytes) !== normalized) {
      throw new TypeError("Invalid X9.63 point encoding.");
    }
    return normalized;
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_PUBLIC_KEY must be an unpadded base64url P-256 X9.63 key.",
    );
  }
}

function p256SigningKeyId(value: string | undefined, bindingName: string): string {
  const result = requiredBounded(
    value,
    bindingName,
    120,
  );
  if (!/^[A-Za-z0-9._-]+$/u.test(result)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      `${bindingName} must be a release-scoped identifier.`,
    );
  }
  return result;
}

function p256SigningPublicKey(value: string | undefined, bindingName: string): string {
  try {
    const normalized = normalizeEvaluatorPublicKey(
      requiredBounded(
        value,
        bindingName,
        200,
      ),
    );
    const bytes = base64UrlToBytes(normalized);
    if (bytes[0] !== 0x04 || bytesToBase64Url(bytes) !== normalized) {
      throw new TypeError("Invalid X9.63 point encoding.");
    }
    return normalized;
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      `${bindingName} must be an unpadded base64url P-256 X9.63 key.`,
    );
  }
}

export function getDeploymentProfile(bindings: HerdBindings): DeploymentProfile {
  const value = bindings.HERD_DEPLOYMENT_PROFILE?.trim().toLowerCase();
  if (value === "production" || value === "test") return value;
  if (value) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_DEPLOYMENT_PROFILE must be production or test.",
    );
  }
  // Local harnesses carry an explicit QA marker. Anything else is production,
  // so a missing profile can never silently enable a weaker evaluator path.
  return bindings.HERD_TEST_BYPASS_ENABLED?.trim().toLowerCase() === "true"
    ? "test"
    : "production";
}

function optionalBoolean(value: string | undefined, name: string): boolean {
  if (value === undefined || value.trim() === "") return false;
  const normalized = value.trim().toLowerCase();
  if (normalized === "true") return true;
  if (normalized === "false") return false;
  throw new ApiError(500, "server_misconfigured", `${name} must be true or false.`);
}

function qaTestBypassConfig(bindings: HerdBindings): {
  enabled: boolean;
  generation: string | null;
} {
  const enabled = optionalBoolean(
    bindings.HERD_TEST_BYPASS_ENABLED,
    "HERD_TEST_BYPASS_ENABLED",
  );
  if (
    enabled &&
    !optionalBoolean(
      bindings.HERD_ALLOW_INSECURE_QA_BYPASS,
      "HERD_ALLOW_INSECURE_QA_BYPASS",
    )
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The QA authentication bypass requires a second explicit safety acknowledgement.",
    );
  }
  if (enabled && getDeploymentProfile(bindings) !== "test") {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The QA authentication bypass is forbidden in the production deployment profile.",
    );
  }
  if (!enabled) return { enabled: false, generation: null };

  const generation = requiredBounded(
    bindings.HERD_QA_BYPASS_GENERATION,
    "HERD_QA_BYPASS_GENERATION",
    120,
  );
  if (
    generation.length < 16 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/u.test(generation)
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_QA_BYPASS_GENERATION must be a unique identifier of at least 16 safe characters.",
    );
  }
  return { enabled: true, generation };
}

export function getEvaluatorServiceConfig(
  bindings: HerdBindings,
): EvaluatorServiceConfig {
  const rawUrl = requiredBounded(bindings.HERD_EVALUATOR_URL, "HERD_EVALUATOR_URL", 2_048);
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_URL must be a valid HTTPS endpoint.",
    );
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.origin === "null"
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_URL must be a valid HTTPS endpoint.",
    );
  }
  const token = requiredBounded(
    bindings.HERD_EVALUATOR_TOKEN,
    "HERD_EVALUATOR_TOKEN",
    512,
  );
  if (token.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_TOKEN must contain at least 32 characters.",
    );
  }
  const sitesBypassToken = bindings.HERD_EVALUATOR_SITES_BYPASS_TOKEN
    ? requiredBounded(
        bindings.HERD_EVALUATOR_SITES_BYPASS_TOKEN,
        "HERD_EVALUATOR_SITES_BYPASS_TOKEN",
        512,
      )
    : null;
  if (sitesBypassToken && sitesBypassToken.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_EVALUATOR_SITES_BYPASS_TOKEN must contain at least 32 characters.",
    );
  }
  return { url: url.toString(), token, sitesBypassToken };
}

export function getEvaluatorTransport(bindings: HerdBindings): EvaluatorTransport {
  const value = bindings.HERD_EVALUATOR_TRANSPORT?.trim().toLowerCase();
  const profile = getDeploymentProfile(bindings);
  if (!value) return profile === "production" ? "client_relay" : "direct";
  if (value === "direct") {
    if (profile === "production") {
      throw new ApiError(
        500,
        "server_misconfigured",
        "Production evaluation must use the signed client-relay transport.",
      );
    }
    return "direct";
  }
  if (value === "client_relay") return "client_relay";
  throw new ApiError(
    500,
    "server_misconfigured",
    "HERD_EVALUATOR_TRANSPORT must be direct or client_relay.",
  );
}

export function getEvaluatorRelayConfig(
  bindings: HerdBindings,
): EvaluatorRelayConfig {
  if (getEvaluatorTransport(bindings) !== "client_relay") {
    throw new ApiError(
      409,
      "evaluation_relay_disabled",
      "Client-relay evaluation is not enabled.",
    );
  }
  const service = getEvaluatorServiceConfig(bindings);
  const url = new URL(service.url);
  if (
    url.pathname !== "/api/v1/relay/" ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Client-relay evaluation must use the exact HTTPS /api/v1/relay/ endpoint.",
    );
  }
  const resultSigning = getEvaluatorResultSigningConfig(bindings);
  return {
    ...service,
    ...resultSigning,
    transport: "client_relay",
    evaluatorHost: url.origin,
    evaluatorKeyId: evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID),
    evaluatorPublicKey: evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY),
  };
}

export function getEvaluatorResultSigningConfig(
  bindings: HerdBindings,
): EvaluatorResultSigningConfig {
  const resultSigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID",
  );
  const resultSigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY",
  );
  const evaluatorEncryptionKeyId = evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID);
  const evaluatorEncryptionPublicKey = evaluatorPublicKey(
    bindings.HERD_EVALUATOR_PUBLIC_KEY,
  );
  if (
    resultSigningKeyId === evaluatorEncryptionKeyId ||
    resultSigningPublicKey === evaluatorEncryptionPublicKey
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The evaluator result signing key must be distinct from its response decryption key.",
    );
  }
  return {
    resultSigningKeyId,
    resultSigningPublicKey,
  };
}

export function getEvaluatorTrustSigningConfig(
  bindings: HerdBindings,
): EvaluatorTrustSigningConfig | null {
  const values = [
    bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
  ];
  const configured = values.filter((value) => Boolean(value?.trim())).length;
  if (configured === 0 && getDeploymentProfile(bindings) === "test") return null;
  if (configured !== values.length) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Evaluator policy and transparency signing pins must be configured together.",
    );
  }

  const service = getEvaluatorServiceConfig(bindings);
  const policySigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_POLICY_SIGNING_KEY_ID,
    "HERD_EVALUATOR_POLICY_SIGNING_KEY_ID",
  );
  const policySigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY",
  );
  const transparencySigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID,
    "HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID",
  );
  const transparencySigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY",
  );
  const encryptionKeyId = evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID);
  const encryptionPublicKey = evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY);
  const resultSigningKeyId = p256SigningKeyId(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_KEY_ID,
    "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID",
  );
  const resultSigningPublicKey = p256SigningPublicKey(
    bindings.HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY,
    "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY",
  );
  const keyIds = [
    encryptionKeyId,
    resultSigningKeyId,
    policySigningKeyId,
    transparencySigningKeyId,
  ];
  const publicKeys = [
    encryptionPublicKey,
    resultSigningPublicKey,
    policySigningPublicKey,
    transparencySigningPublicKey,
  ];
  if (new Set(keyIds).size !== keyIds.length || new Set(publicKeys).size !== publicKeys.length) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Every evaluator purpose must use a distinct release-scoped key pair.",
    );
  }

  return {
    ...service,
    policySigningKeyId,
    policySigningPublicKey,
    transparencySigningKeyId,
    transparencySigningPublicKey,
  };
}

export function getEvaluatorAttestationProxyConfig(
  bindings: HerdBindings,
): EvaluatorAttestationProxyConfig {
  const service = getEvaluatorServiceConfig(bindings);
  const rawUrl = bindings.HERD_ATTESTATION_URL?.trim() ||
    new URL("/api/v1/attestation", service.url).toString();
  let attestationUrl: URL;
  try {
    attestationUrl = new URL(rawUrl);
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_ATTESTATION_URL must be a valid HTTPS endpoint.",
    );
  }
  if (
    attestationUrl.protocol !== "https:" ||
    attestationUrl.pathname !== "/api/v1/attestation" ||
    attestationUrl.search ||
    attestationUrl.hash ||
    attestationUrl.username ||
    attestationUrl.password ||
    attestationUrl.origin !== new URL(service.url).origin
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Evaluator attestation must use the evaluator origin's exact /api/v1/attestation endpoint.",
    );
  }
  return { ...service, attestationUrl: attestationUrl.toString() };
}

export function getSchedulerConfig(bindings: HerdBindings): SchedulerConfig {
  const token = requiredBounded(
    bindings.HERD_SCHEDULER_TOKEN,
    "HERD_SCHEDULER_TOKEN",
    512,
  );
  if (token.length < 32 || !/^[A-Za-z0-9_-]+$/u.test(token)) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_SCHEDULER_TOKEN must contain at least 32 URL-safe characters.",
    );
  }
  if (
    token === bindings.HERD_AUTH_PEPPER?.trim() ||
    token === bindings.HERD_EVALUATOR_TOKEN?.trim()
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_SCHEDULER_TOKEN must be distinct from other service secrets.",
    );
  }
  return { token };
}

function twilioSid(value: string | undefined, name: string, prefix: string): string {
  const result = requiredBounded(value, name, 34);
  if (!new RegExp(`^${prefix}[0-9a-fA-F]{32}$`, "u").test(result)) {
    throw new ApiError(500, "server_misconfigured", `${name} is invalid.`);
  }
  return result;
}

export function getInvitationDeliveryConfig(
  bindings: HerdBindings,
): InvitationDeliveryConfig | null {
  const activationValues = [
    bindings.HERD_PUBLIC_APP_URL,
    bindings.TWILIO_ACCOUNT_SID,
    bindings.TWILIO_MESSAGING_SERVICE_SID,
  ];
  if (!activationValues.some((value) => Boolean(value?.trim()))) return null;

  const rawPublicAppUrl = requiredBounded(
    bindings.HERD_PUBLIC_APP_URL,
    "HERD_PUBLIC_APP_URL",
    2_048,
  );
  let publicAppUrl: URL;
  try {
    publicAppUrl = new URL(rawPublicAppUrl);
  } catch {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_PUBLIC_APP_URL must be a valid HTTPS URL.",
    );
  }
  if (
    publicAppUrl.protocol !== "https:" ||
    publicAppUrl.username ||
    publicAppUrl.password ||
    publicAppUrl.search ||
    publicAppUrl.hash ||
    publicAppUrl.origin === "null"
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_PUBLIC_APP_URL must be a valid HTTPS URL without credentials, query, or fragment.",
    );
  }
  publicAppUrl.pathname = publicAppUrl.pathname.replace(/\/+$/u, "") || "/";

  return {
    publicAppUrl: publicAppUrl.toString().replace(/\/$/u, ""),
    twilio: {
      accountSid: twilioSid(bindings.TWILIO_ACCOUNT_SID, "TWILIO_ACCOUNT_SID", "AC"),
      apiKeySid: twilioSid(bindings.TWILIO_API_KEY_SID, "TWILIO_API_KEY_SID", "SK"),
      apiKeySecret: requiredBounded(
        bindings.TWILIO_API_KEY_SECRET,
        "TWILIO_API_KEY_SECRET",
        512,
      ),
      messagingServiceSid: twilioSid(
        bindings.TWILIO_MESSAGING_SERVICE_SID,
        "TWILIO_MESSAGING_SERVICE_SID",
        "MG",
      ),
    },
  };
}

export function qaInvitationSuppressionReason(
  bindings: HerdBindings,
  phoneNumber: string,
): string | null {
  if (!qaTestBypassConfig(bindings).enabled) return null;
  if (/^\+1415555010[1-9]$/u.test(phoneNumber)) return "qa_alias";
  if (/^\+1[2-9][0-9]{2}55501[0-9]{2}$/u.test(phoneNumber)) return "qa_fixture";
  const configuredFixtures = [
    bindings.HERD_TEST_PHONE_E164,
    bindings.HERD_TEST_HOST_PHONE_E164,
    "+14155550187",
  ];
  return configuredFixtures.some((value) => value?.trim() === phoneNumber)
    ? "qa_fixture"
    : null;
}

export function getAuthConfig(bindings: HerdBindings): AuthConfig {
  const pepper = required(bindings.HERD_AUTH_PEPPER, "HERD_AUTH_PEPPER");
  if (pepper.length < 32) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "HERD_AUTH_PEPPER must contain at least 32 characters.",
    );
  }

  const qaBypass = qaTestBypassConfig(bindings);
  const testBypassEnabled = qaBypass.enabled;
  const testPhoneNumber =
    testBypassEnabled
      ? normalizePhoneNumber(
          required(bindings.HERD_TEST_PHONE_E164, "HERD_TEST_PHONE_E164"),
        )
      : null;

  const twilioValues = [
    bindings.TWILIO_API_KEY_SID,
    bindings.TWILIO_API_KEY_SECRET,
    bindings.TWILIO_VERIFY_SERVICE_SID,
  ];
  const hasAnyTwilioValue = twilioValues.some((value) => Boolean(value?.trim()));
  const hasAllTwilioValues = twilioValues.every((value) => Boolean(value?.trim()));
  if (hasAnyTwilioValue && !hasAllTwilioValues) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Phone verification credentials are incomplete.",
    );
  }
  const twilio = hasAllTwilioValues
    ? {
        apiKeySid: bindings.TWILIO_API_KEY_SID!.trim(),
        apiKeySecret: bindings.TWILIO_API_KEY_SECRET!.trim(),
        verifyServiceSid: bindings.TWILIO_VERIFY_SERVICE_SID!.trim(),
      }
    : null;

  const privateResponseValues = [
    bindings.HERD_EVALUATOR_KEY_ID,
    bindings.HERD_EVALUATOR_PUBLIC_KEY,
    bindings.HERD_EVALUATOR_MEASUREMENT,
    bindings.HERD_RELEASE_ID,
  ];
  const hasAnyPrivateResponseValue = privateResponseValues.some((value) => Boolean(value?.trim()));
  const hasAllPrivateResponseValues = privateResponseValues.every((value) => Boolean(value?.trim()));
  if (hasAnyPrivateResponseValue && !hasAllPrivateResponseValues) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "Private-response credentials are incomplete.",
    );
  }
  const privateResponse = hasAllPrivateResponseValues
    ? {
        evaluatorKeyId: evaluatorKeyId(bindings.HERD_EVALUATOR_KEY_ID),
        evaluatorPublicKey: evaluatorPublicKey(bindings.HERD_EVALUATOR_PUBLIC_KEY),
        evaluatorMeasurement: requiredBounded(
          bindings.HERD_EVALUATOR_MEASUREMENT,
          "HERD_EVALUATOR_MEASUREMENT",
          500,
        ),
        releaseId: requiredBounded(bindings.HERD_RELEASE_ID, "HERD_RELEASE_ID", 200),
      }
    : null;

  return {
    pepper,
    testBypassEnabled,
    qaBypassGeneration: qaBypass.generation,
    testPhoneNumber,
    challengeTtlSeconds: boundedInteger(
      bindings.HERD_CHALLENGE_TTL_SECONDS,
      600,
      120,
      1_800,
    ),
    resendSeconds: boundedInteger(bindings.HERD_RESEND_SECONDS, 60, 30, 600),
    maxCodeAttempts: boundedInteger(bindings.HERD_MAX_CODE_ATTEMPTS, 5, 3, 10),
    phoneRequestsPerHour: boundedInteger(
      bindings.HERD_PHONE_REQUESTS_PER_HOUR,
      5,
      2,
      20,
    ),
    ipRequestsPerHour: boundedInteger(
      bindings.HERD_IP_REQUESTS_PER_HOUR,
      30,
      5,
      200,
    ),
    sessionTtlSeconds: boundedInteger(
      bindings.HERD_SESSION_TTL_SECONDS,
      2_592_000,
      3_600,
      7_776_000,
    ),
    privateResponse,
    twilio,
  };
}
