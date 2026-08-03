import type { AuthConfig } from "./config";
import { ApiError } from "./http";

type TwilioVerification = {
  sid?: string;
  status?: string;
  message?: string;
};

function basicAuthorization(username: string, password: string): string {
  return `Basic ${btoa(`${username}:${password}`)}`;
}

async function twilioVerifyRequest(
  config: NonNullable<AuthConfig["twilio"]>,
  endpoint: string,
  body: URLSearchParams,
  invalidCodeIsDenied = false,
): Promise<TwilioVerification> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);
  try {
    const response = await fetch(
      `https://verify.twilio.com/v2/Services/${encodeURIComponent(config.verifyServiceSid)}/${endpoint}`,
      {
        method: "POST",
        headers: {
          Authorization: basicAuthorization(config.apiKeySid, config.apiKeySecret),
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body,
        signal: controller.signal,
      },
    );
    const payload = (await response.json().catch(() => ({}))) as TwilioVerification;
    if (invalidCodeIsDenied && (response.status === 400 || response.status === 404)) {
      return { status: "denied" };
    }
    if (!response.ok) {
      console.error("Twilio Verify request failed", {
        status: response.status,
        providerMessage: payload.message,
      });
      throw new ApiError(
        503,
        "sms_unavailable",
        "The verification message could not be sent. Try again shortly.",
      );
    }
    return payload;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    console.error("Twilio Verify network error", error);
    throw new ApiError(
      503,
      "sms_unavailable",
      "The verification service is temporarily unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

export async function sendTwilioVerification(
  config: NonNullable<AuthConfig["twilio"]>,
  phoneNumber: string,
): Promise<string> {
  const payload = await twilioVerifyRequest(
    config,
    "Verifications",
    new URLSearchParams({ To: phoneNumber, Channel: "sms" }),
  );
  if (!payload.sid || payload.status !== "pending") {
    throw new ApiError(
      503,
      "sms_unavailable",
      "The verification message could not be sent.",
    );
  }
  return payload.sid;
}

export async function checkTwilioVerification(
  config: NonNullable<AuthConfig["twilio"]>,
  phoneNumber: string,
  code: string,
): Promise<boolean> {
  const payload = await twilioVerifyRequest(
    config,
    "VerificationCheck",
    new URLSearchParams({ To: phoneNumber, Code: code }),
    true,
  );
  return payload.status === "approved";
}
