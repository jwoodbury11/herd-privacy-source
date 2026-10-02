import type { HerdBindings } from "@/db";
import { ApiError } from "./http";

/** Authenticate all original fields before reading recipient or message content. */
export async function readTwilioSms(request: Request, bindings: HerdBindings): Promise<URLSearchParams> {
  const token = bindings.TWILIO_AUTH_TOKEN?.trim();
  const publicOrigin = bindings.HERD_PUBLIC_APP_URL?.trim().replace(/\/$/u, "");
  if (!token || !publicOrigin || !bindings.HERD_SMS_FROM_NUMBER) {
    throw new ApiError(503, "sms_replies_unavailable", "Text replies are not configured.");
  }
  const signature = request.headers.get("x-twilio-signature") ?? "";
  if (!/^[A-Za-z0-9+/]{27}=$/u.test(signature)) {
    throw new ApiError(403, "invalid_twilio_signature", "Invalid message signature.");
  }
  if (!(request.headers.get("content-type") ?? "").toLowerCase().startsWith("application/x-www-form-urlencoded")) {
    throw new ApiError(415, "unsupported_media_type", "Expected a form-encoded message.");
  }
  const reader = request.body?.getReader();
  if (!reader) throw new ApiError(400, "invalid_sms", "Missing message.");
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > 16_384) {
        await reader.cancel();
        throw new ApiError(413, "payload_too_large", "Message is too large.");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  const params = new URLSearchParams(new TextDecoder().decode(bytes));
  const keys = [...params.keys()];
  if (new Set(keys).size !== keys.length || new URL(request.url).search) {
    throw new ApiError(400, "invalid_sms", "Invalid message fields.");
  }
  const canonical = `${publicOrigin}/api/webhooks/twilio/sms`
    + keys.sort().map((key) => `${key}${params.get(key)!}`).join("");
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", encoder.encode(token), { name: "HMAC", hash: "SHA-1" }, false, ["verify"]);
  const valid = await crypto.subtle.verify("HMAC", key, Uint8Array.from(atob(signature), (c) => c.charCodeAt(0)), encoder.encode(canonical));
  if (!valid || params.get("AccountSid") !== bindings.TWILIO_ACCOUNT_SID
      || params.get("To") !== bindings.HERD_SMS_FROM_NUMBER
      || !/^SM[0-9a-fA-F]{32}$/u.test(params.get("MessageSid") ?? "")
      || !/^\+[1-9]\d{7,14}$/u.test(params.get("From") ?? "")) {
    throw new ApiError(403, "invalid_twilio_signature", "Invalid message signature.");
  }
  return params;
}

export function smsResponse(message?: string): Response {
  const escaped = message?.replace(/[<>&"']/gu, (c) => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;", "'": "&apos;" })[c]!);
  return new Response(`<?xml version="1.0" encoding="UTF-8"?><Response>${escaped ? `<Message>${escaped}</Message>` : ""}</Response>`, {
    headers: { "content-type": "application/xml; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}
