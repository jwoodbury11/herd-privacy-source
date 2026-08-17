import { createHash, timingSafeEqual } from "node:crypto";

import { BASE64URL_PATTERN } from "./constants.mjs";
import { ConfigurationError, invalidRequest } from "./errors.mjs";

export const encoder = new TextEncoder();
export const fatalDecoder = new TextDecoder("utf-8", { fatal: true });

export function exactKeys(value, expected, onError = invalidRequest) {
  if (!value || typeof value !== "object" || Array.isArray(value)) onError();
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (
    actual.length !== wanted.length ||
    actual.some((key, index) => key !== wanted[index])
  ) {
    onError();
  }
  return value;
}

export function decodeBase64Url(value, expectedBytes, onError = invalidRequest) {
  if (
    typeof value !== "string" ||
    !BASE64URL_PATTERN.test(value) ||
    value.includes("=")
  ) {
    onError();
  }
  let bytes;
  try {
    bytes = Buffer.from(value, "base64url");
  } catch {
    onError();
  }
  if (
    bytes.length !== expectedBytes ||
    bytes.toString("base64url") !== value
  ) {
    onError();
  }
  return Uint8Array.from(bytes);
}

export function decodeConfiguredBase64Url(value, expectedBytes) {
  return decodeBase64Url(value, expectedBytes, () => {
    throw new ConfigurationError();
  });
}

export function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64url");
}

export function sha256Bytes(...values) {
  const hash = createHash("sha256");
  for (const value of values) hash.update(value);
  return Uint8Array.from(hash.digest());
}

export function sha256Base64Url(...values) {
  return encodeBase64Url(sha256Bytes(...values));
}

export function domainSeparatedBytes(domain, payload) {
  return Buffer.concat([
    Buffer.from(`${domain}\0`, "utf8"),
    Buffer.from(payload, "utf8"),
  ]);
}

export function constantTimeTextEqual(left, right) {
  const leftHash = createHash("sha256").update(String(left)).digest();
  const rightHash = createHash("sha256").update(String(right)).digest();
  return timingSafeEqual(leftHash, rightHash);
}

export function parseCompactCanonicalJson(value, maximumBytes) {
  if (
    typeof value !== "string" ||
    value.length < 2 ||
    Buffer.byteLength(value, "utf8") > maximumBytes
  ) {
    invalidRequest();
  }
  let parsed;
  try {
    parsed = JSON.parse(value);
  } catch {
    invalidRequest();
  }
  if (
    !parsed ||
    typeof parsed !== "object" ||
    Array.isArray(parsed) ||
    JSON.stringify(parsed) !== value
  ) {
    invalidRequest();
  }
  return parsed;
}
