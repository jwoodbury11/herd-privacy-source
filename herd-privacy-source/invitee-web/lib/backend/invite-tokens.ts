import { base64UrlToBytes, bytesToBase64Url } from "@/lib/privacy/protocol";

import { pepperedHash, randomToken } from "./crypto";
import { ApiError } from "./http";

const encoder = new TextEncoder();
const TOKEN_BYTES = 32;
const TOKEN_STORAGE_VERSION = 1;
const TOKEN_NONCE_BYTES = 12;
const TOKEN_STORAGE_SALT = encoder.encode("Herd invitation-token storage key v1");

export type SealedInviteToken = {
  token: string;
  tokenHash: string;
  tokenCiphertext: string;
  tokenNonce: string;
  tokenStorageVersion: typeof TOKEN_STORAGE_VERSION;
};

export type StoredInviteToken = {
  tokenCiphertext: string | null;
  tokenNonce: string | null;
  tokenStorageVersion: number | null;
};

async function storageKey(pepper: string): Promise<CryptoKey> {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(pepper),
    "HKDF",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: TOKEN_STORAGE_SALT,
      info: encoder.encode("AES-256-GCM"),
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function tokenAdditionalData(
  eventId: string,
  inviteeId: string,
): Uint8Array<ArrayBuffer> {
  return new Uint8Array(
    encoder.encode(`herd-invite-token\u0000v1\u0000${eventId}\u0000${inviteeId}`),
  );
}

function validateRawToken(value: string): string {
  try {
    const bytes = base64UrlToBytes(value);
    if (bytes.length !== TOKEN_BYTES || bytesToBase64Url(bytes) !== value) {
      throw new TypeError("Unexpected token encoding.");
    }
    return value;
  } catch {
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared.",
    );
  }
}

export async function createSealedInviteToken(
  pepper: string,
  eventId: string,
  inviteeId: string,
): Promise<SealedInviteToken> {
  const token = validateRawToken(randomToken(TOKEN_BYTES));
  const nonce = crypto.getRandomValues(new Uint8Array(TOKEN_NONCE_BYTES));
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: nonce,
      additionalData: tokenAdditionalData(eventId, inviteeId),
      tagLength: 128,
    },
    await storageKey(pepper),
    encoder.encode(token),
  );
  return {
    token,
    tokenHash: await pepperedHash(pepper, "invite-token", token),
    tokenCiphertext: bytesToBase64Url(new Uint8Array(ciphertext)),
    tokenNonce: bytesToBase64Url(nonce),
    tokenStorageVersion: TOKEN_STORAGE_VERSION,
  };
}

export async function openSealedInviteToken(
  pepper: string,
  eventId: string,
  inviteeId: string,
  stored: StoredInviteToken,
): Promise<string> {
  if (
    stored.tokenStorageVersion !== TOKEN_STORAGE_VERSION ||
    !stored.tokenCiphertext ||
    !stored.tokenNonce
  ) {
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared.",
    );
  }
  try {
    const nonce = new Uint8Array(base64UrlToBytes(stored.tokenNonce));
    if (nonce.length !== TOKEN_NONCE_BYTES) throw new TypeError("Invalid nonce.");
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: nonce,
        additionalData: tokenAdditionalData(eventId, inviteeId),
        tagLength: 128,
      },
      await storageKey(pepper),
      new Uint8Array(base64UrlToBytes(stored.tokenCiphertext)),
    );
    return validateRawToken(new TextDecoder().decode(plaintext));
  } catch (error) {
    if (error instanceof ApiError) throw error;
    throw new ApiError(
      500,
      "invite_token_unavailable",
      "The private invitation link could not be prepared.",
    );
  }
}
