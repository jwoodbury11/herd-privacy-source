import { ApiError } from "./http";

export function normalizePhoneNumber(input: unknown): string {
  if (typeof input !== "string") {
    throw new ApiError(400, "invalid_phone_number", "Enter a valid phone number.");
  }

  const trimmed = input.trim();
  const digits = trimmed.replace(/\D/g, "");
  let normalized: string;
  if (trimmed.startsWith("+")) normalized = `+${digits}`;
  else if (digits.length === 10) normalized = `+1${digits}`;
  else if (digits.length === 11 && digits.startsWith("1")) normalized = `+${digits}`;
  else normalized = `+${digits}`;

  if (!/^\+[1-9]\d{7,14}$/.test(normalized)) {
    throw new ApiError(400, "invalid_phone_number", "Enter a valid phone number.");
  }
  return normalized;
}

export function maskPhoneNumber(phoneNumber: string): string {
  const digits = phoneNumber.replace(/\D/g, "");
  return `••• ••• ${digits.slice(-4)}`;
}
