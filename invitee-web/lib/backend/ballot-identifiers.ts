import type { HerdBindings } from "@/db";

import { pepperedHash } from "./crypto";
import { ApiError } from "./http";

function ballotKey(bindings: HerdBindings): string {
  const configured = bindings.HERD_BALLOT_PSEUDONYM_KEY?.trim() ?? "";
  if (configured.length >= 32) return configured;
  if (bindings.HERD_DEPLOYMENT_PROFILE === "test") {
    const testKey = bindings.HERD_AUTH_PEPPER?.trim() ?? "";
    if (testKey.length >= 32) return testKey;
  }
  throw new ApiError(
    500,
    "server_misconfigured",
    "The ballot pseudonym key is not configured.",
  );
}

export async function deriveBallotId(
  bindings: HerdBindings,
  eventId: string,
  inviteeId: string,
): Promise<string> {
  return pepperedHash(ballotKey(bindings), "HERD-BALLOT-V2", `${eventId}:${inviteeId}`);
}

export async function deriveBallotMemberId(
  bindings: HerdBindings,
  eventId: string,
  inviteeId: string,
): Promise<string> {
  return pepperedHash(ballotKey(bindings), "HERD-MEMBER-V2", `${eventId}:${inviteeId}`);
}
