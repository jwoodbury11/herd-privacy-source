import { getBindings, getD1 } from "@/db";
import { ApiError, jsonResponse, withApiErrors } from "@/lib/backend/http";

export const dynamic = "force-dynamic";

const CONFIRMATION = "DELETE ALL EVENTS";

async function constantTimeEqual(left: string, right: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const [leftHash, rightHash] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(left)),
    crypto.subtle.digest("SHA-256", encoder.encode(right)),
  ]);
  const leftBytes = new Uint8Array(leftHash);
  const rightBytes = new Uint8Array(rightHash);
  let difference = 0;
  for (let index = 0; index < leftBytes.length; index += 1) {
    difference |= leftBytes[index] ^ rightBytes[index];
  }
  return difference === 0;
}

async function authorize(request: Request, expectedInput: string | undefined) {
  const expected = expectedInput?.trim() ?? "";
  const authorization = request.headers.get("authorization") ?? "";
  const supplied = authorization.startsWith("Bearer ")
    ? authorization.slice("Bearer ".length)
    : "";
  if (
    expected.length < 32 ||
    supplied.length < 32 ||
    !(await constantTimeEqual(supplied, expected))
  ) {
    throw new ApiError(404, "not_found", "Not Found");
  }
}

async function requireConfirmation(request: Request): Promise<void> {
  const mediaType = (request.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json.");
  }
  let payload: unknown;
  try {
    payload = await request.json();
  } catch {
    throw new ApiError(400, "invalid_json", "The request body must be valid JSON.");
  }
  if (
    !payload ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    (payload as { confirmation?: unknown }).confirmation !== CONFIRMATION
  ) {
    throw new ApiError(400, "confirmation_required", `Type ${CONFIRMATION} to confirm.`);
  }
}

function changes(result: D1Result<unknown>): number {
  return result.meta.changes ?? 0;
}

/**
 * One-time production reset valve. It is unreachable unless a separate,
 * short-lived reset token is provisioned, and it removes event-scoped data
 * without touching users, profiles, account keys, sessions, or service config.
 */
export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await authorize(request, bindings.HERD_DATA_RESET_TOKEN);
    await requireConfirmation(request);
    const db = await getD1();
    const results = await db.batch([
      db.prepare("DELETE FROM response_transparency_heads"),
      db.prepare("DELETE FROM response_transparency_entries"),
      db.prepare("DELETE FROM ballot_operator_actions"),
      db.prepare("DELETE FROM events"),
      db.prepare("DELETE FROM sqlite_sequence WHERE name = 'response_transparency_entries'"),
    ]);
    const remaining = await db
      .prepare("SELECT COUNT(*) AS count FROM events")
      .first<{ count: number }>();
    if ((remaining?.count ?? -1) !== 0) {
      throw new ApiError(500, "reset_incomplete", "The event reset did not complete.");
    }
    console.warn("Herd event history reset completed", {
      deletedTransparencyHeads: changes(results[0]),
      deletedTransparencyEntries: changes(results[1]),
      deletedOperatorActions: changes(results[2]),
      deletedEvents: changes(results[3]),
    });
    return jsonResponse(
      {
        deletedEvents: changes(results[3]),
        deletedTransparencyEntries: changes(results[1]),
        remainingEvents: 0,
      },
      {
        headers: {
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff",
        },
      },
    );
  });
}
