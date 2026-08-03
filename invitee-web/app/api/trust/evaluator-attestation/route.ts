import { getBindings } from "@/db";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import {
  fetchEvaluatorAttestation,
  normalizeAttestationNonce,
} from "@/lib/backend/attestation";
import {
  ApiError,
  jsonResponse,
  readJsonObject,
  withApiErrors,
} from "@/lib/backend/http";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    await getAuthenticatedSession(request);
    const payload = await readJsonObject(request);
    if (Object.keys(payload).length !== 1 || !("nonce" in payload)) {
      throw new ApiError(400, "invalid_request", "The request must contain only nonce.");
    }
    const nonce = normalizeAttestationNonce(payload.nonce);
    return jsonResponse(
      await fetchEvaluatorAttestation(await getBindings(), nonce),
      { headers: { "Cache-Control": "no-store" } },
    );
  });
}
