import { getBindings, getD1 } from "@/db";
import {
  initializeAccountKeyEpoch,
  normalizeAccountKeyCommitment,
} from "@/lib/backend/account-keys";
import { getAuthenticatedSession } from "@/lib/backend/auth";
import {
  jsonResponse,
  readJsonObject,
  requireUuid,
  withApiErrors,
} from "@/lib/backend/http";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const db = await getD1();
    const bindings = await getBindings();
    const session = await getAuthenticatedSession(request, { db, bindings });
    const payload = await readJsonObject(request);
    const expectedAccountKeyEpochId = requireUuid(
      payload.expectedAccountKeyEpochId,
      "expectedAccountKeyEpochId",
    );
    const keyCommitment = normalizeAccountKeyCommitment(payload.keyCommitment);
    const result = await initializeAccountKeyEpoch(
      db,
      session!,
      expectedAccountKeyEpochId,
      keyCommitment,
    );
    return jsonResponse(result);
  });
}
