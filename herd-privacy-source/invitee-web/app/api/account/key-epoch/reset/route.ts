import { getBindings, getD1 } from "@/db";
import { resetAccountKeyEpoch } from "@/lib/backend/account-keys";
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
    const result = await resetAccountKeyEpoch(
      db,
      session!,
      expectedAccountKeyEpochId,
    );
    return jsonResponse(result);
  });
}
