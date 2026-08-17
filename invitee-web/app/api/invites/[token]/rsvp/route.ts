import { getBindings, getD1 } from "@/db";
import {
  jsonResponse,
  readJsonObject,
  withApiErrors,
} from "@/lib/backend/http";
import { putInviteRsvp } from "@/lib/backend/invites";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ token: string }> };

export async function PUT(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    const { token } = await context.params;
    const payload = await readJsonObject(request);
    const result = await putInviteRsvp(
      request,
      await getD1(),
      await getBindings(),
      token,
      payload,
    );
    return jsonResponse(result);
  });
}
