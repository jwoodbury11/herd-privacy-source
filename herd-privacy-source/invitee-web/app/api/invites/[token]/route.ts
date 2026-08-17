import { getBindings, getD1 } from "@/db";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import { getInviteByToken } from "@/lib/backend/invites";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ token: string }> };

export async function GET(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    const { token } = await context.params;
    const invite = await getInviteByToken(
      request,
      await getD1(),
      await getBindings(),
      token,
    );
    return jsonResponse(invite);
  });
}
