import { getBindings, getD1 } from "@/db";
import { getOwnBallot, putOwnBallot } from "@/lib/backend/ballots";
import { jsonResponse, readJsonObject, withApiErrors } from "@/lib/backend/http";

export const dynamic = "force-dynamic";

type RouteContext = { params: Promise<{ token: string }> };

export async function GET(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    const { token } = await context.params;
    return jsonResponse({
      ballot: await getOwnBallot(request, await getD1(), await getBindings(), token),
    });
  });
}

export async function PUT(request: Request, context: RouteContext) {
  return withApiErrors(async () => {
    const { token } = await context.params;
    const payload = await readJsonObject(request);
    return jsonResponse({
      ballot: await putOwnBallot(request, await getD1(), await getBindings(), token, payload),
    });
  });
}
