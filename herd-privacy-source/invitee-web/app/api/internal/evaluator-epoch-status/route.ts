import { getBindings, getD1 } from "@/db";
import { getEvaluatorEpochStatus } from "@/lib/backend/evaluator-epoch";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import {
  requireEmptySchedulerBody,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireSchedulerAuthorization(request, bindings);
    await requireEmptySchedulerBody(request);
    return jsonResponse(
      await getEvaluatorEpochStatus(await getD1(), bindings),
      { headers: { "Cache-Control": "no-store" } },
    );
  });
}
