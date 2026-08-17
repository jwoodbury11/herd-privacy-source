import { getBindings, getD1 } from "@/db";
import {
  activateEvaluatorEpoch,
  parseEvaluatorEpochTransitionRequest,
} from "@/lib/backend/evaluator-epoch";
import { jsonResponse, withApiErrors } from "@/lib/backend/http";
import {
  readSchedulerJsonObject,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireSchedulerAuthorization(request, bindings);
    const transition = parseEvaluatorEpochTransitionRequest(
      await readSchedulerJsonObject(request),
    );
    return jsonResponse(
      await activateEvaluatorEpoch(await getD1(), bindings, transition),
      { headers: { "Cache-Control": "no-store" } },
    );
  });
}
