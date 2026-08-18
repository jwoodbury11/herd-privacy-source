import { getBindings, getD1 } from "@/db";
import {
  getEvaluatorEpochStatus,
  requireEvaluatorEpochPolicyFence,
} from "@/lib/backend/evaluator-epoch";
import { requireEvaluatorCompatibility } from "@/lib/backend/evaluator-compatibility";
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
    const db = await getD1();

    // This is intentionally the same fail-closed fence used by private event
    // creation. A deployment is not ready merely because its HTTP process is up.
    await requireEvaluatorEpochPolicyFence(db, bindings);
    const evaluatorCompatibility = await requireEvaluatorCompatibility(bindings);
    const status = await getEvaluatorEpochStatus(db, bindings);

    return jsonResponse(
      {
        ...status,
        evaluatorCompatibility,
        readyForPrivateEventCreation: true,
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  });
}
