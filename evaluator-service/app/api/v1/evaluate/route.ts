import { getEvaluatorBindings } from "@/lib/bindings";
import { handleEvaluationRequest } from "@/lib/evaluate";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return handleEvaluationRequest(request, await getEvaluatorBindings());
}
