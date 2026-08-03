import { getEvaluatorBindings } from "@/lib/bindings";
import { handleQaPolicySigningRequest } from "@/lib/qa-trust-signer";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return handleQaPolicySigningRequest(request, await getEvaluatorBindings());
}
