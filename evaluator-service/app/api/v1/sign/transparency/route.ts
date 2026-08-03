import { getEvaluatorBindings } from "@/lib/bindings";
import { handleQaTransparencySigningRequest } from "@/lib/qa-trust-signer";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return handleQaTransparencySigningRequest(request, await getEvaluatorBindings());
}
