import { getEvaluatorBindings } from "@/lib/bindings";
import {
  handleRelayOptionsRequest,
  handleRelayRequest,
} from "@/lib/relay";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return handleRelayRequest(request, await getEvaluatorBindings());
}

export async function OPTIONS(request: Request) {
  return handleRelayOptionsRequest(request, await getEvaluatorBindings());
}
