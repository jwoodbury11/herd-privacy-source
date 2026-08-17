import type { EvaluatorBindings } from "./evaluate";

export async function getEvaluatorBindings(): Promise<EvaluatorBindings> {
  const runtime = await import("cloudflare:workers");
  return runtime.env as unknown as EvaluatorBindings;
}
