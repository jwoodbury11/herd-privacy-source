import { getBindings, getD1 } from "@/db";
import { withApiErrors } from "@/lib/backend/http";
import {
  requireEmptySchedulerBody,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";
import { runDataRetentionSweep } from "@/lib/backend/data-retention";
import { purgeOperationalMetrics } from "@/lib/backend/observability";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    await requireSchedulerAuthorization(request, bindings);
    await requireEmptySchedulerBody(request);
    const database = await getD1();
    const invokedAt = new Date();
    const summary = await runDataRetentionSweep(database, invokedAt.toISOString());
    await purgeOperationalMetrics(database, invokedAt);
    console.info("Herd authenticated data-retention sweep", summary);
    return new Response(null, {
      status: 204,
      headers: {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
