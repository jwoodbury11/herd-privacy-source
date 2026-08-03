import { getBindings, getD1 } from "@/db";
import { withApiErrors } from "@/lib/backend/http";
import {
  requireQaResetConfirmation,
  requireQaResetEnabled,
  resetQaDatabase,
} from "@/lib/backend/qa-reset";
import {
  readSchedulerJsonObject,
  requireSchedulerAuthorization,
} from "@/lib/backend/scheduler-auth";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const bindings = await getBindings();
    requireQaResetEnabled(bindings);
    await requireSchedulerAuthorization(request, bindings);
    requireQaResetConfirmation(await readSchedulerJsonObject(request));
    await resetQaDatabase(await getD1());
    return new Response(null, {
      status: 204,
      headers: {
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
