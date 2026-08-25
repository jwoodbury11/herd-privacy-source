import { getBindings, getD1 } from "@/db";
import {
  getAuthenticatedSession,
  requestAuthCode,
  sessionCookie,
} from "@/lib/backend/auth";
import { readJsonObject, jsonResponse, withApiErrors } from "@/lib/backend/http";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const payload = await readJsonObject(request);
    const bindings = await getBindings();
    const db = await getD1();
    const currentSession = await getAuthenticatedSession(request, {
      required: false,
      db,
      bindings,
    });
    const result = await requestAuthCode(
      request,
      payload.phoneNumber,
      db,
      bindings,
      currentSession,
    );
    if ("accessToken" in result) {
      return jsonResponse(result, {
        headers: {
          "Set-Cookie": sessionCookie(result.accessToken, result.expiresAt),
        },
      });
    }
    return jsonResponse(result, { status: 201 });
  });
}
