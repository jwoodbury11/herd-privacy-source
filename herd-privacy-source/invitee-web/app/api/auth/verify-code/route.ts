import { sessionCookie, verifyAuthCode } from "@/lib/backend/auth";
import { readJsonObject, jsonResponse, withApiErrors } from "@/lib/backend/http";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const payload = await readJsonObject(request);
    const result = await verifyAuthCode(payload.challengeId, payload.code);
    return jsonResponse(result, {
      headers: { "Set-Cookie": sessionCookie(result.accessToken, result.expiresAt) },
    });
  });
}
