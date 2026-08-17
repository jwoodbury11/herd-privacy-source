import { clearSessionCookie, revokeRequestSession } from "@/lib/backend/auth";
import { jsonResponse, requireSameOrigin, withApiErrors } from "@/lib/backend/http";

export const dynamic = "force-dynamic";

export async function DELETE(request: Request) {
  return withApiErrors(async () => {
    requireSameOrigin(request);
    await revokeRequestSession(request);
    return jsonResponse(
      { signedOut: true },
      { headers: { "Set-Cookie": clearSessionCookie() } },
    );
  });
}
