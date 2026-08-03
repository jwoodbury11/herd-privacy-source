import { getBindings, getD1 } from "@/db";
import { isQaAccountPhoneNumber, requestAuthCode, sessionCookie } from "@/lib/backend/auth";
import { getAuthConfig } from "@/lib/backend/config";
import { ApiError, readJsonObject, jsonResponse, withApiErrors } from "@/lib/backend/http";
import { ensurePokerPartyFixture } from "@/lib/backend/invites";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  return withApiErrors(async () => {
    const payload = await readJsonObject(request);
    let inviteToken: string | undefined;
    if (payload.inviteToken !== undefined) {
      if (
        typeof payload.inviteToken !== "string" ||
        payload.inviteToken.length < 8 ||
        payload.inviteToken.length > 200 ||
        !/^[A-Za-z0-9_-]+$/u.test(payload.inviteToken)
      ) {
        throw new ApiError(
          400,
          "invalid_invite_token",
          "Open the original invitation link and try again.",
        );
      }
      inviteToken = payload.inviteToken;
    }
    const bindings = await getBindings();
    const db = await getD1();
    if (
      inviteToken === "poker-party" &&
      getAuthConfig(bindings).testBypassEnabled
    ) {
      // Native authentication can carry the QA link directly, without first
      // making the anonymous preview request that normally creates this fixture.
      await ensurePokerPartyFixture(db, bindings);
    }
    const result = await requestAuthCode(
      request,
      payload.phoneNumber,
      db,
      bindings,
      inviteToken,
    );
    if ("accessToken" in result) {
      if (!isQaAccountPhoneNumber(result.user.phoneNumber)) {
        await ensurePokerPartyFixture(db, bindings);
      }
      return jsonResponse(result, {
        headers: {
          "Set-Cookie": sessionCookie(result.accessToken, result.expiresAt),
        },
      });
    }
    return jsonResponse(result, { status: 201 });
  });
}
