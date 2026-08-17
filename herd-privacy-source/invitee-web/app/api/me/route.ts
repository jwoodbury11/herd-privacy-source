import { getBindings, getD1 } from "@/db";
import { deleteAuthenticatedAccount } from "@/lib/backend/accounts";
import {
  clearSessionCookie,
  getAuthenticatedSession,
} from "@/lib/backend/auth";
import {
  ApiError,
  jsonResponse,
  readJsonObject,
  requireString,
  withApiErrors,
} from "@/lib/backend/http";
import type { HerdUser } from "@/lib/backend/types";

export const dynamic = "force-dynamic";

export async function GET(request: Request) {
  return withApiErrors(async () => {
    const session = await getAuthenticatedSession(request);
    return jsonResponse({ user: session!.user });
  });
}

export async function PATCH(request: Request) {
  return withApiErrors(async () => {
    const session = await getAuthenticatedSession(request);
    const payload = await readJsonObject(request);
    const hasName = Object.prototype.hasOwnProperty.call(payload, "name");
    const hasAddress = Object.prototype.hasOwnProperty.call(payload, "address");
    if (!hasName && !hasAddress) {
      throw new ApiError(
        400,
        "invalid_request",
        "Provide a name or address to update.",
      );
    }

    const name = hasName
      ? requireString(payload.name, "name", { max: 80, allowEmpty: true })
      : session!.user.name;
    const address = hasAddress
      ? requireString(payload.address, "address", { max: 240, allowEmpty: true })
      : session!.user.address;
    const db = await getD1();
    await db
      .prepare(
        `UPDATE users
         SET name = ?, address = ?, updated_at = ?
         WHERE id = ?`,
      )
      .bind(name, address, new Date().toISOString(), session!.user.id)
      .run();
    const user = await db
      .prepare(
        `SELECT id, phone_number AS phoneNumber, name, address
         FROM users
         WHERE id = ?`,
      )
      .bind(session!.user.id)
      .first<HerdUser>();
    if (!user) throw new ApiError(404, "user_not_found", "The account was not found.");
    return jsonResponse({ user });
  });
}

export async function DELETE(request: Request) {
  return withApiErrors(async () => {
    const session = await getAuthenticatedSession(request);
    const payload = await readJsonObject(request);
    if (payload.confirmation !== "DELETE") {
      throw new ApiError(
        400,
        "account_deletion_not_confirmed",
        "Type DELETE to confirm permanent account deletion.",
      );
    }

    await deleteAuthenticatedAccount(
      await getD1(),
      await getBindings(),
      session!,
    );
    return new Response(null, {
      status: 204,
      headers: {
        "Cache-Control": "no-store",
        "Set-Cookie": clearSessionCookie(),
        "X-Content-Type-Options": "nosniff",
      },
    });
  });
}
