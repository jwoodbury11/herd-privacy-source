import type { HerdBindings } from "@/db";

import { ApiError } from "./http";

function iosAppIdentifier(value: string | undefined): string {
  const appId = value?.trim() ?? "";
  if (
    appId.length > 300 ||
    !/^[A-Z0-9]{10}\.[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$/u.test(appId) ||
    appId.includes("..")
  ) {
    throw new ApiError(
      500,
      "server_misconfigured",
      "The iOS universal-link application identifier is not configured.",
    );
  }
  return appId;
}

export function appleAppSiteAssociationResponse(bindings: HerdBindings): Response {
  const appID = iosAppIdentifier(bindings.HERD_IOS_APP_ID);
  return new Response(
    JSON.stringify({
      applinks: {
        apps: [],
        details: [
          {
            appID,
            paths: ["/invite/*"],
          },
        ],
      },
    }),
    {
      headers: {
        "Cache-Control": "public, max-age=3600, stale-while-revalidate=86400",
        "Content-Type": "application/json; charset=utf-8",
        "X-Content-Type-Options": "nosniff",
      },
    },
  );
}
