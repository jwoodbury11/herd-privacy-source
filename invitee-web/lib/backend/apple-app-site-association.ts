import type { HerdBindings } from "@/db";

import { getDeploymentProfile } from "./config";
import { ApiError } from "./http";

const QA_APP_ID = "R4UPN8ZDV8.com.jameswoodbury.HerdPrototype";

function iosAppIdentifier(value: string | undefined, isTest: boolean): string {
  const appId = value?.trim() || (isTest ? QA_APP_ID : "");
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
  const appID = iosAppIdentifier(
    bindings.HERD_IOS_APP_ID,
    getDeploymentProfile(bindings) === "test",
  );
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
