import { getD1 } from "@/db";
import { ApiError, jsonResponse, withApiErrors } from "@/lib/backend/http";
import { getPublicResponseTransparencyLog } from "@/lib/backend/response-transparency";

export const dynamic = "force-dynamic";

function boundedInteger(
  value: string | null,
  fallback: number,
  minimum: number,
  maximum: number,
  name: string,
): number {
  if (value === null || value === "") return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new ApiError(400, "invalid_request", `${name} is invalid.`);
  }
  return parsed;
}

export async function GET(request: Request) {
  return withApiErrors(async () => {
    const url = new URL(request.url);
    const after = boundedInteger(url.searchParams.get("after"), 0, 0, 2_147_483_647, "after");
    const limit = boundedInteger(url.searchParams.get("limit"), 100, 1, 500, "limit");
    if ([...url.searchParams.keys()].some((key) => key !== "after" && key !== "limit")) {
      throw new ApiError(400, "invalid_request", "The query contains unsupported fields.");
    }
    return jsonResponse(
      await getPublicResponseTransparencyLog(await getD1(), after, limit),
      {
        headers: {
          "Cache-Control": "public, max-age=30, stale-while-revalidate=30",
        },
      },
    );
  });
}
