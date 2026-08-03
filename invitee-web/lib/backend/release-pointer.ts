import type { HerdBindings } from "@/db";

import { getDeploymentProfile } from "./config";
import { ApiError } from "./http";

const MAXIMUM_POINTER_BYTES = 64 * 1024;

function pointerUrl(value: string | undefined): URL | null {
  if (!value?.trim()) return null;
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw new ApiError(500, "server_misconfigured", "The public release pointer is misconfigured.");
  }
  if (
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    url.hostname !== "storage.googleapis.com" ||
    !url.pathname.endsWith("/herd-release.json")
  ) {
    throw new ApiError(500, "server_misconfigured", "The public release pointer is misconfigured.");
  }
  return url;
}

function validatePointer(bytes: Uint8Array, expectedReleaseId: string): void {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
  } catch {
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
  if (
    !value ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    (value as { schemaVersion?: unknown }).schemaVersion !== 1 ||
    (value as { releaseId?: unknown }).releaseId !== expectedReleaseId
  ) {
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
}

export async function releasePointerResponse(
  bindings: HerdBindings,
  fetcher: typeof fetch = fetch,
): Promise<Response> {
  const configuredUrl = pointerUrl(bindings.HERD_RELEASE_POINTER_URL);
  if (!configuredUrl) {
    if (getDeploymentProfile(bindings) === "test") return new Response("Not found", { status: 404 });
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
  const expectedReleaseId = bindings.HERD_ARTIFACT_RELEASE_ID?.trim();
  if (!expectedReleaseId) {
    throw new ApiError(500, "server_misconfigured", "The artifact release identity is not configured.");
  }
  let upstream: Response;
  try {
    upstream = await fetcher(configuredUrl, {
      method: "GET",
      redirect: "error",
      headers: { accept: "application/json" },
    });
  } catch {
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
  const contentLength = Number(upstream.headers.get("content-length"));
  if (
    !upstream.ok ||
    (Number.isFinite(contentLength) && contentLength > MAXIMUM_POINTER_BYTES)
  ) {
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
  const bytes = new Uint8Array(await upstream.arrayBuffer());
  if (bytes.byteLength === 0 || bytes.byteLength > MAXIMUM_POINTER_BYTES) {
    throw new ApiError(503, "release_evidence_unavailable", "Release evidence is temporarily unavailable.");
  }
  validatePointer(bytes, expectedReleaseId);
  return new Response(bytes, {
    headers: {
      "Cache-Control": "public, max-age=300, stale-while-revalidate=3600",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
    },
  });
}
