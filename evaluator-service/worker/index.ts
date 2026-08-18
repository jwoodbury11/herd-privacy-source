/** Cloudflare Worker entry point for the vinext-starter template. */
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

interface Env {
  ASSETS: Fetcher;
  HERD_EVALUATOR_TOKEN?: string;
  HERD_EVALUATOR_KEY_ID?: string;
  HERD_EVALUATOR_PRIVATE_KEY_PEM?: string;
  HERD_EVALUATOR_PRIVATE_KEY_JWK?: string;
  HERD_EVALUATOR_MEASUREMENT?: string;
  HERD_RELEASE_ID?: string;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
}

interface ExecutionContext {
  waitUntil(promise: Promise<unknown>): void;
  passThroughOnException(): void;
}

// Image security config. SVG sources with .svg extension auto-skip the
// optimization endpoint on the client side (served directly, no proxy).
// To route SVGs through the optimizer (with security headers), set
// dangerouslyAllowSVG: true in next.config.js and uncomment below:
// const imageConfig: ImageConfig = { dangerouslyAllowSVG: true };

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/_vinext/image") {
      const allowedWidths = [...DEFAULT_DEVICE_SIZES, ...DEFAULT_IMAGE_SIZES];
      return handleImageOptimization(request, {
        fetchAsset: (path) => env.ASSETS.fetch(new Request(new URL(path, request.url))),
        transformImage: async (body, { width, format, quality }) => {
          const result = await env.IMAGES.input(body).transform(width > 0 ? { width } : {}).output({ format, quality });
          return result.response();
        },
      }, allowedWidths);
    }

    if (!url.pathname.startsWith("/api/")) return handler.fetch(request, env, ctx);
    const supplied = request.headers.get("x-herd-request-id")?.toLowerCase();
    const requestId = supplied && /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(supplied)
      ? supplied
      : crypto.randomUUID();
    const headers = new Headers(request.headers);
    headers.set("x-herd-request-id", requestId);
    const startedAt = Date.now();
    const response = await handler.fetch(new Request(request, { headers }), env, ctx);
    const responseHeaders = new Headers(response.headers);
    responseHeaders.set("x-herd-request-id", requestId);
    console.info(JSON.stringify({
      schemaVersion: 1,
      kind: "herd.operational",
      recordedAt: new Date().toISOString(),
      component: "evaluator",
      signal: "evaluator_request",
      operation: `${request.method.toLowerCase()}.${url.pathname.replace(/^\/api\//u, "").replaceAll("/", ".")}`.slice(0, 80),
      outcome: response.ok ? "success" : "failure",
      statusCode: response.status,
      errorCode: response.ok ? "none" : "evaluator_request_failed",
      durationMs: Math.max(0, Date.now() - startedAt),
      correlationId: requestId,
      releaseId: env.HERD_RELEASE_ID ?? "unknown",
    }));
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: responseHeaders });
  },
};

export default worker;
