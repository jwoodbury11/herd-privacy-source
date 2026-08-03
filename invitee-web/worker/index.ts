/** Cloudflare Worker entry point for the Herd invitee app. */
import type { HerdBindings } from "@/db";
import { appleAppSiteAssociationResponse } from "@/lib/backend/apple-app-site-association";
import { runDataRetentionSweep } from "@/lib/backend/data-retention";
import { ApiError, jsonResponse } from "@/lib/backend/http";
import { releasePointerResponse } from "@/lib/backend/release-pointer";
import { runScheduledResolutionSweep } from "@/lib/backend/scheduled-resolutions";
import { handleImageOptimization, DEFAULT_DEVICE_SIZES, DEFAULT_IMAGE_SIZES } from "vinext/server/image-optimization";
import handler from "vinext/server/app-router-entry";

type Env = HerdBindings & {
  ASSETS: Fetcher;
  DB: D1Database;
  IMAGES: {
    input(stream: ReadableStream): {
      transform(options: Record<string, unknown>): {
        output(options: { format: string; quality: number }): Promise<{ response(): Response }>;
      };
    };
  };
};

interface ScheduledController {
  scheduledTime: number;
  cron: string;
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

    if (url.pathname === "/.well-known/apple-app-site-association") {
      try {
        return appleAppSiteAssociationResponse(env);
      } catch (error) {
        if (error instanceof ApiError) {
          return jsonResponse(
            { error: { code: error.code, message: error.message } },
            { status: error.status },
          );
        }
        throw error;
      }
    }

    if (url.pathname === "/.well-known/herd-release.json") {
      try {
        return await releasePointerResponse(env);
      } catch (error) {
        if (error instanceof ApiError) {
          return jsonResponse(
            { error: { code: error.code, message: error.message } },
            { status: error.status },
          );
        }
        throw error;
      }
    }

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

    return handler.fetch(request, env, ctx);
  },

  scheduled(
    controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): void {
    const invokedAt = new Date(controller.scheduledTime).toISOString();
    ctx.waitUntil(
      runScheduledResolutionSweep(env.DB, env, invokedAt)
        .then((summary) => {
          if (summary.failedCount > 0) {
            console.error("Herd scheduled resolution sweep incomplete", summary);
          } else {
            console.info("Herd scheduled resolution sweep", summary);
          }
        })
        .catch(() => {
          console.error("Herd scheduled resolution sweep failed", {
            selectedCount: 0,
            relayCount: 0,
            resolvedCount: 0,
            pendingCount: 0,
            failedCount: 1,
            releasedLeaseCount: 0,
          });
        }),
    );
    ctx.waitUntil(
      runDataRetentionSweep(env.DB, invokedAt)
        .then((summary) => {
          console.info("Herd data-retention sweep", summary);
        })
        .catch(() => {
          console.error("Herd data-retention sweep failed");
        }),
    );
  },
};

export default worker;
