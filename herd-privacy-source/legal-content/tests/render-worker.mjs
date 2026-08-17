import { pathToFileURL } from "node:url";

const [workerPath, origin, pathname] = process.argv.slice(2);
if (!workerPath || !origin || !pathname) {
  throw new TypeError("worker path, origin, and pathname are required");
}

const workerUrl = pathToFileURL(workerPath);
workerUrl.searchParams.set("legal-parity", `${process.pid}-${Date.now()}`);
const { default: worker } = await import(workerUrl.href);
const target = new URL(pathname, origin);
const response = await worker.fetch(
  new Request(target, {
    headers: { accept: "text/html", host: target.host },
  }),
  { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
  { waitUntil() {}, passThroughOnException() {} },
);
if (response.status !== 200) {
  throw new Error(`legal route returned HTTP ${response.status}`);
}
process.stdout.write(await response.text());
