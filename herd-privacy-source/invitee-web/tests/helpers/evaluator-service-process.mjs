import { access, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { Log, LogLevel, Miniflare } from "miniflare";

const evaluatorRoot = fileURLToPath(
  new URL("../../../evaluator-service/", import.meta.url),
);
const serverRoot = path.join(evaluatorRoot, "dist/server");
let miniflare;

async function javascriptModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await javascriptModules(entryPath)));
    else if (entry.name.endsWith(".js")) files.push(entryPath);
  }
  return files;
}

async function start(bindings) {
  await access(path.join(serverRoot, "index.js"));
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    bindings,
    log: new Log(LogLevel.NONE),
  });
  const ready = await miniflare.ready;
  process.send?.({ type: "ready", url: ready.origin });
}

async function shutdown() {
  if (miniflare) await miniflare.dispose();
  miniflare = undefined;
  process.send?.({ type: "stopped" });
  process.exit(0);
}

process.on("message", (message) => {
  if (!message || typeof message !== "object") return;
  if (message.type === "start" && !miniflare) {
    void start(message.bindings).catch(() => {
      process.send?.({ type: "error", message: "Evaluator test process failed to start." });
      process.exit(1);
    });
  } else if (message.type === "stop") {
    void shutdown();
  }
});

process.on("disconnect", () => {
  void shutdown();
});
