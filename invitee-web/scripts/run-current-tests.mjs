import { readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const legacyV1ScenarioSuites = new Set([
  "browser-acceptance-harness.test.mjs",
  "cross-service-resolution.test.mjs",
  "event-resolution-lifecycle.test.mjs",
  "invitation-delivery.test.mjs",
]);
const tests = readdirSync(new URL("../tests", import.meta.url))
  .filter((name) => name.endsWith(".test.mjs") && !legacyV1ScenarioSuites.has(name))
  .map((name) => `tests/${name}`)
  .sort();

const result = spawnSync(
  process.execPath,
  ["--test", "--test-concurrency=1", ...tests],
  { cwd: root, stdio: "inherit" },
);
process.exit(result.status ?? 1);
