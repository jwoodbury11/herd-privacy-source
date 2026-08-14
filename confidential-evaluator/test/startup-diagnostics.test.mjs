import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("startup diagnostics identify only the failed stage", () => {
  const missingConfig = "/definitely-not-a-herd-deployment-config.json";
  const result = spawnSync(process.execPath, ["src/server.mjs"], {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
    env: {
      PATH: process.env.PATH,
      HERD_DEPLOYMENT_CONFIG_FILE: missingConfig,
    },
  });

  assert.equal(result.status, 2);
  assert.equal(result.stdout, "");
  assert.equal(
    result.stderr,
    "confidential evaluator failed closed during startup stage=configuration\n",
  );
  assert.equal(result.stderr.includes(missingConfig), false);
  assert.ok(result.status !== 0);
});
