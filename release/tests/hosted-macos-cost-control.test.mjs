import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(
  new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
  "utf8",
);

test("private hosted CI is restricted to deliberate manual runs", () => {
  const triggers = workflow.slice(0, workflow.indexOf("concurrency:"));
  assert.match(triggers, /workflow_dispatch:/u);
  assert.doesNotMatch(triggers, /pull_request:/u);
  assert.doesNotMatch(triggers, /push:/u);
});

test("the paid hosted Mac is restricted to deliberate full-suite runs", () => {
  const iosJob = workflow.slice(workflow.indexOf("  ios-native:"));
  assert.match(iosJob, /needs: release-evidence/u);
  assert.match(iosJob, /github\.event_name == 'workflow_dispatch'/u);
  assert.match(iosJob, /needs\.release-evidence\.result == 'success'/u);
  assert.doesNotMatch(iosJob, /github\.event_name == 'push'/u);
  assert.doesNotMatch(iosJob, /github\.event_name == 'pull_request'/u);
});
