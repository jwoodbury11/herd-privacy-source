import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(
  new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
  "utf8",
);

test("pull requests run only in the free public-source repository", () => {
  const triggers = workflow.slice(0, workflow.indexOf("concurrency:"));
  assert.match(triggers, /workflow_dispatch:/u);
  assert.match(triggers, /pull_request:/u);
  assert.doesNotMatch(triggers, /push:/u);
  const releaseJob = workflow.slice(
    workflow.indexOf("  release-evidence:"),
    workflow.indexOf("  privacy-services:"),
  );
  const servicesJob = workflow.slice(
    workflow.indexOf("  privacy-services:"),
    workflow.indexOf("  ios-native:"),
  );
  for (const job of [releaseJob, servicesJob]) {
    assert.match(job, /github\.event_name == 'workflow_dispatch'/u);
    assert.match(job, /github\.repository == 'jwoodbury11\/herd-privacy-source'/u);
  }
});

test("the paid hosted Mac is restricted to deliberate full-suite runs", () => {
  const iosJob = workflow.slice(workflow.indexOf("  ios-native:"));
  assert.match(iosJob, /needs: release-evidence/u);
  assert.match(iosJob, /github\.event_name == 'workflow_dispatch'/u);
  assert.match(iosJob, /github\.repository == 'jwoodbury11\/herd-privacy-source'/u);
  assert.match(iosJob, /needs\.release-evidence\.result == 'success'/u);
  assert.doesNotMatch(iosJob, /github\.event_name == 'push'/u);
});
