import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";

const workflow = fs.readFileSync(
  new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
  "utf8",
);

test("documentation-only changes do not start privacy CI", () => {
  const markdownIgnores = workflow.match(/- "\*\*\/\*\.md"/gu) ?? [];
  assert.equal(markdownIgnores.length, 2);
});

test("the paid hosted Mac is restricted to deliberate full-suite runs", () => {
  const iosJob = workflow.slice(workflow.indexOf("  ios-native:"));
  assert.match(iosJob, /needs: release-evidence/u);
  assert.match(iosJob, /github\.event_name == 'workflow_dispatch'/u);
  assert.match(iosJob, /needs\.release-evidence\.result == 'success'/u);
  assert.doesNotMatch(iosJob, /github\.event_name == 'push'/u);
  assert.doesNotMatch(iosJob, /github\.event_name == 'pull_request'/u);
});
