import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

const testDirectory = path.dirname(fileURLToPath(import.meta.url));
const repositoryRoot = path.resolve(testDirectory, "../..");
const experience = JSON.parse(
  fs.readFileSync(path.join(repositoryRoot, "invitee-web/shared/HerdExperience.json"), "utf8"),
);

function assertSentenceCase(label, context) {
  const words = label.match(/[A-Za-z][A-Za-z’'-]*/g) ?? [];
  const allowedProperNouns = new Set(["Herd"]);
  const unexpectedCapitalizedWord = words.slice(1).find((word) => (
    /^[A-Z][a-z]/.test(word) && !allowedProperNouns.has(word)
  ));
  assert.equal(
    unexpectedCapitalizedWord,
    undefined,
    `${context} is not sentence case: ${JSON.stringify(label)}`,
  );
}

function collectSharedButtonLabels(value, pathParts = [], result = []) {
  if (!value || typeof value !== "object") return result;
  for (const [key, child] of Object.entries(value)) {
    const childPath = [...pathParts, key];
    if (typeof child === "string" && /(?:Button|action)$/u.test(key)) {
      result.push({ label: child, path: childPath.join(".") });
    } else {
      collectSharedButtonLabels(child, childPath, result);
    }
  }
  return result;
}

test("shared reply actions use sentence case", () => {
  assert.equal(experience.reply.previewButton, "Preview how others will see it");
});

test("all shared button labels use sentence case", () => {
  const labels = collectSharedButtonLabels(experience);
  assert.ok(labels.length > 20);
  for (const { label, path: labelPath } of labels) {
    assertSentenceCase(label, labelPath);
  }
  assert.equal(experience.success.homeButton, "Back to Herd events");
});

test("hard-coded iOS buttons use sentence case", () => {
  const attendeeFlow = fs.readFileSync(
    path.join(repositoryRoot, "HerdHost/AttendeeFlowView.swift"),
    "utf8",
  );

  for (const titleCaseLabel of ["Keep Selecting", "Clear Selections", "Open Settings"]) {
    assert.doesNotMatch(attendeeFlow, new RegExp(`Button\\(\\"${titleCaseLabel}\\"`));
  }

  for (const sentenceCaseLabel of ["Keep selecting", "Clear selections", "Open settings"]) {
    assert.match(attendeeFlow, new RegExp(`Button\\(\\"${sentenceCaseLabel}\\"`));
  }
});

test("conditional alternative buttons use sentence case on iOS and web", () => {
  const home = fs.readFileSync(path.join(repositoryRoot, "HerdHost/HomeView.swift"), "utf8");
  const editor = fs.readFileSync(path.join(repositoryRoot, "HerdHost/EventEditorView.swift"), "utf8");
  const page = fs.readFileSync(path.join(repositoryRoot, "invitee-web/app/page.tsx"), "utf8");

  assert.match(home, /Image\(systemName: "plus"\)\s*Text\("or"\)/u);
  assert.match(editor, /Label\("or", systemImage: "plus"\)/u);
  assert.match(page, /<span aria-hidden="true">\+<\/span> or<\/button>/u);
});
