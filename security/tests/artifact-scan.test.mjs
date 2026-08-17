import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";

import { scanSensitiveArtifacts } from "../../scripts/scan-sensitive-artifacts.mjs";

test("artifact scan detects raw and encoded privacy sentinels", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "herd-privacy-scan-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  const sentinel = "HERD SENTINEL/private condition 2048";
  await writeFile(path.join(directory, "safe.log"), "request complete\n");
  await writeFile(path.join(directory, "raw.dump"), `prefix ${sentinel} suffix`);
  await writeFile(
    path.join(directory, "encoded.log"),
    `body=${encodeURIComponent(sentinel)}`,
  );
  const result = await scanSensitiveArtifacts({
    targets: [directory],
    sentinels: [sentinel],
  });
  assert.equal(result.files, 3);
  assert.ok(result.findings.some((finding) => finding.encoding === "raw"));
  assert.ok(result.findings.some((finding) => finding.encoding === "url-encoded"));
});

test("artifact scan accepts clean files and flags readable response fields", async (t) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "herd-privacy-fields-"));
  t.after(() => rm(directory, { recursive: true, force: true }));
  await writeFile(path.join(directory, "clean.dump"), "payload_ciphertext=opaque\n");
  const clean = await scanSensitiveArtifacts({
    targets: [directory],
    sentinels: ["HERD-SENTINEL-never-present"],
    rejectReadableResponseFields: true,
  });
  assert.deepEqual(clean.findings, []);
  await writeFile(path.join(directory, "unsafe.dump"), '"condition_groups": [["person"]]\n');
  const unsafe = await scanSensitiveArtifacts({
    targets: [directory],
    sentinels: [],
    rejectReadableResponseFields: true,
  });
  assert.equal(unsafe.findings.length, 1);
  assert.equal(unsafe.findings[0].kind, "readable-response-field");
});
