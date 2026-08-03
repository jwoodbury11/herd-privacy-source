import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { resolve } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

const execute = promisify(execFile);
const scripts = resolve(import.meta.dirname, "../scripts");

function exactKeys(value, expected) {
  assert.deepEqual(Object.keys(value), expected);
}

test("key ceremonies create separate exclusive mode-0600 epoch and global bundles", async () => {
  const directory = await mkdtemp(resolve(tmpdir(), "herd-key-ceremony-"));
  const epochFile = resolve(directory, "epoch.json");
  const tokenFile = resolve(directory, "request-token.txt");
  const transparencyFile = resolve(directory, "transparency.json");
  try {
    await execute(process.execPath, [
      resolve(scripts, "generate-key-bundle.mjs"),
      "epoch-test-v1",
      epochFile,
      tokenFile,
    ]);
    await execute(process.execPath, [
      resolve(scripts, "generate-transparency-key-bundle.mjs"),
      "herd-response-log-v1.global",
      transparencyFile,
    ]);

    assert.equal((await stat(epochFile)).mode & 0o777, 0o600);
    assert.equal((await stat(tokenFile)).mode & 0o777, 0o600);
    assert.equal((await stat(transparencyFile)).mode & 0o777, 0o600);
    const epoch = JSON.parse(await readFile(epochFile, "utf8"));
    const transparency = JSON.parse(
      await readFile(transparencyFile, "utf8"),
    );
    exactKeys(epoch, [
      "protocolVersion",
      "releaseId",
      "requestAuthenticationToken",
      "responseDecryptionKey",
      "evaluationResultSigningKey",
      "policySigningKey",
    ]);
    exactKeys(transparency, [
      "protocolVersion",
      "logId",
      "transparencySigningKey",
    ]);
    assert.equal(epoch.releaseId, "epoch-test-v1");
    assert.equal(transparency.logId, "herd-response-log-v1");
    assert.equal("transparencySigningKey" in epoch, false);
    assert.equal("requestAuthenticationToken" in transparency, false);
    assert.equal((await readFile(tokenFile, "utf8")).trim(), epoch.requestAuthenticationToken);
    assert.ok(epoch.requestAuthenticationToken.length >= 32);

    await assert.rejects(
      execute(process.execPath, [
        resolve(scripts, "generate-key-bundle.mjs"),
        "epoch-test-v1",
        epochFile,
        resolve(directory, "replacement-token.txt"),
      ]),
    );

    await assert.rejects(
      execute(process.execPath, [
        resolve(scripts, "generate-transparency-key-bundle.mjs"),
        "replacement-not-allowed",
        transparencyFile,
      ]),
    );
    assert.equal(
      JSON.parse(await readFile(transparencyFile, "utf8"))
        .transparencySigningKey.keyId,
      "herd-response-log-v1.global",
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
