import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import ts from "typescript";

const MAXIMUM_BYTES = 64 * 1024;

const source = await readFile(
  new URL("../lib/backend/http.ts", import.meta.url),
  "utf8",
);
const compiled = ts.transpileModule(source, {
  compilerOptions: {
    module: ts.ModuleKind.ESNext,
    target: ts.ScriptTarget.ES2022,
    isolatedModules: true,
  },
  fileName: "lib/backend/http.ts",
}).outputText;
const { readJsonObject } = await import(
  `data:text/javascript;base64,${Buffer.from(compiled).toString("base64")}`
);

function jsonRequest(body, headers = {}) {
  return new Request("https://herd.test/api/test", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: "https://herd.test",
      ...headers,
    },
    body,
    duplex: "half",
  });
}

function assertApiError(error, status, code) {
  assert.equal(error?.status, status);
  assert.equal(error?.code, code);
  return true;
}

test("readJsonObject accepts exactly 64 KiB of valid UTF-8 JSON", async () => {
  const emptyDocument = JSON.stringify({ value: "" });
  const document = JSON.stringify({
    value: "x".repeat(MAXIMUM_BYTES - Buffer.byteLength(emptyDocument)),
  });
  assert.equal(Buffer.byteLength(document), MAXIMUM_BYTES);

  const parsed = await readJsonObject(jsonRequest(document));
  assert.equal(parsed.value.length, MAXIMUM_BYTES - Buffer.byteLength(emptyDocument));
});

test("readJsonObject cancels a chunked no-Length body at 64 KiB plus one", async () => {
  let cancelled = false;
  let emitted = 0;
  const body = new ReadableStream({
    pull(controller) {
      if (emitted >= MAXIMUM_BYTES + 1) {
        controller.close();
        return;
      }
      const length = Math.min(16 * 1024, MAXIMUM_BYTES + 1 - emitted);
      emitted += length;
      controller.enqueue(new Uint8Array(length).fill(0x78));
    },
    cancel() {
      cancelled = true;
    },
  });
  const request = jsonRequest(body);
  assert.equal(request.headers.has("content-length"), false);

  await assert.rejects(
    readJsonObject(request),
    (error) => assertApiError(error, 413, "payload_too_large"),
  );
  assert.equal(cancelled, true);
});

test("readJsonObject preserves 413 when cancelling the oversized stream fails", async () => {
  let emitted = 0;
  let cancelAttempted = false;
  const body = new ReadableStream({
    pull(controller) {
      if (emitted >= MAXIMUM_BYTES + 1) {
        controller.close();
        return;
      }
      const length = Math.min(32 * 1024, MAXIMUM_BYTES + 1 - emitted);
      emitted += length;
      controller.enqueue(new Uint8Array(length).fill(0x78));
    },
    cancel() {
      cancelAttempted = true;
      throw new Error("cancel failed");
    },
  });

  await assert.rejects(
    readJsonObject(jsonRequest(body)),
    (error) => assertApiError(error, 413, "payload_too_large"),
  );
  assert.equal(cancelAttempted, true);
});

test("readJsonObject rejects an invalid Content-Length before reading", async () => {
  await assert.rejects(
    readJsonObject(jsonRequest("{}", { "content-length": "not-a-number" })),
    (error) => assertApiError(error, 400, "invalid_request"),
  );
});

test("readJsonObject rejects invalid UTF-8 and request stream failures", async (context) => {
  await context.test("invalid UTF-8", async () => {
    await assert.rejects(
      readJsonObject(jsonRequest(new Uint8Array([0xff]))),
      (error) => assertApiError(error, 400, "invalid_json"),
    );
  });

  await context.test("stream failure", async () => {
    const body = new ReadableStream({
      pull(controller) {
        controller.error(new Error("stream failed"));
      },
    });
    await assert.rejects(
      readJsonObject(jsonRequest(body)),
      (error) => assertApiError(error, 400, "invalid_json"),
    );
  });
});
