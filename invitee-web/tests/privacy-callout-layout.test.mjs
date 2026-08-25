import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("privacy callout centers its hidden-status icon against the text block", async () => {
  const css = await readFile(new URL("app/globals.css", projectRoot), "utf8");

  assert.match(css, /\.privacy-flow-boundary \{[^}]*align-items: center;/u);
  assert.match(css, /\.privacy-flow-boundary svg \{[^}]*align-self: center;/u);
});
