import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("mobile scroll screens stop above persistent browser controls", async () => {
  const css = await readFile(new URL("app/globals.css", projectRoot), "utf8");
  const mobileStart = css.indexOf("@media (max-width: 520px)");
  const mobileEnd = css.indexOf("@media (max-width: 370px)", mobileStart);
  const mobileRules = css.slice(mobileStart, mobileEnd);

  assert.ok(mobileStart >= 0 && mobileEnd > mobileStart);
  assert.match(mobileRules, /\.site-stage \{ height: 100svh;/u);
  assert.match(mobileRules, /\.app-shell \{[^}]*height: 100svh;/u);
  assert.doesNotMatch(mobileRules, /100dvh/u);
  assert.match(css, /\.screen-scroll \{[\s\S]*?overflow-y: auto;/u);
});
