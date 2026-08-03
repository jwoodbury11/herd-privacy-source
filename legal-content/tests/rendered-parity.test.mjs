import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const renderer = fileURLToPath(new URL("./render-worker.mjs", import.meta.url));

const targets = [
  {
    name: "standalone",
    origin: "https://legal.herd.test",
    worker: new URL("../../herd-legal/dist/server/index.js", import.meta.url),
  },
  {
    name: "in-app",
    origin: "https://app.herd.test",
    worker: new URL("../../invitee-web/dist/server/index.js", import.meta.url),
  },
];

async function render(target, pathname) {
  const { stdout } = await execFileAsync(
    process.execPath,
    [renderer, fileURLToPath(target.worker), target.origin, pathname],
    { maxBuffer: 10 * 1_024 * 1_024 },
  );
  return stdout;
}

function decodeEntities(value) {
  const named = new Map([
    ["amp", "&"],
    ["apos", "'"],
    ["gt", ">"],
    ["lt", "<"],
    ["nbsp", " "],
    ["quot", '"'],
  ]);
  return value
    .replace(/&#x([0-9a-f]+);/giu, (_match, code) =>
      String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&#([0-9]+);/gu, (_match, code) =>
      String.fromCodePoint(Number.parseInt(code, 10)))
    .replace(/&([a-z]+);/giu, (match, name) => named.get(name.toLowerCase()) ?? match);
}

function articleText(html) {
  const article = html.match(/<article\b[^>]*>([\s\S]*?)<\/article>/iu);
  assert.ok(article, "rendered legal page must contain one article");
  return decodeEntities(
    article[1]
      .replace(/<script\b[\s\S]*?<\/script>/giu, " ")
      .replace(/<!--[^]*?-->/gu, " ")
      .replace(/<[^>]+>/gu, " "),
  ).replace(/\s+/gu, " ").trim();
}

for (const pathname of ["/terms", "/privacy", "/sms-invite-consent"]) {
  test(`${pathname} has identical rendered legal content on both public surfaces`, async () => {
    const [standalone, inApp] = await Promise.all(
      targets.map((target) => render(target, pathname)),
    );
    assert.equal(articleText(standalone), articleText(inApp));
  });
}

test("rendered messaging disclosures attribute inbound keywords to the provider", async () => {
  const pages = await Promise.all(
    targets.flatMap((target) =>
      ["/privacy", "/sms-invite-consent"].map((pathname) => render(target, pathname))),
  );
  for (const page of pages) {
    assert.match(page, /configured messaging provider[\s\S]*handles STOP, START, and HELP replies/iu);
    assert.doesNotMatch(page, /Herd (?:directly )?(?:processes|handles) STOP/iu);
  }
});
