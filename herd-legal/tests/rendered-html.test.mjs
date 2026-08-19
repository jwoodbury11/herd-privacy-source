import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

async function render(pathname = "/") {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${pathname}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`https://legal.herd.test${pathname}`, {
      headers: { accept: "text/html", host: "legal.herd.test" },
    }),
    { ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) } },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("renders the Herd legal landing page", async () => {
  const response = await render();
  assert.equal(response.status, 200);
  const html = await response.text();

  assert.match(html, /Clear rules for one-time Herd invitations/);
  assert.match(html, /Terms of Service/);
  assert.match(html, /Privacy Policy/);
  assert.match(html, /One-time SMS invite policy/);
  assert.match(html, /https:\/\/legal\.herd\.test\/og\.png/);
  assert.doesNotMatch(html, /Your site is taking shape|codex-preview|Starter Project/);
});

test("publishes complete public messaging policies", async () => {
  const [termsResponse, privacyResponse, proofResponse] = await Promise.all([
    render("/terms"),
    render("/privacy"),
    render("/sms-invite-consent"),
  ]);

  for (const response of [termsResponse, privacyResponse, proofResponse]) {
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  }

  const [terms, privacy, proof] = await Promise.all([
    termsResponse.text(),
    privacyResponse.text(),
    proofResponse.text(),
  ]);

  assert.match(terms, /one event invitation from Herd at the host’s request/i);
  assert.match(terms, /Requested phone verification codes/i);
  assert.match(terms, /operated by James Woodbury as a sole proprietor/i);
  assert.match(terms, /Reply <strong>STOP<\/strong> to opt out/i);
  assert.match(privacy, /text messaging originator opt-in data and consent/i);
  assert.match(privacy, /won’t be shared[^<]*with any third parties/i);
  assert.match(privacy, /permanently delete your account from <strong>Your profile<\/strong>/i);
  assert.match(privacy, /private reply revisions are removed 90 days after a final event result/i);
  assert.match(
    privacy,
    /private, event-specific ballot ID—not your name, phone number, account, or other identifying information/i,
  );
  assert.match(privacy, /never shown to hosts, guests, or third parties/i);
  assert.match(privacy, /configured messaging provider handles STOP, START, and HELP replies/i);
  assert.doesNotMatch(privacy, /Herd (?:directly )?(?:processes|handles) STOP/iu);
  assert.match(proof, /Send one-time invitations\?/i);
  assert.match(proof, /Example of prior recipient permission/i);
  assert.match(proof, /Selected individually from your contacts/i);
  assert.match(proof, /No automatic reminders will follow/i);
  assert.match(proof, /have their permission to receive this one-time event invitation/i);
  assert.match(proof, /configured messaging provider[\s\S]*handles STOP, START, and HELP replies/i);
  assert.doesNotMatch(proof, /Herd (?:directly )?(?:processes|handles) STOP/iu);
  assert.match(proof, /\+1 \(855\) 253-9387/);
});

test("all legal routes consume the repository canonical content module", async () => {
  const sources = await Promise.all([
    "terms/page.tsx",
    "privacy/page.tsx",
    "sms-invite-consent/page.tsx",
    "legal-page.tsx",
  ].map((pathname) => readFile(new URL(`../app/${pathname}`, import.meta.url), "utf8")));
  for (const source of sources) {
    assert.match(source, /legal-content/u);
  }
});

test("contains no starter surface and ships branded assets", async () => {
  const [page, layout, packageJson] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/layout.tsx", import.meta.url), "utf8"),
    readFile(new URL("../package.json", import.meta.url), "utf8"),
  ]);

  assert.doesNotMatch(page, /SkeletonPreview|codex-preview/);
  assert.doesNotMatch(layout, /Starter Project|favicon\.svg/);
  assert.doesNotMatch(packageJson, /react-loading-skeleton/);
  await access(new URL("../public/herd-icon.png", import.meta.url));
  await access(new URL("../public/og.png", import.meta.url));
  await assert.rejects(access(new URL("../app/_sites-preview/SkeletonPreview.tsx", import.meta.url)));
});
