import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const relaySource = await readFile(
  new URL("../lib/client/evaluation-relay.ts", import.meta.url),
  "utf8",
);
const pageSource = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");

test("web host evaluation relay is origin-pinned, bounded, and credential-free", () => {
  assert.match(relaySource, /endpoint\.protocol !== "https:"/u);
  assert.match(relaySource, /endpoint\.pathname !== "\/api\/v1\/relay\/"/u);
  assert.match(relaySource, /endpoint\.origin !== pinnedOrigin/u);
  assert.match(relaySource, /credentials: "omit"/u);
  assert.match(relaySource, /redirect: "manual"/u);
  assert.match(relaySource, /referrerPolicy: "no-referrer"/u);
  assert.match(relaySource, /EVALUATOR_RESPONSE_LIMIT_BYTES/u);
  assert.doesNotMatch(relaySource, /authorization/iu);
});

test("web app retries participant evaluations without failing event refresh", () => {
  assert.match(pageSource, /relayHostEventEvaluation/u);
  assert.match(pageSource, /await Promise\.allSettled\(/u);
  assert.match(pageSource, /function needsResolutionRelay\(event: ApiEvent\)/u);
  assert.match(pageSource, /event\.resolution\?\.status === "pending"/u);
  assert.match(pageSource, /event\.resolution\?\.status === "confirmed"/u);
  assert.match(pageSource, /!event\.resolution\.attendanceRevealed/u);
  assert.doesNotMatch(pageSource, /Date\.parse\(event\.rsvpDeadline!\) <= now/u);
  assert.match(pageSource, /trackedFetch\("\/api\/events", \{ credentials: "include" \}\)/u);
  assert.match(relaySource, /trackedFetch/u);
});
