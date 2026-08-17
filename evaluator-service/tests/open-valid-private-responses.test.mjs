import assert from "node:assert/strict";
import test from "node:test";

import { openValidPrivateResponses } from "../lib/open-valid-private-responses.mjs";

test("opens valid responses in policy order while isolating invalid envelopes", async () => {
  const opened = await openValidPrivateResponses(
    ["first", "poisoned", "third"],
    async (value) => {
      if (value === "poisoned") throw new Error("private decrypt detail");
      return { inviteeId: value, response: "going" };
    },
  );

  assert.deepEqual(opened, [
    { inviteeId: "first", response: "going" },
    { inviteeId: "third", response: "going" },
  ]);
});

test("all invalid envelopes become an empty response set without rejecting", async () => {
  const opened = await openValidPrivateResponses([1, 2], async () => {
    throw new Error("must stay inside the evaluator");
  });

  assert.deepEqual(opened, []);
});
