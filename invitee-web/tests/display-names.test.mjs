import assert from "node:assert/strict";
import test from "node:test";

import { requiredAttendeeName } from "../lib/client/display-names.mjs";

test("selected required attendees use first name and uppercase last initial", () => {
  assert.equal(requiredAttendeeName("Grant Bernero"), "Grant B");
  assert.equal(requiredAttendeeName("  Ella   herdTestUser  "), "Ella H");
  assert.equal(requiredAttendeeName("Prince"), "Prince");
  assert.equal(requiredAttendeeName(" \n "), "Guest");
});
