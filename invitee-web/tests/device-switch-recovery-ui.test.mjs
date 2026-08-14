import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("iPhone waits for the key-switch alert to dismiss before presenting recovery", async () => {
  const source = await readFile(
    new URL("../../HerdHost/HomeView.swift", import.meta.url),
    "utf8",
  );

  assert.match(
    source,
    /awaitsDeviceSwitchAlertDismissal = true\s+showsDeviceSwitchConfirmation = false/u,
  );
  assert.match(
    source,
    /\.onChange\(of: showsDeviceSwitchConfirmation\)[\s\S]*?Task\.sleep\(for: \.milliseconds\(250\)\)[\s\S]*?beginDeviceSwitch\(\)/u,
  );
  assert.doesNotMatch(
    source,
    /Button\(replyExperience\.deviceSwitch\.confirmButton[\s\S]{0,180}?beginDeviceSwitch\(\)/u,
  );
});
