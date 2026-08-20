import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const iosEditorPath = new URL("../../HerdHost/EventEditorView.swift", import.meta.url);
const iosLocationPath = new URL("../../HerdHost/LocationSearchView.swift", import.meta.url);
const iosAttendeesPath = new URL("../../HerdHost/AttendeeFlowView.swift", import.meta.url);
const webAppPath = new URL("../app/page.tsx", import.meta.url);

test("keyboard focus is explicitly released across iOS and web navigation boundaries", async () => {
  const [editor, location, attendees, web] = await Promise.all([
    readFile(iosEditorPath, "utf8"),
    readFile(iosLocationPath, "utf8"),
    readFile(iosAttendeesPath, "utf8"),
    readFile(webAppPath, "utf8"),
  ]);

  assert.match(editor, /fullScreenCover\(isPresented: \$showsInvitees, onDismiss: dismissKeyboard\)/u);
  assert.match(editor, /sheet\(isPresented: \$showsLocation, onDismiss: dismissKeyboard\)/u);
  assert.match(location, /Button\("Cancel"\) \{\s+dismissKeyboard\(\)\s+dismiss\(\)/u);
  assert.match(attendees, /\.onDisappear\(perform: dismissKeyboard\)/u);
  assert.match(web, /function goBack\(\)[\s\S]*?blurActiveControl\(\);\s+setScreen\(previous\[screen\]\)/u);
  assert.match(web, /function closeGuestAddition\(\)[\s\S]*?blurActiveControl\(\)/u);
});
