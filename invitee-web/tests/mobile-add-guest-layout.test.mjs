import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

test("page headings stack supporting copy unless a row action is explicitly requested", async () => {
  const css = await readFile(new URL("app/globals.css", projectRoot), "utf8");

  assert.match(css, /\.screen-page-heading \{[\s\S]*?display: block;[\s\S]*?\}/u);
  assert.match(css, /\.screen-page-heading-with-action \{[\s\S]*?display: flex;[\s\S]*?\}/u);
  assert.doesNotMatch(css, /\.attendees-screen \.screen-page-heading/u);
});

test("mobile web adds exactly one guest without numbered cards or bulk controls", async () => {
  const [page, css] = await Promise.all([
    readFile(new URL("app/page.tsx", projectRoot), "utf8"),
    readFile(new URL("app/globals.css", projectRoot), "utf8"),
  ]);

  assert.match(page, /const \[guestDraft, setGuestDraft\] = useState<GuestDraft \| null>/u);
  assert.match(page, /body: JSON\.stringify\(\{ invitees: \[invitee\] \}\)/u);
  assert.match(page, /ATTENDEES_EXPERIENCE\.addGuests\.submitSingleButton/u);
  assert.doesNotMatch(page, /addGuestDraft|removeGuestDraft|addAnotherButton|submitMultipleTemplate/u);
  assert.match(css, /\.guest-entry-fields \{[\s\S]*?display: grid;[\s\S]*?\}/u);
  assert.doesNotMatch(css, /\.guest-draft-card|\.add-another-guest-button/u);
});
