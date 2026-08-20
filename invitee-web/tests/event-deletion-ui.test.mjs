import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("hosted event deletion stays owner-only and confirmation-gated across clients", async () => {
  const [page, css, experienceSource, swiftHome, route, backend] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../app/api/events/[id]/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/backend/events.ts", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.equal(experience.invitation.eventActions.deleteButton, "Delete this event");
  assert.match(experience.invitation.eventActions.deletionBody, /everyone invited/i);
  assert.match(page, /activeEvent\.role === "host"[\s\S]*?className="event-overflow"/u);
  assert.match(page, /openEventDeletion[\s\S]*?setEventDeletionOpen\(true\)/u);
  assert.match(page, /method: "DELETE"[\s\S]*?setEvents\(\(current\) => current\.filter/u);
  assert.match(page, /role="alertdialog"[\s\S]*?eventActions\.deletionBody/u);
  assert.match(page, /data-testid="confirm-delete-hosted-event"/u);
  assert.match(css, /\.event-overflow-menu/u);
  assert.match(css, /\.event-deletion-dialog/u);

  assert.match(swiftHome, /if event\?\.isHosted == true[\s\S]*?event-actions-menu/u);
  assert.match(swiftHome, /UIImage\(systemName: "trash"\)[\s\S]*?withTintColor\(\.systemRed, renderingMode: \.alwaysOriginal\)/u);
  assert.match(swiftHome, /Text\(invitationExperience\.eventActions\.deleteButton\)[\s\S]*?\.foregroundStyle\(\.red\)[\s\S]*?Image\(uiImage: Self\.destructiveTrashImage\)/u);
  assert.match(swiftHome, /eventActions\.deletionTitle[\s\S]*?eventActions\.deletionBody/u);
  assert.match(swiftHome, /await store\.delete\(event\)/u);

  assert.match(route, /requireSameOrigin\(request\)[\s\S]*?deleteHostedEvent/u);
  assert.match(backend, /DELETE FROM events WHERE id = \? AND host_user_id = \?/u);
});
