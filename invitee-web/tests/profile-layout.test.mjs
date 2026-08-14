import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("profile actions and change-aware save stay aligned on web and iPhone", async () => {
  const [page, css, experienceSource, swiftHome] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.equal(
    experience.profile.syncNote,
    "Your phone number and address are never shown to other guests.",
  );
  assert.match(page, /className="screen-page-heading"[\s\S]*PROFILE_EXPERIENCE\.syncNote/u);
  assert.match(page, /className="profile-account-actions"/u);
  assert.match(page, /persistentAction[\s\S]*className="profile-overflow"/u);
  assert.match(page, /MoreHorizontal[\s\S]*More profile actions/u);
  assert.match(page, /LogOut[\s\S]*PROFILE_EXPERIENCE\.logoutButton/u);
  assert.doesNotMatch(page, /profile-inline-delete/u);
  assert.match(page, /className="bottom-action profile-save-action"/u);
  assert.match(page, /disabled=\{!profileHasChanges \|\| profilePending\}/u);
  assert.match(css, /\.profile-inline-action \{[^}]*min-height: 44px/u);
  assert.match(css, /\.profile-save-action \.primary-button:disabled/u);

  assert.match(swiftHome, /Text\(experience\.syncNote\)[\s\S]*ProfileField/u);
  assert.match(swiftHome, /\.safeAreaInset\(edge: \.bottom[\s\S]*saveFooter/u);
  assert.match(swiftHome, /\.disabled\(authStore\.isBusy \|\| !profileHasChanges\)/u);
  assert.match(swiftHome, /private var profileAccountActions: some View/u);
  assert.match(swiftHome, /\.navigationTitle\(""\)/u);
  assert.match(swiftHome, /profile-more-actions/u);
  assert.match(swiftHome, /rectangle\.portrait\.and\.arrow\.right/u);
});
