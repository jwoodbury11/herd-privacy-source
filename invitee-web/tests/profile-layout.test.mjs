import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

test("profile actions and change-aware save stay aligned on web and iPhone", async () => {
  const [page, css, experienceSource, swiftHome, swiftLocationSearch] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/LocationSearchView.swift", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.equal(
    experience.profile.syncNote,
    "Your phone number and address are never shown to other guests.",
  );
  assert.equal(
    experience.profile.phoneImmutableMessage,
    "Your account phone number cannot be changed.",
  );
  assert.match(page, /className="screen-page-heading"[\s\S]*PROFILE_EXPERIENCE\.syncNote/u);
  assert.match(page, /className="profile-account-actions"/u);
  assert.match(page, /persistentAction[\s\S]*className="profile-overflow"/u);
  assert.match(page, /MoreHorizontal[\s\S]*More profile actions/u);
  assert.match(page, /LogOut[\s\S]*PROFILE_EXPERIENCE\.logoutButton/u);
  assert.doesNotMatch(page, /profile-inline-delete/u);
  assert.match(page, /className="bottom-action profile-save-action"/u);
  assert.match(page, /disabled=\{!profileHasChanges \|\| profilePending\}/u);
  assert.match(page, /profileNameInputRef\.current\?\.blur\(\);[\s\S]*profileAddressInputRef\.current\?\.blur\(\);/u);
  assert.doesNotMatch(page, /setProfileNotice\(PROFILE_EXPERIENCE\.savedNotice\)/u);
  assert.doesNotMatch(page, /profileNotice === PROFILE_EXPERIENCE\.savedNotice/u);
  assert.match(css, /\.profile-inline-action \{[^}]*min-height: 44px/u);
  assert.match(css, /\.profile-save-action \.primary-button:disabled/u);
  assert.match(page, /className="profile-field-clear"[\s\S]*Clear \$\{PROFILE_EXPERIENCE\.nameLabel\}/u);
  assert.match(page, /className="profile-field-clear"[\s\S]*Clear \$\{PROFILE_EXPERIENCE\.addressLabel\}/u);
  assert.match(page, /className="profile-field profile-field-readonly"[\s\S]*profile-phone-info/u);
  assert.match(page, /role="tooltip"[\s\S]*PROFILE_EXPERIENCE\.phoneImmutableMessage/u);
  assert.match(css, /\.profile-field:focus-within \.profile-field-clear \{[^}]*opacity: 1/u);

  assert.match(swiftHome, /Text\(experience\.syncNote\)[\s\S]*ProfileField/u);
  assert.match(swiftHome, /\.safeAreaInset\(edge: \.bottom[\s\S]*saveFooter/u);
  assert.match(swiftHome, /\.disabled\(authStore\.isBusy \|\| !profileHasChanges\)/u);
  assert.match(swiftHome, /isNameFocused = false[\s\S]*authStore\.updateProfile/u);
  assert.doesNotMatch(swiftHome, /Label\(savedNotice, systemImage: "checkmark\.circle\.fill"\)/u);
  assert.match(swiftHome, /private var profileAccountActions: some View/u);
  assert.match(swiftHome, /\.navigationTitle\(""\)/u);
  assert.match(swiftHome, /profile-more-actions/u);
  assert.match(swiftHome, /rectangle\.portrait\.and\.arrow\.right/u);
  assert.match(swiftHome, /if isFocused\.wrappedValue && !text\.isEmpty[\s\S]*xmark\.circle\.fill/u);
  assert.match(swiftHome, /info\.circle[\s\S]*popover\(isPresented: \$showsExplanation/u);
  assert.match(swiftHome, /ProfileAddressPicker\([\s\S]*address: \$address[\s\S]*showsAddressSearch = true/u);
  assert.match(swiftHome, /isPresented: \$showsAddressSearch[\s\S]*AddressSearchView\(address: \$address\)/u);
  assert.match(swiftHome, /accessibilityIdentifier\("profile-address"\)/u);
  assert.match(swiftLocationSearch, /LocationSearchModel\(initialQuery: address\.wrappedValue\)/u);
  assert.match(swiftLocationSearch, /accessibilityIdentifier: "profile-address-search"/u);
  assert.match(swiftLocationSearch, /profile-address-result-/u);
});
