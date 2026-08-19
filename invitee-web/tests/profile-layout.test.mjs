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
  const profileAddressPicker = swiftHome.slice(
    swiftHome.indexOf("private struct ProfileAddressPicker"),
    swiftHome.indexOf("private struct EventCard"),
  );

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
  assert.match(page, /profileAddressUnitInputRef\.current\?\.blur\(\)/u);
  assert.doesNotMatch(page, /setProfileNotice\(PROFILE_EXPERIENCE\.savedNotice\)/u);
  assert.doesNotMatch(page, /profileNotice === PROFILE_EXPERIENCE\.savedNotice/u);
  assert.deepEqual(experience.profile.unsavedChanges, {
    title: "Discard changes?",
    body: "Your changes haven’t been saved. If you leave now, they’ll be lost.",
    cancelButton: "Keep editing",
    confirmButton: "Discard",
  });
  assert.match(page, /screen === "profile" && profileHasChanges[\s\S]*setProfileDiscardConfirmationOpen\(true\)/u);
  assert.match(page, /role="alertdialog"[\s\S]*PROFILE_EXPERIENCE\.unsavedChanges\.title/u);
  assert.match(page, /className="danger-button" onClick=\{discardProfileChanges\}/u);
  assert.match(css, /\.profile-inline-action \{[^}]*min-height: 44px/u);
  assert.match(css, /\.profile-save-action \.primary-button:disabled/u);
  assert.match(page, /className="profile-field-clear"[\s\S]*Clear \$\{PROFILE_EXPERIENCE\.nameLabel\}/u);
  assert.match(page, /className="profile-field-clear"[\s\S]*Clear \$\{PROFILE_EXPERIENCE\.addressLabel\}/u);
  assert.match(page, /id="profile-address-unit"[\s\S]*autoComplete="address-line2"/u);
  assert.match(page, /aria-label="Clear unit number"/u);
  assert.match(page, /combineUnitAddress\(address, addressUnit\)/u);
  assert.match(page, /className="profile-field profile-field-readonly"[\s\S]*profile-phone-info/u);
  assert.match(page, /role="tooltip"[\s\S]*PROFILE_EXPERIENCE\.phoneImmutableMessage/u);
  assert.match(css, /\.profile-field:focus-within \.profile-field-clear \{[^}]*opacity: 1/u);
  assert.match(css, /\.profile-field-clear \{[^}]*opacity: 0;[^}]*pointer-events: none/u);

  assert.match(swiftHome, /Text\(experience\.syncNote\)[\s\S]*ProfileField/u);
  assert.match(swiftHome, /\.safeAreaInset\(edge: \.bottom[\s\S]*saveFooter/u);
  assert.match(swiftHome, /\.disabled\(authStore\.isBusy \|\| !profileHasChanges\)/u);
  assert.match(swiftHome, /isNameFocused = false[\s\S]*authStore\.updateProfile/u);
  assert.doesNotMatch(swiftHome, /Label\(savedNotice, systemImage: "checkmark\.circle\.fill"\)/u);
  assert.match(swiftHome, /private var profileAccountActions: some View/u);
  assert.match(swiftHome, /\.navigationTitle\(""\)/u);
  assert.match(swiftHome, /\.navigationBarBackButtonHidden\(true\)/u);
  assert.match(swiftHome, /if profileHasChanges \{[\s\S]*showsUnsavedChangesConfirmation = true/u);
  assert.match(swiftHome, /experience\.unsavedChanges\.title[\s\S]*role: \.destructive/u);
  assert.match(swiftHome, /profile-more-actions/u);
  assert.match(swiftHome, /rectangle\.portrait\.and\.arrow\.right/u);
  assert.match(swiftHome, /if isFocused\.wrappedValue && !text\.isEmpty[\s\S]*xmark\.circle\.fill/u);
  assert.match(swiftHome, /info\.circle[\s\S]*popover\(isPresented: \$showsExplanation/u);
  assert.match(swiftHome, /ProfileAddressPicker\([\s\S]*address: \$address[\s\S]*showsAddressSearch = true/u);
  assert.match(swiftHome, /isPresented: \$showsAddressSearch[\s\S]*AddressSearchView\(address: \$address\)/u);
  assert.match(swiftHome, /accessibilityIdentifier\("profile-address"\)/u);
  assert.doesNotMatch(profileAddressPicker, /chevron\.right|profile-address-clear|xmark\.circle\.fill/u);
  assert.match(swiftLocationSearch, /LocationSearchModel\(initialQuery: parsedAddress\.base\)/u);
  assert.equal((swiftLocationSearch.match(/Button\("Done"\)/gu) ?? []).length, 2);
  assert.doesNotMatch(swiftLocationSearch, /Button\("Save"\)/u);
  assert.match(swiftLocationSearch, /_unitNumber = State\(initialValue: parsedAddress\.unit\)/u);
  assert.match(swiftLocationSearch, /accessibilityIdentifier: "profile-address-search"/u);
  assert.match(swiftLocationSearch, /if isFocused\.wrappedValue && !query\.isEmpty[\s\S]*xmark\.circle\.fill/u);
  assert.match(swiftLocationSearch, /if isFocused\.wrappedValue && showsSuggestions[\s\S]*suggestions/u);
  assert.match(swiftLocationSearch, /profile-address-result-/u);
});
