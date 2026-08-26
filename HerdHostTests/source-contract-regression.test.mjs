import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = async (name) =>
  readFile(new URL(`../HerdHost/${name}`, import.meta.url), "utf8");

test("response success previews one outcome at a time with equal cards", async () => {
  const [home, experience] = await Promise.all([
    source("HomeView.swift"),
    readFile(new URL("../invitee-web/shared/HerdExperience.json", import.meta.url), "utf8"),
  ]);
  assert.match(experience, /"replyPreviewTitle": "This is how your reply will appear to others\."/u);
  assert.match(experience, /"confirmedPreviewOption": "If confirmed"/u);
  assert.match(experience, /"notConfirmedPreviewOption": "If never confirmed"/u);
  assert.doesNotMatch(experience, /"Your latest reply is saved\."/u);
  assert.match(home, /private var outcomeSelector: some View/u);
  assert.match(home, /HStack\(spacing: 0\)/u);
  assert.match(home, /\.frame\(height: 58\)/u);
  assert.match(home, /accessibilityIdentifier\("success-outcome-picker"\)/u);
  assert.match(home, /mode: previewOutcome == \.confirmed \? \.confirmed : \.notConfirmed/u);
  assert.match(home, /background\(attendeeAvatarTone\(1\), in: \.circle\)/u);
  assert.match(home, /accessibilityIdentifier\("reply-preview-confirmed-card"\)/u);
  assert.match(home, /accessibilityIdentifier\("reply-preview-not-confirmed-card"\)/u);
  assert.match(home, /frame\(minHeight: 68\)/u);
});

test("privacy proof omits the essentials label without collapsing its spacing", async () => {
  const home = await source("HomeView.swift");
  assert.match(
    home,
    /HStack\(alignment: \.center, spacing: 14\) \{[\s\S]*Image\(systemName: "eye\.slash\.fill"\)[\s\S]*Text\(experience\.flowPrivacyLabel\)/u,
  );
  assert.match(
    home,
    /eyebrow\(experience\.answersEyebrow\)[\s\S]*?\.hidden\(\)[\s\S]*?Text\(experience\.answersTitle\)/u,
  );
  assert.match(
    home,
    /onScrollGeometryChange\(for: Bool\.self\)[\s\S]*?contentOffset\.y \+ geometry\.contentInsets\.top > 55[\s\S]*?showsCollapsedTitle = shouldShowTitle/u,
  );
  assert.match(home, /accessibilityIdentifier\("privacy-navigation-divider"\)/u);
  assert.match(home, /toolbarBackground\(\.visible, for: \.navigationBar\)/u);
  assert.doesNotMatch(home, /InvitationTitleBottomPreferenceKey/u);
});

test("host drafts reopen in the editor and are labeled as drafts", async () => {
  const home = await source("HomeView.swift");
  assert.match(
    home,
    /if event\.isHosted && !event\.invitationsSent \{\s*presentation = \.create\(event\)/u,
  );
  assert.match(
    home,
    /if isHosted && !invitationsSent \{\s*return status\.draft/u,
  );
});

test("legacy events require an explicit account claim", async () => {
  const [store, home] = await Promise.all([
    source("EventStore.swift"),
    source("HomeView.swift"),
  ]);
  assert.match(store, /herd\.host\.events\.v1\.claimed-user-id/u);
  assert.match(store, /func claimLegacyHostedEvents\(\) async -> Bool/u);
  assert.match(store, /removeLegacyEventsFromOtherCaches/u);
  assert.match(home, /Import into this account/u);
});

test("initial event loading publishes the server snapshot before evaluator maintenance", async () => {
  const [api, store] = await Promise.all([
    source("APIClient.swift"),
    source("EventStore.swift"),
  ]);
  assert.match(api, /private static let mainRequestTimeout: TimeInterval = 15/u);
  assert.match(api, /request\.timeoutInterval = Self\.mainRequestTimeout/u);
  assert.match(
    store,
    /var syncedEvents = try await apiClient\.fetchEvents\(\)[\s\S]*?publishRemoteSnapshot\(syncedEvents, context: context\)[\s\S]*?relayDueHostedEvaluations/u,
  );
});

test("auth completions are generation guarded and logout cannot overlap profile work", async () => {
  const [auth, home] = await Promise.all([
    source("AuthStore.swift"),
    source("HomeView.swift"),
  ]);
  assert.match(auth, /private var sessionGeneration: UInt = 0/u);
  assert.match(auth, /guard operationIsCurrent\(generation\)/u);
  assert.match(auth, /private func synchronizeCredentialState\(\) async throws/u);
  assert.match(
    home,
    /profileAccountActions[\s\S]*?experience\.logoutButton[\s\S]*?\.disabled\(authStore\.isBusy\)/u,
  );
  assert.doesNotMatch(
    home,
    /await authStore\.signOut\(\)\s*eventStore\.clearSession\(\)/u,
  );
});

test("verification-code throttling uses a live retry countdown", async () => {
  const [api, store, auth] = await Promise.all([
    source("APIClient.swift"),
    source("AuthStore.swift"),
    source("AuthenticationView.swift"),
  ]);
  assert.match(api, /case codeRequestThrottled\(message: String, retryAt: Date\)/u);
  assert.doesNotMatch(api, /Try again at/u);
  assert.match(store, /private\(set\) var codeRequestRetryAt: Date\?/u);
  assert.match(store, /catch let APIError\.codeRequestThrottled\(_, retryAt\)/u);
  assert.match(auth, /Try again in \\\(Self\.retryCountdown\(codeRequestRetrySeconds\)\)/u);
  assert.match(auth, /codeRequestRetrySeconds > 0/u);
});

test("profile editing stays private and saves only after a real change", async () => {
  const home = await source("HomeView.swift");
  assert.match(home, /Text\(experience\.syncNote\)[\s\S]*?ProfileField/u);
  assert.match(home, /\.safeAreaInset\(edge: \.bottom[\s\S]*?saveFooter/u);
  assert.match(home, /\.disabled\(authStore\.isBusy \|\| !profileHasChanges\)/u);
  assert.match(home, /private var profileAccountActions: some View/u);
  assert.match(home, /private var profileHasChanges: Bool/u);
});

test("contact search provides an in-field clear action without dropping focus", async () => {
  const attendeeFlow = await source("AttendeeFlowView.swift");
  assert.match(
    attendeeFlow,
    /if !searchText\.isEmpty[\s\S]*searchText = ""[\s\S]*isSearchFocused = true/u,
  );
  assert.match(attendeeFlow, /accessibilityIdentifier\("clear-contact-search"\)/u);
  assert.match(
    attendeeFlow,
    /TextField\("Search contacts"[\s\S]*?\.submitLabel\(\.return\)[\s\S]*?\.onSubmit \{\s*isSearchFocused = false/u,
  );
});

test("contact groups use static list labels instead of floating section headers", async () => {
  const attendeeFlow = await source("AttendeeFlowView.swift");
  assert.match(attendeeFlow, /contactSectionLabel\([\s\S]*?"Selected"/u);
  assert.match(attendeeFlow, /contactSectionLabel\([\s\S]*?"Contacts"/u);
  assert.match(attendeeFlow, /private func contactSectionLabel\(/u);
  assert.doesNotMatch(
    attendeeFlow,
    /Section \{\s*candidateRows\(visibleSelectedCandidates\)[\s\S]*?\} header:/u,
  );
  assert.doesNotMatch(
    attendeeFlow,
    /Section \{\s*candidateRows\(visibleUnselectedCandidates\)[\s\S]*?\} header:/u,
  );
  assert.match(
    attendeeFlow,
    /accessibilityIdentifier\("contact-candidate-\\\(candidate\.id\)"\)[\s\S]*?\.listRowBackground\(HerdTheme\.canvas\)/u,
  );
});

test("home event cards stack status, title, and date without location", async () => {
  const home = await source("HomeView.swift");
  assert.match(
    home,
    /Text\(statusLabel\)[\s\S]*Text\(event\.title\.isEmpty[\s\S]*Text\(formattedCardDate\)/u,
  );
  assert.doesNotMatch(
    home,
    /Label\(event\.locationName, systemImage: "mappin\.and\.ellipse"\)/u,
  );
});

test("response progress unlocks only after the current guest replies", async () => {
  const [home, models] = await Promise.all([
    source("HomeView.swift"),
    source("Models.swift"),
  ]);
  const attendeeView = home.match(
    /private struct InvitationAttendees[\s\S]*?private struct InvitationConditionPicker/u,
  )?.[0] ?? "";
  const attendeeStatus = attendeeView.match(
    /if let status \{[\s\S]*?\} else if let lockedStatusGuestID/u,
  )?.[0] ?? "";
  assert.match(models, /var hasResponded: Bool\?/u);
  assert.match(models, /var respondedParticipantCount: Int[\s\S]*\.count \+ 1/u);
  assert.match(home, /role == \.host \|\| hasResponse/u);
  assert.match(home, /respondedParticipantCount/u);
  assert.match(home, /invitee\.hasResponded == true \? "Responded" : "Not responded"/u);
  assert.match(home, /Image\(systemName: "eye\.slash\.fill"\)/u);
  assert.match(home, /experience\.responseProgressLocked/u);
  assert.match(attendeeView, /if !event\.canViewResponseProgress/u);
  assert.doesNotMatch(attendeeView, /responseProgressVisible|responseProgressDisclosure/u);
  assert.match(home, /lineLimit\(1\)[\s\S]*minimumScaleFactor\(0\.86\)/u);
  assert.match(home, /accessibilityIdentifier\("locked-guest-status-tooltip"\)/u);
  assert.match(home, /responseProgressRefreshInterval = Duration\.seconds\(2\)/u);
  assert.match(home, /private func submitResponse[\s\S]*guard !isSubmitting/u);
  assert.doesNotMatch(attendeeView, /lockedStatusNoticeID|participantLabel/u);
  assert.match(attendeeView, /lineLimit\(2\)[\s\S]*frame\(maxWidth: 152, alignment: \.trailing\)/u);
  assert.doesNotMatch(attendeeStatus, /fixedSize\(horizontal: true, vertical: false\)/u);
  assert.match(home, /history\.totalConfirmedEvents > 0[\s\S]*"No response"/u);
  assert.doesNotMatch(home, /Text\("Guest status"\)[\s\S]*?\.blur\(radius:/u);
  assert.match(
    home,
    /private struct InvitationDetailView[\s\S]*?\.task\(id: eventID\)[\s\S]*?await store\.refresh\(\)[\s\S]*?responseProgressRefreshInterval/u,
  );
  assert.match(
    home,
    /private struct InvitationDetailView[\s\S]*?accessibilityIdentifier\("invitation-detail-scroll"\)[\s\S]*?\.refreshable \{\s*await store\.refresh\(\)/u,
  );
  assert.match(
    home,
    /private struct InvitationAttendees[\s\S]*?\.refreshable \{\s*await store\.refresh\(\)/u,
  );
});

test("selected required-attendee chips abbreviate names without changing stored names", async () => {
  const [editor, home, models] = await Promise.all([
    source("EventEditorView.swift"),
    source("HomeView.swift"),
    source("Models.swift"),
  ]);
  assert.match(models, /enum RequiredAttendeeName[\s\S]*func shortened/u);
  assert.match(editor, /Text\(RequiredAttendeeName\.shortened\(name\(for: memberID\)\)\)/u);
  assert.match(home, /Text\(RequiredAttendeeName\.shortened\(event\.name\(for: memberID\)\)\)/u);
  assert.ok(
    editor.includes('.accessibilityLabel("Remove \\(name(for: memberID)) from required attendees")'),
  );
});

test("account deletion is available in-app and erases server and device state", async () => {
  const [auth, client, home, eventStore, keyStore] = await Promise.all([
    source("AuthStore.swift"),
    source("APIClient.swift"),
    source("HomeView.swift"),
    source("EventStore.swift"),
    source("AccountKeyStore.swift"),
  ]);
  assert.match(client, /func deleteCurrentAccount\(\) async throws/u);
  assert.match(client, /Body\(confirmation: "DELETE"\)/u);
  assert.match(home, /experience\.deleteAccountButton/u);
  assert.match(home, /experience\.accountDeletion\.verificationTitle/u);
  assert.match(auth, /func deleteAccount\(\) async -> AccountDeletionOutcome/u);
  assert.match(auth, /deleteAllRootSecretMaterial\(userID: deletingUserID\)/u);
  assert.match(eventStore, /func eraseLocalAccountData\(userID: String\)/u);
  assert.match(keyStore, /func deleteAllRootSecretMaterial\(userID: String\) throws/u);
});

test("hosted event details expose deletion only behind confirmation", async () => {
  const [home, store, client] = await Promise.all([
    source("HomeView.swift"),
    source("EventStore.swift"),
    source("APIClient.swift"),
  ]);
  assert.match(home, /if event\?\.isHosted == true[\s\S]*?Image\(systemName: "ellipsis"\)/u);
  assert.match(home, /eventActions\.deleteButton[\s\S]*?role: \.destructive/u);
  assert.match(home, /eventActions\.deletionTitle[\s\S]*?eventActions\.deletionBody/u);
  assert.match(home, /if await store\.delete\(event\) \{\s*dismiss\(\)/u);
  assert.match(store, /guard event\.isHosted else \{[\s\S]*?Only the host can delete this event/u);
  assert.match(client, /path: "\/api\/events\/\\\(id\.uuidString\.lowercased\(\)\)"[\s\S]*?method: "DELETE"/u);
});

test("confirmed hosts can reopen event details while attendance rules stay locked", async () => {
  const [home, editor, backend] = await Promise.all([
    source("HomeView.swift"),
    source("EventEditorView.swift"),
    readFile(new URL("../invitee-web/lib/backend/events.ts", import.meta.url), "utf8"),
  ]);
  assert.match(home, /eventActions\.editButton[\s\S]*?edit-hosted-event[\s\S]*?EventEditorView\(event: event\)/u);
  assert.match(editor, /event-rsvp-deadline[\s\S]*?showConfirmedEditNotice/u);
  assert.match(editor, /event-attendance-settings-locked/u);
  assert.match(editor, /event-required-attendees-locked/u);
  assert.match(editor, /locksRSVPDeadline: isConfirmed/u);
  assert.match(editor, /Attendance settings and the RSVP deadline can’t be changed after confirmation\./u);
  assert.doesNotMatch(editor, /\.disabled\(draft\.invitationsSent\)/u);
  assert.match(backend, /confirmed_event_attendance_locked/u);
  assert.match(backend, /if \(!isConfirmed\) \{[\s\S]*?DELETE FROM event_resolutions/u);
});

test("private replies are account-wide and never expose device-transfer ownership", async () => {
  const [home, store, client] = await Promise.all([
    source("HomeView.swift"),
    source("EventStore.swift"),
    source("APIClient.swift"),
  ]);
  assert.match(client, /func fetchSimplifiedBallot\(inviteToken: String\)/u);
  assert.match(client, /func submitSimplifiedBallot\([\s\S]*?inviteToken: String/u);
  assert.match(
    store,
    /submitSimplifiedBallot\([\s\S]*?events\[index\]\.hasBallot = true[\s\S]*?hasResponded = true/u,
  );
  assert.doesNotMatch(home, /deviceSwitch|switchPrivateRepliesToThisDevice/u);
  assert.doesNotMatch(store, /deviceSwitch|switchPrivateRepliesToThisDevice/u);
});

test("invitation details keep private-reply failures visible and retryable", async () => {
  const home = await source("HomeView.swift");
  assert.match(
    home,
    /if let errorMessage = store\.errorMessage \{[\s\S]*?SyncMessageCard\([\s\S]*?accessibilityIdentifier\("invitation-detail-error"\)/u,
  );
});

test("saved-reply opening emits only bounded local diagnostics", async () => {
  const [client, store] = await Promise.all([
    source("APIClient.swift"),
    source("EventStore.swift"),
  ]);
  assert.match(client, /func reportLocalClientTelemetry\(/u);
  assert.match(client, /guard baseURL\.host == "app\.herdprivacy\.com" else \{ return \}/u);
  assert.match(client, /"signal": "client_decode"/u);
  assert.match(client, /"correlationId": UUID\(\)\.uuidString\.lowercased\(\)/u);
  const reporterStart = client.indexOf("func reportLocalClientTelemetry(");
  const reporterEnd = client.indexOf("private func requireSuccess(", reporterStart);
  assert.ok(reporterStart >= 0 && reporterEnd > reporterStart);
  const localReporter = client.slice(reporterStart, reporterEnd);
  assert.doesNotMatch(localReporter, /eventId|inviteToken|phoneNumber|responseEnvelope/u);
  assert.match(store, /operation: "reply\.saved\.open"/u);
  assert.match(store, /saved_reply_invalid_envelope/u);
  assert.match(store, /saved_reply_invalid_policy/u);
});

test("host OR choices exclude people already used in any required row", async () => {
  const editor = await source("EventEditorView.swift");
  assert.match(
    editor,
    /case \.alternative:[\s\S]*?!usedRequiredInviteeIDs\.contains\(\$0\.id\)/u,
  );
});

test("event editor uses attendee language for required-attendee controls", async () => {
  const source = await readFile(new URL("../HerdHost/EventEditorView.swift", import.meta.url), "utf8");

  assert.match(source, /EditorGroup\(title: "Required attendees"/u);
  assert.match(source, /Text\("Add required attendee"\)/u);
  assert.doesNotMatch(source, /Required attendance|Add required attendance/u);
});

test("event editor distinguishes unsaved abandonment from saved-draft deletion", async () => {
  const editor = await source("EventEditorView.swift");
  assert.match(
    editor,
    /if draft\.invitationsSent[\s\S]*else if isExistingEvent \{\s*showsDeleteDraftConfirmation = true\s*\} else \{\s*showsAbandonDraftConfirmation = true/u,
  );
  assert.match(editor, /\.alert\("Abandon this draft\?"[\s\S]*confirm-abandon-draft/u);
  assert.match(editor, /\.alert\("Delete this draft\?"[\s\S]*confirm-delete-draft/u);
  assert.match(editor, /let didDelete = await store\.delete\(draft\)/u);
});

test("blank event drafts always save with the Untitled event fallback", async () => {
  const editor = await source("EventEditorView.swift");
  assert.doesNotMatch(editor, /Text\("Still needed"\)|Add an event title/u);
  assert.match(
    editor,
    /primaryActionTitle == "Send" && !draft\.isValid/u,
  );
  assert.match(
    editor,
    /if draft\.title\.isEmpty \{\s*draft\.title = "Untitled event"\s*\}/u,
  );
  assert.match(editor, /guard !markInvitationsSent \|\| draft\.isValid else/u);
});

test("iOS relays participant evaluations without exposing app credentials", async () => {
  const [client, store] = await Promise.all([
    source("APIClient.swift"),
    source("EventStore.swift"),
  ]);
  assert.match(client, /func relayEvaluation\(eventID: UUID\) async throws -> Bool/u);
  assert.match(client, /\/api\/events\/\\\(expectedEventID\)\/evaluation/u);
  assert.match(client, /credentials|httpShouldHandleCookies = false/u);
  assert.match(client, /NoRedirectSessionDelegate/u);
  assert.match(client, /endpoint\.path == "\/api\/v1\/relay\/"/u);
  assert.match(client, /endpointHost == pinHost/u);
  assert.match(client, /evaluationResponse/u);
  assert.match(client, /session\.bytes\(for: request\)/u);
  assert.match(client, /bytes\.task\.cancel\(\)/u);
  assert.match(client, /guard data\.count < limit/u);
  assert.doesNotMatch(
    client,
    /evaluatorRequest\.setValue\([^\n]+Authorization/u,
  );
  assert.match(store, /relayDueHostedEvaluations/u);
  assert.match(store, /event\.resolution\?\.status == \.pending/u);
  assert.match(store, /event\.resolution\?\.status == \.confirmed/u);
  assert.match(store, /event\.resolution\?\.attendanceRevealed != true/u);
  assert.match(store, /catch \{[\s\S]*?leave the resolution pending/u);
});

test("iOS invitation links use only the exact HTTPS Herd invitation route", async () => {
  const [app, runtime, auth, client, home, entitlements, info] = await Promise.all([
    source("HerdHostApp.swift"),
    source("HerdRuntime.swift"),
    source("AuthenticationView.swift"),
    source("APIClient.swift"),
    source("HomeView.swift"),
    source("HerdHost.entitlements"),
    source("Info.plist"),
  ]);
  assert.match(app, /\.onContinueUserActivity\(NSUserActivityTypeBrowsingWeb\)/u);
  assert.match(app, /HerdRuntime\.invitationToken\(from: activity\)/u);
  assert.match(runtime, /url\.scheme\?\.lowercased\(\) == "https"/u);
  assert.match(runtime, /host == associatedDomain/u);
  assert.match(runtime, /url\.query == nil[\s\S]*url\.fragment == nil/u);
  assert.match(runtime, /components\.count == 2, components\[0\] == "invite"/u);
  assert.match(runtime, /InvitationToken\.normalize\(components\[1\]\)/u);
  assert.doesNotMatch(auth, /InvitationCoordinator|pendingToken|inviteToken/u);
  assert.match(
    auth,
    /automaticallySubmittedCode != digits[\s\S]*?authStore\.verifyCode\(digits\)/u,
  );
  assert.match(client, /func requestCode\(phoneNumber: String\)/u);
  assert.doesNotMatch(client, /func requestCode\(\s*phoneNumber: String,\s*inviteToken/u);
  assert.doesNotMatch(home, /Switch account|invitationGeneration/u);
  assert.match(entitlements, /com\.apple\.developer\.associated-domains/u);
  assert.match(entitlements, /applinks:\$\(HERD_ASSOCIATED_DOMAIN\)/u);
  assert.doesNotMatch(info, /CFBundleURLSchemes|<string>herd<\/string>/u);
});

test("pending invitations keep the normal sign-in screen and native iOS design", async () => {
  const [auth, app, attendeeFlow, info] = await Promise.all([
    source("AuthenticationView.swift"),
    source("HerdHostApp.swift"),
    source("AttendeeFlowView.swift"),
    source("Info.plist"),
  ]);
  assert.doesNotMatch(auth, /Your invitation is ready|pending-invitation-notice/u);
  assert.match(app, /ZStack \{\s*HerdTheme\.canvas\s*\.ignoresSafeArea\(\)/u);
  assert.doesNotMatch(attendeeFlow, /Color\.black/u);
  assert.match(attendeeFlow, /toolbarBackground\(HerdTheme\.canvas/u);
  assert.doesNotMatch(
    info,
    /UIDesignRequiresCompatibility/u,
    "Herd must not opt the whole app out of the current iOS design.",
  );
});

test("leaving an invitation always relocks its encrypted reply", async () => {
  const [home, store] = await Promise.all([
    source("HomeView.swift"),
    source("EventStore.swift"),
  ]);
  assert.match(
    store,
    /func lockPrivateResponse\(for eventID: UUID\)[\s\S]*unlockedResponses\[eventID\] = nil[\s\S]*unlockedDrafts\[eventID\] = nil/u,
  );
  assert.match(home, /onViewInvitation:[\s\S]*showsSuccess = false\s*lockPrivateReply\(\)/u);
  assert.match(home, /onHome:[\s\S]*showsSuccess = false\s*lockPrivateReply\(\)/u);
  assert.match(
    home,
    /\.onDisappear \{[\s\S]*?confirmedReplyNoticeID = nil[\s\S]*?guard !showsSuccess else \{ return \}[\s\S]*?lockPrivateReply\(\)/u,
  );
});

test("location pickers attach autocomplete results and support optional units", async () => {
  const [locationSearch, home] = await Promise.all([
    source("LocationSearchView.swift"),
    source("HomeView.swift"),
  ]);
  assert.match(locationSearch, /LocationAutocompleteField/u);
  assert.match(locationSearch, /if isFocused\.wrappedValue && showsSuggestions \{[\s\S]*Divider\(\)[\s\S]*suggestions/u);
  assert.match(locationSearch, /if isFocused\.wrappedValue && !query\.isEmpty \{[\s\S]*xmark\.circle\.fill/u);
  assert.match(locationSearch, /clear-location-search/u);
  assert.match(locationSearch, /clear-profile-address-search/u);
  assert.match(locationSearch, /location-unit-number/u);
  assert.match(locationSearch, /profile-unit-number/u);
  assert.match(locationSearch, /Text\("Unit number"\)/u);
  assert.match(locationSearch, /LocationUnitAddress\.combine/u);
  assert.equal((locationSearch.match(/Button\("Done"\)/gu) ?? []).length, 2);
  assert.doesNotMatch(locationSearch, /Button\("Save"\)/u);
  assert.doesNotMatch(locationSearch, /Image\(systemName: "chevron\.right"\)/u);
  assert.match(
    locationSearch,
    /Text\(title\)[\s\S]*\.lineLimit\(1\)[\s\S]*\.truncationMode\(\.tail\)/u,
  );
  assert.match(home, /ProfileAddressPicker[\s\S]*\.lineLimit\(1\)[\s\S]*\.truncationMode\(\.tail\)/u);
  assert.match(home, /UIPasteboard\.general\.string = copyText/u);
  assert.match(home, /Text\(addressCopiedNoticeID != nil[\s\S]*"Address copied to clipboard"/u);
  assert.match(home, /accessibilityIdentifier\(addressCopiedNoticeID != nil[\s\S]*"address-copied-toast"/u);
  assert.match(locationSearch, /enum EventLocationPresentation[\s\S]*foldedAddress == foldedName/u);
  assert.match(
    locationSearch,
    /selectedName\.isEmpty && selectedAddress\.isEmpty && trimmedUnit\.isEmpty[\s\S]*locationName = manualQuery[\s\S]*locationAddress = ""/u,
  );
  assert.match(locationSearch, /locationName = normalizedSummary == savedAddress \? "" : savedName/u);
});

test("every iOS build requires hardware evaluator attestation", async () => {
  const [attestation, store, project, info] = await Promise.all([
    source("EvaluatorAttestation.swift"),
    source("EventStore.swift"),
    readFile(new URL("../HerdHost.xcodeproj/project.pbxproj", import.meta.url), "utf8"),
    source("Info.plist"),
  ]);
  assert.doesNotMatch(attestation, /SoftwareQA|HERD_ALLOW_SOFTWARE/u);
  assert.match(store, /fetchEvaluatorAttestation/u);
  assert.doesNotMatch(store, /SoftwareQA|HERD_ALLOW_SOFTWARE/u);
  assert.doesNotMatch(info, /HERD_ALLOW_SOFTWARE_QA_EVALUATOR/u);
  assert.doesNotMatch(project, /herd-invitee-preview|HERD_ALLOW_SOFTWARE_QA_EVALUATOR/u);
});

test("the App Clip is embedded without making the archive generic", async () => {
  const project = await readFile(
    new URL("../HerdHost.xcodeproj/project.pbxproj", import.meta.url),
    "utf8",
  );
  const clipConfigurations = project.match(/PRODUCT_NAME = HerdClip;\s+SKIP_INSTALL = YES;/gu) ?? [];
  assert.equal(clipConfigurations.length, 2);
  assert.doesNotMatch(project, /PRODUCT_NAME = HerdClip;\s+SKIP_INSTALL = NO;/u);
});
