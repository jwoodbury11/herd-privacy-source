import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = async (name) =>
  readFile(new URL(`../HerdHost/${name}`, import.meta.url), "utf8");

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

test("profile editing stays private and saves only after a real change", async () => {
  const home = await source("HomeView.swift");
  assert.match(home, /Text\(experience\.syncNote\)[\s\S]*?ProfileField/u);
  assert.match(home, /\.safeAreaInset\(edge: \.bottom[\s\S]*?saveFooter/u);
  assert.match(home, /\.disabled\(authStore\.isBusy \|\| !profileHasChanges\)/u);
  assert.match(home, /private var profileAccountActions: some View/u);
  assert.match(home, /private var profileHasChanges: Bool/u);
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

test("switching private replies verifies the phone before replacing the saved response", async () => {
  const [home, store] = await Promise.all([
    source("HomeView.swift"),
    source("EventStore.swift"),
  ]);
  const requestCode = home.indexOf("await authStore.requestCode(phoneNumber: phoneNumber)");
  const verifyCode = home.indexOf("await authStore.verifyCode(deviceSwitchVerificationCode)");
  const switchDevice = home.indexOf("await store.switchPrivateRepliesToThisDevice(for: eventID)");

  assert.ok(requestCode >= 0, "device switching must request fresh phone verification");
  assert.ok(verifyCode > requestCode, "device switching must verify the SMS code");
  assert.ok(switchDevice > verifyCode, "the key switch must happen only after verification");
  assert.match(home, /case \.requestFailed:[\s\S]*?requestDeviceSwitchVerificationCode/u);
  assert.match(home, /case \.verified:[\s\S]*?completeDeviceSwitch/u);
  assert.doesNotMatch(
    home,
    /let saved = await store\.switchPrivateRepliesToThisDevice[\s\S]*?else \{\s*store\.cancelDeviceSwitch\(\)/u,
  );
  assert.match(
    home,
    /else if store\.deviceSwitchEventID != eventID \{[\s\S]*?showsDeviceSwitchVerification = false/u,
    "a completed key switch must leave a later reply failure retryable outside the switch sheet",
  );
  assert.match(
    store,
    /pendingDeviceSwitchDrafts\[event\.id\] = draft\s*deviceSwitchEventID = event\.id/u,
  );
  assert.doesNotMatch(
    store,
    /context\.hasResponse[\s\S]{0,300}pendingDeviceSwitchDrafts/u,
  );
  const replaceKey = store.indexOf("replaceRootSecret(");
  const saveReplacement = store.indexOf("return await performRespond(", replaceKey);
  assert.ok(replaceKey >= 0, "device switching must create replacement key material");
  assert.ok(
    saveReplacement > replaceKey,
    "the replacement reply must be saved only after the device key is switched",
  );
  assert.match(
    store.slice(saveReplacement),
    /preparedAccountKey: PreparedAccountKey\([\s\S]*?rootSecret: accountRootSecret/u,
    "the replacement reply must reuse the freshly authenticated device key",
  );
  assert.match(
    store,
    /pendingSubmission\.draft == draft[\s\S]*?envelope = pendingSubmission\.envelope/u,
    "an ambiguous post-write retry must reuse the exact sealed envelope",
  );
  assert.match(
    store,
    /pendingResponseSubmissions\[event\.id\] = PendingResponseSubmission\([\s\S]*?envelope: envelope/u,
    "the sealed envelope must be retained before submission",
  );
  assert.match(
    store,
    /context\.responseEnvelope\?\.envelope == \$0\.envelope/u,
    "a retry must recognize the exact envelope even after the server exposes its committed revision",
  );
  assert.match(
    home,
    /store\.hasPendingResponseSubmission\(for: event\.id, draft: currentDraft\)/u,
    "a committed-but-uncertified envelope must remain retryable after the event refreshes",
  );
  assert.match(
    store,
    /pendingResponseSubmissions\[event\.id\] = nil\s*return true/u,
    "the retained envelope must clear only after the complete receipt path succeeds",
  );
});

test("invitation details keep private-reply failures visible and retryable", async () => {
  const home = await source("HomeView.swift");
  assert.match(
    home,
    /if let errorMessage = store\.errorMessage \{[\s\S]*?SyncMessageCard\([\s\S]*?accessibilityIdentifier\("invitation-detail-error"\)/u,
  );
});

test("host OR choices exclude people already used in any required row", async () => {
  const editor = await source("EventEditorView.swift");
  assert.match(
    editor,
    /case \.alternative:[\s\S]*?!usedRequiredInviteeIDs\.contains\(\$0\.id\)/u,
  );
});

test("iOS relays due host evaluations without exposing app credentials", async () => {
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
  assert.match(store, /catch \{[\s\S]*?leave the resolution pending/u);
});

test("iOS invitation links survive authentication and open only the exact event", async () => {
  const [links, app, auth, client, store, home, entitlements, info] = await Promise.all([
    source("InvitationLinks.swift"),
    source("HerdHostApp.swift"),
    source("AuthenticationView.swift"),
    source("APIClient.swift"),
    source("EventStore.swift"),
    source("HomeView.swift"),
    source("HerdHost.entitlements"),
    source("Info.plist"),
  ]);
  assert.match(links, /kSecAttrAccessibleWhenUnlockedThisDeviceOnly/u);
  assert.match(links, /InvitationToken\.normalize/u);
  assert.match(links, /components\.percentEncodedQuery == nil/u);
  assert.match(links, /components\.host\?\.lowercased\(\) == trustedHost/u);
  assert.match(app, /\.onOpenURL/u);
  assert.match(app, /NSUserActivityTypeBrowsingWeb/u);
  assert.match(auth, /inviteToken: invitationCoordinator\.pendingToken/u);
  assert.match(
    auth,
    /automaticallySubmittedCode != digits[\s\S]*?authStore\.verifyCode\(digits\)/u,
  );
  assert.match(client, /let inviteToken: String\?/u);
  assert.match(client, /case inviteForDifferentAccount/u);
  assert.match(store, /func openInvitation\(inviteToken: String\)/u);
  assert.match(home, /Switch account/u);
  assert.match(home, /presentation = \.detail\(eventID, invitationGeneration: generation\)/u);
  assert.match(home, /acknowledgePresentation\([\s\S]*?of: eventID,[\s\S]*?generation:/u);
  assert.match(entitlements, /com\.apple\.developer\.associated-domains/u);
  assert.match(entitlements, /applinks:\$\(HERD_ASSOCIATED_DOMAIN\)/u);
  assert.doesNotMatch(info, /CFBundleURLSchemes|<string>herd<\/string>/u);
  assert.doesNotMatch(links, /print\(|NSLog|os_log/u);
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
