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
    /if event\.isHosted && !event\.invitationsSent \{\s*return "Draft"/u,
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
    /Button\(experience\.logoutButton\)[\s\S]*?\.disabled\(authStore\.isBusy\)/u,
  );
  assert.doesNotMatch(
    home,
    /await authStore\.signOut\(\)\s*eventStore\.clearSession\(\)/u,
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

test("software evaluator access is DEBUG-only and exact-pin guarded", async () => {
  const [attestation, store, project, info] = await Promise.all([
    source("EvaluatorAttestation.swift"),
    source("EventStore.swift"),
    readFile(new URL("../HerdHost.xcodeproj/project.pbxproj", import.meta.url), "utf8"),
    source("Info.plist"),
  ]);
  assert.match(attestation, /#if DEBUG[\s\S]*?allowsSoftwareQAEvaluator/u);
  assert.match(attestation, /HERD_DEPLOYMENT_PROFILE[\s\S]*?== "test"/u);
  assert.match(attestation, /policy\.evaluatorMeasurement == measurement/u);
  assert.match(store, /#if DEBUG[\s\S]*?allowsSoftwareQAEvaluator/u);
  assert.match(info, /HERD_ALLOW_SOFTWARE_QA_EVALUATOR/u);
  const releaseBlock = project.match(
    /A00000000000000000000019 \/\* Release \*\/[\s\S]*?name = Release;/u,
  )?.[0];
  assert.ok(releaseBlock);
  assert.doesNotMatch(releaseBlock, /HERD_ALLOW_SOFTWARE_QA_EVALUATOR\s*=\s*true/u);
});
