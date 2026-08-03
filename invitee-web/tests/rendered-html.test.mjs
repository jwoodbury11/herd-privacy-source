import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const projectRoot = new URL("../", import.meta.url);

async function render(pathname = "/", bindings = {}) {
  const workerUrl = new URL("../dist/server/index.js", import.meta.url);
  workerUrl.searchParams.set("test", `${process.pid}-${Date.now()}-${pathname}`);
  const { default: worker } = await import(workerUrl.href);

  return worker.fetch(
    new Request(`https://app.herd.test${pathname}`, {
      headers: { accept: "text/html", host: "app.herd.test" },
    }),
    {
      ASSETS: { fetch: async () => new Response("Not found", { status: 404 }) },
      HERD_DEPLOYMENT_PROFILE: "test",
      ...bindings,
    },
    { waitUntil() {}, passThroughOnException() {} },
  );
}

test("publishes the non-redirecting iOS universal-link association", async () => {
  const response = await render("/.well-known/apple-app-site-association");
  assert.equal(response.status, 200);
  assert.match(response.headers.get("content-type") ?? "", /^application\/json\b/i);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
  const association = await response.json();
  assert.deepEqual(association, {
    applinks: {
      apps: [],
      details: [
        {
          appID: "R4UPN8ZDV8.com.jameswoodbury.HerdPrototype",
          paths: ["/invite/*"],
        },
      ],
    },
  });
});

test("production universal links fail closed without the signed app identifier", async () => {
  const response = await render("/.well-known/apple-app-site-association", {
    HERD_DEPLOYMENT_PROFILE: "production",
    HERD_IOS_APP_ID: "",
  });
  assert.equal(response.status, 500);
  assert.equal((await response.json()).error?.code, "server_misconfigured");
});

test("publishes the messaging terms, privacy policy, and carrier proof", async () => {
  const responses = await Promise.all([
    render("/terms"),
    render("/privacy"),
    render("/sms-invite-consent"),
  ]);
  for (const response of responses) {
    assert.equal(response.status, 200);
    assert.match(response.headers.get("content-type") ?? "", /^text\/html\b/i);
  }
  const [terms, privacy, proof] = await Promise.all(responses.map((response) => response.text()));
  assert.match(terms, /one event invitation from Herd at the host’s request/i);
  assert.match(terms, /Requested phone verification codes/i);
  assert.match(terms, /operated by James Woodbury as a sole proprietor/i);
  assert.match(terms, /Reply <strong>STOP<\/strong> to opt out/i);
  assert.match(privacy, /text messaging originator opt-in data and consent/i);
  assert.match(privacy, /permanently delete your account from <strong>Your profile<\/strong>/i);
  assert.match(privacy, /encrypted reply envelopes are removed 90 days after a final event result/i);
  assert.match(privacy, /ordinary application database does not store readable reply, minimum, or required-person fields/i);
  assert.match(privacy, /signed rules retain only an opaque event member ID/i);
  assert.match(privacy, /configured messaging provider handles STOP, START, and HELP replies/i);
  assert.doesNotMatch(privacy, /Herd (?:directly )?(?:processes|handles) STOP/iu);
  assert.match(proof, /Send one-time invitations\?/i);
  assert.match(proof, /Example of prior recipient permission/i);
  assert.match(proof, /No automatic reminders will follow/i);
  assert.match(proof, /Production invitation format/i);
  assert.match(proof, /configured messaging provider[\s\S]*handles STOP, START, and HELP replies/i);
  assert.doesNotMatch(proof, /Herd (?:directly )?(?:processes|handles) STOP/iu);
  assert.doesNotMatch(proof, /Sample production message/i);
});

test("all in-app legal routes consume the repository canonical content module", async () => {
  const sources = await Promise.all([
    "terms/page.tsx",
    "privacy/page.tsx",
    "sms-invite-consent/page.tsx",
    "legal-page.tsx",
  ].map((pathname) => readFile(new URL(`../app/${pathname}`, import.meta.url), "utf8")));
  for (const source of sources) {
    assert.match(source, /legal-content/u);
  }
});

test("root is the normal Herd phone sign-in", async () => {
  const response = await render("/");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /<title>Herd — private event replies<\/title>/i);
  assert.match(html, /Make plans happen\./);
  assert.match(html, /Sign in with your phone number\./);
  assert.doesNotMatch(html, /to see the same Herd events on web and iPhone/i);
  assert.match(html, /aria-label="Phone number"/);
  assert.match(html, /<span class="phone-entry-label">Phone number<\/span>/);
  assert.match(html, /placeholder="\+1 \(555\) 555-5555"/);
  assert.match(html, /Text me a code/);
  assert.match(html, /Release status/);
  assert.doesNotMatch(html, /Poker night|Prototype preview|functional engineering prototype|test sandbox|testing code|sample data/i);
  assert.match(html, /https:\/\/app\.herd\.test\/og\.png/);
  assert.match(html, /href="\/site\.webmanifest"/);
});

test("the web and iPhone shared screens consume one experience contract", async () => {
  const [experienceSource, page, css, privateResponseCrypto, swiftHome, swiftAuth, swiftAuthStore, project] = await Promise.all([
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../lib/privacy/private-response-crypto.ts", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/AuthenticationView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/AuthStore.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost.xcodeproj/project.pbxproj", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.equal(experience.authentication.welcome.title, "Make plans happen.");
  assert.equal(experience.authentication.welcome.requestCodeButton, "Text me a code");
  assert.match(page, /AUTH_EXPERIENCE\.welcome\.title/);
  assert.match(page, /AUTH_EXPERIENCE\.verification\.title/);
  assert.match(swiftAuth, /HerdExperience\.shared\.authentication/);
  assert.match(swiftAuth, /experience\.welcome\.title/);
  assert.match(swiftAuth, /experience\.verification\.title/);
  assert.match(swiftAuth, /maskedPhoneNumber/);
  assert.equal(experience.authentication.layout.verificationCodeWidth, 54);
  assert.equal(experience.authentication.layout.verificationCodeHeight, 62);
  assert.equal(experience.authentication.layout.verificationCodeAlignment, "start");
  assert.match(css, /--auth-verification-code-width/);
  assert.match(
    css,
    /\.otp-row\s*\{[^}]*justify-content:\s*var\(--auth-verification-code-alignment, start\)/s,
  );
  assert.match(swiftAuth, /experience\.layout\.verificationCodeWidth/);
  assert.match(swiftAuth, /experience\.layout\.verificationCodeAlignment/);
  assert.match(swiftAuthStore, /#"\^\[1-9\]\$"#/);
  assert.match(
    privateResponseCrypto,
    /process\.env\.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID\s*\|\|\s*"herd-evaluator-live-v1"/,
  );
  assert.match(
    privateResponseCrypto,
    /process\.env\.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY\s*\|\|/,
  );

  assert.equal(experience.home.title, "Herd events");
  assert.equal(experience.home.createEventTitle, "Host an event");
  assert.equal(experience.home.profile.useGenericIconWithoutName, true);
  assert.equal(experience.home.layout.headerToFirstCardGap, 88);
  assert.doesNotMatch(page, /Welcome back/i);
  assert.match(page, /HOME_EXPERIENCE\.title/);
  assert.match(page, /events\.map\(\(event\)/);
  assert.doesNotMatch(page, /events\.filter\(\(event\) => event\.role/);
  assert.match(page, /sortEventsForHome/);
  assert.match(page, /upsertHomeEvent/);
  assert.match(page, /HOME_EXPERIENCE\.profile\.useGenericIconWithoutName/);
  assert.match(page, /<UserRound aria-hidden="true"/);
  assert.doesNotMatch(page, /personInitials\(profileName \|\| "Host"\)/);
  assert.match(swiftHome, /HerdExperience\.shared\.home/);
  assert.match(swiftHome, /experience\.profile\.useGenericIconWithoutName/);
  assert.match(swiftHome, /Image\(systemName: "person"\)/);
  assert.match(project, /HerdExperience\.json in Resources/);
  assert.match(css, /--home-horizontal-padding/);
  assert.match(css, /--home-header-to-first-card-gap/);
  assert.match(css, /--home-create-card-min-height/);
  assert.match(swiftHome, /headerToFirstCardGap - experience\.layout\.verticalGap/);

  for (const section of ["profile", "invitation", "attendees", "reply", "privacy", "success"]) {
    assert.ok(experience[section], `missing shared ${section} experience`);
  }
  assert.match(page, /PROFILE_EXPERIENCE\.syncNote/);
  assert.match(page, /REPLY_EXPERIENCE\.submitButton/);
  assert.match(page, /PRIVACY_EXPERIENCE\.sections\.map/);
  assert.match(page, /PROFILE_EXPERIENCE\.deleteAccountButton/);
  assert.match(page, /confirmation: "DELETE"/);
  assert.match(page, /forgetAllAccountRootSecrets\(deletedUserId\)/);
  assert.match(experience.profile.accountDeletion.body, /permanently deletes your profile, hosted events, sessions, account keys, and encrypted replies/i);
  assert.match(page, /SUCCESS_EXPERIENCE\.visibilityBody/);
  assert.doesNotMatch(page, /activeEvent\.hasResponse \|\| reply/);
  assert.match(swiftHome, /HerdExperience\.shared\.profile/);
  assert.match(swiftHome, /HerdExperience\.shared\.reply/);
  assert.match(swiftHome, /HerdExperience\.shared\.privacy/);
  assert.match(swiftHome, /HerdExperience\.shared\.success/);
  assert.match(swiftHome, /case let \.create\(event\):/);
  assert.match(
    swiftHome,
    /case let \.detail\(eventID, invitationGeneration\):/,
  );
  assert.match(swiftHome, /submitResponse\(for: event\)/);
});

test("poker invitation link has a distinct API-backed landing screen", async () => {
  const response = await render("/invite/poker-party");
  assert.equal(response.status, 200);
  const html = await response.text();
  assert.match(html, /You’re invited/);
  assert.match(html, /Loading your invitation/);
  assert.match(html, /retrieving the invitation details/i);
  assert.match(html, /Text me a code/);
  assert.match(html, /Release status/);
  assert.doesNotMatch(html, /test sandbox|testing code|sample data/i);
});

test("web app uses authenticated server APIs instead of browser-only product state", async () => {
  const [page, schema, auth, eventsRoute, viteConfig, envExample, experienceSource] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../db/schema.ts", import.meta.url), "utf8"),
    readFile(new URL("../lib/backend/auth.ts", import.meta.url), "utf8"),
    readFile(new URL("../app/api/events/route.ts", import.meta.url), "utf8"),
    readFile(new URL("../vite.config.ts", import.meta.url), "utf8"),
    readFile(new URL("../.env.example", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  for (const endpoint of [
    "/api/auth/request-code",
    "/api/auth/verify-code",
    "/api/auth/session",
    "/api/me",
    "/api/events",
    "/api/invites/",
  ]) {
    assert.match(page, new RegExp(endpoint.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  }
  assert.doesNotMatch(page, /localStorage|HOST_EVENTS_STORAGE_KEY/);
  assert.doesNotMatch(page, /if \(nextOtp\.length === 4\) setScreen\("home"\)/);
  assert.match(page, /const OTP_LENGTH = 4/);
  assert.match(page, /AUTH_EXPERIENCE\.verification\.codeAccessibilityLabel/);
  assert.match(page, /credentials: "include"/);
  assert.match(page, /invitationPreview/);
  assert.match(page, /inviteAccountMismatch/);
  assert.match(page, /invite_for_different_account/);
  assert.match(page, /Switch account/);
  assert.match(page, /setScreen\(openedInvitation \? "event" : "home"\)/);
  assert.match(page, /"user" in body/);
  assert.doesNotMatch(page, /POKER_FIXTURE|URLSearchParams|window\.location\.search|testCode|Testing code:|Shared test sandbox/);
  assert.doesNotMatch(page, /219 Cumberland|20484 Glen Brae|1 Ferry Building|Suggestions/);
  assert.equal(page.match(/AUTH_EXPERIENCE\.releaseStatus\.label/g)?.length, 1);
  assert.match(page, /className="build-status-pill"/);
  assert.match(page, /aria-haspopup="dialog"/);
  assert.match(page, /setReleaseStatusOpen\(true\)/);
  assert.match(page, /AUTH_EXPERIENCE\.releaseStatus\.heading/);
  assert.match(page, /className="release-status-dialog"/);
  assert.match(page, /PRIVACY_EXPERIENCE\.navigationTitle/);
  assert.match(page, /PRIVACY_EXPERIENCE\.builtTitle/);
  assert.match(page, /PRIVACY_EXPERIENCE\.sections\.map/);
  assert.match(experience.privacy.navigationTitle, /Prove it to me/);
  assert.match(experience.privacy.builtTitle, /private-response system is complete/i);
  assert.match(experience.privacy.sections[1].paragraphs[0], /account-linked, not anonymous to Herd/i);
  assert.match(experience.privacy.sections[3].paragraphs[0], /A delivered client can change its code and this explanation together/i);
  assert.match(experience.privacy.statusTitle, /Technically complete/);
  assert.match(experience.privacy.pendingTitle, /External proof is not active yet/);
  assert.match(experience.privacy.pendingBody, /approved release.*signed manifest.*hardware-backed evaluator/i);
  assert.match(experience.privacy.sections[2].paragraphs[1], /complete separate-key, hardware-attested Confidential Space deployment/i);
  assert.match(experience.privacy.sections[2].paragraphs[1], /not called production until a published release proves/i);
  assert.match(experience.privacy.sections[0].paragraphs[1], /Values displayed by the app are not independent proof/i);
  assert.doesNotMatch(JSON.stringify(experience.privacy), /evaluator .* not deployed yet/i);
  assert.doesNotMatch(page, /anonymous submission|impossible to determine|this website proves|independently verified today/i);

  for (const table of [
    "users",
    "sessions",
    "challenges",
    "events",
    "invitees",
    "groups",
    "group_members",
    "account_key_epochs",
    "event_policies",
    "response_envelopes",
    "event_resolutions",
    "invitation_deliveries",
  ]) {
    assert.match(schema, new RegExp(`"${table}"`));
  }
  assert.doesNotMatch(schema, /sqliteTable\(\s*"rsvps"/);
  assert.match(page, /sealPrivateResponse/);
  assert.match(page, /account\/key-epoch\/initialize/);
  assert.match(page, /account\/key-epoch\/reset/);
  assert.match(auth, /maxAttempts|expiresAt|resendAt/);
  assert.match(auth, /SESSION_COOKIE_NAME = "herd_session"/);
  assert.match(eventsRoute, /getAuthenticatedSession/);
  assert.match(viteConfig, /const d1 = "DB"/);
  assert.doesNotMatch(viteConfig, /import hostingConfig/);
  assert.match(envExample, /TWILIO_VERIFY_SERVICE_SID/);
  assert.match(envExample, /HERD_TEST_BYPASS_ENABLED/);
  assert.match(envExample, /HERD_EVALUATOR_PUBLIC_KEY/);
  assert.match(envExample, /NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY/);

  await access(new URL("../app/invite/[token]/page.tsx", import.meta.url));
  await access(new URL("../app/api/invites/[token]/route.ts", import.meta.url));
  await access(new URL("../app/api/invites/[token]/rsvp/route.ts", import.meta.url));
  await access(new URL("../app/api/account/key-epoch/initialize/route.ts", import.meta.url));
  await access(new URL("../app/api/account/key-epoch/reset/route.ts", import.meta.url));
  await assert.rejects(access(new URL("../app/chatgpt-auth.ts", import.meta.url)));
  await assert.rejects(access(new URL("app/_sites-preview/SkeletonPreview.tsx", projectRoot)));
});

test("hosting handoff explains native sync without a dead store link", async () => {
  const [page, css, experienceSource] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);
  assert.match(page, /webCreateEventHandoff\.heading/);
  assert.match(page, /webCreateEventHandoff\.body/);
  assert.match(experience.home.webCreateEventHandoff.heading, /Download Herd to host an event/);
  assert.match(experience.home.webCreateEventHandoff.body, /sign in with the same phone number/);
  assert.match(experience.home.webCreateEventHandoff.body, /Events you host there sync back to this home screen/);
  assert.doesNotMatch(page, /apps\.apple\.com|APP_STORE_URL/);
  assert.match(css, /\.host-app-handoff/);
  assert.match(css, /url\("\/herd-icon\.png"\)/);
  assert.doesNotMatch(css, /\.home-empty-note/);
  assert.match(css, /\.build-status-pill/);
  assert.doesNotMatch(css, /\.test-code-notice|\.test-login-notice|\.address-suggestion/);
});
