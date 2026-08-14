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
      HERD_DEPLOYMENT_PROFILE: "production",
      HERD_IOS_APP_ID: "R4UPN8ZDV8.com.jameswoodbury.HerdPrototype",
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

test("publishes the exact bounded release pointer from durable evidence", async (t) => {
  const originalFetch = globalThis.fetch;
  const releaseId = "2026.08.03.2";
  const pointer = JSON.stringify({ schemaVersion: 1, releaseId, manifest: {} });
  globalThis.fetch = async (input, options) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.hostname === "herd-release-evidence.storage.googleapis.com") {
      assert.equal(options?.redirect, "error");
      assert.equal(options?.cache, "no-store");
      assert.equal(url.pathname, "/releases/2026.08.03.2/herd-release.json");
      return new Response(pointer, { headers: { "content-type": "application/json" } });
    }
    return originalFetch(input, options);
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const response = await render("/.well-known/herd-release.json", {
    HERD_DEPLOYMENT_PROFILE: "production",
    HERD_ARTIFACT_RELEASE_ID: releaseId,
    HERD_RELEASE_POINTER_URL:
      "https://storage.googleapis.com/herd-release-evidence/releases/2026.08.03.2/herd-release.json",
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), pointer);
  assert.match(response.headers.get("content-type") ?? "", /^application\/json\b/iu);
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("publishes an exact validated runtime release pointer without an outbound fetch", async (t) => {
  const originalFetch = globalThis.fetch;
  const releaseId = "2026.08.03.2";
  const pointer = JSON.stringify({ schemaVersion: 1, releaseId, manifest: {} });
  globalThis.fetch = async () => {
    throw new Error("runtime pointer must avoid network access");
  };
  t.after(() => {
    globalThis.fetch = originalFetch;
  });
  const response = await render("/.well-known/herd-release.json", {
    HERD_DEPLOYMENT_PROFILE: "production",
    HERD_ARTIFACT_RELEASE_ID: releaseId,
    HERD_RELEASE_POINTER_JSON: pointer,
    HERD_RELEASE_POINTER_URL:
      "https://storage.googleapis.com/herd-release-evidence/releases/2026.08.03.2/herd-release.json",
  });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), pointer);
});

test("publishes the exact client asset manifest for independent monitoring", async () => {
  const [privateManifest, publicManifest] = await Promise.all([
    readFile(new URL("../dist/client/.vite/manifest.json", import.meta.url)),
    readFile(new URL("../dist/client/assets/manifest.json", import.meta.url)),
  ]);
  assert.deepEqual(publicManifest, privateManifest);
});

test("publishes a canonical static entry document for independent monitoring", async () => {
  const [source, deployed] = await Promise.all([
    readFile(new URL("../public/assets/herd-entry.json", import.meta.url)),
    readFile(new URL("../dist/client/assets/herd-entry.json", import.meta.url)),
  ]);

  assert.deepEqual(deployed, source);
  assert.deepEqual(JSON.parse(deployed.toString("utf8")), {
    applicationPath: "/",
    name: "Herd private invitations",
    publicOrigin: "https://app.herdprivacy.com",
    schemaVersion: 1,
  });
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
  assert.match(html, /Unlock more fun events with completely confidential replies\./);
  assert.doesNotMatch(html, /to see the same Herd events on web and iPhone/i);
  assert.match(html, /aria-label="Sign in with phone number"/);
  assert.match(html, /<span class="phone-entry-label">Sign in with phone number<\/span>/);
  assert.match(html, /placeholder="\+1 \(555\) 555-5555"/);
  assert.match(html, /Text me a code/);
  assert.match(html, /Pre-release alpha/);
  assert.doesNotMatch(html, /Poker night|Prototype preview|functional engineering prototype|test sandbox|testing code|sample data/i);
  assert.match(html, /https:\/\/app\.herd\.test\/og\.png/);
  assert.match(html, /href="\/site\.webmanifest"/);
});

test("reply submission metadata updates cannot reset an in-flight answer or error", async () => {
  const page = await readFile(new URL("../app/page.tsx", import.meta.url), "utf8");
  assert.match(page, /const replySubmissionInFlightRef = useRef\(false\)/u);
  assert.match(
    page,
    /!inviteMetadata\?\.canRespond \|\|[\s\S]*replySubmissionInFlightRef\.current[\s\S]*\) return;/u,
  );
  assert.match(
    page,
    /const submittedReply = reply;[\s\S]*replySubmissionInFlightRef\.current = true;[\s\S]*setAuthPending\(true\)/u,
  );
  assert.match(
    page,
    /finally \{[\s\S]*replySubmissionInFlightRef\.current = false;[\s\S]*setAuthPending\(false\)/u,
  );
});

test("participant counts include the host across web and iPhone surfaces", async () => {
  const [page, experienceSource, swiftModels, swiftHome, swiftEditor] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/Models.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/EventEditorView.swift", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.match(page, /function participantCount[\s\S]*event\.invitees\.length \+ 1/u);
  assert.match(page, /String\(participantCount\(event\)\)/u);
  assert.match(page, /String\(participantCount\(activeEvent\)\)/u);
  assert.match(page, /participantCount\(activeEvent\).*peopleInvitedSuffix/u);
  assert.match(page, /peopleCountLabel\(invitedPeople\.length \+ 1\)/u);
  assert.match(page, /AvatarStack hostName=\{activeEvent\.hostName\}/u);
  assert.equal(experience.home.metrics.invited, "people");
  assert.equal(experience.invitation.metrics.invited, "people");
  assert.equal(experience.invitation.attendeeEntry.peopleInvitedSuffix, "people invited");
  assert.equal(experience.attendees.invitedSuffix, "people");

  assert.match(swiftModels, /var participantCount: Int[\s\S]*invitees\.count \+ 1/u);
  assert.match(swiftHome, /event\.participantCount/u);
  assert.match(swiftEditor, /draft\.participantCount/u);
  assert.match(swiftEditor, /focused\(\$focusedField, equals: \.title\)/u);
  assert.match(swiftEditor, /focused\(\$focusedField, equals: \.description\)/u);
  assert.match(swiftEditor, /focusedField = \.title/u);
  assert.match(swiftEditor, /focusedField = \.description/u);
  assert.match(
    swiftEditor,
    /frame\(maxWidth: \.infinity, alignment: \.leading\)[\s\S]*?contentShape\(\.rect\)/u,
  );
});

test("attendees use one collapsing title and one unified, private-status list", async () => {
  const [page, css, experienceSource, swiftHome] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../app/globals.css", import.meta.url), "utf8"),
    readFile(new URL("../shared/HerdExperience.json", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
  ]);
  const experience = JSON.parse(experienceSource);

  assert.equal(
    experience.attendees.statusDisclosure,
    "Attendance status appears only after the event is confirmed. Guests must send an encrypted reply before their status can be shown.",
  );
  assert.match(page, /ATTENDEES_EXPERIENCE\.statusDisclosure/u);
  assert.match(page, /className="people-list"[\s\S]*person-row person-row-host[\s\S]*host-crown/u);
  assert.doesNotMatch(page, /<section className="host-card">/u);
  assert.doesNotMatch(page, /Hidden until the deadline/u);
  assert.match(page, /<span className="person-status">Going<\/span>/u);
  assert.match(page, /event\.role === "host" \|\| event\.hasResponse/u);
  assert.doesNotMatch(page, /<DeliveryCallout delivery=/u);
  assert.match(page, /activeEvent\?\.role === "host"[\s\S]*DeliveryStatusButton guest=/u);
  assert.match(page, /delivery-status-tooltip" role="tooltip"/u);
  assert.equal(experience.attendees.addGuests.button, "Add attendees");
  assert.match(page, /data-testid="add-event-attendees"/u);
  assert.match(page, /activeEvent\.role === "host" \|\| activeEvent\.allowsAttendeesToAddGuests/u);
  assert.match(page, /\/api\/events\/\$\{encodeURIComponent\(event\.id\)\}\/attendees/u);
  assert.match(page, /ATTENDEES_EXPERIENCE\.addGuests\.submitMultipleTemplate/u);
  assert.match(css, /\.add-attendees-button/u);
  assert.match(css, /\.guest-draft-card/u);

  assert.match(css, /\.app-header h1 \{[\s\S]*visibility: hidden/u);
  assert.match(css, /\.app-header-condensed h1 \{[\s\S]*visibility: visible/u);
  assert.match(swiftHome, /private struct InvitationAttendees[\s\S]*navigationBarTitleDisplayMode\(\.large\)/u);
  assert.match(swiftHome, /private struct InvitationAttendees[\s\S]*attendeeAvatarTone\(tone\)/u);
  assert.match(swiftHome, /Image\(systemName: "crown\.fill"\)/u);
  assert.match(swiftHome, /event\.role == \.host \|\| event\.hasResponse/u);
  assert.doesNotMatch(swiftHome, /invitationDeliveryCard\(delivery\)/u);
  assert.match(swiftHome, /guard event\.isHosted else \{ return nil \}/u);
  assert.match(swiftHome, /popover\(isPresented: isPresented/u);
  assert.match(swiftHome, /event\.isHosted \|\| event\.allowsAttendeesToAddGuests/u);
  assert.match(swiftHome, /experience\.addGuests\.button/u);
  assert.doesNotMatch(
    swiftHome.match(/private struct InvitationAttendees[\s\S]*?private struct InvitationConditionPicker/u)?.[0] ?? "",
    /Text\(experience\.title\)/u,
  );
});

test("reply countdown remains visible until the deadline and uses compact time pairs", async () => {
  const [page, swiftHome] = await Promise.all([
    readFile(new URL("../app/page.tsx", import.meta.url), "utf8"),
    readFile(new URL("../../HerdHost/HomeView.swift", import.meta.url), "utf8"),
  ]);

  assert.match(
    page,
    /event\.resolution\?\.status === "not_confirmed"[\s\S]*Date\.parse\(event\.rsvpDeadline\) <= now[\s\S]*: fallback/u,
  );
  assert.match(page, /minutes > 0[\s\S]*`\$\{minutes\}m \$\{seconds % 60\}s`[\s\S]*`\$\{seconds\}s`/u);
  assert.match(page, /eventThirdMetric\(activeEvent,[\s\S]*, now\)/u);
  assert.match(
    swiftHome,
    /case \.notConfirmed:[\s\S]*event\.rsvpDeadline\.map \{ \$0 <= \.now \}[\s\S]*"Not yet confirmed"/u,
  );
  assert.match(swiftHome, /if minutes > 0 \{ return \("\\\(minutes\)m \\\(seconds % 60\)s"/u);
  assert.match(swiftHome, /return \("\\\(seconds\)s", "left to respond"\)/u);
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
  assert.equal(experience.authentication.welcome.body, "Unlock more fun events with completely confidential replies.");
  assert.equal(experience.authentication.welcome.phoneLabel, "Sign in with phone number");
  assert.equal(experience.authentication.welcome.requestCodeButton, "Text me a code");
  assert.equal(experience.authentication.releaseStatus.label, "Pre-release alpha");
  assert.match(experience.authentication.releaseStatus.heading, /Thanks for trying Herd/);
  assert.match(experience.authentication.releaseStatus.body, /jwoodbury11@gmail\.com/);
  assert.match(page, /AUTH_EXPERIENCE\.welcome\.title/);
  assert.match(page, /AUTH_EXPERIENCE\.verification\.title/);
  assert.match(page, /nextOtp\.length === OTP_LENGTH[\s\S]*?verifyCode\(nextOtp\)/);
  assert.match(page, /verificationInFlightRef\.current/);
  assert.match(swiftAuth, /HerdExperience\.shared\.authentication/);
  assert.match(swiftAuth, /experience\.welcome\.title/);
  assert.match(swiftAuth, /experience\.verification\.title/);
  assert.match(swiftAuth, /Label\(experience\.releaseStatus\.label, systemImage: "hammer\.fill"\)/);
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
  assert.match(privateResponseCrypto, /publicRuntimeValue\("HERD_EVALUATOR_KEY_ID"\)/u);
  assert.match(privateResponseCrypto, /publicRuntimeValue\("HERD_EVALUATOR_PUBLIC_KEY"\)/u);
  assert.match(css, /\.privacy-flow-step[\s\S]*grid-template-columns: 42px minmax\(0, 1fr\)/u);
  assert.match(css, /\.privacy-flow-boundary[\s\S]*grid-template-columns: 42px minmax\(0, 1fr\)/u);
  assert.match(css, /\.privacy-flow-boundary \{[^}]*border: 1px solid var\(--border\)[^}]*background: var\(--surface\)/u);
  assert.doesNotMatch(css, /\.privacy-flow-icon \{[^}]*(?:border-radius|background|border:)/u);
  assert.match(css, /\.privacy-flow-connector \{[\s\S]*top: calc\(50% \+ 29px\)/u);
  assert.match(css, /\.accordion-stack summary \{[^}]*text-align: left/u);
  assert.match(swiftHome, /Image\(systemName: "arrow\.down"\)[\s\S]*y: \(geometry\.size\.height \+ 58\) \/ 2/u);
  assert.match(swiftHome, /VStack\(spacing: 0\) \{[\s\S]*\.wireframeCard\(padding: 0\)/u);
  assert.match(swiftHome, /Text\(experience\.flowPrivacyLabel\)[\s\S]*\.wireframeCard\(padding: 14\)/u);
  assert.match(swiftHome, /Text\(section\.title\)[\s\S]*\.multilineTextAlignment\(\.leading\)/u);

  assert.equal(experience.home.title, "Herd events");
  assert.equal(experience.home.createEventTitle, "Host an event");
  assert.equal(experience.home.invitesSectionTitle, "Your invites");
  assert.equal(experience.home.hostedSectionTitle, "Your hosted events");
  assert.equal(experience.home.unconfirmedSectionTitle, "Events never confirmed");
  assert.equal(
    experience.home.unconfirmedSectionNote,
    "Auto-deletes 5 days after invite deadline",
  );
  assert.equal(experience.home.pastSectionTitle, "Past events");
  assert.equal(experience.home.profile.useGenericIconWithoutName, true);
  assert.equal(experience.home.layout.headerToFirstCardGap, 88);
  assert.doesNotMatch(page, /Welcome back/i);
  assert.match(page, /HOME_EXPERIENCE\.title/);
  assert.match(page, /function homeEventSection/);
  assert.match(page, /event\.invitationsSent[\s\S]*event\.resolution\?\.status !== "confirmed"/u);
  assert.match(page, /eventDay\.setDate\(eventDay\.getDate\(\) \+ 1\)/);
  assert.match(page, /invitedEvents\.map\(\(event\)/);
  assert.match(page, /hostedEvents\.map\(\(event\)/);
  assert.match(page, /unconfirmedEvents\.map\(\(event\)/);
  assert.match(page, /pastEvents\.map\(\(event\)/);
  const webEventCard = page.slice(
    page.indexOf("function EventCard("),
    page.indexOf("export function HerdApp"),
  );
  assert.doesNotMatch(webEventCard, /chevron|ChevronRight/u);
  assert.equal(
    page.match(/<details className="home-event-disclosure">/gu)?.length,
    2,
  );
  assert.doesNotMatch(page, /<details className="home-event-disclosure"[^>]*\sopen/u);
  assert.match(
    page,
    /home-unconfirmed-heading[\s\S]*HOME_EXPERIENCE\.unconfirmedSectionTitle[\s\S]*HOME_EXPERIENCE\.unconfirmedSectionNote[\s\S]*home-event-disclosure-chevron/u,
  );
  assert.match(css, /\.home-event-disclosure\[open\] \.home-event-disclosure-chevron \{ transform: rotate\(90deg\); \}/u);
  assert.doesNotMatch(page, /showsEventSectionHeadings|populatedEventSectionCount/);
  assert.match(page, /\{invitedEvents\.length \? \([\s\S]*aria-labelledby="home-invites-heading"[\s\S]*<h2 id="home-invites-heading">/u);
  assert.match(page, /aria-labelledby="home-hosted-heading"[\s\S]*<h2 id="home-hosted-heading">/u);
  assert.match(page, /aria-labelledby="home-unconfirmed-heading"[\s\S]*<h2 id="home-unconfirmed-heading">/u);
  assert.match(page, /HOME_EXPERIENCE\.unconfirmedSectionNote/u);
  assert.match(page, /aria-labelledby="home-past-heading"[\s\S]*<h2 id="home-past-heading">/u);
  assert.ok(page.indexOf('aria-labelledby="home-past-heading"') < page.indexOf('aria-labelledby="home-unconfirmed-heading"'));
  assert.doesNotMatch(page, /className="home-section-empty"/);
  assert.match(page, /sortEventsForHome/);
  assert.match(page, /upsertHomeEvent/);
  assert.match(page, /HOME_EXPERIENCE\.profile\.useGenericIconWithoutName/);
  assert.match(page, /<UserRound aria-hidden="true"/);
  assert.match(page, /lastUpdatedLabel\(lastEventsUpdatedAt, now\)/);
  assert.doesNotMatch(page, /aria-label="Refresh events"/);
  assert.match(page, /aria-label="Account status"/);
  assert.match(page, /screen === "status"/);
  assert.match(page, /aria-label="Run status checks"/);
  assert.match(page, /Private reply security/);
  assert.match(page, /Trust and verification/);
  assert.match(page, /window\.setInterval\(refreshIfStale, 60_000\)/);
  assert.match(page, /visibilitychange/);
  assert.doesNotMatch(page, /personInitials\(profileName \|\| "Host"\)/);
  assert.match(swiftHome, /HerdExperience\.shared\.home/);
  assert.match(swiftHome, /experience\.profile\.useGenericIconWithoutName/);
  assert.match(swiftHome, /Image\(systemName: "person"\)/);
  assert.match(swiftHome, /events\(in: \.unconfirmed\)/);
  assert.match(swiftHome, /events\(in: \.past\)/);
  assert.doesNotMatch(swiftHome, /showsEventSectionTitles|populatedEventSectionCount/);
  assert.match(swiftHome, /if !invitedEvents\.isEmpty \{[\s\S]*title: experience\.invitesSectionTitle/u);
  assert.match(swiftHome, /title: experience\.hostedSectionTitle/);
  assert.match(swiftHome, /title: experience\.unconfirmedSectionTitle/);
  assert.match(swiftHome, /note: experience\.unconfirmedSectionNote/);
  assert.match(swiftHome, /title: experience\.pastSectionTitle/);
  const swiftEventCard = swiftHome.slice(
    swiftHome.indexOf("private struct EventCard"),
    swiftHome.indexOf("private struct InvitationTitleBottomPreferenceKey"),
  );
  assert.doesNotMatch(swiftEventCard, /Image\(systemName: "chevron\.right"\)/u);
  assert.match(swiftHome, /@State private var pastEventsExpanded = false/u);
  assert.match(swiftHome, /@State private var unconfirmedEventsExpanded = false/u);
  assert.match(
    swiftHome,
    /VStack\(alignment: \.leading, spacing: 3\) \{[\s\S]*Text\(title\)[\s\S]*if let note[\s\S]*Text\(note\)[\s\S]*Image\(systemName: "chevron\.right"\)/u,
  );
  assert.match(swiftHome, /if isExpanded\.wrappedValue \{[\s\S]*ForEach\(events\)/u);
  assert.ok(swiftHome.indexOf("title: experience.pastSectionTitle") < swiftHome.indexOf("title: experience.unconfirmedSectionTitle"));
  assert.doesNotMatch(swiftHome, /emptyMessage: experience\.emptyInvitesMessage/);
  assert.match(swiftHome, /Last updated/);
  assert.match(swiftHome, /automaticRefreshInterval/);
  assert.match(swiftHome, /scenePhase == \.active/);
  assert.match(project, /HerdExperience\.json in Resources/);
  assert.match(css, /--home-horizontal-padding/);
  assert.match(css, /--home-header-to-first-card-gap/);
  assert.match(css, /--home-create-card-min-height/);
  assert.match(swiftHome, /headerToFirstCardGap - experience\.layout\.verticalGap/);
  assert.match(swiftHome, /font\(\.system\(size: 39, weight: \.bold\)\)/);
  assert.match(swiftHome, /background\(HerdTheme\.surface, in: \.rect\(cornerRadius: 9\)\)/);
  assert.match(swiftHome, /private struct InvitationMetric[\s\S]*VStack\(alignment: \.leading/u);
  assert.match(
    swiftHome,
    /goingResponseOption[\s\S]*?Grid\(alignment: \.leading,[\s\S]*?GridRow\(alignment: \.top\)[\s\S]*?privateCriteriaEditor\(event\)/u,
  );
  assert.match(page, /\{reply === "yes" \? <div className=\{`condition-builder/u);
  assert.doesNotMatch(page, /reply-option-header/u);
  assert.match(
    css,
    /\.reply-option-yes \{[\s\S]*?display: grid;[\s\S]*?grid-template-columns: 22px minmax\(0, 1fr\);[\s\S]*?column-gap: 12px;/u,
  );
  assert.match(
    css,
    /\.reply-option-no \{[\s\S]*?display: grid;[\s\S]*?grid-template-columns: 22px minmax\(0, 1fr\);[\s\S]*?column-gap: 12px;/u,
  );
  assert.match(css, /\.condition-builder \{[\s\S]*?grid-column: 2;/u);
  assert.equal(experience.reply.goingCollapsedTitle, "I’m down if…");
  assert.equal(experience.reply.goingCollapsedBody, "Set your encrypted conditions");

  for (const section of ["profile", "invitation", "attendees", "reply", "privacy", "success"]) {
    assert.ok(experience[section], `missing shared ${section} experience`);
  }
  assert.match(page, /PROFILE_EXPERIENCE\.syncNote/);
  assert.match(page, /REPLY_EXPERIENCE\.submitButton/);
  assert.doesNotMatch(page, /window\.confirm\(\s*REPLY_EXPERIENCE\.deviceSwitch/u);
  assert.doesNotMatch(page, /inviteMetadata\.hasResponse \|\| inviteMetadata\.responseEnvelope/u);
  assert.equal(
    experience.reply.unreadable,
    "Your active reply isn’t available on this device. To view or update your reply here, send a new one from this device. It will replace your current reply.",
  );
  assert.equal(experience.reply.deviceSwitch.confirmButton, "Switch to this device");
  assert.equal(experience.reply.deviceSwitch.verifyButton, "Verify and switch");
  assert.match(page, /beginDeviceSwitchVerification/);
  assert.match(page, /verifyDeviceSwitchCode/);
  assert.match(page, /fresh_phone_verification_required|deviceSwitchStage/u);
  assert.match(page, /function ReplyVisibilityPreview/);
  assert.equal((page.match(/<ReplyVisibilityPreview/g) ?? []).length, 2);
  assert.match(css, /\.reply-preview-sheet \.sheet-handle \{[^}]*margin-bottom: 21px/u);
  assert.match(swiftHome, /replyVisibilityPreviewSheet[\s\S]*\.padding\(\.top, 28\)/u);
  assert.match(swiftHome, /accessibilityIdentifier\("reply-preview-dismiss"\)/u);
  assert.match(page, /data-testid="reply-preview-dismiss"/u);
  assert.match(page, /REPLY_EXPERIENCE\.confirmedPreviewLabel/);
  assert.equal(experience.reply.confirmedPreviewLabel, "If the event is confirmed:");
  assert.equal(experience.reply.confirmedPreviewBody, "Your attendance conditions are never shown to anyone.");
  assert.equal(
    experience.reply.noReplyHistoryTemplate,
    "This user has not responded to {missed} of {total} confirmed events they were invited to.",
  );
  assert.equal(
    experience.reply.noReplySingleEventHistory,
    "This user has not responded to their only confirmed event invitation.",
  );
  assert.equal(
    experience.reply.noReplyPreviewBody,
    "Avoid a no response at all costs. No responses are why fun events that could have happened don’t happen.",
  );
  assert.equal(experience.reply.notConfirmedPreviewLabel, "If the event is not confirmed:");
  assert.equal(experience.reply.notConfirmedPreviewTitle, "This event was not confirmed");
  assert.equal(experience.reply.notConfirmedPreviewBody, "Zero information is shown to anybody.");
  assert.match(page, /REPLY_EXPERIENCE\.notConfirmedPreviewLabel[\s\S]*className="reply-preview-hidden"[\s\S]*REPLY_EXPERIENCE\.notConfirmedPreviewTitle[\s\S]*REPLY_EXPERIENCE\.notConfirmedPreviewBody/u);
  assert.match(swiftHome, /private struct ReplyVisibilityPreview[\s\S]*Text\(confirmedBody \?\? experience\.confirmedPreviewBody\)[\s\S]*Text\(experience\.notConfirmedPreviewLabel\)[\s\S]*Text\(experience\.notConfirmedPreviewTitle\)[\s\S]*Text\(experience\.notConfirmedPreviewBody\)/u);
  assert.doesNotMatch(page, /No response by deadline/u);
  assert.doesNotMatch(swiftHome, /No response by deadline/u);
  assert.match(swiftHome, /replyVisibilityPreview\(event\)/);
  assert.match(swiftHome, /noReplyHistory\(including: event\)/);
  assert.match(page, /noReplyHistoryLabel/);
  assert.match(page, /person\.responseHistory\.missedConfirmedEvents/);
  assert.match(swiftHome, /invitee\.responseHistory/);
  assert.match(swiftHome, /replyHistoryLabel/);
  assert.match(page, /PRIVACY_EXPERIENCE\.sections\.map/);
  assert.match(page, /PROFILE_EXPERIENCE\.deleteAccountButton/);
  assert.match(page, /confirmation: "DELETE"/);
  assert.match(page, /forgetAllAccountRootSecrets\(deletedUserId\)/);
  assert.match(experience.profile.accountDeletion.body, /permanently deletes your profile, hosted events, sessions, account keys, and encrypted replies/i);
  assert.equal(experience.success.replyPreviewTitle, "This is how your reply will show up to others");
  assert.match(page, /SUCCESS_EXPERIENCE\.replyPreviewTitle[\s\S]*<ReplyVisibilityPreview/u);
  assert.doesNotMatch(page, /SUCCESS_EXPERIENCE\.(?:savedReply|visibility|goingPrivacy|cantCommitPrivacy)/u);
  assert.match(swiftHome, /Text\(experience\.replyPreviewTitle\)[\s\S]*ReplyVisibilityPreview/u);
  assert.match(swiftHome, /Text\(experience\.replyPreviewTitle\)[\s\S]*Divider\(\)[\s\S]*padding\(\.top, 28\)/u);
  assert.match(css, /\.success-reply-preview > h2 \{[^}]*border-bottom: 1px solid var\(--border\)[^}]*\}/u);
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
  assert.match(page, /<Construction aria-hidden="true" \/>/);
  assert.match(page, /aria-haspopup="dialog"/);
  assert.match(page, /setReleaseStatusOpen\(true\)/);
  assert.match(page, /AUTH_EXPERIENCE\.releaseStatus\.heading/);
  assert.match(page, /className="release-status-dialog"/);
  assert.match(page, /PRIVACY_EXPERIENCE\.navigationTitle/);
  assert.match(page, /PRIVACY_EXPERIENCE\.flowSteps\.map/);
  assert.match(page, /PRIVACY_EXPERIENCE\.flowPrivacyLabel/);
  assert.match(page, /className="privacy-flow-connector"/);
  assert.doesNotMatch(page, /privacy-flow-index/);
  assert.match(page, /PRIVACY_EXPERIENCE\.sections\.map/);
  assert.match(page, /section\.showsVerificationLinks/);
  assert.match(page, /section\.showsPolicyIdentifiers/);
  assert.match(experience.privacy.navigationTitle, /Prove it to me/);
  assert.equal(experience.privacy.flowSteps.length, 4);
  assert.match(experience.privacy.flowPrivacyLabel, /never shown to the host or guests/i);
  const tldrSection = experience.privacy.sections.find((section) => /TL;DR/.test(section.title));
  const conditionSection = experience.privacy.sections.find((section) => /condition set/i.test(section.title));
  const visibleSection = experience.privacy.sections.find((section) => /can be shown/i.test(section.title));
  const metadataSection = experience.privacy.sections.find((section) => /still learn/i.test(section.title));
  const verificationSection = experience.privacy.sections.find((section) => /verify the code/i.test(section.title));
  assert.match(tldrSection.paragraphs[0], /locks your full reply before it sends/i);
  assert.match(conditionSection.paragraphs[0], /^No\./i);
  assert.match(conditionSection.paragraphs[1], /phone number .* not the decryption key/i);
  assert.match(visibleSection.paragraphs[0], /attending members/i);
  assert.match(metadataSection.paragraphs[0], /account-linked, not anonymous to Herd/i);
  assert.equal(verificationSection.showsVerificationLinks, true);
  assert.equal(verificationSection.showsPolicyIdentifiers, true);
  assert.match(verificationSection.paragraphs[0], /Apache 2\.0/i);
  assert.match(verificationSection.paragraphs[2], /not the same as an independent audit/i);
  assert.match(experience.privacy.sourceURL, /github\.com\/jwoodbury11\/herd-privacy-source/);
  assert.match(experience.privacy.releaseEvidenceURL, /\.well-known\/herd-release\.json/);
  assert.doesNotMatch(JSON.stringify(experience.privacy), /evaluator .* not deployed yet/i);
  assert.doesNotMatch(JSON.stringify(experience.privacy), /host may also infer a condition/i);
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
  assert.match(envExample, /HERD_TEST_ACCOUNT_ACCESS_ENABLED/);
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
