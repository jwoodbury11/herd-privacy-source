import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath, pathToFileURL } from "node:url";

import { startBrowserAcceptanceHarness } from "../scripts/browser-acceptance-harness.mjs";
import ts from "typescript";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const temporaryDirectory = await mkdtemp(
  path.join(projectRoot, ".browser-acceptance-harness-"),
);

after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

async function transpile(sourceName, outputName, replacements = []) {
  let source = await readFile(path.join(projectRoot, sourceName), "utf8");
  for (const [pattern, replacement] of replacements) {
    source = source.replace(pattern, replacement);
  }
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
      isolatedModules: true,
    },
    fileName: sourceName,
  }).outputText;
  await writeFile(path.join(temporaryDirectory, outputName), output);
}

await transpile("lib/privacy/protocol.ts", "protocol.mjs");
await transpile(
  "lib/privacy/trust-verification.ts",
  "trust-verification.mjs",
  [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
);
await transpile(
  "lib/privacy/private-response-crypto.ts",
  "private-response-crypto.mjs",
  [
    [/from "\.\/protocol";/u, 'from "./protocol.mjs";'],
    [/from "\.\/trust-verification";/u, 'from "./trust-verification.mjs";'],
  ],
);
await transpile(
  "lib/privacy/device-vault.ts",
  "device-vault.mjs",
  [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
);
await transpile(
  "lib/privacy/evaluator-attestation.ts",
  "evaluator-attestation.mjs",
  [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
);

const moduleUrl = (name) =>
  `${pathToFileURL(path.join(temporaryDirectory, name)).href}?browser-acceptance=1`;
const deviceVault = await import(moduleUrl("device-vault.mjs"));
const evaluatorAttestation = await import(moduleUrl("evaluator-attestation.mjs"));
const trustVerification = await import(moduleUrl("trust-verification.mjs"));

function installClientTrustPins(release) {
  const values = {
    NEXT_PUBLIC_HERD_RELEASE_ID: release.id,
    NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID: release.responseDecryption.id,
    NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY:
      release.responseDecryption.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT: release.measurement,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID:
      release.evaluationResultSigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY:
      release.evaluationResultSigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID:
      release.policySigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY:
      release.policySigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID:
      release.transparencySigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      release.transparencySigning.publicKey,
    NEXT_PUBLIC_HERD_ATTESTATION_AUDIENCE: release.attestation.audience,
    NEXT_PUBLIC_HERD_ATTESTATION_PROJECT_ID: release.attestation.projectId,
    NEXT_PUBLIC_HERD_ATTESTATION_SERVICE_ACCOUNT:
      release.attestation.serviceAccount,
    NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGEST:
      release.attestation.imageDigest,
    NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGESTS:
      release.attestation.imageDigest,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_FINGERPRINT:
      release.attestation.rootFingerprint,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_CERTIFICATE:
      release.attestation.rootCertificate,
    NEXT_PUBLIC_HERD_ATTESTATION_SWVERSIONS:
      release.attestation.swVersion,
    NEXT_PUBLIC_HERD_ATTESTATION_MAX_AGE_SECONDS: "300",
  };
  const previous = new Map(
    Object.keys(values).map((name) => [name, process.env[name]]),
  );
  Object.assign(process.env, values);
  return () => {
    for (const [name, value] of previous) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
  };
}

async function authenticate(baseUrl, alias) {
  const response = await fetch(new URL("/api/auth/request-code", baseUrl), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      origin: baseUrl.origin,
    },
    body: JSON.stringify({ phoneNumber: alias }),
  });
  assert.equal(response.status, 200, await response.clone().text());
  const session = await response.json();
  assert.ok(session.accessToken);
  const setCookie = response.headers.get("set-cookie") ?? "";
  assert.match(setCookie, /herd_session=/u);
  return { ...session, cookie: setCookie.split(";", 1)[0] };
}

test(
  "browser acceptance harness serves one isolated signed nine-account scenario",
  { timeout: 30_000 },
  async (t) => {
    const harness = await startBrowserAcceptanceHarness({ build: false });
    t.after(() => harness.stop());

    assert.equal(harness.baseUrl.hostname, "127.0.0.1");
    assert.equal(harness.migrationCount, 17);
    assert.equal(harness.scenario.counts.testAccountCount, 9);
    assert.equal(harness.scenario.counts.inviteeCount, 8);
    assert.equal(harness.scenario.counts.sentCount, 8);
    assert.equal(harness.scenario.counts.signedPolicyCount, 1);
    assert.equal(harness.scenario.invitePaths.length, 8);
    assert.equal(new Set(harness.scenario.invitePaths).size, 8);
    assert.equal(harness.scenario.inviteApiPaths.length, 8);

    const page = await fetch(harness.browserUrl);
    assert.equal(page.status, 200);
    const pageHtml = await page.text();
    assert.match(pageHtml, /Herd/u);
    const assetPaths = [
      ...new Set(
        [...pageHtml.matchAll(/(?:src|href)="(\/assets\/[^"?#]+)[^"]*"/gu)]
          .map((match) => match[1]),
      ),
    ];
    assert.ok(assetPaths.some((assetPath) => assetPath.endsWith(".js")));
    assert.ok(assetPaths.some((assetPath) => assetPath.endsWith(".css")));
    const assetResponses = await Promise.all(
      assetPaths.map((assetPath) => fetch(new URL(assetPath, harness.baseUrl))),
    );
    assert.ok(assetResponses.every(({ status }) => status === 200));

    const anonymous = await fetch(
      new URL(harness.scenario.inviteApiPath, harness.baseUrl),
    );
    assert.equal(anonymous.status, 200);
    const anonymousBody = await anonymous.json();
    assert.equal(anonymousBody.invitationPreview.requiresAuthentication, true);
    assert.equal(Object.hasOwn(anonymousBody, "event"), false);

    const aliasOne = await authenticate(harness.baseUrl, "2");
    const eventList = await fetch(new URL("/api/events", harness.baseUrl), {
      headers: { authorization: `Bearer ${aliasOne.accessToken}` },
    });
    assert.equal(eventList.status, 200);
    assert.ok(
      (await eventList.json()).events.some(
        ({ id }) => id === harness.scenario.eventId,
      ),
    );
    const correct = await fetch(
      new URL(harness.scenario.inviteApiPath, harness.baseUrl),
      { headers: { authorization: `Bearer ${aliasOne.accessToken}` } },
    );
    assert.equal(correct.status, 200);
    const correctBody = await correct.json();
    assert.equal(correctBody.event.id, harness.scenario.eventId);
    assert.equal(correctBody.inviteMetadata.canRespond, true);
    assert.equal(correctBody.inviteMetadata.hasResponse, false);
    assert.ok(correctBody.event.privateResponsePolicy.policySignature);

    const restorePins = installClientTrustPins(harness.release);
    t.after(restorePins);
    const responseCrypto = await import(
      `${moduleUrl("private-response-crypto.mjs")}&release=${encodeURIComponent(harness.release.id)}`,
    );
    const accountRootSecret = crypto.getRandomValues(new Uint8Array(32));
    const keyCommitment = await deviceVault.accountRootSecretCommitment(
      accountRootSecret,
    );
    const initialize = await fetch(
      new URL("/api/account/key-epoch/initialize", harness.baseUrl),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          cookie: aliasOne.cookie,
          origin: harness.baseUrl.origin,
        },
        body: JSON.stringify({
          expectedAccountKeyEpochId:
            correctBody.inviteMetadata.accountKeyEpochId,
          keyCommitment,
        }),
      },
    );
    assert.equal(initialize.status, 200, await initialize.clone().text());

    const networkFetch = globalThis.fetch;
    globalThis.fetch = (input, init = {}) => {
      const relative = typeof input === "string" && input.startsWith("/");
      const headers = new Headers(init.headers);
      if (relative) {
        headers.set("cookie", aliasOne.cookie);
        headers.set("origin", harness.baseUrl.origin);
      }
      return networkFetch(
        relative ? new URL(input, harness.baseUrl) : input,
        { ...init, headers },
      );
    };
    try {
      await evaluatorAttestation.attestEvaluatorForPolicy(
        correctBody.event.privateResponsePolicy,
      );
    } finally {
      globalThis.fetch = networkFetch;
    }

    const sealed = await responseCrypto.sealPrivateResponse({
      eventId: correctBody.event.id,
      inviteeId: correctBody.inviteMetadata.id,
      accountKeyEpochId: correctBody.inviteMetadata.accountKeyEpochId,
      revision: 1,
      response: "going",
      minimumParticipants: 4,
      requiredGroups: [],
      allowedInviteeIds: correctBody.event.invitees.map(({ id }) => id),
      accountRootSecret,
      policy: correctBody.event.privateResponsePolicy,
    });
    accountRootSecret.fill(0);
    const submission = await networkFetch(
      new URL(`${harness.scenario.inviteApiPath}/rsvp`, harness.baseUrl),
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          cookie: aliasOne.cookie,
          origin: harness.baseUrl.origin,
        },
        body: JSON.stringify({ envelope: sealed.envelope }),
      },
    );
    assert.equal(submission.status, 200, await submission.clone().text());
    const submissionBody = await submission.json();
    assert.equal(
      submissionBody.responseEnvelope.envelopeId,
      sealed.envelope.envelopeId,
    );
    assert.equal(submissionBody.receipt.revision, 1);
    await trustVerification.verifyPrivateResponseReceiptPublication(
      submissionBody.receipt,
      {
        keyId: harness.release.transparencySigning.id,
        publicKey: harness.release.transparencySigning.publicKey,
      },
      (pathname, init) =>
        networkFetch(new URL(String(pathname), harness.baseUrl), init),
    );

    const submittedInvite = await networkFetch(
      new URL(harness.scenario.inviteApiPath, harness.baseUrl),
      { headers: { cookie: aliasOne.cookie } },
    );
    assert.equal(submittedInvite.status, 200);
    const submittedProjection = await submittedInvite.json();
    assert.equal(submittedProjection.inviteMetadata.hasResponse, true);
    assert.equal(submittedProjection.inviteMetadata.responseRevision, 1);
    const storedSubmission = await harness.database
      .prepare(
        `SELECT
           (SELECT COUNT(*) FROM response_envelopes WHERE event_id = ?) AS responseCount,
           (SELECT COUNT(*)
            FROM response_transparency_entries AS transparency
            JOIN response_envelopes AS envelopes
              ON envelopes.id = transparency.envelope_id
            WHERE envelopes.event_id = ?) AS publicationCount`,
      )
      .bind(harness.scenario.eventId, harness.scenario.eventId)
      .first();
    assert.deepEqual(storedSubmission, {
      responseCount: 1,
      publicationCount: 1,
    });

    const aliasTwo = await authenticate(harness.baseUrl, "3");
    const wrong = await fetch(
      new URL(harness.scenario.inviteApiPath, harness.baseUrl),
      { headers: { authorization: `Bearer ${aliasTwo.accessToken}` } },
    );
    assert.equal(wrong.status, 403);
    assert.equal(
      (await wrong.json()).error.code,
      "invite_for_different_account",
    );
  },
);
