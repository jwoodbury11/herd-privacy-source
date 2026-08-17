import assert from "node:assert/strict";
import { after, test } from "node:test";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { loadPrivateResponseTestModules } from "./helpers/private-response-test-modules.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = fileURLToPath(
  new URL("./acceptance/private-response-v1-cross-platform-vectors.json", import.meta.url),
);
const fixture = JSON.parse(await readFile(fixturePath, "utf8"));
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID =
  fixture.trustPins.policySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
  fixture.trustPins.policySigning.publicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID =
  fixture.trustPins.transparencySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY =
  fixture.trustPins.transparencySigning.publicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID =
  fixture.vectors[0].policy.evaluatorKeyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY =
  fixture.vectors[0].policy.evaluatorPublicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT =
  fixture.vectors[0].policy.evaluatorMeasurement;
process.env.NEXT_PUBLIC_HERD_RELEASE_ID = fixture.vectors[0].policy.releaseId;
const { protocol, privateResponseCrypto, cleanup } =
  await loadPrivateResponseTestModules(projectRoot);

after(cleanup);

test("committed Web Crypto and CryptoKit envelopes open with the shared v1 contract", async (t) => {
  assert.equal(fixture.formatVersion, 1);
  assert.ok(fixture.vectors.length >= 2);
  assert.notEqual(
    fixture.trustPins.policySigning.publicKey,
    fixture.trustPins.transparencySigning.publicKey,
  );

  for (const vector of fixture.vectors) {
    await t.test(vector.name, async () => {
      assert.ok(["invitee-web Web Crypto", "HerdHost CryptoKit"].includes(vector.producer));
      const accountRootSecret = protocol.base64UrlToBytes(vector.accountRootSecret);
      const opened = await privateResponseCrypto.openPrivateResponse({
        envelope: vector.envelope,
        eventId: vector.eventId,
        inviteeId: vector.inviteeId,
        allowedInviteeIds: vector.allowedInviteeIds,
        accountRootSecret,
        policy: vector.policy,
      });

      assert.deepEqual(opened, vector.expectedDraft);
      assert.equal(
        await privateResponseCrypto.privateResponseEnvelopeHash(vector.envelope),
        vector.expectedEnvelopeHash,
      );
      assert.equal(
        protocol.base64UrlToBytes(vector.envelope.payloadCiphertext).length,
        protocol.PRIVATE_RESPONSE_PAYLOAD_FRAME_BYTES,
      );
      assert.equal(
        protocol.base64UrlToBytes(vector.envelope.userKeyWrap).length,
        protocol.PRIVATE_RESPONSE_USER_WRAP_BYTES,
      );
      assert.equal(
        protocol.base64UrlToBytes(vector.envelope.evaluatorKeyWrap).length,
        protocol.PRIVATE_RESPONSE_EVALUATOR_WRAP_BYTES,
      );
      assert.equal(
        protocol.base64UrlToBytes(vector.envelope.responseSigningPublicKey).length,
        protocol.PRIVATE_RESPONSE_SIGNING_PUBLIC_KEY_BYTES,
      );
      assert.equal(
        protocol.base64UrlToBytes(vector.envelope.responseSignature).length,
        64,
      );
    });
  }
  assert.deepEqual(
    new Set(fixture.vectors.map((vector) => vector.producer)),
    new Set(["invitee-web Web Crypto", "HerdHost CryptoKit"]),
  );
  const webVector = fixture.vectors.find(
    (vector) => vector.name === "web-going-with-and-of-or-condition",
  );
  const iosVector = fixture.vectors.find(
    (vector) => vector.producer === "HerdHost CryptoKit",
  );
  assert.ok(webVector);
  assert.ok(iosVector);
  assert.equal(iosVector.eventId, webVector.eventId);
  assert.equal(iosVector.inviteeId, webVector.inviteeId);
  assert.equal(iosVector.accountRootSecret, webVector.accountRootSecret);
  assert.equal(
    iosVector.envelope.responseSigningPublicKey,
    webVector.envelope.responseSigningPublicKey,
    "Web Crypto and CryptoKit must derive the same per-event/member authorization key",
  );
  assert.notEqual(
    iosVector.envelope.payloadCiphertext,
    webVector.envelope.payloadCiphertext,
    "encryption remains randomized even when the authorization identity is stable",
  );
});

test("the cross-platform vector rejects authenticated-envelope tampering", async () => {
  const vector = fixture.vectors[0];
  const first = vector.envelope.payloadCiphertext[0];
  const tampered = {
    ...vector.envelope,
    payloadCiphertext: `${first === "A" ? "B" : "A"}${vector.envelope.payloadCiphertext.slice(1)}`,
  };

  await assert.rejects(
    privateResponseCrypto.openPrivateResponse({
      envelope: tampered,
      eventId: vector.eventId,
      inviteeId: vector.inviteeId,
      allowedInviteeIds: vector.allowedInviteeIds,
      accountRootSecret: protocol.base64UrlToBytes(vector.accountRootSecret),
      policy: vector.policy,
    }),
    /device authorization/u,
  );
});

test("the cross-platform vector rejects a forged response authorization", async () => {
  const vector = fixture.vectors[0];
  const first = vector.envelope.responseSignature[0];
  const forged = {
    ...vector.envelope,
    responseSignature: `${first === "A" ? "B" : "A"}${vector.envelope.responseSignature.slice(1)}`,
  };

  await assert.rejects(
    privateResponseCrypto.openPrivateResponse({
      envelope: forged,
      eventId: vector.eventId,
      inviteeId: vector.inviteeId,
      allowedInviteeIds: vector.allowedInviteeIds,
      accountRootSecret: protocol.base64UrlToBytes(vector.accountRootSecret),
      policy: vector.policy,
    }),
    /device authorization/u,
  );
});

test("the cross-platform vector rejects an uncertified frozen policy", async () => {
  const vector = fixture.vectors[0];
  await assert.rejects(
    privateResponseCrypto.openPrivateResponse({
      envelope: vector.envelope,
      eventId: vector.eventId,
      inviteeId: vector.inviteeId,
      allowedInviteeIds: vector.allowedInviteeIds,
      accountRootSecret: protocol.base64UrlToBytes(vector.accountRootSecret),
      policy: { ...vector.policy, policySignature: null },
    }),
    /not certified/u,
  );
});
