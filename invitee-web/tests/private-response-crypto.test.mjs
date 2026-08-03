import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const testsDirectory = fileURLToPath(new URL(".", import.meta.url));
const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryDirectory = await mkdtemp(join(tmpdir(), "herd-private-response-"));

after(async () => {
  await rm(temporaryDirectory, { recursive: true, force: true });
});

async function transpile(sourceName, outputName, replacements = []) {
  let source = await readFile(join(projectRoot, sourceName), "utf8");
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
  await writeFile(join(temporaryDirectory, outputName), output);
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

const protocol = await import(new URL(`file://${join(temporaryDirectory, "protocol.mjs")}`));
const vaultModule = await import(
  new URL(`file://${join(temporaryDirectory, "device-vault.mjs")}`)
);

function randomBytes(length) {
  return crypto.getRandomValues(new Uint8Array(length));
}

async function sha256Base64Url(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return protocol.bytesToBase64Url(new Uint8Array(digest));
}

async function signingKeyFixture(keyId) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    keyId,
    keyPair,
    publicKey: protocol.bytesToBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
    ),
  };
}

async function signPolicy(privateKey, canonicalDocument) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        protocol.domainSeparatedUtf8(
          protocol.PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
          canonicalDocument,
        ),
      ),
    ),
  );
}

async function replaceEncryptedDraft(envelope, responseKeyBytes, draft) {
  const encoded = new TextEncoder().encode(JSON.stringify(draft));
  const plaintext = randomBytes(4_096);
  new DataView(plaintext.buffer).setUint16(0, encoded.length, false);
  plaintext.set(encoded, 2);
  const responseKey = await crypto.subtle.importKey(
    "raw",
    responseKeyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"],
  );
  const iv = randomBytes(12);
  const ciphertextAndTag = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        additionalData: protocol.privateResponseAad("payload", envelope),
        tagLength: 128,
      },
      responseKey,
      plaintext,
    ),
  );
  plaintext.fill(0);
  return {
    ...envelope,
    payloadCiphertext: protocol.bytesToBase64Url(
      protocol.concatenateBytes(iv, ciphertextAndTag),
    ),
  };
}

test("web client seals a fixed-size response that both the user and evaluator can open", async () => {
  const evaluator = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveBits"],
  );
  const evaluatorPublicKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", evaluator.publicKey),
  );
  const evaluatorKeyId = "test-evaluator-v1";
  const policySigning = await signingKeyFixture("test-policy-signing-v1");
  const transparencySigning = await signingKeyFixture(
    "test-transparency-signing-v1",
  );
  assert.notEqual(policySigning.publicKey, transparencySigning.publicKey);
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID = evaluatorKeyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY =
    protocol.bytesToBase64Url(evaluatorPublicKey);
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID =
    policySigning.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
    policySigning.publicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID =
    transparencySigning.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY =
    transparencySigning.publicKey;
  const cryptoModule = await import(
    new URL(`file://${join(temporaryDirectory, "private-response-crypto.mjs")}?roundtrip=1`)
  );

  const eventId = "40000000-0000-4000-8000-000000000001";
  const inviteeId = "50000000-0000-4000-8000-000000000001";
  const otherInviteeId = "50000000-0000-4000-8000-000000000002";
  const evaluatorPublicKeyBase64Url = protocol.bytesToBase64Url(evaluatorPublicKey);
  const canonicalDocument = JSON.stringify({
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    event: { id: eventId },
    members: [{ id: inviteeId }, { id: otherInviteeId }],
    hostRules: { minimumParticipants: 3, requiredGroups: [] },
    limits: { maximumParticipants: 3, paddedPlaintextBytes: 4_096 },
    evaluator: {
      keyId: evaluatorKeyId,
      publicKey: evaluatorPublicKeyBase64Url,
      measurement: "software-test-only",
    },
    releaseId: "test-release",
  });
  const policyHash = await sha256Base64Url(canonicalDocument);
  const policy = {
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    policyHash,
    canonicalDocument,
    evaluatorKeyId,
    evaluatorPublicKey: evaluatorPublicKeyBase64Url,
    evaluatorMeasurement: "software-test-only",
    releaseId: "test-release",
    paddedPlaintextBytes: 4096,
    frozenAt: new Date().toISOString(),
    policySigningKeyId: policySigning.keyId,
    policySignature: await signPolicy(
      policySigning.keyPair.privateKey,
      canonicalDocument,
    ),
  };
  const accountRootSecret = randomBytes(32);
  const accountKeyEpochId = "70000000-0000-4000-8000-000000000001";
  const groupId = "60000000-0000-4000-8000-000000000001";

  await assert.rejects(
    cryptoModule.sealPrivateResponse({
      eventId,
      inviteeId,
      accountKeyEpochId,
      revision: 1,
      response: "going",
      minimumParticipants: 3,
      requiredGroups: [],
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret,
      policy: { ...policy, policySignature: null },
    }),
    /not certified/u,
  );
  const tamperedPolicySignature = protocol.base64UrlToBytes(policy.policySignature);
  tamperedPolicySignature[0] ^= 1;
  await assert.rejects(
    cryptoModule.sealPrivateResponse({
      eventId,
      inviteeId,
      accountKeyEpochId,
      revision: 1,
      response: "going",
      minimumParticipants: 3,
      requiredGroups: [],
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret,
      policy: {
        ...policy,
        policySignature: protocol.bytesToBase64Url(tamperedPolicySignature),
      },
    }),
    /not certified/u,
  );

  for (const [minimumParticipants, expectedError] of [
    [2, /below the frozen host minimum/u],
    [4, /exceed the frozen participant maximum/u],
  ]) {
    await assert.rejects(
      cryptoModule.sealPrivateResponse({
        eventId,
        inviteeId,
        accountKeyEpochId,
        revision: 1,
        response: "going",
        minimumParticipants,
        requiredGroups: [],
        allowedInviteeIds: [inviteeId, otherInviteeId],
        accountRootSecret,
        policy,
      }),
      expectedError,
    );
  }

  const sealed = await cryptoModule.sealPrivateResponse({
    eventId,
    inviteeId,
    accountKeyEpochId,
    revision: 1,
    response: "going",
    minimumParticipants: 3,
    requiredGroups: [{ id: groupId, memberIDs: [otherInviteeId] }],
    allowedInviteeIds: [inviteeId, otherInviteeId],
    accountRootSecret,
    policy,
  });

  assert.equal(protocol.base64UrlToBytes(sealed.envelope.payloadCiphertext).length, 4_124);
  assert.equal(protocol.base64UrlToBytes(sealed.envelope.userKeyWrap).length, 60);
  assert.equal(protocol.base64UrlToBytes(sealed.envelope.evaluatorKeyWrap).length, 157);
  assert.equal(protocol.base64UrlToBytes(sealed.envelope.responseSigningPublicKey).length, 32);
  assert.equal(protocol.base64UrlToBytes(sealed.envelope.responseSignature).length, 64);
  const opened = await cryptoModule.openPrivateResponse({
    envelope: sealed.envelope,
    eventId,
    inviteeId,
    allowedInviteeIds: [inviteeId, otherInviteeId],
    accountRootSecret,
    policy,
  });
  assert.equal(opened.response, "going");
  assert.equal(opened.minimumParticipants, 3);
  assert.deepEqual(opened.requiredGroups, [
    { id: groupId, memberIDs: [otherInviteeId] },
  ]);

  const storedEnvelope = {
    ...sealed.envelope,
    ciphertextHash: await cryptoModule.privateResponseEnvelopeHash(sealed.envelope),
    createdAt: "2026-08-03T00:00:00.000Z",
    updatedAt: "2026-08-03T00:00:01.000Z",
  };
  const openedFromStored = await cryptoModule.openPrivateResponse({
    envelope: storedEnvelope,
    eventId,
    inviteeId,
    allowedInviteeIds: [inviteeId, otherInviteeId],
    accountRootSecret,
    policy,
  });
  assert.equal(openedFromStored.response, "going");
  await assert.rejects(
    cryptoModule.openPrivateResponse({
      envelope: { ...storedEnvelope, ciphertextHash: protocol.bytesToBase64Url(randomBytes(32)) },
      eventId,
      inviteeId,
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret,
      policy,
    }),
    /stored ciphertext hash/u,
  );
  await assert.rejects(
    cryptoModule.openPrivateResponse({
      envelope: { ...storedEnvelope, unexpected: true },
      eventId,
      inviteeId,
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret,
      policy,
    }),
    /unsupported fields/u,
  );

  const evaluatorWrap = protocol.base64UrlToBytes(sealed.envelope.evaluatorKeyWrap);
  const ephemeralPublicKey = evaluatorWrap.subarray(0, 65);
  const salt = evaluatorWrap.subarray(65, 97);
  const wrapIv = evaluatorWrap.subarray(97, 109);
  const wrappedResponseKey = evaluatorWrap.subarray(109);
  const importedEphemeral = await crypto.subtle.importKey(
    "raw",
    ephemeralPublicKey,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: importedEphemeral },
    evaluator.privateKey,
    256,
  );
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );
  const evaluatorIdBytes = new TextEncoder().encode(evaluatorKeyId);
  const evaluatorKek = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: protocol.concatenateBytes(
        protocol.privateResponseAad("evaluator-key-derivation", sealed.envelope),
        evaluatorIdBytes,
      ),
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const responseKeyBytes = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: wrapIv,
        additionalData: protocol.concatenateBytes(
          protocol.privateResponseAad("evaluator-key-wrap", sealed.envelope),
          evaluatorIdBytes,
          ephemeralPublicKey,
          salt,
        ),
        tagLength: 128,
      },
      evaluatorKek,
      wrappedResponseKey,
    ),
  );
  assert.equal(responseKeyBytes.length, 32);
  const payload = protocol.base64UrlToBytes(sealed.envelope.payloadCiphertext);
  const responseKey = await crypto.subtle.importKey(
    "raw",
    responseKeyBytes,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );
  const paddedPlaintext = new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: payload.subarray(0, 12),
        additionalData: protocol.privateResponseAad("payload", sealed.envelope),
        tagLength: 128,
      },
      responseKey,
      payload.subarray(12),
    ),
  );
  assert.equal(paddedPlaintext.length, 4_096);
  const jsonLength = new DataView(paddedPlaintext.buffer).getUint16(0, false);
  const evaluatorDraft = JSON.parse(
    new TextDecoder().decode(paddedPlaintext.subarray(2, 2 + jsonLength)),
  );
  assert.equal(evaluatorDraft.inviteeId, inviteeId);
  assert.equal(evaluatorDraft.response, "going");

  for (const minimumParticipants of [2, 4]) {
    const invalidEnvelope = await replaceEncryptedDraft(
      sealed.envelope,
      responseKeyBytes,
      { ...evaluatorDraft, minimumParticipants },
    );
    await assert.rejects(
      cryptoModule.openPrivateResponse({
        envelope: invalidEnvelope,
        eventId,
        inviteeId,
        allowedInviteeIds: [inviteeId, otherInviteeId],
        accountRootSecret,
        policy,
      }),
      /invalid device authorization/u,
    );
  }

  const second = await cryptoModule.sealPrivateResponse({
    eventId,
    inviteeId,
    accountKeyEpochId,
    revision: 2,
    response: "going",
    minimumParticipants: 3,
    requiredGroups: [{ id: groupId, memberIDs: [otherInviteeId] }],
    allowedInviteeIds: [inviteeId, otherInviteeId],
    accountRootSecret,
    policy,
  });
  assert.notEqual(second.envelope.payloadCiphertext, sealed.envelope.payloadCiphertext);
  assert.equal(
    second.envelope.responseSigningPublicKey,
    sealed.envelope.responseSigningPublicKey,
  );
  assert.notEqual(second.envelope.envelopeId, sealed.envelope.envelopeId);
  assert.notEqual(second.envelope.responseSignature, sealed.envelope.responseSignature);
  assert.equal(
    protocol.base64UrlToBytes(second.envelope.payloadCiphertext).length,
    protocol.base64UrlToBytes(sealed.envelope.payloadCiphertext).length,
  );

  const tamperedWrap = protocol.base64UrlToBytes(sealed.envelope.userKeyWrap);
  tamperedWrap[20] ^= 1;
  await assert.rejects(
    cryptoModule.openPrivateResponse({
      envelope: {
        ...sealed.envelope,
        userKeyWrap: protocol.bytesToBase64Url(tamperedWrap),
      },
      eventId,
      inviteeId,
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret,
      policy,
    }),
    /invalid device authorization/u,
  );
  await assert.rejects(
    cryptoModule.openPrivateResponse({
      envelope: sealed.envelope,
      eventId,
      inviteeId,
      allowedInviteeIds: [inviteeId, otherInviteeId],
      accountRootSecret: randomBytes(32),
      policy,
    }),
    (error) => {
      assert.equal(error.canStartOver, true);
      assert.match(error.message, /not authorized by this device/u);
      return true;
    },
  );
});

test("account-root-secret commitment uses the protocol's exact domain separation", async () => {
  const accountRootSecret = Uint8Array.from({ length: 32 }, (_, index) => index);
  const commitmentInput = protocol.concatenateBytes(
    new TextEncoder().encode("HERD-ARS-COMMITMENT-V1"),
    new Uint8Array([0]),
    accountRootSecret,
  );
  const expected = protocol.bytesToBase64Url(
    new Uint8Array(await crypto.subtle.digest("SHA-256", commitmentInput)),
  );
  assert.equal(
    await vaultModule.accountRootSecretCommitment(accountRootSecret),
    expected,
  );
});

test("browser flow persists only a non-exportable local key and sends only an envelope", async () => {
  const [page, vault] = await Promise.all([
    readFile(join(projectRoot, "app/page.tsx"), "utf8"),
    readFile(join(projectRoot, "lib/privacy/device-vault.ts"), "utf8"),
  ]);
  assert.match(page, /body: JSON\.stringify\(\{ envelope: sealed\.envelope \}\)/u);
  assert.doesNotMatch(page, /body: JSON\.stringify\(\{\s*response:/u);
  assert.match(page, /\/api\/account\/key-epoch\/initialize/u);
  assert.match(page, /\/api\/account\/key-epoch\/reset/u);
  assert.match(page, /accountKeyCommitment/u);
  assert.match(vault, /indexedDB\.open\(DATABASE_NAME/u);
  assert.match(vault, /false,\s*\["encrypt", "decrypt"\]/u);
  assert.match(vault, /HERD-ARS-COMMITMENT-V1/u);
  assert.doesNotMatch(vault, /localStorage|sessionStorage/u);
  assert.ok(testsDirectory.endsWith("tests/"));
});
