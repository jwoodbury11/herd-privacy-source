import { fileURLToPath } from "node:url";
import { loadPrivateResponseTestModules } from "../helpers/private-response-test-modules.mjs";

const projectRoot = fileURLToPath(new URL("../..", import.meta.url));

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function signingKey(keyId) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    keyId,
    keyPair,
    publicKey: base64Url(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
  };
}

const eventId = "40000000-0000-4000-8000-000000000101";
const inviteeIds = [
  "50000000-0000-4000-8000-000000000101",
  "50000000-0000-4000-8000-000000000102",
  "50000000-0000-4000-8000-000000000103",
];
const evaluatorKeyId = "herd-evaluator-live-v1";
const evaluatorPublicKey =
  "BHNbrGR_UH7htxqVZ71tGrzQYgqatUv7u7FceBCMMHO1nkvd9ccl3tenBrODAyZKBB3MozygfRap8T43B0NFHcY";
const canonicalDocument = JSON.stringify({
  protocolVersion: 1,
  cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
  event: { id: eventId },
  members: inviteeIds.map((id) => ({ id })),
  hostRules: { minimumParticipants: 2, requiredGroups: [] },
  limits: { maximumParticipants: 4, paddedPlaintextBytes: 4_096 },
  evaluator: {
    keyId: evaluatorKeyId,
    publicKey: evaluatorPublicKey,
    measurement: "software-interop-vector-v1",
  },
  releaseId: "cross-platform-vector-v1",
});
const digest = await crypto.subtle.digest(
  "SHA-256",
  new TextEncoder().encode(canonicalDocument),
);
const policySigning = await signingKey("interop-policy-signing-v1");
const transparencySigning = await signingKey("interop-transparency-signing-v1");
const policySignature = base64Url(
  await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    policySigning.keyPair.privateKey,
    new TextEncoder().encode(
      `HERD-POLICY-DESCRIPTOR-SIGNATURE-V1\0${canonicalDocument}`,
    ),
  ),
);

// The module reads release trust pins at import time. The generated fixture is
// self-certified, so sealing and every later reader verify the same fresh pin.
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID = policySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
  policySigning.publicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID =
  transparencySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY =
  transparencySigning.publicKey;

const { protocol, privateResponseCrypto, cleanup } =
  await loadPrivateResponseTestModules(projectRoot);

try {
  const policy = {
    protocolVersion: 1,
    cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
    policyHash: base64Url(digest),
    canonicalDocument,
    evaluatorKeyId,
    evaluatorPublicKey,
    evaluatorMeasurement: "software-interop-vector-v1",
    releaseId: "cross-platform-vector-v1",
    paddedPlaintextBytes: 4_096,
    frozenAt: "2026-08-02T00:00:00.000Z",
    policySigningKeyId: policySigning.keyId,
    policySignature,
  };
  const accountRootSecret = Uint8Array.from({ length: 32 }, (_, index) => index);
  const cases = [
    {
      name: "web-going-with-and-of-or-condition",
      inviteeId: inviteeIds[0],
      accountKeyEpochId: "70000000-0000-4000-8000-000000000101",
      revision: 7,
      response: "going",
      minimumParticipants: 3,
      requiredGroups: [
        {
          id: "60000000-0000-4000-8000-000000000101",
          memberIDs: [inviteeIds[1], inviteeIds[2]],
        },
      ],
    },
    {
      name: "web-cant-commit-with-empty-conditions",
      inviteeId: inviteeIds[2],
      accountKeyEpochId: "70000000-0000-4000-8000-000000000102",
      revision: 8,
      response: "cant_commit",
      minimumParticipants: null,
      requiredGroups: [],
    },
  ];

  const vectors = [];
  for (const vectorCase of cases) {
    const sealed = await privateResponseCrypto.sealPrivateResponse({
      eventId,
      inviteeId: vectorCase.inviteeId,
      accountKeyEpochId: vectorCase.accountKeyEpochId,
      revision: vectorCase.revision,
      response: vectorCase.response,
      minimumParticipants: vectorCase.minimumParticipants,
      requiredGroups: vectorCase.requiredGroups,
      allowedInviteeIds: inviteeIds,
      accountRootSecret,
      policy,
    });
    vectors.push({
      name: vectorCase.name,
      producer: "invitee-web Web Crypto",
      eventId,
      inviteeId: vectorCase.inviteeId,
      accountKeyEpochId: vectorCase.accountKeyEpochId,
      minimumAllowedParticipants: 2,
      allowedInviteeIds: inviteeIds,
      accountRootSecret: protocol.bytesToBase64Url(accountRootSecret),
      policy,
      envelope: sealed.envelope,
      expectedDraft: sealed.draft,
      expectedEnvelopeHash: await privateResponseCrypto.privateResponseEnvelopeHash(
        sealed.envelope,
      ),
    });
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        formatVersion: 1,
        trustPins: {
          policySigning: {
            keyId: policySigning.keyId,
            publicKey: policySigning.publicKey,
          },
          transparencySigning: {
            keyId: transparencySigning.keyId,
            publicKey: transparencySigning.publicKey,
          },
        },
        vectors,
      },
      null,
      2,
    )}\n`,
  );
} finally {
  await cleanup();
}
