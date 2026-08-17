import assert from "node:assert/strict";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { loadPrivateResponseTestModules } from "./helpers/private-response-test-modules.mjs";

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const { protocol, trustVerification, cleanup } =
  await loadPrivateResponseTestModules(projectRoot);

after(cleanup);

function encodedBytes(length, fill) {
  return protocol.bytesToBase64Url(new Uint8Array(length).fill(fill));
}

async function sign(privateKey, domain, canonicalPayload) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        privateKey,
        protocol.domainSeparatedUtf8(domain, canonicalPayload),
      ),
    ),
  );
}

async function publicationFixture() {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const pin = {
    keyId: "publication-test-transparency-v1",
    publicKey: protocol.bytesToBase64Url(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
    ),
  };
  const receiptCore = {
    envelopeId: "10000000-0000-4000-8000-000000000001",
    eventId: "20000000-0000-4000-8000-000000000001",
    inviteeId: "30000000-0000-4000-8000-000000000001",
    policyHash: encodedBytes(32, 0x21),
    accountKeyEpochId: "40000000-0000-4000-8000-000000000001",
    revision: 2,
    ciphertextHash: encodedBytes(32, 0x31),
    responseSigningPublicKey: encodedBytes(32, 0x51),
    responseSignature: encodedBytes(64, 0x61),
    committedAt: "2026-08-02T20:00:00.000Z",
  };
  const proofCore = {
    protocolVersion: 1,
    logId: "herd-response-log-v1",
    logIndex: 7,
    previousEntryHash: encodedBytes(32, 0x41),
  };
  const entryHash = protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        protocol.domainSeparatedUtf8(
          protocol.PRIVATE_RESPONSE_LOG_ENTRY_HASH_DOMAIN,
          protocol.canonicalPrivateResponseLogEntryCore(
            receiptCore,
            proofCore,
          ),
        ),
      ),
    ),
  );
  const signedProof = {
    ...proofCore,
    entryHash,
    signingKeyId: pin.keyId,
  };
  const receiptSignature = await sign(
    keyPair.privateKey,
    protocol.PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
    protocol.canonicalPrivateResponseReceiptPayload(receiptCore, signedProof),
  );
  const unsignedHead = {
    protocolVersion: 1,
    logId: proofCore.logId,
    treeSize: proofCore.logIndex,
    headEntryHash: entryHash,
    generatedAt: "2026-08-02T20:00:01.000Z",
    signingKeyId: pin.keyId,
  };
  const logHead = {
    ...unsignedHead,
    signature: await sign(
      keyPair.privateKey,
      protocol.PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
      protocol.canonicalPrivateResponseLogHeadPayload(unsignedHead),
    ),
  };
  const receipt = {
    ...receiptCore,
    transparency: {
      ...signedProof,
      receiptSignature,
      logHead,
    },
  };
  const publication = {
    protocolVersion: 1,
    logId: proofCore.logId,
    entries: [
      {
        logIndex: proofCore.logIndex,
        previousEntryHash: proofCore.previousEntryHash,
        entryHash,
        head: logHead,
      },
    ],
  };
  return { pin, publication, receipt };
}

function jsonResponse(payload, init = {}) {
  return new Response(JSON.stringify(payload), {
    status: init.status ?? 200,
    headers: {
      "content-type": "application/json",
      ...init.headers,
    },
  });
}

test("receipt publication requires the exact public hash and signed head", async (t) => {
  const { pin, publication, receipt } = await publicationFixture();
  const expectedPath =
    `/api/transparency/responses?after=${receipt.transparency.logIndex - 1}&limit=1`;

  await t.test("exact public head succeeds", async () => {
    await assert.doesNotReject(
      trustVerification.verifyPrivateResponseReceiptPublication(
        receipt,
        pin,
        async (path, init) => {
          assert.equal(path, expectedPath);
          assert.equal(init.method, "GET");
          assert.equal(init.credentials, "omit");
          assert.equal(init.redirect, "manual");
          assert.equal(init.cache, "no-store");
          assert.deepEqual(init.headers, { accept: "application/json" });
          return jsonResponse(publication);
        },
      ),
    );
  });

  const failures = [
    [
      "missing entry",
      { ...publication, entries: [] },
    ],
    [
      "forked entry hash",
      (() => {
        const forked = structuredClone(publication);
        forked.entries[0].entryHash = encodedBytes(32, 0x51);
        return forked;
      })(),
    ],
    [
      "forked signed head",
      (() => {
        const forked = structuredClone(publication);
        forked.entries[0].head.headEntryHash = encodedBytes(32, 0x61);
        return forked;
      })(),
    ],
  ];
  for (const [name, payload] of failures) {
    await t.test(name, async () => {
      await assert.rejects(
        trustVerification.verifyPrivateResponseReceiptPublication(
          receipt,
          pin,
          async () => jsonResponse(payload),
        ),
        trustVerification.PrivateResponseTrustError,
      );
    });
  }

  await t.test("redirect is rejected without following it", async () => {
    await assert.rejects(
      trustVerification.verifyPrivateResponseReceiptPublication(
        receipt,
        pin,
        async (_path, init) => {
          assert.equal(init.redirect, "manual");
          return new Response(null, {
            status: 302,
            headers: { location: "https://attacker.example/log" },
          });
        },
      ),
      trustVerification.PrivateResponseTrustError,
    );
  });

  await t.test("oversized body is rejected", async () => {
    await assert.rejects(
      trustVerification.verifyPrivateResponseReceiptPublication(
        receipt,
        pin,
        async () =>
          new Response(" ".repeat(32_769), {
            status: 200,
            headers: { "content-type": "application/json" },
          }),
      ),
      trustVerification.PrivateResponseTrustError,
    );
  });

  for (const [name, mutate] of [
    ["top-level extra field", (value) => { value.extra = true; }],
    ["entry extra field", (value) => { value.entries[0].extra = true; }],
    ["head extra field", (value) => { value.entries[0].head.extra = true; }],
  ]) {
    await t.test(name, async () => {
      const payload = structuredClone(publication);
      mutate(payload);
      await assert.rejects(
        trustVerification.verifyPrivateResponseReceiptPublication(
          receipt,
          pin,
          async () => jsonResponse(payload),
        ),
        trustVerification.PrivateResponseTrustError,
      );
    });
  }
});
