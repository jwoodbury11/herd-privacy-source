import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import {
  POLICY_SIGNATURE_DOMAIN,
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_HEAD_DOMAIN,
  TRANSPARENCY_LOG_ID,
  TRANSPARENCY_RECEIPT_DOMAIN,
} from "../src/constants.mjs";
import {
  domainSeparatedBytes,
  sha256Base64Url,
} from "../src/encoding.mjs";
import {
  signPolicyDescriptor,
  signTransparencyPayload,
} from "../src/signing.mjs";
import {
  canonicalPolicyDocument,
  makeKeyStore,
  publicKeyFromMetadata,
  responseAuthorization,
  testConfig,
} from "./helpers.mjs";

async function verify(publicKey, domain, payload, encodedSignature) {
  return webcrypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    publicKey,
    Buffer.from(encodedSignature, "base64url"),
    domainSeparatedBytes(domain, payload),
  );
}

test("policy signatures bind the canonical descriptor to the dedicated key", async () => {
  const config = testConfig();
  const keyStore = await makeKeyStore(config);
  const canonicalDocument = canonicalPolicyDocument(config, keyStore);
  const result = await signPolicyDescriptor({
    canonicalDocument,
    config,
    keyStore,
  });
  assert.equal(result.domain, POLICY_SIGNATURE_DOMAIN);
  assert.equal(result.signingKeyId, keyStore.metadata.keys.policySigning.keyId);
  assert.equal(Buffer.from(result.signature, "base64url").length, 64);
  const publicKey = await publicKeyFromMetadata(
    keyStore.metadata.keys.policySigning,
  );
  assert.equal(
    await verify(publicKey, POLICY_SIGNATURE_DOMAIN, canonicalDocument, result.signature),
    true,
  );
  assert.equal(
    await verify(
      publicKey,
      TRANSPARENCY_RECEIPT_DOMAIN,
      canonicalDocument,
      result.signature,
    ),
    false,
  );
});

test("receipt and log-head signatures are independently domain separated", async () => {
  const keyStore = await makeKeyStore();
  const signingKeyId = keyStore.metadata.keys.transparencySigning.keyId;
  const unsignedReceipt = {
    protocolVersion: 1,
    envelopeId: "40000000-0000-4000-8000-000000000001",
    eventId: "10000000-0000-4000-8000-000000000001",
    inviteeId: "20000000-0000-4000-8000-000000000001",
    policyHash: Buffer.alloc(32, 6).toString("base64url"),
    accountKeyEpochId: "30000000-0000-4000-8000-000000000001",
    revision: 1,
    ciphertextHash: Buffer.alloc(32, 7).toString("base64url"),
  };
  const receiptCore = {
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    logIndex: 1,
    previousEntryHash: Buffer.alloc(32).toString("base64url"),
    envelopeId: unsignedReceipt.envelopeId,
    eventId: unsignedReceipt.eventId,
    inviteeId: unsignedReceipt.inviteeId,
    policyHash: unsignedReceipt.policyHash,
    accountKeyEpochId: unsignedReceipt.accountKeyEpochId,
    revision: unsignedReceipt.revision,
    ciphertextHash: unsignedReceipt.ciphertextHash,
    ...responseAuthorization(unsignedReceipt),
    committedAt: "2026-01-01T00:00:00.000Z",
  };
  const entryHash = sha256Base64Url(
    domainSeparatedBytes(
      TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
      JSON.stringify(receiptCore),
    ),
  );
  const receiptPayload = JSON.stringify({
    protocolVersion: receiptCore.protocolVersion,
    logId: receiptCore.logId,
    logIndex: receiptCore.logIndex,
    previousEntryHash: receiptCore.previousEntryHash,
    entryHash,
    envelopeId: receiptCore.envelopeId,
    eventId: receiptCore.eventId,
    inviteeId: receiptCore.inviteeId,
    policyHash: receiptCore.policyHash,
    accountKeyEpochId: receiptCore.accountKeyEpochId,
    revision: receiptCore.revision,
    ciphertextHash: receiptCore.ciphertextHash,
    responseSigningPublicKey: receiptCore.responseSigningPublicKey,
    responseSignature: receiptCore.responseSignature,
    committedAt: receiptCore.committedAt,
    signingKeyId,
  });
  const logHeadPayload = JSON.stringify({
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    treeSize: 1,
    headEntryHash: entryHash,
    generatedAt: "2026-01-01T00:00:01.000Z",
    signingKeyId,
  });
  const receipt = await signTransparencyPayload({
    kind: "receipt",
    canonicalPayload: receiptPayload,
    keyStore,
  });
  const logHead = await signTransparencyPayload({
    kind: "log_head",
    canonicalPayload: logHeadPayload,
    keyStore,
  });
  assert.equal(receipt.domain, TRANSPARENCY_RECEIPT_DOMAIN);
  assert.equal(logHead.domain, TRANSPARENCY_LOG_HEAD_DOMAIN);
  const publicKey = await publicKeyFromMetadata(
    keyStore.metadata.keys.transparencySigning,
  );
  assert.equal(
    await verify(
      publicKey,
      TRANSPARENCY_RECEIPT_DOMAIN,
      receiptPayload,
      receipt.signature,
    ),
    true,
  );
  assert.equal(
    await verify(
      publicKey,
      TRANSPARENCY_LOG_HEAD_DOMAIN,
      receiptPayload,
      receipt.signature,
    ),
    false,
  );
});

test("transparency signer rejects arbitrary JSON and inconsistent chain fields", async () => {
  const keyStore = await makeKeyStore();
  await assert.rejects(
    signTransparencyPayload({
      kind: "receipt",
      canonicalPayload: JSON.stringify({ sequence: 7, rootHash: "abc" }),
      keyStore,
    }),
    (error) => error?.code === "invalid_request",
  );
  await assert.rejects(
    signTransparencyPayload({
      kind: "log_head",
      canonicalPayload: JSON.stringify({
        protocolVersion: 1,
        logId: TRANSPARENCY_LOG_ID,
        treeSize: 1,
        headEntryHash: Buffer.alloc(32, 9).toString("base64url"),
        generatedAt: "2026-01-01T00:00:00.000Z",
        signingKeyId: "wrong-key",
      }),
      keyStore,
    }),
    (error) => error?.code === "invalid_request",
  );
  await assert.rejects(
    signTransparencyPayload({
      kind: "log_head",
      canonicalPayload: JSON.stringify({
        protocolVersion: 1,
        logId: TRANSPARENCY_LOG_ID,
        treeSize: 1,
        headEntryHash: Buffer.alloc(32).toString("base64url"),
        generatedAt: "2026-01-01T00:00:00.000Z",
        signingKeyId: keyStore.metadata.keys.transparencySigning.keyId,
      }),
      keyStore,
    }),
    (error) => error?.code === "invalid_request",
  );
});

test("policy signer rejects descriptors for another release or evaluator key", async () => {
  const config = testConfig();
  const keyStore = await makeKeyStore(config);
  const parsed = JSON.parse(canonicalPolicyDocument(config, keyStore));
  parsed.releaseId = "other-release";
  await assert.rejects(
    signPolicyDescriptor({
      canonicalDocument: JSON.stringify(parsed),
      config,
      keyStore,
    }),
    (error) => error?.code === "invalid_request",
  );
});

test("policy signer rejects names and phone-derived assignments in immutable membership", async () => {
  const config = testConfig();
  const keyStore = await makeKeyStore(config);
  const parsed = JSON.parse(canonicalPolicyDocument(config, keyStore));
  parsed.members[0].displayName = "Must remain deletable";
  parsed.members[0].phoneAssignment = Buffer.alloc(32, 9).toString("base64url");
  await assert.rejects(
    signPolicyDescriptor({
      canonicalDocument: JSON.stringify(parsed),
      config,
      keyStore,
    }),
    (error) => error?.code === "invalid_request",
  );
});
