import assert from "node:assert/strict";
import { webcrypto } from "node:crypto";
import test from "node:test";

import { createEvaluatorApp } from "../src/app.mjs";
import {
  POLICY_SIGNATURE_DOMAIN,
  TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
  TRANSPARENCY_LOG_ID,
  TRANSPARENCY_RECONCILIATION_DOMAIN,
} from "../src/constants.mjs";
import { domainSeparatedBytes, sha256Base64Url } from "../src/encoding.mjs";
import { StatefulTransparencyAuthority } from "../src/transparency-authority.mjs";
import {
  authHeaders,
  canonicalPolicyDocument,
  InMemoryTransparencyStore,
  makeKeyStore,
  publicKeyFromMetadata,
  responseAuthorization,
  testConfig,
} from "./helpers.mjs";

function harness() {
  const config = testConfig();
  const attestations = [];
  const now = { value: "2026-01-01T00:00:00.000Z" };
  return makeKeyStore(config).then((keyStore) => {
    const transparencyAuthority = new StatefulTransparencyAuthority({
      store: new InMemoryTransparencyStore(),
      keyStore,
      clock: () => new Date(now.value),
    });
    return {
      config,
      keyStore,
      attestations,
      now,
      app: createEvaluatorApp({
        config,
        keyStore,
        clock: () => new Date(now.value),
        attestationProvider: {
          async attest(input) {
            attestations.push(input);
            return "fake-header.fake-payload.fake-signature";
          },
        },
        transparencyAuthority,
      }),
    };
  });
}

function post(path, body, headers = authHeaders()) {
  return new Request(`https://evaluator.test${path}`, {
    method: "POST",
    headers,
    body: JSON.stringify(body),
  });
}

function canonicalTransparencyReceipt(config, keyStore, discriminator) {
  const suffix = String(discriminator).padStart(12, "0");
  const envelopeId = `40000000-0000-4000-8000-${suffix}`;
  const eventId = `10000000-0000-4000-8000-${suffix}`;
  const inviteeId = `20000000-0000-4000-8000-${suffix}`;
  const policyHash =
    discriminator === 1
      ? sha256Base64Url(
          Buffer.from(canonicalPolicyDocument(config, keyStore), "utf8"),
        )
      : sha256Base64Url(Buffer.from(eventId, "utf8"));
  const accountKeyEpochId = `30000000-0000-4000-8000-${suffix}`;
  const ciphertextHash = Buffer.alloc(32, discriminator).toString("base64url");
  const authorization = responseAuthorization({
    protocolVersion: 1,
    eventId,
    inviteeId,
    policyHash,
    accountKeyEpochId,
    revision: 1,
    envelopeId,
    ciphertextHash,
  });
  const core = {
    protocolVersion: 1,
    logId: TRANSPARENCY_LOG_ID,
    logIndex: 1,
    previousEntryHash: Buffer.alloc(32).toString("base64url"),
    envelopeId,
    eventId,
    inviteeId,
    policyHash,
    accountKeyEpochId,
    revision: 1,
    ciphertextHash,
    ...authorization,
    committedAt: "2026-01-01T00:00:00.000Z",
  };
  const entryHash = sha256Base64Url(
    domainSeparatedBytes(
      TRANSPARENCY_LOG_ENTRY_HASH_DOMAIN,
      JSON.stringify(core),
    ),
  );
  return JSON.stringify({
    protocolVersion: core.protocolVersion,
    logId: core.logId,
    logIndex: core.logIndex,
    previousEntryHash: core.previousEntryHash,
    entryHash,
    envelopeId: core.envelopeId,
    eventId: core.eventId,
    inviteeId: core.inviteeId,
    policyHash: core.policyHash,
    accountKeyEpochId: core.accountKeyEpochId,
    revision: core.revision,
    ciphertextHash: core.ciphertextHash,
    responseSigningPublicKey: core.responseSigningPublicKey,
    responseSignature: core.responseSignature,
    committedAt: core.committedAt,
    signingKeyId: keyStore.metadata.keys.transparencySigning.keyId,
  });
}

test("health exposes only public key binding metadata", async () => {
  const { app, keyStore } = await harness();
  const response = await app(new Request("https://evaluator.test/healthz"));
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const body = await response.json();
  assert.equal(body.status, "ok");
  assert.deepEqual(body.keyBinding, keyStore.metadata);
  assert.equal(body.keyBindingHash, keyStore.keyBindingHash);
  assert.equal(JSON.stringify(body).includes("private"), false);
  const ready = await app(new Request("https://evaluator.test/readyz"));
  assert.equal(ready.status, 200);
});

test("backend signing POSTs require the decrypted bearer token", async () => {
  const { app } = await harness();
  for (const path of ["/api/v1/sign/policy", "/api/v1/sign/transparency"]) {
    const response = await app(
      post(path, { protocolVersion: 1 }, { "content-type": "application/json" }),
    );
    assert.equal(response.status, 401, path);
    assert.deepEqual(await response.json(), { error: { code: "unauthorized" } });
  }
});

test("challenge attestation binds the caller nonce and all four public keys", async () => {
  const { app, config, keyStore, attestations } = await harness();
  const nonce = Buffer.alloc(32, 9).toString("base64url");
  const response = await app(
    post(
      "/api/v1/attestation",
      { protocolVersion: 1, nonce },
      { "content-type": "application/json" },
    ),
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.audience, config.attestationAudience);
  assert.equal(body.nonce, nonce);
  assert.deepEqual(body.keyBinding, keyStore.metadata);
  assert.equal(body.keyBindingHash, keyStore.keyBindingHash);
  assert.deepEqual(attestations, [
    {
      audience: config.attestationAudience,
      nonces: [nonce, keyStore.keyBindingHash],
    },
  ]);
});

test("policy signing endpoint signs exact compact descriptors", async () => {
  const { app, config, keyStore } = await harness();
  const canonicalDocument = canonicalPolicyDocument(config, keyStore);
  const response = await app(
    post("/api/v1/sign/policy", {
      protocolVersion: 1,
      canonicalDocument,
    }),
  );
  assert.equal(response.status, 200);
  const proof = await response.json();
  assert.equal(proof.domain, POLICY_SIGNATURE_DOMAIN);
  const publicKey = await publicKeyFromMetadata(
    keyStore.metadata.keys.policySigning,
  );
  assert.equal(
    await webcrypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      Buffer.from(proof.signature, "base64url"),
      domainSeparatedBytes(POLICY_SIGNATURE_DOMAIN, canonicalDocument),
    ),
    true,
  );
});

test("transparency endpoint is policy-bound, append-only, and rejects former operations", async () => {
  const { app, config, keyStore } = await harness();
  const policyResponse = await app(
    post("/api/v1/sign/policy", {
      protocolVersion: 1,
      canonicalDocument: canonicalPolicyDocument(config, keyStore),
    }),
  );
  assert.equal(policyResponse.status, 200);
  const canonicalReceiptPayload = canonicalTransparencyReceipt(
    config,
    keyStore,
    1,
  );
  const first = await app(
    post("/api/v1/sign/transparency", {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload,
    }),
  );
  assert.equal(first.status, 200);
  const firstCertification = await first.json();
  const retry = await app(
    post("/api/v1/sign/transparency", {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload,
    }),
  );
  assert.equal(retry.status, 200);
  assert.deepEqual(await retry.json(), firstCertification);

  const conflict = await app(
    post("/api/v1/sign/transparency", {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: canonicalTransparencyReceipt(
        config,
        keyStore,
        2,
      ),
    }),
  );
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), {
    error: { code: "transparency_conflict" },
  });

  for (const kind of ["receipt", "log_head"]) {
    const formerOperation = await app(
      post("/api/v1/sign/transparency", {
        protocolVersion: 1,
        kind,
        canonicalReceiptPayload,
      }),
    );
    assert.equal(formerOperation.status, 400);
  }
});

test("a late response append receives the normal certified receipt", async () => {
  const { app, config, keyStore, now } = await harness();
  const policyResponse = await app(
    post("/api/v1/sign/policy", {
      protocolVersion: 1,
      canonicalDocument: canonicalPolicyDocument(config, keyStore),
    }),
  );
  assert.equal(policyResponse.status, 200);
  const canonicalReceiptPayload = canonicalTransparencyReceipt(
    config,
    keyStore,
    1,
  );
  now.value = "2026-01-01T00:00:00.001Z";
  const response = await app(
    post("/api/v1/sign/transparency", {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload,
    }),
  );
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.equal(body.protocolVersion, 1);
  assert.equal(body.kind, "append");

  const malformed = JSON.parse(canonicalReceiptPayload);
  malformed.entryHash = Buffer.alloc(32, 9).toString("base64url");
  const invalid = await app(
    post("/api/v1/sign/transparency", {
      protocolVersion: 1,
      kind: "append",
      canonicalReceiptPayload: JSON.stringify(malformed),
    }),
  );
  assert.equal(invalid.status, 400);
  assert.deepEqual(await invalid.json(), { error: { code: "invalid_request" } });
});

test("the production direct evaluation endpoint is disabled", async () => {
  const { app } = await harness();
  const response = await app(post("/api/v1/evaluate", { protocolVersion: 1 }));
  assert.equal(response.status, 404);
  assert.deepEqual(await response.json(), { error: { code: "not_found" } });
});

test("browser origins are exact and preflight is bounded", async () => {
  const { app, config } = await harness();
  const rejected = await app(
    new Request("https://evaluator.test/api/v1/attestation", {
      method: "OPTIONS",
      headers: {
        origin: "https://evil.example",
        "access-control-request-method": "POST",
      },
    }),
  );
  assert.equal(rejected.status, 403);
  const accepted = await app(
    new Request("https://evaluator.test/api/v1/attestation", {
      method: "OPTIONS",
      headers: {
        origin: config.allowedOrigin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, content-type",
      },
    }),
  );
  assert.equal(accepted.status, 204);
  assert.equal(
    accepted.headers.get("access-control-allow-origin"),
    config.allowedOrigin,
  );
});

test("policy and transparency signing are server-only even for the allowed origin", async () => {
  const { app, config, keyStore } = await harness();
  const policy = await app(
    post(
      "/api/v1/sign/policy",
      {
        protocolVersion: 1,
        canonicalDocument: canonicalPolicyDocument(config, keyStore),
      },
      authHeaders({ origin: config.allowedOrigin }),
    ),
  );
  assert.equal(policy.status, 403);
  const preflightResponse = await app(
    new Request("https://evaluator.test/api/v1/sign/transparency", {
      method: "OPTIONS",
      headers: {
        origin: config.allowedOrigin,
        "access-control-request-method": "POST",
        "access-control-request-headers": "authorization, content-type",
      },
    }),
  );
  assert.equal(preflightResponse.status, 403);
});
