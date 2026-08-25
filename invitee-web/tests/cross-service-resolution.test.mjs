import assert from "node:assert/strict";
import { fork } from "node:child_process";
import { mkdtemp, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { createFetchMock, Miniflare } from "miniflare";
import ts from "typescript";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const workspaceRoot = fileURLToPath(new URL("../../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const evaluatorHelper = path.join(
  projectRoot,
  "tests/helpers/evaluator-service-process.mjs",
);
const temporaryDirectory = await mkdtemp(
  path.join(tmpdir(), "herd-cross-service-resolution-"),
);

const HOST_PHONE = "+14155550187";
const TWILIO_API_KEY_SID = `SK${"7".repeat(32)}`;
const TWILIO_VERIFY_SERVICE_SID = `VA${"8".repeat(32)}`;
const TWILIO_ACCOUNT_SID = `AC${"6".repeat(32)}`;
const TWILIO_MESSAGING_SERVICE_SID = `MG${"5".repeat(32)}`;
const TEST_PEPPER = "herd-cross-service-pepper-0123456789-abcdefghijklmnopqrstuvwxyz";
const EVALUATOR_KEY_ID = "herd-cross-service-evaluator-v1";
const EVALUATOR_MEASUREMENT = "cross-service-software-evaluator-sha384";
const RELEASE_ID = "herd-cross-service-release-v1";
const EVALUATOR_TOKEN =
  "herd-cross-service-token-0123456789-abcdefghijklmnopqrstuvwxyz";
const EVALUATOR_PUBLIC_URL = "https://evaluator.test/api/v1/evaluate";
const EVALUATOR_RELAY_URL = "https://evaluator.test/api/v1/relay/";
const EVALUATOR_SIGNING_KEY_ID = "herd-cross-service-result-v1";
const POLICY_SIGNING_KEY_ID = "herd-cross-service-policy-v1";
const TRANSPARENCY_SIGNING_KEY_ID = "herd-cross-service-transparency-v1";
const SCHEDULER_TOKEN =
  "herd_scheduler_test_token_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const CONFIRMED_EVENT_ID = "92000000-0000-4000-8000-000000000001";
const FAILED_EVENT_ID = "96000000-0000-4000-8000-000000000001";
const POISON_EVENT_ID = "a0000000-0000-4000-8000-000000000001";
const SCHEDULED_DUE_EVENT_ID = "d2000000-0000-4000-8000-000000000001";
const SCHEDULED_FUTURE_EVENT_ID = "d2000000-0000-4000-8000-000000000002";
const SCHEDULED_RETRY_EVENT_ID = "e2000000-0000-4000-8000-000000000001";
const COURIER_DUE_EVENT_ID = "f2000000-0000-4000-8000-000000000001";
const COURIER_FUTURE_EVENT_ID = "f2000000-0000-4000-8000-000000000002";
const COURIER_CONCURRENT_EVENT_ID = "f3000000-0000-4000-8000-000000000001";
const COURIER_OTHER_EVENT_ID = "f3000000-0000-4000-8000-000000000002";
const COURIER_RELEASE_EVENT_ID = "f4000000-0000-4000-8000-000000000001";

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

const protocol = await import(
  new URL(`file://${path.join(temporaryDirectory, "protocol.mjs")}`)
);
const vault = await import(
  new URL(`file://${path.join(temporaryDirectory, "device-vault.mjs")}`)
);

function derElement(tag, value) {
  assert.ok(value.length < 128);
  return Buffer.concat([Buffer.from([tag, value.length]), Buffer.from(value)]);
}

function sec1Pem(privateJwk) {
  const publicPoint = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(privateJwk.x, "base64url"),
    Buffer.from(privateJwk.y, "base64url"),
  ]);
  const curveOid = derElement(
    0x06,
    Buffer.from([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
  );
  const body = Buffer.concat([
    derElement(0x02, Buffer.from([0x01])),
    derElement(0x04, Buffer.from(privateJwk.d, "base64url")),
    derElement(0xa0, curveOid),
    derElement(
      0xa1,
      derElement(0x03, Buffer.concat([Buffer.from([0x00]), publicPoint])),
    ),
  ]);
  const encoded = derElement(0x30, body).toString("base64");
  const lines = encoded.match(/.{1,64}/gu);
  assert.ok(lines);
  return `-----BEGIN EC PRIVATE KEY-----\n${lines.join("\n")}\n-----END EC PRIVATE KEY-----`;
}

async function ecdsaSigningFixture(keyId) {
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

const evaluatorKeyPair = await crypto.subtle.generateKey(
  { name: "ECDH", namedCurve: "P-256" },
  true,
  ["deriveBits"],
);
const evaluatorPrivateJwk = await crypto.subtle.exportKey(
  "jwk",
  evaluatorKeyPair.privateKey,
);
const evaluatorPrivatePem = sec1Pem(evaluatorPrivateJwk);
const evaluatorPublicKey = protocol.bytesToBase64Url(
  new Uint8Array(await crypto.subtle.exportKey("raw", evaluatorKeyPair.publicKey)),
);
const evaluatorSigningKeyPair = await crypto.subtle.generateKey(
  { name: "ECDSA", namedCurve: "P-256" },
  true,
  ["sign", "verify"],
);
const evaluatorSigningPrivateJwk = await crypto.subtle.exportKey(
  "jwk",
  evaluatorSigningKeyPair.privateKey,
);
const evaluatorSigningPublicKey = protocol.bytesToBase64Url(
  new Uint8Array(
    await crypto.subtle.exportKey("raw", evaluatorSigningKeyPair.publicKey),
  ),
);
const policySigning = await ecdsaSigningFixture(POLICY_SIGNING_KEY_ID);
const transparencySigning = await ecdsaSigningFixture(
  TRANSPARENCY_SIGNING_KEY_ID,
);
assert.notEqual(policySigning.publicKey, transparencySigning.publicKey);
process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID = EVALUATOR_KEY_ID;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY = evaluatorPublicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID =
  policySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
  policySigning.publicKey;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID =
  transparencySigning.keyId;
process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY =
  transparencySigning.publicKey;
const responseCrypto = await import(
  new URL(
    `file://${path.join(temporaryDirectory, "private-response-crypto.mjs")}?cross-service=1`,
  ),
);
const trustVerification = await import(
  new URL(
    `file://${path.join(temporaryDirectory, "trust-verification.mjs")}?cross-service=1`,
  ),
);

const ED25519_PKCS8_SEED_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

async function authorizeMutatedResponseEnvelope(envelope, accountRootSecret) {
  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    accountRootSecret,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const seed = new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: protocol.base64UrlToBytes(envelope.policyHash),
        info: protocol.concatenateBytes(
          new TextEncoder().encode("HERD-RESPONSE-SIGNING-SEED-V1"),
          new Uint8Array([0]),
          protocol.uuidToBytes(envelope.eventId),
          protocol.uuidToBytes(envelope.inviteeId),
        ),
      },
      hkdfKey,
      256,
    ),
  );
  const pkcs8 = protocol.concatenateBytes(ED25519_PKCS8_SEED_PREFIX, seed);
  try {
    const signingKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const ciphertextHash = protocol.bytesToBase64Url(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(protocol.canonicalEnvelopeJson(envelope)),
        ),
      ),
    );
    return {
      ...envelope,
      responseSignature: protocol.bytesToBase64Url(
        new Uint8Array(
          await crypto.subtle.sign(
            { name: "Ed25519" },
            signingKey,
            protocol.privateResponseAuthorizationBytes(envelope, ciphertextHash),
          ),
        ),
      ),
    };
  } finally {
    seed.fill(0);
    pkcs8.fill(0);
  }
}

function jsonRequest(method, body, accessToken) {
  return {
    method,
    headers: {
      "content-type": "application/json",
      origin: "https://herd.test",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify(body),
  };
}

function authorizedRequest(accessToken) {
  return { headers: { authorization: `Bearer ${accessToken}` } };
}

function chunkedBody(totalBytes, chunkBytes = 16 * 1024) {
  let emitted = 0;
  return new ReadableStream({
    pull(controller) {
      if (emitted >= totalBytes) {
        controller.close();
        return;
      }
      const length = Math.min(chunkBytes, totalBytes - emitted);
      emitted += length;
      controller.enqueue(new Uint8Array(length).fill(0x78));
    },
  });
}

function api(miniflare, pathname, init = {}) {
  return miniflare.dispatchFetch(`https://herd.test${pathname}`, init);
}

function schedulerRequest(token = SCHEDULER_TOKEN, body) {
  return {
    method: "POST",
    headers: {
      authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { "content-type": "application/json" }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  };
}

async function javascriptModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await javascriptModules(entryPath)));
    else if (entry.name.endsWith(".js")) files.push(entryPath);
  }
  return files;
}

async function trustSignature(keyPair, domain, canonicalPayload) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        keyPair.privateKey,
        protocol.domainSeparatedUtf8(domain, canonicalPayload),
      ),
    ),
  );
}

async function trustPayloadHash(canonicalPayload) {
  return protocol.bytesToBase64Url(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonicalPayload),
      ),
    ),
  );
}

function installEvaluatorTrustSigningTransport(fetchMock, signingRequests) {
  fetchMock.disableNetConnect();
  const evaluatorOrigin = fetchMock.get("https://evaluator.test");
  const appendResponses = new Map();
  let lastLogIndex = 0;
  let lastEntryHash = protocol.bytesToBase64Url(new Uint8Array(32));
  const appendCertification = async (canonicalReceiptPayload) => {
    const receipt = JSON.parse(canonicalReceiptPayload);
    assert.equal(JSON.stringify(receipt), canonicalReceiptPayload);
    assert.deepEqual(Object.keys(receipt).sort(), [
      "accountKeyEpochId",
      "ciphertextHash",
      "committedAt",
      "entryHash",
      "envelopeId",
      "eventId",
      "inviteeId",
      "logId",
      "logIndex",
      "policyHash",
      "previousEntryHash",
      "protocolVersion",
      "responseSignature",
      "responseSigningPublicKey",
      "revision",
      "signingKeyId",
    ]);
    assert.equal(receipt.protocolVersion, 1);
    assert.equal(receipt.logId, "herd-response-log-v1");
    assert.equal(receipt.logIndex, lastLogIndex + 1);
    assert.equal(receipt.previousEntryHash, lastEntryHash);
    assert.equal(receipt.signingKeyId, transparencySigning.keyId);
    lastLogIndex = receipt.logIndex;
    lastEntryHash = receipt.entryHash;
    const canonicalHeadPayload = protocol.canonicalPrivateResponseLogHeadPayload({
      protocolVersion: 1,
      logId: receipt.logId,
      treeSize: receipt.logIndex,
      headEntryHash: receipt.entryHash,
      generatedAt: new Date().toISOString(),
      signingKeyId: transparencySigning.keyId,
    });
    const [receiptSignature, headSignature] = await Promise.all([
      trustSignature(
        transparencySigning.keyPair,
        protocol.PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
        canonicalReceiptPayload,
      ),
      trustSignature(
        transparencySigning.keyPair,
        protocol.PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
        canonicalHeadPayload,
      ),
    ]);
    return JSON.stringify({
      protocolVersion: 1,
      kind: "append",
      signingKeyId: transparencySigning.keyId,
      receipt: {
        domain: protocol.PRIVATE_RESPONSE_RECEIPT_SIGNATURE_DOMAIN,
        payloadHash: await trustPayloadHash(canonicalReceiptPayload),
        signature: receiptSignature,
      },
      logHead: {
        canonicalPayload: canonicalHeadPayload,
        domain: protocol.PRIVATE_RESPONSE_LOG_HEAD_SIGNATURE_DOMAIN,
        payloadHash: await trustPayloadHash(canonicalHeadPayload),
        signature: headSignature,
      },
    });
  };
  evaluatorOrigin
    .intercept({
      method: "POST",
      path: /^\/api\/v1\/sign\/policy\/?$/u,
    })
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        assert.equal(headers.get("authorization"), `Bearer ${EVALUATOR_TOKEN}`);
        assert.equal(headers.get("content-type"), "application/json");
        const body = JSON.parse(await new Response(request.body).text());
        assert.deepEqual(Object.keys(body).sort(), [
          "canonicalDocument",
          "protocolVersion",
        ]);
        assert.equal(body.protocolVersion, 1);
        signingRequests.push("policy");
        return JSON.stringify({
          protocolVersion: 1,
          domain: protocol.PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
          signingKeyId: policySigning.keyId,
          payloadHash: await trustPayloadHash(body.canonicalDocument),
          signature: await trustSignature(
            policySigning.keyPair,
            protocol.PRIVATE_RESPONSE_POLICY_SIGNATURE_DOMAIN,
            body.canonicalDocument,
          ),
        });
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
  evaluatorOrigin
    .intercept({
      method: "POST",
      path: /^\/api\/v1\/sign\/transparency\/?$/u,
    })
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        assert.equal(headers.get("authorization"), `Bearer ${EVALUATOR_TOKEN}`);
        assert.equal(headers.get("content-type"), "application/json");
        const body = JSON.parse(await new Response(request.body).text());
        assert.deepEqual(Object.keys(body).sort(), [
          "canonicalReceiptPayload",
          "kind",
          "protocolVersion",
        ]);
        assert.equal(body.protocolVersion, 1);
        assert.equal(body.kind, "append");
        assert.equal(typeof body.canonicalReceiptPayload, "string");
        signingRequests.push(body.kind);
        let certification = appendResponses.get(body.canonicalReceiptPayload);
        if (!certification) {
          certification = appendCertification(body.canonicalReceiptPayload);
          appendResponses.set(body.canonicalReceiptPayload, certification);
        }
        return certification;
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
}

async function createBackendHarness(fetchMock, bindingOverrides = {}) {
  const trustSigningRequests = [];
  installEvaluatorTrustSigningTransport(fetchMock, trustSigningRequests);
  const twilio = fetchMock.get("https://verify.twilio.com");
  twilio
    .intercept({
      method: "POST",
      path: `/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/Verifications`,
    })
    .reply(201, { sid: `VE${"9".repeat(32)}`, status: "pending" })
    .persist();
  fetchMock
    .get("https://api.twilio.com")
    .intercept({
      method: "POST",
      path: `/2010-04-01/Accounts/${TWILIO_ACCOUNT_SID}/Messages.json`,
    })
    .reply(201, { sid: `SM${"4".repeat(32)}`, status: "accepted" })
    .persist();
  twilio
    .intercept({
      method: "POST",
      path: `/v2/Services/${TWILIO_VERIFY_SERVICE_SID}/VerificationCheck`,
    })
    .reply(200, { sid: `VE${"9".repeat(32)}`, status: "approved", valid: true })
    .persist();
  const modulePaths = await javascriptModules(serverRoot);
  modulePaths.sort((left, right) => {
    const entry = path.join(serverRoot, "index.js");
    if (left === entry) return -1;
    if (right === entry) return 1;
    return left.localeCompare(right);
  });
  const miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    d1Databases: {
      DB: `herd-cross-service-${process.pid}-${Date.now()}`,
    },
    fetchMock,
    bindings: {
      HERD_DEPLOYMENT_PROFILE: "test",
      HERD_AUTH_PEPPER: TEST_PEPPER,
      HERD_TEST_ACCOUNT_ACCESS_ENABLED: "true",
      HERD_TEST_ACCOUNT_ACCESS_GENERATION: "herd-test-generation-v1",
      HERD_TEST_HOST_PHONE_E164: "+14155550111",
      TWILIO_API_KEY_SID,
      TWILIO_API_KEY_SECRET: "cross-service-twilio-secret",
      TWILIO_VERIFY_SERVICE_SID,
      TWILIO_ACCOUNT_SID,
      TWILIO_MESSAGING_SERVICE_SID,
      HERD_PUBLIC_APP_URL: "https://app.herdprivacy.com",
      HERD_EVALUATOR_KEY_ID: EVALUATOR_KEY_ID,
      HERD_EVALUATOR_PUBLIC_KEY: evaluatorPublicKey,
      HERD_EVALUATOR_MEASUREMENT: EVALUATOR_MEASUREMENT,
      HERD_RELEASE_ID: RELEASE_ID,
      HERD_ARTIFACT_RELEASE_ID: "2026.08.12.cross-service",
      HERD_EVALUATOR_URL: EVALUATOR_PUBLIC_URL,
      HERD_EVALUATOR_TOKEN: EVALUATOR_TOKEN,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
      HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: policySigning.keyId,
      HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: policySigning.publicKey,
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID: transparencySigning.keyId,
      HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
        transparencySigning.publicKey,
      HERD_SCHEDULER_TOKEN: SCHEDULER_TOKEN,
      ...bindingOverrides,
    },
  });
  const database = await miniflare.getD1Database("DB");
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(
      path.join(migrationDirectory, migrationFile),
      "utf8",
    );
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return { miniflare, database, trustSigningRequests };
}

async function startEvaluatorService() {
  const child = fork(evaluatorHelper, [], {
    cwd: workspaceRoot,
    stdio: ["ignore", "ignore", "ignore", "ipc"],
  });
  const ready = new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Evaluator service did not start in time."));
    }, 15_000);
    const onExit = () => {
      clearTimeout(timeout);
      reject(new Error("Evaluator service stopped before becoming ready."));
    };
    child.once("exit", onExit);
    child.on("message", (message) => {
      if (message?.type === "ready") {
        clearTimeout(timeout);
        child.off("exit", onExit);
        resolve(message.url);
      } else if (message?.type === "error") {
        clearTimeout(timeout);
        child.off("exit", onExit);
        reject(new Error(message.message));
      }
    });
  });
  child.send({
    type: "start",
    bindings: {
      HERD_EVALUATOR_TOKEN: EVALUATOR_TOKEN,
      HERD_EVALUATOR_KEY_ID: EVALUATOR_KEY_ID,
      HERD_EVALUATOR_PRIVATE_KEY_PEM: evaluatorPrivatePem,
      HERD_EVALUATOR_MEASUREMENT: EVALUATOR_MEASUREMENT,
      HERD_RELEASE_ID: RELEASE_ID,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK: JSON.stringify(
        evaluatorSigningPrivateJwk,
      ),
      HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN: "https://herd.test",
    },
  });
  const url = await ready;
  return {
    url,
    async stop() {
      if (child.exitCode !== null || !child.connected) return;
      await new Promise((resolve) => {
        const timeout = setTimeout(() => {
          child.kill("SIGTERM");
          resolve();
        }, 5_000);
        child.once("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
        child.send({ type: "stop" });
      });
    },
  };
}

function installEvaluatorTransport(fetchMock, directBaseUrl, requestLog, responseLog) {
  fetchMock.disableNetConnect();
  fetchMock
    .get("https://evaluator.test")
    .intercept({
      method: "POST",
      path: "/api/v1/evaluate",
      headers: {
        authorization: `Bearer ${EVALUATOR_TOKEN}`,
        "content-type": "application/json",
      },
    })
    .reply(
      200,
      async (request) => {
        const requestBody = await new Response(request.body).text();
        requestLog.push(JSON.parse(requestBody));
        const response = await fetch(
          new URL("/api/v1/evaluate", directBaseUrl),
          {
            method: "POST",
            headers: {
              authorization: `Bearer ${EVALUATOR_TOKEN}`,
              "content-type": "application/json",
              accept: "application/json",
            },
            body: requestBody,
          },
        );
        const responseBody = await response.text();
        responseLog.push({
          status: response.status,
          body: JSON.parse(responseBody),
        });
        return responseBody;
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
}

function installEvaluatorRelayTransport(
  fetchMock,
  directBaseUrl,
  requestLog,
  responseLog,
  { delayMilliseconds = 0, failFirst = false } = {},
) {
  fetchMock.disableNetConnect();
  const evaluatorOrigin = fetchMock.get("https://evaluator.test");
  const matcher = () => ({
    method: "POST",
    path: "/api/v1/relay/",
  });

  if (failFirst) {
    evaluatorOrigin
      .intercept(matcher())
      .reply(
        503,
        async (request) => {
          const headers = new Headers(request.headers);
          assert.equal(headers.get("authorization"), null);
          assert.equal(headers.get("origin"), null);
          assert.equal(headers.get("content-type"), "application/json");
          const requestBody = await new Response(request.body).text();
          requestLog.push(JSON.parse(requestBody));
          responseLog.push({ status: 503 });
          return JSON.stringify({ error: { code: "temporarily_unavailable" } });
        },
        { headers: { "content-type": "application/json" } },
      )
      .times(1);
  }

  const scope = evaluatorOrigin
    .intercept(matcher())
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        assert.equal(headers.get("authorization"), null);
        assert.equal(headers.get("origin"), null);
        assert.equal(headers.get("content-type"), "application/json");
        const requestBody = await new Response(request.body).text();
        requestLog.push(JSON.parse(requestBody));
        const response = await fetch(
          new URL("/api/v1/relay/", directBaseUrl),
          {
            method: "POST",
            headers: {
              "content-type": "application/json",
              accept: "application/json",
            },
            body: requestBody,
          },
        );
        const responseBody = await response.text();
        responseLog.push({ status: response.status });
        assert.equal(response.status, 200);
        return responseBody;
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
  if (delayMilliseconds > 0) scope.delay(delayMilliseconds);
}

async function authenticate(miniflare, phoneNumber) {
  const fixedAccount = /^\+1415555010([1-9])$/u.exec(phoneNumber);
  const alias = /^[1-9]$/u.test(phoneNumber) ? phoneNumber : fixedAccount?.[1];
  const phoneInput = alias ?? phoneNumber;
  const response = await api(
    miniflare,
    "/api/auth/request-code",
    jsonRequest("POST", { phoneNumber: phoneInput }),
  );
  if (alias) {
    assert.equal(response.status, 200, await response.clone().text());
    return response.json();
  }
  assert.equal(response.status, 201, await response.clone().text());
  const challenge = await response.json();
  const verified = await api(
    miniflare,
    "/api/auth/verify-code",
    jsonRequest("POST", { challengeId: challenge.challengeId, code: "1234" }),
  );
  assert.equal(verified.status, 200, await verified.clone().text());
  return verified.json();
}

async function initializeAccountKey(miniflare, session) {
  const rootSecret = crypto.getRandomValues(new Uint8Array(32));
  const keyCommitment = await vault.accountRootSecretCommitment(rootSecret);
  const response = await api(
    miniflare,
    "/api/account/key-epoch/initialize",
    jsonRequest(
      "POST",
      {
        expectedAccountKeyEpochId: session.accountKeyEpochId,
        keyCommitment,
      },
      session.accessToken,
    ),
  );
  assert.equal(response.status, 200);
  const result = await response.json();
  assert.equal(result.accountKeyEpochId, session.accountKeyEpochId);
  assert.equal(result.keyCommitment, keyCommitment);
  return rootSecret;
}

function invitees(prefix) {
  return Array.from({ length: 9 }, (_, index) => ({
    id: `${prefix}000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    displayName: `test account ${index + 1}`,
    phoneNumber: `+1415555010${index + 1}`,
  }));
}

function eventPayload({
  id,
  title,
  invitees: eventInvitees,
  deadline,
  minimumParticipants,
  requiredGroups,
  eventDateOffset,
}) {
  const eventDate = new Date(Date.now() + eventDateOffset).toISOString();
  return {
    id,
    title,
    eventDate,
    endDate: new Date(Date.parse(eventDate) + 3_600_000).toISOString(),
    hostName: "Cross-service host",
    locationName: "Herd test",
    locationAddress: "San Francisco, CA",
    invitees: eventInvitees,
    minimumParticipants,
    requiredGroups,
    rsvpDeadline: deadline,
    eventDescription: "Real encrypted cross-service resolution test.",
    createdAt: new Date().toISOString(),
    invitationsSent: true,
  };
}

async function createEvent(miniflare, host, payload) {
  const response = await api(
    miniflare,
    `/api/events/${payload.id}`,
    jsonRequest("PUT", payload, host.accessToken),
  );
  assert.equal(response.status, 200, JSON.stringify(await response.clone().json()));
  return (await response.json()).event;
}

async function submitResponse({
  miniflare,
  session,
  rootSecret,
  event,
  inviteeId,
  allowedInviteeIds,
  revision,
  response,
  minimumParticipants,
  requiredGroups,
}) {
  const sealed = await responseCrypto.sealPrivateResponse({
    eventId: event.id,
    inviteeId,
    accountKeyEpochId: session.accountKeyEpochId,
    revision,
    response,
    minimumParticipants,
    requiredGroups,
    allowedInviteeIds,
    accountRootSecret: rootSecret,
    policy: event.privateResponsePolicy,
  });
  const apiResponse = await api(
    miniflare,
    `/api/invites/${event.inviteToken}/rsvp`,
    jsonRequest("PUT", { envelope: sealed.envelope }, session.accessToken),
  );
  assert.equal(apiResponse.status, 200, JSON.stringify(await apiResponse.clone().json()));
  const receipt = await apiResponse.json();
  await trustVerification.verifyPrivateResponseReceiptPublication(
    receipt.receipt,
    transparencySigning,
    (pathname, init) => api(miniflare, String(pathname), init),
  );
  return { sealed, receipt };
}

async function waitPast(iso) {
  const milliseconds = Math.max(0, Date.parse(iso) - Date.now() + 75);
  await new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function assertCourierJob(job, expectedEventId) {
  assert.deepEqual(Object.keys(job).sort(), [
    "evaluatorHost",
    "evaluatorUrl",
    "eventId",
    "expiresAt",
    "leaseId",
    "relayRequest",
    "releaseId",
  ]);
  assert.equal(job.eventId, expectedEventId);
  assert.equal(job.evaluatorUrl, EVALUATOR_RELAY_URL);
  assert.equal(job.evaluatorHost, "https://evaluator.test");
  assert.equal(job.releaseId, RELEASE_ID);
  assert.match(
    job.leaseId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  assert.equal(new Date(Date.parse(job.expiresAt)).toISOString(), job.expiresAt);
  assert.ok(Date.parse(job.expiresAt) > Date.now());
  assert.deepEqual(Object.keys(job.relayRequest).sort(), [
    "capabilityMac",
    "cipherSuite",
    "ciphertext",
    "ephemeralPublicKey",
    "evaluatorKeyId",
    "protocolVersion",
    "salt",
  ]);
  assert.equal(job.relayRequest.protocolVersion, 1);
  assert.equal(
    job.relayRequest.cipherSuite,
    "P256_HKDF_SHA256_AES256_GCM",
  );
  assert.equal(job.relayRequest.evaluatorKeyId, EVALUATOR_KEY_ID);
  assert.equal(
    Buffer.from(job.relayRequest.ephemeralPublicKey, "base64url").length,
    65,
  );
  assert.equal(Buffer.from(job.relayRequest.salt, "base64url").length, 32);
  assert.equal(
    Buffer.from(job.relayRequest.ciphertext, "base64url").length,
    327_708,
  );
  assert.equal(
    Buffer.from(job.relayRequest.capabilityMac, "base64url").length,
    32,
  );
  const serializedRelay = JSON.stringify(job.relayRequest);
  for (const forbidden of [
    expectedEventId,
    HOST_PHONE,
    SCHEDULER_TOKEN,
    EVALUATOR_TOKEN,
    '"eventId"',
    '"policyHash"',
    '"batchHash"',
    '"slots"',
    '"response"',
    '"minimumParticipants"',
    '"requiredGroups"',
  ]) {
    assert.equal(serializedRelay.includes(forbidden), false, forbidden);
  }
}

async function relayCourierJobWithoutOrigin(job, evaluatorBaseUrl) {
  const headers = new Headers({
    accept: "application/json",
    "cache-control": "no-store",
    "content-type": "application/json",
  });
  assert.equal(headers.get("authorization"), null);
  assert.equal(headers.get("origin"), null);
  const response = await fetch(new URL("/api/v1/relay/", evaluatorBaseUrl), {
    method: "POST",
    headers,
    body: JSON.stringify(job.relayRequest),
    redirect: "manual",
  });
  assert.equal(response.status, 200, await response.clone().text());
  assert.equal(response.headers.get("access-control-allow-origin"), null);
  return response.json();
}

function assertGenericSchedulerError(body, forbiddenValues = []) {
  assert.deepEqual(Object.keys(body), ["error"]);
  assert.deepEqual(Object.keys(body.error).sort(), ["code", "message"]);
  const serialized = JSON.stringify(body);
  for (const forbidden of [
    SCHEDULER_TOKEN,
    EVALUATOR_TOKEN,
    "ciphertext",
    "capabilityMac",
    "batchHash",
    "policyHash",
    ...forbiddenValues,
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
}

function courierBindingOverrides() {
  return {
    HERD_EVALUATOR_TRANSPORT: "client_relay",
    HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
    HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
  };
}

async function createCourierBackend(t) {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const result = await createBackendHarness(
    fetchMock,
    courierBindingOverrides(),
  );
  t.after(() => result.miniflare.dispose());
  return result;
}

async function createSingleGoingEvent({
  miniflare,
  host,
  session,
  rootSecret,
  eventId,
  inviteePrefix,
  deadline,
  title,
}) {
  const [invitee] = invitees(inviteePrefix);
  await createEvent(
    miniflare,
    host,
    eventPayload({
      id: eventId,
      title,
      invitees: [invitee],
      deadline,
      minimumParticipants: 2,
      requiredGroups: [],
      eventDateOffset: 120_000,
    }),
  );
  const listing = await api(
    miniflare,
    "/api/events",
    authorizedRequest(session.accessToken),
  );
  assert.equal(listing.status, 200);
  const event = (await listing.json()).events.find(({ id }) => id === eventId);
  assert.ok(event?.inviteToken);
  await submitResponse({
    miniflare,
    session,
    rootSecret,
    event,
    inviteeId: invitee.id,
    allowedInviteeIds: [invitee.id],
    revision: 1,
    response: "going",
    minimumParticipants: 2,
    requiredGroups: [],
  });
  return { event, invitee };
}

function assertNoPrivateResponseLeak(event) {
  const serialized = JSON.stringify(event);
  for (const forbidden of [
    '"payloadCiphertext"',
    '"userKeyWrap"',
    '"evaluatorKeyWrap"',
    '"envelopeHash"',
    '"batchHash"',
    '"response":"going"',
    '"response":"cant_commit"',
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
}

function withoutReceiptSignature(result) {
  const { receiptSignature, ...transparency } = result.receipt.transparency;
  void receiptSignature;
  return {
    ...result,
    receipt: {
      ...result.receipt,
      transparency,
    },
  };
}

test("scheduler wake-up authenticates before accepting an empty request", async (t) => {
  const fetchMock = createFetchMock();
  fetchMock.disableNetConnect();
  const { miniflare } = await createBackendHarness(fetchMock);
  t.after(() => miniflare.dispose());
  const endpoint = "/api/internal/scheduled-resolutions";

  const missing = await api(miniflare, endpoint, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ shouldNotBeRead: true }),
  });
  assert.equal(missing.status, 401);
  assert.equal((await missing.json()).error.code, "scheduler_unauthorized");

  const wrong = await api(
    miniflare,
    endpoint,
    schedulerRequest("wrong_scheduler_token_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
  );
  assert.equal(wrong.status, 401);
  assert.equal((await wrong.json()).error.code, "scheduler_unauthorized");

  const nonempty = await api(
    miniflare,
    endpoint,
    schedulerRequest(SCHEDULER_TOKEN, { forbidden: true }),
  );
  assert.equal(nonempty.status, 400);
  assert.equal((await nonempty.json()).error.code, "invalid_request");

  const accepted = await api(
    miniflare,
    endpoint,
    schedulerRequest(),
  );
  assert.equal(accepted.status, 204);
  assert.equal(await accepted.text(), "");
  assert.equal(accepted.headers.get("cache-control"), "no-store");
});

test(
  "unattended scheduler resolves only due events through one opaque relay under concurrency",
  { timeout: 30_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const relayRequests = [];
    const relayResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorRelayTransport(
      fetchMock,
      evaluator.url,
      relayRequests,
      relayResponses,
      { delayMilliseconds: 250 },
    );
    const { miniflare, database } = await createBackendHarness(fetchMock, {
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
    });
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const session = await authenticate(miniflare, "1");
    const rootSecret = await initializeAccountKey(miniflare, session);
    const dueDeadline = new Date(Date.now() + 3_000).toISOString();
    const { invitee } = await createSingleGoingEvent({
      miniflare,
      host,
      session,
      rootSecret,
      eventId: SCHEDULED_DUE_EVENT_ID,
      inviteePrefix: "d1",
      deadline: dueDeadline,
      title: "Unattended due event",
    });

    const futureDeadline = new Date(Date.now() + 60_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: SCHEDULED_FUTURE_EVENT_ID,
        title: "Future event must stay pending",
        invitees: invitees("d3").slice(0, 1),
        deadline: futureDeadline,
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 180_000,
      }),
    );
    await database
      .prepare("DELETE FROM event_resolutions WHERE event_id = ?")
      .bind(SCHEDULED_DUE_EVENT_ID)
      .run();

    await waitPast(dueDeadline);
    const wakeups = await Promise.all([
      api(
        miniflare,
        "/api/internal/scheduled-resolutions",
        schedulerRequest(),
      ),
      api(
        miniflare,
        "/api/internal/scheduled-resolutions",
        schedulerRequest(),
      ),
    ]);
    assert.deepEqual(wakeups.map(({ status }) => status), [204, 204]);
    assert.equal(relayRequests.length, 1);
    assert.deepEqual(relayResponses, [{ status: 200 }]);

    const outerRequest = relayRequests[0];
    assert.deepEqual(Object.keys(outerRequest).sort(), [
      "capabilityMac",
      "cipherSuite",
      "ciphertext",
      "ephemeralPublicKey",
      "evaluatorKeyId",
      "protocolVersion",
      "salt",
    ]);
    assert.equal(
      Buffer.from(outerRequest.ciphertext, "base64url").length,
      327_708,
    );
    assert.equal(
      JSON.stringify(outerRequest).includes(SCHEDULED_DUE_EVENT_ID),
      false,
    );

    const rows = await database
      .prepare(
        `SELECT event_id AS eventId, status,
                attending_member_ids AS attendingMemberIds,
                resolved_at AS resolvedAt,
                result_attestation_protocol_version AS attestationProtocolVersion,
                result_attestation_signing_key_id AS attestationSigningKeyId,
                result_attestation_evaluated_at AS attestationEvaluatedAt,
                result_attestation_canonical_document AS attestationCanonicalDocument,
                result_attestation_signature AS attestationSignature
         FROM event_resolutions
         WHERE event_id IN (?, ?)
         ORDER BY event_id ASC`,
      )
      .bind(SCHEDULED_DUE_EVENT_ID, SCHEDULED_FUTURE_EVENT_ID)
      .all();
    assert.deepEqual(
      rows.results.map(({ eventId, status }) => ({ eventId, status })),
      [
        { eventId: SCHEDULED_DUE_EVENT_ID, status: "confirmed" },
        { eventId: SCHEDULED_FUTURE_EVENT_ID, status: "pending" },
      ],
    );
    assert.deepEqual(
      JSON.parse(rows.results[0].attendingMemberIds),
      ["host", invitee.id],
    );
    assert.match(rows.results[0].resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
    assert.equal(rows.results[1].attendingMemberIds, null);
    assert.equal(rows.results[1].resolvedAt, null);

    const inviteeRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(session.accessToken),
    );
    assert.equal(inviteeRead.status, 200);
    const resolved = (await inviteeRead.json()).events.find(
      ({ id }) => id === SCHEDULED_DUE_EVENT_ID,
    );
    assert.equal(resolved.resolution.status, "confirmed");
    assert.deepEqual(resolved.resolution.attendingMemberIds, ["host", invitee.id]);
    assert.equal(resolved.resolution.resolvedAt, rows.results[0].resolvedAt);
    assert.deepEqual(resolved.resolution.attestation, {
      protocolVersion: rows.results[0].attestationProtocolVersion,
      signingKeyId: rows.results[0].attestationSigningKeyId,
      evaluatedAt: rows.results[0].attestationEvaluatedAt,
      canonicalDocument: rows.results[0].attestationCanonicalDocument,
      signature: rows.results[0].attestationSignature,
    });
    assert.equal(resolved.resolution.resolvedAt, resolved.resolution.attestation.evaluatedAt);
    assertNoPrivateResponseLeak(resolved);
    assert.equal(relayRequests.length, 1);

    const repeatedWakeup = await api(
      miniflare,
      "/api/internal/scheduled-resolutions",
      schedulerRequest(),
    );
    assert.equal(repeatedWakeup.status, 204);
    assert.equal(relayRequests.length, 1);
  },
);

test(
  "unattended scheduler releases a failed relay lease and retries successfully",
  { timeout: 30_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const relayRequests = [];
    const relayResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorRelayTransport(
      fetchMock,
      evaluator.url,
      relayRequests,
      relayResponses,
      { failFirst: true },
    );
    const { miniflare, database } = await createBackendHarness(fetchMock, {
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
    });
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const session = await authenticate(miniflare, "1");
    const rootSecret = await initializeAccountKey(miniflare, session);
    const deadline = new Date(Date.now() + 3_000).toISOString();
    const { invitee } = await createSingleGoingEvent({
      miniflare,
      host,
      session,
      rootSecret,
      eventId: SCHEDULED_RETRY_EVENT_ID,
      inviteePrefix: "e1",
      deadline,
      title: "Unattended retry event",
    });
    await waitPast(deadline);

    const first = await api(
      miniflare,
      "/api/internal/scheduled-resolutions",
      schedulerRequest(),
    );
    assert.equal(first.status, 503);
    const firstBody = await first.json();
    assert.deepEqual(firstBody, {
      error: {
        code: "scheduled_resolution_incomplete",
        message: "The due-event sweep was incomplete and can be retried safely.",
      },
    });
    assert.equal(first.headers.get("retry-after"), "5");
    const serializedFailure = JSON.stringify(firstBody);
    assert.equal(serializedFailure.includes(SCHEDULED_RETRY_EVENT_ID), false);
    assert.equal(serializedFailure.includes(SCHEDULER_TOKEN), false);
    assert.equal(serializedFailure.includes("ciphertext"), false);
    assert.equal(relayRequests.length, 1);
    assert.deepEqual(relayResponses, [{ status: 503 }]);
    const released = await database
      .prepare(
        `SELECT status, batch_hash AS batchHash,
                evaluation_request_hash AS requestHash,
                evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions
         WHERE event_id = ?`,
      )
      .bind(SCHEDULED_RETRY_EVENT_ID)
      .first();
    assert.deepEqual(released, {
      status: "pending",
      batchHash: null,
      requestHash: null,
      leaseId: null,
      leaseExpiresAt: null,
    });

    const retry = await api(
      miniflare,
      "/api/internal/scheduled-resolutions",
      schedulerRequest(),
    );
    assert.equal(retry.status, 204);
    assert.equal(relayRequests.length, 2);
    assert.deepEqual(relayResponses, [{ status: 503 }, { status: 200 }]);
    assert.notEqual(
      relayRequests[0].capabilityMac,
      relayRequests[1].capabilityMac,
    );
    const resolved = await database
      .prepare(
        `SELECT status, attending_member_ids AS attendingMemberIds,
                evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions
         WHERE event_id = ?`,
      )
      .bind(SCHEDULED_RETRY_EVENT_ID)
      .first();
    assert.deepEqual(resolved, {
      status: "confirmed",
      attendingMemberIds: JSON.stringify(["host", invitee.id]),
      leaseId: null,
      leaseExpiresAt: null,
    });
  },
);

test(
  "external scheduler courier keeps claims opaque and accepts only bound signed completions",
  { timeout: 90_000 },
  async (t) => {
    const claimEndpoint = "/api/internal/scheduled-resolutions/claim";
    const completeEndpoint = "/api/internal/scheduled-resolutions/complete";
    const releaseEndpoint = "/api/internal/scheduled-resolutions/release";
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());

    await t.test(
      "scheduler authentication precedes request bodies and event database access",
      async (st) => {
        const { miniflare, database } = await createCourierBackend(st);
        await database.exec("DROP TABLE events");

        const missingClaimAuth = await api(miniflare, claimEndpoint, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: chunkedBody(64 * 1024 + 1),
          duplex: "half",
        });
        assert.equal(missingClaimAuth.status, 401);
        const missingClaimBody = await missingClaimAuth.json();
        assert.equal(missingClaimBody.error.code, "scheduler_unauthorized");
        assertGenericSchedulerError(missingClaimBody);

        const protectedEventId = "f1000000-0000-4000-8000-000000000001";
        const missingCompleteAuth = await api(
          miniflare,
          completeEndpoint,
          jsonRequest("POST", {
            eventId: protectedEventId,
            evaluationResponse: { ciphertext: "must-not-be-read" },
          }),
        );
        assert.equal(missingCompleteAuth.status, 401);
        const missingCompleteBody = await missingCompleteAuth.json();
        assert.equal(missingCompleteBody.error.code, "scheduler_unauthorized");
        assertGenericSchedulerError(missingCompleteBody, [
          protectedEventId,
          "must-not-be-read",
        ]);

        const wrongReleaseAuth = await api(
          miniflare,
          releaseEndpoint,
          schedulerRequest(
            "wrong_scheduler_token_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            {
              eventId: protectedEventId,
              leaseId: "f1000000-0000-4000-8000-000000000002",
            },
          ),
        );
        assert.equal(wrongReleaseAuth.status, 401);
        const wrongReleaseBody = await wrongReleaseAuth.json();
        assert.equal(wrongReleaseBody.error.code, "scheduler_unauthorized");
        assertGenericSchedulerError(wrongReleaseBody, [protectedEventId]);
      },
    );

    await t.test(
      "claim requires an empty body, ignores future work, and returns one fixed-size opaque due job",
      async (st) => {
        const { miniflare, database } = await createCourierBackend(st);

        const nonempty = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, { forbidden: true }),
        );
        assert.equal(nonempty.status, 400);
        const nonemptyBody = await nonempty.json();
        assert.equal(nonemptyBody.error.code, "invalid_request");
        assertGenericSchedulerError(nonemptyBody);

        const emptyDatabase = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(emptyDatabase.status, 204);
        assert.equal(await emptyDatabase.text(), "");
        assert.equal(emptyDatabase.headers.get("cache-control"), "no-store");

        const host = await authenticate(miniflare, HOST_PHONE);
        const session = await authenticate(miniflare, "1");
        const rootSecret = await initializeAccountKey(miniflare, session);
        const futureDeadline = new Date(Date.now() + 60_000).toISOString();
        await createEvent(
          miniflare,
          host,
          eventPayload({
            id: COURIER_FUTURE_EVENT_ID,
            title: "External courier future event",
            invitees: invitees("f2").slice(0, 1),
            deadline: futureDeadline,
            minimumParticipants: 2,
            requiredGroups: [],
            eventDateOffset: 180_000,
          }),
        );
        const futureOnly = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(futureOnly.status, 204);
        assert.equal(await futureOnly.text(), "");
        const futureRow = await database
          .prepare(
            `SELECT status, evaluation_lease_id AS leaseId
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_FUTURE_EVENT_ID)
          .first();
        assert.deepEqual(futureRow, { status: "pending", leaseId: null });

        const dueDeadline = new Date(Date.now() + 1_200).toISOString();
        await createSingleGoingEvent({
          miniflare,
          host,
          session,
          rootSecret,
          eventId: COURIER_DUE_EVENT_ID,
          inviteePrefix: "f1",
          deadline: dueDeadline,
          title: "External courier due event",
        });
        await waitPast(dueDeadline);

        const claimed = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(claimed.status, 200, await claimed.clone().text());
        assert.equal(claimed.headers.get("cache-control"), "no-store");
        const job = await claimed.json();
        assertCourierJob(job, COURIER_DUE_EVENT_ID);

        const follower = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(follower.status, 204);
        assert.equal(await follower.text(), "");
        const claimedRow = await database
          .prepare(
            `SELECT status, evaluation_lease_id AS leaseId,
                    length(batch_hash) AS batchHashLength,
                    length(evaluation_request_hash) AS requestHashLength
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_DUE_EVENT_ID)
          .first();
        assert.deepEqual(claimedRow, {
          status: "evaluating",
          leaseId: job.leaseId,
          batchHashLength: 43,
          requestHashLength: 43,
        });
      },
    );

    await t.test(
      "a due candidate with broken relay configuration returns a generic retryable failure",
      async (st) => {
        const fetchMock = createFetchMock();
        fetchMock.disableNetConnect();
        const { miniflare, database } = await createBackendHarness(fetchMock, {
          ...courierBindingOverrides(),
          HERD_EVALUATOR_URL: EVALUATOR_PUBLIC_URL,
        });
        st.after(() => miniflare.dispose());
        const host = await authenticate(miniflare, HOST_PHONE);
        const eventId = "f2500000-0000-4000-8000-000000000001";
        const deadline = new Date(Date.now() + 1_200).toISOString();
        await createEvent(
          miniflare,
          host,
          eventPayload({
            id: eventId,
            title: "Broken courier relay configuration",
            invitees: invitees("f6").slice(0, 1),
            deadline,
            minimumParticipants: 2,
            requiredGroups: [],
            eventDateOffset: 120_000,
          }),
        );
        await waitPast(deadline);

        for (let attempt = 0; attempt < 2; attempt += 1) {
          const failedClaim = await api(
            miniflare,
            claimEndpoint,
            schedulerRequest(),
          );
          assert.equal(failedClaim.status, 503);
          assert.equal(failedClaim.headers.get("retry-after"), "5");
          assert.equal(failedClaim.headers.get("cache-control"), "no-store");
          const failureBody = await failedClaim.json();
          assert.deepEqual(failureBody, {
            error: {
              code: "scheduled_claim_unavailable",
              message: "A due event could not be prepared for the scheduler.",
            },
          });
          assertGenericSchedulerError(failureBody, [
            eventId,
            EVALUATOR_PUBLIC_URL,
          ]);
        }
        const pending = await database
          .prepare(
            `SELECT status, batch_hash AS batchHash,
                    evaluation_request_hash AS requestHash,
                    evaluation_lease_id AS leaseId,
                    evaluation_lease_expires_at AS leaseExpiresAt
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(eventId)
          .first();
        assert.deepEqual(pending, {
          status: "pending",
          batchHash: null,
          requestHash: null,
          leaseId: null,
          leaseExpiresAt: null,
        });
      },
    );

    await t.test(
      "a no-Origin evaluator relay and exact scheduler completion persist the signed result",
      async (st) => {
        const { miniflare, database } = await createCourierBackend(st);
        const host = await authenticate(miniflare, HOST_PHONE);
        const session = await authenticate(miniflare, "1");
        const rootSecret = await initializeAccountKey(miniflare, session);
        const deadline = new Date(Date.now() + 1_200).toISOString();
        const { invitee } = await createSingleGoingEvent({
          miniflare,
          host,
          session,
          rootSecret,
          eventId: COURIER_DUE_EVENT_ID,
          inviteePrefix: "f1",
          deadline,
          title: "External courier signed completion",
        });
        await waitPast(deadline);

        const claim = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(claim.status, 200, await claim.clone().text());
        const job = await claim.json();
        assertCourierJob(job, COURIER_DUE_EVENT_ID);
        const evaluationResponse = await relayCourierJobWithoutOrigin(
          job,
          evaluator.url,
        );

        for (const invalidBody of [
          {},
          { eventId: COURIER_DUE_EVENT_ID },
          { eventId: COURIER_DUE_EVENT_ID, evaluationResponse, extra: true },
          [],
        ]) {
          const invalid = await api(
            miniflare,
            completeEndpoint,
            schedulerRequest(SCHEDULER_TOKEN, invalidBody),
          );
          assert.equal(invalid.status, 400);
          const invalidResponse = await invalid.json();
          assert.equal(invalidResponse.error.code, "invalid_request");
          assertGenericSchedulerError(invalidResponse, [
            COURIER_DUE_EVENT_ID,
            job.leaseId,
          ]);
        }

        const wrongMediaType = await api(miniflare, completeEndpoint, {
          method: "POST",
          headers: { authorization: `Bearer ${SCHEDULER_TOKEN}` },
          body: JSON.stringify({
            eventId: COURIER_DUE_EVENT_ID,
            evaluationResponse,
          }),
        });
        assert.equal(wrongMediaType.status, 415);
        assertGenericSchedulerError(await wrongMediaType.json(), [
          COURIER_DUE_EVENT_ID,
          job.leaseId,
        ]);

        const completed = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_DUE_EVENT_ID,
            evaluationResponse,
          }),
        );
        assert.equal(completed.status, 204, await completed.clone().text());
        assert.equal(await completed.text(), "");
        assert.equal(completed.headers.get("cache-control"), "no-store");

        const repeated = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_DUE_EVENT_ID,
            evaluationResponse,
          }),
        );
        assert.equal(repeated.status, 204);
        assert.equal(await repeated.text(), "");

        const stored = await database
          .prepare(
            `SELECT status, attending_member_ids AS attendingMemberIds,
                    resolved_at AS resolvedAt,
                    batch_hash AS batchHash,
                    result_attestation_protocol_version AS attestationProtocolVersion,
                    result_attestation_signing_key_id AS attestationSigningKeyId,
                    result_attestation_evaluated_at AS attestationEvaluatedAt,
                    result_attestation_canonical_document AS attestationCanonicalDocument,
                    result_attestation_signature AS attestationSignature,
                    evaluation_lease_id AS leaseId,
                    evaluation_lease_expires_at AS leaseExpiresAt
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_DUE_EVENT_ID)
          .first();
        assert.equal(stored.status, "confirmed");
        assert.deepEqual(JSON.parse(stored.attendingMemberIds), [
          "host",
          invitee.id,
        ]);
        assert.match(stored.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
        assert.equal(stored.resolvedAt, evaluationResponse.attestation.evaluatedAt);
        assert.equal(stored.attestationProtocolVersion, 1);
        assert.equal(stored.attestationSigningKeyId, evaluationResponse.attestation.signingKeyId);
        assert.equal(stored.attestationEvaluatedAt, evaluationResponse.attestation.evaluatedAt);
        assert.equal(stored.attestationCanonicalDocument, evaluationResponse.attestation.canonicalDocument);
        assert.equal(stored.attestationSignature, evaluationResponse.attestation.signature);
        assert.equal(stored.leaseId, null);
        assert.equal(stored.leaseExpiresAt, null);

        const inviteeRead = await api(
          miniflare,
          "/api/events",
          authorizedRequest(session.accessToken),
        );
        assert.equal(inviteeRead.status, 200);
        const resolved = (await inviteeRead.json()).events.find(
          ({ id }) => id === COURIER_DUE_EVENT_ID,
        );
        assert.deepEqual(resolved.resolution, {
          status: "confirmed",
          attendingMemberIds: ["host", invitee.id],
          attendanceRevealed: true,
          resolvedAt: evaluationResponse.attestation.evaluatedAt,
          attestation: evaluationResponse.attestation,
          guestStates: [
            { memberId: invitee.id, status: "going", missedDeadline: false },
          ],
        });
        assertNoPrivateResponseLeak(resolved);

        await database
          .prepare(
            `UPDATE event_resolutions
             SET result_attestation_protocol_version = NULL,
                 result_attestation_signing_key_id = NULL,
                 result_attestation_evaluated_at = NULL,
                 result_attestation_canonical_document = NULL,
                 result_attestation_signature = NULL
             WHERE event_id = ?`,
          )
          .bind(COURIER_DUE_EVENT_ID)
          .run();
        const legacyRead = await api(
          miniflare,
          "/api/events",
          authorizedRequest(session.accessToken),
        );
        assert.equal(legacyRead.status, 200);
        const legacyResolution = (await legacyRead.json()).events.find(
          ({ id }) => id === COURIER_DUE_EVENT_ID,
        ).resolution;
        assert.equal(legacyResolution.status, "confirmed");
        assert.equal("attestation" in legacyResolution, false);
      },
    );

    await t.test(
      "concurrent claims create one lease and wrong, tampered, or stale completions cannot persist",
      async (st) => {
        const { miniflare, database } = await createCourierBackend(st);
        const host = await authenticate(miniflare, HOST_PHONE);
        const session = await authenticate(miniflare, "1");
        const rootSecret = await initializeAccountKey(miniflare, session);
        const deadline = new Date(Date.now() + 1_200).toISOString();
        await createSingleGoingEvent({
          miniflare,
          host,
          session,
          rootSecret,
          eventId: COURIER_CONCURRENT_EVENT_ID,
          inviteePrefix: "f3",
          deadline,
          title: "External courier concurrent claim",
        });
        await createEvent(
          miniflare,
          host,
          eventPayload({
            id: COURIER_OTHER_EVENT_ID,
            title: "Wrong completion target",
            invitees: invitees("f5").slice(0, 1),
            deadline: new Date(Date.now() + 60_000).toISOString(),
            minimumParticipants: 2,
            requiredGroups: [],
            eventDateOffset: 180_000,
          }),
        );
        await waitPast(deadline);

        const concurrent = await Promise.all([
          api(miniflare, claimEndpoint, schedulerRequest()),
          api(miniflare, claimEndpoint, schedulerRequest()),
        ]);
        assert.deepEqual(
          concurrent.map(({ status }) => status).sort((left, right) => left - right),
          [200, 204],
        );
        const winner = concurrent.find(({ status }) => status === 200);
        assert.ok(winner);
        const firstJob = await winner.json();
        assertCourierJob(firstJob, COURIER_CONCURRENT_EVENT_ID);
        const firstEvaluationResponse = await relayCourierJobWithoutOrigin(
          firstJob,
          evaluator.url,
        );
        const activeRows = await database
          .prepare(
            `SELECT event_id AS eventId, evaluation_lease_id AS leaseId
             FROM event_resolutions WHERE status = 'evaluating'`,
          )
          .all();
        assert.deepEqual(activeRows.results, [
          {
            eventId: COURIER_CONCURRENT_EVENT_ID,
            leaseId: firstJob.leaseId,
          },
        ]);

        const wrongEvent = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_OTHER_EVENT_ID,
            evaluationResponse: firstEvaluationResponse,
          }),
        );
        assert.equal(wrongEvent.status, 409);
        assertGenericSchedulerError(await wrongEvent.json(), [
          COURIER_OTHER_EVENT_ID,
          COURIER_CONCURRENT_EVENT_ID,
          firstJob.leaseId,
        ]);

        const tamperedEvaluationResponse = structuredClone(
          firstEvaluationResponse,
        );
        const tamperedSignature = Buffer.from(
          tamperedEvaluationResponse.attestation.signature,
          "base64url",
        );
        tamperedSignature[0] ^= 0x01;
        tamperedEvaluationResponse.attestation.signature =
          tamperedSignature.toString("base64url");
        const tampered = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_CONCURRENT_EVENT_ID,
            evaluationResponse: tamperedEvaluationResponse,
          }),
        );
        assert.equal(tampered.status, 400);
        const tamperedBody = await tampered.json();
        assert.equal(tamperedBody.error.code, "invalid_evaluator_attestation");
        assertGenericSchedulerError(tamperedBody, [
          COURIER_CONCURRENT_EVENT_ID,
          firstJob.leaseId,
        ]);

        await database
          .prepare(
            `UPDATE event_resolutions SET evaluation_lease_expires_at = ?
             WHERE event_id = ?`,
          )
          .bind(
            new Date(Date.now() - 1_000).toISOString(),
            COURIER_CONCURRENT_EVENT_ID,
          )
          .run();
        const replacementClaim = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(
          replacementClaim.status,
          200,
          await replacementClaim.clone().text(),
        );
        const replacementJob = await replacementClaim.json();
        assertCourierJob(replacementJob, COURIER_CONCURRENT_EVENT_ID);
        assert.notEqual(replacementJob.leaseId, firstJob.leaseId);

        const stale = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_CONCURRENT_EVENT_ID,
            evaluationResponse: firstEvaluationResponse,
          }),
        );
        assert.equal(stale.status, 400);
        const staleBody = await stale.json();
        assert.equal(staleBody.error.code, "invalid_evaluator_attestation");
        assertGenericSchedulerError(staleBody, [
          COURIER_CONCURRENT_EVENT_ID,
          firstJob.leaseId,
          replacementJob.leaseId,
        ]);
        const stillActive = await database
          .prepare(
            `SELECT status, resolved_at AS resolvedAt,
                    evaluation_lease_id AS leaseId
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_CONCURRENT_EVENT_ID)
          .first();
        assert.deepEqual(stillActive, {
          status: "evaluating",
          resolvedAt: null,
          leaseId: replacementJob.leaseId,
        });

        const replacementEvaluationResponse =
          await relayCourierJobWithoutOrigin(replacementJob, evaluator.url);
        const completed = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_CONCURRENT_EVENT_ID,
            evaluationResponse: replacementEvaluationResponse,
          }),
        );
        assert.equal(completed.status, 204);
        const finalRows = await database
          .prepare(
            `SELECT event_id AS eventId, status, resolved_at AS resolvedAt
             FROM event_resolutions
             WHERE event_id IN (?, ?) ORDER BY event_id ASC`,
          )
          .bind(COURIER_CONCURRENT_EVENT_ID, COURIER_OTHER_EVENT_ID)
          .all();
        assert.deepEqual(
          finalRows.results.map(({ eventId, status }) => ({ eventId, status })),
          [
            { eventId: COURIER_CONCURRENT_EVENT_ID, status: "confirmed" },
            { eventId: COURIER_OTHER_EVENT_ID, status: "pending" },
          ],
        );
        assert.match(finalRows.results[0].resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
        assert.equal(finalRows.results[1].resolvedAt, null);
      },
    );

    await t.test(
      "a generic lease release permits safe retry after courier transport failure",
      async (st) => {
        const { miniflare, database } = await createCourierBackend(st);
        const host = await authenticate(miniflare, HOST_PHONE);
        const session = await authenticate(miniflare, "1");
        const rootSecret = await initializeAccountKey(miniflare, session);
        const deadline = new Date(Date.now() + 1_200).toISOString();
        const { invitee } = await createSingleGoingEvent({
          miniflare,
          host,
          session,
          rootSecret,
          eventId: COURIER_RELEASE_EVENT_ID,
          inviteePrefix: "f4",
          deadline,
          title: "External courier release retry",
        });
        await waitPast(deadline);
        const firstClaim = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(firstClaim.status, 200, await firstClaim.clone().text());
        const firstJob = await firstClaim.json();
        assertCourierJob(firstJob, COURIER_RELEASE_EVENT_ID);

        const extraKey = await api(
          miniflare,
          releaseEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_RELEASE_EVENT_ID,
            leaseId: firstJob.leaseId,
            extra: true,
          }),
        );
        assert.equal(extraKey.status, 400);
        assertGenericSchedulerError(await extraKey.json(), [
          COURIER_RELEASE_EVENT_ID,
          firstJob.leaseId,
        ]);

        for (const releaseBody of [
          {
            eventId: "f4000000-0000-4000-8000-000000000099",
            leaseId: firstJob.leaseId,
          },
          {
            eventId: COURIER_RELEASE_EVENT_ID,
            leaseId: "f4000000-0000-4000-8000-000000000099",
          },
        ]) {
          const ignored = await api(
            miniflare,
            releaseEndpoint,
            schedulerRequest(SCHEDULER_TOKEN, releaseBody),
          );
          assert.equal(ignored.status, 204);
          assert.equal(await ignored.text(), "");
        }
        const notReleased = await database
          .prepare(
            `SELECT status, evaluation_lease_id AS leaseId
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_RELEASE_EVENT_ID)
          .first();
        assert.deepEqual(notReleased, {
          status: "evaluating",
          leaseId: firstJob.leaseId,
        });

        const releasedResponse = await api(
          miniflare,
          releaseEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_RELEASE_EVENT_ID,
            leaseId: firstJob.leaseId,
          }),
        );
        assert.equal(releasedResponse.status, 204);
        assert.equal(await releasedResponse.text(), "");
        assert.equal(releasedResponse.headers.get("cache-control"), "no-store");
        const released = await database
          .prepare(
            `SELECT status, batch_hash AS batchHash,
                    evaluation_request_hash AS requestHash,
                    evaluation_lease_id AS leaseId,
                    evaluation_lease_expires_at AS leaseExpiresAt
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_RELEASE_EVENT_ID)
          .first();
        assert.deepEqual(released, {
          status: "pending",
          batchHash: null,
          requestHash: null,
          leaseId: null,
          leaseExpiresAt: null,
        });

        const duplicateRelease = await api(
          miniflare,
          releaseEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_RELEASE_EVENT_ID,
            leaseId: firstJob.leaseId,
          }),
        );
        assert.equal(duplicateRelease.status, 204);
        assert.equal(await duplicateRelease.text(), "");

        const retryClaim = await api(
          miniflare,
          claimEndpoint,
          schedulerRequest(),
        );
        assert.equal(retryClaim.status, 200, await retryClaim.clone().text());
        const retryJob = await retryClaim.json();
        assertCourierJob(retryJob, COURIER_RELEASE_EVENT_ID);
        assert.notEqual(retryJob.leaseId, firstJob.leaseId);
        assert.notEqual(
          retryJob.relayRequest.capabilityMac,
          firstJob.relayRequest.capabilityMac,
        );
        const evaluationResponse = await relayCourierJobWithoutOrigin(
          retryJob,
          evaluator.url,
        );
        const completion = await api(
          miniflare,
          completeEndpoint,
          schedulerRequest(SCHEDULER_TOKEN, {
            eventId: COURIER_RELEASE_EVENT_ID,
            evaluationResponse,
          }),
        );
        assert.equal(completion.status, 204);
        const final = await database
          .prepare(
            `SELECT status, attending_member_ids AS attendingMemberIds,
                    evaluation_lease_id AS leaseId
             FROM event_resolutions WHERE event_id = ?`,
          )
          .bind(COURIER_RELEASE_EVENT_ID)
          .first();
        assert.deepEqual(final, {
          status: "confirmed",
          attendingMemberIds: JSON.stringify(["host", invitee.id]),
          leaseId: null,
        });
      },
    );
  },
);

test(
  "legacy iOS cant-commit updates may omit the empty minimum condition",
  { timeout: 30_000 },
  async (t) => {
    const fetchMock = createFetchMock();
    fetchMock.disableNetConnect();
    const { miniflare } = await createBackendHarness(fetchMock);
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const eventId = "b1000000-0000-4000-8000-000000000001";
    const eventInvitees = invitees("b0").slice(0, 1);
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: eventId,
        title: "Condition-free reply update",
        invitees: eventInvitees,
        deadline: new Date(Date.now() + 60_000).toISOString(),
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 120_000,
      }),
    );
    const invitee = await authenticate(miniflare, "1");
    const listing = await api(
      miniflare,
      "/api/events",
      authorizedRequest(invitee.accessToken),
    );
    const inviteeEvent = (await listing.json()).events.find(({ id }) => id === eventId);
    assert.ok(inviteeEvent?.inviteToken);

    const initial = await api(
      miniflare,
      `/api/invites/${inviteeEvent.inviteToken}/ballot`,
      jsonRequest("PUT", {
        response: "going",
        minimumParticipants: 2,
        requiredGroups: [],
      }, invitee.accessToken),
    );
    assert.equal(initial.status, 200, await initial.clone().text());

    const updated = await api(
      miniflare,
      `/api/invites/${inviteeEvent.inviteToken}/ballot`,
      jsonRequest("PUT", {
        response: "cant_commit",
        requiredGroups: [],
      }, invitee.accessToken),
    );
    assert.equal(updated.status, 200, await updated.clone().text());
    const ballot = (await updated.json()).ballot;
    assert.equal(ballot.revision, 2);
    assert.equal(ballot.response, "cant_commit");
    assert.equal(ballot.minimumParticipants, null);
    assert.deepEqual(ballot.requiredGroups, []);
  },
);

test(
  "participant relay upgrades a sealed confirmation and accepts only the current signed lease",
  { timeout: 30_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const fetchMock = createFetchMock();
    fetchMock.disableNetConnect();
    const { miniflare, database } = await createBackendHarness(fetchMock, {
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
    });
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const eventId = "b2000000-0000-4000-8000-000000000001";
    const eventInvitees = invitees("b1").slice(0, 1);
    const deadline = new Date(Date.now() + 60_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: eventId,
        title: "Opaque host relay",
        invitees: eventInvitees,
        deadline,
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 120_000,
      }),
    );
    const invitee = await authenticate(miniflare, "1");
    const inviteeListing = await api(
      miniflare,
      "/api/events",
      authorizedRequest(invitee.accessToken),
    );
    const inviteeEvent = (await inviteeListing.json()).events.find(({ id }) => id === eventId);
    const ballotResponse = await api(
      miniflare,
      `/api/invites/${inviteeEvent.inviteToken}/ballot`,
      jsonRequest("PUT", {
        response: "going",
        minimumParticipants: 2,
        requiredGroups: [],
      }, invitee.accessToken),
    );
    assert.equal(ballotResponse.status, 200, await ballotResponse.clone().text());
    const legacyResolvedAt = new Date().toISOString();
    await database
      .prepare(
        `UPDATE event_resolutions
         SET status = 'confirmed', batch_hash = ?, resolved_at = ?
         WHERE event_id = ?`,
      )
      .bind("A".repeat(43), legacyResolvedAt, eventId)
      .run();
    const outsider = await authenticate(miniflare, "2");
    const denied = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${outsider.accessToken}`,
          origin: "https://herd.test",
        },
      },
    );
    assert.equal(denied.status, 404);

    const unauthenticatedOversize = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      {
        method: "PUT",
        headers: {
          "content-type": "application/json",
          origin: "https://herd.test",
        },
        body: chunkedBody(64 * 1024 + 1),
        duplex: "half",
      },
    );
    assert.equal(unauthenticatedOversize.status, 401);

    const authenticatedOversize = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${host.accessToken}`,
          "content-type": "application/json",
          origin: "https://herd.test",
        },
        body: chunkedBody(64 * 1024 + 1),
        duplex: "half",
      },
    );
    assert.equal(authenticatedOversize.status, 413);
    assert.equal(
      (await authenticatedOversize.json()).error.code,
      "payload_too_large",
    );

    const listing = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(listing.status, 200);
    const pending = (await listing.json()).events.find(({ id }) => id === eventId);
    assert.deepEqual(pending.resolution, {
      status: "confirmed",
      attendanceRevealed: false,
      resolvedAt: legacyResolvedAt,
    });

    const startRequest = {
      method: "POST",
      headers: {
        authorization: `Bearer ${invitee.accessToken}`,
        origin: "https://herd.test",
      },
    };
    const started = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      startRequest,
    );
    assert.equal(started.status, 200, await started.clone().text());
    const firstJob = await started.json();
    assert.deepEqual(Object.keys(firstJob).sort(), [
      "evaluatorHost",
      "evaluatorUrl",
      "eventId",
      "expiresAt",
      "leaseId",
      "relayRequest",
      "releaseId",
    ]);
    assert.equal(firstJob.eventId, eventId);
    assert.equal(firstJob.evaluatorUrl, EVALUATOR_RELAY_URL);
    assert.equal(firstJob.evaluatorHost, "https://evaluator.test");
    assert.equal(firstJob.releaseId, RELEASE_ID);
    assert.deepEqual(Object.keys(firstJob.relayRequest).sort(), [
      "capabilityMac",
      "cipherSuite",
      "ciphertext",
      "ephemeralPublicKey",
      "evaluatorKeyId",
      "protocolVersion",
      "salt",
    ]);
    assert.equal(
      Buffer.from(firstJob.relayRequest.ciphertext, "base64url").length,
      327_708,
    );
    assertNoPrivateResponseLeak(firstJob);

    const follower = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      startRequest,
    );
    assert.equal(follower.status, 202);
    assert.deepEqual(await follower.json(), {
      eventId,
      resolution: { status: "pending" },
    });

    const firstEvaluatorResponse = await fetch(
      new URL("/api/v1/relay/", evaluator.url),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://herd.test",
        },
        body: JSON.stringify(firstJob.relayRequest),
      },
    );
    assert.equal(
      firstEvaluatorResponse.status,
      200,
      await firstEvaluatorResponse.clone().text(),
    );
    const firstAttestation = await firstEvaluatorResponse.json();

    await database
      .prepare(
        `UPDATE event_resolutions
         SET evaluation_lease_expires_at = ?
         WHERE event_id = ?`,
      )
      .bind(new Date(Date.now() - 1_000).toISOString(), eventId)
      .run();
    const takeover = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      startRequest,
    );
    assert.equal(takeover.status, 200, await takeover.clone().text());
    const secondJob = await takeover.json();
    assert.notEqual(secondJob.leaseId, firstJob.leaseId);
    assert.notEqual(
      secondJob.relayRequest.capabilityMac,
      firstJob.relayRequest.capabilityMac,
    );

    const staleCompletion = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      jsonRequest(
        "PUT",
        { evaluationResponse: firstAttestation },
        invitee.accessToken,
      ),
    );
    assert.equal(staleCompletion.status, 400);
    assert.equal(
      (await staleCompletion.json()).error.code,
      "invalid_evaluator_attestation",
    );

    const secondEvaluatorResponse = await fetch(
      new URL("/api/v1/relay/", evaluator.url),
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          origin: "https://herd.test",
        },
        body: JSON.stringify(secondJob.relayRequest),
      },
    );
    assert.equal(
      secondEvaluatorResponse.status,
      200,
      await secondEvaluatorResponse.clone().text(),
    );
    const currentAttestation = await secondEvaluatorResponse.json();
    const completionBody = {
      evaluationResponse: currentAttestation,
    };
    const completed = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      jsonRequest("PUT", completionBody, invitee.accessToken),
    );
    assert.equal(completed.status, 200, await completed.clone().text());
    const resolution = (await completed.json()).resolution;
    assert.equal(resolution.status, "confirmed");
    assert.equal(resolution.attendanceRevealed, true);
    assert.deepEqual(resolution.attendingMemberIds, ["host", eventInvitees[0].id]);
    assert.match(resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);

    const repeated = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      jsonRequest("PUT", completionBody, invitee.accessToken),
    );
    assert.equal(repeated.status, 200);
    assert.deepEqual((await repeated.json()).resolution, resolution);
    const stored = await database
      .prepare(
        `SELECT status, batch_hash AS batchHash,
                evaluation_request_hash AS requestHash,
                evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.equal(stored.status, "confirmed");
    assert.equal(stored.batchHash.length, 43);
    assert.equal(stored.requestHash.length, 43);
    assert.equal(stored.leaseId, null);
    assert.equal(stored.leaseExpiresAt, null);
    const ballotRun = await database.prepare(
      `SELECT input_digest AS inputDigest, input_revisions AS inputRevisions,
              status, attending_member_ids AS attendingMemberIds
       FROM ballot_evaluation_runs WHERE event_id = ?`,
    ).bind(eventId).first();
    assert.equal(ballotRun.inputDigest, stored.batchHash);
    assert.equal(ballotRun.status, "confirmed");
    assert.equal(ballotRun.attendingMemberIds, null);
    const inputRevisions = JSON.parse(ballotRun.inputRevisions);
    assert.equal(inputRevisions.length, 1);
    assert.deepEqual(Object.keys(inputRevisions[0]).sort(), ["ballotId", "revision"]);
  },
);

test(
  "an early negative relay stays pending and a stored premature negative self-heals",
  { timeout: 30_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const fetchMock = createFetchMock();
    fetchMock.disableNetConnect();
    const { miniflare, database } = await createBackendHarness(fetchMock, {
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
    });
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const eventId = "b2000000-0000-4000-8000-000000000002";
    const deadline = new Date(Date.now() + 60_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: eventId,
        title: "Early negative remains pending",
        invitees: invitees("b2").slice(0, 1),
        deadline,
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 120_000,
      }),
    );

    const started = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      {
        method: "POST",
        headers: {
          authorization: `Bearer ${host.accessToken}`,
          origin: "https://herd.test",
        },
      },
    );
    assert.equal(started.status, 200, await started.clone().text());
    const job = await started.json();
    const evaluationResponse = await relayCourierJobWithoutOrigin(
      job,
      evaluator.url,
    );
    assert.equal(evaluationResponse.result.status, "not_confirmed");

    const completed = await api(
      miniflare,
      `/api/events/${eventId}/evaluation`,
      jsonRequest(
        "PUT",
        { evaluationResponse },
        host.accessToken,
      ),
    );
    assert.equal(completed.status, 200, await completed.clone().text());
    assert.deepEqual((await completed.json()).resolution, {
      status: "pending",
    });

    const pendingRow = await database
      .prepare(
        `SELECT status, batch_hash AS batchHash,
                attending_member_ids AS attendingMemberIds,
                resolved_at AS resolvedAt,
                evaluation_request_hash AS requestHash,
                evaluation_lease_id AS leaseId,
                evaluation_lease_expires_at AS leaseExpiresAt,
                result_attestation_canonical_document AS attestationDocument
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(pendingRow, {
      status: "pending",
      batchHash: null,
      attendingMemberIds: null,
      resolvedAt: null,
      requestHash: null,
      leaseId: null,
      leaseExpiresAt: null,
      attestationDocument: null,
    });

    const prematureResolvedAt = new Date(Date.now() - 1_000).toISOString();
    await database
      .prepare(
        `UPDATE event_resolutions
         SET status = 'not_confirmed', batch_hash = ?, resolved_at = ?
         WHERE event_id = ?`,
      )
      .bind("A".repeat(43), prematureResolvedAt, eventId)
      .run();

    const listing = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(listing.status, 200, await listing.clone().text());
    const repaired = (await listing.json()).events.find(({ id }) => id === eventId);
    assert.deepEqual(repaired.resolution, {
      status: "pending",
      relayNeeded: true,
    });
    const repairedRow = await database
      .prepare(
        `SELECT status, batch_hash AS batchHash, resolved_at AS resolvedAt
         FROM event_resolutions WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(repairedRow, {
      status: "pending",
      batchHash: null,
      resolvedAt: null,
    });
  },
);

test(
  "unattended scheduler confirms all nine varied private replies through the opaque relay",
  { timeout: 35_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const relayRequests = [];
    const relayResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorRelayTransport(
      fetchMock,
      evaluator.url,
      relayRequests,
      relayResponses,
    );
    const { miniflare } = await createBackendHarness(fetchMock, {
      HERD_EVALUATOR_TRANSPORT: "client_relay",
      HERD_EVALUATOR_URL: EVALUATOR_RELAY_URL,
      HERD_EVALUATOR_RESULT_SIGNING_KEY_ID: EVALUATOR_SIGNING_KEY_ID,
      HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY: evaluatorSigningPublicKey,
    });
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const sessions = [];
    const rootSecrets = [];
    for (let number = 1; number <= 9; number += 1) {
      const session = await authenticate(miniflare, String(number));
      sessions.push(session);
      rootSecrets.push(await initializeAccountKey(miniflare, session));
    }
    const eventId = "c2000000-0000-4000-8000-000000000001";
    const eventInvitees = invitees("c1");
    const deadline = new Date(Date.now() + 6_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: eventId,
        title: "Nine-person relay confirmation",
        invitees: eventInvitees,
        deadline,
        minimumParticipants: 6,
        requiredGroups: [
          {
            id: "c3000000-0000-4000-8000-000000000001",
            memberIDs: [eventInvitees[0].id, eventInvitees[1].id],
          },
          {
            id: "c3000000-0000-4000-8000-000000000002",
            memberIDs: [eventInvitees[4].id],
          },
        ],
        eventDateOffset: 120_000,
      }),
    );
    const views = [];
    for (const session of sessions) {
      const response = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(response.status, 200);
      views.push((await response.json()).events.find(({ id }) => id === eventId));
    }
    const specs = [
      { response: "going", minimumParticipants: 6, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 6,
        requiredGroups: [
          {
            id: "c4000000-0000-4000-8000-000000000003",
            memberIDs: [eventInvitees[3].id],
          },
        ],
      },
      { response: "going", minimumParticipants: 6, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 6,
        requiredGroups: [
          {
            id: "c4000000-0000-4000-8000-000000000005",
            memberIDs: [eventInvitees[5].id, eventInvitees[6].id],
          },
        ],
      },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      { response: "going", minimumParticipants: 6, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 6,
        requiredGroups: [
          {
            id: "c4000000-0000-4000-8000-000000000009",
            memberIDs: [eventInvitees[7].id],
          },
        ],
      },
    ];
    for (const [index, spec] of specs.entries()) {
      await submitResponse({
        miniflare,
        session: sessions[index],
        rootSecret: rootSecrets[index],
        event: views[index],
        inviteeId: eventInvitees[index].id,
        allowedInviteeIds: eventInvitees.map(({ id }) => id),
        revision: 1,
        ...spec,
      });
    }
    await waitPast(deadline);

    const scheduled = await api(
      miniflare,
      "/api/internal/scheduled-resolutions",
      schedulerRequest(),
    );
    assert.equal(scheduled.status, 204, await scheduled.clone().text());
    assert.equal(relayRequests.length, 1);
    assert.deepEqual(relayResponses, [{ status: 200 }]);
    assertNoPrivateResponseLeak(relayRequests[0]);
    assert.equal(
      JSON.stringify(relayRequests[0]).includes(eventId),
      false,
    );

    const completedRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(sessions[0].accessToken),
    );
    assert.equal(completedRead.status, 200);
    const expectedAttending = [
      "host",
      eventInvitees[0].id,
      eventInvitees[2].id,
      eventInvitees[3].id,
      eventInvitees[4].id,
      eventInvitees[6].id,
    ];
    const resolution = (await completedRead.json()).events.find(
      ({ id }) => id === eventId,
    ).resolution;
    assert.equal(resolution.status, "confirmed");
    assert.deepEqual(resolution.attendingMemberIds, expectedAttending);
    assert.match(resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
    assert.equal(resolution.attestation.evaluatedAt, resolution.resolvedAt);
    assert.equal(resolution.attestation.signingKeyId, EVALUATOR_SIGNING_KEY_ID);
    for (const session of sessions) {
      const response = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(response.status, 200);
      const event = (await response.json()).events.find(({ id }) => id === eventId);
      assert.deepEqual(event.resolution, resolution);
      assertNoPrivateResponseLeak(event);
    }
  },
);

test(
  "real backend and evaluator resolve all nine test accounts without response leakage",
  { timeout: 45_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const evaluatorRequests = [];
    const evaluatorResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorTransport(
      fetchMock,
      evaluator.url,
      evaluatorRequests,
      evaluatorResponses,
    );
    const { miniflare, database, trustSigningRequests } =
      await createBackendHarness(fetchMock);
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const sessions = [];
    const rootSecrets = [];
    for (let number = 1; number <= 9; number += 1) {
      const session = await authenticate(miniflare, String(number));
      sessions.push(session);
      rootSecrets.push(await initializeAccountKey(miniflare, session));
    }
    assert.equal(new Set(sessions.map(({ user }) => user.id)).size, 9);
    assert.equal(new Set(sessions.map(({ accountKeyEpochId }) => accountKeyEpochId)).size, 9);

    const confirmedInvitees = invitees("93");
    const failedInvitees = invitees("97");
    const deadline = new Date(Date.now() + 8_000).toISOString();
    const confirmedEvent = await createEvent(
      miniflare,
      host,
      eventPayload({
        id: CONFIRMED_EVENT_ID,
        title: "Cross-service confirmation",
        invitees: confirmedInvitees,
        deadline,
        minimumParticipants: 5,
        requiredGroups: [
          {
            id: "94000000-0000-4000-8000-000000000001",
            memberIDs: [confirmedInvitees[0].id, confirmedInvitees[3].id],
          },
          {
            id: "94000000-0000-4000-8000-000000000002",
            memberIDs: [confirmedInvitees[4].id],
          },
        ],
        eventDateOffset: 120_000,
      }),
    );
    const failedEvent = await createEvent(
      miniflare,
      host,
      eventPayload({
        id: FAILED_EVENT_ID,
        title: "Cross-service non-confirmation",
        invitees: failedInvitees,
        deadline,
        minimumParticipants: 8,
        requiredGroups: [],
        eventDateOffset: 180_000,
      }),
    );
    assert.ok(confirmedEvent.privateResponsePolicy?.policyHash);
    assert.ok(failedEvent.privateResponsePolicy?.policyHash);

    const confirmedViews = [];
    const failedViews = [];
    for (const session of sessions) {
      const response = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(response.status, 200);
      const events = (await response.json()).events;
      const confirmed = events.find(({ id }) => id === CONFIRMED_EVENT_ID);
      const failed = events.find(({ id }) => id === FAILED_EVENT_ID);
      assert.ok(confirmed?.inviteToken);
      assert.ok(failed?.inviteToken);
      assert.deepEqual(confirmed.resolution, { status: "pending" });
      assert.deepEqual(failed.resolution, { status: "pending" });
      confirmedViews.push(confirmed);
      failedViews.push(failed);
    }

    const confirmedSpecs = [
      { response: "going", minimumParticipants: 5, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 5,
        requiredGroups: [
          {
            id: "95000000-0000-4000-8000-000000000001",
            memberIDs: [confirmedInvitees[2].id, confirmedInvitees[3].id],
          },
        ],
      },
      { response: "going", minimumParticipants: 5, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 5,
        requiredGroups: [
          {
            id: "95000000-0000-4000-8000-000000000002",
            memberIDs: [confirmedInvitees[5].id],
          },
        ],
      },
      { response: "going", minimumParticipants: 5, requiredGroups: [] },
      { response: "going", minimumParticipants: 5, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 5,
        requiredGroups: [
          {
            id: "95000000-0000-4000-8000-000000000003",
            memberIDs: [confirmedInvitees[7].id],
          },
        ],
      },
    ];
    const confirmedSubmissions = [];
    for (const [index, spec] of confirmedSpecs.entries()) {
      confirmedSubmissions.push(
        await submitResponse({
          miniflare,
          session: sessions[index],
          rootSecret: rootSecrets[index],
          event: confirmedViews[index],
          inviteeId: confirmedInvitees[index].id,
          allowedInviteeIds: confirmedInvitees.map(({ id }) => id),
          revision: 1,
          ...spec,
        }),
      );
    }
    const exactRetry = await api(
      miniflare,
      `/api/invites/${confirmedViews[0].inviteToken}/rsvp`,
      jsonRequest(
        "PUT",
        { envelope: confirmedSubmissions[0].sealed.envelope },
        sessions[0].accessToken,
      ),
    );
    assert.equal(exactRetry.status, 200);
    assert.deepEqual(await exactRetry.json(), confirmedSubmissions[0].receipt);

    const seventhRevision = await submitResponse({
      miniflare,
      session: sessions[6],
      rootSecret: rootSecrets[6],
      event: confirmedViews[6],
      inviteeId: confirmedInvitees[6].id,
      allowedInviteeIds: confirmedInvitees.map(({ id }) => id),
      revision: 2,
      response: "going",
      minimumParticipants: 10,
      requiredGroups: [],
    });
    assert.equal(seventhRevision.receipt.receipt.revision, 2);

    const failedSpecs = [
      { response: "going", minimumParticipants: 8, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 8,
        requiredGroups: [
          {
            id: "98000000-0000-4000-8000-000000000001",
            memberIDs: [failedInvitees[2].id],
          },
        ],
      },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      { response: "going", minimumParticipants: 8, requiredGroups: [] },
      { response: "going", minimumParticipants: 10, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      {
        response: "going",
        minimumParticipants: 8,
        requiredGroups: [
          {
            id: "98000000-0000-4000-8000-000000000002",
            memberIDs: [failedInvitees[7].id],
          },
        ],
      },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
      { response: "cant_commit", minimumParticipants: null, requiredGroups: [] },
    ];
    for (const [index, spec] of failedSpecs.entries()) {
      await submitResponse({
        miniflare,
        session: sessions[index],
        rootSecret: rootSecrets[index],
        event: failedViews[index],
        inviteeId: failedInvitees[index].id,
        allowedInviteeIds: failedInvitees.map(({ id }) => id),
        revision: 1,
        ...spec,
      });
    }

    assert.ok(Date.now() < Date.parse(deadline));
    assert.equal(evaluatorRequests.length, 0);
    await waitPast(deadline);

    const hostRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(hostRead.status, 200, JSON.stringify(await hostRead.clone().json()));
    const hostEvents = (await hostRead.json()).events;
    const confirmed = hostEvents.find(({ id }) => id === CONFIRMED_EVENT_ID);
    const failed = hostEvents.find(({ id }) => id === FAILED_EVENT_ID);
    const expectedAttending = [
      "host",
      confirmedInvitees[0].id,
      confirmedInvitees[1].id,
      confirmedInvitees[2].id,
      confirmedInvitees[4].id,
      confirmedInvitees[5].id,
    ];
    assert.deepEqual(confirmed.resolution, {
      status: "confirmed",
      attendingMemberIds: expectedAttending,
      attendanceRevealed: true,
      resolvedAt: confirmed.resolution.resolvedAt,
      guestStates: confirmedInvitees.map(({ id }) => ({
        memberId: id,
        status: expectedAttending.includes(id) ? "going" : "cant_commit",
        missedDeadline: false,
      })),
    }, JSON.stringify(evaluatorResponses));
    assert.match(confirmed.resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
    assert.deepEqual(failed.resolution, {
      status: "not_confirmed",
      resolvedAt: failed.resolution.resolvedAt,
    });
    assert.match(failed.resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
    assertNoPrivateResponseLeak(confirmed);
    assertNoPrivateResponseLeak(failed);
    assert.equal(evaluatorRequests.length, 2);
    assert.equal(evaluatorResponses.length, 2);
    assert.ok(evaluatorResponses.every(({ status }) => status === 200));
    const confirmedEvaluatorResponse = evaluatorResponses.find(
      ({ body }) => body.eventId === CONFIRMED_EVENT_ID,
    );
    const failedEvaluatorResponse = evaluatorResponses.find(
      ({ body }) => body.eventId === FAILED_EVENT_ID,
    );
    assert.deepEqual(confirmedEvaluatorResponse.body.attendingMemberIds, expectedAttending);
    assert.equal(confirmedEvaluatorResponse.body.status, "confirmed");
    assert.equal(failedEvaluatorResponse.body.status, "not_confirmed");
    assert.equal(Object.hasOwn(failedEvaluatorResponse.body, "attendingMemberIds"), false);

    for (const request of evaluatorRequests) {
      assert.equal(request.protocolVersion, 1);
      assert.equal(request.slots.length, 9);
      assert.ok(request.slots.every(({ envelope, envelopeHash }) => envelope && envelopeHash));
      for (const { envelope } of request.slots) {
        assert.equal(Buffer.from(envelope.payloadCiphertext, "base64url").length, 4_124);
        assert.equal(Buffer.from(envelope.userKeyWrap, "base64url").length, 60);
        assert.equal(Buffer.from(envelope.evaluatorKeyWrap, "base64url").length, 157);
        assert.equal(Object.hasOwn(envelope, "response"), false);
        assert.equal(Object.hasOwn(envelope, "minimumParticipants"), false);
        assert.equal(Object.hasOwn(envelope, "requiredGroups"), false);
      }
    }
    const confirmedEvaluatorRequest = evaluatorRequests.find(
      ({ eventId }) => eventId === CONFIRMED_EVENT_ID,
    );
    assert.equal(confirmedEvaluatorRequest.slots[6].envelope.revision, 2);

    const inviteeResolutions = [];
    for (const session of sessions) {
      const response = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(response.status, 200);
      const events = (await response.json()).events;
      const invitedConfirmed = events.find(({ id }) => id === CONFIRMED_EVENT_ID);
      const invitedFailed = events.find(({ id }) => id === FAILED_EVENT_ID);
      assert.deepEqual(invitedConfirmed.resolution, confirmed.resolution);
      assert.deepEqual(invitedFailed.resolution, failed.resolution);
      assert.deepEqual(Object.keys(invitedFailed.resolution).sort(), [
        "resolvedAt",
        "status",
      ]);
      assert.ok(invitedConfirmed.invitees.every((invitee) => !invitee.phoneNumber));
      assertNoPrivateResponseLeak(invitedConfirmed);
      assertNoPrivateResponseLeak(invitedFailed);
      inviteeResolutions.push([
        invitedConfirmed.resolution,
        invitedFailed.resolution,
      ]);
    }
    assert.equal(evaluatorRequests.length, 2);

    const repeatedHostRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(repeatedHostRead.status, 200);
    const repeatedHostEvents = (await repeatedHostRead.json()).events;
    const repeatedGuestReads = await Promise.all(
      sessions.map((session) =>
        api(miniflare, "/api/events", authorizedRequest(session.accessToken)),
      ),
    );
    assert.ok(repeatedGuestReads.every(({ status }) => status === 200));
    assert.equal(evaluatorRequests.length, 2);
    assert.deepEqual(
      repeatedHostEvents.find(({ id }) => id === CONFIRMED_EVENT_ID).resolution,
      confirmed.resolution,
    );
    assert.deepEqual(
      repeatedHostEvents.find(({ id }) => id === FAILED_EVENT_ID).resolution,
      failed.resolution,
    );

    const resolutions = await database
      .prepare(
        `SELECT event_id AS eventId, status, batch_hash AS batchHash,
                attending_member_ids AS attendingMemberIds,
                resolved_at AS resolvedAt
         FROM event_resolutions
         WHERE event_id IN (?, ?)
         ORDER BY event_id ASC`,
      )
      .bind(CONFIRMED_EVENT_ID, FAILED_EVENT_ID)
      .all();
    assert.deepEqual(
      resolutions.results.map(({ eventId, status }) => ({ eventId, status })),
      [
        { eventId: CONFIRMED_EVENT_ID, status: "confirmed" },
        { eventId: FAILED_EVENT_ID, status: "not_confirmed" },
      ],
    );
    assert.equal(resolutions.results[0].batchHash.length, 43);
    assert.deepEqual(
      JSON.parse(resolutions.results[0].attendingMemberIds),
      expectedAttending,
    );
    assert.equal(resolutions.results[1].batchHash.length, 43);
    assert.equal(resolutions.results[1].attendingMemberIds, null);
    assert.equal(resolutions.results[0].resolvedAt, confirmed.resolution.resolvedAt);
    assert.equal(resolutions.results[1].resolvedAt, failed.resolution.resolvedAt);

    const envelopeCounts = await database
      .prepare(
        `SELECT event_id AS eventId, COUNT(*) AS count
         FROM response_envelopes
         WHERE event_id IN (?, ?)
         GROUP BY event_id
         ORDER BY event_id ASC`,
      )
      .bind(CONFIRMED_EVENT_ID, FAILED_EVENT_ID)
      .all();
    assert.deepEqual(envelopeCounts.results, [
      { eventId: CONFIRMED_EVENT_ID, count: 10 },
      { eventId: FAILED_EVENT_ID, count: 9 },
    ]);
    const initializedEpochs = await database
      .prepare(
        `SELECT COUNT(*) AS count
         FROM account_key_epochs
         WHERE key_commitment IS NOT NULL AND superseded_at IS NULL`,
      )
      .first();
    assert.equal(initializedEpochs.count, 9);
    const deliveryRows = await database
      .prepare(
        `SELECT COUNT(*) AS count,
                SUM(CASE WHEN status = 'suppressed' THEN 1 ELSE 0 END) AS suppressedCount
         FROM invitation_deliveries`,
      )
      .first();
    assert.equal(deliveryRows.count, 18);
    assert.equal(deliveryRows.suppressedCount, 0);
    assert.ok(
      trustSigningRequests.filter((kind) => kind === "policy").length >= 2,
    );
    assert.equal(
      trustSigningRequests.filter((kind) => kind === "append").length,
      19,
    );
  },
);

test(
  "all nine test aliases complete the real invite and reply lifecycle through the built API",
  { timeout: 45_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const evaluatorRequests = [];
    const evaluatorResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorTransport(
      fetchMock,
      evaluator.url,
      evaluatorRequests,
      evaluatorResponses,
    );
    const { miniflare, database } = await createBackendHarness(fetchMock);
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const sessions = Array(9);
    const rootSecrets = Array(9);
    const accountsCreatedBeforeInvite = [0, 2, 4, 6, 8];
    for (const index of accountsCreatedBeforeInvite) {
      sessions[index] = await authenticate(miniflare, String(index + 1));
      rootSecrets[index] = await initializeAccountKey(miniflare, sessions[index]);
    }

    const eventId = "b1000000-0000-4000-8000-000000000001";
    const eventInvitees = invitees("b2");
    const deadline = new Date(Date.now() + 8_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: eventId,
        title: "Nine-account invite lifecycle acceptance",
        invitees: eventInvitees,
        deadline,
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 120_000,
      }),
    );

    assert.equal(
      await database
        .prepare(
          `SELECT COUNT(*) AS count
           FROM invitees
           WHERE event_id = ? AND user_id IS NOT NULL`,
        )
        .bind(eventId)
        .first("count"),
      accountsCreatedBeforeInvite.length,
    );
    for (let index = 0; index < sessions.length; index += 1) {
      if (sessions[index]) continue;
      sessions[index] = await authenticate(miniflare, String(index + 1));
      rootSecrets[index] = await initializeAccountKey(miniflare, sessions[index]);
    }
    assert.equal(new Set(sessions.map(({ user }) => user.id)).size, 9);
    assert.equal(
      new Set(sessions.map(({ accountKeyEpochId }) => accountKeyEpochId)).size,
      9,
    );

    const inviteViews = [];
    for (const session of sessions) {
      const listing = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(listing.status, 200);
      const invitedEvent = (await listing.json()).events.find(
        ({ id }) => id === eventId,
      );
      assert.ok(invitedEvent?.inviteToken);
      assert.deepEqual(invitedEvent.resolution, { status: "pending" });
      inviteViews.push(invitedEvent);
    }
    assert.equal(new Set(inviteViews.map(({ inviteToken }) => inviteToken)).size, 9);

    const storedInvitations = await database
      .prepare(
        `SELECT COUNT(*) AS count,
                COUNT(DISTINCT user_id) AS accountCount
         FROM invitees
         WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(storedInvitations, { count: 9, accountCount: 9 });

    const acceptedRevisions = [];
    const lateRevisions = [];
    for (const [index, event] of inviteViews.entries()) {
      const publicOpen = await api(
        miniflare,
        `/api/invites/${event.inviteToken}`,
      );
      assert.equal(publicOpen.status, 401);

      const authenticatedOpen = await api(
        miniflare,
        `/api/invites/${event.inviteToken}`,
        authorizedRequest(sessions[index].accessToken),
      );
      assert.equal(authenticatedOpen.status, 200);
      const authenticatedProjection = await authenticatedOpen.json();
      assert.equal(authenticatedProjection.event.id, eventId);
      assert.equal(authenticatedProjection.inviteMetadata.authenticated, true);
      assert.equal(authenticatedProjection.inviteMetadata.canRespond, true);
      assert.equal(authenticatedProjection.inviteMetadata.hasResponse, false);
      assert.equal(authenticatedProjection.inviteMetadata.responseRevision, null);

      const allowedInviteeIds = eventInvitees.map(({ id }) => id);
      const firstReply = index % 2 === 0 ? "going" : "cant_commit";
      const secondReply = firstReply === "going" ? "cant_commit" : "going";
      const firstSealed = await responseCrypto.sealPrivateResponse({
        eventId,
        inviteeId: eventInvitees[index].id,
        accountKeyEpochId: sessions[index].accountKeyEpochId,
        revision: 1,
        response: firstReply,
        minimumParticipants: firstReply === "going" ? 2 + (index % 3) : null,
        requiredGroups: [],
        allowedInviteeIds,
        accountRootSecret: rootSecrets[index],
        policy: event.privateResponsePolicy,
      });
      for (const [wrongIndex, wrongSession] of sessions.entries()) {
        if (wrongIndex === index) continue;
        const wrongAccountOpen = await api(
          miniflare,
          `/api/invites/${event.inviteToken}`,
          authorizedRequest(wrongSession.accessToken),
        );
        assert.equal(
          wrongAccountOpen.status,
          403,
          `invite ${index + 1} opened by wrong account ${wrongIndex + 1}`,
        );
        assert.equal(
          (await wrongAccountOpen.json()).error.code,
          "invite_for_different_account",
        );

        const wrongAccountWrite = await api(
          miniflare,
          `/api/invites/${event.inviteToken}/rsvp`,
          jsonRequest(
            "PUT",
            { envelope: firstSealed.envelope },
            wrongSession.accessToken,
          ),
        );
        assert.equal(
          wrongAccountWrite.status,
          403,
          `invite ${index + 1} written by wrong account ${wrongIndex + 1}`,
        );
        assert.equal(
          (await wrongAccountWrite.json()).error.code,
          "invite_for_different_account",
        );
      }

      const firstWrites = await Promise.all(
        Array.from({ length: 2 }, () =>
          api(
            miniflare,
            `/api/invites/${event.inviteToken}/rsvp`,
            jsonRequest(
              "PUT",
              { envelope: firstSealed.envelope },
              sessions[index].accessToken,
            ),
          ),
        ),
      );
      assert.deepEqual(firstWrites.map(({ status }) => status), [200, 200]);
      const firstResults = await Promise.all(firstWrites.map((response) => response.json()));
      assert.deepEqual(
        withoutReceiptSignature(firstResults[1]),
        withoutReceiptSignature(firstResults[0]),
      );
      for (const result of firstResults) {
        await trustVerification.verifyPrivateResponseReceiptPublication(
          result.receipt,
          transparencySigning,
          (pathname, init) => api(miniflare, String(pathname), init),
        );
      }

      const secondDraft = {
        eventId,
        inviteeId: eventInvitees[index].id,
        accountKeyEpochId: sessions[index].accountKeyEpochId,
        revision: 2,
        response: secondReply,
        minimumParticipants: secondReply === "going" ? 2 + (index % 3) : null,
        requiredGroups: [],
        allowedInviteeIds,
        accountRootSecret: rootSecrets[index],
        policy: event.privateResponsePolicy,
      };
      const competingSecondSeals = await Promise.all([
        responseCrypto.sealPrivateResponse(secondDraft),
        responseCrypto.sealPrivateResponse(secondDraft),
      ]);
      assert.notEqual(
        competingSecondSeals[0].envelope.envelopeId,
        competingSecondSeals[1].envelope.envelopeId,
      );
      const competingSecondWrites = await Promise.all(
        competingSecondSeals.map(({ envelope }) =>
          api(
            miniflare,
            `/api/invites/${event.inviteToken}/rsvp`,
            jsonRequest(
              "PUT",
              { envelope },
              sessions[index].accessToken,
            ),
          ),
        ),
      );
      assert.deepEqual(
        competingSecondWrites.map(({ status }) => status).sort((a, b) => a - b),
        [200, 409],
      );
      const competingSecondPayloads = await Promise.all(
        competingSecondWrites.map((response) => response.json()),
      );
      const winningIndex = competingSecondWrites.findIndex(({ status }) => status === 200);
      const losingIndex = 1 - winningIndex;
      const revised = competingSecondPayloads[winningIndex];
      assert.equal(revised.responseEnvelope.revision, 2);
      acceptedRevisions[index] = {
        envelope: competingSecondSeals[winningIndex].envelope,
        result: revised,
      };
      await trustVerification.verifyPrivateResponseReceiptPublication(
        revised.receipt,
        transparencySigning,
        (pathname, init) => api(miniflare, String(pathname), init),
      );
      assert.equal(
        competingSecondPayloads[losingIndex].error.code,
        "response_revision_conflict",
      );

      const revisedRetry = await api(
        miniflare,
        `/api/invites/${event.inviteToken}/rsvp`,
        jsonRequest(
          "PUT",
          { envelope: competingSecondSeals[winningIndex].envelope },
          sessions[index].accessToken,
        ),
      );
      assert.equal(revisedRetry.status, 200);
      assert.deepEqual(await revisedRetry.json(), revised);

      const revisedOpen = await api(
        miniflare,
        `/api/invites/${event.inviteToken}`,
        authorizedRequest(sessions[index].accessToken),
      );
      assert.equal(revisedOpen.status, 200);
      const revisedProjection = await revisedOpen.json();
      assert.equal(revisedProjection.inviteMetadata.hasResponse, true);
      assert.equal(revisedProjection.inviteMetadata.responseRevision, 2);
      assert.equal(
        Object.hasOwn(revisedProjection.inviteMetadata.responseEnvelope, "response"),
        false,
      );
    }

    const pendingHostRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(pendingHostRead.status, 200);
    const pendingHostEvent = (await pendingHostRead.json()).events.find(
      ({ id }) => id === eventId,
    );
    assert.deepEqual(pendingHostEvent.resolution, { status: "pending" });
    assertNoPrivateResponseLeak(pendingHostEvent);
    assert.equal(evaluatorRequests.length, 0);

    const storedResponses = await database
      .prepare(
        `SELECT COUNT(*) AS count,
                COUNT(DISTINCT invitee_id) AS inviteeCount,
                MIN(revision) AS minimumRevision,
                MAX(revision) AS maximumRevision
         FROM response_envelopes
         WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.deepEqual(storedResponses, {
      count: 18,
      inviteeCount: 9,
      minimumRevision: 1,
      maximumRevision: 2,
    });
    const transparencyEntries = await database
      .prepare(
        `SELECT COUNT(*) AS count
         FROM response_transparency_entries AS transparency
         JOIN response_envelopes AS envelopes
           ON envelopes.id = transparency.envelope_id
         WHERE envelopes.event_id = ?`,
      )
      .bind(eventId)
      .first("count");
    assert.equal(transparencyEntries, 18);

    assert.ok(Date.now() < Date.parse(deadline));
    await waitPast(deadline);
    for (const [index, event] of inviteViews.entries()) {
      const expiredEnvelope = await responseCrypto.sealPrivateResponse({
        eventId,
        inviteeId: eventInvitees[index].id,
        accountKeyEpochId: sessions[index].accountKeyEpochId,
        revision: 3,
        response: index % 2 === 0 ? "going" : "cant_commit",
        minimumParticipants: index % 2 === 0 ? 2 : null,
        requiredGroups: [],
        allowedInviteeIds: eventInvitees.map(({ id }) => id),
        accountRootSecret: rootSecrets[index],
        policy: event.privateResponsePolicy,
      });
      const expiredWrite = await api(
        miniflare,
        `/api/invites/${event.inviteToken}/rsvp`,
        jsonRequest(
          "PUT",
          { envelope: expiredEnvelope.envelope },
          sessions[index].accessToken,
        ),
      );
      assert.equal(expiredWrite.status, 200);
      lateRevisions.push({
        envelope: expiredEnvelope.envelope,
        result: await expiredWrite.clone().json(),
      });
    }
    assert.equal(
      await database
        .prepare(
          `SELECT COUNT(*) AS count
           FROM response_envelopes
           WHERE event_id = ?`,
        )
        .bind(eventId)
        .first("count"),
      27,
    );

    const resolvedHostRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(
      resolvedHostRead.status,
      200,
      JSON.stringify(await resolvedHostRead.clone().json()),
    );
    const resolvedHostEvent = (await resolvedHostRead.json()).events.find(
      ({ id }) => id === eventId,
    );
    const expectedAttending = [
      "host",
      ...eventInvitees
        .filter((_, index) => index % 2 === 0)
        .map(({ id }) => id),
    ];
    assert.deepEqual(resolvedHostEvent.resolution, {
      status: "confirmed",
      attendingMemberIds: expectedAttending,
      attendanceRevealed: true,
      resolvedAt: resolvedHostEvent.resolution.resolvedAt,
      guestStates: eventInvitees.map(({ id }, index) => ({
        memberId: id,
        status: index % 2 === 0 ? "going" : "cant_commit",
        missedDeadline: false,
      })),
    });
    assert.match(resolvedHostEvent.resolution.resolvedAt, /^\d{4}-\d{2}-\d{2}T/u);
    assertNoPrivateResponseLeak(resolvedHostEvent);
    assert.equal(evaluatorRequests.length, 1);
    assert.equal(evaluatorResponses.length, 1);
    assert.equal(evaluatorResponses[0].status, 200);
    assert.deepEqual(evaluatorResponses[0].body.attendingMemberIds, expectedAttending);

    for (const [index, event] of inviteViews.entries()) {
      const finalizedInviteOpen = await api(
        miniflare,
        `/api/invites/${event.inviteToken}`,
        authorizedRequest(sessions[index].accessToken),
      );
      assert.equal(finalizedInviteOpen.status, 200);
      const finalizedProjection = await finalizedInviteOpen.json();
      assert.deepEqual(
        finalizedProjection.event.resolution,
        resolvedHostEvent.resolution,
      );
      assert.equal(finalizedProjection.inviteMetadata.hasResponse, true);
      assert.equal(finalizedProjection.inviteMetadata.responseRevision, 3);
      assertNoPrivateResponseLeak(finalizedProjection.event);

      // A device that lost the successful HTTP response must be able to retry
      // the exact encrypted write even after the deadline and finalization.
      const finalizedExactRetry = await api(
        miniflare,
        `/api/invites/${event.inviteToken}/rsvp`,
        jsonRequest(
          "PUT",
          { envelope: lateRevisions[index].envelope },
          sessions[index].accessToken,
        ),
      );
      assert.equal(finalizedExactRetry.status, 200);
      assert.deepEqual(
        await finalizedExactRetry.json(),
        lateRevisions[index].result,
      );
    }
    assert.equal(evaluatorRequests.length, 1);
    assert.equal(
      await database
        .prepare(
          `SELECT COUNT(*) AS count
           FROM response_envelopes
           WHERE event_id = ?`,
        )
        .bind(eventId)
        .first("count"),
      27,
    );
    assert.equal(
      await database
        .prepare(
          `SELECT COUNT(*) AS count
           FROM response_transparency_entries AS transparency
           JOIN response_envelopes AS envelopes
             ON envelopes.id = transparency.envelope_id
           WHERE envelopes.event_id = ?`,
        )
        .bind(eventId)
        .first("count"),
      27,
    );

    const storedResolution = await database
      .prepare(
        `SELECT status, attending_member_ids AS attendingMemberIds,
                batch_hash AS batchHash
         FROM event_resolutions
         WHERE event_id = ?`,
      )
      .bind(eventId)
      .first();
    assert.equal(storedResolution.status, "confirmed");
    assert.deepEqual(JSON.parse(storedResolution.attendingMemberIds), expectedAttending);
    assert.equal(storedResolution.batchHash.length, 43);
  },
);

test(
  "one undecryptable invitee envelope becomes a nonresponse instead of poisoning resolution",
  { timeout: 30_000 },
  async (t) => {
    const evaluator = await startEvaluatorService();
    t.after(() => evaluator.stop());
    const evaluatorRequests = [];
    const evaluatorResponses = [];
    const fetchMock = createFetchMock();
    installEvaluatorTransport(
      fetchMock,
      evaluator.url,
      evaluatorRequests,
      evaluatorResponses,
    );
    const { miniflare, database } = await createBackendHarness(fetchMock);
    t.after(() => miniflare.dispose());

    const host = await authenticate(miniflare, HOST_PHONE);
    const sessions = [
      await authenticate(miniflare, "1"),
      await authenticate(miniflare, "2"),
    ];
    const rootSecrets = [
      await initializeAccountKey(miniflare, sessions[0]),
      await initializeAccountKey(miniflare, sessions[1]),
    ];
    const eventInvitees = invitees("a1").slice(0, 2);
    const deadline = new Date(Date.now() + 3_000).toISOString();
    await createEvent(
      miniflare,
      host,
      eventPayload({
        id: POISON_EVENT_ID,
        title: "Poisoned response isolation",
        invitees: eventInvitees,
        deadline,
        minimumParticipants: 2,
        requiredGroups: [],
        eventDateOffset: 60_000,
      }),
    );

    const views = [];
    for (const session of sessions) {
      const response = await api(
        miniflare,
        "/api/events",
        authorizedRequest(session.accessToken),
      );
      assert.equal(response.status, 200);
      views.push(
        (await response.json()).events.find(({ id }) => id === POISON_EVENT_ID),
      );
    }
    assert.ok(views.every((event) => event?.inviteToken));

    const sealedPoison = await responseCrypto.sealPrivateResponse({
      eventId: POISON_EVENT_ID,
      inviteeId: eventInvitees[0].id,
      accountKeyEpochId: sessions[0].accountKeyEpochId,
      revision: 1,
      response: "going",
      minimumParticipants: 2,
      requiredGroups: [],
      allowedInviteeIds: eventInvitees.map(({ id }) => id),
      accountRootSecret: rootSecrets[0],
      policy: views[0].privateResponsePolicy,
    });
    const poisonedCiphertext = Buffer.from(
      sealedPoison.envelope.payloadCiphertext,
      "base64url",
    );
    poisonedCiphertext[poisonedCiphertext.length - 1] ^= 1;
    const poisonedEnvelope = await authorizeMutatedResponseEnvelope(
      {
        ...sealedPoison.envelope,
        payloadCiphertext: poisonedCiphertext.toString("base64url"),
      },
      rootSecrets[0],
    );
    const poisonWrite = await api(
      miniflare,
      `/api/invites/${views[0].inviteToken}/rsvp`,
      jsonRequest(
        "PUT",
        { envelope: poisonedEnvelope },
        sessions[0].accessToken,
      ),
    );
    assert.equal(
      poisonWrite.status,
      200,
      JSON.stringify(await poisonWrite.clone().json()),
    );

    await submitResponse({
      miniflare,
      session: sessions[1],
      rootSecret: rootSecrets[1],
      event: views[1],
      inviteeId: eventInvitees[1].id,
      allowedInviteeIds: eventInvitees.map(({ id }) => id),
      revision: 1,
      response: "going",
      minimumParticipants: 2,
      requiredGroups: [],
    });

    await waitPast(deadline);
    const hostRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(hostRead.status, 200, JSON.stringify(await hostRead.clone().json()));
    const resolved = (await hostRead.json()).events.find(
      ({ id }) => id === POISON_EVENT_ID,
    );
    assert.deepEqual(resolved.resolution, {
      status: "confirmed",
      attendingMemberIds: ["host", eventInvitees[1].id],
      attendanceRevealed: true,
      resolvedAt: resolved.resolution.resolvedAt,
      guestStates: [
        {
          memberId: eventInvitees[0].id,
          status: "cant_commit",
          missedDeadline: false,
        },
        {
          memberId: eventInvitees[1].id,
          status: "going",
          missedDeadline: false,
        },
      ],
    });
    assertNoPrivateResponseLeak(resolved);

    assert.equal(evaluatorRequests.length, 1);
    assert.equal(evaluatorResponses.length, 1);
    assert.equal(evaluatorResponses[0].status, 200);
    assert.deepEqual(evaluatorResponses[0].body, {
      protocolVersion: 1,
      eventId: POISON_EVENT_ID,
      policyHash: resolved.privateResponsePolicy.policyHash,
      batchHash: evaluatorRequests[0].batchHash,
      evaluatorKeyId: EVALUATOR_KEY_ID,
      status: "confirmed",
      revealAttendance: true,
      attendingMemberIds: ["host", eventInvitees[1].id],
    });
    assert.equal(
      JSON.stringify(evaluatorResponses[0].body).includes("invalid"),
      false,
    );

    const repeatedRead = await api(
      miniflare,
      "/api/events",
      authorizedRequest(host.accessToken),
    );
    assert.equal(repeatedRead.status, 200);
    assert.equal(evaluatorRequests.length, 1);
    const stored = await database
      .prepare(
        `SELECT status, attending_member_ids AS attendingMemberIds
         FROM event_resolutions
         WHERE event_id = ?`,
      )
      .bind(POISON_EVENT_ID)
      .first();
    assert.deepEqual(stored, {
      status: "confirmed",
      attendingMemberIds: JSON.stringify(["host", eventInvitees[1].id]),
    });
  },
);
