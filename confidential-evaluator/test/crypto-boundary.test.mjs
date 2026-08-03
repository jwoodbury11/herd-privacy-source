import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import test from "node:test";

import {
  attestedImageDigestFromOidcToken,
  ConfidentialSpaceAttestationProvider,
  ConfidentialSpaceFederatedAccessTokenProvider,
  GoogleKmsBundleDecryptor,
} from "../src/confidential-space.mjs";
import { ConfigurationError } from "../src/errors.mjs";
import { loadKeyStore, parseKeyBundles } from "../src/key-bundle.mjs";
import {
  kmsPlaintextResponse,
  makeBundle,
  makeKeyStore,
  makeTransparencyBundle,
  TEST_IMAGE_DIGEST,
  TOKEN,
  testConfig,
  testDeploymentConfig,
} from "./helpers.mjs";

function oidcToken({
  imageDigest = TEST_IMAGE_DIGEST,
  restartPolicy = "Always",
  cmdOverride = [],
  envOverride = {},
  omitEmptyOverrides = false,
  memoryMonitoring = false,
  hwmodel = "GCP_INTEL_TDX",
} = {}) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString(
    "base64url",
  );
  const payload = Buffer.from(
    JSON.stringify({
      aud: "https://sts.googleapis.com",
      iss: "https://confidentialcomputing.googleapis.com",
      swname: "CONFIDENTIAL_SPACE",
      dbgstat: "disabled-since-boot",
      secboot: true,
      hwmodel,
      attester_tcb: ["INTEL"],
      submods: {
        container: {
          image_digest: imageDigest,
          args: ["docker-entrypoint.sh", "node", "src/server.mjs"],
          env: {
            HERD_DEPLOYMENT_CONFIG_FILE: "/app/config/deployment.json",
            HOSTNAME: "herd-evaluator-tdx-ab12",
            NODE_ENV: "production",
            NODE_VERSION: "22.13.0",
            PATH: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            YARN_VERSION: "1.22.22",
          },
          ...(omitEmptyOverrides ? {} : { cmd_override: cmdOverride }),
          ...(omitEmptyOverrides ? {} : { env_override: envOverride }),
          restart_policy: restartPolicy,
        },
        confidential_space: {
          support_attributes: ["STABLE"],
          monitoring_enabled: { memory: memoryMonitoring },
        },
      },
    }),
  ).toString("base64url");
  return `${header}.${payload}.c2lnbmF0dXJl`;
}

function launcherRequest(token, calls) {
  return (options, callback) => {
    const operation = new EventEmitter();
    operation.end = (body) => {
      calls.push({ options, body: JSON.parse(Buffer.from(body).toString("utf8")) });
      const response = Readable.from([Buffer.from(token)]);
      response.statusCode = 200;
      callback(response);
    };
    operation.destroy = (error) => operation.emit("error", error);
    return operation;
  };
}

test("loads four distinct P-256 keys and binds every public key", async () => {
  const keyStore = await makeKeyStore();
  assert.deepEqual(Object.keys(keyStore.metadata.keys), [
    "responseDecryption",
    "evaluationResultSigning",
    "policySigning",
    "transparencySigning",
  ]);
  assert.equal(new Set(Object.values(keyStore.metadata.keys).map((key) => key.keyId)).size, 4);
  assert.equal(
    new Set(Object.values(keyStore.metadata.keys).map((key) => key.publicKey)).size,
    4,
  );
  assert.match(keyStore.keyBindingHash, /^[A-Za-z0-9_-]{43}$/u);
  assert.equal(JSON.stringify(keyStore).includes(TOKEN), false);
  assert.equal(JSON.stringify(keyStore).includes("requestAuthenticationToken"), false);
});

test("rejects reuse of one private key for two domains", async () => {
  const config = testConfig();
  const bundle = await makeBundle();
  const transparencyBundle = await makeTransparencyBundle();
  bundle.policySigningKey = structuredClone(bundle.evaluationResultSigningKey);
  bundle.policySigningKey.keyId = "different-id-but-same-key";
  await assert.rejects(
    parseKeyBundles(
      Uint8Array.from(Buffer.from(JSON.stringify(bundle), "utf8")),
      Uint8Array.from(
        Buffer.from(JSON.stringify(transparencyBundle), "utf8"),
      ),
      config,
      config.evaluatorMeasurement,
    ),
    ConfigurationError,
  );
});

test("evaluator epochs reuse one separately parsed global transparency identity", async () => {
  const firstConfig = testConfig();
  const secondConfig = testConfig({ releaseId: "herd-confidential-test-v2" });
  const firstBundle = await makeBundle();
  const secondBundle = await makeBundle({ releaseId: secondConfig.releaseId });
  const transparencyBundle = await makeTransparencyBundle();
  const encodedTransparency = JSON.stringify(transparencyBundle);
  const first = await parseKeyBundles(
    Uint8Array.from(Buffer.from(JSON.stringify(firstBundle))),
    Uint8Array.from(Buffer.from(encodedTransparency)),
    firstConfig,
    firstConfig.evaluatorMeasurement,
  );
  const second = await parseKeyBundles(
    Uint8Array.from(Buffer.from(JSON.stringify(secondBundle))),
    Uint8Array.from(Buffer.from(encodedTransparency)),
    secondConfig,
    secondConfig.evaluatorMeasurement,
  );

  assert.equal(
    first.metadata.keys.transparencySigning.keyId,
    second.metadata.keys.transparencySigning.keyId,
  );
  assert.equal(
    first.metadata.keys.transparencySigning.publicKey,
    second.metadata.keys.transparencySigning.publicKey,
  );
  assert.notEqual(
    first.metadata.keys.responseDecryption.publicKey,
    second.metadata.keys.responseDecryption.publicKey,
  );
});

test("epoch bundles cannot smuggle a replacement transparency key", async () => {
  const config = testConfig();
  const epochBundle = await makeBundle();
  const transparencyBundle = await makeTransparencyBundle();
  epochBundle.transparencySigningKey =
    transparencyBundle.transparencySigningKey;
  await assert.rejects(
    parseKeyBundles(
      Uint8Array.from(Buffer.from(JSON.stringify(epochBundle))),
      Uint8Array.from(Buffer.from(JSON.stringify(transparencyBundle))),
      config,
      config.evaluatorMeasurement,
    ),
    ConfigurationError,
  );
});

test("loads epoch and global identity ciphertexts through independent attested KMS gates", async () => {
  const config = testDeploymentConfig();
  const epochBundle = Buffer.from(JSON.stringify(await makeBundle()));
  const transparencyBundle = Buffer.from(
    JSON.stringify(await makeTransparencyBundle()),
  );
  const reads = [];
  const decryptor = {
    async decrypt(ciphertext) {
      assert.equal(Buffer.from(ciphertext).toString(), "epoch-ciphertext");
      return Uint8Array.from(epochBundle);
    },
    getAttestedImageDigest: () => TEST_IMAGE_DIGEST,
  };
  const transparencyDecryptor = {
    async decrypt(ciphertext) {
      assert.equal(Buffer.from(ciphertext).toString(), "global-ciphertext");
      return Uint8Array.from(transparencyBundle);
    },
    getAttestedImageDigest: () => TEST_IMAGE_DIGEST,
  };
  const keyStore = await loadKeyStore({
    config,
    decryptor,
    transparencyDecryptor,
    read: async (filePath) => {
      reads.push(filePath);
      return Buffer.from(
        filePath === config.keyBundleCiphertextFile
          ? "epoch-ciphertext"
          : "global-ciphertext",
      );
    },
  });

  assert.deepEqual(reads.sort(), [
    config.keyBundleCiphertextFile,
    config.transparencyKeyCiphertextFile,
  ].sort());
  assert.equal(
    keyStore.metadata.keys.transparencySigning.keyId,
    "transparency-signing-test-v1",
  );
});

test("refuses key bundles authorized under different attested image digests", async () => {
  const config = testDeploymentConfig();
  const epochBundle = Buffer.from(JSON.stringify(await makeBundle()));
  const transparencyBundle = Buffer.from(
    JSON.stringify(await makeTransparencyBundle()),
  );
  const decryptor = {
    decrypt: async () => Uint8Array.from(epochBundle),
    getAttestedImageDigest: () => TEST_IMAGE_DIGEST,
  };
  const transparencyDecryptor = {
    decrypt: async () => Uint8Array.from(transparencyBundle),
    getAttestedImageDigest: () => `sha256:${"b".repeat(64)}`,
  };

  await assert.rejects(
    loadKeyStore({
      config,
      decryptor,
      transparencyDecryptor,
      read: async () => Buffer.from("ciphertext"),
    }),
    ConfigurationError,
  );
});

test("exchanges a launcher OIDC token and verifies KMS plaintext CRC32C", async () => {
  const config = testConfig();
  const launcherCalls = [];
  const fetchCalls = [];
  const plaintext = Buffer.from("encrypted-key-bundle");
  const fetchImplementation = async (url, options) => {
    fetchCalls.push({ url, options });
    if (fetchCalls.length === 1) {
      return new Response(
        JSON.stringify({
          access_token: "federated-access-token-with-sufficient-length",
          token_type: "Bearer",
          expires_in: 3600,
        }),
        { status: 200 },
      );
    }
    return new Response(JSON.stringify(kmsPlaintextResponse(plaintext)), {
      status: 200,
    });
  };
  const decryptor = new GoogleKmsBundleDecryptor({
    socketPath: config.attestationSocket,
    workloadIdentityProvider: config.workloadIdentityProvider,
    kmsKeyResource: config.kmsKeyResource,
    fetchImplementation,
    launcherRequest: launcherRequest(oidcToken(), launcherCalls),
  });
  assert.throws(() => decryptor.getAttestedImageDigest(), ConfigurationError);
  const decrypted = await decryptor.decrypt(Uint8Array.from([1, 2, 3]));
  assert.equal(Buffer.from(decrypted).toString(), "encrypted-key-bundle");
  assert.equal(decryptor.getAttestedImageDigest(), TEST_IMAGE_DIGEST);
  assert.deepEqual(launcherCalls[0].body, {
    audience: "https://sts.googleapis.com",
    token_type: "OIDC",
  });
  const stsBody = new URLSearchParams(fetchCalls[0].options.body);
  assert.equal(
    stsBody.get("audience"),
    `//iam.googleapis.com/${config.workloadIdentityProvider}`,
  );
  assert.match(fetchCalls[1].url, /:decrypt$/u);
});

test("extracts only a canonical sha256 image digest from the STS subject token", () => {
  assert.equal(
    attestedImageDigestFromOidcToken(oidcToken()),
    TEST_IMAGE_DIGEST,
  );
  assert.equal(
    attestedImageDigestFromOidcToken(
      oidcToken({ omitEmptyOverrides: true }),
    ),
    TEST_IMAGE_DIGEST,
  );
  assert.throws(
    () =>
      attestedImageDigestFromOidcToken(
        oidcToken({ imageDigest: "source-sha256:abc" }),
      ),
    ConfigurationError,
  );
  assert.throws(
    () => attestedImageDigestFromOidcToken("header.payload.signature"),
    ConfigurationError,
  );
});

test("rejects unsafe attested launcher settings including non-Always restart", () => {
  for (const token of [
    oidcToken({ restartPolicy: "OnFailure" }),
    oidcToken({ cmdOverride: ["node", "other.mjs"] }),
    oidcToken({ envOverride: { NODE_OPTIONS: "--inspect" } }),
    oidcToken({ memoryMonitoring: true }),
    oidcToken({ hwmodel: "GCP_AMD_SEV" }),
  ]) {
    assert.throws(
      () => attestedImageDigestFromOidcToken(token),
      ConfigurationError,
    );
  }
});

test("non-Always launcher token is rejected before STS or KMS is called", async () => {
  const config = testConfig();
  const fetchCalls = [];
  const decryptor = new GoogleKmsBundleDecryptor({
    socketPath: config.attestationSocket,
    workloadIdentityProvider: config.workloadIdentityProvider,
    kmsKeyResource: config.kmsKeyResource,
    fetchImplementation: async (...input) => {
      fetchCalls.push(input);
      throw new Error("must not be called");
    },
    launcherRequest: launcherRequest(
      oidcToken({ restartPolicy: "Never" }),
      [],
    ),
  });
  await assert.rejects(
    decryptor.decrypt(Uint8Array.from([1, 2, 3])),
    ConfigurationError,
  );
  assert.equal(fetchCalls.length, 0);
  assert.throws(() => decryptor.getAttestedImageDigest(), ConfigurationError);
});

test("requests a PKI challenge token with both caller and key-binding nonces", async () => {
  const calls = [];
  const provider = new ConfidentialSpaceAttestationProvider({
    socketPath: "/test/teeserver.sock",
    launcherRequest: launcherRequest("header.payload.signature", calls),
  });
  const token = await provider.attest({
    audience: "https://herd.example/attestation",
    nonces: ["caller-nonce-0123456789", "key-binding-0123456789"],
  });
  assert.equal(token, "header.payload.signature");
  assert.deepEqual(calls[0].body, {
    audience: "https://herd.example/attestation",
    token_type: "PKI",
    nonces: ["caller-nonce-0123456789", "key-binding-0123456789"],
  });
});

test("Firestore credentials come only from the same attested WIF principal and are cached", async () => {
  const config = testConfig();
  const launcherCalls = [];
  const fetchCalls = [];
  let now = 1_000_000;
  const provider = new ConfidentialSpaceFederatedAccessTokenProvider({
    socketPath: config.attestationSocket,
    workloadIdentityProvider: config.workloadIdentityProvider,
    expectedImageDigest: TEST_IMAGE_DIGEST,
    launcherRequest: launcherRequest(oidcToken(), launcherCalls),
    clock: () => now,
    fetchImplementation: async (url, options) => {
      fetchCalls.push({ url, options });
      return new Response(
        JSON.stringify({
          access_token: `attested-firestore-token-${fetchCalls.length}-with-safe-length`,
          token_type: "Bearer",
          expires_in: 3600,
        }),
        { status: 200 },
      );
    },
  });
  const first = await provider.getAccessToken();
  assert.equal(await provider.getAccessToken(), first);
  assert.equal(fetchCalls.length, 1);
  assert.equal(launcherCalls.length, 1);
  now += 3_541_000;
  const refreshed = await provider.getAccessToken();
  assert.notEqual(refreshed, first);
  assert.equal(fetchCalls.length, 2);
  assert.equal(launcherCalls.length, 2);
  assert.equal(
    new URLSearchParams(fetchCalls[0].options.body).get("audience"),
    `//iam.googleapis.com/${config.workloadIdentityProvider}`,
  );
});

test("a WIF token for a different measured image is rejected before state access", async () => {
  const config = testConfig();
  const fetchCalls = [];
  const provider = new ConfidentialSpaceFederatedAccessTokenProvider({
    socketPath: config.attestationSocket,
    workloadIdentityProvider: config.workloadIdentityProvider,
    expectedImageDigest: TEST_IMAGE_DIGEST,
    launcherRequest: launcherRequest(
      oidcToken({
        imageDigest:
          "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      }),
      [],
    ),
    fetchImplementation: async (...input) => {
      fetchCalls.push(input);
      throw new Error("must not be called");
    },
  });
  await assert.rejects(provider.getAccessToken(), ConfigurationError);
  assert.equal(fetchCalls.length, 0);
});
