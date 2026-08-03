import assert from "node:assert/strict";
import test from "node:test";

import {
  bindAttestedImageDigest,
  loadDeploymentConfig,
  normalizeDeploymentConfig,
} from "../src/config.mjs";
import { ConfigurationError } from "../src/errors.mjs";
import {
  TEST_IMAGE_DIGEST,
  testDeploymentConfig,
} from "./helpers.mjs";

test("normalizes the exact production deployment config", () => {
  const deploymentConfig = testDeploymentConfig();
  assert.equal("evaluatorMeasurement" in deploymentConfig, false);
  const config = bindAttestedImageDigest(deploymentConfig, TEST_IMAGE_DIGEST);
  assert.equal(config.releaseId, "herd-confidential-test-v1");
  assert.equal(config.evaluatorMeasurement, TEST_IMAGE_DIGEST);
  assert.equal(config.transparencyStateProjectId, "herd-key-test");
  assert.equal(config.transparencyStateDatabaseId, "herd-transparency");
  assert.equal(config.transparencyStateCollection, "herd_response_log_v1");
  assert.equal(config.port, 8080);
  assert.ok(Object.isFrozen(config));
});

test("fails closed on unknown config fields and mutable resource references", () => {
  const base = { ...testDeploymentConfig() };
  assert.throws(
    () => normalizeDeploymentConfig({ ...base, unexpected: true }),
    ConfigurationError,
  );
  assert.throws(
    () => normalizeDeploymentConfig({ ...base, kmsKeyResource: "projects/key" }),
    ConfigurationError,
  );
  assert.throws(
    () =>
      normalizeDeploymentConfig({
        ...base,
        transparencyKeyCiphertextFile: base.keyBundleCiphertextFile,
      }),
    ConfigurationError,
  );
  assert.throws(
    () =>
      normalizeDeploymentConfig({
        ...base,
        transparencyKmsKeyResource: base.kmsKeyResource,
      }),
    ConfigurationError,
  );
  assert.throws(
    () =>
      normalizeDeploymentConfig({
        ...base,
        workloadIdentityProvider: "projects/name/providers/latest",
      }),
    ConfigurationError,
  );
  assert.throws(
    () => normalizeDeploymentConfig({ ...base, allowedOrigin: "http://herd.test" }),
    ConfigurationError,
  );
  assert.throws(
    () =>
      normalizeDeploymentConfig({
        ...base,
        transparencyStateProjectId: "123-invalid",
      }),
    ConfigurationError,
  );
  assert.throws(
    () =>
      normalizeDeploymentConfig({
        ...base,
        transparencyStateCollection: "logs/path",
      }),
    ConfigurationError,
  );
  assert.throws(
    () => bindAttestedImageDigest(testDeploymentConfig(), "source-sha256:abc"),
    ConfigurationError,
  );
  assert.throws(
    () =>
      bindAttestedImageDigest(
        testDeploymentConfig(),
        `sha256:${"A".repeat(64)}`,
      ),
    ConfigurationError,
  );
});

test("rejects private keys and bearer tokens supplied through environment variables", async () => {
  await assert.rejects(
    loadDeploymentConfig({
      runtimeEnvironment: {
        HERD_DEPLOYMENT_CONFIG_FILE: "/test/deployment.json",
        HERD_EVALUATOR_PRIVATE_KEY_JWK: "not-allowed",
      },
      read: async () => Buffer.from(JSON.stringify(testDeploymentConfig())),
    }),
    ConfigurationError,
  );
  await assert.rejects(
    loadDeploymentConfig({
      runtimeEnvironment: {
        HERD_DEPLOYMENT_CONFIG_FILE: "/test/deployment.json",
        HERD_SOMETHING_SECRET: "not-allowed",
      },
      read: async () => Buffer.from(JSON.stringify(testDeploymentConfig())),
    }),
    ConfigurationError,
  );
});
