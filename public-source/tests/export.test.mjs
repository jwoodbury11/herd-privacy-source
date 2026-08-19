import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, readFile, symlink, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { canonicalJson, sha256Hex } from "../../release/lib/canonical.mjs";
import {
  collectExportFiles,
  createExportManifest,
  createTarArchive,
  normalizeExportPolicy,
} from "../lib/export-core.mjs";

const run = promisify(execFile);
const repositoryRoot = path.resolve(import.meta.dirname, "../..");

function rawPolicy() {
  return {
    schemaVersion: 1,
    archivePrefix: "herd-test-source",
    license: "Apache-2.0",
    maximumFileBytes: 1024 * 1024,
    prohibitedPathFragments: [".git", "node_modules", "partiful ios", "screenshots"],
    prohibitedExtensions: [".key", ".pem", ".png"],
    includes: [
      { path: "LICENSE" },
      { path: "src", recursive: true },
      { path: "docs", recursive: true },
    ],
  };
}

function policy() {
  return normalizeExportPolicy(rawPolicy());
}

async function fixtureRoot() {
  const root = await mkdtemp(path.join(os.tmpdir(), "herd-export-test-"));
  await mkdir(path.join(root, "src"), { recursive: true });
  await mkdir(path.join(root, "docs"), { recursive: true });
  await mkdir(path.join(root, "Partiful iOS"), { recursive: true });
  await mkdir(path.join(root, "screenshots"), { recursive: true });
  await writeFile(path.join(root, "LICENSE"), "Apache License 2.0\n");
  await writeFile(path.join(root, "src", "privacy.mjs"), "export const privateByDesign = true;\n");
  await writeFile(path.join(root, "docs", "protocol.md"), "# Protocol\n");
  await writeFile(path.join(root, "Partiful iOS", "proprietary.swift"), "private implementation\n");
  await writeFile(path.join(root, "screenshots", "event.png"), "not really an image\n");
  return root;
}

test("allowlisted source export is byte-for-byte deterministic and excludes proprietary material", async () => {
  const root = await fixtureRoot();
  const normalizedPolicy = policy();
  const files = await collectExportFiles(root, normalizedPolicy);
  assert.deepEqual(files.map(({ path: filePath }) => filePath), ["LICENSE", "docs/protocol.md", "src/privacy.mjs"]);
  const policyBytes = Buffer.from(canonicalJson(rawPolicy()));
  const manifest = createExportManifest({
    files,
    policyBytes,
    policyPath: "public-source/export-policy.json",
    sourceRevision: "ab".repeat(20),
    sourceDateEpoch: 1785657600,
    archivePrefix: normalizedPolicy.archivePrefix,
  });
  const first = createTarArchive(files, manifest, manifest.sourceDateEpoch);
  const second = createTarArchive(files, manifest, manifest.sourceDateEpoch);
  assert.deepEqual(first, second);
});

test("recursive includes skip prohibited generated and dependency subtrees", async () => {
  const root = await fixtureRoot();
  await mkdir(path.join(root, "src", "node_modules", "dependency"), { recursive: true });
  await mkdir(path.join(root, "src", "release", "generated"), { recursive: true });
  await writeFile(path.join(root, "src", "node_modules", "dependency", "index.mjs"), "secret\n");
  await writeFile(path.join(root, "src", "release", "generated", "runtime.json"), "secret\n");

  const files = await collectExportFiles(root, normalizeExportPolicy({
    ...rawPolicy(),
    prohibitedPathFragments: [
      ...rawPolicy().prohibitedPathFragments,
      "release/generated",
    ],
  }));

  assert.deepEqual(files.map(({ path: filePath }) => filePath), [
    "LICENSE",
    "docs/protocol.md",
    "src/privacy.mjs",
  ]);
});

test("standalone verifier accepts a canonical export and rejects one changed byte", async () => {
  const root = await fixtureRoot();
  const normalizedPolicy = policy();
  const files = await collectExportFiles(root, normalizedPolicy);
  const policyPath = path.join(root, "policy.json");
  const manifestPath = path.join(root, "manifest.json");
  const archivePath = path.join(root, "source.tar");
  const policyBytes = Buffer.from(canonicalJson(rawPolicy()));
  const manifest = createExportManifest({
    files,
    policyBytes,
    policyPath: "policy.json",
    sourceRevision: "cd".repeat(20),
    sourceDateEpoch: 1785657600,
    archivePrefix: normalizedPolicy.archivePrefix,
  });
  await writeFile(policyPath, policyBytes);
  await writeFile(manifestPath, canonicalJson(manifest));
  await writeFile(archivePath, createTarArchive(files, manifest, manifest.sourceDateEpoch));
  await run(process.execPath, ["public-source/verify-export.mjs", "--archive", archivePath, "--manifest", manifestPath, "--policy", policyPath], { cwd: repositoryRoot });
  const changed = await readFile(archivePath);
  changed[600] ^= 1;
  await writeFile(archivePath, changed);
  await assert.rejects(
    run(process.execPath, ["public-source/verify-export.mjs", "--archive", archivePath, "--manifest", manifestPath, "--policy", policyPath], { cwd: repositoryRoot }),
  );
});

test("export rejects symbolic links and private-key markers", async () => {
  const root = await fixtureRoot();
  await symlink(path.join(root, "LICENSE"), path.join(root, "src", "license-link"));
  await assert.rejects(collectExportFiles(root, policy()), /Symbolic links/u);
  const secondRoot = await fixtureRoot();
  const marker = ["-----BEGIN", " PRIVATE KEY-----"].join("");
  await writeFile(
    path.join(secondRoot, "src", "credential.txt"),
    `${marker}\n${Buffer.alloc(32, 7).toString("base64")}\n`,
  );
  await assert.rejects(collectExportFiles(secondRoot, policy()), /Private key material/u);
});

test("binary export requires an exact path, valid PNG structure, and pinned digest", async () => {
  const root = await fixtureRoot();
  const binaryPath = path.join(root, "public", "icon.png");
  await mkdir(path.dirname(binaryPath), { recursive: true });
  const png = Buffer.from(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=",
    "base64",
  );
  await writeFile(binaryPath, png);
  const binaryPolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      {
        path: "public/icon.png",
        binarySha256: "431ced6916a2a21a156e38701afe55bbd7f88969fbbfc56d7fe099d47f265460",
      },
    ],
  });
  const files = await collectExportFiles(root, binaryPolicy);
  assert.equal(files.some(({ path: filePath }) => filePath === "public/icon.png"), true);

  assert.throws(
    () => normalizeExportPolicy({
      ...rawPolicy(),
      includes: [
        ...rawPolicy().includes,
        { path: "public", recursive: true, binarySha256: "00".repeat(32) },
      ],
    }),
    /only for an exact PNG/u,
  );
  const changedPolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      { path: "public/icon.png", binarySha256: "00".repeat(32) },
    ],
  });
  await assert.rejects(collectExportFiles(root, changedPolicy), /digest changed/u);
  await writeFile(binaryPath, Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00]));
  await assert.rejects(collectExportFiles(root, binaryPolicy), /not a PNG/u);
});

test("configuration examples require an exact .env.example path and pinned digest", async () => {
  const root = await fixtureRoot();
  const examplePath = path.join(root, "app", ".env.example");
  await mkdir(path.dirname(examplePath), { recursive: true });
  const example = Buffer.from("PUBLIC_ORIGIN=https://example.test\nSECRET=replace-me\n");
  await writeFile(examplePath, example);
  const digest = "0ab8675a9ca6155659783eba98defc84b54114adbf9ad70cd1d7a73f264525b9";
  const examplePolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      { path: "app/.env.example", exampleSha256: digest },
    ],
  });
  const files = await collectExportFiles(root, examplePolicy);
  assert.equal(files.some(({ path: filePath }) => filePath === "app/.env.example"), true);

  assert.throws(
    () => normalizeExportPolicy({
      ...rawPolicy(),
      includes: [
        ...rawPolicy().includes,
        { path: "app", recursive: true, exampleSha256: digest },
      ],
    }),
    /only for an exact \.env\.example/u,
  );
  assert.throws(
    () => normalizeExportPolicy({
      ...rawPolicy(),
      includes: [
        ...rawPolicy().includes,
        { path: "app/.env.production", exampleSha256: digest },
      ],
    }),
    /only for an exact \.env\.example/u,
  );

  const changedPolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      { path: "app/.env.example", exampleSha256: "00".repeat(32) },
    ],
  });
  await assert.rejects(collectExportFiles(root, changedPolicy), /digest changed/u);

  const unsafeExample = Buffer.from("API_SECRET=a-real-deployed-value\n");
  await writeFile(examplePath, unsafeExample);
  const unsafePolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      { path: "app/.env.example", exampleSha256: sha256Hex(unsafeExample) },
    ],
  });
  await assert.rejects(collectExportFiles(root, unsafePolicy), /non-placeholder secret/u);

  const unsafeCommentedExample = Buffer.from("# API_SECRET=a-real-deployed-value\n");
  await writeFile(examplePath, unsafeCommentedExample);
  const unsafeCommentedPolicy = normalizeExportPolicy({
    ...rawPolicy(),
    includes: [
      ...rawPolicy().includes,
      { path: "app/.env.example", exampleSha256: sha256Hex(unsafeCommentedExample) },
    ],
  });
  await assert.rejects(
    collectExportFiles(root, unsafeCommentedPolicy),
    /non-placeholder secret/u,
  );

  const unpinnedRoot = await fixtureRoot();
  await writeFile(path.join(unpinnedRoot, "src", ".env.example"), "SECRET=replace-me\n");
  await assert.rejects(collectExportFiles(unpinnedRoot, policy()), /Environment file/u);
});

test("repository policy includes the executable privacy contracts and acceptance dependencies", async () => {
  const policyPath = path.join(repositoryRoot, "public-source", "export-policy.json");
  const repositoryPolicy = normalizeExportPolicy(JSON.parse(await readFile(policyPath, "utf8")));
  assert.equal(
    repositoryPolicy.prohibitedPathFragments.includes("release/generated"),
    true,
    "generated release configuration must not enter a public-source archive",
  );
  assert.equal(
    repositoryPolicy.prohibitedPathFragments.includes(".ds_store"),
    true,
    "desktop metadata must never enter a public-source archive",
  );
  const files = await collectExportFiles(repositoryRoot, repositoryPolicy);
  const included = new Set(files.map(({ path: filePath }) => filePath));
  for (const requiredPath of [
    "README.md",
    "security/data-inventory.json",
    "security/tests/artifact-scan.test.mjs",
    "scripts/verify-data-contract.mjs",
    "scripts/scan-sensitive-artifacts.mjs",
    "docs/data-retention-and-privacy-operations.md",
    "invitee-web/scripts/browser-acceptance-harness.mjs",
    "invitee-web/.env.example",
    "invitee-web/lib/backend/accounts.ts",
    "invitee-web/legal-content/index.tsx",
    "invitee-web/tests/account-deletion.test.mjs",
    "invitee-web/app/page.tsx",
    "herd-legal/app/privacy/page.tsx",
    "herd-legal/legal-content/index.tsx",
    "herd-legal/tests/rendered-html.test.mjs",
    "confidential-evaluator/src/transparency-authority.mjs",
    "confidential-evaluator/src/transparency-store.mjs",
    "confidential-evaluator/test/transparency-authority.test.mjs",
    "HerdHostTests/HerdHostCoreTests.swift",
    "HerdHost/UITestSupport.swift",
    "HerdHostUITests/HerdHostUITests.swift",
    "release/HerdRelease.xcconfig",
    "HerdHost/Assets.xcassets/AppIcon.appiconset/HerdAppIcon.png",
    "invitee-web/app/globals.css",
    "invitee-web/app/invite/[token]/page.tsx",
    "invitee-web/public/icons/herd-512.png",
    "herd-legal/app/layout.tsx",
    "herd-legal/app/terms/page.tsx",
    "herd-legal/app/sms-invite-consent/page.tsx",
    "herd-legal/build/sites-vite-plugin.ts",
    "herd-legal/vite.config.ts",
    "herd-legal/public/og.png",
    "evaluator-service/.env.example",
  ]) {
    assert.equal(included.has(requiredPath), true, `${requiredPath} is absent from the public export`);
  }
});

test("hosted and local gates execute the unpacked public export from a clean checkout", async () => {
  const [workflow, rootReadme, localGate, ...viteConfigs] = await Promise.all([
    readFile(path.join(repositoryRoot, ".github", "workflows", "privacy-ci.yml"), "utf8"),
    readFile(path.join(repositoryRoot, "README.md"), "utf8"),
    readFile(path.join(repositoryRoot, "scripts", "test-all"), "utf8"),
    ...[
      "invitee-web/vite.config.ts",
      "herd-legal/vite.config.ts",
      "evaluator-service/vite.config.ts",
    ].map((filePath) => readFile(path.join(repositoryRoot, filePath), "utf8")),
  ]);
  assert.match(workflow, /Build, verify, and unpack the reviewed public source/u);
  assert.match(workflow, /HERD_TEST_ROOT=.*herd-privacy-source/u);
  assert.match(workflow, /npm test --prefix "\$HERD_TEST_ROOT\/invitee-web"/u);
  assert.match(workflow, /npm test --prefix "\$HERD_TEST_ROOT\/herd-legal"/u);
  assert.match(workflow, /terraform "-chdir=\$HERD_TEST_ROOT\/infrastructure\/gcp-confidential-space" validate/u);
  const nativeJob = workflow.slice(workflow.indexOf("  ios-native:"));
  assert.match(nativeJob, /Build, verify, and unpack the reviewed public source/u);
  assert.match(nativeJob, /cd "\$HERD_TEST_ROOT"/u);
  assert.doesNotMatch(nativeJob, /if: github\.repository/u);
  for (const viteConfig of viteConfigs) {
    assert.doesNotMatch(viteConfig, /import hostingConfig/u);
  }
  assert.doesNotMatch(rootReadme, /Partiful iOS|TestFlightExportOptions|WORKING_NOTES/u);
  assert.match(rootReadme, /Apache License 2\.0/u);
  assert.match(rootReadme, /npm ci --prefix invitee-web --ignore-scripts/u);
  assert.match(rootReadme, /same commands work from the root of the extracted\npublic archive/u);
  assert.match(localGate, /PUBLIC-SOURCE-MANIFEST\.json/u);
  assert.match(localGate, /manifest\.sourceDateEpoch/u);
  assert.match(localGate, /\[ -e "\$repository_root\/\.git" \]/u);
});
