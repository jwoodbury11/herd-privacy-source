import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  normalizeProductionReleaseTemplate,
  PRODUCTION_SBOM_NAME,
  PRODUCTION_EVIDENCE_LIMIT_BYTES,
  PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
  PRODUCTION_FETCH_LIMIT_BYTES,
  PRODUCTION_INSPECTION_LIMIT_BYTES,
  PRODUCTION_RELEASE_CONTINUITY_NAME,
  PRODUCTION_SOURCE_ARCHIVE_NAME,
  PRODUCTION_SOURCE_MANIFEST_NAME,
  PRODUCTION_WORKFLOW_RESERVED_STAGE_PATHS,
} from "../lib/production-template.mjs";
import { makeReleaseFixture } from "./fixture.mjs";

function makeProductionTemplate() {
  const template = structuredClone(makeReleaseFixture().manifest);
  template.evidence.provenance = [];
  template.evidence.transparency = [];
  template.evidence.transitions = [];
  template.evidence.deployments = [];
  return template;
}

test("production templates pin the workflow-generated source and SBOM names", () => {
  const normalized = normalizeProductionReleaseTemplate(makeProductionTemplate());
  assert.equal(normalized.source.exportArchive.name, PRODUCTION_SOURCE_ARCHIVE_NAME);
  assert.equal(normalized.source.exportManifest.name, PRODUCTION_SOURCE_MANIFEST_NAME);
  assert.deepEqual(normalized.evidence.sboms.map(({ name }) => name), [PRODUCTION_SBOM_NAME]);

  for (const [field, wrongName] of [
    ["exportArchive", "privacy-source.tar"],
    ["exportManifest", "privacy-source.manifest.json"],
  ]) {
    const template = makeProductionTemplate();
    template.source[field].name = wrongName;
    assert.throws(
      () => normalizeProductionReleaseTemplate(template),
      /must name its generated source artifacts/u,
    );
  }

  const wrongSbom = makeProductionTemplate();
  wrongSbom.evidence.sboms[0].name = "release.spdx.json";
  assert.throws(
    () => normalizeProductionReleaseTemplate(wrongSbom),
    /exactly one generated SBOM named herd\.spdx\.json/u,
  );

  const extraSbom = makeProductionTemplate();
  extraSbom.evidence.sboms.push({
    ...extraSbom.evidence.sboms[0],
    name: "extra.spdx.json",
    url: "https://evidence.example/extra.spdx.json",
  });
  assert.throws(
    () => normalizeProductionReleaseTemplate(extraSbom),
    /exactly one generated SBOM named herd\.spdx\.json/u,
  );
});

test("production templates reject workflow-reserved paths for core and audit inputs", () => {
  for (const reservedPath of PRODUCTION_WORKFLOW_RESERVED_STAGE_PATHS) {
    const template = makeProductionTemplate();
    template.artifacts.web.deploymentArchive.name = reservedPath.toUpperCase();
    assert.throws(
      () => normalizeProductionReleaseTemplate(template),
      /uses a workflow-reserved staging path/u,
      reservedPath,
    );
  }

  const auditCollision = makeProductionTemplate();
  auditCollision.evidence.audits[0].name = "Release-Public.pem";
  assert.throws(
    () => normalizeProductionReleaseTemplate(auditCollision),
    /uses a workflow-reserved staging path/u,
  );

  const caseCollision = makeProductionTemplate();
  caseCollision.evidence.audits[0].name =
    caseCollision.artifacts.scheduler.name.toUpperCase();
  assert.throws(
    () => normalizeProductionReleaseTemplate(caseCollision),
    /unique on case-insensitive filesystems/u,
  );

  for (const [mutate, expected] of [
    [
      (template) => {
        template.artifacts.ordinaryApi.size = PRODUCTION_FETCH_LIMIT_BYTES + 1;
      },
      /1 GiB fetch limit/u,
    ],
    [
      (template) => {
        template.artifacts.web.deploymentArchive.size = PRODUCTION_INSPECTION_LIMIT_BYTES + 1;
      },
      /256 MiB inspection limit/u,
    ],
    [
      (template) => {
        template.evidence.audits[0].size = PRODUCTION_EVIDENCE_LIMIT_BYTES + 1;
      },
      /64 MiB evidence limit/u,
    ],
  ]) {
    const oversized = makeProductionTemplate();
    mutate(oversized);
    assert.throws(() => normalizeProductionReleaseTemplate(oversized), expected);
  }
});

test("release-manifest schema mirrors the production workflow contract", async () => {
  const schema = JSON.parse(
    await readFile(new URL("../schemas/release-manifest-v1.schema.json", import.meta.url), "utf8"),
  );
  assert.equal(
    schema.$defs.provenance.properties.predicateType.const,
    "https://slsa.dev/provenance/v1",
  );
  assert.equal(
    schema.$defs.provenance.properties.issuer.const,
    "https://token.actions.githubusercontent.com/",
  );
  assert.equal(schema.$defs.transparency.properties.provider.const, "sigstore-rekor");

  const production = schema.allOf.find(
    ({ if: condition }) => condition?.properties?.releaseStage?.const === "production",
  )?.then?.properties;
  assert.ok(production, "production conditional must exist");
  assert.equal(
    production.source.properties.exportArchive.allOf[1].properties.name.const,
    PRODUCTION_SOURCE_ARCHIVE_NAME,
  );
  assert.equal(
    production.source.properties.exportManifest.allOf[1].properties.name.const,
    PRODUCTION_SOURCE_MANIFEST_NAME,
  );
  assert.equal(production.evidence.properties.sboms.minItems, 1);
  assert.equal(production.evidence.properties.sboms.maxItems, 1);
  assert.equal(
    production.evidence.properties.sboms.items.allOf[1].properties.name.const,
    PRODUCTION_SBOM_NAME,
  );
  assert.equal(production.evidence.properties.provenance.minItems, 1);
  assert.equal(production.evidence.properties.transparency.minItems, 1);
  assert.equal(production.evidence.properties.transitions.minItems, 1);
  assert.deepEqual(
    production.evidence.properties.transitions.items.allOf[1].properties.name.enum,
    [PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME, PRODUCTION_RELEASE_CONTINUITY_NAME],
  );
  assert.equal(production.evidence.properties.audits.minItems, 1);
  assert.deepEqual(
    schema.$defs.productionExternalArtifact.allOf[1].properties.name.not.enum,
    [...PRODUCTION_WORKFLOW_RESERVED_STAGE_PATHS],
  );
  assert.equal(
    schema.$defs.productionExternalArtifact.allOf[1].properties.size.maximum,
    PRODUCTION_FETCH_LIMIT_BYTES,
  );
  assert.deepEqual(schema.$defs.productionArtifact.allOf[1].properties.url.type, "string");
  assert.equal(schema.$defs.productionArtifact.allOf[1].properties.url.pattern, "^https://");
});

test("protected workflow verifies predecessor continuity before provenance", async () => {
  const workflow = await readFile(
    new URL("../../.github/workflows/release-evidence.yml", import.meta.url),
    "utf8",
  );
  assert.match(workflow, /verify-current-release-continuity\.mjs/u);
  assert.match(workflow, /Require exact-main hosted privacy gates before production signing/u);
  assert.match(workflow, /test "\$GITHUB_REF" = "refs\/heads\/main"/u);
  assert.match(workflow, /head_sha=\$GITHUB_SHA&status=completed/u);
  assert.match(workflow, /run\.event==="push"&&run\.conclusion==="success"/u);
  assert.match(workflow, /cosign-release: v2\.6\.2/u);
  assert.equal(
    workflow.match(/cosign sign-blob --yes --new-bundle-format=true/gu)?.length,
    2,
    "both keyless signatures must use the modern Sigstore bundle format",
  );
  assert.match(
    workflow,
    /generate-provenance\.mjs[^\n]+--evaluator-epoch-transition[^\n]+continuity_args/u,
  );
  assert.match(
    workflow,
    /assemble-release-manifest\.mjs[^\n]+--evaluator-epoch-transition[^\n]+continuity_args/u,
  );
});

test("monitor dependencies and syntax checks gate every clean CI test path", async () => {
  const [releaseWorkflow, privacyWorkflow, localGate] = await Promise.all([
    readFile(
      new URL("../../.github/workflows/release-evidence.yml", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../../scripts/test-all", import.meta.url), "utf8"),
  ]);
  for (const [label, workflow] of [
    ["release evidence", releaseWorkflow],
    ["privacy CI", privacyWorkflow],
  ]) {
    const install = workflow.indexOf("npm ci --prefix monitor --ignore-scripts");
    const syntax = workflow.indexOf("npm --prefix monitor run check");
    const tests = workflow.indexOf("monitor/tests/*.test.mjs");
    assert.ok(install >= 0, `${label} does not install monitor dependencies`);
    assert.ok(syntax > install, `${label} checks monitor syntax before installation`);
    assert.ok(tests > syntax, `${label} runs monitor tests before its syntax check`);
  }
  assert.ok(
    localGate.indexOf("npm --prefix monitor run check") <
      localGate.indexOf("monitor/tests/*.test.mjs"),
    "local full-test gate must syntax-check the monitor before its tests",
  );
});

test("hosted native iOS CI runs the public export on pull requests with the exact release toolchain", async () => {
  const [privacyWorkflow, releaseWorkflow, toolchains, scheme, localGate] = await Promise.all([
    readFile(
      new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
      "utf8",
    ),
    readFile(
      new URL("../../.github/workflows/release-evidence.yml", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../toolchains.json", import.meta.url), "utf8").then(JSON.parse),
    readFile(
      new URL("../../HerdHost.xcodeproj/xcshareddata/xcschemes/HerdHost.xcscheme", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../../scripts/test-all", import.meta.url), "utf8"),
  ]);
  const nativeJob = privacyWorkflow.slice(privacyWorkflow.indexOf("  ios-native:"));
  assert.match(nativeJob, /runs-on: macos-26/u);
  assert.doesNotMatch(nativeJob, /event_name != 'pull_request'|github\.repository|self-hosted/u);
  assert.match(nativeJob, /Build, verify, and unpack the reviewed public source/u);
  assert.match(nativeJob, /--require-clean/u);
  assert.match(nativeJob, /cd "\$HERD_TEST_ROOT"/u);
  assert.match(
    nativeJob,
    /xcode-select --switch \/Applications\/Xcode_26\.6\.app\/Contents\/Developer/u,
  );
  assert.match(nativeJob, /SOURCE_DATE_EPOCH=\$source_epoch/u);
  assert.match(nativeJob, /--profile ios/u);
  assert.match(nativeJob, /name=iPhone 17 Pro,OS=26\.5/u);
  assert.match(nativeJob, /-configuration Release/u);
  assert.match(nativeJob, /CODE_SIGNING_ALLOWED=NO/u);
  assert.match(scheme, /BlueprintName = "HerdHostUITests"/u);
  assert.match(scheme, /skipped = "NO"/u);
  assert.match(localGate, /verify-toolchains\.mjs --spec release\/toolchains\.json --profile release/u);
  assert.match(localGate, /verify-toolchains\.mjs --spec release\/toolchains\.json --profile ios/u);
  assert.match(localGate, /name=iPhone 17 Pro,OS=26\.5/u);

  const preflightJob = releaseWorkflow.slice(
    releaseWorkflow.indexOf("  production-artifact-preflight:"),
  );
  assert.match(preflightJob, /runs-on: macos-26/u);
  assert.doesNotMatch(preflightJob, /self-hosted/u);
  assert.match(
    preflightJob,
    /xcode-select --switch \/Applications\/Xcode_26\.6\.app\/Contents\/Developer/u,
  );
  assert.match(preflightJob, /--profile ios/u);
  assert.match(preflightJob, /extract-ios-preflight-inputs\.mjs/u);
  assert.match(preflightJob, /--ios-entitlements-json/u);
  const extractor = await readFile(
    new URL("../extract-ios-preflight-inputs.mjs", import.meta.url),
    "utf8",
  );
  assert.match(extractor, /codesign", \["--verify", "--strict", appPath\]/u);
  assert.match(extractor, /rejectExtractedLinks\(extractionRoot\)/u);
  assert.match(extractor, /codesign",\s*\["-d", "--entitlements", ":-"/u);
  assert.deepEqual(toolchains.ios.runnerLabels, ["macos-26"]);
});

test("privacy CI validates the exact production infrastructure with a pinned Terraform", async () => {
  const [privacyWorkflow, toolchains] = await Promise.all([
    readFile(
      new URL("../../.github/workflows/privacy-ci.yml", import.meta.url),
      "utf8",
    ),
    readFile(new URL("../toolchains.json", import.meta.url), "utf8").then(JSON.parse),
  ]);
  assert.equal(toolchains.linux.terraform, "1.15.8");
  assert.match(
    privacyWorkflow,
    /hashicorp\/setup-terraform@b9cd54a3c349d3f38e8881555d616ced269862dd/u,
  );
  assert.match(privacyWorkflow, /terraform_version: 1\.15\.8/u);
  assert.match(
    privacyWorkflow,
    /terraform "-chdir=\$HERD_TEST_ROOT\/infrastructure\/gcp-confidential-space" init -backend=false -input=false -lockfile=readonly/u,
  );
  assert.match(
    privacyWorkflow,
    /terraform "-chdir=\$HERD_TEST_ROOT\/infrastructure\/gcp-confidential-space" validate -no-color/u,
  );
});
