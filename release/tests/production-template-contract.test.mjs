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
