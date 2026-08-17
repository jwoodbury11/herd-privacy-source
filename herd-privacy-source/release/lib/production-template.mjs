import { normalizeReleaseManifest } from "./release-manifest.mjs";

export const PRODUCTION_SOURCE_ARCHIVE_NAME = "herd-privacy-source.tar";
export const PRODUCTION_SOURCE_MANIFEST_NAME = "herd-privacy-source.manifest.json";
export const PRODUCTION_SBOM_NAME = "herd.spdx.json";
export const PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME =
  "evaluator-epoch-transition.json";
export const PRODUCTION_RELEASE_CONTINUITY_NAME = "release-continuity.json";
export const PRODUCTION_FETCH_LIMIT_BYTES = 1024 * 1024 * 1024;
export const PRODUCTION_INSPECTION_LIMIT_BYTES = 256 * 1024 * 1024;
export const PRODUCTION_EVIDENCE_LIMIT_BYTES = 64 * 1024 * 1024;

// These paths are created by the protected workflow in its flat staging
// directory. External artifacts are downloaded before the later entries are
// generated, so reserving every path prevents a protected input from replacing
// a generated artifact (including after transfer to a case-insensitive macOS
// filesystem).
export const PRODUCTION_WORKFLOW_RESERVED_STAGE_PATHS = Object.freeze([
  PRODUCTION_SOURCE_ARCHIVE_NAME,
  PRODUCTION_SOURCE_MANIFEST_NAME,
  "herd-privacy-source.second.tar",
  "herd-privacy-source.second.manifest.json",
  PRODUCTION_SBOM_NAME,
  "build-provenance.intoto.json",
  "build-provenance.sigstore.json",
  "build-provenance.rekor.json",
  PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
  PRODUCTION_RELEASE_CONTINUITY_NAME,
  "release-manifest.json",
  "release-manifest.sig.json",
  "release-public.pem",
  "release-manifest.sigstore.json",
  "production-config",
]);

const RESERVED_STAGE_PATHS_CASE_INSENSITIVE = new Set(
  PRODUCTION_WORKFLOW_RESERVED_STAGE_PATHS.map((name) => name.toLowerCase()),
);

export function normalizeProductionReleaseTemplate(value) {
  if (value?.releaseStage !== "production") {
    throw new TypeError("A production release template is required.");
  }
  if (
    !Array.isArray(value.evidence?.provenance) ||
    !Array.isArray(value.evidence?.transparency) ||
    !Array.isArray(value.evidence?.transitions) ||
    !Array.isArray(value.evidence?.deployments) ||
    value.evidence.provenance.length !== 0 ||
    value.evidence.transparency.length !== 0 ||
    value.evidence.transitions.length !== 0 ||
    value.evidence.deployments.length !== 0
  ) {
    throw new TypeError(
      "A production release template must not contain preexisting provenance, transparency, transition, or deployment evidence.",
    );
  }
  const candidate = structuredClone(value);
  candidate.releaseStage = "candidate";
  const normalized = normalizeReleaseManifest(candidate);
  normalized.releaseStage = "production";
  const requiredArtifacts = productionProvenanceArtifacts(normalized);
  const externallyFetched = productionExternalArtifacts(normalized);
  if (
    normalized.source.exportArchive.name !== PRODUCTION_SOURCE_ARCHIVE_NAME ||
    normalized.source.exportManifest.name !== PRODUCTION_SOURCE_MANIFEST_NAME
  ) {
    throw new TypeError(
      `A production release template must name its generated source artifacts ${PRODUCTION_SOURCE_ARCHIVE_NAME} and ${PRODUCTION_SOURCE_MANIFEST_NAME}.`,
    );
  }
  if (
    normalized.evidence.sboms.length !== 1 ||
    normalized.evidence.sboms[0].name !== PRODUCTION_SBOM_NAME
  ) {
    throw new TypeError(
      `A production release template must contain exactly one generated SBOM named ${PRODUCTION_SBOM_NAME}.`,
    );
  }
  const reservedExternalArtifact = externallyFetched.find(({ name }) =>
    RESERVED_STAGE_PATHS_CASE_INSENSITIVE.has(name.toLowerCase()),
  );
  if (reservedExternalArtifact) {
    throw new TypeError(
      `External production artifact ${reservedExternalArtifact.name} uses a workflow-reserved staging path.`,
    );
  }
  if ([...requiredArtifacts, ...normalized.evidence.audits].some(({ url }) => url === null)) {
    throw new TypeError("Every production release-template artifact must have a durable HTTPS URL.");
  }
  if (normalized.evidence.sboms.some(({ mediaType }) => mediaType !== "application/spdx+json")) {
    throw new TypeError("Production release-template SBOMs must use application/spdx+json.");
  }
  if (
    normalized.evidence.audits.length === 0 ||
    normalized.evidence.audits.some(({ mediaType }) => mediaType !== "application/pdf")
  ) {
    throw new TypeError("A production release template requires PDF audit evidence.");
  }
  if (externallyFetched.some(({ size }) => size > PRODUCTION_FETCH_LIMIT_BYTES)) {
    throw new TypeError("An external production artifact exceeds the 1 GiB fetch limit.");
  }
  if (
    normalized.artifacts.web.deploymentArchive.size > PRODUCTION_INSPECTION_LIMIT_BYTES ||
    normalized.artifacts.scheduler.size > PRODUCTION_INSPECTION_LIMIT_BYTES
  ) {
    throw new TypeError("A web or scheduler archive exceeds the 256 MiB inspection limit.");
  }
  if (
    [...normalized.evidence.sboms, ...normalized.evidence.audits].some(
      ({ size }) => size > PRODUCTION_EVIDENCE_LIMIT_BYTES,
    )
  ) {
    throw new TypeError("An SBOM or audit exceeds the 64 MiB evidence limit.");
  }
  const stageArtifacts = [...requiredArtifacts, ...normalized.evidence.audits];
  if (
    new Set(stageArtifacts.map(({ name }) => name.toLowerCase())).size !== stageArtifacts.length
  ) {
    throw new TypeError(
      "Production release-template artifact names must be unique on case-insensitive filesystems.",
    );
  }
  return normalized;
}

export function productionProvenanceArtifacts(template) {
  return [
    template.source.exportArchive,
    template.source.exportManifest,
    template.artifacts.web.deploymentArchive,
    template.artifacts.ios.submissionArchive,
    template.artifacts.ordinaryApi,
    template.artifacts.evaluator,
    template.artifacts.scheduler,
    ...template.evidence.sboms,
    ...template.evidence.transitions,
  ];
}

export function productionExternalArtifacts(template) {
  return [
    template.artifacts.web.deploymentArchive,
    template.artifacts.ios.submissionArchive,
    template.artifacts.ordinaryApi,
    template.artifacts.evaluator,
    template.artifacts.scheduler,
    ...template.evidence.audits,
  ];
}
