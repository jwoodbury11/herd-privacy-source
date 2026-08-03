#!/usr/bin/env node
import { lstat, readFile, readdir } from "node:fs/promises";
import path from "node:path";

import {
  parseArgs,
  hashFile,
  readJson,
  requireArg,
  requireCanonicalTimestamp,
  requireString,
  sha256Hex,
  writeCanonicalJson,
} from "./lib/canonical.mjs";
import {
  normalizeProductionReleaseTemplate,
  PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
  PRODUCTION_RELEASE_CONTINUITY_NAME,
  productionProvenanceArtifacts,
} from "./lib/production-template.mjs";

async function subjects(root, current = "", excluded = new Set()) {
  const directory = path.join(root, ...current.split("/").filter(Boolean));
  const children = await readdir(directory);
  children.sort();
  const result = [];
  for (const child of children) {
    const relativePath = current ? `${current}/${child}` : child;
    if (excluded.has(relativePath)) continue;
    const absolutePath = path.join(root, ...relativePath.split("/"));
    const metadata = await lstat(absolutePath);
    if (metadata.isSymbolicLink()) throw new TypeError(`Provenance subject is a symbolic link: ${relativePath}`);
    if (metadata.isDirectory()) result.push(...(await subjects(root, relativePath, excluded)));
    else if (metadata.isFile()) {
      result.push({ name: relativePath, digest: { sha256: (await hashFile(absolutePath)).sha256 } });
    } else throw new TypeError(`Provenance subject is not regular: ${relativePath}`);
  }
  return result;
}

async function transitionSubject(root, inputPath, expectedName) {
  const absolutePath = path.resolve(inputPath);
  if (path.dirname(absolutePath) !== root || path.basename(absolutePath) !== expectedName) {
    throw new TypeError(`Transition evidence must be ${expectedName} inside the artifact root.`);
  }
  const metadata = await lstat(absolutePath);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new TypeError(`Transition evidence ${expectedName} is not a regular file.`);
  }
  return { name: expectedName, digest: { sha256: (await hashFile(absolutePath)).sha256 } };
}

async function releaseSubjects(root, templatePath, args) {
  const template = normalizeProductionReleaseTemplate(await readJson(templatePath));
  const result = [];
  for (const artifact of productionProvenanceArtifacts(template)) {
    const filePath = path.join(root, artifact.name);
    const metadata = await lstat(filePath);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      throw new TypeError(`Provenance subject ${artifact.name} is not a regular file.`);
    }
    const { sha256, size } = await hashFile(filePath);
    if (size !== artifact.size || sha256 !== artifact.sha256) {
      throw new TypeError(`Provenance subject ${artifact.name} differs from the release template.`);
    }
    result.push({ name: artifact.name, digest: { sha256 } });
  }
  result.push(
    await transitionSubject(
      root,
      requireArg(args, "evaluator-epoch-transition"),
      PRODUCTION_EVALUATOR_EPOCH_TRANSITION_NAME,
    ),
  );
  if (template.previousRelease === null) {
    if (args["release-continuity"]) {
      throw new TypeError("Bootstrap provenance must not include release-continuity evidence.");
    }
  } else {
    result.push(
      await transitionSubject(
        root,
        requireArg(args, "release-continuity"),
        PRODUCTION_RELEASE_CONTINUITY_NAME,
      ),
    );
  }
  return result.sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 : 0,
  );
}

function httpsUrl(value, label) {
  requireString(value, label, { maximum: 2048 });
  const url = new URL(value);
  if (url.protocol !== "https:" || url.username || url.password || url.hash) {
    throw new TypeError(`${label} must be a safe HTTPS URL.`);
  }
  return url.toString();
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const artifactRoot = path.resolve(requireArg(args, "artifact-root"));
  const output = path.resolve(requireArg(args, "output"));
  const relativeOutput = path.relative(artifactRoot, output).replaceAll(path.sep, "/");
  if (relativeOutput.startsWith("../") || relativeOutput === "..") {
    throw new TypeError("Provenance output must be inside artifact root so it can exclude itself safely.");
  }
  const startedOn = requireCanonicalTimestamp(requireArg(args, "started-at"), "startedAt");
  const finishedOn = requireCanonicalTimestamp(requireArg(args, "finished-at"), "finishedAt");
  if (finishedOn < startedOn) throw new TypeError("Provenance finish precedes start.");
  const sourceRepository = httpsUrl(requireArg(args, "source-repository"), "source repository");
  const sourceRevision = requireString(requireArg(args, "source-revision"), "source revision", {
    minimum: 40,
    maximum: 64,
    pattern: /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/u,
  });
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: args["release-template"]
      ? await releaseSubjects(artifactRoot, args["release-template"], args)
      : await subjects(artifactRoot, "", new Set([relativeOutput])),
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "urn:herd:build-type:privacy-release-evidence:v1",
        externalParameters: {
          releaseId: requireString(requireArg(args, "release-id"), "release ID", { maximum: 120 }),
          source: { repository: sourceRepository, revision: sourceRevision },
        },
        internalParameters: {},
        resolvedDependencies: [
          { uri: `${sourceRepository}@${sourceRevision}`, digest: { gitCommit: sourceRevision } },
          {
            uri: "release/toolchains.json",
            digest: { sha256: sha256Hex(await readFile(requireArg(args, "toolchain-spec"))) },
          },
        ],
      },
      runDetails: {
        builder: { id: httpsUrl(requireArg(args, "builder-id"), "builder ID") },
        metadata: {
          invocationId: requireString(requireArg(args, "invocation-id"), "invocation ID", {
            maximum: 300,
          }),
          startedOn,
          finishedOn,
        },
        byproducts: [],
      },
    },
  };
  if (statement.subject.length === 0) throw new TypeError("Provenance has no subjects.");
  await writeCanonicalJson(output, statement);
  process.stdout.write(`${JSON.stringify({ output, subjects: statement.subject.length })}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : error}\n`);
  process.exitCode = 1;
});
