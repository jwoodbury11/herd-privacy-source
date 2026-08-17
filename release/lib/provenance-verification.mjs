import { execFile } from "node:child_process";
import path from "node:path";
import { promisify } from "node:util";

import { hashFile } from "./canonical.mjs";

const run = promisify(execFile);
const GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com";

function localArtifactPath(root, descriptor) {
  const filePath = path.resolve(root, descriptor.name);
  if (path.dirname(filePath) !== root) {
    throw new TypeError(`Provenance artifact ${descriptor.name} escapes its artifact root.`);
  }
  return filePath;
}

async function requirePinnedArtifact(root, descriptor, label) {
  const filePath = localArtifactPath(root, descriptor);
  const actual = await hashFile(filePath);
  if (actual.sha256 !== descriptor.sha256 || actual.size !== descriptor.size) {
    throw new TypeError(`${label} does not match its signed release-manifest descriptor.`);
  }
  return filePath;
}

export async function verifyProvenanceBundles(
  manifest,
  artifactRoot,
  { cosign = "cosign" } = {},
) {
  const root = path.resolve(artifactRoot);
  let verified = 0;
  for (const [index, provenance] of manifest.evidence.provenance.entries()) {
    if (provenance.issuer !== `${GITHUB_ACTIONS_OIDC_ISSUER}/`) {
      throw new TypeError(`Provenance ${index} does not use the GitHub Actions OIDC issuer.`);
    }
    const statementPath = await requirePinnedArtifact(
      root,
      provenance.statement,
      `Provenance statement ${index}`,
    );
    const bundlePath = await requirePinnedArtifact(
      root,
      provenance.bundle,
      `Provenance bundle ${index}`,
    );
    try {
      await run(
        cosign,
        [
          "verify-blob",
          "--bundle",
          bundlePath,
          "--certificate-identity",
          provenance.workflowIdentity,
          "--certificate-oidc-issuer",
          GITHUB_ACTIONS_OIDC_ISSUER,
          statementPath,
        ],
        { maxBuffer: 4 * 1024 * 1024 },
      );
    } catch (error) {
      throw new TypeError(
        `Cosign verification failed for provenance bundle ${provenance.bundle.name}: ${error instanceof Error ? error.message : error}`,
      );
    }
    verified += 1;
  }
  return verified;
}
