import path from "node:path";

import { hashFile } from "./canonical.mjs";
import { manifestArtifactReferences } from "./release-manifest.mjs";

export async function verifyLocalArtifacts(manifest, artifactRoot) {
  const root = path.resolve(artifactRoot);
  const references = manifestArtifactReferences(manifest);
  const names = new Set();
  for (const reference of references) {
    if (names.has(reference.name)) throw new TypeError(`Artifact name ${reference.name} is repeated.`);
    names.add(reference.name);
    const filePath = path.resolve(root, reference.name);
    if (path.dirname(filePath) !== root) throw new TypeError(`Artifact name ${reference.name} escapes its root.`);
    const digest = await hashFile(filePath);
    if (digest.size !== reference.size || digest.sha256 !== reference.sha256) {
      throw new TypeError(`Artifact ${reference.name} does not match its release-manifest hash and size.`);
    }
  }
  return references.length;
}

export async function artifactReference(filePath, { name = path.basename(filePath), mediaType, url = null } = {}) {
  const { sha256, size } = await hashFile(filePath);
  return {
    name,
    mediaType,
    sha256,
    size,
    url,
  };
}
