import { access, cp, mkdir, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { Plugin } from "vite";

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return false;
    }
    throw error;
  }
}

// Packages Sites metadata and migrations after Vite finishes compiling.
export function sites(): Plugin {
  let root = process.cwd();

  return {
    name: "sites",
    apply: "build",
    configResolved(config) {
      root = config.root;
    },
    async closeBundle() {
      const distributionDirectory = resolve(root, "dist");
      const outputDirectory = resolve(distributionDirectory, ".openai");
      const hostingConfig = resolve(root, ".openai", "hosting.json");
      const drizzleSource = resolve(root, "drizzle");
      const releaseMarker = resolve(
        distributionDirectory,
        "HERD-RELEASE-CONFIG-SHA256",
      );
      const artifactReleaseMarker = resolve(
        distributionDirectory,
        "HERD-ARTIFACT-RELEASE-ID",
      );
      const privateAssetManifest = resolve(
        distributionDirectory,
        "client",
        ".vite",
        "manifest.json",
      );
      const publicAssetManifest = resolve(
        distributionDirectory,
        "client",
        "assets",
        "manifest.json",
      );

      await rm(outputDirectory, { recursive: true, force: true });
      await mkdir(outputDirectory, { recursive: true });

      if (await exists(hostingConfig)) {
        await cp(hostingConfig, resolve(outputDirectory, "hosting.json"));
      }
      if (await exists(drizzleSource)) {
        await cp(drizzleSource, resolve(outputDirectory, "drizzle"), {
          recursive: true,
        });
      }
      // vinext runs this hook once for each build environment. The client
      // manifest does not exist during the early analysis environments, but
      // it is present before the final server close. Publish it only then.
      if (await exists(privateAssetManifest)) {
        await cp(privateAssetManifest, publicAssetManifest);
      }
      // The signed production preflight requires this marker inside the exact
      // deployment archive. Remove any stale marker on ordinary test builds.
      await rm(releaseMarker, { force: true });
      await rm(artifactReleaseMarker, { force: true });
      const publicDigest =
        process.env.NEXT_PUBLIC_HERD_RELEASE_CONFIGURATION_SHA256?.trim();
      const runtimeDigest = process.env.HERD_RELEASE_CONFIGURATION_SHA256?.trim();
      if (publicDigest !== undefined) {
        if (!/^[0-9a-f]{64}$/u.test(publicDigest)) {
          throw new TypeError(
            "NEXT_PUBLIC_HERD_RELEASE_CONFIGURATION_SHA256 must be a lowercase SHA-256 digest.",
          );
        }
        if (runtimeDigest !== undefined && runtimeDigest !== publicDigest) {
          throw new TypeError(
            "Public and runtime Herd release-configuration digests do not match.",
          );
        }
        await writeFile(releaseMarker, `${publicDigest}\n`, {
          encoding: "utf8",
          mode: 0o644,
        });
      }

      const publicArtifactReleaseId =
        process.env.NEXT_PUBLIC_HERD_ARTIFACT_RELEASE_ID?.trim();
      const runtimeArtifactReleaseId =
        process.env.HERD_ARTIFACT_RELEASE_ID?.trim();
      if (publicArtifactReleaseId !== undefined) {
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(publicArtifactReleaseId)) {
          throw new TypeError(
            "NEXT_PUBLIC_HERD_ARTIFACT_RELEASE_ID must be a safe release identifier.",
          );
        }
        if (
          runtimeArtifactReleaseId !== undefined &&
          runtimeArtifactReleaseId !== publicArtifactReleaseId
        ) {
          throw new TypeError(
            "Public and runtime Herd artifact release identifiers do not match.",
          );
        }
        await writeFile(artifactReleaseMarker, `${publicArtifactReleaseId}\n`, {
          encoding: "utf8",
          mode: 0o644,
        });
      }
    },
  };
}
