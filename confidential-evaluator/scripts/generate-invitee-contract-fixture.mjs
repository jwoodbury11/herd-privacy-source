import { execFile } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

const execute = promisify(execFile);
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const repository = resolve(root, "..");
const outputDirectory = resolve(root, "test/vendor");
await mkdir(outputDirectory, { recursive: true });
await execute(resolve(repository, "invitee-web/node_modules/.bin/esbuild"), [
  "invitee-web/lib/backend/resolutions.ts",
  "--bundle",
  "--platform=node",
  "--format=esm",
  "--target=node20",
  "--legal-comments=none",
  "--alias:@=./invitee-web",
  "--banner:js=// Generated from invitee-web/lib/backend/resolutions.ts for compatibility testing; do not edit by hand.",
  `--outfile=${resolve(outputDirectory, "invitee-relay-completion.mjs")}`,
], { cwd: repository });
