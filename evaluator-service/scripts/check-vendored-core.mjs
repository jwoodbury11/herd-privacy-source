import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { access, readFile } from "node:fs/promises";

const files = [
  {
    local: new URL("../vendor/privacy-evaluator/fixed-point.mjs", import.meta.url),
    upstream: new URL("../../privacy-evaluator/src/fixed-point.mjs", import.meta.url),
    sha256: "a9d622965eee9fc145b4615eea289819f4cb01ce42105c784de02b318c765221",
  },
  {
    local: new URL(
      "../vendor/privacy-evaluator/private-response-envelope.mjs",
      import.meta.url,
    ),
    upstream: new URL(
      "../../privacy-evaluator/src/private-response-envelope.mjs",
      import.meta.url,
    ),
    sha256: "3d948f18f57eac37ce5374053336eccd4e300b66c5d21974d0fd1b7d9a0dd600",
  },
];

function digest(value) {
  return createHash("sha256").update(value).digest("hex");
}

for (const file of files) {
  const local = await readFile(file.local);
  assert.equal(digest(local), file.sha256, `vendored core changed: ${file.local.pathname}`);
  try {
    await access(file.upstream);
  } catch {
    continue;
  }
  const upstream = await readFile(file.upstream);
  assert.deepEqual(local, upstream, `vendored core differs from ${file.upstream.pathname}`);
}
