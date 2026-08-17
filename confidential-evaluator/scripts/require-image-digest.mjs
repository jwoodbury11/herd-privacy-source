const reference = process.argv[2] ?? process.env.NODE_IMAGE ?? "";
const match = reference.match(
  /^node:22\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-bookworm-slim@sha256:[0-9a-f]{64}$/u,
);
if (!match || Number(match[1]) < 13) {
  process.stderr.write(
    "base image must be an immutable official node:22.13.0-or-newer-bookworm-slim @sha256 reference\n",
  );
  process.exitCode = 1;
} else {
  process.stdout.write("immutable supported Node base image reference verified\n");
}
