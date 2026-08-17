import { webcrypto } from "node:crypto";
import { open } from "node:fs/promises";

function usage() {
  process.stderr.write(
    "usage: node scripts/generate-transparency-key-bundle.mjs <global-key-id> <output-file>\n",
  );
  process.exitCode = 2;
}

const [, , keyId, outputFile] = process.argv;
if (
  !keyId ||
  !/^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u.test(keyId) ||
  !outputFile
) {
  usage();
} else {
  const pair = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const exported = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
  const bundle = {
    protocolVersion: 1,
    logId: "herd-response-log-v1",
    transparencySigningKey: {
      keyId,
      privateKeyJwk: {
        kty: "EC",
        crv: "P-256",
        x: exported.x,
        y: exported.y,
        d: exported.d,
      },
    },
  };
  try {
    const handle = await open(outputFile, "wx", 0o600);
    try {
      await handle.writeFile(`${JSON.stringify(bundle)}\n`, { encoding: "utf8" });
      await handle.sync();
    } finally {
      await handle.close();
    }
  } finally {
    exported.x = "";
    exported.y = "";
    exported.d = "";
    bundle.transparencySigningKey.privateKeyJwk.x = "";
    bundle.transparencySigningKey.privateKeyJwk.y = "";
    bundle.transparencySigningKey.privateKeyJwk.d = "";
  }
  process.stdout.write(
    `wrote one-time mode-0600 global response-log key bundle to ${outputFile}\n`,
  );
}
