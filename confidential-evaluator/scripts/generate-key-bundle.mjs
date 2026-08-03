import { randomBytes, webcrypto } from "node:crypto";
import { open } from "node:fs/promises";

function usage() {
  process.stderr.write(
    "usage: node scripts/generate-key-bundle.mjs <release-id> <output-file>\n",
  );
  process.exitCode = 2;
}

const [, , releaseId, outputFile] = process.argv;
if (
  !releaseId ||
  !/^[A-Za-z0-9._-]{1,80}$/u.test(releaseId) ||
  !outputFile
) {
  usage();
} else {
  async function key(keyId, algorithm, usages) {
    const pair = await webcrypto.subtle.generateKey(
      { name: algorithm, namedCurve: "P-256" },
      true,
      usages,
    );
    const exported = await webcrypto.subtle.exportKey("jwk", pair.privateKey);
    return {
      keyId,
      privateKeyJwk: {
        kty: "EC",
        crv: "P-256",
        x: exported.x,
        y: exported.y,
        d: exported.d,
      },
    };
  }

  const bundle = {
    protocolVersion: 1,
    releaseId,
    requestAuthenticationToken: randomBytes(48).toString("base64url"),
    responseDecryptionKey: await key(
      `${releaseId}.response-decryption`,
      "ECDH",
      ["deriveBits"],
    ),
    evaluationResultSigningKey: await key(
      `${releaseId}.evaluation-result-signing`,
      "ECDSA",
      ["sign", "verify"],
    ),
    policySigningKey: await key(
      `${releaseId}.policy-signing`,
      "ECDSA",
      ["sign", "verify"],
    ),
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
    bundle.requestAuthenticationToken = "";
    for (const name of [
      "responseDecryptionKey",
      "evaluationResultSigningKey",
      "policySigningKey",
    ]) {
      bundle[name].privateKeyJwk.x = "";
      bundle[name].privateKeyJwk.y = "";
      bundle[name].privateKeyJwk.d = "";
    }
  }
  process.stdout.write(
    `wrote mode-0600 evaluator-epoch bundle to ${outputFile}; the global transparency identity is provisioned separately\n`,
  );
}
