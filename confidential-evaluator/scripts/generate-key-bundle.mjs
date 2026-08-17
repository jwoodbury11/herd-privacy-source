import { randomBytes, webcrypto } from "node:crypto";
import { open } from "node:fs/promises";

function usage() {
  process.stderr.write(
    "usage: node scripts/generate-key-bundle.mjs <release-id> <bundle-output-file> <request-token-output-file>\n",
  );
  process.exitCode = 2;
}

const [, , releaseId, outputFile, tokenOutputFile] = process.argv;
if (
  !releaseId ||
  !/^[A-Za-z0-9._-]{1,80}$/u.test(releaseId) ||
  !outputFile ||
  !tokenOutputFile ||
  tokenOutputFile === outputFile
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
    const bundleHandle = await open(outputFile, "wx", 0o600);
    try {
      const tokenHandle = await open(tokenOutputFile, "wx", 0o600);
      try {
        await bundleHandle.writeFile(`${JSON.stringify(bundle)}\n`, { encoding: "utf8" });
        await bundleHandle.sync();
        await tokenHandle.writeFile(`${bundle.requestAuthenticationToken}\n`, {
          encoding: "utf8",
        });
        await tokenHandle.sync();
      } finally {
        await tokenHandle.close();
      }
    } finally {
      await bundleHandle.close();
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
    `wrote mode-0600 evaluator-epoch bundle to ${outputFile} and backend token to ${tokenOutputFile}; the global transparency identity is provisioned separately\n`,
  );
}
