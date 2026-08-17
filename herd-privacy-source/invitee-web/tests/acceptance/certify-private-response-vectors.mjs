import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";

const fixturePath = process.argv[2]
  ? process.argv[2]
  : fileURLToPath(
      new URL("./private-response-v1-cross-platform-vectors.json", import.meta.url),
    );
const fixture = JSON.parse(await readFile(fixturePath, "utf8"));

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

async function signingKey(keyId) {
  const keyPair = await crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  return {
    keyId,
    keyPair,
    publicKey: base64Url(await crypto.subtle.exportKey("raw", keyPair.publicKey)),
  };
}

const policySigning = await signingKey("interop-policy-signing-v1");
const transparencySigning = await signingKey("interop-transparency-signing-v1");
const signatures = new Map();
for (const vector of fixture.vectors) {
  let signature = signatures.get(vector.policy.canonicalDocument);
  if (!signature) {
    signature = base64Url(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        policySigning.keyPair.privateKey,
        new TextEncoder().encode(
          `HERD-POLICY-DESCRIPTOR-SIGNATURE-V1\0${vector.policy.canonicalDocument}`,
        ),
      ),
    );
    signatures.set(vector.policy.canonicalDocument, signature);
  }
  vector.policy.policySigningKeyId = policySigning.keyId;
  vector.policy.policySignature = signature;
}
fixture.trustPins = {
  policySigning: {
    keyId: policySigning.keyId,
    publicKey: policySigning.publicKey,
  },
  transparencySigning: {
    keyId: transparencySigning.keyId,
    publicKey: transparencySigning.publicKey,
  },
};

process.stdout.write(`${JSON.stringify(fixture, null, 2)}\n`);
