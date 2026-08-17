import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import {
  canonicalJson,
  exactKeys,
  requireCanonicalTimestamp,
  requireSha256,
  requireString,
  sha256Hex,
} from "./canonical.mjs";

const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,119}$/u;

function coordinate(value, label) {
  if (typeof value !== "string") throw new TypeError(`${label} is missing.`);
  const bytes = Buffer.from(value, "base64url");
  if (bytes.byteLength !== 32 || bytes.toString("base64url") !== value) {
    throw new TypeError(`${label} must be a canonical 32-byte P-256 coordinate.`);
  }
  return bytes;
}

export function rawP256PublicKey(keyInput) {
  const key = keyInput?.type === "public" ? keyInput : createPublicKey(keyInput);
  const jwk = key.export({ format: "jwk" });
  if (jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new TypeError("The release signing key must be P-256.");
  }
  return Buffer.concat([Buffer.from([0x04]), coordinate(jwk.x, "public key x"), coordinate(jwk.y, "public key y")]);
}

export function releaseSigningKeyDescriptor(publicKeyInput, keyId) {
  const raw = rawP256PublicKey(publicKeyInput);
  return {
    keyId: requireString(keyId, "release signing key ID", { maximum: 120, pattern: KEY_ID }),
    algorithm: "ECDSA_P256_SHA256",
    publicKeyFormat: "P256_X963_BASE64URL",
    publicKey: raw.toString("base64url"),
    publicKeySha256: sha256Hex(raw),
  };
}

export function assertPrivateKeyMatchesPublic(privateKeyInput, publicKeyInput) {
  const privateKey = createPrivateKey(privateKeyInput);
  if (privateKey.asymmetricKeyType !== "ec" || privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") {
    throw new TypeError("The release signing private key must be P-256.");
  }
  const expected = rawP256PublicKey(publicKeyInput);
  const derived = rawP256PublicKey(createPublicKey(privateKey));
  if (!expected.equals(derived)) throw new TypeError("The release signing public and private keys do not match.");
  return privateKey;
}

export function signCanonicalArtifact({ bytes, privateKey, publicKey, keyId, signedAt, artifactType }) {
  const signingKey = assertPrivateKeyMatchesPublic(privateKey, publicKey);
  const descriptor = releaseSigningKeyDescriptor(publicKey, keyId);
  const signature = cryptoSign("sha256", bytes, {
    key: signingKey,
    dsaEncoding: "ieee-p1363",
  });
  if (signature.byteLength !== 64) throw new TypeError("Release signature did not produce 64-byte P1363 output.");
  return {
    schemaVersion: 1,
    artifactType: requireString(artifactType, "artifact type", { maximum: 200 }),
    algorithm: "ECDSA_P256_SHA256",
    keyId: descriptor.keyId,
    publicKeySha256: descriptor.publicKeySha256,
    signedDigest: { algorithm: "sha256", value: sha256Hex(bytes) },
    signatureFormat: "P1363_BASE64URL",
    signature: signature.toString("base64url"),
    signedAt: requireCanonicalTimestamp(signedAt, "signedAt"),
  };
}

export function normalizeSignatureEnvelope(value, expectedArtifactType) {
  exactKeys(
    value,
    [
      "schemaVersion",
      "artifactType",
      "algorithm",
      "keyId",
      "publicKeySha256",
      "signedDigest",
      "signatureFormat",
      "signature",
      "signedAt",
    ],
    "signature envelope",
  );
  if (
    value.schemaVersion !== 1 ||
    value.artifactType !== expectedArtifactType ||
    value.algorithm !== "ECDSA_P256_SHA256" ||
    value.signatureFormat !== "P1363_BASE64URL"
  ) {
    throw new TypeError("Signature envelope uses an unsupported format.");
  }
  exactKeys(value.signedDigest, ["algorithm", "value"], "signature envelope signedDigest");
  if (value.signedDigest.algorithm !== "sha256") {
    throw new TypeError("Signature envelope digest algorithm is unsupported.");
  }
  const signature = Buffer.from(value.signature, "base64url");
  if (signature.byteLength !== 64 || signature.toString("base64url") !== value.signature) {
    throw new TypeError("Signature envelope signature is not canonical 64-byte P1363 base64url.");
  }
  return {
    schemaVersion: 1,
    artifactType: expectedArtifactType,
    algorithm: "ECDSA_P256_SHA256",
    keyId: requireString(value.keyId, "signature envelope keyId", { maximum: 120, pattern: KEY_ID }),
    publicKeySha256: requireSha256(value.publicKeySha256, "signature envelope publicKeySha256"),
    signedDigest: {
      algorithm: "sha256",
      value: requireSha256(value.signedDigest.value, "signature envelope signedDigest.value"),
    },
    signatureFormat: "P1363_BASE64URL",
    signature: value.signature,
    signedAt: requireCanonicalTimestamp(value.signedAt, "signature envelope signedAt"),
  };
}

export function verifyCanonicalArtifact({ bytes, envelope, publicKey, artifactType, expectedKey }) {
  const normalized = normalizeSignatureEnvelope(envelope, artifactType);
  if (canonicalJson(normalized) !== canonicalJson(envelope)) {
    throw new TypeError("Signature envelope is not canonical JSON data.");
  }
  const descriptor = releaseSigningKeyDescriptor(publicKey, normalized.keyId);
  if (
    normalized.publicKeySha256 !== descriptor.publicKeySha256 ||
    normalized.signedDigest.value !== sha256Hex(bytes)
  ) {
    throw new TypeError("Signature envelope does not bind the supplied artifact and public key.");
  }
  if (
    expectedKey &&
    (expectedKey.keyId !== normalized.keyId ||
      expectedKey.publicKeySha256 !== normalized.publicKeySha256 ||
      expectedKey.publicKey !== descriptor.publicKey)
  ) {
    throw new TypeError("Release signature does not use the key pinned by the manifest.");
  }
  const verified = cryptoVerify("sha256", bytes, {
    key: createPublicKey(publicKey),
    dsaEncoding: "ieee-p1363",
  }, Buffer.from(normalized.signature, "base64url"));
  if (!verified) throw new TypeError("Release signature verification failed.");
  return normalized;
}
