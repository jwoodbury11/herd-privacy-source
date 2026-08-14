import { readFile } from "node:fs/promises";
import { webcrypto } from "node:crypto";

import {
  IDENTIFIER_PATTERN,
  KEY_BINDING_DOMAIN,
  PROTOCOL_VERSION,
  TRANSPARENCY_LOG_ID,
} from "./constants.mjs";
import { normalizeImageDigest } from "./config.mjs";
import {
  decodeConfiguredBase64Url,
  domainSeparatedBytes,
  encodeBase64Url,
  exactKeys,
  sha256Base64Url,
} from "./encoding.mjs";
import { ConfigurationError } from "./errors.mjs";

const BUNDLE_KEYS = Object.freeze([
  "protocolVersion",
  "releaseId",
  "requestAuthenticationToken",
  "responseDecryptionKey",
  "evaluationResultSigningKey",
  "policySigningKey",
]);
const TRANSPARENCY_BUNDLE_KEYS = Object.freeze([
  "protocolVersion",
  "logId",
  "transparencySigningKey",
]);
const KEY_KEYS = Object.freeze(["keyId", "privateKeyJwk"]);
const JWK_KEYS = Object.freeze(["kty", "crv", "x", "y", "d"]);

function fail() {
  throw new ConfigurationError();
}

function identifier(value) {
  if (typeof value !== "string" || !IDENTIFIER_PATTERN.test(value)) fail();
  return value;
}

function normalizePrivateJwk(value) {
  const input = exactKeys(value, JWK_KEYS, fail);
  if (input.kty !== "EC" || input.crv !== "P-256") fail();
  return {
    kty: "EC",
    crv: "P-256",
    x: encodeBase64Url(decodeConfiguredBase64Url(input.x, 32)),
    y: encodeBase64Url(decodeConfiguredBase64Url(input.y, 32)),
    d: encodeBase64Url(decodeConfiguredBase64Url(input.d, 32)),
  };
}

async function importKey(value, usage) {
  const input = exactKeys(value, KEY_KEYS, fail);
  const keyId = identifier(input.keyId);
  const jwk = normalizePrivateJwk(input.privateKeyJwk);
  let privateKey;
  try {
    privateKey = await webcrypto.subtle.importKey(
      "jwk",
      {
        ...jwk,
        ext: false,
        key_ops: usage === "deriveBits" ? ["deriveBits"] : ["sign"],
      },
      usage === "deriveBits"
        ? { name: "ECDH", namedCurve: "P-256" }
        : { name: "ECDSA", namedCurve: "P-256" },
      false,
      [usage],
    );
  } catch {
    fail();
  }
  const rawPublicKey = new Uint8Array(65);
  rawPublicKey[0] = 0x04;
  rawPublicKey.set(decodeConfiguredBase64Url(jwk.x, 32), 1);
  rawPublicKey.set(decodeConfiguredBase64Url(jwk.y, 32), 33);
  const publicKey = encodeBase64Url(rawPublicKey);
  const privateScalar = Buffer.from(jwk.d, "base64url");
  const privateFingerprint = sha256Base64Url(privateScalar);
  privateScalar.fill(0);
  jwk.x = "";
  jwk.y = "";
  jwk.d = "";
  if (input.privateKeyJwk && typeof input.privateKeyJwk === "object") {
    input.privateKeyJwk.x = "";
    input.privateKeyJwk.y = "";
    input.privateKeyJwk.d = "";
  }
  return { keyId, privateKey, publicKey, privateFingerprint };
}

function publicKeyMetadata(releaseId, keys) {
  return Object.freeze({
    protocolVersion: PROTOCOL_VERSION,
    releaseId,
    keys: Object.freeze({
      responseDecryption: Object.freeze({
        keyId: keys.responseDecryption.keyId,
        algorithm: "ECDH_P256",
        publicKey: keys.responseDecryption.publicKey,
      }),
      evaluationResultSigning: Object.freeze({
        keyId: keys.evaluationResultSigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: keys.evaluationResultSigning.publicKey,
      }),
      policySigning: Object.freeze({
        keyId: keys.policySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: keys.policySigning.publicKey,
      }),
      transparencySigning: Object.freeze({
        keyId: keys.transparencySigning.keyId,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: keys.transparencySigning.publicKey,
      }),
    }),
  });
}

function parsePlaintextJson(plaintext) {
  if (!(plaintext instanceof Uint8Array) || plaintext.length === 0) fail();
  if (plaintext.length > 64 * 1024) fail();
  let input;
  try {
    input = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
  } catch {
    fail();
  } finally {
    plaintext.fill(0);
  }
  return input;
}

export async function parseKeyBundles(
  epochPlaintext,
  transparencyPlaintext,
  config,
  attestedImageDigest,
) {
  const input = parsePlaintextJson(epochPlaintext);
  const transparencyInput = parsePlaintextJson(transparencyPlaintext);
  exactKeys(input, BUNDLE_KEYS, fail);
  exactKeys(transparencyInput, TRANSPARENCY_BUNDLE_KEYS, fail);
  if (input.protocolVersion !== PROTOCOL_VERSION) fail();
  if (
    transparencyInput.protocolVersion !== PROTOCOL_VERSION ||
    transparencyInput.logId !== TRANSPARENCY_LOG_ID
  ) {
    fail();
  }
  if (input.releaseId !== config.releaseId) fail();
  const imageDigest = normalizeImageDigest(attestedImageDigest);
  const requestAuthenticationToken = input.requestAuthenticationToken;
  if (
    typeof requestAuthenticationToken !== "string" ||
    requestAuthenticationToken.length < 32 ||
    requestAuthenticationToken.length > 512 ||
    /[\u0000-\u0020\u007f]/u.test(requestAuthenticationToken)
  ) {
    fail();
  }
  const keys = {
    responseDecryption: await importKey(
      input.responseDecryptionKey,
      "deriveBits",
    ),
    evaluationResultSigning: await importKey(
      input.evaluationResultSigningKey,
      "sign",
    ),
    policySigning: await importKey(input.policySigningKey, "sign"),
    transparencySigning: await importKey(
      transparencyInput.transparencySigningKey,
      "sign",
    ),
  };
  const ids = Object.values(keys).map(({ keyId }) => keyId);
  const publicKeys = Object.values(keys).map(({ publicKey }) => publicKey);
  const privateFingerprints = Object.values(keys).map(
    ({ privateFingerprint }) => privateFingerprint,
  );
  if (
    new Set(ids).size !== ids.length ||
    new Set(publicKeys).size !== publicKeys.length ||
    new Set(privateFingerprints).size !== privateFingerprints.length
  ) {
    fail();
  }
  const relayBindings = Object.freeze({
    HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN: config.allowedOrigin ?? "",
  });
  for (const key of Object.values(keys)) delete key.privateFingerprint;
  const metadata = publicKeyMetadata(config.releaseId, keys);
  const keyBindingHash = sha256Base64Url(
    domainSeparatedBytes(KEY_BINDING_DOMAIN, JSON.stringify(metadata)),
  );
  input.requestAuthenticationToken = "";
  const evaluatorConfig = {
    keyId: keys.responseDecryption.keyId,
    privateKey: keys.responseDecryption.privateKey,
    publicKey: keys.responseDecryption.publicKey,
    measurement: config.policyMeasurement,
    releaseId: config.releaseId,
  };
  Object.defineProperty(evaluatorConfig, "token", {
    value: requestAuthenticationToken,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.freeze(evaluatorConfig);
  const keyStore = {
    keys: Object.freeze(keys),
    metadata,
    keyBindingHash,
    evaluatorConfig,
    attestedImageDigest: imageDigest,
  };
  Object.defineProperty(keyStore, "requestAuthenticationToken", {
    value: requestAuthenticationToken,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  Object.defineProperty(keyStore, "relayBindings", {
    value: relayBindings,
    enumerable: false,
    writable: false,
    configurable: false,
  });
  return Object.freeze(keyStore);
}

export async function loadKeyStore({
  config,
  decryptor,
  transparencyDecryptor,
  read = readFile,
}) {
  if (!transparencyDecryptor) fail();
  async function decryptFile(filePath, provider) {
    let ciphertext;
    try {
      ciphertext = await read(filePath);
    } catch {
      fail();
    }
    if (!Buffer.isBuffer(ciphertext)) ciphertext = Buffer.from(ciphertext);
    if (ciphertext.length === 0 || ciphertext.length > 64 * 1024) {
      ciphertext.fill(0);
      fail();
    }
    try {
      return await provider.decrypt(Uint8Array.from(ciphertext));
    } finally {
      ciphertext.fill(0);
    }
  }
  const results = await Promise.allSettled([
    decryptFile(config.keyBundleCiphertextFile, decryptor),
    decryptFile(config.transparencyKeyCiphertextFile, transparencyDecryptor),
  ]);
  if (results.some(({ status }) => status === "rejected")) {
    for (const result of results) {
      if (result.status === "fulfilled") result.value.fill(0);
    }
    fail();
  }
  const plaintext = results[0].value;
  const transparencyPlaintext = results[1].value;
  let attestedImageDigest;
  try {
    attestedImageDigest = decryptor.getAttestedImageDigest();
    if (
      transparencyDecryptor.getAttestedImageDigest() !== attestedImageDigest
    ) {
      fail();
    }
  } catch {
    plaintext?.fill(0);
    transparencyPlaintext?.fill(0);
    fail();
  }
  return parseKeyBundles(
    plaintext,
    transparencyPlaintext,
    config,
    attestedImageDigest,
  );
}
