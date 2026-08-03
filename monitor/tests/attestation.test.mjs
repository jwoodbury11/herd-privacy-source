import "reflect-metadata";

import assert from "node:assert/strict";
import test from "node:test";

import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";

import {
  LiveEvaluatorAttestationError,
  verifyLiveEvaluatorAttestation,
} from "../src/attestation.mjs";

cryptoProvider.set(globalThis.crypto);

const NOW = new Date("2026-08-02T12:00:00.000Z");
const NOW_SECONDS = Math.floor(NOW.getTime() / 1000);
const ORIGIN = "https://evaluator.herd.example";
const AUDIENCE = `${ORIGIN}/attestation`;
const PROJECT_ID = "herd-prod";
const SERVICE_ACCOUNT = "herd-evaluator@herd-prod.iam.gserviceaccount.com";
const IMAGE_DIGEST = `sha256:${"1".repeat(64)}`;
const SW_VERSION = "260600";
const RELEASE_ID = "herd-evaluator-epoch-2026.08";
const FIXED_NONCE = Uint8Array.from({ length: 32 }, (_, index) => index + 1);

const rsaAlgorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2_048,
};
const signingAlgorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
};

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function rsaKeys() {
  return crypto.subtle.generateKey(rsaAlgorithm, true, ["sign", "verify"]);
}

async function certificateChain(name) {
  const notBefore = new Date("2026-08-01T00:00:00.000Z");
  const notAfter = new Date("2026-08-03T23:59:59.000Z");
  const rootKeys = await rsaKeys();
  const root = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${name}`,
    notBefore,
    notAfter,
    signingAlgorithm,
    keys: rootKeys,
    extensions: [
      new BasicConstraintsExtension(true, 1, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  const intermediateKeys = await rsaKeys();
  const intermediate = await X509CertificateGenerator.create({
    serialNumber: "02",
    subject: `CN=${name} Intermediate`,
    issuer: root.subject,
    notBefore,
    notAfter,
    publicKey: intermediateKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm,
    extensions: [
      new BasicConstraintsExtension(true, 0, true),
      new KeyUsagesExtension(
        KeyUsageFlags.keyCertSign | KeyUsageFlags.cRLSign,
        true,
      ),
    ],
  });
  const leafKeys = await rsaKeys();
  const leaf = await X509CertificateGenerator.create({
    serialNumber: "03",
    subject: `CN=${name} Attestation Leaf`,
    issuer: intermediate.subject,
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    signingAlgorithm,
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
    ],
  });
  return { root, intermediate, leaf, leafKeys };
}

async function p256PublicKey(algorithm) {
  const pair = await crypto.subtle.generateKey(
    algorithm === "ECDH_P256"
      ? { name: "ECDH", namedCurve: "P-256" }
      : { name: "ECDSA", namedCurve: "P-256" },
    true,
    algorithm === "ECDH_P256" ? ["deriveBits"] : ["sign", "verify"],
  );
  return base64Url(await crypto.subtle.exportKey("raw", pair.publicKey));
}

const trustedChain = await certificateChain("Herd Monitor Test Root");
const untrustedChain = await certificateChain("Other Monitor Test Root");
const rootFingerprint = Buffer.from(
  await sha256(trustedChain.root.rawData),
).toString("hex");

const keyBinding = {
  protocolVersion: 1,
  releaseId: RELEASE_ID,
  keys: {
    responseDecryption: {
      keyId: "response-decryption-2026",
      algorithm: "ECDH_P256",
      publicKey: await p256PublicKey("ECDH_P256"),
    },
    evaluationResultSigning: {
      keyId: "result-signing-2026",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
    policySigning: {
      keyId: "policy-signing-2026",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
    transparencySigning: {
      keyId: "receipt-signing-2026",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
  },
};

async function bindingHash(binding) {
  return base64Url(
    await sha256(
      new TextEncoder().encode(
        `HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1\0${JSON.stringify(binding)}`,
      ),
    ),
  );
}

const manifest = {
  evaluatorKeyEpochId: RELEASE_ID,
  trust: {
    evaluatorEncryption: keyBinding.keys.responseDecryption,
    resultSigning: keyBinding.keys.evaluationResultSigning,
    policySigning: keyBinding.keys.policySigning,
    receiptTransparencySigning: keyBinding.keys.transparencySigning,
    workload: {
      imageDigest: { algorithm: "sha256", value: IMAGE_DIGEST.slice(7) },
      attestationRootFingerprint: {
        algorithm: "sha256",
        value: rootFingerprint,
      },
      attestationClaimPolicy: {
        audience: AUDIENCE,
        maxAgeSeconds: 300,
        keyBindingHash: await bindingHash(keyBinding),
        projectId: PROJECT_ID,
        serviceAccount: SERVICE_ACCOUNT,
        allowedSwversions: [SW_VERSION],
      },
    },
  },
};

const configuration = {
  origin: ORIGIN,
  rootCertificateDerBase64: Buffer.from(trustedChain.root.rawData).toString(
    "base64",
  ),
  manifest,
};

async function jwt(header, claims, { badSignature = false } = {}) {
  const headerSegment = base64Url(Buffer.from(JSON.stringify(header)));
  const claimSegment = base64Url(Buffer.from(JSON.stringify(claims)));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      trustedChain.leafKeys.privateKey,
      new TextEncoder().encode(`${headerSegment}.${claimSegment}`),
    ),
  );
  if (badSignature) signature[0] ^= 1;
  return `${headerSegment}.${claimSegment}.${base64Url(signature)}`;
}

async function responseBody(nonce, mutation = {}) {
  const binding = structuredClone(keyBinding);
  mutation.binding?.(binding);
  const computedBindingHash = await bindingHash(binding);
  const claims = {
    iss: "https://confidentialcomputing.googleapis.com",
    aud: AUDIENCE,
    iat: NOW_SECONDS,
    nbf: NOW_SECONDS - 1,
    exp: NOW_SECONDS + 300,
    eat_nonce: [nonce, computedBindingHash],
    secboot: true,
    dbgstat: "disabled-since-boot",
    hwmodel: "GCP_INTEL_TDX",
    swname: "CONFIDENTIAL_SPACE",
    oemid: 11129,
    attester_tcb: ["INTEL"],
    swversion: [SW_VERSION],
    google_service_accounts: [SERVICE_ACCOUNT],
    submods: {
      gce: { project_id: PROJECT_ID },
      container: {
        image_digest: IMAGE_DIGEST,
        restart_policy: "Always",
        env_override: {},
        cmd_override: [],
      },
      confidential_space: {
        support_attributes: ["USABLE", "STABLE"],
        monitoring_enabled: { memory: false },
      },
    },
  };
  mutation.claims?.(claims);
  const header = {
    alg: "RS256",
    typ: "JWT",
    x5c: [
      trustedChain.leaf.toString("base64"),
      trustedChain.intermediate.toString("base64"),
    ],
  };
  mutation.header?.(header);
  const body = {
    protocolVersion: 1,
    tokenType: "google-pki",
    audience: AUDIENCE,
    nonce,
    keyBinding: binding,
    keyBindingHash: computedBindingHash,
    attestationToken: await jwt(header, claims, mutation),
  };
  mutation.response?.(body);
  return body;
}

function verifierOptions(mutation = {}) {
  return {
    now: () => new Date(NOW),
    randomBytes: (length) => {
      assert.equal(length, 32);
      return Uint8Array.from(FIXED_NONCE);
    },
    fetchImpl: async (url, init) => {
      assert.equal(url, `${ORIGIN}/api/v1/attestation`);
      assert.equal(init.method, "POST");
      assert.equal(init.redirect, "manual");
      assert.equal(init.cache, "no-store");
      assert.equal(init.headers.authorization, undefined);
      const { protocolVersion, nonce } = JSON.parse(init.body);
      assert.equal(protocolVersion, 1);
      assert.equal(nonce, base64Url(FIXED_NONCE));
      const body = await responseBody(nonce, mutation);
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  };
}

test("independent monitor verifies a direct nonce challenge against its offline root", async () => {
  const result = await verifyLiveEvaluatorAttestation(
    configuration,
    verifierOptions(),
  );
  assert.deepEqual(result, {
    verifiedAt: NOW.toISOString(),
    origin: ORIGIN,
    audience: AUDIENCE,
    imageDigest: IMAGE_DIGEST,
    keyBindingHash: manifest.trust.workload.attestationClaimPolicy.keyBindingHash,
    rootFingerprint,
  });
});

test("live attestation fails closed across token, key, claim, and root attacks", async (t) => {
  const mutations = [
    ["wrong nonce", { claims: (claims) => { claims.eat_nonce[0] = base64Url(new Uint8Array(32)); } }],
    ["wrong image", { claims: (claims) => { claims.submods.container.image_digest = `sha256:${"2".repeat(64)}`; } }],
    ["extra TCB", { claims: (claims) => { claims.attester_tcb.push("UNREVIEWED"); } }],
    ["fractional OEM", { claims: (claims) => { claims.oemid = 11129.5; } }],
    ["fractional issued-at", { claims: (claims) => { claims.iat += 0.5; } }],
    ["inverted expiry", { claims: (claims) => { claims.exp = claims.iat; } }],
    ["wrong service account", { claims: (claims) => { claims.google_service_accounts = ["other@herd-prod.iam.gserviceaccount.com"]; } }],
    ["extra monitoring mode", { claims: (claims) => { claims.submods.confidential_space.monitoring_enabled.disk = true; } }],
    ["missing command override", { claims: (claims) => { delete claims.submods.container.cmd_override; } }],
    ["wrong environment override shape", { claims: (claims) => { claims.submods.container.env_override = []; } }],
    ["unapproved OS", { claims: (claims) => { claims.swversion = ["999999"]; } }],
    ["bad signature", { badSignature: true }],
    ["dangerous remote key header", { header: (header) => { header.jku = "https://evil.example/key"; } }],
    ["changed key binding", { binding: (binding) => { binding.keys.policySigning.keyId = "other-policy-key"; } }],
  ];
  for (const [name, mutation] of mutations) {
    await t.test(name, async () => {
      await assert.rejects(
        verifyLiveEvaluatorAttestation(configuration, verifierOptions(mutation)),
        LiveEvaluatorAttestationError,
      );
    });
  }

  await t.test("root differs from signed manifest", async () => {
    await assert.rejects(
      verifyLiveEvaluatorAttestation(
        {
          ...configuration,
          rootCertificateDerBase64: Buffer.from(
            untrustedChain.root.rawData,
          ).toString("base64"),
        },
        verifierOptions(),
      ),
      /configured attestation root differs/u,
    );
  });

  await t.test("audience is outside independently pinned origin", async () => {
    const changed = structuredClone(configuration);
    changed.manifest.trust.workload.attestationClaimPolicy.audience =
      "https://other.herd.example/attestation";
    await assert.rejects(
      verifyLiveEvaluatorAttestation(changed, verifierOptions()),
      /outside the independently configured evaluator origin/u,
    );
  });
});

test("live endpoint rejects redirects, non-JSON, and oversized bodies", async (t) => {
  const base = {
    now: () => new Date(NOW),
    randomBytes: () => Uint8Array.from(FIXED_NONCE),
  };
  await t.test("redirect", async () => {
    await assert.rejects(
      verifyLiveEvaluatorAttestation(configuration, {
        ...base,
        fetchImpl: async () => new Response(null, {
          status: 302,
          headers: { location: "https://evil.example/attestation" },
        }),
      }),
      /redirected/u,
    );
  });
  await t.test("non-JSON", async () => {
    await assert.rejects(
      verifyLiveEvaluatorAttestation(configuration, {
        ...base,
        fetchImpl: async () => new Response("no", {
          headers: { "content-type": "text/plain" },
        }),
      }),
      /non-JSON/u,
    );
  });
  await t.test("oversized", async () => {
    await assert.rejects(
      verifyLiveEvaluatorAttestation(configuration, {
        ...base,
        fetchImpl: async () => new Response("{}", {
          headers: {
            "content-type": "application/json",
            "content-length": String(256 * 1024),
          },
        }),
      }),
      /oversized/u,
    );
  });
});
