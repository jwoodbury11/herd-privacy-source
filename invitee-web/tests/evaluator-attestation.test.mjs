import assert from "node:assert/strict";
import { after, test } from "node:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL, fileURLToPath } from "node:url";
import ts from "typescript";

// @peculiar/x509 uses tsyringe for its internal registries. The production
// bundle expects the standard metadata reflection API, but does not ship its
// optional polyfill. These tests only need constructor-level metadata.
const reflectionMetadata = new WeakMap();
Reflect.defineMetadata ??= (key, value, target) => {
  let metadata = reflectionMetadata.get(target);
  if (!metadata) {
    metadata = new Map();
    reflectionMetadata.set(target, metadata);
  }
  metadata.set(key, value);
};
Reflect.getOwnMetadata ??= (key, target) =>
  reflectionMetadata.get(target)?.get(key);
Reflect.getMetadata ??= (key, target) => {
  for (let current = target; current; current = Object.getPrototypeOf(current)) {
    const value = Reflect.getOwnMetadata(key, current);
    if (value !== undefined) return value;
  }
  return undefined;
};

const {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
  cryptoProvider,
} = await import("@peculiar/x509");

const projectRoot = fileURLToPath(new URL("..", import.meta.url));
const temporaryDirectory = await mkdtemp(join(projectRoot, ".attestation-test-"));
const originalFetch = globalThis.fetch;

after(async () => {
  globalThis.fetch = originalFetch;
  await rm(temporaryDirectory, { recursive: true, force: true });
});

async function transpile(sourceName, outputName, replacements = []) {
  let source = await readFile(join(projectRoot, sourceName), "utf8");
  for (const [pattern, replacement] of replacements) {
    source = source.replace(pattern, replacement);
  }
  const output = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
      isolatedModules: true,
    },
    fileName: sourceName,
  }).outputText;
  await writeFile(join(temporaryDirectory, outputName), output);
}

await transpile("lib/privacy/protocol.ts", "protocol.mjs");
await transpile(
  "lib/privacy/evaluator-attestation.ts",
  "evaluator-attestation.mjs",
  [[/from "\.\/protocol";/u, 'from "./protocol.mjs";']],
);

const attestationModule = await import(
  `${pathToFileURL(join(temporaryDirectory, "evaluator-attestation.mjs")).href}?test=1`,
);

cryptoProvider.set(globalThis.crypto);

const rsaAlgorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
  publicExponent: new Uint8Array([1, 0, 1]),
  modulusLength: 2_048,
};
const certificateSigningAlgorithm = {
  name: "RSASSA-PKCS1-v1_5",
  hash: "SHA-256",
};

async function rsaKeys() {
  return crypto.subtle.generateKey(rsaAlgorithm, true, ["sign", "verify"]);
}

async function certificateChain(rootName) {
  const now = Date.now();
  const notBefore = new Date(now - 86_400_000);
  const notAfter = new Date(now + 86_400_000);
  const rootKeys = await rsaKeys();
  const root = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: `CN=${rootName}`,
    notBefore,
    notAfter,
    signingAlgorithm: certificateSigningAlgorithm,
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
    subject: `CN=${rootName} Intermediate`,
    issuer: root.subject,
    notBefore,
    notAfter,
    publicKey: intermediateKeys.publicKey,
    signingKey: rootKeys.privateKey,
    signingAlgorithm: certificateSigningAlgorithm,
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
    subject: `CN=${rootName} Attestation Leaf`,
    issuer: intermediate.subject,
    notBefore,
    notAfter,
    publicKey: leafKeys.publicKey,
    signingKey: intermediateKeys.privateKey,
    signingAlgorithm: certificateSigningAlgorithm,
    extensions: [
      new BasicConstraintsExtension(false, undefined, true),
      new KeyUsagesExtension(KeyUsageFlags.digitalSignature, true),
    ],
  });
  return { root, intermediate, leaf, leafKeys };
}

function base64Url(value) {
  return Buffer.from(value).toString("base64url");
}

async function sha256(value) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", value));
}

async function p256PublicKey(algorithm) {
  const keyPair = await crypto.subtle.generateKey(
    algorithm === "ECDH_P256"
      ? { name: "ECDH", namedCurve: "P-256" }
      : { name: "ECDSA", namedCurve: "P-256" },
    true,
    algorithm === "ECDH_P256" ? ["deriveBits"] : ["sign", "verify"],
  );
  return base64Url(await crypto.subtle.exportKey("raw", keyPair.publicKey));
}

const releaseId = "attestation-test-release-v1";
const audience = "https://herd.test/attestation";
const projectId = "herd-attestation-test-project";
const serviceAccount = "evaluator@herd-attestation-test.iam.gserviceaccount.com";
const imageDigest = `sha256:${"a".repeat(64)}`;
const rolloutImageDigest = `sha256:${"c".repeat(64)}`;
const policyMeasurement = `sha256:${"c".repeat(64)}`;
const swVersion = "260600";
const keyBinding = {
  protocolVersion: 1,
  releaseId,
  keys: {
    responseDecryption: {
      keyId: "attestation-response-v1",
      algorithm: "ECDH_P256",
      publicKey: await p256PublicKey("ECDH_P256"),
    },
    evaluationResultSigning: {
      keyId: "attestation-result-v1",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
    policySigning: {
      keyId: "attestation-policy-v1",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
    transparencySigning: {
      keyId: "attestation-transparency-v1",
      algorithm: "ECDSA_P256_SHA256",
      publicKey: await p256PublicKey("ECDSA_P256_SHA256"),
    },
  },
};
const trustedChain = await certificateChain("Herd Test Root");
const untrustedChain = await certificateChain("Untrusted Test Root");

async function fingerprint(certificate) {
  return Buffer.from(await sha256(certificate.rawData)).toString("hex");
}

function installTrustEnvironment(root = trustedChain.root) {
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_AUDIENCE = audience;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_PROJECT_ID = projectId;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_SERVICE_ACCOUNT = serviceAccount;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGEST = imageDigest;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGESTS = imageDigest;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_MEASUREMENT = policyMeasurement;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_ROOT_CERTIFICATE = root.toString("pem");
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_SWVERSIONS = swVersion;
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_MAX_AGE_SECONDS = "300";
  process.env.NEXT_PUBLIC_HERD_RELEASE_ID = releaseId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID =
    keyBinding.keys.responseDecryption.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY =
    keyBinding.keys.responseDecryption.publicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID =
    keyBinding.keys.evaluationResultSigning.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY =
    keyBinding.keys.evaluationResultSigning.publicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID =
    keyBinding.keys.policySigning.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY =
    keyBinding.keys.policySigning.publicKey;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID =
    keyBinding.keys.transparencySigning.keyId;
  process.env.NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY =
    keyBinding.keys.transparencySigning.publicKey;
}

const policy = {
  protocolVersion: 1,
  cipherSuite: "P256_HKDF_SHA256_AES256_GCM",
  policyHash: base64Url(new Uint8Array(32)),
  canonicalDocument: "{}",
  evaluatorKeyId: keyBinding.keys.responseDecryption.keyId,
  evaluatorPublicKey: keyBinding.keys.responseDecryption.publicKey,
  evaluatorMeasurement: policyMeasurement,
  releaseId,
  paddedPlaintextBytes: 4_096,
  frozenAt: "2026-08-02T00:00:00.000Z",
  policySigningKeyId: keyBinding.keys.policySigning.keyId,
  policySignature: base64Url(new Uint8Array(64)),
};

async function keyBindingHash(binding) {
  return base64Url(
    await sha256(
      new TextEncoder().encode(
        `HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1\0${JSON.stringify(binding)}`,
      ),
    ),
  );
}

async function jwt(header, claims, { badSignature = false } = {}) {
  const headerSegment = base64Url(Buffer.from(JSON.stringify(header)));
  const claimsSegment = base64Url(Buffer.from(JSON.stringify(claims)));
  const signature = new Uint8Array(
    await crypto.subtle.sign(
      { name: "RSASSA-PKCS1-v1_5" },
      trustedChain.leafKeys.privateKey,
      new TextEncoder().encode(`${headerSegment}.${claimsSegment}`),
    ),
  );
  if (badSignature) signature[0] ^= 1;
  return `${headerSegment}.${claimsSegment}.${base64Url(signature)}`;
}

async function attestationResponse(nonce, mutation = {}) {
  const binding = structuredClone(keyBinding);
  mutation.binding?.(binding);
  const bindingHash = await keyBindingHash(binding);
  const now = Math.floor(Date.now() / 1_000);
  const claims = {
    iss: "https://confidentialcomputing.googleapis.com",
    aud: audience,
    iat: now,
    nbf: now - 1,
    exp: now + 300,
    eat_nonce: [nonce, bindingHash],
    secboot: true,
    dbgstat: "disabled-since-boot",
    hwmodel: "GCP_INTEL_TDX",
    swname: "CONFIDENTIAL_SPACE",
    oemid: 11129,
    attester_tcb: ["INTEL"],
    swversion: [swVersion],
    google_service_accounts: [serviceAccount],
    submods: {
      gce: { project_id: projectId },
      container: {
        image_digest: imageDigest,
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
  return {
    protocolVersion: 1,
    tokenType: "google-pki",
    audience,
    nonce,
    keyBinding: binding,
    keyBindingHash: bindingHash,
    attestationToken: await jwt(
      {
        alg: "RS256",
        typ: "JWT",
        x5c: [
          trustedChain.leaf.toString("base64"),
          trustedChain.intermediate.toString("base64"),
        ],
      },
      claims,
      mutation,
    ),
  };
}

async function verifyScenario(
  mutation = {},
  root = trustedChain.root,
  allowedImageDigests = [imageDigest],
) {
  installTrustEnvironment(root);
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGESTS =
    allowedImageDigests.join(",");
  process.env.NEXT_PUBLIC_HERD_ATTESTATION_ROOT_FINGERPRINT =
    await fingerprint(root);
  globalThis.fetch = async (url, init) => {
    assert.equal(url, "/api/trust/evaluator-attestation");
    assert.equal(init.method, "POST");
    assert.equal(init.credentials, "include");
    assert.equal(init.cache, "no-store");
    const { nonce } = JSON.parse(init.body);
    const response = await attestationResponse(nonce, mutation);
    return new Response(JSON.stringify(response), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  return attestationModule.attestEvaluatorForPolicy(policy);
}

test("RS256 Google-PKI evaluator attestation is certificate- and release-bound", async (t) => {
  await t.test("valid proof passes", async () => {
    await assert.doesNotReject(verifyScenario());
  });

  await t.test("second exact rollout image passes", async () => {
    await assert.doesNotReject(
      verifyScenario(
        {
          claims(claims) {
            claims.submods.container.image_digest = rolloutImageDigest;
          },
        },
        trustedChain.root,
        [imageDigest, rolloutImageDigest],
      ),
    );
  });

  await t.test("omitted empty container overrides pass", async () => {
    await assert.doesNotReject(
      verifyScenario({
        claims(claims) {
          delete claims.submods.container.env_override;
          delete claims.submods.container.cmd_override;
        },
      }),
    );
  });

  await t.test("expired Herd session requests authentication instead of masking it", async () => {
    installTrustEnvironment(trustedChain.root);
    globalThis.fetch = async () => new Response(
      JSON.stringify({ error: { code: "unauthorized" } }),
      { status: 401, headers: { "content-type": "application/json" } },
    );
    await assert.rejects(
      attestationModule.attestEvaluatorForPolicy(policy),
      (error) =>
        error instanceof attestationModule.EvaluatorAuthenticationError &&
        error.message === "Your session expired. Sign in again to continue.",
    );
  });

  const adversarialClaims = [
    ["wrong nonce", (claims) => { claims.eat_nonce[0] = base64Url(new Uint8Array(32)); }],
    ["wrong image", (claims) => { claims.submods.container.image_digest = `sha256:${"b".repeat(64)}`; }],
    ["restart policy can stop", (claims) => { claims.submods.container.restart_policy = "Never"; }],
    ["wrong project", (claims) => { claims.submods.gce.project_id = "wrong-project"; }],
    ["wrong service account", (claims) => { claims.google_service_accounts = ["wrong@example.com"]; }],
    ["debug enabled", (claims) => { claims.dbgstat = "enabled"; }],
    ["wrong hardware model", (claims) => { claims.hwmodel = "GCP_AMD_SEV"; }],
    ["fractional OEM ID", (claims) => { claims.oemid = 11_129.5; }],
    ["extra attester TCB", (claims) => { claims.attester_tcb = ["INTEL", "UNREVIEWED"]; }],
    ["wrong command override shape", (claims) => { claims.submods.container.cmd_override = {}; }],
    ["non-empty command override", (claims) => { claims.submods.container.cmd_override = ["override"]; }],
    ["wrong environment override shape", (claims) => { claims.submods.container.env_override = []; }],
    ["non-empty environment override", (claims) => { claims.submods.container.env_override = { SECRET: "override" }; }],
    ["extra monitoring mode", (claims) => {
      claims.submods.confidential_space.monitoring_enabled = {
        memory: false,
        disk: true,
      };
    }],
    ["unapproved OS version", (claims) => { claims.swversion = ["999999"]; }],
    ["expired token", (claims) => {
      const now = Math.floor(Date.now() / 1_000);
      claims.iat = now - 600;
      claims.nbf = now - 600;
      claims.exp = now - 60;
    }],
    ["expiry before issuance", (claims) => {
      claims.exp = claims.iat;
    }],
  ];
  for (const [name, mutateClaims] of adversarialClaims) {
    await t.test(name, async () => {
      await assert.rejects(
        verifyScenario({ claims: mutateClaims }),
        attestationModule.EvaluatorAttestationError,
      );
    });
  }

  await t.test("wrong key binding", async () => {
    await assert.rejects(
      verifyScenario({
        binding(binding) {
          binding.keys.policySigning.keyId = "attestation-wrong-policy-v1";
        },
      }),
      attestationModule.EvaluatorAttestationError,
    );
  });
  await t.test("untrusted root", async () => {
    await assert.rejects(
      verifyScenario({}, untrustedChain.root),
      attestationModule.EvaluatorAttestationError,
    );
  });
  await t.test("bad JWT signature", async () => {
    await assert.rejects(
      verifyScenario({ badSignature: true }),
      attestationModule.EvaluatorAttestationError,
    );
  });
});
