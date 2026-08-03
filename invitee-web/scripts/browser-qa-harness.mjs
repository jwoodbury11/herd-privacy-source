import { spawn } from "node:child_process";
import { randomBytes, randomUUID, webcrypto } from "node:crypto";
import { access, readFile, readdir } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { createFetchMock, Miniflare } from "miniflare";
import "reflect-metadata";
import {
  BasicConstraintsExtension,
  KeyUsageFlags,
  KeyUsagesExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from "@peculiar/x509";

const projectRoot = fileURLToPath(new URL("../", import.meta.url));
const serverRoot = path.join(projectRoot, "dist/server");
const migrationDirectory = path.join(projectRoot, "drizzle");
const evaluatorOrigin = "https://herd-browser-qa-evaluator.invalid";
const evaluatorToken =
  "herd_browser_qa_evaluator_token_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const schedulerToken =
  "herd_browser_qa_scheduler_token_0123456789_ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const hostPhoneNumber = "+14155550187";
const qaPhoneNumbers = Array.from(
  { length: 9 },
  (_, index) => `+1415555010${index + 1}`,
);
const eventId = "b7000000-0000-4000-8000-000000000001";
const policySignatureDomain = "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1";
const receiptSignatureDomain = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1";
const logHeadSignatureDomain = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1";
const keyBindingDomain = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1";
const attestationIssuer = "https://confidentialcomputing.googleapis.com";
const attestationAudience = "https://herd-browser-qa.invalid/evaluator-attestation/v1";
const attestationProjectId = "herd-browser-qa-project";
const attestationServiceAccount =
  "evaluator@herd-browser-qa-project.iam.gserviceaccount.com";
const attestationSwVersion = "20260801";

cryptoProvider.set(webcrypto);

class BrowserQaHarnessError extends Error {
  constructor(message) {
    super(message);
    this.name = "BrowserQaHarnessError";
  }
}

function ensure(condition, message) {
  if (!condition) throw new BrowserQaHarnessError(message);
}

function validateNodeVersion() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  ensure(
    major > 22 || (major === 22 && minor >= 13),
    `The browser QA harness requires Node.js 22.13 or newer; found ${process.version}.`,
  );
}

function base64Url(bytes) {
  return Buffer.from(bytes).toString("base64url");
}

function domainSeparated(domain, payload) {
  return Buffer.concat([
    Buffer.from(domain, "utf8"),
    Buffer.from([0]),
    Buffer.from(payload, "utf8"),
  ]);
}

async function p256KeyFixture(id, algorithm, usages) {
  const keyPair = await webcrypto.subtle.generateKey(
    { name: algorithm, namedCurve: "P-256" },
    true,
    usages,
  );
  return {
    id,
    keyPair,
    publicKey: base64Url(
      await webcrypto.subtle.exportKey("raw", keyPair.publicKey),
    ),
  };
}

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

async function rsaKeyPair() {
  return webcrypto.subtle.generateKey(rsaAlgorithm, true, ["sign", "verify"]);
}

async function createAttestationFixture(release) {
  const now = Date.now();
  const notBefore = new Date(now - 86_400_000);
  const notAfter = new Date(now + 30 * 86_400_000);
  const rootKeys = await rsaKeyPair();
  const root = await X509CertificateGenerator.createSelfSigned({
    serialNumber: "01",
    name: "CN=Herd Browser QA Root",
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
  const intermediateKeys = await rsaKeyPair();
  const intermediate = await X509CertificateGenerator.create({
    serialNumber: "02",
    subject: "CN=Herd Browser QA Intermediate",
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
  const leafKeys = await rsaKeyPair();
  const leaf = await X509CertificateGenerator.create({
    serialNumber: "03",
    subject: "CN=Herd Browser QA Attestation Leaf",
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
  const rootFingerprint = Buffer.from(
    await webcrypto.subtle.digest("SHA-256", root.rawData),
  ).toString("hex");
  return {
    audience: attestationAudience,
    projectId: attestationProjectId,
    serviceAccount: attestationServiceAccount,
    imageDigest: release.measurement,
    swVersion: attestationSwVersion,
    rootCertificate: root.toString("pem"),
    rootFingerprint,
    leafCertificate: leaf.toString("base64"),
    intermediateCertificate: intermediate.toString("base64"),
    leafPrivateKey: leafKeys.privateKey,
  };
}

export async function createLocalQaRelease() {
  const nonce = randomUUID();
  const responseDecryption = await p256KeyFixture(
    `browser-qa-response-${nonce}`,
    "ECDH",
    ["deriveBits"],
  );
  const evaluationResultSigning = await p256KeyFixture(
    `browser-qa-result-${nonce}`,
    "ECDSA",
    ["sign", "verify"],
  );
  const policySigning = await p256KeyFixture(
    `browser-qa-policy-${nonce}`,
    "ECDSA",
    ["sign", "verify"],
  );
  const transparencySigning = await p256KeyFixture(
    `browser-qa-transparency-${nonce}`,
    "ECDSA",
    ["sign", "verify"],
  );
  const release = {
    id: `browser-qa-release-${nonce}`,
    measurement: `sha256:${"a".repeat(64)}`,
    responseDecryption,
    evaluationResultSigning,
    policySigning,
    transparencySigning,
  };
  release.attestation = await createAttestationFixture(release);
  return release;
}

function sanitizedBuildEnvironment(release) {
  const environment = {};
  for (const [name, value] of Object.entries(process.env)) {
    if (
      /^(?:HERD_|NEXT_PUBLIC_HERD_|TWILIO_|CLOUDFLARE_|CF_)/u.test(name)
    ) {
      continue;
    }
    environment[name] = value;
  }
  Object.assign(environment, {
    HERD_DEPLOYMENT_PROFILE: "test",
    HERD_TEST_BYPASS_ENABLED: "false",
    HERD_ALLOW_INSECURE_QA_BYPASS: "false",
    NEXT_PUBLIC_HERD_RELEASE_ID: release.id,
    NEXT_PUBLIC_HERD_EVALUATOR_KEY_ID: release.responseDecryption.id,
    NEXT_PUBLIC_HERD_EVALUATOR_PUBLIC_KEY:
      release.responseDecryption.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_KEY_ID:
      release.evaluationResultSigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY:
      release.evaluationResultSigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_KEY_ID:
      release.policySigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY:
      release.policySigning.publicKey,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID:
      release.transparencySigning.id,
    NEXT_PUBLIC_HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      release.transparencySigning.publicKey,
    NEXT_PUBLIC_HERD_ATTESTATION_AUDIENCE: release.attestation.audience,
    NEXT_PUBLIC_HERD_ATTESTATION_PROJECT_ID: release.attestation.projectId,
    NEXT_PUBLIC_HERD_ATTESTATION_SERVICE_ACCOUNT:
      release.attestation.serviceAccount,
    NEXT_PUBLIC_HERD_ATTESTATION_IMAGE_DIGEST:
      release.attestation.imageDigest,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_FINGERPRINT:
      release.attestation.rootFingerprint,
    NEXT_PUBLIC_HERD_ATTESTATION_ROOT_CERTIFICATE:
      release.attestation.rootCertificate,
    NEXT_PUBLIC_HERD_ATTESTATION_SWVERSIONS: release.attestation.swVersion,
    NEXT_PUBLIC_HERD_ATTESTATION_MAX_AGE_SECONDS: "300",
    WRANGLER_SEND_METRICS: "false",
  });
  return environment;
}

async function runBuild(release) {
  await new Promise((resolve, reject) => {
    const child = spawn(
      process.platform === "win32" ? "npm.cmd" : "npm",
      ["run", "build"],
      {
        cwd: projectRoot,
        env: sanitizedBuildEnvironment(release),
        stdio: "inherit",
      },
    );
    child.once("error", reject);
    child.once("exit", (code, signal) => {
      if (code === 0) resolve();
      else {
        reject(
          new BrowserQaHarnessError(
            `The local Worker build failed${signal ? ` (${signal})` : ""}.`,
          ),
        );
      }
    });
  });
}

async function javascriptModules(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) files.push(...(await javascriptModules(entryPath)));
    else if (entry.name.endsWith(".js")) files.push(entryPath);
  }
  return files;
}

async function applyMigrations(database) {
  const migrationFiles = (await readdir(migrationDirectory))
    .filter((name) => /^\d+_.+\.sql$/u.test(name))
    .sort();
  ensure(migrationFiles.length > 0, "No D1 migrations were found.");
  for (const migrationFile of migrationFiles) {
    const migration = await readFile(
      path.join(migrationDirectory, migrationFile),
      "utf8",
    );
    for (const chunk of migration.split("--> statement-breakpoint")) {
      const statement = chunk.trim();
      if (statement) await database.exec(statement.replace(/\s+/gu, " "));
    }
  }
  return migrationFiles.length;
}

async function signatureFor(keyPair, domain, payload) {
  return base64Url(
    await webcrypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      keyPair.privateKey,
      domainSeparated(domain, payload),
    ),
  );
}

async function payloadHash(payload) {
  return base64Url(
    await webcrypto.subtle.digest("SHA-256", Buffer.from(payload, "utf8")),
  );
}

function localQaKeyBinding(release) {
  return {
    protocolVersion: 1,
    releaseId: release.id,
    keys: {
      responseDecryption: {
        keyId: release.responseDecryption.id,
        algorithm: "ECDH_P256",
        publicKey: release.responseDecryption.publicKey,
      },
      evaluationResultSigning: {
        keyId: release.evaluationResultSigning.id,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: release.evaluationResultSigning.publicKey,
      },
      policySigning: {
        keyId: release.policySigning.id,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: release.policySigning.publicKey,
      },
      transparencySigning: {
        keyId: release.transparencySigning.id,
        algorithm: "ECDSA_P256_SHA256",
        publicKey: release.transparencySigning.publicKey,
      },
    },
  };
}

async function localAttestationResponse(release, nonce) {
  const keyBinding = localQaKeyBinding(release);
  const keyBindingHash = await payloadHash(
    `${keyBindingDomain}\0${JSON.stringify(keyBinding)}`,
  );
  const now = Math.floor(Date.now() / 1_000);
  const claims = {
    iss: attestationIssuer,
    aud: release.attestation.audience,
    iat: now,
    nbf: now - 1,
    exp: now + 300,
    eat_nonce: [nonce, keyBindingHash],
    secboot: true,
    dbgstat: "disabled-since-boot",
    hwmodel: "GCP_INTEL_TDX",
    swname: "CONFIDENTIAL_SPACE",
    oemid: 11129,
    attester_tcb: ["INTEL"],
    swversion: [release.attestation.swVersion],
    google_service_accounts: [release.attestation.serviceAccount],
    submods: {
      gce: { project_id: release.attestation.projectId },
      container: {
        image_digest: release.attestation.imageDigest,
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
  const header = {
    alg: "RS256",
    typ: "JWT",
    x5c: [
      release.attestation.leafCertificate,
      release.attestation.intermediateCertificate,
    ],
  };
  const headerSegment = base64Url(Buffer.from(JSON.stringify(header), "utf8"));
  const claimsSegment = base64Url(Buffer.from(JSON.stringify(claims), "utf8"));
  const signingInput = `${headerSegment}.${claimsSegment}`;
  const signature = await webcrypto.subtle.sign(
    { name: "RSASSA-PKCS1-v1_5" },
    release.attestation.leafPrivateKey,
    Buffer.from(signingInput, "utf8"),
  );
  return {
    protocolVersion: 1,
    tokenType: "google-pki",
    audience: release.attestation.audience,
    nonce,
    keyBinding,
    keyBindingHash,
    attestationToken: `${signingInput}.${base64Url(signature)}`,
  };
}

function installLocalSigner(fetchMock, release) {
  fetchMock.disableNetConnect();
  const evaluator = fetchMock.get(evaluatorOrigin);
  const appendResponses = new Map();
  let lastLogIndex = 0;
  let lastEntryHash = base64Url(new Uint8Array(32));
  const appendCertification = async (canonicalReceiptPayload) => {
    const receipt = JSON.parse(canonicalReceiptPayload);
    ensure(
      JSON.stringify(receipt) === canonicalReceiptPayload &&
        receipt.protocolVersion === 1 &&
        receipt.logId === "herd-response-log-v1" &&
        receipt.logIndex === lastLogIndex + 1 &&
        receipt.previousEntryHash === lastEntryHash &&
        receipt.signingKeyId === release.transparencySigning.id,
      "The Worker sent an invalid transparency append.",
    );
    lastLogIndex = receipt.logIndex;
    lastEntryHash = receipt.entryHash;
    const canonicalHeadPayload = JSON.stringify({
      protocolVersion: 1,
      logId: receipt.logId,
      treeSize: receipt.logIndex,
      headEntryHash: receipt.entryHash,
      generatedAt: new Date().toISOString(),
      signingKeyId: release.transparencySigning.id,
    });
    const [receiptSignature, headSignature] = await Promise.all([
      signatureFor(
        release.transparencySigning.keyPair,
        receiptSignatureDomain,
        canonicalReceiptPayload,
      ),
      signatureFor(
        release.transparencySigning.keyPair,
        logHeadSignatureDomain,
        canonicalHeadPayload,
      ),
    ]);
    return JSON.stringify({
      protocolVersion: 1,
      kind: "append",
      signingKeyId: release.transparencySigning.id,
      receipt: {
        domain: receiptSignatureDomain,
        payloadHash: await payloadHash(canonicalReceiptPayload),
        signature: receiptSignature,
      },
      logHead: {
        canonicalPayload: canonicalHeadPayload,
        domain: logHeadSignatureDomain,
        payloadHash: await payloadHash(canonicalHeadPayload),
        signature: headSignature,
      },
    });
  };
  evaluator
    .intercept({ method: "POST", path: "/api/v1/sign/policy" })
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        ensure(
          headers.get("authorization") === `Bearer ${evaluatorToken}`,
          "The Worker sent an invalid local signer credential.",
        );
        const body = JSON.parse(await new Response(request.body).text());
        ensure(
          body.protocolVersion === 1 &&
            typeof body.canonicalDocument === "string",
          "The Worker sent an invalid policy-signing request.",
        );
        return JSON.stringify({
          protocolVersion: 1,
          domain: policySignatureDomain,
          signingKeyId: release.policySigning.id,
          payloadHash: await payloadHash(body.canonicalDocument),
          signature: await signatureFor(
            release.policySigning.keyPair,
            policySignatureDomain,
            body.canonicalDocument,
          ),
        });
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
  evaluator
    .intercept({ method: "POST", path: "/api/v1/sign/transparency" })
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        ensure(
          headers.get("authorization") === `Bearer ${evaluatorToken}`,
          "The Worker sent an invalid local signer credential.",
        );
        const body = JSON.parse(await new Response(request.body).text());
        ensure(
          body.protocolVersion === 1 &&
            body.kind === "append" &&
            typeof body.canonicalReceiptPayload === "string",
          "The Worker sent an invalid transparency-signing request.",
        );
        let certification = appendResponses.get(body.canonicalReceiptPayload);
        if (!certification) {
          certification = appendCertification(body.canonicalReceiptPayload);
          appendResponses.set(body.canonicalReceiptPayload, certification);
        }
        return certification;
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
  evaluator
    .intercept({ method: "POST", path: "/api/v1/attestation" })
    .reply(
      200,
      async (request) => {
        const headers = new Headers(request.headers);
        ensure(
          headers.get("authorization") === `Bearer ${evaluatorToken}`,
          "The Worker sent an invalid local attestation credential.",
        );
        const body = JSON.parse(await new Response(request.body).text());
        ensure(
          body.protocolVersion === 1 &&
            typeof body.nonce === "string" &&
            Buffer.from(body.nonce, "base64url").length === 32 &&
            base64Url(Buffer.from(body.nonce, "base64url")) === body.nonce,
          "The Worker sent an invalid local attestation nonce.",
        );
        return JSON.stringify(
          await localAttestationResponse(release, body.nonce),
        );
      },
      { headers: { "content-type": "application/json" } },
    )
    .persist();
}

function workerBindings(release) {
  return {
    HERD_DEPLOYMENT_PROFILE: "test",
    HERD_AUTH_PEPPER:
      `browser-qa-only-${randomBytes(48).toString("base64url")}`,
    HERD_TEST_BYPASS_ENABLED: "true",
    HERD_ALLOW_INSECURE_QA_BYPASS: "true",
    HERD_QA_BYPASS_GENERATION: `browser-qa-${randomUUID()}`,
    HERD_TEST_PHONE_E164: hostPhoneNumber,
    HERD_TEST_HOST_PHONE_E164: "+14155550111",
    HERD_PHONE_REQUESTS_PER_HOUR: "20",
    HERD_IP_REQUESTS_PER_HOUR: "200",
    HERD_RELEASE_ID: release.id,
    HERD_EVALUATOR_KEY_ID: release.responseDecryption.id,
    HERD_EVALUATOR_PUBLIC_KEY: release.responseDecryption.publicKey,
    HERD_EVALUATOR_RESULT_SIGNING_KEY_ID:
      release.evaluationResultSigning.id,
    HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY:
      release.evaluationResultSigning.publicKey,
    HERD_EVALUATOR_POLICY_SIGNING_KEY_ID: release.policySigning.id,
    HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY: release.policySigning.publicKey,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID:
      release.transparencySigning.id,
    HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY:
      release.transparencySigning.publicKey,
    HERD_EVALUATOR_MEASUREMENT: release.measurement,
    HERD_EVALUATOR_TRANSPORT: "client_relay",
    HERD_EVALUATOR_URL: `${evaluatorOrigin}/api/v1/relay/`,
    HERD_ATTESTATION_URL: `${evaluatorOrigin}/api/v1/attestation`,
    HERD_EVALUATOR_TOKEN: evaluatorToken,
    HERD_SCHEDULER_TOKEN: schedulerToken,
  };
}

async function apiJson(baseUrl, pathname, options = {}) {
  const method = options.method ?? "GET";
  const headers = new Headers(options.headers);
  if (options.accessToken) {
    headers.set("authorization", `Bearer ${options.accessToken}`);
  }
  if (options.body !== undefined) {
    headers.set("content-type", "application/json");
  }
  if (method !== "GET" && method !== "HEAD") {
    headers.set("origin", baseUrl.origin);
  }
  const response = await fetch(new URL(pathname, baseUrl), {
    method,
    headers,
    redirect: "manual",
    ...(options.body === undefined
      ? {}
      : { body: JSON.stringify(options.body) }),
  });
  const text = await response.text();
  let body = null;
  if (text) {
    try {
      body = JSON.parse(text);
    } catch {
      body = text;
    }
  }
  return { response, body };
}

async function requireStatus(result, status, context) {
  ensure(
    result.response.status === status,
    `${context} returned ${result.response.status}: ${JSON.stringify(result.body)}`,
  );
  return result.body;
}

async function authenticate(baseUrl, phoneNumber) {
  const result = await apiJson(baseUrl, "/api/auth/request-code", {
    method: "POST",
    body: { phoneNumber },
  });
  const session = await requireStatus(result, 200, `Authentication for ${phoneNumber}`);
  ensure(
    typeof session?.accessToken === "string" && session.accessToken.length >= 40,
    `Authentication for ${phoneNumber} did not return a session.`,
  );
  return session;
}

async function updateProfile(baseUrl, session, name) {
  const result = await apiJson(baseUrl, "/api/me", {
    method: "PATCH",
    accessToken: session.accessToken,
    body: { name, address: "Local browser QA only" },
  });
  await requireStatus(result, 200, `Profile update for ${name}`);
}

function qaInvitees() {
  return qaPhoneNumbers.map((phoneNumber, index) => ({
    id: `b7100000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
    displayName: `QA account ${index + 1}`,
    phoneNumber,
  }));
}

async function seedBrowserScenario(baseUrl, database) {
  const host = await authenticate(baseUrl, hostPhoneNumber);
  await updateProfile(baseUrl, host, "Local QA Host");
  const aliases = [];
  for (let alias = 1; alias <= 9; alias += 1) {
    const session = await authenticate(baseUrl, String(alias));
    await updateProfile(baseUrl, session, `QA account ${alias}`);
    aliases.push(session);
  }

  const now = Date.now();
  const invitees = qaInvitees();
  const eventPayload = {
    id: eventId,
    title: "Local QA reply composer",
    eventDate: new Date(now + 14 * 24 * 60 * 60 * 1_000).toISOString(),
    endDate: new Date(now + 14 * 24 * 60 * 60 * 1_000 + 3_600_000)
      .toISOString(),
    hostName: "Local QA Host",
    locationName: "Herd browser QA",
    locationAddress: "Local test data — never sent",
    invitees,
    minimumParticipants: 4,
    requiredGroups: [
      {
        id: "b7200000-0000-4000-8000-000000000001",
        memberIDs: [invitees[1].id, invitees[2].id],
      },
    ],
    rsvpDeadline: new Date(now + 7 * 24 * 60 * 60 * 1_000).toISOString(),
    eventDescription:
      "A disposable local scenario for anonymous, account-bound, event-detail, and reply-composer QA.",
    createdAt: new Date(now).toISOString(),
    invitationsSent: true,
  };
  const created = await apiJson(baseUrl, `/api/events/${eventId}`, {
    method: "PUT",
    accessToken: host.accessToken,
    body: eventPayload,
  });
  const createdBody = await requireStatus(created, 200, "Sent event creation");
  ensure(
    createdBody?.event?.privateResponsePolicy?.policySignature,
    "The local event policy was not signed.",
  );

  const inviteViews = [];
  for (const [index, session] of aliases.entries()) {
    const listing = await apiJson(baseUrl, "/api/events", {
      accessToken: session.accessToken,
    });
    const listingBody = await requireStatus(
      listing,
      200,
      `Event listing for alias ${index + 1}`,
    );
    const event = listingBody?.events?.find((candidate) => candidate.id === eventId);
    ensure(event?.inviteToken, `Alias ${index + 1} has no private invite link.`);
    inviteViews.push(event);
  }
  ensure(
    new Set(inviteViews.map((event) => event.inviteToken)).size === 9,
    "The aliases did not receive nine distinct invite links.",
  );

  const invitePaths = inviteViews.map(
    (event) => `/invite/${encodeURIComponent(event.inviteToken)}`,
  );
  const inviteApiPaths = inviteViews.map(
    (event) => `/api/invites/${encodeURIComponent(event.inviteToken)}`,
  );
  const [invitePath] = invitePaths;
  const [inviteApiPath] = inviteApiPaths;
  const anonymous = await apiJson(baseUrl, inviteApiPath);
  const anonymousBody = await requireStatus(
    anonymous,
    200,
    "Anonymous invitation preview",
  );
  ensure(
    anonymousBody?.invitationPreview?.requiresAuthentication === true &&
      !Object.hasOwn(anonymousBody, "event"),
    "The anonymous invitation exposed authenticated event data.",
  );

  const correct = await apiJson(baseUrl, inviteApiPath, {
    accessToken: aliases[0].accessToken,
  });
  const correctBody = await requireStatus(
    correct,
    200,
    "Correct-account invitation access",
  );
  ensure(
    correctBody?.event?.id === eventId &&
      correctBody?.inviteMetadata?.canRespond === true &&
      correctBody?.inviteMetadata?.hasResponse === false,
    "The correct account did not receive the reply-composer projection.",
  );

  const wrong = await apiJson(baseUrl, inviteApiPath, {
    accessToken: aliases[1].accessToken,
  });
  await requireStatus(wrong, 403, "Wrong-account invitation access");
  ensure(
    wrong.body?.error?.code === "invite_for_different_account",
    "Wrong-account access did not fail with the account-binding error.",
  );

  const counts = await database
    .prepare(
      `SELECT
         (SELECT COUNT(*) FROM users) AS userCount,
         (SELECT COUNT(*) FROM users
          WHERE phone_number = ? OR phone_number LIKE '+1415555010_') AS qaAccountCount,
         (SELECT COUNT(*) FROM events WHERE id = ?) AS eventCount,
         (SELECT COUNT(*) FROM invitees WHERE event_id = ?) AS inviteeCount,
         (SELECT COUNT(*) FROM invitation_deliveries
          WHERE event_id = ? AND status = 'suppressed') AS suppressedCount,
         (SELECT COUNT(*) FROM event_policies
          WHERE event_id = ? AND policy_signature IS NOT NULL) AS signedPolicyCount`,
    )
    .bind(hostPhoneNumber, eventId, eventId, eventId, eventId)
    .first();
  ensure(
    counts?.qaAccountCount === 10 &&
      counts.eventCount === 1 &&
      counts.inviteeCount === 9 &&
      counts.suppressedCount === 9 &&
      counts.signedPolicyCount === 1,
    `The local seed counts are invalid: ${JSON.stringify(counts)}`,
  );

  // Seed sessions and rate-limit rows are not part of the browser scenario.
  // Removing them lets a human sign in immediately with aliases 1–9.
  await database.batch([
    database.prepare("DELETE FROM sessions"),
    database.prepare("DELETE FROM challenges"),
    database.prepare("DELETE FROM auth_phone_rate_limits"),
    database.prepare("DELETE FROM auth_ip_rate_limits"),
  ]);

  return {
    eventId,
    invitePath,
    inviteApiPath,
    invitePaths,
    inviteApiPaths,
    title: eventPayload.title,
    counts,
  };
}

export async function startBrowserQaHarness(options = {}) {
  validateNodeVersion();
  const release = options.release ?? await createLocalQaRelease();
  if (options.build !== false) await runBuild(release);
  await access(path.join(serverRoot, "index.js")).catch(() => {
    throw new BrowserQaHarnessError(
      "The built Worker is missing. Run `npm run build` or launch `npm run qa:browser`.",
    );
  });

  const fetchMock = createFetchMock();
  installLocalSigner(fetchMock, release);
  const modulePaths = await javascriptModules(serverRoot);
  const entryPath = path.join(serverRoot, "index.js");
  modulePaths.sort((left, right) => {
    if (left === entryPath) return -1;
    if (right === entryPath) return 1;
    return left.localeCompare(right);
  });
  const miniflare = new Miniflare({
    modules: modulePaths.map((modulePath) => ({
      type: "ESModule",
      path: modulePath,
    })),
    modulesRoot: serverRoot,
    compatibilityDate: "2026-05-15",
    compatibilityFlags: ["nodejs_compat"],
    host: options.host ?? "127.0.0.1",
    port: options.port ?? 0,
    d1Databases: {
      DB: `herd-browser-qa-${process.pid}-${Date.now()}-${randomUUID()}`,
    },
    d1Persist: false,
    assets: {
      directory: path.join(projectRoot, "dist/client"),
      routerConfig: { has_user_worker: true },
    },
    fetchMock,
    bindings: workerBindings(release),
  });

  try {
    const readyUrl = await miniflare.ready;
    const database = await miniflare.getD1Database("DB");
    const migrationCount = await applyMigrations(database);
    const scenario = await seedBrowserScenario(readyUrl, database);
    const browserUrl = new URL(scenario.invitePath, readyUrl);
    return {
      miniflare,
      database,
      release,
      migrationCount,
      scenario,
      baseUrl: readyUrl,
      browserUrl,
      stop: () => miniflare.dispose(),
    };
  } catch (error) {
    await miniflare.dispose();
    throw error;
  }
}

function parsePort(argumentsList) {
  if (argumentsList.length === 0) return 0;
  ensure(
    argumentsList.length === 2 && argumentsList[0] === "--port",
    "Usage: npm run qa:browser -- [--port 8788]",
  );
  ensure(/^\d+$/u.test(argumentsList[1]), "The QA port must be a whole number.");
  const port = Number(argumentsList[1]);
  ensure(
    Number.isSafeInteger(port) && port >= 1 && port <= 65_535,
    "The QA port must be between 1 and 65535.",
  );
  return port;
}

async function waitForInterruption() {
  await new Promise((resolve) => {
    process.once("SIGINT", resolve);
    process.once("SIGTERM", resolve);
  });
}

async function main() {
  const port = parsePort(process.argv.slice(2));
  console.log("Building the current Worker with ephemeral browser-QA public pins…");
  const harness = await startBrowserQaHarness({ port });
  console.log(`\nLocal QA URL: ${harness.browserUrl.href}`);
  console.log("\nUse the same URL for each check:");
  console.log("  • Signed out: anonymous invitation landing");
  console.log("  • Enter 1: correct-account event list, detail, and reply composer");
  console.log("  • Sign out, reopen it, and enter 2: wrong-account denial");
  console.log("  • Aliases 1–9 are available; no text messages are sent");
  console.log(
    "  • Alias 1 can submit through the normal attestation, encryption, signed-receipt, and public-log checks",
  );
  console.log("  • All keys, certificates, sessions, and data are ephemeral and local to this process");
  console.log("\nPress Ctrl-C to stop and discard the in-memory database.");
  await waitForInterruption();
  await harness.stop();
}

const isMain = process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  main().catch((error) => {
    console.error(
      error instanceof Error ? error.message : "The browser QA harness failed.",
    );
    process.exitCode = 1;
  });
}
