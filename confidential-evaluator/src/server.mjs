import http from "node:http";

import { createEvaluatorApp } from "./app.mjs";
import {
  ConfidentialSpaceAttestationProvider,
  ConfidentialSpaceFederatedAccessTokenProvider,
  GoogleKmsBundleDecryptor,
} from "./confidential-space.mjs";
import {
  bindAttestedImageDigest,
  loadDeploymentConfig,
} from "./config.mjs";
import { HttpError } from "./errors.mjs";
import { loadKeyStore } from "./key-bundle.mjs";
import { StatefulTransparencyAuthority } from "./transparency-authority.mjs";
import { FirestoreTransparencyStore } from "./transparency-store.mjs";

// Must match evaluator-service/lib/relay.ts. The encrypted relay envelope is
// deliberately much larger than a direct evaluation request.
const MAXIMUM_HTTP_BODY_BYTES = 437_391;

async function incomingBody(request) {
  if (request.method === "GET" || request.method === "HEAD") return undefined;
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.length;
    if (length > MAXIMUM_HTTP_BODY_BYTES) {
      request.resume();
      throw new HttpError(413, "request_too_large");
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

async function toFetchRequest(request) {
  const body = await incomingBody(request);
  return new Request(new URL(request.url ?? "/", "http://localhost"), {
    method: request.method,
    headers: request.headers,
    ...(body === undefined ? {} : { body }),
  });
}

function writeResponse(nodeResponse, response) {
  nodeResponse.statusCode = response.status;
  for (const [name, value] of response.headers) nodeResponse.setHeader(name, value);
  response.arrayBuffer().then(
    (body) => nodeResponse.end(Buffer.from(body)),
    () => {
      nodeResponse.statusCode = 503;
      nodeResponse.end('{"error":{"code":"service_unavailable"}}');
    },
  );
}

async function start() {
  const deploymentConfig = await loadDeploymentConfig();
  const decryptor = new GoogleKmsBundleDecryptor({
    socketPath: deploymentConfig.attestationSocket,
    workloadIdentityProvider: deploymentConfig.workloadIdentityProvider,
    kmsKeyResource: deploymentConfig.kmsKeyResource,
  });
  const transparencyDecryptor = new GoogleKmsBundleDecryptor({
    socketPath: deploymentConfig.attestationSocket,
    workloadIdentityProvider: deploymentConfig.workloadIdentityProvider,
    kmsKeyResource: deploymentConfig.transparencyKmsKeyResource,
  });
  const keyStore = await loadKeyStore({
    config: deploymentConfig,
    decryptor,
    transparencyDecryptor,
  });
  const config = bindAttestedImageDigest(
    deploymentConfig,
    keyStore.evaluatorConfig.measurement,
  );
  const attestationProvider = new ConfidentialSpaceAttestationProvider({
    socketPath: config.attestationSocket,
  });
  const accessTokenProvider = new ConfidentialSpaceFederatedAccessTokenProvider({
    socketPath: config.attestationSocket,
    workloadIdentityProvider: config.workloadIdentityProvider,
    expectedImageDigest: config.evaluatorMeasurement,
  });
  const transparencyStore = new FirestoreTransparencyStore({
    projectId: config.transparencyStateProjectId,
    databaseId: config.transparencyStateDatabaseId,
    collectionId: config.transparencyStateCollection,
    accessTokenProvider,
  });
  const transparencyAuthority = new StatefulTransparencyAuthority({
    store: transparencyStore,
    keyStore,
  });
  // Do not advertise or accept traffic until the attested WIF principal has
  // demonstrated read access to the durable non-equivocation state.
  await transparencyAuthority.checkReady();
  const app = createEvaluatorApp({
    config,
    keyStore,
    attestationProvider,
    transparencyAuthority,
  });
  const server = http.createServer(async (request, response) => {
    try {
      writeResponse(response, await app(await toFetchRequest(request)));
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 503;
      const code = error instanceof HttpError ? error.code : "service_unavailable";
      response.writeHead(status, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "x-content-type-options": "nosniff",
      });
      response.end(JSON.stringify({ error: { code } }));
    }
  });
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  server.maxRequestsPerSocket = 100;
  server.listen(config.port, "0.0.0.0");
}

start().catch(() => {
  process.stderr.write("confidential evaluator failed closed during startup\n");
  process.exitCode = 1;
});
