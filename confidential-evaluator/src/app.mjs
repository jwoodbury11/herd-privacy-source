import {
  handleRelayOptionsRequest,
  handleRelayRequest,
} from "../vendor/relay-core.mjs";

import {
  MAXIMUM_ATTESTATION_BYTES,
  MAXIMUM_CANONICAL_PAYLOAD_BYTES,
  POLICY_DESCRIPTOR_CAPABILITY,
  PROTOCOL_VERSION,
} from "./constants.mjs";
import {
  constantTimeTextEqual,
  decodeBase64Url,
  encodeBase64Url,
  exactKeys,
  fatalDecoder,
} from "./encoding.mjs";
import {
  forbidden,
  HttpError,
  invalidRequest,
  unauthorized,
} from "./errors.mjs";
import { policyAuthorityRecord, signPolicyDescriptor } from "./signing.mjs";

function responseHeaders(extra = {}) {
  return {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
    ...extra,
  };
}

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: responseHeaders(headers),
  });
}

function errorResponse(error) {
  if (
    error.status === 409 &&
    error.code === "transparency_late_missing_entry" &&
    error.details &&
    typeof error.details === "object" &&
    !Array.isArray(error.details) &&
    error.details.proof &&
    typeof error.details.proof === "object" &&
    !Array.isArray(error.details.proof) &&
    Object.keys(error.details).length === 1 &&
    JSON.stringify(Object.keys(error.details.proof).sort()) ===
      JSON.stringify([
        "canonicalPayload",
        "domain",
        "payloadHash",
        "signature",
        "signingKeyId",
      ].sort()) &&
    Object.values(error.details.proof).every(
      (value) => typeof value === "string" && value.length > 0,
    )
  ) {
    return jsonResponse({
      error: {
        code: error.code,
        proof: error.details.proof,
      },
    }, error.status);
  }
  return jsonResponse({ error: { code: error.code } }, error.status);
}

function checkOrigin(request, config) {
  const origin = request.headers.get("origin");
  if (origin === null) return {};
  if (config.allowedOrigin === null || origin !== config.allowedOrigin) forbidden();
  return {
    "access-control-allow-origin": origin,
    vary: "Origin",
    "access-control-expose-headers": "Herd-Evaluation-Proof",
  };
}

function authenticate(request, keyStore) {
  const expected = `Bearer ${keyStore.requestAuthenticationToken}`;
  const actual = request.headers.get("authorization") ?? "";
  if (!constantTimeTextEqual(actual, expected)) unauthorized();
}

async function jsonBody(request, maximumBytes) {
  const mediaType = (request.headers.get("content-type") ?? "")
    .split(";", 1)[0]
    .trim()
    .toLowerCase();
  if (mediaType !== "application/json") invalidRequest();
  const contentLength = request.headers.get("content-length");
  if (contentLength !== null) {
    const length = Number(contentLength);
    if (!Number.isInteger(length) || length < 1 || length > maximumBytes) {
      throw new HttpError(length > maximumBytes ? 413 : 400, length > maximumBytes ? "request_too_large" : "invalid_request");
    }
  }
  const bytes = new Uint8Array(await request.arrayBuffer());
  if (bytes.length === 0) invalidRequest();
  if (bytes.length > maximumBytes) throw new HttpError(413, "request_too_large");
  try {
    return JSON.parse(fatalDecoder.decode(bytes));
  } catch {
    invalidRequest();
  }
}

function preflight(request, config) {
  const cors = checkOrigin(request, config);
  if (request.headers.get("access-control-request-method") !== "POST") {
    forbidden();
  }
  const requestedHeaders = (request.headers.get("access-control-request-headers") ?? "")
    .toLowerCase()
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const allowed = new Set(["authorization", "content-type", "cache-control", "pragma"]);
  if (requestedHeaders.some((header) => !allowed.has(header))) forbidden();
  return new Response(null, {
    status: 204,
    headers: {
      ...cors,
      "access-control-allow-methods": "POST",
      "access-control-allow-headers": [...allowed].join(", "),
      "access-control-max-age": "600",
      "cache-control": "no-store",
    },
  });
}

function isRelayPath(pathname) {
  return pathname === "/api/v1/relay" || pathname === "/api/v1/relay/";
}

function isBackendSigningPath(pathname) {
  return (
    pathname === "/api/v1/sign/policy" ||
    pathname === "/api/v1/sign/transparency"
  );
}

function requireServerRequest(request) {
  if (request.headers.has("origin")) forbidden();
}

export function createEvaluatorApp({
  config,
  keyStore,
  attestationProvider,
  transparencyAuthority,
  clock = () => new Date(),
}) {
  if (!config || !keyStore || !attestationProvider || !transparencyAuthority) {
    throw new TypeError("evaluator app dependencies are required");
  }
  return async function handle(request) {
    try {
      const url = new URL(request.url);
      if (isRelayPath(url.pathname)) {
        if (request.method === "OPTIONS") {
          return handleRelayOptionsRequest(request, keyStore.relayBindings);
        }
        if (request.method === "POST") {
          return handleRelayRequest(
            request,
            keyStore.relayBindings,
            clock(),
            (claim) => transparencyAuthority.consumeCanonicalBatch(claim),
            keyStore.evaluatorConfig,
            {
              keyId: keyStore.keys.evaluationResultSigning.keyId,
              privateKey: keyStore.keys.evaluationResultSigning.privateKey,
            },
          );
        }
      }
      if (request.method === "OPTIONS" && isBackendSigningPath(url.pathname)) {
        forbidden();
      }
      if (request.method === "OPTIONS") return preflight(request, config);
      const cors = checkOrigin(request, config);
      if (
        request.method === "GET" &&
        (url.pathname === "/healthz" || url.pathname === "/readyz")
      ) {
        if (url.pathname === "/readyz") {
          await transparencyAuthority.checkReady();
        }
        return jsonResponse(
          {
            status: "ok",
            protocolVersion: PROTOCOL_VERSION,
            capabilities: [POLICY_DESCRIPTOR_CAPABILITY],
            keyBinding: keyStore.metadata,
            keyBindingHash: keyStore.keyBindingHash,
          },
          200,
          cors,
        );
      }
      if (request.method !== "POST") {
        return jsonResponse({ error: { code: "not_found" } }, 404, cors);
      }
      if (url.pathname === "/api/v1/attestation") {
        const input = exactKeys(
          await jsonBody(request, MAXIMUM_ATTESTATION_BYTES),
          ["protocolVersion", "nonce"],
        );
        if (input.protocolVersion !== PROTOCOL_VERSION) invalidRequest();
        const nonce = encodeBase64Url(decodeBase64Url(input.nonce, 32));
        const attestationToken = await attestationProvider.attest({
          audience: config.attestationAudience,
          nonces: [nonce, keyStore.keyBindingHash],
        });
        if (typeof attestationToken !== "string" || attestationToken.length > 64 * 1024) {
          throw new HttpError(503, "service_unavailable");
        }
        return jsonResponse(
          {
            protocolVersion: PROTOCOL_VERSION,
            tokenType: "google-pki",
            audience: config.attestationAudience,
            nonce,
            keyBinding: keyStore.metadata,
            keyBindingHash: keyStore.keyBindingHash,
            attestationToken,
          },
          200,
          cors,
        );
      }
      authenticate(request, keyStore);
      if (isBackendSigningPath(url.pathname)) requireServerRequest(request);
      if (url.pathname === "/api/v1/sign/policy") {
        const input = exactKeys(
          await jsonBody(request, MAXIMUM_CANONICAL_PAYLOAD_BYTES + 1024),
          ["protocolVersion", "canonicalDocument"],
        );
        if (input.protocolVersion !== PROTOCOL_VERSION) invalidRequest();
        const signingInput = {
          canonicalDocument: input.canonicalDocument,
          config,
          keyStore,
        };
        const proof = await signPolicyDescriptor(signingInput);
        await transparencyAuthority.freezePolicy(
          policyAuthorityRecord(signingInput),
        );
        return jsonResponse(proof, 200, cors);
      }
      if (url.pathname === "/api/v1/sign/transparency") {
        const input = exactKeys(
          await jsonBody(request, MAXIMUM_CANONICAL_PAYLOAD_BYTES + 1024),
          ["protocolVersion", "kind", "canonicalReceiptPayload"],
        );
        if (input.protocolVersion !== PROTOCOL_VERSION || input.kind !== "append") {
          invalidRequest();
        }
        return jsonResponse(
          await transparencyAuthority.append(input.canonicalReceiptPayload),
          200,
          cors,
        );
      }
      return jsonResponse({ error: { code: "not_found" } }, 404, cors);
    } catch (error) {
      if (error instanceof HttpError) {
        return errorResponse(error);
      }
      return errorResponse(new HttpError(503, "service_unavailable"));
    }
  };
}
