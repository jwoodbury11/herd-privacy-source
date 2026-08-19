# Herd confidential evaluator service

This is Herd's isolated, stateless HTTP boundary for resolving encrypted RSVP
envelopes. The ordinary Herd web backend never receives the evaluator private
key and never sees decrypted response conditions.

The service is a migration-free Vinext/Cloudflare Worker application. Its only
state is release configuration held in runtime secrets. It intentionally emits
no event logs, plaintext diagnostics, condition traces, or per-invitee failure
details.

## HTTP contract

Configure the Herd backend's `HERD_EVALUATOR_URL` as this service's complete
`POST /api/v1/evaluate` URL. Both services share a high-entropy
`HERD_EVALUATOR_TOKEN`; the backend sends it as:

```http
Authorization: Bearer <token>
Content-Type: application/json
```

The request has exactly this shape:

```json
{
  "protocolVersion": 1,
  "eventId": "<lowercase UUID>",
  "policy": "<full frozen PrivateResponsePolicyV1 object>",
  "batchHash": "<SHA-256 base64url commitment>",
  "slots": [
    {
      "inviteeId": "<lowercase UUID>",
      "envelopeHash": "<SHA-256 base64url hash or null>",
      "envelope": "<normalized v1 envelope or null>"
    }
  ]
}
```

There is exactly one slot per frozen-policy member in lexicographic invitee ID
order. A missing response is represented only by a `null` hash and `null`
envelope. For a response slot, `envelopeHash` is SHA-256 base64url of the UTF-8
bytes of `JSON.stringify(normalizedEnvelope)`.

`batchHash` is SHA-256 base64url of the UTF-8 bytes of:

```js
JSON.stringify({
  protocolVersion: 1,
  eventId,
  policyHash: policy.policyHash,
  slots: slots.map(({ inviteeId, envelopeHash }) => ({ inviteeId, envelopeHash })),
})
```

A failed resolution returns exactly:

```json
{
  "protocolVersion": 1,
  "eventId": "<event UUID>",
  "policyHash": "<policy hash>",
  "batchHash": "<batch hash>",
  "evaluatorKeyId": "<release key ID>",
  "status": "not_confirmed"
}
```

A confirmed resolution adds only `attendingMemberIds`, ordered as `host`
followed by attending invitee IDs in frozen member order. No other success
fields are returned.

## Opaque client relay contract

`POST /api/v1/relay` lets the Herd backend route an evaluation through an
untrusted browser or native client when the backend cannot directly reach this
service. The client receives only a fixed-size encrypted request and a
short-lived capability MAC. It never receives `HERD_EVALUATOR_TOKEN`, the
evaluation plaintext, either evaluator private key, or an unsigned result.

The relay request has exactly these fields. JSON object ordering and whitespace
are transport-independent; the evaluator normalizes the values in the order
shown before hashing or authenticating them.

```json
{
  "protocolVersion": 1,
  "cipherSuite": "P256_HKDF_SHA256_AES256_GCM",
  "evaluatorKeyId": "<ECDH evaluator key ID>",
  "ephemeralPublicKey": "<base64url 65-byte uncompressed P-256 point>",
  "salt": "<base64url 32 bytes>",
  "ciphertext": "<base64url 327708 bytes>",
  "capabilityMac": "<base64url 32-byte HMAC-SHA-256>"
}
```

`ciphertext` is `iv || ciphertext-and-tag`: a 12-byte AES-GCM IV followed by
the encryption of exactly 327680 plaintext bytes and its 16-byte tag. Derive
the AES-256 key from the P-256 ECDH shared secret with HKDF-SHA-256, the request
`salt`, and this `info` byte string:

```text
UTF8("HERD-EVALUATOR-RELAY-KEY-V1\0") || UTF8(context)
```

`context` is the exact compact JSON serialization of:

```json
{
  "protocolVersion": 1,
  "cipherSuite": "P256_HKDF_SHA256_AES256_GCM",
  "evaluatorKeyId": "<key ID>",
  "ephemeralPublicKey": "<canonical base64url>",
  "salt": "<canonical base64url>"
}
```

AES-GCM additional authenticated data is
`UTF8("HERD-EVALUATOR-RELAY-AAD-V1\0") || UTF8(context)`. The fixed plaintext
frame begins with a four-byte unsigned big-endian JSON byte length, followed by
the compact UTF-8 JSON below, followed only by zero bytes:

```json
{
  "protocolVersion": 1,
  "relayRequestId": "<lowercase UUID>",
  "leaseId": "<lowercase UUID>",
  "issuedAt": "<canonical ISO 8601 timestamp>",
  "expiresAt": "<canonical ISO 8601 timestamp>",
  "evaluationRequest": "<the existing /api/v1/evaluate request object>"
}
```

The compact inner JSON is limited to 256 KiB. `expiresAt` must be after
`issuedAt` by no more than 120 seconds; an issuance may be at most 30 seconds in
the future and five minutes old; and the capability must not be expired.

The backend computes `capabilityMac` with HMAC-SHA-256 keyed by the UTF-8 bytes
of `HERD_EVALUATOR_TOKEN` over:

```text
UTF8("HERD-EVALUATOR-RELAY-CAPABILITY-V1\0") ||
UTF8(JSON.stringify({
  protocolVersion,
  cipherSuite,
  evaluatorKeyId,
  ephemeralPublicKey,
  salt,
  ciphertext
}))
```

The successful response has exactly this shape:

```json
{
  "protocolVersion": 1,
  "relayRequestHash": "<SHA-256 base64url>",
  "relayRequestId": "<request UUID>",
  "leaseId": "<lease UUID>",
  "result": "<existing EvaluationResult object>",
  "attestation": {
    "protocolVersion": 1,
    "signingKeyId": "<result-signing key ID>",
    "evaluatedAt": "<canonical ISO 8601 timestamp>",
    "canonicalDocument": "<compact canonical attestation JSON>",
    "signature": "<base64url raw 64-byte P-256 ECDSA signature>"
  }
}
```

`relayRequestHash` is SHA-256 of the UTF-8 compact normalized relay request,
including `capabilityMac`. `canonicalDocument` is the exact compact JSON of
`{protocolVersion, signingKeyId, relayRequestHash, relayRequestId, leaseId,
evaluatedAt, result}` in that order. `signature` is ECDSA P-256/SHA-256 over
those exact UTF-8 bytes, normalized to the raw IEEE-P1363 `r || s` form. The
backend must reconstruct and compare the canonical document, pin the signing
key ID and public key, verify the signature, match the active request hash and
lease, and validate the result before accepting it.

Browser preflight permits only the exact configured HTTPS origin, `POST`, and a
bounded header set: required `content-type` plus optional `cache-control` and
`pragma` headers that browsers may add for no-store fetches. POSTs with another Origin are rejected;
native requests without an Origin remain valid because the capability MAC is
mandatory. Relay responses are never cacheable. The maximum relay request body
is 437391 bytes. Authentication/time failures return generic `401` responses,
origin failures `403`, malformed input `400`, oversized input `413`, and
configuration failures `503`.

## Validation boundary

Before decrypting anything, the service verifies:

- bearer authentication, JSON media type, and a 256 KiB body limit;
- the exact request, policy, canonical policy-document, slot, and envelope
  schemas;
- the canonical policy hash and all release/key/measurement pins;
- that the configured private JWK's public point matches the policy public key;
- canonical event timestamps and a sent-event date;
- the exact frozen member set and ordering, required-group membership, and host
  minimum;
- every envelope's event, member, policy, evaluator key, canonical hash, and
  fixed-size encoding; and
- the exact batch commitment before fixed-point evaluation.

After those public commitments pass, every fixed-size envelope is opened
independently. An envelope that fails authenticated decryption or private-value
validation is treated exactly like a nonresponse for aggregate evaluation.
The service never returns or logs which slot failed, so one damaged or hostile
reply cannot hold the event result open or create a new guest-level disclosure.
Request-level validation errors return only a generic error code. Decrypted
response bodies and internal exceptions are never serialized or logged.

## Runtime configuration

Copy `.env.example` for local work and configure the same values as hosted
runtime variables before deployment:

- `HERD_EVALUATOR_TOKEN` — shared random bearer secret, at least 32 characters;
- `HERD_EVALUATOR_KEY_ID` — release-scoped P-256 key identifier;
- `HERD_EVALUATOR_PRIVATE_KEY_PEM` — the production SEC1 P-256 private PEM,
  including its standard named-curve and uncompressed public-point fields; or
- `HERD_EVALUATOR_PRIVATE_KEY_JWK` — an alternative secret P-256 private JWK
  containing canonical 32-byte base64url `x`, `y`, and `d` values (configure
  exactly one private-key format);
- `HERD_EVALUATOR_MEASUREMENT` — evaluator measurement frozen into policies;
- `HERD_RELEASE_ID` — release identifier frozen into policies.
- `HERD_EVALUATOR_RELAY_ALLOWED_ORIGIN` — the one exact Herd web HTTPS origin
  permitted to relay from a browser;
- `HERD_EVALUATOR_RESULT_SIGNING_KEY_ID` — release-scoped result-attestation
  signing key identifier; and
- `HERD_EVALUATOR_RESULT_SIGNING_PRIVATE_KEY_JWK` — a distinct secret P-256
  ECDSA private JWK used only to sign relayed results.

Never put the private JWK in the Herd web app, a `NEXT_PUBLIC_*` value, source
control, fixtures, logs, or deployment archives. Convert/import the production
private key only at the secret-management boundary.

## Build and verification

Node.js 22.13 or newer is required.

```bash
npm install
npm test
```

The test suite builds the deployable Worker and exercises the real HTTP routes
with valid encrypted envelopes, deadline and commitment checks, strict result
projection, authentication, malformed/tampered inputs, and misconfiguration.

The service vendors a deployment-self-contained copy of the dependency-free
`privacy-evaluator` core. `npm run check:vendor` enforces byte parity when the
adjacent Herd source tree is present and always pins these source hashes:

- `fixed-point.mjs`: `a9d622965eee9fc145b4615eea289819f4cb01ce42105c784de02b318c765221`
- `private-response-envelope.mjs`: `0d19a0b9bf0f67b06ccaea016e4c0fd4d534606e9a91fd65baa7a4257875da7d`

This isolates the key from the ordinary application, but a standard Worker is
not an attested hardware enclave. If Herd's launch policy requires independent
hardware attestation, deploy the same contract and evaluation core inside the
approved enclave runtime and update the frozen measurement pin accordingly.
