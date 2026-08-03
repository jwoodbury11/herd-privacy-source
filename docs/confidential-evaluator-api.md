# Confidential evaluator API v1

This is the byte-level integration contract for `confidential-evaluator`.
Objects reject missing and extra fields. Base64url values are unpadded and must
round-trip canonically. Every response is JSON with `Cache-Control: no-store`.

Backend POST endpoints require:

```http
Authorization: Bearer <requestAuthenticationToken from the encrypted bundle>
Content-Type: application/json
```

`POST /api/v1/relay/` and `POST /api/v1/attestation` are the two exceptions:
neither requires a bearer header. For the relay, authorization is the HMAC
capability inside its opaque encrypted request. That HMAC key is exactly the
same `requestAuthenticationToken` stored in the encrypted bundle; it is not a
second browser-visible credential. The attestation endpoint returns only a
fresh Google-signed platform proof and public key metadata.

Policy and transparency signing are backend-only and reject every request with
an `Origin` header, including the configured origin. Other browser-capable
endpoints accept `Origin` only when it exactly equals the configured HTTPS
origin. Native and server requests omit `Origin`.

## Public key binding

`GET /healthz` and `GET /readyz` return:

```json
{
  "status": "ok",
  "protocolVersion": 1,
  "keyBinding": {
    "protocolVersion": 1,
    "releaseId": "<evaluator-key epoch ID (protocol-v1 legacy field)>",
    "keys": {
      "responseDecryption": {
        "keyId": "<key ID>",
        "algorithm": "ECDH_P256",
        "publicKey": "<base64url 65-byte uncompressed P-256 point>"
      },
      "evaluationResultSigning": {
        "keyId": "<key ID>",
        "algorithm": "ECDSA_P256_SHA256",
        "publicKey": "<base64url 65-byte uncompressed P-256 point>"
      },
      "policySigning": {
        "keyId": "<key ID>",
        "algorithm": "ECDSA_P256_SHA256",
        "publicKey": "<base64url 65-byte uncompressed P-256 point>"
      },
      "transparencySigning": {
        "keyId": "<key ID>",
        "algorithm": "ECDSA_P256_SHA256",
        "publicKey": "<base64url 65-byte uncompressed P-256 point>"
      }
    }
  },
  "keyBindingHash": "<base64url SHA-256>"
}
```

The object order shown above is normative. Compute the binding as:

```text
base64url(SHA-256(
  UTF8("HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1\0") ||
  UTF8(JSON.stringify(keyBinding))
))
```

Health metadata is informational until verified against a fresh attestation.
`/healthz` is process liveness. Before returning the same metadata, `/readyz`
also reads the Firestore tail and its matching immutable entry and validates
their receipt/head signatures against the lifetime-global response-log key. The
process performs this readiness check before it starts listening; there is no
ready state without access to the durable authority.

## Challenge attestation

`POST /api/v1/attestation` accepts exactly:

```json
{
  "protocolVersion": 1,
  "nonce": "<base64url 32 random bytes>"
}
```

This endpoint is intentionally public so an independent monitor can challenge
the evaluator without trusting the ordinary application backend or sharing its
bearer secret. Requests carrying an `Origin` header are accepted only from the
one configured application origin; requests with no `Origin` are permitted for
server-side monitors. Cloud Armor applies a dedicated per-source limit of 60
attestation requests per minute; other evaluator paths use the broader
600-request-per-minute rule. Responses are non-cacheable and contain no
response plaintext or private key material.

It returns exactly:

```json
{
  "protocolVersion": 1,
  "tokenType": "google-pki",
  "audience": "<fixed configured HTTPS audience>",
  "nonce": "<same caller nonce>",
  "keyBinding": "<the public key-binding object above>",
  "keyBindingHash": "<the computed binding hash>",
  "attestationToken": "<Google Confidential Space PKI JWT>"
}
```

The workload requests the PKI token with nonces in this exact order:

```json
["<caller nonce>", "<keyBindingHash>"]
```

A relying party must validate the PKI certificate chain against its pinned
Google Confidential Space root, require `alg=RS256`, validate signature and
time claims, require the configured `aud`, and require both `eat_nonce` entries
in order. It must then enforce at least:

- `swname == "CONFIDENTIAL_SPACE"`;
- `dbgstat == "disabled-since-boot"`;
- `secboot == true`;
- `hwmodel == "GCP_INTEL_TDX"`;
- `STABLE` support status;
- the expected workload project and service account;
- no command or environment overrides;
- restart policy `Always` and memory monitoring disabled; and
- the independently approved `submods.container.image_digest`.

Finally, recompute `keyBindingHash` from the response and trust the four keys
only if that value is the second attested nonce. Never trust health metadata,
the response body, or TLS alone as a substitute.

The policy/evaluation measurement is not embedded in the image configuration.
It is the canonical `submods.container.image_digest` value from the OIDC tokens
that successfully passed WIP/STS authorization and both KMS decryptions; the
two extracted values must be identical. It
must match `^sha256:[0-9a-f]{64}$` and the independently approved digest pinned
by the relying party and WIP condition. Before becoming ready, the workload
also requires from that token: production Confidential Space, debug disabled
since boot, secure boot, Intel TDX, `attester_tcb == ["INTEL"]`, `STABLE`
support, empty command/environment overrides, restart policy exactly `Always`,
and memory monitoring disabled.

Google documents `tdx.gcp_attester_tcb_status` as a string tied to Intel PCS but
does not publish an acceptable-value enum in the Confidential Space claim
reference. This release deliberately does not invent an allowlist for that
field. The independent verifier/key custodian must apply a reviewed, current
TCB policy if it has authoritative Intel/Google rollout data; `STABLE` and the
other fixed production checks remain mandatory.

## Encrypted client relay

`POST /api/v1/relay/` is wire-compatible with
`evaluator-service/lib/relay.ts` and the existing invitee-web
`completeClientRelayEvaluation` flow. It accepts exactly:

```json
{
  "protocolVersion": 1,
  "cipherSuite": "P256_HKDF_SHA256_AES256_GCM",
  "evaluatorKeyId": "<response-decryption key ID>",
  "ephemeralPublicKey": "<base64url 65-byte uncompressed P-256 point>",
  "salt": "<base64url 32 bytes>",
  "ciphertext": "<base64url 327708 bytes>",
  "capabilityMac": "<base64url 32 bytes>"
}
```

The ciphertext is a 12-byte IV, a 327,680-byte AES-GCM ciphertext, and a
16-byte tag. Its padded plaintext frame is a four-byte big-endian JSON length,
the compact canonical inner request, then all-zero padding. The inner request
contains exactly `protocolVersion`, `relayRequestId`, `leaseId`, `issuedAt`,
`expiresAt`, and `evaluationRequest` and is bounded by the existing relay clock
and lifetime rules.

The relay context is compact JSON of the first five outer fields. Derive the
AES-256-GCM key using P-256 ECDH followed by HKDF-SHA-256 with the 32-byte
`salt` and info
`UTF8("HERD-EVALUATOR-RELAY-KEY-V1\0") || UTF8(context)`. Authenticate
`UTF8("HERD-EVALUATOR-RELAY-AAD-V1\0") || UTF8(context)` as AES-GCM AAD.

The capability document is compact JSON containing the outer fields in the
order above but omitting `capabilityMac`. Compute:

```text
HMAC-SHA256(
  UTF8(requestAuthenticationToken),
  UTF8("HERD-EVALUATOR-RELAY-CAPABILITY-V1\0") ||
  UTF8(capabilityDocument)
)
```

The endpoint returns the exact object consumed by invitee-web, without an
adapter:

```json
{
  "protocolVersion": 1,
  "relayRequestHash": "<base64url SHA-256 of normalized outer request JSON>",
  "relayRequestId": "<inner UUID>",
  "leaseId": "<inner UUID>",
  "result": "<existing evaluator result object>",
  "attestation": {
    "protocolVersion": 1,
    "signingKeyId": "<evaluation-result-signing key ID>",
    "evaluatedAt": "<canonical ISO timestamp>",
    "canonicalDocument": "<compact JSON string>",
    "signature": "<base64url raw 64-byte P-256 signature>"
  }
}
```

Reconstruct `canonicalDocument` in this exact order:

```js
JSON.stringify({
  protocolVersion: 1,
  signingKeyId,
  relayRequestHash,
  relayRequestId,
  leaseId,
  evaluatedAt,
  result,
})
```

For compatibility this relay signature is P-256/SHA-256 over the UTF-8
canonical document directly, with no added domain prefix. Pin the attested
evaluation-result signing key. Browser preflight allows only `content-type`,
`cache-control`, and `pragma`; `authorization` and private-network preflight are
rejected. A POST may omit `Origin` for the native courier path or use the one
exact configured invitee-web origin.

## Policy descriptor signing

`POST /api/v1/sign/policy` accepts exactly:

```json
{
  "protocolVersion": 1,
  "canonicalDocument": "<compact frozen policy descriptor JSON>"
}
```

The string must satisfy
`JSON.stringify(JSON.parse(canonicalDocument)) === canonicalDocument`, be at
most 64 KiB, use the existing policy descriptor schema, and pin the configured
release, response-decryption key ID/public point, and evaluator measurement.

It returns exactly:

```json
{
  "protocolVersion": 1,
  "domain": "HERD-POLICY-DESCRIPTOR-SIGNATURE-V1",
  "signingKeyId": "<policy-signing key ID>",
  "payloadHash": "<base64url SHA-256 of canonicalDocument UTF-8>",
  "signature": "<base64url raw 64-byte IEEE-P1363 P-256 ECDSA signature>"
}
```

Verify the signature over:

```text
UTF8("HERD-POLICY-DESCRIPTOR-SIGNATURE-V1\0") ||
UTF8(canonicalDocument)
```

The verifier must pin `signingKeyId` and use only the attested `policySigning`
public key. A policy signature is not a transparency receipt.

Before returning the signature, the evaluator first-writes an immutable
Firestore policy authority document keyed by `eventId`. It contains exactly the
protocol version, event ID, policy hash, RSVP deadline, ordered opaque member
IDs, release ID, evaluator key ID, response sequence, and empty evaluation
consumption fields. An exact policy retry is idempotent; any different policy
for the same event is a conflict. New policy registration after its deadline is
rejected. The authority never stores the canonical policy document, event
title, names, phones, location, address, or description.

This endpoint is backend-only and rejects browser `Origin` requests.

## Stateful transparency append authority

`POST /api/v1/sign/transparency` accepts exactly:

```json
{
  "protocolVersion": 1,
  "kind": "append",
  "canonicalReceiptPayload": "<compact canonical receipt JSON>"
}
```

`kind` is only `append`. The former direct `receipt` and `log_head` signing
operations are rejected; the caller cannot choose a head. The compact receipt
payload must have exactly this order and schema:

```json
{
  "protocolVersion": 1,
  "logId": "herd-response-log-v1",
  "logIndex": 1,
  "previousEntryHash": "<base64url 32 bytes>",
  "entryHash": "<base64url 32 bytes>",
  "envelopeId": "<UUID>",
  "eventId": "<UUID>",
  "inviteeId": "<UUID>",
  "policyHash": "<base64url 32 bytes>",
  "accountKeyEpochId": "<UUID>",
  "revision": 1,
  "ciphertextHash": "<base64url 32 bytes>",
  "responseSigningPublicKey": "<base64url 32-byte Ed25519 public key>",
  "responseSignature": "<base64url 64-byte Ed25519 signature>",
  "committedAt": "<canonical ISO timestamp>",
  "signingKeyId": "<lifetime-global transparency key ID>"
}
```

`logIndex` is 1 through 2,147,483,647; revision is 1 through 1,000,000. Index 1
requires the all-zero 32-byte genesis hash and later indexes forbid it. The
signer reconstructs the canonical entry core without `entryHash` and
`signingKeyId` and requires:

```text
entryHash = base64url(SHA-256(
  UTF8("HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1\0") || UTF8(entryCore)
))
```

`ciphertextHash` commits the compact unsigned envelope, including
`responseSigningPublicKey` but excluding `responseSignature`. Before any
transparency signature, the authority reconstructs this compact document in
the shown order:

```js
JSON.stringify({
  protocolVersion,
  eventId,
  inviteeId,
  policyHash,
  accountKeyEpochId,
  revision,
  envelopeId,
  ciphertextHash,
  responseSigningPublicKey,
})
```

It verifies `responseSignature` as Ed25519 over:

```text
UTF8("HERD-RESPONSE-AUTHORIZATION-V1\0") ||
UTF8(the compact response-authorization document)
```

After validating the receipt, the authority exact-reads the frozen policy and
member state. The policy hash, membership, and deadline must match. A member's
first receipt must have revision 1; later receipts must be exactly previous + 1
and use the identical pinned account-key epoch and Ed25519 public key.
Before a later receipt can advance the member, every field of that latest-member
index is matched against its referenced immutable receipt and that receipt and
log head are signature-verified. A corrupted member index therefore fails
closed instead of becoming unsigned revision state.
Authority-clock appends after
the deadline or after evaluation consumption are rejected. The new receipt is
also accepted only when `logIndex === treeSize + 1` and
`previousEntryHash` equals the durable head hash (or the all-zero genesis hash
for index 1). It derives this compact head itself:

```json
{
  "protocolVersion": 1,
  "logId": "herd-response-log-v1",
  "treeSize": 1,
  "headEntryHash": "<base64url 32 bytes>",
  "generatedAt": "<authority-generated, monotonic canonical ISO timestamp>",
  "signingKeyId": "<lifetime-global transparency key ID>"
}
```

`treeSize` has the same log-index bounds. All hashes are canonical unpadded
base64url, a non-empty head cannot use the all-zero genesis hash, all
UUIDs/timestamps are canonical, and the key ID must equal the attested
transparency key. Both payloads round-trip through compact `JSON.stringify`
unchanged and fit within 64 KiB.

The authority signs the receipt and derived head, then atomically CAS-commits
both signatures, the immutable entry, the new tail, the incremented policy
response sequence, and the member's latest envelope/hash/revision/key/log
certification in the independently administered Firestore database. The
policy CAS is shared with evaluation consumption, so a deadline-edge last
receipt and evaluation have exactly one winner. Only after that commit does it
return exactly:

```json
{
  "protocolVersion": 1,
  "kind": "append",
  "signingKeyId": "<transparency-signing key ID>",
  "receipt": {
    "domain": "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1",
    "payloadHash": "<base64url SHA-256 of canonicalReceiptPayload UTF-8>",
    "signature": "<base64url raw 64-byte IEEE-P1363 P-256 ECDSA signature>"
  },
  "logHead": {
    "canonicalPayload": "<the compact authority-derived head above>",
    "domain": "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1",
    "payloadHash": "<base64url SHA-256 of canonicalPayload UTF-8>",
    "signature": "<base64url raw 64-byte IEEE-P1363 P-256 ECDSA signature>"
  }
}
```

Verify each signature over:

```text
UTF8(domain || "\0") || UTF8(the corresponding canonical payload)
```

Only the attested `transparencySigning` public key is valid. It is the stable
identity of `herd-response-log-v1` across artifact releases and evaluator-key
epochs. Receipt and log-head signatures are intentionally non-interchangeable
even though they use the same global key. The authority fails readiness if the
durable tail has another key ID or cannot be verified by this key; an in-place
key change is never accepted as log continuity.

An exact retry, including one after a restart, lost HTTP response, deadline, or
evaluation consumption, reads and returns the byte-identical stored
signatures. A different receipt at an already committed index, unsigned or
wrong-key revision, revision gap, stale index, or wrong previous hash returns
`409 transparency_conflict` without a signature. Concurrent replicas race on
the Firestore update-time preconditions and only one successor can commit.
There is no in-memory or stateless fallback when Firestore is unavailable.

There is one narrow, signed recovery disposition for a locally reserved entry
that the authority never committed before the window closed. It is returned
only after the candidate has passed the complete policy, membership, timestamp,
Ed25519 authorization, revision, account-key epoch, and response-key checks;
the candidate index must be exactly the next index and its previous hash must
equal the verified durable authority head (with the all-zero genesis exception).
If and only if the entry is absent and the deadline or evaluation consumption
is the sole remaining reason it cannot append, the endpoint returns 409:

```json
{
  "error": {
    "code": "transparency_late_missing_entry",
    "proof": {
      "canonicalPayload": "<compact reconciliation payload below>",
      "domain": "HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1",
      "payloadHash": "<base64url SHA-256 of canonicalPayload UTF-8>",
      "signature": "<base64url raw 64-byte P-256 signature>",
      "signingKeyId": "<lifetime-global transparency key ID>"
    }
  }
}
```

The canonical reconciliation payload has exactly this order:

```json
{
  "protocolVersion": 1,
  "logId": "herd-response-log-v1",
  "rejectedLogIndex": 7,
  "rejectedEntryHash": "<candidate entry hash>",
  "authorityTreeSize": 6,
  "authorityHeadEntryHash": "<verified durable authority head hash>",
  "generatedAt": "<authority canonical ISO timestamp>",
  "signingKeyId": "<lifetime-global transparency key ID>"
}
```

Verify the payload hash and the domain-separated signature with the attested
global transparency key. The proof binds the rejected candidate to the exact
authority predecessor; it is not permission to accept the response late. A
caller may use it only to abandon a wholly uncertified local suffix anchored to
that predecessor. Any invalid signature, revision, timestamp, account epoch,
response key, entry hash, index, or predecessor remains the unsigned generic
`transparency_conflict` (or `invalid_request`) and must never trigger cleanup.

This endpoint is backend-only and rejects browser `Origin` requests. The
ordinary application backend cannot replace a genuinely enrolled response
without its device-derived Ed25519 key. It can front-run a never-enrolled slot
with its own key or suppress a genuine submission, causing integrity failure or
visible conflict/denial. Preventing that first-enrollment attack requires an
independently authenticated direct client identity-enrollment channel that the
current SMS/backend trust path does not provide. The backend cannot ask the
authority to reset, skip, roll back, sign two successors at one size, or query
alternate evaluation subsets. The key-custodian administrators remain a trust boundary because
they can alter Firestore IAM or data. Public publication and independent
witness/gossip comparison remain required to expose custodian compromise,
operational rollback, or suppression.

## Canonical evaluation consumption

The production direct `POST /api/v1/evaluate` route is disabled and returns
404. Production evaluation is available only through the encrypted relay.

After decrypting the relay frame but before decrypting a response envelope, the
ordinary evaluation preparation first retries up to 64 oldest locally pending
canonical receipts in log order. This repairs a lost authority HTTP response or
lost local certification persist, including after the deadline, because only an
exact already-committed payload can succeed then. If work remains, evaluation
fails closed and resumes on a later pass; stored-but-uncertified envelopes are
never selected. A generic authority `409` remains a permanent transparency
conflict, not a transient `503`. Only a fully verified
`transparency_late_missing_entry` proof permits the ordinary mirror to abandon
the exact wholly uncertified suffix described above.

The evaluator then derives a non-secret authority claim containing the policy
commitments, deadline, ordered member IDs, proposed batch hash, and every
slot's envelope hash/revision/response-signing public key (or three explicit
nulls). It exact-GETs every independently stored member document and requires
the proposal to equal the latest certified state position by position. It also
exact-GETs each referenced immutable entry, matches every member field to the
canonical receipt, and verifies both receipt and log-head signatures before it
may consume the batch.

If the policy is not yet consumed, the evaluator CAS-writes that one batch hash
and authority timestamp to the policy document. If already consumed, only the
exact same batch hash is accepted. A lost response or crash after consumption
therefore retries safely; an omitted slot, null substituted for a response,
stale revision, changed signing key, or repeatedly chosen subset never reaches
response decryption. Only after successful consumption does the evaluator open
envelopes, compute the permitted result, and return the relay attestation
defined above.

## Errors

Errors have one generic shape:

```json
{ "error": { "code": "invalid_request" } }
```

Expected statuses are 400 malformed input, 401 authentication failure, 403
origin failure, 409 deadline not reached, 413 oversized input, 404 unknown
route, and 503 configuration/provider failure. The service never identifies
which encrypted response failed to open.
