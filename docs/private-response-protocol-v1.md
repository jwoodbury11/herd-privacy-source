# Herd private-response protocol v1

Status: implementation contract. The web client, iOS client, ordinary API, and
confidential evaluator must reject any value that does not match this document.

## Security boundary

The browser or iOS client encrypts a response before sending it. The ordinary
Herd API stores only fixed-size ciphertext and routing metadata. It never accepts
the legacy plaintext response, minimum, or condition fields.

Protocol v1 protects response contents from ordinary API, database, log, and
backup access. It does not by itself provide evaluator attestation, anonymous
network submission, or protection from an unapproved web release. Hardware
attestation, release transparency, and independent witnessing are separate
launch requirements. Response authorization and inclusion receipts are part of
this protocol.

## Envelope

```json
{
  "protocolVersion": 1,
  "cipherSuite": "P256_HKDF_SHA256_AES256_GCM",
  "envelopeId": "UUID",
  "eventId": "UUID",
  "inviteeId": "UUID",
  "policyHash": "base64url SHA-256",
  "revision": 1,
  "accountKeyEpochId": "UUID",
  "evaluatorKeyId": "release-scoped identifier",
  "payloadCiphertext": "base64url 4124 bytes",
  "userKeyWrap": "base64url 60 bytes",
  "evaluatorKeyWrap": "base64url 157 bytes",
  "responseSigningPublicKey": "base64url raw Ed25519 public key, 32 bytes",
  "responseSignature": "base64url raw Ed25519 signature, 64 bytes"
}
```

All UUIDs are lowercase in canonical storage. Base64url values are unpadded.
The unsigned envelope is the object above without `responseSignature`, in the
same field order. Its `ciphertextHash` is the base64url SHA-256 of the UTF-8
canonical unsigned-envelope JSON. The API reconstructs that object before
hashing or storing it. Extra and malformed fields are rejected.

`revision` starts at one and uses compare-and-swap. A replacement must have the
current revision plus one and retain the exact first revision's account-key
epoch and response-signing public key. An SMS-authenticated account reset
creates a new `accountKeyEpochId` without changing the phone-linked account or
invitations, but it cannot replace an already answered invitation.

## Cryptographic context

The context is exactly 101 bytes:

```text
u8(protocolVersion)
|| event UUID (16)
|| invitee UUID (16)
|| policy hash (32)
|| envelope UUID (16)
|| account-key epoch UUID (16)
|| revision u32 big-endian (4)
```

Including the invitee UUID prevents moving a valid envelope into another guest's
response slot.

Each label below is ASCII followed by a single zero byte and then the context.

- Payload AAD: `HERD-RSVP-PAYLOAD-AAD-V1`
- User-wrap AAD: `HERD-RSVP-USER-WRAP-AAD-V1`
- User HKDF info: `HERD-RSVP-USER-KEK-V1`
- Evaluator HKDF info: `HERD-RSVP-EVALUATOR-KEK-V1`
- Evaluator-wrap AAD: `HERD-RSVP-EVALUATOR-WRAP-AAD-V1`

The evaluator key identifier is appended to the evaluator HKDF info. The
evaluator X9.63 public key and random HKDF salt are also appended to the
evaluator-wrap AAD.

## Plaintext and payload frame

The plaintext body is canonical UTF-8 JSON containing only:

```json
{
  "protocolVersion": 1,
  "eventId": "UUID",
  "inviteeId": "UUID",
  "policyHash": "base64url SHA-256",
  "envelopeId": "UUID",
  "accountKeyEpochId": "UUID",
  "revision": 1,
  "response": "going",
  "minimumParticipants": 4,
  "requiredGroups": [
    { "id": "UUID", "memberIDs": ["UUID"] }
  ],
  "nonce": "base64url 16 bytes"
}
```

`cant_commit` uses a null minimum and no groups. Names and phone numbers are
forbidden. Member IDs must belong to the frozen event, cannot include the
respondent, and may occur at most once across condition groups.

Frame the JSON as a two-byte big-endian length, the JSON bytes, and cryptographic
random padding to exactly 4,096 bytes. Encrypt it with a random 32-byte response
key using AES-256-GCM and the payload AAD:

```text
nonce (12) || ciphertext (4096) || tag (16) = 4124 bytes
```

## User key wrap

Each account-key epoch has a random 32-byte Account Root Secret (ARS), which is
available only to a trusted client device. Derive the user key-encryption key:

```text
HKDF-SHA256(
  input key = ARS,
  salt = policy hash,
  info = user HKDF label || 0x00 || context,
  output = 32 bytes
)
```

Wrap the raw 32-byte response key with AES-256-GCM and the user-wrap AAD:

```text
nonce (12) || ciphertext (32) || tag (16) = 60 bytes
```

Browser storage uses a non-exportable IndexedDB CryptoKey to protect the local
ARS. iOS uses a this-device-only Keychain key. Logging out does not delete it.

Before the first response in an epoch, the client registers this one-way
commitment using a compare-and-set initialization endpoint:

```text
base64url(SHA-256("HERD-ARS-COMMITMENT-V1" || 0x00 || ARS))
```

The API stores the 32-byte commitment but never the ARS. A client with a local
ARS must reproduce the commitment. If the epoch is already initialized and the
device has no matching local ARS, it must not silently generate another secret;
it must use trusted-device pairing (when implemented) or the explicit reset
flow. Response upload is refused until the active epoch is initialized.

## Evaluator key wrap

Generate an ephemeral P-256 key pair and derive a shared secret with the pinned
evaluator X9.63 public key. Generate a random 32-byte HKDF salt and derive an
AES-256-GCM key:

```text
HKDF-SHA256(
  input key = P-256 ECDH shared secret,
  salt = random 32 bytes,
  info = evaluator HKDF label || 0x00 || context || UTF-8 evaluatorKeyId,
  output = 32 bytes
)
```

Wrap the same raw response key. The evaluator-wrap AAD is its label, zero byte,
context, UTF-8 key identifier, ephemeral public key, and salt:

```text
ephemeral X9.63 public key (65)
|| HKDF salt (32)
|| nonce (12)
|| ciphertext (32)
|| tag (16)
= 157 bytes
```

Clients accept an evaluator key only when its identifier and public key match a
trusted value embedded in the approved client release. The API cannot introduce
a new evaluator key by itself.

## Response authorization

The client deterministically derives a response-signing seed from the same ARS
without storing another private key:

```text
HKDF-SHA256(
  input key = ARS,
  salt = policy hash,
  info = UTF-8 "HERD-RESPONSE-SIGNING-SEED-V1"
         || 0x00
         || event UUID (16)
         || invitee UUID (16),
  output = 32 bytes
)
```

Interpret the 32-byte output as an Ed25519 private-key seed. Put its 32-byte raw
public key in `responseSigningPublicKey`, canonicalize and hash the unsigned
envelope, and construct this exact ordered JSON document:

```json
{
  "protocolVersion": 1,
  "eventId": "UUID",
  "inviteeId": "UUID",
  "policyHash": "base64url SHA-256",
  "accountKeyEpochId": "UUID",
  "revision": 1,
  "envelopeId": "UUID",
  "ciphertextHash": "base64url SHA-256 of the unsigned envelope",
  "responseSigningPublicKey": "base64url raw Ed25519 public key"
}
```

Sign these bytes with Ed25519:

```text
UTF-8 "HERD-RESPONSE-AUTHORIZATION-V1" || 0x00 || UTF-8 ordered JSON above
```

The ordinary API verifies this signature before an exact-retry lookup or any
response/transparency write. The confidential authority and evaluator verify
it independently. Changing ciphertext, policy, event/member slot, account
epoch, revision, envelope identifier, or signing key invalidates it.

For each event/member slot, the first certified response must be revision one
and pins both the account-key epoch and response-signing public key. Every later
certified response must be the immediately following revision with those exact
values. The ordinary API enforces the same rule in its precheck and again in
the conditional insert so a concurrent request cannot bypass it.

This signature proves possession of the ARS-derived response key; it does not
independently prove who was entitled to enroll the first key. With the current
SMS/account path, a malicious ordinary backend could front-run a never-enrolled
slot with its own valid key and cause a detectable conflict/denial of service.
Preventing that first-enrollment forgery requires a direct identity-enrollment
channel outside the ordinary backend and is not claimed by protocol v1.

## Receipt and inclusion commitment

An accepted response receipt binds the envelope ID, event ID, invitee ID,
policy hash, account-key epoch ID, revision, ciphertext hash,
response-signing public key, response signature, commit time, log index,
previous-entry hash, entry hash, and transparency signing-key ID. The
confidential authority atomically advances the member revision, policy state,
log entry, and signed log head before certifying the receipt. An exact retry of
an already certified envelope returns that same certification, including after
the deadline or an account reset.

A reservation that is absent from the authority when its deadline closes is
not accepted late. Only after all response authorization, revision, policy, and
exact-next-head checks pass may the authority return a
`HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1` proof binding the rejected entry
to the current signed predecessor. A relying application may remove only a
wholly uncertified local suffix matching that proof; an invalid proof or any
certified suffix row is corruption and fails closed.

Only authority-certified member commitments may enter the evaluation batch.
Before accepting a later revision and again at evaluation, the authority
revalidates every field in the latest-member index against its referenced
immutable receipt and verifies that receipt and log head under the transparency
key. It then exact-reads every frozen member slot and consumes one canonical
batch hash before any response plaintext is opened. Corrupted indexes, omitted,
substituted, stale, unsigned, or alternate batches are rejected.

## Signed event result

The evaluator signs the exact final result under the release-scoped
evaluation-result key. The signed result contains, in order, protocol version,
event ID, frozen policy hash, canonical batch hash, evaluator key ID, status,
and—only for `confirmed`—the ordered attending member IDs. The attestation's
canonical document is exactly:

```json
{
  "protocolVersion": 1,
  "signingKeyId": "release-scoped result key ID",
  "relayRequestHash": "base64url SHA-256",
  "relayRequestId": "UUID",
  "leaseId": "UUID",
  "evaluatedAt": "canonical ISO-8601 timestamp",
  "result": { "the exact signed result fields above": "in protocol order" }
}
```

`signature` is the raw 64-byte ECDSA P-256/SHA-256 signature over those exact
UTF-8 bytes. The ordinary API verifies it before committing a final row and
persists the protocol version, key ID, evaluation time, canonical document,
and signature without re-encoding them. The public final projection returns
that exact attestation. Its `resolvedAt` must equal the signed `evaluatedAt`;
the database update uses `evaluatedAt` as the authoritative value.

Before displaying `confirmed` or `not_confirmed`, web and iOS clients verify
the signature with the result-signing key embedded in their approved release,
require exact schemas, and bind the signed event, policy, batch, evaluator,
status, attendee set, and timestamp to the event and API projection. Missing,
malformed, mutated, or differently keyed proof is never treated as a final
answer. It produces `verification_unavailable` instead.

This is also the migration and key-rotation rule. A historical row without the
proof columns remains listable but displays `verification_unavailable`. A
client whose current release no longer carries the historical result key does
the same. Herd does not fall back to an unsigned database result; retaining
verified historical display across a future key rotation requires an
authenticated key-lineage design and client support in that future protocol.

## Frozen policy

Before responses are accepted, the API canonicalizes and freezes the event
identity, event timing/location, ordered guest IDs and phone assignments, host
rules, response deadline, reveal policy, protocol limits, evaluator descriptor,
and release identifier. The SHA-256 of those canonical bytes is `policyHash`.

After freezing, a host cannot modify any policy field or return
`invitationsSent` to false. A changed event requires a new event and new explicit
responses.

## Reset behavior

If an authenticated device cannot open the active epoch, the user may start over
after fresh SMS verification. Herd supersedes the old epoch, creates a new epoch,
revokes other server sessions, and retains the stable phone-linked user and
invitations. The new ARS derives different response-signing keys. It may enroll
the first response for a never-answered invitation or a new event, but it may
not create a later revision for an invitation whose first response was pinned
under the old epoch. The exact old signed envelope remains safely retryable if
the device or caller still has it. Old criteria remain cryptographically
unavailable to the reset device.

Protocol v1 does not yet define trusted-device pairing. Consequently, a second
browser or iPhone without the active ARS must start over even if the first device
still exists. Pairing can later add an ARS wrap for a newly approved device
without changing the response-envelope format.

Protocol v1 knowingly accepts the SIM-swap and recycled-number takeover risk for
this reset path. That risk must remain disclosed until stronger recovery ships.
