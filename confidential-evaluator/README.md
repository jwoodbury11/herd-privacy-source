# Herd Confidential Space evaluator

This package is a standalone Node HTTP evaluator for Google Confidential Space
on Intel TDX. It reuses the existing Herd evaluator algorithm as a reviewed,
hash-pinned bundle, decrypts its runtime keys only after a production
attestation satisfies the key-custodian project's Workload Identity Provider,
and keeps all private-key operations inside the workload.

Nothing in this directory provisions cloud resources or contains production
credentials. The test suite uses generated test keys and fake providers only.

## Security boundary

At startup the process:

1. reads an exact, non-secret deployment configuration from the image;
2. reads separate KMS ciphertexts for the evaluator-key epoch and the
   lifetime-global response-log identity from the image;
3. requests an OIDC attestation token from the Confidential Space launcher over
   `/run/container_launcher/teeserver.sock`;
4. exchanges that token directly through the configured Workload Identity
   Provider and independently calls Cloud KMS `cryptoKeys.decrypt` for both
   wrapping keys; the same attested
   principal, never the VM service account, later receives Firestore data-plane
   access;
5. validates fixed production claims from that token, including Intel TDX,
   secure boot, stable support, no command/environment overrides, restart
   policy `Always`, memory monitoring disabled, and a canonical
   `sha256:<64 lowercase hex>` image digest, then exposes the digest only after
   KMS decryption succeeds;
6. requires both decryptions to report the same attested image digest, verifies
   both KMS response CRC32Cs, imports four distinct non-exportable P-256 private
   keys, clears both plaintext byte buffers, binds policy evaluation to the
   attested image digest, and only then listens; and
7. serves health, challenge attestation, encrypted browser relay, policy
   signing, and a stateful policy/response/evaluation authority without request
   logging. The production direct-evaluation route is disabled.

The four keys cannot share a key ID, public point, or private scalar:

- `responseDecryptionKey`: P-256 ECDH for encrypted RSVP envelopes;
- `evaluationResultSigningKey`: P-256 ECDSA for evaluation results;
- `policySigningKey`: P-256 ECDSA for frozen policy descriptors; and
- `transparencySigningKey`: P-256 ECDSA for receipts and log heads.

The first three keys and bearer token form an evaluator-key epoch. The
transparency key is not release- or epoch-scoped: it is a separately wrapped,
lifetime-global identity for `herd-response-log-v1`. Every evaluator epoch
must reuse it. Startup rejects a stored tail with any other key ID or signature,
so changing this identity in place cannot silently fork or reset the log.

Their public metadata is committed into one domain-separated key-binding hash.
Challenge attestations place both the caller nonce and that binding hash in the
Google PKI token's `eat_nonce` claim.

## Commands

Run all local checks from this directory:

```sh
npm test
```

The suite validates fail-closed configuration, four-key isolation, launcher
OIDC and PKI request shapes, KMS CRC32C validation, policy/transparency domain
separation, Firestore CAS and lost-response recovery, restart and multi-replica
non-equivocation, exact transparency schemas, the canonical evaluator/relay
cores, CORS, invitee-web relay compatibility, and signed evaluation proofs.

`npm run check:core` verifies both generated bundles and every upstream source
hash recorded in `vendor/evaluator-core.sources.json` and
`vendor/relay-core.sources.json`. It also pins the test-only bundled
invitee-web completion path in
`test/vendor/invitee-relay-completion.sources.json`, so the compatibility test
executes the real `completeClientRelayEvaluation` implementation. A source
change must be reviewed and the corresponding bundle deliberately regenerated;
silently drifting from the evaluator, relay, or invitee completion contract is
a test failure.

After reviewing an upstream contract change, `npm run generate:core`
deterministically rebuilds all three snapshots. Update the recorded SHA-256
values only after reviewing the generated diffs; `npm run check:core` then pins
both the generator inputs and resulting bundles.

## Runtime artifacts

The container build receives a named BuildKit context called
`release-config` containing exactly:

- `deployment.json`: the non-secret configuration shown in
  `release-config.example/deployment.json`;
- `key-bundle.ciphertext`: the KMS-encrypted evaluator-epoch bundle; and
- `transparency-key.ciphertext`: the independently KMS-encrypted global
  response-log identity.

The decrypted evaluator-epoch bundle has exactly this shape. Its legacy
protocol field `releaseId` identifies the evaluator-key epoch, not an artifact
build:

```json
{
  "protocolVersion": 1,
  "releaseId": "herd-evaluator-2026-08-01",
  "requestAuthenticationToken": "<at least 32 non-whitespace characters>",
  "responseDecryptionKey": {
    "keyId": "<epoch-scoped ID>",
    "privateKeyJwk": { "kty": "EC", "crv": "P-256", "x": "<32-byte base64url>", "y": "<32-byte base64url>", "d": "<32-byte base64url>" }
  },
  "evaluationResultSigningKey": {
    "keyId": "<different ID>",
    "privateKeyJwk": { "kty": "EC", "crv": "P-256", "x": "<32-byte base64url>", "y": "<32-byte base64url>", "d": "<32-byte base64url>" }
  },
  "policySigningKey": {
    "keyId": "<different ID>",
    "privateKeyJwk": { "kty": "EC", "crv": "P-256", "x": "<32-byte base64url>", "y": "<32-byte base64url>", "d": "<32-byte base64url>" }
  }
}
```

The independently decrypted transparency bundle has exactly this shape:

```json
{
  "protocolVersion": 1,
  "logId": "herd-response-log-v1",
  "transparencySigningKey": {
    "keyId": "<lifetime-global log key ID>",
    "privateKeyJwk": { "kty": "EC", "crv": "P-256", "x": "<32-byte base64url>", "y": "<32-byte base64url>", "d": "<32-byte base64url>" }
  }
}
```

`scripts/generate-key-bundle.mjs` creates a new evaluator-epoch plaintext and a
separate mode-0600 copy of its request-authentication token for immediate
placement in the ordinary application's protected secret store.
`scripts/generate-transparency-key-bundle.mjs` creates the global log plaintext
only for the initial log ceremony; it must not run for routine releases or
epoch rotations. Both use mode `0600` and exclusive creation and refuse to
overwrite a file. Never run either in a repository directory or CI log, and
never put a plaintext bundle in source control, a container layer, Terraform
state, or a shell variable. KMS wrapping-key version rotation or controlled
rewrapping may change ciphertext bytes but must preserve the same global
transparency public key and key ID.

Production rejects legacy private-key, token, credential, and secret
environment variables. The only Herd environment setting is the path to the
non-secret deployment config; the image fixes it to
`/app/config/deployment.json`.

The config's `policyMeasurement` is a stable protocol identity for the current
evaluator-key epoch. Artifact-only rebuilds preserve it so unresolved policies
remain valid. It is never accepted as proof of the running artifact: KMS and
Firestore access remain bound to the exact image digest extracted from the
Google-attested launcher token, and that exact digest is kept separately from
the policy-facing measurement at runtime.

## HTTP surface

`GET /healthz` and `GET /readyz` return public key-binding metadata. Backend
POSTs require the bearer token decrypted from the key bundle. Policy and
transparency signing reject all browser `Origin` requests. The encrypted relay
and challenge-attestation paths are the deliberate public exceptions. The
browser relay sends no bearer header, and its backend-authorized envelope
contains an HMAC capability made with that same decrypted token. Attestation
accepts a caller nonce and returns only public key metadata plus the
Google-signed proof, allowing an independent monitor to verify the live
workload without sharing the backend bearer. Requests with an `Origin` header
still require the exact configured application origin. The endpoints are:

- `POST /api/v1/relay/`
- `POST /api/v1/attestation`
- `POST /api/v1/sign/policy`
- `POST /api/v1/sign/transparency`

The exact schemas, canonical byte strings, and verification rules are in
[`docs/confidential-evaluator-api.md`](../docs/confidential-evaluator-api.md).
Deployment and operations are in
[`docs/confidential-evaluator-deployment.md`](../docs/confidential-evaluator-deployment.md)
and
[`docs/confidential-evaluator-runbook.md`](../docs/confidential-evaluator-runbook.md).

All responses use `Cache-Control: no-store`. Request-validation failures are
generic. Decrypted RSVP values, private keys, ciphertext slot failures, and
internal exceptions are never returned or logged.

Policy signing first-writes a durable policy hash, deadline, ordered opaque
member IDs, and evaluator commitments to the custodian Firestore database; no
event or person display data is stored there. Before any reply exists, an
atomic roster expansion may retain every existing member and add new opaque
members. After the first reply, the policy is immutable. The transparency
endpoint accepts one operation: atomically append a canonical, Ed25519-authorized response
receipt to the durable tail. It pins the member's response key within an
account-key epoch, permits only paired epoch/key rotation for a device switch,
enforces exactly increasing revisions and the authority deadline, derives the matching
head, signs both, and CAS-commits the immutable entry, new tail, policy sequence,
and latest member commitment together. Exact retries return the stored
signatures even after the deadline or evaluation consumption, while forks,
gaps, stale revisions/indexes, wrong keys, and wrong previous hashes fail
without signatures. There is no stateless production fallback.

If a valid local reservation never reached the authority before the deadline,
the authority returns a separate domain-signed proof binding that absent entry
to its exact current predecessor. The application verifies that proof and may
delete only a wholly uncertified local suffix; any signed row or mismatch fails
closed. Later inserts explicitly require the current predecessor, so the global
log resumes without accepting the missed response late or leaving every event
wedged behind it.

Before relay evaluation decrypts any response, the authority exact-reads every
member, revalidates every latest-member field against its exact signed immutable
receipt/log-head entry, and consumes one complete latest batch hash. The same
certification revalidation occurs before a later revision can advance a member.
Only an exact crash retry may reuse the batch; corrupted indexes, omitted slots,
stale revisions, and alternate chosen subsets are rejected.

This prevents an ordinary backend, workload operator, restart, or replica race
from producing conflicting same-size signed heads, replacing an enrolled
response without its device key, or querying chosen evaluation subsets. A
malicious backend can still front-run a never-enrolled response slot or suppress
a submission; preventing that requires an independent direct client identity
enrollment channel not present in the current SMS trust path. The design also
does not make a malicious key custodian harmless.
Production still requires public log publication plus an independent
witness/gossip monitor; the operations runbook treats rollback, suppression,
a key-identity change, or a conflicting head as a security incident. A
compromised global transparency key permanently seals this log and requires a
new log ID/protocol and witness bootstrap ceremony, never an in-place key swap.

## Container guarantees

The Dockerfile:

- rejects any base image that is not an `@sha256` reference;
- embeds only non-secret configuration and two KMS ciphertexts;
- runs as numeric user `65532`;
- forbids command, environment, capability, cgroup, and mount overrides through
  Confidential Space launch-policy labels;
- forbids container log redirection and memory monitoring; and
- exposes only port 8080.

The workload image digest attested by Confidential Space is the final authority
for what ran. An image digest alone does **not** prove that an image was built
from public source; publish and independently verify BuildKit provenance, the
source commit, dependency lock material, and rebuild results as a separate
release process.
