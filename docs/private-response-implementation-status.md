# Private-response implementation status

Last reviewed: 2026-08-03
Scope: repository state, not a claim about an unverified external deployment

## Technical completion

The privacy-critical product path is implemented in this repository. There is
no remaining planned core feature that needs to change the response format,
policy semantics, evaluator result, invitation/account behavior, or client
trust decision before production validation begins.

- Web and iOS encrypt the reply, private minimum, and required-person groups on
  the device into one fixed-size protocol-v1 envelope. The ordinary API accepts
  no readable replacement fields.
- Each response key is wrapped independently to the device-held account epoch
  and the release-pinned evaluator. Account-key commitments prevent silent key
  substitution; an explicit freshly authenticated reset starts a new epoch
  without pretending to recover old criteria.
- Sending invitations freezes an exact canonical policy. A purpose-specific
  confidential-evaluator key signs it, and both clients recompute the hash,
  verify the signature, and enforce the pinned release/evaluator identity.
- Every accepted response revision is committed to a sequential hash chain.
  The confidential evaluator signs the receipt and log head. A client accepts
  success only after validating both signatures and finding the exact hash-only
  entry on the public log.
- Evaluation uses a greatest-fixed-point rule, binds the exact committed batch
  and frozen policy, and emits only `not_confirmed` or the confirmed attendance
  member IDs. A purpose-specific result key signs the response used by the
  client-relay and unattended scheduler paths. The API now persists and returns
  that exact signed attestation, and derives `resolvedAt` from its signed
  `evaluatedAt`; web and iOS verify the event, policy, batch, evaluator, status,
  attendees, key ID, and signature before displaying a final answer.
- Legacy rows without result proof, mutated proof, and results signed by a key
  absent from the current client release remain listable but render an explicit
  verification-unavailable state. Neither client falls back to mutable final
  fields during migration or evaluator-key rotation.
- The self-contained production evaluator runs only after an authenticated
  Confidential Space launcher token has successfully authorized STS and KMS.
  It derives its measurement from that accepted token, holds four non-exportable
  purpose-specific P-256 private keys in memory, rejects arbitrary signing, and
  exposes no plaintext diagnostics. Its VPC has no external IP or NAT and
  denies all outbound traffic except HTTPS to Google's restricted API VIP for
  its pinned image, attestation, token exchange, KMS, and independently
  administered response/evaluation authority.
- Browser and iOS clients validate a fresh Google-PKI RS256 certificate chain,
  nonce and key binding, exact release/project/service account/image, secure
  boot, debug-off Intel TDX, approved Confidential Space OS version, empty
  command/environment overrides, `restart_policy == Always`, and memory
  monitoring off.
- Production configuration fails closed: the production profile forbids QA
  authentication and direct evaluation, requires the client relay, four
  distinct key pairs, signed policies, signed/public receipts, exact HTTPS
  destinations, and manifest-derived trust pins.
- The response store contains only ciphertext, wraps, commitments, and
  metadata. The live retention sweep removes expired auth data, scrubs provider
  diagnostics, and deletes resolved encrypted payloads after the declared
  period without rewriting public commitments.
- A redistributable Apache-2.0 source-export boundary, signed release/deployment
  manifests, SBOM/release-assembly provenance generation, toolchain verification, public
  well-known evidence, and a stateful external response-log/web-release monitor
  are implemented as release inputs.

## Verified in this worktree

The complete gate covers:

- deterministic evaluator properties, exhaustive small-group truth tables, and
  the full 3^9 conditional-response state space;
- browser, iOS, ordinary evaluator, and confidential evaluator cryptographic
  interoperability and canonical cross-platform vectors;
- malformed, truncated, wrong-key, wrong-policy, replay, duplicate, stale,
  late, revision-race, forged response authorization, interrupted
  certification, signed late-missing reconciliation, and plaintext-API
  rejection;
- signed policy, persisted result proof, web/iOS final-projection tampering,
  missing historical proof, result-key rotation, receipt, public-entry,
  hash-chain, fork, rewind, gap,
  key-change, redirect, oversized-response, and extra-field adversarial cases;
- valid and mutated web/iOS attestation certificate/JWT claims;
- isolated QA software-evaluator operation with exact signed release/key/
  measurement pins, plus production-profile and Release-build rejection;
- a built-Worker/D1 nine-account acceptance matrix with anonymous invite opens,
  correct and wrong accounts, both reply values, revisions, idempotent retries,
  deadline expiry, transparency publication, and storage assertions;
- iOS source contracts and native XCTest against the production verifiers;
- confidential evaluator startup, KMS/STS authorization, exact relay
  compatibility, fail-closed runtime claims, provenance-pinned vendored cores,
  and Terraform formatting/initialization/validation;
- schema-to-data-inventory coverage, scheduled retention, and sentinel scanner
  positive/negative tests.

The exact current counts belong in the signed release evidence rather than this
document, so they cannot become stale independently of a release.

## Data ordinary Herd infrastructure can read

Herd is account-linked, not anonymous. Ordinary account/event infrastructure
can read phone and profile data, event details, host rules, guest names and
membership, invitation/authentication/delivery records, frozen policies,
submission slot and timing, key commitments, ciphertext hashes/revisions, and
the final permitted event result. Network providers can see IP, timing, user
agent, origin, and fixed payload size.

It cannot read a compliant response's answer, invitee minimum, or required
person groups. Those values exist in readable form on the user's active device
and transiently inside the approved confidential evaluator. The exact database
inventory and retention schedule are machine-checked in
[`security/data-inventory.json`](../security/data-inventory.json) and
[`docs/data-retention-and-privacy-operations.md`](data-retention-and-privacy-operations.md).

## External activation still required

These are deployment/evidence actions, not missing product algorithms:

1. Build and publish the evaluator container by immutable digest, create the
   production Google Cloud projects/KMS/WIP/TDX resources, and perform the
   attestation/KMS/key-rotation/destruction drills with production authority.
2. Generate the three evaluator-epoch production keys, provision the separate
   lifetime-global response-log identity, and create a signed manifest, exact
   web/iOS artifacts, SBOM, and release-assembly provenance; promote those exact
   artifacts without a rebuild and publish the well-known/deployment
   statements. Publish component build provenance separately where available;
   assembly evidence alone does not prove a source-to-artifact build.
3. Publish the sanitized licensed source export and record its public commit and
   release tag. Never publish the private repository history containing
   third-party reference material or local operational artifacts.
4. Provision physically/logically separate production and QA origins,
   databases, auth roots, evaluator keys, release keys, and monitoring state.
   Existing preview/software-evaluator resources are test resources and must
   not be described or promoted as confidential production.
5. Run the live sentinel, database/log, restore, evaluator restart, rollback,
   and key-destruction exercises. Delete any legacy plaintext prototype data
   from live storage and let provider backup-retention windows expire.
6. Give the release/web/log monitor to an operator outside the production
   account and commission an independent review. A developer cannot make their
   own work “independently verified” by adding more self-authored tests.

Until those actions produce verifiable evidence, the source is technically
ready for production activation but the deployed privacy claim is not. A
client continues to fail closed when the manifest pins, signed policy, public
receipt, or fresh hardware attestation are absent.

## Honest product claim after activation

> Herd's ordinary services store your reply conditions only as sealed data.
> Your verified client can reopen your response, and a published, remotely
> attested evaluator processes it in isolated memory only to produce the result
> the frozen event permits. Herd still sees account, event, network, timing, and
> delivery metadata; the final outcome and real-world context can allow guesses.

Do not claim anonymity, zero knowledge, impossibility of inference, protection
from a compromised device, or source-to-deployment equivalence that the
published evidence does not actually establish.
