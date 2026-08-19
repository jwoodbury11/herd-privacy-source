# Confidential evaluator operations runbook

> Protocol-v1 compatibility runbook. Use this only for the isolated evaluator and installed legacy
> clients during the bounded migration window. Current clients use the account-wide ballot path.

This runbook covers a deployed release of the Confidential Space evaluator.
It assumes the release passed `docs/confidential-evaluator-deployment.md` and
that the application pins its image digest, artifact release ID, evaluator-key
epoch ID, key-binding hash, four public keys, and fixed attestation audience.
The transparency public key is the lifetime-global identity of
`herd-response-log-v1`; the other three keys belong to the evaluator epoch.

## Service objectives and safe signals

Use only aggregate, non-payload telemetry:

- HTTPS load-balancer availability and latency;
- MIG healthy/target instance counts and replacement rate;
- Google Managed Certificate state and expiry;
- restricted-Google-API private-zone, response-policy, static-route, and
  firewall drift;
- Cloud KMS/WIP allow and deny counts plus aggregate Firestore availability and
  conditional-write failures in the independently administered key project;
  and
- client-side counts of generic status codes and attestation-verification
  failures, without event IDs, policy documents, ciphertexts, tokens, or bodies.

Container stdout/stderr redirection, serial output, backend-service request
logging, and memory monitoring are deliberately off. The deployment has no
Cloud NAT or router and therefore no translation logs.
Do not turn them on to diagnose production. The workload emits only a generic
startup failure before exiting; repeated MIG replacement plus failed health is
the intended signal for a fail-closed configuration.

Suggested alerts:

- no healthy backend for two consecutive health intervals;
- healthy instances below target for five minutes;
- certificate not `ACTIVE` or within the organization's renewal threshold;
- sustained 5xx above 1%, or any unexpected 401/403 step change;
- WIP/KMS deny spike, provider policy change, KMS IAM change, Firestore IAM
  change, delete-protection change, VPC Service Controls perimeter/exception
  change, or unexpected database administration;
- VM template, WIP digest, KMS principal-set digest, and approved release digest
  no longer all equal; and
- any attempt to enable logs, memory monitoring, command/env overrides, debug
  Confidential Space, a non-TDX machine, a restart policy other than `Always`,
  or a mutable container reference.

## Routine health check

1. Confirm the DNS A record still equals `terraform output load_balancer_ip`.
2. Confirm the managed certificate is active.
3. Confirm MIG target and healthy counts agree across the configured zones.
4. Fetch `GET /healthz`; require 200, `no-store`, the expected release ID, four
   unique keys, and the pinned key-binding hash.
5. Fetch `GET /readyz`; require 200. Readiness performs an authenticated read
   of the durable Firestore tail and its matching immutable entry, then proves
   the instance can still use its in-memory transparency signing key; a
   missing, inaccessible, inconsistent, or unusable state is an outage.
6. Do not treat health as trust evidence. Confirm the separately operated
   monitor sent a fresh random 32-byte challenge directly to public
   `POST /api/v1/attestation`, without the ordinary-backend bearer, and
   independently validated the returned PKI token and key binding against its
   offline root pin.
7. Require the attested image digest and all production claims to equal the
   release record. A valid TLS certificate with a failed attestation is an
   outage, not a degraded-trust mode.
8. Compare the latest public response-log head with at least one independent
   witness/gossip view. Two different hashes for the same log ID/tree size are
   an incident even when both signatures verify.

Never paste the bearer token into an interactive command, ticket, chat, or
dashboard. Challenge attestation does not require it; policy signing,
transparency append, and relay evaluation retain their normal secret boundary.
The production image has no direct evaluation endpoint.

## Diagnosing startup and KMS release failures

The service starts listening only after the exact STS subject token passes its
local production-claim checks (including restart policy `Always`), STS/WIP and
KMS authorization succeed, the exact attested image digest is bound to runtime
resource access, both independent KMS plaintext CRC32Cs are verified, four unique
keys are imported, both decryptions report the same attested image digest, and
the same attested WIF principal can read the Firestore transparency tail. If all
instances churn or stay unhealthy, compare only public configuration:

1. VM template `tee-image-reference` equals the approved `@sha256` reference.
2. Artifact Registry still contains that digest and the launcher service
   account retains repository reader plus
   `roles/confidentialcomputing.workloadUser`.
3. VM uses the exact production Confidential Space image, TDX, secure boot,
   `TERMINATE` maintenance, no external IP, and the expected project/service
   account.
4. WIP provider is enabled and its condition contains the same digest, project,
   service account, and production claims.
5. Both KMS wrapping keys contain the principal set for that digest in the key
   project number, not the workload project number.
6. `deployment.json` contains both exact KMS resources and the WIP resource,
   matches the evaluator-epoch bundle's legacy `releaseId`, and contains the
   reviewed stable `policyMeasurement` for that epoch. This compatibility value
   is not attestation evidence. The exact artifact digest still comes only from
   the STS-accepted token and must independently match the WIP/IAM rollout set.
7. Both binary KMS ciphertexts are present and non-empty in the image. The
   transparency ciphertext decrypts to the fixed `herd-response-log-v1` bundle
   and approved lifetime-global key ID/point.
8. STS, KMS, Firestore, Artifact Registry, Confidential Computing, Compute, and
   IAM APIs are enabled; Private Google Access is enabled; private DNS maps
   `*.googleapis.com` and `*.pkg.dev` to `199.36.153.4/30`; the VPC response
   policy bypasses only the apex and wildcard forms of those namespaces and
   maps the less-specific `*.` A-name to `0.0.0.0`; tagged static routes and
   TCP-443 egress allow cover only that restricted VIP; and the following deny
   rule blocks every other IPv4 destination. There must be no default route,
   external VM IP, Cloud Router, or Cloud NAT. Inspect effective
   organization/folder and network firewall policies plus the full effective
   route table; no higher-level allow, policy-based route, peering, VPN,
   Interconnect, dynamic route, or additional Google API route may bypass the
   VPC rules and one tagged static route.
9. The independent organization administrator confirms the required projects
   and supported APIs remain inside the enforced VPC Service Controls perimeter
   with no unreviewed ingress or egress exception. Re-run one allowed
   in-perimeter request and one denied cross-project read/write test. DNS and
   route controls alone do not prove this boundary, and this Terraform module
   does not manage it.
10. The named database/collection match `deployment.json`; delete protection and
   PITR remain enabled; and only the exact image-digest principal set has the
   custom appender role. Require exactly database-get plus entity
   create/get/update permissions; the role must exclude delete/list and every
   database administration permission. The VM service account must not have
   that role.

Do not decrypt the bundle on a VM, add a service-account KMS/Firestore role,
reset the transparency collection, enable debug images, loosen the WIP
condition, add an env override, or enable container logs as a shortcut.
Reproduce with generated test keys in a separate non-production project and
build a new reviewed digest.

## Attestation verification failures

Classify failures without accepting the response:

- **nonce mismatch:** reject as replay/misbinding; generate a new challenge;
- **key-binding mismatch:** reject all four keys; compare canonical field order
  and domain prefix, then investigate release routing;
- **digest/project/service-account mismatch:** immediately stop routing; this is
  an unauthorized workload even if every other claim is valid;
- **debug, non-TDX, insecure boot, non-STABLE, overrides, logging, or monitoring:**
  stop routing and begin incident response;
- **restart policy not `Always`:** startup must fail before readiness and KMS
  should deny the token; do not relax either check; or
- **expired/not-yet-valid/certificate-chain failure:** reject and inspect clock,
  pinned PKI root lifecycle, and Google status; never skip validation; or
- **quota/provider timeout:** return unavailable and back off. Google attestation
  token issuance is rate limited, so cache only a token already verified for
  its exact audience/key binding until shortly before expiry; never reuse a
  caller-specific nonce response for another caller.

## Policy, response, and evaluation authority failures

The Firestore policy, latest-member document, tail, and per-index entry are one
monotonic authority. A response append creates the immutable entry and
CAS-updates the tail, policy response sequence, and member revision/key in one
atomic commit. Evaluation CAS-consumes that same policy for one exact complete
batch before decryption. Never enable a memory-only signer, separate
head-signing endpoint, backend-selected batch bypass, direct production
evaluation endpoint, or "continue without transparency" mode.

- **409 `transparency_conflict`:** stop new response submissions. Compare the
  D1 tail, Firestore tail/entry, public endpoint, and independent witness. A
  concurrent exact retry is not a conflict; it returns byte-identical stored
  signatures.
- **409 `transparency_late_missing_entry`:** verify the proof payload hash and
  `HERD-TRANSPARENCY-RECONCILIATION-SIGNATURE-V1` P-256 signature with the
  attested lifetime-global transparency key. Require the rejected index/hash
  and authority predecessor to match the local pending entry exactly. This
  proves only that a fully valid candidate was never committed before the
  window closed; it does not make the response eligible. Automated recovery may
  abandon only the wholly uncertified local suffix anchored to that signed
  predecessor. A missing/invalid proof, any certified row in the suffix, or any
  mismatch is a permanent conflict and requires investigation.
- **lost/timeout response:** retry the exact canonical receipt. The evaluator
  re-reads Firestore and returns the committed bytes if the atomic write won.
  Do not create a new envelope or advance D1 to work around uncertainty.
  Evaluation preparation also drains up to 64 oldest pending exact receipts per
  pass before choosing any batch, then fails closed for a later retry if more
  remain. A generic signer `409` is a permanent transparency conflict and must
  not be flattened into the transient-unavailable path; only the exact signed
  late-missing disposition above permits bounded local reconciliation.
- **response key/revision conflict (legacy v1 only):** do not reset the authority document or
  invent a revision. Confirm the client receipt includes the exact Ed25519
  public key/signature and has revision 1 or previous + 1. Within an epoch the
  response key must remain unchanged. A phone-verified device switch must rotate
  the account-key epoch and response key together; changing only one is invalid.
- **deadline/consumption conflict:** new receipts are forbidden after the
  authority clock deadline and after canonical batch consumption. An exact
  already committed receipt retry remains valid. Do not change the deadline or
  clear the consumed batch hash.
- **evaluation batch conflict:** compare every proposed slot with the exact
  Firestore member documents and each member's referenced signed immutable
  entry. Omitted/null-substituted responses, stale revisions, changed response
  keys, corrupted member indexes, and alternate batch hashes must remain
  rejected. A crash retries only the exact consumed batch hash.
- **readiness 503:** treat as an outage. Check STS/WIF, the exact digest IAM
  principal, database/collection configuration, Firestore availability, and
  tail-entry consistency without granting the VM service account access.
- **D1 behind Firestore:** this can follow D1 rollback or a malicious/accidental
  direct append through the authenticated API. Freeze submissions and
  reconcile from immutable receipts/public witnesses. Never rewind Firestore
  to make D1 fit.
- **Firestore behind the public log:** treat as custodian rollback or data
  corruption. Freeze the log, revoke all writer authorization, and begin
  incident recovery; do not sign from the older tail or swap keys in place.
- **tail key ID or signature differs from the configured global identity:**
  readiness must remain failed. Treat it as a log-fork/key-substitution incident,
  preserve the maximum independently witnessed head, and do not reset the
  collection.

The ordinary backend cannot create a later valid revision after a genuine
response key is enrolled. It can still front-run a never-enrolled slot with its
own key or suppress a genuine submission, causing integrity failure or visible
denial; the current SMS trust path has no independent direct client identity
enrollment capable of preventing that first write. It cannot choose a head,
gap the sequence, replace a committed index, reset the tail/policy, evaluate
alternate subsets, or access Firestore directly. Key-custodian administrators
can change IAM/data and remain an explicit trust boundary; independent
witnesses are the external detection layer.

## Release and key rotation

Response-decryption keys are frozen into event policies. Replacing a release
in place would make unresolved events encrypted to the old key undecryptable.
Artifact releases, evaluator-key epochs, KMS wrapping-key versions, and the
global log identity are four different lifecycles:

- An **artifact-only release** changes reviewed code/image provenance but reuses
  the exact evaluator-epoch bundle and global transparency identity.
- An **evaluator-key epoch** rotates the bearer token plus response-decryption,
  evaluation-result, and policy-signing keys only after the application proves
  that no unresolved policy depends on the old response-decryption key.
- A **KMS wrapping-key version** may rotate or rewrap either ciphertext without
  changing any P-256 public key. Verify the attested public metadata is unchanged
  before resuming.
- The **global transparency identity** never rotates in place for
  `herd-response-log-v1`.

Use the bounded zero-unavailable procedure below only for an artifact-only
release that reuses the byte-identical encrypted epoch and global bundles and
the identical `releaseId`, `policyMeasurement`, four key IDs, four public keys,
and key-binding hash. Any uncertainty or any epoch/global-identity change uses
the serving-off procedure that follows.

Artifact-only same-epoch rollout:

1. Capture the old digest, D1 tail, Firestore tail, public head, and independent
   witness head; require exact agreement. Build and approve the new immutable
   image and prove its embedded ciphertext hashes and stable policy identity
   equal the old release.
2. Add a new `evaluator_slots` entry (alternate `blue` and `green`) with the new
   digest, three instances, and `serve_traffic = false`. Do not edit or remove
   the serving slot. Review that the plan creates a separate template and MIG,
   leaves it detached from the public backend, and authorizes exactly the old
   and new digests.
3. Apply while continuously probing `/readyz`. Prove every candidate instance
   through a temporary, access-restricted validation path, then require its
   exact attestation digest. A failed candidate must leave the serving MIG
   untouched; remove only the candidate slot and grants. Never attach a new
   digest while released clients still pin only the old digest.
4. After released clients accept both exact digests, set the candidate's
   `serve_traffic` to true in a reviewed apply and require both slots healthy.
   In the next reviewed apply, set the old slot's `serve_traffic` to false and
   then its `instance_count` to zero. Require the candidate to remain healthy
   throughout. In a later apply, remove the empty old slot and revoke its
   digest. Reconfirm tails, witnesses, policy creation, response certification,
   and evaluation after every phase.
5. Never change a slot's digest in place, remove the serving slot while creating
   its candidate, or use two slots to bridge an epoch change. Two authorized
   digests are a short-lived, explicitly reviewed maximum.

Evaluator-key epoch or uncertain transition (serving off):

1. Freeze new submissions and policy creation. Capture the D1 tail, Firestore
   tail, public head, and independent witness head and require exact agreement.
2. For an epoch change, additionally prove through the application epoch gate
   that the old epoch has zero pending/frozen policies, in-flight submissions,
   and unresolved evaluation work. An emergency is not permission to skip this
   proof: cancel/finalize affected events or use a separately reviewed isolated
   recovery procedure.
3. Remove serving traffic, scale the old MIG to zero, wait for every old instance
   to terminate, and revoke the old digest's WIP/KMS/Firestore grants. Revoking
   KMS alone cannot erase keys already loaded in a running TEE.
4. Build and approve the new immutable artifact. For an uncertain artifact-only
   release, embed the existing epoch and global ciphertexts. For an epoch change,
   generate only the three new epoch keys and bearer token, but embed the
   existing global transparency ciphertext and assign the new reviewed stable
   policy measurement.
5. Authorize only the new exact image digest, deploy it, and require startup
   readiness to verify the existing Firestore tail under the same global log
   key. Compare fresh attestation, artifact release ID, epoch ID, all four public
   keys, and the expected global transparency key.
6. Reconcile D1, Firestore, public publication, and witnesses again; then reopen
   policy creation, submissions, and serving.
7. Retain required public metadata, attestations, signatures, ciphertexts, and
   wrapping-key history. Never retain plaintext JWKs or destroy old epoch
   recovery material before its retention gate passes.

Availability deliberately pauses during the epoch ceremony. Never use blue/
green slots to bridge two evaluator-key epochs: revoking KMS does not remove key
material already loaded in a running TEE.

### Global transparency-key compromise

A suspected leak, unauthorized signature, key substitution, or conflicting
valid head permanently seals `herd-response-log-v1`. Immediately freeze
submissions and publication, revoke every attested Firestore/KMS writer, stop
all evaluator instances, preserve the maximum witnessed chain and audit
evidence, and mark the log compromised. Recovery requires reviewed code and a
new protocol/log ID, a new Firestore authority namespace, a one-time global-key
ceremony, new signed trust metadata, and independent witness/gossip bootstrap.
Never start again at index 1 under the old log ID and never present an in-place
key replacement as continuity.

## Rollback

Rollback is allowed only to a previously approved immutable digest and its
matching evaluator-epoch ciphertext, global-transparency ciphertext, WIP
condition, four-key trust record, and exact Confidential Space image. A tag is
never a rollback target. Apply the same serving-off, revoke-old-before-
authorize-new ceremony; rollback is not permission for overlapping writers.

Before rollback:

1. establish that the previous release remains authorized and has keys for the
   affected frozen policies;
2. verify its attestation fresh, including current support/time claims;
3. re-run the Terraform plan and have the key custodian compare every digest;
4. restore application trust/routing before sending requests; and
5. retain the failed release for forensic comparison without decrypting its
   bundle outside a TEE.

If the prior image is no longer `STABLE`, its certificate/attestation cannot be
validated, or its KMS authorization was retired, do not weaken controls to
restore it. Deploy a new fixed release and accept an outage.

## Suspected compromise or unauthorized change

Treat any of the following as an incident: unexpected image/WIP/KMS digest,
unknown public key, attestation claim downgrade, leaked bearer token,
release-assembly evidence failure, a mismatch in separately published
component build provenance, conflicting signed response-log heads, unexpected
Terraform drift, or evidence of private response/key exposure.

Contain in this order:

1. Stop application routing and reject the release's attestations/public keys.
2. In the key-custodian project, remove the release digest's KMS and Firestore
   IAM members or disable its WIP provider. This prevents new instances from
   decrypting the bundle or mutating the tail; already-running instances may
   retain keys/tokens in memory.
3. Set the MIG target to zero or detach its backend after preserving public
   resource metadata. Do not rely on this before revoking KMS release.
4. Preserve Terraform plans/state, image manifest/digest, provenance, SBOM,
   public key metadata, attestation tokens, IAM audit logs, and KMS/WIP audit
   events. Never collect process memory, plaintext bundles, decrypted RSVPs, or
   request bodies.
5. Classify the affected key domain. A bearer-token or evaluator-epoch key leak
   requires a new three-key epoch bundle and image, but outstanding policies
   must first be cancelled/finalized or handled through reviewed isolated
   recovery; do not strand them silently. A transparency-key compromise follows
   the new-log ceremony above and never rotates in place.
6. Determine which event policies and receipts reference the affected key IDs;
   do not silently re-encrypt, reinterpret, or re-sign historical data.
7. Reconcile any emergency console/gcloud change back into Terraform before the
   next ordinary apply.

KMS revocation is not retroactive erasure of keys already released into a live
TEE. Network isolation, backend removal, instance shutdown, application trust
revocation, and domain-specific key response are all required containment layers.

## Disaster recovery

Required recovery material is:

- protected Terraform state and reviewed plans;
- exact container and Confidential Space image digests;
- Artifact Registry manifest, provenance, SBOM, and signature;
- evaluator-epoch and global-transparency KMS ciphertext bundles;
- the non-secret deployment config;
- enabled, recoverable KMS wrapping-key versions and their audited IAM history;
- the Firestore database configuration/IAM audit history, immutable entry
  export, and the highest independently witnessed public head; and
- public release/key-binding metadata and application routing records.

Test recovery with generated data in another pair of projects. Never test by
exporting production keys—Cloud KMS keys are not exportable, and a destroyed or
disabled key version can make the encrypted bundle permanently unrecoverable.

PITR and backups are forensic/recovery inputs, not permission to rewind the
production authority. Restore or clone into an isolated database, validate the
entire chain through the highest independently witnessed tree size, and compare
every stored signature. Do not route a signer to a recovered tail below any
previously signed/published head: that would make a new fork possible. If the
authoritative database cannot be proven current, revoke the affected release,
freeze submissions, reconstruct the maximum witnessed chain under custodian
review, and resume only through a separately approved recovery procedure.

## Decommissioning checklist

Before removing a release, prove all of the following:

- no pending/frozen event references its response-decryption key;
- no accepted result/policy still requires online epoch-key
  discovery beyond the retained public record;
- retention and legal requirements are met;
- application routing and trust no longer include the release;
- the key custodian has removed both KMS decrypter grants for its digest;
- the key custodian has removed Firestore writer authorization for its digest;
- and the MIG is drained and no instance is running.

KMS, Firestore, and Artifact Registry resources have destruction prevention.
Do not bypass it as part of routine decommissioning. Archive public evidence,
the maximum witnessed tail, and ciphertexts, then follow a separately approved
epoch-key destruction procedure if policy requires cryptographic erasure. Never
destroy the global transparency identity as part of retiring one evaluator
epoch while `herd-response-log-v1` remains active.
