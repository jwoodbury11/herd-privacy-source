# Confidential evaluator deployment

This runbook builds and deploys one release of Herd's Node evaluator to Google
Confidential Space on Intel TDX. It is intentionally a controlled, two-phase
process because both private-key bundles must be encrypted before the container
is built, while KMS authorization must be pinned to the final container digest.

The commands below are instructions for an authorized operator. They were not
run while this implementation was created. `terraform apply`, Cloud KMS,
Firestore, Artifact Registry, Compute Engine, Cloud DNS, Cloud Armor, load
balancing, and certificate resources can incur charges. This design creates no
Cloud Router or Cloud NAT.

## 1. Prerequisites and separation of duties

Prepare two existing, billing-enabled projects:

1. `WORKLOAD_PROJECT_ID`: administered by the workload/operator team; and
2. `KEY_PROJECT_ID`: administered by an independent key custodian.

Record both numeric project numbers. Do not place either project under a shared
administrator if independent key release is part of the security claim. The
key custodian reviews the image digest and WIP condition before KMS access is
enabled.

Operators need current Terraform, Google Cloud CLI, Docker Buildx, `jq`, and a
DNS name. Use organization-managed identities; do not create or copy service
account keys. Application credentials and either private-key plaintext must
never be stored in this repository, Terraform variables/state, CI logs, shell
history, or container build arguments.

The key-custodian project must remain outside workload-operator administration.
Its named Firestore database is the monotonic policy, response-log, latest-member,
and evaluation-consumption authority, not an application cache. It stores only
opaque IDs, hashes, keys, revisions, deadlines, timestamps, and certifications;
never event/person display data or response ciphertext/plaintext. The key
custodian owns database administration and recovery; the workload operator and
VM service account receive no Firestore role.

Copy the example variables outside source control:

```sh
cd infrastructure/gcp-confidential-space
cp terraform.tfvars.example production.auto.tfvars
chmod 600 production.auto.tfvars
```

Fill the four project fields. Keep `runtime_enabled = false`. Decide whether
this stack is allowed to enable APIs; otherwise have administrators enable the
services listed in `locals.tf` and leave `manage_project_services = false`.

Use an encrypted, access-controlled remote Terraform backend for production.
The local backend is acceptable only for a disposable validation plan with no
secrets.

## 2. Create only the foundation

Initialize, validate, and save a reviewed plan:

```sh
terraform init
terraform fmt -check -recursive
terraform validate
terraform plan -out=foundation.tfplan
terraform show -no-color foundation.tfplan
```

The plan must contain no projects, billing resources, VM instances, Cloud
Router, Cloud NAT, Workload Identity Provider, or load balancer while
`runtime_enabled` is false.
It should contain the immutable Artifact Registry repository, workload service
account and minimal IAM, private network/subnet, KMS key ring/two wrapping keys,
and one named Firestore Native database with delete protection and point-in-time
recovery enabled, plus the four-permission custom appender role with no member
until the reviewed runtime digest exists. It must not create transparency log
documents yet.

After an independent review, the authorized operator may apply the exact saved
plan:

```sh
terraform apply foundation.tfplan
terraform output -raw artifact_repository
terraform output -raw kms_key_resource
terraform output -raw transparency_kms_key_resource
terraform output -raw workload_service_account
terraform output -raw workload_identity_provider_resource
terraform output -raw transparency_state_project_id
terraform output -raw transparency_state_database_id
terraform output -raw transparency_state_collection
```

Do not use `-auto-approve`. Confirm that the service account has only
`roles/confidentialcomputing.workloadUser` and repository reader access. It
must not have Cloud KMS decrypter, Firestore/Datastore, or logging writer roles;
KMS decryption and transparency-state access are granted later to the exact
attested federated identity.

## 3. Prepare the global log identity and evaluator-key epoch outside the repository

The transparency signing identity belongs to the full lifetime of
`herd-response-log-v1`; it does not belong to an artifact release or evaluator
key epoch. For the first production activation only, create a mode-0700 ceremony
directory in an approved encrypted workspace outside the checkout and generate
the global plaintext with exclusive mode-0600 creation:

```sh
node confidential-evaluator/scripts/generate-transparency-key-bundle.mjs \
  herd-response-log-v1.global \
  /approved/encrypted/log-ceremony/transparency-key.plaintext.json
```

Encrypt it with the independently protected transparency wrapping key:

```sh
gcloud kms encrypt \
  --project=KEY_PROJECT_ID \
  --location=us-central1 \
  --keyring=herd-evaluator-keys \
  --key=response-transparency-identity \
  --plaintext-file=/approved/encrypted/log-ceremony/transparency-key.plaintext.json \
  --ciphertext-file=/approved/encrypted/log-ceremony/transparency-key.ciphertext
```

Have independent custodians record the log ID, public key ID/point, ciphertext
hash, and wrapping-key resource, then destroy the plaintext with the approved
secret-destruction procedure. Every later artifact release and evaluator epoch
must reuse this same global identity. Copy the retained ciphertext into the
release directory and verify its approved hash; never run the transparency-key
generator again for routine rotation. Automatic KMS wrapping-key version
rotation and controlled rewrapping do not authorize a new log identity: after
any rewrap, attest and compare the exact public key ID/point before serving.

Choose an evaluator-key epoch identifier containing at most 80 letters, digits,
dots, underscores, or hyphens. In protocol v1 this identifier occupies the
legacy `releaseId` field. Create the epoch plaintext in the approved release
directory:

```sh
node confidential-evaluator/scripts/generate-key-bundle.mjs \
  herd-evaluator-epoch-YYYY-MM-DD \
  /approved/encrypted/release/key-bundle.plaintext.json \
  /approved/encrypted/release/request-authentication-token.txt
```

This produces three epoch-scoped P-256 keys and a high-entropy bearer token. Do
not reuse a key across cryptographic domains. An artifact-only rebuild within
the same evaluator epoch reuses this exact encrypted epoch bundle; a deliberate
epoch rotation creates a new one only after the application proves no
unresolved policy still depends on the old response-decryption key. Record only
public keys/IDs after the attested service exposes them; do not extract private
JWKs into application configuration.

The separate mode-0600 token file contains only the bearer shared with the
ordinary API. Move that token into the production application's protected
secret store before deleting the file. Never discard the only backend copy:
the browser relay capability, policy signing, transparency signing, and backend
attestation verification all require the same token sealed into the evaluator
bundle. The ordinary application receives no evaluator private JWK.

Encrypt the plaintext with the foundation KMS key. Substitute the exact IDs
from the Terraform output:

```sh
gcloud kms encrypt \
  --project=KEY_PROJECT_ID \
  --location=us-central1 \
  --keyring=herd-evaluator-keys \
  --key=key-bundle \
  --plaintext-file=/approved/encrypted/release/key-bundle.plaintext.json \
  --ciphertext-file=/approved/encrypted/release/key-bundle.ciphertext
```

Verify that the ciphertext file is non-empty. Have the key custodian validate a
single controlled decrypt before the WIP is locked down, then remove the
plaintext using the organization's approved secret-destruction procedure.
Ordinary file deletion is not guaranteed to erase data from SSD snapshots.
Retain both KMS ciphertexts and both protected wrapping keys; they are recovery
material. The separately wrapped transparency private key remains global even
when the three epoch keys change.

## 4. Create the non-secret deployment config

Copy `confidential-evaluator/release-config.example/deployment.json` to the same
approved release directory and fill these deterministic values:

- `releaseId`: exactly the evaluator-key epoch ID in the bundle;
- `policyMeasurement`: the stable, canonical `sha256:<64 lowercase hex>`
  protocol identity assigned to this evaluator-key epoch. Preserve it exactly
  for every artifact-only rebuild in the epoch; change it only with a reviewed
  epoch transition. For an existing epoch, retain the value already pinned by
  clients and frozen policies;
- `kmsKeyResource`: exact `terraform output -raw kms_key_resource`;
- `transparencyKmsKeyResource`: exact
  `terraform output -raw transparency_kms_key_resource`;
- `workloadIdentityProvider`: exact
  `terraform output -raw workload_identity_provider_resource` (the name is
  deterministic in the foundation phase even though the provider is created
  only in the runtime phase);
- `transparencyStateProjectId`, `transparencyStateDatabaseId`, and
  `transparencyStateCollection`: the three exact transparency outputs from the
  foundation state. Never point a release at a fresh/empty collection when a
  production log already exists;
- `attestationAudience`: the fixed HTTPS identifier relying parties will pin;
- `allowedOrigin`: the one exact HTTPS invitee-web origin. `null` disables the
  browser relay and is valid only for a server-only deployment; and
- the fixed paths, port, and launcher socket from the example unchanged.

The release BuildKit context must now contain exactly:

```text
/approved/encrypted/release/
├── deployment.json
├── key-bundle.ciphertext
└── transparency-key.ciphertext
```

`deployment.json` is not secret. The ciphertexts are safe to distribute only
because the KMS IAM policy is attestation-gated; still treat it as release
material and do not commit it.

`policyMeasurement` is a protocol compatibility identity, not proof of which
artifact ran. Keeping it stable prevents an artifact-only rebuild from
invalidating unresolved policies. The final container digest cannot be embedded
as its own security authority because that would be self-referential. At startup
the workload separately extracts `submods.container.image_digest` from the exact
launcher OIDC token that Google STS accepts, validates canonical
`sha256:<64 lowercase hex>` syntax, completes both WIP-authorized KMS decrypts,
requires both decryptors to report the identical attested image digest, and
uses that exact digest for subsequent WIF access. It also locally requires
production Confidential Space, disabled debug, secure boot, Intel TDX, Intel
attestation root, stable support, empty command/env overrides, restart policy
`Always`, and memory monitoring disabled. Only then
does it bind that digest into evaluator and policy-signing configuration. The
server never listens if any step fails. The WIP condition remains the
independent allowlist for the reviewed digest and repeats these production
checks before Google releases KMS access.

The official claim reference describes `tdx.gcp_attester_tcb_status` but does
not define a stable acceptable-value enum. This stack does not guess one. Add a
TCB-status condition only after the key custodian has authoritative current
Google/Intel values and a rollout policy; record that decision in the release
approval.

## 5. Build and push an immutable image

Select a supported, patched Node 22.13.0-or-newer Bookworm-slim base and resolve its registry
digest. Record an immutable value of the form:

```text
node:22.x.y-bookworm-slim@sha256:<64 lowercase hex>
```

Review the digest independently; do not pass a mutable tag alone. Authenticate
Docker to the foundation repository with short-lived Google credentials:

```sh
gcloud auth configure-docker us-central1-docker.pkg.dev
```

Build for Intel TDX (`linux/amd64`), attach maximum BuildKit provenance and an
SBOM, and push once under the immutable release tag:

```sh
docker buildx build \
  --platform=linux/amd64 \
  --build-context=release-config=/approved/encrypted/release \
  --build-arg=NODE_IMAGE='node:22.x.y-bookworm-slim@sha256:<verified digest>' \
  --provenance=mode=max \
  --sbom=true \
  --tag=us-central1-docker.pkg.dev/WORKLOAD_PROJECT_ID/herd-confidential-evaluator/evaluator:herd-evaluator-YYYY-MM-DD \
  --push \
  confidential-evaluator
```

The Dockerfile refuses an unpinned base, runs as UID 65532, and embeds only the
deployment config plus the two KMS ciphertexts. Artifact Registry has immutable
tags.

Resolve the pushed digest from Artifact Registry, never from local output:

```sh
gcloud artifacts docker images describe \
  us-central1-docker.pkg.dev/WORKLOAD_PROJECT_ID/herd-confidential-evaluator/evaluator:herd-evaluator-YYYY-MM-DD \
  --project=WORKLOAD_PROJECT_ID \
  --format='value(image_summary.digest)'
```

Require `sha256:` plus 64 lowercase hex characters. Inspect the manifest,
BuildKit provenance, SBOM, launch-policy labels, included file list, and base
digest. Sign the digest using the organization's approved keyless or HSM-backed
container-signing process, publish the signature/provenance, and independently
rebuild from the reviewed public source. Confidential Space attests the image
digest; it does not itself prove that public source produced that digest.

## 6. Pin an exact production Confidential Space VM image

Resolve the current production family to an exact image self-link:

```sh
gcloud compute images describe-from-family confidential-space \
  --project=confidential-space-images \
  --format='value(selfLink)'
```

Review that exact image against Google's current support status. Never store a
family alias in Terraform. The WIP additionally requires production `dbgstat`
and `STABLE`, so a debug or unsupported image cannot release the key bundle.

## 7. Plan the attestation gate and paid runtime

Edit `production.auto.tfvars`:

```hcl
runtime_enabled          = true
evaluator_slots = {
  blue = {
    image_digest   = "sha256:<pushed workload digest>"
    instance_count = 3
    serve_traffic  = true
  }
}
confidential_space_image = "<exact self-link from the previous step>"
evaluator_domain         = "evaluator.example.com"
```

Create and review a second saved plan:

```sh
terraform fmt -check -recursive
terraform validate
terraform plan -out=runtime.tfplan
terraform show -no-color runtime.tfplan
```

The key custodian must verify that the WIP condition, both KMS `principalSet`
grants, and custom Firestore appender-role principal set contain the exact
pushed digest.
That custom role must contain only `datastore.databases.get` and
`datastore.entities.create/get/update`; it must not contain entity delete/list
or database administration/import/export/clone/restore permissions. Its IAM
grant must be conditioned on `resource.name` equaling the one configured
transparency authority database, so those permissions cannot reach another
Firestore database in the key-custodian project.
Confirm that no workload service account or workload-operator principal has
Firestore access. Confirm production TDX, secure boot, stable support,
project/service-account pins, no command/environment overrides, `Always`
restart, and memory monitoring disabled. Confirm the VM template uses the same
digest, an exact production VM image, no external IP, no logging writer role,
and no mutable image tag.

Confirm the VPC has no default route, external VM IP, Cloud Router, or Cloud
NAT. Private DNS must map `*.googleapis.com` and `*.pkg.dev` to the four
`199.36.153.4/30` restricted-VIP addresses. Exactly one backend-tagged static
route may use `default-internet-gateway`, for `199.36.153.4/30`. A
higher-priority egress rule must allow TCP 443 only to that range, followed by
a deny-all IPv4 rule. Require one response policy bound to the evaluator VPC:
`googleapis.com.`, `*.googleapis.com.`, `pkg.dev.`, and `*.pkg.dev.` must use
`bypassResponsePolicy` so the private zones continue resolving, and the
less-specific `*.` local-data rule must return only `0.0.0.0`. The subnet must
keep Private Google Access enabled. Do not add a `0.0.0.0/0` route or any other
API route for startup troubleshooting. Every Herd runtime URL and the image
registry are covered by the private `googleapis.com` and `pkg.dev` zones.
Inspect effective
organization/folder and network firewall policies and the full effective route
table too: no higher-level allow, policy-based route, peering, VPN,
Interconnect, dynamic route, or additional Google API route may bypass this
baseline. The instance interface must remain `IPV4_ONLY`; enabling IPv6
requires a separately reviewed IPv6 deny/allow and route design.

The restricted VIP and this DNS policy do not by themselves stop a workload
from using an allowed Google API to reach a resource in another project. Before
production, the independent organization administrator must place the required
projects and supported services in an enforced VPC Service Controls perimeter,
review every ingress and egress exception, and provide evidence of both an
allowed in-perimeter request and a denied cross-project request. The Terraform
module deliberately does not claim to create or validate that organization-
level boundary.

The source commit/tree digest belongs in published release provenance, not in
the stable policy measurement. The provenance and reproducible-build record
must map that reviewed source to the exact WIP-pinned attested container digest.

After cost and security approval, apply exactly that plan:

```sh
terraform apply runtime.tfplan
terraform output -raw load_balancer_ip
terraform output -raw container_image_reference
terraform output -raw attestation_condition
```

Create the evaluator domain's DNS A record with `load_balancer_ip`. Google
Managed Certificate provisioning remains pending until DNS points to the load
balancer. Do not route production traffic until the certificate is active and
all MIG instances are healthy.

## 8. Acceptance gates

From a clean network, verify:

1. HTTPS is valid and HTTP/port 80 is not exposed.
2. `/healthz` reports four unique key IDs/public points and one binding hash;
   the transparency key ID/point exactly equals the lifetime-global log record.
3. Unauthorized policy-signing and transparency-append POSTs return 401 with
   no distinguishing detail. Authenticated `POST /api/v1/evaluate` returns 404;
   the production direct-evaluation route does not exist. Relay and challenge
   attestation remain the two intentionally public capability/proof paths.
4. A direct, bearer-free random 32-byte challenge returns a Google PKI token
   containing the caller nonce and the recomputed key-binding hash. Cloud Armor
   enforces its dedicated 60-per-minute per-source throttle.
5. An independent verifier enforces the complete claims list from
   `docs/confidential-evaluator-api.md`, including the exact image digest.
6. Policy, receipt, log-head, and evaluation signatures verify only with their
   attested keys and domain prefixes; cross-domain verification fails.
7. The existing no-response relay fixture returns the expected aggregate result
   and a valid bound relay attestation.
8. Invitee-web can send its existing encrypted client-relay fixture directly to
   `/api/v1/relay/` with no bearer header and accept the response unchanged.
   Verify that a capability made with any token other than the encrypted bundle
   token is rejected.
9. Policy registration is immutable/idempotent and Firestore contains no event
   title, name, phone, location, address, or description. The stateful append
   authority rejects arbitrary JSON, direct `receipt` or `log_head` signing,
   wrong key IDs, malformed hashes, forged Ed25519 response authorization,
   changed enrolled keys, non-next revisions, noncanonical fields, inconsistent
   entry hashes, gaps, stale indexes, late/consumed appends, and wrong previous
   hashes. An exact already committed receipt retry still succeeds after the
   deadline and evaluation consumption.
   Race two different valid index-1 receipts through separate evaluator
   replicas and require exactly one success; retry the winner after restarting
   every replica and require byte-identical stored receipt/head signatures.
10. Simulate lost responses after append and evaluation commits and require
    exact retries to recover the stored certification/consumed batch. Confirm
    tail, immutable entry, member latest state, and policy response sequence are
    one atomic CAS. Race a deadline-edge last receipt against consumption and
    require exactly one snapshot to win. Omitted/null/stale/chosen subsets must
    fail before envelope decryption. Confirm no stateless fallback exists when
    Firestore is unavailable.
11. Confirm the public transparency endpoint is monitored by an independent
    witness for rollback, suppression, and conflicting heads. The authority
    prevents ordinary backend equivocation, but key-custodian administration
    remains a trust boundary.
12. No private key, token, decrypted response, request body, or container output
   appears in Cloud Logging, serial logs, load-balancer logs, Terraform state,
   provenance, SBOM, or image history.
13. From a backend VM, DNS resolves `restricted.googleapis.com` to exactly
    `199.36.153.4` through `.7`, service names under `googleapis.com` through
    that restricted name, and the regional `pkg.dev` registry through the same
    VIP. An arbitrary external A-name returns only `0.0.0.0`, with no usable
    AAAA answer. Approved API calls and image pulls succeed, while a third-party
    HTTPS destination and an arbitrary public IP have no route. Verify the one
    tagged static route, response-policy rule set, and allow-before-deny
    firewall priorities from the deployed control plane; do not add NAT or
    enable firewall logging for the test.
14. Under the independently enforced VPC Service Controls perimeter, exercise
    a permitted request to each required supported service and a deliberately
    unauthorized cross-project read and write. Require the permitted requests
    to succeed, the cross-project requests to be denied by the perimeter, and
    the organization administrator to retain the policy and audit evidence.
    Network reachability through `restricted.googleapis.com` is not sufficient
    evidence for this gate.

Only after all gates pass should the application pin the attested public keys,
key-binding hash, stable policy measurement, exact attested image digest,
evaluator-key epoch ID, artifact release ID, and evaluator URL. Artifact-only
cutovers may use the runbook's bounded two-digest transition only when the
encrypted epoch/global bundles, public keys, key IDs, and `policyMeasurement`
are identical. An evaluator-key epoch may rotate only after every policy frozen
to its response-decryption key has resolved.

## Official references

- [Direct resource access with Confidential Space](https://cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)
- [Custom audience and PKI attestation tokens](https://cloud.google.com/confidential-computing/confidential-space/docs/connect-external-resources)
- [Confidential Space attestation claims](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Workload metadata variables](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables)
- [Launch policies](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies)
- [Intel TDX supported configurations](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
- [Configure Private Google Access](https://cloud.google.com/vpc/docs/configure-private-google-access)
- [Artifact Registry restricted VIP DNS](https://cloud.google.com/artifact-registry/docs/gke-private-clusters)
- [Cloud DNS response policies](https://cloud.google.com/dns/docs/zones/manage-response-policies)
- [VPC Service Controls overview](https://cloud.google.com/vpc-service-controls/docs/overview)
- [VPC firewall always-allowed metadata traffic](https://cloud.google.com/firewall/docs/firewalls#always_allowed_traffic)
- [Cloud KMS decrypt REST method](https://cloud.google.com/kms/docs/reference/rest/v1/projects.locations.keyRings.cryptoKeys/decrypt)
- [Firestore atomic commit REST method](https://cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit)
- [Firestore database delete protection and Terraform](https://cloud.google.com/firestore/docs/manage-databases)
- [Workload Identity Federation principal sets](https://cloud.google.com/iam/docs/workload-identity-federation)
- [Firestore IAM roles and individual permissions](https://cloud.google.com/iam/docs/roles-permissions/firestore)
