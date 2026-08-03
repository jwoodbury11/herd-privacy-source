# Google Confidential Space infrastructure

This Terraform package defines the recommended two-project production boundary:

- an existing **workload-operator project** owns Artifact Registry, a private
  VPC with restricted-Google-API-only egress, a regional Intel TDX managed
  instance group, Cloud Armor, and an external HTTPS load balancer; and
- an existing, independently administered **key-custodian project** owns Cloud
  KMS, a deletion-protected named Firestore database, and a Workload Identity
  Pool whose policy authorizes one exact workload image digest.

It never creates projects, billing accounts, DNS records, credentials, or a
container image. Running `terraform apply` creates billable resources. No apply
was run while creating or testing this package.

## Two phases

`runtime_enabled = false` is the foundation phase. It creates independent KMS
wrapping keys for the evaluator-epoch bundle and lifetime-global response-log
identity, a deletion-protected/PITR-enabled Firestore database, immutable-tag
Artifact Registry repository, workload service account, network, and subnet.
Those deterministic outputs are needed to encrypt both private-key bundles,
configure the durable transparency authority, and build the final container.
Both wrapping keys rotate versions every 90 days; this does not rotate the
P-256 keys inside either ciphertext.

After the image is pushed, set:

```hcl
runtime_enabled           = true
image_digest              = "sha256:<64 lowercase hex>"
confidential_space_image  = "<exact production image self-link, not a family>"
confidential_space_swversions = ["<signed eight-digit swversion>"]
evaluator_domain          = "evaluator.example.com"
```

The runtime phase then creates:

- an OIDC provider for Google Cloud Attestation;
- direct decrypt access to both Cloud KMS wrapping keys and a four-permission
  Firestore appender role for only the exact `attribute.image_digest` principal
  set, conditioned on the exact configured authority database resource name;
  the appender can get that database and create/get/update exact entities, but
  cannot reach another database, delete/list entities, or
  administer/import/export/clone/restore the database;
- production `c3-standard-4` Intel TDX VMs across three supported
  `us-central1` zones, with secure boot and no external IPs;
- no external IP or Cloud NAT, a deny-all outbound firewall, and one HTTPS
  route to `restricted.googleapis.com` for Artifact Registry, STS, KMS,
  Firestore, and attestation;
- a regional MIG with autohealing and replacement-only updates; and
- a no-CDN HTTPS load balancer with Cloud Armor throttling.

The Workload Identity Provider requires all of these claims at once:

- `CONFIDENTIAL_SPACE`, production `dbgstat`, secure boot, `GCP_INTEL_TDX`,
  Google OEM `11129`, and the exact singleton `attester_tcb = ["INTEL"]`;
- the `STABLE` Confidential Space support attribute;
- exactly one release-approved Confidential Space `swversion`;
- the exact workload container digest, workload project, and attached service
  account, with no additional service account accepted;
- no command or environment overrides;
- restart policy `Always`; and
- memory monitoring disabled with no additional monitoring mode accepted.

Container launch-policy labels independently forbid command/environment,
capability, cgroup, and mount overrides and forbid log redirection and memory
monitoring. The WIP check is still required: labels constrain the operator,
while attestation lets the key custodian verify what actually launched.

Private Cloud DNS zones force every `*.googleapis.com` call and every
`*.pkg.dev` image pull to `199.36.153.4/30`. A network-bound Cloud DNS response
policy bypasses only the apex and wildcard forms of those two namespaces so
the private zones can answer; its less-specific `*.` rule returns `0.0.0.0` for
every other A-name lookup. A higher-priority firewall rule allows only TCP 443
to that restricted VIP; the next rule denies every other IPv4 destination. The
network is created without a default route. Its only tagged default-gateway
route covers that `/30`. Google Cloud's metadata server remains reachable
outside VPC firewall enforcement for DHCP, DNS, NTP, instance metadata, and the
launcher. Every Herd runtime endpoint is under the forced `googleapis.com` or
`pkg.dev` zones, so the workload cannot resolve third-party names or route to
third-party services, unrestricted Google API endpoints, or any additional
Google API range.
Ingress response traffic remains valid because Google VPC firewall rules are
stateful. Before production, inspect effective hierarchical and network
firewall policies and the complete effective route table: no higher-level
allow, policy-based route, peering, VPN, Interconnect, dynamic route, or
additional Google API route may bypass this local baseline.

This Terraform is a network baseline, not a complete Google-API data-exfiltration
boundary. Calls to supported APIs still traverse the shared restricted VIP, so
cross-project access must be independently constrained with an organization-
administered, enforced VPC Service Controls perimeter and reviewed ingress and
egress rules. This module does not create or prove that perimeter. Production
approval must include a negative cross-project access test and evidence from
the organization administrator that the required projects and restricted
services are inside the enforced perimeter.

The VM service account has no Firestore or KMS role. The exact attested image
uses its launcher OIDC token to obtain a short-lived WIF token and performs
exact-document Firestore operations for immutable policy registration,
authenticated response append (entry, tail, policy sequence, and member latest
state in one CAS), and one-time complete-batch evaluation consumption. The
custom role still contains only database get plus entity create/get/update; it
is conditioned on the exact configured database and cannot list, delete,
administer, import, export, clone, or restore. The ordinary
application API has no Firestore credential or route for deletion, reset, or rollback. A key
custodian administrator can still change IAM or data and is therefore an
explicit trust boundary checked by public witnesses.

## Validation

The configuration is formatted and validated with Terraform 1.15.8 and the
locked Google provider. Re-run before every plan:

```sh
terraform fmt -check -recursive
terraform init -backend=false -input=false -lockfile=readonly
terraform validate
```

Use a protected remote backend for real environments. Terraform state contains
resource identifiers and policy but must never contain either plaintext bundle,
the bearer token, or any private JWK. The global transparency identity must be
reused across every evaluator epoch for `herd-response-log-v1`; replacing it
requires a new log ID/protocol and a separate incident ceremony.

The exact controlled deployment sequence is in
[`docs/confidential-evaluator-deployment.md`](../../docs/confidential-evaluator-deployment.md).

Primary references:

- [Confidential Space: create and grant access to confidential resources](https://cloud.google.com/confidential-computing/confidential-space/docs/create-grant-access-confidential-resources)
- [Confidential Space workload metadata](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/metadata-variables)
- [Confidential Space launch policies](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies)
- [Intel TDX supported configurations](https://cloud.google.com/confidential-computing/confidential-vm/docs/supported-configurations)
- [Attestation token claims](https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims)
- [Configure Private Google Access](https://cloud.google.com/vpc/docs/configure-private-google-access)
- [Artifact Registry restricted VIP DNS](https://cloud.google.com/artifact-registry/docs/gke-private-clusters)
- [Cloud DNS response policies](https://cloud.google.com/dns/docs/zones/manage-response-policies)
- [VPC Service Controls overview](https://cloud.google.com/vpc-service-controls/docs/overview)
- [VPC firewall semantics](https://cloud.google.com/firewall/docs/firewalls)
- [Google Cloud route selection](https://cloud.google.com/vpc/docs/routes)
