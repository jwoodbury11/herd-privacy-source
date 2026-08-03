# Privacy release process

This process stages evidence only until an authorized maintainer deliberately
publishes and deploys it. Private signing material never belongs in the source
tree or uploaded build artifact.

## 1. Freeze source and tools

Use the exact Node, npm, Xcode, Swift, iPhoneOS SDK, Wrangler, runner, locale,
timezone, and Sigstore versions in `release/toolchains.json`. Use a clean commit,
set `TZ=UTC`, `LC_ALL=C.UTF-8`, and derive `SOURCE_DATE_EPOCH` from that commit.
The release workflow and all third-party actions are pinned; dependency lockfiles
must be npm lockfile version 3.

## 2. Test the privacy boundary

Run the evaluator, confidential evaluator, scheduler, web/API, iOS contract and
XCTest suites, plus the release/export/monitor tests. A production release stops
on any failure. Fork pull requests run read-only CI and never receive release
secrets or OIDC publication permissions.

## 3. Build deterministic inputs

Before building, derive every public web, non-secret runtime, and iOS Release
setting from one unsigned draft of the production manifest. The draft may use a
placeholder `configurationSha256`; `--prepare` reports the digest without
accepting that placeholder as verified:

```sh
node release/generate-production-config.mjs \
  --manifest /secure/draft-release-manifest.json \
  --evaluator-url https://evaluator.example/api/v1/relay/ \
  --attestation-root-certificate /secure/google-attestation-root.pem \
  --output-directory release/generated \
  --prepare
```

Set `productionPolicy.configurationSha256` to the reported digest and run the
same command with `--verify-template` in place of `--prepare`. Template
verification uses the full fail-closed production-template normalizer and
requires the configured digest to match before either client is built. Running
without either mode is intentionally reserved for the final assembled
production manifest and still requires its complete provenance, transparency,
transition, and deployment evidence. The digest excludes release artifact
hashes and evidence references, so filling those after the build does not create
a self-reference.

Wire the Xcode Release configuration, and only the Release configuration, to
the checked-in fail-closed wrapper `release/HerdRelease.xcconfig`. That wrapper
provides no usable trust defaults and optionally includes
`release/generated/HerdRelease.generated.xcconfig`; the production preflight
therefore rejects a locally compiled Release build when generated settings are
absent. The processed Info.plist must expose
`HERD_RELEASE_CONFIGURATION_SHA256`, `HERD_ARTIFACT_RELEASE_ID`, and the
protocol-compatible evaluator epoch in `HERD_RELEASE_ID` from settings of the
same names, in addition to the existing key, API, and attestation settings. The
generated xcconfig also sets `PRODUCT_BUNDLE_IDENTIFIER`, `MARKETING_VERSION`,
and `CURRENT_PROJECT_VERSION` from the signed manifest's iOS artifact identity;
the processed plist must expose those exact values as `CFBundleIdentifier`,
`CFBundleShortVersionString`, and `CFBundleVersion`. The checked-in wrapper uses
an invalid bundle identity and zero versions until that generated file exists.
Debug keeps its local development identity. The web build consumes
`web-public.env`; the deployment configuration consumes only the non-secret
values in `web-runtime-vars.json` and supplies service secrets through its
protected secret store. The scheduler deployment similarly consumes
`scheduler-runtime-vars.json` and supplies its courier token only through the
protected secret store.

Build the web deployment, ordinary API, evaluator image, scheduler, and iOS
submission with the pinned toolchains. Before packaging the web directory, add
`HERD-RELEASE-CONFIG-SHA256` containing the lowercase configuration digest and
one LF, plus `HERD-ARTIFACT-RELEASE-ID` containing the signed artifact release
ID and one LF. The web build plugin creates both from the generated environment;
preflight rejects either a missing or mismatched marker. Package directory
artifacts with `release/package-directory.mjs`.
Record provider-independent normalized hashes for the web entry document, asset
manifest, and the iOS executable after `codesign --remove-signature`. Create the
public source archive twice and require byte equality, then verify it
independently.

Generate the SPDX SBOM against the exported source manifest and checked-out
source root:

```sh
node release/generate-sbom.mjs \
  --source-manifest release/staging/herd-privacy-source.manifest.json \
  --source-root . \
  --output release/staging/herd.spdx.json \
  --name "Herd <release-id>" \
  invitee-web/package-lock.json \
  herd-legal/package-lock.json \
  evaluator-service/package-lock.json \
  scheduler-service/package-lock.json \
  monitor/package-lock.json
```

Generate SLSA v1 release-assembly provenance only after the subject directory is
complete. It attests that the protected workflow fetched or generated and
verified the exact released bytes; it is not a substitute for build provenance
emitted by each component's own build pipeline. Sign the complete subject set
with keyless Cosign from the protected workflow and keep the complete Sigstore
bundle. `release/record-transparency.mjs` converts its single Rekor entry into
the canonical record used by a manifest.

## 4. Assemble and sign the manifest

Prepare a production release template outside the repository. It contains real
hashes, sizes, media types, and durable URLs for source, SBOM, web, iOS,
ordinary-API, evaluator, scheduler, and audit artifacts; five public key
descriptors; the exact Confidential Space claim policy; and database and
configuration digests. Give every artifact/evidence release a fresh `releaseId`.
Set `evaluatorKeyEpochId` independently: reuse it only for an identical image
and epoch-scoped key tuple, or choose a fresh epoch and replace all three
epoch-scoped keys. Keep the response-transparency signing identity stable. Set
`previousRelease` to `null` only for the one-time bootstrap; every later
template must contain the currently published release ID and canonical manifest
SHA-256. Its `provenance`, `transparency`, `transitions`, and `deployments`
arrays must be empty. The protected workflow rejects preexisting entries in
those fields. Generated source artifacts must be named
`herd-privacy-source.tar` and `herd-privacy-source.manifest.json`, and the one
generated SBOM must be `herd.spdx.json`. External descriptors cannot use a
workflow-reserved name or collide on a case-insensitive filesystem.

The workflow then constructs the graph bottom-up:

1. regenerate and verify source/SBOM artifacts and fetch every external core
   artifact and audit by exact media type, size, and SHA-256;
2. generate one canonical SLSA v1 statement whose subject set exactly covers
   source archive/manifest, web, IPA, ordinary API, evaluator, scheduler, and
   every SBOM, plus the generated evaluator-epoch transition and successor
   release-continuity records;
3. keylessly sign that statement, verify the GitHub OIDC identity, and record
   its Rekor inclusion using the Rekor JSON API;
4. assemble a production manifest that binds the statement, Sigstore bundle,
   complete subject set, and Rekor record; and
5. only then sign and locally verify the manifest with the offline release key.

```sh
node release/assemble-release-manifest.mjs \
  --template /secure/release-template.json \
  --provenance-statement release/staging/build-provenance.intoto.json \
  --sigstore-bundle release/staging/build-provenance.sigstore.json \
  --transparency-record release/staging/build-provenance.rekor.json \
  --evidence-base-url https://evidence.example/releases/<release-id>/ \
  --issuer https://token.actions.githubusercontent.com \
  --workflow-identity <exact-protected-workflow-identity> \
  --output release/staging/release-manifest.json

node release/sign-release-manifest.mjs \
  --manifest release/staging/release-manifest.json \
  --output release/staging/release-manifest.sig.json

node release/verify-release-manifest.mjs \
  --manifest release/staging/release-manifest.json \
  --signature release/staging/release-manifest.sig.json \
  --public-key /secure/release-public.pem \
  --artifact-root release/staging \
  --require-production
```

Production verification requires the complete artifact root and the pinned
Cosign executable on `PATH`. It rehashes every descriptor and cryptographically
verifies each provenance statement/bundle against the exact stored workflow
identity and GitHub Actions OIDC issuer.

The protected workflow receives the template and P-256 PEM values only as
canonical base64 secrets. Missing inputs fail before a build. For production it
also receives the public attestation root as
`HERD_ATTESTATION_ROOT_CERTIFICATE_B64`, evaluator URL, and durable evidence
directory URL as workflow inputs. Its pinned macOS preflight runner verifies
every staged descriptor, independently downloads the public web and iOS
archives, verifies compiled client/scheduler configuration and the normalized
iOS executable, and fails the workflow before any evidence can be treated as
releasable. It verifies the submitted executable's code signature before
normalization, extracts entitlements from those signed bytes, and requires the
exact production application identifier, development team, one associated
domain, and one Keychain access group. A debug entitlement, an extra
capability, or a source-only entitlement absent from the signed app fails the
release.

For the one-time bootstrap, `--initial` succeeds only when `previousRelease` is
`null`. For every successor, the workflow fetches the current public release
pointer, downloads its exact manifest and detached signature with redirects
disabled and bounded sizes, verifies both hashes and the persistent release
key, and runs `verifyReleaseContinuity` against the protected template before
provenance is generated.

The one-time production bootstrap must use a newly provisioned, empty D1
database. Production and QA use different database IDs, projects, bindings,
origins, keys, and secrets. Apply every migration through the release snapshot
to that empty database, bind it to the candidate runtime, and call the
authenticated evaluator-epoch status endpoint before opening user traffic. It
must initialize generation 1 as `active` with `runtimeMatchesState: true`.

Never promote, clone into production, or reuse a preview/QA/software-evaluator
database containing frozen policies, resolutions, or response-transparency
records. Those rows predate the signed epoch-descriptor fence and cannot be
safely rebound. The runtime deliberately refuses to bootstrap such a database;
there is no legacy backfill override. Provision and migrate a fresh database
instead, and retain or dispose of the old isolated database under its existing
data-retention policy.

Evaluator-epoch reuse requires the live v2 D1 status to be `active`, to match
the runtime descriptor digest, and to equal the template's exact epoch tuple.
An epoch change requires an already persisted `draining` generation, the fixed
minimum drain interval, and zero unresolved policies, live evaluator leases,
evaluation jobs, and uncertified transparency records. The release gate checks
the transition generation/digests and canonical activation history; a standalone
zero-count snapshot is insufficient. The generated v2 epoch-transition record
and, for successors, the release-continuity record are both subjects of the
signed release-assembly provenance and artifacts in the production manifest.

## 5. Bind the deployment

After each provider returns immutable deployment IDs, fill a deployment input
with web, ordinary-API, evaluator, and scheduler IDs; the release artifact hash
for each; the published manifest/signature references; endpoints; and the exact
entry-document and asset-manifest hashes. It must also bind the exact live
`/.well-known/apple-app-site-association` bytes as an `application/json`
monitored resource. Those bytes must authorize only
`R4UPN8ZDV8.<signed bundle identifier>` and `/invite/*`.

Pass the same downloaded association file to both deployment signing and
`.well-known` generation:

```sh
node release/sign-deployment-statement.mjs \
  --statement /secure/deployment-statement.json \
  --manifest release/staging/release-manifest.json \
  --apple-app-site-association /secure/apple-app-site-association \
  --private-key /secure/release-private.pem \
  --public-key /secure/release-public.pem \
  --output release/staging/deployment-statement.sig.json

node release/generate-well-known.mjs \
  --manifest release/staging/release-manifest.json \
  --manifest-signature release/staging/release-manifest.sig.json \
  --deployment /secure/deployment-statement.json \
  --deployment-signature release/staging/deployment-statement.sig.json \
  --apple-app-site-association /secure/apple-app-site-association \
  --public-key /secure/release-public.pem \
  --deployment-url https://evidence.example/releases/<release-id>/deployment-statement.json \
  --deployment-signature-url https://evidence.example/releases/<release-id>/deployment-statement.sig.json \
  --verifier-source-url https://source.example/herd/<source-revision>/ \
  --output release/staging/herd-release.json
```

The second command verifies both signed records before generating the pointer.
The pointer includes the hash-only response-log URL and its
receipt/transparency P-256 pin.

Do not update `.well-known` until all referenced evidence URLs are durable and
the deployment bytes match. Do not mutate assets in place after publication;
create a new artifact release ID and evidence chain. The `.well-known` pointer
also publishes the signed predecessor and evaluator-key epoch so an external
witness can enforce continuity across updates.

## 6. Independent verification and claims

Deploy the monitor under separate credentials and, preferably, a separate
account/operator. Configure the persistent release pin, allowed evidence
origins, production requirement, response-log URL, and transparency signing pin
out of band. Also configure the exact evaluator origin and canonical DER-base64
Google attestation root from the separately approved certificate. The monitor
requires the signed evaluator endpoint to be that origin's exact
`/api/v1/relay/` path and directly challenges `/api/v1/attestation` with a fresh
nonce on every run; it hashes the independently configured root and requires
the signed manifest fingerprint to match before verifying the live JWT chain.
It also fetches and hashes the exact association resource named by the signed
deployment statement and repeats the app-identifier and `/invite/*` semantic
check, so a provider-side universal-link change cannot pass as healthy.
Confirm an initial successful check, preserve its KV history, and test alert
delivery.

Never delete or reset the monitor's last-good witness during an ordinary
release. It is the continuity authority that rejects a skipped predecessor,
same-epoch tuple drift, response-log key change, or signed rollback.

Only then may status copy say that signed release evidence is published and
continuously monitored. “Independently audited,” “reproducible,” and
“hardware-attested” each require the corresponding public evidence; generating
this toolchain alone is not that evidence.
