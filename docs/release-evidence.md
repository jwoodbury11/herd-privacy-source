# Herd release evidence

Herd's release evidence makes a deployed privacy boundary inspectable and
tamper-evident. It does not turn a single-developer project into an independently
governed organization, and it must not be described as a completed independent
audit until an outside reviewer has actually published one.

## Evidence chain

1. A deterministic Apache-2.0 source archive identifies the reviewable
   privacy-critical source at one Git revision.
2. An SPDX 2.3 SBOM identifies the exported files and locked npm dependencies.
3. Release-assembly provenance identifies the source revision, pinned toolchain
   document, protected workflow, invocation, and the complete name/SHA-256 set
   of the source archive and manifest, web and iOS clients, ordinary API,
   confidential evaluator, scheduler, and every SBOM. It attests verification
   and assembly of those bytes, not their upstream component build process.
4. The canonical release manifest binds a unique artifact release ID, a
   separately named evaluator-key epoch, the exact preceding release
   ID/manifest hash, source, protocol, all operational keys, the Confidential
   Space workload policy, web and iOS artifacts, backend
   artifacts, database/configuration digests, SBOMs, provenance, transparency
   records, deployments, and audits.
5. A persistent offline P-256 release key signs that manifest. A separate
   Sigstore keyless signature and Rekor inclusion bind the provenance statement
   to the protected GitHub Actions workflow identity before the manifest is
   assembled. The manifest binds the exact statement, Sigstore bundle, and
   Rekor record. An optional outer keyless signature on the completed manifest
   is useful corroborating evidence but, by definition, is not self-referenced
   by that manifest.
6. A signed deployment statement binds provider deployment IDs and deployed web
   resources to the released artifact hashes, including the exact live Apple
   app-site association for the signed iOS identity and invitation path.
7. `/.well-known/herd-release.json` publishes the signed artifact pointers,
   trust pins, response-log endpoint, and hash-only data policy.
8. A separately deployed monitor verifies the whole chain and the currently
   served bytes, directly challenges the live evaluator and verifies its Google
   PKI token against an out-of-band X.509 root, and witnesses the append-only
   response log.

The `.well-known` document is a discovery pointer, not a trust root. A monitor
must configure the release key ID, raw public key, and SHA-256 fingerprint out of
band. For production it must also configure the evaluator origin and full
Google attestation root DER out of band. It follows only HTTPS URLs on
explicitly allowed origins, refuses redirects, bounds every response, and then
verifies hashes and signatures. It sends a fresh 32-byte nonce directly to the
public attestation path without an application bearer and retains only a compact
verification result, never the returned PKI token.

## Canonical manifest

`release/schemas/release-manifest-v1.schema.json` documents the JSON shape and
`release/lib/release-manifest.mjs` is the normative fail-closed normalizer. The
serialized form sorts object keys, preserves array order after deterministic
normalization, uses UTF-8, and ends with one LF. Signatures are ECDSA P-256 with
SHA-256 and 64-byte IEEE-P1363 output, wrapped in a canonical detached envelope.

The manifest requires distinct keys and IDs for:

- evaluator encryption;
- evaluation-result signing;
- event-policy signing;
- receipt and response-transparency signing; and
- release-manifest/deployment signing.

Reusing a key for two purposes is rejected.

`releaseId` identifies the complete signed artifact/evidence release.
`evaluatorKeyEpochId` identifies the response-decryption, result-signing,
policy-signing, and workload-image tuple used by private-response protocol v1.
The protocol's existing wire field and runtime variable remain `releaseId` and
`HERD_RELEASE_ID` for compatibility, but their value is the evaluator-key epoch,
not the artifact release. `HERD_ARTIFACT_RELEASE_ID` and
`NEXT_PUBLIC_HERD_ARTIFACT_RELEASE_ID` carry the artifact identity explicitly.

Every successor manifest sets `previousRelease` to the exact preceding
artifact `releaseId` and canonical manifest SHA-256. The first release alone
uses `null`. An artifact-only release may reuse an evaluator epoch only when the
workload image and three epoch-scoped key identities are byte-for-byte stable.
A new evaluator epoch must replace all three epoch-scoped keys. The
receipt/response-transparency signing identity is lifetime-global for
`herd-response-log-v1` and must remain stable across both kinds of release.

Production release-assembly provenance is set equality, not a nonempty checkbox. Each subject
has both an artifact name and SHA-256 digest; subject names cannot overlap
between statements, and their union must exactly equal every required release
artifact, SBOM, and rotation/continuity record. It establishes which already
built bytes were verified and assembled into the release; it is not component
source-to-artifact build provenance. Every provenance record binds both its canonical in-toto
statement and Sigstore bundle, and exactly one transparency record must bind
that bundle hash, Rekor log ID/index, and integrated time. Preexisting evidence
in a release template is rejected so the protected workflow cannot accidentally
reuse unrelated provenance from an earlier build.

## Confidential Space attestation contract

The workload is exactly `gcp-confidential-space` using a Google PKI attestation
token. Its claim policy pins the Google issuer, a custom audience, maximum token
age, challenge nonce requirement, workload image digest, GCP project, service
account, exact attestation root fingerprint, and the allowed Confidential Space
software versions. It also requires:

- `hwmodel = GCP_INTEL_TDX`;
- `secboot = true`;
- `dbgstat = disabled-since-boot`;
- `swname = CONFIDENTIAL_SPACE`;
- `oemid = 11129`;
- `attesterTcb = INTEL`; and
- no environment or command override.

The runtime key binding deliberately matches the evaluator, web, and iOS
implementations byte for byte. Its preimage is the UTF-8 bytes of the domain
`HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1`, one NUL byte, and the exact
`JSON.stringify` serialization of this insertion-ordered object (with no final
LF):

```json
{
  "protocolVersion": 1,
  "releaseId": "<evaluator-key epoch ID>",
  "keys": {
    "responseDecryption": {
      "keyId": "<encryption key ID>",
      "algorithm": "ECDH_P256",
      "publicKey": "<raw P-256 public key>"
    },
    "evaluationResultSigning": {
      "keyId": "<result key ID>",
      "algorithm": "ECDSA_P256_SHA256",
      "publicKey": "<raw P-256 public key>"
    },
    "policySigning": {
      "keyId": "<policy key ID>",
      "algorithm": "ECDSA_P256_SHA256",
      "publicKey": "<raw P-256 public key>"
    },
    "transparencySigning": {
      "keyId": "<transparency key ID>",
      "algorithm": "ECDSA_P256_SHA256",
      "publicKey": "<raw P-256 public key>"
    }
  }
}
```

The SHA-256 result is encoded as canonical unpadded base64url. The manifest
normalizer recomputes this value; it never accepts a caller-supplied binding on
trust. Event-policy signatures remain a separate control; they are not treated
as an attestation claim.

## Build-configuration binding

`release/generate-production-config.mjs` derives one canonical configuration
contract from the production manifest, evaluator URL, and attestation root
certificate. The evaluator URL is exactly the public relay endpoint
`/api/v1/relay/`, with no query; direct `/api/v1/evaluate` endpoints are not a
valid web/scheduler production binding. The contract includes both release identities, the deterministic
evaluator-key epoch descriptor SHA-256, public web origin,
confidential-evaluator endpoint, signed iOS bundle identifier/marketing
version/build number, client-relay transport, protocol sizes, four operational
keys, every workload/claim pin, the exact DER root certificate, and all disabled
production safety switches. Its canonical JSON SHA-256 must equal the signed
`productionPolicy.configurationSha256`. Any bundle-identifier, marketing-version,
or build-number change therefore requires regenerating that digest and signing a
new manifest.

For the pre-build production template, `--prepare` computes that digest without
accepting the placeholder as verified; after inserting the result,
`--verify-template` re-normalizes the exact production template and requires a
match. Omitting both flags remains the stricter final-manifest mode and requires
the complete assembled production evidence graph.

The generator emits five byte-deterministic files: `release-config.json`,
`web-public.env`, `web-runtime-vars.json`, `scheduler-runtime-vars.json`, and
`HerdRelease.generated.xcconfig`. The scheduler file binds its production
profile, public app/evaluator URLs, evaluator key ID, artifact release ID,
protocol evaluator epoch ID, and the same configuration digest. Web server
runtime also receives `HERD_EVALUATOR_KEY_EPOCH_SHA256`, recomputed from the
signed epoch tuple so the live database fence can reject configuration drift.
The output contains no service token, auth pepper,
provider credential, or signing private key. Production host names and
identifiers containing preview/test/staging/development tokens or the legacy
`live-v1` key ID are rejected.

The protected production preflight verifies the release-key signature,
regenerates and byte-compares all five files, downloads the web and iOS archives
only from their signed HTTPS URLs, and verifies their exact names, sizes, and
SHA-256 digests. It also cryptographically verifies each SLSA statement's
Sigstore bundle against the exact GitHub workflow identity and OIDC issuer. It
then requires the compiled web archive to contain every
public trust value plus exact `HERD-RELEASE-CONFIG-SHA256` and
`HERD-ARTIFACT-RELEASE-ID` markers, requires the
processed iOS Info.plist to equal every derived setting—including exact
`CFBundleIdentifier`, `CFBundleShortVersionString`, and `CFBundleVersion`—and
extracts entitlements from the verified signed executable. The signed
entitlements must contain the exact application identifier, team identifier,
`applinks` domain, and Keychain group, with debug disabled and no unexpected
capabilities. It then compares the codesign-stripped executable to
`normalizedBinarySha256`. Web and scheduler
archives larger than 256 MiB are rejected before content inspection. An
unresolved Xcode setting or known preview/legacy value stops the release.

Before that client-specific check, the workflow fetches every externally built
client/service artifact and audit with redirects disabled and exact media type,
size, and digest enforcement. The final local preflight rehashes every manifest
descriptor: source artifacts, all five deployed components, SBOMs, evaluator
epoch/release-continuity records, provenance statements, Sigstore bundles,
deployment evidence, and audits. After
publication, the independent monitor repeats those checks over HTTPS and also
requires the pinned Rekor URL to return matching JSON rather than a search-page
or dead link. The deployment statement must name the exact production
`/.well-known/apple-app-site-association` resource; deployment signing,
`.well-known` generation, and the monitor all verify its hash, size,
`application/json` media type, signed app identifier, and sole `/invite/*`
path.

## Response-transparency witnessing

The confidential evaluator's Firestore-backed append authority atomically
assigns the next index, commits the hash link, and returns the receipt and signed
log head as one operation. The ordinary API cannot independently ask the
signing boundary for arbitrary receipt or log-head signatures. The public
endpoint exposes only a sequential index, previous-entry hash, entry hash, and
signed log head. It does not expose envelope, event, invitee, response,
condition, ciphertext, or account identifiers. A client that owns a receipt
verifies its receipt payload and entry hash; the independent witness verifies
the public hash chain and every signed head without receiving that private
receipt payload.

On each poll the witness starts one entry before its stored tail. A missing tail
is a rewind, a changed tail is a fork, a non-sequential next index is a gap, and
a changed key is rejected. The latest witnessed index, entry hash, previous
hash, key fingerprint, and observation time are stored in the independent KV
namespace. This detects equivocation against the witness's observed history; it
cannot prove that a response never shown to any client existed.

The same durable witness stores the last signed manifest hash, predecessor,
artifact release ID, and evaluator-key epoch fingerprint. A new manifest must
name that exact last-good manifest as its predecessor. Reusing an epoch with a
different image/key tuple, incompletely rotating the three epoch keys, or
changing the lifetime-global transparency identity fails the monitor.

## Production requirements

A `production` manifest is rejected unless it contains release-assembly
provenance, transition/continuity evidence, transparency, SBOM, and audit
references and all production safety flags are false. Publication is still an operational act: reviewers must verify the
public URLs, licensing, audit authorship and scope, Rekor inclusion, protected
workflow identity, attestation root and claim mapping, deployed provider IDs,
and live monitor ownership before describing the release as independently
verified.
