# Herd release-evidence tools

This directory contains dependency-free Node.js tools for producing and checking
Herd's privacy release evidence. They canonicalize the release manifest and
deployment statement, create deterministic archives and SPDX SBOMs, derive web
and iOS production configuration from the signed trust contract, preflight the
compiled artifacts, sign canonical records with a pinned P-256 key, generate
SLSA release-assembly provenance, retain Sigstore/Rekor identifiers, and build the public
`.well-known` release record.

The signed `releaseId` identifies one artifact/evidence release, while
`evaluatorKeyEpochId` identifies the private-response key/workload epoch carried
on protocol-v1's existing `releaseId` wire field. Successor manifests hash-link
to `previousRelease`; tooling and the independent monitor reject same-epoch
tuple drift and any rotation of the lifetime-global response-transparency key.

Production verification requires the complete staged artifact directory and a
pinned Cosign verifier. It rehashes each descriptor and cryptographically checks
every provenance bundle against the statement, GitHub OIDC issuer, and exact
protected-workflow identity recorded in the signed manifest.

The generated iOS xcconfig owns the Release app's bundle identifier, marketing
version, build number, development team, associated domain, and Keychain access
group. Debug retains its development settings; Release falls back to an
intentionally invalid identity until a signed production manifest generates
the production values. Preflight verifies the submitted executable signature,
extracts its signed entitlements, and compares both the processed plist and
capabilities back to that manifest-derived contract.

Deployment signing and `.well-known` generation require the exact live Apple
app-site association file. The deployment statement binds it as a monitored
resource, and both release tooling and the independent monitor require it to
authorize only the signed production app and `/invite/*`.

The tools deliberately fail on unknown fields, non-canonical JSON, reused trust
keys, inconsistent artifact hashes, unsafe URLs, permissive production flags,
or an incomplete production evidence set. A successful tool run proves that the
inputs are internally consistent; it does not by itself prove that a deployment,
audit, public source mirror, or hardware attestation exists.

Production configuration has three deliberate phases: `--prepare` computes the
draft template digest, `--verify-template` requires that digest against the
strict production-template contract before client builds, and the no-flag mode
accepts only a fully assembled final production manifest. Template verification
does not weaken or replace final-manifest evidence validation.

Start with [the release process](../docs/release-process.md) and [the evidence
format](../docs/release-evidence.md). Run the local tests with:

```sh
node --test release/tests/*.test.mjs
```

Generated material belongs in `release/generated/`, `release/staging/`, or
`release/out/`; all three paths are ignored and excluded from public-source
archives. `release/HerdRelease.xcconfig` is the checked-in Xcode Release base
configuration; it fail-closes and optionally includes the generated
`release/generated/HerdRelease.generated.xcconfig`. Never place a private key
in the repository. The signing commands accept canonical base64-encoded PEM via
`HERD_RELEASE_SIGNING_PRIVATE_KEY_PEM_B64` and
`HERD_RELEASE_SIGNING_PUBLIC_KEY_PEM_B64` in protected release automation.
