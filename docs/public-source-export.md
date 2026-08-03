# Public-source export policy

Herd publishes the privacy-critical implementation needed to review encrypted
response creation, storage, scheduling, confidential evaluation, result and
receipt verification, attestation, release evidence, and monitoring. The export
is a deliberate allowlist rather than a copy of the repository.

## Included material

The current policy includes the Apache-2.0 license and security policy; protocol,
attestation, release, and deployment documents; relevant Swift client and
project files; privacy evaluator code; confidential evaluator service and GCP
Confidential Space infrastructure; ordinary API, scheduler, database migrations,
privacy libraries and tests; complete build input closure for the exported
application surfaces; and the release/export/monitor toolchains.
It also includes the machine-readable data inventory, retention/privacy
operations contract, data-contract verifier, sensitive-artifact scanner and its
tests, and the browser QA harness needed by the exported browser acceptance
tests. Account deletion is represented end to end: ordinary-API implementation,
web and native tests/UI, Keychain erasure coverage, public retention contract,
and the matching privacy-policy disclosure. The confidential evaluator export
also includes its atomic transparency append authority, persistence adapter,
infrastructure, and tests.

## Excluded material

The export excludes proprietary reference applications and screenshots, local
secrets and environment files, certificates and key containers, databases,
Terraform state, dependency directories, build caches and products, generated
archives, and unallowlisted binary media. The small set of first-party PNG
assets required by the exported builds is admitted only by exact path and
SHA-256 in the reviewed policy; PNG structure and the pinned digest are both
verified during collection. Placeholder-only `.env.example` files required by
the exported web and software-evaluator tests are admitted by exact path and
SHA-256, and secret-bearing assignments must remain explicit placeholders even
when commented out; no unpinned or runtime environment file is exportable. A path outside
the allowlist is absent even if it is not named on the denylist. A prohibited
item reached by an allowlisted recursive path causes a hard failure.

The repository's private visual references and third-party assets are not
relicensed. The archive manifest records `Apache-2.0` for the exported Herd
material; a file with its own compatible notice retains that notice.

## Reproducibility and review

The archive is uncompressed USTAR to avoid compressor timestamps and platform
variation. Entries use sorted normalized paths, UID/GID zero, modes `0644` or
`0755`, a fixed commit-derived modification time, and no owner names. The final
two zero blocks and embedded canonical manifest are deterministic.

CI builds two archives from the same commit and compares all bytes. Reviewers
should download the archive, detached manifest, policy, and signed release
manifest; run `public-source/verify-export.mjs`; compare the source revision and
policy digest; inspect exclusions; and rebuild with the pinned toolchain.

Changing `public-source/export-policy.json` changes the policy digest and must be
reviewed as a security-sensitive release change. New privacy-critical code is
not considered publicly reviewable until its path is explicitly included and a
new signed archive is published.
