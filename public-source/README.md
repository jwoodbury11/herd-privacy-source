# Deterministic public-source export

`export.mjs` creates an uncompressed, deterministic USTAR archive from the
allowlist in `export-policy.json`. It records every exported path, mode, size,
and SHA-256 digest in a canonical manifest stored both next to and inside the
archive. The source revision and `SOURCE_DATE_EPOCH` determine all metadata.

The allowlist contains the privacy-critical clients, services, evaluator,
infrastructure definitions, release tools, monitor, tests, and relevant design
documents. It excludes proprietary visual references, screenshots, secrets,
certificates, private keys, databases, deployment state, dependencies, and build
outputs. The few first-party PNG build inputs are admitted only by exact path
and policy-pinned SHA-256. The documented `.env.example` files required by the
web and software-evaluator test/build closures are likewise admitted only by
exact path and digest; active and commented secret-bearing assignments must
also contain explicit placeholder values. All other environment files remain forbidden. Other
binary/NUL data, symlinks, private-key markers, oversized files, unsafe paths,
and case-folding collisions fail the export instead of being silently included.

```sh
node public-source/export.mjs \
  --root . \
  --policy public-source/export-policy.json \
  --source-revision "$(git rev-parse HEAD)" \
  --source-date-epoch "$(git show -s --format=%ct HEAD)" \
  --output /tmp/herd-privacy-source.tar \
  --manifest /tmp/herd-privacy-source.manifest.json \
  --require-clean

node public-source/verify-export.mjs \
  --archive /tmp/herd-privacy-source.tar \
  --manifest /tmp/herd-privacy-source.manifest.json \
  --policy public-source/export-policy.json
```

The verifier checks the policy digest, canonical manifest, every USTAR header
and file digest, then reconstructs the complete archive and requires it to be
byte-for-byte identical. See [the public-source guide](../docs/public-source-export.md).
