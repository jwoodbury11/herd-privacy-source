# Independent Herd release and transparency monitor

This Cloudflare Worker is designed to run in an account separate from Herd's
production account. Every five minutes it verifies the public release pointer,
the persistent P-256 release key pin, signed canonical release manifest, signed
deployment statement, protocol and Confidential Space trust pins, deployment
artifact bindings, and the exact bytes and media types of deployed web resources.
It then sends a fresh random 32-byte nonce directly to the evaluator, with no
ordinary-backend credential, and verifies the returned Google PKI attestation
JWT offline against an independently configured X.509 root.

For every production target it also witnesses the public encrypted-response transparency log. The witness
accepts only `logIndex`, `previousEntryHash`, `entryHash`, and a signed `head`.
It deliberately rejects receipt payloads and identifiers. It verifies every
P-256 signed head, sequential index, and previous-hash link, re-fetches its last
witnessed entry on every run, and persists the latest index/hash in a Durable Object. Gaps,
rewinds, forks, key changes, redirects, oversized pages, and bad signatures fail
the check and trigger an alert.

The Durable Object serializes scheduled and manual checks, so two checks cannot
advance the same witness concurrently. Its last-good deployment and response-log
witness is stored separately from the latest health status and is never erased by
a fetch failure or failed check. `STATUS_KV` is a required independently backed
mirror; a failed KV write makes the check red without rolling the witness back.
The same last-good record stores the signed manifest predecessor link and the
evaluator-key epoch fingerprint. It rejects a skipped predecessor, a changed
image/key tuple under an existing epoch ID, an incomplete three-key epoch
rotation, and any change to the lifetime-global response-transparency key.

Configure `TARGETS_JSON` as a Worker secret. For a Sites origin protected by
Sign in with ChatGPT, also configure `SITES_BYPASS_BEARER_TOKEN` as a Worker
secret. The monitor sends it only to the target's exact `expectedWebOrigin`;
evidence, Rekor, and evaluator requests never receive the Sites credential.
Both `responseTransparency` and
`evaluatorAttestation` are mandatory when `requireProduction` is true:

```json
[
  {
    "name": "herd-production",
    "wellKnownUrl": "https://herd.example/.well-known/herd-release.json",
    "expectedWebOrigin": "https://herd.example",
    "allowedEvidenceOrigins": [
      "https://releases.herd.example",
      "https://rekor.sigstore.dev"
    ],
    "requireProduction": true,
    "releaseSigningKey": {
      "keyId": "herd-release-2026",
      "algorithm": "ECDSA_P256_SHA256",
      "publicKeyFormat": "P256_X963_BASE64URL",
      "publicKey": "<65-byte uncompressed P-256 point, base64url>",
      "publicKeySha256": "<sha256 hex>"
    },
    "evaluatorAttestation": {
      "origin": "https://evaluator.herd.example",
      "rootCertificateDerBase64": "<canonical DER bytes of the approved Google attestation root, standard base64>"
    },
    "responseTransparency": {
      "url": "https://herd.example/api/transparency/responses",
      "logId": "herd-response-log-v1",
      "signingKey": {
        "keyId": "herd-response-transparency-2026",
        "algorithm": "ECDSA_P256_SHA256",
        "publicKeyFormat": "P256_X963_BASE64URL",
        "publicKey": "<65-byte uncompressed P-256 point, base64url>",
        "publicKeySha256": "<sha256 hex>"
      }
    }
  }
]
```

The attestation `origin` is an origin only—no path, query, credentials, or
fragment. The signed deployment evaluator URL must be exactly that origin plus
`/api/v1/relay/`; the signed attestation audience must use the same origin. On
every check, the monitor posts to exactly that origin plus
`/api/v1/attestation`, refuses redirects, bounds the response to 128 KiB, and
sends no bearer header. The public endpoint allows server-side requests without
an `Origin` header and is Cloud-Armor throttled to 60 requests per minute per
source IP. Browser requests remain limited to the configured application
origin.

`rootCertificateDerBase64` is the full self-signed root certificate, not merely
the fingerprint and not a URL. The monitor hashes its DER bytes and requires
that SHA-256 to equal the signed manifest's root fingerprint, then verifies the
supplied JWT chain ends at that exact root. It also verifies RS256, validity and
freshness, the two ordered nonces, exact release key binding, project, singleton
service account, image digest, singleton approved OS version and Intel TCB,
secure/debug state, empty command/environment overrides, `Always` restart,
stable/usable support, and memory monitoring off. It stores only the compact
verification result; the PKI token, chain, and response body are neither logged
nor persisted. A root rollover requires an intentionally coordinated signed
release and out-of-band monitor-secret update; silently trusting a root from
the public release record is forbidden.

Also configure a random `MONITOR_BEARER_TOKEN` of at least 32 characters. Bind
`STATUS_KV` and the `MONITOR_COORDINATOR` Durable Object using `wrangler.jsonc`.
Optional alerts require both an HTTPS
`ALERT_WEBHOOK_URL` and an `ALERT_HMAC_SECRET` of at least 32 characters; alert
bodies carry `x-herd-signature: sha256=<HMAC>`.

```sh
npm ci --prefix monitor
npm test --prefix monitor
npm exec --prefix monitor -- wrangler deploy --config monitor/wrangler.jsonc
```

`GET /status` and `POST /check` require `Authorization: Bearer <token>`. The
worker fetches and digest-verifies every release artifact and evidence item;
it additionally validates the public-source identity, SPDX document, in-toto
subjects, Sigstore/Rekor binding, and PDF audit framing. It stores no fetched
artifact or response body and never logs one. Protect and back up the Durable
Object storage: deleting its last-good witness removes historical fork and
rollback detection. KV is a status/witness mirror, not the concurrency authority.
