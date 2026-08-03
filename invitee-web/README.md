# Herd web app

This is Herd’s responsive web app. People sign in with a one-time phone code,
see their synced events, review invitations, and save device-encrypted
conditional replies. Hosting remains in the iPhone app, and both clients use the
same authenticated API and Cloudflare D1 data.

The root route is the normal Herd sign-in. Invitation links use
`/invite/:token`; test tokens are generated only inside isolated QA runs.

It runs on [vinext](https://github.com/cloudflare/vinext), Cloudflare D1, and Drizzle.

## Prerequisites

- Node.js `>=22.13.0`
- A fresh, environment-specific D1 database for first production or QA
  bootstrap; production and QA must never share or promote a database

## Quick Start

```bash
npm install
npm run dev
npm run build
npm run qa:browser
```

`qa:browser` prints one disposable localhost invite URL and the temporary QA
accounts for that run. It exercises the event list, invite detail, reply
composer, ephemeral RS256/x5c evaluator attestation, encrypted submission,
signed receipt, public-log publication, and wrong-account denial. Nothing is
messaged or persisted after the process stops.

This starter does not use `wrangler.jsonc`.

## First database bootstrap

Provision a new D1 database for each production or QA environment and apply all
migrations before serving traffic. After binding the clean database and signed
runtime configuration, call the scheduler-authenticated
`/api/internal/evaluator-epoch-status` endpoint and verify generation 1 is
`active` with `runtimeMatchesState: true`.

Do not attach this release to a preview, QA, or software-evaluator database that
already contains frozen policies, resolutions, or response-transparency rows.
Those records do not carry the signed evaluator-epoch descriptor introduced by
the current fence. Bootstrap intentionally fails closed, and no unsafe legacy
backfill path exists: create and migrate a fresh database instead.

## Project shape

- `app/page.tsx` contains the shared authenticated app shell
- `app/invite/[token]/page.tsx` provides invitation-specific entry links
- `app/api/` exposes phone auth, profile, event, account-key, and encrypted-response endpoints used by web and iPhone
- `db/schema.ts` and `drizzle/` define the shared D1 data model and migrations
- `lib/privacy/` defines the shared protocol and browser cryptography/key vault
- `.openai/hosting.json` declares the Sites D1 binding

## Private responses

The browser pads every response to 4,096 plaintext bytes, encrypts it with
AES-256-GCM, and separately wraps its response key for this user's local account
key and the release-pinned P-256 evaluator. The API accepts only the exact
fixed-size envelope; it never accepts the legacy plaintext response fields.

An account-key commitment prevents another browser from silently creating a
different key under the same epoch. If the key is unavailable, a freshly
phone-verified user can explicitly start over without losing the account or
invitations. Starting over cannot recover the old criteria.

The evaluator key ID and public key must be supplied both as server values and
as `NEXT_PUBLIC_...` values baked into the browser build. See `.env.example` and
the repository's private-response implementation status before deployment.

## Unattended resolution

The Worker includes a minute-level scheduled handler that scans only sent,
due, unresolved events. Each attempt reuses the same leased, signed client-relay
protocol: the backend forwards a fixed-size opaque package and cannot decrypt
individual replies. Work is bounded and failures release only the matching
lease so a later run can retry safely.

When the hosting platform cannot register the native Worker schedule or make
the evaluator relay request, a trusted external courier can use the internal
`/api/internal/scheduled-resolutions/claim`, `/complete`, and `/release`
endpoints. Claim returns at most one fixed-size encrypted evaluator job. The
courier must send that opaque relay request only to the exact returned HTTPS
destination, then return the evaluator's signed response for backend
verification and persistence. A failed delivery can release only its matching
lease. Completion and release return no event projection or result body.

These endpoints require the distinct URL-safe `HERD_SCHEDULER_TOKEN` as a
Bearer credential, read bounded bodies only after authentication, and do not
require a browser Origin header. The credential can claim and release
evaluation leases, so give it only to the trusted courier and never reuse the
authentication pepper or evaluator token. Individual replies remain encrypted
from the courier; the signed evaluator response necessarily reveals the final
aggregate status and, for a confirmed event, the attending member IDs. The
original authenticated `/api/internal/scheduled-resolutions` sweep remains
available to deployments that can perform the relay request natively.

## Phone authentication

Production SMS uses Twilio Verify through server-only environment values. An optional, short-lived QA phone can authenticate immediately for internal testing only when both the enable flag and a separate safety-acknowledgement flag are set. Enabling it also requires a fresh, deployment-unique `HERD_QA_BYPASS_GENERATION` (a random UUID is recommended). Generate a new value for every enablement or rotation and never reuse an old value. QA sessions are bound to that generation; presenting one from another generation permanently revokes it. Disable both flags before release. The bypass is configuration-only and must never be identified or described in product UI.

An isolated QA deployment may additionally expose authenticated
`POST /api/internal/qa-reset` only when `HERD_DEPLOYMENT_PROFILE=test`, both QA
bypass acknowledgements, and `HERD_QA_RESET_ENABLED=true` are all present. The
route requires the role-specific scheduler bearer token and the exact JSON body
`{"confirmation":"RESET HERD QA DATA"}`. It atomically erases all QA accounts,
events, encrypted responses, receipts, evaluator-epoch state, challenges, rate
limits, and delivery records, resets the transparency sequence, and restores
the immutable epoch guards before committing. Production returns `404` even if
the flag is accidentally present. Never point a reset-enabled deployment at
production data.

That isolated deployment may compile the browser with
`NEXT_PUBLIC_HERD_DEPLOYMENT_PROFILE=test` and
`NEXT_PUBLIC_HERD_ALLOW_SOFTWARE_QA_EVALUATOR=true`. This permits the reference
software evaluator only when the signed policy exactly matches the build's
release ID, response-decryption key ID/public key, and evaluator measurement.
The signed policy is still verified. Production configuration generation sets
the exception to `false`; production uses fresh Confidential Space hardware
attestation.

Verification challenges expire, enforce resend and attempt limits, and create revocable server sessions. Browsers receive a secure HTTP-only cookie. The iPhone app uses the returned bearer token and stores it in Keychain.

## Invitation delivery

The draft-to-sent transition freezes the event policy and creates one durable
outbox record per guest in the same database transaction. Real recipients get
the exact one-time, consent-aligned SMS format through the configured Twilio
Messaging Service. Internal QA aliases are recorded as suppressed while their
accounts can still open and answer the event.

Private invitation tokens are random, stored encrypted under a key derived from
`HERD_AUTH_PEPPER`, and exposed only in the guest's private link. A successful
provider receipt is recorded as sent; definitive rejections are failed, while
timeouts and ambiguous provider failures become unknown and are never retried
automatically. Host projections expose guest names and delivery states, never
phone numbers, tokens, provider credentials, or provider message IDs.

## Useful Commands

- `npm run dev`: start local development
- `npm run build`: verify the vinext build output
- `npm run qa:browser`: build and serve a disposable local browser-QA scenario with aliases 1–9
- `npm run test:browser-ui`: run the real-browser nine-account acceptance suite, all 72 wrong-account invite pairs, and link-preserving account switching
- `npm test`: build the production bundle and verify both entry routes and backend contracts
- `npm run db:generate`: generate Drizzle migrations after schema changes
- `node scripts/live-scheduler-smoke.mjs`: run the host-bound production scheduler smoke after temporarily enabling QA authentication; it intentionally resets the nine shared QA key epochs and retains two timestamped QA events as audit evidence

## Learn More

- [vinext Documentation](https://github.com/cloudflare/vinext)
- [Drizzle D1 Guide](https://orm.drizzle.team/docs/get-started/d1-new)
