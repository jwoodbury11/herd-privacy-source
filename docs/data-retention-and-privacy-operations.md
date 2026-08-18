# Herd data retention, backup, and privacy validation

Status: production operating contract
Last reviewed: 2026-08-17

Herd's private reply, minimum, and required-person groups are sealed on the
user's device. Ordinary application storage receives a fixed-size ciphertext,
two key wraps, commitments, and routing metadata. Phone numbers, profiles,
events, guest membership, authentication records, timing, and the final
policy-authorized outcome are not server-blind; the exact field-level inventory
is [`security/data-inventory.json`](../security/data-inventory.json).

## Enforced live-data schedule

The Worker runs the retention task independently of event evaluation on every
scheduled invocation. A failed evaluator call therefore cannot postpone data
minimization.

| Data | Live D1 retention |
| --- | --- |
| Expired SMS challenges, including destination phone | 24 hours after expiry |
| Phone/IP rate-limit keys | 24 hours after last request |
| Expired or revoked sessions | 30 days |
| Messaging-provider IDs, status text, bounded error details, dispatch time | Scrubbed after 30 days; delivery outcome remains |
| Privacy-safe hourly operational counters and latency buckets | 30 days |
| Bounded independent-monitor failure/recovery records | 30 days |
| Events that were not confirmed | Deleted 5 days after the reply deadline |
| Sealed response envelopes and both key wraps | Deleted 90 days after final event resolution, or earlier when the host deletes the event |
| Signed response-log commitments and heads | Indefinite, append-only; they contain hashes and identifiers, not condition plaintext or response ciphertext |
| Confirmed event, account, guest, final-result, and signed result-proof records | Until the host/account owner deletes the owning record; the result proof is public verification material and is retained with the final outcome. Invitee deletion preserves a scrubbed mutable member placeholder while the immutable signed policy retains only the opaque event-scoped member ID |

The operational tables contain only fixed component, signal, operation, outcome, status/error
class, latency bucket, release ID, and aggregate counts—or a fixed monitor target/failure class.
They never persist correlation IDs. The retention task logs counts only. It never logs IDs, phones, tokens,
ciphertext, conditions, or request bodies. Its behavior is exercised against a
real built Worker and D1 database in `invitee-web/tests/data-retention.test.mjs`.

## Account deletion contract

Account deletion is available from **Your profile** in both clients. The API
accepts it only from a phone-authenticated session created within the previous
five minutes and requires an exact destructive confirmation. A stale session
must complete phone verification again.

The deletion runs as one D1 batch. It invalidates invitation capabilities,
deletes guest delivery diagnostics, scrubs guest name and phone fields, removes
hosted events, profile, sessions, account-key epochs, and sealed response
envelopes, and clears phone-linked challenges and rate-limit state. A membership
row used by somebody else's frozen event becomes an unlinked “Deleted account”
placeholder. The immutable signed policy contains only that opaque event-scoped
member ID—never the guest name, phone number, or a phone-derived assignment—so
deletion does not have to rewrite signed rules to erase those fields.
Append-only response commitments remain because they contain no response
ciphertext or plaintext and deleting them would make the public log rewritable.

`invitee-web/tests/account-deletion.test.mjs` verifies the recent-authentication
gate, cross-origin and confirmation failures, database cascades, tombstoning,
old-link invalidation, session invalidation, commitment survival, an in-flight
verified-SMS/deletion race, PII-free frozen membership, and clean same-phone
account recreation.

## Release gates

Before promoting a release:

1. Run the full repository test gate.
2. Run `node scripts/verify-data-contract.mjs`. It compares the machine-readable
   inventory to every column in the final migration snapshot, rejects readable
   private-response tables/columns, and requires the response payload and key
   wraps to remain classified as sealed.
3. Export the candidate database schema without data and compare it to the
   release migration snapshot. Reject any unknown table or column before
   serving traffic.
4. Confirm production has only the approved SMS-only single-digit access switch,
   with no test keys, test origins, request-body logging, session replay, DOM
   capture, or third-party scripts on reply screens.
5. Confirm the confidential evaluator has container log redirect and memory
   monitoring disabled, no debug access, and only the documented count/status
   operational signals.

## Sentinel privacy drill

Run this only in the isolated test project, never by inserting artificial data
into production.

1. Create a test event through the normal clients. Put a unique high-entropy
   sentinel in the invitee-only condition input and exercise both reply values,
   edits, the deadline, and resolution.
2. Export the test D1 database and collect the corresponding application/CDN
   logs and any approved diagnostic export. Do not add request-body logging for
   the drill.
3. Put one sentinel per line in the local `HERD_PRIVACY_SENTINELS` environment
   variable. Run `node scripts/scan-sensitive-artifacts.mjs` over the exports.
   The scanner checks raw, JSON-escaped, URL-encoded, base64, and base64url
   forms without printing the sentinel itself.
4. For a database dump, also pass `--reject-readable-response-fields`. Any
   readable reply/condition field or sentinel occurrence fails the drill.
5. Retain the signed pass/fail report and export digests, then securely remove
   the drill artifacts.

The scanner itself has positive and negative regression tests in
`security/tests/artifact-scan.test.mjs`.

## Backup and restore

Cloudflare D1 Time Travel is always enabled for databases on its production
storage backend and supports point-in-time recovery. Provider history is
retained for 30 days on paid Workers plans and 7 days on free plans, so a live
deletion can remain in encrypted provider backup history for that additional
window. Herd does not claim immediate erasure from provider disaster-recovery
media. [Cloudflare's current Time Travel documentation](https://developers.cloudflare.com/d1/reference/time-travel/)
is authoritative for the plan and recovery window.

Before every migration or incident restore:

1. Verify the exact project and database; production and test databases must
   never share an identifier.
2. Record the current Time Travel bookmark and the signed release/deployment ID.
3. Apply and rehearse migrations on a disposable test database first.
4. Treat a production restore as destructive: stop writes, require an incident
   approver, record the target timestamp/bookmark, and preserve the pre-restore
   bookmark so the restore can be undone.
5. After restore, rerun schema/data-contract verification, transparency-head
   continuity checks, production-config verification, authentication isolation,
   and a complete encrypted-response smoke test before reopening writes.

D1 currently overwrites the selected database during Time Travel restore; it
does not provide a general clone/fork recovery operation. Never rehearse by
restoring the production database. For longer-lived encrypted exports, use the
documented D1 export path to a separately access-controlled account and apply
an explicit lifecycle rule. [Cloudflare's import/export documentation](https://developers.cloudflare.com/d1/best-practices/import-export-data/)
describes the current export format and its operational limitations.

## Incident conditions

Immediately stop new response submissions if any of the following occurs:

- a sentinel appears outside the confidential evaluator;
- a response table gains a readable private field;
- a signed receipt is absent from the public log, or witnesses observe a gap,
  rewind, fork, or signing-key change;
- a production client accepts a test root, unknown evaluator measurement,
  debug-enabled workload, environment/command override, non-Always restart
  policy, or memory monitoring;
- an evaluator/release private key, backend bearer token, or production auth
  pepper may have been exposed;
- test access changes any behavior after SMS verification.

Follow the confidential evaluator incident and key-rotation runbooks, preserve
hash-only evidence, and publish the affected release IDs. Rotate the ordinary
release or evaluator epoch when that contains the affected material. A global
response-log key exposure or observed fork permanently seals that log and
requires the documented new-log-ID and witness-bootstrap ceremony; it is not
an in-place release rotation. Do not resume until the applicable replacement
has passed every gate above.
