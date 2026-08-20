# Private-response implementation status

Last reviewed: 2026-08-19
Scope: current repository state; production activation still requires the release gates.

## Implemented

- Web and iOS use the same account-wide protocol-v2 ballot API.
- Ballot and condition-member identifiers are stable within an event and distinct across events.
- Ballot revisions are append-only, exact retries are idempotent, and confirmed events reject
  changes.
- Ballot rows contain no user, account, invitee, name, phone, token, or session field.
- Protocol-v2 ballots resolve directly and deterministically in the API. Ordinary event edits,
  attendee edits, and replies do not require a remote evaluator certificate, frozen policy,
  browser relay, lease, or device-owned key.
- Pre-confirmation roster edits preserve append-only ballot revisions. Conditions that reference a
  removed attendee become unsatisfied; they never make the event uneditable or unreadable.
- The protected operator API supports de-identified inspection and append-only correction with a
  required audit record. It is not exposed in product UI or ordinary telemetry.
- The data inventory and generated database snapshot include every v2 table and field.
- User-facing privacy copy is shared across web, iOS, and legal surfaces and stays within the
  narrow product statement in `simplified-ballot-architecture.md`.
- Protocol-v1 remains a bounded, read-only compatibility bridge for untouched historical events;
  no protocol-v1 device-transfer or evaluator behavior remains in the current product UI.

## Required for production activation

- Apply the additive ballot migration to the production D1 database.
- Provision `HERD_BALLOT_PSEUDONYM_KEY` and the separate `HERD_OPERATOR_TOKEN` through protected
  production secrets.
- Pass the protected exact-SHA web/service, native, and release/security gates.
- Deploy the web/API revision, upload the matching iOS build, and complete account-wide cross-
  session ballot read/update plus deterministic evaluation in the isolated production canary.
- Publish signed release/deployment evidence only after live readiness, TestFlight metadata, and
  independent monitoring are green.

See [`simplified-ballot-architecture.md`](simplified-ballot-architecture.md) for the design and
[`operations/private-ballot-troubleshooting.md`](operations/private-ballot-troubleshooting.md) for
the private operational runbook.
