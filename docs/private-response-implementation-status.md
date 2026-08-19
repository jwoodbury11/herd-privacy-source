# Private-response implementation status

Last reviewed: 2026-08-18
Scope: current repository state; production activation still requires the release gates.

## Implemented

- Web and iOS use the same account-wide protocol-v2 ballot API.
- Ballot and condition-member identifiers are stable within an event and distinct across events.
- Ballot revisions are append-only, exact retries are idempotent, and confirmed events reject
  changes.
- Ballot rows contain no user, account, invitee, name, phone, token, or session field.
- The evaluator bridge deterministically seals a revision-specific slot and records the exact
  revision set and input digest used for each evaluation.
- The protected operator API supports de-identified inspection and append-only correction with a
  required audit record. It is not exposed in product UI or ordinary telemetry.
- The data inventory and generated database snapshot include every v2 table and field.
- User-facing privacy copy is shared across web, iOS, and legal surfaces and stays within the
  narrow product statement in `simplified-ballot-architecture.md`.
- Protocol-v1 remains a bounded compatibility and rollback bridge for already-installed clients;
  no device-transfer behavior remains in the current product UI.

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
