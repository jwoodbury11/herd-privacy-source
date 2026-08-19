# Herd private-response architecture

Status: protocol-v2 current-state summary
Last reviewed: 2026-08-18

The normative contract is
[`simplified-ballot-architecture.md`](simplified-ballot-architecture.md). This short file exists so
older links resolve to the current architecture instead of the retired device-owned design.

## Current system

1. A phone-authenticated account can read or update its own reply from any signed-in iOS or web
   session. There is no active encryption device, device transfer, or device-owned response.
2. The authenticated identity boundary derives a stable, event-specific ballot ID and separate
   event-specific member IDs with a versioned HMAC. Those identifiers cannot be reversed by the
   ballot store or evaluator.
3. D1 stores append-only ballot revisions without account IDs, invitee IDs, names, phone numbers,
   tokens, or sessions. Exact retries are idempotent and confirmed events reject changes.
4. The evaluator bridge deterministically converts the latest ballot revisions into sealed
   evaluator slots. The existing isolated evaluator computes the same greatest-fixed-point event
   result and returns only the permitted aggregate outcome.
5. Hosts and guests can see event details, response progress where allowed, and the confirmed
   result. They never receive another guest's conditions.
6. Ordinary analytics contain only bounded aggregate reliability signals. Ballot content and
   identifiers are excluded.

The only expanded user-facing explanation is:

> Your conditions are evaluated using a private, event-specific ballot ID—not your name, phone
> number, account, or other identifying information. They’re never shown to hosts, guests, or
> third parties.

Do not add product copy about internal troubleshooting or operator access.

## Compatibility boundary

Protocol-v1 envelopes, account-key endpoints, and their evaluator validation remain temporarily
available only for already-installed clients and rollback during the v2 rollout. New and updated
replies use v2 ballots, and a v2 ballot takes precedence for that participant.

The compatibility bridge may be deleted after production observation proves that supported iOS
and web clients use v2, no unresolved event depends solely on a v1 envelope, rollback no longer
targets the old client, and the removal passes replay and release-continuity gates. Until then,
keep it isolated from product UI and do not add new v1 behavior or tests beyond compatibility and
rollback coverage.

Historical v1 details remain in
[`private-response-protocol-v1.md`](private-response-protocol-v1.md) and the immutable
`archive/pre-simplification-2026-08-18` savepoint.
