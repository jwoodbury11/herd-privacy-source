# Herd private-response evaluator

This package is the dependency-free reference implementation of Herd's
privacy-critical evaluation core. It:

- strictly validates and decrypts the evaluator wrap and fixed-size payload from
  a protocol-v1 response envelope;
- rejects tampering, unexpected fields, wrong evaluator key IDs, and invalid
  condition references; and
- applies Herd's deterministic attendance rule, emitting only:

- `not_confirmed` when the host policy fails; or
- `confirmed` plus the final attendance list.

It never returns thresholds, condition groups, failed predicates, traces, or
counterfactual results.

Run `npm test` in this directory to verify the encrypted-envelope boundary,
tamper rejection, fixed-point behavior, 5/10/20-participant scenarios, all
`3^9` unconditional response patterns at every launch threshold, and the
nine-invitee conditional/host-rule property matrix against an independent
subset-search oracle.

The self-contained production package is implemented in
[`../confidential-evaluator`](../confidential-evaluator). Its container vendors
this core under a source-manifest hash, runs it inside the fail-closed
Confidential Space boundary, verifies frozen policies and committed batches,
signs only the minimal result, and suppresses plaintext diagnostics. Publishing
and activating an actual production deployment remains the external release
operation documented in
[`../docs/private-response-implementation-status.md`](../docs/private-response-implementation-status.md).
