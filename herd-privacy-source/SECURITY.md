# Security policy

Herd's privacy boundary includes the client-side response encryption, account-key
handling, frozen event policy, response store, evaluator, scheduler, release
evidence, and independent monitor. Please treat a way to expose an individual
response or condition, accept an unapproved evaluator or release, bypass production
authentication, forge a result or receipt, or omit a committed response without
detection as security-sensitive.

## Reporting a vulnerability

Do not include vulnerability details in a public issue. Use GitHub's private
security-advisory reporting for this repository when it is available. If that
entry point is unavailable, contact the repository owner through GitHub and ask
for a private reporting channel without disclosing exploit details in the first
message.

Include the affected release ID or commit, the component and environment, a
minimal reproduction, expected and observed behavior, and whether plaintext,
keys, authentication, attestation, or release evidence may have been exposed.
Please avoid accessing other people's data and use reserved fixture identities.

Herd will acknowledge receipt, preserve relevant evidence, assess affected
releases and deployments, coordinate a fix and disclosure, and rotate or revoke
keys when required. No release should claim independent verification until open
critical or high findings against that release are resolved.

## Supported versions

Until signed public release manifests are published, no version is represented
as independently verified. Once publication begins, the signed release manifest
and deployment statement are the authoritative support record.
