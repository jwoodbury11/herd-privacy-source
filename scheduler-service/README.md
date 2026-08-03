# Herd scheduler

The production design uses one dedicated Cloudflare Cron Worker. It runs every
minute so events can resolve after their RSVP deadlines even while every host
and guest is offline. There is deliberately no repository-hosted manual or
GitHub Actions recovery runner: an independent runner could drift from the
signed release configuration or send the scheduler credential to the wrong
origin. Recover an unavailable scheduler by restoring the pinned Worker and its
cron trigger from the approved production release.

The Worker claims a short-lived Herd lease, carries only the existing fixed-size
encrypted package to the pinned evaluator, and returns the signed result to
Herd. It cannot decrypt individual replies, and Herd still verifies the lease,
event policy, batch commitment, signature, and permitted final projection
before anything is saved.

The signed response contains the aggregate outcome and, when confirmed, opaque
member IDs. Neither courier logs request or response bodies, names, phone
numbers, or individual answers. The Worker has no public HTTP trigger and is
deployed with `workers_dev` disabled.

The Worker has no compiled-in origin, evaluator destination, key, or release
fallback. A release must apply the exact values generated in
`release/generated/scheduler-runtime-vars.json`:

- `HERD_DEPLOYMENT_PROFILE`
- `HERD_PUBLIC_APP_URL`
- `HERD_EVALUATOR_URL`
- `HERD_EVALUATOR_KEY_ID`
- `HERD_ARTIFACT_RELEASE_ID`
- `HERD_RELEASE_ID`
- `HERD_RELEASE_CONFIGURATION_SHA256`

Cloudflare also requires an encrypted `HERD_SCHEDULER_TOKEN` secret. It must
match the distinct secret configured in the production Herd Site. Missing,
preview/test, legacy, cross-release, same-origin, or malformed production
settings fail before the Worker makes a network request.

The authenticated `/claim`, `/complete`, and `/release` service paths remain a
private courier protocol, not an operator interface. A future alternate courier
must be separately reviewed, consume the exact seven-variable
`scheduler-runtime-vars.json` generated from the signed release, keep
`HERD_SCHEDULER_TOKEN` outside that file, apply the same pre-network validation,
and prove that the bearer is attached only to the pinned Herd origin and never
to the evaluator. Until then, do not copy the token into a shell command or
construct a manual request.

Run the Worker tests with `npm test`. Deploy the exact signed release artifact,
apply its generated non-secret bindings, and then set the secret with
`wrangler secret put HERD_SCHEDULER_TOKEN`.
