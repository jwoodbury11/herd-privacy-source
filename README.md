# Herd

Documentation entry point: [`docs/README.md`](docs/README.md). Current deployed state:
[`CURRENT_BUILDS.md`](CURRENT_BUILDS.md). Operational troubleshooting:
[`docs/observability/troubleshooting.md`](docs/observability/troubleshooting.md).

Herd helps groups make plans that depend on enough people—and sometimes the right combination of people—being able to attend. This repository keeps the iPhone and web experiences together on one authenticated backend.

## Start here

Use [`CURRENT_BUILDS.md`](CURRENT_BUILDS.md) as the single view of the latest
shared source, production web app, and production-configured Xcode project.

## Repository layout

- `HerdHost/` and `HerdHost.xcodeproj/`: native SwiftUI app with phone sign-in and server-backed event sync
- `invitee-web/`: responsive web app, invitation routes, authenticated API, and D1 schema
- `invitee-web/shared/HerdExperience.json`: cross-platform product copy and layout contract consumed by both app renderers
- `privacy-evaluator/`: protocol-v1 envelope decryption and deterministic event-resolution core
- `confidential-evaluator/`: measured evaluator workload and its isolated response/evaluation authority
- `infrastructure/gcp-confidential-space/`: pinned Confidential Space production infrastructure
- `release/`, `public-source/`, and `monitor/`: signed release evidence, deterministic source export, and independent verification
- `docs/`: the private-response protocol, threat model, and implementation/launch status

## Run the iPhone app

1. Open `HerdHost.xcodeproj` in Xcode 26 or newer.
2. Select an iPhone simulator or a connected iPhone.
3. Press Run.

The app uses the real Contacts permission and displays only contacts made available to Herd. Contact identifiers remain on-device.

## Run the web app

The web app requires Node.js 22.13 or newer.

```bash
cd invitee-web
npm ci
npm run dev
```

Use `npm test` for the production build and rendered-page checks.

## Verify the privacy boundary

The permanent local gate exercises the clients, services, release evidence,
public-source export, monitor, Terraform configuration, and native iOS tests:

```sh
npm ci --prefix invitee-web --ignore-scripts
npm ci --prefix herd-legal --ignore-scripts
npm ci --prefix evaluator-service --ignore-scripts
npm ci --prefix scheduler-service --ignore-scripts
npm ci --prefix monitor --ignore-scripts
scripts/test-all
```

Use the exact Node, npm, Terraform, and Apple versions in
`release/toolchains.json`. The same commands work from the root of the extracted
public archive; hosted CI verifies the archive and runs the privacy service,
browser, infrastructure, source-contract, native unit, and native UI gates from
that extracted copy.

The same privacy-critical surfaces have hosted gates in
`.github/workflows/privacy-ci.yml`. The deterministic public export is an
allowlist: it includes the implementation and tests needed to inspect the
privacy boundary while excluding credentials, local deployment state, private
reference material, generated artifacts, and unallowlisted non-code media. The
few first-party PNGs needed to build the product surfaces are exact-path and
SHA-256 pinned by the policy. See
[`docs/public-source-export.md`](docs/public-source-export.md).

## Shared backend

Both apps use the same phone-authenticated API for accounts, profiles, events,
and account-wide private ballots. The iPhone app keeps a per-user offline cache,
while Cloudflare D1 remains the source of truth. Contact identifiers stay
on-device and are never sent to the API.

Private conditions are stored under event-specific ballot identifiers without
names, phone numbers, account identifiers, or other identifying fields. They are
never shown to hosts, guests, or third parties. See
[`docs/private-response-implementation-status.md`](docs/private-response-implementation-status.md)
for the exact implemented boundary and the production-activation evidence
still required before launch claims are appropriate.

## Cross-platform experience

The iPhone and web apps render with native SwiftUI and React components, but
shared product decisions belong in `invitee-web/shared/HerdExperience.json`. Both builds
consume that file directly, so changing a shared home-screen label or layout
value changes both experiences. The home feed uses the same current, unconfirmed,
and past event grouping, card language, profile treatment, and empty state on
both platforms.

The only intentional home-screen capability difference is event creation: the
iPhone opens the native event editor, while the same web card opens the iPhone
handoff. See `docs/cross-platform-experience.md` for the parity rule.

Live verification is delivered through Twilio Verify. One-time event invitations use a separate Twilio Messaging Service and a durable delivery outbox. Internal test-account access changes only the initial SMS challenge; authenticated accounts then use the exact production database, messaging, privacy, and product paths. Confidential evaluator deployment and verifiable releases remain separate production rollout steps.

## License

The material selected by `public-source/export-policy.json` is available under
Apache License 2.0. Private repository history and material outside that
explicit export boundary are not part of the public distribution.
