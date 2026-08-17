# Herd web app

Herd’s responsive web app shares one authenticated production backend and D1
database with the iPhone app. People sign in by phone, see the same persisted
events, and save device-encrypted conditional replies.

## Run and verify

Node.js 22.13 or newer is required.

```bash
npm install
npm run dev
npm run build
npm test
npm run test:browser-ui
```

Browser acceptance tests use disposable local databases and service doubles.
They are test infrastructure, not another deployed Herd product.

## Production architecture

- `app/` contains the web renderer and the API used by both web and iPhone.
- `db/schema.ts` and `drizzle/` define the single production data model.
- `shared/HerdExperience.json` is consumed directly by both renderers.
- `lib/privacy/` implements browser cryptography and trust verification.
- `.openai/hosting.json` identifies the only deployed Sites project.

Public evaluator and Confidential Space attestation pins are injected from the
production runtime configuration. Secrets stay server-only. The production
database remains the system of record for accounts, events, key epochs,
encrypted responses, signed results, and invitation delivery.

## Internal test-account access

Production SMS verification uses Twilio Verify. Internal access can be enabled
with `HERD_TEST_ACCOUNT_ACCESS_ENABLED` and rotated with
`HERD_TEST_ACCOUNT_ACCESS_GENERATION`. It changes only the initial SMS
challenge. Once authenticated, those users follow the same production code,
database, invitation messaging, evaluator, cryptography, and UI paths as every
other account. Disabling access or changing the generation invalidates those
sessions.

The mechanism is intentionally absent from product copy and screenshots.

## Private responses and delivery

The browser pads each response to 4,096 plaintext bytes, encrypts it with
AES-256-GCM, and wraps the response key separately for the user’s local account
key and the release-pinned evaluator. The API accepts only the fixed-size
encrypted envelope.

Sending an event freezes its signed policy and creates a durable invitation
outbox row for every guest. Every recipient uses the same configured Twilio
Messaging Service path. Provider acceptance, rejection, and ambiguous failures
are persisted without exposing phone numbers, tokens, or provider credentials
in client projections.

## Database changes

Apply every migration in `drizzle/` before serving a new version. After a fresh
bootstrap, verify `/api/internal/evaluator-epoch-status` reports generation 1 as
active with `runtimeMatchesState: true`. The release fails closed rather than
silently backfilling unsigned legacy evaluator state.
