# Cross-platform experience parity

Herd has one product experience with two renderers. The web experience is the
design, content, information-architecture, and interaction source of truth for
every shared surface. A difference between web and iPhone must be caused by a
real platform capability, not by independent product decisions.

React and SwiftUI may use different code and native implementation patterns.
They do not need structural code parity. They do need user-visible parity in
screen inventory, content order, copy, control meaning, validation, and
loading, empty, error, confirmation, success, and completed states.

## Source of truth

`invitee-web/shared/HerdExperience.json` owns cross-platform product copy and the layout
values needed to keep equivalent components aligned. The SwiftUI app decodes
the bundled file through `HerdExperience.shared`; the web app imports the same
file through `lib/experience.ts`.

Both apps also use the same authenticated event API and canonical event fields.
Platform components remain separate so iPhone can keep native navigation,
accessibility, Contacts, Keychain, and offline behavior, while the web keeps
browser navigation and browser cryptography.

## Authentication contract

Both authentication renderers consume `authentication` from the shared
experience file. The welcome and verification screens use the same:

- brand, release status disclosure, headline, supporting copy, and action labels;
- phone placeholder, validation readiness, and hidden single-digit test aliases;
- legal consent copy and links;
- masked phone-number treatment and four-cell verification-code entry;
- horizontal padding, control sizing, corner radii, and action placement.

The test aliases are request behavior only. They remain absent from product copy
and, while enabled, bypass only SMS before entering the normal production path.

## Invitation-link contract

Both renderers preserve the invitation capability through phone authentication
and then open the exact linked event. On iPhone, the app accepts only the
configured HTTPS origin's canonical `/invite/:token` universal link, rejects
credentials, queries, fragments, escaped path data, extra components, malformed
tokens, and every custom scheme, and never logs the token. A pending token is
stored device-only in Keychain rather than ordinary preferences and is removed
only after the linked detail actually appears or the person explicitly dismisses
it.

When either renderer carries an invitation into phone authentication, the
backend hashes both values and requires the token and normalized phone to match
the same invitee row before creating a challenge, granting a test-access session, or
calling the SMS provider. A missing token and a different phone receive the
same generic response with no event or phone details. The network request
budget is consumed before this comparison; the phone/SMS resend budget is
consumed only after a valid pair, so correcting a bad link does not throttle the
legitimate number.

If an authenticated phone number does not own the invitation, both renderers
offer an explicit account switch and preserve the link while the current
session is removed. The iPhone target declares the associated domain, and the
web origin serves `/.well-known/apple-app-site-association` directly without a
redirect. Production release configuration derives that domain from the signed
web origin and publishes the signed app identifier to the web runtime.

## Intentional differences

| Experience | iPhone | Web |
| --- | --- | --- |
| Create an event | Opens the native event editor and contact picker | Opens the iPhone download handoff |

Everything else is presumed to require parity. Add a difference to this table
before shipping it, with the platform constraint that requires it.

## Home-screen contract

Both home screens now:

- show `Herd events` without a greeting or platform-only eyebrow;
- use profile initials in the same circular control;
- group current events into `Your invites` and `Your hosted events`;
- move all other events into `Past events` at local midnight after the event date;
- move events whose reply deadline has passed without confirmation into the final
  `Events never confirmed` section, with a note that they automatically delete
  five days after the reply deadline;
- show section headings only when more than one event group is populated;
- label cards `Hosting` or `Invited` consistently;
- use the same event metrics, countdown states, spacing, card radius, and create-card height;
- show the same `Host an event` card when the list is empty or populated.

The web card alone routes to the iPhone handoff, which is the explicit exception
above.

Existing hosted events are not part of that exception. On both platforms they
open the shared event-detail experience. Only a newly started event opens the
iPhone editor.

## Shared account and invitation contract

The `profile`, `invitation`, `attendees`, `reply`, `privacy`, and `success`
sections of `HerdExperience.json` are the content contract for both renderers.
Together they require both platforms to use the same:

- profile field order, sync/privacy note, save and logout order, and logout warning;
- event hero, status semantics, metadata, metrics, guest-list entry, and resolution states;
- dedicated guest-list screen with host and current-user markers;
- privacy callout and full proof/limits screen;
- reply selection and condition editing before an explicit submit action;
- unavailable-response language and the verified switch-to-this-device warning; and
- successful-response summary and return actions.

Selecting a reply is local editing state. It must never show `Responded` or
perform a network write until the explicit encrypted-reply submit action
succeeds.

For invitation details, both renderers use `invited` and `min attendees` in the
metric strip, `Your encrypted reply has been sent` beside the lock, and
`View my encrypted reply` for the primary unlock action. An unreadable local
reply changes to the replacement action instead of repeating an unusable unlock.
Primary reply actions share one filled treatment; platform-native Face ID and
keyboard controls may use their native symbols while keeping equivalent meaning.

Existing draft hosted events expose the same `Allow attendees to add guests`
boolean. iPhone uses the native switch and web uses an accessible `role=switch`
control; both show a distinct track and thumb, persist the value to the shared
event, and disable mutation after invitations freeze the event policy.

## Visual regression evidence

Paired reference screenshots and the screen-by-screen decision matrix live in
`docs/parity-audit-2026-07-31/`. Capture both renderers at the same mobile
device class and data state whenever a shared experience changes.
