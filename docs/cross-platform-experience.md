# Cross-platform experience parity

Herd has one product experience with three renderers: web, the downloaded
iPhone app, and the App Clip. The web experience is the
design, content, information-architecture, and interaction source of truth for
every shared surface. A difference among web, downloaded app, and App Clip must
be caused by a real platform capability, not by independent product decisions.

React and SwiftUI may use different code and native implementation patterns.
The two native targets may also share SwiftUI source. None of the renderers need
structural code parity. They do need user-visible parity in
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

If an authenticated phone number does not own the invitation, every renderer
offer an explicit account switch and preserve the link while the current
session is removed. The iPhone target declares the associated domain, and the
web origin serves `/.well-known/apple-app-site-association` directly without a
redirect. Production release configuration derives that domain from the signed
web origin and publishes the signed app identifier to the web runtime.

The App Clip uses the native guest experience, including authentication,
invitation detail, private replies, attendee visibility, refresh, and profile
management. Hosting entry points lead to the full-app download handoff because
App Clips cannot use Contacts. Its reply-success screen has one `Download Herd`
action. Both native download entry points keep Apple's full-app card and show
“Once downloaded, tap Open to continue” above it in bundled Gochi Hand, with a
short handwriting reveal and downward arrow. Reduce Motion shows the complete
note immediately. The hosting handoff content stays near the upper third of
the page before and during the card presentation; the content can scroll on
smaller displays. The font and its SIL Open Font License are in `HerdHost/Fonts`.
It stores sessions and protected reply material in its own default
Keychain; on iOS 15.4 and later the system makes those items available to the
corresponding full app through the signed parent/App Clip association. Neither
target declares a custom Keychain-sharing group.

## Intentional differences

| Experience | Downloaded iPhone app | Web | App Clip |
| --- | --- | --- | --- |
| Full event authoring | Creates and edits drafts in the native event editor and contact picker | New events open the iPhone handoff; hosted drafts retain shared detail and bounded management actions but not the full editor | New events open the iPhone handoff; the shared guest experience remains native |
| Add people | Uses the system Contacts picker, with manual entry available | Uses manual entry because browsers do not provide dependable cross-browser Contacts access | Hosting entry points hand off to the downloaded app because App Clips cannot use Contacts |
| Address suggestions | Uses MapKit search suggestions | Uses browser address autofill; adding a third-party geocoder requires a separate privacy and provider review | Not shown because full event authoring hands off to the downloaded app |
| Protect an opened reply | May use Face ID to protect the local screen | Uses the authenticated account session because browsers cannot require Face ID consistently | May use Face ID to protect the local screen |

Everything else is presumed to require parity. Add a difference to this table
before shipping it, with the platform constraint that requires it.

## Home-screen contract

All three home screens now:

- show `Herd events` without a greeting or platform-only eyebrow;
- use profile initials in the same circular control;
- show invited and hosted current events together in one chronological list,
  without separate `Your invites` or `Your hosted events` headings;
- move all other events into `Past events` at local midnight after the event date;
- move events whose reply deadline has passed without confirmation into the final
  `Events never confirmed` section, with a note that they automatically delete
  five days after the reply deadline;
- use the same event metrics, countdown states, spacing, and card radius;
- put event creation in the circular plus control in the header; and
- show a centered `No upcoming events` state with a `Host an event` action only
  when the account has no event cards at all.

The web and App Clip creation actions route to the downloaded-iPhone-app
handoff. Sent hosted events open the shared event-detail experience on every
applicable renderer. An unsent hosted draft opens the full editor in the
downloaded app and the bounded hosted-draft detail on web, as recorded in the
exception table above.

`Account diagnostics` is a profile setting on all three renderers. It must not
occupy a primary action in the Herd Events header.

## Shared account and invitation contract

The `profile`, `invitation`, `attendees`, `reply`, `privacy`, and `success`
sections of `HerdExperience.json` are the content contract for all three
renderers. Together they require every applicable renderer to use the same:

- profile field order, sync/privacy note, save and logout order, and logout warning;
- event hero, status semantics, metadata, metrics, guest-list entry, and resolution states;
- dedicated guest-list screen with host and current-user markers;
- privacy callout and full proof/limits screen;
- reply selection and condition editing before an explicit submit action;
- unavailable-response language and account-wide saved-reply recovery; and
- successful-response summary and return actions.

On the privacy screen, the navigation divider stays hidden at rest and while
only the space above the heading has scrolled. It appears when the top of the
heading lettering reaches the navigation edge, and hides again on return. The
compact navigation title still appears only after the large title has scrolled
out of view. This applies to web, iPhone, and App Clip.

Selecting a reply is local editing state. It must never show `Responded` or
perform a network write until the explicit encrypted-reply submit action
succeeds.

For invitation details, all renderers use `invited` and `min attendees` in the
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

Matched reference screenshots and the screen-by-screen decision matrix live in
`docs/parity-audit-2026-07-31/`. Capture all applicable renderers at the same
mobile device class and data state whenever a shared experience changes,
including the App Clip whenever its shared SwiftUI experience or handoff
behavior is affected.

The latest executable audit is recorded in `docs/parity-audit-2026-08-18.md`.
