import type { ComponentType, ReactNode } from "react";

export const LEGAL_EFFECTIVE_DATE = "Effective August 18, 2026";
export const HERD_SUPPORT_EMAIL = "jwoodbury11@gmail.com";
export const HERD_MESSAGING_NUMBER = "+1 (855) 253-9387";

export const termsMetadata = {
  title: "Terms of Service — Herd",
  description:
    "Terms for Herd, phone verification, and one-time event invitation messages.",
} as const;

export const privacyMetadata = {
  title: "Privacy Policy — Herd",
  description:
    "How Herd handles event invitation, messaging, and reply information.",
} as const;

export const smsConsentMetadata = {
  title: "One-Time SMS Invitation Consent — Herd",
  description:
    "Carrier-review documentation for Herd’s consumer-directed, one-time event invitation flow.",
} as const;

type PageFrame = ComponentType<{
  eyebrow: string;
  title: string;
  intro: string;
  children: ReactNode;
}>;

type SectionFrame = ComponentType<{
  title: string;
  children: ReactNode;
}>;

type DocumentFrameProps = {
  Page: PageFrame;
  Section: SectionFrame;
};

function SupportLink() {
  return <a href={`mailto:${HERD_SUPPORT_EMAIL}`}>{HERD_SUPPORT_EMAIL}</a>;
}

export function TermsDocument({ Page, Section }: DocumentFrameProps) {
  return (
    <Page
      eyebrow="Terms of service"
      title="Simple terms for making plans together."
      intro="These terms govern Herd’s event-planning experience, requested verification codes, and one-time event invitation text messages. Herd is operated by James Woodbury as a sole proprietor."
    >
      <Section title="Using Herd">
        <p>
          Herd helps a host invite people they know to an event and collect private replies. You may use Herd only for lawful,
          personal event planning and must provide accurate information when creating an invitation.
        </p>
      </Section>

      <Section title="Requested phone verification codes">
        <p>
          When you enter your phone number and choose “Text me a code,” Herd sends a one-time verification message so you can
          access your account. A code is sent only after that request, expires after a short period, and is not a marketing
          subscription. Message and data rates may apply.
        </p>
      </Section>

      <Section title="Host responsibilities">
        <p>Before sending an invitation, a host must:</p>
        <ul>
          <li>Select each recipient individually.</li>
          <li>Know the recipient and have their prior permission to receive the invitation.</li>
          <li>Use Herd only for the event described in the invitation.</li>
          <li>Never use contact uploads, purchased lists, incentives, or an “Invite All” workflow.</li>
        </ul>
      </Section>

      <Section title="One-time SMS and MMS invitations">
        <p>
          Each invited person receives one event invitation from Herd at the host’s request. Message frequency is one message
          per invitation. Herd does not send automatic reminder or promotional messages from this invitation flow. Message and
          data rates may apply.
        </p>
        <p>
          Reply <strong>STOP</strong> to opt out. Reply <strong>HELP</strong> for help, visit this website, or email <SupportLink />.
        </p>
      </Section>

      <Section title="No unwanted messages">
        <p>
          You may not use Herd to spam, harass, mislead, or repeatedly contact anyone. Herd may block invitations or suspend
          access when activity violates these terms, carrier requirements, or applicable law.
        </p>
      </Section>

      <Section title="Availability and changes">
        <p>
          Herd may change or be unavailable from time to time. We may update these terms as the service develops. Material
          changes will be reflected by a new effective date on this page.
        </p>
      </Section>

      <Section title="Contact">
        <p>Questions about these terms or Herd’s messaging program can be sent to <SupportLink />.</p>
      </Section>
    </Page>
  );
}

export function PrivacyDocument({
  Page,
  Section,
  requiredClauseClassName,
}: DocumentFrameProps & { requiredClauseClassName: string }) {
  return (
    <Page
      eyebrow="Privacy policy"
      title="Private replies, with honest boundaries."
      intro="This policy describes the information Herd uses for accounts, events, invitations, private replies, and one-time text delivery."
    >
      <Section title="Information Herd handles">
        <ul>
          <li>Your phone number, profile name and address, and phone-verification and session records.</li>
          <li>
            Event details, guest names and phone numbers supplied by a host, event membership, reply timing, and the final event
            result.
          </li>
          <li>
            Invitation delivery, provider-reported opt-out and support status, abuse-prevention, security, and limited network
            and operational records.
          </li>
        </ul>
      </Section>

      <Section title="How private replies work">
        <p>
          Your conditions are evaluated using a private, event-specific ballot ID—not your name, phone number, account, or
          other identifying information. They’re never shown to hosts, guests, or third parties.
        </p>
      </Section>

      <Section title="How the information is used">
        <p>
          Herd uses this information to authenticate accounts, create and display events, deliver a one-time invitation, open
          the correct event page, protect the service, and compute the permitted final event
          result. The configured messaging provider handles STOP, START, and HELP replies and maintains its messaging block
          list. The invitation flow is not used to enroll recipients in recurring marketing or reminder texts.
        </p>
      </Section>

      <Section title="Service providers and sharing">
        <p>
          Herd uses service providers for text delivery and phone verification, hosting and database storage, confidential
          computation, security, and product operations. They receive only the information needed to perform those services.
          Herd does not sell personal information or use invitation data for unrelated advertising.
        </p>
        <p className={requiredClauseClassName}>
          All the above categories exclude text messaging originator opt-in data and consent; this information won’t be shared
          with any third parties.
        </p>
      </Section>

      <Section title="Retention">
        <p>
          Expired phone-verification challenges and rate-limit keys are removed after 24 hours. Expired or revoked sessions are
          removed after 30 days. Messaging-provider identifiers and delivery diagnostics are scrubbed after 30 days. Private
          reply revisions are removed 90 days after a final event result, or sooner when the owning event or account is deleted.
        </p>
        <p>
          Event and account information otherwise remains until the owner deletes it. A deletion may remain temporarily in a
          hosting provider’s disaster-recovery history for its published recovery window.
        </p>
      </Section>

      <Section title="Delete your account and other choices">
        <p>
          You can permanently delete your account from <strong>Your profile</strong> in the Herd app or web experience. Herd
          confirms your phone again when the current session is not recent. Deletion removes your profile and phone, hosted
          events, sessions, invitation capabilities tied to you, and private replies. In another host’s already-sent event,
          the guest record may remain as “Deleted account” so the event record and final result stay consistent.
        </p>
        <p>
          The configured messaging provider handles STOP, START, and HELP replies and maintains its opt-out block list. Reply
          STOP to block future invitation texts to that number, START to opt back in, or HELP for help.
        </p>
      </Section>

      <Section title="Security">
        <p>
          Herd uses reasonable administrative and technical safeguards designed to protect information. No online service can
          promise absolute security, and Herd will continue to strengthen these safeguards as the service evolves.
        </p>
      </Section>

      <Section title="Contact">
        <p>Privacy and messaging questions can be sent to <SupportLink />.</p>
      </Section>
    </Page>
  );
}

export type SmsConsentClassNames = {
  statusCard: string;
  proofFrame: string;
  proofTopbar: string;
  proofBody: string;
  proofIcon: string;
  proofSummary: string;
  proofAttestation: string;
  proofSend: string;
  proofDisclosure: string;
  proofLinks: string;
  messageFormat: string;
  programDetails: string;
};

export function SmsConsentDocument({
  Page,
  Section,
  classNames,
}: DocumentFrameProps & { classNames: SmsConsentClassNames }) {
  return (
    <Page
      eyebrow="Carrier review document"
      title="Herd’s one-time invitation consent flow."
      intro="This public document shows the exact confirmation a host must complete before Herd sends a single event invitation to each selected recipient."
    >
      <div className={classNames.statusCard}>
        <span aria-hidden="true">✓</span>
        <div>
          <strong>Consumer-directed, one-time invitations</strong>
          <p>No recurring messages, automated follow-ups, contact-list uploads, or Invite All control.</p>
        </div>
      </div>

      <Section title="How the host initiates an invitation">
        <ol>
          <li>The host creates one specific event in the Herd iPhone app.</li>
          <li>The host individually selects known recipients from Contacts and reviews each name and phone number.</li>
          <li>When the host taps Send, Herd displays the confirmation shown below.</li>
          <li>The host’s final Send action affirmatively confirms prior recipient permission.</li>
          <li>Herd sends one invitation per selected recipient and schedules no automatic follow-up.</li>
        </ol>
      </Section>

      <Section title="Example of prior recipient permission">
        <p>
          <strong>Host:</strong> “May I send you one Herd text invitation for [event name]? It will be one message with the event
          details and a private response link. Message and data rates may apply. You can reply STOP to opt out or HELP for help.”
        </p>
        <p><strong>Recipient:</strong> “Yes.”</p>
        <p>
          The host then selects that recipient individually in Herd and completes the confirmation shown below. This permission
          applies only to that single invitation and does not authorize recurring messages.
        </p>
      </Section>

      <Section title="Exact confirmation shown before Send">
        <div className={classNames.proofFrame} aria-label="Herd host confirmation screen">
          <div className={classNames.proofTopbar}>
            <button type="button" disabled>Cancel</button>
            <strong>Confirm invitations</strong>
            <span aria-hidden="true" />
          </div>

          <div className={classNames.proofBody}>
            <div className={classNames.proofIcon} aria-hidden="true">↗</div>
            <h3>Send one-time invitations?</h3>
            <p>Herd will send one message to each guest you selected. No automatic reminders will follow.</p>

            <div className={classNames.proofSummary}>
              <div>
                <span aria-hidden="true">◎</span>
                <p><strong>4 invites</strong><small>Selected individually from your contacts</small></p>
              </div>
              <div>
                <span aria-hidden="true">◇</span>
                <p><strong>One message per guest</strong><small>Messaging provider handles STOP and HELP</small></p>
              </div>
            </div>

            <div className={classNames.proofAttestation}>
              By tapping Send, you confirm that you know these people and have their permission to receive this one-time event invitation.
            </div>

            <button className={classNames.proofSend} type="button" disabled>Send 4 invites</button>
            <small className={classNames.proofDisclosure}>
              Message and data rates may apply. Reply STOP to opt out or HELP for help.
            </small>
            <div className={classNames.proofLinks}>
              <a href="/terms">Terms</a><span>•</span><a href="/privacy">Privacy</a>
            </div>
          </div>
        </div>
      </Section>

      <Section title="Platform safeguards">
        <ul>
          <li>Every recipient is selected individually; there is no bulk import or Invite All function.</li>
          <li>The host must affirm prior recipient permission immediately before sending.</li>
          <li>No payment, reward, discount, credit, or referral incentive is offered for sending invitations.</li>
          <li>
            The invitation clearly identifies Herd and the host and states its one-time nature. The configured messaging provider
            handles STOP, START, and HELP replies and maintains its block list.
          </li>
          <li>An invitation does not enroll a recipient in recurring communication.</li>
        </ul>
      </Section>

      <Section title="Production invitation format">
        <blockquote className={classNames.messageFormat}>
          [Unique invitation link] [Host name] invited you to [Event title] — [event date and time in the event time zone]. Open
          the invitation and reply privately. One-time message sent at [Host name]’s request. Reply STOP to opt out; HELP for
          help. Msg &amp; data rates may apply.
        </blockquote>
      </Section>

      <Section title="Program information">
        <dl className={classNames.programDetails}>
          <div><dt>Brand</dt><dd>Herd, operated by James Woodbury</dd></div>
          <div><dt>Message purpose</dt><dd>One-time personal event invitation</dd></div>
          <div><dt>Message frequency</dt><dd>One message per invitation</dd></div>
          <div><dt>Sending number</dt><dd>{HERD_MESSAGING_NUMBER}</dd></div>
          <div><dt>Support</dt><dd><SupportLink /></dd></div>
        </dl>
      </Section>
    </Page>
  );
}
