"use client";

import Image from "next/image";
import { ChevronLeft, Clock, ContactRound, Crown, MapPin, UserRound } from "lucide-react";
import { Fragment, useEffect, useRef, useState, type CSSProperties } from "react";
import { herdExperience } from "@/lib/experience";
import { relayHostEventEvaluation } from "@/lib/client/evaluation-relay";
import {
  PrivateVaultError,
  accountRootSecretCommitment,
  forgetAllAccountRootSecrets,
  getOrCreateAccountRootSecret,
  loadAccountRootSecret,
} from "@/lib/privacy/device-vault";
import { attestEvaluatorForPolicy } from "@/lib/privacy/evaluator-attestation";
import {
  displayableEventResolution,
  type DisplayableEventResolution,
} from "@/lib/privacy/event-resolution-proof";
import {
  PrivateResponseCryptoError,
  newConditionGroupId,
  openPrivateResponse,
  privateResponseEnvelopeHash,
  sealPrivateResponse,
} from "@/lib/privacy/private-response-crypto";
import type {
  PrivateResponsePolicyV1,
  PrivateResponseReceiptV1,
  StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";
import {
  configuredTransparencySigningPin,
  verifyPrivateResponseReceiptPublication,
} from "@/lib/privacy/trust-verification";

const OTP_LENGTH = 4;
const AUTH_EXPERIENCE = herdExperience.authentication;
const HOME_EXPERIENCE = herdExperience.home;
const PROFILE_EXPERIENCE = herdExperience.profile;
const INVITATION_EXPERIENCE = herdExperience.invitation;
const ATTENDEES_EXPERIENCE = herdExperience.attendees;
const REPLY_EXPERIENCE = herdExperience.reply;
const PRIVACY_EXPERIENCE = herdExperience.privacy;
const SUCCESS_EXPERIENCE = herdExperience.success;

const authLayoutStyle = {
  "--auth-horizontal-padding": `${AUTH_EXPERIENCE.layout.horizontalPadding}px`,
  "--auth-top-padding": `${AUTH_EXPERIENCE.layout.topPadding}px`,
  "--auth-welcome-top-spacing": `${AUTH_EXPERIENCE.layout.welcomeTopSpacing}px`,
  "--auth-field-height": `${AUTH_EXPERIENCE.layout.fieldHeight}px`,
  "--auth-button-height": `${AUTH_EXPERIENCE.layout.buttonHeight}px`,
  "--auth-field-corner-radius": `${AUTH_EXPERIENCE.layout.fieldCornerRadius}px`,
  "--auth-button-corner-radius": `${AUTH_EXPERIENCE.layout.buttonCornerRadius}px`,
  "--auth-verification-code-gap": `${AUTH_EXPERIENCE.layout.verificationCodeGap}px`,
  "--auth-verification-code-width": `${AUTH_EXPERIENCE.layout.verificationCodeWidth}px`,
  "--auth-verification-code-height": `${AUTH_EXPERIENCE.layout.verificationCodeHeight}px`,
  "--auth-verification-code-corner-radius": `${AUTH_EXPERIENCE.layout.verificationCodeCornerRadius}px`,
  "--auth-verification-code-alignment": AUTH_EXPERIENCE.layout.verificationCodeAlignment,
} as CSSProperties;

const homeLayoutStyle = {
  "--home-horizontal-padding": `${HOME_EXPERIENCE.layout.horizontalPadding}px`,
  "--home-top-padding": `${HOME_EXPERIENCE.layout.topPadding}px`,
  "--home-bottom-padding": `${HOME_EXPERIENCE.layout.bottomPadding}px`,
  "--home-vertical-gap": `${HOME_EXPERIENCE.layout.verticalGap}px`,
  "--home-header-to-first-card-gap": `${HOME_EXPERIENCE.layout.headerToFirstCardGap}px`,
  "--home-card-corner-radius": `${HOME_EXPERIENCE.layout.cardCornerRadius}px`,
  "--home-card-padding": `${HOME_EXPERIENCE.layout.cardPadding}px`,
  "--home-create-card-min-height": `${HOME_EXPERIENCE.layout.createCardMinimumHeight}px`,
  "--home-profile-avatar-diameter": `${HOME_EXPERIENCE.layout.profileAvatarDiameter}px`,
} as CSSProperties;

type Screen =
  | "welcome"
  | "verify"
  | "home"
  | "profile"
  | "host-download"
  | "event"
  | "attendees"
  | "privacy"
  | "success";

type Reply = "yes" | "no" | null;
type PrivateResponseState = "idle" | "loading" | "ready" | "unreadable";

type ApiUser = {
  id: string;
  phoneNumber: string;
  name: string;
  address: string;
};

type ApiInvitee = {
  id: string;
  displayName: string;
  phoneNumber?: string;
  isCurrentUser?: boolean;
};

type ApiRequiredGroup = {
  id: string;
  memberIDs: string[];
};

type InvitationDeliveryStatus =
  | "pending"
  | "dispatching"
  | "sent"
  | "failed"
  | "unknown"
  | "suppressed";

type InvitationDeliverySummary = {
  status: "in_progress" | "complete" | "attention_needed" | "suppressed";
  total: number;
  counts: Record<InvitationDeliveryStatus, number>;
  guests: {
    inviteeId: string;
    displayName: string;
    status: InvitationDeliveryStatus;
  }[];
};

export type ApiEvent = {
  id: string;
  title: string;
  eventDate: string | null;
  endDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  invitees: ApiInvitee[];
  minimumParticipants: number;
  requiredGroups: ApiRequiredGroup[];
  rsvpDeadline: string | null;
  eventDescription: string;
  createdAt: string;
  invitationsSent: boolean;
  role?: "host" | "invitee";
  inviteToken?: string;
  privateResponsePolicy: PrivateResponsePolicyV1 | null;
  accountKeyEpochId?: string;
  accountKeyCommitment?: string | null;
  hasResponse?: boolean;
  responseRevision?: number | null;
  resolution?: DisplayableEventResolution | null;
  invitationDelivery?: InvitationDeliverySummary | null;
};

async function verifiedApiEvent(event: ApiEvent): Promise<ApiEvent> {
  return {
    ...event,
    resolution: await displayableEventResolution(
      {
        eventId: event.id,
        rsvpDeadline: event.rsvpDeadline,
        privateResponsePolicy: event.privateResponsePolicy,
      },
      event.resolution,
    ),
  };
}

function sortEventsForHome(events: ApiEvent[]) {
  return [...events].sort((left, right) => {
    if (!left.eventDate && !right.eventDate) {
      return left.createdAt.localeCompare(right.createdAt);
    }
    if (!left.eventDate) return 1;
    if (!right.eventDate) return -1;
    return left.eventDate.localeCompare(right.eventDate);
  });
}

function upsertHomeEvent(events: ApiEvent[], event: ApiEvent) {
  return sortEventsForHome([event, ...events.filter((item) => item.id !== event.id)]);
}

type InviteMetadata = {
  id: string;
  displayName: string;
  phoneNumberMasked: string;
  authenticated: boolean;
  canRespond: boolean;
  requiresAuthentication: boolean;
  accountKeyEpochId: string;
  accountKeyCommitment: string | null;
  hasResponse: boolean;
  responseRevision: number | null;
  responseEnvelope: StoredPrivateResponseEnvelopeV1 | null;
};

type AuthenticatedInviteResponse = {
  event?: ApiEvent;
  invitation?: ApiEvent;
  inviteMetadata?: InviteMetadata;
};

type AuthChallenge = {
  challengeId: string;
  phoneNumber: string;
  expiresAt: string;
  resendAt: string;
};

type AuthSession = {
  user: ApiUser;
  accountKeyEpochId: string;
  accessToken: string;
  expiresAt: string;
};

type InvitationPreview = {
  eventId: string;
  title: string;
  hostName: string;
  eventDate: string | null;
  phoneNumberMasked: string;
  requiresAuthentication: true;
};

function initialsTone(index: number) {
  return `avatar-tone-${(index % 5) + 1}`;
}

function focusInputAtEnd(input: HTMLInputElement | null) {
  if (!input) return;
  input.focus();
  input.setSelectionRange(input.value.length, input.value.length);
}

function formatPhoneNumber(value: string) {
  const rawDigits = value.replace(/\D/g, "");
  if (value.trimStart().startsWith("+")) return `+${rawDigits.slice(0, 15)}`;
  if (rawDigits.length > 10) {
    if (rawDigits.length === 11 && rawDigits.startsWith("1")) {
      const nationalNumber = rawDigits.slice(1);
      return `+1 (${nationalNumber.slice(0, 3)}) ${nationalNumber.slice(3, 6)}-${nationalNumber.slice(6)}`;
    }
    return `+${rawDigits.slice(0, 15)}`;
  }
  const digits = rawDigits;
  if (digits.length <= 3) return digits;
  if (digits.length <= 6) return `(${digits.slice(0, 3)}) ${digits.slice(3)}`;
  return `(${digits.slice(0, 3)}) ${digits.slice(3, 6)}-${digits.slice(6)}`;
}

function phoneNumberIsReady(value: string) {
  const trimmed = value.trim();
  if (/^[1-9]$/.test(trimmed)) return true;
  const digits = trimmed.replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;
}

function maskedPhoneNumber(value: string) {
  const digits = value.replace(/\D/g, "");
  return `••• ••• ${digits.slice(-4).padStart(4, "•")}`;
}

function personInitials(name: string) {
  const parts = name.trim().split(/\s+/).filter(Boolean);
  return (parts.length > 1
    ? `${parts[0][0]}${parts.at(-1)?.[0]}`
    : parts[0]?.slice(0, 2) || "?"
  ).toUpperCase();
}

function formatEventDate(value: string | null, includeWeekday = true) {
  if (!value) return "Date not set";
  return new Intl.DateTimeFormat("en-US", {
    ...(includeWeekday ? { weekday: "long" as const } : {}),
    month: "long",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(value));
}

function formatCardDate(value: string | null) {
  if (!value) return HOME_EXPERIENCE.dateNotSet;
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function cardCountdownFor(deadline: string | null, now: number) {
  if (!deadline) {
    return { value: "—", label: HOME_EXPERIENCE.metrics.noDeadline };
  }
  const seconds = Math.max(0, Math.ceil((new Date(deadline).getTime() - now) / 1000));
  if (seconds <= 0) {
    return { value: "Closed", label: HOME_EXPERIENCE.metrics.responsesClosed };
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const value = days > 0
    ? `${days}d ${hours}h`
    : hours > 0
      ? `${hours}h ${minutes}m`
      : `${minutes}m ${seconds % 60}s`;
  return { value, label: HOME_EXPERIENCE.metrics.leftToRespond };
}

function countdownFor(deadline: string | null, now: number) {
  if (!deadline) return "No deadline";
  const seconds = Math.max(0, Math.floor((new Date(deadline).getTime() - now) / 1000));
  if (seconds <= 0) return "Closed";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  return `${minutes}m ${seconds % 60}s`;
}

function eventStatusLabel(event: ApiEvent) {
  if (event.role === "host" && event.invitationDelivery?.status === "attention_needed") {
    return "Delivery issue";
  }
  if (event.role === "host" && event.invitationDelivery?.status === "in_progress") {
    return "Sending";
  }
  if (event.resolution?.status === "confirmed") return INVITATION_EXPERIENCE.status.confirmed;
  if (event.resolution?.status === "not_confirmed") return INVITATION_EXPERIENCE.status.notConfirmed;
  if (event.resolution?.status === "verification_unavailable") return "Result unavailable";
  if (event.resolution?.status === "pending") {
    if (event.resolution.retrying) return "Retrying result";
    return event.rsvpDeadline && Date.parse(event.rsvpDeadline) <= Date.now()
      ? INVITATION_EXPERIENCE.status.finalizing
      : INVITATION_EXPERIENCE.status.repliesOpen;
  }
  if (
    event.invitationsSent &&
    event.rsvpDeadline &&
    Date.parse(event.rsvpDeadline) <= Date.now() &&
    !event.privateResponsePolicy
  ) {
    return "Result unavailable";
  }
  if (event.role === "host") return INVITATION_EXPERIENCE.status.hosting;
  return event.hasResponse
    ? INVITATION_EXPERIENCE.status.responded
    : INVITATION_EXPERIENCE.status.replyNeeded;
}

function deliveryAttentionBody(delivery: InvitationDeliverySummary) {
  const details: string[] = [];
  if (delivery.counts.failed > 0) {
    details.push(
      `${delivery.counts.failed} ${delivery.counts.failed === 1 ? "invitation was" : "invitations were"} rejected and not sent.`,
    );
  }
  if (delivery.counts.unknown > 0) {
    details.push(
      `Delivery could not be confirmed for ${delivery.counts.unknown} ${delivery.counts.unknown === 1 ? "invitation" : "invitations"}. Herd did not retry automatically, which avoids sending a duplicate.`,
    );
  }
  return details.join(" ");
}

function DeliveryCallout({ delivery }: { delivery: InvitationDeliverySummary }) {
  const attentionGuests = delivery.guests.filter(
    (guest) => guest.status === "failed" || guest.status === "unknown",
  );
  return (
    <section className={`resolution-callout delivery-callout delivery-${delivery.status}`} aria-live="polite">
      {delivery.status === "attention_needed" ? (
        <>
          <h3>Some invitations need attention</h3>
          <p>{deliveryAttentionBody(delivery)}</p>
          {attentionGuests.length > 0 ? (
            <ul>
              {attentionGuests.map((guest) => (
                <li key={guest.inviteeId}>
                  {guest.displayName}: {guest.status === "failed" ? "not sent" : "delivery unknown"}
                </li>
              ))}
            </ul>
          ) : null}
        </>
      ) : delivery.status === "in_progress" ? (
        <>
          <h3>Invitations are being submitted</h3>
          <p>Herd is waiting for the messaging provider to accept every invitation.</p>
        </>
      ) : delivery.status === "suppressed" ? (
        <>
          <h3>Test invitations are ready in Herd</h3>
          <p>No text messages were sent to the controlled QA accounts.</p>
        </>
      ) : (
        <>
          <h3>Invitations submitted</h3>
          <p>The messaging provider accepted all {delivery.total} invitations.</p>
        </>
      )}
    </section>
  );
}

function eventThirdMetric(event: ApiEvent, fallback: { value: string; label: string }) {
  if (event.resolution?.status === "confirmed") {
    return {
      value: String(event.resolution.attendingMemberIds.length),
      label: INVITATION_EXPERIENCE.metrics.attending,
    };
  }
  if (event.resolution?.status === "not_confirmed") {
    return { value: "No", label: INVITATION_EXPERIENCE.metrics.notConfirmed };
  }
  return fallback;
}

function resolvedAttendees(event: ApiEvent) {
  if (event.resolution?.status !== "confirmed") return [];
  const names = new Map(event.invitees.map((invitee) => [invitee.id, invitee.displayName]));
  return event.resolution.attendingMemberIds.flatMap((memberId) => {
    if (memberId === "host") return [{ id: memberId, name: event.hostName }];
    const name = names.get(memberId);
    return name ? [{ id: memberId, name }] : [];
  });
}

async function responseError(response: Response, fallback: string) {
  try {
    const body = await response.json() as {
      error?: string | { message?: string };
      message?: string;
    };
    if (typeof body.error === "string") return body.error;
    return body.error?.message || body.message || fallback;
  } catch {
    return fallback;
  }
}

async function responseErrorDetails(response: Response, fallback: string) {
  try {
    const body = await response.json() as {
      error?: string | { code?: string; message?: string };
      message?: string;
    };
    if (typeof body.error === "string") {
      return { message: body.error };
    }
    return {
      code: body.error?.code,
      message: body.error?.message || body.message || fallback,
    };
  } catch {
    return { message: fallback };
  }
}

function AppHeader({
  title,
  headingId,
  onBack,
  backLabel = "Go back",
  action,
}: {
  title: string;
  headingId: string;
  onBack?: () => void;
  backLabel?: string;
  action?: React.ReactNode;
}) {
  const [isCondensed, setIsCondensed] = useState(false);
  const headerRef = useRef<HTMLElement>(null);

  useEffect(() => {
    const header = headerRef.current;
    const scrollRoot = header?.nextElementSibling;
    const heading = document.getElementById(headingId);

    if (!(scrollRoot instanceof HTMLElement) || !heading) return;

    const updateHeader = () => {
      setIsCondensed(
        heading.getBoundingClientRect().bottom <= scrollRoot.getBoundingClientRect().top,
      );
    };

    updateHeader();
    scrollRoot.addEventListener("scroll", updateHeader, { passive: true });
    return () => scrollRoot.removeEventListener("scroll", updateHeader);
  }, [headingId]);

  return (
    <header ref={headerRef} className={`app-header ${isCondensed ? "app-header-condensed" : ""}`}>
      <div className="header-side">
        {onBack ? (
          <button className="circle-button" onClick={onBack} aria-label={backLabel}>
            <ChevronLeft size={23} strokeWidth={2.2} aria-hidden="true" />
          </button>
        ) : null}
      </div>
      <h1 aria-hidden={!isCondensed}>{title}</h1>
      <div className="header-side header-side-right">{isCondensed ? action : null}</div>
    </header>
  );
}

function BrandMark() {
  return (
    <div className="brand-lockup" aria-label={AUTH_EXPERIENCE.brandName}>
      <Image
        src="/icons/herd-108.png"
        alt=""
        width={36}
        height={36}
        priority
        unoptimized
      />
      <span>{AUTH_EXPERIENCE.brandName}</span>
    </div>
  );
}

function AvatarStack({ invitees }: { invitees: ApiInvitee[] }) {
  return (
    <span className="avatar-stack" aria-label={`${invitees.length} people invited`}>
      {invitees.slice(0, 5).map((person, index) => (
        <span
          className={`avatar ${initialsTone(index)}`}
          key={person.id}
          title={person.displayName}
        >
          {personInitials(person.displayName)}
        </span>
      ))}
      {invitees.length > 5 ? <span className="avatar avatar-more">+{invitees.length - 5}</span> : null}
    </span>
  );
}

function Metric({ value, label }: { value: string; label: string }) {
  return (
    <div className="metric">
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function PlusMark() {
  return <span className="host-create-plus" aria-hidden="true">+</span>;
}

function EventCard({
  event,
  now,
  onClick,
}: {
  event: ApiEvent;
  now: number;
  onClick: () => void;
}) {
  const countdown = cardCountdownFor(event.rsvpDeadline, now);
  const thirdMetric = eventThirdMetric(event, countdown);
  return (
    <article className="event-card">
      <button
        className="event-card-hit"
        onClick={onClick}
        aria-label={`Open ${event.title || "event"}`}
      ></button>
      <div className="card-topline">
        <span>{formatCardDate(event.eventDate)}</span>
        <span className="status-pill">
          {eventStatusLabel(event)}
        </span>
        <span className="chevron" aria-hidden="true">›</span>
      </div>
      <h2>{event.title || HOME_EXPERIENCE.untitledEvent}</h2>
      {event.locationName ? (
        <p className="location-line">
          <MapPin className="location-icon" size={16} strokeWidth={1.8} aria-hidden="true" />
          {event.locationName}
        </p>
      ) : null}
      <div className="metric-row">
        <Metric value={String(event.invitees.length)} label={HOME_EXPERIENCE.metrics.invited} />
        <Metric value={String(event.minimumParticipants)} label={HOME_EXPERIENCE.metrics.minimum} />
        <Metric value={thirdMetric.value} label={thirdMetric.label} />
      </div>
    </article>
  );
}

export function HerdApp({ inviteToken }: { inviteToken?: string }) {
  const [screen, setScreen] = useState<Screen>("welcome");
  const [otp, setOtp] = useState("");
  const [otpError, setOtpError] = useState("");
  const [resendSeconds, setResendSeconds] = useState(0);
  const [resendNotice, setResendNotice] = useState("");
  const [reply, setReply] = useState<Reply>(null);
  const [events, setEvents] = useState<ApiEvent[]>([]);
  const [selectedEvent, setSelectedEvent] = useState<ApiEvent | null>(null);
  const [invitationPreview, setInvitationPreview] = useState<InvitationPreview | null>(null);
  const [invitePreviewPending, setInvitePreviewPending] = useState(Boolean(inviteToken));
  const [invitePreviewError, setInvitePreviewError] = useState("");
  const [invitePreviewRefresh, setInvitePreviewRefresh] = useState(0);
  const [inviteAccountMismatch, setInviteAccountMismatch] = useState(false);
  const [challenge, setChallenge] = useState<AuthChallenge | null>(null);
  const [authPending, setAuthPending] = useState(false);
  const [authError, setAuthError] = useState("");
  const [profileNotice, setProfileNotice] = useState("");
  const [replyError, setReplyError] = useState("");
  const [currentUser, setCurrentUser] = useState<ApiUser | null>(null);
  const [inviteMetadata, setInviteMetadata] = useState<InviteMetadata | null>(null);
  const [privateResponseState, setPrivateResponseState] = useState<PrivateResponseState>("idle");
  const [profileName, setProfileName] = useState("");
  const [phoneNumber, setPhoneNumber] = useState("");
  const [address, setAddress] = useState("");
  const [releaseStatusOpen, setReleaseStatusOpen] = useState(false);
  const [logoutConfirmationOpen, setLogoutConfirmationOpen] = useState(false);
  const [accountDeletionOpen, setAccountDeletionOpen] = useState(false);
  const [accountDeletionStage, setAccountDeletionStage] = useState<"confirm" | "verify">("confirm");
  const [accountDeletionChallenge, setAccountDeletionChallenge] = useState<AuthChallenge | null>(null);
  const [accountDeletionCode, setAccountDeletionCode] = useState("");
  const [accountDeletionError, setAccountDeletionError] = useState("");
  const [accountDeletionPending, setAccountDeletionPending] = useState(false);
  const [minimum, setMinimum] = useState(4);
  const [conditionGroups, setConditionGroups] = useState<string[][]>([]);
  const [conditionTargetGroup, setConditionTargetGroup] = useState<number | null>(null);
  const [conditionSheetOpen, setConditionSheetOpen] = useState(false);
  const [sheetDragY, setSheetDragY] = useState(0);
  const otpInputRef = useRef<HTMLInputElement | null>(null);
  const hostDownloadTriggerRef = useRef<HTMLButtonElement | null>(null);
  const hostDownloadHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const releaseStatusTriggerRef = useRef<HTMLButtonElement | null>(null);
  const releaseStatusCloseRef = useRef<HTMLButtonElement | null>(null);
  const privacyTriggerRef = useRef<HTMLButtonElement | null>(null);
  const privacyHeadingRef = useRef<HTMLHeadingElement | null>(null);
  const restorePrivacyTriggerFocusRef = useRef(false);
  const conditionSheetRef = useRef<HTMLElement | null>(null);
  const conditionReturnFocusRef = useRef<HTMLElement | null>(null);
  const sheetDragStartRef = useRef<number | null>(null);
  const sheetDragLatestRef = useRef(0);
  const lastResolutionRefreshRef = useRef(0);
  const resolutionRefreshInFlightRef = useRef(false);
  const [now, setNow] = useState(() => Date.now());
  const activeEvent = selectedEvent ?? events[0] ?? null;
  const displayProfileName = profileName.trim();
  const invitedPeople = activeEvent?.invitees ?? [];
  const conditionCandidates = invitedPeople.filter((person) => !person.isCurrentUser);
  const countdown = countdownFor(activeEvent?.rsvpDeadline ?? null, now);
  const activeThirdMetric = activeEvent
    ? eventThirdMetric(activeEvent, { value: countdown, label: "left to respond" })
    : { value: countdown, label: "left to respond" };
  const resolutionRefreshTarget = screen === "event"
    ? activeEvent
    : screen === "home"
      ? events.find((event) =>
          event.resolution?.status === "pending" &&
          Boolean(event.rsvpDeadline) &&
          Date.parse(event.rsvpDeadline!) <= now
        ) ?? null
      : null;

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    if (
      !resolutionRefreshTarget?.rsvpDeadline ||
      resolutionRefreshTarget.resolution?.status !== "pending" ||
      Date.parse(resolutionRefreshTarget.rsvpDeadline) > now ||
      resolutionRefreshInFlightRef.current ||
      now - lastResolutionRefreshRef.current < 5_000
    ) {
      return;
    }
    lastResolutionRefreshRef.current = now;
    resolutionRefreshInFlightRef.current = true;
    void (async () => {
      try {
        const token = resolutionRefreshTarget.inviteToken ?? inviteToken;
        if (screen === "event" && resolutionRefreshTarget.role !== "host" && token) {
          const response = await fetch(`/api/invites/${encodeURIComponent(token)}`, {
            credentials: "include",
          });
          if (!response.ok) {
            throw new Error(await responseError(response, "Couldn’t finalize this event."));
          }
          const body = await response.json() as AuthenticatedInviteResponse;
          const rawRefreshedEvent = body.event ?? body.invitation;
          if (!rawRefreshedEvent) throw new Error("Couldn’t finalize this event.");
          const refreshedEvent = await verifiedApiEvent(rawRefreshedEvent);
          setSelectedEvent(refreshedEvent);
          setInviteMetadata(body.inviteMetadata ?? null);
          setEvents((current) => upsertHomeEvent(current, refreshedEvent));
          return;
        }

        const dueHostEvents = (screen === "event"
          ? [resolutionRefreshTarget]
          : events
        ).filter((event) =>
          event.role === "host" &&
          event.invitationsSent &&
          event.resolution?.status === "pending" &&
          Boolean(event.rsvpDeadline) &&
          Date.parse(event.rsvpDeadline!) <= now
        );
        await Promise.allSettled(
          dueHostEvents.map((event) => relayHostEventEvaluation(event.id)),
        );

        const response = await fetch("/api/events", { credentials: "include" });
        if (!response.ok) {
          throw new Error(await responseError(response, "Couldn’t finalize this event."));
        }
        const body = await response.json() as { events?: ApiEvent[] };
        const refreshedEvents = sortEventsForHome(
          await Promise.all(
            (Array.isArray(body.events) ? body.events : []).map(verifiedApiEvent),
          ),
        );
        setEvents(refreshedEvents);
        const refreshedEvent = refreshedEvents.find(
          (event) => event.id === resolutionRefreshTarget.id,
        );
        if (refreshedEvent) {
          setSelectedEvent((current) =>
            current?.id === refreshedEvent.id ? refreshedEvent : current
          );
        }
      } catch (error) {
        if (screen === "event") {
          setReplyError(
            error instanceof Error ? error.message : "Couldn’t finalize this event.",
          );
        }
      } finally {
        resolutionRefreshInFlightRef.current = false;
      }
    })();
  }, [events, inviteToken, now, resolutionRefreshTarget, screen]);

  useEffect(() => {
    if (!inviteToken) return;
    let cancelled = false;
    void (async () => {
      setInvitePreviewPending(true);
      setInvitePreviewError("");
      try {
        const response = await fetch(`/api/invites/${encodeURIComponent(inviteToken)}`, {
          credentials: "include",
        });
        if (!response.ok) {
          const error = await responseErrorDetails(
            response,
            "This invitation could not be loaded.",
          );
          if (error.code === "invite_for_different_account") {
            setInviteAccountMismatch(true);
          }
          throw new Error(error.message);
        }
        const body = await response.json() as {
          invitationPreview?: InvitationPreview;
          event?: ApiEvent;
          inviteMetadata?: InviteMetadata;
        };
        if (cancelled) return;
        if (body.invitationPreview) {
          setInviteAccountMismatch(false);
          setInvitationPreview(body.invitationPreview);
          return;
        }
        if (body.event) {
          const event = await verifiedApiEvent(body.event);
          setInviteAccountMismatch(false);
          setSelectedEvent(event);
          setMinimum(event.minimumParticipants);
          setReply(null);
          setConditionGroups([]);
          setInviteMetadata(body.inviteMetadata ?? null);
          setEvents((current) => upsertHomeEvent(current, event));
          return;
        }
        throw new Error("This invitation could not be loaded.");
      } catch (error) {
        if (!cancelled) {
          setInvitePreviewError(error instanceof Error ? error.message : "This invitation could not be loaded.");
        }
      } finally {
        if (!cancelled) setInvitePreviewPending(false);
      }
    })();
    return () => { cancelled = true; };
  }, [invitePreviewRefresh, inviteToken]);

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const response = await fetch("/api/me", { credentials: "include" });
        if (response.status === 401) return;
        if (!response.ok) throw new Error(await responseError(response, "Couldn’t restore your session."));
        const body = await response.json() as { user: ApiUser; accountKeyEpochId?: string };
        if (cancelled) return;
        applyUser(body.user);
        const openedInvitation = await loadAuthenticatedData();
        if (!cancelled) setScreen(openedInvitation ? "event" : "home");
      } catch (error) {
        if (!cancelled) setAuthError(error instanceof Error ? error.message : "Couldn’t restore your session.");
      }
    })();
    return () => { cancelled = true; };
  // This intentionally runs once to restore the server session.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!currentUser || !selectedEvent || !inviteMetadata?.canRespond) return;
    let cancelled = false;
    void (async () => {
      setReplyError("");
      if (!inviteMetadata.hasResponse) {
        setReply(null);
        setMinimum(selectedEvent.minimumParticipants);
        setConditionGroups([]);
        if (!inviteMetadata.accountKeyCommitment) {
          setPrivateResponseState("ready");
          return;
        }
        setPrivateResponseState("loading");
        try {
          const activeAccountRootSecret = await loadAccountRootSecret(
            currentUser.id,
            inviteMetadata.accountKeyEpochId,
            inviteMetadata.accountKeyCommitment,
          );
          if (cancelled) {
            activeAccountRootSecret?.bytes.fill(0);
            return;
          }
          if (!activeAccountRootSecret) {
            setPrivateResponseState("unreadable");
            return;
          }
          activeAccountRootSecret.bytes.fill(0);
          setPrivateResponseState("ready");
        } catch (error) {
          if (cancelled) return;
          setPrivateResponseState(
            error instanceof PrivateVaultError && error.canStartOver
              ? "unreadable"
              : "idle",
          );
          setReplyError(
            error instanceof Error
              ? error.message
              : "This device could not verify its private account key.",
          );
        }
        return;
      }
      if (!inviteMetadata.responseEnvelope) {
        setPrivateResponseState("idle");
        setReplyError("Your encrypted response could not be loaded. Refresh and try again.");
        return;
      }
      setPrivateResponseState("loading");
      try {
        const envelopeUsesActiveEpoch =
          inviteMetadata.responseEnvelope.accountKeyEpochId ===
          inviteMetadata.accountKeyEpochId;
        if (envelopeUsesActiveEpoch && !inviteMetadata.accountKeyCommitment) {
          throw new Error("The active account-key commitment is missing.");
        }
        const accountRootSecret = await loadAccountRootSecret(
          currentUser.id,
          inviteMetadata.responseEnvelope.accountKeyEpochId,
          envelopeUsesActiveEpoch
            ? inviteMetadata.accountKeyCommitment ?? undefined
            : undefined,
        );
        if (cancelled) {
          accountRootSecret?.bytes.fill(0);
          return;
        }
        if (!accountRootSecret) {
          setPrivateResponseState("unreadable");
          setReply(null);
          setMinimum(selectedEvent.minimumParticipants);
          setConditionGroups([]);
          return;
        }
        if (!selectedEvent.privateResponsePolicy) {
          throw new Error("This event does not have a frozen private-response policy.");
        }
        const draft = await openPrivateResponse({
          envelope: inviteMetadata.responseEnvelope,
          eventId: selectedEvent.id,
          inviteeId: inviteMetadata.id,
          allowedInviteeIds: selectedEvent.invitees.map((person) => person.id),
          accountRootSecret: accountRootSecret.bytes,
          policy: selectedEvent.privateResponsePolicy,
        }).finally(() => {
          accountRootSecret.bytes.fill(0);
        });
        if (cancelled) return;
        setReply(draft.response === "going" ? "yes" : "no");
        setMinimum(
          draft.response === "going" && draft.minimumParticipants !== null
            ? draft.minimumParticipants
            : selectedEvent.minimumParticipants,
        );
        setConditionGroups(draft.requiredGroups.map((group) => group.memberIDs));
        setPrivateResponseState("ready");
      } catch (error) {
        if (cancelled) return;
        setPrivateResponseState(
          (error instanceof PrivateVaultError && error.canStartOver) ||
            (error instanceof PrivateResponseCryptoError && error.canStartOver)
            ? "unreadable"
            : "idle",
        );
        setReplyError(
          error instanceof Error
            ? error.message
            : "This device could not open your encrypted response.",
        );
      }
    })();
    return () => { cancelled = true; };
  }, [currentUser, inviteMetadata, selectedEvent]);

  useEffect(() => {
    if (screen !== "verify" || resendSeconds <= 0) return;
    const timer = window.setInterval(
      () => setResendSeconds((seconds) => Math.max(0, seconds - 1)),
      1000,
    );
    return () => window.clearInterval(timer);
  }, [screen, resendSeconds]);

  useEffect(() => {
    if (screen === "verify") {
      window.setTimeout(() => focusInputAtEnd(otpInputRef.current), 50);
    }
  }, [screen]);

  useEffect(() => {
    if (screen === "host-download") {
      window.requestAnimationFrame(() => hostDownloadHeadingRef.current?.focus({ preventScroll: true }));
    }
  }, [screen]);

  useEffect(() => {
    if (screen === "privacy") {
      window.requestAnimationFrame(() => privacyHeadingRef.current?.focus({ preventScroll: true }));
      return;
    }
    if (screen === "event" && restorePrivacyTriggerFocusRef.current) {
      restorePrivacyTriggerFocusRef.current = false;
      window.requestAnimationFrame(() => privacyTriggerRef.current?.focus({ preventScroll: true }));
    }
  }, [screen]);

  useEffect(() => {
    if (!releaseStatusOpen) return;
    window.requestAnimationFrame(() => releaseStatusCloseRef.current?.focus());
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.preventDefault();
      setReleaseStatusOpen(false);
      window.requestAnimationFrame(() => releaseStatusTriggerRef.current?.focus());
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [releaseStatusOpen]);

  useEffect(() => {
    if (!conditionSheetOpen) return;
    const sheet = conditionSheetRef.current;
    const focusableSelector =
      'button:not([disabled]), [href], input:not([disabled]), [tabindex]:not([tabindex="-1"])';
    const focusable = sheet
      ? Array.from(sheet.querySelectorAll<HTMLElement>(focusableSelector))
      : [];
    focusable[0]?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setConditionSheetOpen(false);
        window.requestAnimationFrame(() => conditionReturnFocusRef.current?.focus());
        return;
      }
      if (event.key !== "Tab" || focusable.length === 0) return;
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [conditionSheetOpen]);

  const selectedConditionPeople = conditionGroups.flat();
  function goBack() {
    const previous: Record<Screen, Screen> = {
      welcome: "welcome",
      verify: "welcome",
      home: "home",
      profile: "home",
      "host-download": "home",
      event: "home",
      attendees: "event",
      privacy: "event",
      success: "event",
    };
    if (screen === "privacy") restorePrivacyTriggerFocusRef.current = true;
    setScreen(previous[screen]);
  }

  function applyUser(nextUser: ApiUser) {
    setCurrentUser(nextUser);
    setProfileName(nextUser.name || "");
    setPhoneNumber(nextUser.phoneNumber || "");
    setAddress(nextUser.address || "");
  }

  async function loadAuthenticatedData(): Promise<boolean> {
    const requests: Promise<Response>[] = [
      fetch("/api/events", { credentials: "include" }),
    ];
    if (inviteToken) {
      requests.push(fetch(`/api/invites/${encodeURIComponent(inviteToken)}`, { credentials: "include" }));
    }

    const [eventsResponse, inviteResponse] = await Promise.all(requests);
    if (!eventsResponse.ok) {
      throw new Error(await responseError(eventsResponse, "Couldn’t load your events."));
    }
    const body = await eventsResponse.json() as { events?: ApiEvent[] };
    const verifiedEvents = await Promise.all(
      (Array.isArray(body.events) ? body.events : []).map(verifiedApiEvent),
    );
    setEvents(sortEventsForHome(verifiedEvents));
    if (inviteResponse && !inviteResponse.ok) {
      const error = await responseErrorDetails(
        inviteResponse,
        "This invitation could not be loaded.",
      );
      if (error.code === "invite_for_different_account") {
        setInviteAccountMismatch(true);
      }
      throw new Error(error.message);
    }
    if (inviteResponse?.ok) {
      const inviteBody = await inviteResponse.json() as AuthenticatedInviteResponse;
      const rawEvent = inviteBody.event ?? inviteBody.invitation;
      if (rawEvent) {
        const event = await verifiedApiEvent(rawEvent);
        setInviteAccountMismatch(false);
        setSelectedEvent(event);
        setMinimum(event.minimumParticipants);
        setReply(null);
        setConditionGroups([]);
        setInviteMetadata(inviteBody.inviteMetadata ?? null);
        setEvents((current) => upsertHomeEvent(current, event));
        return true;
      }
    }
    return false;
  }

  async function openEvent(event: ApiEvent) {
    setSelectedEvent(event);
    setMinimum(event.minimumParticipants);
    setReply(null);
    setConditionGroups([]);
    setInviteMetadata(null);
    setReplyError("");
    setScreen("event");
    if (event.role === "host") {
      setPrivateResponseState("idle");
      return;
    }
    const token = event.inviteToken ?? inviteToken;
    if (!token) {
      setReplyError("This invitation does not have an active reply link yet.");
      setPrivateResponseState("idle");
      return;
    }
    setPrivateResponseState("loading");
    try {
      const response = await fetch(`/api/invites/${encodeURIComponent(token)}`, {
        credentials: "include",
      });
      if (!response.ok) {
        throw new Error(await responseError(response, "This invitation could not be loaded."));
      }
      const body = await response.json() as AuthenticatedInviteResponse;
      const rawRefreshedEvent = body.event ?? body.invitation;
      if (!rawRefreshedEvent || !body.inviteMetadata) {
        throw new Error("This invitation could not be loaded.");
      }
      const refreshedEvent = await verifiedApiEvent(rawRefreshedEvent);
      setSelectedEvent(refreshedEvent);
      setInviteMetadata(body.inviteMetadata);
      setEvents((current) => current.map((item) =>
        item.id === refreshedEvent.id ? refreshedEvent : item
      ));
    } catch (error) {
      setPrivateResponseState("idle");
      setReplyError(
        error instanceof Error ? error.message : "This invitation could not be loaded.",
      );
    }
  }

  async function saveProfile() {
    setProfileNotice("");
    const response = await fetch("/api/me", {
      method: "PATCH",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ name: profileName.trim(), address: address.trim() }),
    });
    if (!response.ok) {
      setProfileNotice(await responseError(response, "Couldn’t save your profile."));
      return false;
    }
    const body = await response.json() as { user: ApiUser };
    applyUser(body.user);
    setProfileNotice(PROFILE_EXPERIENCE.savedNotice);
    return true;
  }

  function resetAuthenticatedExperience() {
    setLogoutConfirmationOpen(false);
    setAccountDeletionOpen(false);
    setAccountDeletionStage("confirm");
    setAccountDeletionChallenge(null);
    setAccountDeletionCode("");
    setAccountDeletionError("");
    setAccountDeletionPending(false);
    setOtp("");
    setChallenge(null);
    setEvents([]);
    setSelectedEvent(null);
    setCurrentUser(null);
    setInviteMetadata(null);
    setPrivateResponseState("idle");
    setInvitationPreview(null);
    setInvitePreviewPending(Boolean(inviteToken));
    setInvitePreviewError("");
    setInviteAccountMismatch(false);
    setInvitePreviewRefresh((value) => value + 1);
    setProfileName("");
    setPhoneNumber("");
    setAddress("");
    setScreen("welcome");
  }

  async function logOut() {
    await fetch("/api/auth/session", { method: "DELETE", credentials: "include" }).catch(() => undefined);
    resetAuthenticatedExperience();
  }

  async function switchInviteAccount() {
    if (authPending) return;
    setAuthPending(true);
    await fetch("/api/auth/session", {
      method: "DELETE",
      credentials: "include",
    }).catch(() => undefined);
    resetAuthenticatedExperience();
    setAuthPending(false);
  }

  async function performAccountDeletion(): Promise<"deleted" | "reauthenticate"> {
    const response = await fetch("/api/me", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ confirmation: "DELETE" }),
    });
    if (response.ok) {
      const deletedUserId = currentUser?.id;
      let localCleanupWarning = "";
      if (deletedUserId) {
        try {
          await forgetAllAccountRootSecrets(deletedUserId);
        } catch {
          localCleanupWarning =
            "Your account was deleted, but this browser could not remove its local private key. Clear this site’s stored data before sharing the device.";
        }
      }
      resetAuthenticatedExperience();
      if (localCleanupWarning) setAuthError(localCleanupWarning);
      return "deleted";
    }
    const error = await responseErrorDetails(response, "Your account could not be deleted.");
    if (error.code === "recent_authentication_required") return "reauthenticate";
    throw new Error(error.message);
  }

  async function requestAccountDeletionCode() {
    if (!currentUser) throw new Error("Sign in again before deleting your account.");
    const response = await fetch("/api/auth/request-code", {
      method: "POST",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ phoneNumber: currentUser.phoneNumber }),
    });
    if (!response.ok) {
      throw new Error(await responseError(response, "Couldn’t send a verification code."));
    }
    const body = await response.json() as AuthChallenge | AuthSession;
    if ("user" in body) {
      applyUser(body.user);
      const outcome = await performAccountDeletion();
      if (outcome !== "deleted") {
        throw new Error("Confirm your phone number again before deleting your account.");
      }
      return;
    }
    if (!body.challengeId || !body.phoneNumber || !body.expiresAt || !body.resendAt) {
      throw new Error("The verification request could not be started.");
    }
    setAccountDeletionChallenge(body);
    setAccountDeletionCode("");
    setAccountDeletionStage("verify");
  }

  async function beginAccountDeletion() {
    if (accountDeletionPending) return;
    setAccountDeletionPending(true);
    setAccountDeletionError("");
    try {
      const outcome = await performAccountDeletion();
      if (outcome === "reauthenticate") await requestAccountDeletionCode();
    } catch (error) {
      setAccountDeletionError(
        error instanceof Error ? error.message : "Your account could not be deleted.",
      );
    } finally {
      setAccountDeletionPending(false);
    }
  }

  async function confirmAccountDeletionCode() {
    if (
      accountDeletionPending ||
      accountDeletionCode.length !== OTP_LENGTH ||
      !accountDeletionChallenge
    ) return;
    setAccountDeletionPending(true);
    setAccountDeletionError("");
    try {
      const response = await fetch("/api/auth/verify-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          challengeId: accountDeletionChallenge.challengeId,
          code: accountDeletionCode,
        }),
      });
      if (!response.ok) {
        throw new Error(await responseError(response, "That code could not be verified."));
      }
      const body = await response.json() as AuthSession;
      applyUser(body.user);
      const outcome = await performAccountDeletion();
      if (outcome !== "deleted") {
        throw new Error("Confirm your phone number again before deleting your account.");
      }
    } catch (error) {
      setAccountDeletionError(
        error instanceof Error ? error.message : "Your account could not be deleted.",
      );
    } finally {
      setAccountDeletionPending(false);
    }
  }

  function closeAccountDeletion() {
    if (accountDeletionPending) return;
    setAccountDeletionOpen(false);
    setAccountDeletionStage("confirm");
    setAccountDeletionChallenge(null);
    setAccountDeletionCode("");
    setAccountDeletionError("");
  }

  function handleOtpChange(rawValue: string) {
    const nextOtp = rawValue.replace(/\D/g, "").slice(0, OTP_LENGTH);
    setOtp(nextOtp);
    setOtpError("");
  }

  async function requestCode(): Promise<boolean> {
    if (authPending) return false;
    if (inviteToken && !invitationPreview && !selectedEvent) {
      setAuthError(invitePreviewPending ? "Your invitation is still loading." : invitePreviewError || "This invitation could not be loaded.");
      return false;
    }
    if (!phoneNumberIsReady(phoneNumber)) {
      setAuthError("Enter a complete phone number.");
      return false;
    }
    setAuthPending(true);
    setAuthError("");
    setResendNotice("");
    try {
      const response = await fetch("/api/auth/request-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ phoneNumber, inviteToken }),
      });
      if (!response.ok) throw new Error(await responseError(response, "Couldn’t send a code."));
      const body = await response.json() as AuthChallenge | AuthSession;
      if ("user" in body) {
        applyUser(body.user);
        setChallenge(null);
        const openedInvitation = await loadAuthenticatedData();
        setScreen(openedInvitation ? "event" : "home");
        return false;
      }
      if (!body.challengeId || !body.phoneNumber || !body.expiresAt || !body.resendAt) {
        throw new Error("The verification request could not be started.");
      }
      setChallenge(body);
      setPhoneNumber(body.phoneNumber);
      setOtp("");
      setResendSeconds(Math.max(1, Math.ceil((new Date(body.resendAt).getTime() - Date.now()) / 1000)));
      setScreen("verify");
      return true;
    } catch (error) {
      setAuthError(error instanceof Error ? error.message : "Couldn’t send a code.");
      return false;
    } finally {
      setAuthPending(false);
    }
  }

  async function verifyCode() {
    if (otp.length !== OTP_LENGTH) {
      setOtpError("Enter all four digits to continue.");
      focusInputAtEnd(otpInputRef.current);
      return;
    }
    if (!challenge || authPending) return;
    setAuthPending(true);
    setOtpError("");
    try {
      const response = await fetch("/api/auth/verify-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ challengeId: challenge.challengeId, code: otp }),
      });
      if (!response.ok) throw new Error(await responseError(response, "That code could not be verified."));
      const body = await response.json() as { user: ApiUser };
      applyUser(body.user);
      const openedInvitation = await loadAuthenticatedData();
      setScreen(openedInvitation ? "event" : "home");
    } catch (error) {
      setOtpError(error instanceof Error ? error.message : "That code could not be verified.");
      focusInputAtEnd(otpInputRef.current);
    } finally {
      setAuthPending(false);
    }
  }

  async function resendCode() {
    if (resendSeconds > 0) return;
    if (await requestCode()) setResendNotice("A new code was sent.");
  }

  function toggleReply(nextReply: Exclude<Reply, null>) {
    setReply(nextReply);
  }

  function addCondition(personID: string) {
    setConditionGroups((current) => {
      if (current.some((group) => group.includes(personID))) return current;
      if (conditionTargetGroup === null || !current[conditionTargetGroup]) {
        return [...current, [personID]];
      }
      return current.map((group, index) =>
        index === conditionTargetGroup ? [...group, personID] : group,
      );
    });
    closeConditionSheet();
    setReply("yes");
  }

  function openConditionSheet(trigger: HTMLElement, targetGroup: number | null = null) {
    conditionReturnFocusRef.current = trigger;
    setConditionTargetGroup(targetGroup);
    setSheetDragY(0);
    sheetDragLatestRef.current = 0;
    setConditionSheetOpen(true);
    setReply("yes");
  }

  function closeConditionSheet() {
    setConditionSheetOpen(false);
    setSheetDragY(0);
    window.requestAnimationFrame(() => conditionReturnFocusRef.current?.focus());
  }

  function handleSheetPointerDown(event: React.PointerEvent<HTMLButtonElement>) {
    sheetDragStartRef.current = event.clientY;
    sheetDragLatestRef.current = 0;
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function handleSheetPointerMove(event: React.PointerEvent<HTMLButtonElement>) {
    if (sheetDragStartRef.current === null) return;
    const distance = Math.max(0, event.clientY - sheetDragStartRef.current);
    sheetDragLatestRef.current = distance;
    setSheetDragY(distance);
  }

  function handleSheetPointerUp(event: React.PointerEvent<HTMLButtonElement>) {
    if (sheetDragStartRef.current === null) return;
    sheetDragStartRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    if (sheetDragLatestRef.current > 70) closeConditionSheet();
    else setSheetDragY(0);
  }

  async function submitReply() {
    if (
      !reply ||
      !activeEvent ||
      !currentUser ||
      !inviteMetadata?.canRespond ||
      authPending ||
      privateResponseState === "loading"
    ) return;
    const token = activeEvent.inviteToken ?? inviteToken;
    if (!token) {
      setReplyError("This invitation does not have an active reply link yet.");
      return;
    }
    if (!activeEvent.privateResponsePolicy) {
      setReplyError("This event is not ready to accept encrypted responses.");
      return;
    }
    const submittedReply = reply;
    setAuthPending(true);
    setReplyError("");
    let accountRootSecret: Uint8Array | null = null;
    try {
      let accountKeyEpochId = inviteMetadata.accountKeyEpochId;
      let accountKeyCommitment = inviteMetadata.accountKeyCommitment;
      let localAccountKey = null;
      if (accountKeyCommitment) {
        try {
          localAccountKey = await loadAccountRootSecret(
            currentUser.id,
            accountKeyEpochId,
            accountKeyCommitment,
          );
        } catch (error) {
          if (!(error instanceof PrivateVaultError) || !error.canStartOver) {
            throw error;
          }
        }
      }
      accountRootSecret = localAccountKey?.bytes ?? null;
      const savedResponseUsesActiveEpoch =
        inviteMetadata.responseEnvelope?.accountKeyEpochId === accountKeyEpochId;
      const mustResetAccountKey =
        Boolean(accountKeyCommitment && !localAccountKey) ||
        (privateResponseState === "unreadable" && savedResponseUsesActiveEpoch);
      if (mustResetAccountKey) {
        if (inviteMetadata.hasResponse || inviteMetadata.responseEnvelope) {
          throw new Error(
            "This saved reply is locked to the account key that authorized it. Starting over can secure future replies, but it cannot replace this one.",
          );
        }
        const confirmed = window.confirm(
          REPLY_EXPERIENCE.reset.body,
        );
        if (!confirmed) return;
        const resetResponse = await fetch("/api/account/key-epoch/reset", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            expectedAccountKeyEpochId: inviteMetadata.accountKeyEpochId,
          }),
        });
        if (!resetResponse.ok) {
          throw new Error(
            await responseError(
              resetResponse,
              "Confirm your phone number again before starting over.",
            ),
          );
        }
        const reset = await resetResponse.json() as { accountKeyEpochId: string };
        accountRootSecret?.fill(0);
        accountRootSecret = null;
        accountKeyEpochId = reset.accountKeyEpochId;
        accountKeyCommitment = null;
        localAccountKey = null;
        setInviteMetadata((current) => current ? {
          ...current,
          accountKeyEpochId,
          accountKeyCommitment: null,
        } : current);
      }

      if (!accountKeyCommitment) {
        localAccountKey = await getOrCreateAccountRootSecret(
          currentUser.id,
          accountKeyEpochId,
        );
        accountRootSecret = localAccountKey.bytes;
        accountKeyCommitment = await accountRootSecretCommitment(
          localAccountKey.bytes,
        );
        const initializeResponse = await fetch("/api/account/key-epoch/initialize", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            expectedAccountKeyEpochId: accountKeyEpochId,
            keyCommitment: accountKeyCommitment,
          }),
        });
        if (!initializeResponse.ok) {
          throw new Error(
            await responseError(
              initializeResponse,
              "The account encryption key could not be initialized.",
            ),
          );
        }
        const initialized = await initializeResponse.json() as {
          accountKeyEpochId: string;
          keyCommitment: string;
        };
        if (
          initialized.accountKeyEpochId !== accountKeyEpochId ||
          initialized.keyCommitment !== accountKeyCommitment
        ) {
          throw new Error("Herd returned an invalid account-key commitment.");
        }
        setInviteMetadata((current) => current ? {
          ...current,
          accountKeyEpochId,
          accountKeyCommitment,
        } : current);
      }
      if (!localAccountKey) {
        throw new Error("The active account key is not available on this device.");
      }
      accountRootSecret = localAccountKey.bytes;
      const revision = (inviteMetadata.responseRevision ?? 0) + 1;
      await attestEvaluatorForPolicy(activeEvent.privateResponsePolicy);
      const sealed = await sealPrivateResponse({
        eventId: activeEvent.id,
        inviteeId: inviteMetadata.id,
        accountKeyEpochId,
        revision,
        response: submittedReply === "yes" ? "going" : "cant_commit",
        minimumParticipants: submittedReply === "yes" ? minimum : null,
        requiredGroups: submittedReply === "yes"
          ? conditionGroups.map((memberIDs) => ({
              id: newConditionGroupId(),
              memberIDs: [...memberIDs].sort(),
            }))
          : [],
        allowedInviteeIds: activeEvent.invitees.map((person) => person.id),
        accountRootSecret,
        policy: activeEvent.privateResponsePolicy,
      });
      const response = await fetch(`/api/invites/${encodeURIComponent(token)}/rsvp`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ envelope: sealed.envelope }),
      });
      if (!response.ok) {
        throw new Error(await responseError(response, "Couldn’t save your reply."));
      }
      const body = await response.json() as {
        responseEnvelope: StoredPrivateResponseEnvelopeV1;
        receipt: PrivateResponseReceiptV1;
      };
      const expectedHash = await privateResponseEnvelopeHash(sealed.envelope);
      const transparencySigningPin = configuredTransparencySigningPin();
      if (
        body.receipt?.ciphertextHash !== expectedHash ||
        body.responseEnvelope?.ciphertextHash !== expectedHash ||
        body.responseEnvelope?.envelopeId !== sealed.envelope.envelopeId ||
        body.responseEnvelope?.responseSigningPublicKey !== sealed.envelope.responseSigningPublicKey ||
        body.responseEnvelope?.responseSignature !== sealed.envelope.responseSignature ||
        body.receipt?.envelopeId !== sealed.envelope.envelopeId ||
        body.receipt?.eventId !== sealed.envelope.eventId ||
        body.receipt?.inviteeId !== sealed.envelope.inviteeId ||
        body.receipt?.policyHash !== sealed.envelope.policyHash ||
        body.receipt?.accountKeyEpochId !== sealed.envelope.accountKeyEpochId ||
        body.receipt?.revision !== sealed.envelope.revision ||
        body.receipt?.responseSigningPublicKey !== sealed.envelope.responseSigningPublicKey ||
        body.receipt?.responseSignature !== sealed.envelope.responseSignature ||
        !transparencySigningPin
      ) {
        throw new Error("Herd returned an invalid encrypted-response receipt.");
      }
      try {
        await verifyPrivateResponseReceiptPublication(
          body.receipt,
          transparencySigningPin,
        );
      } catch {
        throw new Error("Herd returned an invalid encrypted-response receipt.");
      }
      setInviteMetadata((current) => current ? {
        ...current,
        accountKeyEpochId,
        accountKeyCommitment,
        hasResponse: true,
        responseRevision: revision,
        responseEnvelope: body.responseEnvelope,
      } : current);
      setSelectedEvent((current) => current ? {
        ...current,
        accountKeyEpochId,
        accountKeyCommitment,
        hasResponse: true,
        responseRevision: revision,
      } : current);
      setEvents((current) => current.map((event) =>
        event.id === activeEvent.id
          ? { ...event, accountKeyEpochId, accountKeyCommitment, hasResponse: true, responseRevision: revision }
          : event
      ));
      // Initializing the local account key updates invite metadata and causes
      // the saved-response loader to clear its draft. Keep the answer that was
      // actually sealed authoritative for the immediate success projection.
      setReply(submittedReply);
      setPrivateResponseState("ready");
      setScreen("success");
    } catch (error) {
      setReplyError(error instanceof Error ? error.message : "Couldn’t save your reply.");
    } finally {
      accountRootSecret?.fill(0);
      setAuthPending(false);
    }
  }

  function openHostDownload() {
    setScreen("host-download");
  }

  function closeHostDownload() {
    setScreen("home");
    window.requestAnimationFrame(() => hostDownloadTriggerRef.current?.focus());
  }

  function closeReleaseStatus() {
    setReleaseStatusOpen(false);
    window.requestAnimationFrame(() => releaseStatusTriggerRef.current?.focus());
  }

  return (
    <main className="site-stage">
      <div className={`app-shell screen-${screen}`}>
        <div
          className="screen-stack"
          inert={conditionSheetOpen || releaseStatusOpen ? true : undefined}
          aria-hidden={conditionSheetOpen || releaseStatusOpen || undefined}
        >
        {screen === "welcome" ? (
          <section className="onboarding-screen" style={authLayoutStyle}>
            <div className="onboarding-top">
              <BrandMark />
              <button
                ref={releaseStatusTriggerRef}
                type="button"
                className="build-status-pill"
                aria-haspopup="dialog"
                aria-expanded={releaseStatusOpen}
                onClick={() => setReleaseStatusOpen(true)}
              >
                {AUTH_EXPERIENCE.releaseStatus.label}
              </button>
            </div>
            <div className="welcome-copy">
              {inviteToken ? <p className="eyebrow">You’re invited</p> : null}
              <h1>
                {inviteAccountMismatch
                  ? "Switch accounts to open this invitation"
                  : inviteToken
                  ? invitationPreview?.title || activeEvent?.title || (invitePreviewPending ? "Loading your invitation…" : "Invitation unavailable")
                  : AUTH_EXPERIENCE.welcome.title}
              </h1>
              <p>
                {inviteAccountMismatch
                  ? "This link belongs to a different phone number than the account currently signed in. Your link will stay here while you switch."
                  : inviteToken
                  ? invitationPreview || activeEvent
                    ? `${(invitationPreview?.hostName || activeEvent?.hostName || "Your host").split(" ")[0]} invited you. Confirm your phone number to view and reply.`
                    : invitePreviewPending
                      ? "We’re retrieving the invitation details."
                      : "Check the invitation link and try again."
                  : AUTH_EXPERIENCE.welcome.body}
              </p>
            </div>
            {!inviteAccountMismatch ? <label className="phone-entry-group" htmlFor="phone-number">
              <span className="phone-entry-label">{AUTH_EXPERIENCE.welcome.phoneLabel}</span>
              <input
                id="phone-number"
                className="phone-entry-field"
                value={formatPhoneNumber(phoneNumber)}
                onChange={(event) => {
                  const value = event.target.value;
                  const digits = value.replace(/\D/g, "").slice(0, 15);
                  setPhoneNumber(value.trimStart().startsWith("+") ? `+${digits}` : digits);
                  setAuthError("");
                }}
                onKeyDown={(event) => {
                  if (event.key === "Enter") void requestCode();
                }}
                placeholder={AUTH_EXPERIENCE.welcome.phonePlaceholder}
                type="tel"
                inputMode="tel"
                autoComplete="tel"
                aria-label="Phone number"
                autoFocus
              />
            </label> : null}
            {!inviteAccountMismatch && invitePreviewError ? <p className="inline-error welcome-error" role="alert">{invitePreviewError}</p> : null}
            {!inviteAccountMismatch && authError ? <p className="inline-error welcome-error" role="alert">{authError}</p> : null}
            <div className="bottom-action onboarding-action">
              <button
                className="primary-button"
                disabled={inviteAccountMismatch
                  ? authPending
                  : authPending || invitePreviewPending || Boolean(inviteToken && !invitationPreview && !selectedEvent) || !phoneNumberIsReady(phoneNumber)}
                onClick={() => inviteAccountMismatch
                  ? void switchInviteAccount()
                  : void requestCode()}
              >
                {inviteAccountMismatch
                  ? authPending ? "Switching…" : "Switch account"
                  : authPending
                  ? AUTH_EXPERIENCE.welcome.requestCodePendingButton
                  : AUTH_EXPERIENCE.welcome.requestCodeButton}
              </button>
              <p className="auth-footnote">
                {AUTH_EXPERIENCE.legal.prefix} <a href="/terms">{AUTH_EXPERIENCE.legal.terms}</a> and{" "}
                <a href="/privacy">{AUTH_EXPERIENCE.legal.privacy}</a>. {AUTH_EXPERIENCE.legal.suffix}
              </p>
            </div>
          </section>
        ) : null}

        {screen === "verify" ? (
          <section className="screen-layout" style={authLayoutStyle}>
            <AppHeader
              title={AUTH_EXPERIENCE.verification.navigationTitle}
              headingId="verification-heading"
              backLabel={AUTH_EXPERIENCE.verification.changePhoneAccessibilityLabel}
              onBack={goBack}
            />
            <div className="screen-scroll verification-screen">
              <h2 id="verification-heading">{AUTH_EXPERIENCE.verification.title}</h2>
              <p className="lead-copy" id="otp-help">
                {AUTH_EXPERIENCE.verification.bodyPrefix}{" "}
                {maskedPhoneNumber(challenge?.phoneNumber || phoneNumber)}.
              </p>
              <div className="otp-row" onClick={() => focusInputAtEnd(otpInputRef.current)}>
                <input
                  className="otp-native-input"
                  ref={otpInputRef}
                  value={otp}
                  onChange={(event) => handleOtpChange(event.target.value)}
                  onKeyDown={(event) => {
                    if (event.key === "Enter") void verifyCode();
                  }}
                  inputMode="numeric"
                  autoComplete="one-time-code"
                  enterKeyHint="done"
                  aria-label={AUTH_EXPERIENCE.verification.codeAccessibilityLabel}
                  aria-describedby={otpError ? "otp-help otp-error" : "otp-help"}
                  aria-invalid={Boolean(otpError)}
                  maxLength={OTP_LENGTH}
                  autoFocus
                />
                {Array.from({ length: OTP_LENGTH }, (_, index) => (
                  <span
                    className={`otp-box ${otp[index] ? "filled" : ""} ${index === otp.length && otp.length < OTP_LENGTH ? "active" : ""}`}
                    key={index}
                    aria-hidden="true"
                  >
                    {otp[index] ?? ""}
                  </span>
                ))}
              </div>
              {otpError ? <p className="inline-error" id="otp-error" role="alert">{otpError}</p> : null}
              {resendNotice ? <p className="inline-success">{resendNotice}</p> : null}
              <button
                className="text-button"
                disabled={resendSeconds > 0}
                onClick={() => void resendCode()}
              >
                {resendSeconds > 0
                  ? `${AUTH_EXPERIENCE.verification.resendPendingPrefix} 0:${String(resendSeconds).padStart(2, "0")}`
                  : AUTH_EXPERIENCE.verification.resendButton}
              </button>
            </div>
            <div className="bottom-action">
              <button className="primary-button" disabled={authPending} onClick={() => void verifyCode()}>
                {authPending
                  ? AUTH_EXPERIENCE.verification.verifyPendingButton
                  : AUTH_EXPERIENCE.verification.verifyButton}
              </button>
            </div>
          </section>
        ) : null}

        {screen === "home" ? (
          <section className="screen-layout">
            <div className="screen-scroll home-content" style={homeLayoutStyle}>
              <div className="home-header">
                <h1>{HOME_EXPERIENCE.title}</h1>
                <button
                  className="profile-avatar"
                  aria-label={displayProfileName
                    ? `${HOME_EXPERIENCE.profile.accessibilityLabel} for ${displayProfileName}`
                    : HOME_EXPERIENCE.profile.accessibilityLabel}
                  onClick={() => setScreen("profile")}
                >
                  {!displayProfileName && HOME_EXPERIENCE.profile.useGenericIconWithoutName
                    ? <UserRound aria-hidden="true" size={20} strokeWidth={1.8} />
                    : personInitials(displayProfileName || "Host")}
                </button>
              </div>
              {events.length ? (
                <div className="home-event-list">
                  {events.map((event) => (
                    <EventCard key={event.id} event={event} now={now} onClick={() => void openEvent(event)} />
                  ))}
                </div>
              ) : null}
              <div className="host-event-entry">
                <button
                  ref={hostDownloadTriggerRef}
                  type="button"
                  className="host-event-create-card"
                  onClick={openHostDownload}
                >
                  <PlusMark />
                  <strong>{HOME_EXPERIENCE.createEventTitle}</strong>
                </button>
              </div>
            </div>
          </section>
        ) : null}

        {screen === "host-download" ? (
          <section className="screen-layout host-app-handoff" aria-labelledby="host-app-heading">
            <AppHeader
              title={HOME_EXPERIENCE.createEventTitle}
              headingId="host-app-heading"
              onBack={closeHostDownload}
              backLabel={HOME_EXPERIENCE.webCreateEventHandoff.backButton}
            />
            <div className="screen-scroll host-app-content">
              <div className="host-app-visual" aria-hidden="true">
                <span className="host-app-orbit host-app-orbit-outer" />
                <span className="host-app-orbit host-app-orbit-inner" />
                <span className="host-app-icon" />
                <span className="host-app-contact-mark">
                  <ContactRound size={25} strokeWidth={1.9} />
                </span>
              </div>
              <div className="host-app-copy">
                <h2 id="host-app-heading" ref={hostDownloadHeadingRef} tabIndex={-1}>
                  {HOME_EXPERIENCE.webCreateEventHandoff.heading}
                </h2>
                <p>
                  {HOME_EXPERIENCE.webCreateEventHandoff.body}
                </p>
              </div>
            </div>
            <div className="bottom-action host-app-action">
              <button className="primary-button host-app-download" onClick={closeHostDownload}>
                {HOME_EXPERIENCE.webCreateEventHandoff.backButton}
              </button>
            </div>
          </section>
        ) : null}

        {screen === "profile" ? (
          <section className="screen-layout">
            <AppHeader title={PROFILE_EXPERIENCE.navigationTitle} headingId="profile-heading" onBack={goBack} />
            <div className="screen-scroll profile-content">
              <div className="screen-page-heading">
                <h2 id="profile-heading">{PROFILE_EXPERIENCE.title}</h2>
              </div>
              <div className="profile-fields-card">
                <label className="profile-field">
                  <span>{PROFILE_EXPERIENCE.nameLabel}</span>
                  <input
                    value={profileName}
                    onChange={(event) => setProfileName(event.target.value)}
                    placeholder={PROFILE_EXPERIENCE.namePlaceholder}
                    autoComplete="name"
                  />
                </label>
                <div className="profile-divider" />
                <label className="profile-field">
                  <span>{PROFILE_EXPERIENCE.phoneLabel}</span>
                  <input
                    value={formatPhoneNumber(phoneNumber)}
                    readOnly
                    aria-readonly="true"
                  />
                </label>
                <div className="profile-divider" />
                <label className="profile-field">
                  <span>{PROFILE_EXPERIENCE.addressLabel}</span>
                  <input
                    value={address}
                    onChange={(event) => setAddress(event.target.value)}
                    placeholder={PROFILE_EXPERIENCE.addressPlaceholder}
                    autoComplete="street-address"
                  />
                </label>
              </div>
              <p className="profile-note">{PROFILE_EXPERIENCE.syncNote}</p>
              {profileNotice ? <p className={profileNotice === PROFILE_EXPERIENCE.savedNotice ? "inline-success" : "inline-error"}>{profileNotice}</p> : null}
              <button className="primary-button profile-save" onClick={() => void saveProfile()}>
                {PROFILE_EXPERIENCE.saveButton}
              </button>
              <button className="secondary-button profile-logout" onClick={() => setLogoutConfirmationOpen(true)}>
                {PROFILE_EXPERIENCE.logoutButton}
              </button>
              <button
                className="secondary-button profile-delete"
                onClick={() => {
                  setAccountDeletionStage("confirm");
                  setAccountDeletionChallenge(null);
                  setAccountDeletionCode("");
                  setAccountDeletionError("");
                  setAccountDeletionOpen(true);
                }}
              >
                {PROFILE_EXPERIENCE.deleteAccountButton}
              </button>
            </div>
          </section>
        ) : null}

        {screen === "event" && activeEvent ? (
          <section className="screen-layout">
            <AppHeader
              title={INVITATION_EXPERIENCE.navigationTitle}
              headingId="event-heading"
              onBack={goBack}
              action={<span className="header-countdown">{countdown}</span>}
            />
            <div className="screen-scroll event-detail-scroll">
              <section className="event-hero">
                <div className="event-hero-heading">
                  <div>
                    <p className="eyebrow">{activeEvent.eventDate ? formatEventDate(activeEvent.eventDate) : INVITATION_EXPERIENCE.dateNotSet}</p>
                    <h2 id="event-heading">{activeEvent.title || INVITATION_EXPERIENCE.untitledEvent}</h2>
                  </div>
                  <span className={`status-pill ${activeEvent.hasResponse ? "status-responded" : ""}`}>
                    {eventStatusLabel(activeEvent)}
                  </span>
                </div>
                <div className="event-meta-list">
                  <div><span aria-hidden="true"><MapPin size={16} strokeWidth={1.8} /></span><p><strong>{activeEvent.locationName || INVITATION_EXPERIENCE.locationNotSet}</strong><small>{activeEvent.locationAddress}</small></p></div>
                  <div><span aria-hidden="true"><Crown size={17} strokeWidth={1.8} /></span><p><strong>{INVITATION_EXPERIENCE.hostPrefix} {activeEvent.hostName.split(" ")[0] || activeEvent.hostName}</strong><small>{INVITATION_EXPERIENCE.hostMinimumNote}</small></p></div>
                  <div><span aria-hidden="true"><Clock size={17} strokeWidth={1.8} /></span><p><strong>{activeEvent.rsvpDeadline ? `${INVITATION_EXPERIENCE.replyByPrefix} ${formatEventDate(activeEvent.rsvpDeadline)}` : INVITATION_EXPERIENCE.noReplyDeadline}</strong><small>{countdown === "Closed" ? INVITATION_EXPERIENCE.responsesClosed : `${countdown} ${INVITATION_EXPERIENCE.remainingSuffix}`}</small></p></div>
                </div>
                {activeEvent.eventDescription ? <p className="event-description">{activeEvent.eventDescription}</p> : null}
                <div className="metric-row hero-metrics">
                  <Metric value={String(activeEvent.invitees.length)} label={INVITATION_EXPERIENCE.metrics.invited} />
                  <Metric value={String(activeEvent.minimumParticipants)} label={INVITATION_EXPERIENCE.metrics.minimum} />
                  <Metric value={activeThirdMetric.value} label={activeThirdMetric.label} />
                </div>
              </section>

              {activeEvent.role === "host" && activeEvent.invitationDelivery ? (
                <DeliveryCallout delivery={activeEvent.invitationDelivery} />
              ) : null}

              {activeEvent.resolution ? (
                <section className={`resolution-callout resolution-${activeEvent.resolution.status}`} aria-live="polite">
                  {activeEvent.resolution.status === "pending" ? (
                    <>
                      <h3>{activeEvent.resolution.retrying
                        ? "Still finalizing"
                        : INVITATION_EXPERIENCE.resolution.pendingTitle}</h3>
                      <p>{activeEvent.resolution.retrying
                        ? "The private evaluator is temporarily unavailable. Herd will retry automatically; nobody needs to resubmit a response."
                        : INVITATION_EXPERIENCE.resolution.pendingBody}</p>
                    </>
                  ) : activeEvent.resolution.status === "verification_unavailable" ? (
                    <>
                      <h3>Result verification unavailable</h3>
                      <p>Herd will not show a final answer without the evaluator’s valid signed proof. This may be an older result or a temporary release-key mismatch.</p>
                    </>
                  ) : activeEvent.resolution.status === "confirmed" ? (
                    <>
                      <h3>{INVITATION_EXPERIENCE.resolution.confirmedTitle}</h3>
                      <p>{INVITATION_EXPERIENCE.resolution.confirmedBody}</p>
                      <ul>
                        {resolvedAttendees(activeEvent).map((attendee) => (
                          <li key={attendee.id}>{attendee.name}</li>
                        ))}
                      </ul>
                      <small>{INVITATION_EXPERIENCE.resolution.finalizedPrefix} {formatEventDate(activeEvent.resolution.resolvedAt)}</small>
                    </>
                  ) : (
                    <>
                      <h3>{INVITATION_EXPERIENCE.resolution.notConfirmedTitle}</h3>
                      <p>{INVITATION_EXPERIENCE.resolution.notConfirmedBody}</p>
                      <small>{INVITATION_EXPERIENCE.resolution.finalizedPrefix} {formatEventDate(activeEvent.resolution.resolvedAt)}</small>
                    </>
                  )}
                </section>
              ) : null}

              <button className="attendee-entry" onClick={() => setScreen("attendees")}>
                <AvatarStack invitees={activeEvent.invitees} />
                <span className="attendee-entry-copy">
                  <strong>{activeEvent.invitees.length} {INVITATION_EXPERIENCE.attendeeEntry.peopleInvitedSuffix}</strong>
                  <span>{INVITATION_EXPERIENCE.attendeeEntry.action}</span>
                </span>
                <span className="chevron" aria-hidden="true">›</span>
              </button>

              <section className="privacy-callout">
                <div className="lock-mark" aria-hidden="true"><span></span></div>
                <div>
                  <h3>{INVITATION_EXPERIENCE.privacyCallout.title}</h3>
                  <p>{INVITATION_EXPERIENCE.privacyCallout.body}</p>
                  <button
                    ref={privacyTriggerRef}
                    className="inline-link"
                    onClick={() => setScreen("privacy")}
                  >
                    {INVITATION_EXPERIENCE.privacyCallout.action} <span aria-hidden="true">›</span>
                  </button>
                </div>
              </section>

              {activeEvent.role !== "host" && countdown !== "Closed" && (
                !activeEvent.resolution || activeEvent.resolution.status === "pending"
              ) ? <section className="reply-section">
                <div className="section-heading">
                  <h3 id="reply-choice-label">{REPLY_EXPERIENCE.title}</h3>
                  <p>{REPLY_EXPERIENCE.privacyNote}</p>
                </div>

                {privateResponseState === "loading" ? (
                  <p className="edit-note" role="status">{REPLY_EXPERIENCE.openingSaved}</p>
                ) : null}
                {privateResponseState === "unreadable" ? (
                  <p className="inline-error" role="status">
                    {REPLY_EXPERIENCE.unreadable}
                  </p>
                ) : null}

                <div className="reply-choice-group" role="radiogroup" aria-labelledby="reply-choice-label">
                  <div
                    className={`reply-option reply-option-yes ${reply === "yes" ? "selected" : ""}`}
                    onClick={() => toggleReply("yes")}
                  >
                  <div className="reply-option-header">
                    <strong className="reply-option-title">
                      <span>{REPLY_EXPERIENCE.goingPrefix}</span>
                      <span className="stepper" aria-label="Minimum people">
                      <button
                        type="button"
                        disabled={minimum <= activeEvent.minimumParticipants}
                        onClick={(event) => {
                          event.stopPropagation();
                          setMinimum((value) => Math.max(activeEvent.minimumParticipants, value - 1));
                          setReply("yes");
                        }}
                        aria-label={REPLY_EXPERIENCE.decreaseMinimum}
                      >−</button>
                      <span aria-live="polite">{minimum}</span>
                      <button
                        type="button"
                        disabled={minimum >= activeEvent.invitees.length + 1}
                        onClick={(event) => {
                          event.stopPropagation();
                          setMinimum((value) => Math.min(activeEvent.invitees.length + 1, value + 1));
                          setReply("yes");
                        }}
                        aria-label={REPLY_EXPERIENCE.increaseMinimum}
                      >+</button>
                      </span>
                      <span>{REPLY_EXPERIENCE.goingSuffix}</span>
                    </strong>
                    <button
                      type="button"
                      className="reply-selection"
                      role="radio"
                      aria-checked={reply === "yes"}
                      aria-label={`${REPLY_EXPERIENCE.goingPrefix} ${minimum} ${REPLY_EXPERIENCE.goingSuffix}`}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleReply("yes");
                      }}
                    >
                      <span className="selection-check" aria-hidden="true">✓</span>
                    </button>
                  </div>

                  <div className={`condition-builder ${conditionGroups.length ? "" : "condition-builder-empty"}`}>
                    {conditionGroups.map((group, groupIndex) => (
                      <div className="condition-row" key={groupIndex}>
                        <div className="condition-chips">
                          <span className="chip-and">AND</span>
                          {group.map((personID, index) => {
                            const name = invitedPeople.find((person) => person.id === personID)?.displayName || "Guest";
                            return <Fragment key={personID}>
                              {index > 0 ? <span className="chip-or">OR</span> : null}
                              <button
                                type="button"
                                className="person-chip"
                                aria-label={`Remove ${name} from this condition`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  setConditionGroups((groups) =>
                                    groups
                                      .map((people, index) =>
                                        index === groupIndex
                                          ? people.filter((person) => person !== personID)
                                          : people,
                                      )
                                      .filter((people) => people.length > 0),
                                  );
                                }}
                              >
                                <span>{name.split(" ")[0]}</span>
                                <span className="chip-remove" aria-hidden="true">×</span>
                              </button>
                            </Fragment>;
                          })}
                          <span className="condition-tail">
                            <button
                              type="button"
                              className="dotted-chip"
                              aria-label="Add an OR alternative"
                              onClick={(event) => {
                                event.stopPropagation();
                                openConditionSheet(event.currentTarget, groupIndex);
                              }}
                            >+ OR</button>
                            <span className="chip-goes">goes</span>
                          </span>
                        </div>
                      </div>
                    ))}
                    <div className={`condition-add-row ${conditionGroups.length ? "condition-add-row-divided" : ""}`}>
                      <button
                        type="button"
                        className="dotted-condition"
                        aria-label={conditionGroups.length ? "Add another required person condition" : "Add a required person condition"}
                        onClick={(event) => {
                          event.stopPropagation();
                          openConditionSheet(event.currentTarget);
                        }}
                      >
                        <span>+</span> {REPLY_EXPERIENCE.addCondition}
                      </button>
                    </div>
                  </div>
                  <p className="edit-note">{REPLY_EXPERIENCE.conditionHelp}</p>
                  </div>

                <button
                  className={`reply-option reply-option-no ${reply === "no" ? "selected" : ""}`}
                  role="radio"
                  aria-checked={reply === "no"}
                  onClick={() => toggleReply("no")}
                >
                  <span className="reply-option-copy">
                    <strong>{REPLY_EXPERIENCE.cantCommitTitle}</strong>
                    <span>{REPLY_EXPERIENCE.cantCommitBody}</span>
                  </span>
                  <span className="selection-check" aria-hidden="true">✓</span>
                </button>
                </div>

                <div className="response-submit">
                  {replyError ? <p className="inline-error" role="alert">{replyError}</p> : null}
                  <button className="primary-button" disabled={!reply || authPending || privateResponseState === "loading"} onClick={() => void submitReply()}>
                    {authPending
                      ? REPLY_EXPERIENCE.submittingButton
                      : reply
                        ? REPLY_EXPERIENCE.submitButton
                        : REPLY_EXPERIENCE.chooseButton}
                  </button>
                </div>
              </section> : null}
            </div>
          </section>
        ) : null}

        {screen === "attendees" ? (
          <section className="screen-layout">
            <AppHeader title={ATTENDEES_EXPERIENCE.navigationTitle} headingId="attendees-heading" onBack={goBack} />
            <div className="screen-scroll attendees-screen">
              <div className="screen-page-heading">
                <h2 id="attendees-heading">{ATTENDEES_EXPERIENCE.title}</h2>
              </div>
              <section className="host-card">
                <span className="avatar avatar-host">{personInitials(activeEvent?.hostName || "Host")}</span>
                <div><span>{ATTENDEES_EXPERIENCE.hostLabel}</span><strong>{activeEvent?.hostName || ATTENDEES_EXPERIENCE.hostLabel}</strong></div>
              </section>
              <p className="section-label">{invitedPeople.length} {ATTENDEES_EXPERIENCE.invitedSuffix}</p>
              <div className="people-list">
                {invitedPeople.map((person, index) => (
                  <div className="person-row" key={person.id}>
                    <span className={`avatar ${initialsTone(index)}`}>{personInitials(person.displayName)}</span>
                    <div><strong>{person.displayName}</strong>{person.isCurrentUser ? <span>{ATTENDEES_EXPERIENCE.currentUserLabel}</span> : null}</div>
                  </div>
                ))}
              </div>
            </div>
          </section>
        ) : null}

        {screen === "privacy" ? (
          <section className="screen-layout">
            <AppHeader title={PRIVACY_EXPERIENCE.navigationTitle} headingId="privacy-heading" onBack={goBack} />
            <div className="screen-scroll privacy-screen">
              <section className="privacy-hero">
                <div className="large-lock" aria-hidden="true"><span></span></div>
                <p className="eyebrow">{PRIVACY_EXPERIENCE.eyebrow}</p>
                <h2 id="privacy-heading" ref={privacyHeadingRef} tabIndex={-1}>{PRIVACY_EXPERIENCE.title}</h2>
                <p>{PRIVACY_EXPERIENCE.intro}</p>
              </section>

              <section className="proof-snapshot" aria-labelledby="proof-status-heading">
                <p className="eyebrow">{PRIVACY_EXPERIENCE.statusEyebrow}</p>
                <h3 id="proof-status-heading">{PRIVACY_EXPERIENCE.statusTitle}</h3>
                <div className="proof-status-stack">
                  <article className="proof-status-card proof-status-built">
                    <span className="proof-status-label"><span aria-hidden="true">✓</span> {PRIVACY_EXPERIENCE.builtLabel}</span>
                    <strong>{PRIVACY_EXPERIENCE.builtTitle}</strong>
                    <p>{PRIVACY_EXPERIENCE.builtBody}</p>
                  </article>
                  <article className="proof-status-card proof-status-pending">
                    <span className="proof-status-label"><span aria-hidden="true">○</span> {PRIVACY_EXPERIENCE.pendingLabel}</span>
                    <strong>{PRIVACY_EXPERIENCE.pendingTitle}</strong>
                    <p>{PRIVACY_EXPERIENCE.pendingBody}</p>
                  </article>
                </div>
              </section>

              <section className="proof-flow" aria-labelledby="proof-flow-heading">
                <p className="eyebrow">{PRIVACY_EXPERIENCE.flowEyebrow}</p>
                <h3 id="proof-flow-heading">{PRIVACY_EXPERIENCE.flowTitle}</h3>
                <div className="sealed-diagram" role="img" aria-label={`${PRIVACY_EXPERIENCE.flowSourceTitle} turns a readable response into a fixed-size encrypted payload before ordinary Herd storage receives it`}>
                  <div className="diagram-node">
                    <span className="key-dot" aria-hidden="true">YOU</span>
                    <strong>{PRIVACY_EXPERIENCE.flowSourceTitle}</strong>
                    <small>{PRIVACY_EXPERIENCE.flowSourceBody}</small>
                  </div>
                  <span className="diagram-arrow" aria-hidden="true">→</span>
                  <div className="diagram-envelope">
                    <span aria-hidden="true">sealed</span>
                    <strong>{PRIVACY_EXPERIENCE.flowEnvelopeTitle}</strong>
                    <small>{PRIVACY_EXPERIENCE.flowEnvelopeBody}</small>
                  </div>
                  <span className="diagram-arrow" aria-hidden="true">→</span>
                  <div className="diagram-node">
                    <span className="key-dot" aria-hidden="true">DB</span>
                    <strong>{PRIVACY_EXPERIENCE.flowDestinationTitle}</strong>
                    <small>{PRIVACY_EXPERIENCE.flowDestinationBody}</small>
                  </div>
                </div>
                <p className="proof-flow-note">{PRIVACY_EXPERIENCE.flowNote}</p>
              </section>

              <section className="privacy-architecture">
                <p className="eyebrow">{PRIVACY_EXPERIENCE.answersEyebrow}</p>
                <h3>{PRIVACY_EXPERIENCE.answersTitle}</h3>
                <p className="privacy-architecture-intro">{PRIVACY_EXPERIENCE.answersIntro}</p>
                <div className="accordion-stack">
                  {PRIVACY_EXPERIENCE.sections.map((section, sectionIndex) => (
                    <details open={sectionIndex === 0} key={section.title}>
                      <summary>{section.title} <span className="accordion-icon" aria-hidden="true">+</span></summary>
                      <div className="accordion-copy">
                        {section.paragraphs.map((paragraph, paragraphIndex) => (
                          <Fragment key={paragraph}>
                            <p>{paragraph}</p>
                            {sectionIndex === 0 && paragraphIndex === 0 ? (
                              activeEvent?.privateResponsePolicy ? (
                                <dl className="proof-identifiers" aria-label="Current event privacy identifiers">
                                  <div><dt>Protocol</dt><dd>v{activeEvent.privateResponsePolicy.protocolVersion}</dd></div>
                                  <div><dt>Cipher suite</dt><dd><code>{activeEvent.privateResponsePolicy.cipherSuite}</code></dd></div>
                                  <div><dt>Padded body</dt><dd>{activeEvent.privateResponsePolicy.paddedPlaintextBytes.toLocaleString("en-US")} bytes</dd></div>
                                  <div><dt>Policy fingerprint</dt><dd><code>{activeEvent.privateResponsePolicy.policyHash}</code></dd></div>
                                  <div><dt>Frozen</dt><dd>{formatEventDate(activeEvent.privateResponsePolicy.frozenAt)}</dd></div>
                                  <div><dt>Declared release</dt><dd><code>{activeEvent.privateResponsePolicy.releaseId}</code></dd></div>
                                  <div><dt>Evaluator key</dt><dd><code>{activeEvent.privateResponsePolicy.evaluatorKeyId}</code></dd></div>
                                  <div><dt>Declared measurement</dt><dd><code>{activeEvent.privateResponsePolicy.evaluatorMeasurement}</code></dd></div>
                                </dl>
                              ) : (
                                <p className="proof-unavailable">This event does not currently expose a frozen private-response policy, so the client cannot submit a private response.</p>
                              )
                            ) : null}
                          </Fragment>
                        ))}
                      </div>
                    </details>
                  ))}
                </div>
              </section>
            </div>
          </section>
        ) : null}

        {screen === "success" ? (
          <section className="success-screen">
            <BrandMark />
            <div className="success-content">
              <div className="success-burst" aria-hidden="true">
                <i></i><i></i><i></i><i></i><i></i><i></i>
                <span>✓</span>
              </div>
              <h1>{SUCCESS_EXPERIENCE.title}</h1>
              <p>{SUCCESS_EXPERIENCE.body}</p>
              <div className="reply-outcomes" aria-label="Saved reply details">
                <article>
                  <span className="reply-outcome-label">{SUCCESS_EXPERIENCE.savedReplyLabel}</span>
                  <strong>{SUCCESS_EXPERIENCE.savedReplyTitle}</strong>
                  <span className={`public-reply-pill ${reply === "yes" ? "public-reply-going" : "public-reply-cant"}`}>
                    {reply === "yes" ? SUCCESS_EXPERIENCE.goingLabel : SUCCESS_EXPERIENCE.cantCommitLabel}
                  </span>
                  <small>
                    {reply === "yes"
                      ? SUCCESS_EXPERIENCE.goingPrivacy
                      : SUCCESS_EXPERIENCE.cantCommitPrivacy}
                  </small>
                </article>
                <article>
                  <span className="reply-outcome-label">{SUCCESS_EXPERIENCE.visibilityLabel}</span>
                  <strong>{SUCCESS_EXPERIENCE.visibilityTitle}</strong>
                  <p>{SUCCESS_EXPERIENCE.visibilityBody}</p>
                </article>
              </div>
            </div>
            <div className="bottom-action">
              <p className="edit-note">{activeEvent?.rsvpDeadline ? `${SUCCESS_EXPERIENCE.changeWithDeadlinePrefix} ${formatEventDate(activeEvent.rsvpDeadline)}.` : SUCCESS_EXPERIENCE.changeWithoutDeadline}</p>
              <button className="primary-button" onClick={() => setScreen("event")}>{SUCCESS_EXPERIENCE.viewInvitationButton}</button>
              <button className="secondary-button" onClick={() => setScreen("home")}>
                {SUCCESS_EXPERIENCE.homeButton}
              </button>
            </div>
          </section>
        ) : null}
        </div>

        {releaseStatusOpen ? (
          <div className="dialog-backdrop" onClick={closeReleaseStatus}>
            <section
              className="release-status-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="release-status-dialog-title"
              onClick={(event) => event.stopPropagation()}
            >
              <h2 id="release-status-dialog-title">{AUTH_EXPERIENCE.releaseStatus.heading}</h2>
              <p>{AUTH_EXPERIENCE.releaseStatus.body}</p>
              <button ref={releaseStatusCloseRef} className="primary-button" onClick={closeReleaseStatus}>
                {AUTH_EXPERIENCE.releaseStatus.dismissButton}
              </button>
            </section>
          </div>
        ) : null}

        {conditionSheetOpen ? (
          <div className="sheet-backdrop" onClick={closeConditionSheet}>
            <section
              className="condition-sheet"
              ref={conditionSheetRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="condition-sheet-title"
              onClick={(event) => event.stopPropagation()}
              style={{ transform: sheetDragY ? `translateY(${sheetDragY}px)` : undefined }}
            >
              <button
                className="sheet-handle"
                aria-label="Dismiss required person sheet"
                onClick={closeConditionSheet}
                onPointerDown={handleSheetPointerDown}
                onPointerMove={handleSheetPointerMove}
                onPointerUp={handleSheetPointerUp}
                onPointerCancel={handleSheetPointerUp}
              >
                <span aria-hidden="true"></span>
              </button>
              <div className="sheet-heading">
                <h2 id="condition-sheet-title">{REPLY_EXPERIENCE.conditionPickerTitle}</h2>
                <p>{REPLY_EXPERIENCE.conditionPickerBody}</p>
              </div>
              <div className="sheet-list">
                {conditionCandidates.filter((person) => !selectedConditionPeople.includes(person.id)).length === 0
                  ? <p className="edit-note">{REPLY_EXPERIENCE.conditionPickerEmpty}</p>
                  : null}
                {conditionCandidates
                  .filter((person) => !selectedConditionPeople.includes(person.id))
                  .map((person, index) => (
                    <button key={person.id} onClick={() => addCondition(person.id)}>
                      <span className={`avatar ${initialsTone(index + 1)}`}>{personInitials(person.displayName)}</span>
                      <strong>{person.displayName}</strong>
                      <span className="sheet-plus" aria-hidden="true">+</span>
                    </button>
                  ))}
              </div>
            </section>
          </div>
        ) : null}

        {logoutConfirmationOpen ? (
          <div className="dialog-backdrop" onClick={() => setLogoutConfirmationOpen(false)}>
            <section className="logout-dialog" role="dialog" aria-modal="true" aria-labelledby="logout-title" onClick={(event) => event.stopPropagation()}>
              <h2 id="logout-title">{PROFILE_EXPERIENCE.logout.title}</h2>
              <p>{PROFILE_EXPERIENCE.logout.body}</p>
              <div>
                <button className="secondary-button" onClick={() => setLogoutConfirmationOpen(false)}>{PROFILE_EXPERIENCE.logout.cancelButton}</button>
                <button className="primary-button" onClick={logOut}>{PROFILE_EXPERIENCE.logout.confirmButton}</button>
              </div>
            </section>
          </div>
        ) : null}

        {accountDeletionOpen ? (
          <div className="dialog-backdrop" onClick={closeAccountDeletion}>
            <section
              className="account-deletion-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="account-deletion-title"
              onClick={(event) => event.stopPropagation()}
            >
              {accountDeletionStage === "confirm" ? (
                <>
                  <h2 id="account-deletion-title">{PROFILE_EXPERIENCE.accountDeletion.title}</h2>
                  <p>{PROFILE_EXPERIENCE.accountDeletion.body}</p>
                  {accountDeletionError ? <p className="inline-error" role="alert">{accountDeletionError}</p> : null}
                  <div className="dialog-actions">
                    <button className="secondary-button" disabled={accountDeletionPending} onClick={closeAccountDeletion}>
                      {PROFILE_EXPERIENCE.accountDeletion.cancelButton}
                    </button>
                    <button className="danger-button" disabled={accountDeletionPending} onClick={() => void beginAccountDeletion()}>
                      {accountDeletionPending
                        ? PROFILE_EXPERIENCE.accountDeletion.deletingButton
                        : PROFILE_EXPERIENCE.accountDeletion.continueButton}
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <h2 id="account-deletion-title">{PROFILE_EXPERIENCE.accountDeletion.verificationTitle}</h2>
                  <p>{PROFILE_EXPERIENCE.accountDeletion.verificationBody}</p>
                  <label className="deletion-code-field">
                    <span>{PROFILE_EXPERIENCE.accountDeletion.codeLabel}</span>
                    <input
                      value={accountDeletionCode}
                      onChange={(event) => {
                        setAccountDeletionCode(event.target.value.replace(/\D/g, "").slice(0, OTP_LENGTH));
                        setAccountDeletionError("");
                      }}
                      placeholder={PROFILE_EXPERIENCE.accountDeletion.codePlaceholder}
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      aria-invalid={Boolean(accountDeletionError)}
                      autoFocus
                    />
                  </label>
                  {accountDeletionError ? <p className="inline-error" role="alert">{accountDeletionError}</p> : null}
                  <div className="dialog-actions">
                    <button className="secondary-button" disabled={accountDeletionPending} onClick={closeAccountDeletion}>
                      {PROFILE_EXPERIENCE.accountDeletion.cancelButton}
                    </button>
                    <button
                      className="danger-button"
                      disabled={accountDeletionPending || accountDeletionCode.length !== OTP_LENGTH}
                      onClick={() => void confirmAccountDeletionCode()}
                    >
                      {accountDeletionPending
                        ? PROFILE_EXPERIENCE.accountDeletion.deletingButton
                        : PROFILE_EXPERIENCE.accountDeletion.verifyButton}
                    </button>
                  </div>
                </>
              )}
            </section>
          </div>
        ) : null}
      </div>
    </main>
  );
}

export default function Home() {
  return <HerdApp />;
}
