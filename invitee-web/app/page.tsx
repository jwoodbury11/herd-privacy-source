"use client";

import Image from "next/image";
import { Activity, ArrowDown, CheckCircle2, ChevronLeft, ChevronRight, CircleAlert, Clock, Construction, ContactRound, Crown, EyeOff, HardDrive, Hourglass, KeyRound, Link2, LockKeyhole, LogOut, MapPin, MoreHorizontal, Network, Plus, RefreshCw, Send, ShieldCheck, Smartphone, Trash2, UserRound, X } from "lucide-react";
import { Fragment, useCallback, useEffect, useRef, useState, type CSSProperties } from "react";
import { herdExperience } from "@/lib/experience";
import { relayHostEventEvaluation } from "@/lib/client/evaluation-relay";
import {
  PrivateVaultError,
  accountRootSecretCommitment,
  forgetAllAccountRootSecrets,
  getOrCreateAccountRootSecret,
  loadAccountRootSecret,
} from "@/lib/privacy/device-vault";
import {
  EvaluatorAuthenticationError,
  attestEvaluatorForPolicy,
} from "@/lib/privacy/evaluator-attestation";
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
  PrivateResponseEnvelopeV1,
  PrivateResponsePolicyV1,
  PrivateResponseReceiptV1,
  StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";
import {
  configuredTransparencySigningPin,
  verifyPrivateResponseReceiptPublication,
} from "@/lib/privacy/trust-verification";

const OTP_LENGTH = 4;
const RECENT_PHONE_VERIFICATION_WINDOW_MS = 9 * 60 * 1000;
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
  | "status"
  | "profile"
  | "host-download"
  | "event"
  | "attendees"
  | "add-attendees"
  | "privacy"
  | "success";

type Reply = "yes" | "no" | null;
type PrivateResponseState = "idle" | "loading" | "ready" | "unreadable";
type AccountStatusState = "healthy" | "attention" | "not-configured";
type DeviceSwitchStage = "confirm" | "requesting" | "verify" | "switching";
type ReplySubmissionResult = {
  saved: boolean;
  deviceSwitchCompleted: boolean;
  recoveryCompleted: boolean;
  errorMessage: string | null;
  errorCode: string | null;
};

type PendingReplySubmission = {
  eventId: string;
  inviteToken: string;
  draftFingerprint: string;
  accountKeyEpochId: string;
  revision: number;
  policyHash: string;
  envelope: PrivateResponseEnvelopeV1;
};

type PrivateResponseSubmissionBody = {
  responseEnvelope: StoredPrivateResponseEnvelopeV1;
  receipt: PrivateResponseReceiptV1;
};

function submissionEnvelope(
  stored: StoredPrivateResponseEnvelopeV1,
): PrivateResponseEnvelopeV1 {
  const { ciphertextHash, createdAt, updatedAt, ...envelope } = stored;
  void ciphertextHash;
  void createdAt;
  void updatedAt;
  return envelope;
}

async function verifyPrivateResponseSubmission(
  envelope: PrivateResponseEnvelopeV1,
  body: PrivateResponseSubmissionBody,
): Promise<void> {
  const expectedHash = await privateResponseEnvelopeHash(envelope);
  const transparencySigningPin = configuredTransparencySigningPin();
  if (
    body.receipt?.ciphertextHash !== expectedHash ||
    body.responseEnvelope?.ciphertextHash !== expectedHash ||
    body.responseEnvelope?.envelopeId !== envelope.envelopeId ||
    body.responseEnvelope?.responseSigningPublicKey !== envelope.responseSigningPublicKey ||
    body.responseEnvelope?.responseSignature !== envelope.responseSignature ||
    body.receipt?.envelopeId !== envelope.envelopeId ||
    body.receipt?.eventId !== envelope.eventId ||
    body.receipt?.inviteeId !== envelope.inviteeId ||
    body.receipt?.policyHash !== envelope.policyHash ||
    body.receipt?.accountKeyEpochId !== envelope.accountKeyEpochId ||
    body.receipt?.revision !== envelope.revision ||
    body.receipt?.responseSigningPublicKey !== envelope.responseSigningPublicKey ||
    body.receipt?.responseSignature !== envelope.responseSignature ||
    !transparencySigningPin
  ) {
    throw new Error("Herd returned an invalid encrypted-response receipt.");
  }
  try {
    await verifyPrivateResponseReceiptPublication(body.receipt, transparencySigningPin);
  } catch {
    throw new Error("Herd returned an invalid encrypted-response receipt.");
  }
}

class HerdResponseError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(message: string, status: number, code?: string) {
    super(message);
    this.name = "HerdResponseError";
    this.status = status;
    this.code = code ?? null;
  }
}

type AccountKeyStatusSummary = {
  available: number;
  missing: number;
  total: number;
};

function replyDraftFingerprint(
  reply: Reply,
  minimum: number,
  conditionGroups: string[][],
): string | null {
  if (!reply) return null;
  return JSON.stringify({
    reply,
    minimum: reply === "yes" ? minimum : null,
    conditionGroups: reply === "yes"
      ? conditionGroups.map((group) => [...group].sort())
      : [],
  });
}

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
  responseHistory?: {
    missedConfirmedEvents: number;
    totalConfirmedEvents: number;
  };
};

type GuestDraft = {
  id: string;
  displayName: string;
  phoneNumber: string;
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
  allowsAttendeesToAddGuests: boolean;
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
  responseCertificationStatus?: "certified" | "pending" | null;
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

type HomeEventSection = "invites" | "hosted" | "unconfirmed" | "past";

function homeEventSection(event: ApiEvent, now: number): HomeEventSection {
  if (
    event.invitationsSent &&
    event.rsvpDeadline &&
    Date.parse(event.rsvpDeadline) <= now &&
    event.resolution?.status !== "confirmed"
  ) {
    return "unconfirmed";
  }

  if (event.eventDate) {
    const eventDay = new Date(event.eventDate);
    if (!Number.isNaN(eventDay.getTime())) {
      eventDay.setHours(0, 0, 0, 0);
      eventDay.setDate(eventDay.getDate() + 1);
      if (now >= eventDay.getTime()) return "past";
    }
  }

  return event.role === "invitee" ? "invites" : "hosted";
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
  responseCertificationStatus: "certified" | "pending" | null;
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

function guestPhoneNumberIsReady(value: string) {
  const digits = value.replace(/\D/g, "");
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

function ReplyVisibilityPreview({
  displayName,
  status,
  confirmedBody,
}: {
  displayName: string;
  status: string;
  confirmedBody?: string;
}) {
  return (
    <div className="reply-visibility-preview">
      <p className="reply-preview-label">{REPLY_EXPERIENCE.confirmedPreviewLabel}</p>
      <div className="people-list reply-preview-person">
        <div className="person-row">
          <span className="avatar avatar-tone-1">{personInitials(displayName)}</span>
          <div>
            <strong>{displayName}</strong>
            <span>{status}</span>
          </div>
        </div>
      </div>
      <p className="reply-preview-note">{confirmedBody ?? REPLY_EXPERIENCE.confirmedPreviewBody}</p>
      <p className="reply-preview-label">{REPLY_EXPERIENCE.notConfirmedPreviewLabel}</p>
      <div className="reply-preview-hidden">
        <EyeOff size={18} aria-hidden="true" />
        <strong>{REPLY_EXPERIENCE.notConfirmedPreviewTitle}</strong>
      </div>
      <p className="reply-preview-note">{REPLY_EXPERIENCE.notConfirmedPreviewBody}</p>
    </div>
  );
}

function noReplyHistory(currentEvent: ApiEvent | null) {
  const currentInvitee = currentEvent?.invitees.find((person) => person.isCurrentUser);
  let missed = currentInvitee?.responseHistory?.missedConfirmedEvents ?? 0;
  let total = currentInvitee?.responseHistory?.totalConfirmedEvents ?? 0;
  const includesCurrentEvent = currentEvent?.resolution?.status === "confirmed"
    && currentEvent.resolution.attendanceRevealed;

  // This preview shows the outcome if the current invitation confirms
  // without a reply, so include that prospective result in the history.
  if (currentEvent && !includesCurrentEvent) {
    total += 1;
    missed += 1;
  }
  return { missed, total };
}

function noReplyHistoryLabel(missed: number, total: number) {
  if (missed === 1 && total === 1) {
    return REPLY_EXPERIENCE.noReplySingleEventHistory;
  }
  return REPLY_EXPERIENCE.noReplyHistoryTemplate
    .replace("{missed}", String(missed))
    .replace("{total}", String(total));
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

function formatReplyDeadline(value: string) {
  const deadline = new Date(value);
  const weekday = new Intl.DateTimeFormat("en-US", { weekday: "short" })
    .format(deadline)
    .replace("Tue", "Tues")
    .replace("Thu", "Thurs");
  const date = new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
  }).format(deadline);
  const time = new Intl.DateTimeFormat("en-US", {
    hour: "numeric",
    minute: "2-digit",
  }).format(deadline).replace(/\s/g, "").toLowerCase();
  return `${weekday}, ${date}, ${time}`;
}

function cardCountdownFor(deadline: string | null, now: number) {
  if (!deadline) {
    return { value: "—", label: HOME_EXPERIENCE.metrics.noDeadline };
  }
  const seconds = Math.max(0, Math.ceil((new Date(deadline).getTime() - now) / 1000));
  if (seconds <= 0) {
    return { value: "Passed", label: "deadline passed" };
  }
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const value = days > 0
    ? `${days}d ${hours}h`
    : hours > 0
      ? `${hours}h ${minutes}m`
      : minutes > 0
        ? `${minutes}m ${seconds % 60}s`
        : `${seconds}s`;
  return { value, label: HOME_EXPERIENCE.metrics.leftToRespond };
}

function countdownFor(deadline: string | null, now: number) {
  if (!deadline) return "No deadline";
  const seconds = Math.max(0, Math.ceil((new Date(deadline).getTime() - now) / 1000));
  if (seconds <= 0) return "Passed";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function PrivacyFlowIcon({ index }: { index: number }) {
  if (index === 0) return <Smartphone aria-hidden="true" />;
  if (index === 1) return <LockKeyhole aria-hidden="true" />;
  if (index === 2) return <HardDrive aria-hidden="true" />;
  return <ShieldCheck aria-hidden="true" />;
}

function lastUpdatedLabel(lastUpdatedAt: number | null, now: number) {
  if (lastUpdatedAt === null) return "Not updated yet";
  const elapsedSeconds = Math.max(0, Math.floor((now - lastUpdatedAt) / 1000));
  if (elapsedSeconds < 60) return "Last updated just now";
  if (elapsedSeconds < 3_600) {
    const minutes = Math.floor(elapsedSeconds / 60);
    return `Last updated ${minutes} ${minutes === 1 ? "minute" : "minutes"} ago`;
  }
  if (elapsedSeconds < 86_400) {
    const hours = Math.floor(elapsedSeconds / 3_600);
    return `Last updated ${hours} ${hours === 1 ? "hour" : "hours"} ago`;
  }
  const days = Math.floor(elapsedSeconds / 86_400);
  return `Last updated ${days} ${days === 1 ? "day" : "days"} ago`;
}

function eventStatusLabel(event: ApiEvent) {
  if (event.role === "host" && event.invitationDelivery?.status === "attention_needed") {
    return "Delivery issue";
  }
  if (event.role === "host" && event.invitationDelivery?.status === "in_progress") {
    return "Sending";
  }
  if (event.resolution?.status === "confirmed") return INVITATION_EXPERIENCE.status.confirmed;
  if (event.resolution?.status === "not_confirmed") {
    return event.rsvpDeadline && Date.parse(event.rsvpDeadline) <= Date.now()
      ? INVITATION_EXPERIENCE.status.notConfirmed
      : "Not yet confirmed";
  }
  if (event.resolution?.status === "verification_unavailable") return "Result unavailable";
  if (event.resolution?.status === "pending") {
    if (event.resolution.retrying) return "Retrying result";
    return event.rsvpDeadline && Date.parse(event.rsvpDeadline) <= Date.now()
      ? INVITATION_EXPERIENCE.status.finalizing
      : INVITATION_EXPERIENCE.status.unconfirmed;
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

function deliveryExplanation(status: InvitationDeliveryStatus) {
  switch (status) {
    case "sent":
      return "The messaging provider accepted this invitation.";
    case "failed":
      return "The messaging provider rejected this invitation, so it was not sent.";
    case "unknown":
      return "Herd could not confirm delivery and did not retry automatically to avoid sending a duplicate.";
    case "pending":
      return "This invitation is waiting to be submitted to the messaging provider.";
    case "dispatching":
      return "This invitation is being submitted to the messaging provider.";
    case "suppressed":
      return "No message was sent. This guest can still open the event directly in Herd.";
  }
}

function DeliveryStatusButton({ guest }: { guest: InvitationDeliverySummary["guests"][number] }) {
  const [isOpen, setIsOpen] = useState(false);
  const isSent = guest.status === "sent";
  return (
    <span className="delivery-status-control">
      <button
        type="button"
        className={`delivery-status-button ${isSent ? "delivery-status-sent" : "delivery-status-error"}`}
        aria-label={`${guest.displayName}: ${isSent ? "invitation sent" : "invitation delivery issue"}`}
        aria-expanded={isOpen}
        onClick={() => setIsOpen((open) => !open)}
        onBlur={() => setIsOpen(false)}
      >
        {isSent ? <Send size={16} aria-hidden="true" /> : <CircleAlert size={17} aria-hidden="true" />}
      </button>
      {isOpen ? <span className="delivery-status-tooltip" role="tooltip">{deliveryExplanation(guest.status)}</span> : null}
    </span>
  );
}

function eventThirdMetric(
  event: ApiEvent,
  fallback: { value: string; label: string },
  now = Date.now(),
) {
  if (event.resolution?.status === "confirmed") {
    if (!event.resolution.attendanceRevealed) {
      return { value: "Yes", label: "confirmed" };
    }
    return {
      value: String(event.resolution.attendingMemberIds?.length ?? 0),
      label: INVITATION_EXPERIENCE.metrics.attending,
    };
  }
  if (event.resolution?.status === "not_confirmed") {
    return event.rsvpDeadline && Date.parse(event.rsvpDeadline) <= now
      ? { value: "No", label: INVITATION_EXPERIENCE.metrics.notConfirmed }
      : fallback;
  }
  return fallback;
}

function attendeeStatusLabel(
  event: ApiEvent | null,
  person: { id: string },
) {
  if (!event) return null;
  if (
    event.resolution?.status === "confirmed"
    && event.resolution.attendanceRevealed
    && (event.role === "host" || event.hasResponse)
  ) {
    const state = event.resolution.guestStates?.find(({ memberId }) => memberId === person.id);
    if (!state) return null;
    const label = state.status === "going"
      ? "Going"
      : state.status === "cant_commit"
        ? "Can’t commit"
        : person.responseHistory
          ? noReplyHistoryLabel(
              person.responseHistory.missedConfirmedEvents,
              person.responseHistory.totalConfirmedEvents,
            )
          : "This user did not respond by the deadline.";
    return state.missedDeadline && state.status !== "no_response"
      ? `${label} · replied late`
      : label;
  }
  return null;
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
  persistentAction = false,
}: {
  title: string;
  headingId: string;
  onBack?: () => void;
  backLabel?: string;
  action?: React.ReactNode;
  persistentAction?: boolean;
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
      <div className="header-side header-side-right">{isCondensed || persistentAction ? action : null}</div>
    </header>
  );
}

function BrandMark() {
  return (
    <div className="brand-lockup" aria-label={AUTH_EXPERIENCE.brandName}>
      <Image
        src="/herd-icon.png"
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

function AvatarStack({ hostName, invitees }: { hostName: string; invitees: ApiInvitee[] }) {
  const participantCount = invitees.length + 1;
  return (
    <span className="avatar-stack" aria-label={`${participantCount} people`}>
      <span className="avatar avatar-tone-1" title={hostName}>{personInitials(hostName)}</span>
      {invitees.slice(0, 2).map((person, index) => (
        <span
          className={`avatar ${initialsTone(index + 1)}`}
          key={person.id}
          title={person.displayName}
        >
          {personInitials(person.displayName)}
        </span>
      ))}
      {participantCount > 3 ? <span className="avatar avatar-more">+{participantCount - 3}</span> : null}
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

function AccountStatusRow({
  state,
  icon,
  title,
  detail,
  value,
}: {
  state: AccountStatusState;
  icon: React.ReactNode;
  title: string;
  detail: string;
  value?: string;
}) {
  return (
    <div className={`account-status-row account-status-${state}`}>
      <span className="account-status-row-icon" aria-hidden="true">{icon}</span>
      <span className="account-status-row-copy">
        <strong>{title}</strong>
        <small>{detail}</small>
        {value ? <code>{value}</code> : null}
      </span>
      {state === "healthy"
        ? <CheckCircle2 className="account-status-state-icon" aria-label="Passed" />
        : state === "attention"
          ? <CircleAlert className="account-status-state-icon" aria-label="Needs attention" />
          : null}
    </div>
  );
}

function participantCount(event: Pick<ApiEvent, "invitees">) {
  return event.invitees.length + 1;
}

function peopleCountLabel(count: number) {
  return `${count} ${count === 1 ? "person" : "people"}`;
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
  const thirdMetric = eventThirdMetric(event, countdown, now);
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
      </div>
      <h2>{event.title || HOME_EXPERIENCE.untitledEvent}</h2>
      {event.locationName ? (
        <p className="location-line">
          <MapPin className="location-icon" size={16} strokeWidth={1.8} aria-hidden="true" />
          {event.locationName}
        </p>
      ) : null}
      <div className="metric-row">
        <Metric value={String(participantCount(event))} label={HOME_EXPERIENCE.metrics.invited} />
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
  const [savedReplyFingerprint, setSavedReplyFingerprint] = useState<string | null>(null);
  const [events, setEvents] = useState<ApiEvent[]>([]);
  const [lastEventsUpdatedAt, setLastEventsUpdatedAt] = useState<number | null>(null);
  const [eventsRefreshPending, setEventsRefreshPending] = useState(false);
  const [statusCheckPending, setStatusCheckPending] = useState(false);
  const [statusCheckedAt, setStatusCheckedAt] = useState<number | null>(null);
  const [accountKeyStatus, setAccountKeyStatus] = useState<AccountKeyStatusSummary | null>(null);
  const [homeRefreshError, setHomeRefreshError] = useState("");
  const [selectedEvent, setSelectedEvent] = useState<ApiEvent | null>(null);
  const [invitationPreview, setInvitationPreview] = useState<InvitationPreview | null>(null);
  const [invitePreviewPending, setInvitePreviewPending] = useState(Boolean(inviteToken));
  const [invitePreviewError, setInvitePreviewError] = useState("");
  const [invitePreviewRefresh, setInvitePreviewRefresh] = useState(0);
  const [inviteAccountMismatch, setInviteAccountMismatch] = useState(false);
  const [challenge, setChallenge] = useState<AuthChallenge | null>(null);
  const [authPending, setAuthPending] = useState(false);
  const [lastPhoneVerificationAt, setLastPhoneVerificationAt] = useState<number | null>(null);
  const [authError, setAuthError] = useState("");
  const [profileNotice, setProfileNotice] = useState("");
  const [profilePending, setProfilePending] = useState(false);
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
  const [eventDeletionOpen, setEventDeletionOpen] = useState(false);
  const [eventDeletionError, setEventDeletionError] = useState("");
  const [eventDeletionPending, setEventDeletionPending] = useState(false);
  const [guestDrafts, setGuestDrafts] = useState<GuestDraft[]>([]);
  const [guestAdditionError, setGuestAdditionError] = useState("");
  const [guestAdditionPending, setGuestAdditionPending] = useState(false);
  const [deviceSwitchOpen, setDeviceSwitchOpen] = useState(false);
  const [deviceSwitchStage, setDeviceSwitchStage] = useState<DeviceSwitchStage>("confirm");
  const [deviceSwitchChallenge, setDeviceSwitchChallenge] = useState<AuthChallenge | null>(null);
  const [deviceSwitchCode, setDeviceSwitchCode] = useState("");
  const [deviceSwitchError, setDeviceSwitchError] = useState("");
  const [deviceSwitchPending, setDeviceSwitchPending] = useState(false);
  const [minimum, setMinimum] = useState(4);
  const [conditionGroups, setConditionGroups] = useState<string[][]>([]);
  const [conditionTargetGroup, setConditionTargetGroup] = useState<number | null>(null);
  const [conditionSheetOpen, setConditionSheetOpen] = useState(false);
  const [sheetDragY, setSheetDragY] = useState(0);
  const [replyPreviewOpen, setReplyPreviewOpen] = useState(false);
  const [replyPreviewDragY, setReplyPreviewDragY] = useState(0);
  const otpInputRef = useRef<HTMLInputElement | null>(null);
  const verificationInFlightRef = useRef(false);
  const replySubmissionInFlightRef = useRef(false);
  const pendingReplySubmissionRef = useRef<PendingReplySubmission | null>(null);
  const eventActionsRef = useRef<HTMLDetailsElement | null>(null);
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
  const replyPreviewTriggerRef = useRef<HTMLButtonElement | null>(null);
  const replyPreviewSheetRef = useRef<HTMLElement | null>(null);
  const replyPreviewDragStartRef = useRef<number | null>(null);
  const replyPreviewDragLatestRef = useRef(0);
  const lastResolutionRefreshRef = useRef(0);
  const resolutionRefreshInFlightRef = useRef(false);
  const homeRefreshInFlightRef = useRef(false);
  const lastEventsUpdatedAtRef = useRef<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const resetAuthenticatedExperience = useCallback(() => {
    setLogoutConfirmationOpen(false);
    setAccountDeletionOpen(false);
    setAccountDeletionStage("confirm");
    setEventDeletionOpen(false);
    setEventDeletionError("");
    setEventDeletionPending(false);
    setGuestDrafts([]);
    setGuestAdditionError("");
    setGuestAdditionPending(false);
    setDeviceSwitchOpen(false);
    setDeviceSwitchStage("confirm");
    setDeviceSwitchChallenge(null);
    setDeviceSwitchCode("");
    setDeviceSwitchError("");
    setAccountDeletionChallenge(null);
    setAccountDeletionCode("");
    setAccountDeletionError("");
    setAccountDeletionPending(false);
    setOtp("");
    setChallenge(null);
    setEvents([]);
    setSelectedEvent(null);
    setCurrentUser(null);
    setLastPhoneVerificationAt(null);
    setInviteMetadata(null);
    setPrivateResponseState("idle");
    pendingReplySubmissionRef.current = null;
    setInvitationPreview(null);
    setInvitePreviewPending(Boolean(inviteToken));
    setInvitePreviewError("");
    setInviteAccountMismatch(false);
    setInvitePreviewRefresh((value) => value + 1);
    setProfileName("");
    setPhoneNumber("");
    setAddress("");
    setScreen("welcome");
  }, [inviteToken]);
  const recoverExpiredSession = useCallback(() => {
    resetAuthenticatedExperience();
    setAuthError("Your session expired. Sign in again to continue.");
  }, [resetAuthenticatedExperience]);
  const markEventsUpdated = useCallback(() => {
    const updatedAt = Date.now();
    lastEventsUpdatedAtRef.current = updatedAt;
    setLastEventsUpdatedAt(updatedAt);
  }, []);
  const refreshHomeEvents = useCallback(async () => {
    if (homeRefreshInFlightRef.current) return;
    homeRefreshInFlightRef.current = true;
    setEventsRefreshPending(true);
    setHomeRefreshError("");
    try {
      const response = await fetch("/api/events", { credentials: "include" });
      if (response.status === 401) {
        recoverExpiredSession();
        return;
      }
      if (!response.ok) {
        throw new Error(await responseError(response, "Couldn’t refresh your events."));
      }
      const body = await response.json() as { events?: ApiEvent[] };
      const verifiedEvents = await Promise.all(
        (Array.isArray(body.events) ? body.events : []).map(verifiedApiEvent),
      );
      setEvents(sortEventsForHome(verifiedEvents));
      markEventsUpdated();
    } catch (error) {
      setHomeRefreshError(
        error instanceof Error ? error.message : "Couldn’t refresh your events.",
      );
    } finally {
      homeRefreshInFlightRef.current = false;
      setEventsRefreshPending(false);
    }
  }, [markEventsUpdated, recoverExpiredSession]);
  const activeEvent = selectedEvent ?? events[0] ?? null;
  const hasPendingResponseCertification =
    inviteMetadata?.responseCertificationStatus === "pending" &&
    Boolean(inviteMetadata.responseEnvelope);
  const currentReplyFingerprint = replyDraftFingerprint(reply, minimum, conditionGroups);
  const hasPendingReplySubmission = Boolean(
    activeEvent &&
    currentReplyFingerprint &&
    pendingReplySubmissionRef.current?.eventId === activeEvent.id &&
    pendingReplySubmissionRef.current?.draftFingerprint === currentReplyFingerprint,
  );
  const replyHasUnsavedChanges = Boolean(currentReplyFingerprint) && (
    !activeEvent?.hasResponse ||
    currentReplyFingerprint !== savedReplyFingerprint ||
    hasPendingReplySubmission
  );
  const invitedEvents = events.filter((event) => homeEventSection(event, now) === "invites");
  const hostedEvents = events.filter((event) => homeEventSection(event, now) === "hosted");
  const unconfirmedEvents = events.filter((event) => homeEventSection(event, now) === "unconfirmed");
  const pastEvents = events.filter((event) => homeEventSection(event, now) === "past");
  const activeInvitationCount = events.filter((event) => event.role === "invitee" && event.inviteToken).length;
  const protectedEventCount = events.filter((event) => event.privateResponsePolicy !== null).length;
  const verificationIssueCount = events.filter((event) => event.resolution?.status === "verification_unavailable").length;
  const accountStatusNeedsAttention = Boolean(homeRefreshError)
    || Boolean(accountKeyStatus?.missing)
    || verificationIssueCount > 0;
  const displayProfileName = profileName.trim();
  const profileHasChanges = currentUser !== null && (
    profileName.trim() !== currentUser.name.trim() ||
    address.trim() !== currentUser.address.trim()
  );
  const invitedPeople = activeEvent?.invitees ?? [];
  const canAddAttendees = Boolean(
    activeEvent &&
    activeEvent.invitees.length < 19 &&
    (activeEvent.role === "host" || activeEvent.allowsAttendeesToAddGuests),
  );
  const conditionCandidates = invitedPeople.filter((person) => !person.isCurrentUser);
  const replyPreviewName = invitedPeople.find((person) => person.isCurrentUser)?.displayName
    || currentUser?.name
    || ATTENDEES_EXPERIENCE.currentUserLabel;
  const replyPreviewNoResponseHistory = noReplyHistory(activeEvent);
  const countdown = countdownFor(activeEvent?.rsvpDeadline ?? null, now);
  const activeThirdMetric = activeEvent
    ? eventThirdMetric(activeEvent, { value: countdown, label: "left to respond" }, now)
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
    if (screen !== "home" || !currentUser) return;
    const refreshIfStale = () => {
      if (document.visibilityState !== "visible") return;
      const lastUpdatedAt = lastEventsUpdatedAtRef.current;
      if (lastUpdatedAt !== null && Date.now() - lastUpdatedAt < 60_000) return;
      void refreshHomeEvents();
    };
    refreshIfStale();
    const timer = window.setInterval(refreshIfStale, 60_000);
    document.addEventListener("visibilitychange", refreshIfStale);
    return () => {
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", refreshIfStale);
    };
  }, [currentUser, refreshHomeEvents, screen]);

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
          if (response.status === 401) {
            recoverExpiredSession();
            return;
          }
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
          markEventsUpdated();
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
        if (response.status === 401) {
          recoverExpiredSession();
          return;
        }
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
        markEventsUpdated();
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
  }, [events, inviteToken, markEventsUpdated, now, recoverExpiredSession, resolutionRefreshTarget, screen]);

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
    if (
      !currentUser ||
      !selectedEvent ||
      !inviteMetadata?.canRespond ||
      replySubmissionInFlightRef.current
    ) return;
    let cancelled = false;
    void (async () => {
      setReplyError("");
      if (!inviteMetadata.hasResponse) {
        setSavedReplyFingerprint(null);
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
            error instanceof PrivateVaultError && error.canSwitchDevice
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
          setSavedReplyFingerprint(null);
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
        const savedReply = draft.response === "going" ? "yes" : "no";
        const savedMinimum =
          draft.response === "going" && draft.minimumParticipants !== null
            ? draft.minimumParticipants
            : selectedEvent.minimumParticipants;
        const savedConditionGroups = draft.requiredGroups.map((group) => group.memberIDs);
        const fingerprint = replyDraftFingerprint(
          savedReply,
          savedMinimum,
          savedConditionGroups,
        );
        setReply(savedReply);
        setMinimum(savedMinimum);
        setConditionGroups(savedConditionGroups);
        setSavedReplyFingerprint(fingerprint);
        if (
          fingerprint &&
          inviteMetadata.responseCertificationStatus === "pending" &&
          selectedEvent.privateResponsePolicy
        ) {
          const token = selectedEvent.inviteToken ?? inviteToken;
          if (token) {
            pendingReplySubmissionRef.current = {
              eventId: selectedEvent.id,
              inviteToken: token,
              draftFingerprint: fingerprint,
              accountKeyEpochId: inviteMetadata.responseEnvelope.accountKeyEpochId,
              revision: inviteMetadata.responseEnvelope.revision,
              policyHash: selectedEvent.privateResponsePolicy.policyHash,
              envelope: submissionEnvelope(inviteMetadata.responseEnvelope),
            };
          }
        }
        setPrivateResponseState("ready");
      } catch (error) {
        if (cancelled) return;
        setPrivateResponseState(
          (error instanceof PrivateVaultError && error.canSwitchDevice) ||
            (error instanceof PrivateResponseCryptoError && error.canSwitchDevice)
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
  }, [currentUser, inviteMetadata, inviteToken, selectedEvent]);

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

  useEffect(() => {
    if (!replyPreviewOpen) return;
    const sheet = replyPreviewSheetRef.current;
    const focusable = sheet
      ? Array.from(sheet.querySelectorAll<HTMLElement>('button:not([disabled]), [tabindex]:not([tabindex="-1"])'))
      : [];
    focusable[0]?.focus();

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setReplyPreviewOpen(false);
        window.requestAnimationFrame(() => replyPreviewTriggerRef.current?.focus());
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
  }, [replyPreviewOpen]);

  const selectedConditionPeople = conditionGroups.flat();
  function goBack() {
    const previous: Record<Screen, Screen> = {
      welcome: "welcome",
      verify: "welcome",
      home: "home",
      status: "home",
      profile: "home",
      "host-download": "home",
      event: "home",
      attendees: "event",
      "add-attendees": "attendees",
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

  async function runAccountStatusChecks() {
    if (statusCheckPending) return;
    setStatusCheckPending(true);
    try {
      await refreshHomeEvents();
      if (!currentUser) {
        setAccountKeyStatus({ available: 0, missing: 0, total: 0 });
        return;
      }

      const epochs = new Map<string, string | undefined>();
      for (const event of events) {
        if (event.accountKeyEpochId) {
          epochs.set(event.accountKeyEpochId, event.accountKeyCommitment ?? undefined);
        }
      }

      let available = 0;
      let missing = 0;
      for (const [epochID, commitment] of epochs) {
        try {
          const secret = await loadAccountRootSecret(currentUser.id, epochID, commitment);
          if (secret) {
            available += 1;
            secret.bytes.fill(0);
          } else if (commitment) {
            missing += 1;
          }
        } catch {
          missing += 1;
        }
      }
      setAccountKeyStatus({ available, missing, total: epochs.size });
    } finally {
      setStatusCheckedAt(Date.now());
      setStatusCheckPending(false);
    }
  }

  async function loadAuthenticatedData(): Promise<boolean> {
    const requests: Promise<Response>[] = [
      fetch("/api/events", { credentials: "include" }),
    ];
    if (inviteToken) {
      requests.push(fetch(`/api/invites/${encodeURIComponent(inviteToken)}`, { credentials: "include" }));
    }

    const [eventsResponse, inviteResponse] = await Promise.all(requests);
    if (eventsResponse.status === 401 || inviteResponse?.status === 401) {
      recoverExpiredSession();
      throw new Error("Your session expired. Sign in again to continue.");
    }
    if (!eventsResponse.ok) {
      throw new Error(await responseError(eventsResponse, "Couldn’t load your events."));
    }
    const body = await eventsResponse.json() as { events?: ApiEvent[] };
    const verifiedEvents = await Promise.all(
      (Array.isArray(body.events) ? body.events : []).map(verifiedApiEvent),
    );
    setEvents(sortEventsForHome(verifiedEvents));
    markEventsUpdated();
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
        setSavedReplyFingerprint(null);
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
    setSavedReplyFingerprint(null);
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
      if (response.status === 401) {
        recoverExpiredSession();
        return;
      }
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

  function openEventDeletion() {
    if (activeEvent?.role !== "host") return;
    eventActionsRef.current?.removeAttribute("open");
    setEventDeletionError("");
    setEventDeletionOpen(true);
  }

  function newGuestDraft(): GuestDraft {
    return { id: crypto.randomUUID(), displayName: "", phoneNumber: "" };
  }

  function openGuestAddition() {
    if (!canAddAttendees) return;
    setGuestDrafts([newGuestDraft()]);
    setGuestAdditionError("");
    setScreen("add-attendees");
  }

  function closeGuestAddition() {
    if (guestAdditionPending) return;
    setGuestDrafts([]);
    setGuestAdditionError("");
    setScreen("attendees");
  }

  function updateGuestDraft(
    id: string,
    field: "displayName" | "phoneNumber",
    value: string,
  ) {
    setGuestDrafts((current) => current.map((guest) =>
      guest.id === id ? { ...guest, [field]: value } : guest
    ));
    setGuestAdditionError("");
  }

  function addGuestDraft() {
    if (!activeEvent || activeEvent.invitees.length + guestDrafts.length >= 19) return;
    setGuestDrafts((current) => [...current, newGuestDraft()]);
  }

  function removeGuestDraft(id: string) {
    setGuestDrafts((current) => current.length === 1
      ? current
      : current.filter((guest) => guest.id !== id)
    );
    setGuestAdditionError("");
  }

  async function addEventGuests() {
    const event = activeEvent;
    if (!event || guestAdditionPending || guestDrafts.length === 0) return;
    const invitees = guestDrafts.map((guest) => ({
      id: guest.id,
      displayName: guest.displayName.trim(),
      phoneNumber: guest.phoneNumber.trim(),
    }));
    if (invitees.some((guest) => !guest.displayName)) {
      setGuestAdditionError("Enter a name for every guest.");
      return;
    }
    if (invitees.some((guest) => !guestPhoneNumberIsReady(guest.phoneNumber))) {
      setGuestAdditionError("Enter a complete phone number for every guest.");
      return;
    }
    const phoneKeys = invitees.map((guest) => guest.phoneNumber.replace(/\D/g, ""));
    if (new Set(phoneKeys).size !== phoneKeys.length) {
      setGuestAdditionError("Each guest needs a different phone number.");
      return;
    }

    setGuestAdditionPending(true);
    setGuestAdditionError("");
    try {
      const response = await fetch(`/api/events/${encodeURIComponent(event.id)}/attendees`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ invitees }),
      });
      if (response.status === 401) {
        recoverExpiredSession();
        return;
      }
      if (!response.ok) {
        throw new Error(await responseError(response, ATTENDEES_EXPERIENCE.addGuests.failureBody));
      }
      const body = await response.json() as { event?: ApiEvent };
      if (!body.event) throw new Error(ATTENDEES_EXPERIENCE.addGuests.failureBody);
      const updatedEvent = await verifiedApiEvent(body.event);
      setSelectedEvent(updatedEvent);
      setEvents((current) => upsertHomeEvent(current, updatedEvent));
      setGuestDrafts([]);
      setScreen("attendees");
      markEventsUpdated();
    } catch (error) {
      setGuestAdditionError(
        error instanceof Error ? error.message : ATTENDEES_EXPERIENCE.addGuests.failureBody,
      );
    } finally {
      setGuestAdditionPending(false);
    }
  }

  function closeEventDeletion() {
    if (eventDeletionPending) return;
    setEventDeletionOpen(false);
    setEventDeletionError("");
  }

  async function deleteHostedEvent() {
    const eventToDelete = activeEvent;
    if (eventToDelete?.role !== "host" || eventDeletionPending) return;
    setEventDeletionPending(true);
    setEventDeletionError("");
    try {
      const response = await fetch(`/api/events/${encodeURIComponent(eventToDelete.id)}`, {
        method: "DELETE",
        credentials: "include",
      });
      if (response.status === 401) {
        recoverExpiredSession();
        return;
      }
      if (!response.ok) {
        throw new Error(await responseError(
          response,
          INVITATION_EXPERIENCE.eventActions.failureBody,
        ));
      }
      setEvents((current) => current.filter((event) => event.id !== eventToDelete.id));
      setSelectedEvent(null);
      setEventDeletionOpen(false);
      setScreen("home");
      markEventsUpdated();
    } catch (error) {
      setEventDeletionError(
        error instanceof Error
          ? error.message
          : INVITATION_EXPERIENCE.eventActions.failureBody,
      );
    } finally {
      setEventDeletionPending(false);
    }
  }

  async function saveProfile() {
    if (!profileHasChanges || profilePending) return false;
    setProfileNotice("");
    setProfilePending(true);
    try {
      const response = await fetch("/api/me", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ name: profileName.trim(), address: address.trim() }),
      });
      if (response.status === 401) {
        recoverExpiredSession();
        return false;
      }
      if (!response.ok) {
        setProfileNotice(await responseError(response, "Couldn’t save your profile."));
        return false;
      }
      const body = await response.json() as { user: ApiUser };
      applyUser(body.user);
      setProfileNotice(PROFILE_EXPERIENCE.savedNotice);
      return true;
    } catch {
      setProfileNotice("Couldn’t save your profile.");
      return false;
    } finally {
      setProfilePending(false);
    }
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
    // Start a clean document on the same invitation URL. An account restore
    // request from this document may already be in flight and must not be able
    // to re-apply the account that was just signed out.
    window.location.reload();
  }

  async function performAccountDeletion(): Promise<"deleted" | "reauthenticate"> {
    const response = await fetch("/api/me", {
      method: "DELETE",
      headers: { "content-type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ confirmation: "DELETE" }),
    });
    if (response.status === 401) {
      recoverExpiredSession();
      throw new Error("Your session expired. Sign in again to continue.");
    }
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
    if (nextOtp.length === OTP_LENGTH) void verifyCode(nextOtp);
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
        setLastPhoneVerificationAt(Date.now());
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

  async function verifyCode(code = otp) {
    if (code.length !== OTP_LENGTH) {
      setOtpError("Enter all four digits to continue.");
      focusInputAtEnd(otpInputRef.current);
      return;
    }
    if (!challenge || authPending || verificationInFlightRef.current) return;
    verificationInFlightRef.current = true;
    setAuthPending(true);
    setOtpError("");
    try {
      const response = await fetch("/api/auth/verify-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ challengeId: challenge.challengeId, code }),
      });
      if (!response.ok) throw new Error(await responseError(response, "That code could not be verified."));
      const body = await response.json() as { user: ApiUser };
      applyUser(body.user);
      setLastPhoneVerificationAt(Date.now());
      const openedInvitation = await loadAuthenticatedData();
      setScreen(openedInvitation ? "event" : "home");
    } catch (error) {
      setOtpError(error instanceof Error ? error.message : "That code could not be verified.");
      focusInputAtEnd(otpInputRef.current);
    } finally {
      verificationInFlightRef.current = false;
      setAuthPending(false);
    }
  }

  async function resendCode() {
    if (resendSeconds > 0) return;
    if (await requestCode()) setResendNotice("A new code was sent.");
  }

  function toggleReply(nextReply: Exclude<Reply, null>) {
    setReply((current) => current === nextReply ? null : nextReply);
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

  function removeConditionPerson(groupIndex: number, personID: string) {
    setConditionGroups((current) =>
      current
        .map((group, index) =>
          index === groupIndex ? group.filter((id) => id !== personID) : group,
        )
        .filter((group) => group.length > 0),
    );
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

  function openReplyPreview() {
    setReplyPreviewDragY(0);
    setReplyPreviewOpen(true);
  }

  function closeReplyPreview() {
    setReplyPreviewOpen(false);
    setReplyPreviewDragY(0);
    window.requestAnimationFrame(() => replyPreviewTriggerRef.current?.focus());
  }

  function handleReplyPreviewPointerDown(event: React.PointerEvent<HTMLButtonElement>) {
    replyPreviewDragStartRef.current = event.clientY;
    replyPreviewDragLatestRef.current = 0;
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function handleReplyPreviewPointerMove(event: React.PointerEvent<HTMLButtonElement>) {
    if (replyPreviewDragStartRef.current === null) return;
    const distance = Math.max(0, event.clientY - replyPreviewDragStartRef.current);
    replyPreviewDragLatestRef.current = distance;
    setReplyPreviewDragY(distance);
  }

  function handleReplyPreviewPointerUp(event: React.PointerEvent<HTMLButtonElement>) {
    if (replyPreviewDragStartRef.current === null) return;
    replyPreviewDragStartRef.current = null;
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
    if (replyPreviewDragLatestRef.current > 70) closeReplyPreview();
    else setReplyPreviewDragY(0);
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

  function closeDeviceSwitch() {
    if (deviceSwitchPending || authPending) return;
    setDeviceSwitchOpen(false);
    setDeviceSwitchStage("confirm");
    setDeviceSwitchChallenge(null);
    setDeviceSwitchCode("");
    setDeviceSwitchError("");
  }

  async function finishDeviceSwitchAfterVerification() {
    setDeviceSwitchStage("switching");
    const result = await submitReply(true);
    if (result.saved || result.deviceSwitchCompleted || result.recoveryCompleted) {
      setDeviceSwitchOpen(false);
      setDeviceSwitchStage("confirm");
      setDeviceSwitchChallenge(null);
      setDeviceSwitchCode("");
      setDeviceSwitchError("");
    } else {
      setDeviceSwitchStage("confirm");
      if (result.errorCode === "fresh_phone_verification_required") {
        setLastPhoneVerificationAt(null);
      }
      setDeviceSwitchError(
        result.errorMessage ?? REPLY_EXPERIENCE.deviceSwitch.failure,
      );
    }
  }

  async function beginDeviceSwitchVerification() {
    if (!currentUser || deviceSwitchPending) return;
    if (
      lastPhoneVerificationAt !== null &&
      Date.now() - lastPhoneVerificationAt < RECENT_PHONE_VERIFICATION_WINDOW_MS
    ) {
      setDeviceSwitchPending(true);
      setDeviceSwitchError("");
      try {
        await finishDeviceSwitchAfterVerification();
      } finally {
        setDeviceSwitchPending(false);
      }
      return;
    }
    setDeviceSwitchPending(true);
    setDeviceSwitchStage("requesting");
    setDeviceSwitchError("");
    try {
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
        setLastPhoneVerificationAt(Date.now());
        setDeviceSwitchPending(false);
        await finishDeviceSwitchAfterVerification();
        return;
      }
      if (!body.challengeId || !body.phoneNumber || !body.expiresAt || !body.resendAt) {
        throw new Error("The verification request could not be started.");
      }
      setDeviceSwitchChallenge(body);
      setDeviceSwitchCode("");
      setDeviceSwitchStage("verify");
    } catch (error) {
      setDeviceSwitchStage("confirm");
      setDeviceSwitchError(
        error instanceof Error ? error.message : REPLY_EXPERIENCE.deviceSwitch.requestFailed,
      );
    } finally {
      setDeviceSwitchPending(false);
    }
  }

  async function verifyDeviceSwitchCode() {
    if (
      !deviceSwitchChallenge ||
      deviceSwitchCode.length !== OTP_LENGTH ||
      deviceSwitchPending
    ) return;
    setDeviceSwitchPending(true);
    setDeviceSwitchError("");
    try {
      const response = await fetch("/api/auth/verify-code", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({
          challengeId: deviceSwitchChallenge.challengeId,
          code: deviceSwitchCode,
        }),
      });
      if (!response.ok) {
        throw new Error(await responseError(response, "That code could not be verified."));
      }
      const body = await response.json() as { user: ApiUser };
      applyUser(body.user);
      setLastPhoneVerificationAt(Date.now());
      setDeviceSwitchPending(false);
      await finishDeviceSwitchAfterVerification();
    } catch (error) {
      setDeviceSwitchStage("verify");
      setDeviceSwitchError(
        error instanceof Error ? error.message : "That code could not be verified.",
      );
    } finally {
      setDeviceSwitchPending(false);
    }
  }

  async function submitReply(
    deviceSwitchConfirmed = false,
  ): Promise<ReplySubmissionResult> {
    const notSaved = (
      errorMessage: string | null = null,
      deviceSwitchCompleted = false,
      errorCode: string | null = null,
      recoveryCompleted = false,
    ): ReplySubmissionResult => ({
      saved: false,
      deviceSwitchCompleted,
      recoveryCompleted,
      errorMessage,
      errorCode,
    });
    if (
      !reply ||
      !activeEvent ||
      !currentUser ||
      !inviteMetadata?.canRespond ||
      authPending ||
      privateResponseState === "loading"
    ) return notSaved();
    const token = activeEvent.inviteToken ?? inviteToken;
    if (!token) {
      const message = "This invitation does not have an active reply link yet.";
      setReplyError(message);
      return notSaved(message);
    }
    if (!activeEvent.privateResponsePolicy) {
      const message = "This event is not ready to accept encrypted responses.";
      setReplyError(message);
      return notSaved(message);
    }
    const submittedReply = reply;
    const submittedMinimum = minimum;
    const submittedConditionGroups = conditionGroups.map((group) => [...group]);
    const submittedFingerprint = replyDraftFingerprint(
      submittedReply,
      submittedMinimum,
      submittedConditionGroups,
    );
    if (!submittedFingerprint) return notSaved();
    replySubmissionInFlightRef.current = true;
    setAuthPending(true);
    setReplyError("");
    let accountRootSecret: Uint8Array | null = null;
    let deviceSwitchCompleted = false;
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
          if (!(error instanceof PrivateVaultError) || !error.canSwitchDevice) {
            throw error;
          }
        }
      }
      accountRootSecret = localAccountKey?.bytes ?? null;
      const savedResponseUsesActiveEpoch =
        inviteMetadata.responseEnvelope?.accountKeyEpochId === accountKeyEpochId;
      const mustSwitchAccountKey =
        Boolean(accountKeyCommitment && !localAccountKey) ||
        (privateResponseState === "unreadable" && savedResponseUsesActiveEpoch);
      if (mustSwitchAccountKey && !deviceSwitchConfirmed) {
        setDeviceSwitchStage("confirm");
        setDeviceSwitchChallenge(null);
        setDeviceSwitchCode("");
        setDeviceSwitchError("");
        setDeviceSwitchOpen(true);
        return notSaved();
      }
      if (mustSwitchAccountKey) {
        const switchResponse = await fetch("/api/account/key-epoch/reset", {
          method: "POST",
          headers: { "content-type": "application/json" },
          credentials: "include",
          body: JSON.stringify({
            expectedAccountKeyEpochId: inviteMetadata.accountKeyEpochId,
          }),
        });
        if (!switchResponse.ok) {
          const error = await responseErrorDetails(
            switchResponse,
            "This device couldn’t prepare a new encrypted reply.",
          );
          throw new HerdResponseError(error.message, switchResponse.status, error.code);
        }
        const switchedEpoch = await switchResponse.json() as { accountKeyEpochId: string };
        accountRootSecret?.fill(0);
        accountRootSecret = null;
        accountKeyEpochId = switchedEpoch.accountKeyEpochId;
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
          const error = await responseErrorDetails(
            initializeResponse,
            "The account encryption key could not be initialized.",
          );
          throw new HerdResponseError(error.message, initializeResponse.status, error.code);
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
        if (mustSwitchAccountKey) deviceSwitchCompleted = true;
      }
      if (!localAccountKey) {
        throw new Error("The active account key is not available on this device.");
      }
      accountRootSecret = localAccountKey.bytes;
      const revision = (inviteMetadata.responseRevision ?? 0) + 1;
      const pendingSubmission = pendingReplySubmissionRef.current;
      const storedResponseIsPendingSubmission = Boolean(
        pendingSubmission &&
        inviteMetadata.responseEnvelope?.envelopeId === pendingSubmission.envelope.envelopeId &&
        inviteMetadata.responseEnvelope?.responseSignature === pendingSubmission.envelope.responseSignature,
      );
      let envelope: PrivateResponseEnvelopeV1;
      if (
        pendingSubmission &&
        pendingSubmission.eventId === activeEvent.id &&
        pendingSubmission.inviteToken === token &&
        pendingSubmission.draftFingerprint === submittedFingerprint &&
        pendingSubmission.accountKeyEpochId === accountKeyEpochId &&
        (pendingSubmission.revision === revision || storedResponseIsPendingSubmission) &&
        pendingSubmission.policyHash === activeEvent.privateResponsePolicy.policyHash
      ) {
        envelope = pendingSubmission.envelope;
      } else {
        await attestEvaluatorForPolicy(activeEvent.privateResponsePolicy);
        const sealed = await sealPrivateResponse({
          eventId: activeEvent.id,
          inviteeId: inviteMetadata.id,
          accountKeyEpochId,
          revision,
          response: submittedReply === "yes" ? "going" : "cant_commit",
          minimumParticipants: submittedReply === "yes" ? submittedMinimum : null,
          requiredGroups: submittedReply === "yes"
            ? submittedConditionGroups.map((memberIDs) => ({
                id: newConditionGroupId(),
                memberIDs: [...memberIDs].sort(),
              }))
            : [],
          allowedInviteeIds: activeEvent.invitees.map((person) => person.id),
          accountRootSecret,
          policy: activeEvent.privateResponsePolicy,
        });
        envelope = sealed.envelope;
        pendingReplySubmissionRef.current = {
          eventId: activeEvent.id,
          inviteToken: token,
          draftFingerprint: submittedFingerprint,
          accountKeyEpochId,
          revision,
          policyHash: activeEvent.privateResponsePolicy.policyHash,
          envelope,
        };
      }
      const response = await fetch(`/api/invites/${encodeURIComponent(token)}/rsvp`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ envelope }),
      });
      if (!response.ok) {
        const error = await responseErrorDetails(response, "Couldn’t save your reply.");
        throw new HerdResponseError(error.message, response.status, error.code);
      }
      const body = await response.json() as PrivateResponseSubmissionBody;
      await verifyPrivateResponseSubmission(envelope, body);
      setInviteMetadata((current) => current ? {
        ...current,
        accountKeyEpochId,
        accountKeyCommitment,
        hasResponse: true,
        responseRevision: revision,
        responseEnvelope: body.responseEnvelope,
        responseCertificationStatus: "certified",
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
      setSavedReplyFingerprint(
        replyDraftFingerprint(
          submittedReply,
          submittedMinimum,
          submittedConditionGroups,
        ),
      );
      setPrivateResponseState("ready");
      pendingReplySubmissionRef.current = null;
      setScreen("success");
      return {
        saved: true,
        deviceSwitchCompleted,
        recoveryCompleted: false,
        errorMessage: null,
        errorCode: null,
      };
    } catch (error) {
      if (
        error instanceof EvaluatorAuthenticationError ||
        (error instanceof HerdResponseError && error.status === 401)
      ) {
        const message = "Your session expired. Sign in again to continue.";
        resetAuthenticatedExperience();
        setAuthError(message);
        return notSaved(message, deviceSwitchCompleted, "authentication_required");
      }
      if (
        error instanceof HerdResponseError &&
        error.code === "account_key_epoch_changed"
      ) {
        pendingReplySubmissionRef.current = null;
        try {
          const openedInvitation = await loadAuthenticatedData();
          setScreen(openedInvitation ? "event" : "home");
          const message = "Private-reply security changed on another device. Herd refreshed it; choose your reply and try again.";
          setReplyError(message);
          return notSaved(message, false, "account_key_epoch_refreshed", true);
        } catch (refreshError) {
          if (refreshError instanceof Error) {
            setReplyError(refreshError.message);
            return notSaved(refreshError.message, false, error.code);
          }
        }
      }
      const message = error instanceof Error ? error.message : "Couldn’t save your reply.";
      setReplyError(message);
      return notSaved(
        message,
        deviceSwitchCompleted,
        error instanceof HerdResponseError ? error.code : null,
      );
    } finally {
      accountRootSecret?.fill(0);
      replySubmissionInFlightRef.current = false;
      setAuthPending(false);
    }
  }

  async function retryStoredReplyCertification(): Promise<void> {
    if (
      authPending ||
      !activeEvent ||
      !inviteMetadata?.canRespond ||
      inviteMetadata.responseCertificationStatus !== "pending" ||
      !inviteMetadata.responseEnvelope
    ) return;
    const token = activeEvent.inviteToken ?? inviteToken;
    if (!token) {
      setReplyError("This invitation does not have an active reply link yet.");
      return;
    }
    const envelope = submissionEnvelope(inviteMetadata.responseEnvelope);
    replySubmissionInFlightRef.current = true;
    setAuthPending(true);
    setReplyError("");
    try {
      const response = await fetch(`/api/invites/${encodeURIComponent(token)}/rsvp`, {
        method: "PUT",
        headers: { "content-type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ envelope }),
      });
      if (response.status === 401) {
        recoverExpiredSession();
        return;
      }
      if (!response.ok) {
        const error = await responseErrorDetails(
          response,
          "Your encrypted reply is saved, but its certification could not be finished yet.",
        );
        throw new HerdResponseError(error.message, response.status, error.code);
      }
      const body = await response.json() as PrivateResponseSubmissionBody;
      await verifyPrivateResponseSubmission(envelope, body);
      setInviteMetadata((current) => current ? {
        ...current,
        hasResponse: true,
        responseRevision: envelope.revision,
        responseEnvelope: body.responseEnvelope,
        responseCertificationStatus: "certified",
      } : current);
      setSelectedEvent((current) => current ? {
        ...current,
        hasResponse: true,
        responseRevision: envelope.revision,
        responseCertificationStatus: "certified",
      } : current);
      setEvents((current) => current.map((event) =>
        event.id === activeEvent.id
          ? {
              ...event,
              hasResponse: true,
              responseRevision: envelope.revision,
              responseCertificationStatus: "certified",
            }
          : event
      ));
      pendingReplySubmissionRef.current = null;
      setScreen("success");
    } catch (error) {
      setReplyError(
        error instanceof Error
          ? error.message
          : "Your encrypted reply is saved, but its certification could not be finished yet.",
      );
    } finally {
      replySubmissionInFlightRef.current = false;
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
          inert={conditionSheetOpen || releaseStatusOpen || eventDeletionOpen ? true : undefined}
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
                <Construction aria-hidden="true" />
                {AUTH_EXPERIENCE.releaseStatus.label}
              </button>
            </div>
            <div className="welcome-copy">
              {inviteToken ? <p className="eyebrow">You’re invited</p> : null}
              <h1 className={!inviteToken ? "welcome-headline" : undefined}>
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
                aria-label={AUTH_EXPERIENCE.welcome.phoneLabel}
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
                <div className="home-header-copy">
                  <h1>{HOME_EXPERIENCE.title}</h1>
                  <p aria-live="polite">
                    {eventsRefreshPending && lastEventsUpdatedAt === null
                      ? "Updating…"
                      : lastUpdatedLabel(lastEventsUpdatedAt, now)}
                  </p>
                </div>
                <div className="home-header-actions">
                  <button
                    className="profile-avatar"
                    aria-label="Account status"
                    onClick={() => {
                      setScreen("status");
                      void runAccountStatusChecks();
                    }}
                  >
                    <Activity aria-hidden="true" size={19} strokeWidth={1.8} />
                  </button>
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
              </div>
              {homeRefreshError ? <p className="inline-error home-refresh-error" role="alert">{homeRefreshError}</p> : null}
              {invitedEvents.length ? (
                <section
                  className="home-event-section"
                  aria-labelledby="home-invites-heading"
                >
                  <h2 id="home-invites-heading">{HOME_EXPERIENCE.invitesSectionTitle}</h2>
                  <div className="home-event-list">
                    {invitedEvents.map((event) => (
                      <EventCard key={event.id} event={event} now={now} onClick={() => void openEvent(event)} />
                    ))}
                  </div>
                </section>
              ) : null}
              <section
                className="home-event-section"
                aria-labelledby="home-hosted-heading"
              >
                <h2 id="home-hosted-heading">{HOME_EXPERIENCE.hostedSectionTitle}</h2>
                {hostedEvents.length ? (
                  <div className="home-event-list">
                    {hostedEvents.map((event) => (
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
              </section>
              {pastEvents.length ? (
                <section
                  className="home-event-section home-event-section-collapsible"
                  aria-labelledby="home-past-heading"
                >
                  <details className="home-event-disclosure">
                    <summary>
                      <span className="home-event-section-heading">
                        <h2 id="home-past-heading">{HOME_EXPERIENCE.pastSectionTitle}</h2>
                      </span>
                      <ChevronRight className="home-event-disclosure-chevron" size={19} strokeWidth={2.2} aria-hidden="true" />
                    </summary>
                    <div className="home-event-list">
                      {pastEvents.map((event) => (
                        <EventCard key={event.id} event={event} now={now} onClick={() => void openEvent(event)} />
                      ))}
                    </div>
                  </details>
                </section>
              ) : null}
              {unconfirmedEvents.length ? (
                <section
                  className="home-event-section home-event-section-collapsible"
                  aria-labelledby="home-unconfirmed-heading"
                >
                  <details className="home-event-disclosure">
                    <summary>
                      <span className="home-event-section-heading">
                        <h2 id="home-unconfirmed-heading">{HOME_EXPERIENCE.unconfirmedSectionTitle}</h2>
                        <span>{HOME_EXPERIENCE.unconfirmedSectionNote}</span>
                      </span>
                      <ChevronRight className="home-event-disclosure-chevron" size={19} strokeWidth={2.2} aria-hidden="true" />
                    </summary>
                    <div className="home-event-list">
                      {unconfirmedEvents.map((event) => (
                        <EventCard key={event.id} event={event} now={now} onClick={() => void openEvent(event)} />
                      ))}
                    </div>
                  </details>
                </section>
              ) : null}
            </div>
          </section>
        ) : null}

        {screen === "status" ? (
          <section className="screen-layout">
            <AppHeader
              title="Account status"
              headingId="account-status-heading"
              onBack={goBack}
              persistentAction
              action={(
                <button
                  className="circle-button"
                  aria-label="Run status checks"
                  disabled={statusCheckPending}
                  onClick={() => void runAccountStatusChecks()}
                >
                  <RefreshCw className={statusCheckPending ? "refresh-spinning" : undefined} aria-hidden="true" size={19} strokeWidth={1.8} />
                </button>
              )}
            />
            <div className="screen-scroll account-status-content">
              <div className={`account-status-summary account-status-${accountStatusNeedsAttention ? "attention" : "healthy"}`}>
                {accountStatusNeedsAttention
                  ? <CircleAlert aria-hidden="true" />
                  : <CheckCircle2 aria-hidden="true" />}
                <div>
                  <h2 id="account-status-heading">
                    {accountStatusNeedsAttention ? "Some checks need attention" : "Everything looks good"}
                  </h2>
                  <p>
                    {accountStatusNeedsAttention
                      ? "Open the checks below to see what may prevent sync or private replies."
                      : "Your account, event sync, and browser security checks passed."}
                  </p>
                  {statusCheckedAt ? <small>Checked {new Date(statusCheckedAt).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" })}</small> : null}
                </div>
              </div>

              <div className="account-status-section">
                <h3>Account</h3>
                <div className="account-status-card">
                  <AccountStatusRow
                    state={currentUser ? "healthy" : "attention"}
                    icon={<UserRound />}
                    title="Signed-in session"
                    detail={currentUser ? `Phone ending in ${phoneNumber.replace(/\D/g, "").slice(-4) || "••••"}` : "No active account session"}
                  />
                  <AccountStatusRow
                    state={activeInvitationCount ? "healthy" : "not-configured"}
                    icon={<Link2 />}
                    title="Invitation access"
                    detail={activeInvitationCount ? `${activeInvitationCount} active invitation ${activeInvitationCount === 1 ? "link" : "links"}` : "No active invitation links on this account"}
                  />
                </div>
              </div>

              <div className="account-status-section">
                <h3>Connections</h3>
                <div className="account-status-card">
                  <AccountStatusRow
                    state={homeRefreshError ? "attention" : "healthy"}
                    icon={<Network />}
                    title="Herd services"
                    detail={homeRefreshError || "Authenticated API access is working"}
                    value={typeof window === "undefined" ? undefined : window.location.host}
                  />
                  <AccountStatusRow
                    state={lastEventsUpdatedAt ? "healthy" : "attention"}
                    icon={<RefreshCw />}
                    title="Event sync"
                    detail={lastEventsUpdatedAt ? lastUpdatedLabel(lastEventsUpdatedAt, now) : "Events have not synced yet"}
                  />
                </div>
              </div>

              <div className="account-status-section">
                <h3>Private reply security</h3>
                <div className="account-status-card">
                  <AccountStatusRow
                    state={accountKeyStatus?.missing ? "attention" : accountKeyStatus?.available ? "healthy" : "not-configured"}
                    icon={<KeyRound />}
                    title={accountKeyStatus?.missing ? "Private replies unavailable on this device" : accountKeyStatus?.available ? "Private replies available" : "Private replies not set up yet"}
                    detail={accountKeyStatus?.missing
                      ? `This device can’t open private replies protected by ${accountKeyStatus.missing} existing ${accountKeyStatus.missing === 1 ? "key" : "keys"}. When you send a new reply, Herd can verify your phone number and switch private replies to this device.`
                      : accountKeyStatus?.available
                        ? `This device can open private replies protected by ${accountKeyStatus.available} account ${accountKeyStatus.available === 1 ? "key" : "keys"}`
                        : "Herd will set up this device when you send the first private reply"}
                  />
                </div>
              </div>

              <div className="account-status-section">
                <h3>Trust and verification</h3>
                <div className="account-status-card">
                  <AccountStatusRow
                    state={protectedEventCount ? "healthy" : "not-configured"}
                    icon={<ShieldCheck />}
                    title="Herd evaluator trust"
                    detail={protectedEventCount ? `${protectedEventCount} signed event ${protectedEventCount === 1 ? "policy" : "policies"} loaded` : "No encrypted-reply policies are active"}
                  />
                  <AccountStatusRow
                    state={verificationIssueCount ? "attention" : "healthy"}
                    icon={<CheckCircle2 />}
                    title="Result verification"
                    detail={verificationIssueCount ? `${verificationIssueCount} event ${verificationIssueCount === 1 ? "has" : "have"} an unverifiable result` : "No event verification failures detected"}
                  />
                </div>
              </div>

              <p className="account-status-footnote">Private keys never leave this browser and are not shown here. Only availability checks are displayed.</p>
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
            <AppHeader
              title=""
              headingId="profile-heading"
              onBack={goBack}
              persistentAction
              action={(
                <details className="profile-overflow">
                  <summary className="circle-button" aria-label="More profile actions">
                    <MoreHorizontal size={22} strokeWidth={2.2} aria-hidden="true" />
                  </summary>
                  <div className="profile-overflow-menu" role="menu">
                    <button
                      type="button"
                      role="menuitem"
                      className="profile-delete-action"
                      onClick={() => {
                        setAccountDeletionStage("confirm");
                        setAccountDeletionChallenge(null);
                        setAccountDeletionCode("");
                        setAccountDeletionError("");
                        setAccountDeletionOpen(true);
                      }}
                    >
                      <Trash2 size={17} aria-hidden="true" />
                      {PROFILE_EXPERIENCE.deleteAccountButton}
                    </button>
                  </div>
                </details>
              )}
            />
            <div className="screen-scroll profile-content">
              <div className="screen-page-heading">
                <div>
                  <h2 id="profile-heading">{PROFILE_EXPERIENCE.title}</h2>
                  <p className="profile-note">{PROFILE_EXPERIENCE.syncNote}</p>
                </div>
              </div>
              <div className="profile-fields-card">
                <label className="profile-field">
                  <span>{PROFILE_EXPERIENCE.nameLabel}</span>
                  <input
                    value={profileName}
                    onChange={(event) => {
                      setProfileName(event.target.value);
                      setProfileNotice("");
                    }}
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
                    onChange={(event) => {
                      setAddress(event.target.value);
                      setProfileNotice("");
                    }}
                    placeholder={PROFILE_EXPERIENCE.addressPlaceholder}
                    autoComplete="street-address"
                  />
                </label>
              </div>
              <div className="profile-account-actions" aria-label="Account actions">
                <button type="button" className="profile-inline-action" onClick={() => setLogoutConfirmationOpen(true)}>
                  <LogOut size={16} aria-hidden="true" />
                  {PROFILE_EXPERIENCE.logoutButton}
                </button>
              </div>
              {profileNotice ? <p className={profileNotice === PROFILE_EXPERIENCE.savedNotice ? "inline-success" : "inline-error"}>{profileNotice}</p> : null}
            </div>
            <div className="bottom-action profile-save-action">
              <button
                className="primary-button"
                disabled={!profileHasChanges || profilePending}
                onClick={() => void saveProfile()}
              >
                {profilePending ? "Saving…" : PROFILE_EXPERIENCE.saveButton}
              </button>
            </div>
          </section>
        ) : null}

        {screen === "event" && activeEvent ? (
          <section className="screen-layout">
            <AppHeader
              title={activeEvent.title || INVITATION_EXPERIENCE.untitledEvent}
              headingId="event-heading"
              onBack={goBack}
              persistentAction={activeEvent.role === "host"}
              action={activeEvent.role === "host" ? (
                <details ref={eventActionsRef} className="event-overflow">
                  <summary
                    className="circle-button"
                    aria-label={INVITATION_EXPERIENCE.eventActions.moreLabel}
                    data-testid="event-actions-menu"
                  >
                    <MoreHorizontal size={22} strokeWidth={2.2} aria-hidden="true" />
                  </summary>
                  <div className="event-overflow-menu" role="menu">
                    <button
                      type="button"
                      role="menuitem"
                      className="event-delete-action"
                      onClick={openEventDeletion}
                    >
                      <Trash2 size={17} aria-hidden="true" />
                      {INVITATION_EXPERIENCE.eventActions.deleteButton}
                    </button>
                  </div>
                </details>
              ) : <span className="header-countdown">{countdown}</span>}
            />
            <div className="screen-scroll event-detail-scroll">
              <section className="event-hero">
                <div className="event-hero-heading">
                  <span className={`status-pill ${activeEvent.hasResponse ? "status-responded" : ""}`}>
                    {eventStatusLabel(activeEvent)}
                  </span>
                  <h2 id="event-heading">{activeEvent.title || INVITATION_EXPERIENCE.untitledEvent}</h2>
                  {activeEvent.eventDescription ? <p className="event-description">{activeEvent.eventDescription}</p> : null}
                </div>
                <div className="event-meta-list">
                  <div><span aria-hidden="true"><Clock size={17} strokeWidth={1.8} /></span><p><strong>{activeEvent.eventDate ? formatEventDate(activeEvent.eventDate) : INVITATION_EXPERIENCE.dateNotSet}</strong></p></div>
                  <div><span aria-hidden="true"><MapPin size={16} strokeWidth={1.8} /></span><p><strong>{activeEvent.locationName || INVITATION_EXPERIENCE.locationNotSet}</strong><small>{activeEvent.locationAddress}</small></p></div>
                  <div><span aria-hidden="true"><Crown size={17} strokeWidth={1.8} /></span><p><strong>{INVITATION_EXPERIENCE.hostPrefix} {activeEvent.hostName.split(" ")[0] || activeEvent.hostName}</strong></p></div>
                  <div><span aria-hidden="true"><Hourglass size={17} strokeWidth={1.8} /></span><p><strong>{activeEvent.rsvpDeadline ? INVITATION_EXPERIENCE.replyByPrefix : INVITATION_EXPERIENCE.noReplyDeadline}</strong>{activeEvent.rsvpDeadline ? <small>{formatReplyDeadline(activeEvent.rsvpDeadline)}</small> : null}</p></div>
                </div>
                <div className="metric-row hero-metrics">
                  <Metric value={String(participantCount(activeEvent))} label={INVITATION_EXPERIENCE.metrics.invited} />
                  <Metric value={String(activeEvent.minimumParticipants)} label={INVITATION_EXPERIENCE.metrics.minimum} />
                  <Metric value={activeThirdMetric.value} label={activeThirdMetric.label} />
                </div>
              </section>

              {!(activeEvent.resolution?.status === "not_confirmed" && countdown === "Passed") ? <button className="attendee-entry" onClick={() => setScreen("attendees")}>
                <span className="attendee-entry-copy">
                  <strong>{participantCount(activeEvent)} {INVITATION_EXPERIENCE.attendeeEntry.peopleInvitedSuffix}</strong>
                  <span>{INVITATION_EXPERIENCE.attendeeEntry.action}</span>
                </span>
                <AvatarStack hostName={activeEvent.hostName} invitees={activeEvent.invitees} />
                <span className="chevron" aria-hidden="true">›</span>
              </button> : null}

              <section className="privacy-callout">
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

              {activeEvent.role !== "host" ? <section className="reply-section">
                <div className="section-heading">
                  <h3 id="reply-choice-label">{REPLY_EXPERIENCE.title}</h3>
                  <p>{REPLY_EXPERIENCE.privacyNote}</p>
                </div>

                {privateResponseState === "loading" ? (
                  <p className="edit-note" role="status">{REPLY_EXPERIENCE.openingSaved}</p>
                ) : null}
                {privateResponseState === "unreadable" && inviteMetadata?.hasResponse ? (
                  <p className="inline-error" role="status">
                    {REPLY_EXPERIENCE.unreadable}
                  </p>
                ) : null}
                {hasPendingResponseCertification ? (
                  <p className="edit-note" role="status">
                    Your encrypted reply is saved. Finish certification so every device can verify it.
                  </p>
                ) : null}

                {hasPendingResponseCertification && privateResponseState === "unreadable" ? (
                  <button
                    type="button"
                    className="primary-button"
                    disabled={authPending}
                    onClick={() => void retryStoredReplyCertification()}
                  >
                    {authPending ? "Finishing certification…" : "Finish saved reply certification"}
                  </button>
                ) : null}

                <div className="reply-choice-group" role="radiogroup" aria-labelledby="reply-choice-label">
                  <div
                    className={`reply-option reply-option-yes ${reply === "yes" ? "selected" : ""}`}
                    onClick={() => toggleReply("yes")}
                  >
                    <button
                      type="button"
                      className="reply-selection"
                      role="radio"
                      aria-checked={reply === "yes"}
                      aria-label={reply === "yes"
                        ? `${REPLY_EXPERIENCE.goingPrefix} ${minimum} ${REPLY_EXPERIENCE.goingSuffix}`
                        : REPLY_EXPERIENCE.goingCollapsedTitle}
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleReply("yes");
                      }}
                    >
                      <span className="selection-radio" aria-hidden="true" />
                    </button>
                    {reply === "yes" ? <strong className="reply-option-title">
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
                    </strong> : <span className="reply-option-copy">
                      <strong>{REPLY_EXPERIENCE.goingCollapsedTitle}</strong>
                      <span>{REPLY_EXPERIENCE.goingCollapsedBody}</span>
                    </span>}

                  {reply === "yes" ? <div className={`condition-builder ${conditionGroups.length ? "" : "condition-builder-empty"}`}>
                    {conditionGroups.map((group, groupIndex) => (
                      <div className="condition-row" key={groupIndex}>
                        <span className="condition-prefix">AND</span>
                        {group.map((personID, personIndex) => {
                          const displayName = invitedPeople.find((person) => person.id === personID)?.displayName || "Guest";
                          return (
                            <Fragment key={personID}>
                              {personIndex > 0 ? <span className="condition-operator">OR</span> : null}
                              <button
                                type="button"
                                className="condition-name-pill"
                                aria-label={`Remove ${displayName} from this condition`}
                                onClick={(event) => {
                                  event.stopPropagation();
                                  removeConditionPerson(groupIndex, personID);
                                }}
                              >
                                <span>{displayName}</span>
                                <span aria-hidden="true">×</span>
                              </button>
                            </Fragment>
                          );
                        })}
                        <button
                          type="button"
                          className="condition-or-button"
                          aria-label="Add an OR alternative"
                          onClick={(event) => {
                            event.stopPropagation();
                            setReply("yes");
                            openConditionSheet(event.currentTarget, groupIndex);
                          }}
                        ><span aria-hidden="true">+</span> OR</button>
                        <span className="condition-goes">goes</span>
                      </div>
                    ))}
                    <div className="condition-add-row">
                      <button
                        type="button"
                        className="dotted-condition"
                        aria-label={conditionGroups.length ? "Add another required person condition" : "Add a required person condition"}
                        onClick={(event) => {
                          event.stopPropagation();
                          setReply("yes");
                          openConditionSheet(event.currentTarget);
                        }}
                      >
                        <span>+</span> {REPLY_EXPERIENCE.addCondition}
                      </button>
                    </div>
                  </div> : null}
                  </div>

                <button
                  className={`reply-option reply-option-no ${reply === "no" ? "selected" : ""}`}
                  role="radio"
                  aria-checked={reply === "no"}
                  onClick={() => toggleReply("no")}
                >
                  <span className="selection-radio" aria-hidden="true" />
                  <span className="reply-option-copy">
                    <strong>{REPLY_EXPERIENCE.cantCommitTitle}</strong>
                    <span>{REPLY_EXPERIENCE.cantCommitBody}</span>
                  </span>
                </button>
                </div>

                <div className="response-submit">
                  {replyError ? <p className="inline-error" role="alert">{replyError}</p> : null}
                  <button
                    className="primary-button"
                    disabled={!replyHasUnsavedChanges || authPending || privateResponseState === "loading"}
                    onClick={() => void (
                      hasPendingResponseCertification &&
                      currentReplyFingerprint === savedReplyFingerprint
                        ? retryStoredReplyCertification()
                        : submitReply()
                    )}
                  >
                    {authPending
                      ? REPLY_EXPERIENCE.submittingButton
                      : !reply
                        ? REPLY_EXPERIENCE.chooseButton
                        : hasPendingResponseCertification &&
                            currentReplyFingerprint === savedReplyFingerprint
                          ? "Finish saved reply certification"
                        : activeEvent.hasResponse
                          ? replyHasUnsavedChanges
                            ? REPLY_EXPERIENCE.updateButton
                            : REPLY_EXPERIENCE.sentButton
                          : REPLY_EXPERIENCE.submitButton}
                  </button>
                  <button
                    ref={replyPreviewTriggerRef}
                    type="button"
                    className="secondary-button response-preview-button"
                    onClick={openReplyPreview}
                  >
                    {REPLY_EXPERIENCE.previewButton}
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
                <p className="attendees-disclosure">{ATTENDEES_EXPERIENCE.statusDisclosure}</p>
              </div>
              <p className="section-label">{peopleCountLabel(invitedPeople.length + 1)}</p>
              <div className="people-list">
                <div className="person-row person-row-host">
                  <span
                    className="attendee-avatar-wrap"
                    role="img"
                    aria-label={`${activeEvent?.hostName || ATTENDEES_EXPERIENCE.hostLabel}, ${ATTENDEES_EXPERIENCE.hostLabel.toLowerCase()}`}
                  >
                    <span className="avatar avatar-tone-1" aria-hidden="true">
                      {personInitials(activeEvent?.hostName || ATTENDEES_EXPERIENCE.hostLabel)}
                    </span>
                    <span className="host-crown" aria-hidden="true"><Crown size={10} /></span>
                  </span>
                  <strong className="person-name">{activeEvent?.hostName || ATTENDEES_EXPERIENCE.hostLabel}</strong>
                  <span className="person-status">Going</span>
                </div>
                {invitedPeople.map((person, index) => {
                  const attendanceStatus = attendeeStatusLabel(activeEvent, person);
                  const deliveryGuest = activeEvent?.role === "host"
                    ? activeEvent.invitationDelivery?.guests.find((guest) => guest.inviteeId === person.id)
                    : undefined;
                  return (
                    <div className="person-row" key={person.id}>
                      <span className={`avatar ${initialsTone(index + 1)}`}>{personInitials(person.displayName)}</span>
                      <strong className="person-name">{person.displayName}</strong>
                      {attendanceStatus ? <span className="person-status">{attendanceStatus}</span> : null}
                      {deliveryGuest ? <DeliveryStatusButton guest={deliveryGuest} /> : null}
                    </div>
                  );
                })}
              </div>
              {canAddAttendees ? (
                <button
                  type="button"
                  className="add-attendees-button"
                  onClick={openGuestAddition}
                  data-testid="add-event-attendees"
                >
                  <span aria-hidden="true"><Plus size={20} strokeWidth={2.2} /></span>
                  <strong>{ATTENDEES_EXPERIENCE.addGuests.button}</strong>
                </button>
              ) : null}
            </div>
          </section>
        ) : null}

        {screen === "add-attendees" ? (
          <section className="screen-layout">
            <AppHeader
              title={ATTENDEES_EXPERIENCE.addGuests.navigationTitle}
              headingId="add-attendees-heading"
              onBack={closeGuestAddition}
            />
            <div className="screen-scroll add-attendees-screen">
              <div className="screen-page-heading">
                <h2 id="add-attendees-heading">{ATTENDEES_EXPERIENCE.addGuests.title}</h2>
                <p>{ATTENDEES_EXPERIENCE.addGuests.body}</p>
              </div>
              <div className="guest-draft-list">
                {guestDrafts.map((guest, index) => (
                  <section className="guest-draft-card" key={guest.id}>
                    <div className="guest-draft-heading">
                      <strong>Guest {index + 1}</strong>
                      {guestDrafts.length > 1 ? (
                        <button
                          type="button"
                          aria-label={`${ATTENDEES_EXPERIENCE.addGuests.removeButton} ${index + 1}`}
                          onClick={() => removeGuestDraft(guest.id)}
                        >
                          <X size={18} aria-hidden="true" />
                        </button>
                      ) : null}
                    </div>
                    <label className="guest-draft-field">
                      <span>{ATTENDEES_EXPERIENCE.addGuests.nameLabel}</span>
                      <input
                        value={guest.displayName}
                        onChange={(event) => updateGuestDraft(guest.id, "displayName", event.target.value)}
                        placeholder={ATTENDEES_EXPERIENCE.addGuests.namePlaceholder}
                        autoComplete="name"
                        maxLength={80}
                        autoFocus={index === 0}
                      />
                    </label>
                    <label className="guest-draft-field">
                      <span>{ATTENDEES_EXPERIENCE.addGuests.phoneLabel}</span>
                      <input
                        type="tel"
                        inputMode="tel"
                        value={formatPhoneNumber(guest.phoneNumber)}
                        onChange={(event) => {
                          const value = event.target.value;
                          const digits = value.replace(/\D/g, "").slice(0, 15);
                          updateGuestDraft(
                            guest.id,
                            "phoneNumber",
                            value.trimStart().startsWith("+") ? `+${digits}` : digits,
                          );
                        }}
                        placeholder={ATTENDEES_EXPERIENCE.addGuests.phonePlaceholder}
                        autoComplete="tel"
                      />
                    </label>
                  </section>
                ))}
              </div>
              {activeEvent && activeEvent.invitees.length + guestDrafts.length < 19 ? (
                <button type="button" className="add-another-guest-button" onClick={addGuestDraft}>
                  <Plus size={18} aria-hidden="true" />
                  {ATTENDEES_EXPERIENCE.addGuests.addAnotherButton}
                </button>
              ) : null}
              {guestAdditionError ? <p className="inline-error" role="alert">{guestAdditionError}</p> : null}
              <button
                type="button"
                className="primary-button add-guests-submit"
                disabled={guestAdditionPending || guestDrafts.length === 0}
                onClick={() => void addEventGuests()}
              >
                {guestAdditionPending
                  ? ATTENDEES_EXPERIENCE.addGuests.submittingButton
                  : guestDrafts.length === 1
                    ? ATTENDEES_EXPERIENCE.addGuests.submitSingleButton
                    : ATTENDEES_EXPERIENCE.addGuests.submitMultipleTemplate.replace(
                        "{count}",
                        String(guestDrafts.length),
                      )}
              </button>
            </div>
          </section>
        ) : null}

        {screen === "privacy" ? (
          <section className="screen-layout">
            <AppHeader title={PRIVACY_EXPERIENCE.navigationTitle} headingId="privacy-heading" onBack={goBack} />
            <div className="screen-scroll privacy-screen">
              <section className="privacy-hero">
                <p className="eyebrow">{PRIVACY_EXPERIENCE.eyebrow}</p>
                <h2 id="privacy-heading" ref={privacyHeadingRef} tabIndex={-1}>{PRIVACY_EXPERIENCE.title}</h2>
                <p>{PRIVACY_EXPERIENCE.intro}</p>
              </section>

              <section className="proof-flow" aria-labelledby="proof-flow-heading">
                <h3 id="proof-flow-heading">{PRIVACY_EXPERIENCE.flowTitle}</h3>
                <div className="privacy-flow-diagram">
                  {PRIVACY_EXPERIENCE.flowSteps.map((step, index) => (
                    <div className="privacy-flow-item" key={step.title}>
                      <article className="privacy-flow-step">
                        <span className="privacy-flow-icon"><PrivacyFlowIcon index={index} /></span>
                        <div>
                          <strong>{step.title}</strong>
                          <p>{step.body}</p>
                        </div>
                      </article>
                      {index < PRIVACY_EXPERIENCE.flowSteps.length - 1 ? (
                        <div className="privacy-flow-connector" aria-hidden="true">
                          <ArrowDown />
                        </div>
                      ) : null}
                    </div>
                  ))}
                </div>
                <div className="privacy-flow-boundary">
                  <EyeOff aria-hidden="true" />
                  <strong>{PRIVACY_EXPERIENCE.flowPrivacyLabel}</strong>
                </div>
              </section>

              <section className="privacy-architecture">
                <p className="eyebrow">{PRIVACY_EXPERIENCE.answersEyebrow}</p>
                <h3>{PRIVACY_EXPERIENCE.answersTitle}</h3>
                <div className="accordion-stack">
                  {PRIVACY_EXPERIENCE.sections.map((section, sectionIndex) => (
                    <details open={sectionIndex === 0} key={section.title}>
                      <summary>{section.title} <span className="accordion-icon" aria-hidden="true">+</span></summary>
                      <div className="accordion-copy">
                        {section.paragraphs.map((paragraph, paragraphIndex) => (
                          <p className={paragraphIndex === 0 ? "accordion-lead" : undefined} key={paragraph}>{paragraph}</p>
                        ))}
                        {section.showsVerificationLinks ? (
                          <div className="proof-links">
                            <a href={PRIVACY_EXPERIENCE.sourceURL} target="_blank" rel="noreferrer">
                              <span><CheckCircle2 aria-hidden="true" /> View public source</span>
                              <span aria-hidden="true">↗</span>
                            </a>
                            <a href={PRIVACY_EXPERIENCE.releaseEvidenceURL} target="_blank" rel="noreferrer">
                              <span><ShieldCheck aria-hidden="true" /> Inspect signed release evidence</span>
                              <span aria-hidden="true">↗</span>
                            </a>
                          </div>
                        ) : null}
                        {section.showsPolicyIdentifiers ? (
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
            <div className="success-content">
              <div className="success-burst" aria-hidden="true">
                <i></i><i></i><i></i><i></i><i></i><i></i>
                <span>✓</span>
              </div>
              <h1>{SUCCESS_EXPERIENCE.title}</h1>
              <p>{SUCCESS_EXPERIENCE.body}</p>
              <div className="success-reply-preview" aria-label="How your reply will appear">
                <h2>{SUCCESS_EXPERIENCE.replyPreviewTitle}</h2>
                <ReplyVisibilityPreview
                  displayName={replyPreviewName}
                  status={reply === "yes" ? "Going" : REPLY_EXPERIENCE.cantCommitTitle}
                />
              </div>
            </div>
            <div className="bottom-action">
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

        {eventDeletionOpen ? (
          <div className="dialog-backdrop" onClick={closeEventDeletion}>
            <section
              className="event-deletion-dialog"
              role="alertdialog"
              aria-modal="true"
              aria-labelledby="event-deletion-title"
              aria-describedby="event-deletion-body"
              onClick={(event) => event.stopPropagation()}
            >
              <h2 id="event-deletion-title">
                {INVITATION_EXPERIENCE.eventActions.deletionTitle}
              </h2>
              <p id="event-deletion-body">
                {INVITATION_EXPERIENCE.eventActions.deletionBody}
              </p>
              {eventDeletionError ? (
                <p className="inline-error" role="alert">{eventDeletionError}</p>
              ) : null}
              <div className="dialog-actions">
                <button
                  className="secondary-button"
                  disabled={eventDeletionPending}
                  onClick={closeEventDeletion}
                >
                  {INVITATION_EXPERIENCE.eventActions.cancelButton}
                </button>
                <button
                  className="danger-button"
                  disabled={eventDeletionPending}
                  data-testid="confirm-delete-hosted-event"
                  onClick={() => void deleteHostedEvent()}
                >
                  {eventDeletionPending
                    ? INVITATION_EXPERIENCE.eventActions.deletingButton
                    : INVITATION_EXPERIENCE.eventActions.confirmButton}
                </button>
              </div>
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

        {replyPreviewOpen ? (
          <div className="sheet-backdrop" onClick={closeReplyPreview}>
            <section
              className="condition-sheet reply-preview-sheet"
              ref={replyPreviewSheetRef}
              role="dialog"
              aria-modal="true"
              aria-labelledby="reply-preview-title"
              onClick={(event) => event.stopPropagation()}
              style={{ transform: replyPreviewDragY ? `translateY(${replyPreviewDragY}px)` : undefined }}
            >
              <button
                className="sheet-handle"
                aria-label="Dismiss reply preview"
                onClick={closeReplyPreview}
                onPointerDown={handleReplyPreviewPointerDown}
                onPointerMove={handleReplyPreviewPointerMove}
                onPointerUp={handleReplyPreviewPointerUp}
                onPointerCancel={handleReplyPreviewPointerUp}
              >
                <span aria-hidden="true"></span>
              </button>
              <div className="sheet-heading">
                <h2 id="reply-preview-title">{REPLY_EXPERIENCE.previewTitle}</h2>
              </div>
              <ReplyVisibilityPreview
                displayName={replyPreviewName}
                status={reply === "yes"
                  ? "Going"
                  : reply === "no"
                    ? REPLY_EXPERIENCE.cantCommitTitle
                    : noReplyHistoryLabel(
                        replyPreviewNoResponseHistory.missed,
                        replyPreviewNoResponseHistory.total,
                      )}
                confirmedBody={reply === null ? REPLY_EXPERIENCE.noReplyPreviewBody : undefined}
              />
              <button
                className="primary-button"
                data-testid="reply-preview-dismiss"
                onClick={closeReplyPreview}
              >
                {REPLY_EXPERIENCE.previewDismissButton}
              </button>
            </section>
          </div>
        ) : null}

        {deviceSwitchOpen ? (
          <div className="dialog-backdrop" onClick={closeDeviceSwitch}>
            <section
              className="device-switch-dialog"
              role="dialog"
              aria-modal="true"
              aria-labelledby="device-switch-title"
              onClick={(event) => event.stopPropagation()}
            >
              <h2 id="device-switch-title">{REPLY_EXPERIENCE.deviceSwitch.title}</h2>
              {deviceSwitchStage === "verify" ? (
                <>
                  <p>
                    {REPLY_EXPERIENCE.deviceSwitch.verificationPrefix}{" "}
                    {maskedPhoneNumber(deviceSwitchChallenge?.phoneNumber || currentUser?.phoneNumber || "")}{" "}
                    {REPLY_EXPERIENCE.deviceSwitch.verificationSuffix}
                  </p>
                  <label className="device-switch-code-field">
                    <span>Verification code</span>
                    <input
                      value={deviceSwitchCode}
                      onChange={(event) => {
                        setDeviceSwitchCode(event.target.value.replace(/\D/g, "").slice(0, OTP_LENGTH));
                        setDeviceSwitchError("");
                      }}
                      placeholder="0000"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      aria-invalid={Boolean(deviceSwitchError)}
                      autoFocus
                    />
                  </label>
                </>
              ) : (
                <p>
                  {deviceSwitchStage === "requesting"
                    ? REPLY_EXPERIENCE.deviceSwitch.requestingCode
                    : deviceSwitchStage === "switching"
                      ? REPLY_EXPERIENCE.deviceSwitch.verifiedBody
                      : inviteMetadata?.hasResponse
                        ? REPLY_EXPERIENCE.deviceSwitch.replaceBody
                        : REPLY_EXPERIENCE.deviceSwitch.newReplyBody}
                </p>
              )}
              {deviceSwitchError ? <p className="inline-error" role="alert">{deviceSwitchError}</p> : null}
              <div className="dialog-actions">
                <button
                  className="secondary-button"
                  disabled={deviceSwitchPending || authPending}
                  onClick={closeDeviceSwitch}
                >
                  {REPLY_EXPERIENCE.deviceSwitch.cancelButton}
                </button>
                <button
                  className="danger-button"
                  disabled={
                    deviceSwitchPending ||
                    authPending ||
                    deviceSwitchStage === "requesting" ||
                    deviceSwitchStage === "switching" ||
                    (deviceSwitchStage === "verify" && deviceSwitchCode.length !== OTP_LENGTH)
                  }
                  onClick={() => void (
                    deviceSwitchStage === "verify"
                      ? verifyDeviceSwitchCode()
                      : beginDeviceSwitchVerification()
                  )}
                >
                  {deviceSwitchStage === "verify"
                    ? deviceSwitchPending
                      ? REPLY_EXPERIENCE.deviceSwitch.verifyingButton
                      : REPLY_EXPERIENCE.deviceSwitch.verifyButton
                    : deviceSwitchStage === "switching" || authPending
                      ? REPLY_EXPERIENCE.deviceSwitch.switchingButton
                      : REPLY_EXPERIENCE.deviceSwitch.confirmButton}
                </button>
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
