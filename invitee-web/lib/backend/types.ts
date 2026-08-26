import type {
  PrivateResponsePolicyV1,
  StoredPrivateResponseEnvelopeV1,
} from "@/lib/privacy/protocol";
import type { InvitationDeliverySummary } from "./invitation-delivery";
import type { EventImageID } from "@/lib/event-images";

export type HerdUser = {
  id: string;
  phoneNumber: string;
  name: string;
  address: string;
  accountKeyEpochId?: string;
  accountKeyCommitment?: string | null;
};

export type CanonicalInvitee = {
  id: string;
  displayName: string;
  phoneNumber: string;
};

export type CanonicalRequiredGroup = {
  id: string;
  memberIDs: string[];
};

export type CanonicalEvent = {
  id: string;
  title: string;
  eventDate: string | null;
  endDate: string | null;
  hostName: string;
  locationName: string;
  locationAddress: string;
  invitees: CanonicalInvitee[];
  minimumParticipants: number;
  allowsAttendeesToAddGuests: boolean;
  requiredGroups: CanonicalRequiredGroup[];
  rsvpDeadline: string | null;
  eventDescription: string;
  eventImageID: EventImageID;
  createdAt: string;
  invitationsSent: boolean;
  privateResponsePolicy: PrivateResponsePolicyV1 | null;
  invitationDelivery: InvitationDeliverySummary | null;
};

export type PublicInvitee = {
  id: string;
  displayName: string;
  hasResponded?: boolean;
  responseHistory?: {
    missedConfirmedEvents: number;
    totalConfirmedEvents: number;
  };
};

export type PublicEvent = Omit<CanonicalEvent, "invitees" | "invitationDelivery"> & {
  invitees: PublicInvitee[];
};

export type AccountKeyEpoch = {
  id: string;
  userId: string;
  epochNumber: number;
  keyCommitment: string | null;
  createdAt: string;
  supersededAt: string | null;
};

export type PrivateResponseEnvelope = StoredPrivateResponseEnvelopeV1;

export type EvaluationResultAttestation = {
  protocolVersion: 1;
  signingKeyId: string;
  evaluatedAt: string;
  canonicalDocument: string;
  signature: string;
};

export type EventResolution =
  | { status: "pending"; retrying?: true; relayNeeded?: true }
  | { status: "verification_unavailable" }
  | {
      status: "confirmed";
      attendingMemberIds?: string[];
      attendanceRevealed: boolean;
      guestStates?: Array<{
        memberId: string;
        status: "going" | "cant_commit" | "no_response";
        missedDeadline: boolean;
      }>;
      resolvedAt: string;
      attestation?: EvaluationResultAttestation;
    }
  | {
      status: "not_confirmed";
      resolvedAt: string;
      attestation?: EvaluationResultAttestation;
    };

export type AuthenticatedSession = {
  sessionId: string;
  tokenHash: string;
  authMode: "twilio" | "test";
  createdAt: string;
  expiresAt: string;
  accountKeyEpochId: string;
  accountKeyCommitment: string | null;
  user: HerdUser;
};

export type InviteAccess = {
  inviteeId: string;
  eventId: string;
  displayName: string;
  phoneNumber: string;
  phoneHash: string;
  hostUserId: string;
};
