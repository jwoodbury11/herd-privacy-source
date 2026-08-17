export type RequiredGroup = { id: string; memberIDs: string[] };

export type PrivateResponse = {
  inviteeId: string;
  response: "going" | "cant_commit";
  minimumParticipants: number | null;
  requiredGroups: RequiredGroup[];
};

export type PrivateEventPolicy = {
  eventId: string;
  hostMemberId?: string;
  inviteeIds: string[];
  minimumParticipants: number;
  requiredGroups?: RequiredGroup[];
};

export function resolvePrivateEvent(
  policy: PrivateEventPolicy,
  responses: PrivateResponse[],
):
  | { eventId: string; status: "not_confirmed" }
  | { eventId: string; status: "confirmed"; attendingMemberIds: string[] };
