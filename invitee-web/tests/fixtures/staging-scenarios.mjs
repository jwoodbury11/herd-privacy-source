const FICTIONAL_PHONE_PREFIX = "+120255501";

function decimal(value, width) {
  return String(value).padStart(width, "0");
}

function eventId(participantCount) {
  return `a0000000-0000-4000-8000-${decimal(participantCount, 12)}`;
}

function inviteeId(participantCount, index) {
  return `b${decimal(participantCount, 2)}00000-${decimal(index, 4)}-4000-8000-${decimal(
    participantCount * 100 + index,
    12,
  )}`;
}

/**
 * Test-only identities for isolated staging/preview environments.
 *
 * These use NANPA's reserved fictional 202-555-0100 through -0199 range and
 * are never imported by product code or accepted by production authentication.
 */
export function stagingScenario(participantCount, now = new Date()) {
  if (![5, 10, 20].includes(participantCount)) {
    throw new TypeError("Staging scenarios support exactly 5, 10, or 20 participants.");
  }
  const inviteeCount = participantCount - 1;
  const eventDate = new Date(now.getTime() + 14 * 86_400_000);
  const endDate = new Date(eventDate.getTime() + 3 * 3_600_000);
  const rsvpDeadline = new Date(eventDate.getTime() - 2 * 86_400_000);
  const invitees = Array.from({ length: inviteeCount }, (_, offset) => {
    const index = offset + 1;
    return {
      id: inviteeId(participantCount, index),
      displayName: `Scenario ${participantCount} Guest ${index}`,
      phoneNumber: `${FICTIONAL_PHONE_PREFIX}${decimal(offset, 2)}`,
    };
  });
  return {
    participantCount,
    accounts: [
      {
        role: "host",
        displayName: `Scenario ${participantCount} Host`,
        phoneNumber: "+12025550199",
      },
      ...invitees.map(({ id, displayName, phoneNumber }) => ({
        id,
        role: "invitee",
        displayName,
        phoneNumber,
      })),
    ],
    event: {
      id: eventId(participantCount),
      title: `${participantCount}-person encrypted-response scenario`,
      eventDate: eventDate.toISOString(),
      endDate: endDate.toISOString(),
      hostName: `Scenario ${participantCount} Host`,
      locationName: "Isolated staging",
      locationAddress: "Fictional test environment",
      invitees,
      minimumParticipants: participantCount,
      requiredGroups: [],
      rsvpDeadline: rsvpDeadline.toISOString(),
      eventDescription: "Test-only encrypted-response capacity scenario.",
      createdAt: now.toISOString(),
      invitationsSent: true,
    },
  };
}

export const launchStagingScenarios = Object.freeze(
  [5, 10, 20].map((participantCount) => stagingScenario(participantCount)),
);
