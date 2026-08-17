function requireIdentifier(value, field) {
  if (typeof value !== "string" || !value || value.length > 160) {
    throw new TypeError(`${field} is invalid.`);
  }
  return value;
}

function requireInteger(value, field, minimum, maximum) {
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new TypeError(`${field} must be an integer from ${minimum} to ${maximum}.`);
  }
  return value;
}

function normalizeGroups(value, field, allowedMembers, excludedMember = null) {
  if (!Array.isArray(value) || value.length > allowedMembers.size) {
    throw new TypeError(`${field} is invalid.`);
  }
  const seenMembers = new Set();
  const seenGroups = new Set();
  return value.map((group, groupIndex) => {
    if (!group || typeof group !== "object" || Array.isArray(group)) {
      throw new TypeError(`${field}[${groupIndex}] is invalid.`);
    }
    const id = requireIdentifier(group.id, `${field}[${groupIndex}].id`);
    if (seenGroups.has(id)) throw new TypeError(`${field} contains a duplicate group.`);
    seenGroups.add(id);
    if (!Array.isArray(group.memberIDs) || group.memberIDs.length === 0) {
      throw new TypeError(`${field}[${groupIndex}] has no members.`);
    }
    const memberIDs = group.memberIDs.map((member, memberIndex) => {
      const memberID = requireIdentifier(
        member,
        `${field}[${groupIndex}].memberIDs[${memberIndex}]`,
      );
      if (
        memberID === excludedMember ||
        !allowedMembers.has(memberID) ||
        seenMembers.has(memberID)
      ) {
        throw new TypeError(`${field} contains an invalid or repeated member.`);
      }
      seenMembers.add(memberID);
      return memberID;
    });
    return { id, memberIDs };
  });
}

function groupsSatisfied(groups, attending) {
  return groups.every((group) => group.memberIDs.some((memberID) => attending.has(memberID)));
}

/**
 * Resolve Herd's deterministic greatest-fixed-point attendance rule.
 *
 * On failure this intentionally returns no guest-level information. On success
 * it returns only the final attendance list in frozen policy order.
 */
export function resolvePrivateEvent(policyInput, responsesInput) {
  if (!policyInput || typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new TypeError("policy is invalid.");
  }
  const eventId = requireIdentifier(policyInput.eventId, "policy.eventId");
  const hostMemberId = requireIdentifier(
    policyInput.hostMemberId ?? "host",
    "policy.hostMemberId",
  );
  if (!Array.isArray(policyInput.inviteeIds) || policyInput.inviteeIds.length > 19) {
    throw new TypeError("policy.inviteeIds is invalid.");
  }
  const inviteeIds = policyInput.inviteeIds.map((value, index) =>
    requireIdentifier(value, `policy.inviteeIds[${index}]`),
  );
  if (new Set(inviteeIds).size !== inviteeIds.length || inviteeIds.includes(hostMemberId)) {
    throw new TypeError("policy member IDs must be unique.");
  }
  const inviteeSet = new Set(inviteeIds);
  const maximumParticipants = inviteeIds.length + 1;
  const hostMinimumParticipants = requireInteger(
    policyInput.minimumParticipants,
    "policy.minimumParticipants",
    2,
    maximumParticipants,
  );
  const hostRequiredGroups = normalizeGroups(
    policyInput.requiredGroups ?? [],
    "policy.requiredGroups",
    inviteeSet,
  );

  if (!Array.isArray(responsesInput) || responsesInput.length > inviteeIds.length) {
    throw new TypeError("responses are invalid.");
  }
  const responses = new Map();
  for (const [index, value] of responsesInput.entries()) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      throw new TypeError(`responses[${index}] is invalid.`);
    }
    const inviteeId = requireIdentifier(value.inviteeId, `responses[${index}].inviteeId`);
    if (!inviteeSet.has(inviteeId) || responses.has(inviteeId)) {
      throw new TypeError("responses contain an unknown or duplicate invitee.");
    }
    if (value.response !== "going" && value.response !== "cant_commit") {
      throw new TypeError(`responses[${index}].response is invalid.`);
    }
    const going = value.response === "going";
    if (!going && value.minimumParticipants !== null) {
      throw new TypeError("A cant_commit response must use a null minimum.");
    }
    const minimumParticipants = going
      ? requireInteger(
          value.minimumParticipants,
          `responses[${index}].minimumParticipants`,
          hostMinimumParticipants,
          maximumParticipants,
        )
      : null;
    const requiredGroups = normalizeGroups(
      value.requiredGroups ?? [],
      `responses[${index}].requiredGroups`,
      inviteeSet,
      inviteeId,
    );
    if (!going && requiredGroups.length > 0) {
      throw new TypeError("A non-attending response cannot contain conditions.");
    }
    responses.set(inviteeId, {
      inviteeId,
      response: value.response,
      minimumParticipants,
      requiredGroups,
    });
  }

  let candidates = new Set([
    hostMemberId,
    ...inviteeIds.filter((inviteeId) => responses.get(inviteeId)?.response === "going"),
  ]);
  for (let iteration = 0; iteration <= inviteeIds.length; iteration += 1) {
    const next = new Set([hostMemberId]);
    for (const inviteeId of inviteeIds) {
      const response = responses.get(inviteeId);
      if (
        response?.response === "going" &&
        candidates.has(inviteeId) &&
        candidates.size >= response.minimumParticipants &&
        groupsSatisfied(response.requiredGroups, candidates)
      ) {
        next.add(inviteeId);
      }
    }
    if (
      next.size === candidates.size &&
      [...next].every((memberID) => candidates.has(memberID))
    ) {
      candidates = next;
      break;
    }
    candidates = next;
  }

  if (
    candidates.size < hostMinimumParticipants ||
    !groupsSatisfied(hostRequiredGroups, candidates)
  ) {
    return { eventId, status: "not_confirmed" };
  }

  return {
    eventId,
    status: "confirmed",
    attendingMemberIds: [
      hostMemberId,
      ...inviteeIds.filter((inviteeId) => candidates.has(inviteeId)),
    ],
  };
}
