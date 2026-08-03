import assert from "node:assert/strict";
import test from "node:test";
import { resolvePrivateEvent } from "../../privacy-evaluator/src/fixed-point.mjs";

const TOTAL_PEOPLE = [5, 10, 20];
const DEADLINE = 2_000_000_000_000;
const FORBIDDEN_HOST_FIELDS = [
  "account",
  "inviteToken",
  "minimumParticipants",
  "phone",
  "requiredGroups",
  "response",
  "revision",
];

function makePopulation(totalPeople) {
  const eventId = `event-${totalPeople}`;
  const host = { id: `host-${totalPeople}`, role: "host" };
  const invitees = Array.from({ length: totalPeople - 1 }, (_, index) => ({
    id: `guest-${totalPeople}-${index + 1}`,
    role: "invitee",
  }));
  const accounts = [host, ...invitees];
  const invitations = invitees.map((account, index) => ({
    id: `invite-${totalPeople}-${index + 1}`,
    eventId,
    accountId: account.id,
  }));
  return { eventId, host, invitees, accounts, invitations };
}

function responseForBit(inviteeId, going) {
  return {
    inviteeId,
    response: going ? "going" : "cant_commit",
    minimumParticipants: going ? 2 : null,
    requiredGroups: [],
  };
}

function revisionHistory(inviteeIds, mask, mode) {
  return inviteeIds.flatMap((inviteeId, index) => {
    const desired = responseForBit(inviteeId, Boolean(mask & (1 << index)));
    const opposite = responseForBit(inviteeId, desired.response !== "going");
    if (mode === "latest-on-time-wins") {
      return [
        { ...opposite, revision: 1, submittedAt: DEADLINE - 2_000 },
        { ...desired, revision: 2, submittedAt: DEADLINE - 1_000 },
      ];
    }
    return [
      { ...desired, revision: 1, submittedAt: DEADLINE - 1_000 },
      { ...opposite, revision: 2, submittedAt: DEADLINE + 1_000 },
    ];
  });
}

function selectLatestAtDeadline(history, deadline) {
  const selected = new Map();
  for (const candidate of history) {
    if (candidate.submittedAt > deadline) continue;
    const previous = selected.get(candidate.inviteeId);
    if (!previous || candidate.revision > previous.revision) {
      selected.set(candidate.inviteeId, candidate);
    }
  }
  return [...selected.values()].map((candidate) => ({
    inviteeId: candidate.inviteeId,
    response: candidate.response,
    minimumParticipants: candidate.minimumParticipants,
    requiredGroups: candidate.requiredGroups,
  }));
}

function groupsSatisfied(groups, attending) {
  return groups.every((group) =>
    group.memberIDs.some((memberId) => attending.has(memberId)),
  );
}

function expectedUnconditionalProjection(policy, responses) {
  const going = new Set(
    responses
      .filter((response) => response.response === "going")
      .map((response) => response.inviteeId),
  );
  const attendingCount = going.size + 1;
  if (
    attendingCount < policy.minimumParticipants ||
    !groupsSatisfied(policy.requiredGroups, going)
  ) {
    return { eventId: policy.eventId, status: "not_confirmed" };
  }
  return {
    eventId: policy.eventId,
    status: "confirmed",
    attendingMemberIds: [
      policy.hostMemberId,
      ...policy.inviteeIds.filter((inviteeId) => going.has(inviteeId)),
    ],
  };
}

function assertPrivacySafeHostProjection(projection) {
  const allowedKeys = projection.status === "confirmed"
    ? ["attendingMemberIds", "eventId", "status"]
    : ["eventId", "status"];
  assert.deepEqual(Object.keys(projection).sort(), allowedKeys);
  const serialized = JSON.stringify(projection);
  for (const forbidden of FORBIDDEN_HOST_FIELDS) {
    assert.equal(serialized.includes(`\"${forbidden}\"`), false);
  }
}

function referenceResolve(policy, responses) {
  const responseByInvitee = new Map(
    responses.map((response) => [response.inviteeId, response]),
  );
  let candidates = new Set([
    policy.hostMemberId,
    ...policy.inviteeIds.filter(
      (inviteeId) => responseByInvitee.get(inviteeId)?.response === "going",
    ),
  ]);
  for (let iteration = 0; iteration <= policy.inviteeIds.length; iteration += 1) {
    const next = new Set([policy.hostMemberId]);
    for (const inviteeId of policy.inviteeIds) {
      const response = responseByInvitee.get(inviteeId);
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
      [...next].every((memberId) => candidates.has(memberId))
    ) {
      candidates = next;
      break;
    }
    candidates = next;
  }
  if (
    candidates.size < policy.minimumParticipants ||
    !groupsSatisfied(policy.requiredGroups, candidates)
  ) {
    return { eventId: policy.eventId, status: "not_confirmed" };
  }
  return {
    eventId: policy.eventId,
    status: "confirmed",
    attendingMemberIds: [
      policy.hostMemberId,
      ...policy.inviteeIds.filter((inviteeId) => candidates.has(inviteeId)),
    ],
  };
}

test("every yes/no reply mask at 5, 10, and 20 people preserves revisions, deadlines, minima, AND-of-OR rules, and host privacy", () => {
  let evaluatedMasks = 0;
  for (const totalPeople of TOTAL_PEOPLE) {
    const population = makePopulation(totalPeople);
    const inviteeIds = population.invitees.map((invitee) => invitee.id);
    assert.equal(population.accounts.length, totalPeople);
    assert.equal(population.invitations.length, totalPeople - 1);
    assert.deepEqual(
      population.invitations.map((invitation) => invitation.accountId),
      inviteeIds,
    );

    const minima = [2, Math.ceil(totalPeople / 2), totalPeople];
    const split = Math.ceil(inviteeIds.length / 2);
    const hostAndOfOr = [
      { id: `host-rule-${totalPeople}-a`, memberIDs: inviteeIds.slice(0, split) },
      { id: `host-rule-${totalPeople}-b`, memberIDs: inviteeIds.slice(split) },
    ];
    const maskCount = 1 << inviteeIds.length;

    for (let mask = 0; mask < maskCount; mask += 1) {
      const revisionMode = mask & 1
        ? "latest-on-time-wins"
        : "late-revision-is-ignored";
      const selected = selectLatestAtDeadline(
        revisionHistory(inviteeIds, mask, revisionMode),
        DEADLINE,
      );
      const selectedMask = selected.reduce(
        (value, response, index) =>
          response.response === "going" ? value | (1 << index) : value,
        0,
      );
      assert.equal(selectedMask, mask);

      const policy = {
        eventId: population.eventId,
        hostMemberId: population.host.id,
        inviteeIds,
        minimumParticipants: minima[(mask >>> 1) % minima.length],
        requiredGroups: mask & 4 ? hostAndOfOr : [],
      };
      const policyValidResponses = selected.map((response) => ({
        ...response,
        minimumParticipants:
          response.response === "going" ? policy.minimumParticipants : null,
      }));
      const resolved = resolvePrivateEvent(policy, policyValidResponses);
      assert.deepEqual(
        resolved,
        expectedUnconditionalProjection(policy, policyValidResponses),
      );
      assertPrivacySafeHostProjection(resolved);

      const deadlineStillOpen = Boolean(mask & 8);
      const hostProjection = deadlineStillOpen
        ? { eventId: policy.eventId, status: "pending" }
        : resolved;
      assertPrivacySafeHostProjection(hostProjection);
      if (deadlineStillOpen) assert.equal(hostProjection.status, "pending");
      evaluatedMasks += 1;
    }
  }
  assert.equal(evaluatedMasks, 16 + 512 + 524_288);
});

test("invitee-level AND-of-OR conditions converge to the independent reference projection", () => {
  for (const totalPeople of TOTAL_PEOPLE) {
    const population = makePopulation(totalPeople);
    const inviteeIds = population.invitees.map((invitee) => invitee.id);
    const allMask = (1 << inviteeIds.length) - 1;
    const masks = new Set([
      0,
      1,
      allMask,
      allMask ^ 1,
      Math.floor(allMask / 3),
      Math.floor((allMask * 2) / 3),
    ]);
    const policy = {
      eventId: population.eventId,
      hostMemberId: population.host.id,
      inviteeIds,
      minimumParticipants: Math.ceil(totalPeople / 2),
      requiredGroups: [],
    };

    for (const mask of masks) {
      const responses = inviteeIds.map((inviteeId, index) => {
        const going = Boolean(mask & (1 << index));
        if (!going) return responseForBit(inviteeId, false);
        const otherInvitees = inviteeIds.filter((candidate) => candidate !== inviteeId);
        const split = Math.ceil(otherInvitees.length / 2);
        return {
          inviteeId,
          response: "going",
          minimumParticipants: Math.ceil(totalPeople / 2),
          requiredGroups: [
            {
              id: `${inviteeId}-condition-a`,
              memberIDs: otherInvitees.slice(0, split),
            },
            {
              id: `${inviteeId}-condition-b`,
              memberIDs: otherInvitees.slice(split),
            },
          ],
        };
      });
      const actual = resolvePrivateEvent(policy, responses);
      assert.deepEqual(actual, referenceResolve(policy, responses));
      assertPrivacySafeHostProjection(actual);
    }
  }
});
