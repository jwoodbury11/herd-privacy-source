import assert from "node:assert/strict";
import test from "node:test";

import { resolvePrivateEvent } from "../src/fixed-point.mjs";

const INVITEE_IDS = Array.from({ length: 9 }, (_, index) => `guest-${index + 1}`);
const INVITEE_INDEX = new Map(INVITEE_IDS.map((inviteeId, index) => [inviteeId, index]));
const ATTENDANCE_MASK_COUNT = 2 ** INVITEE_IDS.length;
const ALL_INVITEES_MASK = ATTENDANCE_MASK_COUNT - 1;
const POPCOUNT = Array.from({ length: ATTENDANCE_MASK_COUNT }, (_, mask) => {
  let count = 0;
  for (let remaining = mask; remaining > 0; remaining >>= 1) count += remaining & 1;
  return count;
});

function group(id, ...memberIDs) {
  return { id, memberIDs };
}

const DEPENDENCY_FAMILIES = [
  {
    name: "chain-to-anchor",
    groupsByInvitee: Object.fromEntries(
      INVITEE_IDS.slice(0, -1).map((inviteeId, index) => [
        inviteeId,
        [group(`chain-${index + 1}`, INVITEE_IDS[index + 1])],
      ]),
    ),
  },
  {
    name: "nine-cycle",
    groupsByInvitee: Object.fromEntries(
      INVITEE_IDS.map((inviteeId, index) => [
        inviteeId,
        [group(`cycle-${index + 1}`, INVITEE_IDS[(index + 1) % INVITEE_IDS.length])],
      ]),
    ),
  },
  {
    name: "cycles-with-tails",
    groupsByInvitee: {
      "guest-1": [group("three-cycle-1", "guest-2")],
      "guest-2": [group("three-cycle-2", "guest-3")],
      "guest-3": [group("three-cycle-3", "guest-1")],
      "guest-4": [group("tail-4", "guest-1")],
      "guest-5": [group("tail-5", "guest-4")],
      "guest-6": [group("two-cycle-6", "guest-7")],
      "guest-7": [group("two-cycle-7", "guest-6")],
      "guest-8": [group("tail-8", "guest-7")],
    },
  },
  {
    name: "or-branches",
    groupsByInvitee: {
      "guest-1": [group("branch-1", "guest-2", "guest-3")],
      "guest-2": [group("branch-2", "guest-4")],
      "guest-3": [group("branch-3", "guest-5")],
      "guest-6": [group("branch-6", "guest-7", "guest-8", "guest-9")],
      "guest-7": [group("branch-7", "guest-6")],
      "guest-8": [group("branch-8", "guest-9")],
    },
  },
  {
    name: "and-of-or-network",
    groupsByInvitee: {
      "guest-1": [
        group("network-1-a", "guest-2", "guest-3"),
        group("network-1-b", "guest-4", "guest-5"),
      ],
      "guest-2": [group("network-2", "guest-6", "guest-7")],
      "guest-3": [group("network-3", "guest-7")],
      "guest-4": [group("network-4", "guest-8")],
      "guest-5": [group("network-5", "guest-9")],
      "guest-6": [group("network-6", "guest-1")],
      "guest-8": [group("network-8", "guest-9")],
    },
  },
];

const HOST_RULES = [
  { name: "none", groups: [] },
  {
    name: "singleton",
    groups: [group("host-singleton", "guest-5")],
  },
  {
    name: "or",
    groups: [group("host-or", "guest-1", "guest-5", "guest-9")],
  },
  {
    name: "and-of-or",
    groups: [
      group("host-and-a", "guest-1", "guest-2"),
      group("host-and-b", "guest-4", "guest-5", "guest-6"),
      group("host-and-c", "guest-8", "guest-9"),
    ],
  },
];

function minimumForInvitee(hostMinimum, familyIndex, inviteeIndex) {
  const availableMinimums = 11 - hostMinimum;
  return hostMinimum + ((familyIndex * 3 + inviteeIndex * 5) % availableMinimums);
}

function buildResponses(attendanceMask, family, familyIndex, hostRuleIndex, hostMinimum) {
  const responses = [];
  for (const [inviteeIndex, inviteeId] of INVITEE_IDS.entries()) {
    if ((attendanceMask & (1 << inviteeIndex)) !== 0) {
      responses.push({
        inviteeId,
        response: "going",
        minimumParticipants: minimumForInvitee(hostMinimum, familyIndex, inviteeIndex),
        requiredGroups: family.groupsByInvitee[inviteeId] ?? [],
      });
      continue;
    }

    // A deterministic mix of explicit declines and missing replies exercises
    // both wire states without multiplying the matrix by an equivalent axis.
    if ((attendanceMask + inviteeIndex + familyIndex + hostRuleIndex + hostMinimum) % 2 === 0) {
      responses.push({
        inviteeId,
        response: "cant_commit",
        minimumParticipants: null,
        requiredGroups: [],
      });
    }
  }
  return responses;
}

function groupsSatisfiedByMask(groups, attendanceMask) {
  return groups.every((requiredGroup) =>
    requiredGroup.memberIDs.some((memberId) => {
      const memberIndex = INVITEE_INDEX.get(memberId);
      return memberIndex !== undefined && (attendanceMask & (1 << memberIndex)) !== 0;
    }),
  );
}

/**
 * Independent reference oracle.
 *
 * Instead of iteratively removing guests like the production resolver, this
 * searches every subset of going replies. The union of every self-supporting
 * subset is the unique greatest fixed point because all supported predicates
 * (minimum size and positive OR groups) are monotone under set union.
 */
function resolveWithSubsetOracle(policy, responses, oracleStats) {
  const goingByIndex = new Map();
  let goingMask = 0;
  for (const response of responses) {
    if (response.response !== "going") continue;
    const inviteeIndex = INVITEE_INDEX.get(response.inviteeId);
    goingMask |= 1 << inviteeIndex;
    goingByIndex.set(inviteeIndex, response);
  }

  let greatestMask = 0;
  for (
    let subsetMask = goingMask;
    ;
    subsetMask = (subsetMask - 1) & goingMask
  ) {
    oracleStats.subsetEvaluations += 1;
    const participantCount = POPCOUNT[subsetMask] + 1;
    let selfSupporting = true;
    for (const [inviteeIndex, response] of goingByIndex) {
      if ((subsetMask & (1 << inviteeIndex)) === 0) continue;
      if (
        participantCount < response.minimumParticipants ||
        !groupsSatisfiedByMask(response.requiredGroups, subsetMask)
      ) {
        selfSupporting = false;
        break;
      }
    }
    if (selfSupporting) greatestMask |= subsetMask;
    if (subsetMask === 0) break;
  }

  // This also guards the oracle's union argument rather than assuming it.
  const finalParticipantCount = POPCOUNT[greatestMask] + 1;
  for (const [inviteeIndex, response] of goingByIndex) {
    if ((greatestMask & (1 << inviteeIndex)) === 0) continue;
    assert.ok(finalParticipantCount >= response.minimumParticipants);
    assert.ok(groupsSatisfiedByMask(response.requiredGroups, greatestMask));
  }

  if (
    finalParticipantCount < policy.minimumParticipants ||
    !groupsSatisfiedByMask(policy.requiredGroups, greatestMask)
  ) {
    return { eventId: policy.eventId, status: "not_confirmed" };
  }

  return {
    eventId: policy.eventId,
    status: "confirmed",
    attendingMemberIds: [
      policy.hostMemberId,
      ...INVITEE_IDS.filter((_, inviteeIndex) =>
        (greatestMask & (1 << inviteeIndex)) !== 0),
    ],
  };
}

function shuffledResponses(responses, salt) {
  return responses
    .map((response, originalIndex) => ({
      response,
      rank: ((originalIndex + 1) * 17 + salt * 13) % 37,
      originalIndex,
    }))
    .sort((left, right) => left.rank - right.rank || right.originalIndex - left.originalIndex)
    .map(({ response }) => response);
}

test(
  "exhaustive nine-invitee conditional and host-rule matrix matches a subset oracle",
  { timeout: 30_000 },
  (context) => {
    let logicalCases = 0;
    let resolverEvaluations = 0;
    let confirmedCases = 0;
    let notConfirmedCases = 0;
    let intactNineCycleCases = 0;
    let brokenNineCycleCases = 0;
    const oracleStats = { subsetEvaluations: 0 };
    const confirmedByFamily = Object.fromEntries(
      DEPENDENCY_FAMILIES.map(({ name }) => [name, 0]),
    );
    const confirmedByHostRule = Object.fromEntries(
      HOST_RULES.map(({ name }) => [name, 0]),
    );

    for (const [familyIndex, family] of DEPENDENCY_FAMILIES.entries()) {
      for (const [hostRuleIndex, hostRule] of HOST_RULES.entries()) {
        for (let hostMinimum = 2; hostMinimum <= 10; hostMinimum += 1) {
          const policy = {
            eventId: `matrix-${family.name}-${hostRule.name}-${hostMinimum}`,
            hostMemberId: "host",
            inviteeIds: INVITEE_IDS,
            minimumParticipants: hostMinimum,
            requiredGroups: hostRule.groups,
          };

          for (let attendanceMask = 0; attendanceMask < ATTENDANCE_MASK_COUNT; attendanceMask += 1) {
            const responses = buildResponses(
              attendanceMask,
              family,
              familyIndex,
              hostRuleIndex,
              hostMinimum,
            );
            const expected = resolveWithSubsetOracle(policy, responses, oracleStats);
            const label = `${family.name}/${hostRule.name}/minimum-${hostMinimum}/mask-${attendanceMask}`;
            const responseOrders = [
              responses,
              [...responses].reverse(),
              shuffledResponses(responses, attendanceMask + familyIndex + hostMinimum),
            ];

            for (const orderedResponses of responseOrders) {
              assert.deepEqual(resolvePrivateEvent(policy, orderedResponses), expected, label);
              resolverEvaluations += 1;
            }

            if (expected.status === "confirmed") {
              confirmedCases += 1;
              confirmedByFamily[family.name] += 1;
              confirmedByHostRule[hostRule.name] += 1;
            } else {
              notConfirmedCases += 1;
            }

            if (family.name === "nine-cycle") {
              if (attendanceMask === ALL_INVITEES_MASK) {
                assert.equal(expected.status, "confirmed", label);
                intactNineCycleCases += 1;
              } else {
                assert.deepEqual(expected, { eventId: policy.eventId, status: "not_confirmed" });
                brokenNineCycleCases += 1;
              }
            }
            logicalCases += 1;
          }
        }
      }
    }

    assert.equal(logicalCases, 92_160);
    assert.equal(resolverEvaluations, 276_480);
    assert.equal(oracleStats.subsetEvaluations, 3_542_940);
    assert.equal(confirmedCases, 603);
    assert.equal(notConfirmedCases, 91_557);
    assert.equal(intactNineCycleCases, 36);
    assert.equal(brokenNineCycleCases, 18_396);
    assert.deepEqual(confirmedByFamily, {
      "chain-to-anchor": 82,
      "nine-cycle": 36,
      "cycles-with-tails": 103,
      "or-branches": 266,
      "and-of-or-network": 116,
    });
    assert.deepEqual(confirmedByHostRule, {
      none: 174,
      singleton: 159,
      or: 174,
      "and-of-or": 96,
    });

    context.diagnostic(
      `${logicalCases.toLocaleString("en-US")} oracle cases; ` +
      `${oracleStats.subsetEvaluations.toLocaleString("en-US")} subsets searched; ` +
      `${resolverEvaluations.toLocaleString("en-US")} resolver evaluations; ` +
      `${confirmedCases.toLocaleString("en-US")} confirmed; ` +
      `${notConfirmedCases.toLocaleString("en-US")} not confirmed`,
    );
    context.diagnostic(`confirmed by dependency family: ${JSON.stringify(confirmedByFamily)}`);
    context.diagnostic(`confirmed by host rule: ${JSON.stringify(confirmedByHostRule)}`);
  },
);
