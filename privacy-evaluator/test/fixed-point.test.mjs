import assert from "node:assert/strict";
import test from "node:test";

import { resolvePrivateEvent } from "../src/fixed-point.mjs";

const policy = {
  eventId: "event-1",
  hostMemberId: "host",
  inviteeIds: ["a", "b", "c", "d"],
  minimumParticipants: 3,
  requiredGroups: [],
};

function going(inviteeId, minimumParticipants = 3, requiredGroups = []) {
  return {
    inviteeId,
    response: "going",
    minimumParticipants,
    requiredGroups,
  };
}

function cantCommit(inviteeId) {
  return {
    inviteeId,
    response: "cant_commit",
    minimumParticipants: null,
    requiredGroups: [],
  };
}

test("confirms and reveals only the final attendance list", () => {
  assert.deepEqual(
    resolvePrivateEvent(policy, [going("a"), going("b"), going("c")]),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "a", "b", "c"],
    },
  );
});

test("failure reveals no guest-level status or failed condition", () => {
  assert.deepEqual(resolvePrivateEvent(policy, [going("a")]), {
    eventId: "event-1",
    status: "not_confirmed",
  });
});

test("mutual conditions survive in the greatest fixed point", () => {
  const result = resolvePrivateEvent(policy, [
    going("a", 3, [{ id: "a-needs-b", memberIDs: ["b"] }]),
    going("b", 3, [{ id: "b-needs-a", memberIDs: ["a"] }]),
  ]);
  assert.equal(result.status, "confirmed");
  assert.deepEqual(result.attendingMemberIds, ["host", "a", "b"]);
});

test("removes a cascading chain until the fixed point stabilizes", () => {
  const result = resolvePrivateEvent(
    { ...policy, minimumParticipants: 2 },
    [
      going("a", 2, [{ id: "a-needs-b", memberIDs: ["b"] }]),
      going("b", 2, [{ id: "b-needs-c", memberIDs: ["c"] }]),
      cantCommit("c"),
    ],
  );
  assert.deepEqual(result, { eventId: "event-1", status: "not_confirmed" });
});

test("a required singleton is enforced for both host and invitee rules", () => {
  const hostRule = [{ id: "host-needs-a", memberIDs: ["a"] }];
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2, requiredGroups: hostRule },
      [going("b", 2), going("c", 2)],
    ),
    { eventId: "event-1", status: "not_confirmed" },
  );
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2, requiredGroups: hostRule },
      [going("a", 2), going("b", 2)],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "a", "b"],
    },
  );

  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [
        going("a", 2, [{ id: "a-needs-b", memberIDs: ["b"] }]),
        going("c", 2),
      ],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "c"],
    },
  );
});

test("a required OR group is satisfied by any one attending member", () => {
  const needsBorC = [{ id: "a-needs-b-or-c", memberIDs: ["b", "c"] }];
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [going("a", 2, needsBorC), going("c", 2)],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "a", "c"],
    },
  );
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [going("a", 2, needsBorC), going("d", 2)],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "d"],
    },
  );
});

test("AND-of-OR groups require one attending member from every group", () => {
  const groups = [
    { id: "first", memberIDs: ["b", "c"] },
    { id: "second", memberIDs: ["d"] },
  ];
  assert.equal(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [going("a", 2, groups), going("b", 2), going("d", 2)],
    ).status,
    "confirmed",
  );
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [going("a", 2, groups), going("b", 2)],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "b"],
    },
  );
});

test("cycles survive at the greatest fixed point while broken cycles cascade away", () => {
  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 3 },
      [
        going("a", 3, [{ id: "a-needs-b", memberIDs: ["b"] }]),
        going("b", 3, [{ id: "b-needs-a", memberIDs: ["a"] }]),
      ],
    ),
    {
      eventId: "event-1",
      status: "confirmed",
      attendingMemberIds: ["host", "a", "b"],
    },
  );

  assert.deepEqual(
    resolvePrivateEvent(
      { ...policy, minimumParticipants: 2 },
      [
        going("a", 2, [{ id: "a-needs-b", memberIDs: ["b"] }]),
        going("b", 2, [{ id: "b-needs-c", memberIDs: ["c"] }]),
        going("c", 2, [{ id: "c-needs-d", memberIDs: ["d"] }]),
      ],
    ),
    { eventId: "event-1", status: "not_confirmed" },
  );
});

test("response order cannot change resolution or frozen-policy attendance order", () => {
  const orderedPolicy = {
    eventId: "ordered-event",
    hostMemberId: "host",
    inviteeIds: ["d", "b", "a", "c"],
    minimumParticipants: 3,
    requiredGroups: [],
  };
  const expected = {
    eventId: "ordered-event",
    status: "confirmed",
    attendingMemberIds: ["host", "d", "b", "a"],
  };
  const responses = [going("a"), cantCommit("c"), going("d"), going("b")];
  assert.deepEqual(resolvePrivateEvent(orderedPolicy, responses), expected);
  assert.deepEqual(resolvePrivateEvent(orderedPolicy, [...responses].reverse()), expected);
  assert.deepEqual(
    resolvePrivateEvent(orderedPolicy, [responses[2], responses[0], responses[3], responses[1]]),
    expected,
  );
});

test("resolver boundaries enforce production participant minimum semantics", () => {
  assert.throws(
    () => resolvePrivateEvent({ ...policy, minimumParticipants: 1 }, []),
    /policy\.minimumParticipants must be an integer from 2 to 5/u,
  );
  assert.throws(
    () => resolvePrivateEvent(policy, [going("a", 2)]),
    /responses\[0\]\.minimumParticipants must be an integer from 3 to 5/u,
  );
  assert.throws(
    () => resolvePrivateEvent(policy, [going("a", 6)]),
    /responses\[0\]\.minimumParticipants must be an integer from 3 to 5/u,
  );
  assert.throws(
    () => resolvePrivateEvent(policy, [{ ...cantCommit("a"), minimumParticipants: 3 }]),
    /cant_commit response must use a null minimum/u,
  );
});

test("exhausts all 3^9 reply patterns at every production host threshold", () => {
  const inviteeIds = Array.from({ length: 9 }, (_, index) => `guest-${index + 1}`);
  const states = ["no_reply", "cant_commit", "going"];
  const patternsPerThreshold = 3 ** inviteeIds.length;
  const expectedConfirmedByMinimum = new Map([
    [2, 19_171],
    [3, 16_867],
    [4, 12_259],
    [5, 6_883],
    [6, 2_851],
    [7, 835],
    [8, 163],
    [9, 19],
    [10, 1],
  ]);
  let evaluatedPatterns = 0;
  let confirmedPatterns = 0;

  for (let minimumParticipants = 2; minimumParticipants <= 10; minimumParticipants += 1) {
    let confirmedAtMinimum = 0;
    const exhaustivePolicy = {
      eventId: `event-minimum-${minimumParticipants}`,
      hostMemberId: "host",
      inviteeIds,
      minimumParticipants,
      requiredGroups: [],
    };
    for (let encodedPattern = 0; encodedPattern < patternsPerThreshold; encodedPattern += 1) {
      let remainingPattern = encodedPattern;
      const goingInviteeIds = [];
      const responses = [];
      for (const inviteeId of inviteeIds) {
        const state = states[remainingPattern % states.length];
        remainingPattern = Math.floor(remainingPattern / states.length);
        if (state === "going") {
          goingInviteeIds.push(inviteeId);
          responses.push(going(inviteeId, minimumParticipants));
        } else if (state === "cant_commit") {
          responses.push(cantCommit(inviteeId));
        }
      }

      // Independent oracle: with no conditional groups and every going guest
      // using the host threshold, only the count of going replies can matter.
      const expected = goingInviteeIds.length + 1 >= minimumParticipants
        ? {
            eventId: exhaustivePolicy.eventId,
            status: "confirmed",
            attendingMemberIds: ["host", ...goingInviteeIds],
          }
        : { eventId: exhaustivePolicy.eventId, status: "not_confirmed" };
      const actual = resolvePrivateEvent(exhaustivePolicy, responses);
      assert.deepEqual(actual, expected);
      if (actual.status === "confirmed") {
        confirmedAtMinimum += 1;
        confirmedPatterns += 1;
      }
      evaluatedPatterns += 1;
    }
    assert.equal(
      confirmedAtMinimum,
      expectedConfirmedByMinimum.get(minimumParticipants),
    );
  }

  assert.equal(patternsPerThreshold, 19_683);
  assert.equal(evaluatedPatterns, 177_147);
  assert.equal(confirmedPatterns, 59_049);
  assert.equal(evaluatedPatterns - confirmedPatterns, 118_098);
});

for (const participantCount of [5, 10, 20]) {
  test(`resolves the ${participantCount}-participant launch scenario`, () => {
    const inviteeIds = Array.from(
      { length: participantCount - 1 },
      (_, index) => `guest-${index + 1}`,
    );
    const result = resolvePrivateEvent(
      {
        eventId: `event-${participantCount}`,
        hostMemberId: "host",
        inviteeIds,
        minimumParticipants: participantCount,
        requiredGroups: [],
      },
      inviteeIds.map((inviteeId) =>
        going(inviteeId, participantCount),
      ),
    );
    assert.equal(result.status, "confirmed");
    assert.equal(result.attendingMemberIds.length, participantCount);
  });
}
