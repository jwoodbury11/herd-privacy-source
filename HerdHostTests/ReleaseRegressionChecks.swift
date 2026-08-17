import Foundation

@main
private enum ReleaseRegressionChecks {
    static func main() {
        testNearTermDeadlineSuggestion()
        testOptionalEndDateRemainsValid()
        testExpiredDraftDeadlineIsRejected()
        testRequiredPeopleCannotAppearAcrossRows()
        print("HerdHost release regression checks passed")
    }

    private static func testNearTermDeadlineSuggestion() {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let eventDate = now.addingTimeInterval(60 * 60)
        let deadline = require(
            EventDeadlineRules.suggestedReplyDeadline(
                before: eventDate,
                now: now,
                calendar: Calendar(identifier: .gregorian)
            ),
            "A one-hour-away event should receive a usable deadline."
        )
        precondition(deadline > now, "Suggested deadline must be in the future.")
        precondition(
            deadline <= eventDate.addingTimeInterval(-EventDeadlineRules.minimumEventSeparation),
            "Suggested deadline must leave room before the event."
        )

        let tooSoon = now.addingTimeInterval(
            EventDeadlineRules.suggestedLeadTime +
                EventDeadlineRules.minimumEventSeparation - 1
        )
        precondition(
            EventDeadlineRules.suggestedReplyDeadline(before: tooSoon, now: now) == nil,
            "An event without a safe deadline window must not get a past deadline."
        )
    }

    private static func testOptionalEndDateRemainsValid() {
        let now = Date.now
        let event = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600),
            requiredGroups: []
        )
        precondition(event.isValid, "A valid draft must not require an end date.")
    }

    private static func testExpiredDraftDeadlineIsRejected() {
        let now = Date.now
        let event = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(-60),
            requiredGroups: []
        )
        precondition(
            event.outstandingTasks.contains("Move the RSVP deadline into the future"),
            "An expired draft deadline must block sending before the server rejects it."
        )
    }

    private static func testRequiredPeopleCannotAppearAcrossRows() {
        let now = Date.now
        let first = Invitee(displayName: "First", phoneNumber: "+14155550101")
        let second = Invitee(displayName: "Second", phoneNumber: "+14155550102")
        let duplicate = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600),
            invitees: [first, second],
            requiredGroups: [
                RequiredAttendeeGroup(memberIDs: [first.id]),
                RequiredAttendeeGroup(memberIDs: [first.id, second.id]),
            ]
        )
        precondition(
            duplicate.outstandingTasks.contains("Fix the required-attendee rules"),
            "A person repeated across host-rule rows must be rejected on device."
        )

        let valid = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600),
            invitees: [first, second],
            requiredGroups: [RequiredAttendeeGroup(memberIDs: [first.id, second.id])]
        )
        precondition(valid.isValid, "Distinct host-rule membership should remain valid.")
    }

    private static func makeDraft(
        eventDate: Date,
        endDate: Date?,
        deadline: Date,
        invitees: [Invitee] = [
            Invitee(displayName: "Guest", phoneNumber: "+14155550101"),
        ],
        requiredGroups: [RequiredAttendeeGroup]
    ) -> HerdEvent {
        HerdEvent(
            id: UUID(),
            title: "Regression event",
            eventDate: eventDate,
            endDate: endDate,
            hostName: "Host",
            locationName: "",
            locationAddress: "",
            invitees: invitees,
            minimumParticipants: 2,
            requiredGroups: requiredGroups,
            rsvpDeadline: deadline,
            eventDescription: "",
            createdAt: .now
        )
    }

    private static func require<T>(_ value: T?, _ message: String) -> T {
        guard let value else { preconditionFailure(message) }
        return value
    }
}
