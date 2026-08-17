import Foundation

@main
private enum LegacyOwnershipRegressionChecks {
    @MainActor
    static func main() async throws {
        let suiteName = "HerdHost.LegacyOwnershipRegression.\(UUID().uuidString)"
        let defaults = require(
            UserDefaults(suiteName: suiteName),
            "Could not create isolated defaults."
        )
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let legacy = HerdEvent(
            id: UUID(),
            title: "Older local event",
            eventDate: Date.now.addingTimeInterval(7_200),
            endDate: nil,
            hostName: "Original host",
            locationName: "",
            locationAddress: "",
            invitees: [],
            minimumParticipants: 2,
            requiredGroups: [],
            rsvpDeadline: Date.now.addingTimeInterval(3_600),
            eventDescription: "",
            createdAt: .now
        )
        defaults.set(
            try JSONEncoder().encode([legacy]),
            forKey: "herd.host.events.v1"
        )

        let client = APIClient(baseURL: URL(string: "http://localhost:1")!)
        let store = EventStore(defaults: defaults, apiClient: client)

        store.activate(userID: "account-a")
        let unclaimedEvents = store.events
        let unclaimedCount = store.legacyImportCandidateCount
        precondition(
            unclaimedEvents.allSatisfy { $0.id != legacy.id },
            "Unclaimed legacy events must not appear in an account."
        )
        precondition(
            unclaimedCount == 1,
            "The account should receive an explicit import choice."
        )

        let claimed = await store.claimLegacyHostedEvents()
        let claimedEvents = store.events
        precondition(claimed, "The current account should be able to claim legacy events.")
        precondition(
            claimedEvents.contains { $0.id == legacy.id },
            "A claimed legacy event should become an editable local draft."
        )

        store.clearSession()
        store.activate(userID: "account-b")
        let otherAccountEvents = store.events
        let otherAccountCandidateCount = store.legacyImportCandidateCount
        precondition(
            otherAccountEvents.allSatisfy { $0.id != legacy.id },
            "A legacy event claimed by one account must not cross into another."
        )
        precondition(
            otherAccountCandidateCount == 0,
            "Other accounts must not be offered an already claimed legacy event."
        )

        print("HerdHost legacy ownership regression checks passed")
    }

    private static func require<T>(_ value: T?, _ message: String) -> T {
        guard let value else { preconditionFailure(message) }
        return value
    }
}
