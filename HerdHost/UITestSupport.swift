#if DEBUG
import CryptoKit
import Foundation

/// Deterministic, process-local dependencies used only by the XCUITest target.
/// Release builds do not compile this implementation, and the fixture transport
/// recognizes only the non-routable test origin selected by an explicit launch
/// argument.
struct HerdUITestEnvironment {
    enum Scenario: String {
        case hostCreate = "host-create"
        case hostEdit = "host-edit"
        case invitationAccountSwitch = "invitation-account-switch"
    }

    static let fixtureOrigin = URL(string: "https://herd-ui-testing.invalid")!
    static let invitationToken = "ui-invitation-token-123"
    static let correctInvitePhoneNumber = "+14155550102"
    static let wrongInvitePhoneNumber = "+14155550101"
    static let resultSigningKeyID = "herd-ui-result-signing-v1"
    static let resultSigningPrivateKey = "8cux37M5HcHj1MxyOu6VwFnVzXhLCaISDdqAl_CDsIo"
    static let resultSigningPublicKey =
        "BKT1u-jRmfD6Se9sIXMy1H3JyUE5u1wqiV20sneUNN5YQi9CHKv5HPa_nBJkkz-nkxrU38-RCe4tclUQM_5SEVY"

    let scenario: Scenario

    static var current: HerdUITestEnvironment? {
        let arguments = ProcessInfo.processInfo.arguments
        guard
            let marker = arguments.firstIndex(of: "--herd-ui-testing"),
            arguments.indices.contains(marker + 1),
            let scenario = Scenario(rawValue: arguments[marker + 1])
        else { return nil }
        return HerdUITestEnvironment(scenario: scenario)
    }

    var startsWithAuthenticatedHost: Bool {
        scenario == .hostCreate || scenario == .hostEdit
    }

    var prefilledCreateEvent: HerdEvent? {
        guard scenario == .hostCreate else { return nil }
        return Self.hostDraft(
            id: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
            title: ""
        )
    }

    var pendingInvitationURL: URL? {
        guard scenario == .invitationAccountSwitch else { return nil }
        return Self.fixtureOrigin.appending(path: "invite/\(Self.invitationToken)")
    }

    var sessionStore: KeychainSessionStore {
        KeychainSessionStore(service: "com.herd.ui-tests.auth.\(scenario.rawValue)")
    }

    var pendingInvitationStore: PendingInvitationKeychainStore {
        PendingInvitationKeychainStore(
            service: "com.herd.ui-tests.invitation.\(scenario.rawValue)"
        )
    }

    var accountKeyStore: AccountKeyStore {
        AccountKeyStore(service: "com.herd.ui-tests.response.\(scenario.rawValue)")
    }

    var defaults: UserDefaults {
        let suiteName = "com.herd.ui-tests.defaults.\(scenario.rawValue)"
        return UserDefaults(suiteName: suiteName)!
    }

    func prepare() {
        HerdUITestURLProtocol.reset(to: scenario)

        let suiteName = "com.herd.ui-tests.defaults.\(scenario.rawValue)"
        defaults.removePersistentDomain(forName: suiteName)
        try? sessionStore.delete()
        try? pendingInvitationStore.delete()

        guard startsWithAuthenticatedHost else { return }
        try? sessionStore.save(
            AuthSession(
                user: Self.hostUser,
                accessToken: HerdUITestURLProtocol.hostAccessToken,
                expiresAt: .now.addingTimeInterval(86_400)
            )
        )
    }

    func makeAPIClient() -> APIClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [HerdUITestURLProtocol.self]
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        let session = URLSession(configuration: configuration)
        return APIClient(
            baseURL: Self.fixtureOrigin,
            urlSession: session,
            evaluatorURLSession: session
        )
    }

    static let hostUser = HerdUser(
        id: "ui-host-account",
        phoneNumber: "+14155550100",
        name: "UI Host",
        address: "1 Fixture Way"
    )

    static let fixtureContacts: [ContactCandidate] = [
        ContactCandidate(
            id: "herd-ui-contact-1",
            displayName: "_1 herdTestUser",
            phoneNumber: "+1 (415) 555-0101"
        ),
        ContactCandidate(
            id: "herd-ui-contact-2",
            displayName: "_2 herdTestUser",
            phoneNumber: "+1 (415) 555-0102"
        ),
        ContactCandidate(
            id: "herd-ui-contact-3",
            displayName: "_3 herdTestUser",
            phoneNumber: "+1 (415) 555-0103"
        ),
    ]

    static func hostDraft(id: UUID, title: String) -> HerdEvent {
        HerdEvent(
            id: id,
            title: title,
            eventDate: .now.addingTimeInterval(7 * 86_400),
            endDate: .now.addingTimeInterval(7 * 86_400 + 7_200),
            hostName: hostUser.name,
            locationName: "Fixture Park",
            locationAddress: "1 Test Lane",
            invitees: [],
            minimumParticipants: 2,
            requiredGroups: [],
            rsvpDeadline: .now.addingTimeInterval(86_400),
            eventDescription: "Deterministic native UI coverage fixture.",
            createdAt: .now,
            invitationsSent: false
        )
    }
}

private final class HerdUITestURLProtocol: URLProtocol, @unchecked Sendable {
    static let hostAccessToken = "ui-host-access-token"

    private static let lock = NSLock()
    private static var scenario: HerdUITestEnvironment.Scenario = .hostCreate
    private static var events: [[String: Any]] = []
    private static var shouldResolveSentEvents = false
    private static var invitationSignInCount = 0

    static func reset(to scenario: HerdUITestEnvironment.Scenario) {
        lock.lock()
        defer { lock.unlock() }
        self.scenario = scenario
        shouldResolveSentEvents = false
        invitationSignInCount = 0
        switch scenario {
        case .hostCreate, .invitationAccountSwitch:
            events = []
        case .hostEdit:
            events = [hostEventDictionary(
                HerdUITestEnvironment.hostDraft(
                    id: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
                    title: "Fixture Draft"
                )
            )]
        }
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == HerdUITestEnvironment.fixtureOrigin.host
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url else {
            finish(status: 400, object: ["error": "Missing fixture URL"])
            return
        }

        let result = Self.response(
            method: request.httpMethod ?? "GET",
            path: url.path,
            authorization: request.value(forHTTPHeaderField: "Authorization")
        )
        finish(status: result.status, object: result.object)
    }

    override func stopLoading() {}

    private func finish(status: Int, object: Any) {
        guard
            let url = request.url,
            let response = HTTPURLResponse(
                url: url,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            ),
            JSONSerialization.isValidJSONObject(object),
            let data = try? JSONSerialization.data(withJSONObject: object)
        else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: data)
        client?.urlProtocolDidFinishLoading(self)
    }

    private static func response(
        method: String,
        path: String,
        authorization: String?
    ) -> (status: Int, object: Any) {
        lock.lock()
        defer { lock.unlock() }

        if method == "GET", path == "/api/me" {
            return (200, ["user": userDictionary(for: authorization)])
        }

        if method == "GET", path == "/api/events" {
            if shouldResolveSentEvents {
                events = events.map(resolvedEventDictionary)
                shouldResolveSentEvents = false
            }
            return (200, ["events": events])
        }

        if method == "PUT", path.hasPrefix("/api/events/") {
            var event: [String: Any]
            switch scenario {
            case .hostCreate:
                guard path == "/api/events/10000000-0000-0000-0000-000000000001" else {
                    return (404, ["error": "Unexpected create event identifier"])
                }
                var saved = HerdUITestEnvironment.hostDraft(
                    id: UUID(uuidString: "10000000-0000-0000-0000-000000000001")!,
                    title: "UI Coverage Dinner"
                )
                saved.invitees = [Invitee(
                    id: UUID(uuidString: "50000000-0000-0000-0000-000000000005")!,
                    sourceContactIdentifier: "herd-ui-contact-1",
                    displayName: "_1 herdTestUser",
                    phoneNumber: "+14155550101"
                )]
                saved.invitationsSent = true
                event = hostEventDictionary(saved)
                event["privateResponsePolicy"] = frozenPolicyDictionary()
                event["resolution"] = [
                    "status": "pending",
                    "retrying": false,
                ]
                event["invitationDelivery"] = deliveryDictionary(for: event)
                shouldResolveSentEvents = true
            case .hostEdit:
                guard path == "/api/events/20000000-0000-0000-0000-000000000002" else {
                    return (404, ["error": "Unexpected edit event identifier"])
                }
                event = hostEventDictionary(
                    HerdUITestEnvironment.hostDraft(
                        id: UUID(uuidString: "20000000-0000-0000-0000-000000000002")!,
                        title: "Edited Fixture Draft"
                    )
                )
            case .invitationAccountSwitch:
                return (400, ["error": "Invitation fixtures cannot edit events"])
            }
            upsert(event)
            return (200, ["event": event])
        }

        if method == "POST", path == "/api/auth/request-code" {
            guard scenario == .invitationAccountSwitch else {
                return (400, ["error": "Unexpected fixture sign-in"])
            }
            invitationSignInCount += 1
            let isCorrect = invitationSignInCount > 1
            let phoneNumber = isCorrect
                ? HerdUITestEnvironment.correctInvitePhoneNumber
                : HerdUITestEnvironment.wrongInvitePhoneNumber
            let user = HerdUser(
                id: isCorrect ? "ui-correct-invite-account" : "ui-wrong-invite-account",
                phoneNumber: phoneNumber,
                name: isCorrect ? "Correct Invitee" : "Wrong Invitee",
                address: ""
            )
            return (200, sessionDictionary(
                user: user,
                accessToken: isCorrect ? "ui-correct-invite-token" : "ui-wrong-invite-token"
            ))
        }

        if method == "DELETE", path == "/api/auth/session" {
            return (200, ["ok": true])
        }

        if method == "GET", path == "/api/invites/\(HerdUITestEnvironment.invitationToken)" {
            guard authorization == "Bearer ui-correct-invite-token" else {
                return (403, [
                    "error": [
                        "code": "invite_for_different_account",
                        "message": "This invitation belongs to a different phone number.",
                    ],
                ])
            }
            return (200, ["event": invitationEventDictionary()])
        }

        return (404, ["error": "No UI fixture for \(method) \(path)"])
    }

    private static func upsert(_ event: [String: Any]) {
        guard let id = event["id"] as? String else { return }
        if let index = events.firstIndex(where: { $0["id"] as? String == id }) {
            events[index] = event
        } else {
            events.append(event)
        }
    }

    private static func resolvedEventDictionary(_ event: [String: Any]) -> [String: Any] {
        guard event["invitationsSent"] as? Bool == true else { return event }
        var resolved = event
        guard
            let eventID = event["id"] as? String,
            let policy = event["privateResponsePolicy"] as? [String: Any],
            let policyHash = policy["policyHash"] as? String,
            let evaluatorKeyID = policy["evaluatorKeyId"] as? String
        else { return event }
        let inviteeIDs = (event["invitees"] as? [[String: Any]] ?? []).compactMap {
            $0["id"] as? String
        }.map { $0.lowercased() }
        let attendingMemberIDs = ["host"] + inviteeIDs
        let evaluatedAt = dateString(.now.addingTimeInterval(2 * 86_400))
        let batchHash = canonicalHashFixture
        let relayRequestID = "60000000-0000-0000-0000-000000000006"
        let leaseID = "70000000-0000-0000-0000-000000000007"
        let status = "confirmed"
        let attendingJSON = attendingMemberIDs.map(quoted).joined(separator: ",")
        let canonicalDocument = "{" +
            "\"protocolVersion\":1," +
            "\"signingKeyId\":\(quoted(HerdUITestEnvironment.resultSigningKeyID))," +
            "\"relayRequestHash\":\(quoted(canonicalHashFixture))," +
            "\"relayRequestId\":\(quoted(relayRequestID))," +
            "\"leaseId\":\(quoted(leaseID))," +
            "\"evaluatedAt\":\(quoted(evaluatedAt))," +
            "\"result\":{" +
            "\"protocolVersion\":1," +
            "\"eventId\":\(quoted(eventID.lowercased()))," +
            "\"policyHash\":\(quoted(policyHash))," +
            "\"batchHash\":\(quoted(batchHash))," +
            "\"evaluatorKeyId\":\(quoted(evaluatorKeyID))," +
            "\"status\":\(quoted(status))," +
            "\"attendingMemberIds\":[\(attendingJSON)]}}"
        let signature = resultSignature(for: canonicalDocument)
        resolved["resolution"] = [
            "status": "confirmed",
            "attendingMemberIds": attendingMemberIDs,
            "resolvedAt": evaluatedAt,
            "attestation": [
                "protocolVersion": 1,
                "signingKeyId": HerdUITestEnvironment.resultSigningKeyID,
                "evaluatedAt": evaluatedAt,
                "canonicalDocument": canonicalDocument,
                "signature": signature,
            ],
        ]
        return resolved
    }

    private static func deliveryDictionary(for event: [String: Any]) -> [String: Any] {
        let invitees = event["invitees"] as? [[String: Any]] ?? []
        let guests = invitees.compactMap { invitee -> [String: Any]? in
            guard
                let id = invitee["id"] as? String,
                let name = invitee["displayName"] as? String
            else { return nil }
            return [
                "inviteeId": id,
                "displayName": name,
                "status": "sent",
            ]
        }
        return [
            "status": "complete",
            "total": guests.count,
            "counts": [
                "pending": 0,
                "dispatching": 0,
                "sent": guests.count,
                "failed": 0,
                "unknown": 0,
                "suppressed": 0,
            ],
            "guests": guests,
        ]
    }

    private static func frozenPolicyDictionary() -> [String: Any] {
        [
            "protocolVersion": 1,
            "cipherSuite": "HERD-UI-TEST-ONLY",
            "policyHash": canonicalHashFixture,
            "canonicalDocument": "{\"fixture\":true}",
            "evaluatorKeyId": "ui-test-evaluator",
            "evaluatorPublicKey": "ui-test-public-key",
            "evaluatorMeasurement": "ui-test-measurement",
            "releaseId": "ui-test-release",
            "paddedPlaintextBytes": 4096,
            "frozenAt": dateString(.now),
        ]
    }

    private static func invitationEventDictionary() -> [String: Any] {
        let inviteeID = "30000000-0000-0000-0000-000000000003"
        return [
            "id": "40000000-0000-0000-0000-000000000004",
            "title": "Private Picnic Invitation",
            "eventDate": dateString(.now.addingTimeInterval(7 * 86_400)),
            "endDate": dateString(.now.addingTimeInterval(7 * 86_400 + 7_200)),
            "hostName": "Fixture Host",
            "locationName": "Invitation Park",
            "locationAddress": "2 Test Lane",
            "invitees": [[
                "id": inviteeID,
                "displayName": "Correct Invitee",
                "phoneNumber": HerdUITestEnvironment.correctInvitePhoneNumber,
                "isCurrentUser": true,
            ]],
            "minimumParticipants": 2,
            "requiredGroups": [],
            "rsvpDeadline": dateString(.now.addingTimeInterval(86_400)),
            "eventDescription": "Opened only after the invitation account matches.",
            "createdAt": dateString(.now),
            "invitationsSent": true,
            "role": "invitee",
            "inviteToken": HerdUITestEnvironment.invitationToken,
            "privateResponsePolicy": frozenPolicyDictionary(),
            "resolution": [
                "status": "pending",
                "retrying": false,
            ],
        ]
    }

    private static func hostEventDictionary(_ event: HerdEvent) -> [String: Any] {
        let data = try! HerdJSON.makeEncoder().encode(event)
        var object = try! JSONSerialization.jsonObject(with: data) as! [String: Any]
        object["role"] = "host"
        return object
    }

    private static func userDictionary(for authorization: String?) -> [String: Any] {
        switch authorization {
        case "Bearer ui-correct-invite-token":
            return [
                "id": "ui-correct-invite-account",
                "phoneNumber": HerdUITestEnvironment.correctInvitePhoneNumber,
                "name": "Correct Invitee",
                "address": "",
            ]
        case "Bearer ui-wrong-invite-token":
            return [
                "id": "ui-wrong-invite-account",
                "phoneNumber": HerdUITestEnvironment.wrongInvitePhoneNumber,
                "name": "Wrong Invitee",
                "address": "",
            ]
        default:
            return userDictionary(HerdUITestEnvironment.hostUser)
        }
    }

    private static func userDictionary(_ user: HerdUser) -> [String: Any] {
        [
            "id": user.id,
            "phoneNumber": user.phoneNumber,
            "name": user.name,
            "address": user.address,
        ]
    }

    private static func sessionDictionary(user: HerdUser, accessToken: String) -> [String: Any] {
        [
            "user": userDictionary(user),
            "accessToken": accessToken,
            "expiresAt": dateString(.now.addingTimeInterval(86_400)),
        ]
    }

    private static func dateString(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    private static let canonicalHashFixture =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

    private static func resultSignature(for canonicalDocument: String) -> String {
        let privateKeyData = Data(
            base64URLEncoded: HerdUITestEnvironment.resultSigningPrivateKey
        )!
        let privateKey = try! P256.Signing.PrivateKey(rawRepresentation: privateKeyData)
        let signature = try! privateKey.signature(for: Data(canonicalDocument.utf8))
        return signature.rawRepresentation.base64URLEncodedString()
    }

    private static func quoted(_ value: String) -> String {
        String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
    }
}
#endif
