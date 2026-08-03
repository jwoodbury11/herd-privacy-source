import Foundation
import XCTest
@testable import HerdHost

final class InvitationLinkParserTests: XCTestCase {
    func testAcceptsOnlyCanonicalLinksForThePinnedOrigin() throws {
        let parser = try XCTUnwrap(
            InvitationLinkParser(trustedWebOrigin: URL(string: "https://herd.example")!)
        )
        let token = "Abcdefgh_123-xyz"

        XCTAssertEqual(
            parser.token(from: URL(string: "https://herd.example/invite/\(token)")!),
            token
        )
        let rejected = [
            "http://herd.example/invite/\(token)",
            "https://evil.example/invite/\(token)",
            "https://herd.example.evil.test/invite/\(token)",
            "https://user@herd.example/invite/\(token)",
            "https://herd.example:444/invite/\(token)",
            "https://herd.example/invite/\(token)?continue=1",
            "https://herd.example/invite/\(token)#reply",
            "https://herd.example/invite/short",
            "https://herd.example/invite/\(token)/extra",
            "https://herd.example/invite/Abcdefgh%2Fescape",
            "https://herd.example/invite/%41bcdefgh",
            "herd://invite/\(token)",
            "herd:///invite/\(token)",
            "herd://evil/\(token)",
            "herd://invite/\(token)/extra",
        ]
        for value in rejected {
            XCTAssertNil(parser.token(from: try XCTUnwrap(URL(string: value))), value)
        }

        let overlong = String(repeating: "a", count: InvitationToken.maximumLength + 1)
        XCTAssertNil(
            parser.token(from: URL(string: "https://herd.example/invite/\(overlong)")!)
        )
    }

    func testRejectsNonOriginBaseURLs() {
        XCTAssertNil(
            InvitationLinkParser(
                trustedWebOrigin: URL(string: "https://herd.example/application")!
            )
        )
        XCTAssertNil(
            InvitationLinkParser(
                trustedWebOrigin: URL(string: "https://herd.example?tenant=one")!
            )
        )
    }
}

@MainActor
final class PendingInvitationLifecycleTests: XCTestCase {
    func testPendingInvitationSurvivesRelaunchAndClearsOnlyAfterPresentation() throws {
        let service = "com.herd.tests.pending-invitation.\(UUID().uuidString.lowercased())"
        let keychain = PendingInvitationKeychainStore(service: service)
        defer { try? keychain.delete() }
        let origin = URL(string: "https://herd.example")!
        let eventID = UUID()
        let token = "Durable_invite-token-123"

        let first = InvitationCoordinator(trustedWebOrigin: origin, keychainStore: keychain)
        XCTAssertTrue(
            first.accept(URL(string: "https://herd.example/invite/\(token)")!)
        )
        XCTAssertEqual(first.pendingToken, token)

        let relaunched = InvitationCoordinator(
            trustedWebOrigin: origin,
            keychainStore: keychain
        )
        XCTAssertEqual(relaunched.pendingToken, token)

        // An unrelated event can never consume the pending invitation.
        relaunched.acknowledgePresentation(
            of: eventID,
            generation: relaunched.requestGeneration
        )
        XCTAssertEqual(relaunched.pendingToken, token)

        relaunched.discard()
        XCTAssertNil(relaunched.pendingToken)
        let afterDiscard = InvitationCoordinator(
            trustedWebOrigin: origin,
            keychainStore: keychain
        )
        XCTAssertNil(afterDiscard.pendingToken)
    }
}

@MainActor
final class InvitationLinkIntegrationTests: XCTestCase {
    override func tearDown() {
        InvitationMockURLProtocol.reset()
        super.tearDown()
    }

    func testAuthenticationRequestCarriesThePendingInviteToken() async throws {
        let token = "Auth_invite-token-123"
        let requestExpectation = expectation(description: "auth request")
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(request.url?.path, "/api/auth/request-code")
            let body = try Self.requestBody(request)
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: body) as? [String: Any]
            )
            XCTAssertEqual(object["phoneNumber"] as? String, "+14155550123")
            XCTAssertEqual(object["inviteToken"] as? String, token)
            requestExpectation.fulfill()
            return try Self.jsonResponse(
                request,
                status: 201,
                object: [
                    "challengeId": "challenge_invitation_auth",
                    "phoneNumber": "+14155550123",
                    "expiresAt": "2026-08-03T04:10:00.000Z",
                    "resendAt": "2026-08-03T04:00:00.000Z",
                ]
            )
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )

        _ = try await client.requestCode(
            phoneNumber: "+14155550123",
            inviteToken: token
        )
        await fulfillment(of: [requestExpectation], timeout: 1)
    }

    func testCorrectAccountLoadsExactInvitationAndStagesDirectDetail() async throws {
        let token = "Correct_account-token-123"
        let eventID = UUID()
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(
                request.url?.path,
                "/api/invites/\(token)"
            )
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Authorization"),
                "Bearer test-access-token"
            )
            return try Self.jsonResponse(
                request,
                object: Self.invitationResponse(eventID: eventID, token: token)
            )
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )
        await client.setAccessToken("test-access-token")
        let defaults = try XCTUnwrap(
            UserDefaults(suiteName: "com.herd.tests.invitation-correct.\(UUID().uuidString)")
        )
        let eventStore = EventStore(defaults: defaults, apiClient: client)
        eventStore.activate(userID: "correct-account")
        let keychain = PendingInvitationKeychainStore(
            service: "com.herd.tests.invitation-correct.\(UUID().uuidString)"
        )
        defer { try? keychain.delete() }
        let coordinator = InvitationCoordinator(
            trustedWebOrigin: URL(string: "https://herd.example")!,
            keychainStore: keychain
        )
        XCTAssertTrue(
            coordinator.accept(URL(string: "https://herd.example/invite/\(token)")!)
        )

        await coordinator.resolve(using: eventStore, accountID: "correct-account")

        XCTAssertEqual(coordinator.loadedEventID, eventID)
        XCTAssertFalse(coordinator.requiresAccountSwitch)
        XCTAssertEqual(eventStore.events.map(\.id), [eventID])
        XCTAssertEqual(eventStore.events.first?.inviteToken, token)
        coordinator.acknowledgePresentation(
            of: eventID,
            generation: try XCTUnwrap(coordinator.loadedRequestGeneration)
        )
        XCTAssertNil(coordinator.pendingToken)
        XCTAssertNil(coordinator.loadedEventID)
    }

    func testWrongAccountOffersSwitchAndPreservesInvitationAcrossSignOut() async throws {
        let token = "Different_account-token-123"
        InvitationMockURLProtocol.install { request in
            try Self.jsonResponse(
                request,
                status: 403,
                object: [
                    "error": [
                        "code": "invite_for_different_account",
                        "message": "This invitation belongs to a different phone number.",
                    ],
                ]
            )
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )
        await client.setAccessToken("wrong-account-token")
        let defaults = try XCTUnwrap(
            UserDefaults(suiteName: "com.herd.tests.invitation-wrong.\(UUID().uuidString)")
        )
        let eventStore = EventStore(defaults: defaults, apiClient: client)
        eventStore.activate(userID: "wrong-account")
        let service = "com.herd.tests.invitation-wrong.\(UUID().uuidString)"
        let keychain = PendingInvitationKeychainStore(service: service)
        defer { try? keychain.delete() }
        let coordinator = InvitationCoordinator(
            trustedWebOrigin: URL(string: "https://herd.example")!,
            keychainStore: keychain
        )
        XCTAssertTrue(
            coordinator.accept(URL(string: "https://herd.example/invite/\(token)")!)
        )

        await coordinator.resolve(using: eventStore, accountID: "wrong-account")

        XCTAssertTrue(coordinator.requiresAccountSwitch)
        XCTAssertEqual(coordinator.pendingToken, token)
        XCTAssertNil(coordinator.loadedEventID)
        coordinator.prepareForAccountSwitch()
        XCTAssertFalse(coordinator.requiresAccountSwitch)
        XCTAssertEqual(coordinator.pendingToken, token)
        XCTAssertEqual(
            InvitationCoordinator(
                trustedWebOrigin: URL(string: "https://herd.example")!,
                keychainStore: keychain
            ).pendingToken,
            token
        )
    }

    func testASecondLinkCannotBeOverwrittenByAnOlderInFlightResolution() async throws {
        let firstToken = "First_inflight-token-123"
        let secondToken = "Second_inflight-token-456"
        let firstEventID = UUID()
        let secondEventID = UUID()
        InvitationMockURLProtocol.install { request in
            if request.url?.path == "/api/invites/\(firstToken)" {
                Thread.sleep(forTimeInterval: 0.08)
                return try Self.jsonResponse(
                    request,
                    object: Self.invitationResponse(
                        eventID: firstEventID,
                        token: firstToken
                    )
                )
            }
            XCTAssertEqual(request.url?.path, "/api/invites/\(secondToken)")
            return try Self.jsonResponse(
                request,
                object: Self.invitationResponse(
                    eventID: secondEventID,
                    token: secondToken
                )
            )
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )
        await client.setAccessToken("replacement-account-token")
        let defaults = try XCTUnwrap(
            UserDefaults(suiteName: "com.herd.tests.invitation-replace.\(UUID().uuidString)")
        )
        let eventStore = EventStore(defaults: defaults, apiClient: client)
        eventStore.activate(userID: "replacement-account")
        let keychain = PendingInvitationKeychainStore(
            service: "com.herd.tests.invitation-replace.\(UUID().uuidString)"
        )
        defer { try? keychain.delete() }
        let coordinator = InvitationCoordinator(
            trustedWebOrigin: URL(string: "https://herd.example")!,
            keychainStore: keychain
        )
        XCTAssertTrue(
            coordinator.accept(
                URL(string: "https://herd.example/invite/\(firstToken)")!
            )
        )
        let firstResolution = Task {
            await coordinator.resolve(using: eventStore, accountID: "replacement-account")
        }
        try await Task.sleep(nanoseconds: 10_000_000)
        XCTAssertTrue(
            coordinator.accept(
                URL(string: "https://herd.example/invite/\(secondToken)")!
            )
        )
        let secondResolution = Task {
            await coordinator.resolve(using: eventStore, accountID: "replacement-account")
        }

        await firstResolution.value
        await secondResolution.value

        XCTAssertEqual(coordinator.pendingToken, secondToken)
        XCTAssertEqual(coordinator.loadedEventID, secondEventID)
        XCTAssertNotEqual(coordinator.loadedEventID, firstEventID)
    }

    func testAccountSwitchSupersedesAnOlderWrongAccountRequest() async throws {
        let token = "Account_switch-token-123"
        let eventID = UUID()
        InvitationMockURLProtocol.install { request in
            switch request.value(forHTTPHeaderField: "Authorization") {
            case "Bearer wrong-account-token":
                Thread.sleep(forTimeInterval: 0.08)
                return try Self.jsonResponse(
                    request,
                    status: 403,
                    object: [
                        "error": [
                            "code": "invite_for_different_account",
                            "message": "This invitation belongs to a different phone number.",
                        ],
                    ]
                )
            case "Bearer correct-account-token":
                return try Self.jsonResponse(
                    request,
                    object: Self.invitationResponse(eventID: eventID, token: token)
                )
            default:
                XCTFail("Unexpected account authorization")
                return try Self.jsonResponse(request, status: 401, object: [:])
            }
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )
        await client.setAccessToken("wrong-account-token")
        let defaults = try XCTUnwrap(
            UserDefaults(suiteName: "com.herd.tests.invitation-account-race.\(UUID().uuidString)")
        )
        let eventStore = EventStore(defaults: defaults, apiClient: client)
        eventStore.activate(userID: "wrong-account")
        let keychain = PendingInvitationKeychainStore(
            service: "com.herd.tests.invitation-account-race.\(UUID().uuidString)"
        )
        defer { try? keychain.delete() }
        let coordinator = InvitationCoordinator(
            trustedWebOrigin: URL(string: "https://herd.example")!,
            keychainStore: keychain
        )
        XCTAssertTrue(
            coordinator.accept(URL(string: "https://herd.example/invite/\(token)")!)
        )
        let oldAccountResolution = Task {
            await coordinator.resolve(using: eventStore, accountID: "wrong-account")
        }
        try await Task.sleep(nanoseconds: 10_000_000)

        coordinator.prepareForAccountSwitch()
        eventStore.activate(userID: "correct-account")
        await client.setAccessToken("correct-account-token")
        let correctAccountResolution = Task {
            await coordinator.resolve(using: eventStore, accountID: "correct-account")
        }

        await oldAccountResolution.value
        await correctAccountResolution.value

        XCTAssertEqual(coordinator.pendingToken, token)
        XCTAssertEqual(coordinator.loadedEventID, eventID)
        XCTAssertFalse(coordinator.requiresAccountSwitch)
        XCTAssertEqual(eventStore.events.map(\.id), [eventID])
    }

    private static func mockSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [InvitationMockURLProtocol.self]
        return URLSession(configuration: configuration)
    }

    private static func requestBody(_ request: URLRequest) throws -> Data {
        if let body = request.httpBody { return body }
        let stream = try XCTUnwrap(request.httpBodyStream)
        stream.open()
        defer { stream.close() }

        var body = Data()
        var buffer = [UInt8](repeating: 0, count: 4_096)
        while true {
            let count = stream.read(&buffer, maxLength: buffer.count)
            if count == 0 { return body }
            if count < 0 { throw try XCTUnwrap(stream.streamError) }
            body.append(buffer, count: count)
        }
    }

    private static func jsonResponse(
        _ request: URLRequest,
        status: Int = 200,
        object: [String: Any]
    ) throws -> (HTTPURLResponse, Data) {
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
        )
        return (response, try JSONSerialization.data(withJSONObject: object))
    }

    private static func invitationResponse(eventID: UUID, token: String) -> [String: Any] {
        [
            "event": [
                "id": eventID.uuidString.lowercased(),
                "title": "Linked invitation",
                "eventDate": "2026-08-20T18:00:00.000Z",
                "endDate": "2026-08-20T20:00:00.000Z",
                "hostName": "Host",
                "locationName": "Park",
                "locationAddress": "San Francisco",
                "invitees": [],
                "minimumParticipants": 2,
                "requiredGroups": [],
                "rsvpDeadline": "2026-08-10T18:00:00.000Z",
                "eventDescription": "Exact linked event",
                "createdAt": "2026-08-01T18:00:00.000Z",
                "invitationsSent": true,
                "role": "invitee",
                "inviteToken": token,
                "hasResponse": false,
            ],
        ]
    }
}

private final class InvitationMockURLProtocol: URLProtocol, @unchecked Sendable {
    nonisolated(unsafe) private static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?
    private static let lock = NSLock()

    static func install(
        _ handler: @escaping (URLRequest) throws -> (HTTPURLResponse, Data)
    ) {
        lock.lock()
        self.handler = handler
        lock.unlock()
    }

    static func reset() {
        lock.lock()
        handler = nil
        lock.unlock()
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        Self.lock.lock()
        let handler = Self.handler
        Self.lock.unlock()
        do {
            let (response, data) = try XCTUnwrap(handler)(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}
