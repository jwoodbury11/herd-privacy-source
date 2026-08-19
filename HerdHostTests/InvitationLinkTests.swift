import CryptoKit
import Foundation
import Security
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

    func testAuthenticationThrottleParsesTheExactRetryTime() async {
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(request.url?.path, "/api/auth/request-code")
            return try Self.jsonResponse(
                request,
                status: 429,
                object: [
                    "error": [
                        "code": "code_request_throttled",
                        "message": "Please wait before requesting another code.",
                        "details": ["retryAt": "2026-08-13T21:01:46.715Z"],
                    ],
                ]
            )
        }
        let client = APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: Self.mockSession()
        )

        do {
            _ = try await client.requestCode(phoneNumber: "2")
            XCTFail("Expected the throttled request to fail.")
        } catch let APIError.codeRequestThrottled(message, retryAt) {
            XCTAssertEqual(message, "Please wait before requesting another code.")
            XCTAssertEqual(retryAt.timeIntervalSince1970, 1_786_654_906.715, accuracy: 0.001)
        } catch {
            XCTFail("Expected codeRequestThrottled, got \(error)")
        }
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

@MainActor
final class AuthStoreRecoveryTests: XCTestCase {
    override func tearDown() {
        InvitationMockURLProtocol.reset()
        super.tearDown()
    }

    func testAllNineBypassAccountsSurviveSequentialSwitchesAndExpirationRace() async throws {
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(request.url?.path, "/api/auth/request-code")
            let body = try Self.requestBody(request)
            let object = try XCTUnwrap(
                JSONSerialization.jsonObject(with: body) as? [String: Any]
            )
            let alias = try XCTUnwrap(object["phoneNumber"] as? String)
            XCTAssertTrue((1...9).map(String.init).contains(alias))
            XCTAssertNil(object["inviteToken"] as? String)
            return try Self.jsonResponse(
                request,
                object: Self.sessionObject(alias: alias)
            )
        }

        let sessionService = "com.herd.tests.auth.aliases.\(UUID().uuidString.lowercased())"
        let keyService = "com.herd.tests.auth.aliases.keys.\(UUID().uuidString.lowercased())"
        let sessionStore = KeychainSessionStore(service: sessionService)
        defer { try? sessionStore.delete() }
        let store = AuthStore(
            apiClient: Self.client(),
            sessionStore: sessionStore,
            accountKeyStore: AccountKeyStore(service: keyService)
        )

        for alias in (1...8).map(String.init) {
            let loggedIn = await store.requestCode(phoneNumber: alias)
            XCTAssertTrue(loggedIn, alias)
            XCTAssertTrue(store.isAuthenticated, alias)
            XCTAssertEqual(store.user?.id, "test-account-\(alias)", alias)
            XCTAssertEqual(store.user?.phoneNumber, "+1415555010\(alias)", alias)
            XCTAssertEqual(try sessionStore.load()?.accessToken, "access-token-\(alias)", alias)
        }

        store.expireSession()
        XCTAssertFalse(store.isAuthenticated)
        let finalLogin = await store.requestCode(phoneNumber: "9")
        XCTAssertTrue(finalLogin)
        for _ in 0..<10 { await Task.yield() }

        XCTAssertTrue(store.isAuthenticated)
        XCTAssertEqual(store.user?.id, "test-account-9")
        XCTAssertEqual(store.user?.phoneNumber, "+14155550109")
        XCTAssertEqual(try sessionStore.load()?.accessToken, "access-token-9")
        XCTAssertNil(store.challenge)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isBusy)
    }

    func testFormattedNumberChallengeRejectsMalformedCodeThenCommitsVerifiedSession() async throws {
        let challengeID = "personal-number-challenge"
        InvitationMockURLProtocol.install { request in
            switch request.url?.path {
            case "/api/auth/request-code":
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                XCTAssertEqual(object["phoneNumber"] as? String, "+14155550123")
                return try Self.jsonResponse(
                    request,
                    status: 201,
                    object: [
                        "challengeId": challengeID,
                        "phoneNumber": "+14155550123",
                        "expiresAt": "2030-08-13T18:10:00.000Z",
                        "resendAt": "2020-08-13T18:00:00.000Z",
                    ]
                )
            case "/api/auth/verify-code":
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                XCTAssertEqual(object["challengeId"] as? String, challengeID)
                XCTAssertEqual(object["code"] as? String, "1234")
                return try Self.jsonResponse(
                    request,
                    object: Self.sessionObject(
                        alias: "personal",
                        phoneNumber: "+14155550123"
                    )
                )
            default:
                XCTFail("Unexpected authentication request: \(request.url?.path ?? "nil")")
                return try Self.jsonResponse(request, status: 404, object: [:])
            }
        }

        let sessionService = "com.herd.tests.auth.personal.\(UUID().uuidString.lowercased())"
        let sessionStore = KeychainSessionStore(service: sessionService)
        defer { try? sessionStore.delete() }
        let store = AuthStore(
            apiClient: Self.client(),
            sessionStore: sessionStore,
            accountKeyStore: AccountKeyStore(
                service: "com.herd.tests.auth.personal.keys.\(UUID().uuidString.lowercased())"
            )
        )

        let requested = await store.requestCode(phoneNumber: "415-555-0123")
        XCTAssertTrue(requested)
        XCTAssertEqual(store.challenge?.challengeId, challengeID)
        let malformedVerified = await store.verifyCode("12-3")
        XCTAssertFalse(malformedVerified)
        XCTAssertEqual(store.errorMessage, "Enter all four digits to continue.")
        let verified = await store.verifyCode("1 2-3 4")
        XCTAssertTrue(verified)

        XCTAssertTrue(store.isAuthenticated)
        XCTAssertEqual(store.user?.phoneNumber, "+14155550123")
        XCTAssertNil(store.challenge)
        XCTAssertNil(store.errorMessage)
        XCTAssertEqual(try sessionStore.load()?.accessToken, "access-token-personal")
    }

    func testSessionPersistenceFailureRollsBackAndNextLoginSelfHeals() async throws {
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(request.url?.path, "/api/auth/request-code")
            return try Self.jsonResponse(
                request,
                object: Self.sessionObject(alias: "1")
            )
        }
        let sessionStore = FailOnceSessionStore()
        let store = AuthStore(
            apiClient: Self.client(),
            sessionStore: sessionStore,
            accountKeyStore: AccountKeyStore(
                service: "com.herd.tests.auth.failure.keys.\(UUID().uuidString.lowercased())"
            )
        )

        let firstLogin = await store.requestCode(phoneNumber: "1")
        XCTAssertFalse(firstLogin)
        XCTAssertFalse(store.isAuthenticated)
        XCTAssertNil(store.user)
        XCTAssertNil(sessionStore.savedSession)
        XCTAssertNotNil(store.errorMessage)

        let retryLogin = await store.requestCode(phoneNumber: "1")
        XCTAssertTrue(retryLogin)
        XCTAssertTrue(store.isAuthenticated)
        XCTAssertEqual(store.user?.id, "test-account-1")
        XCTAssertEqual(sessionStore.savedSession?.accessToken, "access-token-1")
        XCTAssertNil(store.errorMessage)
    }

    private static func client() -> APIClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [InvitationMockURLProtocol.self]
        return APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: URLSession(configuration: configuration)
        )
    }

    private static func sessionObject(
        alias: String,
        phoneNumber: String? = nil
    ) -> [String: Any] {
        [
            "user": [
                "id": "test-account-\(alias)",
                "phoneNumber": phoneNumber ?? "+1415555010\(alias)",
                "name": "Test Account \(alias)",
                "address": "",
            ],
            "accessToken": "access-token-\(alias)",
            "expiresAt": "2030-08-13T18:00:00.000Z",
            "accountKeyEpochId": NSNull(),
        ]
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
}

private final class FailOnceSessionStore: SessionStoring, @unchecked Sendable {
    private let lock = NSLock()
    private var remainingSaveFailures = 1
    private var session: AuthSession?

    var savedSession: AuthSession? {
        lock.lock()
        defer { lock.unlock() }
        return session
    }

    func load() throws -> AuthSession? {
        savedSession
    }

    func save(_ session: AuthSession) throws {
        lock.lock()
        defer { lock.unlock() }
        if remainingSaveFailures > 0 {
            remainingSaveFailures -= 1
            throw NSError(
                domain: "AuthStoreRecoveryTests",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "Injected session persistence failure."]
            )
        }
        self.session = session
    }

    func delete() throws {
        lock.lock()
        session = nil
        lock.unlock()
    }
}

@MainActor
final class EventStoreRecoveryTests: XCTestCase {
    override func tearDown() {
        InvitationMockURLProtocol.reset()
        super.tearDown()
    }


    func testOpeningInvitationReconcilesPrivateReplyMetadataWhenEventProjectionIsStale() async throws {
        let eventID = UUID()
        let token = "Recovery_stale-projection-token-123"
        let epochID = UUID(uuidString: "80000000-0000-4000-8000-000000000008")!
        let storedEnvelope: [String: Any] = [
            "protocolVersion": 1,
            "cipherSuite": PrivateResponseProtocol.cipherSuite,
            "envelopeId": UUID().uuidString.lowercased(),
            "eventId": eventID.uuidString.lowercased(),
            "inviteeId": "30000000-0000-4000-8000-000000000003",
            "policyHash": String(repeating: "b", count: 64),
            "revision": 1,
            "accountKeyEpochId": epochID.uuidString.lowercased(),
            "evaluatorKeyId": "test-evaluator",
            "payloadCiphertext": "fixture-payload",
            "userKeyWrap": "fixture-user-wrap",
            "evaluatorKeyWrap": "fixture-evaluator-wrap",
            "responseSigningPublicKey": "fixture-signing-key",
            "responseSignature": "fixture-signature",
            "ciphertextHash": "fixture-ciphertext-hash",
            "createdAt": "2026-08-13T18:00:01.000Z",
            "updatedAt": "2026-08-13T18:00:01.000Z",
        ]
        InvitationMockURLProtocol.install { request in
            var response = Self.privateInvitationResponse(
                eventID: eventID,
                token: token,
                storedEnvelope: storedEnvelope,
                certificationStatus: "certified"
            )
            var event = response["event"] as! [String: Any]
            event["hasResponse"] = false
            event.removeValue(forKey: "responseRevision")
            event.removeValue(forKey: "responseCertificationStatus")
            response["event"] = event
            var inviteMetadata = response["inviteMetadata"] as! [String: Any]
            inviteMetadata.removeValue(forKey: "hasResponse")
            response["inviteMetadata"] = inviteMetadata
            return try Self.jsonResponse(request, object: response)
        }
        let client = Self.client()
        await client.setAccessToken("recovery-stale-projection-token")
        let store = EventStore(
            defaults: try Self.defaults("stale-private-reply-projection"),
            apiClient: client,
            accountKeyStore: AccountKeyStore(
                service: "com.herd.tests.recovery.projection.\(UUID().uuidString.lowercased())"
            )
        )
        store.activate(userID: "recovery-stale-projection-account")

        let outcome = await store.openInvitation(inviteToken: token)

        XCTAssertEqual(outcome, .loaded(eventID))
        let event = try XCTUnwrap(store.events.first)
        XCTAssertTrue(event.hasResponse)
        XCTAssertEqual(event.responseRevision, 1)
        XCTAssertEqual(event.responseCertificationStatus, .certified)
    }

    func testUnreadableSavedReplyBecomesActionableWithoutExposingProtocolFailure() async throws {
        let eventID = UUID()
        let token = "Recovery_unreadable-saved-reply-token-123"
        let epochID = UUID(uuidString: "80000000-0000-4000-8000-000000000008")!
        let userID = "recovery-unreadable-saved-reply-account"
        let keyStore = AccountKeyStore(
            service: "com.herd.tests.recovery.unreadable.\(UUID().uuidString.lowercased())"
        )
        let rootSecret = try await keyStore.createRootSecret(userID: userID, epochID: epochID)
        let commitment = await keyStore.commitment(for: rootSecret)
        let storedEnvelope: [String: Any] = [
            "protocolVersion": PrivateResponseProtocol.version,
            "cipherSuite": PrivateResponseProtocol.cipherSuite,
            "envelopeId": UUID().uuidString.lowercased(),
            "eventId": eventID.uuidString.lowercased(),
            "inviteeId": "30000000-0000-4000-8000-000000000003",
            "policyHash": String(repeating: "b", count: 64),
            "revision": 1,
            "accountKeyEpochId": epochID.uuidString.lowercased(),
            "evaluatorKeyId": "test-evaluator",
            "payloadCiphertext": "fixture-payload",
            "userKeyWrap": "fixture-user-wrap",
            "evaluatorKeyWrap": "fixture-evaluator-wrap",
            "responseSigningPublicKey": "fixture-signing-key",
            "responseSignature": "fixture-signature",
            "ciphertextHash": "fixture-ciphertext-hash",
            "createdAt": "2026-08-13T18:00:01.000Z",
            "updatedAt": "2026-08-13T18:00:01.000Z",
        ]
        InvitationMockURLProtocol.install { request in
            try Self.jsonResponse(
                request,
                object: Self.privateInvitationResponse(
                    eventID: eventID,
                    token: token,
                    epochID: epochID,
                    commitment: commitment,
                    storedEnvelope: storedEnvelope,
                    certificationStatus: "certified"
                )
            )
        }
        let client = Self.client()
        await client.setAccessToken("recovery-unreadable-saved-reply-token")
        let dependencies = EventStorePrivateResponseDependencies(
            makeCrypto: {
                throw PrivateResponseCryptoError.invalidEnvelope(
                    "This private reply uses an unsupported policy or cipher suite."
                )
            },
            verifyAttestation: { _, _, _ in },
            verifyReceipt: { _ in },
            verifyPublication: { _, _ in }
        )
        let store = EventStore(
            defaults: try Self.defaults("unreadable-saved-reply"),
            apiClient: client,
            accountKeyStore: keyStore,
            privateResponseDependencies: dependencies
        )
        store.activate(userID: userID)

        let outcome = await store.openInvitation(inviteToken: token)
        XCTAssertEqual(outcome, .loaded(eventID))
        let event = try XCTUnwrap(store.events.first)

        let unlocked = await store.unlockPrivateResponse(for: event)

        XCTAssertFalse(unlocked)
        XCTAssertEqual(store.unavailablePrivateResponseEventID, eventID)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isMutating)
        XCTAssertNil(store.unlockedDrafts[eventID])
    }

    func testOnlyUnreadableSavedReplyFailuresOfferReplacement() {
        XCTAssertEqual(
            EventStore.savedReplyReplacementErrorCode(
                for: .invalidEnvelope("mismatched envelope")
            ),
            "saved_reply_invalid_envelope"
        )
        XCTAssertEqual(
            EventStore.savedReplyReplacementErrorCode(for: .invalidDraft("invalid draft")),
            "saved_reply_invalid_draft"
        )
        XCTAssertEqual(
            EventStore.savedReplyReplacementErrorCode(for: .decryptionFailed),
            "saved_reply_decryption_failed"
        )
        XCTAssertNil(
            EventStore.savedReplyReplacementErrorCode(for: .invalidPolicy("untrusted policy"))
        )
        XCTAssertNil(
            EventStore.savedReplyReplacementErrorCode(for: .untrustedEvaluator)
        )
        XCTAssertNil(
            EventStore.savedReplyReplacementErrorCode(for: .invalidReceipt("bad receipt"))
        )
        XCTAssertEqual(
            EventStore.savedReplyBlockedErrorCode(for: .invalidPolicy("untrusted policy")),
            "saved_reply_invalid_policy"
        )
        XCTAssertEqual(
            EventStore.savedReplyBlockedErrorCode(for: .untrustedEvaluator),
            "saved_reply_untrusted_evaluator"
        )
        XCTAssertEqual(
            EventStore.savedReplyBlockedErrorCode(for: .invalidReceipt("bad receipt")),
            "saved_reply_invalid_receipt"
        )
    }


    func testDelayedOldAccountReplyCannotContaminateNewAccountState() async throws {
        let eventID = UUID()
        let token = "Recovery_stale-account-token-123"
        let shouldDelay = LockedFlag()
        InvitationMockURLProtocol.install { request in
            if shouldDelay.value {
                Thread.sleep(forTimeInterval: 0.08)
            }
            return try Self.jsonResponse(
                request,
                object: Self.privateInvitationResponse(eventID: eventID, token: token)
            )
        }
        let client = Self.client()
        await client.setAccessToken("old-account-token")
        let store = EventStore(
            defaults: try Self.defaults("stale-account"),
            apiClient: client,
            accountKeyStore: AccountKeyStore(
                service: "com.herd.tests.recovery.stale.\(UUID().uuidString.lowercased())"
            )
        )
        store.activate(userID: "old-account")
        let openOutcome = await store.openInvitation(inviteToken: token)
        XCTAssertEqual(openOutcome, .loaded(eventID))
        let oldEvent = try XCTUnwrap(store.events.first)
        shouldDelay.set()

        let staleReply = Task {
            await store.respond(to: oldEvent, with: .cantCommit)
        }
        try await Task.sleep(nanoseconds: 10_000_000)
        store.activate(userID: "new-account")

        let staleReplySaved = await staleReply.value
        XCTAssertFalse(staleReplySaved)
        XCTAssertTrue(store.events.isEmpty)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isMutating)
        let diagnostics = await store.accountKeyDiagnostics()
        XCTAssertTrue(diagnostics.isEmpty)
    }

    func testUnauthorizedRecoveryClearsSensitiveStateAndNotifiesAuthentication() async throws {
        let eventID = UUID()
        let token = "Recovery_unauthorized-token-123"
        InvitationMockURLProtocol.install { request in
            try Self.jsonResponse(
                request,
                object: Self.privateInvitationResponse(eventID: eventID, token: token)
            )
        }
        let client = Self.client()
        await client.setAccessToken("expired-account-token")
        let store = EventStore(
            defaults: try Self.defaults("unauthorized"),
            apiClient: client,
            accountKeyStore: AccountKeyStore(
                service: "com.herd.tests.recovery.unauthorized.\(UUID().uuidString.lowercased())"
            )
        )
        store.activate(userID: "expired-account")
        let openOutcome = await store.openInvitation(inviteToken: token)
        XCTAssertEqual(openOutcome, .loaded(eventID))
        let event = try XCTUnwrap(store.events.first)
        var didRequestAuthentication = false
        store.setUnauthorizedHandler { didRequestAuthentication = true }
        InvitationMockURLProtocol.install { request in
            try Self.jsonResponse(request, status: 401, object: [
                "error": ["code": "unauthorized", "message": "Sign in again."],
            ])
        }

        let responseSaved = await store.respond(to: event, with: .cantCommit)
        XCTAssertFalse(responseSaved)
        XCTAssertTrue(didRequestAuthentication)
        XCTAssertTrue(store.events.isEmpty)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isMutating)
        let diagnostics = await store.accountKeyDiagnostics()
        XCTAssertTrue(diagnostics.isEmpty)
    }

    private static func client() -> APIClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [InvitationMockURLProtocol.self]
        let session = URLSession(configuration: configuration)
        return APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: session,
            evaluatorURLSession: session
        )
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

    private static func defaults(_ name: String) throws -> UserDefaults {
        try XCTUnwrap(
            UserDefaults(
                suiteName: "com.herd.tests.recovery.\(name).\(UUID().uuidString.lowercased())"
            )
        )
    }

    private static func keychainItemCount(service: String) throws -> Int {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return 0 }
        guard status == errSecSuccess else {
            throw AccountKeyStoreError.keychain(status)
        }
        return (result as? [[String: Any]])?.count ?? 0
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

    private static func privateInvitationResponse(
        eventID: UUID,
        token: String,
        epochID: UUID = UUID(uuidString: "80000000-0000-4000-8000-000000000008")!,
        commitment: String? = String(repeating: "a", count: 64),
        policy: [String: Any]? = nil,
        storedEnvelope: [String: Any]? = nil,
        certificationStatus: String? = nil
    ) -> [String: Any] {
        let policy = policy ?? [
            "protocolVersion": 1,
            "cipherSuite": "HERD-X25519-HKDF-SHA256-AES-256-GCM-v1",
            "policyHash": String(repeating: "b", count: 64),
            "canonicalDocument": "{\"fixture\":true}",
            "evaluatorKeyId": "test-evaluator",
            "evaluatorPublicKey": "test-public-key",
            "evaluatorMeasurement": "test-measurement",
            "releaseId": "test-release",
            "paddedPlaintextBytes": 4096,
            "frozenAt": "2026-08-01T18:00:00.000Z",
        ]
        var event: [String: Any] = [
            "id": eventID.uuidString.lowercased(),
            "title": "Recovery invitation",
            "eventDate": "2026-08-20T18:00:00.000Z",
            "endDate": "2026-08-20T20:00:00.000Z",
            "hostName": "Host",
            "locationName": "Park",
            "locationAddress": "San Francisco",
            "invitees": [[
                "id": "30000000-0000-4000-8000-000000000003",
                "displayName": "Recovery Invitee",
                "phoneNumber": "+14155550123",
                "isCurrentUser": true,
            ]],
            "minimumParticipants": 2,
            "requiredGroups": [],
            "rsvpDeadline": "2026-08-19T18:00:00.000Z",
            "eventDescription": "Cross-device recovery fixture",
            "createdAt": "2026-08-01T18:00:00.000Z",
            "invitationsSent": true,
            "role": "invitee",
            "inviteToken": token,
            "hasResponse": false,
            "accountKeyEpochId": epochID.uuidString.lowercased(),
            "accountKeyCommitment": (commitment as Any?) ?? NSNull(),
            "privateResponsePolicy": policy,
            "resolution": ["status": "pending", "retrying": false],
        ]
        var inviteMetadata: [String: Any] = [
            "id": "30000000-0000-4000-8000-000000000003",
            "accountKeyEpochId": epochID.uuidString.lowercased(),
            "accountKeyCommitment": (commitment as Any?) ?? NSNull(),
            "hasResponse": false,
        ]
        if let storedEnvelope {
            let revision = storedEnvelope["revision"] as? Int ?? 1
            event["hasResponse"] = true
            event["responseRevision"] = revision
            event["responseCertificationStatus"] = certificationStatus ?? "pending"
            inviteMetadata["hasResponse"] = true
            inviteMetadata["responseRevision"] = revision
            inviteMetadata["responseCertificationStatus"] = certificationStatus ?? "pending"
            inviteMetadata["responseEnvelope"] = storedEnvelope
        }
        return [
            "event": event,
            "inviteMetadata": inviteMetadata,
        ]
    }

    private static let transparencyProof: [String: Any] = [
        "protocolVersion": 1,
        "logId": "native-recovery-log-v1",
        "logIndex": 1,
        "previousEntryHash": String(repeating: "0", count: 43),
        "entryHash": String(repeating: "1", count: 43),
        "signingKeyId": "native-recovery-transparency-v1",
        "receiptSignature": String(repeating: "2", count: 86),
        "logHead": [
            "protocolVersion": 1,
            "logId": "native-recovery-log-v1",
            "treeSize": 1,
            "headEntryHash": String(repeating: "1", count: 43),
            "generatedAt": "2026-08-13T18:00:01.000Z",
            "signingKeyId": "native-recovery-transparency-v1",
            "signature": String(repeating: "3", count: 86),
        ],
    ]

    private static let transparencyLog: [String: Any] = [
        "protocolVersion": 1,
        "logId": "native-recovery-log-v1",
        "entries": [[
            "logIndex": 1,
            "previousEntryHash": String(repeating: "0", count: 43),
            "entryHash": String(repeating: "1", count: 43),
            "head": [
                "protocolVersion": 1,
                "logId": "native-recovery-log-v1",
                "treeSize": 1,
                "headEntryHash": String(repeating: "1", count: 43),
                "generatedAt": "2026-08-13T18:00:01.000Z",
                "signingKeyId": "native-recovery-transparency-v1",
                "signature": String(repeating: "3", count: 86),
            ],
        ]],
    ]
}

private final class LockedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var isSet = false

    var value: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isSet
    }

    func set() {
        lock.lock()
        isSet = true
        lock.unlock()
    }
}

@MainActor
final class SimplifiedBallotAPIClientTests: XCTestCase {
    override func tearDown() {
        InvitationMockURLProtocol.reset()
        super.tearDown()
    }

    func testBallotRoundTripsAcrossIndependentAuthenticatedClients() async throws {
        let token = "Account_wide-ballot-token-123"
        let ballotID = String(repeating: "A", count: 43)
        let memberID = UUID()
        let response: [String: Any] = [
            "ballot": [
                "protocolVersion": 2,
                "ballotId": ballotID,
                "revision": 1,
                "response": "going",
                "minimumParticipants": 2,
                "requiredGroups": [[
                    "id": "friends",
                    "memberIDs": [memberID.uuidString.lowercased()],
                ]],
                "createdAt": "2026-08-18T20:00:00.000Z",
            ],
        ]
        let submitted = expectation(description: "account-wide ballot submitted")
        InvitationMockURLProtocol.install { request in
            XCTAssertEqual(request.url?.path, "/api/invites/\(token)/ballot")
            XCTAssertEqual(request.value(forHTTPHeaderField: "Authorization"), "Bearer account-session")
            if request.httpMethod == "PUT" {
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                XCTAssertEqual(object["response"] as? String, "going")
                XCTAssertEqual(object["minimumParticipants"] as? Int, 2)
                let serialized = String(decoding: body, as: UTF8.self)
                XCTAssertFalse(serialized.localizedCaseInsensitiveContains("phone"))
                XCTAssertFalse(serialized.localizedCaseInsensitiveContains("account"))
                XCTAssertFalse(serialized.localizedCaseInsensitiveContains("invitee"))
                submitted.fulfill()
            } else {
                XCTAssertEqual(request.httpMethod, "GET")
            }
            return try Self.jsonResponse(request, object: response)
        }

        let first = Self.client()
        await first.setAccessToken("account-session")
        let draft = PrivateResponseDraft(
            response: .going,
            minimumParticipants: 2,
            requiredGroups: [RSVPConditionGroup(id: "friends", memberIDs: [memberID])]
        )
        let saved = try await first.submitSimplifiedBallot(inviteToken: token, draft: draft)
        await fulfillment(of: [submitted], timeout: 1)
        XCTAssertEqual(saved.ballotId, ballotID)
        XCTAssertEqual(saved.requiredGroups, draft.requiredGroups)

        let second = Self.client()
        await second.setAccessToken("account-session")
        let reopened = try await second.fetchSimplifiedBallot(inviteToken: token)
        XCTAssertEqual(reopened, saved)
    }

    private static func client() -> APIClient {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [InvitationMockURLProtocol.self]
        return APIClient(
            baseURL: URL(string: "https://herd.example")!,
            urlSession: URLSession(configuration: configuration)
        )
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
        object: [String: Any]
    ) throws -> (HTTPURLResponse, Data) {
        let response = try XCTUnwrap(
            HTTPURLResponse(
                url: try XCTUnwrap(request.url),
                statusCode: 200,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/json"]
            )
        )
        return (response, try JSONSerialization.data(withJSONObject: object))
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
