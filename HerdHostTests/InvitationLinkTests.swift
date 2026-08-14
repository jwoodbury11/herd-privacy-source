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

    func testAuthenticationThrottleShowsTheExactRetryTime() async {
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
        } catch {
            XCTAssertTrue(
                error.localizedDescription.hasPrefix(
                    "Please wait before requesting another code. Try again at "
                )
            )
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

    func testForeignAccountKeyStagesCancelableAndRepeatableDeviceSwitch() async throws {
        let eventID = UUID()
        let token = "Recovery_device-switch-token-123"
        InvitationMockURLProtocol.install { request in
            try Self.jsonResponse(
                request,
                object: Self.privateInvitationResponse(eventID: eventID, token: token)
            )
        }
        let client = Self.client()
        await client.setAccessToken("recovery-access-token")
        let defaults = try Self.defaults("device-switch")
        let keyStore = AccountKeyStore(
            service: "com.herd.tests.recovery.keys.\(UUID().uuidString.lowercased())"
        )
        let store = EventStore(
            defaults: defaults,
            apiClient: client,
            accountKeyStore: keyStore
        )
        store.activate(userID: "recovery-account")

        let openOutcome = await store.openInvitation(inviteToken: token)
        XCTAssertEqual(openOutcome, .loaded(eventID))
        let event = try XCTUnwrap(store.events.first)
        let draft = PrivateResponseDraft(
            response: .cantCommit,
            minimumParticipants: nil,
            requiredGroups: []
        )

        let firstResponseSaved = await store.respond(to: event, draft: draft)
        XCTAssertFalse(firstResponseSaved)
        XCTAssertEqual(store.deviceSwitchEventID, eventID)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isMutating)
        let diagnostics = await store.accountKeyDiagnostics()
        XCTAssertEqual(diagnostics.count, 1)
        XCTAssertTrue(diagnostics[0].requiresRecovery)
        XCTAssertFalse(diagnostics[0].isAvailableOnDevice)

        store.cancelDeviceSwitch()
        XCTAssertNil(store.deviceSwitchEventID)
        let canceledSwitchCompleted = await store.switchPrivateRepliesToThisDevice(for: eventID)
        XCTAssertFalse(canceledSwitchCompleted)

        let secondResponseSaved = await store.respond(to: event, draft: draft)
        XCTAssertFalse(secondResponseSaved)
        XCTAssertEqual(store.deviceSwitchEventID, eventID)
        store.cancelDeviceSwitch()
        XCTAssertNil(store.deviceSwitchEventID)
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

    func testDeviceSwitchCompletesResetReencryptionCertificationAndLocalUnlock() async throws {
        try await verifyDeviceSwitchTransaction(failingOnceAt: nil)
    }

    func testDeviceSwitchSelfHealsAfterEveryRecoveryBoundaryFailure() async throws {
        for path in [
            "/api/account/key-epoch/reset",
            "/api/account/key-epoch/initialize",
            "/api/trust/evaluator-attestation",
            "/api/invites/recovery/rsvp",
            "/api/transparency/responses",
        ] {
            try await verifyDeviceSwitchTransaction(failingOnceAt: path)
        }
    }

    func testPersistedRSVPSelfHealsAfterTransparencyResponseLossAndRelaunch() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: "/api/transparency/responses",
            relaunchAfterFailure: true
        )
    }

    func testOpeningInvitationSelfHealsPersistedPendingRSVP() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: "/api/transparency/responses",
            relaunchAfterFailure: true,
            recoverPendingCertificationWithRefresh: false
        )
    }

    func testKeyInitializationSelfHealsAfterRelaunch() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: "/api/account/key-epoch/initialize",
            relaunchAfterFailure: true
        )
    }

    func testCommittedKeyResetSelfHealsAfterResponseLossAndRelaunch() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: "/api/account/key-epoch/reset",
            relaunchAfterFailure: true
        )
    }

    func testDevicePasscodeDenialLeavesKeySwitchActionableAndRetrySucceeds() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: nil,
            failKeyReplacementOnce: true
        )
    }

    func testDeviceSwitchReusesFreshlyAuthenticatedKeyForReplacementReply() async throws {
        try await verifyDeviceSwitchTransaction(
            failingOnceAt: nil,
            denyPostReplacementUnlock: true
        )
    }

    private func verifyDeviceSwitchTransaction(
        failingOnceAt failurePath: String?,
        relaunchAfterFailure: Bool = false,
        recoverPendingCertificationWithRefresh: Bool = true,
        failKeyReplacementOnce: Bool = false,
        denyPostReplacementUnlock: Bool = false
    ) async throws {
        let eventID = UUID()
        let inviteeID = UUID(uuidString: "30000000-0000-4000-8000-000000000003")!
        let oldEpochID = UUID(uuidString: "80000000-0000-4000-8000-000000000008")!
        let newEpochID = UUID(uuidString: "90000000-0000-4000-8000-000000000009")!
        let retryEpochID = UUID(uuidString: "a0000000-0000-4000-8000-00000000000a")!
        let token = "Recovery_\(UUID().uuidString.lowercased())"
        let rsvpPath = "/api/invites/\(token)/rsvp"
        let normalizedFailurePath = failurePath == "/api/invites/recovery/rsvp"
            ? rsvpPath
            : failurePath
        let evaluatorKey = P256.KeyAgreement.PrivateKey()
        let policySigningKey = P256.Signing.PrivateKey()
        let pinnedEvaluator = PinnedEvaluator(
            keyID: "native-recovery-evaluator-v1",
            publicKey: evaluatorKey.publicKey.x963Representation,
            policySigningKeyID: "native-recovery-policy-v1",
            policySigningPublicKey: policySigningKey.publicKey.x963Representation
        )
        let crypto = PrivateResponseCrypto(pinnedEvaluator: pinnedEvaluator)
        let canonicalPolicy = "{\"fixture\":\"native-device-switch\"}"
        let policyHash = Data(SHA256.hash(data: Data(canonicalPolicy.utf8)))
            .base64URLEncodedString()
        let policySignature = try policySigningKey.signature(
            for: concatenate(
                Data("HERD-POLICY-DESCRIPTOR-SIGNATURE-V1".utf8),
                Data([0]),
                Data(canonicalPolicy.utf8)
            )
        ).rawRepresentation.base64URLEncodedString()
        let policy: [String: Any] = [
            "protocolVersion": PrivateResponseProtocol.version,
            "cipherSuite": PrivateResponseProtocol.cipherSuite,
            "policyHash": policyHash,
            "canonicalDocument": canonicalPolicy,
            "evaluatorKeyId": pinnedEvaluator.keyID,
            "evaluatorPublicKey": pinnedEvaluator.publicKey.base64URLEncodedString(),
            "evaluatorMeasurement": "native-recovery-measurement-v1",
            "releaseId": "native-recovery-release-v1",
            "paddedPlaintextBytes": PrivateResponseProtocol.paddedPlaintextBytes,
            "frozenAt": "2026-08-01T18:00:00.000Z",
            "policySigningKeyId": pinnedEvaluator.policySigningKeyID,
            "policySignature": policySignature,
        ]
        let transaction = RecoveryTransactionState(
            oldEpochID: oldEpochID,
            resetEpochIDs: [newEpochID, retryEpochID],
            failOnceAt: normalizedFailurePath
        )

        InvitationMockURLProtocol.install { request in
            let path = try XCTUnwrap(request.url?.path)
            switch (request.httpMethod, path) {
            case ("GET", "/api/events"):
                let snapshot = transaction.snapshot()
                let response = Self.privateInvitationResponse(
                    eventID: eventID,
                    token: token,
                    epochID: snapshot.epochID,
                    commitment: snapshot.commitment,
                    policy: policy,
                    storedEnvelope: snapshot.storedEnvelope,
                    certificationStatus: snapshot.certificationStatus
                )
                return try Self.jsonResponse(request, object: [
                    "events": [try XCTUnwrap(response["event"])],
                ])
            case ("GET", "/api/invites/\(token)"):
                let snapshot = transaction.snapshot()
                return try Self.jsonResponse(
                    request,
                    object: Self.privateInvitationResponse(
                        eventID: eventID,
                        token: token,
                        epochID: snapshot.epochID,
                        commitment: snapshot.commitment,
                        policy: policy,
                        storedEnvelope: snapshot.storedEnvelope,
                        certificationStatus: snapshot.certificationStatus
                    )
                )
            case ("POST", "/api/account/key-epoch/reset"):
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                XCTAssertEqual(
                    (object["expectedAccountKeyEpochId"] as? String).flatMap(UUID.init(uuidString:)),
                    transaction.snapshot().epochID
                )
                let resetEpochID = transaction.reset(path: path)
                if transaction.shouldFail(path) {
                    return try Self.jsonResponse(
                        request,
                        status: 503,
                        object: ["error": ["message": "Temporary recovery interruption."]]
                    )
                }
                return try Self.jsonResponse(request, object: [
                    "accountKeyEpochId": resetEpochID.uuidString.lowercased(),
                    "resetAt": "2026-08-13T18:00:00.000Z",
                ])
            case ("POST", "/api/account/key-epoch/initialize"):
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                let commitment = try XCTUnwrap(object["keyCommitment"] as? String)
                XCTAssertEqual(
                    (object["expectedAccountKeyEpochId"] as? String).flatMap(UUID.init(uuidString:)),
                    transaction.snapshot().epochID
                )
                transaction.record(path)
                if transaction.shouldFail(path) {
                    return try Self.jsonResponse(
                        request,
                        status: 503,
                        object: ["error": ["message": "Temporary recovery interruption."]]
                    )
                }
                transaction.initialize(commitment: commitment)
                return try Self.jsonResponse(request, object: [
                    "accountKeyEpochId": transaction.snapshot().epochID.uuidString.lowercased(),
                    "keyCommitment": commitment,
                ])
            case ("POST", "/api/trust/evaluator-attestation"):
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                let nonce = try XCTUnwrap(object["nonce"] as? String)
                transaction.record(path)
                if transaction.shouldFail(path) {
                    return try Self.jsonResponse(
                        request,
                        status: 503,
                        object: ["error": ["message": "Temporary recovery interruption."]]
                    )
                }
                let key: [String: Any] = [
                    "keyId": "fixture-key",
                    "algorithm": "fixture-algorithm",
                    "publicKey": "fixture-public-key",
                ]
                return try Self.jsonResponse(request, object: [
                    "protocolVersion": 1,
                    "tokenType": "fixture",
                    "audience": "fixture",
                    "nonce": nonce,
                    "keyBinding": [
                        "protocolVersion": 1,
                        "releaseId": "native-recovery-release-v1",
                        "keys": [
                            "responseDecryption": key,
                            "evaluationResultSigning": key,
                            "policySigning": key,
                            "transparencySigning": key,
                        ],
                    ],
                    "keyBindingHash": "fixture-hash",
                    "attestationToken": "fixture-token",
                ])
            case ("PUT", "/api/invites/\(token)/rsvp"):
                let body = try Self.requestBody(request)
                let object = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: body) as? [String: Any]
                )
                let envelopeObject = try XCTUnwrap(object["envelope"] as? [String: Any])
                let envelopeData = try JSONSerialization.data(withJSONObject: envelopeObject)
                let envelope = try HerdJSON.makeDecoder().decode(
                    PrivateResponseEnvelopeV1.self,
                    from: envelopeData
                )
                XCTAssertEqual(envelope.eventId, eventID.uuidString.lowercased())
                XCTAssertEqual(envelope.inviteeId, inviteeID.uuidString.lowercased())
                XCTAssertEqual(
                    envelope.accountKeyEpochId,
                    transaction.snapshot().epochID.uuidString.lowercased()
                )
                XCTAssertEqual(envelope.revision, 1)
                transaction.recordEnvelope(envelope.envelopeId, path: path)
                if transaction.shouldFail(path) {
                    return try Self.jsonResponse(
                        request,
                        status: 503,
                        object: ["error": ["message": "Temporary recovery interruption."]]
                    )
                }
                let ciphertextHash = try crypto.envelopeHash(envelope)
                var storedEnvelope = envelopeObject
                storedEnvelope["ciphertextHash"] = ciphertextHash
                storedEnvelope["createdAt"] = "2026-08-13T18:00:01.000Z"
                storedEnvelope["updatedAt"] = "2026-08-13T18:00:01.000Z"
                transaction.storeEnvelope(storedEnvelope)
                return try Self.jsonResponse(request, object: [
                    "responseEnvelope": storedEnvelope,
                    "receipt": [
                        "envelopeId": envelope.envelopeId,
                        "eventId": envelope.eventId,
                        "inviteeId": envelope.inviteeId,
                        "policyHash": envelope.policyHash,
                        "accountKeyEpochId": envelope.accountKeyEpochId,
                        "revision": envelope.revision,
                        "ciphertextHash": ciphertextHash,
                        "responseSigningPublicKey": envelope.responseSigningPublicKey,
                        "responseSignature": envelope.responseSignature,
                        "committedAt": "2026-08-13T18:00:01.000Z",
                        "transparency": Self.transparencyProof,
                    ],
                ])
            case ("GET", "/api/transparency/responses"):
                XCTAssertEqual(request.url?.query, "after=0&limit=1")
                transaction.record(path)
                if transaction.shouldFail(path) {
                    return try Self.jsonResponse(
                        request,
                        status: 503,
                        object: ["error": ["message": "Temporary recovery interruption."]]
                    )
                }
                transaction.certifyStoredEnvelope()
                return try Self.jsonResponse(request, object: Self.transparencyLog)
            default:
                XCTFail("Unexpected recovery request: \(request.httpMethod ?? "nil") \(path)")
                return try Self.jsonResponse(request, status: 404, object: [:])
            }
        }

        let client = Self.client()
        await client.setAccessToken("recovery-success-token")
        let keyService = "com.herd.tests.recovery.success.\(UUID().uuidString.lowercased())"
        let keyStore: any AccountKeyStoring
        if failKeyReplacementOnce {
            keyStore = FailOnceAccountKeyStore(initialEpochID: oldEpochID)
        } else if denyPostReplacementUnlock {
            keyStore = DenyPostReplacementUnlockAccountKeyStore()
        } else {
            let persistentKeyStore = AccountKeyStore(service: keyService)
            _ = try await persistentKeyStore.createRootSecret(
                userID: "recovery-success-account",
                epochID: oldEpochID
            )
            keyStore = persistentKeyStore
        }
        let defaults = try Self.defaults("successful-device-switch")
        let dependencies = EventStorePrivateResponseDependencies(
            makeCrypto: { crypto },
            verifyAttestation: { _, _, _ in },
            verifyReceipt: { _ in },
            verifyPublication: { _, _ in }
        )
        var store = EventStore(
            defaults: defaults,
            apiClient: client,
            accountKeyStore: keyStore,
            privateResponseDependencies: dependencies
        )
        store.activate(userID: "recovery-success-account")
        let openOutcome = await store.openInvitation(inviteToken: token)
        XCTAssertEqual(openOutcome, .loaded(eventID))
        let event = try XCTUnwrap(store.events.first)
        let draft = PrivateResponseDraft(
            response: .going,
            minimumParticipants: 2,
            requiredGroups: []
        )

        let initiallySaved = await store.respond(to: event, draft: draft)
        XCTAssertFalse(initiallySaved)
        XCTAssertEqual(store.deviceSwitchEventID, eventID)
        let firstSwitchCompleted = await store.switchPrivateRepliesToThisDevice(for: eventID)
        if failKeyReplacementOnce {
            XCTAssertFalse(firstSwitchCompleted)
            XCTAssertEqual(
                store.errorMessage,
                "Set a passcode on this iPhone before saving private replies."
            )
            XCTAssertEqual(store.deviceSwitchEventID, eventID)
            let retryCompleted = await store.switchPrivateRepliesToThisDevice(for: eventID)
            XCTAssertTrue(retryCompleted)
        } else if let normalizedFailurePath {
            XCTAssertFalse(firstSwitchCompleted, normalizedFailurePath)
            XCTAssertNotNil(store.errorMessage, normalizedFailurePath)
            if relaunchAfterFailure {
                XCTAssertTrue([
                    "/api/account/key-epoch/reset",
                    "/api/account/key-epoch/initialize",
                    "/api/transparency/responses",
                ].contains(normalizedFailurePath))
                store = EventStore(
                    defaults: defaults,
                    apiClient: client,
                    accountKeyStore: keyStore,
                    privateResponseDependencies: dependencies
                )
                store.activate(userID: "recovery-success-account")
                if normalizedFailurePath == "/api/transparency/responses" {
                    if recoverPendingCertificationWithRefresh {
                        await store.refresh()
                    } else {
                        let reopenOutcome = await store.openInvitation(inviteToken: token)
                        XCTAssertEqual(reopenOutcome, .loaded(eventID))
                    }
                    let relaunchedEvent = try XCTUnwrap(store.events.first)
                    XCTAssertEqual(relaunchedEvent.responseCertificationStatus, .certified)
                    XCTAssertNil(store.errorMessage)
                    XCTAssertEqual(
                        transaction.recordedPaths.filter {
                            $0 == "/api/transparency/responses"
                        }.count,
                        2
                    )
                    let unlocked = await store.unlockPrivateResponse(for: relaunchedEvent)
                    XCTAssertTrue(unlocked, normalizedFailurePath)
                } else {
                    let reopenOutcome = await store.openInvitation(inviteToken: token)
                    XCTAssertEqual(reopenOutcome, .loaded(eventID))
                    let relaunchedEvent = try XCTUnwrap(store.events.first)
                    XCTAssertNil(relaunchedEvent.responseCertificationStatus)
                    let retryCompleted = await store.respond(to: relaunchedEvent, draft: draft)
                    XCTAssertTrue(retryCompleted, normalizedFailurePath)
                }
            } else if [
                "/api/account/key-epoch/reset",
                "/api/account/key-epoch/initialize",
            ].contains(normalizedFailurePath) {
                XCTAssertEqual(store.deviceSwitchEventID, eventID)
                let retryCompleted = await store.switchPrivateRepliesToThisDevice(for: eventID)
                XCTAssertTrue(retryCompleted, normalizedFailurePath)
            } else {
                XCTAssertNil(store.deviceSwitchEventID)
                let retryCompleted = await store.respond(to: event, draft: draft)
                XCTAssertTrue(retryCompleted, normalizedFailurePath)
            }
            let expectedFailurePathAttempts = relaunchAfterFailure
                && normalizedFailurePath == "/api/account/key-epoch/reset" ? 1 : 2
            XCTAssertEqual(
                transaction.recordedPaths.filter { $0 == normalizedFailurePath }.count,
                expectedFailurePathAttempts,
                normalizedFailurePath
            )
            if [rsvpPath, "/api/transparency/responses"].contains(normalizedFailurePath) {
                XCTAssertEqual(transaction.envelopeIDs.count, 2)
                XCTAssertEqual(Set(transaction.envelopeIDs).count, 1)
            }
        } else {
            XCTAssertTrue(firstSwitchCompleted)
        }

        let recoveredEvent = try XCTUnwrap(store.events.first)
        XCTAssertNil(store.deviceSwitchEventID)
        XCTAssertNil(store.errorMessage)
        XCTAssertFalse(store.isSwitchingDevice)
        let finalSnapshot = transaction.snapshot()
        XCTAssertEqual(recoveredEvent.accountKeyEpochId, finalSnapshot.epochID)
        XCTAssertEqual(recoveredEvent.accountKeyCommitment, transaction.snapshot().commitment)
        XCTAssertTrue(recoveredEvent.hasResponse)
        XCTAssertEqual(recoveredEvent.responseRevision, 1)
        XCTAssertEqual(recoveredEvent.responseCertificationStatus, .certified)
        XCTAssertEqual(store.unlockedResponses[eventID], .going)
        XCTAssertEqual(store.unlockedDrafts[eventID], draft)
        let hasOldKey = await keyStore.hasRootSecret(
            userID: "recovery-success-account",
            epochID: oldEpochID
        )
        let hasNewKey = await keyStore.hasRootSecret(
            userID: "recovery-success-account",
            epochID: finalSnapshot.epochID
        )
        XCTAssertFalse(hasOldKey)
        XCTAssertTrue(hasNewKey)
        if !failKeyReplacementOnce && !denyPostReplacementUnlock {
            XCTAssertEqual(try Self.keychainItemCount(service: keyService), 2)
        }
        if finalSnapshot.epochID != newEpochID {
            let hasSupersededRetryKey = await keyStore.hasRootSecret(
                userID: "recovery-success-account",
                epochID: newEpochID
            )
            XCTAssertFalse(hasSupersededRetryKey)
        }
        let diagnostics = await store.accountKeyDiagnostics()
        XCTAssertEqual(diagnostics.count, 1)
        XCTAssertTrue(diagnostics[0].isAvailableOnDevice)
        XCTAssertFalse(diagnostics[0].requiresRecovery)
        if normalizedFailurePath == nil && !failKeyReplacementOnce {
            XCTAssertEqual(transaction.recordedPaths, [
                "/api/account/key-epoch/reset",
                "/api/account/key-epoch/initialize",
                "/api/trust/evaluator-attestation",
                rsvpPath,
                "/api/transparency/responses",
            ])
        } else if failKeyReplacementOnce {
            XCTAssertEqual(transaction.recordedPaths, [
                "/api/account/key-epoch/reset",
                "/api/account/key-epoch/reset",
                "/api/account/key-epoch/initialize",
                "/api/trust/evaluator-attestation",
                rsvpPath,
                "/api/transparency/responses",
            ])
        }
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
        XCTAssertNil(store.deviceSwitchEventID)
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
        XCTAssertNil(store.deviceSwitchEventID)
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

private actor FailOnceAccountKeyStore: AccountKeyStoring {
    private var epochID: UUID?
    private var secret: SymmetricKey?
    private var remainingReplacementFailures = 1

    init(initialEpochID: UUID) {
        epochID = initialEpochID
        secret = SymmetricKey(size: .bits256)
    }

    func hasRootSecret(userID: String, epochID: UUID) -> Bool {
        self.epochID == epochID && secret != nil
    }

    func createRootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        if self.epochID == epochID, let secret { return secret }
        let created = SymmetricKey(size: .bits256)
        self.epochID = epochID
        secret = created
        return created
    }

    func rootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        guard self.epochID == epochID, let secret else {
            throw AccountKeyStoreError.wrongEpoch
        }
        return secret
    }

    func commitment(for accountRootSecret: SymmetricKey) -> String {
        let secret = accountRootSecret.withUnsafeBytes { Data($0) }
        return Data(
            SHA256.hash(
                data: concatenate(
                    Data("HERD-ARS-COMMITMENT-V1".utf8),
                    Data([0]),
                    secret
                )
            )
        ).base64URLEncodedString()
    }

    func replaceRootSecret(userID: String, newEpochID: UUID) throws -> SymmetricKey {
        if remainingReplacementFailures > 0 {
            remainingReplacementFailures -= 1
            throw AccountKeyStoreError.devicePasscodeRequired
        }
        let replacement = SymmetricKey(size: .bits256)
        epochID = newEpochID
        secret = replacement
        return replacement
    }

    func deleteAllRootSecretMaterial(userID: String) throws {
        epochID = nil
        secret = nil
    }
}

private actor DenyPostReplacementUnlockAccountKeyStore: AccountKeyStoring {
    private var epochID: UUID?
    private var secret: SymmetricKey?

    func hasRootSecret(userID: String, epochID: UUID) -> Bool {
        self.epochID == epochID && secret != nil
    }

    func createRootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        let created = SymmetricKey(size: .bits256)
        self.epochID = epochID
        secret = created
        return created
    }

    func rootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        throw AccountKeyStoreError.decryptionFailed
    }

    func commitment(for accountRootSecret: SymmetricKey) -> String {
        let secret = accountRootSecret.withUnsafeBytes { Data($0) }
        return Data(
            SHA256.hash(
                data: concatenate(
                    Data("HERD-ARS-COMMITMENT-V1".utf8),
                    Data([0]),
                    secret
                )
            )
        ).base64URLEncodedString()
    }

    func replaceRootSecret(userID: String, newEpochID: UUID) throws -> SymmetricKey {
        let replacement = SymmetricKey(size: .bits256)
        epochID = newEpochID
        secret = replacement
        return replacement
    }

    func deleteAllRootSecretMaterial(userID: String) throws {
        epochID = nil
        secret = nil
    }
}

private final class RecoveryTransactionState: @unchecked Sendable {
    private let lock = NSLock()
    private let resetEpochIDs: [UUID]
    private let failOnceAt: String?
    private var activeEpochID: UUID
    private var activeCommitment: String? = String(repeating: "f", count: 64)
    private var resetCount = 0
    private var hasInjectedFailure = false
    private var paths: [String] = []
    private var submittedEnvelopeIDs: [String] = []
    private var storedEnvelope: [String: Any]?
    private var certificationStatus: String?

    init(oldEpochID: UUID, resetEpochIDs: [UUID], failOnceAt: String? = nil) {
        precondition(!resetEpochIDs.isEmpty)
        self.activeEpochID = oldEpochID
        self.resetEpochIDs = resetEpochIDs
        self.failOnceAt = failOnceAt
    }

    func snapshot() -> (
        epochID: UUID,
        commitment: String?,
        storedEnvelope: [String: Any]?,
        certificationStatus: String?
    ) {
        lock.lock()
        defer { lock.unlock() }
        return (activeEpochID, activeCommitment, storedEnvelope, certificationStatus)
    }

    func reset(path: String) -> UUID {
        lock.lock()
        defer { lock.unlock() }
        precondition(resetCount < resetEpochIDs.count)
        activeEpochID = resetEpochIDs[resetCount]
        activeCommitment = nil
        resetCount += 1
        paths.append(path)
        return activeEpochID
    }

    func initialize(commitment: String) {
        lock.lock()
        activeCommitment = commitment
        lock.unlock()
    }

    func shouldFail(_ path: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !hasInjectedFailure, failOnceAt == path else { return false }
        hasInjectedFailure = true
        return true
    }

    func recordEnvelope(_ envelopeID: String, path: String) {
        lock.lock()
        submittedEnvelopeIDs.append(envelopeID)
        paths.append(path)
        lock.unlock()
    }

    func storeEnvelope(_ envelope: [String: Any]) {
        lock.lock()
        storedEnvelope = envelope
        certificationStatus = "pending"
        lock.unlock()
    }

    func certifyStoredEnvelope() {
        lock.lock()
        certificationStatus = "certified"
        lock.unlock()
    }

    func record(_ path: String) {
        lock.lock()
        paths.append(path)
        lock.unlock()
    }

    var recordedPaths: [String] {
        lock.lock()
        defer { lock.unlock() }
        return paths
    }

    var envelopeIDs: [String] {
        lock.lock()
        defer { lock.unlock() }
        return submittedEnvelopeIDs
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
