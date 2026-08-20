import Foundation

private final class NoRedirectSessionDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping @Sendable (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

enum HerdJSON {
    static func makeEncoder() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(iso8601String(from: date))
        }
        return encoder
    }

    static func makeDecoder() -> JSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .custom { decoder in
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self)
            guard let date = date(from: value) else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "Expected an ISO-8601 timestamp."
                )
            }
            return date
        }
        return decoder
    }

    private static func iso8601String(from date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        return formatter.string(from: date)
    }

    private static func date(from value: String) -> Date? {
        let fractionalFormatter = ISO8601DateFormatter()
        fractionalFormatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractionalFormatter.date(from: value) {
            return date
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }
}

struct AuthChallenge: Codable, Hashable, Sendable {
    let challengeId: String
    let phoneNumber: String
    let expiresAt: Date
    let resendAt: Date
}

struct AuthSession: Codable, Hashable, Sendable {
    let user: HerdUser
    let accessToken: String
    let expiresAt: Date
    let accountKeyEpochId: UUID?

    init(
        user: HerdUser,
        accessToken: String,
        expiresAt: Date,
        accountKeyEpochId: UUID? = nil
    ) {
        self.user = user
        self.accessToken = accessToken
        self.expiresAt = expiresAt
        self.accountKeyEpochId = accountKeyEpochId
    }
}

enum AuthStartResult: Decodable, Sendable {
    case challenge(AuthChallenge)
    case session(AuthSession)

    private enum CodingKeys: String, CodingKey {
        case user
        case accessToken
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        if container.contains(.user) || container.contains(.accessToken) {
            self = .session(try AuthSession(from: decoder))
        } else {
            self = .challenge(try AuthChallenge(from: decoder))
        }
    }
}

enum APIError: LocalizedError, Sendable {
    case invalidBaseURL
    case invalidResponse
    case unauthorized
    case inviteForDifferentAccount
    case codeRequestThrottled(message: String, retryAt: Date)
    case server(statusCode: Int, message: String)

    var errorDescription: String? {
        switch self {
        case .invalidBaseURL:
            "Herd’s server address is invalid."
        case .invalidResponse:
            "Herd received an unexpected response from the server."
        case .unauthorized:
            "Your session has expired. Please confirm your phone number again."
        case .inviteForDifferentAccount:
            "This invitation belongs to a different phone number."
        case let .codeRequestThrottled(message, _):
            message
        case let .server(_, message):
            message
        }
    }
}

actor APIClient {
    private static let mainRequestTimeout: TimeInterval = 15
    private static let mainEvaluationResponseLimit = 600 * 1_024
    private static let evaluatorRequestLimit = 600 * 1_024
    private static let evaluatorResponseLimit = 512 * 1_024
    private static let attestationResponseLimit = 128 * 1_024
    private static let transparencyResponseLimit = 32 * 1_024
    private static let evaluationTimeout: TimeInterval = 12

    private let baseURL: URL
    private let urlSession: URLSession
    private let evaluatorURLSession: URLSession
    private var accessToken: String?

    init(
        baseURL: URL = APIClient.configuredBaseURL,
        urlSession: URLSession = .shared,
        evaluatorURLSession: URLSession? = nil
    ) {
        self.baseURL = baseURL
        self.urlSession = urlSession
        self.evaluatorURLSession = evaluatorURLSession ?? Self.makeEvaluatorURLSession()
    }

    func setAccessToken(_ accessToken: String?) {
        self.accessToken = accessToken
    }

    func requestCode(
        phoneNumber: String,
        inviteToken: String? = nil
    ) async throws -> AuthStartResult {
        struct Body: Encodable {
            let phoneNumber: String
            let inviteToken: String?
        }

        let normalizedInviteToken: String?
        if let inviteToken {
            guard let token = InvitationToken.normalize(inviteToken) else {
                throw APIError.invalidResponse
            }
            normalizedInviteToken = token
        } else {
            normalizedInviteToken = nil
        }

        var request = try makeRequest(path: "/api/auth/request-code", method: "POST")
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Body(phoneNumber: phoneNumber, inviteToken: normalizedInviteToken)
        )
        return try await perform(request, as: AuthStartResult.self)
    }

    func verifyCode(challengeId: String, code: String) async throws -> AuthSession {
        struct Body: Encodable {
            let challengeId: String
            let code: String
        }

        var request = try makeRequest(path: "/api/auth/verify-code", method: "POST")
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Body(challengeId: challengeId, code: code)
        )
        return try await perform(request, as: AuthSession.self)
    }

    func fetchCurrentUser() async throws -> HerdUser {
        let request = try makeRequest(path: "/api/me", method: "GET", authenticated: true)
        let data = try await performData(request)
        return try decodeUserResponse(from: data)
    }

    func updateCurrentUser(name: String, address: String) async throws -> HerdUser {
        struct Body: Encodable {
            let name: String
            let address: String
        }

        var request = try makeRequest(path: "/api/me", method: "PATCH", authenticated: true)
        request.httpBody = try HerdJSON.makeEncoder().encode(Body(name: name, address: address))
        let data = try await performData(request)
        return try decodeUserResponse(from: data)
    }

    func deleteSession() async throws {
        let request = try makeRequest(
            path: "/api/auth/session",
            method: "DELETE",
            authenticated: true
        )
        _ = try await performData(request)
    }

    func deleteCurrentAccount() async throws {
        struct Body: Encodable {
            let confirmation: String
        }

        var request = try makeRequest(path: "/api/me", method: "DELETE", authenticated: true)
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try HerdJSON.makeEncoder().encode(Body(confirmation: "DELETE"))
        _ = try await performData(request)
    }

    func fetchEvents() async throws -> [HerdEvent] {
        struct Response: Decodable {
            let events: [RemoteEvent]
        }

        let request = try makeRequest(path: "/api/events", method: "GET", authenticated: true)
        let response = try await perform(request, as: Response.self)
        return response.events.map { EventResolutionVerifier.failClosed($0.herdEvent) }
    }

    /// Acquires an event-participant evaluation lease, relays its opaque request without
    /// app credentials, and returns the evaluator's opaque signed response to
    /// Herd. `false` means another client owns the lease; callers should leave
    /// the event pending and retry later.
    func relayEvaluation(eventID: UUID) async throws -> Bool {
        let expectedEventID = eventID.uuidString.lowercased()
        let path = "/api/events/\(expectedEventID)/evaluation"

        var leaseRequest = try makeRequest(
            path: path,
            method: "POST",
            authenticated: true
        )
        leaseRequest.timeoutInterval = Self.evaluationTimeout
        let (leaseData, leaseResponse) = try await boundedData(
            for: leaseRequest,
            using: evaluatorURLSession,
            limit: Self.mainEvaluationResponseLimit
        )

        if leaseResponse.statusCode == 202 || leaseResponse.statusCode == 409 {
            return false
        }
        try requireSuccess(leaseResponse, data: leaseData, request: leaseRequest)
        guard
            let lease = try JSONSerialization.jsonObject(with: leaseData) as? [String: Any],
            lease["eventId"] as? String == expectedEventID
        else { throw APIError.invalidResponse }

        // Acquiring a lease is idempotent. A concurrent completion can return
        // the already-final resolution instead of another relay request.
        if lease["relayRequest"] == nil, lease["resolution"] is [String: Any] {
            return true
        }

        guard
            let relayRequest = lease["relayRequest"] as? [String: Any],
            let evaluatorURLValue = lease["evaluatorUrl"] as? String,
            let evaluatorPin = lease["evaluatorHost"] as? String,
            let leaseID = lease["leaseId"] as? String,
            !leaseID.isEmpty,
            leaseID.count <= 128,
            let expiresAt = lease["expiresAt"] as? String,
            Self.validISO8601Timestamp(expiresAt),
            let evaluatorURL = Self.validatedEvaluatorURL(
                evaluatorURLValue,
                pinnedTo: evaluatorPin
            ),
            JSONSerialization.isValidJSONObject(relayRequest)
        else { throw APIError.invalidResponse }

        let relayData = try JSONSerialization.data(withJSONObject: relayRequest)
        guard relayData.count <= Self.evaluatorRequestLimit else {
            throw APIError.invalidResponse
        }
        var evaluatorRequest = URLRequest(url: evaluatorURL)
        evaluatorRequest.httpMethod = "POST"
        evaluatorRequest.timeoutInterval = Self.evaluationTimeout
        evaluatorRequest.cachePolicy = .reloadIgnoringLocalCacheData
        evaluatorRequest.httpShouldHandleCookies = false
        evaluatorRequest.setValue("application/json", forHTTPHeaderField: "Accept")
        evaluatorRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
        evaluatorRequest.httpBody = relayData

        let (evaluationData, evaluationResponse) = try await boundedData(
            for: evaluatorRequest,
            using: evaluatorURLSession,
            limit: Self.evaluatorResponseLimit
        )
        guard (200..<300).contains(evaluationResponse.statusCode) else {
            throw APIError.server(
                statusCode: evaluationResponse.statusCode,
                message: "The evaluator is temporarily unavailable."
            )
        }
        guard
            (try JSONSerialization.jsonObject(with: evaluationData)) is [String: Any]
        else { throw APIError.invalidResponse }

        // Keep the signed evaluator object byte-for-byte intact inside the
        // completion wrapper instead of decoding and re-encoding its contents.
        var completionData = Data("{\"evaluationResponse\":".utf8)
        completionData.append(evaluationData)
        completionData.append(Data("}".utf8))
        guard completionData.count <= Self.mainEvaluationResponseLimit else {
            throw APIError.invalidResponse
        }

        var completionRequest = try makeRequest(
            path: path,
            method: "PUT",
            authenticated: true
        )
        completionRequest.timeoutInterval = Self.evaluationTimeout
        completionRequest.httpBody = completionData
        let (completionResponseData, completionResponse) = try await boundedData(
            for: completionRequest,
            using: evaluatorURLSession,
            limit: Self.mainEvaluationResponseLimit
        )
        if completionResponse.statusCode == 202 || completionResponse.statusCode == 409 {
            return false
        }
        try requireSuccess(
            completionResponse,
            data: completionResponseData,
            request: completionRequest
        )
        return true
    }

    func upsertEvent(_ event: HerdEvent) async throws -> HerdEvent {
        struct Response: Decodable {
            let event: RemoteEvent
        }

        var request = try makeRequest(
            path: "/api/events/\(event.id.uuidString.lowercased())",
            method: "PUT",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(HostEventPayload(event))
        let response = try await perform(request, as: Response.self)
        return EventResolutionVerifier.failClosed(response.event.herdEvent)
    }

    func deleteEvent(id: UUID) async throws {
        let request = try makeRequest(
            path: "/api/events/\(id.uuidString.lowercased())",
            method: "DELETE",
            authenticated: true
        )
        _ = try await performData(request)
    }

    func addAttendees(eventID: UUID, invitees: [Invitee]) async throws -> HerdEvent {
        struct Response: Decodable {
            let event: RemoteEvent
        }
        struct Payload: Encodable {
            let invitees: [HostInviteePayload]
        }

        var request = try makeRequest(
            path: "/api/events/\(eventID.uuidString.lowercased())/attendees",
            method: "POST",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Payload(invitees: invitees.map(HostInviteePayload.init))
        )
        let response = try await perform(request, as: Response.self)
        return EventResolutionVerifier.failClosed(response.event.herdEvent)
    }

    func fetchInvitePrivateResponse(inviteToken: String) async throws -> InvitePrivateResponseContext {
        struct InviteMetadata: Decodable {
            let id: UUID
            let accountKeyEpochId: UUID?
            let accountKeyCommitment: String?
            let responseEnvelope: StoredPrivateResponseEnvelopeV1?
            let hasResponse: Bool?
            let hasBallot: Bool?
            let responseRevision: Int?
            let responseCertificationStatus: PrivateResponseCertificationStatus?
        }

        struct Response: Decodable {
            let event: RemoteEvent
            let inviteMetadata: InviteMetadata
        }

        guard let token = InvitationToken.normalize(inviteToken) else {
            throw APIError.invalidResponse
        }
        let request = try makeRequest(
            path: "/api/invites/\(token)",
            method: "GET",
            authenticated: true
        )
        let response = try await perform(request, as: Response.self)
        let event = EventResolutionVerifier.failClosed(response.event.herdEvent)
        guard event.role != .invitee || event.inviteToken == token else {
            throw APIError.invalidResponse
        }
        guard let epochID = response.inviteMetadata.accountKeyEpochId ?? event.accountKeyEpochId else {
            throw APIError.invalidResponse
        }
        let responseEnvelope = response.inviteMetadata.responseEnvelope
        let hasResponse = response.inviteMetadata.hasResponse
            ?? (responseEnvelope != nil)
            || event.hasResponse
        let certificationStatus = response.inviteMetadata.responseCertificationStatus
            ?? event.responseCertificationStatus
        guard
            hasResponse == (responseEnvelope != nil),
            (responseEnvelope == nil) == (certificationStatus == nil)
        else { throw APIError.invalidResponse }
        return InvitePrivateResponseContext(
            event: event,
            inviteeID: response.inviteMetadata.id,
            accountKeyEpochID: epochID,
            accountKeyCommitment: response.inviteMetadata.accountKeyCommitment
                ?? event.accountKeyCommitment,
            responseEnvelope: responseEnvelope,
            hasResponse: hasResponse,
            responseRevision: response.inviteMetadata.responseRevision
                ?? response.inviteMetadata.responseEnvelope?.revision
                ?? event.responseRevision,
            responseCertificationStatus: certificationStatus
        )
    }

    func fetchInvitation(inviteToken: String) async throws -> HerdEvent {
        struct InviteMetadata: Decodable {
            let accountKeyEpochId: UUID?
            let accountKeyCommitment: String?
            let responseEnvelope: StoredPrivateResponseEnvelopeV1?
            let hasResponse: Bool?
            let hasBallot: Bool?
            let responseRevision: Int?
            let responseCertificationStatus: PrivateResponseCertificationStatus?
        }

        struct Response: Decodable {
            let event: RemoteEvent
            let inviteMetadata: InviteMetadata?
        }

        guard let token = InvitationToken.normalize(inviteToken) else {
            throw APIError.invalidResponse
        }
        let request = try makeRequest(
            path: "/api/invites/\(token)",
            method: "GET",
            authenticated: true
        )
        let response = try await perform(request, as: Response.self)
        var event = EventResolutionVerifier.failClosed(response.event.herdEvent)
        guard event.role != .invitee || event.inviteToken == token else {
            throw APIError.invalidResponse
        }
        if let metadata = response.inviteMetadata {
            event.accountKeyEpochId = metadata.accountKeyEpochId ?? event.accountKeyEpochId
            event.accountKeyCommitment = metadata.accountKeyCommitment
                ?? event.accountKeyCommitment
            event.hasResponse = metadata.hasResponse
                ?? (metadata.responseEnvelope != nil)
                || event.hasResponse
            event.hasBallot = metadata.hasBallot ?? event.hasBallot
            event.responseRevision = metadata.responseRevision
                ?? metadata.responseEnvelope?.revision
                ?? event.responseRevision
            event.responseCertificationStatus = metadata.responseCertificationStatus
                ?? event.responseCertificationStatus
        }
        return event
    }

    func submitRSVP(
        inviteToken: String,
        envelope: PrivateResponseEnvelopeV1
    ) async throws -> PrivateResponseSubmissionResult {
        struct Body: Encodable {
            let envelope: PrivateResponseEnvelopeV1
        }

        struct Response: Decodable {
            let responseEnvelope: StoredPrivateResponseEnvelopeV1
            let receipt: PrivateResponseReceiptV1
        }

        guard let token = InvitationToken.normalize(inviteToken) else {
            throw APIError.invalidResponse
        }
        var request = try makeRequest(
            path: "/api/invites/\(token)/rsvp",
            method: "PUT",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(Body(envelope: envelope))
        let result = try await perform(request, as: Response.self)
        return PrivateResponseSubmissionResult(
            responseEnvelope: result.responseEnvelope,
            receipt: result.receipt
        )
    }

    func fetchSimplifiedBallot(inviteToken: String) async throws -> SimplifiedBallot? {
        struct Response: Decodable { let ballot: SimplifiedBallot? }
        guard let token = InvitationToken.normalize(inviteToken) else {
            throw APIError.invalidResponse
        }
        let request = try makeRequest(
            path: "/api/invites/\(token)/ballot",
            method: "GET",
            authenticated: true
        )
        return try await perform(request, as: Response.self).ballot
    }

    func submitSimplifiedBallot(
        inviteToken: String,
        draft: PrivateResponseDraft
    ) async throws -> SimplifiedBallot {
        struct Body: Encodable {
            let response: RSVPResponse
            let minimumParticipants: Int?
            let requiredGroups: [RSVPConditionGroup]

            enum CodingKeys: String, CodingKey {
                case response
                case minimumParticipants
                case requiredGroups
            }

            func encode(to encoder: Encoder) throws {
                var container = encoder.container(keyedBy: CodingKeys.self)
                try container.encode(response, forKey: .response)
                if let minimumParticipants {
                    try container.encode(minimumParticipants, forKey: .minimumParticipants)
                } else {
                    try container.encodeNil(forKey: .minimumParticipants)
                }
                try container.encode(requiredGroups, forKey: .requiredGroups)
            }
        }
        struct Response: Decodable { let ballot: SimplifiedBallot }
        guard let token = InvitationToken.normalize(inviteToken) else {
            throw APIError.invalidResponse
        }
        var request = try makeRequest(
            path: "/api/invites/\(token)/ballot",
            method: "PUT",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Body(
                response: draft.response,
                minimumParticipants: draft.response == .going
                    ? draft.minimumParticipants
                    : nil,
                requiredGroups: draft.response == .going
                    ? draft.requiredGroups
                    : []
            )
        )
        return try await perform(request, as: Response.self).ballot
    }

    func fetchEvaluatorAttestation(nonce: String) async throws -> EvaluatorAttestationResponse {
        struct Body: Encodable {
            let nonce: String
        }

        guard
            let nonceData = Data(base64URLEncoded: nonce),
            nonceData.count == 32,
            nonceData.base64URLEncodedString() == nonce
        else { throw APIError.invalidResponse }
        var request = try makeRequest(
            path: "/api/trust/evaluator-attestation",
            method: "POST",
            authenticated: true
        )
        request.timeoutInterval = Self.evaluationTimeout
        request.cachePolicy = .reloadIgnoringLocalCacheData
        request.httpBody = try HerdJSON.makeEncoder().encode(Body(nonce: nonce))
        let (data, response) = try await boundedData(
            for: request,
            using: urlSession,
            limit: Self.attestationResponseLimit
        )
        try requireSuccess(response, data: data, request: request)
        do {
            return try HerdJSON.makeDecoder().decode(
                EvaluatorAttestationResponse.self,
                from: data
            )
        } catch {
            throw APIError.invalidResponse
        }
    }

    func fetchResponseTransparencyEntry(
        logIndex: Int
    ) async throws -> PrivateResponseTransparencyLogV1 {
        guard (1...Int(Int32.max)).contains(logIndex) else {
            throw APIError.invalidResponse
        }
        var request = try makeRequest(
            path: "/api/transparency/responses",
            method: "GET"
        )
        guard
            let requestURL = request.url,
            var components = URLComponents(url: requestURL, resolvingAgainstBaseURL: false)
        else { throw APIError.invalidResponse }
        components.queryItems = [
            URLQueryItem(name: "after", value: String(logIndex - 1)),
            URLQueryItem(name: "limit", value: "1"),
        ]
        guard let url = components.url else { throw APIError.invalidResponse }
        request.url = url
        request.timeoutInterval = Self.evaluationTimeout
        request.cachePolicy = .reloadIgnoringLocalCacheData
        let (data, response) = try await boundedData(
            for: request,
            using: evaluatorURLSession,
            limit: Self.transparencyResponseLimit
        )
        try requireSuccess(response, data: data, request: request)
        do {
            guard
                let raw = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                Set(raw.keys) == Set(["protocolVersion", "logId", "entries"]),
                let entries = raw["entries"] as? [[String: Any]],
                entries.count == 1,
                Set(entries[0].keys) == Set([
                    "logIndex", "previousEntryHash", "entryHash", "head",
                ]),
                let head = entries[0]["head"] as? [String: Any],
                Set(head.keys) == Set([
                    "protocolVersion", "logId", "treeSize", "headEntryHash",
                    "generatedAt", "signingKeyId", "signature",
                ])
            else { throw APIError.invalidResponse }
            return try HerdJSON.makeDecoder().decode(
                PrivateResponseTransparencyLogV1.self,
                from: data
            )
        } catch let error as APIError {
            throw error
        } catch {
            throw APIError.invalidResponse
        }
    }

    func resetAccountKeyEpoch(expectedAccountKeyEpochId: UUID) async throws -> UUID {
        struct Body: Encodable {
            let expectedAccountKeyEpochId: UUID
        }
        struct Response: Decodable {
            let accountKeyEpochId: UUID
            let resetAt: String
        }

        var request = try makeRequest(
            path: "/api/account/key-epoch/reset",
            method: "POST",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Body(expectedAccountKeyEpochId: expectedAccountKeyEpochId)
        )
        let response = try await perform(request, as: Response.self)
        _ = response.resetAt
        return response.accountKeyEpochId
    }

    func initializeAccountKeyEpoch(
        expectedAccountKeyEpochId: UUID,
        keyCommitment: String
    ) async throws {
        struct Body: Encodable {
            let expectedAccountKeyEpochId: UUID
            let keyCommitment: String
        }
        struct Response: Decodable {
            let accountKeyEpochId: UUID
            let keyCommitment: String
        }

        var request = try makeRequest(
            path: "/api/account/key-epoch/initialize",
            method: "POST",
            authenticated: true
        )
        request.httpBody = try HerdJSON.makeEncoder().encode(
            Body(
                expectedAccountKeyEpochId: expectedAccountKeyEpochId,
                keyCommitment: keyCommitment
            )
        )
        let response = try await perform(request, as: Response.self)
        guard
            response.accountKeyEpochId == expectedAccountKeyEpochId,
            response.keyCommitment == keyCommitment
        else { throw APIError.invalidResponse }
    }

    private func makeRequest(
        path: String,
        method: String,
        authenticated: Bool = false
    ) throws -> URLRequest {
        var url = baseURL
        for component in path.split(separator: "/") {
            url.appendPathComponent(String(component))
        }

        guard url.scheme == "https" || url.host == "localhost" else {
            throw APIError.invalidBaseURL
        }

        var request = URLRequest(url: url)
        request.timeoutInterval = Self.mainRequestTimeout
        request.httpMethod = method
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("ios", forHTTPHeaderField: "X-Herd-Client-Platform")
        request.setValue(UUID().uuidString.lowercased(), forHTTPHeaderField: "X-Herd-Request-ID")
        if method != "GET" && method != "DELETE" {
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        if authenticated {
            guard let accessToken else {
                throw APIError.unauthorized
            }
            request.setValue("Bearer \(accessToken)", forHTTPHeaderField: "Authorization")
        }
        return request
    }

    private func perform<Response: Decodable>(
        _ request: URLRequest,
        as responseType: Response.Type
    ) async throws -> Response {
        let data = try await performData(request)
        do {
            return try HerdJSON.makeDecoder().decode(responseType, from: data)
        } catch {
            reportClientTelemetry(
                request: request,
                signal: "client_decode",
                outcome: "failure",
                statusCode: 0,
                errorCode: "invalid_response",
                durationMilliseconds: 0
            )
            throw APIError.invalidResponse
        }
    }

    private func performData(_ request: URLRequest) async throws -> Data {
        let startedAt = ContinuousClock.now
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await urlSession.data(for: request)
        } catch {
            reportClientTelemetry(
                request: request,
                signal: "client_api_request",
                outcome: error is CancellationError ? "cancelled" : "failure",
                statusCode: 0,
                errorCode: error is CancellationError ? "cancelled" : "network_error",
                durationMilliseconds: milliseconds(since: startedAt)
            )
            throw error
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            reportClientTelemetry(
                request: request,
                signal: "client_api_request",
                outcome: "failure",
                statusCode: 0,
                errorCode: "invalid_response",
                durationMilliseconds: milliseconds(since: startedAt)
            )
            throw APIError.invalidResponse
        }
        reportClientTelemetry(
            request: request,
            signal: "client_api_request",
            outcome: (200..<300).contains(httpResponse.statusCode) ? "success" : "failure",
            statusCode: httpResponse.statusCode,
            errorCode: httpResponse.value(forHTTPHeaderField: "X-Herd-Error-Code") ?? "none",
            durationMilliseconds: milliseconds(since: startedAt),
            responseRequestID: httpResponse.value(forHTTPHeaderField: "X-Herd-Request-ID")
        )
        guard (200..<300).contains(httpResponse.statusCode) else {
            if
                httpResponse.statusCode == 401,
                request.value(forHTTPHeaderField: "Authorization") != nil
            {
                throw APIError.unauthorized
            }
            if
                httpResponse.statusCode == 403,
                errorCode(from: data) == "invite_for_different_account"
            {
                throw APIError.inviteForDifferentAccount
            }
            if let throttle = codeRequestThrottle(from: data) {
                throw throttle
            }
            throw APIError.server(
                statusCode: httpResponse.statusCode,
                message: errorMessage(from: data, statusCode: httpResponse.statusCode)
            )
        }
        return data
    }

    private func boundedData(
        for request: URLRequest,
        using session: URLSession,
        limit: Int
    ) async throws -> (Data, HTTPURLResponse) {
        let startedAt = ContinuousClock.now
        let bytes: URLSession.AsyncBytes
        let response: URLResponse
        do {
            (bytes, response) = try await session.bytes(for: request)
        } catch {
            reportClientTelemetry(
                request: request,
                signal: "client_api_request",
                outcome: error is CancellationError ? "cancelled" : "failure",
                statusCode: 0,
                errorCode: error is CancellationError ? "cancelled" : "network_error",
                durationMilliseconds: milliseconds(since: startedAt)
            )
            throw error
        }
        guard let httpResponse = response as? HTTPURLResponse else {
            bytes.task.cancel()
            throw APIError.invalidResponse
        }
        var declaredLength: Int?
        if
            let value = httpResponse.value(forHTTPHeaderField: "Content-Length"),
            let length = Int(value)
        {
            guard length >= 0, length <= limit else {
                bytes.task.cancel()
                throw APIError.invalidResponse
            }
            declaredLength = length
        }

        var data = Data()
        data.reserveCapacity(declaredLength ?? min(limit, 16 * 1_024))
        do {
            for try await byte in bytes {
                guard data.count < limit else {
                    bytes.task.cancel()
                    throw APIError.invalidResponse
                }
                data.append(byte)
            }
        } catch {
            bytes.task.cancel()
            reportClientTelemetry(
                request: request,
                signal: "client_api_request",
                outcome: error is CancellationError ? "cancelled" : "failure",
                statusCode: httpResponse.statusCode,
                errorCode: error is CancellationError ? "cancelled" : "response_read_error",
                durationMilliseconds: milliseconds(since: startedAt),
                responseRequestID: httpResponse.value(forHTTPHeaderField: "X-Herd-Request-ID")
            )
            throw error
        }
        reportClientTelemetry(
            request: request,
            signal: "client_api_request",
            outcome: (200..<300).contains(httpResponse.statusCode) ? "success" : "failure",
            statusCode: httpResponse.statusCode,
            errorCode: httpResponse.value(forHTTPHeaderField: "X-Herd-Error-Code") ?? "none",
            durationMilliseconds: milliseconds(since: startedAt),
            responseRequestID: httpResponse.value(forHTTPHeaderField: "X-Herd-Request-ID")
        )
        return (data, httpResponse)
    }

    private func milliseconds(since instant: ContinuousClock.Instant) -> Int {
        let duration = instant.duration(to: .now)
        let components = duration.components
        let milliseconds = components.seconds * 1_000 + components.attoseconds / 1_000_000_000_000_000
        return max(0, min(120_000, Int(milliseconds)))
    }

    private func telemetryOperation(for request: URLRequest) -> String {
        let method = (request.httpMethod ?? "GET").lowercased()
        guard let path = request.url?.path else { return "unknown" }
        let parts = path.split(separator: "/").map(String.init)
        let normalized = parts.enumerated().map { index, part in
            guard index > 0 else { return part }
            let prior = parts[index - 1]
            return prior == "events" ? "event" : prior == "invites" ? "invite" : part
        }
        .joined(separator: ".")
        let route = normalized.hasPrefix("api.") ? String(normalized.dropFirst(4)) : normalized
        let value = "\(method).\(route.replacingOccurrences(of: ":", with: ""))"
        return String(value.prefix(80)).lowercased()
    }

    private func reportClientTelemetry(
        request: URLRequest,
        signal: String,
        outcome: String,
        statusCode: Int,
        errorCode: String,
        durationMilliseconds: Int,
        responseRequestID: String? = nil
    ) {
        // Unit/UI tests inject non-production API origins. Never let best-effort
        // diagnostics escape those isolated environments or add test latency.
        guard baseURL.host == "app.herdprivacy.com" else { return }
        guard var url = URL(string: "/api/telemetry", relativeTo: baseURL)?.absoluteURL else { return }
        url = url.standardized
        let requestID = responseRequestID ?? request.value(forHTTPHeaderField: "X-Herd-Request-ID") ?? UUID().uuidString.lowercased()
        let body: [String: Any] = [
            "schemaVersion": 1,
            "platform": "ios",
            "signal": signal,
            "operation": telemetryOperation(for: request),
            "outcome": outcome,
            "statusCode": statusCode,
            "errorCode": errorCode.lowercased().filter { $0.isLetter || $0.isNumber || "._:-".contains($0) }.prefix(80).description,
            "durationMs": durationMilliseconds,
            "correlationId": requestID.lowercased(),
        ]
        guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return }
        Task {
            var telemetryRequest = URLRequest(url: url)
            telemetryRequest.httpMethod = "POST"
            telemetryRequest.httpBody = payload
            telemetryRequest.timeoutInterval = 3
            telemetryRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            telemetryRequest.setValue("ios", forHTTPHeaderField: "X-Herd-Client-Platform")
            _ = try? await URLSession.shared.data(for: telemetryRequest)
        }
    }

    func reportLocalClientTelemetry(
        operation: String,
        outcome: String,
        errorCode: String,
        durationMilliseconds: Int
    ) {
        // Local privacy operations have no HTTP request to correlate. Emit only
        // a fresh run-scoped ID and fixed, low-cardinality outcome fields.
        guard baseURL.host == "app.herdprivacy.com" else { return }
        guard var url = URL(string: "/api/telemetry", relativeTo: baseURL)?.absoluteURL else { return }
        url = url.standardized
        let safeOperation = operation.lowercased().filter {
            $0.isLetter || $0.isNumber || "._:-".contains($0)
        }.prefix(80).description
        let safeErrorCode = errorCode.lowercased().filter {
            $0.isLetter || $0.isNumber || "._:-".contains($0)
        }.prefix(80).description
        let body: [String: Any] = [
            "schemaVersion": 1,
            "platform": "ios",
            "signal": "client_decode",
            "operation": safeOperation,
            "outcome": outcome,
            "statusCode": 0,
            "errorCode": safeErrorCode,
            "durationMs": max(0, min(120_000, durationMilliseconds)),
            "correlationId": UUID().uuidString.lowercased(),
        ]
        guard let payload = try? JSONSerialization.data(withJSONObject: body) else { return }
        Task {
            var telemetryRequest = URLRequest(url: url)
            telemetryRequest.httpMethod = "POST"
            telemetryRequest.httpBody = payload
            telemetryRequest.timeoutInterval = 3
            telemetryRequest.setValue("application/json", forHTTPHeaderField: "Content-Type")
            telemetryRequest.setValue("ios", forHTTPHeaderField: "X-Herd-Client-Platform")
            _ = try? await URLSession.shared.data(for: telemetryRequest)
        }
    }

    private func requireSuccess(
        _ response: HTTPURLResponse,
        data: Data,
        request: URLRequest
    ) throws {
        guard (200..<300).contains(response.statusCode) else {
            if
                response.statusCode == 401,
                request.value(forHTTPHeaderField: "Authorization") != nil
            {
                throw APIError.unauthorized
            }
            if
                response.statusCode == 403,
                errorCode(from: data) == "invite_for_different_account"
            {
                throw APIError.inviteForDifferentAccount
            }
            if let throttle = codeRequestThrottle(from: data) {
                throw throttle
            }
            throw APIError.server(
                statusCode: response.statusCode,
                message: errorMessage(from: data, statusCode: response.statusCode)
            )
        }
    }

    private func decodeUserResponse(from data: Data) throws -> HerdUser {
        struct Response: Decodable {
            let user: HerdUser
        }

        let decoder = HerdJSON.makeDecoder()
        if let response = try? decoder.decode(Response.self, from: data) {
            return response.user
        }
        if let user = try? decoder.decode(HerdUser.self, from: data) {
            return user
        }
        throw APIError.invalidResponse
    }

    private func errorMessage(from data: Data, statusCode: Int) -> String {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else {
            return "Herd couldn’t complete that request (error \(statusCode))."
        }

        if let message = object["message"] as? String, !message.isEmpty {
            return message
        }
        if let error = object["error"] as? String, !error.isEmpty {
            return error
        }
        if
            let error = object["error"] as? [String: Any],
            let message = error["message"] as? String,
            !message.isEmpty
        {
            return message
        }
        return "Herd couldn’t complete that request (error \(statusCode))."
    }

    private static func iso8601Date(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private func codeRequestThrottle(from data: Data) -> APIError? {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let error = object["error"] as? [String: Any],
            error["code"] as? String == "code_request_throttled",
            let message = error["message"] as? String,
            let details = error["details"] as? [String: Any],
            let retryAtValue = details["retryAt"] as? String,
            let retryAt = Self.iso8601Date(retryAtValue)
        else { return nil }
        return .codeRequestThrottled(message: message, retryAt: retryAt)
    }

    private func errorCode(from data: Data) -> String? {
        guard
            let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            let error = object["error"] as? [String: Any],
            let code = error["code"] as? String,
            !code.isEmpty
        else { return nil }
        return code
    }

    static var configuredBaseURL: URL {
        let configured = Bundle.main.object(forInfoDictionaryKey: "HERD_API_BASE_URL") as? String
        let value = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if
            let url = URL(string: value),
            url.scheme?.lowercased() == "https",
            url.host != nil,
            url.user == nil,
            url.password == nil,
            url.fragment == nil
        {
            return url
        }
        return URL(string: "https://app.herdprivacy.com")!
    }

    private static func makeEvaluatorURLSession() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = evaluationTimeout
        configuration.timeoutIntervalForResource = evaluationTimeout
        configuration.waitsForConnectivity = false
        return URLSession(
            configuration: configuration,
            delegate: NoRedirectSessionDelegate(),
            delegateQueue: nil
        )
    }

    private static func validatedEvaluatorURL(
        _ rawValue: String,
        pinnedTo rawPin: String
    ) -> URL? {
        guard
            let endpoint = URLComponents(string: rawValue),
            endpoint.scheme?.lowercased() == "https",
            endpoint.user == nil,
            endpoint.password == nil,
            let endpointHost = endpoint.host?.lowercased(),
            endpoint.path == "/api/v1/relay/",
            endpoint.query == nil,
            endpoint.fragment == nil,
            let endpointURL = endpoint.url,
            let pin = URLComponents(string: rawPin),
            pin.scheme?.lowercased() == "https",
            pin.user == nil,
            pin.password == nil,
            let pinHost = pin.host?.lowercased(),
            pin.path.isEmpty || pin.path == "/",
            pin.query == nil,
            pin.fragment == nil,
            endpointHost == pinHost,
            (endpoint.port ?? 443) == (pin.port ?? 443)
        else { return nil }
        return endpointURL
    }

    private static func validISO8601Timestamp(_ value: String) -> Bool {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if fractional.date(from: value) != nil { return true }
        let basic = ISO8601DateFormatter()
        basic.formatOptions = [.withInternetDateTime]
        return basic.date(from: value) != nil
    }
}

private struct RemoteInvitee: Decodable, Sendable {
    let id: UUID
    var displayName: String
    var phoneNumber: String?
    var isCurrentUser: Bool?
    var hasResponded: Bool?
    var responseHistory: Invitee.ResponseHistory?

    var invitee: Invitee {
        Invitee(
            id: id,
            sourceContactIdentifier: nil,
            displayName: displayName,
            phoneNumber: phoneNumber ?? "",
            isCurrentUser: isCurrentUser ?? false,
            hasResponded: hasResponded,
            responseHistory: responseHistory
        )
    }
}

private struct RemoteEvent: Decodable, Sendable {
    let id: UUID
    var title: String
    var eventDate: Date?
    var endDate: Date?
    var hostName: String
    var locationName: String
    var locationAddress: String
    var invitees: [RemoteInvitee]
    var minimumParticipants: Int
    var allowsAttendeesToAddGuests: Bool?
    var requiredGroups: [RequiredAttendeeGroup]
    var rsvpDeadline: Date?
    var eventDescription: String
    let createdAt: Date
    var invitationsSent: Bool
    var role: EventAccessRole?
    var inviteToken: String?
    var accountKeyEpochId: UUID?
    var accountKeyCommitment: String?
    var hasResponse: Bool?
    var hasBallot: Bool?
    var responseRevision: Int?
    var responseCertificationStatus: PrivateResponseCertificationStatus?
    var privateResponsePolicy: PrivateResponsePolicyV1?
    var resolution: EventResolution?
    var invitationDelivery: InvitationDeliverySummary?

    var herdEvent: HerdEvent {
        HerdEvent(
            id: id,
            title: title,
            eventDate: eventDate,
            endDate: endDate,
            hostName: hostName,
            locationName: locationName,
            locationAddress: locationAddress,
            invitees: invitees.map(\.invitee),
            minimumParticipants: minimumParticipants,
            allowsAttendeesToAddGuests: allowsAttendeesToAddGuests ?? true,
            requiredGroups: requiredGroups,
            rsvpDeadline: rsvpDeadline,
            eventDescription: eventDescription,
            createdAt: createdAt,
            invitationsSent: invitationsSent,
            role: role ?? .host,
            inviteToken: inviteToken,
            accountKeyEpochId: accountKeyEpochId,
            accountKeyCommitment: accountKeyCommitment,
            hasResponse: hasResponse ?? false,
            hasBallot: hasBallot ?? false,
            responseRevision: responseRevision,
            responseCertificationStatus: responseCertificationStatus,
            privateResponsePolicy: privateResponsePolicy,
            resolution: resolution,
            invitationDelivery: invitationDelivery
        )
    }
}

private struct HostInviteePayload: Encodable, Sendable {
    let id: UUID
    let displayName: String
    let phoneNumber: String

    init(_ invitee: Invitee) {
        id = invitee.id
        displayName = invitee.displayName
        phoneNumber = invitee.phoneNumber
    }
}

private struct HostEventPayload: Encodable, Sendable {
    let id: UUID
    let title: String
    let eventDate: Date?
    let endDate: Date?
    let hostName: String
    let locationName: String
    let locationAddress: String
    let invitees: [HostInviteePayload]
    let minimumParticipants: Int
    let allowsAttendeesToAddGuests: Bool
    let requiredGroups: [RequiredAttendeeGroup]
    let rsvpDeadline: Date?
    let eventDescription: String
    let createdAt: Date
    let invitationsSent: Bool

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case eventDate
        case endDate
        case hostName
        case locationName
        case locationAddress
        case invitees
        case minimumParticipants
        case allowsAttendeesToAddGuests
        case requiredGroups
        case rsvpDeadline
        case eventDescription
        case createdAt
        case invitationsSent
    }

    init(_ event: HerdEvent) {
        id = event.id
        title = event.title
        eventDate = event.eventDate
        endDate = event.endDate
        hostName = event.hostName
        locationName = event.locationName
        locationAddress = event.locationAddress
        invitees = event.invitees.map(HostInviteePayload.init)
        minimumParticipants = event.minimumParticipants
        allowsAttendeesToAddGuests = event.allowsAttendeesToAddGuests
        requiredGroups = event.requiredGroups
        rsvpDeadline = event.rsvpDeadline
        eventDescription = event.eventDescription
        createdAt = event.createdAt
        invitationsSent = event.invitationsSent
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        if let eventDate {
            try container.encode(eventDate, forKey: .eventDate)
        } else {
            try container.encodeNil(forKey: .eventDate)
        }
        if let endDate {
            try container.encode(endDate, forKey: .endDate)
        } else {
            try container.encodeNil(forKey: .endDate)
        }
        try container.encode(hostName, forKey: .hostName)
        try container.encode(locationName, forKey: .locationName)
        try container.encode(locationAddress, forKey: .locationAddress)
        try container.encode(invitees, forKey: .invitees)
        try container.encode(minimumParticipants, forKey: .minimumParticipants)
        try container.encode(allowsAttendeesToAddGuests, forKey: .allowsAttendeesToAddGuests)
        try container.encode(requiredGroups, forKey: .requiredGroups)
        if let rsvpDeadline {
            try container.encode(rsvpDeadline, forKey: .rsvpDeadline)
        } else {
            try container.encodeNil(forKey: .rsvpDeadline)
        }
        try container.encode(eventDescription, forKey: .eventDescription)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(invitationsSent, forKey: .invitationsSent)
    }
}
