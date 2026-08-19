import CryptoKit
import Foundation
import Observation

enum InvitationOpenOutcome: Equatable {
    case loaded(UUID)
    case differentAccount
    case unauthorized
    case failed(String)
}

struct AccountKeyDiagnostic: Identifiable, Hashable, Sendable {
    let epochID: UUID
    let commitment: String?
    let eventCount: Int
    let hasSavedResponse: Bool
    let isAvailableOnDevice: Bool

    var id: UUID { epochID }
    var requiresRecovery: Bool { commitment != nil && !isAvailableOnDevice }
}

struct EventStorePrivateResponseDependencies {
    let makeCrypto: () throws -> PrivateResponseCrypto
    let verifyAttestation: (
        EvaluatorAttestationResponse,
        String,
        PrivateResponsePolicyV1
    ) throws -> Void
    let verifyReceipt: (PrivateResponseReceiptV1) throws -> Void
    let verifyPublication: (
        PrivateResponseReceiptV1,
        PrivateResponseTransparencyLogV1
    ) throws -> Void

    static let live = EventStorePrivateResponseDependencies(
        makeCrypto: { try PrivateResponseCrypto.configured() },
        verifyAttestation: { response, nonce, policy in
            try EvaluatorAttestationVerifier.configured().verify(
                response,
                nonce: nonce,
                policy: policy
            )
        },
        verifyReceipt: { receipt in
            try PrivateResponseReceiptVerifier.configured().verify(receipt)
        },
        verifyPublication: { receipt, publicLog in
            try PrivateResponseReceiptPublicationVerifier.verify(
                receipt: receipt,
                publicLog: publicLog
            )
        }
    )
}

private actor EventStoreOperationGate {
    private var isHeld = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func acquire() async {
        if !isHeld {
            isHeld = true
            return
        }

        await withCheckedContinuation { continuation in
            waiters.append(continuation)
        }
    }

    func release() {
        guard !waiters.isEmpty else {
            isHeld = false
            return
        }

        waiters.removeFirst().resume()
    }
}

@MainActor
@Observable
final class EventStore {
    private struct OperationContext: Equatable {
        let userID: String
        let sessionGeneration: UInt
    }

    private struct PendingResponseSubmission {
        let draft: PrivateResponseDraft
        let accountKeyEpochID: UUID
        let revision: Int
        let policyHash: String
        let envelope: PrivateResponseEnvelopeV1
    }

    private(set) var events: [HerdEvent] = []
    private(set) var isRefreshing = false
    private(set) var isMutating = false
    private(set) var isUsingCachedData = false
    private(set) var errorMessage: String?
    private(set) var lastUpdatedAt: Date?
    private(set) var unlockedResponses: [UUID: RSVPResponse] = [:]
    private(set) var unlockedDrafts: [UUID: PrivateResponseDraft] = [:]
    private(set) var unavailablePrivateResponseEventID: UUID?
    private(set) var legacyImportCandidateCount = 0

    private let defaults: UserDefaults
    private let apiClient: APIClient
    private let accountKeyStore: any AccountKeyStoring
    private let privateResponseDependencies: EventStorePrivateResponseDependencies
    private let operationGate = EventStoreOperationGate()
    private var activeUserID: String?
    private var sessionGeneration: UInt = 0
    private var unauthorizedHandler: (() -> Void)?
    private var pendingResponseSubmissions: [UUID: PendingResponseSubmission] = [:]
    private var pendingCertificationEnvelopes: [UUID: PrivateResponseEnvelopeV1] = [:]
    private var pendingLegacyEvents: [HerdEvent] = []
    private var privacyLockGeneration: UInt = 0
    private static let legacyEventsKey = "herd.host.events.v1"
    private static let legacyOwnerKey = "herd.host.events.v1.claimed-user-id"
    private static let lastUpdatedKeyPrefix = "herd.events.lastUpdated.v1"

    init(
        defaults: UserDefaults = .standard,
        apiClient: APIClient = APIClient(),
        accountKeyStore: any AccountKeyStoring = AccountKeyStore(),
        privateResponseDependencies: EventStorePrivateResponseDependencies = .live
    ) {
        self.defaults = defaults
        self.apiClient = apiClient
        self.accountKeyStore = accountKeyStore
        self.privateResponseDependencies = privateResponseDependencies
    }

    func setUnauthorizedHandler(_ handler: @escaping () -> Void) {
        unauthorizedHandler = handler
    }

    func activate(userID: String) {
        guard activeUserID != userID else { return }
        sessionGeneration &+= 1
        privacyLockGeneration &+= 1
        activeUserID = userID
        unlockedResponses = [:]
        unlockedDrafts = [:]
        pendingResponseSubmissions = [:]
        pendingCertificationEnvelopes = [:]
        unavailablePrivateResponseEventID = nil
        isRefreshing = false
        isMutating = false
        removeLegacyPrivateResponseCaches()
        let legacyEvents = loadLegacyHostedEvents()
        let legacyEventIDs = Set(legacyEvents.map(\.id))
        let legacyOwnerID = defaults.string(forKey: Self.legacyOwnerKey)
        events = loadCachedEvents().filter {
            legacyOwnerID == userID || !legacyEventIDs.contains($0.id)
        }
        pendingLegacyEvents = legacyOwnerID == userID ? legacyEvents : []
        legacyImportCandidateCount = legacyOwnerID == nil ? legacyEvents.count : 0
        events = mergeEvents(events, with: pendingLegacyEvents)
        sortEvents()
        lastUpdatedAt = defaults.object(
            forKey: Self.lastUpdatedKey(for: userID)
        ) as? Date
        isUsingCachedData = !events.isEmpty
        errorMessage = nil
    }

    func clearSession() {
        sessionGeneration &+= 1
        privacyLockGeneration &+= 1
        activeUserID = nil
        events = []
        unlockedResponses = [:]
        unlockedDrafts = [:]
        pendingResponseSubmissions = [:]
        pendingCertificationEnvelopes = [:]
        pendingLegacyEvents = []
        unavailablePrivateResponseEventID = nil
        isRefreshing = false
        isMutating = false
        legacyImportCandidateCount = 0
        lastUpdatedAt = nil
        isUsingCachedData = false
        errorMessage = nil
    }

    func eraseLocalAccountData(userID: String) {
        defaults.removeObject(forKey: "herd.events.cache.v2.\(userID)")
        defaults.removeObject(forKey: Self.lastUpdatedKey(for: userID))
        removeClaimedLegacyStorage(for: userID)
        if activeUserID == userID {
            clearSession()
        }
    }

    @discardableResult
    func claimLegacyHostedEvents() async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            guard self.operationIsCurrent(context) else { return false }
            let ownerID = self.defaults.string(forKey: Self.legacyOwnerKey)
            guard ownerID == nil || ownerID == context.userID else { return false }

            let legacyEvents = self.loadLegacyHostedEvents()
            guard !legacyEvents.isEmpty else {
                self.legacyImportCandidateCount = 0
                return false
            }

            self.defaults.set(context.userID, forKey: Self.legacyOwnerKey)
            self.removeLegacyEventsFromOtherCaches(
                ownerID: context.userID,
                eventIDs: Set(legacyEvents.map(\.id))
            )
            self.pendingLegacyEvents = legacyEvents
            self.events = self.mergeEvents(self.events, with: legacyEvents)
            self.sortEvents()
            self.persistCache()
            self.isUsingCachedData = true
            self.legacyImportCandidateCount = 0
            return true
        } ?? false
    }

    func deferLegacyImport() {
        legacyImportCandidateCount = 0
    }

    func refresh() async {
        guard let context = currentOperationContext else { return }
        _ = await withSerializedOperation(context) {
            await self.performRefresh(context: context)
        }
    }

    func accountKeyDiagnostics() async -> [AccountKeyDiagnostic] {
        guard let context = currentOperationContext else { return [] }
        let keyedEvents = events.filter {
            $0.role == .invitee && $0.accountKeyEpochId != nil
        }
        let groupedEvents = Dictionary(grouping: keyedEvents) { $0.accountKeyEpochId! }
        var diagnostics: [AccountKeyDiagnostic] = []

        for epochID in groupedEvents.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            guard operationIsCurrent(context), let matchingEvents = groupedEvents[epochID] else {
                return []
            }
            let isAvailable = await accountKeyStore.hasRootSecret(
                userID: context.userID,
                epochID: epochID
            )
            guard operationIsCurrent(context) else { return [] }
            diagnostics.append(
                AccountKeyDiagnostic(
                    epochID: epochID,
                    commitment: matchingEvents.compactMap(\.accountKeyCommitment).first,
                    eventCount: matchingEvents.count,
                    hasSavedResponse: matchingEvents.contains { $0.hasResponse || $0.hasBallot },
                    isAvailableOnDevice: isAvailable
                )
            )
        }

        return diagnostics
    }

    func openInvitation(inviteToken: String) async -> InvitationOpenOutcome {
        guard
            InvitationToken.normalize(inviteToken) != nil,
            let context = currentOperationContext
        else {
            return .failed("This invitation link is invalid. Open the original link and try again.")
        }
        return await withSerializedOperation(context) {
            guard self.operationIsCurrent(context) else { return .unauthorized }
            self.errorMessage = nil
            do {
                let invitation = try await self.apiClient.fetchInvitation(
                    inviteToken: inviteToken
                )
                try self.requireCurrentOperation(context)
                if let index = self.events.firstIndex(where: { $0.id == invitation.id }) {
                    self.events[index] = invitation
                } else {
                    self.events.append(invitation)
                }
                if invitation.responseCertificationStatus == .pending,
                   invitation.responseRevision != nil {
                    _ = await self.performRetryPendingResponseCertification(
                        for: invitation,
                        context: context
                    )
                    guard self.operationIsCurrent(context) else { return .unauthorized }
                }
                self.sortEvents()
                self.persistCache()
                self.isUsingCachedData = false
                return .loaded(invitation.id)
            } catch APIError.inviteForDifferentAccount {
                guard self.operationIsCurrent(context) else { return .unauthorized }
                return .differentAccount
            } catch APIError.unauthorized {
                guard self.operationIsCurrent(context) else { return .unauthorized }
                self.handleUnauthorized()
                return .unauthorized
            } catch is CancellationError {
                return .failed("Herd stopped opening this invitation. Try again.")
            } catch {
                guard self.operationIsCurrent(context) else { return .unauthorized }
                let message = Self.message(for: error)
                self.errorMessage = message
                return .failed(message)
            }
        } ?? .unauthorized
    }

    private func performRefresh(context: OperationContext) async {
        guard operationIsCurrent(context) else { return }
        isRefreshing = true
        errorMessage = nil
        defer { isRefreshing = false }

        do {
            var syncedEvents = try await apiClient.fetchEvents()
            try requireCurrentOperation(context)
            let didCompleteEvaluation = try await relayDueHostedEvaluations(
                in: syncedEvents,
                context: context
            )
            try requireCurrentOperation(context)
            if didCompleteEvaluation {
                syncedEvents = try await apiClient.fetchEvents()
                try requireCurrentOperation(context)
            }
            let migrationError = try await migrateLegacyHostedEvents(
                into: &syncedEvents,
                context: context
            )
            try requireCurrentOperation(context)
            events = mergeEvents(syncedEvents, with: pendingLegacyEvents)
            sortEvents()
            let pendingCertifications = events.filter {
                $0.role == .invitee &&
                    $0.responseCertificationStatus == .pending &&
                    $0.responseRevision != nil
            }
            for pendingEvent in pendingCertifications {
                try requireCurrentOperation(context)
                guard await performRetryPendingResponseCertification(
                    for: pendingEvent,
                    context: context
                ) else {
                    break
                }
            }
            try requireCurrentOperation(context)
            persistCache()
            let updatedAt = Date()
            lastUpdatedAt = updatedAt
            defaults.set(updatedAt, forKey: Self.lastUpdatedKey(for: context.userID))
            isUsingCachedData = !pendingLegacyEvents.isEmpty
            if let migrationError {
                let eventLabel = pendingLegacyEvents.count == 1 ? "event" : "events"
                errorMessage = "Couldn’t sync \(pendingLegacyEvents.count) older \(eventLabel) yet. \(Self.message(for: migrationError))"
            }
        } catch APIError.unauthorized {
            guard operationIsCurrent(context) else { return }
            handleUnauthorized()
        } catch is CancellationError {
            return
        } catch {
            guard operationIsCurrent(context) else { return }
            isUsingCachedData = !events.isEmpty
            errorMessage = events.isEmpty
                ? Self.message(for: error)
                : "Couldn’t refresh right now. Showing your last synced events."
        }
    }

    private static func lastUpdatedKey(for userID: String) -> String {
        "\(lastUpdatedKeyPrefix).\(userID)"
    }

    private func relayDueHostedEvaluations(
        in syncedEvents: [HerdEvent],
        context: OperationContext
    ) async throws -> Bool {
        let dueEventIDs = syncedEvents.compactMap { event -> UUID? in
            guard
                event.invitationsSent,
                event.privateResponsePolicy != nil,
                event.resolution == nil ||
                    event.resolution?.status == .pending ||
                    (event.resolution?.status == .confirmed &&
                        event.resolution?.attendanceRevealed != true)
            else { return nil }
            return event.id
        }

        var didComplete = false
        for eventID in dueEventIDs {
            do {
                didComplete = try await apiClient.relayEvaluation(eventID: eventID) || didComplete
                try requireCurrentOperation(context)
            } catch APIError.unauthorized {
                throw APIError.unauthorized
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                // Relays are deliberately retryable. Keep normal event refreshes
                // working and leave the resolution pending for the next pass.
                try requireCurrentOperation(context)
            }
        }
        return didComplete
    }

    @discardableResult
    func upsert(_ event: HerdEvent) async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            await self.performUpsert(event, context: context)
        } ?? false
    }

    private func performUpsert(_ event: HerdEvent, context: OperationContext) async -> Bool {
        guard operationIsCurrent(context) else { return false }
        guard event.isHosted else {
            errorMessage = "Only the host can edit this event."
            return false
        }
        isMutating = true
        errorMessage = nil
        defer { isMutating = false }

        do {
            let savedEvent = try await apiClient.upsertEvent(event)
            try requireCurrentOperation(context)
            if let index = events.firstIndex(where: { $0.id == savedEvent.id }) {
                events[index] = savedEvent
            } else {
                events.append(savedEvent)
            }
            sortEvents()
            persistCache()
            isUsingCachedData = false
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(context) else { return false }
            handleUnauthorized()
            return false
        } catch is CancellationError {
            return false
        } catch {
            guard operationIsCurrent(context) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    @discardableResult
    func addAttendees(_ invitees: [Invitee], to eventID: UUID) async -> Bool {
        guard !invitees.isEmpty, let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            guard self.operationIsCurrent(context) else { return false }
            self.isMutating = true
            self.errorMessage = nil
            defer { self.isMutating = false }

            do {
                let savedEvent = try await self.apiClient.addAttendees(
                    eventID: eventID,
                    invitees: invitees
                )
                try self.requireCurrentOperation(context)
                guard let index = self.events.firstIndex(where: { $0.id == eventID }) else {
                    throw APIError.invalidResponse
                }
                self.events[index] = savedEvent
                self.sortEvents()
                self.persistCache()
                self.isUsingCachedData = false
                return true
            } catch APIError.unauthorized {
                guard self.operationIsCurrent(context) else { return false }
                self.handleUnauthorized()
                return false
            } catch is CancellationError {
                return false
            } catch {
                guard self.operationIsCurrent(context) else { return false }
                self.errorMessage = Self.message(for: error)
                return false
            }
        } ?? false
    }

    @discardableResult
    func delete(_ event: HerdEvent) async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            await self.performDelete(event, context: context)
        } ?? false
    }

    private func performDelete(_ event: HerdEvent, context: OperationContext) async -> Bool {
        guard operationIsCurrent(context) else { return false }
        guard event.isHosted else {
            errorMessage = "Only the host can delete this event."
            return false
        }
        isMutating = true
        errorMessage = nil
        defer { isMutating = false }

        do {
            try await apiClient.deleteEvent(id: event.id)
            try requireCurrentOperation(context)
            events.removeAll { $0.id == event.id }
            persistCache()
            isUsingCachedData = false
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(context) else { return false }
            handleUnauthorized()
            return false
        } catch is CancellationError {
            return false
        } catch {
            guard operationIsCurrent(context) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    @discardableResult
    func respond(to event: HerdEvent, with response: RSVPResponse) async -> Bool {
        await respond(
            to: event,
            draft: PrivateResponseDraft(
                response: response,
                minimumParticipants: response == .going ? event.minimumParticipants : nil,
                requiredGroups: []
            )
        )
    }

    @discardableResult
    func respond(to event: HerdEvent, draft: PrivateResponseDraft) async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            await self.performRespond(to: event, draft: draft, context: context)
        } ?? false
    }

    private func performRespond(
        to event: HerdEvent,
        draft: PrivateResponseDraft,
        context operationContext: OperationContext
    ) async -> Bool {
        guard operationIsCurrent(operationContext) else { return false }
        let activeUserID = operationContext.userID
        guard event.role == .invitee, let inviteToken = event.inviteToken, !inviteToken.isEmpty else {
            errorMessage = "This invitation doesn’t have an active reply link."
            return false
        }
        isMutating = true
        let initialPrivacyLockGeneration = privacyLockGeneration
        errorMessage = nil
        defer { isMutating = false }

        do {
            do {
                let ballot = try await apiClient.submitSimplifiedBallot(
                    inviteToken: inviteToken,
                    draft: draft
                )
                try requireCurrentOperation(operationContext)
                guard let index = events.firstIndex(where: { $0.id == event.id }) else {
                    throw APIError.invalidResponse
                }
                events[index].hasBallot = true
                events[index].responseRevision = ballot.revision
                if let inviteeIndex = events[index].invitees.firstIndex(where: \.isCurrentUser) {
                    events[index].invitees[inviteeIndex].hasResponded = true
                }
                unavailablePrivateResponseEventID = nil
                if privacyLockGeneration == initialPrivacyLockGeneration {
                    unlockedResponses[event.id] = draft.response
                    unlockedDrafts[event.id] = draft
                }
                pendingCertificationEnvelopes[event.id] = nil
                pendingResponseSubmissions[event.id] = nil
                persistCache()
                isUsingCachedData = false
                return true
            } catch let APIError.server(statusCode, _) where statusCode == 404 {
                // A bounded rollout fallback for a pre-ballot server. Once all
                // supported servers expose /ballot, the legacy path below can
                // be deleted without changing the account-wide product flow.
            }

            // Legacy protocol-v1 fallback is intentionally retained only for
            // rollback compatibility with a server predating ballot support.
            let context = try await apiClient.fetchInvitePrivateResponse(inviteToken: inviteToken)
            try requireCurrentOperation(operationContext)
            if let index = events.firstIndex(where: { $0.id == event.id }) {
                events[index].responseCertificationStatus = context.responseCertificationStatus
            }
            if
                context.responseCertificationStatus == .pending,
                let storedEnvelope = context.responseEnvelope
            {
                pendingCertificationEnvelopes[event.id] = storedEnvelope.envelope
            } else {
                pendingCertificationEnvelopes[event.id] = nil
            }
            guard context.event.id == event.id, let policy = context.event.privateResponsePolicy else {
                throw PrivateResponseCryptoError.invalidPolicy(
                    "This event is not ready to accept encrypted private replies."
                )
            }

            let accountRootSecret: SymmetricKey
            let keyCommitment: String
            let hasLocalKey = await accountKeyStore.hasRootSecret(
                userID: activeUserID,
                epochID: context.accountKeyEpochID
            )
            try requireCurrentOperation(operationContext)
            if hasLocalKey {
                accountRootSecret = try await accountKeyStore.rootSecret(
                    userID: activeUserID,
                    epochID: context.accountKeyEpochID
                )
                try requireCurrentOperation(operationContext)
            } else if context.accountKeyCommitment == nil {
                accountRootSecret = try await accountKeyStore.createRootSecret(
                    userID: activeUserID,
                    epochID: context.accountKeyEpochID
                )
                try requireCurrentOperation(operationContext)
            } else {
                throw PrivateResponseCryptoError.decryptionFailed
            }
            keyCommitment = await accountKeyStore.commitment(for: accountRootSecret)
            try requireCurrentOperation(operationContext)
            if let expectedCommitment = context.accountKeyCommitment {
                guard expectedCommitment == keyCommitment else {
                    throw PrivateResponseCryptoError.decryptionFailed
                }
            } else {
                try await apiClient.initializeAccountKeyEpoch(
                    expectedAccountKeyEpochId: context.accountKeyEpochID,
                    keyCommitment: keyCommitment
                )
                try requireCurrentOperation(operationContext)
            }
            let crypto = try privateResponseDependencies.makeCrypto()
            let revision = (context.responseRevision ?? 0) + 1
            let pendingSubmission = pendingResponseSubmissions[event.id]
            let serverAlreadyStoredPendingSubmission = pendingSubmission.map {
                context.responseEnvelope?.envelope == $0.envelope
            } ?? false
            let envelope: PrivateResponseEnvelopeV1
            if
                let pendingSubmission,
                pendingSubmission.draft == draft,
                pendingSubmission.accountKeyEpochID == context.accountKeyEpochID,
                (
                    pendingSubmission.revision == revision ||
                    serverAlreadyStoredPendingSubmission
                ),
                pendingSubmission.policyHash == policy.policyHash
            {
                envelope = pendingSubmission.envelope
            } else {
                let attestationNonce = try secureRandomData(count: 32)
                    .base64URLEncodedString()
                let attestation = try await apiClient.fetchEvaluatorAttestation(
                    nonce: attestationNonce
                )
                try requireCurrentOperation(operationContext)
                try privateResponseDependencies.verifyAttestation(
                    attestation,
                    attestationNonce,
                    policy
                )
                envelope = try crypto.seal(
                    eventID: event.id,
                    inviteeID: context.inviteeID,
                    accountKeyEpochID: context.accountKeyEpochID,
                    revision: revision,
                    response: draft.response,
                    minimumParticipants: draft.minimumParticipants,
                    minimumAllowedParticipants: context.event.minimumParticipants,
                    requiredGroups: draft.requiredGroups,
                    allowedMemberIDs: Set(context.event.invitees.map(\.id)),
                    policy: policy,
                    accountRootSecret: accountRootSecret
                )
                pendingResponseSubmissions[event.id] = PendingResponseSubmission(
                    draft: draft,
                    accountKeyEpochID: context.accountKeyEpochID,
                    revision: revision,
                    policyHash: policy.policyHash,
                    envelope: envelope
                )
            }
            let result = try await apiClient.submitRSVP(
                inviteToken: inviteToken,
                envelope: envelope
            )
            try requireCurrentOperation(operationContext)
            let expectedCiphertextHash = try crypto.envelopeHash(envelope)
            guard
                result.responseEnvelope.envelope == envelope,
                result.receipt.eventId == envelope.eventId,
                result.receipt.inviteeId == envelope.inviteeId,
                result.receipt.envelopeId == envelope.envelopeId,
                result.receipt.policyHash == envelope.policyHash,
                result.receipt.accountKeyEpochId == envelope.accountKeyEpochId,
                result.receipt.revision == envelope.revision,
                result.receipt.responseSigningPublicKey == envelope.responseSigningPublicKey,
                result.receipt.responseSignature == envelope.responseSignature,
                result.responseEnvelope.ciphertextHash == expectedCiphertextHash,
                result.receipt.ciphertextHash == expectedCiphertextHash
            else { throw APIError.invalidResponse }
            try privateResponseDependencies.verifyReceipt(result.receipt)
            guard let proof = result.receipt.transparency else {
                throw APIError.invalidResponse
            }
            let publicLog = try await apiClient.fetchResponseTransparencyEntry(
                logIndex: proof.logIndex
            )
            try requireCurrentOperation(operationContext)
            try privateResponseDependencies.verifyPublication(result.receipt, publicLog)
            guard let index = events.firstIndex(where: { $0.id == event.id }) else {
                throw APIError.invalidResponse
            }
            events[index].accountKeyEpochId = context.accountKeyEpochID
            events[index].accountKeyCommitment = keyCommitment
            events[index].hasResponse = true
            events[index].responseRevision = result.receipt.revision
            events[index].responseCertificationStatus = .certified
            if let inviteeIndex = events[index].invitees.firstIndex(where: \.isCurrentUser) {
                events[index].invitees[inviteeIndex].hasResponded = true
            }
            events[index].privateResponsePolicy = policy
            unavailablePrivateResponseEventID = nil
            if privacyLockGeneration == initialPrivacyLockGeneration {
                unlockedResponses[event.id] = draft.response
                unlockedDrafts[event.id] = draft
            }
            persistCache()
            isUsingCachedData = false
            pendingCertificationEnvelopes[event.id] = nil
            pendingResponseSubmissions[event.id] = nil
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(operationContext) else { return false }
            handleUnauthorized()
            return false
        } catch is CancellationError {
            return false
        } catch {
            guard operationIsCurrent(operationContext) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    @discardableResult
    func unlockPrivateResponse(for event: HerdEvent) async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            await self.performUnlockPrivateResponse(for: event, context: context)
        } ?? false
    }

    private func performUnlockPrivateResponse(
        for event: HerdEvent,
        context operationContext: OperationContext
    ) async -> Bool {
        let startedAt = Date()
        func report(_ outcome: String, _ errorCode: String) async {
            await apiClient.reportLocalClientTelemetry(
                operation: "reply.saved.open",
                outcome: outcome,
                errorCode: errorCode,
                durationMilliseconds: Int(Date().timeIntervalSince(startedAt) * 1_000)
            )
        }
        guard operationIsCurrent(operationContext) else { return false }
        let activeUserID = operationContext.userID
        guard
            event.role == .invitee,
            let inviteToken = event.inviteToken,
            (event.hasResponse || event.hasBallot)
        else { return false }
        if unlockedDrafts[event.id] != nil { return true }

        isMutating = true
        let initialPrivacyLockGeneration = privacyLockGeneration
        errorMessage = nil
        defer { isMutating = false }
        do {
            let ballot: SimplifiedBallot?
            do {
                ballot = try await apiClient.fetchSimplifiedBallot(inviteToken: inviteToken)
            } catch let APIError.server(statusCode, _) where statusCode == 404 {
                ballot = nil
            }
            if let ballot {
                try requireCurrentOperation(operationContext)
                let draft = PrivateResponseDraft(
                    response: ballot.response,
                    minimumParticipants: ballot.minimumParticipants,
                    requiredGroups: ballot.requiredGroups
                )
                guard privacyLockGeneration == initialPrivacyLockGeneration else {
                    return false
                }
                unlockedResponses[event.id] = ballot.response
                unlockedDrafts[event.id] = draft
                if let index = events.firstIndex(where: { $0.id == event.id }) {
                    events[index].hasBallot = true
                    events[index].responseRevision = ballot.revision
                }
                unavailablePrivateResponseEventID = nil
                await report("success", "none")
                return true
            }
            let context = try await apiClient.fetchInvitePrivateResponse(inviteToken: inviteToken)
            try requireCurrentOperation(operationContext)
            guard
                context.event.id == event.id,
                let storedEnvelope = context.responseEnvelope,
                let policy = context.event.privateResponsePolicy,
                context.responseRevision == storedEnvelope.revision
            else { throw APIError.invalidResponse }
            if let index = events.firstIndex(where: { $0.id == event.id }) {
                events[index].responseCertificationStatus = context.responseCertificationStatus
            }
            if context.responseCertificationStatus == .pending {
                pendingCertificationEnvelopes[event.id] = storedEnvelope.envelope
            } else {
                pendingCertificationEnvelopes[event.id] = nil
            }
            let hasRootSecret = await accountKeyStore.hasRootSecret(
                userID: activeUserID,
                epochID: context.accountKeyEpochID
            )
            try requireCurrentOperation(operationContext)
            guard hasRootSecret else { throw AccountKeyStoreError.missingKey }
            let accountRootSecret = try await accountKeyStore.rootSecret(
                userID: activeUserID,
                epochID: context.accountKeyEpochID
            )
            try requireCurrentOperation(operationContext)
            let keyCommitment = await accountKeyStore.commitment(for: accountRootSecret)
            try requireCurrentOperation(operationContext)
            guard keyCommitment == context.accountKeyCommitment else {
                throw AccountKeyStoreError.wrongEpoch
            }
            let crypto = try privateResponseDependencies.makeCrypto()
            guard try crypto.envelopeHash(storedEnvelope.envelope) == storedEnvelope.ciphertextHash else {
                throw APIError.invalidResponse
            }
            let plaintext = try crypto.open(
                storedEnvelope.envelope,
                eventID: event.id,
                inviteeID: context.inviteeID,
                accountKeyEpochID: context.accountKeyEpochID,
                minimumAllowedParticipants: context.event.minimumParticipants,
                allowedMemberIDs: Set(context.event.invitees.map(\.id)),
                policy: policy,
                accountRootSecret: accountRootSecret
            )
            guard
                plaintext.eventId == event.id.uuidString.lowercased(),
                plaintext.inviteeId == context.inviteeID.uuidString.lowercased()
            else { throw APIError.invalidResponse }
            let draft = PrivateResponseDraft(
                response: plaintext.response,
                minimumParticipants: plaintext.minimumParticipants,
                requiredGroups: plaintext.requiredGroups
            )
            guard privacyLockGeneration == initialPrivacyLockGeneration else {
                return false
            }
            unlockedResponses[event.id] = plaintext.response
            unlockedDrafts[event.id] = draft
            if context.responseCertificationStatus == .pending {
                pendingResponseSubmissions[event.id] = PendingResponseSubmission(
                    draft: draft,
                    accountKeyEpochID: UUID(uuidString: storedEnvelope.accountKeyEpochId)
                        ?? context.accountKeyEpochID,
                    revision: storedEnvelope.revision,
                    policyHash: storedEnvelope.policyHash,
                    envelope: storedEnvelope.envelope
                )
            }
            unavailablePrivateResponseEventID = nil
            await report("success", "none")
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(operationContext) else { return false }
            await report("failure", "session_expired")
            handleUnauthorized()
            return false
        } catch is CancellationError {
            await report("cancelled", "cancelled")
            return false
        } catch let error as AccountKeyStoreError {
            guard operationIsCurrent(operationContext) else { return false }
            let telemetryCode: String
            switch error {
            case .missingKey:
                telemetryCode = "saved_reply_missing_key"
                unavailablePrivateResponseEventID = event.id
                errorMessage = nil
            case .wrongEpoch:
                telemetryCode = "saved_reply_wrong_epoch"
                unavailablePrivateResponseEventID = event.id
                errorMessage = nil
            case .decryptionFailed:
                telemetryCode = "saved_reply_key_decryption_failed"
                unavailablePrivateResponseEventID = event.id
                errorMessage = nil
            case .invalidRecord:
                telemetryCode = "saved_reply_invalid_key_record"
                unavailablePrivateResponseEventID = event.id
                errorMessage = nil
            case .devicePasscodeRequired:
                telemetryCode = "device_passcode_required"
                errorMessage = Self.message(for: error)
            case .keychain:
                telemetryCode = "keychain_unavailable"
                errorMessage = Self.message(for: error)
            }
            await report("failure", telemetryCode)
            return false
        } catch let error as PrivateResponseCryptoError {
            guard operationIsCurrent(operationContext) else { return false }
            let telemetryCode = Self.savedReplyReplacementErrorCode(for: error)
                ?? Self.savedReplyBlockedErrorCode(for: error)
            if Self.savedReplyReplacementErrorCode(for: error) != nil {
                unavailablePrivateResponseEventID = event.id
                errorMessage = nil
            } else {
                errorMessage = Self.message(for: error)
            }
            await report("failure", telemetryCode)
            return false
        } catch {
            guard operationIsCurrent(operationContext) else { return false }
            errorMessage = Self.message(for: error)
            await report("failure", "saved_reply_open_failed")
            return false
        }
    }

    func hasPendingResponseSubmission(
        for eventID: UUID,
        draft: PrivateResponseDraft
    ) -> Bool {
        pendingResponseSubmissions[eventID]?.draft == draft
    }

    func hasPendingResponseCertification(for eventID: UUID) -> Bool {
        pendingCertificationEnvelopes[eventID] != nil ||
            events.first(where: { $0.id == eventID })?.responseCertificationStatus == .pending
    }

    @discardableResult
    func retryPendingResponseCertification(for event: HerdEvent) async -> Bool {
        guard let operationContext = currentOperationContext else { return false }
        return await withSerializedOperation(operationContext) {
            await self.performRetryPendingResponseCertification(
                for: event,
                context: operationContext
            )
        } ?? false
    }

    private func performRetryPendingResponseCertification(
        for event: HerdEvent,
        context operationContext: OperationContext
    ) async -> Bool {
        guard
            operationIsCurrent(operationContext),
            let inviteToken = event.inviteToken,
            !inviteToken.isEmpty
        else { return false }
        isMutating = true
        errorMessage = nil
        defer { isMutating = false }
        do {
            let context = try await apiClient.fetchInvitePrivateResponse(
                inviteToken: inviteToken
            )
            try requireCurrentOperation(operationContext)
            guard
                context.event.id == event.id,
                let storedEnvelope = context.responseEnvelope
            else { throw APIError.invalidResponse }
            if context.responseCertificationStatus == .certified {
                guard let index = events.firstIndex(where: { $0.id == event.id }) else {
                    throw APIError.invalidResponse
                }
                events[index].responseCertificationStatus = .certified
                pendingCertificationEnvelopes[event.id] = nil
                pendingResponseSubmissions[event.id] = nil
                persistCache()
                return true
            }
            guard context.responseCertificationStatus == .pending else {
                throw APIError.invalidResponse
            }
            let envelope = storedEnvelope.envelope
            let result = try await apiClient.submitRSVP(
                inviteToken: inviteToken,
                envelope: envelope
            )
            try requireCurrentOperation(operationContext)
            let expectedCiphertextHash = try privateResponseDependencies.makeCrypto()
                .envelopeHash(envelope)
            guard
                result.responseEnvelope.envelope == envelope,
                result.responseEnvelope.ciphertextHash == expectedCiphertextHash,
                result.receipt.envelopeId == envelope.envelopeId,
                result.receipt.eventId == envelope.eventId,
                result.receipt.inviteeId == envelope.inviteeId,
                result.receipt.policyHash == envelope.policyHash,
                result.receipt.accountKeyEpochId == envelope.accountKeyEpochId,
                result.receipt.revision == envelope.revision,
                result.receipt.responseSigningPublicKey == envelope.responseSigningPublicKey,
                result.receipt.responseSignature == envelope.responseSignature,
                result.receipt.ciphertextHash == expectedCiphertextHash
            else { throw APIError.invalidResponse }
            try privateResponseDependencies.verifyReceipt(result.receipt)
            guard let proof = result.receipt.transparency else {
                throw APIError.invalidResponse
            }
            let publicLog = try await apiClient.fetchResponseTransparencyEntry(
                logIndex: proof.logIndex
            )
            try requireCurrentOperation(operationContext)
            try privateResponseDependencies.verifyPublication(result.receipt, publicLog)
            guard let index = events.firstIndex(where: { $0.id == event.id }) else {
                throw APIError.invalidResponse
            }
            events[index].hasResponse = true
            events[index].responseRevision = envelope.revision
            events[index].responseCertificationStatus = .certified
            if let inviteeIndex = events[index].invitees.firstIndex(where: \.isCurrentUser) {
                events[index].invitees[inviteeIndex].hasResponded = true
            }
            pendingCertificationEnvelopes[event.id] = nil
            pendingResponseSubmissions[event.id] = nil
            persistCache()
            isUsingCachedData = false
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(operationContext) else { return false }
            handleUnauthorized()
            return false
        } catch is CancellationError {
            return false
        } catch {
            guard operationIsCurrent(operationContext) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    func clearError() {
        errorMessage = nil
    }

    func lockPrivateResponses() {
        privacyLockGeneration &+= 1
        unlockedResponses = [:]
        unlockedDrafts = [:]
    }

    func lockPrivateResponse(for eventID: UUID) {
        privacyLockGeneration &+= 1
        unlockedResponses[eventID] = nil
        unlockedDrafts[eventID] = nil
    }

    private var currentOperationContext: OperationContext? {
        guard let activeUserID else { return nil }
        return OperationContext(
            userID: activeUserID,
            sessionGeneration: sessionGeneration
        )
    }

    private func operationIsCurrent(_ context: OperationContext) -> Bool {
        !Task.isCancelled
            && activeUserID == context.userID
            && sessionGeneration == context.sessionGeneration
    }

    private func requireCurrentOperation(_ context: OperationContext) throws {
        guard operationIsCurrent(context) else { throw CancellationError() }
    }

    private func withSerializedOperation<T>(
        _ context: OperationContext,
        operation: @MainActor () async -> T
    ) async -> T? {
        await operationGate.acquire()
        guard operationIsCurrent(context) else {
            await operationGate.release()
            return nil
        }
        let result = await operation()
        await operationGate.release()
        return result
    }

    private var cacheKey: String? {
        activeUserID.map { "herd.events.cache.v2.\($0)" }
    }

    private func loadCachedEvents() -> [HerdEvent] {
        guard let cacheKey, let data = defaults.data(forKey: cacheKey) else {
            return []
        }

        if let events = try? HerdJSON.makeDecoder().decode([HerdEvent].self, from: data) {
            return events.map { EventResolutionVerifier.failClosed($0) }
        }

        return []
    }

    private func loadLegacyHostedEvents() -> [HerdEvent] {
        guard
            let data = defaults.data(forKey: Self.legacyEventsKey),
            var legacyEvents = try? JSONDecoder().decode([HerdEvent].self, from: data)
        else { return [] }

        for index in legacyEvents.indices {
            legacyEvents[index].role = .host
            legacyEvents[index].inviteToken = nil
            legacyEvents[index].accountKeyEpochId = nil
            legacyEvents[index].accountKeyCommitment = nil
            legacyEvents[index].hasResponse = false
            legacyEvents[index].responseRevision = nil
            legacyEvents[index].privateResponsePolicy = nil
            legacyEvents[index].resolution = nil
            legacyEvents[index].invitationDelivery = nil
            // Legacy local events predate frozen response policies and cannot safely
            // be treated as already sent. Import them as editable drafts so the host
            // must explicitly send them through the current invitation flow.
            legacyEvents[index].invitationsSent = false
        }
        return legacyEvents
    }

    private func migrateLegacyHostedEvents(
        into syncedEvents: inout [HerdEvent],
        context: OperationContext
    ) async throws -> Error? {
        try requireCurrentOperation(context)

        let syncedEventIDs = Set(syncedEvents.map(\.id))
        pendingLegacyEvents.removeAll { syncedEventIDs.contains($0.id) }
        guard !pendingLegacyEvents.isEmpty else {
            removeClaimedLegacyStorage(for: context.userID)
            return nil
        }

        var remainingEvents: [HerdEvent] = []
        var firstError: Error?
        for event in pendingLegacyEvents {
            do {
                let savedEvent = try await apiClient.upsertEvent(event)
                try requireCurrentOperation(context)
                syncedEvents = mergeEvents(syncedEvents, with: [savedEvent])
            } catch APIError.unauthorized {
                throw APIError.unauthorized
            } catch is CancellationError {
                throw CancellationError()
            } catch {
                try requireCurrentOperation(context)
                remainingEvents.append(event)
                firstError = firstError ?? error
            }
        }

        try requireCurrentOperation(context)
        pendingLegacyEvents = remainingEvents
        if remainingEvents.isEmpty {
            removeClaimedLegacyStorage(for: context.userID)
        }
        return firstError
    }

    private func removeClaimedLegacyStorage(for userID: String) {
        guard defaults.string(forKey: Self.legacyOwnerKey) == userID else { return }
        defaults.removeObject(forKey: Self.legacyEventsKey)
        defaults.removeObject(forKey: Self.legacyOwnerKey)
    }

    private func removeLegacyEventsFromOtherCaches(ownerID: String, eventIDs: Set<UUID>) {
        guard !eventIDs.isEmpty else { return }
        let ownerCacheKey = "herd.events.cache.v2.\(ownerID)"
        for key in defaults.dictionaryRepresentation().keys
            where key.hasPrefix("herd.events.cache.v2.") && key != ownerCacheKey {
            guard
                let data = defaults.data(forKey: key),
                let cachedEvents = try? HerdJSON.makeDecoder().decode([HerdEvent].self, from: data)
            else { continue }
            let filtered = cachedEvents.filter { !eventIDs.contains($0.id) }
            if filtered.isEmpty {
                defaults.removeObject(forKey: key)
            } else if let filteredData = try? HerdJSON.makeEncoder().encode(filtered) {
                defaults.set(filteredData, forKey: key)
            }
        }
    }

    private func mergeEvents(_ primary: [HerdEvent], with fallback: [HerdEvent]) -> [HerdEvent] {
        var merged = primary
        let primaryIDs = Set(primary.map(\.id))
        merged.append(contentsOf: fallback.filter { !primaryIDs.contains($0.id) })
        return merged
    }

    private func persistCache() {
        guard
            let cacheKey,
            let data = try? HerdJSON.makeEncoder().encode(events)
        else {
            return
        }
        defaults.set(data, forKey: cacheKey)
    }

    private func sortEvents() {
        events.sort { lhs, rhs in
            (lhs.eventDate ?? .distantFuture) < (rhs.eventDate ?? .distantFuture)
        }
    }

    private func removeLegacyPrivateResponseCaches() {
        for key in defaults.dictionaryRepresentation().keys where key.hasPrefix("herd.events.cache.v1.") {
            defaults.removeObject(forKey: key)
        }
    }

    private func handleUnauthorized() {
        clearSession()
        unauthorizedHandler?()
    }

    private static func message(for error: Error) -> String {
        if let localizedError = error as? LocalizedError,
           let description = localizedError.errorDescription {
            return description
        }
        return error.localizedDescription
    }

    static func savedReplyReplacementErrorCode(
        for error: PrivateResponseCryptoError
    ) -> String? {
        switch error {
        case .invalidEnvelope:
            "saved_reply_invalid_envelope"
        case .invalidDraft:
            "saved_reply_invalid_draft"
        case .decryptionFailed:
            "saved_reply_decryption_failed"
        case .invalidPolicy, .invalidReceipt, .untrustedEvaluator,
             .payloadTooLarge, .randomGenerationFailed:
            nil
        }
    }

    static func savedReplyBlockedErrorCode(
        for error: PrivateResponseCryptoError
    ) -> String {
        switch error {
        case .invalidPolicy:
            "saved_reply_invalid_policy"
        case .invalidReceipt:
            "saved_reply_invalid_receipt"
        case .untrustedEvaluator:
            "saved_reply_untrusted_evaluator"
        case .payloadTooLarge:
            "saved_reply_payload_too_large"
        case .randomGenerationFailed:
            "saved_reply_random_generation_failed"
        case .invalidEnvelope, .invalidDraft, .decryptionFailed:
            savedReplyReplacementErrorCode(for: error) ?? "saved_reply_open_failed"
        }
    }
}
