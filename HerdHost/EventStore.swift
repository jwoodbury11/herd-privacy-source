import CryptoKit
import Foundation
import Observation

enum InvitationOpenOutcome: Equatable {
    case loaded(UUID)
    case differentAccount
    case unauthorized
    case failed(String)
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

    private(set) var events: [HerdEvent] = []
    private(set) var isRefreshing = false
    private(set) var isMutating = false
    private(set) var isUsingCachedData = false
    private(set) var errorMessage: String?
    private(set) var unlockedResponses: [UUID: RSVPResponse] = [:]
    private(set) var unlockedDrafts: [UUID: PrivateResponseDraft] = [:]
    private(set) var accountResetEventID: UUID?
    private(set) var isResettingAccount = false
    private(set) var legacyImportCandidateCount = 0

    private let defaults: UserDefaults
    private let apiClient: APIClient
    private let accountKeyStore: AccountKeyStore
    private let operationGate = EventStoreOperationGate()
    private var activeUserID: String?
    private var sessionGeneration: UInt = 0
    private var unauthorizedHandler: (() -> Void)?
    private var pendingResetDrafts: [UUID: PrivateResponseDraft] = [:]
    private var pendingLegacyEvents: [HerdEvent] = []
    private var privacyLockGeneration: UInt = 0
    private static let legacyEventsKey = "herd.host.events.v1"
    private static let legacyOwnerKey = "herd.host.events.v1.claimed-user-id"

    init(
        defaults: UserDefaults = .standard,
        apiClient: APIClient = APIClient(),
        accountKeyStore: AccountKeyStore = AccountKeyStore()
    ) {
        self.defaults = defaults
        self.apiClient = apiClient
        self.accountKeyStore = accountKeyStore
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
        pendingResetDrafts = [:]
        accountResetEventID = nil
        isRefreshing = false
        isMutating = false
        isResettingAccount = false
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
        pendingResetDrafts = [:]
        pendingLegacyEvents = []
        accountResetEventID = nil
        isRefreshing = false
        isMutating = false
        isResettingAccount = false
        legacyImportCandidateCount = 0
        isUsingCachedData = false
        errorMessage = nil
    }

    func eraseLocalAccountData(userID: String) {
        defaults.removeObject(forKey: "herd.events.cache.v2.\(userID)")
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
            persistCache()
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

    private func relayDueHostedEvaluations(
        in syncedEvents: [HerdEvent],
        context: OperationContext
    ) async throws -> Bool {
        let dueEventIDs = syncedEvents.compactMap { event -> UUID? in
            guard
                event.role == .host,
                event.invitationsSent,
                event.privateResponsePolicy != nil,
                let deadline = event.rsvpDeadline,
                deadline <= .now,
                event.resolution == nil || event.resolution?.status == .pending
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
            let context = try await apiClient.fetchInvitePrivateResponse(inviteToken: inviteToken)
            try requireCurrentOperation(operationContext)
            guard context.event.id == event.id, let policy = context.event.privateResponsePolicy else {
                throw PrivateResponseCryptoError.invalidPolicy(
                    "This event is not ready to accept encrypted private replies."
                )
            }

            let hasLocalKey = await accountKeyStore.hasRootSecret(
                userID: activeUserID,
                epochID: context.accountKeyEpochID
            )
            try requireCurrentOperation(operationContext)
            let accountRootSecret: SymmetricKey
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
                if context.hasResponse {
                    errorMessage = "This saved reply is locked to the account key that authorized it. Starting over can secure future replies, but it cannot replace this one."
                    return false
                }
                pendingResetDrafts[event.id] = draft
                accountResetEventID = event.id
                errorMessage = nil
                return false
            }
            let keyCommitment = await accountKeyStore.commitment(for: accountRootSecret)
            try requireCurrentOperation(operationContext)
            if let expectedCommitment = context.accountKeyCommitment {
                guard expectedCommitment == keyCommitment else {
                    if context.hasResponse {
                        errorMessage = "This saved reply is locked to the account key that authorized it. Starting over can secure future replies, but it cannot replace this one."
                        return false
                    }
                    pendingResetDrafts[event.id] = draft
                    accountResetEventID = event.id
                    errorMessage = nil
                    return false
                }
            } else {
                try await apiClient.initializeAccountKeyEpoch(
                    expectedAccountKeyEpochId: context.accountKeyEpochID,
                    keyCommitment: keyCommitment
                )
                try requireCurrentOperation(operationContext)
            }
#if DEBUG
            let softwareQAEvaluator = try EvaluatorAttestationVerifier
                .allowsSoftwareQAEvaluator(policy: policy)
#else
            let softwareQAEvaluator = false
#endif
            if !softwareQAEvaluator {
                let attestationNonce = try secureRandomData(count: 32)
                    .base64URLEncodedString()
                let attestation = try await apiClient.fetchEvaluatorAttestation(
                    nonce: attestationNonce
                )
                try requireCurrentOperation(operationContext)
                try EvaluatorAttestationVerifier.configured().verify(
                    attestation,
                    nonce: attestationNonce,
                    policy: policy
                )
            }
            let crypto = try PrivateResponseCrypto.configured()
            let revision = (context.responseRevision ?? 0) + 1
            let envelope = try crypto.seal(
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
            let receiptVerifier = try PrivateResponseReceiptVerifier.configured()
            try receiptVerifier.verify(result.receipt)
            guard let proof = result.receipt.transparency else {
                throw APIError.invalidResponse
            }
            let publicLog = try await apiClient.fetchResponseTransparencyEntry(
                logIndex: proof.logIndex
            )
            try requireCurrentOperation(operationContext)
            try PrivateResponseReceiptPublicationVerifier.verify(
                receipt: result.receipt,
                publicLog: publicLog
            )
            guard let index = events.firstIndex(where: { $0.id == event.id }) else {
                throw APIError.invalidResponse
            }
            events[index].accountKeyEpochId = context.accountKeyEpochID
            events[index].accountKeyCommitment = keyCommitment
            events[index].hasResponse = true
            events[index].responseRevision = result.receipt.revision
            events[index].privateResponsePolicy = policy
            if privacyLockGeneration == initialPrivacyLockGeneration {
                unlockedResponses[event.id] = draft.response
                unlockedDrafts[event.id] = draft
            }
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
        guard operationIsCurrent(operationContext) else { return false }
        let activeUserID = operationContext.userID
        guard
            event.role == .invitee,
            let inviteToken = event.inviteToken,
            event.hasResponse
        else { return false }
        if unlockedDrafts[event.id] != nil { return true }

        isMutating = true
        let initialPrivacyLockGeneration = privacyLockGeneration
        errorMessage = nil
        defer { isMutating = false }
        do {
            let context = try await apiClient.fetchInvitePrivateResponse(inviteToken: inviteToken)
            try requireCurrentOperation(operationContext)
            guard
                context.event.id == event.id,
                let storedEnvelope = context.responseEnvelope,
                let policy = context.event.privateResponsePolicy,
                context.responseRevision == storedEnvelope.revision
            else { throw APIError.invalidResponse }
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
            let crypto = try PrivateResponseCrypto.configured()
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

    func cancelAccountReset() {
        if let accountResetEventID {
            pendingResetDrafts[accountResetEventID] = nil
        }
        accountResetEventID = nil
    }

    @discardableResult
    func startOverAccount(for eventID: UUID) async -> Bool {
        guard let context = currentOperationContext else { return false }
        return await withSerializedOperation(context) {
            await self.performStartOverAccount(for: eventID, context: context)
        } ?? false
    }

    private func performStartOverAccount(
        for eventID: UUID,
        context operationContext: OperationContext
    ) async -> Bool {
        guard operationIsCurrent(operationContext) else { return false }
        let activeUserID = operationContext.userID
        guard
            accountResetEventID == eventID,
            let event = events.first(where: { $0.id == eventID }),
            let inviteToken = event.inviteToken,
            let draft = pendingResetDrafts[eventID]
        else { return false }

        isResettingAccount = true
        errorMessage = nil
        defer { isResettingAccount = false }
        do {
            let context = try await apiClient.fetchInvitePrivateResponse(inviteToken: inviteToken)
            try requireCurrentOperation(operationContext)
            guard context.event.id == event.id else { throw APIError.invalidResponse }
            let newEpochID = try await apiClient.resetAccountKeyEpoch(
                expectedAccountKeyEpochId: context.accountKeyEpochID
            )
            try requireCurrentOperation(operationContext)
            let accountRootSecret = try await accountKeyStore.replaceRootSecret(
                userID: activeUserID,
                newEpochID: newEpochID
            )
            try requireCurrentOperation(operationContext)
            let keyCommitment = await accountKeyStore.commitment(for: accountRootSecret)
            try requireCurrentOperation(operationContext)
            try await apiClient.initializeAccountKeyEpoch(
                expectedAccountKeyEpochId: newEpochID,
                keyCommitment: keyCommitment
            )
            try requireCurrentOperation(operationContext)
            for index in events.indices {
                if events[index].role == .invitee {
                    events[index].accountKeyEpochId = newEpochID
                    events[index].accountKeyCommitment = keyCommitment
                }
            }
            pendingResetDrafts[eventID] = nil
            accountResetEventID = nil
            persistCache()
            return await performRespond(to: event, draft: draft, context: operationContext)
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
}
