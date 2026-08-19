import Foundation
import Observation
import Security

enum AccountDeletionOutcome: Equatable {
    case deleted
    case reauthenticationRequired
    case failed
}

protocol SessionStoring {
    func load() throws -> AuthSession?
    func save(_ session: AuthSession) throws
    func delete() throws
}

@MainActor
@Observable
final class AuthStore {
    private static let verificationCodeLength = 4

    private(set) var user: HerdUser?
    private(set) var challenge: AuthChallenge?
    private(set) var isRestoring = true
    private(set) var isBusy = false
    private(set) var errorMessage: String?
    private(set) var codeRequestRetryAt: Date?

    private let apiClient: APIClient
    private let sessionStore: any SessionStoring
    private let accountKeyStore: any AccountKeyStoring
    private var session: AuthSession?
    private var desiredSession: AuthSession?
    private var challengeInviteToken: String?
    private var sessionGeneration: UInt = 0
    private var accountDeletionCleanupHandler: ((String) -> Void)?

    init(
        apiClient: APIClient,
        sessionStore: any SessionStoring = KeychainSessionStore(),
        accountKeyStore: any AccountKeyStoring = AccountKeyStore()
    ) {
        self.apiClient = apiClient
        self.sessionStore = sessionStore
        self.accountKeyStore = accountKeyStore
    }

    var isAuthenticated: Bool {
        user != nil && session != nil
    }

    func setAccountDeletionCleanupHandler(_ handler: @escaping (String) -> Void) {
        accountDeletionCleanupHandler = handler
    }

    func restoreSession() async {
        let generation = beginOperation()
        defer { isRestoring = false }

        do {
            guard let savedSession = try sessionStore.load() else { return }
            guard operationIsCurrent(generation) else { return }
            guard savedSession.expiresAt > .now else {
                try? sessionStore.delete()
                return
            }

            guard try await commit(savedSession, for: generation) else { return }
            session = savedSession
            user = savedSession.user

            do {
                let refreshedUser = try await apiClient.fetchCurrentUser()
                guard operationIsCurrent(generation) else { return }
                let refreshedSession = AuthSession(
                    user: refreshedUser,
                    accessToken: savedSession.accessToken,
                    expiresAt: savedSession.expiresAt,
                    accountKeyEpochId: savedSession.accountKeyEpochId
                )
                guard try await commit(refreshedSession, for: generation) else { return }
                session = refreshedSession
                user = refreshedUser
            } catch APIError.unauthorized {
                guard operationIsCurrent(generation) else { return }
                await clearLocalSession(for: generation)
            } catch {
                guard operationIsCurrent(generation) else { return }
                errorMessage = "Herd is offline. Your saved events are still available."
            }
        } catch {
            guard operationIsCurrent(generation) else { return }
            await clearLocalSession(for: generation)
            guard operationIsCurrent(generation) else { return }
            errorMessage = "Herd couldn’t restore your saved sign-in."
        }
    }

    func requestCode(
        phoneNumber: String,
        inviteToken: String? = nil
    ) async -> Bool {
        if let codeRequestRetryAt, codeRequestRetryAt > .now {
            return false
        }
        codeRequestRetryAt = nil
        guard let requestPhoneNumber = Self.requestPhoneNumber(phoneNumber) else {
            errorMessage = "Enter a complete phone number, including the country code if outside the U.S."
            return false
        }
        if inviteToken != nil, InvitationToken.normalize(inviteToken) == nil {
            errorMessage = "Open the original invitation link and try again."
            return false
        }

        let generation = beginOperation(isBusy: true)
        errorMessage = nil
        defer { finishOperation(generation) }

        do {
            let result = try await apiClient.requestCode(
                phoneNumber: requestPhoneNumber,
                inviteToken: inviteToken
            )
            guard operationIsCurrent(generation) else { return false }
            switch result {
            case let .challenge(challenge):
                self.challenge = challenge
                challengeInviteToken = inviteToken
            case let .session(authenticatedSession):
                guard try await commit(authenticatedSession, for: generation) else {
                    return false
                }
                session = authenticatedSession
                user = authenticatedSession.user
                challenge = nil
                challengeInviteToken = nil
            }
            codeRequestRetryAt = nil
            return true
        } catch let APIError.codeRequestThrottled(_, retryAt) {
            guard operationIsCurrent(generation) else { return false }
            errorMessage = nil
            codeRequestRetryAt = retryAt
            return false
        } catch {
            guard operationIsCurrent(generation) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    func resendCode() async -> Bool {
        guard let challenge else { return false }
        guard challenge.resendAt <= .now else { return false }
        return await requestCode(
            phoneNumber: challenge.phoneNumber,
            inviteToken: challengeInviteToken
        )
    }

    func verifyCode(_ code: String) async -> Bool {
        guard let challenge else {
            errorMessage = "Request a new code to continue."
            return false
        }

        let normalizedCode = code.filter(\.isWholeNumber)
        guard normalizedCode.count == Self.verificationCodeLength else {
            errorMessage = "Enter all four digits to continue."
            return false
        }

        let generation = beginOperation(isBusy: true)
        errorMessage = nil
        defer { finishOperation(generation) }

        do {
            let verifiedSession = try await apiClient.verifyCode(
                challengeId: challenge.challengeId,
                code: normalizedCode
            )
            guard operationIsCurrent(generation) else { return false }
            guard try await commit(verifiedSession, for: generation) else {
                return false
            }
            session = verifiedSession
            user = verifiedSession.user
            self.challenge = nil
            challengeInviteToken = nil
            return true
        } catch {
            guard operationIsCurrent(generation) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    func updateProfile(name: String, address: String) async -> Bool {
        let normalizedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalizedName.isEmpty else {
            errorMessage = "Add your name before saving."
            return false
        }

        let generation = beginOperation(isBusy: true)
        errorMessage = nil
        defer { finishOperation(generation) }

        do {
            let updatedUser = try await apiClient.updateCurrentUser(
                name: normalizedName,
                address: address.trimmingCharacters(in: .whitespacesAndNewlines)
            )
            guard operationIsCurrent(generation), let session else { return false }
            let updatedSession = AuthSession(
                user: updatedUser,
                accessToken: session.accessToken,
                expiresAt: session.expiresAt,
                accountKeyEpochId: session.accountKeyEpochId
            )
            guard try await commit(updatedSession, for: generation) else {
                return false
            }
            self.session = updatedSession
            user = updatedUser
            return true
        } catch APIError.unauthorized {
            guard operationIsCurrent(generation) else { return false }
            await clearLocalSession(for: generation)
            guard operationIsCurrent(generation) else { return false }
            errorMessage = APIError.unauthorized.localizedDescription
            return false
        } catch {
            guard operationIsCurrent(generation) else { return false }
            errorMessage = Self.message(for: error)
            return false
        }
    }

    func signOut() async {
        let generation = beginOperation(isBusy: true)
        errorMessage = nil
        defer { finishOperation(generation) }

        if session != nil {
            try? await apiClient.deleteSession()
        }
        guard operationIsCurrent(generation) else { return }
        await clearLocalSession(for: generation)
        guard operationIsCurrent(generation) else { return }
        challenge = nil
        challengeInviteToken = nil
    }

    func deleteAccount() async -> AccountDeletionOutcome {
        let generation = beginOperation(isBusy: true)
        errorMessage = nil
        defer { finishOperation(generation) }

        do {
            guard let deletingUserID = user?.id else {
                throw APIError.unauthorized
            }
            try await apiClient.deleteCurrentAccount()
            guard operationIsCurrent(generation) else { return .failed }
            var localCleanupFailed = false
            do {
                try await accountKeyStore.deleteAllRootSecretMaterial(userID: deletingUserID)
            } catch {
                localCleanupFailed = true
            }
            accountDeletionCleanupHandler?(deletingUserID)
            await clearLocalSession(for: generation)
            guard operationIsCurrent(generation) else { return .failed }
            challenge = nil
            challengeInviteToken = nil
            if localCleanupFailed {
                errorMessage = "Your account was deleted, but this iPhone could not remove its local private key. Delete and reinstall Herd before sharing the device."
            }
            return .deleted
        } catch let APIError.server(statusCode, _) where statusCode == 403 {
            guard operationIsCurrent(generation) else { return .failed }
            errorMessage = nil
            return .reauthenticationRequired
        } catch APIError.unauthorized {
            guard operationIsCurrent(generation) else { return .failed }
            await clearLocalSession(for: generation)
            guard operationIsCurrent(generation) else { return .failed }
            challenge = nil
            errorMessage = APIError.unauthorized.localizedDescription
            return .failed
        } catch {
            guard operationIsCurrent(generation) else { return .failed }
            errorMessage = Self.message(for: error)
            return .failed
        }
    }

    func expireSession() {
        invalidatePendingOperations()
        desiredSession = nil
        session = nil
        user = nil
        try? sessionStore.delete()
        challenge = nil
        challengeInviteToken = nil
        isBusy = false
        errorMessage = APIError.unauthorized.localizedDescription

        // The unauthorized callback is synchronous. Reconcile against the
        // latest desired session rather than capturing `nil`, so a newer login
        // can never be cleared by this delayed actor hop.
        Task { [weak self] in
            guard let self else { return }
            try? await self.synchronizeCredentialState()
        }
    }

    func changePhoneNumber() {
        invalidatePendingOperations()
        challenge = nil
        challengeInviteToken = nil
        isBusy = false
        errorMessage = nil
        codeRequestRetryAt = nil
    }

    func clearError() {
        errorMessage = nil
    }

    static func canRequestCode(phoneNumber: String) -> Bool {
        requestPhoneNumber(phoneNumber) != nil
    }

    private func beginOperation(isBusy: Bool = false) -> UInt {
        invalidatePendingOperations()
        self.isBusy = isBusy
        return sessionGeneration
    }

    private func invalidatePendingOperations() {
        sessionGeneration &+= 1
        desiredSession = session
    }

    private func operationIsCurrent(_ generation: UInt) -> Bool {
        generation == sessionGeneration
    }

    private func finishOperation(_ generation: UInt) {
        guard operationIsCurrent(generation) else { return }
        isBusy = false
    }

    private func clearLocalSession(for generation: UInt) async {
        guard operationIsCurrent(generation) else { return }
        desiredSession = nil
        session = nil
        user = nil
        try? await synchronizeCredentialState()
    }

    private func commit(
        _ authenticatedSession: AuthSession,
        for generation: UInt
    ) async throws -> Bool {
        guard operationIsCurrent(generation) else { return false }
        desiredSession = authenticatedSession

        do {
            try await synchronizeCredentialState()
        } catch {
            guard operationIsCurrent(generation) else { return false }
            desiredSession = session
            try? await synchronizeCredentialState()
            throw error
        }

        return operationIsCurrent(generation)
            && desiredSession == authenticatedSession
    }

    private func synchronizeCredentialState() async throws {
        while true {
            let generation = sessionGeneration
            let desiredSession = desiredSession
            var persistenceError: Error?

            do {
                if let desiredSession {
                    try sessionStore.save(desiredSession)
                } else {
                    try sessionStore.delete()
                }
            } catch {
                persistenceError = error
            }

            await apiClient.setAccessToken(desiredSession?.accessToken)

            guard generation == sessionGeneration,
                  desiredSession == self.desiredSession else {
                continue
            }

            if let persistenceError {
                throw persistenceError
            }
            return
        }
    }

    private static func requestPhoneNumber(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.range(of: #"^[1-9]$"#, options: .regularExpression) != nil {
            return trimmed
        }
        let digits = trimmed.filter(\.isWholeNumber)
        if digits.count == 10 {
            return "+1\(digits)"
        }
        if digits.count == 11, digits.first == "1" {
            return "+\(digits)"
        }
        guard (8...15).contains(digits.count) else {
            return nil
        }
        return "+\(digits)"
    }

    private static func message(for error: Error) -> String {
        if let localizedError = error as? LocalizedError,
           let description = localizedError.errorDescription {
            return description
        }
        return error.localizedDescription
    }
}

struct KeychainSessionStore: SessionStoring {
    private let service: String
    private let account = "herd-auth-session"

    init(service: String = Bundle.main.bundleIdentifier ?? "com.herd.app") {
        self.service = service
    }

    func load() throws -> AuthSession? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw KeychainError(status: status)
        }
        return try HerdJSON.makeDecoder().decode(AuthSession.self, from: data)
    }

    func save(_ session: AuthSession) throws {
        let data = try HerdJSON.makeEncoder().encode(session)
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var item = lookup
            attributes.forEach { item[$0.key] = $0.value }
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw KeychainError(status: addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw KeychainError(status: updateStatus)
        }
    }

    func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError(status: status)
        }
    }
}

private struct KeychainError: LocalizedError {
    let status: OSStatus

    var errorDescription: String? {
        "Herd couldn’t securely save your session (Keychain error \(status))."
    }
}
