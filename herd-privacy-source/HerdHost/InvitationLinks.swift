import Foundation
import Observation
import Security

enum InvitationToken {
    static let minimumLength = 8
    static let maximumLength = 200

    static func normalize(_ value: String?) -> String? {
        guard let value else { return nil }
        guard
            (minimumLength...maximumLength).contains(value.utf8.count),
            value.unicodeScalars.allSatisfy({ scalar in
                switch scalar.value {
                case 45, 48...57, 65...90, 95, 97...122:
                    true
                default:
                    false
                }
            })
        else { return nil }
        return value
    }
}

struct InvitationLinkParser {
    private let trustedHost: String
    private let trustedPort: Int

    init?(trustedWebOrigin: URL) {
        guard
            let components = URLComponents(url: trustedWebOrigin, resolvingAgainstBaseURL: false),
            components.scheme?.lowercased() == "https",
            components.user == nil,
            components.password == nil,
            let host = components.host?.lowercased(),
            !host.isEmpty,
            (components.percentEncodedPath.isEmpty || components.percentEncodedPath == "/"),
            components.percentEncodedQuery == nil,
            components.fragment == nil
        else { return nil }
        trustedHost = host
        trustedPort = components.port ?? 443
    }

    func token(from url: URL) -> String? {
        guard
            let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
            components.scheme?.lowercased() == "https",
            components.user == nil,
            components.password == nil,
            components.percentEncodedQuery == nil,
            components.fragment == nil,
            components.host?.lowercased() == trustedHost,
            (components.port ?? 443) == trustedPort
        else { return nil }

        let encodedToken = Self.webToken(from: components.percentEncodedPath)

        // Accept only a canonical, unescaped ASCII bearer token. In particular,
        // encoded slashes, encoded dots, path normalization, and trailing path
        // components can never change which invitation the app requests.
        return InvitationToken.normalize(encodedToken)
    }

    private static func webToken(from encodedPath: String) -> String? {
        let prefix = "/invite/"
        guard encodedPath.hasPrefix(prefix) else { return nil }
        let token = String(encodedPath.dropFirst(prefix.count))
        guard !token.isEmpty, !token.contains("/") else { return nil }
        return token
    }

}

struct PendingInvitationKeychainStore {
    private let service: String
    private let account = "pending-invitation-token"

    init(service: String = "\(Bundle.main.bundleIdentifier ?? "com.herd.app").invitation-links") {
        self.service = service
    }

    func load() throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard
            status == errSecSuccess,
            let data = result as? Data,
            let value = String(data: data, encoding: .utf8),
            let token = InvitationToken.normalize(value)
        else { throw PendingInvitationStorageError(status: status) }
        return token
    }

    func save(_ token: String) throws {
        guard let normalized = InvitationToken.normalize(token) else {
            throw PendingInvitationStorageError(status: errSecParam)
        }
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: Data(normalized.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var item = lookup
            attributes.forEach { item[$0.key] = $0.value }
            let addStatus = SecItemAdd(item as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw PendingInvitationStorageError(status: addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw PendingInvitationStorageError(status: updateStatus)
        }
    }

    func delete() throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PendingInvitationStorageError(status: status)
        }
    }
}

private struct PendingInvitationStorageError: Error {
    let status: OSStatus
}

@MainActor
@Observable
final class InvitationCoordinator {
    private struct ResolutionAttempt: Equatable {
        let generation: UInt
        let accountID: String
    }

    private(set) var pendingToken: String?
    private(set) var loadedEventID: UUID?
    private(set) var loadedRequestGeneration: UInt?
    private(set) var requiresAccountSwitch = false
    private(set) var isResolving = false
    private(set) var errorMessage: String?
    private(set) var requestGeneration: UInt

    private let parser: InvitationLinkParser
    private let keychainStore: PendingInvitationKeychainStore
    private var resolvingAttempt: ResolutionAttempt?

    init(
        trustedWebOrigin: URL,
        keychainStore: PendingInvitationKeychainStore = PendingInvitationKeychainStore()
    ) {
        guard let parser = InvitationLinkParser(trustedWebOrigin: trustedWebOrigin) else {
            preconditionFailure("Herd requires a canonical HTTPS invitation origin.")
        }
        self.parser = parser
        self.keychainStore = keychainStore
        do {
            let restoredToken = try keychainStore.load()
            pendingToken = restoredToken
            requestGeneration = restoredToken == nil ? 0 : 1
        } catch {
            pendingToken = nil
            requestGeneration = 0
            try? keychainStore.delete()
            errorMessage = "Herd couldn’t restore the invitation link securely. Open the original link again."
        }
    }

    @discardableResult
    func accept(_ url: URL) -> Bool {
        guard let token = parser.token(from: url) else { return false }
        if pendingToken == token, errorMessage == nil {
            return true
        }
        do {
            try keychainStore.save(token)
            pendingToken = token
            requestGeneration &+= 1
            loadedEventID = nil
            loadedRequestGeneration = nil
            requiresAccountSwitch = false
            resolvingAttempt = nil
            isResolving = false
            errorMessage = nil
            return true
        } catch {
            errorMessage = "Herd couldn’t securely save this invitation. Try opening the link again."
            return false
        }
    }

    func resolve(using eventStore: EventStore, accountID: String) async {
        guard let pendingToken, loadedEventID == nil else { return }
        let generation = requestGeneration
        let attempt = ResolutionAttempt(
            generation: generation,
            accountID: accountID
        )
        guard resolvingAttempt != attempt else { return }
        resolvingAttempt = attempt
        isResolving = true
        errorMessage = nil
        defer {
            if resolvingAttempt == attempt {
                resolvingAttempt = nil
                isResolving = false
            }
        }

        let outcome = await eventStore.openInvitation(inviteToken: pendingToken)
        guard
            generation == requestGeneration,
            self.pendingToken == pendingToken,
            resolvingAttempt == attempt
        else { return }

        switch outcome {
        case let .loaded(eventID):
            loadedEventID = eventID
            loadedRequestGeneration = generation
            requiresAccountSwitch = false
        case .differentAccount:
            requiresAccountSwitch = true
        case .unauthorized:
            break
        case let .failed(message):
            errorMessage = message
        }
    }

    func acknowledgePresentation(of eventID: UUID, generation: UInt) {
        guard
            loadedEventID == eventID,
            loadedRequestGeneration == generation,
            requestGeneration == generation
        else { return }
        do {
            try keychainStore.delete()
            pendingToken = nil
            requestGeneration &+= 1
            loadedEventID = nil
            loadedRequestGeneration = nil
            resolvingAttempt = nil
            isResolving = false
            errorMessage = nil
        } catch {
            // Keep the token so a crash before the detail is actually visible
            // cannot silently lose the invitation.
            errorMessage = "Herd opened the invitation but couldn’t clear its saved link yet."
        }
    }

    func prepareForAccountSwitch() {
        loadedEventID = nil
        loadedRequestGeneration = nil
        requiresAccountSwitch = false
        resolvingAttempt = nil
        isResolving = false
        errorMessage = nil
    }

    func discard() {
        do {
            try keychainStore.delete()
            pendingToken = nil
            requestGeneration &+= 1
            loadedEventID = nil
            loadedRequestGeneration = nil
            resolvingAttempt = nil
            isResolving = false
            requiresAccountSwitch = false
            errorMessage = nil
        } catch {
            errorMessage = "Herd couldn’t remove the saved invitation link. Try again."
        }
    }
}
