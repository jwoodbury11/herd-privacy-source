import CryptoKit
import Foundation
import LocalAuthentication
import Security

enum AccountKeyStoreError: LocalizedError, Sendable {
    case missingKey
    case wrongEpoch
    case devicePasscodeRequired
    case keychain(OSStatus)
    case invalidRecord
    case decryptionFailed

    var errorDescription: String? {
        switch self {
        case .missingKey, .wrongEpoch:
            "This device does not have the key for your current private replies."
        case .devicePasscodeRequired:
            "Set a passcode on this iPhone before saving private replies."
        case let .keychain(status):
            "Herd couldn’t access the protected account key (Keychain error \(status))."
        case .invalidRecord, .decryptionFailed:
            "Herd couldn’t open the protected account key on this device."
        }
    }
}

protocol AccountKeyStoring: Actor {
    func hasRootSecret(userID: String, epochID: UUID) -> Bool
    func createRootSecret(userID: String, epochID: UUID) throws -> SymmetricKey
    func rootSecret(userID: String, epochID: UUID) throws -> SymmetricKey
    func commitment(for accountRootSecret: SymmetricKey) -> String
    func replaceRootSecret(userID: String, newEpochID: UUID) throws -> SymmetricKey
    func deleteAllRootSecretMaterial(userID: String) throws
}

actor AccountKeyStore: AccountKeyStoring {
    private struct VaultRecord: Codable, Sendable {
        let deviceKeyID: UUID
        let accountKeyEpochID: UUID
        let arsWrap: Data
    }

    private let service: String

    init(service: String = HerdRuntime.parentApplicationBundleIdentifier + ".private-response") {
        self.service = service
    }

    func hasRootSecret(userID: String, epochID: UUID) -> Bool {
        guard let record = try? loadVaultRecord(userID: userID) else { return false }
        return record.accountKeyEpochID == epochID
    }

    func createRootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        do {
            let existing = try loadVaultRecord(userID: userID)
            if existing.accountKeyEpochID == epochID {
                return try unlock(record: existing, userID: userID)
            }
            return try replaceRootSecret(userID: userID, newEpochID: epochID)
        } catch AccountKeyStoreError.missingKey {
            // No protected account key exists yet, so create the first epoch below.
        }

        let deviceKeyID = UUID()
        let deviceKeyData = try secureRandomData(count: 32)
        let accountRootSecretData = try secureRandomData(count: 32)
        try saveDeviceKey(deviceKeyData, userID: userID, deviceKeyID: deviceKeyID)

        do {
            let aad = deviceVaultAAD(
                userID: userID,
                deviceKeyID: deviceKeyID,
                accountKeyEpochID: epochID
            )
            let sealed = try AES.GCM.seal(
                accountRootSecretData,
                using: SymmetricKey(data: deviceKeyData),
                authenticating: aad
            )
            let nonce = sealed.nonce.withUnsafeBytes { Data($0) }
            let wrap = concatenate(nonce, sealed.ciphertext, sealed.tag)
            guard wrap.count == PrivateResponseProtocol.userWrapBytes else {
                throw AccountKeyStoreError.invalidRecord
            }
            try saveVaultRecord(
                VaultRecord(
                    deviceKeyID: deviceKeyID,
                    accountKeyEpochID: epochID,
                    arsWrap: wrap
                ),
                userID: userID
            )
            return SymmetricKey(data: accountRootSecretData)
        } catch {
            try? deleteDeviceKey(userID: userID, deviceKeyID: deviceKeyID)
            throw error
        }
    }

    func rootSecret(userID: String, epochID: UUID) throws -> SymmetricKey {
        let record = try loadVaultRecord(userID: userID)
        guard record.accountKeyEpochID == epochID else {
            throw AccountKeyStoreError.wrongEpoch
        }
        return try unlock(record: record, userID: userID)
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
        let oldRecord = try? loadVaultRecord(userID: userID)
        try deleteVaultRecord(userID: userID)
        do {
            let secret = try createRootSecret(userID: userID, epochID: newEpochID)
            if let oldRecord, oldRecord.deviceKeyID != (try? loadVaultRecord(userID: userID))?.deviceKeyID {
                try? deleteDeviceKey(userID: userID, deviceKeyID: oldRecord.deviceKeyID)
            }
            return secret
        } catch {
            if let oldRecord {
                try? saveVaultRecord(oldRecord, userID: userID)
            }
            throw error
        }
    }

    func deleteAllRootSecretMaterial(userID: String) throws {
        let userKeyHash = userHash(userID)
        let vault = "account-vault.\(userKeyHash)"
        let devicePrefix = "device-key.\(userKeyHash)."
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return }
        guard status == errSecSuccess else {
            throw AccountKeyStoreError.keychain(status)
        }
        guard let items = result as? [[String: Any]] else {
            throw AccountKeyStoreError.invalidRecord
        }

        for item in items {
            guard let account = item[kSecAttrAccount as String] as? String else { continue }
            if account == vault || account.hasPrefix(devicePrefix) {
                try delete(account: account)
            }
        }
    }

    private func unlock(record: VaultRecord, userID: String) throws -> SymmetricKey {
        let deviceKeyData = try loadDeviceKey(
            userID: userID,
            deviceKeyID: record.deviceKeyID
        )
        guard record.arsWrap.count == PrivateResponseProtocol.userWrapBytes else {
            throw AccountKeyStoreError.invalidRecord
        }
        let nonceEnd = 12
        let ciphertextEnd = nonceEnd + 32
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: record.arsWrap[..<nonceEnd]),
                ciphertext: record.arsWrap[nonceEnd..<ciphertextEnd],
                tag: record.arsWrap[ciphertextEnd...]
            )
            let accountRootSecret = try AES.GCM.open(
                box,
                using: SymmetricKey(data: deviceKeyData),
                authenticating: deviceVaultAAD(
                    userID: userID,
                    deviceKeyID: record.deviceKeyID,
                    accountKeyEpochID: record.accountKeyEpochID
                )
            )
            guard accountRootSecret.count == 32 else {
                throw AccountKeyStoreError.invalidRecord
            }
            return SymmetricKey(data: accountRootSecret)
        } catch let error as AccountKeyStoreError {
            throw error
        } catch {
            throw AccountKeyStoreError.decryptionFailed
        }
    }

    private func deviceVaultAAD(
        userID: String,
        deviceKeyID: UUID,
        accountKeyEpochID: UUID
    ) -> Data {
        var deviceID = deviceKeyID.uuid
        var epochID = accountKeyEpochID.uuid
        return concatenate(
            Data("HERD-ARS-DEVICE-WRAP-AAD-V1".utf8),
            Data([0]),
            Data(SHA256.hash(data: Data(userID.utf8))),
            withUnsafeBytes(of: &deviceID) { Data($0) },
            withUnsafeBytes(of: &epochID) { Data($0) }
        )
    }

    private func loadVaultRecord(userID: String) throws -> VaultRecord {
        guard let data = try loadData(account: vaultAccount(userID), authenticationContext: nil) else {
            throw AccountKeyStoreError.missingKey
        }
        do {
            return try JSONDecoder().decode(VaultRecord.self, from: data)
        } catch {
            throw AccountKeyStoreError.invalidRecord
        }
    }

    private func saveVaultRecord(_ record: VaultRecord, userID: String) throws {
        let data = try JSONEncoder().encode(record)
        try upsertData(
            data,
            account: vaultAccount(userID),
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
    }

    private func deleteVaultRecord(userID: String) throws {
        try delete(account: vaultAccount(userID))
    }

    private func saveDeviceKey(_ data: Data, userID: String, deviceKeyID: UUID) throws {
#if targetEnvironment(simulator) || APPCLIP
        try upsertData(
            data,
            account: deviceAccount(userID, deviceKeyID),
            accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        )
#else
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly,
            .userPresence,
            &accessError
        ) else {
            throw AccountKeyStoreError.devicePasscodeRequired
        }
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: deviceAccount(userID, deviceKeyID),
            kSecValueData as String: data,
            kSecAttrAccessControl as String: accessControl
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            if status == errSecAuthFailed || status == errSecInteractionNotAllowed {
                throw AccountKeyStoreError.devicePasscodeRequired
            }
            throw AccountKeyStoreError.keychain(status)
        }
#endif
    }

    private func loadDeviceKey(userID: String, deviceKeyID: UUID) throws -> Data {
#if APPCLIP
        let data = try loadData(
            account: deviceAccount(userID, deviceKeyID),
            authenticationContext: nil
        )
#else
        let context = LAContext()
        context.localizedReason = "Unlock your private Herd reply"
        let data = try loadData(
            account: deviceAccount(userID, deviceKeyID),
            authenticationContext: context
        )
#endif
        guard let data else {
            throw AccountKeyStoreError.missingKey
        }
        guard data.count == 32 else { throw AccountKeyStoreError.invalidRecord }
        return data
    }

    private func deleteDeviceKey(userID: String, deviceKeyID: UUID) throws {
        try delete(account: deviceAccount(userID, deviceKeyID))
    }

    private func loadData(account: String, authenticationContext: LAContext?) throws -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        if let authenticationContext {
            query[kSecUseAuthenticationContext as String] = authenticationContext
        }
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw AccountKeyStoreError.keychain(status)
        }
        return data
    }

    private func upsertData(
        _ data: Data,
        account: String,
        accessibility: CFString
    ) throws {
        let lookup: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: accessibility
        ]
        let update = SecItemUpdate(lookup as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var item = lookup
            attributes.forEach { item[$0.key] = $0.value }
            let add = SecItemAdd(item as CFDictionary, nil)
            guard add == errSecSuccess else { throw AccountKeyStoreError.keychain(add) }
        } else if update != errSecSuccess {
            throw AccountKeyStoreError.keychain(update)
        }
    }

    private func delete(account: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw AccountKeyStoreError.keychain(status)
        }
    }

    private func userHash(_ userID: String) -> String {
        Data(SHA256.hash(data: Data(userID.utf8))).base64URLEncodedString()
    }

    private func vaultAccount(_ userID: String) -> String {
        "account-vault.\(userHash(userID))"
    }

    private func deviceAccount(_ userID: String, _ deviceKeyID: UUID) -> String {
        "device-key.\(userHash(userID)).\(deviceKeyID.uuidString.lowercased())"
    }
}
