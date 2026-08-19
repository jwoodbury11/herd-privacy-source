import CryptoKit
import Foundation
import Security

enum PrivateResponseProtocol {
    static let version = 1
    static let cipherSuite = "P256_HKDF_SHA256_AES256_GCM"
    static let paddedPlaintextBytes = 4_096
    static let payloadFrameBytes = 4_124
    static let userWrapBytes = 60
    static let evaluatorWrapBytes = 157
    static let nonceBytes = 12
    static let tagBytes = 16
    static let responseKeyBytes = 32
    static let contextBytes = 101
    static let responseSigningPublicKeyBytes = 32
    static let responseSignatureBytes = 64
    static let responseAuthorizationDomain = "HERD-RESPONSE-AUTHORIZATION-V1"
    static let responseSigningDerivationLabel = "HERD-RESPONSE-SIGNING-SEED-V1"
}

enum PrivateResponseCryptoError: LocalizedError, Sendable {
    case invalidPolicy(String)
    case invalidReceipt(String)
    case untrustedEvaluator
    case invalidDraft(String)
    case invalidEnvelope(String)
    case payloadTooLarge
    case randomGenerationFailed(OSStatus)
    case decryptionFailed

    var errorDescription: String? {
        switch self {
        case let .invalidPolicy(message), let .invalidReceipt(message),
             let .invalidDraft(message), let .invalidEnvelope(message):
            message
        case .untrustedEvaluator:
            "This event’s private-response evaluator does not match the evaluator approved in this Herd release. Your reply was not sent."
        case .payloadTooLarge:
            "These attendance conditions are too large to save privately."
        case let .randomGenerationFailed(status):
            "Herd couldn’t generate secure random data (error \(status))."
        case .decryptionFailed:
            "This older saved private response could not be verified."
        }
    }
}

struct PrivateResponseReceiptVerifier: Hashable, Sendable {
    private static let receiptDomain = "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1"
    private static let logHeadDomain = "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1"
    private static let entryHashDomain = "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1"

    let signingKeyID: String
    let signingPublicKey: Data

    static func configured(bundle: Bundle = .main) throws -> PrivateResponseReceiptVerifier {
        guard
            let keyID = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID"
            ) as? String,
            PinnedEvaluator.isValidKeyID(keyID),
            let publicKeyValue = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY"
            ) as? String,
            let publicKey = Data(base64URLEncoded: publicKeyValue),
            publicKey.count == 65,
            publicKey.first == 0x04,
            publicKey.base64URLEncodedString() == publicKeyValue
        else {
            throw PrivateResponseCryptoError.invalidReceipt(
                "This Herd release has no valid response-transparency trust pin."
            )
        }
        return PrivateResponseReceiptVerifier(
            signingKeyID: keyID,
            signingPublicKey: publicKey
        )
    }

    func verify(_ receipt: PrivateResponseReceiptV1) throws {
        guard
            let proof = receipt.transparency,
            proof.protocolVersion == PrivateResponseProtocol.version,
            proof.signingKeyId == signingKeyID,
            proof.logHead.protocolVersion == PrivateResponseProtocol.version,
            proof.logHead.signingKeyId == signingKeyID,
            proof.logHead.logId == proof.logId,
            proof.logHead.treeSize == proof.logIndex,
            proof.logHead.headEntryHash == proof.entryHash,
            (1...Int(Int32.max)).contains(proof.logIndex),
            Self.isSafeLogID(proof.logId),
            Self.isCanonicalUUID(receipt.envelopeId),
            Self.isCanonicalUUID(receipt.eventId),
            Self.isCanonicalUUID(receipt.inviteeId),
            Self.canonicalBase64URL(receipt.policyHash, bytes: 32) != nil,
            Self.isCanonicalUUID(receipt.accountKeyEpochId),
            (1...1_000_000).contains(receipt.revision),
            Self.canonicalBase64URL(receipt.ciphertextHash, bytes: 32) != nil,
            Self.canonicalBase64URL(receipt.responseSigningPublicKey, bytes: 32) != nil,
            Self.canonicalBase64URL(receipt.responseSignature, bytes: 64) != nil,
            Self.canonicalBase64URL(proof.previousEntryHash, bytes: 32) != nil,
            Self.canonicalBase64URL(proof.entryHash, bytes: 32) != nil,
            Self.isCanonicalTimestamp(receipt.committedAt),
            Self.isCanonicalTimestamp(proof.logHead.generatedAt)
        else {
            throw Self.invalidReceipt()
        }

        let entryCore = "{" +
            "\"protocolVersion\":\(proof.protocolVersion)," +
            "\"logId\":\(Self.quoted(proof.logId))," +
            "\"logIndex\":\(proof.logIndex)," +
            "\"previousEntryHash\":\(Self.quoted(proof.previousEntryHash))," +
            "\"envelopeId\":\(Self.quoted(receipt.envelopeId))," +
            "\"eventId\":\(Self.quoted(receipt.eventId))," +
            "\"inviteeId\":\(Self.quoted(receipt.inviteeId))," +
            "\"policyHash\":\(Self.quoted(receipt.policyHash))," +
            "\"accountKeyEpochId\":\(Self.quoted(receipt.accountKeyEpochId))," +
            "\"revision\":\(receipt.revision)," +
            "\"ciphertextHash\":\(Self.quoted(receipt.ciphertextHash))," +
            "\"responseSigningPublicKey\":\(Self.quoted(receipt.responseSigningPublicKey))," +
            "\"responseSignature\":\(Self.quoted(receipt.responseSignature))," +
            "\"committedAt\":\(Self.quoted(receipt.committedAt))}"
        let calculatedEntryHash = Data(
            SHA256.hash(
                data: Self.domainSeparated(Self.entryHashDomain, entryCore)
            )
        ).base64URLEncodedString()
        guard calculatedEntryHash == proof.entryHash else {
            throw Self.invalidReceipt()
        }

        let receiptPayload = "{" +
            "\"protocolVersion\":\(proof.protocolVersion)," +
            "\"logId\":\(Self.quoted(proof.logId))," +
            "\"logIndex\":\(proof.logIndex)," +
            "\"previousEntryHash\":\(Self.quoted(proof.previousEntryHash))," +
            "\"entryHash\":\(Self.quoted(proof.entryHash))," +
            "\"envelopeId\":\(Self.quoted(receipt.envelopeId))," +
            "\"eventId\":\(Self.quoted(receipt.eventId))," +
            "\"inviteeId\":\(Self.quoted(receipt.inviteeId))," +
            "\"policyHash\":\(Self.quoted(receipt.policyHash))," +
            "\"accountKeyEpochId\":\(Self.quoted(receipt.accountKeyEpochId))," +
            "\"revision\":\(receipt.revision)," +
            "\"ciphertextHash\":\(Self.quoted(receipt.ciphertextHash))," +
            "\"responseSigningPublicKey\":\(Self.quoted(receipt.responseSigningPublicKey))," +
            "\"responseSignature\":\(Self.quoted(receipt.responseSignature))," +
            "\"committedAt\":\(Self.quoted(receipt.committedAt))," +
            "\"signingKeyId\":\(Self.quoted(proof.signingKeyId))}"
        try verifySignature(
            proof.receiptSignature,
            domain: Self.receiptDomain,
            payload: receiptPayload
        )

        let head = proof.logHead
        let headPayload = "{" +
            "\"protocolVersion\":\(head.protocolVersion)," +
            "\"logId\":\(Self.quoted(head.logId))," +
            "\"treeSize\":\(head.treeSize)," +
            "\"headEntryHash\":\(Self.quoted(head.headEntryHash))," +
            "\"generatedAt\":\(Self.quoted(head.generatedAt))," +
            "\"signingKeyId\":\(Self.quoted(head.signingKeyId))}"
        try verifySignature(
            head.signature,
            domain: Self.logHeadDomain,
            payload: headPayload
        )
    }

    private func verifySignature(
        _ value: String,
        domain: String,
        payload: String
    ) throws {
        guard let signatureData = Self.canonicalBase64URL(value, bytes: 64) else {
            throw Self.invalidReceipt()
        }
        do {
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: signingPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: signatureData
            )
            guard publicKey.isValidSignature(
                signature,
                for: Self.domainSeparated(domain, payload)
            ) else {
                throw Self.invalidReceipt()
            }
        } catch let error as PrivateResponseCryptoError {
            throw error
        } catch {
            throw Self.invalidReceipt()
        }
    }

    private static func invalidReceipt() -> PrivateResponseCryptoError {
        .invalidReceipt(
            "Herd could not verify that the encrypted response was included in its append-only log."
        )
    }

    private static func domainSeparated(_ domain: String, _ payload: String) -> Data {
        concatenate(Data(domain.utf8), Data([0]), Data(payload.utf8))
    }

    private static func quoted(_ value: String) -> String {
        let data = try! JSONEncoder().encode(value)
        return String(decoding: data, as: UTF8.self)
    }

    private static func canonicalBase64URL(_ value: String, bytes: Int) -> Data? {
        guard
            let data = Data(base64URLEncoded: value),
            data.count == bytes,
            data.base64URLEncodedString() == value
        else { return nil }
        return data
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private static func isSafeLogID(_ value: String) -> Bool {
        guard (1...120).contains(value.utf8.count) else { return false }
        return value.utf8.allSatisfy { byte in
            (48...57).contains(byte)
                || (65...90).contains(byte)
                || (97...122).contains(byte)
                || byte == 46 || byte == 45 || byte == 95 || byte == 47
        }
    }

    private static func isCanonicalTimestamp(_ value: String) -> Bool {
        guard value.range(
            of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"#,
            options: .regularExpression
        ) != nil else { return false }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value) != nil
    }
}

struct PrivateResponseReceiptPublicationVerifier: Hashable, Sendable {
    static func verify(
        receipt: PrivateResponseReceiptV1,
        publicLog: PrivateResponseTransparencyLogV1
    ) throws {
        guard
            let proof = receipt.transparency,
            publicLog.protocolVersion == PrivateResponseProtocol.version,
            publicLog.logId == proof.logId,
            publicLog.entries.count == 1,
            let publicEntry = publicLog.entries.first,
            publicEntry.logIndex == proof.logIndex,
            publicEntry.previousEntryHash == proof.previousEntryHash,
            publicEntry.entryHash == proof.entryHash,
            publicEntry.head == proof.logHead
        else {
            throw PrivateResponseCryptoError.invalidReceipt(
                "Herd could not verify that the encrypted response was published in its append-only log."
            )
        }
    }
}

enum EventResolutionVerificationError: LocalizedError, Sendable {
    case invalidProof
    case invalidRelease

    var errorDescription: String? {
        switch self {
        case .invalidProof:
            "The final event result did not include a valid evaluator signature."
        case .invalidRelease:
            "This Herd build is missing its evaluation-result verification key."
        }
    }
}

struct EventResolutionVerifier: Hashable, Sendable {
    let signingKeyID: String
    let signingPublicKey: Data

    static func configured(bundle: Bundle = .main) throws -> EventResolutionVerifier {
        #if DEBUG
        if
            HerdUITestEnvironment.current != nil,
            let signingPublicKey = Data(
                base64URLEncoded: HerdUITestEnvironment.resultSigningPublicKey
            )
        {
            return EventResolutionVerifier(
                signingKeyID: HerdUITestEnvironment.resultSigningKeyID,
                signingPublicKey: signingPublicKey
            )
        }
        #endif

        guard
            let signingKeyID = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID"
            ) as? String,
            PinnedEvaluator.isValidKeyID(signingKeyID),
            let publicKeyValue = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY"
            ) as? String,
            let signingPublicKey = Data(base64URLEncoded: publicKeyValue),
            signingPublicKey.count == 65,
            signingPublicKey.first == 0x04,
            signingPublicKey.base64URLEncodedString() == publicKeyValue
        else { throw EventResolutionVerificationError.invalidRelease }
        return EventResolutionVerifier(
            signingKeyID: signingKeyID,
            signingPublicKey: signingPublicKey
        )
    }

    static func failClosed(_ event: HerdEvent, bundle: Bundle = .main) -> HerdEvent {
        guard
            event.resolution?.status == .confirmed ||
                event.resolution?.status == .notConfirmed,
            let resolution = event.resolution
        else { return event }
        do {
            return try configured(bundle: bundle).failClosed(
                event,
                resolution: resolution
            )
        } catch {
            var safeEvent = event
            safeEvent.resolution = EventResolution(status: .verificationUnavailable)
            return safeEvent
        }
    }

    func failClosed(_ event: HerdEvent) -> HerdEvent {
        guard
            event.resolution?.status == .confirmed ||
                event.resolution?.status == .notConfirmed,
            let resolution = event.resolution
        else { return event }
        return (try? failClosed(event, resolution: resolution)) ?? {
            var safeEvent = event
            safeEvent.resolution = EventResolution(status: .verificationUnavailable)
            return safeEvent
        }()
    }

    private func failClosed(
        _ event: HerdEvent,
        resolution: EventResolution
    ) throws -> HerdEvent {
        try verify(resolution, for: event)
        return event
    }

    func verify(_ resolution: EventResolution, for event: HerdEvent) throws {
        guard
            resolution.status == .confirmed || resolution.status == .notConfirmed,
            resolution.retrying == nil,
            let resolvedAt = resolution.resolvedAt,
            let deadline = event.rsvpDeadline,
            let policy = event.privateResponsePolicy,
            policy.protocolVersion == PrivateResponseProtocol.version,
            Self.canonicalBase64URL(policy.policyHash, bytes: 32) != nil,
            PinnedEvaluator.isValidKeyID(policy.evaluatorKeyId),
            let attestation = resolution.attestation,
            attestation.protocolVersion == PrivateResponseProtocol.version,
            attestation.signingKeyId == signingKeyID,
            let evaluatedAt = Self.canonicalTimestamp(attestation.evaluatedAt),
            evaluatedAt == resolvedAt,
            (2...32_768).contains(attestation.canonicalDocument.utf8.count),
            let signature = Self.canonicalBase64URL(attestation.signature, bytes: 64)
        else { throw EventResolutionVerificationError.invalidProof }

        let revealAttendance = resolution.status == .confirmed
            ? (resolution.attendanceRevealed ?? (resolvedAt >= deadline))
            : resolvedAt >= deadline
        let attendingMemberIDs: [String]
        switch resolution.status {
        case .confirmed:
            if !revealAttendance {
                guard resolution.attendingMemberIds == nil else {
                    throw EventResolutionVerificationError.invalidProof
                }
                attendingMemberIDs = []
                break
            }
            guard
                let members = resolution.attendingMemberIds,
                !members.isEmpty,
                members.first == "host",
                Set(members).count == members.count
            else { throw EventResolutionVerificationError.invalidProof }
            let allowed = Set(["host"] + event.invitees.map { $0.id.uuidString.lowercased() })
            guard members.allSatisfy(allowed.contains) else {
                throw EventResolutionVerificationError.invalidProof
            }
            attendingMemberIDs = members
        case .notConfirmed:
            guard resolution.attendingMemberIds == nil else {
                throw EventResolutionVerificationError.invalidProof
            }
            attendingMemberIDs = []
        case .pending, .verificationUnavailable:
            throw EventResolutionVerificationError.invalidProof
        }

        let documentData = Data(attestation.canonicalDocument.utf8)
        guard
            let value = try? JSONSerialization.jsonObject(with: documentData),
            let document = value as? [String: Any],
            Set(document.keys) == Set([
                "protocolVersion",
                "signingKeyId",
                "relayRequestHash",
                "relayRequestId",
                "leaseId",
                "evaluatedAt",
                "result",
            ]),
            document["protocolVersion"] as? Int == PrivateResponseProtocol.version,
            document["signingKeyId"] as? String == signingKeyID,
            document["evaluatedAt"] as? String == attestation.evaluatedAt,
            let relayRequestHash = document["relayRequestHash"] as? String,
            Self.canonicalBase64URL(relayRequestHash, bytes: 32) != nil,
            let relayRequestID = document["relayRequestId"] as? String,
            Self.isCanonicalUUID(relayRequestID),
            let leaseID = document["leaseId"] as? String,
            Self.isCanonicalUUID(leaseID),
            let result = document["result"] as? [String: Any],
            Set(result.keys) == Set(
                resolution.status == .confirmed
                    ? [
                        "protocolVersion",
                        "eventId",
                        "policyHash",
                        "batchHash",
                        "evaluatorKeyId",
                        "status",
                    ] + (result["revealAttendance"] == nil ? [] : ["revealAttendance"])
                      + (revealAttendance ? ["attendingMemberIds"] : [])
                    : [
                        "protocolVersion",
                        "eventId",
                        "policyHash",
                        "batchHash",
                        "evaluatorKeyId",
                        "status",
                    ] + (result["revealAttendance"] == nil ? [] : ["revealAttendance"])
            ),
            let batchHash = result["batchHash"] as? String,
            Self.canonicalBase64URL(batchHash, bytes: 32) != nil
        else { throw EventResolutionVerificationError.invalidProof }
        if let signedRevealAttendance = result["revealAttendance"] as? Bool {
            guard signedRevealAttendance == revealAttendance else {
                throw EventResolutionVerificationError.invalidProof
            }
        } else if !revealAttendance {
            throw EventResolutionVerificationError.invalidProof
        }

        let status = resolution.status == .confirmed ? "confirmed" : "not_confirmed"
        let attendingJSON = attendingMemberIDs.map(Self.quoted).joined(separator: ",")
        let resultJSON = "{" +
            "\"protocolVersion\":\(PrivateResponseProtocol.version)," +
            "\"eventId\":\(Self.quoted(event.id.uuidString.lowercased()))," +
            "\"policyHash\":\(Self.quoted(policy.policyHash))," +
            "\"batchHash\":\(Self.quoted(batchHash))," +
            "\"evaluatorKeyId\":\(Self.quoted(policy.evaluatorKeyId))," +
            "\"status\":\(Self.quoted(status))" +
            (result["revealAttendance"] == nil
                ? ""
                : ",\"revealAttendance\":\(revealAttendance ? "true" : "false")") +
            (resolution.status == .confirmed && revealAttendance
                ? ",\"attendingMemberIds\":[\(attendingJSON)]}"
                : "}")
        let expectedDocument = "{" +
            "\"protocolVersion\":\(PrivateResponseProtocol.version)," +
            "\"signingKeyId\":\(Self.quoted(signingKeyID))," +
            "\"relayRequestHash\":\(Self.quoted(relayRequestHash))," +
            "\"relayRequestId\":\(Self.quoted(relayRequestID))," +
            "\"leaseId\":\(Self.quoted(leaseID))," +
            "\"evaluatedAt\":\(Self.quoted(attestation.evaluatedAt))," +
            "\"result\":\(resultJSON)}"
        guard attestation.canonicalDocument == expectedDocument else {
            throw EventResolutionVerificationError.invalidProof
        }

        do {
            let publicKey = try P256.Signing.PublicKey(
                x963Representation: signingPublicKey
            )
            let evaluatorSignature = try P256.Signing.ECDSASignature(
                rawRepresentation: signature
            )
            guard publicKey.isValidSignature(evaluatorSignature, for: documentData) else {
                throw EventResolutionVerificationError.invalidProof
            }
        } catch let error as EventResolutionVerificationError {
            throw error
        } catch {
            throw EventResolutionVerificationError.invalidProof
        }
    }

    private static func canonicalBase64URL(_ value: String, bytes: Int) -> Data? {
        guard
            let data = Data(base64URLEncoded: value),
            data.count == bytes,
            data.base64URLEncodedString() == value
        else { return nil }
        return data
    }

    private static func isCanonicalUUID(_ value: String) -> Bool {
        UUID(uuidString: value)?.uuidString.lowercased() == value
    }

    private static func canonicalTimestamp(_ value: String) -> Date? {
        guard value.range(
            of: #"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$"#,
            options: .regularExpression
        ) != nil else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: value)
    }

    private static func quoted(_ value: String) -> String {
        String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
    }
}

struct PinnedEvaluator: Hashable, Sendable {
    let keyID: String
    let publicKey: Data
    let policySigningKeyID: String
    let policySigningPublicKey: Data

    static func configured(bundle: Bundle = .main) throws -> PinnedEvaluator {
        guard
            let keyID = bundle.object(forInfoDictionaryKey: "HERD_EVALUATOR_KEY_ID") as? String,
            !keyID.isEmpty,
            Self.isValidKeyID(keyID),
            let publicKeyValue = bundle.object(forInfoDictionaryKey: "HERD_EVALUATOR_PUBLIC_KEY") as? String,
            let publicKey = Data(base64URLEncoded: publicKeyValue),
            publicKey.count == 65,
            publicKey.base64URLEncodedString() == publicKeyValue,
            publicKey.first == 0x04,
            let policySigningKeyID = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_POLICY_SIGNING_KEY_ID"
            ) as? String,
            Self.isValidKeyID(policySigningKeyID),
            let policySigningPublicKeyValue = bundle.object(
                forInfoDictionaryKey: "HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY"
            ) as? String,
            let policySigningPublicKey = Data(
                base64URLEncoded: policySigningPublicKeyValue
            ),
            policySigningPublicKey.count == 65,
            policySigningPublicKey.base64URLEncodedString() == policySigningPublicKeyValue,
            policySigningPublicKey.first == 0x04,
            policySigningKeyID != keyID,
            policySigningPublicKey != publicKey
        else {
            throw PrivateResponseCryptoError.untrustedEvaluator
        }
        return PinnedEvaluator(
            keyID: keyID,
            publicKey: publicKey,
            policySigningKeyID: policySigningKeyID,
            policySigningPublicKey: policySigningPublicKey
        )
    }

    func verify(_ policy: PrivateResponsePolicyV1) throws {
        guard
            policy.protocolVersion == PrivateResponseProtocol.version,
            policy.cipherSuite == PrivateResponseProtocol.cipherSuite,
            policy.paddedPlaintextBytes == PrivateResponseProtocol.paddedPlaintextBytes,
            policy.evaluatorKeyId == keyID,
            let policyPublicKey = Data(base64URLEncoded: policy.evaluatorPublicKey),
            policyPublicKey.base64URLEncodedString() == policy.evaluatorPublicKey,
            policyPublicKey == publicKey,
            let policyHash = Data(base64URLEncoded: policy.policyHash),
            policyHash.count == 32,
            policyHash.base64URLEncodedString() == policy.policyHash,
            !policy.canonicalDocument.isEmpty,
            policy.policySigningKeyId == policySigningKeyID,
            let policySignatureValue = policy.policySignature,
            let policySignature = Data(base64URLEncoded: policySignatureValue),
            policySignature.count == 64,
            policySignature.base64URLEncodedString() == policySignatureValue
        else {
            throw PrivateResponseCryptoError.untrustedEvaluator
        }

        let calculatedHash = Data(SHA256.hash(data: Data(policy.canonicalDocument.utf8)))
        guard calculatedHash == policyHash else {
            throw PrivateResponseCryptoError.invalidPolicy(
                "The event’s frozen privacy policy does not match its published hash. Your reply was not sent."
            )
        }
        do {
            let signingKey = try P256.Signing.PublicKey(
                x963Representation: policySigningPublicKey
            )
            let signature = try P256.Signing.ECDSASignature(
                rawRepresentation: policySignature
            )
            let signedDocument = concatenate(
                Data("HERD-POLICY-DESCRIPTOR-SIGNATURE-V1".utf8),
                Data([0]),
                Data(policy.canonicalDocument.utf8)
            )
            guard signingKey.isValidSignature(signature, for: signedDocument) else {
                throw PrivateResponseCryptoError.untrustedEvaluator
            }
        } catch let error as PrivateResponseCryptoError {
            throw error
        } catch {
            throw PrivateResponseCryptoError.untrustedEvaluator
        }
    }

    static func isValidKeyID(_ value: String) -> Bool {
        guard (1...120).contains(value.utf8.count) else { return false }
        return value.utf8.allSatisfy { byte in
            (48...57).contains(byte)
                || (65...90).contains(byte)
                || (97...122).contains(byte)
                || byte == 46
                || byte == 45
                || byte == 95
        }
    }
}

struct PrivateResponseCrypto: Sendable {
    private let pinnedEvaluator: PinnedEvaluator

    init(pinnedEvaluator: PinnedEvaluator) {
        self.pinnedEvaluator = pinnedEvaluator
    }

    static func configured(bundle: Bundle = .main) throws -> PrivateResponseCrypto {
        PrivateResponseCrypto(pinnedEvaluator: try .configured(bundle: bundle))
    }

    func seal(
        eventID: UUID,
        inviteeID: UUID,
        accountKeyEpochID: UUID,
        revision: Int,
        response: RSVPResponse,
        minimumParticipants: Int?,
        minimumAllowedParticipants: Int,
        requiredGroups: [RSVPConditionGroup],
        allowedMemberIDs: Set<UUID>,
        policy: PrivateResponsePolicyV1,
        accountRootSecret: SymmetricKey
    ) throws -> PrivateResponseEnvelopeV1 {
        try pinnedEvaluator.verify(policy)
        try validateDraft(
            inviteeID: inviteeID,
            response: response,
            minimumParticipants: minimumParticipants,
            minimumAllowedParticipants: minimumAllowedParticipants,
            requiredGroups: requiredGroups,
            allowedMemberIDs: allowedMemberIDs
        )
        guard (1...1_000_000).contains(revision) else {
            throw PrivateResponseCryptoError.invalidDraft("The private-reply revision is invalid.")
        }

        let envelopeID = UUID()
        let nonce = try secureRandomData(count: 16).base64URLEncodedString()
        let normalizedGroups = requiredGroups.map { group in
            RSVPConditionGroup(
                id: group.id.lowercased(),
                memberIDs: group.memberIDs.map { UUID(uuidString: $0.uuidString.lowercased())! }
            )
        }
        let plaintext = PrivateResponsePlaintextV1(
            protocolVersion: PrivateResponseProtocol.version,
            eventId: eventID.uuidString.lowercased(),
            inviteeId: inviteeID.uuidString.lowercased(),
            policyHash: policy.policyHash,
            envelopeId: envelopeID.uuidString.lowercased(),
            accountKeyEpochId: accountKeyEpochID.uuidString.lowercased(),
            revision: revision,
            response: response,
            minimumParticipants: response == .going ? minimumParticipants : nil,
            requiredGroups: response == .going ? normalizedGroups : [],
            nonce: nonce
        )

        var envelope = PrivateResponseEnvelopeV1(
            protocolVersion: PrivateResponseProtocol.version,
            cipherSuite: PrivateResponseProtocol.cipherSuite,
            envelopeId: plaintext.envelopeId,
            eventId: plaintext.eventId,
            inviteeId: plaintext.inviteeId,
            policyHash: policy.policyHash,
            revision: revision,
            accountKeyEpochId: plaintext.accountKeyEpochId,
            evaluatorKeyId: policy.evaluatorKeyId,
            payloadCiphertext: "",
            userKeyWrap: "",
            evaluatorKeyWrap: "",
            responseSigningPublicKey: "",
            responseSignature: ""
        )
        let context = try cryptographicContext(for: envelope)
        let responseKey = SymmetricKey(size: .bits256)
        let responseKeyData = responseKey.withUnsafeBytes { Data($0) }

        let framedPlaintext = try frame(plaintext)
        let payloadAAD = labeled("HERD-RSVP-PAYLOAD-AAD-V1", context)
        let payloadFrame = try sealFrame(framedPlaintext, using: responseKey, aad: payloadAAD)
        guard payloadFrame.count == PrivateResponseProtocol.payloadFrameBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("The encrypted response frame has an invalid size.")
        }

        let policyHash = try requiredBase64URL(policy.policyHash, bytes: 32, field: "policy hash")
        let userInfo = labeled("HERD-RSVP-USER-KEK-V1", context)
        let userKEK = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: accountRootSecret,
            salt: policyHash,
            info: userInfo,
            outputByteCount: 32
        )
        let userAAD = labeled("HERD-RSVP-USER-WRAP-AAD-V1", context)
        let userWrap = try sealFrame(responseKeyData, using: userKEK, aad: userAAD)
        guard userWrap.count == PrivateResponseProtocol.userWrapBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("The user key wrap has an invalid size.")
        }

        let evaluatorPublicKey = try P256.KeyAgreement.PublicKey(
            x963Representation: pinnedEvaluator.publicKey
        )
        let ephemeralKey = P256.KeyAgreement.PrivateKey()
        let ephemeralPublicKey = ephemeralKey.publicKey.x963Representation
        let salt = try secureRandomData(count: 32)
        let sharedSecret = try ephemeralKey.sharedSecretFromKeyAgreement(with: evaluatorPublicKey)
        let keyID = Data(policy.evaluatorKeyId.utf8)
        let evaluatorInfo = concatenate(
            labeled("HERD-RSVP-EVALUATOR-KEK-V1", context),
            keyID
        )
        let evaluatorKEK = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: evaluatorInfo,
            outputByteCount: 32
        )
        let evaluatorAAD = concatenate(
            labeled("HERD-RSVP-EVALUATOR-WRAP-AAD-V1", context),
            keyID,
            ephemeralPublicKey,
            salt
        )
        let sealedEvaluatorKey = try sealFrame(
            responseKeyData,
            using: evaluatorKEK,
            aad: evaluatorAAD
        )
        let evaluatorWrap = concatenate(ephemeralPublicKey, salt, sealedEvaluatorKey)
        guard evaluatorWrap.count == PrivateResponseProtocol.evaluatorWrapBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("The evaluator key wrap has an invalid size.")
        }

        envelope.payloadCiphertext = payloadFrame.base64URLEncodedString()
        envelope.userKeyWrap = userWrap.base64URLEncodedString()
        envelope.evaluatorKeyWrap = evaluatorWrap.base64URLEncodedString()
        let responseSigningKey = try responseSigningPrivateKey(
            accountRootSecret: accountRootSecret,
            envelope: envelope
        )
        envelope.responseSigningPublicKey = responseSigningKey.publicKey.rawRepresentation
            .base64URLEncodedString()
        let ciphertextHash = Data(SHA256.hash(data: envelope.canonicalJSONData))
            .base64URLEncodedString()
        envelope.responseSignature = try responseSigningKey.signature(
            for: responseAuthorizationBytes(
                envelope: envelope,
                ciphertextHash: ciphertextHash
            )
        ).base64URLEncodedString()
        try validateEnvelopeEncoding(envelope)
        return envelope
    }

    func open(
        _ envelope: PrivateResponseEnvelopeV1,
        eventID: UUID,
        inviteeID: UUID,
        accountKeyEpochID: UUID,
        minimumAllowedParticipants: Int,
        allowedMemberIDs: Set<UUID>,
        policy: PrivateResponsePolicyV1,
        accountRootSecret: SymmetricKey
    ) throws -> PrivateResponsePlaintextV1 {
        try pinnedEvaluator.verify(policy)
        guard
            envelope.protocolVersion == PrivateResponseProtocol.version,
            envelope.cipherSuite == PrivateResponseProtocol.cipherSuite,
            envelope.policyHash == policy.policyHash,
            envelope.evaluatorKeyId == policy.evaluatorKeyId,
            envelope.eventId == eventID.uuidString.lowercased(),
            envelope.inviteeId == inviteeID.uuidString.lowercased(),
            envelope.accountKeyEpochId == accountKeyEpochID.uuidString.lowercased()
        else {
            throw PrivateResponseCryptoError.invalidEnvelope("This private reply uses an unsupported policy or cipher suite.")
        }

        try validateEnvelopeEncoding(envelope)
        let expectedResponseSigningKey = try responseSigningPrivateKey(
            accountRootSecret: accountRootSecret,
            envelope: envelope
        )
        guard
            expectedResponseSigningKey.publicKey.rawRepresentation
                == Data(base64URLEncoded: envelope.responseSigningPublicKey)
        else {
            throw PrivateResponseCryptoError.invalidEnvelope(
                "This private reply was not authorized by this account key."
            )
        }
        let context = try cryptographicContext(for: envelope)
        let policyHash = try requiredBase64URL(envelope.policyHash, bytes: 32, field: "policy hash")
        let userKEK = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: accountRootSecret,
            salt: policyHash,
            info: labeled("HERD-RSVP-USER-KEK-V1", context),
            outputByteCount: 32
        )
        let userWrap = try requiredBase64URL(
            envelope.userKeyWrap,
            bytes: PrivateResponseProtocol.userWrapBytes,
            field: "user key wrap"
        )
        let responseKeyData = try openFrame(
            userWrap,
            using: userKEK,
            aad: labeled("HERD-RSVP-USER-WRAP-AAD-V1", context),
            ciphertextBytes: PrivateResponseProtocol.responseKeyBytes
        )
        let responseKey = SymmetricKey(data: responseKeyData)
        let payload = try requiredBase64URL(
            envelope.payloadCiphertext,
            bytes: PrivateResponseProtocol.payloadFrameBytes,
            field: "payload"
        )
        let framedPlaintext = try openFrame(
            payload,
            using: responseKey,
            aad: labeled("HERD-RSVP-PAYLOAD-AAD-V1", context),
            ciphertextBytes: PrivateResponseProtocol.paddedPlaintextBytes
        )
        let plaintext = try unframe(framedPlaintext)
        guard
            plaintext.protocolVersion == envelope.protocolVersion,
            plaintext.eventId == envelope.eventId,
            plaintext.inviteeId == envelope.inviteeId,
            plaintext.policyHash == envelope.policyHash,
            plaintext.envelopeId == envelope.envelopeId,
            plaintext.accountKeyEpochId == envelope.accountKeyEpochId,
            plaintext.revision == envelope.revision
        else {
            throw PrivateResponseCryptoError.invalidEnvelope("The encrypted reply does not match its authenticated envelope.")
        }
        try validateDraft(
            inviteeID: inviteeID,
            response: plaintext.response,
            minimumParticipants: plaintext.minimumParticipants,
            minimumAllowedParticipants: minimumAllowedParticipants,
            requiredGroups: plaintext.requiredGroups,
            allowedMemberIDs: allowedMemberIDs
        )
        _ = try requiredBase64URL(plaintext.nonce, bytes: 16, field: "private-response nonce")
        return plaintext
    }

    func envelopeHash(_ envelope: PrivateResponseEnvelopeV1) throws -> String {
        try validateEnvelopeEncoding(envelope)
        return Data(SHA256.hash(data: envelope.canonicalJSONData)).base64URLEncodedString()
    }

    private func validateDraft(
        inviteeID: UUID,
        response: RSVPResponse,
        minimumParticipants: Int?,
        minimumAllowedParticipants: Int,
        requiredGroups: [RSVPConditionGroup],
        allowedMemberIDs: Set<UUID>
    ) throws {
        guard allowedMemberIDs.count <= 19 else {
            throw PrivateResponseCryptoError.invalidDraft("Private responses currently support events with up to 20 total participants.")
        }
        if response == .cantCommit {
            guard minimumParticipants == nil, requiredGroups.isEmpty else {
                throw PrivateResponseCryptoError.invalidDraft("A can’t-commit response cannot include attendance conditions.")
            }
            return
        }
        guard
            let minimumParticipants,
            minimumParticipants >= max(2, minimumAllowedParticipants),
            minimumParticipants <= allowedMemberIDs.count + 1
        else {
            throw PrivateResponseCryptoError.invalidDraft("Choose a valid minimum number of participants.")
        }
        guard requiredGroups.count <= 20 else {
            throw PrivateResponseCryptoError.invalidDraft("Add at most 20 required-person groups.")
        }
        var seenMembers = Set<UUID>()
        var seenGroupIDs = Set<String>()
        for group in requiredGroups {
            guard UUID(uuidString: group.id) != nil, seenGroupIDs.insert(group.id.lowercased()).inserted else {
                throw PrivateResponseCryptoError.invalidDraft("Each required-person group must have a unique identifier.")
            }
            guard !group.memberIDs.isEmpty, group.memberIDs.count <= 20 else {
                throw PrivateResponseCryptoError.invalidDraft("Each required-person group must include at least one invited person.")
            }
            for memberID in group.memberIDs {
                guard
                    memberID != inviteeID,
                    allowedMemberIDs.contains(memberID),
                    seenMembers.insert(memberID).inserted
                else {
                    throw PrivateResponseCryptoError.invalidDraft("Conditions may reference each other invited person at most once.")
                }
            }
        }
    }

    private func frame(_ plaintext: PrivateResponsePlaintextV1) throws -> Data {
        let json = plaintext.canonicalJSONData
        guard json.count <= PrivateResponseProtocol.paddedPlaintextBytes - 2, json.count <= Int(UInt16.max) else {
            throw PrivateResponseCryptoError.payloadTooLarge
        }
        var result = Data()
        result.reserveCapacity(PrivateResponseProtocol.paddedPlaintextBytes)
        result.append(UInt8((json.count >> 8) & 0xff))
        result.append(UInt8(json.count & 0xff))
        result.append(json)
        result.append(try secureRandomData(count: PrivateResponseProtocol.paddedPlaintextBytes - result.count))
        return result
    }

    private func unframe(_ data: Data) throws -> PrivateResponsePlaintextV1 {
        guard data.count == PrivateResponseProtocol.paddedPlaintextBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("The decrypted response frame has an invalid size.")
        }
        let length = (Int(data[data.startIndex]) << 8) | Int(data[data.index(after: data.startIndex)])
        guard length >= 2, length <= data.count - 2 else {
            throw PrivateResponseCryptoError.invalidEnvelope("The decrypted response length is invalid.")
        }
        let start = data.index(data.startIndex, offsetBy: 2)
        let end = data.index(start, offsetBy: length)
        let canonicalBytes = Data(data[start..<end])
        do {
            let plaintext = try JSONDecoder().decode(
                PrivateResponsePlaintextV1.self,
                from: canonicalBytes
            )
            guard plaintext.canonicalJSONData == canonicalBytes else {
                throw PrivateResponseCryptoError.invalidEnvelope(
                    "The decrypted response is not in the canonical private-response format."
                )
            }
            return plaintext
        } catch let error as PrivateResponseCryptoError {
            throw error
        } catch {
            throw PrivateResponseCryptoError.invalidEnvelope("The decrypted response has an invalid format.")
        }
    }

    private func validateEnvelopeEncoding(_ envelope: PrivateResponseEnvelopeV1) throws {
        guard
            envelope.protocolVersion == PrivateResponseProtocol.version,
            envelope.cipherSuite == PrivateResponseProtocol.cipherSuite,
            envelope.evaluatorKeyId == pinnedEvaluator.keyID,
            PinnedEvaluator.isValidKeyID(envelope.evaluatorKeyId),
            (1...1_000_000).contains(envelope.revision)
        else {
            throw PrivateResponseCryptoError.invalidEnvelope(
                "The private-response envelope uses unsupported values."
            )
        }
        _ = try cryptographicContext(for: envelope)
        _ = try requiredBase64URL(
            envelope.payloadCiphertext,
            bytes: PrivateResponseProtocol.payloadFrameBytes,
            field: "payload"
        )
        _ = try requiredBase64URL(
            envelope.userKeyWrap,
            bytes: PrivateResponseProtocol.userWrapBytes,
            field: "user key wrap"
        )
        let evaluatorWrap = try requiredBase64URL(
            envelope.evaluatorKeyWrap,
            bytes: PrivateResponseProtocol.evaluatorWrapBytes,
            field: "evaluator key wrap"
        )
        guard evaluatorWrap.first == 0x04 else {
            throw PrivateResponseCryptoError.invalidEnvelope(
                "The evaluator key wrap does not contain an uncompressed P-256 key."
            )
        }
        let responseSigningPublicKey = try requiredBase64URL(
            envelope.responseSigningPublicKey,
            bytes: PrivateResponseProtocol.responseSigningPublicKeyBytes,
            field: "response-signing public key"
        )
        let responseSignature = try requiredBase64URL(
            envelope.responseSignature,
            bytes: PrivateResponseProtocol.responseSignatureBytes,
            field: "response authorization"
        )
        do {
            let publicKey = try Curve25519.Signing.PublicKey(
                rawRepresentation: responseSigningPublicKey
            )
            let ciphertextHash = Data(SHA256.hash(data: envelope.canonicalJSONData))
                .base64URLEncodedString()
            guard publicKey.isValidSignature(
                responseSignature,
                for: responseAuthorizationBytes(
                    envelope: envelope,
                    ciphertextHash: ciphertextHash
                )
            ) else {
                throw PrivateResponseCryptoError.invalidEnvelope(
                    "The private reply has an invalid device authorization."
                )
            }
        } catch let error as PrivateResponseCryptoError {
            throw error
        } catch {
            throw PrivateResponseCryptoError.invalidEnvelope(
                "The private reply has an invalid device authorization."
            )
        }
    }

    private func responseSigningPrivateKey(
        accountRootSecret: SymmetricKey,
        envelope: PrivateResponseEnvelopeV1
    ) throws -> Curve25519.Signing.PrivateKey {
        let policyHash = try requiredBase64URL(
            envelope.policyHash,
            bytes: 32,
            field: "policy hash"
        )
        let info = concatenate(
            Data(PrivateResponseProtocol.responseSigningDerivationLabel.utf8),
            Data([0]),
            try uuidBytes(envelope.eventId, field: "event ID"),
            try uuidBytes(envelope.inviteeId, field: "invitee ID")
        )
        let seedKey = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: accountRootSecret,
            salt: policyHash,
            info: info,
            outputByteCount: 32
        )
        var seed = seedKey.withUnsafeBytes { Data($0) }
        defer { seed.resetBytes(in: seed.indices) }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
    }

    private func responseAuthorizationBytes(
        envelope: PrivateResponseEnvelopeV1,
        ciphertextHash: String
    ) -> Data {
        let document = "{" +
            "\"protocolVersion\":\(envelope.protocolVersion)," +
            "\"eventId\":\"\(envelope.eventId)\"," +
            "\"inviteeId\":\"\(envelope.inviteeId)\"," +
            "\"policyHash\":\"\(envelope.policyHash)\"," +
            "\"accountKeyEpochId\":\"\(envelope.accountKeyEpochId)\"," +
            "\"revision\":\(envelope.revision)," +
            "\"envelopeId\":\"\(envelope.envelopeId)\"," +
            "\"ciphertextHash\":\"\(ciphertextHash)\"," +
            "\"responseSigningPublicKey\":\"\(envelope.responseSigningPublicKey)\"}"
        return concatenate(
            Data(PrivateResponseProtocol.responseAuthorizationDomain.utf8),
            Data([0]),
            Data(document.utf8)
        )
    }

    private func cryptographicContext(for envelope: PrivateResponseEnvelopeV1) throws -> Data {
        guard envelope.protocolVersion == PrivateResponseProtocol.version else {
            throw PrivateResponseCryptoError.invalidEnvelope("The private-response protocol version is unsupported.")
        }
        guard
            let revision = UInt32(exactly: envelope.revision),
            (1...1_000_000).contains(revision)
        else {
            throw PrivateResponseCryptoError.invalidEnvelope("The private-response revision is invalid.")
        }
        var result = Data([UInt8(envelope.protocolVersion)])
        result.append(try uuidBytes(envelope.eventId, field: "event ID"))
        result.append(try uuidBytes(envelope.inviteeId, field: "invitee ID"))
        result.append(try requiredBase64URL(envelope.policyHash, bytes: 32, field: "policy hash"))
        result.append(try uuidBytes(envelope.envelopeId, field: "envelope ID"))
        result.append(try uuidBytes(envelope.accountKeyEpochId, field: "account-key epoch"))
        var bigEndianRevision = revision.bigEndian
        withUnsafeBytes(of: &bigEndianRevision) { result.append(contentsOf: $0) }
        guard result.count == PrivateResponseProtocol.contextBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("The private-response cryptographic context is invalid.")
        }
        return result
    }

    private func uuidBytes(_ value: String, field: String) throws -> Data {
        guard let uuid = UUID(uuidString: value), uuid.uuidString.lowercased() == value else {
            throw PrivateResponseCryptoError.invalidEnvelope("The \(field) is invalid.")
        }
        var raw = uuid.uuid
        return withUnsafeBytes(of: &raw) { Data($0) }
    }

    private func requiredBase64URL(_ value: String, bytes: Int, field: String) throws -> Data {
        guard
            let data = Data(base64URLEncoded: value),
            data.count == bytes,
            data.base64URLEncodedString() == value
        else {
            throw PrivateResponseCryptoError.invalidEnvelope("The \(field) has an invalid size or encoding.")
        }
        return data
    }

    private func labeled(_ label: String, _ context: Data) -> Data {
        concatenate(Data(label.utf8), Data([0]), context)
    }

    private func sealFrame(_ plaintext: Data, using key: SymmetricKey, aad: Data) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key, authenticating: aad)
        let nonce = sealed.nonce.withUnsafeBytes { Data($0) }
        return concatenate(nonce, sealed.ciphertext, sealed.tag)
    }

    private func openFrame(
        _ frame: Data,
        using key: SymmetricKey,
        aad: Data,
        ciphertextBytes: Int
    ) throws -> Data {
        guard frame.count == PrivateResponseProtocol.nonceBytes + ciphertextBytes + PrivateResponseProtocol.tagBytes else {
            throw PrivateResponseCryptoError.invalidEnvelope("An encrypted frame has an invalid size.")
        }
        let nonceEnd = PrivateResponseProtocol.nonceBytes
        let ciphertextEnd = nonceEnd + ciphertextBytes
        do {
            let box = try AES.GCM.SealedBox(
                nonce: AES.GCM.Nonce(data: frame[..<nonceEnd]),
                ciphertext: frame[nonceEnd..<ciphertextEnd],
                tag: frame[ciphertextEnd...]
            )
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw PrivateResponseCryptoError.decryptionFailed
        }
    }
}

struct PrivateResponsePlaintextV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let eventId: String
    let inviteeId: String
    let policyHash: String
    let envelopeId: String
    let accountKeyEpochId: String
    let revision: Int
    let response: RSVPResponse
    let minimumParticipants: Int?
    let requiredGroups: [RSVPConditionGroup]
    let nonce: String

    var canonicalJSONData: Data {
        let minimum = minimumParticipants.map(String.init) ?? "null"
        let groups = requiredGroups.map { group in
            let members = group.memberIDs
                .map { "\"\($0.uuidString.lowercased())\"" }
                .joined(separator: ",")
            return "{\"id\":\"\(group.id.lowercased())\",\"memberIDs\":[\(members)]}"
        }.joined(separator: ",")
        let json = "{" +
            "\"protocolVersion\":\(protocolVersion)," +
            "\"eventId\":\"\(eventId)\"," +
            "\"inviteeId\":\"\(inviteeId)\"," +
            "\"policyHash\":\"\(policyHash)\"," +
            "\"envelopeId\":\"\(envelopeId)\"," +
            "\"accountKeyEpochId\":\"\(accountKeyEpochId)\"," +
            "\"revision\":\(revision)," +
            "\"response\":\"\(response.rawValue)\"," +
            "\"minimumParticipants\":\(minimum)," +
            "\"requiredGroups\":[\(groups)]," +
            "\"nonce\":\"\(nonce)\"}"
        return Data(json.utf8)
    }
}

private extension PrivateResponseEnvelopeV1 {
    var canonicalJSONData: Data {
        let json = "{" +
            "\"protocolVersion\":\(protocolVersion)," +
            "\"cipherSuite\":\"\(cipherSuite)\"," +
            "\"envelopeId\":\"\(envelopeId)\"," +
            "\"eventId\":\"\(eventId)\"," +
            "\"inviteeId\":\"\(inviteeId)\"," +
            "\"policyHash\":\"\(policyHash)\"," +
            "\"revision\":\(revision)," +
            "\"accountKeyEpochId\":\"\(accountKeyEpochId)\"," +
            "\"evaluatorKeyId\":\"\(evaluatorKeyId)\"," +
            "\"payloadCiphertext\":\"\(payloadCiphertext)\"," +
            "\"userKeyWrap\":\"\(userKeyWrap)\"," +
            "\"evaluatorKeyWrap\":\"\(evaluatorKeyWrap)\"," +
            "\"responseSigningPublicKey\":\"\(responseSigningPublicKey)\"}"
        return Data(json.utf8)
    }
}

func secureRandomData(count: Int) throws -> Data {
    var data = Data(count: count)
    let status = data.withUnsafeMutableBytes { bytes in
        SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
    }
    guard status == errSecSuccess else {
        throw PrivateResponseCryptoError.randomGenerationFailed(status)
    }
    return data
}

func concatenate(_ values: Data...) -> Data {
    var result = Data()
    result.reserveCapacity(values.reduce(0) { $0 + $1.count })
    values.forEach { result.append($0) }
    return result
}

extension Data {
    init?(base64URLEncoded value: String) {
        guard !value.isEmpty, !value.contains("=") else { return nil }
        let base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = String(repeating: "=", count: (4 - base64.count % 4) % 4)
        self.init(base64Encoded: base64 + padding)
    }

    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
