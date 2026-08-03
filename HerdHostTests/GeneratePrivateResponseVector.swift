import CryptoKit
import Foundation

@main
private enum GeneratePrivateResponseVector {
    static func main() throws {
        guard CommandLine.arguments.count == 2 else {
            throw GeneratorError.usage
        }
        let fixtureURL = URL(fileURLWithPath: CommandLine.arguments[1])
        let fixture = try JSONDecoder().decode(
            GeneratorFixture.self,
            from: Data(contentsOf: fixtureURL)
        )
        guard let base = fixture.vectors.first else {
            throw GeneratorError.emptyFixture
        }
        let eventID = try requiredUUID(base.eventId)
        // Reuse the Web vector's event/member/epoch/ARS so the independently
        // derived public authorization key must agree across implementations.
        let inviteeID = try requiredUUID(base.inviteeId)
        let accountKeyEpochID = try requiredUUID(base.accountKeyEpochId)
        let allowedMemberIDs = Set(try base.allowedInviteeIds.map(requiredUUID))
        guard
            let evaluatorPublicKey = Data(base64URLEncoded: base.policy.evaluatorPublicKey),
            let rootSecret = Data(base64URLEncoded: base.accountRootSecret)
        else {
            throw GeneratorError.invalidFixture
        }
        let crypto = PrivateResponseCrypto(
            pinnedEvaluator: PinnedEvaluator(
                keyID: base.policy.evaluatorKeyId,
                publicKey: evaluatorPublicKey,
                policySigningKeyID: base.policy.policySigningKeyId ?? "",
                policySigningPublicKey: try requiredData(
                    fixture.trustPins.policySigning.publicKey
                )
            )
        )
        let accountRootSecret = SymmetricKey(data: rootSecret)
        let envelope = try crypto.seal(
            eventID: eventID,
            inviteeID: inviteeID,
            accountKeyEpochID: accountKeyEpochID,
            revision: 8,
            response: .cantCommit,
            minimumParticipants: nil,
            minimumAllowedParticipants: base.minimumAllowedParticipants,
            requiredGroups: [],
            allowedMemberIDs: allowedMemberIDs,
            policy: base.policy,
            accountRootSecret: accountRootSecret
        )
        let plaintext = try crypto.open(
            envelope,
            eventID: eventID,
            inviteeID: inviteeID,
            accountKeyEpochID: accountKeyEpochID,
            minimumAllowedParticipants: base.minimumAllowedParticipants,
            allowedMemberIDs: allowedMemberIDs,
            policy: base.policy,
            accountRootSecret: accountRootSecret
        )
        let vector = GeneratedVector(
            name: "ios-cant-commit-with-empty-conditions",
            producer: "HerdHost CryptoKit",
            eventId: base.eventId,
            inviteeId: inviteeID.uuidString.lowercased(),
            accountKeyEpochId: accountKeyEpochID.uuidString.lowercased(),
            minimumAllowedParticipants: base.minimumAllowedParticipants,
            allowedInviteeIds: base.allowedInviteeIds,
            accountRootSecret: base.accountRootSecret,
            policy: base.policy,
            envelope: envelope,
            expectedDraft: GeneratedDraft(plaintext),
            expectedEnvelopeHash: try crypto.envelopeHash(envelope)
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        var data = try encoder.encode(vector)
        data.append(0x0a)
        FileHandle.standardOutput.write(data)
    }

    private static func requiredUUID(_ value: String) throws -> UUID {
        guard let result = UUID(uuidString: value) else {
            throw GeneratorError.invalidFixture
        }
        return result
    }

    private static func requiredData(_ value: String) throws -> Data {
        guard let result = Data(base64URLEncoded: value) else {
            throw GeneratorError.invalidFixture
        }
        return result
    }
}

private struct GeneratorFixture: Decodable {
    let vectors: [GeneratorBaseVector]
    let trustPins: GeneratorTrustPins
}

private struct GeneratorBaseVector: Decodable {
    let eventId: String
    let inviteeId: String
    let accountKeyEpochId: String
    let minimumAllowedParticipants: Int
    let allowedInviteeIds: [String]
    let accountRootSecret: String
    let policy: PrivateResponsePolicyV1
}

private struct GeneratorTrustPins: Decodable {
    let policySigning: GeneratorTrustPin
}

private struct GeneratorTrustPin: Decodable {
    let publicKey: String
}

private struct GeneratedVector: Encodable {
    let name: String
    let producer: String
    let eventId: String
    let inviteeId: String
    let accountKeyEpochId: String
    let minimumAllowedParticipants: Int
    let allowedInviteeIds: [String]
    let accountRootSecret: String
    let policy: PrivateResponsePolicyV1
    let envelope: PrivateResponseEnvelopeV1
    let expectedDraft: GeneratedDraft
    let expectedEnvelopeHash: String
}

private struct GeneratedDraft: Encodable {
    let value: PrivateResponsePlaintextV1

    init(_ value: PrivateResponsePlaintextV1) {
        self.value = value
    }

    private enum CodingKeys: String, CodingKey {
        case protocolVersion
        case eventId
        case inviteeId
        case policyHash
        case envelopeId
        case accountKeyEpochId
        case revision
        case response
        case minimumParticipants
        case requiredGroups
        case nonce
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(value.protocolVersion, forKey: .protocolVersion)
        try container.encode(value.eventId, forKey: .eventId)
        try container.encode(value.inviteeId, forKey: .inviteeId)
        try container.encode(value.policyHash, forKey: .policyHash)
        try container.encode(value.envelopeId, forKey: .envelopeId)
        try container.encode(value.accountKeyEpochId, forKey: .accountKeyEpochId)
        try container.encode(value.revision, forKey: .revision)
        try container.encode(value.response, forKey: .response)
        if let minimumParticipants = value.minimumParticipants {
            try container.encode(minimumParticipants, forKey: .minimumParticipants)
        } else {
            try container.encodeNil(forKey: .minimumParticipants)
        }
        try container.encode(value.requiredGroups, forKey: .requiredGroups)
        try container.encode(value.nonce, forKey: .nonce)
    }
}

private enum GeneratorError: Error {
    case usage
    case emptyFixture
    case invalidFixture
}
