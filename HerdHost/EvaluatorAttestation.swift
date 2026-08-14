import CryptoKit
import Foundation
import Security

struct EvaluatorKeyMetadata: Codable, Hashable, Sendable {
    let keyId: String
    let algorithm: String
    let publicKey: String
}

struct EvaluatorKeySet: Codable, Hashable, Sendable {
    let responseDecryption: EvaluatorKeyMetadata
    let evaluationResultSigning: EvaluatorKeyMetadata
    let policySigning: EvaluatorKeyMetadata
    let transparencySigning: EvaluatorKeyMetadata
}

struct EvaluatorKeyBinding: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let releaseId: String
    let keys: EvaluatorKeySet

    var canonicalJSON: String {
        "{" +
            "\"protocolVersion\":\(protocolVersion)," +
            "\"releaseId\":\(Self.quoted(releaseId))," +
            "\"keys\":{" +
            "\"responseDecryption\":\(Self.keyJSON(keys.responseDecryption))," +
            "\"evaluationResultSigning\":\(Self.keyJSON(keys.evaluationResultSigning))," +
            "\"policySigning\":\(Self.keyJSON(keys.policySigning))," +
            "\"transparencySigning\":\(Self.keyJSON(keys.transparencySigning))}}"
    }

    private static func keyJSON(_ key: EvaluatorKeyMetadata) -> String {
        "{" +
            "\"keyId\":\(quoted(key.keyId))," +
            "\"algorithm\":\(quoted(key.algorithm))," +
            "\"publicKey\":\(quoted(key.publicKey))}"
    }

    private static func quoted(_ value: String) -> String {
        String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
    }
}

struct EvaluatorAttestationResponse: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let tokenType: String
    let audience: String
    let nonce: String
    let keyBinding: EvaluatorKeyBinding
    let keyBindingHash: String
    let attestationToken: String
}

enum EvaluatorAttestationVerificationError: LocalizedError, Sendable {
    case invalidRelease
    case invalidAttestation
    case untrustedWorkload

    var errorDescription: String? {
        switch self {
        case .invalidRelease:
            "This Herd build is missing a valid confidential-evaluator trust policy."
        case .invalidAttestation:
            "The confidential evaluator returned an invalid hardware attestation."
        case .untrustedWorkload:
            "The evaluator does not match the measured Herd release approved by this app."
        }
    }
}

struct EvaluatorAttestationVerifier: Sendable {
    private static let issuer = "https://confidentialcomputing.googleapis.com"
    private static let keyBindingDomain = "HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1"
    private static let clockSkew: TimeInterval = 30

    let audience: String
    let projectID: String
    let serviceAccount: String
    let imageDigest: String
    let allowedImageDigests: Set<String>
    let policyMeasurement: String
    let rootCertificate: Data
    let rootFingerprint: String
    let allowedSWVersions: Set<String>
    let maximumAge: TimeInterval
    let keyBinding: EvaluatorKeyBinding

    static func configured(bundle: Bundle = .main) throws -> EvaluatorAttestationVerifier {
        func value(_ key: String) throws -> String {
            guard
                let raw = bundle.object(forInfoDictionaryKey: key) as? String,
                !raw.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            else { throw EvaluatorAttestationVerificationError.invalidRelease }
            return raw.trimmingCharacters(in: .whitespacesAndNewlines)
        }

        func key(
            id idSetting: String,
            publicKey publicKeySetting: String,
            algorithm: String
        ) throws -> EvaluatorKeyMetadata {
            let id = try value(idSetting)
            let encodedPublicKey = try value(publicKeySetting)
            guard
                PinnedEvaluator.isValidKeyID(id),
                let publicKey = Data(base64URLEncoded: encodedPublicKey),
                publicKey.count == 65,
                publicKey.first == 0x04,
                publicKey.base64URLEncodedString() == encodedPublicKey
            else { throw EvaluatorAttestationVerificationError.invalidRelease }
            return EvaluatorKeyMetadata(
                keyId: id,
                algorithm: algorithm,
                publicKey: encodedPublicKey
            )
        }

        let releaseID = try value("HERD_RELEASE_ID")
        guard PinnedEvaluator.isValidKeyID(releaseID) else {
            throw EvaluatorAttestationVerificationError.invalidRelease
        }
        let keys = EvaluatorKeySet(
            responseDecryption: try key(
                id: "HERD_EVALUATOR_KEY_ID",
                publicKey: "HERD_EVALUATOR_PUBLIC_KEY",
                algorithm: "ECDH_P256"
            ),
            evaluationResultSigning: try key(
                id: "HERD_EVALUATOR_RESULT_SIGNING_KEY_ID",
                publicKey: "HERD_EVALUATOR_RESULT_SIGNING_PUBLIC_KEY",
                algorithm: "ECDSA_P256_SHA256"
            ),
            policySigning: try key(
                id: "HERD_EVALUATOR_POLICY_SIGNING_KEY_ID",
                publicKey: "HERD_EVALUATOR_POLICY_SIGNING_PUBLIC_KEY",
                algorithm: "ECDSA_P256_SHA256"
            ),
            transparencySigning: try key(
                id: "HERD_EVALUATOR_TRANSPARENCY_SIGNING_KEY_ID",
                publicKey: "HERD_EVALUATOR_TRANSPARENCY_SIGNING_PUBLIC_KEY",
                algorithm: "ECDSA_P256_SHA256"
            )
        )
        let allKeys = [
            keys.responseDecryption,
            keys.evaluationResultSigning,
            keys.policySigning,
            keys.transparencySigning,
        ]
        guard
            Set(allKeys.map(\.keyId)).count == allKeys.count,
            Set(allKeys.map(\.publicKey)).count == allKeys.count
        else { throw EvaluatorAttestationVerificationError.invalidRelease }

        let rootValue = try value("HERD_ATTESTATION_ROOT_CERTIFICATE_BASE64")
        guard
            let rootCertificate = Data(base64Encoded: rootValue),
            rootCertificate.base64EncodedString() == rootValue
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let rootFingerprint = try value("HERD_ATTESTATION_ROOT_FINGERPRINT")
        guard
            rootFingerprint.range(of: "^[0-9a-f]{64}$", options: .regularExpression) != nil,
            Data(SHA256.hash(data: rootCertificate)).hexString == rootFingerprint
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let imageDigest = try value("HERD_ATTESTATION_IMAGE_DIGEST")
        guard imageDigest.range(
            of: "^sha256:[0-9a-f]{64}$",
            options: .regularExpression
        ) != nil else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let configuredDigestList = (bundle.object(
            forInfoDictionaryKey: "HERD_ATTESTATION_IMAGE_DIGESTS"
        ) as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
        let digestListValue = configuredDigestList.flatMap { $0.isEmpty ? nil : $0 } ?? imageDigest
        let imageDigests = digestListValue
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard
            (1...2).contains(imageDigests.count),
            imageDigests.first == imageDigest,
            Set(imageDigests).count == imageDigests.count,
            imageDigests.allSatisfy({
                $0.range(of: "^sha256:[0-9a-f]{64}$", options: .regularExpression) != nil
            })
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let policyMeasurement = try value("HERD_EVALUATOR_MEASUREMENT")
        guard policyMeasurement.range(
            of: "^sha256:[0-9a-f]{64}$",
            options: .regularExpression
        ) != nil else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let versions = try value("HERD_ATTESTATION_SWVERSIONS")
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
        guard
            !versions.isEmpty,
            Set(versions).count == versions.count,
            versions.allSatisfy({
                $0.range(of: "^[0-9]{6}$", options: .regularExpression) != nil
            })
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        let maxAgeValue = try value("HERD_ATTESTATION_MAX_AGE_SECONDS")
        guard let maxAgeSeconds = Int(maxAgeValue), (30...900).contains(maxAgeSeconds) else {
            throw EvaluatorAttestationVerificationError.invalidRelease
        }
        let maxAge = TimeInterval(maxAgeSeconds)
        let audience = try value("HERD_ATTESTATION_AUDIENCE")
        guard
            let audienceURL = URL(string: audience),
            audienceURL.scheme == "https",
            audienceURL.host?.isEmpty == false,
            audienceURL.user == nil,
            audienceURL.password == nil,
            audienceURL.fragment == nil
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        return EvaluatorAttestationVerifier(
            audience: audience,
            projectID: try value("HERD_ATTESTATION_PROJECT_ID"),
            serviceAccount: try value("HERD_ATTESTATION_SERVICE_ACCOUNT"),
            imageDigest: imageDigest,
            allowedImageDigests: Set(imageDigests),
            policyMeasurement: policyMeasurement,
            rootCertificate: rootCertificate,
            rootFingerprint: rootFingerprint,
            allowedSWVersions: Set(versions),
            maximumAge: maxAge,
            keyBinding: EvaluatorKeyBinding(
                protocolVersion: PrivateResponseProtocol.version,
                releaseId: releaseID,
                keys: keys
            )
        )
    }

    func verify(
        _ response: EvaluatorAttestationResponse,
        nonce: String,
        policy: PrivateResponsePolicyV1,
        now: Date = .now
    ) throws {
        let calculatedKeyBindingHash = Data(
            SHA256.hash(
                data: concatenate(
                    Data(Self.keyBindingDomain.utf8),
                    Data([0]),
                    Data(response.keyBinding.canonicalJSON.utf8)
                )
            )
        ).base64URLEncodedString()
        guard
            response.protocolVersion == PrivateResponseProtocol.version,
            response.tokenType == "google-pki",
            response.audience == audience,
            response.nonce == nonce,
            response.keyBinding == keyBinding,
            response.keyBindingHash == calculatedKeyBindingHash,
            policy.releaseId == keyBinding.releaseId,
            policy.evaluatorKeyId == keyBinding.keys.responseDecryption.keyId,
            policy.evaluatorPublicKey == keyBinding.keys.responseDecryption.publicKey,
            policy.evaluatorMeasurement == policyMeasurement
        else { throw EvaluatorAttestationVerificationError.untrustedWorkload }
        try verifyToken(
            response.attestationToken,
            nonce: nonce,
            keyBindingHash: calculatedKeyBindingHash,
            now: now
        )
    }

    private func verifyToken(
        _ token: String,
        nonce: String,
        keyBindingHash: String,
        now: Date
    ) throws {
        let segments = token.split(separator: ".", omittingEmptySubsequences: false)
        guard segments.count == 3, token.utf8.count <= 128 * 1_024 else {
            throw EvaluatorAttestationVerificationError.invalidAttestation
        }
        let headerData = try decodedBase64URL(String(segments[0]))
        let claimsData = try decodedBase64URL(String(segments[1]))
        let signature = try decodedBase64URL(String(segments[2]))
        guard
            let header = try JSONSerialization.jsonObject(with: headerData) as? [String: Any],
            header["alg"] as? String == "RS256",
            header["typ"] == nil || header["typ"] as? String == "JWT",
            header["jku"] == nil,
            header["jwk"] == nil,
            header["x5u"] == nil,
            header["crit"] == nil,
            let encodedCertificates = header["x5c"] as? [String],
            !encodedCertificates.isEmpty,
            encodedCertificates.count <= 6
        else { throw EvaluatorAttestationVerificationError.invalidAttestation }
        let certificates = try encodedCertificates.map { value -> SecCertificate in
            guard
                let data = Data(base64Encoded: value),
                data.base64EncodedString() == value,
                let certificate = SecCertificateCreateWithData(nil, data as CFData)
            else { throw EvaluatorAttestationVerificationError.invalidAttestation }
            return certificate
        }
        guard
            let root = SecCertificateCreateWithData(nil, rootCertificate as CFData),
            Data(SHA256.hash(data: rootCertificate)).hexString == rootFingerprint
        else { throw EvaluatorAttestationVerificationError.invalidRelease }
        var trustValue: SecTrust?
        guard
            SecTrustCreateWithCertificates(
                certificates as CFArray,
                SecPolicyCreateBasicX509(),
                &trustValue
            ) == errSecSuccess,
            let trust = trustValue,
            SecTrustSetAnchorCertificates(trust, [root] as CFArray) == errSecSuccess,
            SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
            SecTrustSetVerifyDate(trust, now as CFDate) == errSecSuccess,
            SecTrustEvaluateWithError(trust, nil),
            let leafKey = SecTrustCopyKey(trust)
        else { throw EvaluatorAttestationVerificationError.invalidAttestation }
        let signingInput = Data("\(segments[0]).\(segments[1])".utf8)
        guard SecKeyVerifySignature(
            leafKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            signature as CFData,
            nil
        ) else { throw EvaluatorAttestationVerificationError.invalidAttestation }

        guard
            let claims = try JSONSerialization.jsonObject(with: claimsData) as? [String: Any],
            claims["iss"] as? String == Self.issuer,
            claims["aud"] as? String == audience,
            let issuedAt = (claims["iat"] as? NSNumber)?.doubleValue,
            let notBefore = (claims["nbf"] as? NSNumber)?.doubleValue,
            let expiresAt = (claims["exp"] as? NSNumber)?.doubleValue,
            issuedAt.isFinite,
            notBefore.isFinite,
            expiresAt.isFinite,
            issuedAt.rounded(.towardZero) == issuedAt,
            notBefore.rounded(.towardZero) == notBefore,
            expiresAt.rounded(.towardZero) == expiresAt,
            issuedAt <= now.timeIntervalSince1970 + Self.clockSkew,
            now.timeIntervalSince1970 - issuedAt <= maximumAge,
            notBefore <= now.timeIntervalSince1970 + Self.clockSkew,
            expiresAt > now.timeIntervalSince1970 - Self.clockSkew,
            expiresAt > issuedAt,
            expiresAt > notBefore,
            expiresAt - issuedAt <= 7_200,
            nonceValues(claims["eat_nonce"]) == [nonce, keyBindingHash],
            claims["secboot"] as? Bool == true,
            claims["dbgstat"] as? String == "disabled-since-boot",
            claims["hwmodel"] as? String == "GCP_INTEL_TDX",
            claims["swname"] as? String == "CONFIDENTIAL_SPACE",
            (claims["oemid"] as? NSNumber)?.doubleValue == 11_129,
            let attesterTCB = claims["attester_tcb"] as? [String],
            attesterTCB == ["INTEL"],
            let swVersions = claims["swversion"] as? [String],
            swVersions.count == 1,
            allowedSWVersions.contains(swVersions[0]),
            let serviceAccounts = claims["google_service_accounts"] as? [String],
            serviceAccounts == [serviceAccount],
            let submods = claims["submods"] as? [String: Any],
            let gce = submods["gce"] as? [String: Any],
            gce["project_id"] as? String == projectID,
            let container = submods["container"] as? [String: Any],
            let attestedImageDigest = container["image_digest"] as? String,
            allowedImageDigests.contains(attestedImageDigest),
            container["restart_policy"] as? String == "Always",
            emptyEnvironmentOverride(container["env_override"]),
            emptyCommandOverride(container["cmd_override"]),
            let confidentialSpace = submods["confidential_space"] as? [String: Any],
            let support = confidentialSpace["support_attributes"] as? [String],
            support.contains("USABLE"),
            support.contains("STABLE"),
            let monitoring = confidentialSpace["monitoring_enabled"] as? [String: Any],
            monitoring.count == 1,
            monitoring["memory"] as? Bool == false
        else { throw EvaluatorAttestationVerificationError.untrustedWorkload }
    }

    private func decodedBase64URL(_ value: String) throws -> Data {
        guard
            let data = Data(base64URLEncoded: value),
            data.base64URLEncodedString() == value
        else { throw EvaluatorAttestationVerificationError.invalidAttestation }
        return data
    }

    private func nonceValues(_ value: Any?) -> [String]? {
        if let single = value as? String { return [single] }
        return value as? [String]
    }

    private func emptyCommandOverride(_ value: Any?) -> Bool {
        if value == nil { return true }
        guard let values = value as? [Any] else { return false }
        return values.isEmpty
    }

    private func emptyEnvironmentOverride(_ value: Any?) -> Bool {
        if value == nil { return true }
        guard let values = value as? [String: Any] else { return false }
        return values.isEmpty
    }
}

private extension Data {
    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
