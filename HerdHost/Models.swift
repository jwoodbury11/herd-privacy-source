import Foundation

enum RequiredAttendeeName {
    static func shortened(_ fullName: String) -> String {
        let parts = fullName.split(whereSeparator: \.isWhitespace)
        guard let firstName = parts.first else { return "Guest" }
        guard parts.count > 1, let lastInitial = parts.last?.first else {
            return String(firstName)
        }
        return "\(firstName) \(String(lastInitial).uppercased())"
    }
}

struct HerdUser: Identifiable, Codable, Hashable, Sendable {
    let id: String
    var phoneNumber: String
    var name: String
    var address: String
}

enum EventAccessRole: String, Codable, Hashable, Sendable {
    case host
    case invitee
}

enum EventHomeSection: Hashable, Sendable {
    case invites
    case hosted
    case unconfirmed
    case past
}

enum RSVPResponse: String, Codable, Hashable, Sendable {
    case going
    case cantCommit = "cant_commit"
}

enum EventResolutionStatus: String, Codable, Hashable, Sendable {
    case pending
    case confirmed
    case notConfirmed = "not_confirmed"
    case verificationUnavailable = "verification_unavailable"
}

struct RevealedGuestState: Codable, Hashable, Sendable {
    enum Status: String, Codable, Hashable, Sendable {
        case going
        case cantCommit = "cant_commit"
        case noResponse = "no_response"
    }

    let memberId: String
    let status: Status
    let missedDeadline: Bool
}

struct EvaluationResultAttestationV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let signingKeyId: String
    let evaluatedAt: String
    let canonicalDocument: String
    let signature: String
}

struct EventResolution: Codable, Hashable, Sendable {
    let status: EventResolutionStatus
    let attendingMemberIds: [String]?
    let attendanceRevealed: Bool?
    let guestStates: [RevealedGuestState]?
    let resolvedAt: Date?
    let retrying: Bool?
    let attestation: EvaluationResultAttestationV1?

    init(
        status: EventResolutionStatus,
        attendingMemberIds: [String]? = nil,
        attendanceRevealed: Bool? = nil,
        guestStates: [RevealedGuestState]? = nil,
        resolvedAt: Date? = nil,
        retrying: Bool? = nil,
        attestation: EvaluationResultAttestationV1? = nil
    ) {
        self.status = status
        self.attendingMemberIds = attendingMemberIds
        self.attendanceRevealed = attendanceRevealed
        self.guestStates = guestStates
        self.resolvedAt = resolvedAt
        self.retrying = retrying
        self.attestation = attestation
    }
}

enum InvitationDeliveryAggregateStatus: String, Codable, Hashable, Sendable {
    case inProgress = "in_progress"
    case complete
    case attentionNeeded = "attention_needed"
    case suppressed
}

enum InvitationDeliveryStatus: String, Codable, Hashable, Sendable {
    case pending
    case dispatching
    case sent
    case failed
    case unknown
    case suppressed
}

struct InvitationDeliveryCounts: Codable, Hashable, Sendable {
    let pending: Int
    let dispatching: Int
    let sent: Int
    let failed: Int
    let unknown: Int
    let suppressed: Int
}

struct InvitationDeliveryGuest: Codable, Hashable, Sendable {
    let inviteeId: UUID
    let displayName: String
    let status: InvitationDeliveryStatus
}

struct InvitationDeliverySummary: Codable, Hashable, Sendable {
    let status: InvitationDeliveryAggregateStatus
    let total: Int
    let counts: InvitationDeliveryCounts
    let guests: [InvitationDeliveryGuest]
}

struct RSVPConditionGroup: Identifiable, Codable, Hashable, Sendable {
    let id: String
    var memberIDs: [UUID]

    init(id: String = UUID().uuidString.lowercased(), memberIDs: [UUID]) {
        self.id = id
        self.memberIDs = memberIDs
    }
}

struct PrivateResponsePolicyV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let cipherSuite: String
    let policyHash: String
    let canonicalDocument: String
    let evaluatorKeyId: String
    let evaluatorPublicKey: String
    let evaluatorMeasurement: String
    let releaseId: String
    let paddedPlaintextBytes: Int
    let frozenAt: String
    let policySigningKeyId: String?
    let policySignature: String?
}

struct PrivateResponseEnvelopeV1: Codable, Hashable, Sendable {
    var protocolVersion: Int
    var cipherSuite: String
    var envelopeId: String
    var eventId: String
    var inviteeId: String
    var policyHash: String
    var revision: Int
    var accountKeyEpochId: String
    var evaluatorKeyId: String
    var payloadCiphertext: String
    var userKeyWrap: String
    var evaluatorKeyWrap: String
    var responseSigningPublicKey: String
    var responseSignature: String
}

struct StoredPrivateResponseEnvelopeV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let cipherSuite: String
    let envelopeId: String
    let eventId: String
    let inviteeId: String
    let policyHash: String
    let revision: Int
    let accountKeyEpochId: String
    let evaluatorKeyId: String
    let payloadCiphertext: String
    let userKeyWrap: String
    let evaluatorKeyWrap: String
    let responseSigningPublicKey: String
    let responseSignature: String
    let ciphertextHash: String
    let createdAt: String
    let updatedAt: String

    var envelope: PrivateResponseEnvelopeV1 {
        PrivateResponseEnvelopeV1(
            protocolVersion: protocolVersion,
            cipherSuite: cipherSuite,
            envelopeId: envelopeId,
            eventId: eventId,
            inviteeId: inviteeId,
            policyHash: policyHash,
            revision: revision,
            accountKeyEpochId: accountKeyEpochId,
            evaluatorKeyId: evaluatorKeyId,
            payloadCiphertext: payloadCiphertext,
            userKeyWrap: userKeyWrap,
            evaluatorKeyWrap: evaluatorKeyWrap,
            responseSigningPublicKey: responseSigningPublicKey,
            responseSignature: responseSignature
        )
    }
}

struct PrivateResponseReceiptV1: Codable, Hashable, Sendable {
    let envelopeId: String
    let eventId: String
    let inviteeId: String
    let policyHash: String
    let accountKeyEpochId: String
    let revision: Int
    let ciphertextHash: String
    let responseSigningPublicKey: String
    let responseSignature: String
    let committedAt: String
    let transparency: PrivateResponseTransparencyProofV1?
}

struct PrivateResponseLogHeadV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let logId: String
    let treeSize: Int
    let headEntryHash: String
    let generatedAt: String
    let signingKeyId: String
    let signature: String
}

struct PrivateResponseTransparencyProofV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let logId: String
    let logIndex: Int
    let previousEntryHash: String
    let entryHash: String
    let signingKeyId: String
    let receiptSignature: String
    let logHead: PrivateResponseLogHeadV1
}

struct PrivateResponseTransparencyLogEntryV1: Codable, Hashable, Sendable {
    let logIndex: Int
    let previousEntryHash: String
    let entryHash: String
    let head: PrivateResponseLogHeadV1
}

struct PrivateResponseTransparencyLogV1: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let logId: String
    let entries: [PrivateResponseTransparencyLogEntryV1]
}

struct PrivateResponseSubmissionResult: Hashable, Sendable {
    let responseEnvelope: StoredPrivateResponseEnvelopeV1
    let receipt: PrivateResponseReceiptV1
}

struct PrivateResponseDraft: Hashable, Sendable {
    let response: RSVPResponse
    let minimumParticipants: Int?
    let requiredGroups: [RSVPConditionGroup]
}

struct SimplifiedBallot: Codable, Hashable, Sendable {
    let protocolVersion: Int
    let ballotId: String
    let revision: Int
    let response: RSVPResponse
    let minimumParticipants: Int?
    let requiredGroups: [RSVPConditionGroup]
    let createdAt: Date
}

enum PrivateResponseCertificationStatus: String, Codable, Hashable, Sendable {
    case certified
    case pending
}

struct InvitePrivateResponseContext: Hashable, Sendable {
    let event: HerdEvent
    let inviteeID: UUID
    let accountKeyEpochID: UUID
    let accountKeyCommitment: String?
    let responseEnvelope: StoredPrivateResponseEnvelopeV1?
    let hasResponse: Bool
    let responseRevision: Int?
    let responseCertificationStatus: PrivateResponseCertificationStatus?
}

struct Invitee: Identifiable, Codable, Hashable, Sendable {
    struct ResponseHistory: Codable, Hashable, Sendable {
        let missedConfirmedEvents: Int
        let totalConfirmedEvents: Int
    }

    let id: UUID
    var sourceContactIdentifier: String?
    var displayName: String
    var phoneNumber: String
    var isCurrentUser: Bool
    var hasResponded: Bool?
    var responseHistory: ResponseHistory?

    init(
        id: UUID = UUID(),
        sourceContactIdentifier: String? = nil,
        displayName: String,
        phoneNumber: String,
        isCurrentUser: Bool = false,
        hasResponded: Bool? = nil,
        responseHistory: ResponseHistory? = nil
    ) {
        self.id = id
        self.sourceContactIdentifier = sourceContactIdentifier
        self.displayName = displayName
        self.phoneNumber = phoneNumber
        self.isCurrentUser = isCurrentUser
        self.hasResponded = hasResponded
        self.responseHistory = responseHistory
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case sourceContactIdentifier
        case displayName
        case phoneNumber
        case isCurrentUser
        case hasResponded
        case responseHistory
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        sourceContactIdentifier = try container.decodeIfPresent(
            String.self,
            forKey: .sourceContactIdentifier
        )
        displayName = try container.decode(String.self, forKey: .displayName)
        phoneNumber = try container.decodeIfPresent(String.self, forKey: .phoneNumber) ?? ""
        isCurrentUser = try container.decodeIfPresent(Bool.self, forKey: .isCurrentUser) ?? false
        hasResponded = try container.decodeIfPresent(Bool.self, forKey: .hasResponded)
        responseHistory = try container.decodeIfPresent(ResponseHistory.self, forKey: .responseHistory)
    }
}

struct RequiredAttendeeGroup: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    var memberIDs: [UUID]

    init(id: UUID = UUID(), memberIDs: [UUID]) {
        self.id = id
        self.memberIDs = memberIDs
    }
}

enum EventDeadlineRules {
    static let minimumEventSeparation: TimeInterval = 60
    static let submissionSafetyInterval: TimeInterval = 5
    static let suggestedLeadTime: TimeInterval = 60

    static func suggestedReplyDeadline(
        before eventDate: Date,
        now: Date = .now,
        calendar: Calendar = .current
    ) -> Date? {
        let earliest = now.addingTimeInterval(suggestedLeadTime)
        let latest = eventDate.addingTimeInterval(-minimumEventSeparation)
        guard earliest <= latest else { return nil }

        let preferred = calendar.date(byAdding: .day, value: -2, to: eventDate) ?? latest
        return min(max(preferred, earliest), latest)
    }

    static func canSubmit(deadline: Date, now: Date = .now) -> Bool {
        deadline > now.addingTimeInterval(submissionSafetyInterval)
    }
}

enum EventDraftDefaults {
    static func eventDate(
        now: Date = .now,
        calendar: Calendar = .current
    ) -> Date {
        let weekday = calendar.component(.weekday, from: now)
        let daysUntilSaturday = (7 - weekday + 7) % 7
        // Wednesday is the cutoff for planning the coming weekend. From then
        // on, start people on the following Saturday instead.
        let daysToAdd = weekday >= 4 ? daysUntilSaturday + 7 : daysUntilSaturday
        let saturday = calendar.date(byAdding: .day, value: daysToAdd, to: now)!
        return calendar.date(bySettingHour: 19, minute: 0, second: 0, of: saturday)!
    }

    static func rsvpDeadline(
        for eventDate: Date,
        calendar: Calendar = .current
    ) -> Date {
        let thursday = calendar.date(byAdding: .day, value: -2, to: eventDate)!
        return calendar.date(bySettingHour: 23, minute: 59, second: 0, of: thursday)!
    }
}

struct HerdEvent: Identifiable, Codable, Hashable, Sendable {
    let id: UUID
    var title: String
    var eventDate: Date?
    var eventTimeZone: String
    var endDate: Date?
    var hostName: String
    var locationName: String
    var locationAddress: String
    var invitees: [Invitee]
    var minimumParticipants: Int
    var allowsAttendeesToAddGuests: Bool
    var requiredGroups: [RequiredAttendeeGroup]
    var rsvpDeadline: Date?
    var eventDescription: String
    var eventImageID: EventImageID?
    let createdAt: Date
    var invitationsSent: Bool
    var role: EventAccessRole
    var inviteToken: String?
    var accountKeyEpochId: UUID?
    var accountKeyCommitment: String?
    var hasResponse: Bool
    var hasBallot: Bool
    var responseRevision: Int?
    var responseCertificationStatus: PrivateResponseCertificationStatus?
    var privateResponsePolicy: PrivateResponsePolicyV1?
    var resolution: EventResolution?
    var invitationDelivery: InvitationDeliverySummary?

    init(
        id: UUID,
        title: String,
        eventDate: Date?,
        eventTimeZone: String = TimeZone.autoupdatingCurrent.identifier,
        endDate: Date?,
        hostName: String,
        locationName: String,
        locationAddress: String,
        invitees: [Invitee],
        minimumParticipants: Int,
        allowsAttendeesToAddGuests: Bool = true,
        requiredGroups: [RequiredAttendeeGroup],
        rsvpDeadline: Date?,
        eventDescription: String,
        eventImageID: EventImageID? = .poker,
        createdAt: Date,
        invitationsSent: Bool = false,
        role: EventAccessRole = .host,
        inviteToken: String? = nil,
        accountKeyEpochId: UUID? = nil,
        accountKeyCommitment: String? = nil,
        hasResponse: Bool = false,
        hasBallot: Bool = false,
        responseRevision: Int? = nil,
        responseCertificationStatus: PrivateResponseCertificationStatus? = nil,
        privateResponsePolicy: PrivateResponsePolicyV1? = nil,
        resolution: EventResolution? = nil,
        invitationDelivery: InvitationDeliverySummary? = nil
    ) {
        self.id = id
        self.title = title
        self.eventDate = eventDate
        self.eventTimeZone = eventTimeZone
        self.endDate = endDate
        self.hostName = hostName
        self.locationName = locationName
        self.locationAddress = locationAddress
        self.invitees = invitees
        self.minimumParticipants = minimumParticipants
        self.allowsAttendeesToAddGuests = allowsAttendeesToAddGuests
        self.requiredGroups = requiredGroups
        self.rsvpDeadline = rsvpDeadline
        self.eventDescription = eventDescription
        self.eventImageID = eventImageID
        self.createdAt = createdAt
        self.invitationsSent = invitationsSent
        self.role = role
        self.inviteToken = inviteToken
        self.accountKeyEpochId = accountKeyEpochId
        self.accountKeyCommitment = accountKeyCommitment
        self.hasResponse = hasResponse
        self.hasBallot = hasBallot
        self.responseRevision = responseRevision
        self.responseCertificationStatus = responseCertificationStatus
        self.privateResponsePolicy = privateResponsePolicy
        self.resolution = resolution
        self.invitationDelivery = invitationDelivery
    }

    var resolvedEventImageID: EventImageID {
        eventImageID ?? .poker
    }

    mutating func ensureEventImageSelection() {
        if eventImageID == nil {
            eventImageID = .poker
        }
    }

    static func newDraft(
        hostName: String = "Host",
        now: Date = .now,
        calendar: Calendar = .current
    ) -> HerdEvent {
        let eventDate = EventDraftDefaults.eventDate(now: now, calendar: calendar)
        return HerdEvent(
            id: UUID(),
            title: "",
            eventDate: eventDate,
            endDate: nil,
            hostName: hostName,
            locationName: "",
            locationAddress: "",
            invitees: [],
            minimumParticipants: 4,
            allowsAttendeesToAddGuests: true,
            requiredGroups: [],
            rsvpDeadline: EventDraftDefaults.rsvpDeadline(
                for: eventDate,
                calendar: calendar
            ),
            eventDescription: "",
            eventImageID: .poker,
            createdAt: now,
            invitationsSent: false
        )
    }

    var isValid: Bool {
        outstandingTasks.isEmpty
    }

    var isHosted: Bool {
        role == .host
    }

    func homeSection(
        at now: Date = .now,
        calendar: Calendar = .current
    ) -> EventHomeSection {
        if invitationsSent,
           let rsvpDeadline,
           rsvpDeadline <= now,
           resolution?.status != .confirmed {
            return .unconfirmed
        }

        if let eventDate,
           let dayAfterEvent = calendar.date(
               byAdding: .day,
               value: 1,
               to: calendar.startOfDay(for: eventDate)
           ),
           now >= dayAfterEvent {
            return .past
        }

        return isHosted ? .hosted : .invites
    }

    var participantCount: Int {
        invitees.count + 1
    }

    /// The host is an affirmative participant by definition, so response
    /// progress starts at one before any invitee has submitted a reply.
    var respondedParticipantCount: Int {
        invitees.filter { $0.hasResponded == true }.count + 1
    }

    var outstandingTasks: [String] {
        var tasks: [String] = []

        if title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            tasks.append("Add an event title")
        }

        if eventDate == nil {
            tasks.append("Set the event date and time")
        }

        if let eventDate, let endDate, endDate <= eventDate {
            tasks.append("Move the end time after the start")
        }

        if !invitees.isEmpty {
            let requiredInviteeCount = max(1, minimumParticipants - 1)
            if invitees.count < requiredInviteeCount {
                let remaining = requiredInviteeCount - invitees.count
                let attendeeLabel = remaining == 1 ? "attendee" : "attendees"
                tasks.append("Add \(remaining) more \(attendeeLabel) or lower the minimum")
            }
        }

        if rsvpDeadline == nil {
            tasks.append("Set an RSVP deadline")
        }

        if !invitationsSent,
           let rsvpDeadline,
           !EventDeadlineRules.canSubmit(deadline: rsvpDeadline) {
            tasks.append("Move the RSVP deadline into the future")
        }

        if let eventDate, let rsvpDeadline, rsvpDeadline >= eventDate {
            tasks.append("Move the RSVP deadline before the event")
        }

        let inviteeIDs = Set(invitees.map(\.id))
        let requiredMemberIDs = requiredGroups.flatMap(\.memberIDs)
        let requiredGroupIDs = requiredGroups.map(\.id)
        if Set(requiredGroupIDs).count != requiredGroupIDs.count ||
            Set(requiredMemberIDs).count != requiredMemberIDs.count ||
            requiredGroups.contains(where: { group in
                group.memberIDs.isEmpty || !group.memberIDs.allSatisfy(inviteeIDs.contains)
            }) {
            tasks.append("Fix the required-attendee rules")
        }

        return tasks
    }

    mutating func removeInvalidRequiredAttendees() {
        let validIDs = Set(invitees.map(\.id))
        requiredGroups = requiredGroups.compactMap { group in
            let members = group.memberIDs.filter(validIDs.contains)
            return members.isEmpty ? nil : RequiredAttendeeGroup(id: group.id, memberIDs: members)
        }
    }

    func name(for inviteeID: UUID) -> String {
        invitees.first(where: { $0.id == inviteeID })?.displayName ?? "Unknown"
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case title
        case eventDate
        case eventTimeZone
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
        case role
        case inviteToken
        case accountKeyEpochId
        case accountKeyCommitment
        case hasResponse
        case hasBallot
        case responseRevision
        case privateResponsePolicy
        case resolution
        case invitationDelivery
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decode(UUID.self, forKey: .id)
        title = try container.decode(String.self, forKey: .title)
        eventDate = try container.decodeIfPresent(Date.self, forKey: .eventDate)
        eventTimeZone = try container.decodeIfPresent(String.self, forKey: .eventTimeZone)
            ?? TimeZone.autoupdatingCurrent.identifier
        endDate = try container.decodeIfPresent(Date.self, forKey: .endDate)
        hostName = try container.decode(String.self, forKey: .hostName)
        locationName = try container.decode(String.self, forKey: .locationName)
        locationAddress = try container.decode(String.self, forKey: .locationAddress)
        invitees = try container.decode([Invitee].self, forKey: .invitees)
        minimumParticipants = try container.decode(Int.self, forKey: .minimumParticipants)
        allowsAttendeesToAddGuests = try container.decodeIfPresent(
            Bool.self,
            forKey: .allowsAttendeesToAddGuests
        ) ?? true
        requiredGroups = try container.decode([RequiredAttendeeGroup].self, forKey: .requiredGroups)
        rsvpDeadline = try container.decodeIfPresent(Date.self, forKey: .rsvpDeadline)
        eventDescription = try container.decode(String.self, forKey: .eventDescription)
        createdAt = try container.decode(Date.self, forKey: .createdAt)
        invitationsSent = try container.decodeIfPresent(Bool.self, forKey: .invitationsSent) ?? false
        role = try container.decodeIfPresent(EventAccessRole.self, forKey: .role) ?? .host
        inviteToken = try container.decodeIfPresent(String.self, forKey: .inviteToken)
        accountKeyEpochId = try container.decodeIfPresent(UUID.self, forKey: .accountKeyEpochId)
        accountKeyCommitment = try container.decodeIfPresent(String.self, forKey: .accountKeyCommitment)
        hasResponse = try container.decodeIfPresent(Bool.self, forKey: .hasResponse) ?? false
        hasBallot = try container.decodeIfPresent(Bool.self, forKey: .hasBallot) ?? false
        responseRevision = try container.decodeIfPresent(Int.self, forKey: .responseRevision)
        privateResponsePolicy = try container.decodeIfPresent(
            PrivateResponsePolicyV1.self,
            forKey: .privateResponsePolicy
        )
        resolution = try container.decodeIfPresent(EventResolution.self, forKey: .resolution)
        invitationDelivery = try container.decodeIfPresent(
            InvitationDeliverySummary.self,
            forKey: .invitationDelivery
        )
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(title, forKey: .title)
        try container.encodeIfPresent(eventDate, forKey: .eventDate)
        try container.encode(eventTimeZone, forKey: .eventTimeZone)
        try container.encodeIfPresent(endDate, forKey: .endDate)
        try container.encode(hostName, forKey: .hostName)
        try container.encode(locationName, forKey: .locationName)
        try container.encode(locationAddress, forKey: .locationAddress)
        try container.encode(invitees, forKey: .invitees)
        try container.encode(minimumParticipants, forKey: .minimumParticipants)
        try container.encode(allowsAttendeesToAddGuests, forKey: .allowsAttendeesToAddGuests)
        try container.encode(requiredGroups, forKey: .requiredGroups)
        try container.encodeIfPresent(rsvpDeadline, forKey: .rsvpDeadline)
        try container.encode(eventDescription, forKey: .eventDescription)
        try container.encode(createdAt, forKey: .createdAt)
        try container.encode(invitationsSent, forKey: .invitationsSent)
        try container.encode(role, forKey: .role)
        try container.encodeIfPresent(inviteToken, forKey: .inviteToken)
        try container.encodeIfPresent(accountKeyEpochId, forKey: .accountKeyEpochId)
        try container.encodeIfPresent(accountKeyCommitment, forKey: .accountKeyCommitment)
        try container.encode(hasResponse, forKey: .hasResponse)
        try container.encode(hasBallot, forKey: .hasBallot)
        try container.encodeIfPresent(responseRevision, forKey: .responseRevision)
        try container.encodeIfPresent(privateResponsePolicy, forKey: .privateResponsePolicy)
        try container.encodeIfPresent(resolution, forKey: .resolution)
        try container.encodeIfPresent(invitationDelivery, forKey: .invitationDelivery)
    }
}

struct ContactCandidate: Identifiable, Hashable, Sendable {
    let id: String
    let displayName: String
    let phoneNumber: String
}
