import CryptoKit
import Security
import XCTest
@testable import HerdHost

final class AccountKeyDeletionTests: XCTestCase {
    func testDeletingAnAccountRemovesEveryLocalRootSecretItem() async throws {
        let service = "com.herd.tests.account-deletion.\(UUID().uuidString.lowercased())"
        let userID = "user-account-deletion"
        let epochID = UUID()
        let store = AccountKeyStore(service: service)

        _ = try await store.createRootSecret(userID: userID, epochID: epochID)
        let existedBeforeDeletion = await store.hasRootSecret(
            userID: userID,
            epochID: epochID
        )
        XCTAssertTrue(existedBeforeDeletion)

        try await store.deleteAllRootSecretMaterial(userID: userID)
        let existsAfterDeletion = await store.hasRootSecret(
            userID: userID,
            epochID: epochID
        )
        XCTAssertFalse(existsAfterDeletion)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        XCTAssertEqual(SecItemCopyMatching(query as CFDictionary, nil), errSecItemNotFound)
    }
}

final class PrivateResponseInteropTests: XCTestCase {
    func testWebCryptoVectorsOpenOnIOSByteForByte() throws {
        let fixture = try loadFixture()
        XCTAssertEqual(fixture.formatVersion, 1)
        XCTAssertGreaterThanOrEqual(fixture.vectors.count, 2)

        for vector in fixture.vectors {
            let crypto = try makeCrypto(for: vector)
            let opened = try crypto.open(
                vector.envelope,
                eventID: try XCTUnwrap(UUID(uuidString: vector.eventId)),
                inviteeID: try XCTUnwrap(UUID(uuidString: vector.inviteeId)),
                accountKeyEpochID: try XCTUnwrap(UUID(uuidString: vector.accountKeyEpochId)),
                minimumAllowedParticipants: vector.minimumAllowedParticipants,
                allowedMemberIDs: try allowedMemberIDs(vector),
                policy: vector.policy,
                accountRootSecret: try accountRootSecret(vector)
            )

            XCTAssertEqual(opened, vector.expectedDraft, vector.name)
            XCTAssertEqual(
                try crypto.envelopeHash(vector.envelope),
                vector.expectedEnvelopeHash,
                vector.name
            )
        }
    }

    func testWebCryptoVectorRejectsCiphertextAndPolicyTampering() throws {
        let vector = try XCTUnwrap(loadFixture().vectors.first)
        let crypto = try makeCrypto(for: vector)
        var tamperedEnvelope = vector.envelope
        let first = try XCTUnwrap(tamperedEnvelope.payloadCiphertext.first)
        tamperedEnvelope.payloadCiphertext.replaceSubrange(
            tamperedEnvelope.payloadCiphertext.startIndex...tamperedEnvelope.payloadCiphertext.startIndex,
            with: first == "A" ? "B" : "A"
        )
        XCTAssertThrowsError(
            try crypto.open(
                tamperedEnvelope,
                eventID: try XCTUnwrap(UUID(uuidString: vector.eventId)),
                inviteeID: try XCTUnwrap(UUID(uuidString: vector.inviteeId)),
                accountKeyEpochID: try XCTUnwrap(UUID(uuidString: vector.accountKeyEpochId)),
                minimumAllowedParticipants: vector.minimumAllowedParticipants,
                allowedMemberIDs: try allowedMemberIDs(vector),
                policy: vector.policy,
                accountRootSecret: try accountRootSecret(vector)
            )
        )

        let policy = PrivateResponsePolicyV1(
            protocolVersion: vector.policy.protocolVersion,
            cipherSuite: vector.policy.cipherSuite,
            policyHash: vector.policy.policyHash,
            canonicalDocument: vector.policy.canonicalDocument + " ",
            evaluatorKeyId: vector.policy.evaluatorKeyId,
            evaluatorPublicKey: vector.policy.evaluatorPublicKey,
            evaluatorMeasurement: vector.policy.evaluatorMeasurement,
            releaseId: vector.policy.releaseId,
            paddedPlaintextBytes: vector.policy.paddedPlaintextBytes,
            frozenAt: vector.policy.frozenAt,
            policySigningKeyId: vector.policy.policySigningKeyId,
            policySignature: vector.policy.policySignature
        )
        XCTAssertThrowsError(try makePinnedEvaluator(for: vector).verify(policy))
    }

    func testIOSSealRoundTripEnforcesEnvelopeAndDraftRules() throws {
        let vector = try XCTUnwrap(loadFixture().vectors.first)
        let crypto = try makeCrypto(for: vector)
        let eventID = try XCTUnwrap(UUID(uuidString: vector.eventId))
        let inviteeID = try XCTUnwrap(UUID(uuidString: vector.inviteeId))
        let accountKeyEpochID = UUID(uuidString: "70000000-0000-4000-8000-000000000199")!
        let allowed = try allowedMemberIDs(vector)
        let otherInvitees = allowed.filter { $0 != inviteeID }
        let conditionMember = try XCTUnwrap(otherInvitees.first)
        let group = RSVPConditionGroup(
            id: "60000000-0000-4000-8000-000000000199",
            memberIDs: [conditionMember]
        )

        let sealed = try crypto.seal(
            eventID: eventID,
            inviteeID: inviteeID,
            accountKeyEpochID: accountKeyEpochID,
            revision: 99,
            response: .going,
            minimumParticipants: 3,
            minimumAllowedParticipants: 2,
            requiredGroups: [group],
            allowedMemberIDs: allowed,
            policy: vector.policy,
            accountRootSecret: try accountRootSecret(vector)
        )
        let opened = try crypto.open(
            sealed,
            eventID: eventID,
            inviteeID: inviteeID,
            accountKeyEpochID: accountKeyEpochID,
            minimumAllowedParticipants: 2,
            allowedMemberIDs: allowed,
            policy: vector.policy,
            accountRootSecret: try accountRootSecret(vector)
        )
        XCTAssertEqual(opened.response, .going)
        XCTAssertEqual(opened.minimumParticipants, 3)
        XCTAssertEqual(opened.requiredGroups, [group])
        XCTAssertEqual(Data(base64URLEncoded: sealed.payloadCiphertext)?.count, 4_124)
        XCTAssertEqual(Data(base64URLEncoded: sealed.userKeyWrap)?.count, 60)
        XCTAssertEqual(Data(base64URLEncoded: sealed.evaluatorKeyWrap)?.count, 157)

        let duplicateMemberGroups = [
            group,
            RSVPConditionGroup(
                id: "60000000-0000-4000-8000-000000000198",
                memberIDs: [conditionMember]
            ),
        ]
        XCTAssertThrowsError(
            try crypto.seal(
                eventID: eventID,
                inviteeID: inviteeID,
                accountKeyEpochID: accountKeyEpochID,
                revision: 100,
                response: .going,
                minimumParticipants: 3,
                minimumAllowedParticipants: 2,
                requiredGroups: duplicateMemberGroups,
                allowedMemberIDs: allowed,
                policy: vector.policy,
                accountRootSecret: try accountRootSecret(vector)
            )
        )
        XCTAssertThrowsError(
            try crypto.seal(
                eventID: eventID,
                inviteeID: inviteeID,
                accountKeyEpochID: accountKeyEpochID,
                revision: 101,
                response: .cantCommit,
                minimumParticipants: 2,
                minimumAllowedParticipants: 2,
                requiredGroups: [group],
                allowedMemberIDs: allowed,
                policy: vector.policy,
                accountRootSecret: try accountRootSecret(vector)
            )
        )

        var malformed = sealed
        malformed.revision = 0
        XCTAssertThrowsError(try crypto.envelopeHash(malformed))
    }

    private func loadFixture() throws -> InteropFixture {
        let bundle = Bundle(for: PrivateResponseInteropTests.self)
        let url = try XCTUnwrap(
            bundle.url(
                forResource: "private-response-v1-cross-platform-vectors",
                withExtension: "json"
            )
        )
        return try JSONDecoder().decode(InteropFixture.self, from: Data(contentsOf: url))
    }

    private func makePinnedEvaluator(for vector: InteropVector) throws -> PinnedEvaluator {
        let policySigning = try loadFixture().trustPins.policySigning
        return PinnedEvaluator(
            keyID: vector.policy.evaluatorKeyId,
            publicKey: try XCTUnwrap(Data(base64URLEncoded: vector.policy.evaluatorPublicKey)),
            policySigningKeyID: policySigning.keyId,
            policySigningPublicKey: try XCTUnwrap(
                Data(base64URLEncoded: policySigning.publicKey)
            )
        )
    }

    private func makeCrypto(for vector: InteropVector) throws -> PrivateResponseCrypto {
        PrivateResponseCrypto(pinnedEvaluator: try makePinnedEvaluator(for: vector))
    }

    private func allowedMemberIDs(_ vector: InteropVector) throws -> Set<UUID> {
        Set(try vector.allowedInviteeIds.map { try XCTUnwrap(UUID(uuidString: $0)) })
    }

    private func accountRootSecret(_ vector: InteropVector) throws -> SymmetricKey {
        SymmetricKey(
            data: try XCTUnwrap(Data(base64URLEncoded: vector.accountRootSecret))
        )
    }
}

final class HerdHostBusinessRuleTests: XCTestCase {
    func testRequiredAttendeeNamesUseFirstNameAndUppercaseLastInitial() {
        XCTAssertEqual(RequiredAttendeeName.shortened("Grant Bernero"), "Grant B")
        XCTAssertEqual(RequiredAttendeeName.shortened("  Ella   herdTestUser  "), "Ella H")
        XCTAssertEqual(RequiredAttendeeName.shortened("Prince"), "Prince")
        XCTAssertEqual(RequiredAttendeeName.shortened(" \n "), "Guest")
    }

    func testNewEventDefaultsChooseSaturdayAndThursdayDeadline() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!

        let tuesday = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 4, hour: 9))
        )
        let tuesdayDraft = HerdEvent.newDraft(now: tuesday, calendar: calendar)
        let tuesdayEvent = try XCTUnwrap(tuesdayDraft.eventDate)
        let tuesdayDeadline = try XCTUnwrap(tuesdayDraft.rsvpDeadline)
        XCTAssertEqual(
            calendar.dateComponents([.year, .month, .day, .hour, .minute], from: tuesdayEvent),
            DateComponents(year: 2026, month: 8, day: 8, hour: 19, minute: 0)
        )
        XCTAssertEqual(
            calendar.dateComponents([.year, .month, .day, .hour, .minute], from: tuesdayDeadline),
            DateComponents(year: 2026, month: 8, day: 6, hour: 23, minute: 59)
        )

        let wednesday = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 5, hour: 9))
        )
        let wednesdayDraft = HerdEvent.newDraft(now: wednesday, calendar: calendar)
        let wednesdayEvent = try XCTUnwrap(wednesdayDraft.eventDate)
        let wednesdayDeadline = try XCTUnwrap(wednesdayDraft.rsvpDeadline)
        XCTAssertEqual(
            calendar.dateComponents([.year, .month, .day, .hour, .minute], from: wednesdayEvent),
            DateComponents(year: 2026, month: 8, day: 15, hour: 19, minute: 0)
        )
        XCTAssertEqual(
            calendar.dateComponents([.year, .month, .day, .hour, .minute], from: wednesdayDeadline),
            DateComponents(year: 2026, month: 8, day: 13, hour: 23, minute: 59)
        )
    }

    func testLocationSuggestionsUseOnlyANonemptyProfileAddressBeforeSearch() {
        XCTAssertEqual(
            LocationSearchSuggestions.profileAddress(from: "  219 Cumberland St  "),
            "219 Cumberland St"
        )
        XCTAssertNil(LocationSearchSuggestions.profileAddress(from: " \n "))
    }

    func testLocationUnitAddressRoundTripsWithoutChangingLegacyAddresses() {
        XCTAssertEqual(
            LocationUnitAddress.combine(base: "219 Cumberland St", unit: "5"),
            "219 Cumberland St, Unit 5"
        )

        let separated = LocationUnitAddress.split(" 219 Cumberland St, Unit 5 ")
        XCTAssertEqual(separated.base, "219 Cumberland St")
        XCTAssertEqual(separated.unit, "5")

        let legacy = LocationUnitAddress.split("219 Cumberland St")
        XCTAssertEqual(legacy.base, "219 Cumberland St")
        XCTAssertEqual(legacy.unit, "")
        XCTAssertEqual(
            LocationUnitAddress.combine(base: " 219 Cumberland St ", unit: "  "),
            "219 Cumberland St"
        )
    }

    func testLocationPresentationRemovesDuplicateAddressNames() {
        XCTAssertEqual(
            EventLocationPresentation.summary(
                name: "219 Cumberland St",
                address: "219 Cumberland St",
                separator: " · "
            ),
            "219 Cumberland St"
        )
        XCTAssertEqual(
            EventLocationPresentation.summary(
                name: "219 Cumberland St",
                address: "219 Cumberland St, Unit 5",
                separator: " · "
            ),
            "219 Cumberland St, Unit 5"
        )
        XCTAssertEqual(
            EventLocationPresentation.summary(
                name: "The Conservatory",
                address: "100 John F Kennedy Dr",
                separator: " · "
            ),
            "The Conservatory · 100 John F Kennedy Dr"
        )
    }

    func testParticipantCountAlwaysIncludesTheHost() {
        var event = HerdEvent.newDraft()
        XCTAssertEqual(event.participantCount, 1)

        event.invitees = [
            Invitee(displayName: "First Guest", phoneNumber: "+1 415 555 0101"),
            Invitee(displayName: "Second Guest", phoneNumber: "+1 415 555 0102"),
        ]

        XCTAssertEqual(event.participantCount, 3)
    }

    func testResponseCountAlwaysIncludesTheAffirmativeHost() {
        var event = HerdEvent.newDraft()
        XCTAssertEqual(event.respondedParticipantCount, 1)

        event.invitees = [
            Invitee(
                displayName: "Responded Guest",
                phoneNumber: "+1 415 555 0101",
                hasResponded: true
            ),
            Invitee(
                displayName: "Waiting Guest",
                phoneNumber: "+1 415 555 0102",
                hasResponded: false
            ),
        ]

        XCTAssertEqual(event.respondedParticipantCount, 2)
    }

    func testHomeSectionsSeparateUnconfirmedAndPastEvents() throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        let eventDate = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 7, hour: 19))
        )
        let deadline = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 6, hour: 23))
        )
        let eventDay = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 7, hour: 23))
        )
        let followingDay = try XCTUnwrap(
            calendar.date(from: DateComponents(year: 2026, month: 8, day: 8, hour: 0))
        )

        var event = makeDraft(eventDate: eventDate, endDate: nil, deadline: deadline)
        event.role = .invitee
        event.invitationsSent = true
        event.resolution = EventResolution(status: .confirmed)
        XCTAssertEqual(event.homeSection(at: eventDay, calendar: calendar), .invites)
        XCTAssertEqual(event.homeSection(at: followingDay, calendar: calendar), .past)

        event.resolution = EventResolution(status: .notConfirmed)
        XCTAssertEqual(event.homeSection(at: eventDay, calendar: calendar), .unconfirmed)
        XCTAssertEqual(event.homeSection(at: followingDay, calendar: calendar), .unconfirmed)
    }

    func testManuallyAddedHerdContactsPersistAndDeduplicateByPhoneNumber() throws {
        let suiteName = "com.herd.tests.saved-contacts.\(UUID().uuidString.lowercased())"
        let defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        defer { defaults.removePersistentDomain(forName: suiteName) }

        let firstService = ContactStoreService(defaults: defaults)
        let firstContact = firstService.saveManualContact(
            ContactCandidate(
                id: "manual-contact-one",
                displayName: "Manual Guest",
                phoneNumber: "4155550199"
            )
        )

        let reloadedService = ContactStoreService(defaults: defaults)
        XCTAssertEqual(reloadedService.candidates, [firstContact])

        let updatedContact = reloadedService.saveManualContact(
            ContactCandidate(
                id: "manual-contact-two",
                displayName: "Updated Guest",
                phoneNumber: "(415) 555-0199"
            )
        )

        XCTAssertEqual(updatedContact.id, firstContact.id)
        XCTAssertEqual(updatedContact.displayName, "Updated Guest")
        XCTAssertEqual(reloadedService.candidates, [updatedContact])
        XCTAssertEqual(ContactStoreService(defaults: defaults).candidates, [updatedContact])
    }

    func testDeadlineSuggestionsAndSubmissionBoundary() throws {
        let now = Date(timeIntervalSince1970: 2_000_000_000)
        let eventDate = now.addingTimeInterval(60 * 60)
        let deadline = try XCTUnwrap(
            EventDeadlineRules.suggestedReplyDeadline(
                before: eventDate,
                now: now,
                calendar: Calendar(identifier: .gregorian)
            )
        )
        XCTAssertGreaterThan(deadline, now)
        XCTAssertLessThanOrEqual(
            deadline,
            eventDate.addingTimeInterval(-EventDeadlineRules.minimumEventSeparation)
        )
        XCTAssertFalse(
            EventDeadlineRules.canSubmit(
                deadline: now.addingTimeInterval(EventDeadlineRules.submissionSafetyInterval),
                now: now
            )
        )
        XCTAssertTrue(
            EventDeadlineRules.canSubmit(
                deadline: now.addingTimeInterval(EventDeadlineRules.submissionSafetyInterval + 1),
                now: now
            )
        )
        XCTAssertNil(
            EventDeadlineRules.suggestedReplyDeadline(
                before: now.addingTimeInterval(
                    EventDeadlineRules.suggestedLeadTime
                        + EventDeadlineRules.minimumEventSeparation - 1
                ),
                now: now
            )
        )
    }

    func testDraftAllowsOptionalEndAndRejectsExpiredDeadline() {
        let now = Date.now
        let valid = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600)
        )
        XCTAssertTrue(valid.isValid)

        let expired = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(-60)
        )
        XCTAssertTrue(
            expired.outstandingTasks.contains("Move the RSVP deadline into the future")
        )
    }

    func testRequiredPeopleAreUniqueAcrossAndOfOrRows() {
        let now = Date.now
        let first = Invitee(displayName: "First", phoneNumber: "+14155550101")
        let second = Invitee(displayName: "Second", phoneNumber: "+14155550102")
        let duplicate = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600),
            invitees: [first, second],
            requiredGroups: [
                RequiredAttendeeGroup(memberIDs: [first.id]),
                RequiredAttendeeGroup(memberIDs: [first.id, second.id]),
            ]
        )
        XCTAssertTrue(duplicate.outstandingTasks.contains("Fix the required-attendee rules"))

        let valid = makeDraft(
            eventDate: now.addingTimeInterval(7_200),
            endDate: nil,
            deadline: now.addingTimeInterval(3_600),
            invitees: [first, second],
            requiredGroups: [RequiredAttendeeGroup(memberIDs: [first.id, second.id])]
        )
        XCTAssertTrue(valid.isValid)
    }

    private func makeDraft(
        eventDate: Date,
        endDate: Date?,
        deadline: Date,
        invitees: [Invitee] = [
            Invitee(displayName: "Guest", phoneNumber: "+14155550101"),
        ],
        requiredGroups: [RequiredAttendeeGroup] = []
    ) -> HerdEvent {
        HerdEvent(
            id: UUID(),
            title: "XCTest event",
            eventDate: eventDate,
            endDate: endDate,
            hostName: "Host",
            locationName: "",
            locationAddress: "",
            invitees: invitees,
            minimumParticipants: 2,
            requiredGroups: requiredGroups,
            rsvpDeadline: deadline,
            eventDescription: "",
            createdAt: .now
        )
    }
}

final class PrivateResponseReceiptVerificationTests: XCTestCase {
    func testValidSignedReceiptAndPublishedEntryVerify() throws {
        let fixture = try makeReceiptFixture()

        XCTAssertNoThrow(try fixture.verifier.verify(fixture.receipt))
        XCTAssertNoThrow(
            try PrivateResponseReceiptPublicationVerifier.verify(
                receipt: fixture.receipt,
                publicLog: fixture.publicLog
            )
        )
    }

    func testTamperedReceiptSignatureAndCiphertextHashFail() throws {
        let fixture = try makeReceiptFixture()
        let proof = try XCTUnwrap(fixture.receipt.transparency)
        let tamperedSignature = PrivateResponseTransparencyProofV1(
            protocolVersion: proof.protocolVersion,
            logId: proof.logId,
            logIndex: proof.logIndex,
            previousEntryHash: proof.previousEntryHash,
            entryHash: proof.entryHash,
            signingKeyId: proof.signingKeyId,
            receiptSignature: try mutateBase64URL(proof.receiptSignature),
            logHead: proof.logHead
        )
        let signatureReceipt = replacingTransparency(
            in: fixture.receipt,
            with: tamperedSignature
        )
        XCTAssertThrowsError(try fixture.verifier.verify(signatureReceipt))

        let hashReceipt = PrivateResponseReceiptV1(
            envelopeId: fixture.receipt.envelopeId,
            eventId: fixture.receipt.eventId,
            inviteeId: fixture.receipt.inviteeId,
            policyHash: fixture.receipt.policyHash,
            accountKeyEpochId: fixture.receipt.accountKeyEpochId,
            revision: fixture.receipt.revision,
            ciphertextHash: Data(repeating: 0x7f, count: 32).base64URLEncodedString(),
            responseSigningPublicKey: fixture.receipt.responseSigningPublicKey,
            responseSignature: fixture.receipt.responseSignature,
            committedAt: fixture.receipt.committedAt,
            transparency: proof
        )
        XCTAssertThrowsError(try fixture.verifier.verify(hashReceipt))
    }

    func testTamperedSignedHeadFails() throws {
        let fixture = try makeReceiptFixture()
        let proof = try XCTUnwrap(fixture.receipt.transparency)
        let tamperedHead = PrivateResponseLogHeadV1(
            protocolVersion: proof.logHead.protocolVersion,
            logId: proof.logHead.logId,
            treeSize: proof.logHead.treeSize,
            headEntryHash: proof.logHead.headEntryHash,
            generatedAt: proof.logHead.generatedAt,
            signingKeyId: proof.logHead.signingKeyId,
            signature: try mutateBase64URL(proof.logHead.signature)
        )
        let tamperedProof = PrivateResponseTransparencyProofV1(
            protocolVersion: proof.protocolVersion,
            logId: proof.logId,
            logIndex: proof.logIndex,
            previousEntryHash: proof.previousEntryHash,
            entryHash: proof.entryHash,
            signingKeyId: proof.signingKeyId,
            receiptSignature: proof.receiptSignature,
            logHead: tamperedHead
        )

        XCTAssertThrowsError(
            try fixture.verifier.verify(
                replacingTransparency(in: fixture.receipt, with: tamperedProof)
            )
        )
    }

    func testForkedPublishedEntryFailsExactMatch() throws {
        let fixture = try makeReceiptFixture()
        let entry = try XCTUnwrap(fixture.publicLog.entries.first)
        let forkedEntry = PrivateResponseTransparencyLogEntryV1(
            logIndex: entry.logIndex,
            previousEntryHash: entry.previousEntryHash,
            entryHash: Data(repeating: 0x55, count: 32).base64URLEncodedString(),
            head: entry.head
        )
        let forkedLog = PrivateResponseTransparencyLogV1(
            protocolVersion: fixture.publicLog.protocolVersion,
            logId: fixture.publicLog.logId,
            entries: [forkedEntry]
        )

        XCTAssertThrowsError(
            try PrivateResponseReceiptPublicationVerifier.verify(
                receipt: fixture.receipt,
                publicLog: forkedLog
            )
        )
    }

    private func makeReceiptFixture() throws -> ReceiptFixture {
        let signingKey = P256.Signing.PrivateKey()
        let signingKeyID = "transparency-test-v1"
        let logID = "herd-response-log-test"
        let logIndex = 7
        let previousEntryHash = Data(repeating: 0x11, count: 32)
            .base64URLEncodedString()
        let envelopeID = "10000000-0000-4000-8000-000000000001"
        let eventID = "20000000-0000-4000-8000-000000000002"
        let inviteeID = "30000000-0000-4000-8000-000000000003"
        let policyHash = Data(repeating: 0x33, count: 32)
            .base64URLEncodedString()
        let accountKeyEpochID = "40000000-0000-4000-8000-000000000004"
        let revision = 4
        let ciphertextHash = Data(repeating: 0x22, count: 32)
            .base64URLEncodedString()
        let responseSigningPublicKey = Data(repeating: 0x44, count: 32)
            .base64URLEncodedString()
        let responseSignature = Data(repeating: 0x55, count: 64)
            .base64URLEncodedString()
        let committedAt = "2026-08-03T03:30:00.000Z"
        let generatedAt = "2026-08-03T03:30:01.000Z"

        let entryCore = "{" +
            "\"protocolVersion\":1," +
            "\"logId\":\(quoted(logID))," +
            "\"logIndex\":\(logIndex)," +
            "\"previousEntryHash\":\(quoted(previousEntryHash))," +
            "\"envelopeId\":\(quoted(envelopeID))," +
            "\"eventId\":\(quoted(eventID))," +
            "\"inviteeId\":\(quoted(inviteeID))," +
            "\"policyHash\":\(quoted(policyHash))," +
            "\"accountKeyEpochId\":\(quoted(accountKeyEpochID))," +
            "\"revision\":\(revision)," +
            "\"ciphertextHash\":\(quoted(ciphertextHash))," +
            "\"responseSigningPublicKey\":\(quoted(responseSigningPublicKey))," +
            "\"responseSignature\":\(quoted(responseSignature))," +
            "\"committedAt\":\(quoted(committedAt))}"
        let entryHash = Data(
            SHA256.hash(
                data: domainSeparated(
                    "HERD-TRANSPARENCY-LOG-ENTRY-HASH-V1",
                    entryCore
                )
            )
        ).base64URLEncodedString()
        let receiptPayload = "{" +
            "\"protocolVersion\":1," +
            "\"logId\":\(quoted(logID))," +
            "\"logIndex\":\(logIndex)," +
            "\"previousEntryHash\":\(quoted(previousEntryHash))," +
            "\"entryHash\":\(quoted(entryHash))," +
            "\"envelopeId\":\(quoted(envelopeID))," +
            "\"eventId\":\(quoted(eventID))," +
            "\"inviteeId\":\(quoted(inviteeID))," +
            "\"policyHash\":\(quoted(policyHash))," +
            "\"accountKeyEpochId\":\(quoted(accountKeyEpochID))," +
            "\"revision\":\(revision)," +
            "\"ciphertextHash\":\(quoted(ciphertextHash))," +
            "\"responseSigningPublicKey\":\(quoted(responseSigningPublicKey))," +
            "\"responseSignature\":\(quoted(responseSignature))," +
            "\"committedAt\":\(quoted(committedAt))," +
            "\"signingKeyId\":\(quoted(signingKeyID))}"
        let receiptSignature = try signingKey.signature(
            for: domainSeparated(
                "HERD-TRANSPARENCY-RECEIPT-SIGNATURE-V1",
                receiptPayload
            )
        ).rawRepresentation.base64URLEncodedString()
        let headPayload = "{" +
            "\"protocolVersion\":1," +
            "\"logId\":\(quoted(logID))," +
            "\"treeSize\":\(logIndex)," +
            "\"headEntryHash\":\(quoted(entryHash))," +
            "\"generatedAt\":\(quoted(generatedAt))," +
            "\"signingKeyId\":\(quoted(signingKeyID))}"
        let headSignature = try signingKey.signature(
            for: domainSeparated(
                "HERD-TRANSPARENCY-LOG-HEAD-SIGNATURE-V1",
                headPayload
            )
        ).rawRepresentation.base64URLEncodedString()
        let head = PrivateResponseLogHeadV1(
            protocolVersion: 1,
            logId: logID,
            treeSize: logIndex,
            headEntryHash: entryHash,
            generatedAt: generatedAt,
            signingKeyId: signingKeyID,
            signature: headSignature
        )
        let proof = PrivateResponseTransparencyProofV1(
            protocolVersion: 1,
            logId: logID,
            logIndex: logIndex,
            previousEntryHash: previousEntryHash,
            entryHash: entryHash,
            signingKeyId: signingKeyID,
            receiptSignature: receiptSignature,
            logHead: head
        )
        let receipt = PrivateResponseReceiptV1(
            envelopeId: envelopeID,
            eventId: eventID,
            inviteeId: inviteeID,
            policyHash: policyHash,
            accountKeyEpochId: accountKeyEpochID,
            revision: revision,
            ciphertextHash: ciphertextHash,
            responseSigningPublicKey: responseSigningPublicKey,
            responseSignature: responseSignature,
            committedAt: committedAt,
            transparency: proof
        )
        let publicLog = PrivateResponseTransparencyLogV1(
            protocolVersion: 1,
            logId: logID,
            entries: [
                PrivateResponseTransparencyLogEntryV1(
                    logIndex: logIndex,
                    previousEntryHash: previousEntryHash,
                    entryHash: entryHash,
                    head: head
                ),
            ]
        )
        return ReceiptFixture(
            receipt: receipt,
            publicLog: publicLog,
            verifier: PrivateResponseReceiptVerifier(
                signingKeyID: signingKeyID,
                signingPublicKey: signingKey.publicKey.x963Representation
            )
        )
    }

    private func replacingTransparency(
        in receipt: PrivateResponseReceiptV1,
        with proof: PrivateResponseTransparencyProofV1
    ) -> PrivateResponseReceiptV1 {
        PrivateResponseReceiptV1(
            envelopeId: receipt.envelopeId,
            eventId: receipt.eventId,
            inviteeId: receipt.inviteeId,
            policyHash: receipt.policyHash,
            accountKeyEpochId: receipt.accountKeyEpochId,
            revision: receipt.revision,
            ciphertextHash: receipt.ciphertextHash,
            responseSigningPublicKey: receipt.responseSigningPublicKey,
            responseSignature: receipt.responseSignature,
            committedAt: receipt.committedAt,
            transparency: proof
        )
    }

    private func domainSeparated(_ domain: String, _ payload: String) -> Data {
        Data(domain.utf8) + Data([0]) + Data(payload.utf8)
    }

    private func quoted(_ value: String) -> String {
        String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
    }

    private func mutateBase64URL(_ value: String) throws -> String {
        var data = try XCTUnwrap(Data(base64URLEncoded: value))
        data[data.startIndex] ^= 0x01
        return data.base64URLEncodedString()
    }
}

private struct ReceiptFixture {
    let receipt: PrivateResponseReceiptV1
    let publicLog: PrivateResponseTransparencyLogV1
    let verifier: PrivateResponseReceiptVerifier
}

final class EvaluatorAttestationVerificationTests: XCTestCase {
    func testValidPinnedCertificateAndSignedJWTVerify() throws {
        let fixture = try makeAttestationFixture()

        XCTAssertNoThrow(
            try fixture.verifier.verify(
                fixture.response,
                nonce: fixture.nonce,
                policy: fixture.policy,
                now: fixture.now
            )
        )
    }

    func testSecondRolloutImageDigestVerifies() throws {
        let rolloutDigest = "sha256:" + String(repeating: "c", count: 64)
        let fixture = try makeAttestationFixture(
            allowedImageDigests: [Self.imageDigest, rolloutDigest],
            attestedImageDigest: rolloutDigest
        )

        XCTAssertNoThrow(
            try fixture.verifier.verify(
                fixture.response,
                nonce: fixture.nonce,
                policy: fixture.policy,
                now: fixture.now
            )
        )
    }

    func testOmittedEmptyContainerOverridesVerify() throws {
        let fixture = try makeAttestationFixture()
        var claims = fixture.validClaims
        var submods = claims["submods"] as! [String: Any]
        var container = submods["container"] as! [String: Any]
        container.removeValue(forKey: "env_override")
        container.removeValue(forKey: "cmd_override")
        submods["container"] = container
        claims["submods"] = submods
        let response = EvaluatorAttestationResponse(
            protocolVersion: fixture.response.protocolVersion,
            tokenType: fixture.response.tokenType,
            audience: fixture.response.audience,
            nonce: fixture.response.nonce,
            keyBinding: fixture.response.keyBinding,
            keyBindingHash: fixture.response.keyBindingHash,
            attestationToken: try signedToken(claims: claims)
        )

        XCTAssertNoThrow(
            try fixture.verifier.verify(
                response,
                nonce: fixture.nonce,
                policy: fixture.policy,
                now: fixture.now
            )
        )
    }

    func testSignedAdversarialAttestationClaimsFailClosed() throws {
        let fixture = try makeAttestationFixture()

        try assertRejected(fixture, caseName: "restart policy") { claims in
            self.setContainerClaim("restart_policy", to: "Never", in: &claims)
        }
        try assertRejected(fixture, caseName: "nonce") { claims in
            claims["eat_nonce"] = ["wrong-nonce", fixture.response.keyBindingHash]
        }
        try assertRejected(fixture, caseName: "image") { claims in
            self.setContainerClaim(
                "image_digest",
                to: "sha256:" + String(repeating: "b", count: 64),
                in: &claims
            )
        }
        try assertRejected(fixture, caseName: "service account") { claims in
            claims["google_service_accounts"] = [
                "attacker@herd-native-attestation-test.iam.gserviceaccount.com",
            ]
        }
        try assertRejected(fixture, caseName: "debug state") { claims in
            claims["dbgstat"] = "enabled"
        }
        try assertRejected(fixture, caseName: "fractional OEM ID") { claims in
            claims["oemid"] = 11_129.5
        }
        try assertRejected(fixture, caseName: "extra attester TCB") { claims in
            claims["attester_tcb"] = ["INTEL", "UNREVIEWED"]
        }
        try assertRejected(fixture, caseName: "wrong command override shape") { claims in
            self.setContainerClaim("cmd_override", to: [String: String](), in: &claims)
        }
        try assertRejected(fixture, caseName: "non-empty command override") { claims in
            self.setContainerClaim("cmd_override", to: ["override"], in: &claims)
        }
        try assertRejected(fixture, caseName: "wrong environment override shape") { claims in
            self.setContainerClaim("env_override", to: [String](), in: &claims)
        }
        try assertRejected(fixture, caseName: "non-empty environment override") { claims in
            self.setContainerClaim("env_override", to: ["SECRET": "override"], in: &claims)
        }
        try assertRejected(fixture, caseName: "extra monitoring mode") { claims in
            self.setConfidentialSpaceClaim(
                "monitoring_enabled",
                to: ["memory": false, "disk": true],
                in: &claims
            )
        }
        try assertRejected(fixture, caseName: "expiry") { claims in
            let now = Int(fixture.now.timeIntervalSince1970)
            claims["iat"] = now - 600
            claims["nbf"] = now - 600
            claims["exp"] = now - 60
        }
        try assertRejected(fixture, caseName: "expiry before issuance") { claims in
            claims["exp"] = claims["iat"]
        }
        try assertRejected(fixture, caseName: "fractional issued-at") { claims in
            claims["iat"] = fixture.now.timeIntervalSince1970 - 0.5
        }
        try assertRejected(fixture, caseName: "JWT key binding") { claims in
            claims["eat_nonce"] = [
                fixture.nonce,
                Data(repeating: 0x5a, count: 32).base64URLEncodedString(),
            ]
        }

        let binding = fixture.response.keyBinding
        let alteredKeys = EvaluatorKeySet(
            responseDecryption: binding.keys.responseDecryption,
            evaluationResultSigning: binding.keys.evaluationResultSigning,
            policySigning: binding.keys.policySigning,
            transparencySigning: EvaluatorKeyMetadata(
                keyId: "transparency-attacker-v1",
                algorithm: binding.keys.transparencySigning.algorithm,
                publicKey: binding.keys.transparencySigning.publicKey
            )
        )
        let alteredBinding = EvaluatorKeyBinding(
            protocolVersion: binding.protocolVersion,
            releaseId: binding.releaseId,
            keys: alteredKeys
        )
        let alteredResponse = EvaluatorAttestationResponse(
            protocolVersion: fixture.response.protocolVersion,
            tokenType: fixture.response.tokenType,
            audience: fixture.response.audience,
            nonce: fixture.response.nonce,
            keyBinding: alteredBinding,
            keyBindingHash: fixture.response.keyBindingHash,
            attestationToken: fixture.response.attestationToken
        )
        XCTAssertThrowsError(
            try fixture.verifier.verify(
                alteredResponse,
                nonce: fixture.nonce,
                policy: fixture.policy,
                now: fixture.now
            ),
            "response key binding"
        )
    }

    private func makeAttestationFixture(
        allowedImageDigests: Set<String>? = nil,
        attestedImageDigest: String? = nil
    ) throws -> NativeAttestationFixture {
        let acceptedDigests = allowedImageDigests ?? [Self.imageDigest]
        let claimedDigest = attestedImageDigest ?? Self.imageDigest
        let rootCertificate = try XCTUnwrap(
            Data(base64Encoded: Self.rootCertificateBase64)
        )
        let binding = EvaluatorKeyBinding(
            protocolVersion: PrivateResponseProtocol.version,
            releaseId: Self.releaseID,
            keys: EvaluatorKeySet(
                responseDecryption: EvaluatorKeyMetadata(
                    keyId: "response-decryption-test-v1",
                    algorithm: "ECDH_P256",
                    publicKey: P256.KeyAgreement.PrivateKey().publicKey
                        .x963Representation.base64URLEncodedString()
                ),
                evaluationResultSigning: EvaluatorKeyMetadata(
                    keyId: "result-signing-test-v1",
                    algorithm: "ECDSA_P256_SHA256",
                    publicKey: P256.Signing.PrivateKey().publicKey
                        .x963Representation.base64URLEncodedString()
                ),
                policySigning: EvaluatorKeyMetadata(
                    keyId: "policy-signing-test-v1",
                    algorithm: "ECDSA_P256_SHA256",
                    publicKey: P256.Signing.PrivateKey().publicKey
                        .x963Representation.base64URLEncodedString()
                ),
                transparencySigning: EvaluatorKeyMetadata(
                    keyId: "transparency-signing-test-v1",
                    algorithm: "ECDSA_P256_SHA256",
                    publicKey: P256.Signing.PrivateKey().publicKey
                        .x963Representation.base64URLEncodedString()
                )
            )
        )
        let bindingHash = Data(
            SHA256.hash(
                data: Data("HERD-CONFIDENTIAL-EVALUATOR-KEY-BINDING-V1".utf8)
                    + Data([0])
                    + Data(binding.canonicalJSON.utf8)
            )
        ).base64URLEncodedString()
        let nonce = Data(repeating: 0x34, count: 32).base64URLEncodedString()
        let now = Date(timeIntervalSince1970: 1_785_727_800)
        let verifier = EvaluatorAttestationVerifier(
            audience: Self.audience,
            projectID: Self.projectID,
            serviceAccount: Self.serviceAccount,
            imageDigest: Self.imageDigest,
            allowedImageDigests: acceptedDigests,
            policyMeasurement: Self.policyMeasurement,
            rootCertificate: rootCertificate,
            rootFingerprint: sha256Hex(rootCertificate),
            allowedSWVersions: [Self.swVersion],
            maximumAge: 300,
            keyBinding: binding
        )
        let policy = PrivateResponsePolicyV1(
            protocolVersion: PrivateResponseProtocol.version,
            cipherSuite: PrivateResponseProtocol.cipherSuite,
            policyHash: Data(repeating: 0x45, count: 32).base64URLEncodedString(),
            canonicalDocument: "{}",
            evaluatorKeyId: binding.keys.responseDecryption.keyId,
            evaluatorPublicKey: binding.keys.responseDecryption.publicKey,
            evaluatorMeasurement: Self.policyMeasurement,
            releaseId: Self.releaseID,
            paddedPlaintextBytes: PrivateResponseProtocol.paddedPlaintextBytes,
            frozenAt: "2026-08-03T03:25:00.000Z",
            policySigningKeyId: nil,
            policySignature: nil
        )
        var claims = validClaims(
            now: now,
            nonce: nonce,
            keyBindingHash: bindingHash
        )
        setContainerClaim("image_digest", to: claimedDigest, in: &claims)
        let response = EvaluatorAttestationResponse(
            protocolVersion: PrivateResponseProtocol.version,
            tokenType: "google-pki",
            audience: Self.audience,
            nonce: nonce,
            keyBinding: binding,
            keyBindingHash: bindingHash,
            attestationToken: try signedToken(claims: claims)
        )
        return NativeAttestationFixture(
            verifier: verifier,
            response: response,
            policy: policy,
            nonce: nonce,
            now: now,
            validClaims: claims
        )
    }

    private func assertRejected(
        _ fixture: NativeAttestationFixture,
        caseName: String,
        file: StaticString = #filePath,
        line: UInt = #line,
        mutate: (inout [String: Any]) -> Void
    ) throws {
        var claims = fixture.validClaims
        mutate(&claims)
        let response = EvaluatorAttestationResponse(
            protocolVersion: fixture.response.protocolVersion,
            tokenType: fixture.response.tokenType,
            audience: fixture.response.audience,
            nonce: fixture.response.nonce,
            keyBinding: fixture.response.keyBinding,
            keyBindingHash: fixture.response.keyBindingHash,
            attestationToken: try signedToken(claims: claims)
        )

        XCTAssertThrowsError(
            try fixture.verifier.verify(
                response,
                nonce: fixture.nonce,
                policy: fixture.policy,
                now: fixture.now
            ),
            caseName,
            file: file,
            line: line
        )
    }

    private func validClaims(
        now: Date,
        nonce: String,
        keyBindingHash: String
    ) -> [String: Any] {
        let timestamp = Int(now.timeIntervalSince1970)
        return [
            "iss": "https://confidentialcomputing.googleapis.com",
            "aud": Self.audience,
            "iat": timestamp,
            "nbf": timestamp - 1,
            "exp": timestamp + 300,
            "eat_nonce": [nonce, keyBindingHash],
            "secboot": true,
            "dbgstat": "disabled-since-boot",
            "hwmodel": "GCP_INTEL_TDX",
            "swname": "CONFIDENTIAL_SPACE",
            "oemid": 11_129,
            "attester_tcb": ["INTEL"],
            "swversion": [Self.swVersion],
            "google_service_accounts": [Self.serviceAccount],
            "submods": [
                "gce": ["project_id": Self.projectID],
                "container": [
                    "image_digest": Self.imageDigest,
                    "restart_policy": "Always",
                    "env_override": [String: String](),
                    "cmd_override": [String](),
                ] as [String: Any],
                "confidential_space": [
                    "support_attributes": ["USABLE", "STABLE"],
                    "monitoring_enabled": ["memory": false],
                ] as [String: Any],
            ] as [String: Any],
        ]
    }

    private func setContainerClaim(
        _ name: String,
        to value: Any,
        in claims: inout [String: Any]
    ) {
        var submods = claims["submods"] as! [String: Any]
        var container = submods["container"] as! [String: Any]
        container[name] = value
        submods["container"] = container
        claims["submods"] = submods
    }

    private func setConfidentialSpaceClaim(
        _ name: String,
        to value: Any,
        in claims: inout [String: Any]
    ) {
        var submods = claims["submods"] as! [String: Any]
        var confidentialSpace = submods["confidential_space"] as! [String: Any]
        confidentialSpace[name] = value
        submods["confidential_space"] = confidentialSpace
        claims["submods"] = submods
    }

    private func signedToken(claims: [String: Any]) throws -> String {
        let header: [String: Any] = [
            "alg": "RS256",
            "typ": "JWT",
            "x5c": [Self.leafCertificateBase64],
        ]
        let headerData = try JSONSerialization.data(
            withJSONObject: header,
            options: [.sortedKeys]
        )
        let claimsData = try JSONSerialization.data(
            withJSONObject: claims,
            options: [.sortedKeys]
        )
        let headerSegment = headerData.base64URLEncodedString()
        let claimsSegment = claimsData.base64URLEncodedString()
        let signingInput = Data("\(headerSegment).\(claimsSegment)".utf8)
        let keyData = try XCTUnwrap(Data(base64Encoded: Self.leafPrivateKeyBase64))
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits: 2_048,
        ]
        var keyError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateWithData(
            keyData as CFData,
            attributes as CFDictionary,
            &keyError
        ) else {
            throw keyError?.takeRetainedValue()
                ?? NSError(domain: "HerdHostTests.Attestation", code: 1)
        }
        var signatureError: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .rsaSignatureMessagePKCS1v15SHA256,
            signingInput as CFData,
            &signatureError
        ) as Data? else {
            throw signatureError?.takeRetainedValue()
                ?? NSError(domain: "HerdHostTests.Attestation", code: 2)
        }
        return "\(headerSegment).\(claimsSegment).\(signature.base64URLEncodedString())"
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static let audience = "https://herd.test/attestation"
    private static let projectID = "herd-native-attestation-test"
    private static let serviceAccount =
        "evaluator@herd-native-attestation-test.iam.gserviceaccount.com"
    private static let imageDigest = "sha256:" + String(repeating: "a", count: 64)
    private static let policyMeasurement = "sha256:" + String(repeating: "c", count: 64)
    private static let releaseID = "native-attestation-release-v1"
    private static let swVersion = "260600"
    private static let rootCertificateBase64 = "MIIDTDCCAjSgAwIBAgIUcd5Yea49u193cR+/IHNtkiQir+IwDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UEAwwhSGVyZCBOYXRpdmUgQXR0ZXN0YXRpb24gVGVzdCBSb290MB4XDTI2MDgwMzAzMjIxMloXDTM2MDczMTAzMjIxMlowLDEqMCgGA1UEAwwhSGVyZCBOYXRpdmUgQXR0ZXN0YXRpb24gVGVzdCBSb290MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1bGMHfS1ySQDbfZUXq6ln3yLQNC+DLe1DRcyRySlJ0hWVv7Riqk+hBm521LggAdvZfL6yRccHfGLgQVoO3T3jdEpp1eKApuE4cD8LpBLWynWU7RE9KSvfbPjLQkNBbNvW7klJcnA2i8pCMBTPSWqpm5uCb55TuOtuxsomKOpcHGic93ZcRnTX5ecDElFsSWQRdpQ4T2BE+yRk4rcTjq1+LazRxuAXcjCaGLV+K7rnV/wrAAalzHingj1IPKD8t4kIomhXv/GeFD1mpMhgqwX/oz/2Ibucndo1Eg+P4o/6n1Ox5l8quJf7obYkZW/aqDyCkCrgIHR+8RXuCkxtDyt9wIDAQABo2YwZDAdBgNVHQ4EFgQU8DRivfOyjL0ZgpVyqs5pOWVdc4kwHwYDVR0jBBgwFoAU8DRivfOyjL0ZgpVyqs5pOWVdc4kwEgYDVR0TAQH/BAgwBgEB/wIBATAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQELBQADggEBAJyKFcehF41sDrpwnKXAX3GLAljemm2F8B7lBuP0Wt9qpcD/Fzj+a9jVKQWmqQlptqzSGiqbl8z2YAQBzP00AX7IGTMKRkWRKFiZLndTtpynPhmJBVzAhUUw2V4R3OsE4ICMuzhtcjNYXV3129sVrRq1ojN0crWIwzIFHAWRQVd6aGSEHrI+B95YbGKxinmzOPRVuadlcwfx0ZuOTQ8ME1toVkAtC1Qixx1cpFJvS3SepNFciMyDxM+r0xEnUY5Rndqp+WzVL8uKS9xo7nmJOcP3y8FdWKRUS7YGoMLyGvCM/4MnCsurotvkGVNIgpn1zrKB1MQ5t0j+y5uP14bqa4k="
    private static let leafCertificateBase64 = "MIIDKDCCAhCgAwIBAgIUayIzsu3atjZDY/YjkZ/KTYzdYv4wDQYJKoZIhvcNAQELBQAwLDEqMCgGA1UEAwwhSGVyZCBOYXRpdmUgQXR0ZXN0YXRpb24gVGVzdCBSb290MB4XDTI2MDgwMzAzMjIyMFoXDTM2MDczMTAzMjIyMFowLDEqMCgGA1UEAwwhSGVyZCBOYXRpdmUgQXR0ZXN0YXRpb24gVGVzdCBMZWFmMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAniSni8FBxPp5mA2KwUg9LEGufAL7ppy/fn4hYQFqORfMTwDdJ0y18bn0W7/d8PDTxxXlCpr0EgYBu1U30jgiOKpPIVUZNxKUWDKDUFHAfMQKzcQayB0WS0NI8PZJSmmxliZmZgsM9R/TiYWUlBggrvVJ4bWtfa5WHMbJmbBTsB9YRSi6wLJb1IoLAQ88uM8e/M79qHeI6SrCHmRnrZsWzHJwHbLyuvLmDvUs2c2P1fLn7Elrr0ONJvA87080vvmjVg8aoFuteqpl+2LTw32HPHaw284QkImjeJ6jUKkTTzsCJOla14KhGsJfzrOev4Wz9YL+sC0eqFyqIow9kbkuuwIDAQABo0IwQDAdBgNVHQ4EFgQU/N2ZcTsaHMyn6KAAU0tbvlJZXnwwHwYDVR0jBBgwFoAU8DRivfOyjL0ZgpVyqs5pOWVdc4kwDQYJKoZIhvcNAQELBQADggEBAJk3P2S6QYj7YBU5er8IpoA8oID10/3/uzdmNhIO+fMWhou62SDcFo7Firgvih4RPlgfZ0X5RT4QQ8A6uWCj3mzYRtNxeQPDF+WP2kLGD/SZggkxlNazBj/xaZ2IPJgKx3vnjEebu1WjBKYR5pZiGGyWwlmkf7dNhGPH5XezrQeD/K6oSw05qYpf7uViuHs7JxE+WTmrFCgmo2EMuKRsgkdWVa6evKXTdQ9uH7GIxnikycowOT/9ULgxv1ARPn3vkizOBJ55cGWBv2rEaMkgCTxNEhri7sF44cQAkmHWXDKY8IlW7Y05iSN98NP5rC/0s42zVO5KPozIhAdd9++r0CQ="
    private static let leafPrivateKeyBase64 = "MIIEogIBAAKCAQEAniSni8FBxPp5mA2KwUg9LEGufAL7ppy/fn4hYQFqORfMTwDdJ0y18bn0W7/d8PDTxxXlCpr0EgYBu1U30jgiOKpPIVUZNxKUWDKDUFHAfMQKzcQayB0WS0NI8PZJSmmxliZmZgsM9R/TiYWUlBggrvVJ4bWtfa5WHMbJmbBTsB9YRSi6wLJb1IoLAQ88uM8e/M79qHeI6SrCHmRnrZsWzHJwHbLyuvLmDvUs2c2P1fLn7Elrr0ONJvA87080vvmjVg8aoFuteqpl+2LTw32HPHaw284QkImjeJ6jUKkTTzsCJOla14KhGsJfzrOev4Wz9YL+sC0eqFyqIow9kbkuuwIDAQABAoIBADGMAGZb7TQ+2ZvXGlMGRAw6o+U8tgV0dNa3w9N1swciOqPB/IgUk6ihfzrDuVCE04U7ieAxvihrc11zDKMzbR1d1p7134mOq6WaZePjSTCN52iieVWbL2HzOcYtE7dZuAb4DvsHmU6vYwJiNLPVf1/xf+1Uk3+eAGLRsVYSlZXHLiuoeiaRJCSdzkG3DENiHLcfo2tWaRim1KLUkDiFI7Kbt2tpC6P1NznfHj26c5GSjyoso+tE4RAsAkRmYvpESyVZyMozO97Vh/YVPy7omKVN5WO/jLLqgECE1OkpCb1aClGeG7IS8zXZQ2ZAnao0xsWe7+3GwOr3nJ83x1CjI4ECgYEAzqQgNXjsuxrG2JlvRGW4LNKuHCEUlzmaxnZh3DZ0g2JUYrtbS9leJYErbH+MFupd04yDvLcWGG7RVwIwZQ16t8DXT4TAtFbSMmX5zDXqKdIkbnaWdMhInfZcLnOv9coq6XGv0/Bp35+gDgvWyattdBww+Fdua3L61SAOTneFWcECgYEAw+rvFr2pyn7dlIgmP29mMIzX807ihWC3ptrgNUAAXAk2hq5glzJcftXY6SYemKzeN/XZSBY6MZ4DKhhAJTOOSa5qhdmJ3djoj8zAf/O2zcNotIEoffdRM9nk7j/H0bLY3lfH8SaGRNGRJFjmLyXLHJ9i78icAZJcI7Ibgc4Uz3sCgYAErQwZian5tepn/ljZOGAJi57q/gikP2Z0NTuTqxvJ2VDFhy3SspGB0cF0zBIUdqs23Ugh3ha+6MsN5/vGXZ64R8HXh86AhjJtd4dGirXIynuOkFppPBsAkBGX74A81J1R+QOcjSUoLUmG59etapaoePbWt8vE3K42YmpQdj3rQQKBgCe5MtEBk7OjFXpQQLEL/URKyl5i2DsC6TnDl0I0v93pYEzefmcppudwpJJhUELUihn+lxeuqg31Y97dG+RvF6KI4sBQ40s/96dwdHd9Csudm1U9+t/PjX9d5rUH6ZPzF1W9pqSWkxLRCwS7obBdkVk0V/MWUctfyZ7TNhCToFSRAoGAIiQOn/M+781DzN8CeBB9usXzAc/dohWAoDuJWB+814t0cTWCt5tFwExrN8jBKIiuzLFDFdF8V0E35sxdQyRMqW/yQ8tLZxNFnXHt2oKSDXFD07b/NSntfjO5zIrzxUNUBAzE9LCJmB/3lohP6rusmmqoGiAtPh8b1IzvwnZW9eg="
}

final class EventResolutionProofTests: XCTestCase {
    func testSimpleBallotResultIsAcceptedWithoutLegacyEvaluatorProof() throws {
        let inviteeID = UUID(uuidString: "20000000-0000-4000-8000-000000000002")!
        let deadline = Date(timeIntervalSince1970: 1_800_000_000)
        let resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: ["host", inviteeID.uuidString.lowercased()],
            attendanceRevealed: true,
            resolvedAt: deadline.addingTimeInterval(-60)
        )
        let event = HerdEvent(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000002")!,
            title: "Simple result fixture",
            eventDate: deadline.addingTimeInterval(3_600),
            endDate: nil,
            hostName: "Host",
            locationName: "Test",
            locationAddress: "",
            invitees: [Invitee(id: inviteeID, displayName: "Invitee", phoneNumber: "+14155550102")],
            minimumParticipants: 2,
            requiredGroups: [],
            rsvpDeadline: deadline,
            eventDescription: "",
            createdAt: deadline.addingTimeInterval(-3_600),
            invitationsSent: true,
            privateResponsePolicy: nil,
            resolution: resolution
        )

        XCTAssertEqual(EventResolutionVerifier.failClosed(event).resolution?.status, .confirmed)
    }

    func testSimpleBallotResultRejectsUnknownAttendeeWithoutLegacyEvaluatorProof() throws {
        let deadline = Date(timeIntervalSince1970: 1_800_000_000)
        let resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: ["host", UUID().uuidString.lowercased()],
            attendanceRevealed: true,
            resolvedAt: deadline.addingTimeInterval(-60)
        )
        let event = HerdEvent(
            id: UUID(uuidString: "10000000-0000-4000-8000-000000000003")!,
            title: "Invalid simple result fixture",
            eventDate: deadline.addingTimeInterval(3_600),
            endDate: nil,
            hostName: "Host",
            locationName: "Test",
            locationAddress: "",
            invitees: [],
            minimumParticipants: 2,
            requiredGroups: [],
            rsvpDeadline: deadline,
            eventDescription: "",
            createdAt: deadline.addingTimeInterval(-3_600),
            invitationsSent: true,
            privateResponsePolicy: nil,
            resolution: resolution
        )

        XCTAssertEqual(
            EventResolutionVerifier.failClosed(event).resolution?.status,
            .verificationUnavailable
        )
    }

    func testExactSignedResultIsAcceptedAndEveryMutableProjectionIsBound() throws {
        let fixture = try makeFixture()
        try fixture.verifier.verify(fixture.resolution, for: fixture.event)
        XCTAssertEqual(
            fixture.verifier.failClosed(fixture.event).resolution?.status,
            .confirmed
        )

        var missingProof = fixture.event
        missingProof.resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: fixture.resolution.attendingMemberIds,
            resolvedAt: fixture.resolution.resolvedAt
        )
        XCTAssertEqual(
            fixture.verifier.failClosed(missingProof).resolution?.status,
            .verificationUnavailable
        )

        var changedAttendees = fixture.event
        changedAttendees.resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: ["host"],
            resolvedAt: fixture.resolution.resolvedAt,
            attestation: fixture.resolution.attestation
        )
        XCTAssertEqual(
            fixture.verifier.failClosed(changedAttendees).resolution?.status,
            .verificationUnavailable
        )

        var changedStatus = fixture.event
        changedStatus.resolution = EventResolution(
            status: .notConfirmed,
            resolvedAt: fixture.resolution.resolvedAt,
            attestation: fixture.resolution.attestation
        )
        XCTAssertEqual(
            fixture.verifier.failClosed(changedStatus).resolution?.status,
            .verificationUnavailable
        )

        var changedTime = fixture.event
        changedTime.resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: fixture.resolution.attendingMemberIds,
            resolvedAt: try XCTUnwrap(fixture.resolution.resolvedAt).addingTimeInterval(1),
            attestation: fixture.resolution.attestation
        )
        XCTAssertEqual(
            fixture.verifier.failClosed(changedTime).resolution?.status,
            .verificationUnavailable
        )

        let proof = try XCTUnwrap(fixture.resolution.attestation)
        var signature = try XCTUnwrap(Data(base64URLEncoded: proof.signature))
        signature[signature.startIndex] ^= 0x01
        var changedSignature = fixture.event
        changedSignature.resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: fixture.resolution.attendingMemberIds,
            resolvedAt: fixture.resolution.resolvedAt,
            attestation: EvaluationResultAttestationV1(
                protocolVersion: proof.protocolVersion,
                signingKeyId: proof.signingKeyId,
                evaluatedAt: proof.evaluatedAt,
                canonicalDocument: proof.canonicalDocument,
                signature: signature.base64URLEncodedString()
            )
        )
        XCTAssertEqual(
            fixture.verifier.failClosed(changedSignature).resolution?.status,
            .verificationUnavailable
        )
    }

    func testHistoricalResultSignedByAnotherReleaseKeyFailsClosed() throws {
        let fixture = try makeFixture()
        let rotatedKey = P256.Signing.PrivateKey()
        let rotatedVerifier = EventResolutionVerifier(
            signingKeyID: fixture.verifier.signingKeyID,
            signingPublicKey: rotatedKey.publicKey.x963Representation
        )
        XCTAssertEqual(
            rotatedVerifier.failClosed(fixture.event).resolution?.status,
            .verificationUnavailable
        )
    }

    private func makeFixture() throws -> (
        verifier: EventResolutionVerifier,
        event: HerdEvent,
        resolution: EventResolution
    ) {
        let signingKey = P256.Signing.PrivateKey()
        let signingKeyID = "native-result-signing-2026"
        let verifier = EventResolutionVerifier(
            signingKeyID: signingKeyID,
            signingPublicKey: signingKey.publicKey.x963Representation
        )
        let eventID = UUID(uuidString: "10000000-0000-4000-8000-000000000001")!
        let inviteeID = UUID(uuidString: "20000000-0000-4000-8000-000000000001")!
        let evaluatedAtValue = "2026-08-03T20:00:00.000Z"
        let deadlineValue = "2026-08-03T19:59:00.000Z"
        let evaluatedAt = try date(evaluatedAtValue)
        let deadline = try date(deadlineValue)
        let policyHash = Data(repeating: 0x21, count: 32).base64URLEncodedString()
        let batchHash = Data(repeating: 0x42, count: 32).base64URLEncodedString()
        let relayRequestHash = Data(repeating: 0x63, count: 32).base64URLEncodedString()
        let evaluatorKeyID = "native-evaluator-encryption-2026"
        let attendees = ["host", inviteeID.uuidString.lowercased()]
        let canonicalDocument = "{" +
            "\"protocolVersion\":1," +
            "\"signingKeyId\":\(quoted(signingKeyID))," +
            "\"relayRequestHash\":\(quoted(relayRequestHash))," +
            "\"relayRequestId\":\(quoted("30000000-0000-4000-8000-000000000001"))," +
            "\"leaseId\":\(quoted("40000000-0000-4000-8000-000000000001"))," +
            "\"evaluatedAt\":\(quoted(evaluatedAtValue))," +
            "\"result\":{" +
            "\"protocolVersion\":1," +
            "\"eventId\":\(quoted(eventID.uuidString.lowercased()))," +
            "\"policyHash\":\(quoted(policyHash))," +
            "\"batchHash\":\(quoted(batchHash))," +
            "\"evaluatorKeyId\":\(quoted(evaluatorKeyID))," +
            "\"status\":\"confirmed\"," +
            "\"attendingMemberIds\":[\(attendees.map(quoted).joined(separator: ","))]}}"
        let signature = try signingKey.signature(
            for: Data(canonicalDocument.utf8)
        ).rawRepresentation.base64URLEncodedString()
        let policy = PrivateResponsePolicyV1(
            protocolVersion: 1,
            cipherSuite: PrivateResponseProtocol.cipherSuite,
            policyHash: policyHash,
            canonicalDocument: "{}",
            evaluatorKeyId: evaluatorKeyID,
            evaluatorPublicKey: signingKey.publicKey.x963Representation.base64URLEncodedString(),
            evaluatorMeasurement: "sha256:test",
            releaseId: "native-release-2026",
            paddedPlaintextBytes: PrivateResponseProtocol.paddedPlaintextBytes,
            frozenAt: deadlineValue,
            policySigningKeyId: nil,
            policySignature: nil
        )
        let resolution = EventResolution(
            status: .confirmed,
            attendingMemberIds: attendees,
            resolvedAt: evaluatedAt,
            attestation: EvaluationResultAttestationV1(
                protocolVersion: 1,
                signingKeyId: signingKeyID,
                evaluatedAt: evaluatedAtValue,
                canonicalDocument: canonicalDocument,
                signature: signature
            )
        )
        let event = HerdEvent(
            id: eventID,
            title: "Signed result fixture",
            eventDate: evaluatedAt.addingTimeInterval(3_600),
            endDate: nil,
            hostName: "Host",
            locationName: "Test",
            locationAddress: "",
            invitees: [
                Invitee(
                    id: inviteeID,
                    displayName: "Invitee",
                    phoneNumber: "+14155550101"
                ),
            ],
            minimumParticipants: 2,
            requiredGroups: [],
            rsvpDeadline: deadline,
            eventDescription: "",
            createdAt: deadline.addingTimeInterval(-60),
            invitationsSent: true,
            privateResponsePolicy: policy,
            resolution: resolution
        )
        return (verifier, event, resolution)
    }

    private func date(_ value: String) throws -> Date {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return try XCTUnwrap(formatter.date(from: value))
    }

    private func quoted(_ value: String) -> String {
        String(decoding: try! JSONEncoder().encode(value), as: UTF8.self)
    }
}

private struct NativeAttestationFixture {
    let verifier: EvaluatorAttestationVerifier
    let response: EvaluatorAttestationResponse
    let policy: PrivateResponsePolicyV1
    let nonce: String
    let now: Date
    let validClaims: [String: Any]
}

private struct InteropFixture: Decodable {
    let formatVersion: Int
    let trustPins: InteropTrustPins
    let vectors: [InteropVector]
}

private struct InteropTrustPins: Decodable {
    let policySigning: InteropTrustPin
}

private struct InteropTrustPin: Decodable {
    let keyId: String
    let publicKey: String
}

private struct InteropVector: Decodable {
    let name: String
    let eventId: String
    let inviteeId: String
    let accountKeyEpochId: String
    let minimumAllowedParticipants: Int
    let allowedInviteeIds: [String]
    let accountRootSecret: String
    let policy: PrivateResponsePolicyV1
    let envelope: PrivateResponseEnvelopeV1
    let expectedDraft: PrivateResponsePlaintextV1
    let expectedEnvelopeHash: String
}
