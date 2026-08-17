import Contacts
import Combine
import Foundation

final class ContactStoreService: ObservableObject {
    @Published private(set) var authorizationStatus: CNAuthorizationStatus
    @Published private(set) var candidates: [ContactCandidate] = []
    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: String?

    private let contactStore = CNContactStore()
    private let defaults: UserDefaults
    private var phoneCandidates: [ContactCandidate] = []
    private static let savedContactsKey = "herd.saved-contacts.v1"

    init(defaults: UserDefaults? = nil) {
#if DEBUG
        let resolvedDefaults = defaults ?? HerdUITestEnvironment.current?.defaults ?? .standard
#else
        let resolvedDefaults = defaults ?? .standard
#endif
        self.defaults = resolvedDefaults

#if DEBUG
        if HerdUITestEnvironment.current != nil {
            authorizationStatus = .authorized
            phoneCandidates = HerdUITestEnvironment.fixtureContacts
            candidates = Self.merge(
                phoneCandidates: phoneCandidates,
                savedCandidates: Self.loadSavedContacts(from: resolvedDefaults)
            )
            return
        }
#endif
        authorizationStatus = CNContactStore.authorizationStatus(for: .contacts)
        candidates = Self.loadSavedContacts(from: resolvedDefaults)
    }

    func refresh() {
#if DEBUG
        if HerdUITestEnvironment.current != nil {
            authorizationStatus = .authorized
            phoneCandidates = HerdUITestEnvironment.fixtureContacts
            publishMergedCandidates()
            isLoading = false
            errorMessage = nil
            return
        }
#endif
        authorizationStatus = CNContactStore.authorizationStatus(for: .contacts)
        switch authorizationStatus {
        case .authorized, .limited:
            fetchContacts()
        default:
            phoneCandidates = []
            publishMergedCandidates()
        }
    }

    @discardableResult
    func saveManualContact(_ candidate: ContactCandidate) -> ContactCandidate {
        let displayName = candidate.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
        let phoneNumber = HerdPhoneNumberFormatter.format(candidate.phoneNumber)
        let phoneKey = HerdPhoneNumberFormatter.comparisonKey(phoneNumber)
        var savedCandidates = Self.loadSavedContacts(from: defaults)

        let savedCandidate: ContactCandidate
        if let existingIndex = savedCandidates.firstIndex(where: {
            HerdPhoneNumberFormatter.comparisonKey($0.phoneNumber) == phoneKey
        }) {
            savedCandidate = ContactCandidate(
                id: savedCandidates[existingIndex].id,
                displayName: displayName,
                phoneNumber: phoneNumber
            )
            savedCandidates[existingIndex] = savedCandidate
        } else {
            savedCandidate = ContactCandidate(
                id: candidate.id,
                displayName: displayName,
                phoneNumber: phoneNumber
            )
            savedCandidates.append(savedCandidate)
        }

        do {
            let storedContacts = savedCandidates.map(StoredContact.init)
            defaults.set(try JSONEncoder().encode(storedContacts), forKey: Self.savedContactsKey)
            errorMessage = nil
            publishMergedCandidates(savedCandidates: savedCandidates)
        } catch {
            errorMessage = "Herd couldn’t save this contact."
        }
        return candidates.first(where: {
            HerdPhoneNumberFormatter.comparisonKey($0.phoneNumber) == phoneKey
        }) ?? savedCandidate
    }

    func requestAccess() {
#if DEBUG
        if HerdUITestEnvironment.current != nil {
            refresh()
            return
        }
#endif
        errorMessage = nil
        contactStore.requestAccess(for: .contacts) { [weak self] _, error in
            DispatchQueue.main.async {
                guard let self else { return }
                if let error {
                    self.errorMessage = error.localizedDescription
                }
                self.refresh()
            }
        }
    }

    private func fetchContacts() {
        isLoading = true
        errorMessage = nil

        let store = contactStore
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var contacts: [ContactCandidate] = []
            let keys: [CNKeyDescriptor] = [
                CNContactIdentifierKey as CNKeyDescriptor,
                CNContactGivenNameKey as CNKeyDescriptor,
                CNContactFamilyNameKey as CNKeyDescriptor,
                CNContactOrganizationNameKey as CNKeyDescriptor,
                CNContactPhoneNumbersKey as CNKeyDescriptor,
                CNContactFormatter.descriptorForRequiredKeys(for: .fullName)
            ]
            let request = CNContactFetchRequest(keysToFetch: keys)
            request.sortOrder = .userDefault

            do {
                try store.enumerateContacts(with: request) { contact, _ in
                    guard let phone = contact.phoneNumbers.first?.value.stringValue else { return }

                    let formattedName = CNContactFormatter.string(from: contact, style: .fullName)
                    let fallbackName = contact.organizationName.isEmpty ? "Unnamed contact" : contact.organizationName
                    contacts.append(
                        ContactCandidate(
                            id: contact.identifier,
                            displayName: formattedName?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? fallbackName,
                            phoneNumber: phone
                        )
                    )
                }

                #if DEBUG
                if ProcessInfo.processInfo.arguments.contains("--herd-test-contacts") {
                    let existingPhoneDigits = Set(
                        contacts.map { $0.phoneNumber.filter(\.isNumber) }
                    )
                    contacts.insert(
                        contentsOf: Self.testContacts.filter {
                            !existingPhoneDigits.contains($0.phoneNumber.filter(\.isNumber))
                        },
                        at: 0
                    )
                }
                #endif

                let herdTestContacts = contacts
                    .filter(Self.isHerdTestContact)
                    .sorted {
                        $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending
                    }
                contacts = herdTestContacts + contacts.filter { !Self.isHerdTestContact($0) }

                DispatchQueue.main.async {
                    self?.phoneCandidates = contacts
                    self?.publishMergedCandidates()
                    self?.isLoading = false
                }
            } catch {
                DispatchQueue.main.async {
                    self?.errorMessage = error.localizedDescription
                    self?.isLoading = false
                }
            }
        }
    }

    private static func isHerdTestContact(_ contact: ContactCandidate) -> Bool {
        contact.id.hasPrefix("herd-test-contact-") ||
            (contact.displayName.hasPrefix("_") && contact.displayName.hasSuffix(" herdTestUser"))
    }

    private func publishMergedCandidates(
        savedCandidates: [ContactCandidate]? = nil
    ) {
        candidates = Self.merge(
            phoneCandidates: phoneCandidates,
            savedCandidates: savedCandidates ?? Self.loadSavedContacts(from: defaults)
        )
    }

    private static func merge(
        phoneCandidates: [ContactCandidate],
        savedCandidates: [ContactCandidate]
    ) -> [ContactCandidate] {
        var seenPhoneKeys: Set<String> = []
        var merged: [ContactCandidate] = []

        for candidate in phoneCandidates + savedCandidates {
            let phoneKey = HerdPhoneNumberFormatter.comparisonKey(candidate.phoneNumber)
                ?? "id:\(candidate.id)"
            guard seenPhoneKeys.insert(phoneKey).inserted else { continue }
            merged.append(candidate)
        }

        let herdTestContacts = merged
            .filter(isHerdTestContact)
            .sorted(by: contactSort)
        let regularContacts = merged
            .filter { !isHerdTestContact($0) }
            .sorted(by: contactSort)
        return herdTestContacts + regularContacts
    }

    private static func contactSort(
        _ lhs: ContactCandidate,
        _ rhs: ContactCandidate
    ) -> Bool {
        lhs.displayName.localizedStandardCompare(rhs.displayName) == .orderedAscending
    }

    private static func loadSavedContacts(from defaults: UserDefaults) -> [ContactCandidate] {
        guard
            let data = defaults.data(forKey: savedContactsKey),
            let storedContacts = try? JSONDecoder().decode([StoredContact].self, from: data)
        else { return [] }

        return storedContacts.compactMap { stored in
            let displayName = stored.displayName.trimmingCharacters(in: .whitespacesAndNewlines)
            let phoneNumber = HerdPhoneNumberFormatter.format(stored.phoneNumber)
            guard
                !displayName.isEmpty,
                HerdPhoneNumberFormatter.comparisonKey(phoneNumber) != nil
            else { return nil }
            return ContactCandidate(
                id: stored.id,
                displayName: displayName,
                phoneNumber: phoneNumber
            )
        }
    }

    private struct StoredContact: Codable {
        let id: String
        let displayName: String
        let phoneNumber: String

        init(_ candidate: ContactCandidate) {
            id = candidate.id
            displayName = candidate.displayName
            phoneNumber = candidate.phoneNumber
        }
    }

    #if DEBUG
    private static let testContactNames = [
        "One Anderson",
        "Two Brown",
        "Three Davis",
        "Four Garcia",
        "Five Johnson",
        "Six Miller",
        "Seven Smith",
        "Eight Taylor",
        "Nine Wilson"
    ]

    private static let testContacts: [ContactCandidate] = testContactNames.enumerated().map { offset, name in
        let index = offset + 1
        return ContactCandidate(
            id: "herd-test-contact-\(index)",
            displayName: name,
            phoneNumber: "+1 (415) 555-010\(index)"
        )
    }
    #endif
}

private extension String {
    var nonEmpty: String? {
        isEmpty ? nil : self
    }
}
