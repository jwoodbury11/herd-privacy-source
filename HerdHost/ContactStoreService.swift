import Contacts
import Combine
import Foundation

final class ContactStoreService: ObservableObject {
    @Published private(set) var authorizationStatus: CNAuthorizationStatus
    @Published private(set) var candidates: [ContactCandidate] = []
    @Published private(set) var isLoading = false
    @Published private(set) var errorMessage: String?

    private let contactStore = CNContactStore()

    init() {
#if DEBUG
        if HerdUITestEnvironment.current != nil {
            authorizationStatus = .authorized
            candidates = HerdUITestEnvironment.fixtureContacts
            return
        }
#endif
        authorizationStatus = CNContactStore.authorizationStatus(for: .contacts)
    }

    func refresh() {
#if DEBUG
        if HerdUITestEnvironment.current != nil {
            authorizationStatus = .authorized
            candidates = HerdUITestEnvironment.fixtureContacts
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
            candidates = []
        }
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
                if ProcessInfo.processInfo.arguments.contains("--herd-qa-contacts") {
                    let existingPhoneDigits = Set(
                        contacts.map { $0.phoneNumber.filter(\.isNumber) }
                    )
                    contacts.insert(
                        contentsOf: Self.qaContacts.filter {
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
                    self?.candidates = contacts
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
        contact.displayName.hasPrefix("_") && contact.displayName.hasSuffix(" herdTestUser")
    }

    #if DEBUG
    private static let qaContacts: [ContactCandidate] = (1...9).map { index in
        ContactCandidate(
            id: "herd-qa-contact-\(index)",
            displayName: "_\(index) herdTestUser",
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
