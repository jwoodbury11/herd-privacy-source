import Contacts
import SwiftUI
import UIKit

struct AttendeeFlowView: View {
    @Environment(\.dismiss) private var dismiss
    @Binding private var invitees: [Invitee]

    @StateObject private var contactService = ContactStoreService()
    @State private var searchText = ""
    @State private var selectedIDs: Set<String>
    @State private var reviewDrafts: [Invitee]
    @State private var showsReview = false
    @State private var showsContactPicker = false
    @State private var showsManualRecipientSheet = false
    @State private var contactSelectionSnapshot: Set<String> = []
    @State private var returnsToReviewOnCancel = false
    @State private var showsCancelConfirmation = false
    @FocusState private var isSearchFocused: Bool
    private let startsWithReview: Bool
    private let excludedPhoneKeys: Set<String>

    init(
        invitees: Binding<[Invitee]>,
        excludedPhoneNumber: String? = nil,
        excludedPhoneNumbers: [String] = []
    ) {
        _invitees = invitees

        var excludedPhoneKeys = Set(excludedPhoneNumbers.compactMap {
            HerdPhoneNumberFormatter.comparisonKey($0)
        })
        if let excludedPhoneNumber,
           let key = HerdPhoneNumberFormatter.comparisonKey(excludedPhoneNumber) {
            excludedPhoneKeys.insert(key)
        }
        self.excludedPhoneKeys = excludedPhoneKeys

        let currentInvitees = invitees.wrappedValue.filter { invitee in
            guard let key = HerdPhoneNumberFormatter.comparisonKey(invitee.phoneNumber) else {
                return true
            }
            return !excludedPhoneKeys.contains(key)
        }
        startsWithReview = !currentInvitees.isEmpty
        _selectedIDs = State(
            initialValue: Set(currentInvitees.map { invitee in
                invitee.sourceContactIdentifier ?? "existing-\(invitee.id.uuidString)"
            })
        )
        _reviewDrafts = State(initialValue: currentInvitees)
    }

    var body: some View {
        NavigationStack {
            Group {
                if startsWithReview {
                    reviewScreen(isRoot: true)
                } else {
                    contactPicker
                }
            }
            .navigationDestination(isPresented: $showsReview) {
                reviewScreen(isRoot: false)
            }
            .navigationDestination(isPresented: $showsContactPicker) {
                contactPicker
            }
        }
        .onAppear {
            contactService.refresh()
        }
        .task(id: contactPickerIsActive) {
            guard contactPickerIsActive, isAuthorized else { return }
            await Task.yield()
            isSearchFocused = true
        }
        .alert(clearSelectionTitle, isPresented: $showsCancelConfirmation) {
            Button("Keep selecting", role: .cancel) {}
            Button("Clear selections", role: .destructive) {
                selectedIDs.removeAll()
                dismiss()
            }
        } message: {
            Text(clearSelectionMessage)
        }
        .sheet(isPresented: $showsManualRecipientSheet) {
            ManualRecipientSheet(excludedPhoneKeys: excludedPhoneKeys) { candidate in
                addManualRecipient(candidate)
            }
        }
    }

    private var contactPickerIsActive: Bool {
        showsContactPicker || (!startsWithReview && !showsReview)
    }

    private var contactPicker: some View {
        Group {
            if contactService.isLoading {
                ProgressView("Loading contacts…")
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if isAuthorized {
                contactList
            } else {
                permissionState
            }
        }
        .background(Color.black.ignoresSafeArea())
        .navigationBarTitleDisplayMode(.inline)
        .navigationBarBackButtonHidden(startsWithReview && showsContactPicker)
        .toolbarBackground(Color.black, for: .navigationBar)
        .toolbarBackground(.visible, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel", action: cancelContactPicker)
            }

            if isAuthorized {
                ToolbarItem(placement: .principal) {
                    Text("\(selectedIDs.count) selected")
                        .font(.headline.monospacedDigit())
                        .contentTransition(.numericText())
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Next") {
                        prepareReview()
                    }
                    .fontWeight(.semibold)
                    .disabled(selectedIDs.isEmpty)
                }
            }

            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button {
                    isSearchFocused = false
                } label: {
                    Image(systemName: "keyboard.chevron.compact.down")
                }
                .accessibilityLabel("Dismiss keyboard")
            }
        }
    }

    private func reviewScreen(isRoot: Bool) -> some View {
        InviteeReviewView(
            invitees: $reviewDrafts,
            excludedPhoneKeys: excludedPhoneKeys,
            onCancel: isRoot ? { dismiss() } : nil,
            onAddMore: showContactPickerFromReview,
            onSave: saveReview
        )
    }

    private var clearSelectionTitle: String {
        let noun = selectedIDs.count == 1 ? "guest" : "guests"
        return "Clear \(selectedIDs.count) selected \(noun)?"
    }

    private var clearSelectionMessage: String {
        selectedIDs.count == 1
            ? "The guest selected in this step will be cleared."
            : "The guests selected in this step will be cleared."
    }

    private var isAuthorized: Bool {
        switch contactService.authorizationStatus {
        case .authorized, .limited:
            return true
        default:
            return false
        }
    }

    private var visibleCandidates: [ContactCandidate] {
        let query = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return allCandidates }
        return allCandidates.filter {
            $0.displayName.localizedCaseInsensitiveContains(query) ||
            $0.phoneNumber.localizedCaseInsensitiveContains(query)
        }
    }

    private var visibleSelectedCandidates: [ContactCandidate] {
        visibleCandidates.filter { selectedIDs.contains($0.id) }
    }

    private var visibleUnselectedCandidates: [ContactCandidate] {
        visibleCandidates.filter { !selectedIDs.contains($0.id) }
    }

    private var showsSelectionSections: Bool {
        !visibleSelectedCandidates.isEmpty && !visibleUnselectedCandidates.isEmpty
    }

    private var allCandidates: [ContactCandidate] {
        var contacts = contactService.candidates.filter { candidate in
            !isExcludedPhoneNumber(candidate.phoneNumber)
        }
        let existingIDs = Set(contacts.map(\.id))
        let existingPhoneKeys = Set(contacts.compactMap { candidate in
            HerdPhoneNumberFormatter.comparisonKey(candidate.phoneNumber)
        })

        contacts.append(contentsOf: invitees.compactMap { invitee in
            let identifier = invitee.sourceContactIdentifier ?? "existing-\(invitee.id.uuidString)"
            let phoneKey = HerdPhoneNumberFormatter.comparisonKey(invitee.phoneNumber)
            guard
                !existingIDs.contains(identifier),
                phoneKey.map({ !existingPhoneKeys.contains($0) }) ?? true,
                !isExcludedPhoneNumber(invitee.phoneNumber)
            else { return nil }
            return ContactCandidate(
                id: identifier,
                displayName: invitee.displayName,
                phoneNumber: invitee.phoneNumber
            )
        })
        return contacts
    }

    private var contactList: some View {
        List {
            if visibleCandidates.isEmpty {
                Section {
                    VStack(spacing: 14) {
                        Image(systemName: "person.crop.circle.badge.questionmark")
                            .font(.largeTitle)
                            .foregroundStyle(.secondary)
                        Text(allCandidates.isEmpty
                            ? "No contacts with phone numbers were found."
                            : "No matching contacts were found.")
                            .multilineTextAlignment(.center)
                        if allCandidates.isEmpty {
                            Text("Add someone manually below or add a phone number in Contacts.")
                                .font(.footnote)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.center)
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 30)
                }
            } else if showsSelectionSections {
                Section {
                    candidateRows(visibleSelectedCandidates)
                } header: {
                    Text("Selected")
                        .accessibilityIdentifier("contact-section-selected")
                }

                Section {
                    candidateRows(visibleUnselectedCandidates)
                } header: {
                    Text("Contacts")
                        .accessibilityIdentifier("contact-section-contacts")
                }
            } else {
                Section {
                    candidateRows(visibleCandidates)
                }
            }

            Section {
                Button {
                    isSearchFocused = false
                    showsManualRecipientSheet = true
                } label: {
                    VStack(spacing: 10) {
                        Image(systemName: "plus")
                            .font(.title3.weight(.semibold))
                        Text("Manually add recipient")
                            .font(.headline)
                    }
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity, minHeight: 88)
                    .overlay {
                        RoundedRectangle(cornerRadius: 16)
                            .strokeBorder(
                                Color.secondary.opacity(0.65),
                                style: StrokeStyle(lineWidth: 1.25, dash: [7, 5])
                            )
                    }
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
                .accessibilityIdentifier("manually-add-recipient")
                .listRowBackground(Color.clear)
                .listRowSeparator(.hidden)
            }
        }
        .listStyle(.plain)
        .scrollContentBackground(.hidden)
        .background(Color.black)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            searchBar
        }
    }

    @ViewBuilder
    private func candidateRows(_ candidates: [ContactCandidate]) -> some View {
        ForEach(candidates) { candidate in
            Button {
                withAnimation(.snappy) {
                    toggle(candidate)
                }
            } label: {
                ContactCandidateRow(
                    candidate: candidate,
                    isSelected: selectedIDs.contains(candidate.id)
                )
            }
            .buttonStyle(.plain)
            .accessibilityIdentifier("contact-candidate-\(candidate.id)")
        }
    }

    private var searchBar: some View {
        HStack(spacing: 10) {
            Image(systemName: "magnifyingglass")
                .foregroundStyle(.secondary)

            TextField("Search contacts", text: $searchText)
                .focused($isSearchFocused)
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .submitLabel(.search)
        }
        .padding(.horizontal, 16)
        .frame(height: 50)
        .background(HerdTheme.raisedSurface, in: .capsule)
        .overlay {
            Capsule()
                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(Color.black)
    }

    @ViewBuilder
    private var permissionState: some View {
        switch contactService.authorizationStatus {
        case .notDetermined:
            permissionPrimer
        case .denied, .restricted:
            accessDenied
        case .authorized, .limited:
            EmptyView()
        @unknown default:
            accessDenied
        }
    }

    private var permissionPrimer: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "person.crop.circle.badge.plus")
                .font(.system(.largeTitle, design: .rounded, weight: .medium))
                .foregroundStyle(.secondary)
            VStack(spacing: 8) {
                Text("Choose attendees")
                    .font(.title2.weight(.bold))
                Text("Herd uses Contacts so you can choose people to invite. Only the guests you select are sent to Herd.")
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)
            }

            Button("Allow contact access") {
                contactService.requestAccess()
            }
            .buttonStyle(.borderedProminent)
            .foregroundStyle(.black)

            if let errorMessage = contactService.errorMessage {
                Text(errorMessage)
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .multilineTextAlignment(.center)
            }
            Spacer()
        }
        .padding(28)
    }

    private var accessDenied: some View {
        VStack(spacing: 20) {
            Spacer()
            Image(systemName: "person.crop.circle.badge.exclamationmark")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
            Text("Contact access is off")
                .font(.title2.weight(.bold))
            Text("Turn on Contacts access in Settings to choose people to invite.")
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)

            Button("Open settings") {
                guard let url = URL(string: UIApplication.openSettingsURLString) else { return }
                UIApplication.shared.open(url)
            }
            .buttonStyle(.borderedProminent)
            .foregroundStyle(.black)
            Spacer()
        }
        .padding(28)
    }

    private func toggle(_ candidate: ContactCandidate) {
        if selectedIDs.contains(candidate.id) {
            selectedIDs.remove(candidate.id)
        } else {
            selectedIDs.insert(candidate.id)
        }
    }

    private func addManualRecipient(_ candidate: ContactCandidate) {
        let savedCandidate = contactService.saveManualContact(candidate)
        withAnimation(.snappy) {
            _ = selectedIDs.insert(savedCandidate.id)
        }
    }

    private func cancelContactPicker() {
        isSearchFocused = false

        if startsWithReview && showsContactPicker {
            selectedIDs = contactSelectionSnapshot
            showsContactPicker = false
            return
        }

        if returnsToReviewOnCancel {
            selectedIDs = contactSelectionSnapshot
            returnsToReviewOnCancel = false
            showsReview = true
            return
        }

        guard !selectedIDs.isEmpty else {
            dismiss()
            return
        }
        showsCancelConfirmation = true
    }

    private func showContactPickerFromReview() {
        isSearchFocused = false
        selectedIDs = Set(reviewDrafts.map { invitee in
            invitee.sourceContactIdentifier ?? "existing-\(invitee.id.uuidString)"
        })
        contactSelectionSnapshot = selectedIDs

        if startsWithReview {
            showsContactPicker = true
        } else {
            returnsToReviewOnCancel = true
            showsReview = false
        }
    }

    private func prepareReview() {
        isSearchFocused = false
        reviewDrafts = allCandidates
            .filter { selectedIDs.contains($0.id) }
            .map { candidate in
                if let existing = reviewDrafts.first(where: {
                    ($0.sourceContactIdentifier ?? "existing-\($0.id.uuidString)") == candidate.id
                }) ?? invitees.first(where: {
                    ($0.sourceContactIdentifier ?? "existing-\($0.id.uuidString)") == candidate.id
                }) {
                    return existing
                }
                return Invitee(
                    sourceContactIdentifier: candidate.id,
                    displayName: candidate.displayName,
                    phoneNumber: candidate.phoneNumber
                )
            }

        if startsWithReview && showsContactPicker {
            showsContactPicker = false
        } else {
            returnsToReviewOnCancel = false
            showsReview = true
        }
    }

    private func saveReview() {
        guard !reviewDrafts.contains(where: { isExcludedPhoneNumber($0.phoneNumber) }) else {
            return
        }
        invitees = reviewDrafts
        dismiss()
    }

    private func isExcludedPhoneNumber(_ phoneNumber: String) -> Bool {
        guard let key = HerdPhoneNumberFormatter.comparisonKey(phoneNumber) else { return false }
        return excludedPhoneKeys.contains(key)
    }
}

private struct ManualRecipientSheet: View {
    @Environment(\.dismiss) private var dismiss

    let excludedPhoneKeys: Set<String>
    let onSave: (ContactCandidate) -> Void

    @State private var name = ""
    @State private var phoneNumber = ""
    @FocusState private var focusedField: Field?

    private enum Field: Hashable {
        case name
        case phoneNumber
    }

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var phoneKey: String? {
        HerdPhoneNumberFormatter.comparisonKey(phoneNumber)
    }

    private var isHostPhoneNumber: Bool {
        guard let phoneKey else { return false }
        return excludedPhoneKeys.contains(phoneKey)
    }

    private var canSave: Bool {
        let digitCount = phoneNumber.filter(\.isWholeNumber).count
        return !trimmedName.isEmpty &&
            (7...15).contains(digitCount) &&
            !isHostPhoneNumber
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $name)
                        .textInputAutocapitalization(.words)
                        .submitLabel(.next)
                        .focused($focusedField, equals: .name)
                        .onSubmit {
                            focusedField = .phoneNumber
                        }
                        .accessibilityIdentifier("manual-recipient-name")

                    TextField("Phone number", text: $phoneNumber)
                        .keyboardType(.phonePad)
                        .textContentType(.telephoneNumber)
                        .focused($focusedField, equals: .phoneNumber)
                        .onChange(of: phoneNumber) { _, newValue in
                            let formatted = HerdPhoneNumberFormatter.format(newValue)
                            if formatted != newValue {
                                phoneNumber = formatted
                            }
                        }
                        .accessibilityIdentifier("manual-recipient-phone")
                } header: {
                    Text("Recipient")
                } footer: {
                    if isHostPhoneNumber {
                        Text("This person is already on the attendee list.")
                            .foregroundStyle(.red)
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(HerdTheme.canvas)
            .navigationTitle("Add recipient")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        let candidate = ContactCandidate(
                            id: "manual-\(UUID().uuidString)",
                            displayName: trimmedName,
                            phoneNumber: HerdPhoneNumberFormatter.format(phoneNumber)
                        )
                        onSave(candidate)
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(!canSave)
                    .accessibilityIdentifier("save-manual-recipient")
                }
            }
        }
        .presentationDetents([.medium])
        .presentationDragIndicator(.visible)
        .onAppear {
            focusedField = .name
        }
    }
}

private struct ContactCandidateRow: View {
    let candidate: ContactCandidate
    let isSelected: Bool

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: "person.crop.circle")
                .font(.title2)
                .foregroundStyle(.secondary)

            VStack(alignment: .leading, spacing: 3) {
                Text(candidate.displayName)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.primary)
                Text(candidate.phoneNumber)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            Image(systemName: isSelected ? "checkmark.square.fill" : "square")
                .font(.title3)
                .foregroundStyle(isSelected ? .primary : .secondary)
        }
        .contentShape(.rect)
    }
}

private struct InviteeReviewView: View {
    @Binding var invitees: [Invitee]
    let excludedPhoneKeys: Set<String>
    let onCancel: (() -> Void)?
    let onAddMore: () -> Void
    let onSave: () -> Void
    @FocusState private var isEditing: Bool

    private var canSave: Bool {
        !invitees.isEmpty && !containsExcludedPhone && invitees.allSatisfy {
            !$0.displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
            !$0.phoneNumber.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }

    private var containsExcludedPhone: Bool {
        return invitees.contains {
            guard let key = HerdPhoneNumberFormatter.comparisonKey($0.phoneNumber) else {
                return false
            }
            return excludedPhoneKeys.contains(key)
        }
    }

    var body: some View {
        ScrollView {
            VStack(spacing: 12) {
                if invitees.isEmpty {
                    ContentUnavailableView(
                        "No attendees selected",
                        systemImage: "person.crop.circle.badge.minus"
                    )
                    .padding(.top, 60)
                } else {
                    if containsExcludedPhone {
                        Label(
                            "This person is already on the attendee list.",
                            systemImage: "person.crop.circle.badge.exclamationmark"
                        )
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 4)
                    }

                    VStack(spacing: 0) {
                        InviteeReviewHeader()

                        Divider()

                        ForEach($invitees) { $invitee in
                            InviteeReviewRow(
                                invitee: $invitee,
                                isEditing: $isEditing
                            ) {
                                withAnimation {
                                    invitees.removeAll { $0.id == invitee.id }
                                }
                            }

                            if invitee.id != invitees.last?.id {
                                Divider()
                                    .padding(.leading, 14)
                            }
                        }
                    }
                    .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                    .clipShape(.rect(cornerRadius: 18))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                }

                Button {
                    isEditing = false
                    onAddMore()
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "person.badge.plus")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 28)

                        Text("Add more invites")
                            .font(.body.weight(.semibold))

                        Spacer()

                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.tertiary)
                    }
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 14)
                    .frame(minHeight: 56)
                    .background(HerdTheme.surface, in: .rect(cornerRadius: 16))
                    .overlay {
                        RoundedRectangle(cornerRadius: 16)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                    .contentShape(.rect)
                }
                .buttonStyle(.plain)
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 18)
        }
        .background(HerdTheme.canvas)
        .navigationTitle("Review invites")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let onCancel {
                ToolbarItem(placement: .cancellationAction) {
                    Button(action: onCancel) {
                        Image(systemName: "chevron.left")
                    }
                    .accessibilityLabel("Back")
                }
            }

            ToolbarItem(placement: .confirmationAction) {
                Button("Save", action: save)
                    .fontWeight(.semibold)
                    .disabled(!canSave)
                    .accessibilityIdentifier("save-invitees")
            }

            ToolbarItemGroup(placement: .keyboard) {
                Spacer()
                Button {
                    isEditing = false
                } label: {
                    Image(systemName: "keyboard.chevron.compact.down")
                }
                .accessibilityLabel("Dismiss keyboard")
            }
        }
        .onAppear {
            for index in invitees.indices {
                invitees[index].phoneNumber = HerdPhoneNumberFormatter.format(
                    invitees[index].phoneNumber
                )
            }
        }
    }

    private func save() {
        for index in invitees.indices {
            invitees[index].displayName = invitees[index].displayName
                .trimmingCharacters(in: .whitespacesAndNewlines)
            invitees[index].phoneNumber = invitees[index].phoneNumber
                .trimmingCharacters(in: .whitespacesAndNewlines)
        }
        onSave()
    }
}

private struct InviteeReviewHeader: View {
    var body: some View {
        HStack(alignment: .top, spacing: 8) {
            ReviewColumnLabel(
                title: "Name",
                detail: "Shown on invite",
                icon: "person"
            )

            ReviewColumnLabel(
                title: "Phone number",
                detail: "Never shown",
                icon: "lock.fill"
            )

            Color.clear
                .frame(width: 28, height: 1)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 12)
    }
}

private struct ReviewColumnLabel: View {
    let title: String
    let detail: String
    let icon: String

    var body: some View {
        HStack(alignment: .center, spacing: 7) {
            Image(systemName: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.primary)
                .frame(width: 14, height: 16)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.primary)
                Text(detail)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct InviteeReviewRow: View {
    @Binding var invitee: Invitee
    var isEditing: FocusState<Bool>.Binding
    let onDelete: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            TextField("Name", text: $invitee.displayName)
                .textInputAutocapitalization(.words)
                .focused(isEditing)
                .reviewFieldStyle()

            FormattedPhoneTextField(
                text: $invitee.phoneNumber,
                isFocused: isEditing
            )
                .reviewFieldStyle()

            Button(role: .destructive, action: onDelete) {
                Image(systemName: "trash")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .frame(width: 28, height: 40)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Remove \(invitee.displayName)")
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }
}

private struct FormattedPhoneTextField: UIViewRepresentable {
    @Binding var text: String
    var isFocused: FocusState<Bool>.Binding

    func makeCoordinator() -> Coordinator {
        Coordinator(parent: self)
    }

    func makeUIView(context: Context) -> UITextField {
        let textField = UITextField()
        textField.delegate = context.coordinator
        textField.placeholder = "Phone"
        textField.keyboardType = .phonePad
        textField.textContentType = .telephoneNumber
        textField.font = .preferredFont(forTextStyle: .subheadline)
        textField.textColor = .label
        textField.tintColor = .label
        textField.adjustsFontForContentSizeCategory = true
        textField.accessibilityLabel = "Phone number"
        return textField
    }

    func updateUIView(_ textField: UITextField, context: Context) {
        context.coordinator.parent = self

        let formatted = HerdPhoneNumberFormatter.format(text)
        if text != formatted {
            DispatchQueue.main.async {
                self.text = formatted
            }
        }
        if textField.text != formatted {
            textField.text = formatted
        }

        if isFocused.wrappedValue, !textField.isFirstResponder {
            textField.becomeFirstResponder()
        } else if !isFocused.wrappedValue, textField.isFirstResponder {
            textField.resignFirstResponder()
        }
    }

    final class Coordinator: NSObject, UITextFieldDelegate {
        var parent: FormattedPhoneTextField

        init(parent: FormattedPhoneTextField) {
            self.parent = parent
        }

        func textFieldDidBeginEditing(_ textField: UITextField) {
            parent.isFocused.wrappedValue = true
        }

        func textFieldDidEndEditing(_ textField: UITextField) {
            parent.isFocused.wrappedValue = false
        }

        func textField(
            _ textField: UITextField,
            shouldChangeCharactersIn range: NSRange,
            replacementString string: String
        ) -> Bool {
            let current = textField.text ?? ""
            guard let swiftRange = Range(range, in: current) else { return false }

            let proposed = current.replacingCharacters(in: swiftRange, with: string)
            let formatted = HerdPhoneNumberFormatter.format(proposed)

            parent.text = formatted
            textField.text = formatted

            if let end = textField.endOfDocument as UITextPosition? {
                textField.selectedTextRange = textField.textRange(from: end, to: end)
            }

            return false
        }
    }
}

enum HerdPhoneNumberFormatter {
    static func comparisonKey(_ rawValue: String) -> String? {
        let digits = String(rawValue.filter(\.isWholeNumber).prefix(15))
        guard !digits.isEmpty else { return nil }

        if digits.count == 10 {
            return "1\(digits)"
        }
        return digits
    }

    static func format(_ rawValue: String) -> String {
        let trimmed = rawValue.trimmingCharacters(in: .whitespacesAndNewlines)
        let digits = String(trimmed.filter(\.isWholeNumber).prefix(15))

        guard !digits.isEmpty else { return "" }

        if digits.first == "1", digits.count > 10 {
            let nationalStart = digits.index(after: digits.startIndex)
            let nationalEnd = digits.index(nationalStart, offsetBy: min(10, digits.count - 1))
            let national = String(digits[nationalStart..<nationalEnd])
            let overflow = String(digits[nationalEnd...])
            let suffix = overflow.isEmpty ? "" : " \(overflow)"
            return "+1 \(formatNorthAmerican(national))\(suffix)"
        }

        if trimmed.hasPrefix("+") || digits.count > 10 {
            return "+\(digits)"
        }

        return formatNorthAmerican(digits)
    }

    private static func formatNorthAmerican(_ digits: String) -> String {
        guard digits.count > 3 else { return digits }

        let areaEnd = digits.index(digits.startIndex, offsetBy: 3)
        let areaCode = String(digits[..<areaEnd])
        let remainder = String(digits[areaEnd...])

        guard remainder.count > 3 else {
            return "(\(areaCode)) \(remainder)"
        }

        let exchangeEnd = remainder.index(remainder.startIndex, offsetBy: 3)
        let exchange = String(remainder[..<exchangeEnd])
        let subscriber = String(remainder[exchangeEnd...])
        return "(\(areaCode)) \(exchange)-\(subscriber)"
    }
}

private extension View {
    func reviewFieldStyle() -> some View {
        font(.subheadline)
            .padding(.horizontal, 10)
            .frame(maxWidth: .infinity, minHeight: 40)
            .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 10))
            .overlay {
                RoundedRectangle(cornerRadius: 10)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
    }
}
