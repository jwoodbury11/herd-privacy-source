import SwiftUI

struct EventEditorView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(EventStore.self) private var store
    @Environment(AuthStore.self) private var authStore

    @State private var draft: HerdEvent
    @State private var showsEventDate = false
    @State private var showsLocation = false
    @State private var showsInvitees = false
    @State private var showsDeadline = false
    @State private var showsSendConfirmation = false
    @State private var requiredPicker: RequiredPickerContext?
    @State private var isSaving = false
    @State private var saveErrorMessage: String?
    @State private var saveAlertTitle = "Couldn’t save event"
    @FocusState private var focusedField: FocusedField?

    private enum FocusedField: Hashable {
        case title
        case description
    }

    init(event: HerdEvent) {
        _draft = State(initialValue: event)
    }

    private var isExistingEvent: Bool {
        store.events.contains(where: { $0.id == draft.id })
    }

    private var primaryActionTitle: String {
        if isSaving {
            return "Saving…"
        }
        if draft.invitationsSent {
            return "Done"
        }
        return draft.invitationsSent || draft.invitees.isEmpty ? "Save" : "Send"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(alignment: .leading, spacing: 20) {
                    if draft.invitationsSent {
                        sentEventStatus
                    }

                    EditorGroup(title: "Event name") {
                        HStack(alignment: .top, spacing: 12) {
                            TextField("Untitled event", text: $draft.title, axis: .vertical)
                                .font(.title2.weight(.bold))
                                .lineLimit(1...3)
                                .textFieldStyle(.plain)
                                .accessibilityLabel("Event title")
                                .accessibilityIdentifier("event-title")
                                .focused($focusedField, equals: .title)

                            Image(systemName: "pencil")
                                .font(.subheadline.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 30, height: 30)
                                .background(HerdTheme.raisedSurface, in: .circle)
                                .accessibilityHidden(true)
                        }
                        .padding(16)
                        .contentShape(.rect)
                        .onTapGesture {
                            focusedField = .title
                        }
                    }

                    EditorGroup(title: "Event description") {
                        ZStack(alignment: .topLeading) {
                            if draft.eventDescription.isEmpty {
                                Text("Add details your guests should know…")
                                    .foregroundStyle(.tertiary)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 8)
                                    .allowsHitTesting(false)
                            }

                            TextEditor(text: $draft.eventDescription)
                                .scrollContentBackground(.hidden)
                                .frame(minHeight: 130)
                                .accessibilityLabel("Event description")
                                .focused($focusedField, equals: .description)
                        }
                        .padding(16)
                        .contentShape(.rect)
                        .onTapGesture {
                            focusedField = .description
                        }
                    }

                    EditorGroup(title: "Details") {
                        VStack(spacing: 0) {
                            Button {
                                showsEventDate = true
                            } label: {
                                EventEditorRow(
                                    icon: "calendar",
                                    title: "Date & time",
                                    value: dateSummary ?? "Set a date",
                                    showsChevron: true
                                )
                            }
                            .buttonStyle(GroupedRowButtonStyle())
                            .accessibilityIdentifier("event-date")

                            GroupDivider()

                            Button {
                                showsDeadline = true
                            } label: {
                                EventEditorRow(
                                    icon: "hourglass",
                                    title: "RSVP deadline",
                                    value: draft.eventDate == nil
                                        ? "Set the event date first"
                                        : deadlineSummary,
                                    showsChevron: true
                                )
                            }
                            .buttonStyle(GroupedRowButtonStyle())
                            .disabled(draft.eventDate == nil)
                            .opacity(draft.eventDate == nil ? 0.48 : 1)
                            .accessibilityIdentifier("event-rsvp-deadline")

                            GroupDivider()

                            EventEditorRow(
                                icon: "person.crop.circle",
                                title: "Hosted by",
                                value: draft.hostName,
                                showsChevron: false
                            )

                            GroupDivider()

                            Button {
                                showsLocation = true
                            } label: {
                                EventEditorRow(
                                    icon: "mappin.and.ellipse",
                                    title: "Location",
                                    value: locationSummary,
                                    showsChevron: true
                                )
                            }
                            .buttonStyle(GroupedRowButtonStyle())
                            .accessibilityIdentifier("event-location")
                        }
                    }

                    EditorGroup(
                        title: "Attendance",
                        footer: "The host counts as one participant."
                    ) {
                        VStack(spacing: 0) {
                            Button {
                                showsInvitees = true
                            } label: {
                                EventEditorRow(
                                    icon: "person.2",
                                    title: "Attendees",
                                    value: inviteeSummary,
                                    showsChevron: true
                                )
                            }
                            .buttonStyle(GroupedRowButtonStyle())
                            .accessibilityIdentifier("event-attendees")

                            GroupDivider()

                            Stepper(value: $draft.minimumParticipants, in: 2...50) {
                                HStack(spacing: 12) {
                                    EditorRowIcon(systemName: "person.3")
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text("Minimum attendees")
                                        Text("\(draft.minimumParticipants) people")
                                            .font(.footnote.weight(.medium))
                                            .foregroundStyle(.secondary)
                                            .monospacedDigit()
                                    }
                                }
                            }
                            .padding(.horizontal, 16)
                            .frame(minHeight: 66)

                            GroupDivider()

                            Toggle(isOn: $draft.allowsAttendeesToAddGuests) {
                                HStack(spacing: 12) {
                                    EditorRowIcon(systemName: "person.badge.plus")
                                    Text("Allow attendees to add guests")
                                }
                            }
                            .tint(Color(uiColor: .systemGreen))
                            .padding(.horizontal, 16)
                            .frame(minHeight: 66)
                            .accessibilityIdentifier("event-allow-attendee-guests")
                        }
                    }

                    requiredAttendeeSection

                    if !draft.outstandingTasks.isEmpty {
                        VStack(alignment: .leading, spacing: 9) {
                            Text("Still needed")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)

                            ForEach(draft.outstandingTasks, id: \.self) { task in
                                HStack(alignment: .firstTextBaseline, spacing: 9) {
                                    Circle()
                                        .fill(Color.secondary)
                                        .frame(width: 4, height: 4)

                                    Text(task)
                                        .font(.footnote)
                                        .foregroundStyle(.secondary)
                                }
                            }
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(.horizontal, 4)
                        .padding(.top, 2)
                    }
                }
                .padding(.horizontal, 16)
                .padding(.top, 14)
                .padding(.bottom, 36)
                .disabled(draft.invitationsSent)
            }
            .accessibilityIdentifier("event-editor-scroll")
            .scrollDismissesKeyboard(.interactively)
            .background(HerdTheme.canvas)
            .navigationTitle(
                draft.invitationsSent ? "Event" : (isExistingEvent ? "Edit event" : "New event")
            )
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Close")
                }

                ToolbarItem(placement: .confirmationAction) {
                    Button(primaryActionTitle) {
                        handlePrimaryAction()
                    }
                    .fontWeight(.semibold)
                    .disabled(!draft.isValid || isSaving)
                    .accessibilityIdentifier("event-primary-action")
                }

                ToolbarItemGroup(placement: .keyboard) {
                    Spacer()
                    Button("Done") {
                        focusedField = nil
                    }
                    .accessibilityIdentifier("event-keyboard-done")
                }
            }
        }
        .sheet(isPresented: $showsEventDate) {
            EventDateSheet(
                eventDate: $draft.eventDate,
                endDate: $draft.endDate,
                rsvpDeadline: $draft.rsvpDeadline
            )
        }
        .sheet(isPresented: $showsLocation) {
            LocationSearchView(
                locationName: $draft.locationName,
                locationAddress: $draft.locationAddress,
                profileAddress: authStore.user?.address ?? ""
            )
        }
        .sheet(isPresented: $showsDeadline) {
            if let eventDate = draft.eventDate {
                RSVPDeadlineSheet(rsvpDeadline: $draft.rsvpDeadline, eventDate: eventDate)
            }
        }
        .sheet(isPresented: $showsSendConfirmation) {
            SendInviteConfirmationView(invitees: draft.invitees) {
                showsSendConfirmation = false
                save(markInvitationsSent: true)
            }
            .presentationDetents([.large])
            .presentationDragIndicator(.visible)
        }
        .fullScreenCover(isPresented: $showsInvitees) {
            AttendeeFlowView(
                invitees: $draft.invitees,
                excludedPhoneNumber: authStore.user?.phoneNumber
            )
        }
        .sheet(item: $requiredPicker) { context in
            RequiredAttendeePickerView(
                invitees: availableInvitees(for: context),
                explanation: context.explanation,
                onSelect: { invitee in
                    addRequiredAttendee(invitee.id, using: context)
                }
            )
        }
        .onChange(of: draft.invitees) { _, invitees in
            draft.removeInvalidRequiredAttendees()
            draft.minimumParticipants = min(draft.minimumParticipants, max(2, invitees.count + 1))
        }
        .alert(saveAlertTitle, isPresented: Binding(
            get: { saveErrorMessage != nil },
            set: { if !$0 { saveErrorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(saveErrorMessage ?? "Please try again.")
        }
    }

    private var sentEventStatus: some View {
        VStack(alignment: .leading, spacing: 10) {
            if let delivery = draft.invitationDelivery,
               delivery.status == .attentionNeeded {
                Label("Some invitations need attention", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                Text(deliveryAttentionMessage(delivery))
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if let delivery = draft.invitationDelivery,
                      delivery.status == .inProgress {
                Label("Invitations are being submitted", systemImage: "paperplane")
                    .font(.headline)
                Text("Herd is still waiting for the messaging provider to accept every invitation.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.resolution?.status == .confirmed {
                Label("Event confirmed", systemImage: "checkmark.seal.fill")
                    .font(.headline)
                Text("\(draft.resolution?.attendingMemberIds?.count ?? 0) people are in the final group.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.resolution?.status == .notConfirmed {
                Label("Event not confirmed", systemImage: "xmark.seal.fill")
                    .font(.headline)
                Text("The private conditions did not resolve to a group. Individual replies remain private.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.resolution?.status == .verificationUnavailable {
                Label("Result verification unavailable", systemImage: "exclamationmark.shield.fill")
                    .font(.headline)
                Text("Herd will not show a final answer without the evaluator’s valid signed proof.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.resolution?.status == .pending,
                      draft.resolution?.retrying == true {
                Label("Taking longer than expected", systemImage: "clock.badge.exclamationmark")
                    .font(.headline)
                Text("Herd couldn’t finalize the result yet and will retry automatically. No action is needed.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.invitationDelivery?.status == .complete {
                Label("Invitations submitted", systemImage: "lock.shield.fill")
                    .font(.headline)
                Text("The messaging provider accepted every invitation. Replies remain private until the deadline.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.invitationDelivery?.status == .suppressed {
                Label("Invitations ready", systemImage: "lock.shield.fill")
                    .font(.headline)
                Text("Guests can open this event in Herd. Replies remain private until the deadline.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else if draft.resolution?.status == .pending {
                Label("Invitations active", systemImage: "lock.shield.fill")
                    .font(.headline)
                Text("Replies remain private until the deadline, then Herd will finalize the event.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            } else {
                Label("Invitations active", systemImage: "paperplane.fill")
                    .font(.headline)
            }

            Text("Sent events are locked so everyone’s private conditions are evaluated against the same plan.")
                .font(.caption)
                .foregroundStyle(.tertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func deliveryAttentionMessage(_ delivery: InvitationDeliverySummary) -> String {
        var details: [String] = []
        if delivery.counts.failed > 0 {
            let noun = delivery.counts.failed == 1 ? "invitation was" : "invitations were"
            details.append("\(delivery.counts.failed) \(noun) rejected and not sent.")
        }
        if delivery.counts.unknown > 0 {
            let noun = delivery.counts.unknown == 1 ? "invitation" : "invitations"
            details.append(
                "Delivery could not be confirmed for \(delivery.counts.unknown) \(noun). Herd did not retry automatically, which avoids sending a duplicate."
            )
        }
        return details.joined(separator: " ")
    }

    @ViewBuilder
    private var requiredAttendeeSection: some View {
        EditorGroup(title: "Required attendance", footer: requiredAttendeeFooter) {
            VStack(spacing: 0) {
                ForEach(Array(draft.requiredGroups.enumerated()), id: \.element.id) { index, group in
                    if index > 0 {
                        GroupDivider(leadingInset: 16)
                    }

                    RequiredRuleRow(
                        group: group,
                        invitees: draft.invitees,
                        onAddAlternative: {
                            requiredPicker = .alternative(for: group.id)
                        },
                        onRemoveMember: { memberID in
                            remove(memberID: memberID, from: group.id)
                        }
                    )
                    .padding(16)
                }

                if !draft.requiredGroups.isEmpty {
                    GroupDivider(leadingInset: 16)
                }

                Button {
                    requiredPicker = .newGroup()
                } label: {
                    HStack(spacing: 12) {
                        Image(systemName: "plus")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 32)
                        Text("Add required attendance")
                            .font(.body.weight(.medium))
                        Spacer()
                    }
                    .foregroundStyle(.primary)
                    .padding(.horizontal, 16)
                    .frame(minHeight: 62)
                    .contentShape(.rect)
                }
                .buttonStyle(GroupedRowButtonStyle())
                .disabled(draft.invitees.isEmpty || availableForNewGroup.isEmpty)
                .opacity(draft.invitees.isEmpty || availableForNewGroup.isEmpty ? 0.48 : 1)
            }
        }
    }

    private var requiredAttendeeFooter: String {
        if draft.invitees.isEmpty {
            return "Build the attendee list before adding attendance requirements."
        }
        return "Every row must be satisfied. Within a row, any name joined by OR can satisfy that row."
    }

    private var dateSummary: String? {
        guard let eventDate = draft.eventDate else { return nil }
        if let endDate = draft.endDate {
            return "\(eventDate.formatted(date: .abbreviated, time: .shortened)) – \(endDate.formatted(date: .omitted, time: .shortened))"
        }
        return eventDate.formatted(date: .abbreviated, time: .shortened)
    }

    private var locationSummary: String? {
        if draft.locationName.isEmpty { return "Add a place or address" }
        if draft.locationAddress.isEmpty { return draft.locationName }
        return "\(draft.locationName) · \(draft.locationAddress)"
    }

    private var inviteeSummary: String? {
        draft.participantCount == 1
            ? "1 person"
            : "\(draft.participantCount) people"
    }

    private var deadlineSummary: String? {
        draft.rsvpDeadline?.formatted(date: .abbreviated, time: .shortened) ?? "Set reply deadline"
    }

    private var usedRequiredInviteeIDs: Set<UUID> {
        Set(draft.requiredGroups.flatMap(\.memberIDs))
    }

    private var availableForNewGroup: [Invitee] {
        draft.invitees.filter { !usedRequiredInviteeIDs.contains($0.id) }
    }

    private func availableInvitees(for context: RequiredPickerContext) -> [Invitee] {
        switch context.mode {
        case .newGroup:
            return availableForNewGroup
        case .alternative:
            // The frozen policy allows each person to appear in only one row.
            // Exclude everyone already used anywhere, including the current row.
            return draft.invitees.filter { !usedRequiredInviteeIDs.contains($0.id) }
        }
    }

    private func addRequiredAttendee(_ inviteeID: UUID, using context: RequiredPickerContext) {
        switch context.mode {
        case .newGroup:
            draft.requiredGroups.append(RequiredAttendeeGroup(memberIDs: [inviteeID]))
        case let .alternative(groupID):
            guard let index = draft.requiredGroups.firstIndex(where: { $0.id == groupID }) else { return }
            if !draft.requiredGroups[index].memberIDs.contains(inviteeID) {
                draft.requiredGroups[index].memberIDs.append(inviteeID)
            }
        }
        requiredPicker = nil
    }

    private func remove(memberID: UUID, from groupID: UUID) {
        guard let index = draft.requiredGroups.firstIndex(where: { $0.id == groupID }) else { return }
        draft.requiredGroups[index].memberIDs.removeAll { $0 == memberID }
        if draft.requiredGroups[index].memberIDs.isEmpty {
            draft.requiredGroups.remove(at: index)
        }
    }

    private func handlePrimaryAction() {
        if draft.invitationsSent {
            dismiss()
        } else if draft.invitees.isEmpty {
            save()
        } else {
            showsSendConfirmation = true
        }
    }

    private func save(markInvitationsSent: Bool = false) {
        guard !isSaving else { return }
        let wasSent = draft.invitationsSent
        draft.title = draft.title.trimmingCharacters(in: .whitespacesAndNewlines)
        draft.eventDescription = draft.eventDescription.trimmingCharacters(in: .whitespacesAndNewlines)
        if markInvitationsSent {
            draft.invitationsSent = true
        }
        guard draft.isValid else {
            draft.invitationsSent = wasSent
            saveAlertTitle = "Event needs attention"
            saveErrorMessage = draft.outstandingTasks.first ?? "Review the event details and try again."
            return
        }

        isSaving = true
        Task {
            let didSave = await store.upsert(draft)
            isSaving = false
            if didSave {
                if let savedEvent = store.events.first(where: { $0.id == draft.id }) {
                    draft = savedEvent
                }
                if let delivery = draft.invitationDelivery,
                   delivery.status == .attentionNeeded {
                    saveAlertTitle = "Event saved — check delivery"
                    saveErrorMessage = deliveryAttentionMessage(delivery)
                } else {
                    dismiss()
                }
            } else {
                draft.invitationsSent = wasSent
                saveAlertTitle = "Couldn’t save event"
                saveErrorMessage = store.errorMessage ?? "Please check your connection and try again."
            }
        }
    }
}

private struct SendInviteConfirmationView: View {
    @Environment(\.dismiss) private var dismiss

    let invitees: [Invitee]
    let onSend: () -> Void

    private static let termsURL = URL(
        string: "https://herd-legal.jimmy4.chatgpt.site/terms"
    )!
    private static let privacyURL = URL(
        string: "https://herd-legal.jimmy4.chatgpt.site/privacy"
    )!

    private var inviteeCountLabel: String {
        invitees.count == 1 ? "1 invite" : "\(invitees.count) invites"
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Image(systemName: "paperplane.fill")
                            .font(.title2)
                            .foregroundStyle(.primary)
                            .frame(width: 46, height: 46)
                            .background(HerdTheme.raisedSurface, in: .circle)

                        Text("Send invitations?")
                            .font(.title2.weight(.bold))

                        Text("Herd will text each selected guest with the event details and a private response link.")
                            .font(.body)
                            .foregroundStyle(.secondary)
                    }

                    VStack(spacing: 0) {
                        confirmationRow(
                            icon: "person.2",
                            title: inviteeCountLabel,
                            detail: "Selected individually from your contacts"
                        )

                        Divider()
                            .padding(.leading, 58)

                        confirmationRow(
                            icon: "message",
                            title: "Invitations by text",
                            detail: "Guests can reply STOP or HELP"
                        )
                    }
                    .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }

                    Text("By tapping Send, you confirm that you know these people and have their permission to receive event invitations from Herd.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .padding(.vertical, 14)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(HerdTheme.raisedSurface.opacity(0.72), in: .rect(cornerRadius: 14))
                }
                .padding(20)
            }
            .background(HerdTheme.canvas)
            .safeAreaInset(edge: .bottom, spacing: 0) {
                sendFooter
            }
            .navigationTitle("Confirm invitations")
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") {
                        dismiss()
                    }
                }
            }
        }
    }

    private var sendFooter: some View {
        VStack(spacing: 10) {
            Button(action: onSend) {
                Text("Send \(inviteeCountLabel)")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .frame(minHeight: 50)
            }
            .buttonStyle(.borderedProminent)
            .tint(.white)
            .foregroundStyle(.black)
            .accessibilityIdentifier("confirm-send-invitations")

            Text(legalDisclosure)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
                .tint(.secondary)
                .accessibilityIdentifier("invitation-legal-disclosure")
        }
        .padding(.horizontal, 20)
        .padding(.top, 12)
        .padding(.bottom, 8)
        .background(HerdTheme.canvas)
    }

    private var legalDisclosure: AttributedString {
        var disclosure = AttributedString(
            "Message and data rates may apply. Reply STOP to opt out or HELP for help. See our "
        )

        var terms = AttributedString("Terms")
        terms.link = Self.termsURL
        terms.underlineStyle = .single
        disclosure.append(terms)
        disclosure.append(AttributedString(" and "))

        var privacy = AttributedString("Privacy Policy")
        privacy.link = Self.privacyURL
        privacy.underlineStyle = .single
        disclosure.append(privacy)
        disclosure.append(AttributedString("."))
        return disclosure
    }

    private func confirmationRow(icon: String, title: String, detail: String) -> some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.body.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 9))

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.body.weight(.semibold))
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            Spacer()
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 64)
    }
}

private struct EventEditorRow: View {
    let icon: String
    let title: String
    let value: String?
    let showsChevron: Bool

    var body: some View {
        HStack(spacing: 12) {
            EditorRowIcon(systemName: icon)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.primary)
                if let value, !value.isEmpty {
                    Text(value)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            Spacer()

            if showsChevron {
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.semibold))
                    .foregroundStyle(.secondary)
            }
        }
        .padding(.horizontal, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .frame(minHeight: 66)
        .contentShape(.rect)
    }
}

private struct EditorRowIcon: View {
    let systemName: String

    var body: some View {
        Image(systemName: systemName)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(.secondary)
            .frame(width: 32, height: 32)
            .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 9))
    }
}

private struct EditorGroup<Content: View>: View {
    let title: String
    let footer: String?
    let content: Content

    init(
        title: String,
        footer: String? = nil,
        @ViewBuilder content: () -> Content
    ) {
        self.title = title
        self.footer = footer
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                .clipShape(.rect(cornerRadius: 18))
                .overlay {
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }

            if let footer {
                Text(footer)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 4)
            }
        }
    }
}

private struct GroupDivider: View {
    var leadingInset: CGFloat = 60

    var body: some View {
        Divider()
            .padding(.leading, leadingInset)
    }
}

private struct GroupedRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .contentShape(.rect)
            .background(configuration.isPressed ? HerdTheme.raisedSurface.opacity(0.65) : .clear)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

private struct RequiredRuleRow: View {
    let group: RequiredAttendeeGroup
    let invitees: [Invitee]
    let onAddAlternative: () -> Void
    let onRemoveMember: (UUID) -> Void

    var body: some View {
        ScrollView(.horizontal, showsIndicators: false) {
            HStack(spacing: 8) {
                    ForEach(Array(group.memberIDs.enumerated()), id: \.element) { index, memberID in
                        if index > 0 {
                            Text("OR")
                                .font(.caption.weight(.bold))
                                .foregroundStyle(.secondary)
                        }

                        Button {
                            onRemoveMember(memberID)
                        } label: {
                            HStack(spacing: 6) {
                                Text(name(for: memberID))
                                    .lineLimit(1)
                                Image(systemName: "xmark")
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(.secondary)
                            }
                            .font(.subheadline.weight(.medium))
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(Color.white.opacity(0.10), in: .capsule)
                            .overlay {
                                Capsule()
                                    .stroke(Color.white.opacity(0.16), lineWidth: 1)
                            }
                            .contentShape(.capsule)
                        }
                        .buttonStyle(.plain)
                        .accessibilityHint("Removes this person from the rule")
                    }

                    Button {
                        onAddAlternative()
                    } label: {
                        Label("or", systemImage: "plus")
                            .font(.subheadline.weight(.medium))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 11)
                            .padding(.vertical, 7)
                            .overlay {
                                Capsule()
                                    .stroke(
                                        Color.secondary.opacity(0.65),
                                        style: StrokeStyle(lineWidth: 1, dash: [4, 3])
                                    )
                            }
                            .contentShape(.capsule)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Add OR attendee")
            }
        }
        .padding(.vertical, 4)
    }

    private func name(for id: UUID) -> String {
        invitees.first(where: { $0.id == id })?.displayName ?? "Unknown"
    }
}

private struct RequiredPickerContext: Identifiable {
    enum Mode {
        case newGroup
        case alternative(groupID: UUID)
    }

    let id = UUID()
    let mode: Mode

    static func newGroup() -> RequiredPickerContext {
        RequiredPickerContext(mode: .newGroup)
    }

    static func alternative(for groupID: UUID) -> RequiredPickerContext {
        RequiredPickerContext(mode: .alternative(groupID: groupID))
    }

    var explanation: String {
        switch mode {
        case .newGroup:
            return "Choose a person. You can add OR alternatives afterward."
        case .alternative:
            return "Choose another person to add as an OR option."
        }
    }
}

private struct RequiredAttendeePickerView: View {
    @Environment(\.dismiss) private var dismiss

    let invitees: [Invitee]
    let explanation: String
    let onSelect: (Invitee) -> Void

    var body: some View {
        List {
            Section {
                ForEach(invitees) { invitee in
                    Button {
                        onSelect(invitee)
                        dismiss()
                    } label: {
                        HStack {
                            Image(systemName: "person.crop.circle")
                                .foregroundStyle(.secondary)
                            Text(invitee.displayName)
                                .foregroundStyle(.primary)
                            Spacer()
                            Image(systemName: "plus.circle")
                                .foregroundStyle(.secondary)
                        }
                    }
                }
            } header: {
                VStack(alignment: .leading, spacing: 3) {
                    Text("Required attendee")
                        .font(.headline)
                        .foregroundStyle(.primary)

                    Text(explanation)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                }
                .textCase(nil)
            }
        }
        .herdScreenBackground()
        .overlay {
            if invitees.isEmpty {
                ContentUnavailableView(
                    "Everyone is already used",
                    systemImage: "person.2.slash",
                    description: Text("Remove someone from another rule to use them here.")
                )
            }
        }
        .presentationDetents([.medium, .large])
    }
}
