import SwiftUI
import UIKit

struct HomeView: View {
    @Environment(EventStore.self) private var store
    @Environment(AuthStore.self) private var authStore
    @Environment(InvitationCoordinator.self) private var invitationCoordinator
    @State private var presentation: Presentation?
    private let experience = HerdExperience.shared.home
    private static let maximumDeadlineSleepInterval: TimeInterval = 31_536_000

    private enum Presentation: Identifiable {
        case create(HerdEvent)
        case detail(UUID, invitationGeneration: UInt?)

        var id: String {
            switch self {
            case let .create(event): "create-\(event.id.uuidString)"
            case let .detail(eventID, invitationGeneration):
                "detail-\(eventID.uuidString)-\(invitationGeneration.map(String.init) ?? "standard")"
            }
        }
    }

    init(
        startsInCreateFlow: Bool = false,
        initialCreateEvent: HerdEvent? = nil
    ) {
        _presentation = State(
            initialValue: startsInCreateFlow
                ? .create(initialCreateEvent ?? .newDraft())
                : nil
        )
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                LazyVStack(
                    alignment: .leading,
                    spacing: CGFloat(experience.layout.verticalGap)
                ) {
                    pendingInvitationCard
                    homeHeader

                    if let errorMessage = store.errorMessage {
                        SyncMessageCard(
                            message: errorMessage,
                            isCached: store.isUsingCachedData
                        ) {
                            Task {
                                await store.refresh()
                            }
                        }
                    }

                    if store.isRefreshing && store.events.isEmpty {
                        ProgressView("Loading your events…")
                            .frame(maxWidth: .infinity, minHeight: 160)
                            .wireframeCard()
                    } else if store.events.isEmpty {
                        CreateEventCard(experience: experience) {
                            presentation = .create(.newDraft(hostName: profileName))
                        }
                    } else {
                        ForEach(store.events) { event in
                            eventButton(for: event)
                        }

                        CreateEventCard(experience: experience) {
                            presentation = .create(.newDraft(hostName: profileName))
                        }
                    }
                }
                .padding(.horizontal, CGFloat(experience.layout.horizontalPadding))
                .padding(.top, CGFloat(experience.layout.topPadding))
                .padding(.bottom, CGFloat(experience.layout.bottomPadding))
            }
            .background(HerdTheme.canvas)
            .refreshable {
                await store.refresh()
            }
            .toolbar(.hidden, for: .navigationBar)
        }
        .fullScreenCover(item: $presentation) { presentation in
            switch presentation {
            case let .create(event):
                EventEditorView(event: event)
            case let .detail(eventID, invitationGeneration):
                InvitationDetailView(eventID: eventID)
                    .onAppear {
                        if let invitationGeneration {
                            invitationCoordinator.acknowledgePresentation(
                                of: eventID,
                                generation: invitationGeneration
                            )
                        }
                    }
            }
        }
        .onAppear(perform: presentLinkedInvitationIfReady)
        .onChange(of: invitationCoordinator.loadedEventID) { _, _ in
            presentLinkedInvitationIfReady()
        }
        .onChange(of: invitationCoordinator.loadedRequestGeneration) { _, _ in
            // Observe both halves of the linked presentation identity. SwiftUI
            // normally coalesces the coordinator's assignments, but either
            // value arriving first must still be enough to stage the detail.
            presentLinkedInvitationIfReady()
        }
        .alert(
            "Import older events?",
            isPresented: Binding(
                get: { store.legacyImportCandidateCount > 0 },
                set: { isPresented in
                    if !isPresented { store.deferLegacyImport() }
                }
            )
        ) {
            Button("Not now", role: .cancel) {
                store.deferLegacyImport()
            }
            Button("Import into this account") {
                Task {
                    if await store.claimLegacyHostedEvents() {
                        await store.refresh()
                    }
                }
            }
        } message: {
            let count = store.legacyImportCandidateCount
            Text(
                count == 1
                    ? "Herd found one event from an older version. Import it only if it belongs to the account you’re using now."
                    : "Herd found \(count) events from an older version. Import them only if they belong to the account you’re using now."
            )
        }
        .task(id: nextResolutionDeadline) {
            guard let deadline = nextResolutionDeadline else { return }

            // Task.sleep accepts long durations, but keep each wait bounded and
            // recompute the remaining time so deadlines more than a year away do
            // not wake once and silently stop being monitored.
            while !Task.isCancelled {
                let waitInterval = deadline.timeIntervalSinceNow + 0.5
                guard waitInterval > 0 else { break }

                let sleepInterval = min(
                    waitInterval,
                    Self.maximumDeadlineSleepInterval
                )
                do {
                    try await Task.sleep(
                        nanoseconds: UInt64(sleepInterval * 1_000_000_000)
                    )
                } catch {
                    return
                }
            }
            guard !Task.isCancelled else { return }

            while !Task.isCancelled {
                await store.refresh()

                let hasUnresolvedDueEvent = store.events.contains { event in
                    guard let deadline = event.rsvpDeadline else { return false }
                    return event.invitationsSent
                        && event.privateResponsePolicy != nil
                        && deadline <= .now
                        && (event.resolution == nil || event.resolution?.status == .pending)
                }
                guard hasUnresolvedDueEvent else { return }

                do {
                    try await Task.sleep(nanoseconds: 5_000_000_000)
                } catch {
                    return
                }
            }
        }
    }

    @ViewBuilder
    private var pendingInvitationCard: some View {
        if invitationCoordinator.requiresAccountSwitch {
            VStack(alignment: .leading, spacing: 12) {
                Label("This invitation is for another account", systemImage: "person.crop.circle.badge.exclamationmark")
                    .font(.headline)

                Text("Switch accounts and sign in with the phone number that received the invitation. The link will stay ready on this iPhone.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: 12) {
                    Button("Switch account") {
                        invitationCoordinator.prepareForAccountSwitch()
                        Task {
                            await authStore.signOut()
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.white)
                    .foregroundStyle(.black)
                    .accessibilityIdentifier("switch-invitation-account")

                    Button("Keep this account") {
                        invitationCoordinator.discard()
                    }
                    .buttonStyle(.bordered)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .wireframeCard()
        } else if let message = invitationCoordinator.errorMessage,
                  invitationCoordinator.pendingToken != nil {
            VStack(alignment: .leading, spacing: 12) {
                Label("Couldn’t open the invitation", systemImage: "exclamationmark.triangle.fill")
                    .font(.headline)
                Text(message)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 12) {
                    Button("Try again") {
                        if
                            let eventID = invitationCoordinator.loadedEventID,
                            let generation = invitationCoordinator.loadedRequestGeneration
                        {
                            // The event was already shown; this branch retries
                            // only the failed Keychain cleanup.
                            invitationCoordinator.acknowledgePresentation(
                                of: eventID,
                                generation: generation
                            )
                        } else {
                            Task {
                                guard let accountID = authStore.user?.id else { return }
                                await invitationCoordinator.resolve(
                                    using: store,
                                    accountID: accountID
                                )
                            }
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.white)
                    .foregroundStyle(.black)
                    Button("Dismiss") {
                        invitationCoordinator.discard()
                    }
                    .buttonStyle(.bordered)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .wireframeCard()
        } else if invitationCoordinator.pendingToken != nil {
            HStack(spacing: 12) {
                ProgressView()
                Text(invitationCoordinator.isResolving ? "Opening your invitation…" : "Invitation ready to open…")
                    .font(.subheadline.weight(.semibold))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .wireframeCard()
        }
    }

    private func presentLinkedInvitationIfReady() {
        guard
            let eventID = invitationCoordinator.loadedEventID,
            let generation = invitationCoordinator.loadedRequestGeneration
        else { return }
        guard store.events.contains(where: { $0.id == eventID }) else { return }
        presentation = .detail(eventID, invitationGeneration: generation)
    }

    private var nextResolutionDeadline: Date? {
        store.events
            .filter { event in
                event.invitationsSent
                    && event.privateResponsePolicy != nil
                    && (event.resolution == nil || event.resolution?.status == .pending)
            }
            .compactMap(\.rsvpDeadline)
            .min()
    }

    private func eventButton(for event: HerdEvent) -> some View {
        Button {
            if event.isHosted && !event.invitationsSent {
                presentation = .create(event)
            } else {
                presentation = .detail(event.id, invitationGeneration: nil)
            }
        } label: {
            EventCard(event: event, experience: experience)
        }
        .buttonStyle(PlainPressButtonStyle())
        .accessibilityHint(
            event.isHosted && !event.invitationsSent
                ? "Opens this draft for editing"
                : "Opens event details"
        )
    }

    private var homeHeader: some View {
        HStack(spacing: 16) {
            Text(experience.title)
                .font(.largeTitle.weight(.bold))
                .tracking(-0.7)

            Spacer()

            NavigationLink {
                ProfileView()
            } label: {
                Group {
                    if savedProfileName.isEmpty && experience.profile.useGenericIconWithoutName {
                        Image(systemName: "person")
                            .font(.system(size: 18, weight: .regular))
                    } else {
                        Text(profileInitials)
                            .font(.subheadline.weight(.bold))
                    }
                }
                    .foregroundStyle(.primary)
                    .frame(
                        width: CGFloat(experience.layout.profileAvatarDiameter),
                        height: CGFloat(experience.layout.profileAvatarDiameter)
                    )
                    .background(HerdTheme.raisedSurface, in: .circle)
                    .overlay {
                        Circle()
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
            }
            .buttonStyle(PlainPressButtonStyle())
            .accessibilityLabel(experience.profile.accessibilityLabel)
        }
        .padding(
            .bottom,
            max(0, experience.layout.headerToFirstCardGap - experience.layout.verticalGap)
        )
    }

    private var savedProfileName: String {
        authStore.user?.name.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    }

    private var profileName: String {
        savedProfileName.isEmpty ? "Host" : savedProfileName
    }

    private var profileInitials: String {
        let components = profileName.split(whereSeparator: \.isWhitespace)
        let initials: String
        if let first = components.first?.first, let last = components.dropFirst().last?.first {
            initials = "\(first)\(last)"
        } else {
            initials = String(components.first?.prefix(2) ?? "H")
        }
        return initials.uppercased()
    }
}

private struct SyncMessageCard: View {
    let message: String
    let isCached: Bool
    let retry: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: isCached ? "icloud.slash" : "exclamationmark.icloud")
                .foregroundStyle(.secondary)
                .frame(width: 24)

            VStack(alignment: .leading, spacing: 7) {
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                Button("Try again", action: retry)
                    .font(.footnote.weight(.semibold))
                    .buttonStyle(.plain)
            }

            Spacer()
        }
        .padding(14)
        .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
    }
}

private struct CreateEventCard: View {
    let experience: HerdExperience.Home
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 12) {
                Image(systemName: "plus")
                    .font(.title2.weight(.medium))
                Text(experience.createEventTitle)
                    .font(.headline)
            }
            .frame(
                maxWidth: .infinity,
                minHeight: CGFloat(experience.layout.createCardMinimumHeight)
            )
            .padding()
            .overlay {
                RoundedRectangle(cornerRadius: CGFloat(experience.layout.cardCornerRadius))
                    .strokeBorder(
                        Color.secondary.opacity(0.65),
                        style: StrokeStyle(lineWidth: 1.25, dash: [7, 5])
                    )
            }
        }
        .buttonStyle(PlainPressButtonStyle())
        .accessibilityHint("Opens the event creation form")
    }
}

private struct ProfileView: View {
    @Environment(AuthStore.self) private var authStore
    private let experience = HerdExperience.shared.profile
    @State private var name = ""
    @State private var address = ""
    @State private var hasLoadedProfile = false
    @State private var showsLogoutConfirmation = false
    @State private var showsAccountDeletionConfirmation = false
    @State private var showsAccountDeletionVerification = false
    @State private var accountDeletionCode = ""
    @State private var savedNotice = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(experience.title)
                    .font(.largeTitle.weight(.bold))
                    .tracking(-0.7)
                    .padding(.top, 10)

                VStack(spacing: 0) {
                    ProfileField(
                        label: experience.nameLabel,
                        placeholder: experience.namePlaceholder,
                        text: $name
                    )

                    Divider()
                        .padding(.leading, 16)

                    ProfileValue(
                        label: experience.phoneLabel,
                        value: authStore.user?.phoneNumber ?? "Unavailable"
                    )

                    Divider()
                        .padding(.leading, 16)

                    ProfileField(
                        label: experience.addressLabel,
                        placeholder: experience.addressPlaceholder,
                        text: $address,
                        axis: .vertical
                    )
                }
                .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                .overlay {
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }

                Text(experience.syncNote)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .padding(.horizontal, 4)

                if !savedNotice.isEmpty {
                    Label(savedNotice, systemImage: "checkmark.circle.fill")
                        .font(.footnote)
                        .foregroundStyle(.green)
                        .padding(.horizontal, 4)
                }

                if let errorMessage = authStore.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }

                saveButton

                Button(experience.logoutButton) {
                    showsLogoutConfirmation = true
                }
                .font(.headline)
                .foregroundStyle(.primary)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 15)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
                .overlay {
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }
                .buttonStyle(PlainPressButtonStyle())
                .accessibilityHint("Signs out after confirmation")
                .disabled(authStore.isBusy)
                .opacity(authStore.isBusy ? 0.42 : 1)

                Button(experience.deleteAccountButton) {
                    showsAccountDeletionConfirmation = true
                }
                .font(.headline)
                .foregroundStyle(.red)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 15)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
                .overlay {
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(Color.red.opacity(0.42), lineWidth: 1)
                }
                .buttonStyle(PlainPressButtonStyle())
                .accessibilityHint("Permanently deletes the account after confirmation")
                .disabled(authStore.isBusy)
                .opacity(authStore.isBusy ? 0.42 : 1)
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 32)
        }
        .background(HerdTheme.canvas)
        .navigationTitle(experience.navigationTitle)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
        .alert(
            experience.logout.title,
            isPresented: $showsLogoutConfirmation,
        ) {
            Button(experience.logout.cancelButton, role: .cancel) {}
            Button(experience.logout.confirmButton, role: .destructive) {
                Task {
                    await authStore.signOut()
                }
            }
        } message: {
            Text(experience.logout.body)
        }
        .alert(
            experience.accountDeletion.title,
            isPresented: $showsAccountDeletionConfirmation,
        ) {
            Button(experience.accountDeletion.cancelButton, role: .cancel) {}
            Button(experience.accountDeletion.continueButton, role: .destructive) {
                beginAccountDeletion()
            }
        } message: {
            Text(experience.accountDeletion.body)
        }
        .sheet(
            isPresented: $showsAccountDeletionVerification,
            onDismiss: {
                accountDeletionCode = ""
                if authStore.challenge != nil {
                    authStore.changePhoneNumber()
                }
            }
        ) {
            accountDeletionVerificationSheet
        }
        .task {
            guard !hasLoadedProfile, let user = authStore.user else { return }
            name = user.name
            address = user.address
            hasLoadedProfile = true
        }
    }

    private var accountDeletionVerificationSheet: some View {
        NavigationStack {
            VStack(alignment: .leading, spacing: 18) {
                Text(experience.accountDeletion.verificationBody)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 8) {
                    Text(experience.accountDeletion.codeLabel)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(.secondary)
                    TextField(
                        experience.accountDeletion.codePlaceholder,
                        text: $accountDeletionCode
                    )
                    .keyboardType(.numberPad)
                    .textContentType(.oneTimeCode)
                    .font(.title2.monospacedDigit())
                    .padding(14)
                    .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
                    .overlay {
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                    .onChange(of: accountDeletionCode) { _, newValue in
                        accountDeletionCode = String(newValue.filter(\.isWholeNumber).prefix(4))
                        authStore.clearError()
                    }
                }

                if let errorMessage = authStore.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Button {
                    confirmAccountDeletionCode()
                } label: {
                    HStack(spacing: 10) {
                        if authStore.isBusy {
                            ProgressView()
                                .tint(.white)
                        }
                        Text(
                            authStore.isBusy
                                ? experience.accountDeletion.deletingButton
                                : experience.accountDeletion.verifyButton
                        )
                        .font(.headline)
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                }
                .buttonStyle(.borderedProminent)
                .tint(.red)
                .disabled(authStore.isBusy || accountDeletionCode.count != 4)

                Button(experience.accountDeletion.cancelButton) {
                    authStore.changePhoneNumber()
                    showsAccountDeletionVerification = false
                }
                .frame(maxWidth: .infinity)
                .disabled(authStore.isBusy)

                Spacer()
            }
            .padding(20)
            .background(HerdTheme.canvas)
            .navigationTitle(experience.accountDeletion.verificationTitle)
            .navigationBarTitleDisplayMode(.inline)
            .interactiveDismissDisabled(authStore.isBusy)
        }
        .presentationDetents([.medium])
    }

    private func beginAccountDeletion() {
        Task {
            switch await authStore.deleteAccount() {
            case .deleted, .failed:
                return
            case .reauthenticationRequired:
                guard let phoneNumber = authStore.user?.phoneNumber else { return }
                guard await authStore.requestCode(phoneNumber: phoneNumber) else { return }
                if authStore.challenge != nil {
                    accountDeletionCode = ""
                    showsAccountDeletionVerification = true
                } else {
                    _ = await authStore.deleteAccount()
                }
            }
        }
    }

    private func confirmAccountDeletionCode() {
        Task {
            guard await authStore.verifyCode(accountDeletionCode) else { return }
            if await authStore.deleteAccount() == .deleted {
                showsAccountDeletionVerification = false
            }
        }
    }

    private var saveButton: some View {
        Button {
            Task {
                if await authStore.updateProfile(name: name, address: address) {
                    savedNotice = experience.savedNotice
                }
            }
        } label: {
            HStack(spacing: 10) {
                if authStore.isBusy {
                    ProgressView()
                        .tint(.black)
                }
                Text(experience.saveButton)
                    .font(.headline)
            }
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .background(.white, in: .rect(cornerRadius: 14))
        }
        .buttonStyle(PlainPressButtonStyle())
        .disabled(authStore.isBusy)
    }
}

private struct ProfileValue: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(value)
                .foregroundStyle(.primary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
    }
}

private struct ProfileField: View {
    let label: String
    let placeholder: String
    @Binding var text: String
    var keyboardType: UIKeyboardType = .default
    var axis: Axis = .horizontal

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            TextField(placeholder, text: $text, axis: axis)
                .keyboardType(keyboardType)
                .textContentType(textContentType)
                .lineLimit(axis == .vertical ? 2...4 : 1...1)
        }
        .padding(16)
    }

    private var textContentType: UITextContentType? {
        switch label {
        case "Name": .name
        case "Phone number": .telephoneNumber
        case "Address": .fullStreetAddress
        default: nil
        }
    }
}

private struct EventCard: View {
    let event: HerdEvent
    let experience: HerdExperience.Home
    private let invitationExperience = HerdExperience.shared.invitation

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 10) {
                    Text(
                        event.eventDate?.formatted(date: .abbreviated, time: .shortened)
                            ?? experience.dateNotSet
                    )
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.8)

                    Spacer(minLength: 4)

                    Text(statusLabel)
                        .font(.caption.weight(.semibold))
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(HerdTheme.raisedSurface, in: .capsule)
                        .overlay {
                            Capsule()
                                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                        }

                    Image(systemName: "chevron.right")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.tertiary)
                }

                Text(event.title.isEmpty ? experience.untitledEvent : event.title)
                    .font(.title2.weight(.bold))
                    .multilineTextAlignment(.leading)
            }

            if !event.locationName.isEmpty {
                Label(event.locationName, systemImage: "mappin.and.ellipse")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 0) {
                metric(value: "\(event.invitees.count)", label: experience.metrics.invited)
                Rectangle()
                    .fill(HerdTheme.subtleBorder)
                    .frame(width: 1, height: 34)
                metric(value: "\(event.minimumParticipants)", label: experience.metrics.minimum)
                Rectangle()
                    .fill(HerdTheme.subtleBorder)
                    .frame(width: 1, height: 34)
                if event.resolution?.status == .confirmed {
                    metric(
                        value: "\(max(0, event.resolution?.attendingMemberIds?.count ?? 0))",
                        label: "attending"
                    )
                } else if event.resolution?.status == .notConfirmed {
                    metric(value: "No", label: "not confirmed")
                } else {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let countdown = responseCountdown(at: context.date)
                        metric(value: countdown.value, label: countdown.label)
                    }
                }
            }
        }
        .foregroundStyle(.primary)
        .wireframeCard(
            padding: CGFloat(experience.layout.cardPadding),
            cornerRadius: CGFloat(experience.layout.cardCornerRadius)
        )
    }

    private var statusLabel: String {
        if event.isHosted && !event.invitationsSent {
            return "Draft"
        }
        if event.hasUnavailableLegacyResult {
            return "Result unavailable"
        }
        if event.isHosted && event.invitationDelivery?.status == .attentionNeeded {
            return "Delivery issue"
        }
        if event.isHosted && event.invitationDelivery?.status == .inProgress {
            return "Sending"
        }
        switch event.resolution?.status {
        case .confirmed:
            return "Confirmed"
        case .notConfirmed:
            return "Not confirmed"
        case .verificationUnavailable:
            return "Result unavailable"
        case .pending:
            if event.resolution?.retrying == true {
                return "Taking longer"
            } else if let deadline = event.rsvpDeadline, deadline <= .now {
                return invitationExperience.status.finalizing
            } else {
                return invitationExperience.status.repliesOpen
            }
        case nil:
            return event.isHosted ? experience.hostStatus : experience.inviteeStatus
        }
    }

    private func metric(value: String, label: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.headline)
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.72)
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 10)
    }

    private func responseCountdown(at now: Date) -> (value: String, label: String) {
        guard let deadline = event.rsvpDeadline else {
            return ("—", experience.metrics.noDeadline)
        }

        let remaining = deadline.timeIntervalSince(now)
        guard remaining > 0 else {
            return ("Closed", experience.metrics.responsesClosed)
        }

        let totalSeconds = max(1, Int(remaining.rounded(.up)))
        let days = totalSeconds / (24 * 60 * 60)
        let hours = (totalSeconds % (24 * 60 * 60)) / (60 * 60)
        let minutes = (totalSeconds % (60 * 60)) / 60
        let seconds = totalSeconds % 60

        if days > 0 {
            return ("\(days)d \(hours)h", experience.metrics.leftToRespond)
        }

        if hours > 0 {
            return ("\(hours)h \(minutes)m", experience.metrics.leftToRespond)
        }

        return ("\(minutes)m \(seconds)s", experience.metrics.leftToRespond)
    }
}

private extension HerdEvent {
    var hasUnavailableLegacyResult: Bool {
        invitationsSent
            && privateResponsePolicy == nil
            && (resolution == nil || resolution?.status == .pending)
    }
}

private struct ResolvedAttendeeRow: Identifiable {
    let id: String
    let displayName: String
}

private struct InvitationDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(EventStore.self) private var store
    private let invitationExperience = HerdExperience.shared.invitation
    private let replyExperience = HerdExperience.shared.reply

    let eventID: UUID
    @State private var selectedResponse: RSVPResponse?
    @State private var isSubmitting = false
    @State private var showsSuccess = false
    @State private var showsConditionPicker = false
    @State private var conditionTargetGroupID: String?
    @State private var privateMinimumParticipants = 2
    @State private var privateRequiredGroups: [RSVPConditionGroup] = []

    private var event: HerdEvent? {
        store.events.first(where: { $0.id == eventID })
    }

    var body: some View {
        NavigationStack {
            Group {
                if let event {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            invitationHeader(event)
                            eventDetails(event)

                            if event.isHosted,
                               let delivery = event.invitationDelivery {
                                invitationDeliveryCard(delivery)
                            }

                            if event.hasUnavailableLegacyResult {
                                unavailableLegacyResultCard
                            } else if let resolution = event.resolution {
                                resolutionCard(resolution, event: event)
                            }

                            attendeeDetails(event)
                            privacyCallout(event)

                            if event.role == .invitee,
                               event.privateResponsePolicy != nil,
                               !replyIsClosed(for: event),
                               (event.resolution == nil || event.resolution?.status == .pending) {
                                replyCard(event)
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 14)
                        .padding(.bottom, 36)
                    }
                } else {
                    ContentUnavailableView(
                        invitationExperience.unavailableTitle,
                        systemImage: "envelope.badge",
                        description: Text(invitationExperience.unavailableBody)
                    )
                }
            }
            .background(HerdTheme.canvas)
            .navigationTitle(invitationExperience.navigationTitle)
            .navigationBarTitleDisplayMode(.inline)
            .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "chevron.left")
                    }
                    .accessibilityLabel("Back to Herd events")
                }
            }
        }
        .alert(
            replyExperience.reset.title,
            isPresented: Binding(
                get: { store.accountResetEventID == eventID },
                set: { isPresented in
                    if !isPresented { store.cancelAccountReset() }
                }
            )
        ) {
            Button(replyExperience.reset.cancelButton, role: .cancel) {
                store.cancelAccountReset()
            }
            Button(replyExperience.reset.confirmButton, role: .destructive) {
                Task {
                    if await store.startOverAccount(for: eventID) {
                        showsSuccess = true
                    }
                }
            }
        } message: {
            Text(replyExperience.reset.body)
        }
        .sheet(isPresented: $showsConditionPicker) {
            if let event {
                InvitationConditionPicker(
                    invitees: availableConditionInvitees(
                        in: event,
                        excluding: conditionTargetGroupID.flatMap { groupID in
                            privateRequiredGroups.first(where: { $0.id == groupID })?.memberIDs
                        } ?? []
                    ),
                    onSelect: { inviteeID in
                        if let groupID = conditionTargetGroupID {
                            addOrAlternative(inviteeID, to: groupID)
                        } else {
                            privateRequiredGroups.append(
                                RSVPConditionGroup(memberIDs: [inviteeID])
                            )
                        }
                        showsConditionPicker = false
                    }
                )
                .presentationDetents([.medium, .large])
            }
        }
        .fullScreenCover(isPresented: $showsSuccess) {
            if let event {
                InvitationResponseSuccess(
                    event: event,
                    response: selectedResponse ?? .cantCommit,
                    onViewInvitation: { showsSuccess = false },
                    onHome: {
                        showsSuccess = false
                        DispatchQueue.main.async { dismiss() }
                    }
                )
            }
        }
        .onAppear(perform: synchronizePrivateDraft)
        .onChange(of: store.unlockedDrafts[eventID]) { _, _ in
            synchronizePrivateDraft()
        }
    }

    private func invitationHeader(_ event: HerdEvent) -> some View {
        HStack(alignment: .top, spacing: 14) {
            VStack(alignment: .leading, spacing: 7) {
                Text(event.eventDate?.formatted(date: .abbreviated, time: .shortened)
                    ?? invitationExperience.dateNotSet)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(0.8)

                Text(event.title.isEmpty ? invitationExperience.untitledEvent : event.title)
                    .font(.largeTitle.weight(.bold))
                    .tracking(-0.7)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 4)

            Text(statusLabel(for: event))
                .font(.caption.weight(.bold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(HerdTheme.raisedSurface, in: .capsule)
                .overlay {
                    Capsule().stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func eventDetails(_ event: HerdEvent) -> some View {
        let outcomeMetric = detailOutcomeMetric(for: event)

        return VStack(alignment: .leading, spacing: 18) {
            VStack(alignment: .leading, spacing: 16) {
                InvitationMetaRow(
                    icon: "mappin",
                    title: event.locationName.isEmpty
                        ? invitationExperience.locationNotSet
                        : event.locationName,
                    detail: event.locationAddress
                )

                InvitationMetaRow(
                    icon: "crown",
                    title: "\(invitationExperience.hostPrefix) \(event.hostName.split(separator: " ").first.map(String.init) ?? event.hostName)",
                    detail: invitationExperience.hostMinimumNote
                )

                InvitationMetaRow(
                    icon: "clock",
                    title: event.rsvpDeadline.map {
                        "\(invitationExperience.replyByPrefix) \($0.formatted(date: .abbreviated, time: .shortened))"
                    } ?? invitationExperience.noReplyDeadline,
                    detail: replyIsClosed(for: event)
                        ? invitationExperience.responsesClosed
                        : "\(countdown(for: event)) \(invitationExperience.remainingSuffix)"
                )
            }

            if !event.eventDescription.isEmpty {
                Text(event.eventDescription)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: 0) {
                InvitationMetric(
                    value: "\(event.invitees.count)",
                    label: invitationExperience.metrics.invited
                )
                InvitationMetric(
                    value: "\(event.minimumParticipants)",
                    label: invitationExperience.metrics.minimum
                )
                InvitationMetric(
                    value: outcomeMetric.value,
                    label: outcomeMetric.label
                )
            }
        }
        .wireframeCard()
    }

    private func detailOutcomeMetric(for event: HerdEvent) -> (value: String, label: String) {
        switch event.resolution?.status {
        case .confirmed:
            return (
                "\(event.resolution?.attendingMemberIds?.count ?? 0)",
                invitationExperience.metrics.attending
            )
        case .notConfirmed:
            return ("No", invitationExperience.metrics.notConfirmed)
        case .verificationUnavailable:
            return ("—", "result unavailable")
        case .pending, nil:
            return (
                countdown(for: event),
                invitationExperience.metrics.leftToRespond
            )
        }
    }

    private func invitationDeliveryCard(
        _ delivery: InvitationDeliverySummary
    ) -> some View {
        let content = deliveryContent(for: delivery)
        let affectedGuests = delivery.guests.filter {
            $0.status == .failed || $0.status == .unknown
        }

        return VStack(alignment: .leading, spacing: 12) {
            Label(content.title, systemImage: content.icon)
                .font(.headline)

            Text(content.body)
                .font(.subheadline)
                .foregroundStyle(.secondary)

            if !affectedGuests.isEmpty {
                Divider()

                ForEach(affectedGuests, id: \.inviteeId) { guest in
                    HStack(alignment: .firstTextBaseline, spacing: 12) {
                        Text(guest.displayName)
                            .font(.subheadline.weight(.medium))
                            .frame(maxWidth: .infinity, alignment: .leading)

                        Text(deliveryStatusLabel(for: guest.status))
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func deliveryContent(
        for delivery: InvitationDeliverySummary
    ) -> (title: String, body: String, icon: String) {
        switch delivery.status {
        case .attentionNeeded:
            var details: [String] = []
            if delivery.counts.failed > 0 {
                let noun = delivery.counts.failed == 1
                    ? "invitation was"
                    : "invitations were"
                details.append(
                    "\(delivery.counts.failed) \(noun) rejected and not sent."
                )
            }
            if delivery.counts.unknown > 0 {
                let noun = delivery.counts.unknown == 1
                    ? "invitation"
                    : "invitations"
                details.append(
                    "Delivery could not be confirmed for \(delivery.counts.unknown) \(noun); Herd did not retry automatically to avoid duplicates."
                )
            }
            return (
                "Some invitations need attention",
                details.joined(separator: " "),
                "exclamationmark.triangle.fill"
            )
        case .inProgress:
            let remaining = delivery.counts.pending + delivery.counts.dispatching
            return (
                "Invitations are being submitted",
                "\(remaining) of \(delivery.total) are still being processed by the messaging provider.",
                "paperplane"
            )
        case .complete:
            return (
                "Invitations submitted",
                "The messaging provider accepted all \(delivery.total) invitations.",
                "checkmark.circle.fill"
            )
        case .suppressed:
            return (
                "Message delivery suppressed",
                "No invitation messages were sent for this event. Guests can still open it directly in Herd.",
                "message"
            )
        }
    }

    private func deliveryStatusLabel(for status: InvitationDeliveryStatus) -> String {
        switch status {
        case .failed:
            return "Not sent"
        case .unknown:
            return "Delivery unknown"
        case .pending:
            return "Pending"
        case .dispatching:
            return "Submitting"
        case .sent:
            return "Sent"
        case .suppressed:
            return "Suppressed"
        }
    }

    private var unavailableLegacyResultCard: some View {
        VStack(alignment: .leading, spacing: 10) {
            Label("Result unavailable", systemImage: "exclamationmark.lock.fill")
                .font(.headline)
            Text(
                "This older event was sent before private response evaluation was enabled, so Herd cannot safely finalize its result. Create a new event to use private finalization."
            )
            .font(.subheadline)
            .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func resolutionCard(
        _ resolution: EventResolution,
        event: HerdEvent
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            switch resolution.status {
            case .pending:
                if resolution.retrying == true {
                    Label("Taking longer than expected", systemImage: "clock.badge.exclamationmark")
                        .font(.headline)
                    Text("Herd couldn’t finalize the result yet and will retry automatically. No action is needed.")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                } else {
                    Label(invitationExperience.resolution.pendingTitle, systemImage: "lock.shield")
                        .font(.headline)
                    Text(invitationExperience.resolution.pendingBody)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
            case .confirmed:
                Label(invitationExperience.resolution.confirmedTitle, systemImage: "checkmark.seal.fill")
                    .font(.headline)
                Text(invitationExperience.resolution.confirmedBody)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                ForEach(resolvedAttendees(resolution, event: event)) { attendee in
                    Label(attendee.displayName, systemImage: "person.crop.circle.fill")
                        .font(.subheadline.weight(.medium))
                }
            case .notConfirmed:
                Label(invitationExperience.resolution.notConfirmedTitle, systemImage: "xmark.seal.fill")
                    .font(.headline)
                Text(invitationExperience.resolution.notConfirmedBody)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            case .verificationUnavailable:
                Label("Result verification unavailable", systemImage: "exclamationmark.shield.fill")
                    .font(.headline)
                Text("Herd will not show a final answer without the evaluator’s valid signed proof. This may be an older result or a temporary release-key mismatch.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            if let resolvedAt = resolution.resolvedAt {
                Text("\(invitationExperience.resolution.finalizedPrefix) \(resolvedAt.formatted(date: .abbreviated, time: .shortened))")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func resolvedAttendees(
        _ resolution: EventResolution,
        event: HerdEvent
    ) -> [ResolvedAttendeeRow] {
        (resolution.attendingMemberIds ?? []).compactMap { memberID in
            if memberID == "host" {
                return ResolvedAttendeeRow(id: "host", displayName: event.hostName)
            }
            guard let id = UUID(uuidString: memberID) else { return nil }
            guard let invitee = event.invitees.first(where: { $0.id == id }) else {
                return nil
            }
            return ResolvedAttendeeRow(
                id: invitee.id.uuidString.lowercased(),
                displayName: invitee.displayName
            )
        }
    }

    private func attendeeDetails(_ event: HerdEvent) -> some View {
        NavigationLink {
            InvitationAttendees(event: event)
        } label: {
            HStack(spacing: 13) {
                HStack(spacing: -9) {
                    ForEach(Array(event.invitees.prefix(3).enumerated()), id: \.element.id) { index, invitee in
                        Text(initials(for: invitee.displayName))
                            .font(.caption2.weight(.bold))
                            .frame(width: 36, height: 36)
                            .background(index.isMultiple(of: 2) ? HerdTheme.raisedSurface : HerdTheme.surface, in: .circle)
                            .overlay { Circle().stroke(HerdTheme.canvas, lineWidth: 2) }
                            .zIndex(Double(3 - index))
                    }
                }

                VStack(alignment: .leading, spacing: 3) {
                    Text("\(event.invitees.count) \(invitationExperience.attendeeEntry.peopleInvitedSuffix)")
                        .font(.headline)
                    Text(invitationExperience.attendeeEntry.action)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()
                Image(systemName: "chevron.right")
                    .font(.footnote.weight(.bold))
                    .foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(PlainPressButtonStyle())
        .wireframeCard()
    }

    private func privacyCallout(_ event: HerdEvent) -> some View {
        NavigationLink {
            InvitationPrivacyProof(event: event)
        } label: {
            HStack(alignment: .top, spacing: 14) {
                Image(systemName: "lock.fill")
                    .font(.headline)
                    .frame(width: 38, height: 38)
                    .background(HerdTheme.raisedSurface, in: .circle)

                VStack(alignment: .leading, spacing: 8) {
                    Text(invitationExperience.privacyCallout.title)
                        .font(.headline)
                    Text(invitationExperience.privacyCallout.body)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    HStack(spacing: 5) {
                        Text(invitationExperience.privacyCallout.action)
                            .underline()
                        Image(systemName: "chevron.right")
                            .font(.caption.weight(.bold))
                    }
                    .font(.subheadline.weight(.semibold))
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(PlainPressButtonStyle())
        .wireframeCard()
    }

    private func replyCard(_ event: HerdEvent) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 5) {
                Text(replyExperience.title)
                    .font(.title2.weight(.bold))
                Text(replyExperience.privacyNote)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            if event.hasResponse, store.unlockedResponses[event.id] == nil {
                Label(replyExperience.savedTitle, systemImage: "lock.fill")
                    .font(.subheadline.weight(.semibold))
                Button {
                    Task {
                        if await store.unlockPrivateResponse(for: event) {
                            synchronizePrivateDraft()
                        }
                    }
                } label: {
                    Label(replyExperience.unlockButton, systemImage: "faceid")
                        .frame(maxWidth: .infinity)
                }
                .buttonStyle(.bordered)
                .disabled(store.isMutating)
            }

            responseButton(
                title: "\(replyExperience.goingPrefix) \(privateMinimumParticipants) \(replyExperience.goingSuffix)",
                subtitle: replyExperience.conditionHelp,
                response: .going,
                prominent: true
            )

            if selectedResponse == .going {
                privateCriteriaEditor(event)
            }

            responseButton(
                title: replyExperience.cantCommitTitle,
                subtitle: replyExperience.cantCommitBody,
                response: .cantCommit,
                prominent: false
            )

            if replyIsClosed(for: event) {
                Label(replyExperience.closedMessage, systemImage: "clock.badge.exclamationmark")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } else if event.inviteToken == nil {
                Label(replyExperience.missingLinkMessage, systemImage: "link.badge.plus")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            }

            if let errorMessage = store.errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button {
                submitResponse(for: event)
            } label: {
                HStack(spacing: 10) {
                    if isSubmitting {
                        ProgressView().tint(.black)
                    }
                    Text(
                        isSubmitting
                            ? replyExperience.submittingButton
                            : selectedResponse == nil
                                ? replyExperience.chooseButton
                                : replyExperience.submitButton
                    )
                    .font(.headline)
                }
                .foregroundStyle(.black)
                .frame(maxWidth: .infinity)
                .padding(.vertical, 15)
                .background(.white, in: .rect(cornerRadius: 14))
            }
            .buttonStyle(PlainPressButtonStyle())
            .disabled(
                selectedResponse == nil || isSubmitting || store.isResettingAccount
                    || replyIsClosed(for: event) || event.inviteToken == nil
            )
            .opacity(selectedResponse == nil ? 0.45 : 1)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func responseButton(
        title: String,
        subtitle: String,
        response: RSVPResponse,
        prominent: Bool
    ) -> some View {
        let isSelected = selectedResponse == response

        return Button {
            selectedResponse = response
        } label: {
            HStack(spacing: 12) {
                Image(systemName: isSelected ? "checkmark.circle.fill" : "circle")
                    .font(.title3)
                    .frame(width: 24)

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .opacity(0.72)
                }

                Spacer()
            }
            .foregroundStyle(prominent ? Color.black : Color.primary)
            .padding(.horizontal, 16)
            .frame(minHeight: 62)
            .background(
                prominent ? Color.white : HerdTheme.raisedSurface,
                in: .rect(cornerRadius: 14)
            )
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
        }
        .buttonStyle(PlainPressButtonStyle())
    }

    private func privateCriteriaEditor(_ event: HerdEvent) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Stepper(
                value: $privateMinimumParticipants,
                in: max(2, event.minimumParticipants)...max(
                    max(2, event.minimumParticipants),
                    event.invitees.count + 1
                )
            ) {
                Text("\(replyExperience.goingPrefix) **\(privateMinimumParticipants)** \(replyExperience.goingSuffix)")
                    .font(.subheadline)
            }

            ForEach(privateRequiredGroups) { group in
                HStack(spacing: 8) {
                    Text(group.memberIDs.map(event.name(for:)).joined(separator: " OR "))
                        .font(.subheadline.weight(.medium))
                        .lineLimit(2)

                    Spacer()

                    Button {
                        conditionTargetGroupID = group.id
                        showsConditionPicker = true
                    } label: {
                        Image(systemName: "plus")
                    }
                    .disabled(availableConditionInvitees(in: event, excluding: group.memberIDs).isEmpty)

                    Button(role: .destructive) {
                        privateRequiredGroups.removeAll { $0.id == group.id }
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel(replyExperience.removeCondition)
                }
                .padding(10)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 10))
            }

            Button {
                conditionTargetGroupID = nil
                showsConditionPicker = true
            } label: {
                Label(replyExperience.addCondition, systemImage: "plus")
                    .font(.subheadline.weight(.semibold))
            }
            .disabled(availableConditionInvitees(in: event).isEmpty)

            Text(replyExperience.conditionHelp)
                .font(.caption)
                .foregroundStyle(.secondary)
        }
        .padding(12)
        .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
    }

    private func availableConditionInvitees(
        in event: HerdEvent,
        excluding additionalExcludedIDs: [UUID] = []
    ) -> [Invitee] {
        let selectedIDs = Set(privateRequiredGroups.flatMap(\.memberIDs))
            .subtracting(additionalExcludedIDs)
        return event.invitees.filter { invitee in
            !invitee.isCurrentUser
                && !selectedIDs.contains(invitee.id)
                && !additionalExcludedIDs.contains(invitee.id)
        }
    }

    private func addOrAlternative(_ inviteeID: UUID, to groupID: String) {
        guard let index = privateRequiredGroups.firstIndex(where: { $0.id == groupID }) else {
            return
        }
        privateRequiredGroups[index].memberIDs.append(inviteeID)
    }

    private func submitResponse(for event: HerdEvent) {
        guard let selectedResponse else { return }
        isSubmitting = true
        Task {
            let saved = await store.respond(
                to: event,
                draft: PrivateResponseDraft(
                    response: selectedResponse,
                    minimumParticipants: selectedResponse == .going
                        ? privateMinimumParticipants
                        : nil,
                    requiredGroups: selectedResponse == .going
                        ? privateRequiredGroups
                        : []
                )
            )
            isSubmitting = false
            if saved {
                showsSuccess = true
            }
        }
    }

    private func synchronizePrivateDraft() {
        guard let event else { return }
        if let draft = store.unlockedDrafts[eventID] {
            selectedResponse = draft.response
            privateMinimumParticipants = draft.minimumParticipants
                ?? max(2, event.minimumParticipants)
            privateRequiredGroups = draft.requiredGroups
        } else {
            selectedResponse = nil
            privateMinimumParticipants = max(2, event.minimumParticipants)
            privateRequiredGroups = []
        }
    }

    private func statusLabel(for event: HerdEvent) -> String {
        if event.hasUnavailableLegacyResult {
            return "Result unavailable"
        }
        if event.resolution?.status == .confirmed {
            return invitationExperience.status.confirmed
        }
        if event.resolution?.status == .notConfirmed {
            return invitationExperience.status.notConfirmed
        }
        if event.resolution?.status == .verificationUnavailable {
            return "Result unavailable"
        }
        if event.resolution?.status == .pending {
            if event.resolution?.retrying == true {
                return "Taking longer"
            }
            return replyIsClosed(for: event)
                ? invitationExperience.status.finalizing
                : invitationExperience.status.repliesOpen
        }
        if event.role == .host {
            return invitationExperience.status.hosting
        }
        return event.hasResponse
            ? invitationExperience.status.responded
            : invitationExperience.status.replyNeeded
    }

    private func countdown(for event: HerdEvent) -> String {
        guard let deadline = event.rsvpDeadline else { return "—" }
        let seconds = max(0, Int(deadline.timeIntervalSinceNow.rounded(.down)))
        guard seconds > 0 else { return "Closed" }
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return "\(days)d \(hours)h" }
        if hours > 0 { return "\(hours)h \(minutes)m" }
        return "\(minutes)m \(seconds % 60)s"
    }

    private func replyIsClosed(for event: HerdEvent) -> Bool {
        guard let deadline = event.rsvpDeadline else { return false }
        return deadline <= .now
    }

    private func dateSummary(for event: HerdEvent) -> String {
        guard let eventDate = event.eventDate else { return "Date to be announced" }
        if let endDate = event.endDate {
            return "\(eventDate.formatted(date: .abbreviated, time: .shortened)) – \(endDate.formatted(date: .omitted, time: .shortened))"
        }
        return eventDate.formatted(date: .abbreviated, time: .shortened)
    }

    private func locationSummary(for event: HerdEvent) -> String {
        if event.locationName.isEmpty && event.locationAddress.isEmpty {
            return "Location to be announced"
        }
        if event.locationName.isEmpty { return event.locationAddress }
        if event.locationAddress.isEmpty { return event.locationName }
        return "\(event.locationName)\n\(event.locationAddress)"
    }

    private func initials(for name: String) -> String {
        let components = name.split(whereSeparator: \.isWhitespace)
        if let first = components.first?.first, let last = components.dropFirst().last?.first {
            return "\(first)\(last)".uppercased()
        }
        return String(components.first?.prefix(2) ?? "?").uppercased()
    }
}

private struct InvitationMetaRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                if !detail.isEmpty {
                    Text(detail)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer(minLength: 0)
        }
    }
}

private struct InvitationMetric: View {
    let value: String
    let label: String

    var body: some View {
        VStack(spacing: 4) {
            Text(value)
                .font(.headline)
                .lineLimit(1)
                .minimumScaleFactor(0.72)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity)
    }
}

private struct InvitationAttendees: View {
    let event: HerdEvent
    private let experience = HerdExperience.shared.attendees

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                Text(experience.title)
                    .font(.largeTitle.weight(.bold))
                    .tracking(-0.7)
                    .padding(.top, 10)

                HStack(spacing: 13) {
                    avatar(for: event.hostName, emphasized: true)
                    VStack(alignment: .leading, spacing: 3) {
                        Text(experience.hostLabel)
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                        Text(event.hostName)
                            .font(.headline)
                    }
                    Spacer()
                }
                .wireframeCard()

                Text("\(event.invitees.count) \(experience.invitedSuffix)")
                    .font(.caption.weight(.bold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(0.8)

                if event.invitees.isEmpty {
                    Text(experience.emptyMessage)
                        .foregroundStyle(.secondary)
                        .wireframeCard()
                } else {
                    VStack(spacing: 0) {
                        ForEach(Array(event.invitees.enumerated()), id: \.element.id) { index, invitee in
                            HStack(spacing: 13) {
                                avatar(for: invitee.displayName, emphasized: index.isMultiple(of: 2))
                                Text(invitee.displayName)
                                    .font(.body.weight(.semibold))
                                Spacer()
                                if invitee.isCurrentUser {
                                    Text(experience.currentUserLabel)
                                        .font(.caption.weight(.bold))
                                        .foregroundStyle(.secondary)
                                }
                            }
                            .padding(.vertical, 12)
                            if index < event.invitees.count - 1 {
                                Divider().padding(.leading, 52)
                            }
                        }
                    }
                    .padding(.horizontal, 16)
                    .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                    .overlay {
                        RoundedRectangle(cornerRadius: 18)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.bottom, 32)
        }
        .background(HerdTheme.canvas)
        .navigationTitle(experience.navigationTitle)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
    }

    private func avatar(for name: String, emphasized: Bool) -> some View {
        let words = name.split(whereSeparator: \.isWhitespace)
        let initials = words.count > 1
            ? "\(words.first?.first.map(String.init) ?? "")\(words.last?.first.map(String.init) ?? "")"
            : String(words.first?.prefix(2) ?? "?")
        return Text(initials.uppercased())
            .font(.caption.weight(.bold))
            .frame(width: 40, height: 40)
            .background(emphasized ? HerdTheme.raisedSurface : HerdTheme.canvas, in: .circle)
            .overlay { Circle().stroke(HerdTheme.subtleBorder, lineWidth: 1) }
    }
}

private struct InvitationConditionPicker: View {
    @Environment(\.dismiss) private var dismiss
    let invitees: [Invitee]
    let onSelect: (UUID) -> Void
    private let experience = HerdExperience.shared.reply

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    VStack(alignment: .leading, spacing: 7) {
                        Text(experience.conditionPickerTitle)
                            .font(.title2.weight(.bold))
                        Text(experience.conditionPickerBody)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }

                    if invitees.isEmpty {
                        Text(experience.conditionPickerEmpty)
                            .foregroundStyle(.secondary)
                            .wireframeCard()
                    } else {
                        VStack(spacing: 0) {
                            ForEach(invitees) { invitee in
                                Button {
                                    onSelect(invitee.id)
                                } label: {
                                    HStack(spacing: 13) {
                                        Text(initials(for: invitee.displayName))
                                            .font(.caption.weight(.bold))
                                            .frame(width: 38, height: 38)
                                            .background(HerdTheme.raisedSurface, in: .circle)
                                        Text(invitee.displayName)
                                            .font(.body.weight(.semibold))
                                        Spacer()
                                        Image(systemName: "plus")
                                            .font(.subheadline.weight(.bold))
                                    }
                                    .padding(.vertical, 12)
                                    .contentShape(.rect)
                                }
                                .buttonStyle(PlainPressButtonStyle())
                                if invitee.id != invitees.last?.id {
                                    Divider().padding(.leading, 52)
                                }
                            }
                        }
                        .padding(.horizontal, 16)
                        .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                        .overlay {
                            RoundedRectangle(cornerRadius: 18)
                                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                        }
                    }
                }
                .padding(20)
            }
            .background(HerdTheme.canvas)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button {
                        dismiss()
                    } label: {
                        Image(systemName: "xmark")
                    }
                    .accessibilityLabel("Close")
                }
            }
        }
    }

    private func initials(for name: String) -> String {
        let words = name.split(whereSeparator: \.isWhitespace)
        if let first = words.first?.first, let last = words.dropFirst().last?.first {
            return "\(first)\(last)".uppercased()
        }
        return String(words.first?.prefix(2) ?? "?").uppercased()
    }
}

private struct InvitationPrivacyProof: View {
    let event: HerdEvent
    private let experience = HerdExperience.shared.privacy

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 26) {
                VStack(alignment: .leading, spacing: 9) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 34))
                        .frame(width: 66, height: 66)
                        .background(HerdTheme.raisedSurface, in: .circle)
                    eyebrow(experience.eyebrow)
                    Text(experience.title)
                        .font(.largeTitle.weight(.bold))
                        .tracking(-0.7)
                    Text(experience.intro)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 12) {
                    eyebrow(experience.statusEyebrow)
                    Text(experience.statusTitle).font(.title2.weight(.bold))
                    privacyStatusCard(
                        symbol: "checkmark",
                        label: experience.builtLabel,
                        title: experience.builtTitle,
                        body: experience.builtBody
                    )
                    privacyStatusCard(
                        symbol: "circle",
                        label: experience.pendingLabel,
                        title: experience.pendingTitle,
                        body: experience.pendingBody
                    )
                }

                VStack(alignment: .leading, spacing: 12) {
                    eyebrow(experience.flowEyebrow)
                    Text(experience.flowTitle).font(.title2.weight(.bold))
                    VStack(spacing: 10) {
                        flowNode(title: experience.flowSourceTitle, body: experience.flowSourceBody)
                        Image(systemName: "arrow.down").foregroundStyle(.secondary)
                        flowNode(title: experience.flowEnvelopeTitle, body: experience.flowEnvelopeBody)
                        Image(systemName: "arrow.down").foregroundStyle(.secondary)
                        flowNode(title: experience.flowDestinationTitle, body: experience.flowDestinationBody)
                    }
                    Text(experience.flowNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 12) {
                    eyebrow(experience.answersEyebrow)
                    Text(experience.answersTitle).font(.title2.weight(.bold))
                    Text(experience.answersIntro)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    ForEach(Array(experience.sections.enumerated()), id: \.element.id) { index, section in
                        PrivacyDisclosureSection(
                            section: section,
                            policy: index == 0 ? event.privateResponsePolicy : nil,
                            initiallyExpanded: index == 0
                        )
                    }
                }
            }
            .padding(.horizontal, 20)
            .padding(.top, 14)
            .padding(.bottom, 36)
        }
        .background(HerdTheme.canvas)
        .navigationTitle(experience.navigationTitle)
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
    }

    private func eyebrow(_ text: String) -> some View {
        Text(text)
            .font(.caption.weight(.bold))
            .foregroundStyle(.secondary)
            .textCase(.uppercase)
            .tracking(0.8)
    }

    private func privacyStatusCard(
        symbol: String,
        label: String,
        title: String,
        body: String
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(label, systemImage: symbol)
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(title).font(.headline)
            Text(body).font(.subheadline).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private func flowNode(title: String, body: String) -> some View {
        VStack(spacing: 5) {
            Text(title).font(.headline)
            Text(body).font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .wireframeCard(padding: 14, cornerRadius: 14)
    }
}

private struct PrivacyDisclosureSection: View {
    let section: HerdExperience.Privacy.Section
    let policy: PrivateResponsePolicyV1?
    @State private var isExpanded: Bool

    init(
        section: HerdExperience.Privacy.Section,
        policy: PrivateResponsePolicyV1?,
        initiallyExpanded: Bool
    ) {
        self.section = section
        self.policy = policy
        _isExpanded = State(initialValue: initiallyExpanded)
    }

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Array(section.paragraphs.enumerated()), id: \.offset) { index, paragraph in
                    Text(paragraph)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                    if index == 0, let policy {
                        VStack(alignment: .leading, spacing: 8) {
                            identifier("Protocol", "v\(policy.protocolVersion)")
                            identifier("Cipher suite", policy.cipherSuite)
                            identifier("Padded body", "\(policy.paddedPlaintextBytes) bytes")
                            identifier("Policy fingerprint", policy.policyHash)
                            identifier("Frozen", policy.frozenAt)
                            identifier("Declared release", policy.releaseId)
                            identifier("Evaluator key", policy.evaluatorKeyId)
                            identifier("Declared measurement", policy.evaluatorMeasurement)
                        }
                        .padding(12)
                        .background(HerdTheme.canvas, in: .rect(cornerRadius: 12))
                    }
                }
            }
            .padding(.top, 12)
        } label: {
            Text(section.title)
                .font(.headline)
        }
        .tint(.primary)
        .wireframeCard()
    }

    private func identifier(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption2.weight(.bold))
                .foregroundStyle(.secondary)
            Text(value)
                .font(.caption.monospaced())
                .textSelection(.enabled)
        }
    }
}

private struct InvitationResponseSuccess: View {
    let event: HerdEvent
    let response: RSVPResponse
    let onViewInvitation: () -> Void
    let onHome: () -> Void
    private let experience = HerdExperience.shared.success
    private let brand = HerdExperience.shared.authentication.brandName

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) {
                Image(systemName: "person.3.fill")
                    .font(.headline)
                    .foregroundStyle(.black)
                    .frame(width: 36, height: 36)
                    .background(.white, in: .rect(cornerRadius: 9))
                Text(brand).font(.headline.weight(.bold))
            }
            .padding(.horizontal, 22)
            .padding(.top, 22)

            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Image(systemName: "checkmark")
                        .font(.system(size: 38, weight: .bold))
                        .foregroundStyle(.black)
                        .frame(width: 78, height: 78)
                        .background(.white, in: .circle)

                    Text(experience.title)
                        .font(.largeTitle.weight(.bold))
                    Text(experience.body)
                        .font(.title3)
                        .foregroundStyle(.secondary)

                    VStack(alignment: .leading, spacing: 10) {
                        Text(experience.savedReplyLabel)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.secondary)
                        Text(experience.savedReplyTitle).font(.headline)
                        Text(response == .going ? experience.goingLabel : experience.cantCommitLabel)
                            .font(.subheadline.weight(.bold))
                            .padding(.horizontal, 10)
                            .padding(.vertical, 6)
                            .background(HerdTheme.raisedSurface, in: .capsule)
                        Text(response == .going ? experience.goingPrivacy : experience.cantCommitPrivacy)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .wireframeCard()

                    VStack(alignment: .leading, spacing: 8) {
                        Text(experience.visibilityLabel)
                            .font(.caption.weight(.bold))
                            .foregroundStyle(.secondary)
                        Text(experience.visibilityTitle).font(.headline)
                        Text(experience.visibilityBody)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .wireframeCard()
                }
                .padding(22)
            }

            VStack(spacing: 12) {
                Text(event.rsvpDeadline.map {
                    "\(experience.changeWithDeadlinePrefix) \($0.formatted(date: .abbreviated, time: .shortened))."
                } ?? experience.changeWithoutDeadline)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.center)

                Button(experience.viewInvitationButton, action: onViewInvitation)
                    .font(.headline)
                    .foregroundStyle(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .background(.white, in: .rect(cornerRadius: 14))
                    .buttonStyle(PlainPressButtonStyle())

                Button(experience.homeButton, action: onHome)
                    .font(.headline)
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
                    .overlay {
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                    .buttonStyle(PlainPressButtonStyle())
            }
            .padding(20)
            .background(HerdTheme.canvas)
        }
        .background(HerdTheme.canvas)
    }
}

private struct InvitationInfoRow: View {
    let icon: String
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: icon)
                .font(.body.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 8))

            VStack(alignment: .leading, spacing: 3) {
                Text(label)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text(value)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(14)
    }
}

#Preview("Empty") {
    HomeView()
        .environment(AuthStore(apiClient: APIClient()))
        .environment(EventStore(defaults: UserDefaults(suiteName: "HomePreview")!))
        .preferredColorScheme(.dark)
}
