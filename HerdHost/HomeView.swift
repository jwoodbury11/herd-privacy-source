import SwiftUI
import UIKit

struct HomeView: View {
    @Environment(EventStore.self) private var store
    @Environment(AuthStore.self) private var authStore
    @Environment(InvitationCoordinator.self) private var invitationCoordinator
    @Environment(\.scenePhase) private var scenePhase
    @State private var presentation: Presentation?
    @State private var pastEventsExpanded = false
    @State private var unconfirmedEventsExpanded = false
    private let experience = HerdExperience.shared.home
    private static let maximumDeadlineSleepInterval: TimeInterval = 31_536_000
    private static let automaticRefreshInterval: UInt64 = 60_000_000_000

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
                    spacing: CGFloat(experience.layout.sectionGap)
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
                    } else {
                        if !invitedEvents.isEmpty {
                            eventSection(
                                title: experience.invitesSectionTitle,
                                events: invitedEvents
                            )
                        }
                        eventSection(
                            title: experience.hostedSectionTitle,
                            events: hostedEvents,
                            showsCreateAction: true
                        )
                        if !pastEvents.isEmpty {
                            collapsibleEventSection(
                                title: experience.pastSectionTitle,
                                events: pastEvents,
                                isExpanded: $pastEventsExpanded
                            )
                        }
                        if !unconfirmedEvents.isEmpty {
                            collapsibleEventSection(
                                title: experience.unconfirmedSectionTitle,
                                events: unconfirmedEvents,
                                note: experience.unconfirmedSectionNote,
                                isExpanded: $unconfirmedEventsExpanded
                            )
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
        .onChange(of: scenePhase) { _, phase in
            guard phase == .active else { return }
            Task {
                await store.refresh()
            }
        }
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
        .task {
            while !Task.isCancelled {
                do {
                    try await Task.sleep(nanoseconds: Self.automaticRefreshInterval)
                } catch {
                    return
                }
                guard scenePhase == .active else { continue }
                await store.refresh()
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
                .contentShape(Rectangle())
        }
        .buttonStyle(PlainPressButtonStyle())
        .accessibilityHint(
            event.isHosted && !event.invitationsSent
                ? "Opens this draft for editing"
                : "Opens event details"
        )
    }

    private var invitedEvents: [HerdEvent] {
        events(in: .invites)
    }

    private var hostedEvents: [HerdEvent] {
        events(in: .hosted)
    }

    private var unconfirmedEvents: [HerdEvent] {
        events(in: .unconfirmed)
    }

    private var pastEvents: [HerdEvent] {
        events(in: .past)
    }

    private func events(in section: EventHomeSection) -> [HerdEvent] {
        store.events.filter { $0.homeSection() == section }
    }

    private func eventSection(
        title: String?,
        events: [HerdEvent],
        showsCreateAction: Bool = false
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            if let title {
                Text(title)
                    .font(.headline)
                    .padding(.horizontal, 4)
            }

            ForEach(events) { event in
                eventButton(for: event)
            }

            if showsCreateAction {
                CreateEventCard(experience: experience) {
                    presentation = .create(.newDraft(hostName: profileName))
                }
            }
        }
    }

    private func collapsibleEventSection(
        title: String,
        events: [HerdEvent],
        note: String? = nil,
        isExpanded: Binding<Bool>
    ) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Button {
                withAnimation(.easeInOut(duration: 0.16)) {
                    isExpanded.wrappedValue.toggle()
                }
            } label: {
                HStack(spacing: 12) {
                    VStack(alignment: .leading, spacing: 3) {
                        Text(title)
                            .font(.headline)
                        if let note {
                            Text(note)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .multilineTextAlignment(.leading)
                        }
                    }

                    Spacer(minLength: 8)

                    Image(systemName: "chevron.right")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.tertiary)
                        .rotationEffect(.degrees(isExpanded.wrappedValue ? 90 : 0))
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
                .padding(.horizontal, 4)
            }
            .buttonStyle(PlainButtonStyle())
            .accessibilityLabel(title)
            .accessibilityValue(isExpanded.wrappedValue ? "Expanded" : "Collapsed")

            if isExpanded.wrappedValue {
                ForEach(events) { event in
                    eventButton(for: event)
                }
            }
        }
    }

    private var homeHeader: some View {
        HStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 3) {
                Text(experience.title)
                    .font(.largeTitle.weight(.bold))
                    .tracking(-0.7)

                TimelineView(.periodic(from: .now, by: 60)) { context in
                    Text(lastUpdatedText(at: context.date))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            NavigationLink {
                AccountStatusView()
            } label: {
                Image(systemName: "waveform.path.ecg")
                    .font(.system(size: 18, weight: .regular))
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
            .accessibilityLabel("Account status")
            .accessibilityIdentifier("events-status")

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
    }

    private func lastUpdatedText(at now: Date) -> String {
        guard let lastUpdatedAt = store.lastUpdatedAt else {
            return store.isRefreshing ? "Updating…" : "Not updated yet"
        }
        let elapsed = max(0, Int(now.timeIntervalSince(lastUpdatedAt)))
        if elapsed < 60 {
            return "Last updated just now"
        }
        if elapsed < 3_600 {
            let minutes = elapsed / 60
            return "Last updated \(minutes) \(minutes == 1 ? "minute" : "minutes") ago"
        }
        if elapsed < 86_400 {
            let hours = elapsed / 3_600
            return "Last updated \(hours) \(hours == 1 ? "hour" : "hours") ago"
        }
        let days = elapsed / 86_400
        return "Last updated \(days) \(days == 1 ? "day" : "days") ago"
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
        let cardPadding = CGFloat(experience.layout.cardPadding)
        let cardMinimumHeight = CGFloat(experience.layout.cardMinimumHeight)

        Button(action: action) {
            VStack(spacing: 12) {
                Image(systemName: "plus")
                    .font(.title2.weight(.medium))
                Text(experience.createEventTitle)
                    .font(.headline)
            }
            .frame(
                maxWidth: .infinity,
                minHeight: max(0, cardMinimumHeight - (cardPadding * 2))
            )
            .padding(cardPadding)
            .overlay {
                RoundedRectangle(cornerRadius: CGFloat(experience.layout.cardCornerRadius))
                    .strokeBorder(
                        Color.secondary.opacity(0.65),
                        style: StrokeStyle(lineWidth: 1.25, dash: [7, 5])
                    )
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(PlainPressButtonStyle())
        .accessibilityHint("Opens the event creation form")
    }
}

private struct AccountStatusView: View {
    @Environment(EventStore.self) private var store
    @Environment(AuthStore.self) private var authStore
    @State private var checkedAt: Date?
    @State private var isChecking = false

    private var invitedEvents: [HerdEvent] {
        store.events.filter { $0.role == .invitee }
    }

    private var activeInvitationCount: Int {
        invitedEvents.filter { InvitationToken.normalize($0.inviteToken) != nil }.count
    }

    private var verificationIssueCount: Int {
        store.events.filter { $0.resolution?.status == .verificationUnavailable }.count
    }

    private var overallState: StatusState {
        guard authStore.isAuthenticated else { return .problem }
        if store.errorMessage != nil || store.isUsingCachedData || verificationIssueCount > 0 {
            return .attention
        }
        return .healthy
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                statusSummary
                accountSection
                connectionSection
                securitySection
                trustSection
            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 28)
        }
        .background(HerdTheme.canvas)
        .navigationTitle("Account status")
        .navigationBarTitleDisplayMode(.inline)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarTrailing) {
                Button {
                    Task { await runChecks() }
                } label: {
                    if isChecking {
                        ProgressView()
                    } else {
                        Image(systemName: "arrow.clockwise")
                    }
                }
                .disabled(isChecking)
                .accessibilityLabel("Run status checks")
                .accessibilityIdentifier("account-status-run-checks")
            }
        }
        .task { await runChecks() }
    }

    private var statusSummary: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: overallState.symbol)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(overallState.color)
                .frame(width: 34, height: 34)
                .background(overallState.color.opacity(0.12), in: .circle)

            VStack(alignment: .leading, spacing: 4) {
                Text(overallState == .healthy ? "Everything looks good" : "Some checks need attention")
                    .font(.subheadline.weight(.semibold))
                Text(summaryDetail)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let checkedAt {
                    Text("Checked \(checkedAt.formatted(date: .omitted, time: .shortened))")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .padding(.top, 2)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .wireframeCard()
    }

    private var summaryDetail: String {
        switch overallState {
        case .healthy:
            "Your account, event sync, and private reply access checks passed."
        case .attention:
            "Open the checks below to see what may prevent sync or private replies."
        case .problem:
            "Your account session is unavailable. Sign in again to restore access."
        case .notConfigured:
            "This check is not needed yet."
        }
    }

    private var accountSection: some View {
        statusSection("Account") {
            StatusRow(
                state: authStore.isAuthenticated ? .healthy : .problem,
                icon: "person.crop.circle",
                title: "Signed-in session",
                detail: authStore.isAuthenticated ? maskedPhone : "No active account session"
            )
            Divider().padding(.leading, 46)
            StatusRow(
                state: activeInvitationCount > 0 ? .healthy : .notConfigured,
                icon: "link",
                title: "Invitation access",
                detail: activeInvitationCount == 0
                    ? "No active invitation links on this account"
                    : "\(activeInvitationCount) active invitation \(activeInvitationCount == 1 ? "link" : "links")"
            )
        }
    }

    private var connectionSection: some View {
        statusSection("Connections") {
            StatusRow(
                state: connectionState,
                icon: "network",
                title: "Herd services",
                detail: connectionDetail,
                value: APIClient.configuredBaseURL.host
            )
            Divider().padding(.leading, 46)
            StatusRow(
                state: store.lastUpdatedAt == nil ? .attention : connectionState,
                icon: "arrow.triangle.2.circlepath",
                title: "Event sync",
                detail: lastSyncDetail
            )
        }
    }

    private var securitySection: some View {
        statusSection("Private reply security") {
            StatusRow(
                state: authStore.user == nil ? .notConfigured : .healthy,
                icon: "key.fill",
                title: authStore.user == nil
                    ? "Sign in to view private replies"
                    : "Private replies available",
                detail: authStore.user == nil
                    ? "Private replies are connected to your account."
                    : "Your private replies are available anywhere you sign in to this account."
            )
        }
    }

    private var trustSection: some View {
        statusSection("Event results") {
            StatusRow(
                state: verificationIssueCount == 0 ? .healthy : .problem,
                icon: "shield.lefthalf.filled",
                title: "Result checks",
                detail: verificationIssueCount == 0
                    ? "No event result issues detected"
                    : "\(verificationIssueCount) event \(verificationIssueCount == 1 ? "needs" : "need") attention"
            )
        }
    }

    private var connectionState: StatusState {
        if store.errorMessage != nil || store.isUsingCachedData { return .attention }
        return store.lastUpdatedAt == nil ? .attention : .healthy
    }

    private var connectionDetail: String {
        if let errorMessage = store.errorMessage { return errorMessage }
        if store.isUsingCachedData { return "Connected with some locally cached event data" }
        return store.lastUpdatedAt == nil ? "Waiting for the first server check" : "Authenticated API access is working"
    }

    private var lastSyncDetail: String {
        guard let lastUpdatedAt = store.lastUpdatedAt else { return "Events have not synced yet" }
        return "Last successful sync \(lastUpdatedAt.formatted(date: .abbreviated, time: .shortened))"
    }

    private var maskedPhone: String {
        guard let phone = authStore.user?.phoneNumber else { return "Active account" }
        let suffix = phone.suffix(4)
        return suffix.isEmpty ? "Active account" : "Phone ending in \(suffix)"
    }

    @ViewBuilder
    private func statusSection<Content: View>(
        _ title: String,
        @ViewBuilder content: () -> Content
    ) -> some View {
        VStack(alignment: .leading, spacing: 9) {
            Text(title.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)
            VStack(spacing: 0) { content() }
                .wireframeCard(padding: 0)
        }
    }

    private func runChecks() async {
        guard !isChecking else { return }
        isChecking = true
        await store.refresh()
        checkedAt = .now
        isChecking = false
    }
}

private enum StatusState: Equatable {
    case healthy
    case attention
    case problem
    case notConfigured

    var symbol: String {
        switch self {
        case .healthy: "checkmark.circle.fill"
        case .attention: "exclamationmark.triangle.fill"
        case .problem: "xmark.circle.fill"
        case .notConfigured: "minus.circle.fill"
        }
    }

    var color: Color {
        switch self {
        case .healthy: .green
        case .attention: .orange
        case .problem: .red
        case .notConfigured: .secondary
        }
    }
}

private struct StatusRow: View {
    let state: StatusState
    let icon: String
    let title: String
    let detail: String
    var value: String? = nil

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 16, weight: .medium))
                .foregroundStyle(state.color)
                .frame(width: 34, height: 34)
                .background(state.color.opacity(0.12), in: .circle)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(detail)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let value {
                    Text(value)
                        .font(.caption.monospaced())
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                        .minimumScaleFactor(0.75)
                        .padding(.top, 2)
                }
            }

            Spacer(minLength: 8)

            Image(systemName: state.symbol)
                .font(.caption)
                .foregroundStyle(state.color)
                .frame(width: 18, height: 34)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct ProfileView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AuthStore.self) private var authStore
    private let experience = HerdExperience.shared.profile
    @State private var name = ""
    @State private var address = ""
    @State private var hasLoadedProfile = false
    @State private var showsAddressSearch = false
    @State private var showsUnsavedChangesConfirmation = false
    @State private var showsLogoutConfirmation = false
    @State private var showsAccountDeletionConfirmation = false
    @State private var showsAccountDeletionVerification = false
    @State private var accountDeletionCode = ""
    @FocusState private var isNameFocused: Bool

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(experience.title)
                        .font(.largeTitle.weight(.bold))
                        .tracking(-0.7)

                    Text(experience.syncNote)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.top, 10)

                VStack(spacing: 0) {
                    ProfileField(
                        label: experience.nameLabel,
                        placeholder: experience.namePlaceholder,
                        text: $name,
                        accessibilityIdentifier: "profile-name",
                        isFocused: $isNameFocused
                    )

                    Divider()
                        .padding(.leading, 16)

                    ProfileValue(
                        label: experience.phoneLabel,
                        value: authStore.user?.phoneNumber ?? "Unavailable",
                        explanation: experience.phoneImmutableMessage
                    )

                    Divider()
                        .padding(.leading, 16)

                    ProfileAddressPicker(
                        label: experience.addressLabel,
                        placeholder: experience.addressPlaceholder,
                        address: $address,
                        onSelect: {
                            showsAddressSearch = true
                        }
                    )
                }
                .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
                .overlay {
                    RoundedRectangle(cornerRadius: 18)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }

                profileAccountActions

                if let errorMessage = authStore.errorMessage {
                    Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                        .font(.footnote)
                        .foregroundStyle(.red)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.horizontal, 4)
                }

            }
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 24)
        }
        .background(HerdTheme.canvas)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            saveFooter
        }
        .navigationTitle("")
        .navigationBarBackButtonHidden(true)
        .navigationBarTitleDisplayMode(.inline)
        .toolbar(.visible, for: .navigationBar)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
        .toolbar {
            ToolbarItem(placement: .topBarLeading) {
                Button {
                    if profileHasChanges {
                        showsUnsavedChangesConfirmation = true
                    } else {
                        dismiss()
                    }
                } label: {
                    Image(systemName: "chevron.left")
                }
                .accessibilityLabel("Back to Herd events")
                .accessibilityIdentifier("profile-back")
                .disabled(authStore.isBusy)
            }

            ToolbarItem(placement: .topBarTrailing) {
                Menu {
                    Button(role: .destructive) {
                        showsAccountDeletionConfirmation = true
                    } label: {
                        Label {
                            Text(experience.deleteAccountButton)
                        } icon: {
                            Image(systemName: "trash")
                                .symbolRenderingMode(.monochrome)
                                .foregroundStyle(.red)
                        }
                    }
                    .tint(.red)
                    .accessibilityIdentifier("profile-delete-account")
                } label: {
                    Image(systemName: "ellipsis")
                        .font(.system(size: 18, weight: .semibold))
                        .frame(width: 44, height: 44)
                        .contentShape(Rectangle())
                }
                .accessibilityLabel("More profile actions")
                .accessibilityIdentifier("profile-more-actions")
                .disabled(authStore.isBusy)
            }
        }
        .alert(
            experience.unsavedChanges.title,
            isPresented: $showsUnsavedChangesConfirmation
        ) {
            Button(experience.unsavedChanges.cancelButton, role: .cancel) {}
            Button(experience.unsavedChanges.confirmButton, role: .destructive) {
                dismiss()
            }
        } message: {
            Text(experience.unsavedChanges.body)
        }
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
            isPresented: $showsAddressSearch
        ) {
            AddressSearchView(address: $address)
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
            isNameFocused = false
            Task {
                _ = await authStore.updateProfile(name: name, address: address)
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
            .foregroundStyle(profileHasChanges ? Color.black : Color.secondary)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 15)
            .contentShape(Rectangle())
            .background(
                profileHasChanges ? Color.white : HerdTheme.raisedSurface,
                in: .rect(cornerRadius: 14)
            )
        }
        .buttonStyle(PlainPressButtonStyle())
        .disabled(authStore.isBusy || !profileHasChanges)
        .opacity(authStore.isBusy || !profileHasChanges ? 0.48 : 1)
        .accessibilityIdentifier("profile-save-changes")
    }

    private var saveFooter: some View {
        saveButton
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 8)
            .background(HerdTheme.canvas)
    }

    private var profileAccountActions: some View {
        Button {
            showsLogoutConfirmation = true
        } label: {
            Label {
                Text(experience.logoutButton)
            } icon: {
                Image(systemName: "rectangle.portrait.and.arrow.right")
            }
            .frame(minHeight: 44)
            .contentShape(Rectangle())
        }
        .foregroundStyle(.secondary)
        .font(.footnote.weight(.semibold))
        .buttonStyle(.plain)
        .accessibilityHint("Signs out after confirmation")
        .accessibilityIdentifier("profile-log-out")
        .disabled(authStore.isBusy)
        .opacity(authStore.isBusy ? 0.42 : 1)
        .padding(.horizontal, 4)
    }

    private var profileHasChanges: Bool {
        guard let user = authStore.user else { return false }
        return name.trimmingCharacters(in: .whitespacesAndNewlines) !=
            user.name.trimmingCharacters(in: .whitespacesAndNewlines) ||
            address.trimmingCharacters(in: .whitespacesAndNewlines) !=
            user.address.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct ProfileValue: View {
    let label: String
    let value: String
    let explanation: String
    @State private var showsExplanation = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.tertiary)

            HStack(spacing: 12) {
                Text(value)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)

                Spacer(minLength: 8)

                Button {
                    showsExplanation.toggle()
                } label: {
                    Image(systemName: "info.circle")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.secondary)
                        .frame(width: 28, height: 28)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(explanation)
                .popover(isPresented: $showsExplanation, arrowEdge: .top) {
                    Text(explanation)
                        .font(.footnote)
                        .padding(14)
                        .frame(maxWidth: 240)
                        .presentationCompactAdaptation(.popover)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(16)
        .background(HerdTheme.raisedSurface.opacity(0.32))
    }
}

private struct ProfileField: View {
    let label: String
    let placeholder: String
    @Binding var text: String
    var accessibilityIdentifier: String
    var keyboardType: UIKeyboardType = .default
    var axis: Axis = .horizontal
    var isFocused: FocusState<Bool>.Binding

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            HStack(alignment: axis == .vertical ? .top : .center, spacing: 10) {
                TextField(placeholder, text: $text, axis: axis)
                    .keyboardType(keyboardType)
                    .textContentType(textContentType)
                    .lineLimit(axis == .vertical ? 2...4 : 1...1)
                    .focused(isFocused)
                    .accessibilityIdentifier(accessibilityIdentifier)

                if isFocused.wrappedValue && !text.isEmpty {
                    Button {
                        text = ""
                        isFocused.wrappedValue = true
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.tertiary)
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear \(label)")
                }
            }
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

private struct ProfileAddressPicker: View {
    let label: String
    let placeholder: String
    @Binding var address: String
    let onSelect: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)

            Button(action: onSelect) {
                Text(trimmedAddress.isEmpty ? placeholder : trimmedAddress)
                    .foregroundStyle(trimmedAddress.isEmpty ? .tertiary : .primary)
                    .multilineTextAlignment(.leading)
                    .lineLimit(1)
                    .truncationMode(.tail)
                    .frame(maxWidth: .infinity, minHeight: 34, alignment: .leading)
                    .contentShape(.rect)
            }
            .buttonStyle(.plain)
            .accessibilityLabel(label)
            .accessibilityValue(trimmedAddress.isEmpty ? "Not set" : trimmedAddress)
            .accessibilityHint("Opens address search suggestions")
            .accessibilityIdentifier("profile-address")
        }
        .padding(16)
    }

    private var trimmedAddress: String {
        address.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct EventCard: View {
    let event: HerdEvent
    let experience: HerdExperience.Home

    var body: some View {
        let cardPadding = CGFloat(experience.layout.cardPadding)
        let cardMinimumHeight = CGFloat(experience.layout.cardMinimumHeight)

        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(alignment: .top, spacing: 10) {
                    Text(event.title.isEmpty ? experience.untitledEvent : event.title)
                        .font(.title2.weight(.bold))
                        .multilineTextAlignment(.leading)
                        .layoutPriority(1)

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
                }

                Text(formattedCardDate)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }

            if !event.locationName.isEmpty {
                Label(event.locationName, systemImage: "mappin.and.ellipse")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 0) {
                metric(value: "\(event.participantCount)", label: experience.metrics.invited)
                Rectangle()
                    .fill(HerdTheme.subtleBorder)
                    .frame(width: 1, height: 34)
                metric(value: "\(event.minimumParticipants)", label: experience.metrics.minimum)
                Rectangle()
                    .fill(HerdTheme.subtleBorder)
                    .frame(width: 1, height: 34)
                if event.resolution?.status == .confirmed {
                    metric(
                        value: event.resolution?.attendanceRevealed == true
                            ? "\(event.resolution?.attendingMemberIds?.count ?? 0)"
                            : "—",
                        label: "attending"
                    )
                } else if event.canViewResponseProgress {
                    metric(
                        value: "\(event.respondedInviteeCount)",
                        label: "responded"
                    )
                } else {
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        let countdown = responseCountdown(at: context.date)
                        metric(value: countdown.value, label: countdown.label)
                    }
                }
            }
        }
        .frame(
            maxWidth: .infinity,
            minHeight: max(0, cardMinimumHeight - (cardPadding * 2)),
            alignment: .leading
        )
        .foregroundStyle(.primary)
        .wireframeCard(
            padding: cardPadding,
            cornerRadius: CGFloat(experience.layout.cardCornerRadius)
        )
    }

    private var formattedCardDate: String {
        guard let eventDate = event.eventDate else { return experience.dateNotSet }
        let weekdayAndDate = Self.cardWeekdayAndDateFormatter.string(from: eventDate)
        let time = Self.cardTimeFormatter.string(from: eventDate)
            .replacingOccurrences(of: " ", with: "")
            .lowercased()
        return "\(weekdayAndDate) at \(time)"
    }

    private static let cardWeekdayAndDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "EEE M/d"
        return formatter
    }()

    private static let cardTimeFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "ha"
        return formatter
    }()

    private var statusLabel: String {
        event.userFacingStatusLabel()
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
            return ("Passed", experience.metrics.responsesClosed)
        }

        let totalSeconds = max(1, Int(remaining.rounded(.up)))
        let days = totalSeconds / (24 * 60 * 60)
        let hours = (totalSeconds % (24 * 60 * 60)) / (60 * 60)
        let minutes = (totalSeconds % (60 * 60)) / 60
        let seconds = totalSeconds % 60

        if days > 0 {
            return ("\(days)d \(hours)h", "left to respond")
        }

        if hours > 0 {
            return ("\(hours)h \(minutes)m", "left to respond")
        }

        if minutes > 0 {
            return ("\(minutes)m \(seconds)s", "left to respond")
        }

        return ("\(seconds)s", "left to respond")
    }
}

private extension HerdEvent {
    var canViewResponseProgress: Bool {
        role == .host || hasResponse || hasBallot
    }

    var respondedInviteeCount: Int {
        invitees.filter { $0.hasResponded == true }.count
    }

    var hasUnavailableLegacyResult: Bool {
        invitationsSent
            && privateResponsePolicy == nil
            && (resolution == nil || resolution?.status == .pending)
    }

    func userFacingStatusLabel(at now: Date = .now) -> String {
        let status = HerdExperience.shared.invitation.status

        if isHosted && !invitationsSent {
            return status.draft
        }

        if resolution?.status == .confirmed {
            return status.confirmed
        }

        return rsvpDeadline.map { $0 <= now } == true
            ? status.notConfirmed
            : status.unconfirmed
    }
}

private struct InvitationTitleBottomPreferenceKey: PreferenceKey {
    static var defaultValue: CGFloat = .infinity

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

private struct InvitationDetailView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(AuthStore.self) private var authStore
    @Environment(EventStore.self) private var store
    private let invitationExperience = HerdExperience.shared.invitation
    private let replyExperience = HerdExperience.shared.reply

    let eventID: UUID
    @State private var selectedResponse: RSVPResponse?
    @State private var isSubmitting = false
    @State private var isReplacingUnavailableReply = false
    @State private var showsSuccess = false
    @State private var showsConditionPicker = false
    @State private var showsReplyPreview = false
    @State private var conditionTargetGroupID: String?
    @State private var privateMinimumParticipants = 2
    @State private var privateRequiredGroups: [RSVPConditionGroup] = []
    @State private var savedPrivateDraft: PrivateResponseDraft?
    @State private var showsCollapsedEventTitle = false
    @State private var showsEventDeletionConfirmation = false
    @State private var eventDeletionError: String?
    @State private var confirmedReplyNoticeID: UUID?
    @State private var addressCopiedNoticeID: UUID?

    private var event: HerdEvent? {
        store.events.first(where: { $0.id == eventID })
    }

    var body: some View {
        NavigationStack {
            Group {
                if let event {
                    ScrollView {
                        VStack(alignment: .leading, spacing: 20) {
                            if let errorMessage = store.errorMessage {
                                SyncMessageCard(
                                    message: errorMessage,
                                    isCached: store.isUsingCachedData
                                ) {
                                    Task {
                                        await store.refresh()
                                    }
                                }
                                .accessibilityIdentifier("invitation-detail-error")
                            }

                            invitationHeader(event)
                            eventNotices(event)
                            eventDetails(event)

                            VStack(alignment: .leading, spacing: 16) {
                                if !(event.resolution?.status == .notConfirmed &&
                                     event.rsvpDeadline.map { $0 <= .now } == true) {
                                    attendeeDetails(event)
                                }
                                privacyCallout(event)
                            }
                            .padding(.top, -4)

                            if event.role == .invitee,
                               event.privateResponsePolicy != nil {
                                replyCard(event)
                                    .padding(.top, 12)
                            }
                        }
                        .padding(.horizontal, 20)
                        .padding(.top, 14)
                        .padding(.bottom, 36)
                    }
                    .coordinateSpace(name: "invitation-detail-scroll")
                    .onPreferenceChange(InvitationTitleBottomPreferenceKey.self) { titleBottom in
                        showsCollapsedEventTitle = titleBottom <= 0
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
            .navigationTitle(collapsedEventTitle)
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

                if event?.isHosted == true {
                    ToolbarItem(placement: .primaryAction) {
                        Menu {
                            Button(role: .destructive) {
                                showsEventDeletionConfirmation = true
                            } label: {
                                Label(
                                    invitationExperience.eventActions.deleteButton,
                                    systemImage: "trash"
                                )
                                .foregroundStyle(.red)
                            }
                            .accessibilityIdentifier("delete-hosted-event")
                        } label: {
                            Image(systemName: "ellipsis")
                        }
                        .accessibilityLabel(invitationExperience.eventActions.moreLabel)
                        .accessibilityIdentifier("event-actions-menu")
                        .disabled(store.isMutating)
                    }
                }
            }
        }
        .alert(
            invitationExperience.eventActions.deletionTitle,
            isPresented: $showsEventDeletionConfirmation
        ) {
            Button(invitationExperience.eventActions.cancelButton, role: .cancel) {}
            Button(invitationExperience.eventActions.confirmButton, role: .destructive) {
                deleteHostedEvent()
            }
            .accessibilityIdentifier("confirm-delete-hosted-event")
        } message: {
            Text(invitationExperience.eventActions.deletionBody)
        }
        .alert(
            invitationExperience.eventActions.failureTitle,
            isPresented: Binding(
                get: { eventDeletionError != nil },
                set: { if !$0 { eventDeletionError = nil } }
            )
        ) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(eventDeletionError ?? invitationExperience.eventActions.failureBody)
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
        .sheet(isPresented: $showsReplyPreview) {
            if let event {
                replyVisibilityPreviewSheet(event)
                    .presentationDetents([.medium])
                    .presentationDragIndicator(.visible)
            }
        }
        .fullScreenCover(isPresented: $showsSuccess) {
            if let event {
                InvitationResponseSuccess(
                    response: selectedResponse ?? .cantCommit,
                    displayName: event.invitees.first(where: \.isCurrentUser)?.displayName
                        ?? HerdExperience.shared.attendees.currentUserLabel,
                    onViewInvitation: {
                        showsSuccess = false
                        lockPrivateReply()
                    },
                    onHome: {
                        showsSuccess = false
                        lockPrivateReply()
                        DispatchQueue.main.async { dismiss() }
                    }
                )
            }
        }
        .onAppear {
            synchronizePrivateDraft()
        }
        .onDisappear {
            confirmedReplyNoticeID = nil
            addressCopiedNoticeID = nil
            guard !showsSuccess else { return }
            lockPrivateReply()
        }
        .onChange(of: store.unlockedDrafts[eventID]) { _, _ in
            synchronizePrivateDraft()
        }
        .task(id: eventID) {
            guard let inviteToken = event?.inviteToken else { return }
            _ = await store.openInvitation(inviteToken: inviteToken)
        }
        .overlay(alignment: .bottom) {
            if confirmedReplyNoticeID != nil || addressCopiedNoticeID != nil {
                Text(addressCopiedNoticeID != nil
                    ? "Address copied to clipboard"
                    : replyExperience.confirmedLockedMessage)
                    .font(.subheadline.weight(.semibold))
                    .multilineTextAlignment(.center)
                    .padding(.horizontal, 18)
                    .padding(.vertical, 12)
                    .background(.ultraThinMaterial, in: .capsule)
                    .overlay {
                        Capsule().stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
                    .padding(.horizontal, 20)
                    .padding(.bottom, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
                    .accessibilityIdentifier(addressCopiedNoticeID != nil
                        ? "address-copied-toast"
                        : "confirmed-reply-toast")
            }
        }
    }

    private var collapsedEventTitle: String {
        guard showsCollapsedEventTitle, let event else { return "" }
        return event.title.isEmpty ? invitationExperience.untitledEvent : event.title
    }

    private func deleteHostedEvent() {
        guard let event, event.isHosted else { return }
        Task {
            if await store.delete(event) {
                dismiss()
            } else {
                eventDeletionError = store.errorMessage
                    ?? invitationExperience.eventActions.failureBody
            }
        }
    }

    private func invitationHeader(_ event: HerdEvent) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Text(statusLabel(for: event))
                .font(.caption.weight(.bold))
                .padding(.horizontal, 10)
                .padding(.vertical, 7)
                .background(HerdTheme.raisedSurface, in: .capsule)
                .overlay {
                    Capsule().stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }

            Text(event.title.isEmpty ? invitationExperience.untitledEvent : event.title)
                .font(.system(size: 39, weight: .bold))
                .tracking(-1.35)
                .lineSpacing(-3)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 14)
                .background {
                    GeometryReader { geometry in
                        Color.clear.preference(
                            key: InvitationTitleBottomPreferenceKey.self,
                            value: geometry.frame(in: .named("invitation-detail-scroll")).maxY
                        )
                    }
                }

            if !event.eventDescription.isEmpty {
                Text(event.eventDescription)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 10)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private func eventNotices(_ event: HerdEvent) -> some View {
        let notices = invitationExperience.notices

        VStack(alignment: .leading, spacing: 10) {
            if event.isHosted && event.invitationDelivery?.status == .attentionNeeded {
                EventInfoNotice(notice: notices.deliveryIssue, icon: "exclamationmark.triangle")
            } else if event.isHosted && event.invitationDelivery?.status == .inProgress {
                EventInfoNotice(notice: notices.sending, icon: "paperplane")
            }

            if event.hasUnavailableLegacyResult {
                EventInfoNotice(notice: notices.legacyResultUnavailable, icon: "exclamationmark.lock")
            } else if event.resolution?.status == .verificationUnavailable {
                EventInfoNotice(notice: notices.resultUnavailable, icon: "exclamationmark.lock")
            } else if event.resolution?.status == .pending && event.resolution?.retrying == true {
                EventInfoNotice(notice: notices.takingLonger, icon: "clock.arrow.circlepath")
            }
        }
    }

    private func eventDetails(_ event: HerdEvent) -> some View {
        return VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 0) {
                InvitationMetaRow(
                    icon: "clock",
                    title: "Event date",
                    detail: event.eventDate == nil
                        ? invitationExperience.dateNotSet
                        : dateSummary(for: event)
                )
                .padding(.bottom, 12)

                Divider()
                    .padding(.leading, 40)

                if let copyText = locationClipboardText(for: event) {
                    Button {
                        UIPasteboard.general.string = copyText
                        showAddressCopiedNotice()
                    } label: {
                        InvitationMetaRow(
                            icon: "mappin",
                            title: "Location",
                            detail: invitationLocationSummary(for: event)
                        )
                        .contentShape(.rect)
                    }
                    .buttonStyle(.plain)
                    .padding(.vertical, 12)
                    .accessibilityLabel("Copy location address")
                    .accessibilityHint("Copies the address to the clipboard")
                } else {
                    InvitationMetaRow(
                        icon: "mappin",
                        title: "Location",
                        detail: invitationLocationSummary(for: event)
                    )
                    .padding(.vertical, 12)
                }

                Divider()
                    .padding(.leading, 40)

                InvitationMetaRow(
                    icon: "crown",
                    title: invitationExperience.hostPrefix,
                    detail: event.hostName.split(separator: " ").first.map(String.init) ?? event.hostName
                )
                .padding(.vertical, 12)

                if event.resolution?.status != .confirmed {
                    Divider()
                        .padding(.leading, 40)

                    InvitationMetaRow(
                        icon: "hourglass",
                        title: event.rsvpDeadline == nil
                            ? invitationExperience.noReplyDeadline
                            : invitationExperience.replyByPrefix,
                        detail: event.rsvpDeadline.map(replyDeadlineSummary) ?? ""
                    )
                    .padding(.top, 12)
                }
            }

            Divider()
                .padding(.top, 16)

            HStack(spacing: 0) {
                InvitationMetric(
                    value: "\(event.participantCount)",
                    label: invitationExperience.metrics.invited,
                    leadingInset: 0
                )

                Divider()
                    .frame(height: 34)

                InvitationMetric(
                    value: "\(event.minimumParticipants)",
                    label: invitationExperience.metrics.minimum
                )

                Divider()
                    .frame(height: 34)

                TimelineView(.periodic(from: .now, by: 1)) { context in
                    let outcomeMetric = detailOutcomeMetric(
                        for: event,
                        at: context.date
                    )
                    InvitationMetric(
                        value: outcomeMetric.value,
                        label: outcomeMetric.label,
                        trailingInset: 0
                    )
                }
            }
            .padding(.top, 16)

            Divider()
                .padding(.top, 16)
        }
    }

    private func detailOutcomeMetric(
        for event: HerdEvent,
        at now: Date
    ) -> (value: String, label: String) {
        switch event.resolution?.status {
        case .confirmed:
            return (
                event.resolution?.attendanceRevealed == true
                    ? "\(event.resolution?.attendingMemberIds?.count ?? 0)"
                    : "—",
                invitationExperience.metrics.attending
            )
        case .verificationUnavailable:
            return ("—", "result unavailable")
        case .notConfirmed, .pending, nil:
            if event.canViewResponseProgress {
                return ("\(event.respondedInviteeCount)", "responded")
            }
            return responseCountdown(for: event, at: now)
        }
    }

    private func invitationLocationSummary(for event: HerdEvent) -> String {
        let summary = EventLocationPresentation.summary(
            name: event.locationName,
            address: event.locationAddress,
            separator: "\n"
        )
        return summary.isEmpty ? invitationExperience.locationNotSet : summary
    }

    private func locationClipboardText(for event: HerdEvent) -> String? {
        let address = event.locationAddress.trimmingCharacters(in: .whitespacesAndNewlines)
        if !address.isEmpty { return address }
        let name = event.locationName.trimmingCharacters(in: .whitespacesAndNewlines)
        return name.isEmpty ? nil : name
    }

    private func showAddressCopiedNotice() {
        let noticeID = UUID()
        withAnimation(.snappy) {
            addressCopiedNoticeID = noticeID
            confirmedReplyNoticeID = nil
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2.5))
            guard addressCopiedNoticeID == noticeID else { return }
            withAnimation(.easeOut(duration: 0.2)) {
                addressCopiedNoticeID = nil
            }
        }
    }

    private func attendeeDetails(_ event: HerdEvent) -> some View {
        let participantLabel = event.participantCount == 1
            ? "1 person invited"
            : "\(event.participantCount) \(invitationExperience.attendeeEntry.peopleInvitedSuffix)"
        return NavigationLink {
            InvitationAttendees(eventID: event.id)
        } label: {
            HStack(spacing: 13) {
                VStack(alignment: .leading, spacing: 3) {
                    Text(participantLabel)
                        .font(.headline)
                        .lineLimit(1)
                    Text(invitationExperience.attendeeEntry.action)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                }

                Spacer()

                HStack(spacing: -9) {
                    attendeeAvatar(initials: initials(for: event.hostName), tone: 0)
                        .zIndex(6)

                    ForEach(Array(event.invitees.prefix(2).enumerated()), id: \.element.id) { index, invitee in
                        attendeeAvatar(initials: initials(for: invitee.displayName), tone: index + 1)
                            .zIndex(Double(5 - index))
                    }

                    if event.participantCount > 3 {
                        attendeeAvatar(initials: "+\(event.participantCount - 3)", tone: nil)
                            .zIndex(1)
                    }
                }

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

    private func attendeeAvatar(initials: String, tone: Int?) -> some View {
        Text(initials)
            .font(.caption2.weight(.bold))
            .foregroundStyle(tone == nil ? Color.secondary : Color.white)
            .frame(width: 36, height: 36)
            .background(attendeeAvatarColor(tone), in: .circle)
            .overlay { Circle().stroke(HerdTheme.canvas, lineWidth: 2) }
    }

    private func attendeeAvatarColor(_ tone: Int?) -> Color {
        guard let tone else { return HerdTheme.raisedSurface }
        return attendeeAvatarTone(tone)
    }

    private func privacyCallout(_ event: HerdEvent) -> some View {
        NavigationLink {
            InvitationPrivacyProof(event: event)
        } label: {
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
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(.rect)
        }
        .buttonStyle(PlainPressButtonStyle())
        .wireframeCard()
    }

    private func replyCard(_ event: HerdEvent) -> some View {
        let savedReplyIsLocked = event.hasResponse || event.hasBallot
            && store.unlockedDrafts[event.id] == nil
            && !isReplacingUnavailableReply
        let replyIsUnavailable = store.unavailablePrivateResponseEventID == event.id

        return VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 5) {
                Text(replyExperience.title)
                    .font(.title2.weight(.bold))
                Text(replyExperience.privacyNote)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
            }

            if store.hasPendingResponseCertification(for: event.id) {
                Label(
                    "Your encrypted reply is saved, but certification still needs to finish.",
                    systemImage: "arrow.triangle.2.circlepath"
                )
                .font(.subheadline)
                .foregroundStyle(.secondary)

                if savedReplyIsLocked {
                    Button("Finish saved reply certification") {
                        Task {
                            _ = await store.retryPendingResponseCertification(for: event)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(store.isMutating)
                }
            }

            if savedReplyIsLocked {
                Label(
                    replyIsUnavailable
                        ? replyExperience.unavailableTitle
                        : replyExperience.savedTitle,
                    systemImage: "lock.fill"
                )
                    .font(.subheadline.weight(.semibold))
                if replyIsUnavailable {
                    Text(replyExperience.unreadable)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }
                if replyIsUnavailable {
                    Button {
                        store.clearError()
                        isReplacingUnavailableReply = true
                        synchronizePrivateDraft()
                    } label: {
                        primaryReplyActionLabel(title: replyExperience.replaceButton)
                    }
                    .buttonStyle(PlainPressButtonStyle())
                    .disabled(store.isMutating)
                    .accessibilityLabel(replyExperience.replaceButton)
                    .accessibilityIdentifier("reply-replace-unavailable")
                } else {
                    Button {
                        Task {
                            if await store.unlockPrivateResponse(for: event) {
                                isReplacingUnavailableReply = false
                                synchronizePrivateDraft()
                            }
                        }
                    } label: {
                        primaryReplyActionLabel(
                            title: replyExperience.unlockButton,
                            systemImage: "faceid"
                        )
                    }
                    .buttonStyle(PlainPressButtonStyle())
                    .disabled(store.isMutating)
                    .accessibilityLabel(replyExperience.unlockButton)
                    .accessibilityIdentifier("reply-unlock")
                }
            }

            if !savedReplyIsLocked {
                VStack(alignment: .leading, spacing: 16) {
                    goingResponseOption(event)

                    responseButton(
                        title: replyExperience.cantCommitTitle,
                        subtitle: replyExperience.cantCommitBody,
                        response: .cantCommit
                    )

                    if event.inviteToken == nil {
                        Label(replyExperience.missingLinkMessage, systemImage: "link.badge.plus")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }

                    Button {
                        submitResponse(for: event)
                    } label: {
                        primaryReplyActionLabel(
                            title: isSubmitting
                                ? replyExperience.submittingButton
                                : replyActionTitle(for: event),
                            showsProgress: isSubmitting
                        )
                    }
                    .buttonStyle(PlainPressButtonStyle())
                    .disabled(
                        !replyHasUnsavedChanges(for: event) || isSubmitting
                            || event.inviteToken == nil
                    )
                    .opacity(
                        replyHasUnsavedChanges(for: event) && event.inviteToken != nil
                            ? 1
                            : 0.45
                    )
                    .padding(.top, 16)
                }
                .disabled(event.resolution?.status == .confirmed)
                .allowsHitTesting(event.resolution?.status != .confirmed)
                .overlay {
                    if event.resolution?.status == .confirmed {
                        Button(action: showConfirmedReplyNotice) {
                            Color.clear
                                .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(replyExperience.confirmedLockedMessage)
                        .accessibilityIdentifier("confirmed-reply-edit-guard")
                    }
                }
            }

            if let errorMessage = store.errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                    .font(.footnote)
                    .foregroundStyle(.red)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Button {
                showsReplyPreview = true
            } label: {
                Text(replyExperience.previewButton)
                    .font(.headline)
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
                    .overlay {
                        RoundedRectangle(cornerRadius: 14)
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
            }
            .buttonStyle(PlainPressButtonStyle())
            .accessibilityLabel(replyExperience.previewButton)
            .accessibilityIdentifier("reply-preview-trigger")
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func primaryReplyActionLabel(
        title: String,
        systemImage: String? = nil,
        showsProgress: Bool = false
    ) -> some View {
        HStack(spacing: 10) {
            if showsProgress {
                ProgressView().tint(.black)
            }
            if let systemImage {
                Image(systemName: systemImage)
            }
            Text(title)
        }
        .font(.headline)
        .foregroundStyle(.black)
        .frame(maxWidth: .infinity)
        .padding(.vertical, 15)
        .background(.white, in: .rect(cornerRadius: 14))
    }

    private func replyVisibilityPreview(_ event: HerdEvent) -> some View {
        let currentInvitee = event.invitees.first(where: \.isCurrentUser)
        let displayName = currentInvitee?.displayName
            ?? HerdExperience.shared.attendees.currentUserLabel
        let noReplyHistory = noReplyHistory(including: event)
        let status = switch selectedResponse {
        case .going: "Going"
        case .cantCommit: replyExperience.cantCommitTitle
        case nil: replyHistoryLabel(
            missed: noReplyHistory.missed,
            total: noReplyHistory.total
        )
        }

        return ReplyVisibilityPreview(
            displayName: displayName,
            status: status,
            isConfirmed: event.resolution?.status == .confirmed,
            confirmedBody: selectedResponse == nil
                ? replyExperience.noReplyPreviewBody
                : nil
        )
    }

    private func noReplyHistory(including currentEvent: HerdEvent) -> (missed: Int, total: Int) {
        let currentInvitee = currentEvent.invitees.first(where: \.isCurrentUser)
        var missed = currentInvitee?.responseHistory?.missedConfirmedEvents ?? 0
        var total = currentInvitee?.responseHistory?.totalConfirmedEvents ?? 0
        let includesCurrentEvent = currentEvent.resolution?.status == .confirmed &&
            currentEvent.resolution?.attendanceRevealed == true

        // This preview shows the outcome if the current invitation confirms
        // without a reply, so include that prospective result in the history.
        if !includesCurrentEvent {
            total += 1
            missed += 1
        }
        return (missed, total)
    }

    private func replyVisibilityPreviewSheet(_ event: HerdEvent) -> some View {
        VStack(alignment: .leading, spacing: 24) {
            ScrollView {
                VStack(alignment: .leading, spacing: 24) {
                    Text(replyExperience.previewTitle)
                        .font(.title2.weight(.bold))

                    replyVisibilityPreview(event)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Button {
                showsReplyPreview = false
            } label: {
                Text(replyExperience.previewDismissButton)
                    .font(.headline)
                    .foregroundStyle(.black)
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 15)
                    .contentShape(Rectangle())
                    .background(.white, in: .rect(cornerRadius: 14))
            }
            .buttonStyle(PlainPressButtonStyle())
            .accessibilityIdentifier("reply-preview-dismiss")
        }
        .padding(.horizontal, 20)
        .padding(.top, 28)
        .padding(.bottom, 20)
        .background(HerdTheme.canvas)
    }

    private func showConfirmedReplyNotice() {
        let noticeID = UUID()
        withAnimation(.snappy) {
            confirmedReplyNoticeID = noticeID
        }
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2.5))
            guard confirmedReplyNoticeID == noticeID else { return }
            withAnimation(.easeOut(duration: 0.2)) {
                confirmedReplyNoticeID = nil
            }
        }
    }

    private func responseButton(
        title: String,
        subtitle: String,
        response: RSVPResponse
    ) -> some View {
        let isSelected = selectedResponse == response

        return Grid(horizontalSpacing: 4) {
            GridRow(alignment: .center) {
                Button {
                    selectedResponse = isSelected ? nil : response
                } label: {
                    selectionRadio(isSelected: isSelected)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(title)
                .accessibilityValue(isSelected ? "Selected" : "Not selected")

                VStack(alignment: .leading, spacing: 2) {
                    Text(title)
                        .font(.headline)
                    Text(subtitle)
                        .font(.caption)
                        .opacity(0.72)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .foregroundStyle(.primary)
        .padding(.horizontal, 10)
        .padding(.vertical, 12)
        .frame(minHeight: 68)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
        .clipShape(.rect(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(
                    isSelected ? Color.primary.opacity(0.72) : HerdTheme.subtleBorder,
                    lineWidth: isSelected ? 1.5 : 1
                )
        }
        .contentShape(.rect(cornerRadius: 14))
        .onTapGesture {
            guard !isSelected else { return }
            selectedResponse = response
        }
    }

    private func goingResponseOption(_ event: HerdEvent) -> some View {
        let isSelected = selectedResponse == .going

        return Grid(alignment: .leading, horizontalSpacing: 4, verticalSpacing: 14) {
            GridRow(alignment: .center) {
                Button {
                    selectedResponse = isSelected ? nil : .going
                } label: {
                    selectionRadio(isSelected: isSelected)
                }
                .buttonStyle(.plain)
                .accessibilityLabel(
                    isSelected
                        ? "\(replyExperience.goingPrefix) \(privateMinimumParticipants) \(replyExperience.goingSuffix)"
                        : replyExperience.goingCollapsedTitle
                )
                .accessibilityValue(isSelected ? "Selected" : "Not selected")

                if isSelected {
                    HStack(spacing: 8) {
                        Text(replyExperience.goingPrefix)
                            .font(.subheadline.weight(.semibold))
                            .lineLimit(1)
                            .minimumScaleFactor(0.75)

                        compactMinimumStepper(event)

                        Text(replyExperience.goingSuffix)
                            .font(.subheadline.weight(.semibold))
                            .lineLimit(1)
                            .minimumScaleFactor(0.8)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .transition(.opacity)
                } else {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(replyExperience.goingCollapsedTitle)
                            .font(.headline)
                        Text(replyExperience.goingCollapsedBody)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .transition(.opacity)
                }
            }

            if isSelected {
                GridRow(alignment: .top) {
                    Color.clear
                        .frame(width: 44, height: 0)
                        .accessibilityHidden(true)

                    privateCriteriaEditor(event)
                        .transition(.opacity)
                }
            }
        }
        .foregroundStyle(.primary)
        .padding(.horizontal, 10)
        .padding(.vertical, 12)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
        .clipShape(.rect(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(
                    isSelected ? Color.primary.opacity(0.72) : HerdTheme.subtleBorder,
                    lineWidth: isSelected ? 1.5 : 1
                )
        }
        .contentShape(.rect(cornerRadius: 14))
        .onTapGesture {
            guard !isSelected else { return }
            selectedResponse = .going
        }
        .animation(.snappy, value: isSelected)
    }

    private func selectionRadio(isSelected: Bool) -> some View {
        ZStack {
            Circle()
                .stroke(isSelected ? Color.primary : Color.secondary, lineWidth: 1.5)

            Circle()
                .fill(Color.primary)
                .padding(5)
                .scaleEffect(isSelected ? 1 : 0.6)
                .opacity(isSelected ? 1 : 0)
        }
        .frame(width: 22, height: 22)
        .frame(width: 44, height: 44)
        .contentShape(.rect)
        .animation(.easeInOut(duration: 0.14), value: isSelected)
    }

    private func compactMinimumStepper(_ event: HerdEvent) -> some View {
        let minimum = max(2, event.minimumParticipants)
        let maximum = max(minimum, event.invitees.count + 1)

        return HStack(spacing: 0) {
            Button {
                privateMinimumParticipants = max(minimum, privateMinimumParticipants - 1)
                selectedResponse = .going
            } label: {
                Image(systemName: "minus")
                    .frame(width: 44, height: 44)
                    .contentShape(.rect)
            }
            .disabled(privateMinimumParticipants <= minimum)
            .accessibilityLabel(replyExperience.decreaseMinimum)

            Divider()
                .frame(height: 22)

            Text("\(privateMinimumParticipants)")
                .font(.subheadline.weight(.bold))
                .monospacedDigit()
                .frame(width: 30, height: 44)
                .accessibilityHidden(true)

            Divider()
                .frame(height: 22)

            Button {
                privateMinimumParticipants = min(maximum, privateMinimumParticipants + 1)
                selectedResponse = .going
            } label: {
                Image(systemName: "plus")
                    .frame(width: 44, height: 44)
                    .contentShape(.rect)
            }
            .disabled(privateMinimumParticipants >= maximum)
            .accessibilityLabel(replyExperience.increaseMinimum)
        }
        .font(.caption.weight(.semibold))
        .buttonStyle(.plain)
        .background(HerdTheme.surface, in: .capsule)
        .overlay {
            Capsule().stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Minimum people: \(privateMinimumParticipants)")
    }

    private func privateCriteriaEditor(_ event: HerdEvent) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            ForEach(privateRequiredGroups) { group in
                ConditionTokenLayout(spacing: 6) {
                    Text("AND")
                        .font(.caption2.weight(.bold))
                        .tracking(0.6)
                        .foregroundStyle(.secondary)
                        .frame(height: 32, alignment: .center)

                    ForEach(Array(group.memberIDs.enumerated()), id: \.element) { memberIndex, memberID in
                        if memberIndex > 0 {
                            Text("OR")
                                .font(.caption2.weight(.bold))
                                .tracking(0.6)
                                .foregroundStyle(.secondary)
                                .frame(height: 32, alignment: .center)
                        }

                        Button {
                            selectedResponse = .going
                            removeConditionMember(memberID, from: group.id)
                        } label: {
                            HStack(spacing: 6) {
                                Text(RequiredAttendeeName.shortened(event.name(for: memberID)))
                                    .lineLimit(1)
                                Image(systemName: "xmark")
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(.secondary)
                            }
                            .font(.caption.weight(.semibold))
                            .padding(.leading, 11)
                            .padding(.trailing, 9)
                            .frame(height: 32)
                            .background(HerdTheme.surface, in: .capsule)
                            .overlay {
                                Capsule().stroke(HerdTheme.subtleBorder, lineWidth: 1)
                            }
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel("Remove \(event.name(for: memberID)) from this condition")
                    }

                    Button {
                        selectedResponse = .going
                        conditionTargetGroupID = group.id
                        showsConditionPicker = true
                    } label: {
                        HStack(spacing: 4) {
                            Image(systemName: "plus")
                            Text("or")
                        }
                        .font(.caption.weight(.bold))
                        .padding(.horizontal, 10)
                        .frame(height: 32)
                        .overlay {
                            Capsule().stroke(
                                Color.secondary.opacity(0.65),
                                style: StrokeStyle(lineWidth: 1, dash: [4, 3])
                            )
                        }
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Add an OR alternative")
                    .disabled(availableConditionInvitees(in: event, excluding: group.memberIDs).isEmpty)

                    Text("goes")
                        .font(.caption2.weight(.bold))
                        .tracking(0.6)
                        .foregroundStyle(.secondary)
                        .frame(height: 32, alignment: .center)
                }
                .padding(.bottom, 10)
                .overlay(alignment: .bottom) {
                    Divider()
                }
            }

            Button {
                selectedResponse = .going
                conditionTargetGroupID = nil
                showsConditionPicker = true
            } label: {
                Label(replyExperience.addCondition, systemImage: "plus")
                    .font(.subheadline.weight(.semibold))
                    .padding(.horizontal, 12)
                    .padding(.vertical, 8)
                    .overlay {
                        Capsule()
                            .stroke(
                                Color.secondary.opacity(0.65),
                                style: StrokeStyle(lineWidth: 1, dash: [5, 4])
                            )
                    }
            }
            .buttonStyle(.plain)
            .disabled(availableConditionInvitees(in: event).isEmpty)
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

    private func removeConditionMember(_ memberID: UUID, from groupID: String) {
        guard let groupIndex = privateRequiredGroups.firstIndex(where: { $0.id == groupID }) else {
            return
        }
        privateRequiredGroups[groupIndex].memberIDs.removeAll { $0 == memberID }
        if privateRequiredGroups[groupIndex].memberIDs.isEmpty {
            privateRequiredGroups.remove(at: groupIndex)
        }
    }

    private func submitResponse(for event: HerdEvent) {
        guard let draft = currentPrivateDraft else { return }
        isSubmitting = true
        Task {
            let saved: Bool
            if store.hasPendingResponseCertification(for: event.id),
               draft == savedPrivateDraft {
                saved = await store.retryPendingResponseCertification(for: event)
            } else {
                saved = await store.respond(
                    to: event,
                    draft: draft
                )
            }
            isSubmitting = false
            if saved {
                // Establish the exact submitted draft as the comparison baseline
                // before returning from the success screen. Observation of the
                // store's dictionary entry is not guaranteed to precede this view.
                savedPrivateDraft = draft
                showsSuccess = true
            }
        }
    }

    private func replyActionTitle(for event: HerdEvent) -> String {
        guard selectedResponse != nil else { return replyExperience.chooseButton }
        guard event.hasResponse || event.hasBallot else { return replyExperience.submitButton }
        if store.hasPendingResponseCertification(for: event.id),
           currentPrivateDraft == savedPrivateDraft {
            return "Finish saved reply certification"
        }
        return replyHasUnsavedChanges(for: event)
            ? replyExperience.updateButton
            : replyExperience.sentButton
    }

    private func replyHasUnsavedChanges(for event: HerdEvent) -> Bool {
        guard let currentDraft = currentPrivateDraft else { return false }
        return !(event.hasResponse || event.hasBallot) ||
            currentDraft != savedPrivateDraft ||
            store.hasPendingResponseSubmission(for: event.id, draft: currentDraft) ||
            store.hasPendingResponseCertification(for: event.id)
    }

    private var currentPrivateDraft: PrivateResponseDraft? {
        guard let selectedResponse else { return nil }
        return PrivateResponseDraft(
            response: selectedResponse,
            minimumParticipants: selectedResponse == .going
                ? privateMinimumParticipants
                : nil,
            requiredGroups: selectedResponse == .going
                ? privateRequiredGroups
                : []
        )
    }

    private func synchronizePrivateDraft() {
        guard let event else { return }
        if let draft = store.unlockedDrafts[eventID] {
            savedPrivateDraft = draft
            selectedResponse = draft.response
            privateMinimumParticipants = draft.minimumParticipants
                ?? max(2, event.minimumParticipants)
            privateRequiredGroups = draft.requiredGroups
        } else {
            savedPrivateDraft = nil
            selectedResponse = nil
            privateMinimumParticipants = max(2, event.minimumParticipants)
            privateRequiredGroups = []
        }
    }

    private func lockPrivateReply() {
        store.lockPrivateResponse(for: eventID)
        synchronizePrivateDraft()
        isReplacingUnavailableReply = false
    }

    private func statusLabel(for event: HerdEvent) -> String {
        event.userFacingStatusLabel()
    }

    private func responseCountdown(
        for event: HerdEvent,
        at now: Date
    ) -> (value: String, label: String) {
        guard let deadline = event.rsvpDeadline else {
            return ("—", "no deadline")
        }
        let seconds = max(0, Int(deadline.timeIntervalSince(now).rounded(.up)))
        guard seconds > 0 else {
            return ("Passed", "deadline passed")
        }
        let days = seconds / 86_400
        let hours = (seconds % 86_400) / 3_600
        let minutes = (seconds % 3_600) / 60
        if days > 0 { return ("\(days)d \(hours)h", "left to respond") }
        if hours > 0 { return ("\(hours)h \(minutes)m", "left to respond") }
        if minutes > 0 { return ("\(minutes)m \(seconds % 60)s", "left to respond") }
        return ("\(seconds)s", "left to respond")
    }

    private func replyDeadlineSummary(_ deadline: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .autoupdatingCurrent
        formatter.shortWeekdaySymbols = ["Sun", "Mon", "Tues", "Wed", "Thurs", "Fri", "Sat"]
        formatter.dateFormat = "EEE, MMM d, h:mma"
        return formatter.string(from: deadline)
            .replacingOccurrences(of: "AM", with: "am")
            .replacingOccurrences(of: "PM", with: "pm")
    }

    private func dateSummary(for event: HerdEvent) -> String {
        guard let eventDate = event.eventDate else { return "Date to be announced" }
        if let endDate = event.endDate {
            return "\(eventDate.formatted(date: .abbreviated, time: .shortened)) – \(endDate.formatted(date: .omitted, time: .shortened))"
        }
        return eventDate.formatted(date: .abbreviated, time: .shortened)
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
                .font(.system(size: 15, weight: .regular))
                .foregroundStyle(.secondary)
                .frame(width: 28, height: 28)
                .background(HerdTheme.surface, in: .rect(cornerRadius: 9))

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

private struct EventInfoNotice: View {
    let notice: HerdExperience.Invitation.Notice
    let icon: String

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(.secondary)
                .frame(width: 24, height: 24)

            VStack(alignment: .leading, spacing: 3) {
                Text(notice.title)
                    .font(.subheadline.weight(.semibold))
                Text(notice.body)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
        .overlay {
            RoundedRectangle(cornerRadius: 14)
                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
        .accessibilityElement(children: .combine)
    }
}

private struct InvitationMetric: View {
    let value: String
    let label: String
    var leadingInset: CGFloat = 10
    var trailingInset: CGFloat = 10

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(value)
                .font(.headline)
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.72)
            Text(label)
                .font(.caption2)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.leading, leadingInset)
        .padding(.trailing, trailingInset)
    }
}

private struct InvitationAttendees: View {
    @Environment(EventStore.self) private var store
    @Environment(AuthStore.self) private var authStore
    let eventID: UUID
    private let experience = HerdExperience.shared.attendees
    @State private var selectedDeliveryGuestID: UUID?
    @State private var showsAddAttendees = false
    @State private var pendingInvitees: [Invitee] = []
    @State private var addErrorMessage: String?

    private var event: HerdEvent? {
        store.events.first(where: { $0.id == eventID })
    }

    private var canAddAttendees: Bool {
        guard let event else { return false }
        guard event.resolution?.status != .confirmed else { return false }
        return event.isHosted || event.allowsAttendeesToAddGuests
    }

    private var participantLabel: String {
        guard let event else { return "" }
        return event.participantCount == 1
            ? "1 person"
            : "\(event.participantCount) people"
    }

    var body: some View {
        ScrollView {
            if let event {
                VStack(alignment: .leading, spacing: 20) {
                    Text(statusDisclosure(for: event))
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 8)

                    Text(participantLabel)
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                        .textCase(.uppercase)
                        .tracking(0.8)

                    VStack(spacing: 0) {
                        attendeeRow(
                            name: event.hostName,
                            tone: 0,
                            status: experience.hostingLabel,
                            isHost: true
                        )

                        if !event.invitees.isEmpty {
                            Divider().padding(.leading, 52)
                        }

                        ForEach(Array(event.invitees.enumerated()), id: \.element.id) { index, invitee in
                            attendeeRow(
                                name: invitee.displayName,
                                tone: index + 1,
                                status: statusLabel(for: invitee),
                                isHost: false,
                                delivery: deliveryGuest(for: invitee)
                            )
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

                    if canAddAttendees {
                        Button {
                            pendingInvitees = []
                            showsAddAttendees = true
                        } label: {
                            HStack(spacing: 13) {
                                Group {
                                    if store.isMutating {
                                        ProgressView()
                                    } else {
                                        Image(systemName: "plus")
                                            .font(.title3.weight(.semibold))
                                    }
                                }
                                .frame(width: 40, height: 40)

                                Text(experience.addGuests.button)
                                    .font(.body.weight(.semibold))

                                Spacer(minLength: 0)
                            }
                            .contentShape(.rect)
                        }
                        .buttonStyle(.plain)
                        .padding(.horizontal, 16)
                        .padding(.top, -8)
                        .disabled(store.isMutating)
                        .accessibilityIdentifier("add-event-attendees")
                    }
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 32)
            }
        }
        .background(HerdTheme.canvas)
        .navigationTitle(experience.navigationTitle)
        .navigationBarTitleDisplayMode(.large)
        .toolbarBackground(HerdTheme.canvas, for: .navigationBar)
        .fullScreenCover(isPresented: $showsAddAttendees) {
            if let event {
                AttendeeFlowView(
                    invitees: $pendingInvitees,
                    excludedPhoneNumber: authStore.user?.phoneNumber,
                    excludedPhoneNumbers: event.invitees.map(\.phoneNumber)
                )
            }
        }
        .onChange(of: pendingInvitees) { oldValue, newValue in
            guard !newValue.isEmpty, oldValue != newValue else { return }
            Task {
                if await store.addAttendees(newValue, to: eventID) {
                    pendingInvitees = []
                } else {
                    addErrorMessage = store.errorMessage ?? experience.addGuests.failureBody
                }
            }
        }
        .alert(experience.addGuests.failureTitle, isPresented: Binding(
            get: { addErrorMessage != nil },
            set: { if !$0 { addErrorMessage = nil } }
        )) {
            Button("OK", role: .cancel) {}
        } message: {
            Text(addErrorMessage ?? experience.addGuests.failureBody)
        }
    }

    @ViewBuilder
    private func attendeeRow(
        name: String,
        tone: Int,
        status: String?,
        isHost: Bool,
        delivery: InvitationDeliveryGuest? = nil
    ) -> some View {
        HStack(spacing: 13) {
            avatar(for: name, tone: tone, isHost: isHost)
            Text(name)
                .font(.body.weight(.semibold))
            Spacer(minLength: 12)
            if let status {
                Text(status)
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)
                    .multilineTextAlignment(.trailing)
            }
            if let delivery {
                deliveryStatusButton(delivery)
            }
        }
        .padding(.vertical, 12)
    }

    private func deliveryGuest(for invitee: Invitee) -> InvitationDeliveryGuest? {
        guard let event else { return nil }
        guard event.isHosted else { return nil }
        return event.invitationDelivery?.guests.first { $0.inviteeId == invitee.id }
    }

    private func deliveryStatusButton(_ delivery: InvitationDeliveryGuest) -> some View {
        let isSent = delivery.status == .sent
        let isPresented = Binding(
            get: { selectedDeliveryGuestID == delivery.inviteeId },
            set: { presented in
                selectedDeliveryGuestID = presented ? delivery.inviteeId : nil
            }
        )

        return Button {
            selectedDeliveryGuestID = isPresented.wrappedValue ? nil : delivery.inviteeId
        } label: {
            Image(systemName: isSent ? "paperplane.fill" : "exclamationmark.triangle.fill")
                .font(.system(size: 15, weight: .semibold))
                .foregroundStyle(isSent ? Color.secondary : Color.orange)
                .frame(width: 30, height: 30)
                .contentShape(.circle)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(isSent ? "Invitation sent" : "Invitation delivery issue")
        .accessibilityHint("Shows delivery details for \(delivery.displayName)")
        .popover(isPresented: isPresented, arrowEdge: .trailing) {
            Text(deliveryExplanation(for: delivery.status))
                .font(.subheadline)
                .padding(14)
                .frame(idealWidth: 250, alignment: .leading)
                .presentationCompactAdaptation(.popover)
        }
    }

    private func deliveryExplanation(for status: InvitationDeliveryStatus) -> String {
        switch status {
        case .sent:
            return "The messaging provider accepted this invitation."
        case .failed:
            return "The messaging provider rejected this invitation, so it was not sent."
        case .unknown:
            return "Herd could not confirm delivery and did not retry automatically to avoid sending a duplicate."
        case .pending:
            return "This invitation is waiting to be submitted to the messaging provider."
        case .dispatching:
            return "This invitation is being submitted to the messaging provider."
        case .suppressed:
            return "No message was sent. This guest can still open the event directly in Herd."
        }
    }

    private func statusLabel(for invitee: Invitee) -> String? {
        guard let event else { return nil }
        if event.resolution?.status != .confirmed,
           event.canViewResponseProgress {
            return invitee.hasResponded == true ? "Responded" : "Not responded"
        }
        if event.resolution?.status == .confirmed,
           event.resolution?.attendanceRevealed == true,
           (event.role == .host || event.hasResponse || event.hasBallot),
           let state = event.resolution?.guestStates?.first(where: {
               $0.memberId == invitee.id.uuidString.lowercased()
           }) {
            let label: String = switch state.status {
            case .going: "Going"
            case .cantCommit: "Can’t commit"
            case .noResponse:
                if let history = invitee.responseHistory {
                    replyHistoryLabel(
                        missed: history.missedConfirmedEvents,
                        total: history.totalConfirmedEvents
                    )
                } else {
                    "This user did not respond by the deadline."
                }
            }
            return state.missedDeadline && state.status != .noResponse
                ? "\(label) · replied late"
                : label
        }
        return nil
    }

    private func statusDisclosure(for event: HerdEvent) -> String {
        if event.resolution?.status == .confirmed {
            return experience.statusDisclosure
        }
        if event.role == .host {
            return "You can see who has responded. What each person chose stays private until the event is confirmed."
        }
        if event.canViewResponseProgress {
            return "You can see who has responded because your private reply has been sent. What each person chose stays private until the event is confirmed."
        }
        return "Send your private reply to see who has responded. What each person chose stays private until the event is confirmed."
    }

    private func avatar(for name: String, tone: Int, isHost: Bool) -> some View {
        let words = name.split(whereSeparator: \.isWhitespace)
        let initials = words.count > 1
            ? "\(words.first?.first.map(String.init) ?? "")\(words.last?.first.map(String.init) ?? "")"
            : String(words.first?.prefix(2) ?? "?")
        return ZStack(alignment: .topTrailing) {
            Text(initials.uppercased())
                .font(.caption.weight(.bold))
                .foregroundStyle(Color.white)
                .frame(width: 40, height: 40)
                .background(attendeeAvatarTone(tone), in: .circle)
                .overlay { Circle().stroke(HerdTheme.subtleBorder, lineWidth: 1) }

            if isHost {
                Image(systemName: "crown.fill")
                    .font(.system(size: 8, weight: .bold))
                    .foregroundStyle(HerdTheme.canvas)
                    .frame(width: 17, height: 17)
                    .background(Color(red: 0.93, green: 0.82, blue: 0.50), in: .circle)
                    .overlay { Circle().stroke(HerdTheme.canvas, lineWidth: 2) }
                    .offset(x: 4, y: -4)
                    .accessibilityHidden(true)
            }
        }
    }
}

private func replyHistoryLabel(missed: Int, total: Int) -> String {
    if missed == 1 && total == 1 {
        return HerdExperience.shared.reply.noReplySingleEventHistory
    }
    return HerdExperience.shared.reply.noReplyHistoryTemplate
        .replacingOccurrences(of: "{missed}", with: "\(missed)")
        .replacingOccurrences(of: "{total}", with: "\(total)")
}

private func attendeeAvatarTone(_ tone: Int) -> Color {
    let colors = [
        Color(red: 0.365, green: 0.333, blue: 0.302),
        Color(red: 0.286, green: 0.345, blue: 0.400),
        Color(red: 0.349, green: 0.314, blue: 0.420),
        Color(red: 0.306, green: 0.384, blue: 0.333),
        Color(red: 0.400, green: 0.325, blue: 0.310),
    ]
    return colors[tone % colors.count]
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
    @State private var expandedSectionID: String? = HerdExperience.shared.privacy.sections.first?.id

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 30) {
                VStack(alignment: .leading, spacing: 10) {
                    eyebrow(experience.eyebrow)
                    Text(experience.title)
                        .font(.largeTitle.weight(.bold))
                        .tracking(-0.7)
                    Text(experience.intro)
                        .font(.body)
                        .foregroundStyle(.secondary)
                }

                VStack(alignment: .leading, spacing: 12) {
                    Text(experience.flowTitle).font(.title2.weight(.bold))
                    VStack(spacing: 0) {
                        ForEach(Array(experience.flowSteps.enumerated()), id: \.element.id) { index, step in
                            flowItem(
                                step,
                                index: index,
                                showsConnector: index < experience.flowSteps.count - 1
                            )
                        }
                    }
                    .padding(.vertical, 8)
                    .wireframeCard(padding: 0)

                    HStack(alignment: .top, spacing: 14) {
                        Image(systemName: "eye.slash.fill")
                            .font(.subheadline.weight(.semibold))
                            .frame(width: 42, height: 22, alignment: .top)

                        Text(experience.flowPrivacyLabel)
                            .font(.subheadline.weight(.semibold))
                            .fixedSize(horizontal: false, vertical: true)

                        Spacer(minLength: 0)
                    }
                    .foregroundStyle(.primary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .wireframeCard(padding: 14)
                }

                VStack(alignment: .leading, spacing: 12) {
                    eyebrow(experience.answersEyebrow)
                    Text(experience.answersTitle).font(.title2.weight(.bold))
                    ForEach(experience.sections) { section in
                        PrivacyDisclosureSection(
                            section: section,
                            policy: section.showsPolicyIdentifiers
                                ? event.privateResponsePolicy
                                : nil,
                            sourceURL: experience.sourceURL,
                            releaseEvidenceURL: experience.releaseEvidenceURL,
                            isExpanded: Binding(
                                get: { expandedSectionID == section.id },
                                set: { isExpanded in
                                    withAnimation(.snappy) {
                                        expandedSectionID = isExpanded ? section.id : nil
                                    }
                                }
                            )
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

    private func flowNode(
        _ step: HerdExperience.Privacy.FlowStep,
        index: Int
    ) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: flowSymbol(at: index))
                .font(.subheadline.weight(.semibold))
                .frame(width: 42, height: 42)

            VStack(alignment: .leading, spacing: 4) {
                Text(step.title).font(.headline)
                Text(step.body)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
    }

    private func flowItem(
        _ step: HerdExperience.Privacy.FlowStep,
        index: Int,
        showsConnector: Bool
    ) -> some View {
        VStack(spacing: 0) {
            flowNode(step, index: index)

            if showsConnector {
                Color.clear.frame(height: 22)
            }
        }
        .overlay {
            if showsConnector {
                GeometryReader { geometry in
                    Image(systemName: "arrow.down")
                        .font(.caption.weight(.bold))
                        .foregroundStyle(.secondary)
                        .position(
                            x: 35,
                            y: (geometry.size.height + 58) / 2
                        )
                        .accessibilityHidden(true)
                }
                .allowsHitTesting(false)
            }
        }
    }

    private func flowSymbol(at index: Int) -> String {
        let symbols = [
            "person.crop.circle",
            "lock.fill",
            "externaldrive.fill",
            "checkmark.seal.fill",
        ]
        return symbols.indices.contains(index) ? symbols[index] : "circle.fill"
    }
}

private struct PrivacyDisclosureSection: View {
    let section: HerdExperience.Privacy.Section
    let policy: PrivateResponsePolicyV1?
    let sourceURL: String
    let releaseEvidenceURL: String
    @Binding var isExpanded: Bool

    var body: some View {
        DisclosureGroup(isExpanded: $isExpanded) {
            VStack(alignment: .leading, spacing: 12) {
                ForEach(Array(section.paragraphs.enumerated()), id: \.offset) { index, paragraph in
                    Text(paragraph)
                        .font(.subheadline.weight(index == 0 ? .medium : .regular))
                        .foregroundStyle(index == 0 ? .primary : .secondary)
                }

                if section.showsVerificationLinks {
                    VStack(alignment: .leading, spacing: 10) {
                        if let url = URL(string: sourceURL) {
                            Link(destination: url) {
                                Label("View public source", systemImage: "chevron.left.forwardslash.chevron.right")
                            }
                        }
                        if let url = URL(string: releaseEvidenceURL) {
                            Link(destination: url) {
                                Label("Inspect signed release evidence", systemImage: "checkmark.seal")
                            }
                        }
                    }
                    .font(.subheadline.weight(.semibold))
                    .tint(.primary)
                }

                if section.showsPolicyIdentifiers {
                    if let policy {
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
                    } else {
                        Text("This event does not expose a frozen private-response policy, so the client cannot submit a private response.")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                            .padding(12)
                            .background(HerdTheme.canvas, in: .rect(cornerRadius: 12))
                    }
                }
            }
            .padding(.top, 12)
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text(section.title)
                .font(.headline)
                .multilineTextAlignment(.leading)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
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
    let response: RSVPResponse
    let displayName: String
    let onViewInvitation: () -> Void
    let onHome: () -> Void
    private let experience = HerdExperience.shared.success

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    Image(systemName: "checkmark")
                        .font(.system(size: 38, weight: .bold))
                        .foregroundStyle(.black)
                        .frame(width: 78, height: 78)
                        .background(.white, in: .circle)

                    VStack(alignment: .leading, spacing: 8) {
                        Text(experience.title)
                            .font(.largeTitle.weight(.bold))
                        Text(experience.body)
                            .font(.title3)
                            .foregroundStyle(.secondary)
                    }

                    VStack(alignment: .leading, spacing: 0) {
                        Text(experience.replyPreviewTitle)
                            .font(.headline)

                        ReplyVisibilityPreview(
                            displayName: displayName,
                            status: response == .going
                                ? "Going"
                                : HerdExperience.shared.reply.cantCommitTitle
                        )
                        .padding(.top, 56)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .padding(22)
            }

            VStack(spacing: 12) {
                Button(action: onViewInvitation) {
                    Text(experience.viewInvitationButton)
                        .font(.headline)
                        .foregroundStyle(.black)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 15)
                        .contentShape(.rect(cornerRadius: 14))
                        .background(.white, in: .rect(cornerRadius: 14))
                }
                .buttonStyle(PlainPressButtonStyle())
                .accessibilityIdentifier("success-view-invitation")

                Button(action: onHome) {
                    Text(experience.homeButton)
                        .font(.headline)
                        .foregroundStyle(.primary)
                        .frame(maxWidth: .infinity)
                        .padding(.vertical, 15)
                        .contentShape(.rect(cornerRadius: 14))
                        .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 14))
                        .overlay {
                            RoundedRectangle(cornerRadius: 14)
                                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                        }
                }
                .buttonStyle(PlainPressButtonStyle())
                .accessibilityIdentifier("success-back-to-events")
            }
            .padding(20)
            .background(HerdTheme.canvas)
        }
        .background(HerdTheme.canvas)
    }
}

private struct ReplyVisibilityPreview: View {
    let displayName: String
    let status: String
    let isConfirmed: Bool
    let confirmedBody: String?
    private let experience = HerdExperience.shared.reply

    init(
        displayName: String,
        status: String,
        isConfirmed: Bool = false,
        confirmedBody: String? = nil
    ) {
        self.displayName = displayName
        self.status = status
        self.isConfirmed = isConfirmed
        self.confirmedBody = confirmedBody
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            if !isConfirmed {
                Text(experience.confirmedPreviewLabel)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(0.7)
            }

            HStack(spacing: 13) {
                Text(initials)
                    .font(.caption.weight(.bold))
                    .frame(width: 40, height: 40)
                    .background(HerdTheme.raisedSurface, in: .circle)

                VStack(alignment: .leading, spacing: 3) {
                    Text(displayName)
                        .font(.body.weight(.semibold))
                    Text(status)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }

                Spacer()
            }
            .padding(14)
            .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
            .overlay {
                RoundedRectangle(cornerRadius: 14)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
            .padding(.top, isConfirmed ? 0 : 12)

            Text(confirmedBody ?? experience.confirmedPreviewBody)
                .font(.caption)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, 12)

            if !isConfirmed {
                Text(experience.notConfirmedPreviewLabel)
                    .font(.caption2.weight(.bold))
                    .foregroundStyle(.secondary)
                    .textCase(.uppercase)
                    .tracking(0.7)
                    .padding(.top, 32)

                HStack(spacing: 12) {
                    Image(systemName: "eye.slash")
                        .foregroundStyle(.secondary)

                    Text(experience.notConfirmedPreviewTitle)
                        .font(.subheadline.weight(.semibold))
                }
                .padding(14)
                .frame(maxWidth: .infinity, alignment: .leading)
                .background(HerdTheme.surface, in: .rect(cornerRadius: 14))
                .overlay {
                    RoundedRectangle(cornerRadius: 14)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }
                .padding(.top, 12)

                Text(experience.notConfirmedPreviewBody)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 12)
            }
        }
        .accessibilityElement(children: .contain)
    }

    private var initials: String {
        let words = displayName.split(whereSeparator: \.isWhitespace)
        if let first = words.first?.first, let last = words.dropFirst().last?.first {
            return "\(first)\(last)".uppercased()
        }
        return String(words.first?.prefix(2) ?? "?").uppercased()
    }
}

private struct ConditionTokenLayout: Layout {
    let spacing: CGFloat

    func sizeThatFits(
        proposal: ProposedViewSize,
        subviews: Subviews,
        cache: inout ()
    ) -> CGSize {
        let result = layout(subviews: subviews, width: proposal.width ?? .infinity)
        return CGSize(width: proposal.width ?? result.width, height: result.height)
    }

    func placeSubviews(
        in bounds: CGRect,
        proposal: ProposedViewSize,
        subviews: Subviews,
        cache: inout ()
    ) {
        let result = layout(subviews: subviews, width: bounds.width)
        for (index, point) in result.points.enumerated() {
            subviews[index].place(
                at: CGPoint(x: bounds.minX + point.x, y: bounds.minY + point.y),
                anchor: .topLeading,
                proposal: .unspecified
            )
        }
    }

    private func layout(subviews: Subviews, width: CGFloat) -> (
        points: [CGPoint],
        width: CGFloat,
        height: CGFloat
    ) {
        var points: [CGPoint] = []
        var cursorX: CGFloat = 0
        var cursorY: CGFloat = 0
        var lineHeight: CGFloat = 0
        var usedWidth: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            let nextX = cursorX == 0 ? 0 : cursorX + spacing

            if nextX > 0, nextX + size.width > width {
                cursorX = 0
                cursorY += lineHeight + spacing
                lineHeight = 0
            } else {
                cursorX = nextX
            }

            points.append(CGPoint(x: cursorX, y: cursorY))
            cursorX += size.width
            lineHeight = max(lineHeight, size.height)
            usedWidth = max(usedWidth, cursorX)
        }

        return (points, usedWidth, cursorY + lineHeight)
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
