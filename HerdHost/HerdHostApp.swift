import SwiftUI

@main
struct HerdHostApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var authStore: AuthStore
    @State private var eventStore: EventStore
    @State private var invitationCoordinator: InvitationCoordinator

    private let startsInCreateFlow = ProcessInfo.processInfo.arguments.contains("--open-create")

    init() {
#if DEBUG
        if let uiTestEnvironment = HerdUITestEnvironment.current {
            uiTestEnvironment.prepare()
            let apiClient = uiTestEnvironment.makeAPIClient()
            let accountKeyStore = uiTestEnvironment.accountKeyStore
            let invitationCoordinator = InvitationCoordinator(
                trustedWebOrigin: HerdUITestEnvironment.fixtureOrigin,
                keychainStore: uiTestEnvironment.pendingInvitationStore
            )
            if let invitationURL = uiTestEnvironment.pendingInvitationURL {
                _ = invitationCoordinator.accept(invitationURL)
            }
            _authStore = State(
                initialValue: AuthStore(
                    apiClient: apiClient,
                    sessionStore: uiTestEnvironment.sessionStore,
                    accountKeyStore: accountKeyStore
                )
            )
            _eventStore = State(
                initialValue: EventStore(
                    defaults: uiTestEnvironment.defaults,
                    apiClient: apiClient,
                    accountKeyStore: accountKeyStore
                )
            )
            _invitationCoordinator = State(initialValue: invitationCoordinator)
            return
        }
#endif
        let apiBaseURL = APIClient.configuredBaseURL
        let apiClient = APIClient(baseURL: apiBaseURL)
        let accountKeyStore = AccountKeyStore()
        _authStore = State(
            initialValue: AuthStore(
                apiClient: apiClient,
                accountKeyStore: accountKeyStore
            )
        )
        _eventStore = State(
            initialValue: EventStore(
                apiClient: apiClient,
                accountKeyStore: accountKeyStore
            )
        )
        _invitationCoordinator = State(
            initialValue: InvitationCoordinator(trustedWebOrigin: apiBaseURL)
        )
    }

    var body: some Scene {
        WindowGroup {
            AppRootView(startsInCreateFlow: startsInCreateFlow)
                .environment(authStore)
                .environment(eventStore)
                .environment(invitationCoordinator)
                .preferredColorScheme(.dark)
                .tint(.white)
                .overlay {
                    if scenePhase != .active {
                        ZStack {
                            HerdTheme.canvas
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 34, weight: .semibold))
                                .foregroundStyle(.secondary)
                        }
                        .ignoresSafeArea()
                        .accessibilityHidden(true)
                    }
                }
                .onChange(of: scenePhase) { _, phase in
                    if phase != .active {
                        eventStore.lockPrivateResponses()
                    }
                }
                .onOpenURL { url in
                    invitationCoordinator.accept(url)
                }
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                    guard let url = activity.webpageURL else { return }
                    invitationCoordinator.accept(url)
                }
        }
    }
}

private struct AppRootView: View {
    @Environment(AuthStore.self) private var authStore
    @Environment(EventStore.self) private var eventStore
    @Environment(InvitationCoordinator.self) private var invitationCoordinator

    let startsInCreateFlow: Bool

    var body: some View {
        Group {
            if authStore.isRestoring {
                HerdTheme.canvas
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(HerdTheme.canvas)
                .accessibilityLabel("Loading Herd")
            } else if authStore.isAuthenticated {
                HomeView(
                    startsInCreateFlow: startsInCreateFlow,
                    initialCreateEvent: initialCreateEvent
                )
            } else {
                AuthenticationView()
            }
        }
        .task {
            eventStore.setUnauthorizedHandler {
                authStore.expireSession()
            }
            authStore.setAccountDeletionCleanupHandler { userID in
                eventStore.eraseLocalAccountData(userID: userID)
            }
            await authStore.restoreSession()
        }
        .task(id: authStore.user?.id) {
            guard let user = authStore.user else {
                eventStore.clearSession()
                return
            }
            eventStore.activate(userID: user.id)
            await eventStore.refresh()
        }
        .task(
            id: PendingInvitationResolutionID(
                userID: authStore.user?.id,
                generation: invitationCoordinator.requestGeneration
            )
        ) {
            guard
                let user = authStore.user,
                invitationCoordinator.pendingToken != nil
            else { return }
            eventStore.activate(userID: user.id)
            await invitationCoordinator.resolve(
                using: eventStore,
                accountID: user.id
            )
        }
    }

    private var initialCreateEvent: HerdEvent? {
#if DEBUG
        HerdUITestEnvironment.current?.prefilledCreateEvent
#else
        nil
#endif
    }
}

private struct PendingInvitationResolutionID: Hashable {
    let userID: String?
    let generation: UInt
}
