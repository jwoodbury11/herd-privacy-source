import SwiftUI

@main
struct HerdHostApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var authStore: AuthStore
    @State private var eventStore: EventStore

    private let startsInCreateFlow = ProcessInfo.processInfo.arguments.contains("--open-create")

    init() {
#if DEBUG
        if let uiTestEnvironment = HerdUITestEnvironment.current {
            uiTestEnvironment.prepare()
            let apiClient = uiTestEnvironment.makeAPIClient()
            let accountKeyStore = uiTestEnvironment.accountKeyStore
            _authStore = State(
                initialValue: AuthStore(
                    apiClient: apiClient,
                    sessionStore: uiTestEnvironment.makeSessionStore(),
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
    }

    var body: some Scene {
        WindowGroup {
            AppRootView(startsInCreateFlow: startsInCreateFlow)
                .environment(authStore)
                .environment(eventStore)
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
                    // Face ID and Touch ID temporarily make the scene inactive.
                    // Only seal replies when the app actually enters the background,
                    // otherwise a successful authentication clears its own result.
                    if phase == .background {
                        eventStore.lockPrivateResponses()
                    }
                }
        }
    }
}

private struct AppRootView: View {
    @Environment(AuthStore.self) private var authStore
    @Environment(EventStore.self) private var eventStore

    let startsInCreateFlow: Bool

    var body: some View {
        ZStack {
            HerdTheme.canvas
                .ignoresSafeArea()
                .accessibilityHidden(true)

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
        }
        .background {
            HerdWindowCanvasInstaller()
                .frame(width: 0, height: 0)
                .allowsHitTesting(false)
                .accessibilityHidden(true)
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
    }

    private var initialCreateEvent: HerdEvent? {
#if DEBUG
        HerdUITestEnvironment.current?.prefilledCreateEvent
#else
        nil
#endif
    }
}
