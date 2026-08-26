import SwiftUI

@main
struct HerdClipApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var authStore: AuthStore
    @State private var eventStore: EventStore
    @State private var invitationToken: String?

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
        let apiClient = APIClient(baseURL: APIClient.configuredBaseURL)
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
            AppRootView(
                startsInCreateFlow: false,
                invitationToken: invitationToken
            )
            .environment(authStore)
            .environment(eventStore)
            .preferredColorScheme(.dark)
            .tint(.white)
            .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                invitationToken = HerdRuntime.invitationToken(from: activity)
            }
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
                if phase == .background {
                    eventStore.lockPrivateResponses()
                }
            }
        }
    }
}
