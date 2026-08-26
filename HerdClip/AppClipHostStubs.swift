import SwiftUI

/// Contacts are intentionally absent from the App Clip. Host-entry points are
/// routed to the full-app handoff before this fallback can be presented.
struct AttendeeFlowView: View {
    init(
        invitees: Binding<[Invitee]>,
        excludedPhoneNumber: String? = nil,
        excludedPhoneNumbers: [String] = []
    ) {
        _ = invitees
        _ = excludedPhoneNumber
        _ = excludedPhoneNumbers
    }

    var body: some View {
        ContentUnavailableView(
            "Get Herd to add attendees",
            systemImage: "person.crop.circle.badge.plus",
            description: Text("Hosting is available in the full Herd app.")
        )
        .background(HerdTheme.canvas.ignoresSafeArea())
    }
}
