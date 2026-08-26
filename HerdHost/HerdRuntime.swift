import Foundation

enum HerdRuntime {
    static var isAppClip: Bool {
#if APPCLIP
        true
#else
        false
#endif
    }

    static func invitationToken(from userActivity: NSUserActivity) -> String? {
        guard userActivity.activityType == NSUserActivityTypeBrowsingWeb else {
            return nil
        }
        return invitationToken(from: userActivity.webpageURL)
    }

    static func invitationToken(from url: URL?) -> String? {
        guard
            let url,
            url.scheme?.lowercased() == "https",
            let host = url.host?.lowercased(),
            host == associatedDomain,
            url.query == nil,
            url.fragment == nil
        else {
            return nil
        }

        let components = url.pathComponents.filter { $0 != "/" }
        guard components.count == 2, components[0] == "invite" else {
            return nil
        }
        return InvitationToken.normalize(components[1])
    }

    /// App Clip keychain items are made available to the corresponding full
    /// app by iOS 15.4+ using the parent/App Clip association. Both binaries
    /// must use the same service name, without a custom keychain access group.
    static var parentApplicationBundleIdentifier: String {
        if let configured = Bundle.main.object(
            forInfoDictionaryKey: "HERD_PARENT_BUNDLE_IDENTIFIER"
        ) as? String {
            let value = configured.trimmingCharacters(in: .whitespacesAndNewlines)
            if !value.isEmpty, !value.contains("$(") { return value }
        }
        let bundleIdentifier = Bundle.main.bundleIdentifier ?? "com.herd.app"
        return bundleIdentifier.hasSuffix(".Clip")
            ? String(bundleIdentifier.dropLast(".Clip".count))
            : bundleIdentifier
    }

    private static var associatedDomain: String {
        let configured = Bundle.main.object(
            forInfoDictionaryKey: "HERD_ASSOCIATED_DOMAIN"
        ) as? String
        return configured?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            ?? "app.herdprivacy.com"
    }
}
