import Foundation

enum InvitationToken {
    static let minimumLength = 8
    static let maximumLength = 200

    static func normalize(_ value: String?) -> String? {
        guard let value else { return nil }
        guard
            (minimumLength...maximumLength).contains(value.utf8.count),
            value.unicodeScalars.allSatisfy({ scalar in
                switch scalar.value {
                case 45, 48...57, 65...90, 95, 97...122:
                    true
                default:
                    false
                }
            })
        else { return nil }
        return value
    }
}
