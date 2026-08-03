import Foundation

struct HerdExperience: Decodable {
    struct Authentication: Decodable {
        struct ReleaseStatus: Decodable {
            let label: String
            let heading: String
            let body: String
            let dismissButton: String
        }

        struct Welcome: Decodable {
            let title: String
            let body: String
            let phoneLabel: String
            let phonePlaceholder: String
            let requestCodeButton: String
            let requestCodePendingButton: String
        }

        struct Verification: Decodable {
            let navigationTitle: String
            let title: String
            let bodyPrefix: String
            let codeAccessibilityLabel: String
            let changePhoneAccessibilityLabel: String
            let verifyButton: String
            let verifyPendingButton: String
            let resendButton: String
            let resendPendingPrefix: String
        }

        struct Legal: Decodable {
            let prefix: String
            let terms: String
            let privacy: String
            let suffix: String
        }

        struct Layout: Decodable {
            let horizontalPadding: Double
            let topPadding: Double
            let welcomeTopSpacing: Double
            let fieldHeight: Double
            let buttonHeight: Double
            let fieldCornerRadius: Double
            let buttonCornerRadius: Double
            let verificationCodeGap: Double
            let verificationCodeWidth: Double
            let verificationCodeHeight: Double
            let verificationCodeCornerRadius: Double
            let verificationCodeAlignment: String
        }

        let brandName: String
        let releaseStatus: ReleaseStatus
        let welcome: Welcome
        let verification: Verification
        let legal: Legal
        let layout: Layout
    }

    struct Home: Decodable {
        struct Metrics: Decodable {
            let invited: String
            let minimum: String
            let leftToRespond: String
            let noDeadline: String
            let responsesClosed: String
        }

        struct Layout: Decodable {
            let horizontalPadding: Double
            let topPadding: Double
            let bottomPadding: Double
            let verticalGap: Double
            let headerToFirstCardGap: Double
            let cardCornerRadius: Double
            let cardPadding: Double
            let createCardMinimumHeight: Double
            let profileAvatarDiameter: Double
        }

        struct Profile: Decodable {
            let accessibilityLabel: String
            let useGenericIconWithoutName: Bool
        }

        struct WebCreateEventHandoff: Decodable {
            let heading: String
            let body: String
            let backButton: String
        }

        let title: String
        let createEventTitle: String
        let hostStatus: String
        let inviteeStatus: String
        let dateNotSet: String
        let untitledEvent: String
        let profile: Profile
        let metrics: Metrics
        let layout: Layout
        let webCreateEventHandoff: WebCreateEventHandoff
    }

    struct Profile: Decodable {
        struct Logout: Decodable {
            let title: String
            let body: String
            let cancelButton: String
            let confirmButton: String
        }

        struct AccountDeletion: Decodable {
            let title: String
            let body: String
            let cancelButton: String
            let continueButton: String
            let verificationTitle: String
            let verificationBody: String
            let codeLabel: String
            let codePlaceholder: String
            let verifyButton: String
            let deletingButton: String
        }

        let navigationTitle: String
        let title: String
        let nameLabel: String
        let namePlaceholder: String
        let phoneLabel: String
        let addressLabel: String
        let addressPlaceholder: String
        let syncNote: String
        let saveButton: String
        let savedNotice: String
        let logoutButton: String
        let deleteAccountButton: String
        let logout: Logout
        let accountDeletion: AccountDeletion
    }

    struct Invitation: Decodable {
        struct Status: Decodable {
            let hosting: String
            let responded: String
            let replyNeeded: String
            let repliesOpen: String
            let finalizing: String
            let confirmed: String
            let notConfirmed: String
        }

        struct Metrics: Decodable {
            let invited: String
            let minimum: String
            let leftToRespond: String
            let attending: String
            let notConfirmed: String
        }

        struct AttendeeEntry: Decodable {
            let peopleInvitedSuffix: String
            let action: String
        }

        struct PrivacyCallout: Decodable {
            let title: String
            let body: String
            let action: String
        }

        struct Resolution: Decodable {
            let pendingTitle: String
            let pendingBody: String
            let confirmedTitle: String
            let confirmedBody: String
            let notConfirmedTitle: String
            let notConfirmedBody: String
            let finalizedPrefix: String
        }

        let navigationTitle: String
        let untitledEvent: String
        let dateNotSet: String
        let locationNotSet: String
        let hostPrefix: String
        let hostMinimumNote: String
        let replyByPrefix: String
        let noReplyDeadline: String
        let remainingSuffix: String
        let responsesClosed: String
        let status: Status
        let metrics: Metrics
        let attendeeEntry: AttendeeEntry
        let privacyCallout: PrivacyCallout
        let resolution: Resolution
        let unavailableTitle: String
        let unavailableBody: String
    }

    struct Attendees: Decodable {
        let navigationTitle: String
        let title: String
        let hostLabel: String
        let invitedSuffix: String
        let currentUserLabel: String
        let emptyMessage: String
    }

    struct Reply: Decodable {
        struct Reset: Decodable {
            let title: String
            let body: String
            let cancelButton: String
            let confirmButton: String
        }

        let title: String
        let privacyNote: String
        let openingSaved: String
        let unreadable: String
        let goingPrefix: String
        let goingSuffix: String
        let decreaseMinimum: String
        let increaseMinimum: String
        let cantCommitTitle: String
        let cantCommitBody: String
        let addCondition: String
        let addAlternative: String
        let conditionHelp: String
        let conditionPickerTitle: String
        let conditionPickerBody: String
        let conditionPickerEmpty: String
        let removeCondition: String
        let chooseButton: String
        let submitButton: String
        let submittingButton: String
        let savedTitle: String
        let unlockButton: String
        let closedMessage: String
        let missingLinkMessage: String
        let reset: Reset
    }

    struct Privacy: Decodable {
        struct Section: Decodable, Identifiable {
            let title: String
            let paragraphs: [String]
            var id: String { title }
        }

        let navigationTitle: String
        let eyebrow: String
        let title: String
        let intro: String
        let statusEyebrow: String
        let statusTitle: String
        let builtLabel: String
        let builtTitle: String
        let builtBody: String
        let pendingLabel: String
        let pendingTitle: String
        let pendingBody: String
        let flowEyebrow: String
        let flowTitle: String
        let flowSourceTitle: String
        let flowSourceBody: String
        let flowEnvelopeTitle: String
        let flowEnvelopeBody: String
        let flowDestinationTitle: String
        let flowDestinationBody: String
        let flowNote: String
        let answersEyebrow: String
        let answersTitle: String
        let answersIntro: String
        let sections: [Section]
    }

    struct Success: Decodable {
        let title: String
        let body: String
        let savedReplyLabel: String
        let savedReplyTitle: String
        let goingLabel: String
        let cantCommitLabel: String
        let goingPrivacy: String
        let cantCommitPrivacy: String
        let visibilityLabel: String
        let visibilityTitle: String
        let visibilityBody: String
        let changeWithDeadlinePrefix: String
        let changeWithoutDeadline: String
        let viewInvitationButton: String
        let homeButton: String
    }

    let authentication: Authentication
    let home: Home
    let profile: Profile
    let invitation: Invitation
    let attendees: Attendees
    let reply: Reply
    let privacy: Privacy
    let success: Success

    static let shared: HerdExperience = {
        guard let url = Bundle.main.url(forResource: "HerdExperience", withExtension: "json") else {
            preconditionFailure("HerdExperience.json is missing from the app bundle.")
        }

        do {
            return try JSONDecoder().decode(HerdExperience.self, from: Data(contentsOf: url))
        } catch {
            preconditionFailure("HerdExperience.json is invalid: \(error.localizedDescription)")
        }
    }()
}
