import XCTest

@MainActor
final class HerdHostUITests: XCTestCase {
    override func setUp() {
        super.setUp()
        continueAfterFailure = false
    }

    func testHostCreatesSelectsGuestSendsAndSeesResolvedResult() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        let titleField = app.textFields["event-title"]
        XCTAssertTrue(titleField.waitForExistence(timeout: 5))
        titleField.tap()
        titleField.typeText("UI Coverage Dinner")
        let keyboardDone = app.buttons["event-keyboard-done"]
        XCTAssertTrue(keyboardDone.waitForExistence(timeout: 5))
        keyboardDone.tap()

        let attendees = app.buttons["event-attendees"]
        scrollToMakeHittable(attendees, in: app)
        attendees.tap()

        let fixtureGuest = app.staticTexts["_1 herdTestUser"]
        XCTAssertTrue(fixtureGuest.waitForExistence(timeout: 5))
        fixtureGuest.tap()
        app.navigationBars.buttons["Next"].tap()

        let saveInvitees = app.buttons["save-invitees"]
        XCTAssertTrue(saveInvitees.waitForExistence(timeout: 5))
        saveInvitees.tap()

        let primaryAction = app.buttons["event-primary-action"]
        XCTAssertTrue(primaryAction.waitForExistence(timeout: 5))
        XCTAssertEqual(primaryAction.label, "Send")
        primaryAction.tap()

        XCTAssertTrue(app.staticTexts["Send invitations?"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["One message per guest"].exists)
        XCTAssertTrue(app.staticTexts["Invitations by text"].exists)
        let confirmSend = app.buttons["confirm-send-invitations"]
        XCTAssertTrue(confirmSend.waitForExistence(timeout: 5))
        confirmSend.tap()

        let eventTitle = app.staticTexts["UI Coverage Dinner"]
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 10))
        eventTitle.tap()
        XCTAssertTrue(app.buttons["Back to Herd events"].waitForExistence(timeout: 5))

        app.buttons["Back to Herd events"].tap()
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 5))
        let confirmed = app.staticTexts["Confirmed"]
        XCTAssertTrue(app.buttons["events-status"].waitForExistence(timeout: 5))
        app.swipeDown()
        XCTAssertTrue(confirmed.waitForExistence(timeout: 15))

        eventTitle.tap()
        XCTAssertTrue(app.buttons["Back to Herd events"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Confirmed"].exists)
        XCTAssertFalse(app.staticTexts["_1 herdTestUser"].exists)
    }

    func testContactPickerAddsManualRecipientAndGroupsFilteredSelections() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        let attendees = app.buttons["event-attendees"]
        scrollToMakeHittable(attendees, in: app)
        attendees.tap()

        let manualAdd = app.buttons["manually-add-recipient"]
        XCTAssertTrue(manualAdd.waitForExistence(timeout: 5))
        manualAdd.tap()

        let name = app.textFields["manual-recipient-name"]
        XCTAssertTrue(name.waitForExistence(timeout: 5))
        name.typeText("Manual Guest")

        let phone = app.textFields["manual-recipient-phone"]
        phone.tap()
        for digit in "4155550199" {
            phone.typeText(String(digit))
        }

        let save = app.buttons["save-manual-recipient"]
        XCTAssertTrue(save.isEnabled)
        save.tap()

        XCTAssertTrue(app.staticTexts["Manual Guest"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["contact-section-selected"].exists)
        XCTAssertTrue(app.staticTexts["contact-section-contacts"].exists)

        let search = app.textFields["Search contacts"]
        search.tap()
        search.typeText("Manual")

        XCTAssertTrue(app.staticTexts["Manual Guest"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["contact-section-selected"].exists)
        XCTAssertFalse(app.staticTexts["contact-section-contacts"].exists)

        let keyboardDone = app.keyboards.buttons["Done"]
        XCTAssertTrue(keyboardDone.waitForExistence(timeout: 5))
        keyboardDone.tap()
        XCTAssertFalse(app.keyboards.firstMatch.waitForExistence(timeout: 1))

        app.navigationBars.buttons["Next"].tap()
        XCTAssertTrue(app.navigationBars["Review invites"].waitForExistence(timeout: 5))
        let reviewedName = app.textFields["Name"]
        XCTAssertTrue(reviewedName.waitForExistence(timeout: 5))
        XCTAssertEqual(reviewedName.value as? String, "Manual Guest")
    }

    func testNewEventShowsSaturdayAndDeadlineTogetherInDetails() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        let guestPermission = app.switches["event-allow-attendee-guests"]
        scrollToMakeHittable(guestPermission, in: app)
        XCTAssertEqual(guestPermission.value as? String, "1")
        let switchControl = guestPermission.coordinate(
            withNormalizedOffset: CGVector(dx: 0.92, dy: 0.5)
        )
        switchControl.tap()
        XCTAssertEqual(
            XCTWaiter.wait(
                for: [XCTNSPredicateExpectation(
                    predicate: NSPredicate(format: "value == '0'"),
                    object: guestPermission
                )],
                timeout: 2
            ),
            .completed
        )
        switchControl.tap()
        XCTAssertEqual(
            XCTWaiter.wait(
                for: [XCTNSPredicateExpectation(
                    predicate: NSPredicate(format: "value == '1'"),
                    object: guestPermission
                )],
                timeout: 2
            ),
            .completed
        )
        let eventDate = app.buttons["event-date"]
        let deadline = app.buttons["event-rsvp-deadline"]
        XCTAssertTrue(eventDate.waitForExistence(timeout: 5))
        XCTAssertTrue(deadline.waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["Set a date"].exists)
        XCTAssertFalse(app.staticTexts["Set the event date first"].exists)
        XCTAssertLessThan(eventDate.frame.maxY, deadline.frame.minY)
    }

    func testEmptyLocationSearchSuggestsTheSavedProfileAddress() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])
        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))

        let location = app.buttons["event-location"]
        XCTAssertTrue(location.waitForExistence(timeout: 5))
        location.tap()

        let locationSearch = app.textFields["Place name, address, or link"]
        XCTAssertTrue(locationSearch.waitForExistence(timeout: 5))
        locationSearch.tap()
        locationSearch.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: 64))

        let suggestion = app.buttons["profile-address-suggestion"]
        XCTAssertTrue(suggestion.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["1 Fixture Way"].exists)
        XCTAssertTrue(app.staticTexts["Your profile address"].exists)
    }

    func testProfileSaveEnablesOnlyAfterAChangeAndUsesTheWholeButton() {
        let app = launch(scenario: "host-create")
        let profile = app.buttons["Open profile"]
        XCTAssertTrue(profile.waitForExistence(timeout: 10))
        profile.tap()

        XCTAssertTrue(app.navigationBars.firstMatch.waitForExistence(timeout: 5))
        XCTAssertFalse(app.navigationBars.staticTexts["Your profile"].exists)
        XCTAssertTrue(
            app.staticTexts["Your phone number and address are never shown to other guests."]
                .exists
        )

        let save = app.buttons["profile-save-changes"]
        XCTAssertTrue(save.waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled)

        let logOut = app.buttons["profile-log-out"]
        XCTAssertTrue(logOut.exists)
        XCTAssertLessThan(logOut.frame.width, save.frame.width / 2)
        XCTAssertLessThan(logOut.frame.maxY, save.frame.minY)

        let moreActions = app.buttons["profile-more-actions"]
        XCTAssertTrue(moreActions.exists)
        moreActions.tap()
        XCTAssertTrue(app.buttons["profile-delete-account"].waitForExistence(timeout: 2))
        app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)).tap()
        XCTAssertFalse(app.buttons["profile-delete-account"].exists)

        replaceText(in: app.textFields["profile-name"], with: "Updated UI Host")
        XCTAssertTrue(save.isEnabled)
        save.coordinate(withNormalizedOffset: CGVector(dx: 0.08, dy: 0.5)).tap()

        XCTAssertTrue(app.staticTexts["Profile saved."].waitForExistence(timeout: 5))
        XCTAssertFalse(save.isEnabled)
    }

    func testHostEditsAndPersistsExistingDraft() {
        let app = launch(scenario: "host-edit")

        let draftTitle = app.staticTexts["Fixture Draft"]
        XCTAssertTrue(draftTitle.waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Draft"].exists)
        draftTitle.tap()

        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        let titleField = app.textFields["event-title"]
        XCTAssertTrue(titleField.waitForExistence(timeout: 5))
        replaceText(in: titleField, with: "Edited Fixture Draft")

        let save = app.buttons["event-primary-action"]
        XCTAssertEqual(save.label, "Save")
        save.tap()
        XCTAssertTrue(app.staticTexts["Edited Fixture Draft"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Draft"].exists)
    }

    func testHostDeletesEventForEveryoneAfterConfirmation() {
        let app = launch(scenario: "host-delete")

        let eventTitle = app.staticTexts["Deletable Fixture Event"]
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 10))
        eventTitle.tap()

        let actions = app.buttons["event-actions-menu"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
        actions.tap()
        let deleteAction = app.buttons["delete-hosted-event"]
        XCTAssertTrue(deleteAction.waitForExistence(timeout: 5))
        deleteAction.tap()

        let confirmation = app.alerts["Delete this event?"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 5))
        XCTAssertTrue(
            confirmation.staticTexts[
                "This permanently deletes the event for you and everyone invited. This can’t be undone."
            ].exists
        )
        let confirmationScreenshot = XCTAttachment(screenshot: app.screenshot())
        confirmationScreenshot.name = "host-event-deletion-confirmation"
        confirmationScreenshot.lifetime = .keepAlways
        add(confirmationScreenshot)
        confirmation.buttons["Cancel"].tap()
        XCTAssertTrue(eventTitle.exists)

        actions.tap()
        app.buttons["delete-hosted-event"].tap()
        app.buttons["confirm-delete-hosted-event"].firstMatch.tap()

        XCTAssertTrue(app.staticTexts["Herd events"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Deletable Fixture Event"].exists)
    }

    func testInvitationSurvivesWrongAccountAndOpensForCorrectAccount() {
        let app = launch(scenario: "invitation-account-switch")

        let pendingNotice = app.staticTexts[
            "Your invitation is ready and will open after you sign in."
        ]
        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(
            app,
            phoneNumber: "4155550101"
        )

        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        let switchAccount = app.buttons["switch-invitation-account"]
        XCTAssertTrue(switchAccount.exists)
        switchAccount.tap()

        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(
            app,
            phoneNumber: "4155550102"
        )

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].exists)
        XCTAssertFalse(pendingNotice.exists)
    }

    func testReplyPreviewDismissesFromTheEdgeOfTheVisibleButton() {
        let app = launch(scenario: "invitation-account-switch")

        let pendingNotice = app.staticTexts[
            "Your invitation is ready and will open after you sign in."
        ]
        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550101")
        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        app.buttons["switch-invitation-account"].tap()
        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        let preview = app.buttons["reply-preview-trigger"]
        scrollToMakeHittable(preview, in: app.scrollViews.firstMatch)
        preview.tap()

        let dismiss = app.buttons["reply-preview-dismiss"]
        XCTAssertTrue(dismiss.waitForExistence(timeout: 5))
        XCTAssertGreaterThan(dismiss.frame.width, 250)
        dismiss.coordinate(withNormalizedOffset: CGVector(dx: 0.08, dy: 0.5)).tap()

        XCTAssertFalse(dismiss.waitForExistence(timeout: 1))
        XCTAssertFalse(app.staticTexts["See how your reply will show up to others"].exists)
    }

    func testDeviceSwitchConfirmationReliablyPresentsPhoneVerification() {
        let app = launch(scenario: "invitation-account-switch")

        let pendingNotice = app.staticTexts[
            "Your invitation is ready and will open after you sign in."
        ]
        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550101")
        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        app.buttons["switch-invitation-account"].tap()
        XCTAssertTrue(pendingNotice.waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        let cantCommit = app.buttons["Can’t commit"]
        scrollToMakeHittable(cantCommit, in: app.scrollViews.firstMatch)
        cantCommit.tap()

        let submit = app.buttons["Send my encrypted reply"]
        scrollToMakeHittable(submit, in: app.scrollViews.firstMatch)
        submit.tap()

        let confirmation = app.alerts["Switch private replies to this device?"]
        XCTAssertTrue(confirmation.waitForExistence(timeout: 10))
        confirmation.buttons["Switch to this device"].tap()

        // This is the behavioral regression for the alert-to-sheet race: the
        // recovery UI must remain visible after the confirmation alert leaves.
        XCTAssertTrue(
            app.navigationBars["Confirm your phone number"]
                .waitForExistence(timeout: 5)
        )
        XCTAssertTrue(app.buttons["device-switch-action"].exists)

        app.buttons["Cancel"].tap()
        XCTAssertFalse(
            app.navigationBars["Confirm your phone number"]
                .waitForExistence(timeout: 1)
        )
        XCTAssertTrue(submit.waitForExistence(timeout: 5))
        submit.tap()
        XCTAssertTrue(confirmation.waitForExistence(timeout: 10))
        confirmation.buttons["Cancel"].tap()
        XCTAssertFalse(confirmation.waitForExistence(timeout: 1))
        XCTAssertTrue(
            app.staticTexts["Private Picnic Invitation"]
                .waitForExistence(timeout: 5)
        )
    }

    private func launch(
        scenario: String,
        additionalArguments: [String] = []
    ) -> XCUIApplication {
        let app = XCUIApplication()
        app.launchArguments = ["--herd-ui-testing", scenario] + additionalArguments
        app.launch()
        return app
    }

    private func signIn(_ app: XCUIApplication, phoneNumber: String) {
        let phone = app.textFields["authentication-phone"]
        XCTAssertTrue(phone.waitForExistence(timeout: 5))
        phone.tap()
        // Let SwiftUI finish its per-keystroke formatting before sending the
        // next digit. A single batched typeText can race the formatted state
        // update on slower hosted simulators and drop input.
        for digit in phoneNumber {
            phone.typeText(String(digit))
        }
        XCTAssertEqual(
            (phone.value as? String)?.filter(\.isWholeNumber),
            phoneNumber
        )

        let requestCode = app.buttons["authentication-request-code"]
        XCTAssertTrue(requestCode.waitForExistence(timeout: 5))
        let enabled = XCTNSPredicateExpectation(
            predicate: NSPredicate(format: "isEnabled == true"),
            object: requestCode
        )
        XCTAssertEqual(XCTWaiter.wait(for: [enabled], timeout: 5), .completed)
        requestCode.tap()
    }

    private func replaceText(in field: XCUIElement, with replacement: String) {
        field.tap()
        let currentValue = (field.value as? String) ?? ""
        if !currentValue.isEmpty {
            field.typeText(
                String(repeating: XCUIKeyboardKey.delete.rawValue, count: currentValue.count)
            )
        }
        field.typeText(replacement)
    }

    private func scrollToMakeHittable(_ element: XCUIElement, in app: XCUIApplication) {
        let scrollView = app.scrollViews["event-editor-scroll"]
        XCTAssertTrue(scrollView.waitForExistence(timeout: 5))
        // iOS 26 can route upward swipes to the focused multiline TextField's
        // keyboard instead of the editor ScrollView. Dismiss it interactively
        // first so this helper proves the row is actually reachable.
        if app.keyboards.firstMatch.exists {
            scrollView.swipeDown()
        }
        var attempts = 0
        while (!element.exists || !element.isHittable), attempts < 8 {
            scrollView.swipeUp()
            attempts += 1
        }
        XCTAssertTrue(element.exists)
        XCTAssertTrue(element.isHittable)
    }

    private func scrollToMakeHittable(_ element: XCUIElement, in scrollView: XCUIElement) {
        XCTAssertTrue(scrollView.waitForExistence(timeout: 5))
        var attempts = 0
        while (!element.exists || !element.isHittable), attempts < 8 {
            scrollView.swipeUp()
            attempts += 1
        }
        XCTAssertTrue(element.exists)
        XCTAssertTrue(element.isHittable)
    }
}
