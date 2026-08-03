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

        XCTAssertTrue(app.staticTexts["Send one-time invitations?"].waitForExistence(timeout: 5))
        let confirmSend = app.buttons["confirm-send-invitations"]
        XCTAssertTrue(confirmSend.waitForExistence(timeout: 5))
        confirmSend.tap()

        let eventTitle = app.staticTexts["UI Coverage Dinner"]
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 10))
        eventTitle.tap()
        XCTAssertTrue(app.staticTexts["Invitations submitted"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Replies stay private until the deadline"].exists)

        app.buttons["Back to Herd events"].tap()
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 5))
        let confirmed = app.staticTexts["Confirmed"]
        for _ in 0..<2 where !confirmed.exists {
            pullToRefresh(app)
            if confirmed.waitForExistence(timeout: 5) {
                break
            }
        }
        XCTAssertTrue(confirmed.exists)

        eventTitle.tap()
        XCTAssertTrue(app.staticTexts["Event confirmed"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["UI Host"].exists)
        XCTAssertTrue(app.staticTexts["_1 herdTestUser"].exists)
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

        XCTAssertTrue(app.navigationBars["Invitation"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].exists)
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].exists)
        XCTAssertFalse(pendingNotice.exists)
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
        phone.typeText(phoneNumber)

        let requestCode = app.buttons["authentication-request-code"]
        XCTAssertTrue(requestCode.isEnabled)
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
        var attempts = 0
        while (!element.exists || !element.isHittable), attempts < 8 {
            app.swipeUp()
            attempts += 1
        }
        XCTAssertTrue(element.exists)
        XCTAssertTrue(element.isHittable)
    }

    private func pullToRefresh(_ app: XCUIApplication) {
        // A first downward swipe guarantees a retained ScrollView offset is
        // back at its top; the longer drag then crosses the refresh threshold.
        app.swipeDown()
        let start = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.18))
        let end = app.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.82))
        start.press(forDuration: 0.15, thenDragTo: end)
    }
}
