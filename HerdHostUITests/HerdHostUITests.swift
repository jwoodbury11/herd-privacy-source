import UIKit
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
        let editorScroll = app.scrollViews["event-editor-scroll"]
        XCTAssertTrue(editorScroll.waitForExistence(timeout: 5))
        editorScroll.swipeDown()
        let titleField = app.descendants(matching: .any)["event-title"]
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

    func testBlankDraftAlwaysSavesAsUntitledEvent() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Still needed"].exists)
        XCTAssertFalse(app.staticTexts["Add an event title"].exists)

        let save = app.buttons["event-primary-action"]
        XCTAssertTrue(save.waitForExistence(timeout: 5))
        XCTAssertEqual(save.label, "Save")
        XCTAssertTrue(save.isEnabled)
        save.tap()

        let untitledEvent = app.staticTexts["Untitled event"]
        XCTAssertTrue(untitledEvent.waitForExistence(timeout: 10))
        untitledEvent.tap()

        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Untitled event"].exists)
    }

    func testKeyboardSurroundDoesNotExposePureBlack() throws {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        let titleField = app.descendants(matching: .any)["event-title"]
        XCTAssertTrue(titleField.waitForExistence(timeout: 5))
        titleField.tap()

        let keyboard = app.keyboards.firstMatch
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5))
        let screenshot = XCUIScreen.main.screenshot()
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = "Keyboard surround matches Herd canvas"
        attachment.lifetime = .keepAlways
        add(attachment)

        let keyboardFrame = keyboard.frame
        let outsideTopLeft = CGPoint(
            x: keyboardFrame.minX + 3,
            y: keyboardFrame.minY + 3
        )
        let adjacentCanvas = CGPoint(
            x: keyboardFrame.minX + 3,
            y: keyboardFrame.minY - 7
        )
        let outsideColor = try XCTUnwrap(rgb(in: screenshot.image, at: outsideTopLeft))
        let canvasColor = try XCTUnwrap(rgb(in: screenshot.image, at: adjacentCanvas))

        XCTAssertGreaterThan(
            luminance(outsideColor),
            0.05,
            "The keyboard surround must not fall back to pure black."
        )
        XCTAssertLessThan(
            colorDistance(outsideColor, canvasColor),
            0.08,
            "The keyboard's transparent rounded corner must reveal the Herd canvas, not black."
        )
    }

    private func luminance(_ color: (CGFloat, CGFloat, CGFloat)) -> CGFloat {
        0.2126 * color.0 + 0.7152 * color.1 + 0.0722 * color.2
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

        let clearSearch = app.buttons["clear-contact-search"]
        XCTAssertTrue(clearSearch.waitForExistence(timeout: 5))
        clearSearch.tap()
        XCTAssertFalse(clearSearch.exists)
        XCTAssertTrue(app.staticTexts["contact-section-selected"].exists)
        XCTAssertTrue(app.staticTexts["contact-section-contacts"].exists)
        XCTAssertTrue(app.keyboards.firstMatch.exists)

        let keyboardReturn = app.keyboards.buttons["return"]
        XCTAssertTrue(keyboardReturn.waitForExistence(timeout: 5))
        keyboardReturn.tap()
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
        let clearSearch = app.buttons["clear-location-search"]
        XCTAssertTrue(clearSearch.waitForExistence(timeout: 5))
        clearSearch.tap()

        let suggestion = app.buttons["profile-address-suggestion"]
        XCTAssertTrue(suggestion.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["1 Fixture Way"].exists)
        XCTAssertTrue(app.staticTexts["Your profile address"].exists)

        suggestion.tap()
        let unitNumber = app.textFields["location-unit-number"]
        XCTAssertTrue(unitNumber.waitForExistence(timeout: 5))
        unitNumber.tap()
        unitNumber.typeText("7")
        app.navigationBars["Location"].buttons["Done"].tap()

        XCTAssertTrue(location.waitForExistence(timeout: 5))
        location.tap()
        let reopenedUnitNumber = app.textFields["location-unit-number"]
        XCTAssertTrue(reopenedUnitNumber.waitForExistence(timeout: 5))
        XCTAssertEqual(reopenedUnitNumber.value as? String, "7")
    }

    func testKeyboardIsDismissedWhenReturningFromEditorChildFlows() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])
        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))

        let location = app.buttons["event-location"]
        XCTAssertTrue(location.waitForExistence(timeout: 5))
        location.tap()

        let locationSearch = app.textFields["Place name, address, or link"]
        XCTAssertTrue(locationSearch.waitForExistence(timeout: 5))
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        locationSearch.typeText("Coffee")
        app.navigationBars["Location"].buttons["Cancel"].tap()

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.keyboards.firstMatch.waitForExistence(timeout: 1))

        let attendees = app.buttons["event-attendees"]
        scrollToMakeHittable(attendees, in: app)
        attendees.tap()
        XCTAssertTrue(app.textFields["Search contacts"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.keyboards.firstMatch.waitForExistence(timeout: 5))
        app.navigationBars.buttons["Cancel"].tap()

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.keyboards.firstMatch.waitForExistence(timeout: 1))
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

        XCTAssertFalse(app.keyboards.firstMatch.exists)
        XCTAssertFalse(app.staticTexts["Profile saved."].exists)
        XCTAssertFalse(save.isEnabled)
    }

    func testProfileAddressUsesTheLocationAutocompleteFlow() {
        let app = launch(scenario: "host-create")
        let profile = app.buttons["Open profile"]
        XCTAssertTrue(profile.waitForExistence(timeout: 10))
        profile.tap()

        let address = app.buttons["profile-address"]
        XCTAssertTrue(address.waitForExistence(timeout: 5))
        XCTAssertEqual(address.value as? String, "1 Fixture Way")
        address.tap()

        let addressSearch = app.textFields["profile-address-search"]
        XCTAssertTrue(addressSearch.waitForExistence(timeout: 5))
        XCTAssertEqual(addressSearch.value as? String, "1 Fixture Way")
        XCTAssertTrue(app.navigationBars["Address"].exists)

        let clearSearch = app.buttons["clear-profile-address-search"]
        XCTAssertTrue(clearSearch.waitForExistence(timeout: 5))
        clearSearch.tap()
        XCTAssertEqual(addressSearch.value as? String, "Street, city, state")
        addressSearch.typeText("219 Cumberland")

        let suggestion = app.buttons["profile-address-result-0"]
        XCTAssertTrue(suggestion.waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["219 Cumberland Street"].exists)
        suggestion.tap()
        XCTAssertFalse(clearSearch.exists)
        XCTAssertFalse(suggestion.exists)

        let unitNumber = app.textFields["profile-unit-number"]
        XCTAssertTrue(unitNumber.waitForExistence(timeout: 5))
        unitNumber.tap()
        unitNumber.typeText("5")
        app.navigationBars["Address"].buttons["Done"].tap()

        XCTAssertTrue(address.waitForExistence(timeout: 5))
        XCTAssertEqual(
            address.value as? String,
            "219 Cumberland Street, San Francisco, CA 94114, Unit 5"
        )
        XCTAssertTrue(app.buttons["profile-save-changes"].isEnabled)
    }

    func testHostSavesReopensAndDeletesExistingDraft() {
        let app = launch(scenario: "host-edit")

        let draftTitle = app.staticTexts["Fixture Draft"]
        XCTAssertTrue(draftTitle.waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Draft"].exists)
        draftTitle.tap()

        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        let save = app.buttons["event-primary-action"]
        XCTAssertEqual(save.label, "Save")
        save.tap()
        XCTAssertTrue(app.staticTexts["Edited Fixture Draft"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Draft"].exists)

        app.staticTexts["Edited Fixture Draft"].tap()
        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        app.buttons["event-close"].tap()

        let deletion = app.alerts["Delete this draft?"]
        XCTAssertTrue(deletion.waitForExistence(timeout: 5))
        XCTAssertTrue(
            deletion.staticTexts["This permanently deletes the draft. This can’t be undone."].exists
        )
        deletion.buttons["Cancel"].tap()
        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))

        app.buttons["event-close"].tap()
        XCTAssertTrue(deletion.waitForExistence(timeout: 5))
        deletion.buttons.matching(identifier: "confirm-delete-draft").firstMatch.tap()
        XCTAssertTrue(app.staticTexts["Herd events"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Edited Fixture Draft"].exists)
    }

    func testUnsavedDraftRequiresConfirmationBeforeAbandoning() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        app.buttons["event-close"].tap()

        let abandonment = app.alerts["Abandon this draft?"]
        XCTAssertTrue(abandonment.waitForExistence(timeout: 5))
        XCTAssertTrue(abandonment.staticTexts["This unsaved draft will be deleted."].exists)
        abandonment.buttons["Cancel"].tap()
        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 5))

        app.buttons["event-close"].tap()
        XCTAssertTrue(abandonment.waitForExistence(timeout: 5))
        abandonment.buttons.matching(identifier: "confirm-abandon-draft").firstMatch.tap()
        XCTAssertTrue(app.staticTexts["Herd events"].waitForExistence(timeout: 10))
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

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
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

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
        signIn(
            app,
            phoneNumber: "4155550102"
        )

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].exists)
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
    }

    func testReplyPreviewDismissesFromTheEdgeOfTheVisibleButton() {
        let app = launch(scenario: "invitation-account-switch")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
        signIn(app, phoneNumber: "4155550101")
        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        app.buttons["switch-invitation-account"].tap()
        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
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
        XCTAssertFalse(app.staticTexts["How your reply shows up to others"].exists)
    }

    func testRepeatedLockedGuestStatusTapsCannotDismissAttendees() {
        let app = launch(scenario: "invitation-account-switch")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550101")
        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        app.buttons["switch-invitation-account"].tap()
        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        let guestList = app.staticTexts["See the full guest list"]
        scrollToMakeHittable(guestList, in: app.scrollViews.firstMatch)
        guestList.tap()

        XCTAssertTrue(app.navigationBars["Attendees"].waitForExistence(timeout: 5))
        let lockedStatuses = app.buttons.matching(
            NSPredicate(format: "label == %@", "Guest status hidden")
        )
        XCTAssertTrue(lockedStatuses.firstMatch.waitForExistence(timeout: 5))
        let tapPoints = lockedStatuses.allElementsBoundByIndex
            .filter(\.isHittable)
            .prefix(5)
            .map { $0.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.5)) }
        XCTAssertGreaterThanOrEqual(tapPoints.count, 3)
        for _ in 0..<4 {
            for tapPoint in tapPoints {
                tapPoint.tap()
            }
        }

        XCTAssertTrue(app.navigationBars["Attendees"].exists)
        XCTAssertTrue(app.staticTexts["locked-guest-status-notice"].exists)
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "Repeated locked status taps remain on attendees"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testAttendeeResponsesRefreshAcrossAccountsWhileEventIsOpen() {
        let app = launch(scenario: "response-progress-refresh")

        let event = app.staticTexts["Response Refresh Fixture"]
        XCTAssertTrue(event.waitForExistence(timeout: 10))
        event.tap()

        let guestList = app.staticTexts["See the full guest list"]
        scrollToMakeHittable(guestList, in: app.scrollViews.firstMatch)
        guestList.tap()

        XCTAssertTrue(app.navigationBars["Attendees"].waitForExistence(timeout: 5))
        let responded = app.staticTexts.matching(
            NSPredicate(format: "label == %@", "Responded")
        )
        XCTAssertEqual(responded.count, 2)
        XCTAssertTrue(app.staticTexts["Not responded"].exists)
    }

    func testAccountWideReplyNeverPresentsDeviceTransfer() {
        let app = launch(scenario: "invitation-account-switch")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
        signIn(app, phoneNumber: "4155550101")
        XCTAssertTrue(
            app.staticTexts["This invitation is for another account"]
                .waitForExistence(timeout: 10)
        )
        app.buttons["switch-invitation-account"].tap()
        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(
            app.staticTexts["Your invitation is ready and will open after you sign in."].exists
        )
        signIn(app, phoneNumber: "4155550102")

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        let cantCommit = app.buttons["Can’t commit"]
        scrollToMakeHittable(cantCommit, in: app.scrollViews.firstMatch)
        cantCommit.tap()

        let submit = app.buttons["Send my private reply"]
        scrollToMakeHittable(submit, in: app.scrollViews.firstMatch)
        submit.tap()

        XCTAssertFalse(
            app.alerts["Switch private replies to this device?"]
                .waitForExistence(timeout: 1)
        )
        XCTAssertFalse(app.buttons["device-switch-action"].exists)
        XCTAssertFalse(app.navigationBars["Confirm your phone number"].exists)
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

    private func rgb(in image: UIImage, at point: CGPoint) -> (CGFloat, CGFloat, CGFloat)? {
        guard let cgImage = image.cgImage else { return nil }
        let xScale = CGFloat(cgImage.width) / image.size.width
        let yScale = CGFloat(cgImage.height) / image.size.height
        let x = min(max(Int(point.x * xScale), 0), cgImage.width - 1)
        let y = min(max(Int(point.y * yScale), 0), cgImage.height - 1)
        guard
            let data = cgImage.dataProvider?.data,
            let bytes = CFDataGetBytePtr(data)
        else { return nil }

        let pixel = bytes + y * cgImage.bytesPerRow + x * (cgImage.bitsPerPixel / 8)
        guard cgImage.bitsPerPixel >= 24 else { return nil }
        return (
            CGFloat(pixel[0]) / 255,
            CGFloat(pixel[1]) / 255,
            CGFloat(pixel[2]) / 255
        )
    }

    private func colorDistance(
        _ lhs: (CGFloat, CGFloat, CGFloat),
        _ rhs: (CGFloat, CGFloat, CGFloat)
    ) -> CGFloat {
        sqrt(
            pow(lhs.0 - rhs.0, 2) +
            pow(lhs.1 - rhs.1, 2) +
            pow(lhs.2 - rhs.2, 2)
        )
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
