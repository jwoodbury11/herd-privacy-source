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

    func testEventImagePreviewSelectionSaveAndReopenStayInSync() {
        let app = launch(scenario: "host-create", additionalArguments: ["--open-create"])

        XCTAssertTrue(app.navigationBars["New event"].waitForExistence(timeout: 10))
        let poker = app.buttons["event-image-poker"]
        XCTAssertTrue(poker.waitForExistence(timeout: 5))
        XCTAssertEqual(poker.value as? String, "Selected")

        let carousel = app.scrollViews["event-image-carousel"]
        XCTAssertTrue(carousel.waitForExistence(timeout: 5))
        let preview = app.buttons["event-image-preview-fishing"]
        for _ in 0..<6 where !preview.exists || preview.frame.isEmpty || !preview.frame.intersects(carousel.frame) {
            carousel.swipeLeft()
        }
        XCTAssertTrue(preview.exists)
        XCTAssertFalse(preview.frame.isEmpty)
        XCTAssertTrue(preview.frame.intersects(carousel.frame))
        XCTAssertTrue(preview.isHittable)
        preview.tap()
        let fishingPreview = app.images["event-image-preview-full-fishing"]
        XCTAssertTrue(fishingPreview.waitForExistence(timeout: 5))
        app.swipeLeft()
        let birthdayPreview = app.images["event-image-preview-full-birthday-party"]
        XCTAssertTrue(birthdayPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(birthdayPreview.isHittable)
        app.swipeRight()
        XCTAssertTrue(fishingPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(fishingPreview.isHittable)
        app.swipeLeft()
        XCTAssertTrue(birthdayPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(birthdayPreview.isHittable)
        app.swipeLeft()
        let jacuzziPreview = app.images["event-image-preview-full-jacuzzi"]
        XCTAssertTrue(jacuzziPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(jacuzziPreview.isHittable)
        app.swipeLeft()
        let skiingPreview = app.images["event-image-preview-full-skiing"]
        XCTAssertTrue(skiingPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(skiingPreview.isHittable)
        app.swipeLeft()
        let otherPreview = app.images["event-image-preview-full-other"]
        XCTAssertTrue(otherPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(otherPreview.isHittable)
        app.swipeRight()
        XCTAssertTrue(skiingPreview.waitForExistence(timeout: 5))
        XCTAssertTrue(skiingPreview.isHittable)
        let skiingPreviewName = app.staticTexts["event-image-preview-name-skiing"]
        XCTAssertTrue(skiingPreviewName.waitForExistence(timeout: 5))
        XCTAssertEqual(skiingPreviewName.label, "Skiing")
        let previewDone = app.buttons["event-image-preview-done"]
        XCTAssertTrue(previewDone.waitForExistence(timeout: 5))
        XCTAssertEqual(previewDone.label, "Done")
        let previewScreenshot = XCTAttachment(screenshot: app.screenshot())
        previewScreenshot.name = "event-image-preview-selects-current-page"
        previewScreenshot.lifetime = .keepAlways
        add(previewScreenshot)
        previewDone.tap()

        let skiing = app.buttons["event-image-skiing"]
        XCTAssertTrue(skiing.waitForExistence(timeout: 5))
        XCTAssertTrue(skiing.isHittable)
        XCTAssertEqual(skiing.value as? String, "Selected")

        app.buttons["event-primary-action"].tap()
        let cardImage = app.images["event-card-image-skiing"]
        XCTAssertTrue(cardImage.waitForExistence(timeout: 10))

        app.staticTexts["Untitled event"].tap()
        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        let reopenedSkiing = app.buttons["event-image-skiing"]
        XCTAssertTrue(reopenedSkiing.waitForExistence(timeout: 5))
        XCTAssertTrue(reopenedSkiing.isHittable)
        XCTAssertEqual(reopenedSkiing.value as? String, "Selected")
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
        XCTAssertFalse(app.buttons["Dismiss keyboard"].exists)

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

    func testConfirmedHostEditsDetailsWhileAttendanceRulesStayLocked() {
        let app = launch(scenario: "host-delete")

        let eventTitle = app.staticTexts["Deletable Fixture Event"]
        XCTAssertTrue(eventTitle.waitForExistence(timeout: 10))
        eventTitle.tap()

        let actions = app.buttons["event-actions-menu"]
        XCTAssertTrue(actions.waitForExistence(timeout: 5))
        actions.tap()
        let editAction = app.buttons["edit-hosted-event"]
        XCTAssertTrue(editAction.waitForExistence(timeout: 5))
        XCTAssertEqual(editAction.label, "Edit this event")
        editAction.tap()

        XCTAssertTrue(app.navigationBars["Edit event"].waitForExistence(timeout: 5))
        XCTAssertEqual(app.buttons["event-primary-action"].label, "Save")

        let deadline = app.buttons["event-rsvp-deadline"]
        XCTAssertTrue(deadline.waitForExistence(timeout: 5))
        deadline.tap()
        let lockToast = app.staticTexts["confirmed-event-edit-lock-toast"]
        XCTAssertTrue(lockToast.waitForExistence(timeout: 5))
        XCTAssertEqual(
            lockToast.label,
            "Attendance settings and the RSVP deadline can’t be changed after confirmation."
        )
        let lockedEditorScreenshot = XCTAttachment(screenshot: app.screenshot())
        lockedEditorScreenshot.name = "confirmed-event-edit-lock-toast"
        lockedEditorScreenshot.lifetime = .keepAlways
        add(lockedEditorScreenshot)

        let attendanceLock = app.buttons["event-attendance-settings-locked"]
        scrollToMakeHittable(attendanceLock, in: app)
        attendanceLock.tap()
        XCTAssertTrue(lockToast.exists)

        let requiredLock = app.buttons["event-required-attendees-locked"]
        scrollToMakeHittable(requiredLock, in: app)
        requiredLock.tap()
        XCTAssertTrue(lockToast.exists)

        let editorScroll = app.scrollViews["event-editor-scroll"]
        for _ in 0..<5 {
            editorScroll.swipeDown()
        }
        let titleField = app.descendants(matching: .any)["event-title"]
        XCTAssertTrue(titleField.waitForExistence(timeout: 5))
        replaceText(in: titleField, with: "Updated Confirmed Event")
        app.buttons["event-keyboard-done"].tap()
        app.buttons["event-primary-action"].tap()

        let updatedTitle = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS %@", "Updated Confirmed Event")
        ).firstMatch
        XCTAssertTrue(updatedTitle.waitForExistence(timeout: 10))
        XCTAssertTrue(app.staticTexts["Confirmed"].exists)
    }

    func testHomeEventCardStacksStatusTitleAndDateWithoutLocation() {
        let app = launch(scenario: "host-delete")
        let eventID = "20000000-0000-0000-0000-000000000003"

        let status = app.staticTexts["event-card-status-\(eventID)"]
        let title = app.staticTexts["event-card-title-\(eventID)"]
        let date = app.staticTexts["event-card-date-\(eventID)"]
        XCTAssertTrue(status.waitForExistence(timeout: 10))
        XCTAssertTrue(title.exists)
        XCTAssertTrue(date.exists)

        XCTAssertLessThan(status.frame.maxY, title.frame.minY)
        XCTAssertLessThan(title.frame.maxY, date.frame.minY)
        XCTAssertFalse(app.staticTexts["Fixture Park"].exists)

        let eventCard = app.buttons["event-card-\(eventID)"]
        let createCard = app.buttons["create-event-card"]
        let cardImage = app.images["event-card-image-poker"].firstMatch
        XCTAssertTrue(eventCard.exists)
        XCTAssertTrue(createCard.exists)
        XCTAssertTrue(cardImage.exists)
        XCTAssertGreaterThanOrEqual(cardImage.frame.width, 140)
        XCTAssertGreaterThanOrEqual(eventCard.frame.height, 226)
        XCTAssertEqual(eventCard.frame.height, createCard.frame.height, accuracy: 1)
    }

    func testInvitationSignInUsesStandardSplashAndShowsInviteOnHome() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Herd"].exists)
        XCTAssertFalse(app.buttons["Pre-release alpha"].exists)
        XCTAssertFalse(app.staticTexts["Private Picnic Invitation"].exists)
        signIn(app, phoneNumber: "4155550102")

        XCTAssertTrue(app.staticTexts["Private Picnic Invitation"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Opened only after the invitation account matches."].exists)
        XCTAssertFalse(app.buttons["switch-invitation-account"].exists)
    }

    func testWelcomePhoneEntryUsesPlaceholderAndPinsActionsAboveKeyboard() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        let phone = app.textFields["authentication-phone"]
        XCTAssertTrue(phone.waitForExistence(timeout: 5))
        XCTAssertEqual(phone.placeholderValue, "Sign in with phone")
        XCTAssertFalse(app.staticTexts["Sign in with phone number"].exists)

        let keyboard = app.keyboards.firstMatch
        let legal = app.staticTexts["authentication-legal"]
        let action = app.buttons["authentication-request-code"]
        XCTAssertTrue(keyboard.waitForExistence(timeout: 5))
        XCTAssertTrue(legal.exists)
        XCTAssertTrue(action.exists)
        XCTAssertLessThan(action.frame.maxY, legal.frame.minY)
        let keyboardGap = keyboard.frame.minY - legal.frame.maxY
        XCTAssertGreaterThanOrEqual(keyboardGap, 4)
        XCTAssertLessThanOrEqual(keyboardGap, 24)

        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "welcome-keyboard-layout"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testEventDetailHeroReachesNavigationAndScrollShowsTruncatedTitleDivider() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()

        let hero = app.images["event-detail-image-poker"]
        let back = app.buttons["Back to Herd events"]
        XCTAssertTrue(hero.waitForExistence(timeout: 10))
        XCTAssertTrue(back.exists)
        XCTAssertLessThanOrEqual(abs(hero.frame.minY - back.frame.minY), 32)
        XCTAssertGreaterThanOrEqual(hero.frame.height, 315)
        let expandedTitle = app.staticTexts["event-detail-expanded-title"]
        let collapsedTitle = app.staticTexts["event-detail-collapsed-title"]
        XCTAssertTrue(expandedTitle.exists)
        XCTAssertFalse(collapsedTitle.exists)
        let expandedScreenshot = XCTAttachment(screenshot: app.screenshot())
        expandedScreenshot.name = "event-detail-hero-under-navigation"
        expandedScreenshot.lifetime = .keepAlways
        add(expandedScreenshot)

        let detailScroll = app.scrollViews.firstMatch
        let start = detailScroll.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.72))
        let end = detailScroll.coordinate(withNormalizedOffset: CGVector(dx: 0.5, dy: 0.54))
        start.press(forDuration: 0.05, thenDragTo: end)

        XCTAssertTrue(expandedTitle.exists)
        XCTAssertGreaterThan(expandedTitle.frame.maxY, back.frame.maxY)
        XCTAssertFalse(collapsedTitle.exists)
        let transitioningScreenshot = XCTAttachment(screenshot: app.screenshot())
        transitioningScreenshot.name = "event-detail-scrolling-before-title-collapse"
        transitioningScreenshot.lifetime = .keepAlways
        add(transitioningScreenshot)

        detailScroll.swipeUp()
        detailScroll.swipeUp()

        XCTAssertTrue(collapsedTitle.waitForExistence(timeout: 5))
        XCTAssertEqual(collapsedTitle.label, "Private Picnic Invitation")
        XCTAssertLessThan(collapsedTitle.frame.height, 30)
        XCTAssertTrue(
            app.descendants(matching: .any)["event-detail-navigation-divider"].exists
        )
        let collapsedScreenshot = XCTAttachment(screenshot: app.screenshot())
        collapsedScreenshot.name = "event-detail-collapsed-navigation-title"
        collapsedScreenshot.lifetime = .keepAlways
        add(collapsedScreenshot)
    }

    func testReplyPreviewDismissesFromTheEdgeOfTheVisibleButton() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].waitForExistence(timeout: 10))
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

    func testLockedGuestStatusEyesShowAnchoredTooltipWithoutDismissingAttendees() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].waitForExistence(timeout: 10))
        let guestList = app.staticTexts["See the full guest list"]
        scrollToMakeHittable(guestList, in: app.scrollViews.firstMatch)
        guestList.tap()

        XCTAssertTrue(app.navigationBars["Attendees"].waitForExistence(timeout: 5))
        let lockedStatuses = app.buttons.matching(
            NSPredicate(format: "label == %@", "Guest status hidden")
        )
        XCTAssertTrue(lockedStatuses.firstMatch.waitForExistence(timeout: 5))
        lockedStatuses.firstMatch.tap()

        XCTAssertTrue(app.navigationBars["Attendees"].exists)
        let tooltip = app.staticTexts["locked-guest-status-tooltip"]
        XCTAssertTrue(tooltip.waitForExistence(timeout: 2))
        XCTAssertEqual(tooltip.label, "Reply privately to see who has responded.")
        XCTAssertLessThan(tooltip.frame.maxY, lockedStatuses.firstMatch.frame.minY)
        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "attendee-locked-status-tooltip"
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
        XCTAssertFalse(app.staticTexts["You can see who has already responded."].exists)
        let responded = app.staticTexts.matching(
            NSPredicate(format: "label == %@", "Responded")
        )
        XCTAssertEqual(responded.count, 0)
        XCTAssertTrue(responded.element(boundBy: 1).waitForExistence(timeout: 5))
        XCTAssertEqual(responded.count, 2)
        XCTAssertTrue(app.staticTexts["Not responded"].exists)
    }

    func testPrivacyProofKeepsSpacingWithoutTheEssentialsLabelAndCentersBoundaryIcon() {
        let app = launch(scenario: "response-progress-refresh")

        let event = app.staticTexts["Response Refresh Fixture"]
        XCTAssertTrue(event.waitForExistence(timeout: 10))
        event.tap()

        let proofLink = app.staticTexts["Prove it to me"]
        scrollToMakeHittable(proofLink, in: app.scrollViews.firstMatch)
        proofLink.tap()

        XCTAssertTrue(app.staticTexts["How privacy works"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["The essentials"].exists)
        XCTAssertTrue(app.staticTexts["privacy-answers-title"].exists)
        XCTAssertTrue(
            app.descendants(matching: .any)["privacy-navigation-divider"].exists
        )

        let icon = app.images["privacy-flow-boundary-icon"]
        let label = app.staticTexts["privacy-flow-boundary-label"]
        XCTAssertTrue(icon.waitForExistence(timeout: 2))
        XCTAssertTrue(label.waitForExistence(timeout: 2))
        XCTAssertLessThan(abs(icon.frame.midY - label.frame.midY), 2)

        let privacyScroll = app.scrollViews.firstMatch
        privacyScroll.swipeUp()
        privacyScroll.swipeUp()
        XCTAssertTrue(app.navigationBars["How privacy works"].waitForExistence(timeout: 5))
        XCTAssertTrue(
            app.descendants(matching: .any)["privacy-navigation-divider"].exists
        )

        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "privacy-proof-collapsed-navigation"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testConfirmedAttendeeStatusesStayInsideTheirRows() {
        let app = launch(scenario: "confirmed-attendees")

        let event = app.staticTexts["Confirmed Attendee Layout"]
        XCTAssertTrue(event.waitForExistence(timeout: 10))
        event.tap()

        let guestList = app.staticTexts["See the full guest list"]
        scrollToMakeHittable(guestList, in: app.scrollViews.firstMatch)
        guestList.tap()

        XCTAssertTrue(app.navigationBars["Attendees"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["This user has not responded to 0 of 0 confirmed events they were invited to."].exists)
        XCTAssertTrue(app.staticTexts["No response"].exists)

        let history = app.staticTexts[
            "This user has not responded to 2 of 3 confirmed events they were invited to."
        ]
        XCTAssertTrue(history.waitForExistence(timeout: 2))
        XCTAssertGreaterThanOrEqual(history.frame.minX, 0)
        XCTAssertLessThanOrEqual(history.frame.maxX, app.frame.maxX - 20)
        XCTAssertLessThanOrEqual(history.frame.height, 40)

        for name in ["One Anderson", "Two Brown", "Three Davis"] {
            let label = app.staticTexts[name]
            XCTAssertTrue(label.exists)
            XCTAssertGreaterThanOrEqual(label.frame.minX, 20)
        }

        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "confirmed-attendee-status-layout"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testAccountWideReplyNeverPresentsDeviceTransfer() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].waitForExistence(timeout: 10))
        let cantCommit = app.buttons["Can’t commit"]
        scrollToMakeHittable(cantCommit, in: app.scrollViews.firstMatch)
        cantCommit.tap()

        let submit = app.buttons["reply-submit"]
        scrollToMakeHittable(submit, in: app.scrollViews.firstMatch)
        submit.tap()

        XCTAssertFalse(
            app.alerts["Switch private replies to this device?"]
                .waitForExistence(timeout: 1)
        )
        XCTAssertFalse(app.buttons["device-switch-action"].exists)
        XCTAssertFalse(app.navigationBars["Confirm your phone number"].exists)
    }

    func testInvitationDetailSupportsPullToRefresh() {
        let app = launch(scenario: "invitee-home")

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()
        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].waitForExistence(timeout: 10))

        let detailScroll = app.scrollViews["invitation-detail-scroll"]
        XCTAssertTrue(detailScroll.waitForExistence(timeout: 5))
        detailScroll.swipeDown()

        XCTAssertTrue(app.staticTexts["Opened only after the invitation account matches."].exists)
        XCTAssertTrue(app.buttons["Back to Herd events"].exists)
    }

    func testResponseSuccessSwitchesBetweenEqualOutcomeCards() {
        let app = launch(
            scenario: "invitee-home",
            additionalArguments: ["--open-response-success"]
        )

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()

        XCTAssertTrue(app.staticTexts["Thanks for responding"].waitForExistence(timeout: 10))
        XCTAssertFalse(app.staticTexts["Your latest reply is saved."].exists)
        XCTAssertTrue(app.staticTexts["This is how your reply will appear to others."].exists)

        let previewTitle = app.staticTexts["success-reply-preview-title"]
        let outcomePicker = app.otherElements["success-outcome-picker"]
        XCTAssertTrue(previewTitle.exists)
        XCTAssertTrue(outcomePicker.waitForExistence(timeout: 3))
        XCTAssertGreaterThanOrEqual(outcomePicker.frame.height, 54)
        XCTAssertGreaterThanOrEqual(
            outcomePicker.frame.minY - previewTitle.frame.maxY,
            30
        )

        let preview = app.otherElements["success-outcome-preview"]
        XCTAssertTrue(preview.waitForExistence(timeout: 3))
        XCTAssertGreaterThanOrEqual(preview.frame.minY - outcomePicker.frame.maxY, 16)
        XCTAssertTrue(app.staticTexts["Correct Invitee"].exists)
        XCTAssertTrue(app.staticTexts["Going"].exists)
        XCTAssertFalse(app.staticTexts["This event was not confirmed"].exists)
        let confirmedHeight = preview.frame.height

        let confirmedScreenshot = XCTAttachment(screenshot: app.screenshot())
        confirmedScreenshot.name = "response-success-confirmed-outcome"
        confirmedScreenshot.lifetime = .keepAlways
        add(confirmedScreenshot)

        app.buttons["If never confirmed"].tap()
        XCTAssertTrue(app.staticTexts["This event was not confirmed"].waitForExistence(timeout: 3))
        XCTAssertEqual(preview.frame.height, confirmedHeight, accuracy: 1)
        XCTAssertFalse(app.staticTexts["Correct Invitee"].exists)

        let screenshot = XCTAttachment(screenshot: app.screenshot())
        screenshot.name = "response-success-outcome-toggle"
        screenshot.lifetime = .keepAlways
        add(screenshot)
    }

    func testAppClipHostActionUsesNativeFullAppHandoff() {
        let app = launchClip(scenario: "host-create")

        let hostAction = app.buttons["create-event-card"]
        XCTAssertTrue(hostAction.waitForExistence(timeout: 10))
        hostAction.tap()

        XCTAssertTrue(app.navigationBars["Host an event"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["Download Herd"].exists)
        XCTAssertTrue(app.buttons["full-app-download"].exists)
        XCTAssertFalse(app.navigationBars["New event"].exists)
    }

    func testAppClipResponseSuccessOffersOnlyGetHerd() {
        let app = launchClip(
            scenario: "invitee-home",
            additionalArguments: ["--open-response-success"]
        )

        XCTAssertTrue(app.staticTexts["Make plans happen."].waitForExistence(timeout: 10))
        signIn(app, phoneNumber: "4155550102")

        let invitation = app.staticTexts["Private Picnic Invitation"]
        XCTAssertTrue(invitation.waitForExistence(timeout: 10))
        invitation.tap()

        XCTAssertTrue(app.staticTexts["Thanks for responding"].waitForExistence(timeout: 10))
        let getHerd = app.buttons["success-download-herd"]
        XCTAssertTrue(getHerd.waitForExistence(timeout: 5))
        XCTAssertEqual(getHerd.label, "Get Herd")
        XCTAssertFalse(app.buttons["success-view-invitation"].exists)
        XCTAssertFalse(app.buttons["success-back-to-events"].exists)
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

    private func launchClip(
        scenario: String,
        additionalArguments: [String] = []
    ) -> XCUIApplication {
        let app = XCUIApplication(bundleIdentifier: "com.jameswoodbury.HerdPrototype.Clip")
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
        while (!element.exists || !element.isHittable), attempts < 16 {
            scrollView.swipeUp()
            attempts += 1
        }
        XCTAssertTrue(element.exists)
        XCTAssertTrue(element.isHittable)
    }

    private func scrollToMakeHittable(_ element: XCUIElement, in scrollView: XCUIElement) {
        XCTAssertTrue(scrollView.waitForExistence(timeout: 5))
        var attempts = 0
        while (!element.exists || !element.isHittable), attempts < 16 {
            scrollView.swipeUp()
            attempts += 1
        }
        XCTAssertTrue(element.exists)
        XCTAssertTrue(element.isHittable)
    }
}
