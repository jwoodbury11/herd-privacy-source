import SwiftUI

struct EventDateSheet: View {
    @Environment(\.dismiss) private var dismiss

    @Binding var eventDate: Date?
    @Binding var endDate: Date?
    @Binding var rsvpDeadline: Date?

    @State private var workingDate: Date
    @State private var includesEndDate: Bool
    @State private var workingEndDate: Date

    init(
        eventDate: Binding<Date?>,
        endDate: Binding<Date?>,
        rsvpDeadline: Binding<Date?>
    ) {
        _eventDate = eventDate
        _endDate = endDate
        _rsvpDeadline = rsvpDeadline

        let defaultStart = eventDate.wrappedValue ?? EventDraftDefaults.eventDate()
        _workingDate = State(initialValue: defaultStart)
        _includesEndDate = State(initialValue: endDate.wrappedValue != nil)
        _workingEndDate = State(
            initialValue: endDate.wrappedValue ?? Calendar.current.date(byAdding: .hour, value: 4, to: defaultStart)!
        )
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Starts") {
                    DatePicker(
                        "Event date and time",
                        selection: $workingDate,
                        in: Date.now...,
                        displayedComponents: [.date, .hourAndMinute]
                    )
                    .datePickerStyle(.graphical)
                    .labelsHidden()
                }

                Section {
                    Toggle("Add an end date", isOn: $includesEndDate)
                        .toggleStyle(.switch)
                        .tint(Color(uiColor: .systemGreen))

                    if includesEndDate {
                        DatePicker(
                            "Ends",
                            selection: $workingEndDate,
                            in: minimumEndDate...,
                            displayedComponents: [.date, .hourAndMinute]
                        )
                    }
                }
            }
            .herdScreenBackground()
            .navigationTitle("Date & time")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Clear") {
                        eventDate = nil
                        endDate = nil
                        rsvpDeadline = nil
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") {
                        eventDate = workingDate
                        endDate = includesEndDate ? max(workingEndDate, minimumEndDate) : nil

                        if rsvpDeadline == nil ||
                            rsvpDeadline! >= workingDate ||
                            !EventDeadlineRules.canSubmit(deadline: rsvpDeadline!) {
                            rsvpDeadline = Self.testReplyDeadline(before: workingDate)
                                ?? EventDeadlineRules.suggestedReplyDeadline(before: workingDate)
                        }
                        dismiss()
                    }
                    .fontWeight(.semibold)
                }
            }
        }
    }

    private var minimumEndDate: Date {
        workingDate.addingTimeInterval(EventDeadlineRules.minimumEventSeparation)
    }

    private static func testReplyDeadline(before eventDate: Date) -> Date? {
#if DEBUG
        // Simulator-only acceptance testing can exercise real post-deadline resolution
        // without changing production defaults or waiting several days.
        let arguments = ProcessInfo.processInfo.arguments
        guard
            let flagIndex = arguments.firstIndex(of: "--herd-test-rsvp-seconds"),
            arguments.indices.contains(flagIndex + 1),
            let seconds = TimeInterval(arguments[flagIndex + 1]),
            (60...3_600).contains(seconds)
        else { return nil }
        let deadline = Date.now.addingTimeInterval(seconds)
        return deadline < eventDate ? deadline : nil
#else
        return nil
#endif
    }
}

struct RSVPDeadlineSheet: View {
    @Environment(\.dismiss) private var dismiss

    @Binding var rsvpDeadline: Date?
    let eventDate: Date

    @State private var workingDeadline: Date
    private let minimumDeadline: Date
    private let maximumDeadline: Date
    private let hasValidDeadlineRange: Bool

    init(rsvpDeadline: Binding<Date?>, eventDate: Date) {
        _rsvpDeadline = rsvpDeadline
        self.eventDate = eventDate

        let minimumDeadline = Date.now.addingTimeInterval(
            EventDeadlineRules.submissionSafetyInterval
        )
        let candidateMaximum = eventDate.addingTimeInterval(
            -EventDeadlineRules.minimumEventSeparation
        )
        let hasValidDeadlineRange = candidateMaximum > minimumDeadline
        let maximumDeadline = max(minimumDeadline, candidateMaximum)
        let suggested = EventDeadlineRules.suggestedReplyDeadline(before: eventDate)
            ?? minimumDeadline
        let initialDeadline = min(
            max(rsvpDeadline.wrappedValue ?? suggested, minimumDeadline),
            maximumDeadline
        )
        self.minimumDeadline = minimumDeadline
        self.maximumDeadline = maximumDeadline
        self.hasValidDeadlineRange = hasValidDeadlineRange
        _workingDeadline = State(initialValue: initialDeadline)
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    DatePicker(
                        "Reply by",
                        selection: $workingDeadline,
                        in: minimumDeadline...maximumDeadline,
                        displayedComponents: [.date, .hourAndMinute]
                    )
                    .datePickerStyle(.graphical)
                    .labelsHidden()
                } footer: {
                    Text("Guests can reply until this deadline unless the event confirms first.")
                }
            }
            .herdScreenBackground()
            .navigationTitle("RSVP deadline")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Clear") {
                        rsvpDeadline = nil
                        dismiss()
                    }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        let deadline = min(workingDeadline, maximumDeadline)
                        rsvpDeadline = hasValidDeadlineRange &&
                            EventDeadlineRules.canSubmit(deadline: deadline)
                            ? deadline
                            : nil
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(!hasValidDeadlineRange)
                }
            }
        }
    }
}
