import Combine
import MapKit
import SwiftUI

struct LocationSearchSuggestion: Equatable {
    let title: String
    let subtitle: String
}

enum LocationUnitAddress {
    private static let separator = ", Unit "

    static func split(_ address: String) -> (base: String, unit: String) {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        guard
            let separatorRange = trimmed.range(of: separator, options: .backwards),
            separatorRange.upperBound < trimmed.endIndex
        else {
            return (trimmed, "")
        }
        let base = String(trimmed[..<separatorRange.lowerBound])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let unit = String(trimmed[separatorRange.upperBound...])
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return unit.isEmpty ? (trimmed, "") : (base, unit)
    }

    static func combine(base: String, unit: String) -> String {
        let trimmedBase = base.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedUnit = unit.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmedUnit.isEmpty else { return trimmedBase }
        guard !trimmedBase.isEmpty else { return "Unit \(trimmedUnit)" }
        return "\(trimmedBase)\(separator)\(trimmedUnit)"
    }
}

enum EventLocationPresentation {
    static func summary(name: String, address: String, separator: String) -> String {
        let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let trimmedAddress = address.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmedName.isEmpty { return trimmedAddress }
        if trimmedAddress.isEmpty { return trimmedName }

        let foldedName = trimmedName.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
        let foldedAddress = trimmedAddress.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: .current)
        if foldedAddress == foldedName || foldedAddress.hasPrefix("\(foldedName), unit ") {
            return trimmedAddress
        }
        return "\(trimmedName)\(separator)\(trimmedAddress)"
    }
}

final class LocationSearchModel: NSObject, ObservableObject, MKLocalSearchCompleterDelegate {
    @Published var query: String {
        didSet {
            if let fixtureResults {
                results = query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    ? []
                    : fixtureResults
                return
            }
            completer.queryFragment = query
        }
    }
    @Published private(set) var results: [LocationSearchSuggestion] = []

    private let completer = MKLocalSearchCompleter()
    private let fixtureResults: [LocationSearchSuggestion]?

    init(initialQuery: String = "") {
        query = initialQuery
#if DEBUG
        fixtureResults = HerdUITestEnvironment.current == nil
            ? nil
            : [
                LocationSearchSuggestion(
                    title: "219 Cumberland Street",
                    subtitle: "San Francisco, CA 94114"
                )
            ]
#else
        fixtureResults = nil
#endif
        super.init()
        completer.delegate = self
        completer.resultTypes = [.address, .pointOfInterest]
        if let fixtureResults {
            results = initialQuery.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                ? []
                : fixtureResults
        } else {
            completer.queryFragment = initialQuery
        }
    }

    func completerDidUpdateResults(_ completer: MKLocalSearchCompleter) {
        let latestResults = completer.results.map {
            LocationSearchSuggestion(title: $0.title, subtitle: $0.subtitle)
        }
        DispatchQueue.main.async { [weak self] in
            self?.results = latestResults
        }
    }

    func completer(_ completer: MKLocalSearchCompleter, didFailWithError error: Error) {
        DispatchQueue.main.async { [weak self] in
            self?.results = []
        }
    }
}

struct LocationSearchView: View {
    @Environment(\.dismiss) private var dismiss
    @Binding private var locationName: String
    @Binding private var locationAddress: String
    private let profileAddress: String?

    @StateObject private var searchModel: LocationSearchModel
    @State private var selectedName: String
    @State private var selectedAddress: String
    @State private var unitNumber: String
    @FocusState private var isSearchFocused: Bool
    @FocusState private var isUnitFocused: Bool

    init(
        locationName: Binding<String>,
        locationAddress: Binding<String>,
        profileAddress: String
    ) {
        _locationName = locationName
        _locationAddress = locationAddress
        self.profileAddress = LocationSearchSuggestions.profileAddress(from: profileAddress)

        let parsedAddress = LocationUnitAddress.split(locationAddress.wrappedValue)
        let initialQuery = parsedAddress.base.isEmpty
            ? locationName.wrappedValue
            : parsedAddress.base
        _searchModel = StateObject(wrappedValue: LocationSearchModel(initialQuery: initialQuery))
        _selectedName = State(initialValue: locationName.wrappedValue)
        _selectedAddress = State(initialValue: parsedAddress.base)
        _unitNumber = State(initialValue: parsedAddress.unit)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Find a location")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)

                        LocationAutocompleteField(
                            placeholder: "Place name, address, or link",
                            query: $searchModel.query,
                            isFocused: $isSearchFocused,
                            showsSuggestions: showsSuggestions,
                            clearAccessibilityIdentifier: "clear-location-search"
                        ) {
                            if trimmedQuery.isEmpty, let profileAddress {
                                let parsedProfileAddress = LocationUnitAddress.split(profileAddress)
                                Button {
                                    selectedName = parsedProfileAddress.base
                                    selectedAddress = parsedProfileAddress.base
                                    unitNumber = parsedProfileAddress.unit
                                    searchModel.query = parsedProfileAddress.base
                                    isSearchFocused = false
                                } label: {
                                    LocationResultRow(
                                        icon: "house",
                                        title: parsedProfileAddress.base,
                                        subtitle: "Your profile address"
                                    )
                                }
                                .buttonStyle(LocationRowButtonStyle())
                                .accessibilityIdentifier("profile-address-suggestion")
                            } else {
                                ForEach(
                                    Array(searchModel.results.enumerated()),
                                    id: \.offset
                                ) { index, result in
                                    Button {
                                        selectedName = result.title
                                        selectedAddress = result.subtitle
                                        searchModel.query = [result.title, result.subtitle]
                                            .filter { !$0.isEmpty }
                                            .joined(separator: ", ")
                                        isSearchFocused = false
                                    } label: {
                                        LocationResultRow(
                                            icon: "mappin.and.ellipse",
                                            title: result.title,
                                            subtitle: result.subtitle
                                        )
                                    }
                                    .buttonStyle(LocationRowButtonStyle())
                                    .accessibilityIdentifier("location-result-\(index)")

                                    if index < searchModel.results.count - 1 {
                                        Divider()
                                            .padding(.leading, 58)
                                    }
                                }
                            }
                        }

                        UnitNumberField(
                            unitNumber: $unitNumber,
                            isFocused: $isUnitFocused,
                            accessibilityIdentifier: "location-unit-number"
                        )
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 18)
            }
            .background(HerdTheme.canvas)
            .navigationTitle("Location")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        let manualQuery = searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines)
                        let trimmedUnit = unitNumber.trimmingCharacters(in: .whitespacesAndNewlines)
                        if selectedName.isEmpty && selectedAddress.isEmpty && trimmedUnit.isEmpty {
                            locationName = manualQuery
                            locationAddress = ""
                            dismiss()
                            return
                        }
                        let savedAddress = LocationUnitAddress.combine(
                            base: selectedAddress.isEmpty ? manualQuery : selectedAddress,
                            unit: trimmedUnit
                        )
                        let savedName = selectedName.trimmingCharacters(in: .whitespacesAndNewlines)
                        let normalizedSummary = EventLocationPresentation.summary(
                            name: savedName,
                            address: savedAddress,
                            separator: " · "
                        )
                        locationAddress = savedAddress
                        locationName = normalizedSummary == savedAddress ? "" : savedName
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(
                        selectedName.isEmpty &&
                        searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
                    )
                }
            }
        }
        .onChange(of: searchModel.query) { _, query in
            let selectedQuery = selectedName == selectedAddress
                ? selectedName
                : [selectedName, selectedAddress]
                    .filter { !$0.isEmpty }
                    .joined(separator: ", ")
            if query.trimmingCharacters(in: .whitespacesAndNewlines) != selectedQuery {
                selectedName = ""
                selectedAddress = ""
            }
        }
        .onAppear {
            isSearchFocused = true
        }
    }

    private var trimmedQuery: String {
        searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var showsSuggestions: Bool {
        guard isSearchFocused else { return false }
        if trimmedQuery.isEmpty {
            return profileAddress != nil
        }
        return !searchModel.results.isEmpty
    }
}

enum LocationSearchSuggestions {
    static func profileAddress(from address: String) -> String? {
        let trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

struct AddressSearchView: View {
    @Environment(\.dismiss) private var dismiss
    @Binding private var address: String

    @StateObject private var searchModel: LocationSearchModel
    @State private var selectedAddress: String?
    @State private var unitNumber: String
    @FocusState private var isSearchFocused: Bool
    @FocusState private var isUnitFocused: Bool

    init(address: Binding<String>) {
        let parsedAddress = LocationUnitAddress.split(address.wrappedValue)
        _address = address
        _searchModel = StateObject(
            wrappedValue: LocationSearchModel(initialQuery: parsedAddress.base)
        )
        _selectedAddress = State(initialValue: parsedAddress.base.nonEmpty)
        _unitNumber = State(initialValue: parsedAddress.unit)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Home address")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)

                        LocationAutocompleteField(
                            placeholder: "Street, city, state",
                            query: $searchModel.query,
                            isFocused: $isSearchFocused,
                            usesAddressContentType: true,
                            accessibilityIdentifier: "profile-address-search",
                            showsSuggestions: isSearchFocused && !searchModel.results.isEmpty,
                            clearAccessibilityIdentifier: "clear-profile-address-search"
                        ) {
                            ForEach(
                                Array(searchModel.results.enumerated()),
                                id: \.offset
                            ) { index, result in
                                let fullAddress = [result.title, result.subtitle]
                                    .filter { !$0.isEmpty }
                                    .joined(separator: ", ")

                                Button {
                                    selectedAddress = fullAddress
                                    searchModel.query = fullAddress
                                    isSearchFocused = false
                                } label: {
                                    LocationResultRow(
                                        icon: "mappin.and.ellipse",
                                        title: result.title,
                                        subtitle: result.subtitle
                                    )
                                }
                                .buttonStyle(LocationRowButtonStyle())
                                .accessibilityIdentifier("profile-address-result-\(index)")

                                if index < searchModel.results.count - 1 {
                                    Divider()
                                        .padding(.leading, 58)
                                }
                            }
                        }

                        UnitNumberField(
                            unitNumber: $unitNumber,
                            isFocused: $isUnitFocused,
                            accessibilityIdentifier: "profile-unit-number"
                        )
                    }
                }
                .padding(.horizontal, 16)
                .padding(.vertical, 18)
            }
            .background(HerdTheme.canvas)
            .navigationTitle("Address")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        address = LocationUnitAddress.combine(
                            base: selectedAddress ?? trimmedQuery,
                            unit: unitNumber
                        )
                        dismiss()
                    }
                    .fontWeight(.semibold)
                    .disabled(trimmedQuery.isEmpty)
                }
            }
        }
        .onChange(of: searchModel.query) { _, query in
            let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
            if selectedAddress != trimmed {
                selectedAddress = nil
            }
        }
        .onAppear {
            isSearchFocused = true
        }
    }

    private var trimmedQuery: String {
        searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct LocationAutocompleteField<Suggestions: View>: View {
    let placeholder: String
    @Binding var query: String
    let isFocused: FocusState<Bool>.Binding
    var usesAddressContentType = false
    var accessibilityIdentifier: String? = nil
    let showsSuggestions: Bool
    let clearAccessibilityIdentifier: String
    @ViewBuilder let suggestions: Suggestions

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 11) {
                Image(systemName: "magnifyingglass")
                    .font(.subheadline.weight(.semibold))
                    .foregroundStyle(.secondary)

                TextField(placeholder, text: $query)
                    .textContentType(usesAddressContentType ? .fullStreetAddress : .location)
                    .textInputAutocapitalization(.words)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .focused(isFocused)
                    .accessibilityIdentifier(accessibilityIdentifier ?? placeholder)

                if isFocused.wrappedValue && !query.isEmpty {
                    Button {
                        query = ""
                        isFocused.wrappedValue = true
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear search")
                    .accessibilityIdentifier(clearAccessibilityIdentifier)
                }
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 50)

            if isFocused.wrappedValue && showsSuggestions {
                Divider()
                    .padding(.leading, 14)
                VStack(spacing: 0) {
                    suggestions
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 12))
        .clipShape(.rect(cornerRadius: 12))
        .overlay {
            RoundedRectangle(cornerRadius: 12)
                .stroke(HerdTheme.subtleBorder, lineWidth: 1)
        }
    }
}

private struct UnitNumberField: View {
    @Binding var unitNumber: String
    let isFocused: FocusState<Bool>.Binding
    let accessibilityIdentifier: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Unit number")
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

            HStack(spacing: 10) {
                TextField("Optional", text: $unitNumber)
                    .textContentType(.fullStreetAddress)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .submitLabel(.done)
                    .focused(isFocused)
                    .accessibilityIdentifier(accessibilityIdentifier)

                if isFocused.wrappedValue && !unitNumber.isEmpty {
                    Button {
                        unitNumber = ""
                        isFocused.wrappedValue = true
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundStyle(.secondary)
                            .frame(width: 28, height: 28)
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Clear unit number")
                }
            }
            .padding(.horizontal, 14)
            .frame(minHeight: 50)
            .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 12))
            .overlay {
                RoundedRectangle(cornerRadius: 12)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
        }
    }
}

private struct LocationResultRow: View {
    let icon: String
    let title: String
    let subtitle: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 32, height: 32)
                .background(HerdTheme.raisedSurface, in: .rect(cornerRadius: 9))

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.primary)
                    .lineLimit(1)
                    .truncationMode(.tail)
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.tail)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 58)
        .contentShape(.rect)
    }
}

private struct LocationRowButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .contentShape(.rect)
            .background(configuration.isPressed ? HerdTheme.raisedSurface.opacity(0.65) : .clear)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

private extension String {
    var nonEmpty: String? {
        isEmpty ? nil : self
    }
}
