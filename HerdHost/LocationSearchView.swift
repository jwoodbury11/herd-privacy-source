import Combine
import MapKit
import SwiftUI

struct LocationSearchSuggestion: Equatable {
    let title: String
    let subtitle: String
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
        fixtureResults = HerdUITestEnvironment.current == nil
            ? nil
            : [
                LocationSearchSuggestion(
                    title: "219 Cumberland Street",
                    subtitle: "San Francisco, CA 94114"
                )
            ]
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

    init(
        locationName: Binding<String>,
        locationAddress: Binding<String>,
        profileAddress: String
    ) {
        _locationName = locationName
        _locationAddress = locationAddress
        self.profileAddress = LocationSearchSuggestions.profileAddress(from: profileAddress)

        let initialQuery = locationAddress.wrappedValue.isEmpty
            ? locationName.wrappedValue
            : locationAddress.wrappedValue
        _searchModel = StateObject(wrappedValue: LocationSearchModel(initialQuery: initialQuery))
        _selectedName = State(initialValue: locationName.wrappedValue)
        _selectedAddress = State(initialValue: locationAddress.wrappedValue)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Find a location")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)

                        LocationSearchField(
                            placeholder: "Place name, address, or link",
                            query: $searchModel.query
                        )
                    }

                    if searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                        if let profileAddress {
                            LocationGroup(title: "Suggestions") {
                                Button {
                                    selectedName = profileAddress
                                    selectedAddress = profileAddress
                                    searchModel.query = profileAddress
                                } label: {
                                    LocationResultRow(
                                        icon: "house",
                                        title: profileAddress,
                                        subtitle: "Your profile address",
                                        isSelected: selectedAddress == profileAddress
                                    )
                                }
                                .buttonStyle(LocationRowButtonStyle())
                                .accessibilityIdentifier("profile-address-suggestion")
                            }
                        }
                    } else if !searchModel.results.isEmpty {
                        LocationGroup(title: "Suggestions") {
                            ForEach(Array(searchModel.results.enumerated()), id: \.offset) { index, result in
                            Button {
                                selectedName = result.title
                                selectedAddress = result.subtitle
                                searchModel.query = [result.title, result.subtitle]
                                    .filter { !$0.isEmpty }
                                    .joined(separator: ", ")
                            } label: {
                                    LocationResultRow(
                                        icon: "mappin.and.ellipse",
                                        title: result.title,
                                        subtitle: result.subtitle,
                                        isSelected: selectedName == result.title &&
                                            selectedAddress == result.subtitle
                                    )
                            }
                                .buttonStyle(LocationRowButtonStyle())

                                if index < searchModel.results.count - 1 {
                                    Divider()
                                        .padding(.leading, 60)
                                }
                            }
                        }
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
                        locationName = selectedName.isEmpty ? manualQuery : selectedName
                        locationAddress = selectedAddress.isEmpty ? manualQuery : selectedAddress
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
            let selectedQuery = [selectedName, selectedAddress]
                .filter { !$0.isEmpty }
                .joined(separator: ", ")
            if query.trimmingCharacters(in: .whitespacesAndNewlines) != selectedQuery {
                selectedName = ""
                selectedAddress = ""
            }
        }
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

    init(address: Binding<String>) {
        _address = address
        _searchModel = StateObject(
            wrappedValue: LocationSearchModel(initialQuery: address.wrappedValue)
        )
        _selectedAddress = State(initialValue: address.wrappedValue.nonEmpty)
    }

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 20) {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Home address")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .padding(.horizontal, 4)

                        LocationSearchField(
                            placeholder: "Street, city, state",
                            query: $searchModel.query,
                            usesAddressContentType: true,
                            accessibilityIdentifier: "profile-address-search"
                        )
                    }

                    if !searchModel.results.isEmpty {
                        LocationGroup(title: "Suggestions") {
                            ForEach(Array(searchModel.results.enumerated()), id: \.offset) { index, result in
                                let fullAddress = [result.title, result.subtitle]
                                    .filter { !$0.isEmpty }
                                    .joined(separator: ", ")

                                Button {
                                    selectedAddress = fullAddress
                                    searchModel.query = fullAddress
                                } label: {
                                    LocationResultRow(
                                        icon: "mappin.and.ellipse",
                                        title: result.title,
                                        subtitle: result.subtitle,
                                        isSelected: selectedAddress == fullAddress
                                    )
                                }
                                .buttonStyle(LocationRowButtonStyle())
                                .accessibilityIdentifier("profile-address-result-\(index)")

                                if index < searchModel.results.count - 1 {
                                    Divider()
                                        .padding(.leading, 60)
                                }
                            }
                        }
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
                        address = selectedAddress ?? trimmedQuery
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
    }

    private var trimmedQuery: String {
        searchModel.query.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

private struct LocationSearchField: View {
    let placeholder: String
    @Binding var query: String
    var usesAddressContentType = false
    var accessibilityIdentifier: String? = nil

    var body: some View {
        HStack(spacing: 11) {
            Image(systemName: "magnifyingglass")
                .font(.subheadline.weight(.semibold))
                .foregroundStyle(.secondary)

            TextField(placeholder, text: $query)
                .textContentType(usesAddressContentType ? .fullStreetAddress : .location)
                .textInputAutocapitalization(.words)
                .autocorrectionDisabled()
                .submitLabel(.search)
                .accessibilityIdentifier(accessibilityIdentifier ?? placeholder)
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

private struct LocationGroup<Content: View>: View {
    let title: String
    @ViewBuilder let content: Content

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 4)

            VStack(spacing: 0) {
                content
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(HerdTheme.surface, in: .rect(cornerRadius: 18))
            .clipShape(.rect(cornerRadius: 18))
            .overlay {
                RoundedRectangle(cornerRadius: 18)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
        }
    }
}

private struct LocationResultRow: View {
    let icon: String
    let title: String
    let subtitle: String
    let isSelected: Bool

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
                if !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .lineLimit(2)
                }
            }

            Spacer(minLength: 12)

            Image(systemName: isSelected ? "checkmark.circle.fill" : "chevron.right")
                .font(isSelected ? .body : .footnote.weight(.semibold))
                .foregroundStyle(isSelected ? .primary : .secondary)
        }
        .padding(.horizontal, 14)
        .frame(minHeight: 66)
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
