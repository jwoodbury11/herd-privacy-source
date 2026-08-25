import SwiftUI

enum EventImageID: String, Codable, CaseIterable, Hashable, Identifiable, Sendable {
    case poker
    case tennis
    case boardGames = "board-games"
    case houseDrinks = "house-drinks"
    case restaurant
    case cocktailBar = "cocktail-bar"
    case clubDancing = "club-dancing"
    case movieNight = "movie-night"
    case parkPicnic = "park-picnic"
    case travelAirport = "travel-airport"
    case camping
    case fishing
    case birthdayParty = "birthday-party"
    case jacuzzi
    case skiing
    case other

    var label: String {
        switch self {
        case .poker: "Poker"
        case .tennis: "Sports"
        case .boardGames: "Games"
        case .houseDrinks: "Hangout"
        case .restaurant: "Dinner"
        case .cocktailBar: "Bar"
        case .clubDancing: "Club"
        case .movieNight: "Movies"
        case .parkPicnic: "Park"
        case .travelAirport: "Travel"
        case .camping, .fishing: "Outdoors"
        case .other: "Other"
        case .birthdayParty: "Birthday"
        case .jacuzzi: "Hot tub"
        case .skiing: "Skiing"
        }
    }

    var assetName: String {
        "event-scene-\(rawValue)"
    }

    var id: String { rawValue }
}

struct EventSceneImage: View {
    let id: EventImageID

    var body: some View {
        Image(id.assetName)
            .resizable()
            .scaledToFit()
            .accessibilityLabel("\(id.label) event image")
    }
}

struct EventImagePreviewView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var selectedImageID: EventImageID
    let onDone: (EventImageID) -> Void

    init(
        imageID: EventImageID,
        onDone: @escaping (EventImageID) -> Void
    ) {
        _selectedImageID = State(initialValue: imageID)
        self.onDone = onDone
    }

    var body: some View {
        TabView(selection: $selectedImageID) {
            ForEach(EventImageID.allCases) { imageID in
                VStack(spacing: 12) {
                    Spacer(minLength: 24)

                    EventSceneImage(id: imageID)
                        .frame(maxWidth: .infinity)
                        .padding(.horizontal, 22)
                        .accessibilityIdentifier(
                            "event-image-preview-full-\(imageID.rawValue)"
                        )

                    Text(imageID.label)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(.primary)
                        .accessibilityIdentifier(
                            "event-image-preview-name-\(imageID.rawValue)"
                        )

                    Spacer(minLength: 24)
                }
                .tag(imageID)
            }
        }
        .tabViewStyle(.page(indexDisplayMode: .always))
        .indexViewStyle(.page(backgroundDisplayMode: .always))
        .accessibilityIdentifier("event-image-preview-carousel")
        .background(HerdTheme.canvas)
        .safeAreaInset(edge: .bottom, spacing: 0) {
            Button {
                onDone(selectedImageID)
                dismiss()
            } label: {
                Text("Done")
                    .font(.headline)
                    .frame(maxWidth: .infinity)
                    .frame(minHeight: 50)
            }
            .buttonStyle(.borderedProminent)
            .tint(.white)
            .foregroundStyle(.black)
            .padding(.horizontal, 20)
            .padding(.top, 12)
            .padding(.bottom, 8)
            .background(HerdTheme.canvas)
            .accessibilityIdentifier("event-image-preview-done")
        }
        .herdCanvasBehindSystemUI()
    }
}
