import SwiftUI

enum HerdTheme {
    static let canvas = Color(uiColor: .secondarySystemBackground)
    static let surface = Color(uiColor: .tertiarySystemBackground)
    static let raisedSurface = Color(uiColor: .systemGray5)
    static let subtleBorder = Color(uiColor: .separator)
}

struct WireframeCardModifier: ViewModifier {
    let padding: CGFloat
    let cornerRadius: CGFloat

    func body(content: Content) -> some View {
        content
            .padding(padding)
            .background(HerdTheme.surface, in: .rect(cornerRadius: cornerRadius))
            .overlay {
                RoundedRectangle(cornerRadius: cornerRadius)
                    .stroke(HerdTheme.subtleBorder, lineWidth: 1)
            }
    }
}

extension View {
    func wireframeCard(padding: CGFloat = 16, cornerRadius: CGFloat = 18) -> some View {
        modifier(WireframeCardModifier(padding: padding, cornerRadius: cornerRadius))
    }

    func herdScreenBackground() -> some View {
        scrollContentBackground(.hidden)
            .background(HerdTheme.canvas)
    }
}

struct PlainPressButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .contentShape(.rect)
            .opacity(configuration.isPressed ? 0.65 : 1)
            .scaleEffect(configuration.isPressed ? 0.99 : 1)
    }
}
