import SwiftUI
import UIKit

enum HerdKeyboard {
    static func dismiss() {
        UIApplication.shared.sendAction(
            #selector(UIResponder.resignFirstResponder),
            to: nil,
            from: nil,
            for: nil
        )
    }
}

enum HerdTheme {
    static let canvas = Color(uiColor: .secondarySystemBackground)
    static let surface = Color(uiColor: .tertiarySystemBackground)
    static let raisedSurface = Color(uiColor: .systemGray5)
    static let subtleBorder = Color(uiColor: .separator)
}

/// Keeps the UIKit window surface aligned with the SwiftUI canvas. The system
/// keyboard has rounded transparent edges that can reveal this surface.
struct HerdWindowCanvasInstaller: UIViewRepresentable {
    func makeUIView(context: Context) -> HerdWindowCanvasView {
        HerdWindowCanvasView()
    }

    func updateUIView(_ uiView: HerdWindowCanvasView, context: Context) {
        uiView.installCanvasColor()
    }
}

final class HerdWindowCanvasView: UIView {
    override func didMoveToWindow() {
        super.didMoveToWindow()
        installCanvasColor()
    }

    func installCanvasColor() {
        window?.backgroundColor = .secondarySystemBackground
        window?.rootViewController?.view.backgroundColor = .clear
        window?.rootViewController?.view.isOpaque = false
    }
}

struct HerdMonochromeSwitchVisual: View {
    let isOn: Bool

    var body: some View {
        ZStack(alignment: isOn ? .trailing : .leading) {
            Capsule()
                .fill(isOn ? Color.white : Color(uiColor: .systemGray4))
                .overlay {
                    Capsule()
                        .stroke(
                            isOn ? Color.white : Color.white.opacity(0.22),
                            lineWidth: 1
                        )
                }

            Circle()
                .fill(isOn ? Color.black.opacity(0.82) : Color.white)
                .padding(3)
                .shadow(color: .black.opacity(0.34), radius: 2, y: 1)
        }
        .frame(width: 52, height: 32)
        .animation(.easeInOut(duration: 0.18), value: isOn)
        .accessibilityHidden(true)
    }
}

struct HerdMonochromeToggleStyle: ToggleStyle {
    func makeBody(configuration: Configuration) -> some View {
        HStack(spacing: 12) {
            configuration.label
            Spacer(minLength: 12)
            HerdMonochromeSwitchVisual(isOn: configuration.isOn)
        }
        .contentShape(.rect)
        .onTapGesture {
            configuration.isOn.toggle()
        }
    }
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

    /// Paints the app canvas through both the container and keyboard safe areas
    /// without changing the foreground view's keyboard-avoidance layout.
    func herdCanvasBehindSystemUI() -> some View {
        background {
            HerdTheme.canvas
                .ignoresSafeArea(.container, edges: .all)
                .ignoresSafeArea(.keyboard, edges: .all)
        }
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
