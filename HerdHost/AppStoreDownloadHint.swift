import StoreKit
import SwiftUI

extension View {
    func herdAppStoreOverlay(isPresented: Binding<Bool>) -> some View {
        safeAreaInset(edge: .bottom, spacing: 0) {
            if isPresented.wrappedValue {
                AppStoreDownloadHint()
                    .frame(maxWidth: .infinity)
                    .background(HerdTheme.canvas)
            }
        }
        .appStoreOverlay(isPresented: isPresented) {
            SKOverlay.AppClipConfiguration(position: .bottom)
        }
    }
}

private struct AppStoreDownloadHint: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @ScaledMetric(relativeTo: .subheadline) private var cardTextAllowance = 48
    @State private var writesFirstLine = false
    @State private var writesSecondLine = false
    @State private var drawsArrow = false

    var body: some View {
        VStack(spacing: 0) {
            VStack(spacing: 0) {
                handwrittenLine("Once downloaded,", revealed: writesFirstLine)
                handwrittenLine("tap Open to continue", revealed: writesSecondLine)
            }
            .rotationEffect(.degrees(-3))

            DownloadHintArrow()
                .trim(from: 0, to: drawsArrow ? 1 : 0)
                .stroke(style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))
                .frame(width: 66, height: 42)
                .offset(x: 82)
                .padding(.top, 7)
        }
        .foregroundStyle(.primary.opacity(0.9))
        .padding(.horizontal, 24)
        .padding(.top, 12)
        .padding(.bottom, 8)
        .allowsHitTesting(false)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Once downloaded, tap Open to continue")
        .accessibilityIdentifier("app-store-download-hint")
        .onAppear {
            withAnimation(reduceMotion ? nil : .linear(duration: 0.55).delay(0.25)) {
                writesFirstLine = true
            }
            withAnimation(reduceMotion ? nil : .linear(duration: 0.65).delay(0.8)) {
                writesSecondLine = true
            }
            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.45).delay(1.45)) {
                drawsArrow = true
            }
        }
        // StoreKit draws over the scene, and its card grows with Dynamic Type.
        // Reserve the card's text growth as well as the gap below the arrow.
        .padding(.bottom, 148 + max(0, cardTextAllowance - 48))
    }

    private func handwrittenLine(_ text: String, revealed: Bool) -> some View {
        Text(text)
            .font(.custom("GochiHand-Regular", size: 25, relativeTo: .title3))
            .multilineTextAlignment(.center)
            .fixedSize(horizontal: false, vertical: true)
            .mask(alignment: .leading) {
                GeometryReader { geometry in
                    Rectangle()
                        .frame(width: revealed ? geometry.size.width : 0)
                }
            }
    }
}

private struct DownloadHintArrow: Shape {
    func path(in rect: CGRect) -> Path {
        var path = Path()
        path.move(to: CGPoint(x: rect.width * 0.08, y: rect.height * 0.05))
        path.addCurve(
            to: CGPoint(x: rect.width * 0.86, y: rect.height * 0.94),
            control1: CGPoint(x: rect.width * 0.64, y: rect.height * 0.03),
            control2: CGPoint(x: rect.width * 0.95, y: rect.height * 0.36)
        )
        path.move(to: CGPoint(x: rect.width * 0.68, y: rect.height * 0.70))
        path.addLine(to: CGPoint(x: rect.width * 0.86, y: rect.height * 0.94))
        path.addLine(to: CGPoint(x: rect.width * 0.99, y: rect.height * 0.64))
        return path
    }
}
