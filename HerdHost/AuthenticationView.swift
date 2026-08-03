import SwiftUI

struct AuthenticationView: View {
    private static let verificationCodeLength = 4

    @Environment(AuthStore.self) private var authStore
    @Environment(InvitationCoordinator.self) private var invitationCoordinator
    @State private var phoneNumber = ""
    @State private var code = ""
    @State private var showsReleaseStatus = false
    @FocusState private var focusedField: Field?

    private let experience = HerdExperience.shared.authentication

    private enum Field {
        case phone
        case code
    }

    var body: some View {
        Group {
            if let challenge = authStore.challenge {
                verificationScreen(challenge)
            } else {
                welcomeScreen
            }
        }
        .background(HerdTheme.canvas)
        .alert(
            experience.releaseStatus.heading,
            isPresented: $showsReleaseStatus
        ) {
            Button(experience.releaseStatus.dismissButton, role: .cancel) {}
        } message: {
            Text(experience.releaseStatus.body)
        }
        .onAppear {
            focusedField = authStore.challenge == nil ? .phone : .code
        }
        .onChange(of: authStore.challenge?.challengeId) { _, challengeID in
            code = ""
            focusedField = challengeID == nil ? .phone : .code
        }
    }

    private var welcomeScreen: some View {
        GeometryReader { geometry in
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    brand

                    VStack(alignment: .leading, spacing: 7) {
                        Text(experience.welcome.title)
                            .font(.system(size: 42, weight: .bold))
                            .tracking(-1.4)
                            .lineSpacing(-2)

                        Text(experience.welcome.body)
                            .font(.title3)
                            .foregroundStyle(.secondary)

                        if invitationCoordinator.pendingToken != nil {
                            Label(
                                "Your invitation is ready and will open after you sign in.",
                                systemImage: "envelope.badge.fill"
                            )
                            .font(.subheadline.weight(.semibold))
                            .foregroundStyle(.primary)
                            .padding(.top, 12)
                            .accessibilityIdentifier("pending-invitation-notice")
                        }
                    }
                    .padding(.horizontal, 4)
                    .padding(.top, experience.layout.welcomeTopSpacing)
                    .padding(.bottom, 24)

                    phoneEntry

                    if authStore.errorMessage != nil {
                        errorMessage
                            .padding(.top, 12)
                            .padding(.horizontal, 4)
                    }

                    Spacer(minLength: 28)

                    welcomeAction
                }
                .frame(maxWidth: 520)
                .frame(
                    maxWidth: .infinity,
                    minHeight: geometry.size.height,
                    alignment: .top
                )
                .padding(.horizontal, experience.layout.horizontalPadding)
                .padding(.top, experience.layout.topPadding)
                .padding(.bottom, 18)
            }
            .scrollDismissesKeyboard(.interactively)
        }
    }

    private var brand: some View {
        HStack(spacing: 10) {
            Image(systemName: "person.3.fill")
                .font(.headline)
                .foregroundStyle(.black)
                .frame(width: 36, height: 36)
                .background(.white, in: .rect(cornerRadius: 9))

            Text(experience.brandName)
                .font(.system(size: 18, weight: .bold))
                .tracking(-0.3)

            Spacer(minLength: 12)

            Button {
                showsReleaseStatus = true
            } label: {
                Text(experience.releaseStatus.label)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.78)
                    .padding(.horizontal, 9)
                    .padding(.vertical, 6)
                    .background(HerdTheme.surface, in: .capsule)
                    .overlay {
                        Capsule()
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
            }
            .buttonStyle(PlainPressButtonStyle())
        }
    }

    private var phoneEntry: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(experience.welcome.phoneLabel)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
                .padding(.horizontal, 3)

            TextField(experience.welcome.phonePlaceholder, text: $phoneNumber)
                .keyboardType(.phonePad)
                .textContentType(.telephoneNumber)
                .focused($focusedField, equals: .phone)
                .font(.body)
                .padding(.horizontal, 16)
                .frame(minHeight: experience.layout.fieldHeight)
                .background(
                    HerdTheme.surface,
                    in: .rect(cornerRadius: experience.layout.fieldCornerRadius)
                )
                .overlay {
                    RoundedRectangle(cornerRadius: experience.layout.fieldCornerRadius)
                        .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                }
                .onChange(of: phoneNumber) { _, value in
                    let formatted = Self.formattedPhoneNumber(value)
                    if formatted != value {
                        phoneNumber = formatted
                    }
                    authStore.clearError()
                }
                .accessibilityIdentifier("authentication-phone")
        }
    }

    private var welcomeAction: some View {
        VStack(spacing: 12) {
            Button {
                focusedField = nil
                Task {
                    _ = await authStore.requestCode(
                        phoneNumber: phoneNumber,
                        inviteToken: invitationCoordinator.pendingToken
                    )
                }
            } label: {
                HStack(spacing: 10) {
                    if authStore.isBusy {
                        ProgressView()
                            .tint(.black)
                    }
                    Text(
                        authStore.isBusy
                            ? experience.welcome.requestCodePendingButton
                            : experience.welcome.requestCodeButton
                    )
                    .font(.headline)
                }
                .foregroundStyle(.black)
                .frame(maxWidth: .infinity)
                .frame(minHeight: experience.layout.buttonHeight)
                .background(
                    .white,
                    in: .rect(cornerRadius: experience.layout.buttonCornerRadius)
                )
            }
            .buttonStyle(PlainPressButtonStyle())
            .accessibilityIdentifier("authentication-request-code")
            .disabled(
                authStore.isBusy ||
                !AuthStore.canRequestCode(phoneNumber: phoneNumber)
            )
            .opacity(
                authStore.isBusy ||
                !AuthStore.canRequestCode(phoneNumber: phoneNumber)
                    ? 0.42
                    : 1
            )

            legalFootnote
        }
    }

    private var legalFootnote: some View {
        Text(legalAttributedString)
            .font(.system(size: 10))
            .foregroundStyle(Color(uiColor: .tertiaryLabel))
            .multilineTextAlignment(.center)
            .frame(maxWidth: .infinity)
            .tint(.secondary)
    }

    private var legalAttributedString: AttributedString {
        let baseURL = legalBaseURL
        let markdown = """
        \(experience.legal.prefix) [\(experience.legal.terms)](\(baseURL)/terms) and [\(experience.legal.privacy)](\(baseURL)/privacy). \(experience.legal.suffix)
        """
        return (try? AttributedString(markdown: markdown)) ?? AttributedString(markdown)
    }

    private var legalBaseURL: String {
        let configured = Bundle.main.object(forInfoDictionaryKey: "HERD_API_BASE_URL") as? String
        let value = configured?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        if
            let url = URL(string: value),
            url.scheme?.lowercased() == "https",
            url.host != nil,
            url.user == nil,
            url.password == nil,
            url.fragment == nil
        {
            return value
        }
#if DEBUG
        return "https://herd-invitee-preview.jimmy4.chatgpt.site"
#else
        return "https://configuration.invalid"
#endif
    }

    private func verificationScreen(_ challenge: AuthChallenge) -> some View {
        VStack(spacing: 0) {
            verificationHeader

            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    Text(experience.verification.title)
                        .font(.system(size: 32, weight: .bold))
                        .tracking(-1)

                    Text(
                        "\(experience.verification.bodyPrefix) \(Self.maskedPhoneNumber(challenge.phoneNumber))."
                    )
                    .font(.body)
                    .foregroundStyle(.secondary)
                    .padding(.top, 8)

                    verificationCodeEntry
                        .padding(.top, 32)

                    if authStore.errorMessage != nil {
                        errorMessage
                            .padding(.top, 18)
                    }

                    resendButton(challenge)
                        .padding(.top, authStore.errorMessage == nil ? 18 : 0)

                    Spacer(minLength: 30)
                }
                .frame(maxWidth: 520)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, experience.layout.horizontalPadding)
                .padding(.top, 8)
                .padding(.bottom, 30)
            }
            .scrollDismissesKeyboard(.interactively)
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            verificationAction
        }
    }

    private var verificationHeader: some View {
        HStack {
            Button {
                authStore.changePhoneNumber()
            } label: {
                Image(systemName: "chevron.left")
                    .font(.system(size: 18, weight: .semibold))
                    .frame(width: 46, height: 46)
                    .background(HerdTheme.surface, in: .circle)
                    .overlay {
                        Circle()
                            .stroke(HerdTheme.subtleBorder, lineWidth: 1)
                    }
            }
            .buttonStyle(PlainPressButtonStyle())
            .accessibilityLabel(experience.verification.changePhoneAccessibilityLabel)

            Spacer()
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
    }

    private var verificationCodeEntry: some View {
        ZStack {
            HStack(spacing: experience.layout.verificationCodeGap) {
                ForEach(0..<Self.verificationCodeLength, id: \.self) { index in
                    let digit = code.count > index
                        ? String(code[code.index(code.startIndex, offsetBy: index)])
                        : ""
                    let isActive = focusedField == .code && index == min(
                        code.count,
                        Self.verificationCodeLength - 1
                    )

                    Text(digit)
                        .font(.system(size: 25, weight: .semibold, design: .rounded))
                        .frame(
                            width: experience.layout.verificationCodeWidth,
                            height: experience.layout.verificationCodeHeight
                        )
                        .background(
                            isActive ? HerdTheme.raisedSurface : HerdTheme.surface,
                            in: .rect(cornerRadius: experience.layout.verificationCodeCornerRadius)
                        )
                        .overlay {
                            RoundedRectangle(
                                cornerRadius: experience.layout.verificationCodeCornerRadius
                            )
                                .stroke(
                                    isActive ? Color.white.opacity(0.62) : HerdTheme.subtleBorder,
                                    lineWidth: 1
                                )
                        }
                }
            }
            .frame(
                maxWidth: .infinity,
                alignment: experience.layout.verificationCodeAlignment == "start"
                    ? .leading
                    : .center
            )
            .allowsHitTesting(false)
            .accessibilityHidden(true)

            TextField("", text: $code)
                .keyboardType(.numberPad)
                .textContentType(.oneTimeCode)
                .focused($focusedField, equals: .code)
                .foregroundStyle(.clear)
                .tint(.clear)
                .opacity(0.02)
                .accessibilityLabel(experience.verification.codeAccessibilityLabel)
                .onChange(of: code) { _, value in
                    let digits = String(
                        value.filter(\.isWholeNumber).prefix(Self.verificationCodeLength)
                    )
                    if digits != value {
                        code = digits
                    }
                    authStore.clearError()
                }
        }
        .contentShape(.rect)
        .onTapGesture {
            focusedField = .code
        }
    }

    private func resendButton(_ challenge: AuthChallenge) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let remaining = max(
                0,
                Int(challenge.resendAt.timeIntervalSince(context.date).rounded(.up))
            )
            Button {
                Task {
                    _ = await authStore.resendCode()
                }
            } label: {
                Text(
                    remaining > 0
                        ? "\(experience.verification.resendPendingPrefix) 0:\(String(format: "%02d", remaining))"
                        : experience.verification.resendButton
                )
            }
            .buttonStyle(.plain)
            .font(.subheadline.weight(.semibold))
            .foregroundStyle(remaining > 0 ? .tertiary : .primary)
            .disabled(remaining > 0 || authStore.isBusy)
        }
    }

    private var verificationAction: some View {
        Button {
            focusedField = nil
            Task {
                _ = await authStore.verifyCode(code)
            }
        } label: {
            HStack(spacing: 10) {
                if authStore.isBusy {
                    ProgressView()
                        .tint(.black)
                }
                Text(
                    authStore.isBusy
                        ? experience.verification.verifyPendingButton
                        : experience.verification.verifyButton
                )
                .font(.headline)
            }
            .foregroundStyle(.black)
            .frame(maxWidth: .infinity)
            .frame(minHeight: experience.layout.buttonHeight)
            .background(
                .white,
                in: .rect(cornerRadius: experience.layout.buttonCornerRadius)
            )
        }
        .buttonStyle(PlainPressButtonStyle())
        .disabled(authStore.isBusy)
        .opacity(authStore.isBusy ? 0.42 : 1)
        .padding(.horizontal, 18)
        .padding(.top, 13)
        .padding(.bottom, 8)
        .background(HerdTheme.canvas)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(HerdTheme.subtleBorder)
                .frame(height: 0.5)
        }
    }

    @ViewBuilder
    private var errorMessage: some View {
        if let errorMessage = authStore.errorMessage {
            Label(errorMessage, systemImage: "exclamationmark.circle.fill")
                .font(.footnote)
                .foregroundStyle(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private static func formattedPhoneNumber(_ value: String) -> String {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        let digits = String(trimmed.filter(\.isWholeNumber).prefix(15))
        if trimmed.hasPrefix("+") {
            return "+\(digits)"
        }
        if digits.count > 10 {
            if digits.count == 11, digits.hasPrefix("1") {
                let national = String(digits.dropFirst())
                return "+1 \(formattedNationalPhoneNumber(national))"
            }
            return "+\(digits)"
        }
        return formattedNationalPhoneNumber(digits)
    }

    private static func formattedNationalPhoneNumber(_ digits: String) -> String {
        if digits.count <= 3 {
            return digits
        }
        if digits.count <= 6 {
            return "(\(digits.prefix(3))) \(digits.dropFirst(3))"
        }
        let areaCode = digits.prefix(3)
        let exchangeStart = digits.index(digits.startIndex, offsetBy: 3)
        let exchangeEnd = digits.index(digits.startIndex, offsetBy: 6)
        let exchange = digits[exchangeStart..<exchangeEnd]
        let subscriber = digits.dropFirst(6)
        return "(\(areaCode)) \(exchange)-\(subscriber)"
    }

    private static func maskedPhoneNumber(_ value: String) -> String {
        let digits = value.filter(\.isWholeNumber)
        let suffix = String(digits.suffix(4))
        return "••• ••• \(String(repeating: "•", count: max(0, 4 - suffix.count)))\(suffix)"
    }
}
