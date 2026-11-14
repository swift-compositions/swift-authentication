extension Authentication {

    /// A way of proving who one is.
    public enum Factor: String, Sendable, Hashable, CaseIterable {

        /// A code sent by email: a first factor only.
        case emailCode = "email-code"

        /// Signing in with an identity provider (GitHub, Google, X): a first factor only.
        case provider

        /// A passkey with user verification: possession and a biometric or PIN, bound to the site, so it is a
        /// full sign-in by itself.
        case passkey

        /// A code from an authenticator app (RFC 6238): a second factor.
        case authenticatorApp = "authenticator-app"

        /// A single-use recovery code: a second factor, for when the others are lost.
        case recoveryCode = "recovery-code"
    }
}

extension Authentication.Factor {

    /// Whether the factor completes a sign-in that a first factor began.
    public var isSecond: Bool {
        switch self {
        case .passkey, .authenticatorApp, .recoveryCode: true
        case .emailCode, .provider: false
        }
    }
}
