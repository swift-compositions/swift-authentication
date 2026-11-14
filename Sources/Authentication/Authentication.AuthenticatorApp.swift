internal import ASCII
internal import Byte
internal import RFC_3986
internal import RFC_4648

extension Authentication {

    /// An authenticator app enrolled for an account: RFC 6238 as the apps expect it, HMAC-SHA-1, 6 digits and 30
    /// seconds, with a 20-byte secret.
    ///
    /// The server must be able to read the secret back, unlike the other secrets here, which are stored as digests.
    public struct AuthenticatorApp: Sendable {

        /// The shared secret.
        public let secret: [UInt8]

        let totp: RFC_6238.TOTP

        /// An enrolment read back from storage.
        public init(secret: [UInt8]) throws(RFC_6238.Error) {
            self.secret = secret
            self.totp = try RFC_6238.TOTP(secret: secret)
        }

        /// A new enrolment with a 20-byte secret from `generator`.
        public static func enroll(using generator: inout some RandomNumberGenerator) -> AuthenticatorApp {
            var secret: [UInt8] = []
            for _ in 0..<20 {
                secret.append(UInt8.random(in: 0...255, using: &generator))
            }
            do {
                return try AuthenticatorApp(secret: secret)
            } catch {
                preconditionFailure("a 20-byte secret always makes a generator: \(error)")
            }
        }
    }
}

extension Authentication.AuthenticatorApp {

    /// The secret in Base32 without padding, for typing into an app by hand.
    public var base32Secret: String {
        let letters = RFC_4648.Base32.encode(secret.map(Byte.init(_:)), padding: false)
        return String(decoding: letters.map(\.underlying), as: UTF8.self)
    }

    /// The `otpauth://totp/` address an app reads from a QR code (Google's Key Uri Format): the label is the issuer
    /// and the account, each percent-encoded.
    public func uri(issuer: String, account: String) -> String {
        func encoded(_ text: String) -> String {
            String(decoding: RFC_3986.percentEncode(Array(text.utf8)), as: UTF8.self)
        }
        return "otpauth://totp/\(encoded(issuer)):\(encoded(account))"
            + "?secret=\(base32Secret)&issuer=\(encoded(issuer))&algorithm=SHA1&digits=6&period=30"
    }

    /// The step whose code is `code`, one step either side of `now` being accepted, or `nil` when it does not match
    /// or its step is not after `lastStep`, the step of the code accepted before. Store the returned step.
    public func verify(_ code: String, at now: Time.Instant, after lastStep: UInt64?) -> UInt64? {
        let digits = code.filter { $0 != " " }
        guard let step = try? totp.validate(digits, at: now.secondsSinceUnixEpoch, window: 1) else { return nil }
        if let lastStep, step <= lastStep { return nil }
        return step
    }
}
